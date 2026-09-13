from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pandax import native, scenarios, pipeline, server, context
from pandax.context import new_run_dir
from pandax.context import Finding
from pandax.stages.ingest import _extract_tar, UnsafeArtifact


def opkg(tmp_path, version='2.80-16.1', variant='dnsmasq'):
    (tmp_path / 'etc').mkdir(exist_ok=True)
    (tmp_path / 'etc/openwrt_release').write_text("DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='19.07.5'\n")
    status = tmp_path / 'usr/lib/opkg/status'
    status.parent.mkdir(parents=True, exist_ok=True)
    status.write_text(f'Package: {variant}\nVersion: {version}\nStatus: install ok installed\n')
    return native.inventory(tmp_path)


def upstream(project: str, version: str) -> dict:
    return {
        'id': f'{project}-{version}',
        'project': project,
        'version': version,
        'url': f'https://example.invalid/{project}-{version}.tar.gz',
        'sha256': 'a' * 64,
        'status': 'verified',
        'method': 'sha256',
        'verified_at': '2026-09-09T00:00:00Z',
    }


def test_backport_revision_changes_verdict_without_upstream_version_change(tmp_path):
    before = native.assess(opkg(tmp_path))
    after = native.assess(opkg(tmp_path, '2.80-16.2'))
    assert {a['cve'] for a in before if a['state'] == 'affected'} == {'CVE-2020-25684', 'CVE-2020-25686'}
    assert {a['cve'] for a in after if a['state'] == 'fixed'} == {'CVE-2020-25684', 'CVE-2020-25686'}
    assert len(native.findings(after)) == 0


def test_full_variant_exposes_all_seven_and_unknown_revision_is_not_fixed(tmp_path):
    assert len(native.findings(native.assess(opkg(tmp_path, variant='dnsmasq-full')))) == 7
    rows = native.assess(opkg(tmp_path, '2.80-custom', 'dnsmasq-full'))
    assert {a['state'] for a in rows} == {'unknown'}


def test_foreign_package_database_does_not_receive_openwrt_backport_rules(tmp_path):
    opkg(tmp_path)
    (tmp_path / 'etc/openwrt_release').write_text("DISTRIB_ID='Other'\n")
    assert native.inventory(tmp_path)['components'] == []


@pytest.mark.parametrize('version,state', [('8.3.0', 'affected'), ('8.4.0', 'fixed'), ('9.0.0', 'unknown')])
def test_curl_reads_header_not_directory_label(tmp_path, version, state):
    root = tmp_path / 'curl-8.4.0'
    header = root / 'include/curl/curlver.h'
    header.parent.mkdir(parents=True)
    header.write_text(f'#define LIBCURL_VERSION "{version}"\n')
    (root / 'lib').mkdir(); (root / 'lib/socks.c').write_text('source')
    (root / 'src').mkdir(); (root / 'src/tool_main.c').write_text('source')
    data = native.inventory(tmp_path, upstream('curl', version))
    assert native.assess(data)[0]['state'] == state
    assert data['dependencies'][0]['dependsOn'] == [f'pkg:generic/libcurl@{version}']
    assert '65541' in native.assess(data)[0]['detail']


def test_heartbleed_source_and_consumer_inventory(tmp_path):
    (tmp_path / 'crypto').mkdir(); (tmp_path / 'ssl').mkdir(); (tmp_path / 'apps').mkdir()
    (tmp_path / 'crypto/opensslv.h').write_text('#define OPENSSL_VERSION_TEXT "OpenSSL 1.0.1f 6 Jan 2014"')
    (tmp_path / 'ssl/t1_lib.c').write_text('source')
    (tmp_path / 'apps/s_server.c').write_text('source')
    data = native.inventory(tmp_path, upstream('openssl', '1.0.1f'))
    assert {c['name'] for c in data['components']} == {'libssl', 'openssl-s_server'}
    assert native.assess(data)[0]['state'] == 'affected'
    assert 'OPENSSL_NO_HEARTBEATS' in native.assess(data)[0]['detail']


def test_unverified_upstream_lookalike_never_gets_conclusive_assessment(tmp_path):
    root = tmp_path / 'curl-lookalike'
    header = root / 'include/curl/curlver.h'
    header.parent.mkdir(parents=True)
    header.write_text('#define LIBCURL_VERSION "8.3.0"\n')
    (root / 'lib').mkdir()
    (root / 'lib/socks.c').write_text('source')

    rows = native.assess(native.inventory(tmp_path))

    assert len(rows) == 3
    assert {row['state'] for row in rows} == {'unknown'}
    assert all('not matched to the approved upstream SHA-256' in row['detail'] for row in rows)


@pytest.mark.parametrize(
    'project,version,expected',
    [
        ('curl', '8.3.0', {
            'CVE-2023-38545': 'affected',
            'CVE-2023-38546': 'affected',
            'CVE-2023-46218': 'affected',
        }),
        ('curl', '8.4.0', {
            'CVE-2023-38545': 'fixed',
            'CVE-2023-38546': 'fixed',
            'CVE-2023-46218': 'affected',
        }),
        ('curl', '8.5.0', {
            'CVE-2023-38545': 'fixed',
            'CVE-2023-38546': 'fixed',
            'CVE-2023-46218': 'fixed',
        }),
        ('openssl', '1.0.1f', {
            'CVE-2014-0160': 'affected',
            'CVE-2014-0224': 'affected',
            'CVE-2014-0195': 'affected',
        }),
        ('openssl', '1.0.1g', {
            'CVE-2014-0160': 'fixed',
            'CVE-2014-0224': 'affected',
            'CVE-2014-0195': 'affected',
        }),
        ('openssl', '1.0.1h', {
            'CVE-2014-0160': 'fixed',
            'CVE-2014-0224': 'fixed',
            'CVE-2014-0195': 'fixed',
        }),
    ],
)
def test_curated_upstream_boundaries(project, version, expected):
    component = 'libcurl' if project == 'curl' else 'libssl'
    purl = f'pkg:generic/{component}@{version}'
    data = {
        'components': [{
            'name': component,
            'version': version,
            'purl': purl,
            'bom-ref': purl,
        }],
        'source_identity': upstream(project, version),
    }

    rows = native.assess(data)

    assert {row['cve']: row['state'] for row in rows} == expected
    assert all(row['source_records'][0]['raw_assertion'] for row in rows)
    assert all(row['source_retrieved_at'] for row in rows)


def test_curl_vendor_boundary_retains_conflicting_osv_source():
    version = '8.4.0'
    purl = f'pkg:generic/libcurl@{version}'
    data = {
        'components': [{
            'name': 'libcurl',
            'version': version,
            'purl': purl,
            'bom-ref': purl,
        }],
        'source_identity': upstream('curl', version),
    }

    row = next(item for item in native.assess(data) if item['cve'] == 'CVE-2023-38546')

    assert row['state'] == 'fixed'
    assert row['conflicting_sources'][0]['asserted_state'] == 'affected'
    assert 'official curl' in row['conflicting_sources'][0]['resolution']


def test_distro_package_does_not_receive_upstream_curl_version_rule(tmp_path):
    data = opkg(tmp_path, version='8.3.0', variant='libcurl')

    assert native.assess(data) == []


def test_missing_component_cannot_pass_fixed_release(ctx):
    ctx.native_inventory = {'components': []}
    ctx.findings = []
    result = scenarios.check_release(ctx, scenarios.RELEASES['curl-8.4.0'])
    assert not result['passed']
    assert result['checks'][0]['observed'] == 'unknown'


def test_failed_releases_remain_in_comparison():
    report = scenarios.comparison_report(scenarios.SCENARIOS['curl-socks5'], [None, None], ['download failed', 'scan failed'])
    assert not report['passed']
    assert not report['rows'][0]['fix_demonstrated']
    assert report['rows'][0]['before']['detail'] == 'download failed'
    assert report['rows'][0]['after']['detail'] == 'scan failed'


def test_download_checks_cached_and_fetched_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(scenarios, 'CACHE_DIR', tmp_path)
    cached = tmp_path / 'scenarios/curl-8.3.0.tar.gz'
    cached.parent.mkdir(); cached.write_bytes(b'corrupt')
    monkeypatch.setattr(scenarios, 'urlopen', lambda *a, **k: io.BytesIO(b'wrong archive'))
    with pytest.raises(ValueError, match='SHA-256 mismatch'):
        scenarios.download('curl-8.3.0')
    assert cached.read_bytes() == b'corrupt'
    assert not list(cached.parent.glob('*.part'))


def test_pinned_archive_link_mode_records_without_creating_links(tmp_path):
    archive = tmp_path / 'firmware.tar'
    with tarfile.open(archive, 'w') as tf:
        member = tarfile.TarInfo('bin/tool'); member.type = tarfile.SYMTYPE
        member.linkname = '/outside/host'; tf.addfile(member)
    dest = tmp_path / 'extract'; dest.mkdir()
    with pytest.raises(UnsafeArtifact, match='link member refused'):
        _extract_tar(archive, dest)
    links = []
    _extract_tar(archive, dest, links)
    assert not (dest / 'bin/tool').exists()
    assert links == [{'path': 'bin/tool', 'target': '/outside/host'}]


def test_link_recording_still_rejects_traversal(tmp_path):
    archive = tmp_path / 'firmware.tar'
    with tarfile.open(archive, 'w') as tf:
        member = tarfile.TarInfo('../outside'); member.type = tarfile.SYMTYPE
        member.linkname = 'foo'; tf.addfile(member)
    with pytest.raises(UnsafeArtifact, match='path traversal'):
        _extract_tar(archive, tmp_path / 'extract', [])


def test_selector_available_before_downloads_and_validates_ids(monkeypatch):
    monkeypatch.setattr(server, 'CURRENT', None)
    client = TestClient(server.api)
    items = client.get('/api/artifacts').json()
    assert len([i for i in items if i['path'].startswith('scenario:')]) == 5
    assert len([i for i in items if i['path'].startswith('release:')]) == 10
    assert any(i['path'] == 'scenario:tomcat-partial-put' for i in items)
    assert client.post('/api/scan', json={'artifact': 'scenario:invalid'}).status_code == 400
    assert client.post('/api/scan', json={'artifact': ''}).status_code == 400
    calls = []
    monkeypatch.setattr(server.Job, 'start', lambda self, artifact: calls.append(artifact))
    assert client.post('/api/scan', json={'artifact': 'scenario:curl-socks5'}).status_code == 200
    assert calls == ['scenario:curl-socks5']
    assert client.post('/api/scan', json={'artifact': 'scenario:curl-socks5'}).status_code == 409


def test_both_sides_attempted_and_failure_report_is_sealed(tmp_path, monkeypatch):
    monkeypatch.setattr(context, 'KEY_PATH', tmp_path / 'key.pem')
    attempted = []
    def fail(release):
        attempted.append(release)
        raise RuntimeError('download failed')
    monkeypatch.setattr(scenarios, 'download', fail)
    events = list(scenarios.run_scenario('curl-socks5', out_base=tmp_path))
    assert attempted == ['curl-8.3.0', 'curl-8.4.0']
    assert events[-1].data['comparison_passed'] is False
    bundle = Path(events[-1].data['run_dir'])
    from pandax.evidence import verify_run
    assert all(c.ok for c in verify_run(bundle))
    assert not json.loads((bundle / 'comparison.json').read_text())['passed']


def test_fast_runs_do_not_overwrite_each_other(tmp_path):
    assert new_run_dir(tmp_path)[0] != new_run_dir(tmp_path)[0]


@pytest.mark.parametrize('version,found,passed,state', [
    ('9.0.98', True, True, 'affected'),
    ('9.0.98', False, False, 'not_detected'),
    ('9.0.99', False, True, 'fixed'),
    ('9.0.99', True, False, 'affected'),
])
def test_tomcat_real_patch_requires_inventory_and_differential_findings(ctx, version, found, passed, state):
    purl = f'pkg:maven/org.apache.tomcat/tomcat-catalina@{version}'
    ctx.components = [dict(name='catalina', version=version, purl=purl)]
    ctx.findings = [Finding(cve='CVE-2025-24813', osv_id='GHSA-83qj-6fr2-vhqg',
                           purl=purl, component='catalina', version=version, summary='Partial PUT')] if found else []
    result = scenarios.check_release(ctx, scenarios.RELEASES[f'tomcat-{version}'])
    assert result['passed'] is passed
    assert result['checks'][0]['observed'] == state
    assert result['checks'][0]['patch'].startswith('https://github.com/apache/tomcat/commit/')


@pytest.mark.parametrize('components', [
    [],
    [dict(name='tomcat-catalina', version='9.0.99', purl='pkg:maven/other/tomcat-catalina@9.0.99')],
    [dict(name='catalina', version='9.0.98', purl='pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.98')],
    [dict(name='catalina', version='9.0.98', purl='pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.99')],
    [dict(name='catalina', version=v, purl=f'pkg:maven/org.apache.tomcat/tomcat-catalina@{v}')
     for v in ('9.0.98', '9.0.99')],
])
def test_tomcat_missing_wrong_or_mixed_component_cannot_pass(ctx, components):
    ctx.components = components
    ctx.findings = []
    result = scenarios.check_release(ctx, scenarios.RELEASES['tomcat-9.0.99'])
    assert not result['passed']
    assert result['checks'][0]['observed'] == 'unknown'


def test_tomcat_other_vulnerabilities_do_not_fail_targeted_patch_check(ctx):
    ctx.components = [dict(name='catalina', version='9.0.99',
                           purl='pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.99?type=jar')]
    # Existing fixture findings concern other components and CVEs.
    assert scenarios.check_release(ctx, scenarios.RELEASES['tomcat-9.0.99'])['passed']
