"""Evidence-based inventory and a deliberately bounded native advisory supplement.

OSV's PURL API does not cover generic C source packages or OpenWrt opkg packages.
These rules cover the requested public release cases, not all native CVEs. They
read artifact contents, never the selector's name or its expected test outcome.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

from .context import Finding

LIBUBOX_ADVISORY = 'https://openwrt.org/advisory/2020-01-31-2'
DNSMASQ_ADVISORY = 'https://openwrt.org/advisory/2021-01-19-1'
CURL_ADVISORY = 'https://curl.se/docs/CVE-2023-38545.html'
OPENSSL_ADVISORY = 'https://www.openssl.org/news/secadv/20140407.txt'
DNSSEC_CVES = {f'CVE-2020-{n}' for n in (25681, 25682, 25683, 25685, 25687)}
CURL_CONDITIONS = (
    'Requires SOCKS5 remote hostname resolution (socks5h://, --socks5-hostname, '
    'or CURLPROXY_SOCKS5_HOSTNAME), a long hostname and a slow handshake. '
    'The heap overflow requires a download buffer below 65541 bytes; curl CLI '
    'normally uses 100 KiB, but --limit-rate below 65541 can reduce it. '
    'Proxy environment variables also matter. Runtime configuration was not supplied; '
    'reachability is unknown, not confirmed exploitable.'
)
HEARTBLEED_CONDITIONS = (
    'Requires a TLS/DTLS heartbeat implementation enabled in the deployed build '
    'and reachable by a peer. OPENSSL_NO_HEARTBEATS can remove the feature. '
    'This is source inventory, not inspection of a deployed s_server process; '
    'build flags and runtime reachability remain unknown.'
)


def _read(path: Path) -> str:
    return path.read_text(encoding='utf-8', errors='replace')


def inventory(root: Path) -> dict:
    result = {'components': [], 'dependencies': [], 'evidence': [],
              'coverage': 'Native supplement: OpenWrt opkg inventory and curl/OpenSSL source headers. '
                          'Dependency metadata is not a runtime call graph.'}

    def component(name, version, path, kind='library', namespace='generic', **extra):
        purl = f'pkg:{namespace}/{quote(name, safe="")}@{quote(version, safe="")}'
        c = dict(name=name, version=version, purl=purl, type=kind, **extra)
        c['bom-ref'] = purl
        c['properties'] = [{'name': 'pandax:inventory-evidence', 'value': path.relative_to(root).as_posix()},
                           {'name': 'pandax:inventory-kind', 'value': 'package-database' if namespace.startswith('opkg') else 'source'}]
        result['components'].append(c)
        result['evidence'].append(path.relative_to(root).as_posix())
        return c

    # A distro marker is required: never interpret another distro's package
    # revision as an OpenWrt backport version.
    release = root / 'etc/openwrt_release'
    status = root / 'usr/lib/opkg/status'
    if release.is_file() and status.is_file() and "DISTRIB_ID='OpenWrt'" in _read(release):
        version = re.search(r"DISTRIB_RELEASE='([^']+)'", _read(release))
        result['openwrt_release'] = version[1] if version else 'unknown'
        result['evidence'].append('etc/openwrt_release')
        packages = {}
        for block in re.split(r'\n\s*\n', _read(status)):
            fields = dict(re.findall(r'^([A-Za-z-]+):[ \t]*(.*)$', block, re.M))
            if not fields.get('Name', fields.get('Package')) or not fields.get('Version'):
                continue
            if not fields.get('Status', '').endswith(' installed'):
                continue
            name = fields['Package']
            c = component(name, fields['Version'], status,
                          'library' if name.startswith('lib') else 'application', 'opkg/openwrt')
            packages[name] = (c, fields.get('Depends', ''))
        for c, depends in packages.values():
            names = [re.split(r'[ (]', dep.strip())[0] for dep in depends.split(',')]
            result['dependencies'].append({'ref': c['bom-ref'],
                'dependsOn': [packages[n][0]['bom-ref'] for n in names if n in packages]})
        config = root / 'etc/config/dhcp'
        if config.is_file():
            result['evidence'].append('etc/config/dhcp')
            result['dnsmasq_configuration'] = _read(config)

    for header in sorted(root.glob('**/include/curl/curlver.h')):
        src = header.parents[2]
        version = re.search(r'^#define LIBCURL_VERSION "([0-9.]+)"', _read(header), re.M)
        if not version or not (src / 'lib/socks.c').is_file():
            continue
        library = component('libcurl', version[1], header)
        program = src / 'src/tool_main.c'
        if program.is_file():
            app = component('curl', version[1], program, 'application')
            result['dependencies'].append({'ref': app['bom-ref'], 'dependsOn': [library['bom-ref']]})
        result['evidence'].append((src / 'lib/socks.c').relative_to(root).as_posix())

    for header in sorted(root.glob('**/crypto/opensslv.h')):
        src = header.parent.parent
        version = re.search(r'OPENSSL_VERSION_TEXT\s+"OpenSSL (\d+\.\d+\.\d+[a-z]?)\b', _read(header))
        if not version or not (src / 'ssl/t1_lib.c').is_file():
            continue
        library = component('libssl', version[1], header)
        program = src / 'apps/s_server.c'
        if program.is_file():
            app = component('openssl-s_server', version[1], program, 'application')
            result['dependencies'].append({'ref': app['bom-ref'], 'dependsOn': [library['bom-ref']]})
        result['evidence'].append((src / 'ssl/t1_lib.c').relative_to(root).as_posix())
    result['evidence'] = sorted(set(result['evidence']))
    return result


def assess(data: dict) -> list[dict]:
    """Return explicit affected/fixed/unknown/variant-excluded determinations.

    OpenWrt package revisions below come from the official rootfs package DBs.
    Unrecognised revisions remain unknown rather than guessing that they are fixed.
    """
    results = []
    for c in data.get('components', []):
        name, version = c['name'], c['version']
        rows = []
        if c['purl'].startswith('pkg:opkg/openwrt/'):
            if name == 'libblobmsg-json' or re.fullmatch(r'libubox\d*', name):
                state = {'2019-12-28-cd75136b-1': 'affected',
                         '2020-01-20-43a103ff-1': 'fixed',
                         '2020-05-25-66195aee-1': 'fixed'}.get(version, 'unknown')
                rows = [('CVE-2020-7248', state, '2020-01-20-43a103ff-1', LIBUBOX_ADVISORY,
                         'libubox JSON serialization stack buffer overflow. Installed dependency '
                         'metadata links consumers; attacker-controlled blob reachability requires review.')]
            elif name in {'dnsmasq', 'dnsmasq-full', 'dnsmasq-dhcpv6'}:
                state = {'2.80-15': 'affected', '2.80-16.1': 'affected',
                         '2.80-16.2': 'fixed'}.get(version, 'unknown')
                for n in range(25681, 25688):
                    cve = f'CVE-2020-{n}'
                    excluded = cve in DNSSEC_CVES and name != 'dnsmasq-full'
                    rows.append((cve, 'variant_excluded' if excluded else state,
                        '2.80-16.2', DNSMASQ_ADVISORY,
                        'Vendor excludes the standard/dhcpv6 package from this DNSSEC-related CVE.'
                        if excluded else 'dnsmasq DNS response validation or DNSSEC issue. '
                        'Check DNSSEC, cache size and forwarding settings in etc/config/dhcp. '
                        'The full OpenWrt package revision matters: 2.80-16.2 backports the fixes.'))
        elif name == 'libcurl':
            state = {'8.3.0': 'affected', '8.4.0': 'fixed'}.get(version, 'unknown')
            rows = [('CVE-2023-38545', state, '8.4.0', CURL_ADVISORY, CURL_CONDITIONS)]
        elif name == 'libssl':
            state = {'1.0.1f': 'affected', '1.0.1g': 'fixed'}.get(version, 'unknown')
            rows = [('CVE-2014-0160', state, '1.0.1g', OPENSSL_ADVISORY, HEARTBLEED_CONDITIONS)]
        for cve, state, fixed, source, detail in rows:
            results.append(dict(cve=cve, state=state, component=name, version=version,
                                purl=c['purl'], bom_ref=c['bom-ref'], fixed_version=fixed,
                                source=source, detail=detail))
    return results


def findings(assessments: list[dict]) -> list[Finding]:
    return [Finding(cve=a['cve'], osv_id='', purl=a['purl'], component=a['component'],
                    version=a['version'], summary=a['detail'], fixed_version=a['fixed_version'],
                    bom_ref=a['bom_ref'], source='Vendor advisory', source_url=a['source'],
                    applicability=a['detail']) for a in assessments if a['state'] == 'affected']


def enrich_sbom(sbom: dict, data: dict) -> None:
    # Prefer the opkg adapter for packages it identifies, retaining all other
    # Syft discoveries. This avoids duplicate native package rows.
    native = {(c['name'], c['version']) for c in data['components']}
    old = sbom.get('components', [])
    replacements = {c.get('bom-ref'): next(n['bom-ref'] for n in data['components']
                    if (n['name'], n['version']) == (c.get('name'), c.get('version')))
                    for c in old if (c.get('name'), c.get('version')) in native}
    sbom['components'] = [c for c in old if (c.get('name'), c.get('version')) not in native] + data['components']
    deps = {}
    for d in sbom.get('dependencies', []) + data['dependencies']:
        ref = replacements.get(d['ref'], d['ref'])
        deps.setdefault(ref, set()).update(replacements.get(r, r) for r in d.get('dependsOn', []))
    sbom['dependencies'] = [{'ref': ref, 'dependsOn': sorted(targets)} for ref, targets in deps.items()]
