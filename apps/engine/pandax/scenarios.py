"""Downloadable public release pairs and evidence-based differential checks."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

from . import events as ev
from .context import CACHE_DIR
from .evidence import sha256_file, verify_run

CATALOG_PATH = Path(__file__).parent / 'data/scenarios.json'
CATALOG = json.loads(CATALOG_PATH.read_text(encoding='utf-8'))
RELEASES = {r['id']: r for r in CATALOG['releases']}
SCENARIOS = {s['id']: s for s in CATALOG['scenarios']}
MAX_DOWNLOAD = 128 * 1024 * 1024


def identify(path: Path) -> dict | None:
    if not path.is_file():
        return None
    digest = sha256_file(path)
    return next((r for r in RELEASES.values() if r['sha256'] == digest), None)


def download(release_id: str) -> Path:
    release = RELEASES[release_id]
    cache = CACHE_DIR / 'scenarios'
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / (release_id + '.tar.gz')
    if target.exists() and sha256_file(target) == release['sha256']:
        return target
    # Atomic publication: neither a partial download nor concurrent requests
    # can expose unverified bytes as a ready fixture.
    fd, temp_name = tempfile.mkstemp(dir=cache, suffix='.part')
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, 'wb') as out, urlopen(
            Request(release['url'], headers={'User-Agent': 'pandax-scenarios/1'}), timeout=90
        ) as response:
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise ValueError('release download exceeds 128 MiB')
                out.write(chunk)
        if sha256_file(temp) != release['sha256']:
            raise ValueError(f"SHA-256 mismatch for {release_id}; refusing artifact")
        temp.replace(target)
    finally:
        temp.unlink(missing_ok=True)
    return target


def check_release(ctx, release: dict) -> dict:
    """Expectations are a test oracle, kept out of inventory and CVE matching."""
    from .native import assess
    assessments = assess(ctx.native_inventory)
    found = {(f.component, f.cve) for f in ctx.findings}
    checks = []
    for scenario in SCENARIOS.values():
        if release['id'] not in (scenario['before'], scenario['after']):
            continue
        before = release['id'] == scenario['before']
        for cve in scenario['cves']:
            if scenario.get('package'):
                checks.append(_check_package(ctx, release, scenario, cve, before))
                continue
            rows = [a for a in assessments if a['component'] == scenario['component'] and a['cve'] == cve]
            state = rows[0]['state'] if len(rows) == 1 else 'unknown'
            expected = 'affected' if before else 'fixed'
            if scenario['id'] == 'openwrt-dnsmasq':
                from .native import DNSSEC_CVES
                if cve in DNSSEC_CVES:
                    expected = 'variant_excluded'
            present = (scenario['component'], cve) in found
            checks.append(dict(scenario=scenario['id'], cve=cve, expected=expected,
                observed=state, component=scenario['component'],
                component_version=rows[0]['version'] if len(rows) == 1 else '',
                finding_present=present, passed=state == expected and present == (expected == 'affected'),
                source=rows[0]['source'] if len(rows) == 1 else '',
                detail=rows[0]['detail'] if len(rows) == 1 else 'Required component was not identified unambiguously.'))
    return {'release': release, 'checks': checks, 'passed': bool(checks) and all(c['passed'] for c in checks),
            'scope': 'Vendor advisory and component evidence. Not a runtime exploit test or a claim that the release has no other CVEs.'}


def _check_package(ctx, release: dict, scenario: dict, cve: str, before: bool) -> dict:
    """Compare OSV findings with vendor expectations, without changing matching."""
    def identity(purl):
        return purl.split('#', 1)[0].split('?', 1)[0].rpartition('@')

    components = [c for c in ctx.components if identity(c.get('purl', ''))[0] == scenario['package']]
    versions = {identity(c['purl'])[2] for c in components}
    identified = versions == {release['version']} and all(
        c['version'] == release['version'] for c in components)
    present = any(f.cve == cve and identity(f.purl)[0] == scenario['package'] for f in ctx.findings)
    expected = 'affected' if before else 'fixed'
    state = ('affected' if present else 'not_detected' if before else 'fixed') if identified else 'unknown'
    detail = scenario['note'] + ' '
    detail += ('Component revision verified in the SBOM; checked-source finding ' +
               ('present.' if present else 'absent.')) if identified else 'Required component revision is missing or ambiguous.'
    return dict(scenario=scenario['id'], cve=cve, expected=expected, observed=state,
                component=scenario['component'], component_version=', '.join(sorted(versions)),
                finding_present=present, passed=state == expected,
                source=scenario['source'], patch=scenario['patch'], detail=detail)


def comparison_report(scenario: dict, bundles: list[Path | None], errors: list[str] | None = None) -> dict:
    if len(bundles) != 2:
        raise ValueError('Exactly two release outcomes are required')
    reports = []
    errors = errors or ['', '']
    for i, bundle in enumerate(bundles):
        try:
            if bundle is None:
                raise ValueError(errors[i] or 'No completed bundle')
            checks = verify_run(bundle)
            if not checks or not all(c.ok for c in checks):
                raise ValueError(f'Cannot compare unverified bundle: {bundle.name}')
            report = json.loads((bundle / 'release-checks.json').read_text())
            if report['release']['id'] != scenario[('before', 'after')[i]]:
                raise ValueError('Comparison release identity mismatch')
            reports.append(report)
        except Exception as exc:
            errors[i] = str(exc)
            reports.append(None)
    rows = []
    for cve in scenario['cves']:
        sides = [next((c for c in r['checks'] if c['scenario'] == scenario['id'] and c['cve'] == cve),
                      {'passed': False, 'observed': 'unknown', 'detail': 'Missing check'})
                 if r else {'passed': False, 'observed': 'error', 'detail': errors[i], 'component_version': ''}
                 for i, r in enumerate(reports)]
        passed = all(c['passed'] for c in sides)
        fixed = passed and [c['observed'] for c in sides] == ['affected', 'fixed']
        rows.append({'cve': cve, 'before': sides[0], 'after': sides[1], 'passed': passed,
                     'fix_demonstrated': fixed,
                     'result': 'fix evidenced' if fixed else 'excluded package variant in both releases' if passed else 'check failed'})
    return {'scenario': scenario, 'passed': all(r['passed'] for r in rows), 'rows': rows,
            'runs': [{'run_id': p.name if p else '',
                      'manifest_sha256': sha256_file(p / 'manifest.json') if p and (p / 'manifest.json').exists() else '',
                      'error': errors[i], 'release_id': scenario[('before', 'after')[i]]}
                     for i, p in enumerate(bundles)],
            'scope': 'Available input bundles must verify before their checks can pass. Absence without component evidence never counts as a fix.'}


def run_scenario(scenario_id: str, out_base: Path | None = None) -> ev.Stream:
    from . import pipeline
    scenario = SCENARIOS[scenario_id]
    bundles = []
    errors = []
    for side in ('before', 'after'):
        release_id = scenario[side]
        completed = None
        error = ''
        yield ev.log('RUN', f"{scenario['name']}: downloading / verifying {release_id}")
        try:
            artifact = download(release_id)
            for event in pipeline.run(artifact, out_base=out_base):
                if event.kind == ev.RUN_DONE:
                    completed = Path(event.data['run_dir'])
                    yield ev.log('RUN', f"{release_id}: sealed {event.data['run_id']}")
                else:
                    yield event
        except Exception as exc:
            error = f'{type(exc).__name__}: {exc}'
            yield ev.log('RUN', f'{release_id} FAILED: {error}', ev.ALERT_LVL)
        bundles.append(completed)
        errors.append(error)
    report = comparison_report(scenario, bundles, errors)
    # Seal a small comparison bundle too: it records the input manifests and
    # their digests; source runs remain independently verifiable.
    from .context import KEY_PATH, new_run_dir
    from .evidence import Ledger, load_or_create_key, write_manifest
    dest, run_id = new_run_dir(out_base)
    path = dest / 'comparison.json'
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    ledger = Ledger(dest)
    for side, bundle in zip(('before', 'after'), bundles):
        if bundle and (bundle / 'manifest.json').exists():
            (dest / f'{side}.manifest.json').write_bytes((bundle / 'manifest.json').read_bytes())
    ledger.append(stage='COMPARISON', tool='pandax.scenarios', tool_version='1',
                  inputs=[ledger.ref(dest / f'{side}.manifest.json') for side in ('before', 'after')
                          if (dest / f'{side}.manifest.json').exists()],
                  outputs=[ledger.ref(path)], params={'scenario': scenario_id})
    write_manifest(run_dir=dest, run_id=run_id, product={'name': scenario['name'] + ' comparison'},
                   tool_versions={'pandax.scenarios': '1'}, ledger=ledger, key=load_or_create_key(KEY_PATH))
    yield ev.run_done('Comparison checks passed' if report['passed'] else 'Comparison checks failed',
                     ev.GOOD if report['passed'] else ev.ALERT_LVL,
                     run_id=run_id, run_dir=str(dest), comparison=report, comparison_passed=report['passed'])
