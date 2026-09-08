import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pandax.case_service import CaseService
from pandax.cases import CaseStore, CaseError, CaseConflict


@pytest.fixture
def service(tmp_path, monkeypatch):
    from pandax import server
    run = tmp_path / 'run-source'
    run.mkdir()
    (run / 'findings.json').write_text(json.dumps([{'cve': 'CVE-1', 'component': 'lib', 'version': '1', 'purl': 'pkg:npm/lib@1'}]))
    (run / 'dossier.json').write_text(json.dumps({'product': {'name': 'Device', 'version': '1'}, 'generated': '2026-09-01T00:00:00Z'}))
    monkeypatch.setattr(server, 'OUT_DIR', tmp_path)
    monkeypatch.setenv('PANDAX_DATA_DIR', str(tmp_path / 'data'))
    return CaseService(runs_dir=tmp_path)


def create(service):
    return service.execute('create', {'request_id': 'create', 'source_run_id': 'run-source', 'cve': 'CVE-1'})


def measure(case, request_id='measure'):
    return {'request_id': request_id, 'expected_version': case['version'], 'measure_available_at': '2026-09-15T12:00:00Z', 'operator': 'Yaheli', 'authority_attestation': 'Authorised', 'measure_details': 'Release 2 available'}


def test_retry_restart_conflict_and_rollback(service, monkeypatch):
    case = create(service)
    before = (service.runs_dir / 'run-source' / 'findings.json').read_bytes()
    body = measure(case)
    result = service.execute('confirm-measure', body, case['id'])
    reopened = CaseService(runs_dir=service.runs_dir)
    assert reopened.execute('confirm-measure', body, case['id']) == result
    assert reopened.get(case['id']) == result
    assert result['source_product'] == {'name': 'Device', 'version': '1'}
    with pytest.raises(CaseConflict):
        reopened.execute('confirm-measure', {**body, 'measure_details': 'different'}, case['id'])
    with pytest.raises(CaseConflict, match='stale'):
        reopened.execute('confirm-measure', {**body, 'request_id': 'stale'}, case['id'])
    def fail(*args):
        raise RuntimeError('injected event failure')
    monkeypatch.setattr(reopened.store, '_event', fail)
    with pytest.raises(RuntimeError):
        reopened.execute('confirm-measure', measure(result, 'rollback'), case['id'])
    assert reopened.get(case['id']) == result
    assert (service.runs_dir / 'run-source' / 'findings.json').read_bytes() == before
    with reopened.store._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM requests WHERE request_id='rollback'").fetchone()[0] == 0
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO case_runs VALUES ('absent','run-x','absent','source')")


def test_concurrent_writers(service):
    case = create(service)
    def update(i):
        try:
            return service.execute('confirm-measure', measure(case, str(i)), case['id'])
        except CaseConflict:
            return None
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(update, range(2)))
    assert sum(r is not None for r in results) == 1
    assert len(service.get(case['id'])['events']) == 2


def test_explicit_import_and_api_contract(service):
    from pandax.server import api
    run = service.runs_dir / 'run-source'
    (run / 'filings').mkdir()
    (run / 'filings' / 'old.json').write_text('{"approved":true,"awareness":"2000-01-01"}')
    client = TestClient(api)
    assert client.post('/api/cases', json={}).status_code == 422
    case = client.post('/api/cases/import-draft', json={'request_id': 'import', 'source_run_id': 'run-source', 'cve': 'CVE-1', 'draft_file': 'filings/old.json', 'operator': 'Yaheli'}).json()
    assert case['report']['payload']['review_status'] == 'unreviewed'
    assert case['state'] == {}
    assert client.post(f"/api/cases/{case['id']}/confirm-measure", json=measure({**case, 'version': 0})).status_code == 409
    assert client.get('/api/cases/absent').status_code == 404


def test_migration_preserves_legacy_and_rolls_back(tmp_path, monkeypatch):
    from pandax import case_storage
    original = case_storage.MIGRATIONS
    monkeypatch.setattr(case_storage, 'MIGRATIONS', ())
    store = CaseStore(tmp_path / 'legacy.sqlite3')
    with store._connect() as db:
        db.execute("INSERT INTO remediation_cases(id,source_run_id,cve,component,component_version,purl,finding_json,status,created_at,updated_at,final_deadline) VALUES ('old','run-old','CVE-1','lib','1','purl','{}','detected','t','t','deadline')")
        db.execute("INSERT INTO report_revisions(case_id,revision,created_at,report_hash,payload_json) VALUES('old',1,'t','preserve-hash','{}')")
    monkeypatch.setattr(case_storage, 'MIGRATIONS', (original[0] + ('INVALID SQL',),))
    with pytest.raises(sqlite3.OperationalError):
        CaseStore(store.path)
    with sqlite3.connect(store.path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 0
        assert 'version' not in [r[1] for r in db.execute('PRAGMA table_info(remediation_cases)')]
    monkeypatch.setattr(case_storage, 'MIGRATIONS', original)
    migrated = CaseStore(store.path).get('old')
    assert migrated['final_deadline'] == 'deadline'
    assert migrated['report']['report_hash'] == 'preserve-hash'
    assert CaseStore(store.path).get('old') == migrated
    with sqlite3.connect(store.path) as db:
        db.execute('PRAGMA user_version=999')
    with pytest.raises(ValueError, match='newer'):
        CaseStore(store.path)


def test_cli_reads_shared_store(service, tmp_path):
    from pandax.cli import app
    case = create(service)
    runner = CliRunner()
    result = runner.invoke(app, ['case', 'show', case['id']])
    assert result.exit_code == 0
    assert json.loads(result.stdout)['version'] == 1
    file = tmp_path / 'command.json'
    file.write_text(json.dumps(measure(case)))
    result = runner.invoke(app, ['case', 'apply', 'confirm-measure', '--case-id', case['id'], '--input', str(file)])
    assert result.exit_code == 0, result.stdout
    assert service.get(case['id'])['version'] == 2
