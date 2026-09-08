import base64
import hashlib
import io
import json
import sqlite3
import zipfile

import pytest
from fastapi.testclient import TestClient

from pandax.case_service import CaseService
from pandax.case_snapshot import snapshot_bytes
from pandax.cases import CaseConflict, CaseError
from pandax.evidence import verify_run
from test_case_service import service
from test_case_review import command, IDENTITY
from test_case_fields import ready_case


def attempt(service, case, result='submitted', simulated=False, submitted_at='2026-09-15T02:00:00Z'):
    return command(service, case, 'record-submission', revision=case['report']['revision'], report_hash=case['report']['report_hash'], result=result, simulated=simulated, submitted_at=submitted_at, platform_reference='SIM-123' if simulated else 'MANUAL-123', failure_reason='Portal unavailable' if result == 'failed' else '')


def receipt(service, case, submission_id):
    return command(service, case, 'attach-receipt', submission_id=submission_id, filename='receipt.txt', content_base64=base64.b64encode(b'operator-provided receipt').decode(), acknowledged_at='2026-09-15T03:00:00Z')


@pytest.mark.parametrize('kind', ['vulnerability', 'incident'])
def test_failure_retry_receipt_amendment_restart_snapshot(service, kind, tmp_path):
    case = ready_case(service, kind, 'notification')
    source = (service.runs_dir / 'run-source' / 'findings.json').read_bytes()
    case = attempt(service, case, result='failed')
    assert case['readiness']['ready']
    assert case['submissions'][0]['status'] == 'failed'
    if kind == 'incident':
        assert case['deadlines']['final_report'] is None
    with pytest.raises(CaseError, match='failed attempts'):
        receipt(service, case, case['submissions'][0]['id'])
    case = attempt(service, case)
    prior = case['submissions'][-1]
    old_hash = prior['report_hash']
    assert not case['readiness']['ready']
    assert case['readiness']['status'] == 'Operator-recorded submitted'
    if kind == 'incident':
        assert case['deadlines']['final_report'] == '2026-10-15T02:00:00Z'
    with pytest.raises(CaseConflict):
        attempt(service, case)
    case = receipt(service, case, prior['id'])
    assert case['submissions'][-1]['status'] == 'acknowledged'
    case = command(service, case, 'amend', submission_id=prior['id'], reason='New findings', fields={'summary': 'Updated details'})
    assert case['report']['payload']['amends_submission_id'] == prior['id']
    assert not case['approved']
    case = command(service, case, 'prepare-report', stage=case['report']['payload']['stage'], fields={'summary': 'Reviewed amendment details'})
    assert case['report']['payload']['amends_submission_id'] == prior['id']
    with pytest.raises(CaseConflict):
        attempt(service, case)
    case = command(service, case, 'approve', revision=case['report']['revision'], report_hash=case['report']['report_hash'], approved_at='2026-09-15T04:00:00Z')
    case = attempt(service, case, submitted_at='2026-09-16T02:00:00Z')
    assert case['submissions'][-1]['payload']['amends_submission_id'] == prior['id']
    assert case['submissions'][1]['report_hash'] == old_hash
    if kind == 'incident':
        assert case['deadlines']['final_report'] == '2026-10-15T02:00:00Z'
    body = {'request_id': 'snapshot', 'expected_version': case['version'], **IDENTITY, 'revision': case['report']['revision']}
    case = service.execute('snapshot', body, case['id'])
    saved = case['snapshots'][-1]
    blob = snapshot_bytes(service, case['id'], saved['id'])
    assert hashlib.sha256(blob).hexdigest() == saved['sha256']
    extracted = tmp_path / 'snapshot-check'
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        archive.extractall(extracted)
        assert b'not been established externally' in archive.read('trust.txt')
    assert all(check.ok for check in verify_run(extracted))
    assert service.execute('snapshot', body, case['id']) == case
    assert CaseService(runs_dir=service.runs_dir).get(case['id']) == case
    assert (service.runs_dir / 'run-source' / 'findings.json').read_bytes() == source
    from pandax.server import api
    assert TestClient(api).get(f"/api/cases/{case['id']}/snapshots/{saved['id']}").content == blob
    with service.store._connect() as db:
        for table in ('submissions', 'receipts', 'case_snapshots', 'requests'):
            with pytest.raises(sqlite3.IntegrityError, match='immutable'):
                db.execute(f'DELETE FROM {table}')


def test_simulation_never_satisfies_real_clock(service):
    case = ready_case(service, 'incident', 'notification')
    case = attempt(service, case, simulated=True)
    assert case['deadlines']['final_report'] is None
    assert case['readiness']['ready']
    case = receipt(service, case, case['submissions'][-1]['id'])
    assert case['submissions'][-1]['receipts'][0]['payload']['simulated']
    assert case['events'][-1]['payload']['simulated']


def test_simulated_case_clock_is_labeled(service):
    case = ready_case(service, 'incident', 'notification', simulated=True)
    with pytest.raises(CaseError, match='simulated case'):
        attempt(service, case, simulated=False)
    case = attempt(service, case, simulated=True)
    assert case['deadlines']['final_report'] == '2026-10-15T02:00:00Z'
    assert case['readiness']['status'].startswith('SIMULATED')
    assert all(event['payload'].get('simulated') for event in case['events'])


def test_receipt_transaction_rollback_and_digest_validation(service, monkeypatch):
    case = attempt(service, ready_case(service))
    before = service.get(case['id'])
    with pytest.raises(CaseError, match='digest'):
        command(service, case, 'attach-receipt', submission_id=case['submissions'][-1]['id'], filename='r', content_base64='YQ==', sha256='wrong', acknowledged_at='2026-09-15T03:00:00Z')
    def fail(*args):
        raise RuntimeError('injected failure')
    monkeypatch.setattr(service.store, '_event', fail)
    with pytest.raises(RuntimeError):
        receipt(service, case, case['submissions'][-1]['id'])
    assert service.get(case['id']) == before


def test_revision_and_snapshot_rollback(service, monkeypatch):
    case = ready_case(service)
    before = service.get(case['id'])
    revision = service.revision
    def fail_revision(*args):
        revision(*args)
        raise RuntimeError('after revision insert')
    monkeypatch.setattr(service, 'revision', fail_revision)
    with pytest.raises(RuntimeError):
        command(service, case, 'prepare-report', stage='notification')
    assert service.get(case['id']) == before
    monkeypatch.setattr(service, 'revision', revision)
    def fail_event(*args):
        raise RuntimeError('after snapshot insert')
    monkeypatch.setattr(service.store, '_event', fail_event)
    with pytest.raises(RuntimeError):
        command(service, case, 'snapshot', revision=case['report']['revision'])
    assert service.get(case['id']) == before


def test_submission_and_receipt_replay_after_later_events(service):
    case = ready_case(service)
    body = {'request_id': 'attempt', 'expected_version': case['version'], **IDENTITY, 'revision': case['report']['revision'], 'report_hash': case['report']['report_hash'], 'result': 'submitted', 'simulated': False, 'submitted_at': '2026-09-15T02:00:00Z', 'platform_reference': 'MANUAL-123'}
    submitted = service.execute('record-submission', body, case['id'])
    acknowledged = receipt(service, submitted, submitted['submissions'][-1]['id'])
    assert service.execute('record-submission', body, case['id']) == submitted
    assert service.get(case['id']) == acknowledged
    assert len(acknowledged['submissions']) == 1


def test_measure_correction_preserves_structured_report(service):
    from test_case_service import measure
    case = ready_case(service, stage='final_report')
    original = case['report']
    case = service.execute('confirm-measure', {**measure(case, 'correction'), 'measure_available_at': '2026-09-14T12:00:00Z', 'reason': 'Corrected availability evidence'}, case['id'])
    assert case['report']['payload']['stage'] == 'final_report'
    assert case['report']['payload']['fields']['measure_available_at']['value'] == '2026-09-14T12:00:00Z'
    assert not case['approved']
    assert next(r for r in case['revisions'] if r['revision'] == original['revision']) == original


@pytest.mark.parametrize('transport', ['api', 'cli'])
@pytest.mark.parametrize('kind', ['vulnerability', 'incident'])
def test_complete_lifecycle_through_public_adapters(service, tmp_path, monkeypatch, transport, kind):
    from pandax import case_service
    from pandax.server import api
    from pandax.cli import app
    from typer.testing import CliRunner
    monkeypatch.setattr(case_service, 'OUT_DIR', service.runs_dir)
    client = TestClient(api)
    runner = CliRunner()
    class Adapter:
        def execute(self, action, body, case_id=None):
            if transport == 'api':
                route = f'/api/cases/{case_id}/{action}' if case_id else '/api/cases' + ('' if action == 'create' else '/' + action)
                response = client.post(route, json=body)
                assert response.status_code == 200, response.text
                return response.json()
            file = tmp_path / 'adapter-command.json'
            file.write_text(json.dumps(body), encoding='utf-8')
            args = ['case', 'apply', action, '--input', str(file)]
            if case_id:
                args += ['--case-id', case_id]
            response = runner.invoke(app, args)
            assert response.exit_code == 0, response.output
            return json.loads(response.stdout)
    adapter = Adapter()
    case = ready_case(adapter, kind, 'notification')
    case = attempt(adapter, case)
    case = receipt(adapter, case, case['submissions'][-1]['id'])
    case = command(adapter, case, 'amend', submission_id=case['submissions'][-1]['id'], reason='New information', fields={'summary': 'Additional investigation results'})
    case = command(adapter, case, 'approve', revision=case['report']['revision'], report_hash=case['report']['report_hash'], approved_at='2026-09-15T04:00:00Z')
    case = attempt(adapter, case, submitted_at='2026-09-15T05:00:00Z')
    case = command(adapter, case, 'snapshot', revision=case['report']['revision'])
    assert service.get(case['id']) == case
    assert len(case['snapshots']) == 1
