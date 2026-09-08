import sqlite3

import pytest

from pandax.cases import CaseError, CaseConflict
from test_case_service import service, create

IDENTITY = {'operator': 'Yaheli', 'authority_attestation': 'Manufacturer authority'}


def command(service, case, action, **fields):
    return service.execute(action, {'request_id': f'{action}-{case["version"]}', 'expected_version': case['version'], **IDENTITY, **fields}, case['id'])


def test_awareness_approval_and_correction_history(service):
    case = create(service)
    case = command(service, case, 'record-awareness', aware_at='2026-09-08T12:00:00+03:00', detected_at='2026-09-07T00:00:00Z', evidence='Operator email')
    assert case['state']['aware_at'] == '2026-09-08T09:00:00Z'
    case = command(service, case, 'revise', payload={'summary': 'Draft'}, reason='Initial draft')
    original = case['report']
    with pytest.raises(CaseConflict):
        command(service, case, 'approve', revision=original['revision'], report_hash='wrong', approved_at='2026-09-08T10:00:00Z')
    case = command(service, case, 'approve', revision=original['revision'], report_hash=original['report_hash'], approved_at='2026-09-08T10:00:00Z')
    assert case['approved']
    with pytest.raises(CaseError, match='reason'):
        command(service, case, 'record-awareness', aware_at='2026-09-06T00:00:00Z', evidence='Earlier email')
    case = command(service, case, 'record-awareness', aware_at='2026-09-06T00:00:00Z', evidence='Earlier email', reason='Corrected after review')
    assert not case['approved']
    assert case['revisions'][0] == original
    assert len(case['approvals']) == 1
    correction = next(e for e in case['events'] if e['event_type'] == 'awareness_corrected')
    assert correction['payload']['previous']['aware_at'] == '2026-09-08T09:00:00Z'
    with service.store._connect() as db:
        for table in ('report_revisions', 'case_events', 'approvals'):
            with pytest.raises(sqlite3.IntegrityError, match='immutable'):
                db.execute(f'DELETE FROM {table}')


@pytest.mark.parametrize('time', ['2026-09-08T12:00:00', 'bad', None])
def test_timezone_and_attestation_required(service, time):
    case = create(service)
    with pytest.raises(CaseError, match='timezone'):
        command(service, case, 'record-awareness', aware_at=time, evidence='Email')
    with pytest.raises(CaseError, match='authority_attestation'):
        command(service, case, 'record-decision', authority_attestation='', reportability='reportable', evidence='e', reason='r')
