"""Reviewed case clocks. Scan-time demo clocks never enter this state."""
import datetime as dt

from .cases import CaseError, _json, _utc_now
from .case_review import timestamp

STAGES = ('early_warning', 'notification', 'final_report')


def clocks(case, state):
    result = dict.fromkeys(STAGES)
    if state.get('aware_at'):
        awareness = dt.datetime.fromisoformat(state['aware_at'].replace('Z', '+00:00'))
        for stage, hours in (('early_warning', 24), ('notification', 72)):
            result[stage] = timestamp((awareness + dt.timedelta(hours=hours)).isoformat())
    if case.get('measure_available_at'):
        available = dt.datetime.fromisoformat(case['measure_available_at'].replace('Z', '+00:00'))
        result['final_report'] = timestamp((available + dt.timedelta(days=14)).isoformat())
    return result


def persist_clocks(service, db, case, state):
    deadlines = clocks(case, state)
    if state.get('deadlines') != deadlines:
        service.store._event(db, case['id'], 'clocks_updated', _utc_now(), 'PandaX', {'previous': state.get('deadlines'), 'deadlines': deadlines})
    state['deadlines'] = deadlines
    db.execute('UPDATE remediation_cases SET state_json=?, final_deadline=? WHERE id=?', (_json(state), deadlines['final_report'], case['id']))


def clock_status(deadlines, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    return {stage: 'pending' if not value else 'overdue' if dt.datetime.fromisoformat(value.replace('Z', '+00:00')) <= now else 'scheduled' for stage, value in deadlines.items()}


def prepare_report(service, db, case, body):
    from .case_service import required
    from .case_review import attestation, record
    identity = attestation(body)
    stage = required(body, 'stage')
    if stage not in STAGES:
        raise CaseError('unknown reporting stage')
    fields = body.get('fields', {})
    if not isinstance(fields, dict):
        raise CaseError('fields must be an object')
    payload = {
        'case_id': case['id'], 'case_type': case['case_type'], 'stage': stage,
        'case_facts': case['state'], 'source_run_id': case['source_run_id'],
        'product': case['source_product'], 'finding': case['finding'],
        'measure_available_at': case['measure_available_at'],
        'measure_details': case['measure_details'],
        'fields': fields, 'review_status': 'unreviewed',
        'submission_status': 'prepared - not submitted',
    }
    revision = service.revision(db, case['id'], payload)
    record(service, db, case, 'report_prepared', {**identity, 'stage': stage, 'revision': revision}, _utc_now(), identity['operator'])
