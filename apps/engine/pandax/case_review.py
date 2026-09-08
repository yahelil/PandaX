"""Factual timestamps and local human authorization, separate from signing."""
import datetime as dt
import json

from .cases import CaseError, CaseConflict, _json, _utc_now


def timestamp(value):
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError('timezone missing')
        return parsed.astimezone(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    except (AttributeError, TypeError, ValueError) as exc:
        raise CaseError('timestamp requires an explicit timezone (Z or offset)') from exc


def attestation(body):
    from .case_service import required
    return {key: required(body, key) for key in ('operator', 'authority_attestation')}


def record(service, db, case, event_type, payload, occurred_at, actor, table=None):
    service.store._event(db, case['id'], event_type, occurred_at, actor, payload)
    event_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    if table:
        assert table in ('decisions', 'awareness_evidence')
        db.execute(f'INSERT INTO {table}(case_id,event_id,payload_json) VALUES(?,?,?)', (case['id'], event_id, _json(payload)))


def save_state(service, db, case, state):
    db.execute('UPDATE remediation_cases SET state_json=? WHERE id=?', (_json(state), case['id']))
    # A changed factual record cannot retain approval of an earlier snapshot.
    if case['report']:
        payload = dict(case['report']['payload'])
        payload['case_facts'] = state
        payload['review_status'] = 'unreviewed'
        service.revision(db, case['id'], payload)


def apply_review(service, db, action, body, case):
    from .case_service import required
    if action not in ('record-awareness', 'record-decision', 'revise', 'approve'):
        return False
    identity = attestation(body)
    state = dict(case['state'])
    if action == 'record-awareness':
        changes = {key: timestamp(body[key]) for key in ('occurred_at', 'detected_at', 'aware_at') if key in body}
        if not changes:
            raise CaseError('at least one factual timestamp is required')
        evidence = required(body, 'evidence')
        correction = any(key in state and state[key] != value for key, value in changes.items())
        reason = required(body, 'reason') if correction else str(body.get('reason', ''))
        payload = {**identity, 'previous': {key: state.get(key) for key in changes}, 'changes': changes, 'evidence': evidence, 'reason': reason}
        state.update(changes)
        state['awareness_evidence'] = evidence
        record(service, db, case, 'awareness_corrected' if correction else 'awareness_recorded', payload, changes.get('aware_at', next(iter(changes.values()))), identity['operator'], 'awareness_evidence')
        save_state(service, db, case, state)
    elif action == 'record-decision':
        decision = required(body, 'reportability')
        if decision not in ('reportable', 'not_reportable', 'under_review'):
            raise CaseError('reportability must be reportable, not_reportable or under_review')
        payload = {**identity, 'reportability': decision, 'reason': required(body, 'reason'), 'evidence': required(body, 'evidence')}
        state['reportability'] = decision
        state['reportability_decision'] = payload
        record(service, db, case, 'reportability_decided', payload, _utc_now(), identity['operator'], 'decisions')
        save_state(service, db, case, state)
    elif action == 'revise':
        payload = body.get('payload')
        if not isinstance(payload, dict):
            raise CaseError('report payload must be an object')
        payload = {**payload, 'case_id': case['id'], 'case_facts': state, 'review_status': 'unreviewed'}
        revision = service.revision(db, case['id'], payload)
        record(service, db, case, 'report_revised', {**identity, 'revision': revision, 'reason': required(body, 'reason')}, _utc_now(), identity['operator'])
    elif action == 'approve':
        report = case['report']
        if not report or body.get('revision') != report['revision'] or body.get('report_hash') != report['report_hash']:
            raise CaseConflict('approval requires the latest exact revision and report hash')
        approved_at = timestamp(required(body, 'approved_at'))
        db.execute('INSERT INTO approvals(case_id,revision,report_hash,operator,authority_attestation,approved_at,recorded_at) VALUES(?,?,?,?,?,?,?)', (case['id'], report['revision'], report['report_hash'], identity['operator'], identity['authority_attestation'], approved_at, _utc_now()))
        record(service, db, case, 'report_approved', {**identity, 'revision': report['revision'], 'report_hash': report['report_hash']}, approved_at, identity['operator'])
    return True
