"""Operator-recorded manual submissions and explicitly simulated rehearsals."""
import base64
import binascii
import hashlib
import json
import uuid

from .cases import CaseError, CaseConflict, CaseNotFound, _json, _utc_now
from .case_review import attestation, timestamp, record

MAX_RECEIPT_BYTES = 5 * 1024 * 1024


def submission(db, case_id, submission_id):
    row = db.execute('SELECT * FROM submissions WHERE id=? AND case_id=?', (submission_id, case_id)).fetchone()
    if not row:
        raise CaseNotFound('submission not found in this case')
    return {**dict(row), 'payload': json.loads(row['payload_json'])}


def apply_submission(service, db, action, body, case):
    from .case_service import required
    if action not in ('record-submission', 'attach-receipt', 'amend'):
        return False
    identity = attestation(body)
    if action == 'record-submission':
        from .case_export import pack
        report = case['report']
        if not report or body.get('revision') != report['revision'] or body.get('report_hash') != report['report_hash']:
            raise CaseConflict('submission requires latest exact revision and hash')
        if not pack(case)['ready']:
            raise CaseConflict('submission requires a complete approved current revision')
        simulated = body.get('simulated')
        if type(simulated) is not bool:
            raise CaseError('simulated must explicitly be true or false')
        if case['state'].get('simulated', False) and not simulated:
            raise CaseError('a simulated case cannot record a real submission')
        if report['payload'].get('amends_submission_id'):
            predecessor = submission(db, case['id'], report['payload']['amends_submission_id'])
            if predecessor['payload']['simulated'] != simulated:
                raise CaseError('amendment must keep its predecessor simulation mode')
        result = required(body, 'result')
        if result not in ('submitted', 'failed'):
            raise CaseError('result must be submitted or failed')
        submitted_at = timestamp(required(body, 'submitted_at'))
        approvals = [a for a in case['approvals'] if a['revision'] == report['revision'] and a['report_hash'] == report['report_hash']]
        if not any(a['approved_at'] <= submitted_at for a in approvals):
            raise CaseError('submission time predates report approval')
        reference = required(body, 'platform_reference') if result == 'submitted' else str(body.get('platform_reference', ''))
        reason = required(body, 'failure_reason') if result == 'failed' else ''
        submission_id = 'submission-' + uuid.uuid4().hex
        payload = {**identity, 'stage': report['payload']['stage'], 'result': result, 'submitted_at': submitted_at, 'recorded_at': _utc_now(), 'platform_reference': reference, 'failure_reason': reason, 'simulated': simulated, 'amends_submission_id': report['payload'].get('amends_submission_id')}
        db.execute('INSERT INTO submissions VALUES(?,?,?,?,?)', (submission_id, case['id'], report['revision'], report['report_hash'], _json(payload)))
        record(service, db, case, 'submission_recorded', {**payload, 'submission_id': submission_id, 'report_hash': report['report_hash']}, submitted_at, identity['operator'])
        if result == 'submitted' and simulated == case['state'].get('simulated', False) and case['case_type'] == 'incident' and payload['stage'] == 'notification':
            from .case_workflow import persist_clocks
            state = dict(case['state'])
            # Amendments/retries cannot postpone the original notification trigger.
            if not state.get('notification_submitted_at') or submitted_at < state['notification_submitted_at']:
                state['notification_submitted_at'] = submitted_at
                persist_clocks(service, db, case, state)
    else:
        prior = submission(db, case['id'], required(body, 'submission_id'))
        if prior['payload']['result'] != 'submitted':
            raise CaseError('failed attempts cannot be acknowledged or amended')
        if action == 'attach-receipt':
            encoded = required(body, 'content_base64')
            if len(encoded) > (MAX_RECEIPT_BYTES + 2) // 3 * 4:
                raise CaseError('receipt exceeds 5 MiB limit')
            try:
                content = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise CaseError('receipt must be valid base64') from exc
            if not content or len(content) > MAX_RECEIPT_BYTES:
                raise CaseError('receipt must contain 1 byte to 5 MiB')
            digest = hashlib.sha256(content).hexdigest()
            if body.get('sha256') and body['sha256'] != digest:
                raise CaseError('receipt digest mismatch')
            acknowledged_at = timestamp(required(body, 'acknowledged_at'))
            if acknowledged_at < prior['payload']['submitted_at']:
                raise CaseError('acknowledgement predates submission')
            receipt_id = 'receipt-' + uuid.uuid4().hex
            payload = {**identity, 'filename': required(body, 'filename'), 'acknowledged_at': acknowledged_at, 'recorded_at': _utc_now(), 'simulated': prior['payload']['simulated']}
            db.execute('INSERT INTO receipts VALUES(?,?,?,?,?)', (receipt_id, prior['id'], content, digest, _json(payload)))
            record(service, db, case, 'receipt_attached', {**payload, 'receipt_id': receipt_id, 'submission_id': prior['id'], 'sha256': digest}, acknowledged_at, identity['operator'])
        else:
            from .case_workflow import prepare_report
            required(body, 'reason')
            prepare_report(service, db, case, {**body, 'stage': prior['payload']['stage']}, amends_submission_id=prior['id'])
    return True
