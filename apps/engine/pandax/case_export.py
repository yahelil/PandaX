"""Readable manual-entry pack; internal JSON is never an SRP wire schema."""
import html
import json

from .cases import CaseError, CaseNotFound
from .case_fields import missing_fields, definitions

CHECKLIST = [
    'Confirm product identity, factual awareness, affected releases and reportability.',
    'Review every required or conditional field and unavailable-information attestation.',
    'Confirm manufacturer authority and approval of this exact hash.',
    'Sign in to the SRP manually; confirm manufacturer and coordinating CSIRT.',
    'Copy reviewed fields, follow current portal guidance and verify carried values.',
    'Submit manually; record actual time, platform reference and receipt in PandaX.',
    'Prepared packs are not submissions. Simulated records are rehearsal evidence only.',
]


def pack(case, revision=None):
    report = next((r for r in case['revisions'] if r['revision'] == revision), None) if revision is not None else case['report']
    if not report:
        raise CaseNotFound('report revision not found')
    missing = missing_fields(report['payload'])
    approved = any(a['revision'] == report['revision'] and a['report_hash'] == report['report_hash'] for a in case['approvals'])
    current = report['revision'] == case['report']['revision']
    ready = approved and current and not missing
    return {'format': 'PandaX internal manual submission pack', 'case_id': case['id'], 'revision': report['revision'], 'report_hash': report['report_hash'], 'ready': ready, 'status': 'Ready for manual submission — not submitted' if ready else 'INCOMPLETE / REVIEW REQUIRED — not ready', 'missing': missing, 'approved': approved, 'current_revision': current, 'report': report['payload'], 'checklist': CHECKLIST}


def render(case, revision=None, format='json'):
    data = pack(case, revision)
    if format == 'json':
        return json.dumps(data, ensure_ascii=False, indent=2)
    if format == 'checklist':
        return data['status'] + '\n\n' + '\n'.join(f'[ ] {item}' for item in CHECKLIST)
    if format != 'html':
        raise CaseError('format must be json, html or checklist')
    escape = lambda value: html.escape(str(value))
    payload = data['report']
    rows = []
    if payload.get('field_definition'):
        for field in definitions(payload['case_type'], payload['stage'])['fields']:
            entry = payload['fields'].get(field['key'], {})
            value = entry.get('value') or ('Operator attests unavailable' if entry.get('available') is False else 'INPUT REQUIRED')
            rows.append('<tr>' + ''.join(f'<td>{escape(v)}</td>' for v in (field['source_id'], field['label'], field['requirement'], value, entry.get('provenance', 'missing'))) + '</tr>')
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>PandaX manual submission pack</title><style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:1rem}td,th{border:1px solid #bbb;padding:.6rem;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%}code{overflow-wrap:anywhere}</style><h1>' + escape(data['status']) + '</h1><p>Internal pack — no automatic submission. Revision ' + str(data['revision']) + '</p><p>SHA-256: <code>' + data['report_hash'] + '</code></p><p>' + escape(', '.join(data['missing'])) + '</p><table><tr><th>Source ID</th><th>Field</th><th>Requirement</th><th>Value</th><th>Provenance</th></tr>' + ''.join(rows) + '</table><h2>Manual checklist</h2><ul>' + ''.join('<li>' + escape(s) + '</li>' for s in CHECKLIST) + '</ul><p>Definition: ' + escape(json.dumps(payload.get('field_definition', {}))) + '</p></html>'
