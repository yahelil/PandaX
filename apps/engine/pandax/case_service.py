"""Local case commands shared by HTTP and CLI; scan evidence is read-only."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from .cases import CaseStore, CaseError, CaseConflict, CaseNotFound, _json, _utc_now
from .context import OUT_DIR
from .stages.clock import parse_timestamp


def required(body, key):
    value = body.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CaseError(f"{key} is required")
    return value.strip()


class CaseService:
    def __init__(self, data_dir=None, runs_dir=None):
        self.runs_dir = Path(runs_dir or OUT_DIR)
        self.store = CaseStore(Path(data_dir or os.environ.get('PANDAX_DATA_DIR', self.runs_dir / '.pandax')) / 'cases.sqlite3')

    def run_json(self, run_id, name, default):
        if not isinstance(run_id, str) or not re.fullmatch(r'run-[\w.-]+', run_id):
            raise CaseError('invalid run ID')
        path = (self.runs_dir / run_id).resolve()
        if not path.is_relative_to(self.runs_dir.resolve()) or not path.is_dir():
            raise CaseNotFound(f'run not found: {run_id}')
        file = path / name
        if not file.resolve().is_relative_to(path):
            raise CaseError('evidence path escapes run')
        try:
            return json.loads(file.read_text(encoding='utf-8')) if file.exists() else default
        except (ValueError, OSError) as exc:
            raise CaseError(f'unreadable evidence: {name}') from exc

    def product(self, run_id):
        dossier = self.run_json(run_id, 'dossier.json', {})
        manifest = self.run_json(run_id, 'manifest.json', {})
        product = dossier.get('product') or manifest.get('product') or {}
        return {'name': str(product.get('name', '')), 'version': str(product.get('version', ''))}, dossier.get('generated') or manifest.get('created')

    def link_run(self, db, case_id, run_id, role):
        product, _ = self.product(run_id)
        # Unknown products are isolated by run, never silently merged.
        product_id = hashlib.sha256((product['name'].casefold() or run_id).encode()).hexdigest()
        release_id = hashlib.sha256(_json([product_id, product['version'] or run_id]).encode()).hexdigest()
        db.execute('INSERT OR IGNORE INTO products VALUES (?, ?)', (product_id, product['name']))
        db.execute('INSERT OR IGNORE INTO releases VALUES (?, ?, ?)', (release_id, product_id, product['version']))
        db.execute('INSERT OR IGNORE INTO case_runs VALUES (?, ?, ?, ?)', (case_id, run_id, release_id, role))
        if role == 'source':
            db.execute('UPDATE remediation_cases SET release_id=? WHERE id=?', (release_id, case_id))

    def get(self, case_id, db=None):
        if db is None:
            with self.store._connect() as connection:
                connection.execute('BEGIN')
                return self.get(case_id, connection)
        case = self.store.get(case_id, db)
        row = db.execute('SELECT p.name, r.version FROM case_runs cr JOIN releases r ON cr.release_id=r.id JOIN products p ON r.product_id=p.id WHERE cr.case_id=? AND cr.role=\'source\'', (case_id,)).fetchone()
        case['source_product'] = dict(row) if row else case['state'].get('product', {'name': '', 'version': ''})
        case['runs'] = [dict(r) for r in db.execute('SELECT run_id, release_id, role FROM case_runs WHERE case_id=?', (case_id,))]
        case['revisions'] = [{**dict(r), 'payload': json.loads(r['payload_json'])} for r in db.execute('SELECT revision, created_at, report_hash, payload_json FROM report_revisions WHERE case_id=? ORDER BY revision', (case_id,))]
        for revision in case['revisions']:
            revision.pop('payload_json')
        case['approvals'] = [dict(r) for r in db.execute('SELECT * FROM approvals WHERE case_id=? ORDER BY id', (case_id,))]
        case['approved'] = bool(case['report'] and any(a['revision'] == case['report']['revision'] and a['report_hash'] == case['report']['report_hash'] for a in case['approvals']))
        from .case_workflow import clocks, clock_status
        case['deadlines'] = case['state'].get('deadlines', clocks(case, case['state']))
        case['clock_status'] = clock_status(case['deadlines'])
        case['submissions'] = []
        for row in db.execute('SELECT * FROM submissions WHERE case_id=? ORDER BY rowid', (case_id,)):
            item = dict(row)
            item['payload'] = json.loads(item.pop('payload_json'))
            item['receipts'] = [{**dict(r), 'payload': json.loads(r['payload_json'])} for r in db.execute('SELECT id, sha256, payload_json FROM receipts WHERE submission_id=? ORDER BY rowid', (item['id'],))]
            for receipt in item['receipts']:
                receipt.pop('payload_json')
            item['status'] = 'acknowledged' if item['receipts'] else item['payload']['result']
            case['submissions'].append(item)
        case['snapshots'] = [dict(r) for r in db.execute('SELECT id, revision, sha256, created_at FROM case_snapshots WHERE case_id=? ORDER BY rowid', (case_id,))]
        from .case_export import pack
        case['readiness'] = {key: value for key, value in pack(case).items() if key in ('ready', 'missing', 'status')} if case['report'] else {'ready': False, 'missing': ['report revision'], 'status': 'No draft prepared'}
        return case

    def list(self):
        with self.store._connect() as db:
            db.execute('BEGIN')
            return [self.get(row['id'], db) for row in db.execute('SELECT id FROM remediation_cases ORDER BY updated_at DESC')]

    def execute(self, action, body, case_id=None):
        if not isinstance(body, dict):
            raise CaseError('request must be an object')
        request_id = required(body, 'request_id')
        if 'simulated' in body and type(body['simulated']) is not bool:
            raise CaseError('simulated must be a boolean')
        try:
            json.dumps(body, allow_nan=False)
            fingerprint = hashlib.sha256(_json([action, case_id, body]).encode()).hexdigest()
        except (TypeError, ValueError) as exc:
            raise CaseError('request must contain finite JSON values') from exc
        with self.store._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            prior = db.execute('SELECT * FROM requests WHERE request_id=?', (request_id,)).fetchone()
            if prior:
                if prior['fingerprint'] != fingerprint:
                    raise CaseConflict('request_id already used for different content')
                return json.loads(prior['response_json'])
            case = self.get(case_id, db) if case_id else None
            if case:
                version = body.get('expected_version')
                if type(version) is not int or version < 0:
                    raise CaseError('expected_version must be a nonnegative integer')
                if version != case['version']:
                    raise CaseConflict('stale case version; reload before applying changes')
            case_id = self._apply(db, action, body, case)
            db.execute('UPDATE remediation_cases SET version=version+1, updated_at=? WHERE id=?', (_utc_now(), case_id))
            result = self.get(case_id, db)
            db.execute('INSERT INTO requests VALUES (?, ?, ?, ?)', (request_id, fingerprint, case_id, _json(result)))
            return result

    def _apply(self, db, action, body, case):
        if action == 'create-incident' and case is None:
            from .case_workflow import create_incident
            return create_incident(self, db, body)
        if action in ('create', 'import-draft') and case is None:
            run_id = required(body, 'source_run_id')
            cve = required(body, 'cve')
            matches = [f for f in self.run_json(run_id, 'findings.json', []) if f.get('cve') == cve and (not body.get('purl') or f.get('purl') == body['purl'])]
            if not matches:
                raise CaseNotFound('finding not found')
            if len(matches) != 1:
                raise CaseError('multiple findings match; supply purl')
            case = self.store.create(run_id, matches[0], db=db, simulated=body.get('simulated', False))
            if case['state'].get('simulated', False) != body.get('simulated', False):
                raise CaseConflict('existing case has a different simulation mode')
            self.link_run(db, case['id'], run_id, 'source')
            if action == 'import-draft':
                filename = required(body, 'draft_file')
                if not re.fullmatch(r'filings/[\w.-]+\.json', filename):
                    raise CaseError('draft_file must name a JSON file under filings/')
                draft = self.run_json(run_id, filename, None)
                if not isinstance(draft, dict):
                    raise CaseError('historical draft not found or invalid')
                self.revision(db, case['id'], {'review_status': 'unreviewed', 'source_run_id': run_id, 'source_file': filename, 'historical_draft': draft})
                self.store._event(db, case['id'], 'historical_draft_imported', _utc_now(), required(body, 'operator'), {'source_file': filename, 'review_status': 'unreviewed'})
            return case['id']
        if case is None:
            raise CaseError('case ID required')
        if action == 'snapshot':
            from .case_snapshot import create_snapshot
            create_snapshot(self, db, case, body)
            return case['id']
        from .case_review import apply_review, timestamp
        from .case_submissions import apply_submission
        if apply_submission(self, db, action, body, case):
            return case['id']
        if apply_review(self, db, action, body, case):
            return case['id']
        if action == 'prepare-report':
            from .case_workflow import prepare_report
            prepare_report(self, db, case, body)
            return case['id']
        if action == 'observe-release':
            run_id = required(body, 'target_run_id')
            source, source_time = self.product(case['source_run_id'])
            target, target_time = self.product(run_id)
            if not source['name'] or not target['name'] or source['name'].casefold() != target['name'].casefold():
                raise CaseError('release product mismatch or unidentified product')
            if not source_time or not target_time or parse_timestamp(target_time) <= parse_timestamp(source_time):
                raise CaseError('target release scan must be newer than source evidence')
            self.store.observe_release(case['id'], run_id, self.run_json(run_id, 'findings.json', []), self.run_json(run_id, 'sbom.cdx.json', {}).get('components', []), db=db)
            self.link_run(db, case['id'], run_id, 'observed')
            if case['report']:
                if case['report']['payload'].get('field_definition'):
                    from .case_review import save_state
                    save_state(self, db, self.get(case['id'], db), dict(case['state']))
                else:
                    self.revision(db, case['id'], self.store._report_payload(self.get(case['id'], db)))
        elif action == 'confirm-measure':
            if case['case_type'] != 'vulnerability':
                raise CaseError('measure confirmation is a vulnerability operation; use incident assessment')
            if case['measure_available_at'] and timestamp(body.get('measure_available_at')) != case['measure_available_at']:
                required(body, 'reason')
            from .case_workflow import persist_clocks
            persist_clocks(self, db, {**case, 'measure_available_at': timestamp(required(body, 'measure_available_at'))}, dict(case['state']))
            structured = bool(case['report'] and case['report']['payload'].get('field_definition'))
            self.store.confirm_measure(case['id'], timestamp(required(body, 'measure_available_at')), required(body, 'operator'), required(body, 'authority_attestation'), required(body, 'measure_details'), db=db, create_report=not structured)
            if structured:
                from .case_review import save_state
                updated = self.get(case['id'], db)
                save_state(self, db, updated, dict(updated['state']))
            from .case_review import record
            record(self, db, case, 'measure_decision', {key: body.get(key) for key in ('operator', 'authority_attestation', 'measure_details', 'reason')}, timestamp(body['measure_available_at']), body['operator'], 'decisions')
        else:
            raise CaseError(f'unknown case operation: {action}')
        return case['id']

    def revision(self, db, case_id, payload):
        number = db.execute('SELECT COALESCE(MAX(revision), 0)+1 FROM report_revisions WHERE case_id=?', (case_id,)).fetchone()[0]
        encoded = _json(payload)
        db.execute('INSERT INTO report_revisions(case_id,revision,created_at,report_hash,payload_json) VALUES(?,?,?,?,?)', (case_id, number, _utc_now(), hashlib.sha256(encoded.encode()).hexdigest(), encoded))
        return number
