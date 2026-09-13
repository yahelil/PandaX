"""Sealed ZIP snapshots stored atomically in the case database."""
import hashlib
import io
import json
import tempfile
import uuid
import zipfile
from pathlib import Path

from .cases import CaseError, CaseNotFound, _utc_now
from .case_review import attestation, record
from .case_export import render
from .context import signing_key_path
from .evidence import Ledger, load_or_create_key, write_manifest


def create_snapshot(service, db, case, body):
    identity = attestation(body)
    revision = body.get('revision')
    if type(revision) is not int or not any(r['revision'] == revision for r in case['revisions']):
        raise CaseNotFound('snapshot requires an existing report revision')
    snapshot_id = 'snapshot-' + uuid.uuid4().hex
    # Scans and case snapshots share one installation identity. The private key
    # stays outside every exported bundle.
    key = load_or_create_key(signing_key_path())
    with tempfile.TemporaryDirectory(prefix='case-export-', dir=service.store.path.parent) as directory:
        root = Path(directory)
        (root / 'case.json').write_text(json.dumps(case, ensure_ascii=False, indent=2), encoding='utf-8')
        for format, filename in (('json', 'report.json'), ('html', 'report.html'), ('checklist', 'checklist.txt')):
            (root / filename).write_text(render(case, revision, format), encoding='utf-8')
        (root / 'trust.txt').write_text('Local PoC signature. Signer trust has not been established externally. Provision and verify a trusted key separately.\nOriginal scan bundles remain separate and unchanged.\n', encoding='utf-8')
        for row in db.execute('SELECT r.id, r.content, r.sha256 FROM receipts r JOIN submissions s ON r.submission_id=s.id WHERE s.case_id=?', (case['id'],)):
            if hashlib.sha256(row['content']).hexdigest() != row['sha256']:
                raise CaseError('stored receipt digest mismatch')
            (root / (row['id'] + '.bin')).write_bytes(row['content'])
        ledger = Ledger(root)
        ledger.append('CASE_SNAPSHOT', 'PandaX', '0.1.0', [], [ledger.ref(p) for p in sorted(root.iterdir())], {'case_id': case['id'], 'revision': revision, 'version': case['version']})
        write_manifest(root, snapshot_id, case['source_product'], {'pandax': '0.1.0'}, ledger, key)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(root.iterdir()):
                archive.write(file, file.name)
        content = buffer.getvalue()
    digest = hashlib.sha256(content).hexdigest()
    now = _utc_now()
    db.execute('INSERT INTO case_snapshots VALUES(?,?,?,?,?,?)', (snapshot_id, case['id'], revision, digest, content, now))
    record(service, db, case, 'snapshot_created', {**identity, 'snapshot_id': snapshot_id, 'revision': revision, 'sha256': digest, 'externally_trusted': False}, now, identity['operator'])


def snapshot_bytes(service, case_id, snapshot_id):
    with service.store._connect() as db:
        row = db.execute('SELECT content, sha256 FROM case_snapshots WHERE id=? AND case_id=?', (snapshot_id, case_id)).fetchone()
        if not row:
            raise CaseNotFound('snapshot not found')
        if hashlib.sha256(row['content']).hexdigest() != row['sha256']:
            raise CaseError('snapshot digest mismatch')
        return row['content']
