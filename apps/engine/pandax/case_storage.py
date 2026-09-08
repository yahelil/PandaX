"""Versioned additions to the original remediation database."""
from __future__ import annotations

import sqlite3


class Connection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def allow_incident_without_finding(db):
    schema = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='remediation_cases'").fetchone()[0]
    schema = schema.replace('remediation_cases', 'migrated_cases', 1).replace('cve TEXT NOT NULL', 'cve TEXT')
    db.execute(schema)
    db.execute('INSERT INTO migrated_cases SELECT * FROM remediation_cases')
    db.execute('DROP TABLE remediation_cases')
    db.execute('ALTER TABLE migrated_cases RENAME TO remediation_cases')


MIGRATIONS = (
    (
        "ALTER TABLE remediation_cases ADD COLUMN version INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE remediation_cases ADD COLUMN case_type TEXT NOT NULL DEFAULT 'vulnerability'",
        "ALTER TABLE remediation_cases ADD COLUMN state_json TEXT NOT NULL DEFAULT '{}'",
        "CREATE TABLE products (id TEXT PRIMARY KEY, name TEXT NOT NULL)",
        "CREATE TABLE releases (id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id), version TEXT NOT NULL)",
        "CREATE TABLE case_runs (case_id TEXT NOT NULL REFERENCES remediation_cases(id), run_id TEXT NOT NULL, release_id TEXT NOT NULL REFERENCES releases(id), role TEXT NOT NULL, PRIMARY KEY(case_id, run_id))",
        "CREATE TABLE requests (request_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, case_id TEXT NOT NULL REFERENCES remediation_cases(id), response_json TEXT NOT NULL)",
        "CREATE TABLE decisions (id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES remediation_cases(id), event_id INTEGER NOT NULL REFERENCES case_events(id), payload_json TEXT NOT NULL)",
        "CREATE TABLE awareness_evidence (id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES remediation_cases(id), event_id INTEGER NOT NULL REFERENCES case_events(id), payload_json TEXT NOT NULL)",
        "CREATE TABLE approvals (id INTEGER PRIMARY KEY, case_id TEXT NOT NULL, revision INTEGER NOT NULL, report_hash TEXT NOT NULL, operator TEXT NOT NULL, authority_attestation TEXT NOT NULL, approved_at TEXT NOT NULL, recorded_at TEXT NOT NULL, FOREIGN KEY(case_id, revision) REFERENCES report_revisions(case_id, revision))",
        "CREATE TABLE submissions (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, revision INTEGER NOT NULL, report_hash TEXT NOT NULL, payload_json TEXT NOT NULL, FOREIGN KEY(case_id, revision) REFERENCES report_revisions(case_id, revision))",
        "CREATE TABLE receipts (id TEXT PRIMARY KEY, submission_id TEXT NOT NULL REFERENCES submissions(id), content BLOB NOT NULL, sha256 TEXT NOT NULL, payload_json TEXT NOT NULL)",
    ),
    tuple(
        f"CREATE TRIGGER immutable_{table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT, 'immutable case history'); END"
        for table in ('case_events', 'report_revisions', 'approvals', 'decisions', 'awareness_evidence')
        for action in ('UPDATE', 'DELETE')
    ),
    (allow_incident_without_finding,),
)


def migrate(db, legacy_sql):
    # executescript implicitly commits: execute individual statements instead.
    # Rebuilding the parent table must not cascade/delete its immutable children.
    # This connection is migration-only; normal connections enable foreign keys.
    db.execute('PRAGMA foreign_keys=OFF')
    db.execute("BEGIN IMMEDIATE")
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version > len(MIGRATIONS):
        raise ValueError("case database schema is newer than this application")
    for statement in legacy_sql.split(";"):
        if statement.strip():
            db.execute(statement)
    for index in range(version, len(MIGRATIONS)):
        for statement in MIGRATIONS[index]:
            statement(db) if callable(statement) else db.execute(statement)
        db.execute(f"PRAGMA user_version = {index + 1}")
    if db.execute('PRAGMA foreign_key_check').fetchone():
        raise ValueError('case database has broken foreign keys')
