"""SQLite 连接、事务和数据库初始化。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = r"""
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS entities (
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY(entity_type, entity_id)
);
CREATE TABLE IF NOT EXISTS entity_versions (
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    request_key TEXT NOT NULL,
    PRIMARY KEY(entity_type, entity_id, version)
);
CREATE INDEX IF NOT EXISTS entity_versions_asof ON entity_versions(entity_type, entity_id, valid_from, version);
CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    request_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(scope, request_key)
);
CREATE TABLE IF NOT EXISTS audit_entries (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    detail_json TEXT NOT NULL,
    previous_digest TEXT NOT NULL,
    entry_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inbox_messages (
    source TEXT NOT NULL,
    source_key TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    payload_digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY(source, source_key, sequence)
);
CREATE TABLE IF NOT EXISTS inbox_conflicts (
    conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    source_key TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    existing_digest TEXT NOT NULL,
    incoming_digest TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox_messages (
    message_id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    available_at TEXT NOT NULL,
    lease_until TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS outbox_ready ON outbox_messages(status, available_at, lease_until);
CREATE TABLE IF NOT EXISTS journal_entries (
    entry_id TEXT PRIMARY KEY,
    journal_key TEXT NOT NULL,
    account TEXT NOT NULL,
    currency TEXT NOT NULL,
    amount_minor INTEGER NOT NULL,
    direction TEXT NOT NULL,
    reference TEXT NOT NULL,
    reversed_entry_id TEXT,
    occurred_at TEXT NOT NULL,
    posted_by TEXT NOT NULL,
    FOREIGN KEY(reversed_entry_id) REFERENCES journal_entries(entry_id)
);
CREATE INDEX IF NOT EXISTS journal_reference ON journal_entries(journal_key, reference, occurred_at);
CREATE TABLE IF NOT EXISTS resource_reservations (
    reservation_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    start_at TEXT NOT NULL,
    end_at TEXT NOT NULL,
    status TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reservation_window ON resource_reservations(resource_id, start_at, end_at, status);
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    job_id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    run_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    lease_until TEXT,
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS jobs_due ON scheduled_jobs(status, run_at, lease_until);
CREATE TABLE IF NOT EXISTS access_participants (
    participant_id TEXT PRIMARY KEY,
    legal_entity_name TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    status TEXT NOT NULL,
    applicant_id TEXT NOT NULL,
    approver_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    decided_at TEXT NOT NULL DEFAULT '',
    decide_reason TEXT NOT NULL DEFAULT '',
    request_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_config_versions (
    participant_id TEXT NOT NULL,
    config_version INTEGER NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    legal_entity_name TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    environment TEXT NOT NULL,
    business_purpose TEXT NOT NULL,
    cert_chain_json TEXT NOT NULL,
    cert_fingerprint TEXT NOT NULL,
    cert_not_after TEXT NOT NULL DEFAULT '',
    key_custody_ref TEXT NOT NULL,
    route_whitelist_json TEXT NOT NULL,
    limits_json TEXT NOT NULL,
    roles_json TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    effective_to TEXT,
    applicant_id TEXT NOT NULL,
    approver_id TEXT NOT NULL DEFAULT '',
    decision_id TEXT NOT NULL DEFAULT '',
    material_version TEXT NOT NULL DEFAULT '',
    decide_reason TEXT NOT NULL DEFAULT '',
    decided_at TEXT NOT NULL DEFAULT '',
    predecessor_version INTEGER NOT NULL DEFAULT 0,
    detail_json TEXT NOT NULL DEFAULT '{}',
    request_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(participant_id, config_version)
);
CREATE INDEX IF NOT EXISTS access_versions_window ON access_config_versions(participant_id, status, effective_from, effective_to);
CREATE TABLE IF NOT EXISTS access_decisions (
    decision_id TEXT PRIMARY KEY,
    participant_id TEXT NOT NULL,
    config_version INTEGER NOT NULL,
    predecessor_version INTEGER NOT NULL DEFAULT 0,
    action TEXT NOT NULL,
    decided_by TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    material_version TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS access_decisions_subject ON access_decisions(participant_id, decided_at);
CREATE TABLE IF NOT EXISTS access_requests (
    request_id TEXT PRIMARY KEY,
    participant_id TEXT NOT NULL,
    config_version INTEGER NOT NULL,
    environment TEXT NOT NULL,
    route TEXT NOT NULL,
    role TEXT NOT NULL,
    cert_fingerprint TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    admitted_at TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS access_requests_version ON access_requests(participant_id, config_version);
CREATE TABLE IF NOT EXISTS bridge_receipts (
    source TEXT NOT NULL,
    source_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    processed_at TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    PRIMARY KEY(source, source_key)
);
CREATE TABLE IF NOT EXISTS bridge_quarantine (
    quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    source_key TEXT NOT NULL,
    existing_fingerprint TEXT NOT NULL,
    incoming_fingerprint TEXT NOT NULL,
    incoming_payload_json TEXT NOT NULL,
    received_at TEXT NOT NULL,
    status TEXT NOT NULL,
    resolver_id TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    resolved_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS bridge_quarantine_status ON bridge_quarantine(status, received_at);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
