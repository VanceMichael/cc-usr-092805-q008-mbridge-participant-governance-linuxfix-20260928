"""应用装配。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog
from .bridge import BridgeReceipts
from .database import Database
from .idempotency import IdempotencyStore
from .inbox import Inbox
from .jobs import JobQueue
from .ledger import Ledger
from .outbox import Outbox
from .participants import ParticipantGovernance
from .repository import EntityRepository
from .reservations import ReservationBook
from .timeutil import Clock


@dataclass(frozen=True)
class CivicFlow:
    database: Database
    clock: Clock
    repository: EntityRepository
    inbox: Inbox
    outbox: Outbox
    ledger: Ledger
    reservations: ReservationBook
    jobs: JobQueue
    governance: ParticipantGovernance
    bridge: BridgeReceipts

    @classmethod
    def open(cls, path: str | Path, *, fixed_now: str | None = None) -> "CivicFlow":
        database = Database(path); database.initialize(); clock = Clock(fixed_now)
        audit = AuditLog(clock); idempotency = IdempotencyStore(clock)
        repository = EntityRepository(database, clock, audit, idempotency)
        jobs = JobQueue(database, clock)
        outbox = Outbox(database, clock)
        governance = ParticipantGovernance(database, clock, audit, idempotency, jobs, outbox)
        bridge = BridgeReceipts(database, clock, jobs, outbox)
        return cls(database, clock, repository, Inbox(database, clock), outbox, Ledger(database, clock),
                   ReservationBook(database), jobs, governance, bridge)

    def verify(self) -> dict:
        with self.database.connect() as connection:
            audit_count = AuditLog(self.clock).verify(connection)
            entity_count = connection.execute("SELECT COUNT(*) AS n FROM entities").fetchone()["n"]
            conflict_count = connection.execute("SELECT COUNT(*) AS n FROM inbox_conflicts").fetchone()["n"]
            quarantine_count = connection.execute("SELECT COUNT(*) AS n FROM bridge_quarantine WHERE status='open'").fetchone()["n"]
        return {"audit_entries": audit_count, "entities": entity_count,
                "inbox_conflicts": conflict_count, "open_quarantine": quarantine_count}
