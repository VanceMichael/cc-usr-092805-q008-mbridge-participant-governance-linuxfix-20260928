"""桥侧回执归并与异常隔离。

- 回执按 (source, source_key) 来源编号归并，并记录内容指纹。
- 完全相同（编号与指纹都一致）的消息只处理一次，重复投递返回 duplicate。
- 编号不变但指纹变化时，不覆盖原记录，先写入隔离区等待调查，并通过原有
  通知/任务模块发出异常回执提醒。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta

from .database import Database
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .identifiers import new_id, require_safe
from .jobs import insert_job
from .jsonutil import canonical_json, digest_json
from .security import AccessContext
from .timeutil import Clock, canonical_instant


@dataclass(frozen=True)
class BridgeReceipts:
    database: Database
    clock: Clock
    jobs: object = None
    outbox: object = None

    def ingest(self, *, source: str, source_key: str, payload: dict, occurred_at: str) -> dict:
        require_safe(source, "来源"); require_safe(source_key, "来源编号")
        occurred_at = canonical_instant(occurred_at)
        fingerprint = digest_json(payload)
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM bridge_receipts WHERE source=? AND source_key=?",
                                     (source, source_key)).fetchone()
            now = self.clock.now()
            if row:
                if row["fingerprint"] == fingerprint:
                    # 编号与指纹完全一致：只处理一次，不重复入账。
                    return {"status": "duplicate", "source": source, "source_key": source_key,
                            "fingerprint": fingerprint, "first_received_at": row["received_at"]}
                # 编号未变而指纹变化：保留已处理消息，新内容先隔离调查。
                cur = connection.execute(
                    "INSERT INTO bridge_quarantine(source,source_key,existing_fingerprint,incoming_fingerprint,incoming_payload_json,received_at,status) VALUES(?,?,?,?,?,?,?)",
                    (source, source_key, row["fingerprint"], fingerprint, canonical_json(payload), now, "open")).lastrowid
                connection.execute("UPDATE bridge_receipts SET status='quarantined' WHERE source=? AND source_key=?",
                                   (source, source_key))
                self._alert(connection, "bridge.receipt_conflict", source_key,
                            {"quarantine_id": cur, "source": source, "source_key": source_key,
                             "existing_fingerprint": row["fingerprint"], "incoming_fingerprint": fingerprint})
                return {"status": "quarantined", "source": source, "source_key": source_key,
                        "fingerprint": fingerprint, "quarantine_id": cur}
            connection.execute(
                "INSERT INTO bridge_receipts(source,source_key,fingerprint,payload_json,occurred_at,received_at,status) VALUES(?,?,?,?,?,?,?)",
                (source, source_key, fingerprint, canonical_json(payload), occurred_at, now, "accepted"))
            return {"status": "accepted", "source": source, "source_key": source_key, "fingerprint": fingerprint}

    def mark_processed(self, *, source: str, source_key: str) -> dict:
        """将已接收回执标记为已处理；重复标记无效，保证只处理一次。"""
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM bridge_receipts WHERE source=? AND source_key=?",
                                     (source, source_key)).fetchone()
            if not row:
                raise NotFoundError("回执不存在")
            if row["status"] == "processed":
                return {"status": "duplicate", "source": source, "source_key": source_key}
            if row["status"] == "quarantined":
                raise ConflictError("回执存在未结隔离调查，不能处理")
            connection.execute("UPDATE bridge_receipts SET status='processed',processed_at=? WHERE source=? AND source_key=?",
                               (self.clock.now(), source, source_key))
            return {"status": "processed", "source": source, "source_key": source_key,
                    "fingerprint": row["fingerprint"]}

    def get(self, source: str, source_key: str) -> dict:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM bridge_receipts WHERE source=? AND source_key=?",
                                     (require_safe(source, "来源"), require_safe(source_key, "来源编号"))).fetchone()
            if not row:
                raise NotFoundError("回执不存在")
            return dict(row)

    def list_quarantine(self, *, status: str = "open") -> list[dict]:
        with self.database.connect() as connection:
            rows = connection.execute("SELECT * FROM bridge_quarantine WHERE status=? ORDER BY quarantine_id",
                                      (status,)).fetchall()
            return [dict(r) for r in rows]

    def resolve_quarantine(self, context: AccessContext, quarantine_id: int, *, verdict: str, note: str) -> dict:
        """调查结论：discard 丢弃伪造/重复异常内容；accept_new 以新指纹为准重新接收。"""
        context.require("resolve:bridge")
        if verdict not in ("discard", "accept_new"):
            raise ValidationError("调查结论必须是 discard 或 accept_new")
        if not note.strip():
            raise ValidationError("隔离处置必须记录调查说明")
        with self.database.transaction() as connection:
            q = connection.execute("SELECT * FROM bridge_quarantine WHERE quarantine_id=?", (quarantine_id,)).fetchone()
            if not q:
                raise NotFoundError("隔离记录不存在")
            if q["status"] != "open":
                raise ConflictError("该隔离记录已处置")
            now = self.clock.now()
            connection.execute(
                "UPDATE bridge_quarantine SET status='resolved',resolver_id=?,verdict=?,note=?,resolved_at=? WHERE quarantine_id=?",
                (context.actor_id, verdict, note.strip(), now, quarantine_id))
            source, source_key = q["source"], q["source_key"]
            if verdict == "accept_new":
                connection.execute(
                    "UPDATE bridge_receipts SET fingerprint=?,payload_json=?,status='accepted',processed_at='' WHERE source=? AND source_key=?",
                    (q["incoming_fingerprint"], q["incoming_payload_json"], source, source_key))
            else:
                # 丢弃：恢复原回执状态（已处理则保持 processed，否则 accepted）。
                connection.execute("UPDATE bridge_receipts SET status='processed' WHERE source=? AND source_key=? AND processed_at<>''",
                                   (source, source_key))
                connection.execute("UPDATE bridge_receipts SET status='accepted' WHERE source=? AND source_key=? AND processed_at=''",
                                   (source, source_key))
            return {"quarantine_id": quarantine_id, "verdict": verdict, "resolved_by": context.actor_id,
                    "source": source, "source_key": source_key}

    def _alert(self, connection, topic: str, aggregate_id: str, payload: dict) -> None:
        connection.execute(
            "INSERT INTO outbox_messages(message_id,topic,aggregate_id,payload_json,available_at,status) VALUES(?,?,?,?,?,?)",
            (new_id("msg"), topic, aggregate_id, canonical_json(payload), self.clock.now(), "pending"))
        if self.jobs is not None:
            insert_job(connection, job_id=new_id("job"), job_type="access.receipt_investigation",
                       subject_id=aggregate_id, run_at=self.clock.now(), payload=payload)
