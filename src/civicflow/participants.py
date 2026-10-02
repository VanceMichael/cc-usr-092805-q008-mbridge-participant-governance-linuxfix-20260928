"""参与机构接入治理：生效区间配置版本、可追查决定、时点准入与审计。

设计要点：
- 每个参与机构（法律实体）的接入配置以不可变版本保存，带 [effective_from, effective_to)
  生效区间；重叠轮换时多个版本同时在区间内有效。
- 启用、续期、吊销、重叠轮换、降权都走“申请人提交 → 不同审批人批准”，产生 access_decisions
  决定记录和平台原有审计链条目；批准材料以 material_version 固化。
- 新请求按时点和证书指纹钉住当时有效版本并固化；历史请求永远引用当时版本。
- 无授权访问无法区分“参与者不存在”与“参与者尚未获准”。
- 到期、待生效、异常回执与定期复核通过原有定时任务/发件箱模块持续推进。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, Mapping

from .audit import AuditLog
from .database import Database
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .identifiers import new_id, require_safe
from .idempotency import IdempotencyStore
from .jobs import insert_job
from .jsonutil import canonical_json
from .security import AccessContext, assert_distinct
from .timeutil import Clock, canonical_instant, parse_instant

PROPOSED = "proposed"
ACTIVE = "active"
SCHEDULED = "scheduled"
RETIRED = "retired"
REVOKED = "revoked"
REJECTED = "rejected"

PARTICIPANT_PENDING = "pending"
PARTICIPANT_ACTIVE = "active"
PARTICIPANT_REVOKED = "revoked"

# 提交后需要二次审批的决定；每个动作都会留下可追查决定。
DECISION_ACTIONS = ("enable", "renew", "rotate_overlap", "degrade", "revoke")

CONFIG_FIELDS = (
    "environment", "business_purpose", "cert_chain", "cert_fingerprint",
    "cert_not_after", "key_custody_ref", "route_whitelist", "limits", "roles",
)
EFFECTIVE_STATUSES = (ACTIVE, SCHEDULED, RETIRED)

WARN_BEFORE_EFFECT = timedelta(days=1)
WARN_BEFORE_EXPIRY = timedelta(days=7)
REVIEW_PERIOD_DAYS = 180


@dataclass(frozen=True)
class ParticipantGovernance:
    database: Database
    clock: Clock
    audit: AuditLog
    idempotency: IdempotencyStore
    jobs: object = None
    outbox: object = None

    # ---------------------------------------------------------------- 提交

    def submit(self, context: AccessContext, action: str, values: Mapping[str, object], *,
               participant_id: str | None = None, effective_from: str | None = None,
               effective_to: str | None = None, request_key: str) -> dict:
        context.require("submit:access")
        if action not in DECISION_ACTIONS:
            raise ValidationError(f"未知决定动作: {action}")
        request = {"action": action, "participant_id": participant_id, "values": dict(values),
                   "effective_from": effective_from, "effective_to": effective_to}
        with self.database.transaction() as connection:
            def operation() -> dict:
                now = self.clock.now()
                if action == "enable":
                    config = self._validate_config(values, require_all=True)
                    eff_from = canonical_instant(effective_from or now)
                    eff_to = canonical_instant(effective_to) if effective_to else None
                    pid = new_id("participant")
                    connection.execute(
                        "INSERT INTO access_participants(participant_id,legal_entity_name,jurisdiction,status,applicant_id,created_at,request_key) VALUES(?,?,?,?,?,?,?)",
                        (pid, config["legal_entity_name"], config["jurisdiction"], PARTICIPANT_PENDING, context.actor_id, now, request_key))
                    version = self._insert_version(connection, pid, 1, action, PROPOSED, config,
                                                   eff_from, eff_to, applicant=context.actor_id, request_key=request_key, created_at=now)
                else:
                    pid = require_safe(participant_id or "", "参与机构")
                    prow = self._load_participant(connection, pid)
                    self._assert_visible_admitted(prow, allow_history=False)
                    pred = self._latest_version(connection, pid)
                    if pred is None or pred["status"] in (PROPOSED, REJECTED):
                        raise ConflictError("前一版本尚未获批，不能提交该决定")
                    if action in ("renew", "rotate_overlap"):
                        config = self._validate_config(values, require_all=True)
                    elif action == "degrade":
                        # 降权不改证书，只允许收紧角色/路由/限额。
                        config = self._validate_degrade(values, pred)
                    else:  # revoke 沿用当前配置快照
                        config = self._config_from_row(pred)
                    eff_from = canonical_instant(effective_from) if effective_from else now
                    eff_to = canonical_instant(effective_to) if effective_to else None
                    if action == "renew":
                        if not pred["effective_to"]:
                            raise ConflictError("旧版本仍为长期有效，续期请改用重叠轮换 rotate_overlap")
                        if parse_instant(eff_from) < parse_instant(pred["effective_to"]):
                            raise ConflictError("续期的新生效时间不得早于旧版本停用时间")
                    if action == "rotate_overlap":
                        retire = values.get("retire_old_at")
                        if not retire:
                            raise ValidationError("重叠轮换必须给出旧证书停用时间 retire_old_at")
                        retire_at = canonical_instant(str(retire))
                        if parse_instant(retire_at) < parse_instant(eff_from):
                            raise ConflictError("旧证书停用时间不得早于新证书生效时间")
                        if pred["effective_to"] and parse_instant(retire_at) > parse_instant(pred["effective_to"]):
                            raise ConflictError("旧证书停用时间不能晚于其既定有效期")
                        eff_to = None
                    if eff_to and parse_instant(eff_to) <= parse_instant(eff_from):
                        raise ValidationError("生效区间结束必须晚于开始")
                    version = self._insert_version(connection, pid, pred["config_version"] + 1, action, PROPOSED, config,
                                                   eff_from, eff_to, applicant=context.actor_id,
                                                   request_key=request_key, created_at=now,
                                                   predecessor=pred["config_version"], detail=self._submit_detail(values, action))
                return {"participant_id": pid, "config_version": version["config_version"],
                        "action": action, "status": PROPOSED, "effective_from": eff_from,
                        "effective_to": eff_to, "applicant_id": context.actor_id}
            return self.idempotency.execute(connection, scope=f"access:submit:{action}:{participant_id or '-'}",
                                            request_key=request_key, request=request, operation=operation)

    # ---------------------------------------------------------------- 审批

    def approve(self, context: AccessContext, participant_id: str, config_version: int, *,
                verdict: str, reason: str, material_version: str, request_key: str,
                retire_old_at: str | None = None) -> dict:
        context.require("approve:access")
        if verdict not in ("approved", "rejected"):
            raise ValidationError("审批结论必须是 approved 或 rejected")
        if not reason.strip():
            raise ValidationError("审批必须说明原因")
        if verdict == "approved" and not material_version.strip():
            raise ValidationError("批准必须登记所依据的材料版本")
        request = {"participant_id": participant_id, "config_version": config_version,
                   "verdict": verdict, "reason": reason, "material_version": material_version}
        with self.database.transaction() as connection:
            def operation() -> dict:
                pid = require_safe(participant_id, "参与机构")
                prow = self._load_participant(connection, pid)
                if not prow:
                    raise NotFoundError("参与机构不存在或尚未获准")
                version = self._load_version(connection, pid, config_version)
                if not version or version["status"] != PROPOSED:
                    raise ConflictError("该版本不是待审批版本")
                # 职责分离：机构申请人与证书审批人不能是同一人。
                assert_distinct(version["applicant_id"], context.actor_id)
                now = self.clock.now()
                decision_id = new_id("decision")
                self._insert_decision(connection, decision_id, pid, config_version,
                                      version["predecessor_version"], version["action"],
                                      context.actor_id, now, reason.strip(), material_version.strip(),
                                      {"verdict": verdict, **version["detail"]})
                if verdict == "rejected":
                    connection.execute("UPDATE access_config_versions SET status=?,approver_id=?,decision_id=?,decided_at=?,decide_reason=?,material_version=? WHERE participant_id=? AND config_version=?",
                                       (REJECTED, context.actor_id, decision_id, now, reason.strip(), material_version.strip(), pid, config_version))
                    if version["action"] == "enable":
                        connection.execute("UPDATE access_participants SET status='rejected',approver_id=?,decided_at=?,decide_reason=? WHERE participant_id=?",
                                           (context.actor_id, now, reason.strip(), pid))
                    self.audit.append(connection, actor_id=context.actor_id, action=f"access.reject:{version['action']}",
                                      entity_type="access_participants", entity_id=pid, version=config_version,
                                      detail={"decision_id": decision_id, "reason": reason})
                    return {"participant_id": pid, "config_version": config_version, "status": REJECTED, "decision_id": decision_id}

                eff_from = version["effective_from"]
                eff_to = version["effective_to"]
                if version["action"] == "degrade":
                    # 紧急降权立即生效，并同时收回旧版本的操作角色。
                    eff_from = now
                if version["action"] == "revoke":
                    eff_from = now; eff_to = now
                new_status = ACTIVE if parse_instant(eff_from) <= parse_instant(now) else SCHEDULED
                connection.execute(
                    "UPDATE access_config_versions SET status=?,approver_id=?,decision_id=?,decided_at=?,decide_reason=?,material_version=?,effective_from=?,effective_to=? WHERE participant_id=? AND config_version=?",
                    (new_status, context.actor_id, decision_id, now, reason.strip(), material_version.strip(), eff_from, eff_to, pid, config_version))

                if version["action"] == "enable":
                    connection.execute("UPDATE access_participants SET status=?,approver_id=?,decided_at=?,decide_reason=? WHERE participant_id=?",
                                       (PARTICIPANT_ACTIVE, context.actor_id, now, reason.strip(), pid))
                    predecessor_retire_at = None
                else:
                    pred = self._load_version(connection, pid, version["predecessor_version"])
                    retire_at: str | None = None
                    predecessor_retire_at = None
                    if version["action"] == "rotate_overlap":
                        retire_at = canonical_instant(retire_old_at) if retire_old_at else version["detail"].get("retire_old_at")
                        if not retire_at:
                            raise ValidationError("重叠轮换批准必须确认旧证书停用时间")
                        retire_at = canonical_instant(retire_at)
                        # 重叠窗口内旧版本仍保持 active，只登记预定停用时间；到点由可恢复任务转 retired。
                        connection.execute(
                            "UPDATE access_config_versions SET effective_to=? WHERE participant_id=? AND config_version=? AND status IN (?,?)",
                            (retire_at, pid, pred["config_version"], ACTIVE, SCHEDULED))
                        predecessor_retire_at = retire_at
                    elif version["action"] in ("degrade", "revoke"):
                        retire_at = now
                        if pred is not None:
                            connection.execute(
                                "UPDATE access_config_versions SET status=?,effective_to=? WHERE participant_id=? AND config_version=? AND status IN (?,?)",
                                (RETIRED if version["action"] != "revoke" else REVOKED, retire_at, pid, pred["config_version"], ACTIVE, SCHEDULED))
                    if version["action"] == "revoke":
                        connection.execute("UPDATE access_participants SET status=?,decided_at=? WHERE participant_id=?",
                                           (PARTICIPANT_REVOKED, now, pid))
                    else:
                        connection.execute("UPDATE access_participants SET status=?,decided_at=? WHERE participant_id=?",
                                           (PARTICIPANT_ACTIVE, now, pid))

                self.audit.append(connection, actor_id=context.actor_id, action=f"access.approve:{version['action']}",
                                  entity_type="access_participants", entity_id=pid, version=config_version,
                                  detail={"decision_id": decision_id, "effective_from": eff_from, "effective_to": eff_to,
                                          "predecessor_retire_at": predecessor_retire_at,
                                          "material_version": material_version, "reason": reason})
                self._schedule_followups(connection, version, eff_from, eff_to, predecessor_retire_at)
                self._notify(connection, "access.decision", pid,
                             {"decision_id": decision_id, "action": version["action"], "effective_from": eff_from})
                return {"participant_id": pid, "config_version": config_version, "status": new_status,
                        "effective_from": eff_from, "effective_to": eff_to, "decision_id": decision_id,
                        "approved_by": context.actor_id, "material_version": material_version}
            return self.idempotency.execute(connection, scope=f"access:approve:{participant_id}:{config_version}",
                                            request_key=request_key, request=request, operation=operation)

    # ---------------------------------------------------------------- 准入

    def admit(self, context: AccessContext, *, participant_id: str, environment: str, route: str,
              role: str, cert_fingerprint: str, request_id: str, at: str | None = None,
              request_key: str) -> dict:
        """新请求准入：只能落入当时已生效（未过期、未提前）的配置，并钉住该版本。"""
        context.require("admit:access")
        request = {"request_id": request_id, "participant_id": participant_id, "environment": environment,
                   "route": route, "role": role, "cert_fingerprint": cert_fingerprint, "at": at}
        with self.database.transaction() as connection:
            def operation() -> dict:
                instant = canonical_instant(at or self.clock.now())
                pid = require_safe(participant_id, "参与机构")
                prow = self._load_participant(connection, pid)
                if not prow or prow["status"] != PARTICIPANT_ACTIVE:
                    # 不区分不存在 / 未获准 / 已吊销，避免探测参与者是否存在。
                    raise NotFoundError("参与者不存在或当前不接受请求")
                version = self._version_for_request(connection, pid, instant, cert_fingerprint)
                if version is None:
                    raise NotFoundError("参与者不存在或当前不接受请求")
                if environment != version["environment"]:
                    raise PermissionDenied("接入环境与生效配置不符")
                if route not in version["route_whitelist"]:
                    raise PermissionDenied("路由不在生效白名单内")
                if role not in version["roles"]:
                    raise PermissionDenied("操作角色未在生效配置中授权")
                admitted_at = self.clock.now()
                connection.execute(
                    "INSERT INTO access_requests(request_id,participant_id,config_version,environment,route,role,cert_fingerprint,occurred_at,admitted_at,status) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (require_safe(request_id, "请求标识"), pid, version["config_version"], environment, route, role,
                     cert_fingerprint, instant, admitted_at, "admitted"))
                self.audit.append(connection, actor_id=context.actor_id, action="access.admit",
                                  entity_type="access_requests", entity_id=request_id, version=version["config_version"],
                                  detail={"participant_id": pid, "config_version": version["config_version"]})
                return {"request_id": request_id, "participant_id": pid,
                        "config_version": version["config_version"], "status": "admitted",
                        "decision_id": version["decision_id"], "material_version": version["material_version"]}
            return self.idempotency.execute(connection, scope=f"access:admit:{request_id}",
                                            request_key=request_key, request=request, operation=operation)

    def get_request(self, context: AccessContext, request_id: str) -> dict:
        """已完成请求继续引用当时版本：返回固化的版本快照与批准材料。"""
        context.require("read:access")
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM access_requests WHERE request_id=?", (require_safe(request_id, "请求标识"),)).fetchone()
            if not row:
                raise NotFoundError("请求不存在")
            version = self._load_version(connection, row["participant_id"], row["config_version"])
            result = dict(row); result["config_snapshot"] = self._public_version(version)
            return result

    # ---------------------------------------------------------------- 查询

    def get_participant(self, context: AccessContext, participant_id: str) -> dict:
        context.require("read:access")
        with self.database.connect() as connection:
            prow = self._load_participant(connection, require_safe(participant_id, "参与机构"))
            if not prow:
                raise NotFoundError("参与机构不存在或尚未获准")
            can_see_pending = context.allows("history:access") or context.allows("audit:access")
            if prow["status"] in (PARTICIPANT_PENDING, "rejected") and not can_see_pending:
                # 对无历史权限者，未获准参与者与不存在不可区分。
                raise NotFoundError("参与机构不存在或尚未获准")
            return dict(prow)

    def effective_versions(self, context: AccessContext, participant_id: str, *, at: str) -> list[dict]:
        """列出某时点处于生效区间内的全部版本（重叠轮换期间可能有多个）。"""
        context.require("read:access")
        instant = canonical_instant(at)
        with self.database.connect() as connection:
            prow = self._load_participant(connection, require_safe(participant_id, "参与机构"))
            if not prow or prow["status"] == PARTICIPANT_PENDING:
                raise NotFoundError("参与机构不存在或尚未获准")
            rows = self._effective_rows(connection, participant_id, instant)
            return [self._public_version(r) for r in rows]

    def allowed_routes(self, context: AccessContext, participant_id: str, *, at: str) -> dict:
        """重叠窗口内允许的机构角色与路由 = 当时各生效版本的并集。"""
        versions = self.effective_versions(context, participant_id, at=at)
        if not versions:
            raise NotFoundError("该时点没有生效配置")
        routes = sorted({r for v in versions for r in v["route_whitelist"]})
        roles = sorted({r for v in versions for r in v["roles"]})
        return {"as_of": canonical_instant(at), "participant_id": participant_id,
                "effective_versions": [v["config_version"] for v in versions],
                "routes": routes, "roles": roles}

    def audit_view(self, context: AccessContext, *, at: str, jurisdiction: str | None = None) -> list[dict]:
        """按指定时点列出被允许的机构、角色、路由，并附每项决定的批准人与材料版本。"""
        context.require("audit:access")
        instant = canonical_instant(at)
        with self.database.connect() as connection:
            sql = ("SELECT v.*, d.decided_by AS decision_by, d.decided_at AS decision_at, d.reason AS decision_reason "
                   "FROM access_config_versions v JOIN access_decisions d "
                   "ON d.participant_id=v.participant_id AND d.config_version=v.config_version "
                   "JOIN access_participants p ON p.participant_id=v.participant_id "
                   "WHERE v.status IN (?,?,?) AND v.effective_from<=? "
                   "AND (v.effective_to IS NULL OR ?<v.effective_to) AND p.status=?")
            params: list[object] = [ACTIVE, SCHEDULED, RETIRED, instant, instant, PARTICIPANT_ACTIVE]
            if jurisdiction is not None:
                sql += " AND v.jurisdiction=?"; params.append(jurisdiction)
            sql += " ORDER BY v.participant_id,v.config_version"
            result = []
            for row in connection.execute(sql, params):
                item = self._public_version(self._decorate(row))
                item.update({"approved_by": row["decision_by"], "approved_at": row["decision_at"],
                             "approval_reason": row["decision_reason"]})
                result.append(item)
            return result

    def list_decisions(self, context: AccessContext, participant_id: str) -> list[dict]:
        context.require("history:access")
        with self.database.connect() as connection:
            rows = connection.execute("SELECT * FROM access_decisions WHERE participant_id=? ORDER BY decided_at,config_version",
                                      (require_safe(participant_id, "参与机构"),)).fetchall()
            if not rows:
                raise NotFoundError("参与机构不存在或没有决定记录")
            return [dict(r) for r in rows]

    def history(self, context: AccessContext, participant_id: str) -> list[dict]:
        context.require("history:access")
        with self.database.connect() as connection:
            prow = self._load_participant(connection, require_safe(participant_id, "参与机构"))
            if not prow:
                raise NotFoundError("参与机构不存在或尚未获准")
            rows = connection.execute("SELECT * FROM access_config_versions WHERE participant_id=? ORDER BY config_version",
                                      (participant_id,)).fetchall()
            return [self._public_version(self._decorate(r)) for r in rows]

    # ---------------------------------------------------------------- 定时推进

    def _advance_status(self, job: dict, payload: dict) -> None:
        """按任务时点把待生效/已到期的配置版本推进到 active/retired，并留痕。"""
        pid = job["subject_id"]
        instant = job["run_at"]
        with self.database.transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM access_config_versions WHERE participant_id=? AND status IN (?,?)",
                (pid, ACTIVE, SCHEDULED)).fetchall()
            for row in rows:
                target = None
                if row["effective_to"] and instant >= row["effective_to"]:
                    target = RETIRED
                elif row["status"] == SCHEDULED and instant >= row["effective_from"]:
                    target = ACTIVE
                if target:
                    connection.execute("UPDATE access_config_versions SET status=? WHERE participant_id=? AND config_version=?",
                                       (target, pid, row["config_version"]))
                    self.audit.append(connection, actor_id="scheduler", action=f"access.effect:{target}",
                                      entity_type="access_participants", entity_id=pid,
                                      version=row["config_version"], detail={"job_type": job["job_type"]})

    def run_due_tasks(self, *, limit: int = 20) -> list[dict]:
        """领取到期的接入治理任务并通过原有发件箱发出通知；失败可重试、可恢复。"""
        if self.jobs is None:
            raise ValidationError("未装配定时任务队列")
        claimed = self.jobs.claim_due(limit=limit, job_prefix="access.")
        done = []
        for job in claimed:
            try:
                payload = json.loads(job["payload_json"])
                self._advance_status(job, payload)
                self.outbox.enqueue(topic=job["job_type"], aggregate_id=job["subject_id"], payload=payload)
                if job["job_type"] == "access.periodic_review":
                    interval = int(payload.get("review_days", REVIEW_PERIOD_DAYS))
                    nxt = (parse_instant(job["run_at"]) + timedelta(days=interval)).isoformat().replace("+00:00", "Z")
                    self.jobs.schedule(job_type="access.periodic_review", subject_id=job["subject_id"],
                                       run_at=nxt, payload=payload)
                self.jobs.finish(job["job_id"])
                done.append({"job_id": job["job_id"], "job_type": job["job_type"], "subject_id": job["subject_id"]})
            except Exception as exc:  # 任务可恢复：退回重试
                retry_at = (parse_instant(self.clock.now()) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
                self.jobs.retry(job["job_id"], error=str(exc), retry_at=retry_at)
        return done

    # ---------------------------------------------------------------- 内部

    def _schedule_followups(self, connection, version: dict, eff_from: str, eff_to: str | None,
                            predecessor_retire_at: str | None = None) -> None:
        if self.jobs is None:
            return
        pid = version["participant_id"]
        payload = {"participant_id": pid, "config_version": version["config_version"],
                   "cert_fingerprint": version["cert_fingerprint"], "cert_not_after": version["cert_not_after"]}

        def schedule(job_type: str, run_at: str, extra: dict | None = None) -> None:
            insert_job(connection, job_id=new_id("job"), job_type=job_type, subject_id=pid,
                       run_at=run_at, payload={**payload, **(extra or {})})

        now = parse_instant(self.clock.now())
        start = parse_instant(eff_from)
        if start > now:
            warn = (start - WARN_BEFORE_EFFECT).isoformat().replace("+00:00", "Z")
            if parse_instant(warn) > now:
                schedule("access.change_pending", warn)
            schedule("access.version_effective", eff_from)
        if eff_to:
            schedule("access.version_retire", eff_to)
        # 重叠轮换的旧版本到预定停用时点由任务转为 retired。
        if predecessor_retire_at and parse_instant(predecessor_retire_at) > now:
            schedule("access.version_retire", predecessor_retire_at,
                     {"predecessor_version": version["predecessor_version"]})
        if version["cert_not_after"]:
            expiry = parse_instant(version["cert_not_after"])
            if expiry > now:
                warn_exp = (expiry - WARN_BEFORE_EXPIRY).isoformat().replace("+00:00", "Z")
                schedule("access.cert_expiring", max(now, parse_instant(warn_exp)).isoformat().replace("+00:00", "Z"))
                schedule("access.cert_expired", version["cert_not_after"])
        review = (start + timedelta(days=REVIEW_PERIOD_DAYS)).isoformat().replace("+00:00", "Z")
        schedule("access.periodic_review", review, {"review_days": REVIEW_PERIOD_DAYS})

    def _notify(self, connection, topic: str, aggregate_id: str, payload: dict) -> None:
        if self.outbox is None:
            return
        # 与 Outbox 模块同表，事务内直接写入以保证与决定同提交。
        connection.execute(
            "INSERT INTO outbox_messages(message_id,topic,aggregate_id,payload_json,available_at,status) VALUES(?,?,?,?,?,?)",
            (new_id("msg"), topic, aggregate_id, canonical_json(payload), self.clock.now(), "pending"))

    def _version_for_request(self, connection, pid: str, instant: str, fingerprint: str):
        rows = self._effective_rows(connection, pid, instant)
        matches = [r for r in rows if r["cert_fingerprint"] == fingerprint]
        return matches[-1] if matches else None

    def _effective_rows(self, connection, pid: str, instant: str) -> list[dict]:
        rows = connection.execute(
            "SELECT * FROM access_config_versions WHERE participant_id=? AND status IN (?,?,?) AND effective_from<=? "
            "AND (effective_to IS NULL OR ?<effective_to) ORDER BY config_version",
            (pid, ACTIVE, SCHEDULED, RETIRED, instant, instant)).fetchall()
        return [self._decorate(r) for r in rows]

    @staticmethod
    def _load_participant(connection, pid: str):
        return connection.execute("SELECT * FROM access_participants WHERE participant_id=?", (pid,)).fetchone()

    @staticmethod
    def _load_version(connection, pid: str, config_version: int) -> dict | None:
        row = connection.execute("SELECT * FROM access_config_versions WHERE participant_id=? AND config_version=?",
                                 (pid, config_version)).fetchone()
        return ParticipantGovernance._decorate(row) if row else None

    def _latest_version(self, connection, pid: str) -> dict | None:
        row = connection.execute("SELECT * FROM access_config_versions WHERE participant_id=? ORDER BY config_version DESC LIMIT 1",
                                 (pid,)).fetchone()
        return self._decorate(row) if row else None

    @staticmethod
    def _assert_visible_admitted(prow, *, allow_history: bool) -> None:
        if not prow or prow["status"] not in (PARTICIPANT_ACTIVE,):
            raise NotFoundError("参与机构不存在或尚未获准")

    def _insert_decision(self, connection, decision_id, pid, version, predecessor, action,
                         approver, decided_at, reason, material_version, detail) -> None:
        connection.execute(
            "INSERT INTO access_decisions(decision_id,participant_id,config_version,predecessor_version,action,decided_by,decided_at,reason,material_version,detail_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (decision_id, pid, version, predecessor, action, approver, decided_at, reason, material_version,
             canonical_json(detail)))

    def _insert_version(self, connection, pid, config_version, action, status, config, eff_from, eff_to, *,
                        applicant, request_key, created_at, predecessor=0, detail=None) -> dict:
        connection.execute(
            "INSERT INTO access_config_versions(participant_id,config_version,action,status,legal_entity_name,jurisdiction,environment,business_purpose,cert_chain_json,cert_fingerprint,cert_not_after,key_custody_ref,route_whitelist_json,limits_json,roles_json,effective_from,effective_to,applicant_id,predecessor_version,detail_json,request_key,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, config_version, action, status, config["legal_entity_name"], config["jurisdiction"],
             config["environment"], config["business_purpose"], canonical_json(config["cert_chain"]),
             config["cert_fingerprint"], config["cert_not_after"], config["key_custody_ref"],
             canonical_json(config["route_whitelist"]), canonical_json(config["limits"]),
             canonical_json(config["roles"]), eff_from, eff_to, applicant, predecessor,
             canonical_json(detail or {}), request_key, created_at))
        row = connection.execute("SELECT * FROM access_config_versions WHERE participant_id=? AND config_version=?",
                                 (pid, config_version)).fetchone()
        return self._decorate(row)

    @staticmethod
    def _decorate(row) -> dict:
        item = dict(row)
        for key in ("cert_chain", "route_whitelist", "roles", "limits"):
            item[key] = json.loads(item.pop(f"{key}_json"))
        item["detail"] = json.loads(item.pop("detail_json"))
        return item

    @staticmethod
    def _public_version(row: dict) -> dict:
        return {k: row[k] for k in (
            "participant_id", "config_version", "action", "status", "legal_entity_name", "jurisdiction",
            "environment", "business_purpose", "cert_chain", "cert_fingerprint", "cert_not_after",
            "key_custody_ref", "route_whitelist", "limits", "roles", "effective_from", "effective_to",
            "applicant_id", "approver_id", "decision_id", "material_version", "predecessor_version", "detail")}

    @staticmethod
    def _config_from_row(row: dict) -> dict:
        return {key: row[key] for key in
                ("legal_entity_name", "jurisdiction", "environment", "business_purpose", "cert_chain",
                 "cert_fingerprint", "cert_not_after", "key_custody_ref", "route_whitelist", "limits", "roles")}

    def _validate_config(self, values: Mapping[str, object], *, require_all: bool) -> dict:
        required = ("legal_entity_name", "jurisdiction", "environment", "business_purpose", "cert_chain",
                    "cert_fingerprint", "cert_not_after", "key_custody_ref", "route_whitelist", "limits", "roles")
        unknown = set(values) - set(required) - {"retire_old_at"}
        if unknown:
            raise ValidationError("未知字段: " + ", ".join(sorted(unknown)))
        if require_all:
            missing = [f for f in required if f not in values]
            if missing:
                raise ValidationError("缺少字段: " + ", ".join(missing))
        config = dict(values)
        for key in ("legal_entity_name", "jurisdiction", "environment", "business_purpose",
                    "cert_fingerprint", "cert_not_after", "key_custody_ref"):
            if key in config:
                value = str(config[key]).strip()
                if not value:
                    raise ValidationError(f"{key} 不能为空")
                config[key] = value
        config["cert_not_after"] = canonical_instant(config["cert_not_after"])
        config["cert_chain"] = self._validate_str_list(config["cert_chain"], "证书链", min_len=1)
        config["route_whitelist"] = self._validate_str_list(config["route_whitelist"], "路由白名单", min_len=1)
        config["roles"] = self._validate_str_list(config["roles"], "操作角色", min_len=1)
        limits = config["limits"]
        if not isinstance(limits, dict) or not limits:
            raise ValidationError("限额必须是非空对象")
        config["limits"] = {str(k).strip(): v for k, v in limits.items() if str(k).strip()}
        return config

    def _validate_degrade(self, values: Mapping[str, object], pred: dict) -> dict:
        allowed = {"roles", "route_whitelist", "limits"}
        unknown = set(values) - allowed
        if unknown:
            raise ValidationError("降权只能调整 roles/route_whitelist/limits: " + ", ".join(sorted(unknown)))
        config = self._config_from_row(pred)
        if "roles" in values:
            roles = self._validate_str_list(values["roles"], "操作角色", min_len=0)
            if not set(roles) <= set(pred["roles"]):
                raise ConflictError("降权只能收回角色，不能新增角色")
            config["roles"] = roles
        if "route_whitelist" in values:
            routes = self._validate_str_list(values["route_whitelist"], "路由白名单", min_len=1)
            if not set(routes) <= set(pred["route_whitelist"]):
                raise ConflictError("降权只能收缩路由白名单")
            config["route_whitelist"] = routes
        if "limits" in values:
            limits = values["limits"]
            if not isinstance(limits, dict) or not set(limits) <= set(pred["limits"]):
                raise ConflictError("降权只能下调既有路由限额")
            config["limits"] = {**pred["limits"], **limits}
        reduced = (config["roles"] != pred["roles"] or config["route_whitelist"] != pred["route_whitelist"]
                   or config["limits"] != pred["limits"])
        if not reduced:
            raise ConflictError("降权必须实际收回或收紧至少一项角色/路由/限额")
        return config

    @staticmethod
    def _validate_str_list(value: object, label: str, *, min_len: int) -> list[str]:
        if not isinstance(value, Iterable) or isinstance(value, (str, bytes, dict)):
            raise ValidationError(f"{label}必须是字符串数组")
        items = [str(v).strip() for v in value]
        if any(not v for v in items):
            raise ValidationError(f"{label}不能含空值")
        if len(items) < min_len:
            raise ValidationError(f"{label}至少包含 {min_len} 项")
        return items

    @staticmethod
    def _submit_detail(values: Mapping[str, object], action: str) -> dict:
        detail = {}
        if action == "rotate_overlap" and values.get("retire_old_at"):
            detail["retire_old_at"] = canonical_instant(str(values["retire_old_at"]))
        return detail
