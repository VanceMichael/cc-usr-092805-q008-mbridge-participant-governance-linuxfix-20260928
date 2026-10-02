from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from civicflow.application import CivicFlow
from civicflow.errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from civicflow.security import AccessContext


def cfg(**overrides) -> dict:
    base = {
        "legal_entity_name": "海南银行股份有限公司", "jurisdiction": "CN-HI", "environment": "mbridge-prod",
        "business_purpose": "跨境贸易结算", "cert_chain": ["CN=HainanBank", "CN=mBridge-Root"],
        "cert_fingerprint": "sha256:cert-old", "cert_not_after": "2026-10-20T00:00:00Z",
        "key_custody_ref": "hsm:hainan:slot-7", "route_whitelist": ["route:cn-hk", "route:cn-sg"],
        "limits": {"route:cn-hk": 1000000, "route:cn-sg": 500000}, "roles": ["operator", "viewer"],
    }
    base.update(overrides)
    return base


class ParticipantGovernanceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp.name) / "gov.sqlite3")
        self.applicant = AccessContext(actor_id="person:alice",
                                       permissions=frozenset({"submit:access", "admit:access", "read:access"}))
        self.approver = AccessContext(actor_id="person:bob", permissions=frozenset({"approve:access"}))
        self.auditor = AccessContext(actor_id="person:carol",
                                     permissions=frozenset({"audit:access", "read:access", "history:access"}))
        self.reader = AccessContext(actor_id="person:dora", permissions=frozenset({"read:access"}))

    def tearDown(self):
        self.temp.cleanup()

    def open(self, now: str) -> CivicFlow:
        return CivicFlow.open(self.db, fixed_now=now)

    def enable(self, now="2026-10-01T00:00:00Z", eff_to="2026-10-20T00:00:00Z", rk="enable"):
        g = self.open(now).governance
        sub = g.submit(self.applicant, "enable", cfg(), effective_from=now, effective_to=eff_to, request_key=rk)
        g.approve(self.approver, sub["participant_id"], 1, verdict="approved", reason="首次准入",
                  material_version="M1", request_key=rk + "-ok")
        return sub["participant_id"]

    # -------------------------------------------------- 职责分离 / 存在隐藏

    def test_applicant_cannot_approve_own(self):
        g = self.open("2026-10-01T00:00:00Z").governance
        sub = g.submit(self.applicant, "enable", cfg(), effective_from="2026-10-01T00:00:00Z", request_key="e")
        with self.assertRaises(PermissionDenied):
            g.approve(self.applicant, sub["participant_id"], 1, verdict="approved", reason="x",
                      material_version="M1", request_key="e-ok")

    def test_pending_participant_is_indistinguishable_from_missing(self):
        g = self.open("2026-10-01T00:00:00Z").governance
        sub = g.submit(self.applicant, "enable", cfg(), request_key="e")
        # 有 read 权限但无历史/审计权限者：未获准与不存在都返回相同错误。
        with self.assertRaises(NotFoundError):
            g.get_participant(self.reader, sub["participant_id"])
        with self.assertRaises(NotFoundError):
            g.get_participant(self.reader, "participant:does-not-exist")
        # 准入接口同样不泄露。
        with self.assertRaises(NotFoundError):
            g.admit(self.applicant, participant_id=sub["participant_id"], environment="mbridge-prod",
                    route="route:cn-hk", role="operator", cert_fingerprint="sha256:cert-old",
                    request_id="r1", request_key="a1")

    # -------------------------------------------------- 生效区间 / 未来与过期

    def test_request_rejected_before_effective_and_after_expiry(self):
        pid = self.enable()
        # 使用尚未生效的未来新证书 → 拒绝。
        g = self.open("2026-10-02T00:00:00Z").governance
        with self.assertRaises(NotFoundError):
            g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk",
                    role="operator", cert_fingerprint="sha256:cert-future", request_id="rf", request_key="af")
        # 超过旧版本有效期 → 拒绝。
        g = self.open("2026-10-20T00:00:00Z").governance
        with self.assertRaises(NotFoundError):
            g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk",
                    role="operator", cert_fingerprint="sha256:cert-old", request_id="re", request_key="ae")

    def test_route_and_role_must_match_version(self):
        pid = self.enable()
        g = self.open("2026-10-02T00:00:00Z").governance
        with self.assertRaises(PermissionDenied):
            g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-eu",
                    role="operator", cert_fingerprint="sha256:cert-old", request_id="r2", request_key="a2")
        with self.assertRaises(PermissionDenied):
            g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk",
                    role="admin", cert_fingerprint="sha256:cert-old", request_id="r3", request_key="a3")

    # -------------------------------------------------- 重叠轮换

    def test_overlap_rotation_allows_both_certs_then_only_new(self):
        pid = self.enable()
        new_cfg = cfg(cert_chain=["CN=HainanBank-New", "CN=mBridge-Root"], cert_fingerprint="sha256:cert-new",
                      cert_not_after="2027-10-20T00:00:00Z",
                      route_whitelist=["route:cn-hk", "route:cn-sg", "route:cn-eu"])
        g = self.open("2026-10-10T00:00:00Z").governance
        g.submit(self.applicant, "rotate_overlap", {**new_cfg, "retire_old_at": "2026-10-18T00:00:00Z"},
                 participant_id=pid, effective_from="2026-10-15T00:00:00Z", request_key="rot")
        g.approve(self.approver, pid, 2, verdict="approved", reason="年度轮换，三天重叠",
                  material_version="M2", request_key="rot-ok", retire_old_at="2026-10-18T00:00:00Z")

        # 新证生效前：只能用旧证。
        g = self.open("2026-10-14T00:00:00Z").governance
        with self.assertRaises(NotFoundError):
            g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-eu",
                    role="operator", cert_fingerprint="sha256:cert-new", request_id="n0", request_key="an0")

        # 重叠窗口：可恢复任务把新证推进为 active，旧证在停用前仍保持 active。
        g_app = self.open("2026-10-16T00:00:00Z")
        g_app.governance.run_due_tasks(limit=50)
        g = g_app.governance
        hist = {v["config_version"]: v["status"] for v in g.history(self.auditor, pid)}
        self.assertEqual(hist, {1: "active", 2: "active"})
        allowed = g.allowed_routes(self.auditor, pid, at="2026-10-16T00:00:00Z")
        self.assertEqual(allowed["effective_versions"], [1, 2])
        self.assertEqual(set(allowed["routes"]), {"route:cn-hk", "route:cn-sg", "route:cn-eu"})
        old = g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-sg",
                      role="operator", cert_fingerprint="sha256:cert-old", request_id="ro", request_key="aro")
        new = g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-eu",
                      role="operator", cert_fingerprint="sha256:cert-new", request_id="rn", request_key="arn")
        self.assertEqual((old["config_version"], new["config_version"]), (1, 2))

        # 旧证停用后：旧证拒绝，仅新证可用。
        g = self.open("2026-10-18T01:00:00Z").governance
        with self.assertRaises(NotFoundError):
            g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-sg",
                    role="operator", cert_fingerprint="sha256:cert-old", request_id="rx", request_key="arx")
        still = g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-eu",
                        role="operator", cert_fingerprint="sha256:cert-new", request_id="ry", request_key="ary")
        self.assertEqual(still["config_version"], 2)

    # -------------------------------------------------- 紧急降权收权

    def test_degrade_revokes_operational_role_immediately(self):
        pid = self.enable()
        g = self.open("2026-10-05T00:00:00Z").governance
        g.submit(self.applicant, "degrade", {"roles": ["viewer"]}, participant_id=pid, request_key="deg")
        g.approve(self.approver, pid, 2, verdict="approved", reason="风控事件，收回操作角色",
                  material_version="M3", request_key="deg-ok")
        g = self.open("2026-10-05T00:00:01Z").governance
        with self.assertRaises(PermissionDenied):
            g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk",
                    role="operator", cert_fingerprint="sha256:cert-old", request_id="rd", request_key="ard")
        # viewer 仍然允许。
        ok = g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk",
                     role="viewer", cert_fingerprint="sha256:cert-old", request_id="rv", request_key="arv")
        self.assertEqual(ok["config_version"], 2)
        # 降权不能新增角色或路由，也不能维持原状。
        with self.assertRaises(ConflictError):
            g.submit(self.applicant, "degrade", {"roles": ["viewer", "operator"]}, participant_id=pid, request_key="deg2")
        with self.assertRaises(ConflictError):
            g.submit(self.applicant, "degrade", {"roles": ["viewer"]}, participant_id=pid, request_key="deg3")

    # -------------------------------------------------- 吊销

    def test_revoke_stops_all_requests(self):
        pid = self.enable()
        g = self.open("2026-10-06T00:00:00Z").governance
        g.submit(self.applicant, "revoke", {}, participant_id=pid, request_key="rev")
        g.approve(self.approver, pid, 2, verdict="approved", reason="密钥泄露", material_version="M5", request_key="rev-ok")
        g = self.open("2026-10-06T00:00:01Z").governance
        with self.assertRaises(NotFoundError):
            g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk",
                    role="viewer", cert_fingerprint="sha256:cert-old", request_id="rr", request_key="arr")
        view = g.audit_view(self.auditor, at="2026-10-06T00:00:01Z")
        self.assertEqual([v for v in view if v["participant_id"] == pid], [])

    # -------------------------------------------------- 历史版本固化 / 幂等

    def test_completed_request_keeps_its_version_and_is_idempotent(self):
        pid = self.enable()
        g = self.open("2026-10-02T00:00:00Z").governance
        a1 = g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk",
                     role="operator", cert_fingerprint="sha256:cert-old", request_id="hist-1", request_key="h1")
        a2 = g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk",
                     role="operator", cert_fingerprint="sha256:cert-old", request_id="hist-1", request_key="h1")
        self.assertEqual(a1, a2)
        # 之后降权。
        g.submit(self.applicant, "degrade", {"roles": ["viewer"]}, participant_id=pid, request_key="d")
        g.approve(self.approver, pid, 2, verdict="approved", reason="x", material_version="M9", request_key="d-ok")
        # 历史请求仍引用当时版本（v1、operator、M1）。
        record = self.open("2026-10-03T00:00:00Z").governance.get_request(self.auditor, "hist-1")
        self.assertEqual(record["config_version"], 1)
        self.assertEqual(record["config_snapshot"]["roles"], ["operator", "viewer"])
        self.assertEqual(record["config_snapshot"]["material_version"], "M1")
        self.assertEqual(record["config_snapshot"]["decision_id"], a1["decision_id"])

    # -------------------------------------------------- 续期

    def test_renew_after_old_expiry(self):
        pid = self.enable()
        renewed = cfg(cert_fingerprint="sha256:cert-renew", cert_not_after="2027-10-20T00:00:00Z")
        g = self.open("2026-10-19T00:00:00Z").governance
        g.submit(self.applicant, "renew", renewed, participant_id=pid, effective_from="2026-10-20T00:00:00Z", request_key="ren")
        g.approve(self.approver, pid, 2, verdict="approved", reason="到期续期", material_version="M6", request_key="ren-ok")
        g = self.open("2026-10-20T00:00:00Z").governance
        admitted = g.admit(self.applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk",
                           role="operator", cert_fingerprint="sha256:cert-renew", request_id="rren", request_key="aren")
        self.assertEqual(admitted["config_version"], 2)

    # -------------------------------------------------- 时点审计视图

    def test_audit_view_lists_allowed_with_approver_and_material(self):
        pid = self.enable()
        view = self.open("2026-10-02T00:00:00Z").governance.audit_view(self.auditor, at="2026-10-02T00:00:00Z")
        entry = next(v for v in view if v["participant_id"] == pid)
        self.assertEqual(entry["approved_by"], "person:bob")
        self.assertEqual(entry["material_version"], "M1")
        self.assertIn("route:cn-hk", entry["route_whitelist"])
        decisions = self.open("2026-10-02T00:00:00Z").governance.list_decisions(self.auditor, pid)
        self.assertEqual([d["action"] for d in decisions], ["enable"])

    # -------------------------------------------------- 可恢复任务

    def test_due_tasks_advance_and_notify_and_review_reschedules(self):
        pid = self.enable(now="2026-10-01T00:00:00Z", eff_to="2026-10-20T00:00:00Z")
        app = self.open("2026-10-20T00:00:00Z")
        done = app.governance.run_due_tasks(limit=50)
        types = {d["job_type"] for d in done}
        self.assertIn("access.cert_expired", types)
        self.assertIn("access.version_retire", types)
        # 任务执行产生通知。
        leased = app.outbox.lease(owner="w", limit=50)
        self.assertTrue(any(m["topic"].startswith("access.") for m in leased))
        # 定期复核已排期（生效 +180 天），初始为等待态。
        with app.database.connect() as conn:
            review_rows = conn.execute(
                "SELECT * FROM scheduled_jobs WHERE job_type='access.periodic_review' AND status='waiting'").fetchall()
        self.assertEqual(len(review_rows), 1)
        self.assertEqual(review_rows[0]["subject_id"], pid)
        # 复核到期执行后自动续排下一轮。
        future = self.open("2027-04-15T00:00:00Z")
        future.governance.run_due_tasks(limit=50)
        with future.database.connect() as conn:
            rows = conn.execute(
                "SELECT COUNT(*) AS n FROM scheduled_jobs WHERE job_type='access.periodic_review' AND status='waiting'").fetchone()
        self.assertGreaterEqual(rows["n"], 1)


class BridgeReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = CivicFlow.open(str(Path(self.temp.name) / "bridge.sqlite3"), fixed_now="2026-10-19T00:00:00Z")
        self.investigator = AccessContext(actor_id="person:bob", permissions=frozenset({"resolve:bridge"}))

    def tearDown(self):
        self.temp.cleanup()

    def test_identical_message_processed_once(self):
        first = self.app.bridge.ingest(source="mbridge", source_key="R1", payload={"ok": True},
                                       occurred_at="2026-10-19T00:00:00Z")
        second = self.app.bridge.ingest(source="mbridge", source_key="R1", payload={"ok": True},
                                        occurred_at="2026-10-19T00:00:00Z")
        self.assertEqual(first["status"], "accepted")
        self.assertEqual(second["status"], "duplicate")
        processed = self.app.bridge.mark_processed(source="mbridge", source_key="R1")
        self.assertEqual(processed["status"], "processed")
        again = self.app.bridge.mark_processed(source="mbridge", source_key="R1")
        self.assertEqual(again["status"], "duplicate")

    def test_same_key_changed_fingerprint_is_quarantined(self):
        self.app.bridge.ingest(source="mbridge", source_key="R2", payload={"settled": "a"},
                               occurred_at="2026-10-19T00:00:00Z")
        result = self.app.bridge.ingest(source="mbridge", source_key="R2", payload={"settled": "b"},
                                        occurred_at="2026-10-19T00:01:00Z")
        self.assertEqual(result["status"], "quarantined")
        # 存在未结隔离时，原回执不能继续处理。
        with self.assertRaises(ConflictError):
            self.app.bridge.mark_processed(source="mbridge", source_key="R2")
        pending = self.app.bridge.list_quarantine()
        self.assertEqual(len(pending), 1)
        # 发出异常回执提醒（通知 + 可恢复调查任务）。
        msgs = self.app.outbox.lease(owner="w", limit=10)
        self.assertTrue(any(m["topic"] == "bridge.receipt_conflict" for m in msgs))
        jobs = self.app.jobs.claim_due(job_type="access.receipt_investigation")
        self.assertEqual(len(jobs), 1)
        # 调查后丢弃异常内容，原回执恢复。
        resolved = self.app.bridge.resolve_quarantine(self.investigator, result["quarantine_id"],
                                                      verdict="discard", note="疑似重放伪造，保留原件")
        self.assertEqual(resolved["verdict"], "discard")
        self.assertEqual(self.app.bridge.get("mbridge", "R2")["status"], "accepted")
        with self.assertRaises(ConflictError):
            self.app.bridge.resolve_quarantine(self.investigator, result["quarantine_id"],
                                               verdict="discard", note="重复处置")


if __name__ == "__main__":
    unittest.main()
