"""命令行入口。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .application import CivicFlow
from .cases import CaseService
from .security import AccessContext


def emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def demo(app: CivicFlow) -> dict:
    context = AccessContext.system("demo-operator")
    cases = CaseService(app.repository)
    created = cases.create(context, {"case_type": "协同事项", "subject": "示例联合处置", "owner_org": "org:demo", "priority": "high", "opened_at": app.clock.now()}, request_key="demo-case")
    accepted = app.inbox.receive(source="demo", source_key=created["entity_id"], sequence=1, payload={"kind": "opened"}, occurred_at=app.clock.now())
    reservation = app.reservations.reserve(resource_id="room:joint", subject_id=created["entity_id"], quantity=2, capacity=10, start_at="2026-09-28T10:00:00+08:00", end_at="2026-09-28T11:00:00+08:00", actor=context.actor_id)
    debit = app.ledger.post(journal_key="demo", account="coordination", currency="CNY", amount="12.34", direction="debit", reference="demo-debit", actor=context.actor_id)
    credit = app.ledger.post(journal_key="demo", account="coordination", currency="CNY", amount="12.34", direction="credit", reference="demo-credit", actor=context.actor_id)
    message = app.outbox.enqueue(topic="case.opened", aggregate_id=created["entity_id"], payload={"case_id": created["entity_id"]})
    return {"case": created, "inbox": accepted, "reservation": reservation, "entries": [debit, credit], "balance": app.ledger.balance("demo", currency="CNY"), "message_id": message, "verification": app.verify()}


def access_demo(db_path: str) -> dict:
    """数字货币桥证书轮换：启用→重叠轮换→停用→降权，全程可时点回放。"""
    applicant = AccessContext(actor_id="person:alice", permissions=frozenset({"submit:access", "admit:access", "read:access"}))
    approver = AccessContext(actor_id="person:bob", permissions=frozenset({"approve:access"}))
    auditor = AccessContext(actor_id="person:carol", permissions=frozenset({"audit:access", "read:access", "history:access"}))

    def open_at(now: str) -> CivicFlow:
        return CivicFlow.open(Path(db_path), fixed_now=now)

    t0 = "2026-10-01T00:00:00Z"
    old_cfg = {
        "legal_entity_name": "海南银行股份有限公司", "jurisdiction": "CN-HI", "environment": "mbridge-prod",
        "business_purpose": "跨境贸易结算", "cert_chain": ["CN=HainanBank-Old", "CN=mBridge-Root"],
        "cert_fingerprint": "sha256:cert-old", "cert_not_after": "2026-10-20T00:00:00Z",
        "key_custody_ref": "hsm:hainan:slot-7", "route_whitelist": ["route:cn-hk", "route:cn-sg"],
        "limits": {"route:cn-hk": 1000000, "route:cn-sg": 500000}, "roles": ["operator", "viewer"],
    }
    g = open_at(t0).governance
    submitted = g.submit(applicant, "enable", old_cfg, effective_from=t0, effective_to="2026-10-20T00:00:00Z", request_key="enable-hnb")
    pid = submitted["participant_id"]
    enabled = g.approve(approver, pid, 1, verdict="approved", reason="首次准入，材料齐备", material_version="M1", request_key="approve-enable")

    req1 = open_at("2026-10-01T01:00:00Z").governance.admit(
        applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-hk", role="operator",
        cert_fingerprint="sha256:cert-old", request_id="req-0001", request_key="admit-req-0001")

    # 重叠轮换：新证 10-15 生效，旧证 10-18 停用，中间为重叠窗口。
    new_cfg = {**old_cfg, "cert_chain": ["CN=HainanBank-New", "CN=mBridge-Root"], "cert_fingerprint": "sha256:cert-new",
               "cert_not_after": "2027-10-20T00:00:00Z", "route_whitelist": ["route:cn-hk", "route:cn-sg", "route:cn-eu"]}
    g10 = open_at("2026-10-10T00:00:00Z").governance
    g10.submit(applicant, "rotate_overlap", {**new_cfg, "retire_old_at": "2026-10-18T00:00:00Z"},
               participant_id=pid, effective_from="2026-10-15T00:00:00Z", request_key="rotate-hnb")
    g10.approve(approver, pid, 2, verdict="approved", reason="年度证书轮换，保留 3 天重叠窗口",
                material_version="M2", request_key="approve-rotate", retire_old_at="2026-10-18T00:00:00Z")

    overlap = open_at("2026-10-16T00:00:00Z").governance.allowed_routes(auditor, pid, at="2026-10-16T00:00:00Z")
    req_old = open_at("2026-10-16T12:00:00Z").governance.admit(
        applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-sg", role="operator",
        cert_fingerprint="sha256:cert-old", request_id="req-0002", request_key="admit-req-0002")
    req_new = open_at("2026-10-17T12:00:00Z").governance.admit(
        applicant, participant_id=pid, environment="mbridge-prod", route="route:cn-eu", role="operator",
        cert_fingerprint="sha256:cert-new", request_id="req-0003", request_key="admit-req-0003")

    # 紧急降权：立即收回 operator，只保留 viewer。
    g19 = open_at("2026-10-19T00:00:00Z").governance
    g19.submit(applicant, "degrade", {"roles": ["viewer"]}, participant_id=pid, request_key="degrade-hnb")
    degraded = g19.approve(approver, pid, 3, verdict="approved", reason="风控事件，紧急收回操作角色",
                           material_version="M3", request_key="approve-degrade")

    # 桥侧回执归并：相同消息一次处理；编号不变指纹变化先隔离。
    bridge = open_at("2026-10-19T01:00:00Z").bridge
    first = bridge.ingest(source="mbridge", source_key="RCPT-1", payload={"settled": "req-0003"}, occurred_at="2026-10-19T00:30:00Z")
    again = bridge.ingest(source="mbridge", source_key="RCPT-1", payload={"settled": "req-0003"}, occurred_at="2026-10-19T00:30:00Z")
    tampered = bridge.ingest(source="mbridge", source_key="RCPT-1", payload={"settled": "req-9999"}, occurred_at="2026-10-19T00:31:00Z")

    audit_overlap = open_at("2026-10-16T00:00:00Z").governance.audit_view(auditor, at="2026-10-16T00:00:00Z")
    audit_now = open_at("2026-10-19T02:00:00Z").governance.audit_view(auditor, at="2026-10-19T02:00:00Z")
    historical = open_at("2026-10-19T02:00:00Z").governance.get_request(auditor, "req-0002")

    return {
        "enabled": enabled, "first_request": req1, "overlap_window": overlap,
        "request_on_old_cert_in_overlap": req_old, "request_on_new_cert": req_new,
        "degraded": degraded,
        "receipt_first": first, "receipt_duplicate": again, "receipt_tampered": tampered,
        "audit_during_overlap": audit_overlap, "audit_after_degrade": audit_now,
        "historical_request_keeps_version": {"request_id": historical["request_id"],
                                             "config_version": historical["config_version"],
                                             "material_version": historical["config_snapshot"]["material_version"],
                                             "roles": historical["config_snapshot"]["roles"]},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="协同事务平台")
    parser.add_argument("--db", default=os.getenv("CIVICFLOW_DB", "civicflow.sqlite3"))
    parser.add_argument("--now", default=None, help="测试或演示使用的固定时间")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo")
    commands.add_parser("access-demo")
    commands.add_parser("verify")
    commands.add_parser("list-cases")
    audit_cmd = commands.add_parser("access-audit")
    audit_cmd.add_argument("--at", required=True, help="指定审计时点（含时区 ISO 8601）")
    audit_cmd.add_argument("--jurisdiction", default=None)
    args = parser.parse_args(argv)
    if args.command == "access-demo":
        emit(access_demo(args.db)); return 0
    app = CivicFlow.open(Path(args.db), fixed_now=args.now)
    if args.command == "demo": emit(demo(app))
    elif args.command == "verify": emit(app.verify())
    elif args.command == "list-cases": emit(CaseService(app.repository).list_current(AccessContext.system("cli")))
    elif args.command == "access-audit":
        auditor = AccessContext.system("cli-auditor")
        emit(app.governance.audit_view(auditor, at=args.at, jurisdiction=args.jurisdiction))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
