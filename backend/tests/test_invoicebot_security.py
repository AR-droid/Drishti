from app.agent import DemoAgent
from app.models import Action, DataClassification, DecisionReason, Provenance, SecurityDecision
from app.security import EnforcedToolGateway, ToolPolicy
from app.storage import LocalAuditStore
from app.tools import build_demo_gateway


def test_legitimate_invoice_flow_is_allowed_and_audited(tmp_path):
    gateway = build_demo_gateway(tmp_path / "audit.jsonl")
    results = DemoAgent(gateway).find_acme_invoice_and_email("verified.user@example.com")

    assert [result.decision for result in results] == [SecurityDecision.ALLOW] * 3
    assert all(result.executed for result in results)
    events = LocalAuditStore(tmp_path / "audit.jsonl").read_all()
    assert [event["provenance"] for event in events] == ["user"] * 3
    assert all(event["executed"] for event in events)


def test_external_email_requires_review_without_adapter_execution(tmp_path):
    executions = 0
    def email(_):
        nonlocal executions
        executions += 1
        return {"sent": True}
    gateway = EnforcedToolGateway(ToolPolicy(frozenset({"send_email"})), {"send_email": email}, LocalAuditStore(tmp_path / "audit.jsonl"))
    result = gateway.execute(Action("invoicebot", "send_email", "send", "invoice", {"to": "outside@example.com"}, "EXTERNAL", "email invoice", Provenance.USER, DataClassification.CONFIDENTIAL, destination="external"))
    assert result.decision is SecurityDecision.REVIEW
    assert result.executed is False
    assert executions == 0


def test_malicious_document_actions_are_blocked_before_adapters(tmp_path):
    database_executions = 0
    email_executions = 0
    def database(_):
        nonlocal database_executions
        database_executions += 1
        return {"customers": []}
    def email(_):
        nonlocal email_executions
        email_executions += 1
        return {"sent": True}
    gateway = EnforcedToolGateway(ToolPolicy(frozenset({"query_customer", "send_email"})), {"query_customer": database, "send_email": email}, LocalAuditStore(tmp_path / "attack.jsonl"))
    agent = DemoAgent(gateway)
    query, send = agent.follow_malicious_invoice_instruction()
    assert query.decision is SecurityDecision.BLOCK
    assert {DecisionReason.EXCESSIVE_SCOPE, DecisionReason.SENSITIVE_DATA, DecisionReason.OUTSIDE_USER_INTENT, DecisionReason.UNTRUSTED_PROVENANCE} <= set(query.decision_reasons)
    assert send.decision is SecurityDecision.BLOCK
    assert database_executions == 0
    assert email_executions == 0
