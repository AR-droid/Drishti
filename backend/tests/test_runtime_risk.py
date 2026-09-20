from app.models import Action, DataClassification, DecisionReason, Provenance, SecurityDecision
from app.security import EnforcedToolGateway, ToolPolicy
from app.storage import LocalAuditStore


def test_unknown_agent_is_fail_closed_and_risk_is_explainable(tmp_path):
    calls = []
    gateway = EnforcedToolGateway(ToolPolicy(frozenset({"read"}), {"invoicebot": frozenset({"read"})}, frozenset({"invoicebot"})), {"read": lambda _: calls.append(1) or {"ok": True}}, LocalAuditStore(tmp_path / "audit.jsonl"))
    result = gateway.execute(Action("unknown", "read", "read", "invoice", {}, "CURRENT_DOCUMENT", "Read my invoice", Provenance.USER, DataClassification.CONFIDENTIAL))
    assert result.decision is SecurityDecision.BLOCK
    assert DecisionReason.UNAUTHORIZED_AGENT in result.risk_flags
    assert result.executed is False and calls == []


def test_broad_document_chain_flags_deviation_and_never_dispatches(tmp_path):
    calls = []
    gateway = EnforcedToolGateway(ToolPolicy(frozenset({"read", "query"})), {"read": lambda _: {"ok": True}, "query": lambda _: calls.append(1) or {}}, LocalAuditStore(tmp_path / "audit.jsonl"))
    request_id = "chain"
    gateway.execute(Action("agent", "read", "read", "invoice", {}, "CURRENT_DOCUMENT", "Find Acme invoice", Provenance.USER, DataClassification.CONFIDENTIAL, request_id=request_id))
    result = gateway.execute(Action("agent", "query", "query", "customer records", {}, "ALL_CUSTOMERS", "Find Acme invoice", Provenance.DOCUMENT, DataClassification.SENSITIVE, request_id=request_id))
    assert result.decision is SecurityDecision.BLOCK
    assert {DecisionReason.EXCESSIVE_SCOPE, DecisionReason.UNTRUSTED_PROVENANCE, DecisionReason.BEHAVIORAL_DEVIATION} <= set(result.risk_flags)
    assert calls == []
