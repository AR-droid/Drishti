from app.models import Action, DataClassification, Provenance, ToolCall, ToolStatus
from app.tools import build_demo_gateway


def test_gateway_executes_only_registered_synthetic_tool(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    gateway = build_demo_gateway(audit_path)

    result = gateway.execute(
        ToolCall("customer.lookup", {"query": "Aurora"}, actor_id="demo-user", request_id="request-1")
    )

    assert result.status is ToolStatus.SUCCEEDED
    assert result.data["customer"]["name"] == "Aurora Labs"
    assert '"tool_name": "customer.lookup"' in audit_path.read_text(encoding="utf-8")


def test_gateway_denies_unknown_tool_before_any_adapter_dispatch(tmp_path):
    gateway = build_demo_gateway(tmp_path / "audit.jsonl")

    result = gateway.execute(ToolCall("system.shell", {}, actor_id="demo-user", request_id="request-2"))

    assert result.status is ToolStatus.DENIED
    assert result.reason == "Tool 'system.shell' is not registered."


def test_gateway_enforces_per_actor_permissions(tmp_path):
    gateway = build_demo_gateway(tmp_path / "audit.jsonl")

    result = gateway.execute(ToolCall("tasks.list", {}, actor_id="readonly-demo", request_id="request-3"))

    assert result.status is ToolStatus.DENIED
    assert "not permitted" in (result.reason or "")


def test_review_never_calls_adapter_until_explicit_approval(tmp_path):
    gateway = build_demo_gateway(tmp_path / "audit.jsonl")
    action = Action("invoicebot", "send_email", "send", "invoice", {"to": "external@example.com"},
                    "VERIFIED_USER", "Email my invoice", Provenance.USER,
                    DataClassification.CONFIDENTIAL, destination="external", request_id="review-1")

    pending = gateway.execute(action)

    assert pending.decision.value == "review"
    assert pending.executed is False
    approved = gateway.approve("review-1")
    assert approved.executed is True
    assert approved.data["sent"] is True


def test_authorize_never_dispatches_a_native_agent_tool_and_preserves_run_trace(tmp_path):
    from app.models import SecurityDecision
    calls: list[object] = []

    def adapter(arguments):
        calls.append(arguments)
        return {"should_not": "run"}

    from app.security import EnforcedToolGateway, ToolPolicy
    from app.storage import LocalAuditStore
    gateway = EnforcedToolGateway(
        ToolPolicy(frozenset({"query_customer"}), {"openclaw-local": frozenset({"query_customer"})}, frozenset({"openclaw-local"})),
        {"query_customer": adapter}, LocalAuditStore(tmp_path / "audit.jsonl"),
    )
    action = Action("openclaw-local", "query_customer", "query", "customer_records", {"scope": "ALL_CUSTOMERS"}, "ALL_CUSTOMERS", "Find Acme invoice", Provenance.DOCUMENT, DataClassification.SENSITIVE, request_id="openclaw-block", run_id="run-1", session_id="session-1")

    result = gateway.authorize(action)

    assert result.decision is SecurityDecision.BLOCK
    assert result.executed is False
    assert calls == []
    event = LocalAuditStore(tmp_path / "audit.jsonl").get_trace("openclaw-block").events[0]
    assert event.run_id == "run-1" and event.session_id == "session-1"
