from collections.abc import Mapping

from app.agent import DemoAgent
from app.models import (Action, DataClassification, Provenance, SecurityDecision,
                        ToolStatus)
from app.security import EnforcedToolGateway, ToolPolicy
from app.storage import LocalAuditStore


def test_events_with_one_request_id_form_a_typed_trace(tmp_path):
    store = LocalAuditStore(tmp_path / "trace.jsonl")
    gateway = EnforcedToolGateway(
        ToolPolicy(frozenset({"safe"})), {"safe": lambda _: {"ok": True}}, store
    )
    action = Action("agent-1", "safe", "read", "invoice", {}, "CURRENT_DOCUMENT",
                    "Read my invoice", Provenance.USER, DataClassification.CONFIDENTIAL,
                    request_id="trace-1")

    gateway.execute(action)
    trace = store.get_trace("trace-1")

    assert trace.request_id == "trace-1"
    assert len(trace.events) == 1
    event = trace.events[0]
    assert (event.agent_id, event.tool, event.operation) == ("agent-1", "safe", "read")
    assert event.execution_status is ToolStatus.SUCCEEDED
    assert event.executed is True


def test_malicious_invoicebot_trace_is_blocked_without_tool_execution(tmp_path):
    class Adapter:
        def __init__(self):
            self.calls: list[Mapping[str, object]] = []

        def __call__(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
            self.calls.append(arguments)
            return {"unexpected": True}

    adapter = Adapter()
    store = LocalAuditStore(tmp_path / "attack.jsonl")
    gateway = EnforcedToolGateway(ToolPolicy(frozenset({"query_customer", "send_email"})),
                                  {"query_customer": adapter, "send_email": adapter}, store)

    results = DemoAgent(gateway).follow_malicious_invoice_instruction()
    trace = store.get_trace(results[0].request_id)

    assert [event.decision for event in trace.events] == [SecurityDecision.BLOCK] * 2
    assert all(event.provenance is Provenance.DOCUMENT for event in trace.events)
    assert all(event.executed is False for event in trace.events)
    assert all(event.execution_status is ToolStatus.DENIED for event in trace.events)
    assert adapter.calls == []
