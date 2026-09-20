from app.models import ToolResult, ToolStatus
from app.storage import LocalAuditStore


def test_local_audit_store_returns_empty_history_before_first_write(tmp_path):
    store = LocalAuditStore(tmp_path / "nested" / "audit.jsonl")

    assert store.read_all() == []


def test_local_audit_store_persists_synthetic_result(tmp_path):
    store = LocalAuditStore(tmp_path / "audit.jsonl")
    store.record(ToolResult(ToolStatus.SUCCEEDED, "tasks.list", "request-6", data={"source": "synthetic"}))

    assert store.read_all() == [
        {
            "data": {"source": "synthetic"},
            "reason": None,
            "request_id": "request-6",
            "status": "succeeded",
            "tool_name": "tasks.list",
        }
    ]
