"""Append-only local JSONL storage. It is intentionally limited to synthetic data."""

from __future__ import annotations

import json
from pathlib import Path

from app.models import Action, ToolResult


class LocalAuditStore:
    """Persist tool outcomes on the local filesystem for demo inspection."""

    def __init__(self, path: Path):
        self._path = path

    def record(self, action: Action | ToolResult, result: ToolResult | None = None) -> None:
        """Record a security event; one-argument result form remains compatible."""
        if result is None:
            result = action  # type: ignore[assignment]
            event = {}
        else:
            assert isinstance(action, Action)
            event = {
                "agent": action.agent_id, "action": action.operation, "resource": action.resource,
                "scope": action.scope, "provenance": action.provenance.value,
                "data_classification": action.data_classification.value,
                "destination": action.destination, "user_intent": action.user_intent,
                "timestamp": action.timestamp.isoformat(),
            }
        assert isinstance(result, ToolResult)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "status": result.status.value,
            "tool_name": result.tool_name,
            "request_id": result.request_id,
            "data": dict(result.data),
            "reason": result.reason,
        }
        if event:
            document.update({"decision": result.decision.value if result.decision else None, "decision_reasons": [reason.value for reason in result.decision_reasons], "executed": result.executed, **event})
        with self._path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(document, sort_keys=True) + "\n")

    def read_all(self) -> list[dict[str, object]]:
        if not self._path.exists():
            return []
        with self._path.open(encoding="utf-8") as audit_file:
            return [json.loads(line) for line in audit_file if line.strip()]
