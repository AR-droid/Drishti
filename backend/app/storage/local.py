"""Append-only local JSONL storage. It is intentionally limited to synthetic data."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from app.models import Action, AttackTrace, SecurityEvent, ToolResult


class LocalAuditStore:
    """Persist tool outcomes on the local filesystem for demo inspection."""

    def __init__(self, path: Path):
        self._path = path

    def record(self, action: Action | ToolResult, result: ToolResult | None = None) -> None:
        """Record a structured security event; one-argument result form is legacy."""
        if result is None:
            result = action  # type: ignore[assignment]
            event = {}
        else:
            assert isinstance(action, Action)
            event = SecurityEvent.from_action_result(action, result).to_dict()
        assert isinstance(result, ToolResult)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        document: dict[str, object] = {
            "status": result.status.value,
            "tool_name": result.tool_name,
            "request_id": result.request_id,
            "data": dict(result.data),
            "reason": result.reason,
        }
        if event:
            # Legacy aliases keep local consumers of the original audit JSONL working.
            document.update({"agent": event["agent_id"], "action": event["operation"], **event})
        with self._path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(document, sort_keys=True) + "\n")

    def read_all(self) -> list[dict[str, object]]:
        if not self._path.exists():
            return []
        with self._path.open(encoding="utf-8") as audit_file:
            return [json.loads(line) for line in audit_file if line.strip()]

    def events_for_request(self, request_id: str) -> list[SecurityEvent]:
        """Retrieve the ordered structured events for one request/attack trace."""
        return [self._event_from_document(item) for item in self.read_all()
                if item.get("request_id") == request_id and "agent_id" in item]

    def get_trace(self, request_id: str) -> AttackTrace:
        """Return an attack trace, including an empty trace for an unknown ID."""
        return AttackTrace(request_id, tuple(self.events_for_request(request_id)))

    @staticmethod
    def _event_from_document(item: dict[str, object]) -> SecurityEvent:
        from app.models import (DataClassification, DecisionReason, Provenance,
                                SecurityDecision, ToolStatus)
        decision = item["decision"]
        return SecurityEvent(
            request_id=str(item["request_id"]), agent_id=str(item["agent_id"]),
            tool=str(item["tool"]), operation=str(item["operation"]),
            resource=str(item["resource"]), scope=str(item["scope"]),
            user_intent=str(item["user_intent"]), provenance=Provenance(str(item["provenance"])),
            data_classification=DataClassification(str(item["data_classification"])),
            destination=item["destination"] if isinstance(item["destination"], str) else None,
            decision=SecurityDecision(str(decision)) if decision is not None else None,
            decision_reasons=tuple(DecisionReason(str(reason)) for reason in item["decision_reasons"]),
            execution_status=ToolStatus(str(item["execution_status"])),
            executed=bool(item["executed"]), risk_score=int(item.get("risk_score", 0)),
            risk_level=str(item.get("risk_level", "LOW")),
            risk_flags=tuple(DecisionReason(str(reason)) for reason in item.get("risk_flags", [])),
            policy_rule=item.get("policy_rule") if isinstance(item.get("policy_rule"), str) else None,
            timestamp=datetime.fromisoformat(str(item["timestamp"])),
            run_id=item.get("run_id") if isinstance(item.get("run_id"), str) else None,
            session_id=item.get("session_id") if isinstance(item.get("session_id"), str) else None,
        )
