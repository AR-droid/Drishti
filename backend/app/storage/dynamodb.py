"""DynamoDB audit store used only when DRISHTI_STORAGE_BACKEND=dynamodb.

The policy engine remains in-process and records its decision *after* enforcement;
this store is persistence, not an authorization path.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.models import Action, AttackTrace, DataClassification, DecisionReason, Provenance, SecurityDecision, SecurityEvent, ToolResult, ToolStatus


class DynamoDBAuditStore:
    """Persist audit events and retrieve a trace by its partition key."""

    def __init__(self, *, security_events_table: str, attack_traces_table: str,
                 actions_table: str, dynamodb_resource: Any | None = None):
        if dynamodb_resource is None:
            import boto3  # Imported lazily so local development needs no AWS SDK.
            dynamodb_resource = boto3.resource("dynamodb")
        self._events = dynamodb_resource.Table(security_events_table)
        self._traces = dynamodb_resource.Table(attack_traces_table)
        self._actions = dynamodb_resource.Table(actions_table)

    def record(self, action: Action | ToolResult, result: ToolResult | None = None) -> None:
        """Write one enforced outcome; legacy result-only calls have no action data."""
        if result is None:
            return
        assert isinstance(action, Action)
        event = SecurityEvent.from_action_result(action, result)
        document = event.to_dict()
        timestamp = event.timestamp.astimezone(UTC).isoformat()
        self._events.put_item(Item={"event_id": str(uuid4()), "request_id": event.request_id,
                                    "event_timestamp": timestamp, **document})
        # This table deliberately uses request_id as its partition key for GetTrace.
        self._traces.put_item(Item={"request_id": event.request_id, "event_timestamp": timestamp,
                                    **document})
        self._actions.put_item(Item={"request_id": event.request_id, "action_timestamp": timestamp,
                                     "action_id": str(uuid4()), **document})

    def get_trace(self, request_id: str) -> AttackTrace:
        response = self._traces.query(
            KeyConditionExpression=self._key_condition(request_id), ScanIndexForward=True
        )
        return AttackTrace(request_id, tuple(self._event_from_document(item) for item in response["Items"]))

    @staticmethod
    def _key_condition(request_id: str) -> Any:
        from boto3.dynamodb.conditions import Key
        return Key("request_id").eq(request_id)

    @staticmethod
    def _event_from_document(item: dict[str, Any]) -> SecurityEvent:
        decision = item["decision"]
        return SecurityEvent(
            request_id=item["request_id"], agent_id=item["agent_id"], tool=item["tool"],
            operation=item["operation"], resource=item["resource"], scope=item["scope"],
            user_intent=item["user_intent"], provenance=Provenance(item["provenance"]),
            data_classification=DataClassification(item["data_classification"]), destination=item.get("destination"),
            decision=SecurityDecision(decision) if decision else None,
            decision_reasons=tuple(DecisionReason(reason) for reason in item["decision_reasons"]),
            execution_status=ToolStatus(item["execution_status"]), executed=bool(item["executed"]),
            timestamp=datetime.fromisoformat(item["timestamp"]),
        )
