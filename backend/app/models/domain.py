"""Typed, framework-independent security domain types."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Mapping
from uuid import uuid4


class Provenance(StrEnum):
    USER = "user"
    SYSTEM = "system"
    AGENT = "agent"
    DOCUMENT = "document"
    WEBPAGE = "webpage"
    EMAIL = "email"
    TOOL_RESULT = "tool_result"
    MCP_TOOL_DESCRIPTION = "mcp_tool_description"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"


class SecurityDecision(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class DecisionReason(StrEnum):
    EXCESSIVE_SCOPE = "EXCESSIVE_SCOPE"
    SENSITIVE_DATA = "SENSITIVE_DATA"
    OUTSIDE_USER_INTENT = "OUTSIDE_USER_INTENT"
    UNTRUSTED_PROVENANCE = "UNTRUSTED_PROVENANCE"
    UNAUTHORIZED_AGENT = "UNAUTHORIZED_AGENT"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    DESTRUCTIVE_OPERATION = "DESTRUCTIVE_OPERATION"
    UNVERIFIED_DESTINATION = "UNVERIFIED_DESTINATION"
    BEHAVIORAL_DEVIATION = "BEHAVIORAL_DEVIATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    RISKY_ACTION_CHAIN = "RISKY_ACTION_CHAIN"


class ToolStatus(StrEnum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"  # Kept for callers using the original ToolCall API.
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """An immutable, security-relevant outcome of one DRISHTI action.

    Events are keyed by ``request_id``.  A caller may deliberately reuse that ID
    across related actions, making the resulting ordered events an attack trace.
    """

    request_id: str
    agent_id: str
    tool: str
    operation: str
    resource: str
    scope: str
    user_intent: str
    provenance: Provenance
    data_classification: DataClassification
    destination: str | None
    decision: SecurityDecision | None
    decision_reasons: tuple[DecisionReason, ...]
    execution_status: ToolStatus
    executed: bool
    timestamp: datetime
    risk_score: int = 0
    risk_level: str = "LOW"
    risk_flags: tuple[DecisionReason, ...] = ()
    policy_rule: str | None = None

    @classmethod
    def from_action_result(cls, action: Action, result: ToolResult) -> SecurityEvent:
        """Create the canonical audit record at the enforcement boundary."""
        return cls(
            request_id=action.request_id, agent_id=action.agent_id, tool=action.tool,
            operation=action.operation, resource=action.resource, scope=action.scope,
            user_intent=action.user_intent, provenance=action.provenance,
            data_classification=action.data_classification, destination=action.destination,
            decision=result.decision, decision_reasons=result.decision_reasons,
            execution_status=result.status, executed=result.executed, risk_score=result.risk_score,
            risk_level=result.risk_level, risk_flags=result.risk_flags, policy_rule=result.policy_rule,
            timestamp=action.timestamp,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-safe, stable names for the local append-only audit store."""
        return {
            "request_id": self.request_id, "agent_id": self.agent_id, "tool": self.tool,
            "operation": self.operation, "resource": self.resource, "scope": self.scope,
            "user_intent": self.user_intent, "provenance": self.provenance.value,
            "data_classification": self.data_classification.value,
            "destination": self.destination,
            "decision": self.decision.value if self.decision else None,
            "decision_reasons": [reason.value for reason in self.decision_reasons],
            "execution_status": self.execution_status.value, "executed": self.executed,
            "risk_score": self.risk_score, "risk_level": self.risk_level,
            "risk_flags": [flag.value for flag in self.risk_flags], "policy_rule": self.policy_rule,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class AttackTrace:
    """The ordered security events belonging to one request/trace ID."""

    request_id: str
    events: tuple[SecurityEvent, ...]


@dataclass(frozen=True, slots=True)
class Action:
    """The complete security-relevant request evaluated by DRISHTI.

    Instructions from non-user sources are represented explicitly as provenance;
    they are data and never inherit authority from the authenticated user.
    """

    agent_id: str
    tool: str
    operation: str
    resource: str
    arguments: Mapping[str, Any]
    scope: str
    user_intent: str
    provenance: Provenance
    data_classification: DataClassification
    destination: str | None = None
    request_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        for name in ("agent_id", "tool", "operation", "resource", "scope", "user_intent", "request_id"):
            if not getattr(self, name) or not isinstance(getattr(self, name), str):
                raise ValueError(f"Action.{name} must be a non-empty string")
        if not isinstance(self.provenance, Provenance) or not isinstance(self.data_classification, DataClassification):
            raise ValueError("Action provenance and data_classification must be typed enums")


@dataclass(frozen=True, slots=True)
class ToolCall:
    """Legacy agent request. New integrations should submit :class:`Action`."""
    tool_name: str
    arguments: Mapping[str, Any]
    actor_id: str
    request_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_action(self) -> Action:
        """Use conservative legacy defaults without dropping provenance metadata."""
        return Action(self.actor_id, self.tool_name, self.tool_name, self.tool_name, self.arguments,
                      "CURRENT_CUSTOMER", "legacy local demo request", Provenance.USER,
                      DataClassification.INTERNAL, request_id=self.request_id, timestamp=self.created_at)


@dataclass(frozen=True, slots=True)
class ToolResult:
    status: ToolStatus
    tool_name: str
    request_id: str
    data: Mapping[str, Any] = field(default_factory=dict)
    reason: str | None = None
    decision: SecurityDecision | None = None
    decision_reasons: tuple[DecisionReason, ...] = ()
    executed: bool = False
    risk_score: int = 0
    risk_level: str = "LOW"
    risk_flags: tuple[DecisionReason, ...] = ()
    policy_rule: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is ToolStatus.SUCCEEDED


@dataclass(frozen=True, slots=True)
class AgentReply:
    message: str
    tool_result: ToolResult
