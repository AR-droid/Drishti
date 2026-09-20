"""The single, policy-enforced boundary for agent initiated tool actions.

Tool adapters are deliberately kept behind :class:`ToolRegistry`.  Callers cannot
obtain an adapter from the registry; only this module can dispatch an allowed
action to one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Protocol
from uuid import uuid4


class Decision(str, Enum):
    """The only possible outcomes of evaluating a requested action."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class ToolActionRequest:
    """A typed, immutable description of an action requested by an agent."""

    tool: str
    action: str
    actor_id: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid4()))


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    decision: Decision
    reason: str


@dataclass(frozen=True, slots=True)
class RiskEvaluation:
    decision: Decision
    reason: str


@dataclass(frozen=True, slots=True)
class AuditEvent:
    request_id: str
    actor_id: str
    tool: str
    action: str
    decision: Decision
    policy_reason: str
    risk_reason: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class PendingApproval:
    request: ToolActionRequest
    policy_reason: str
    risk_reason: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class EnforcementResult:
    """The decision, trace event, and optional output from a dispatched tool."""

    decision: Decision
    trace_event: AuditEvent
    output: Any | None = None
    pending_approval: PendingApproval | None = None


class PolicyEvaluator(Protocol):
    def evaluate(self, request: ToolActionRequest) -> PolicyEvaluation: ...


class RiskEvaluator(Protocol):
    def evaluate(self, request: ToolActionRequest) -> RiskEvaluation: ...


class AuditLog(Protocol):
    def record(self, event: AuditEvent) -> None: ...


class ApprovalStore(Protocol):
    def create(self, approval: PendingApproval) -> None: ...


class ToolAdapter(Protocol):
    def execute(self, request: ToolActionRequest) -> Any: ...


class DeterministicPolicyEvaluator:
    """Policy evaluator driven by a stable ``tool.action -> decision`` mapping."""

    def __init__(self, rules: Mapping[str, Decision] | None = None) -> None:
        self._rules = dict(rules or {})

    def evaluate(self, request: ToolActionRequest) -> PolicyEvaluation:
        decision = self._rules.get(f"{request.tool}.{request.action}", Decision.ALLOW)
        return PolicyEvaluation(decision, f"policy rule resolved to {decision.value}")


class DeterministicRiskEvaluator:
    """Risk evaluator driven by a stable ``tool.action -> decision`` mapping."""

    def __init__(self, rules: Mapping[str, Decision] | None = None) -> None:
        self._rules = dict(rules or {})

    def evaluate(self, request: ToolActionRequest) -> RiskEvaluation:
        decision = self._rules.get(f"{request.tool}.{request.action}", Decision.ALLOW)
        return RiskEvaluation(decision, f"risk rule resolved to {decision.value}")


class InMemoryAuditLog:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class InMemoryApprovalStore:
    def __init__(self) -> None:
        self.pending: list[PendingApproval] = []

    def create(self, approval: PendingApproval) -> None:
        self.pending.append(approval)


class ToolRegistry:
    """A guarded adapter registry; adapters are never exposed to callers."""

    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, tool: str, adapter: ToolAdapter) -> None:
        if not tool:
            raise ValueError("tool name must not be empty")
        self._adapters[tool] = adapter

    def dispatch_allowed(self, request: ToolActionRequest) -> Any:
        """Dispatch an action after enforcement has made the ALLOW decision."""
        try:
            adapter = self._adapters[request.tool]
        except KeyError as error:
            raise LookupError(f"no adapter registered for tool {request.tool!r}") from error
        return adapter.execute(request)


class EnforcementService:
    """Evaluate, trace, and (only when allowed) dispatch tool actions."""

    def __init__(
        self,
        policy_evaluator: PolicyEvaluator,
        risk_evaluator: RiskEvaluator,
        audit_log: AuditLog,
        approval_store: ApprovalStore,
        tool_registry: ToolRegistry,
    ) -> None:
        self._policy_evaluator = policy_evaluator
        self._risk_evaluator = risk_evaluator
        self._audit_log = audit_log
        self._approval_store = approval_store
        self._tool_registry = tool_registry

    def enforce(self, request: ToolActionRequest) -> EnforcementResult:
        policy = self._policy_evaluator.evaluate(request)
        risk = self._risk_evaluator.evaluate(request)
        decision = _combine_decisions(policy.decision, risk.decision)
        trace = AuditEvent(
            request_id=request.request_id,
            actor_id=request.actor_id,
            tool=request.tool,
            action=request.action,
            decision=decision,
            policy_reason=policy.reason,
            risk_reason=risk.reason,
            occurred_at=datetime.now(timezone.utc),
        )
        self._audit_log.record(trace)

        if decision is Decision.REVIEW:
            approval = PendingApproval(request, policy.reason, risk.reason, trace.occurred_at)
            self._approval_store.create(approval)
            return EnforcementResult(decision, trace, pending_approval=approval)
        if decision is Decision.BLOCK:
            return EnforcementResult(decision, trace)

        return EnforcementResult(decision, trace, output=self._tool_registry.dispatch_allowed(request))


def _combine_decisions(policy: Decision, risk: Decision) -> Decision:
    """Return the most restrictive deterministic result."""
    precedence = {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.BLOCK: 2}
    return max((policy, risk), key=precedence.__getitem__)
