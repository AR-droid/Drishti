"""Mandatory Action -> DRISHTI -> risk/policy Decision -> Adapter boundary."""
from __future__ import annotations
from collections.abc import Callable, Mapping
from typing import Any, Protocol
from app.models import Action, DecisionReason, SecurityDecision, ToolCall, ToolResult, ToolStatus
from app.security.policy import ToolPolicy
from app.security.risk import RuntimeRiskEngine
class AuditSink(Protocol):
    def record(self, action: Action, result: ToolResult) -> None: ...
class ToolExecutor(Protocol):
    def execute(self, action: Action | ToolCall) -> ToolResult: ...
Adapter = Callable[[Mapping[str, Any]], Mapping[str, Any]]
class EnforcedToolGateway:
    def __init__(self, policy: ToolPolicy, adapters: Mapping[str, Adapter], audit_sink: AuditSink, risk_engine: RuntimeRiskEngine | None = None):
        self._policy, self._adapters, self._audit_sink = policy, dict(adapters), audit_sink
        self._risk, self._history = risk_engine or RuntimeRiskEngine(), {}
        # A review is a pending capability, not an adapter invocation.  Keeping the
        # original Action here means approval uses exactly the evaluation boundary.
        self._pending: dict[str, Action] = {}
    def execute(self, action: Action | ToolCall) -> ToolResult:
        legacy_call = action if isinstance(action, ToolCall) else None
        action = action.to_action() if legacy_call else action
        history = tuple(self._history.get(action.request_id, ()))
        known_agent = self._policy.is_registered(action.agent_id)
        authorized = self._policy.is_authorized(action.agent_id, action.tool)
        assessment = self._risk.analyze(action, known_agent=known_agent, authorized=authorized, known_tool=action.tool in self._adapters and action.tool in self._policy.allowed_tools, history=history)
        evaluation = self._policy.evaluate(action)
        reasons = evaluation.reasons
        decision = evaluation.decision
        # Policy/authorization are authoritative; score only guides safe review of high-impact actions.
        if decision is SecurityDecision.ALLOW and assessment.score >= 50 and action.operation.casefold() in {"send", "write", "export", "execute", "delete"}:
            decision = SecurityDecision.REVIEW
        if decision is not SecurityDecision.ALLOW:
            legacy_reason = None
            if legacy_call and action.tool not in self._policy.allowed_tools: legacy_reason = f"Tool '{action.tool}' is not registered."
            elif legacy_call and DecisionReason.UNAUTHORIZED_AGENT in reasons: legacy_reason = f"Actor '{action.agent_id}' is not permitted to use '{action.tool}'."
            result = ToolResult(ToolStatus.DENIED, action.tool, action.request_id, reason=legacy_reason or ", ".join(reasons), decision=decision, decision_reasons=reasons, executed=False, risk_score=assessment.score, risk_level=assessment.level, risk_flags=assessment.flags, policy_rule=self._policy.rule_name(action))
            if decision is SecurityDecision.REVIEW:
                self._pending[action.request_id] = action
        elif (adapter := self._adapters.get(action.tool)) is None:
            result = ToolResult(ToolStatus.DENIED, action.tool, action.request_id, reason="UNKNOWN_TOOL", decision=SecurityDecision.BLOCK, decision_reasons=(DecisionReason.UNKNOWN_TOOL,), risk_score=assessment.score, risk_level=assessment.level, risk_flags=assessment.flags, policy_rule="known-tools-only")
        else:
            try:
                result = ToolResult(ToolStatus.SUCCEEDED, action.tool, action.request_id, data=dict(adapter(action.arguments)), decision=SecurityDecision.ALLOW, executed=True, risk_score=assessment.score, risk_level=assessment.level, risk_flags=assessment.flags, policy_rule=self._policy.rule_name(action))
            except (TypeError, ValueError) as error:
                result = ToolResult(ToolStatus.FAILED, action.tool, action.request_id, reason=f"Synthetic adapter rejected input: {error}", decision=SecurityDecision.ALLOW, risk_score=assessment.score, risk_level=assessment.level, risk_flags=assessment.flags, policy_rule=self._policy.rule_name(action))
        self._history.setdefault(action.request_id, []).append(action)
        self._audit_sink.record(action, result)
        return result

    def approve(self, request_id: str) -> ToolResult:
        """Execute a previously REVIEWed action only after explicit approval.

        This method deliberately cannot approve BLOCK actions: only actions placed
        in ``_pending`` by the REVIEW branch have an executable capability.
        """
        action = self._pending.pop(request_id, None)
        if action is None:
            raise KeyError("No pending review for request_id")
        adapter = self._adapters.get(action.tool)
        if adapter is None:  # fail closed even if configuration changed meanwhile
            result = ToolResult(ToolStatus.DENIED, action.tool, request_id, reason="UNKNOWN_TOOL", decision=SecurityDecision.BLOCK, decision_reasons=(DecisionReason.UNKNOWN_TOOL,))
        else:
            try:
                result = ToolResult(ToolStatus.SUCCEEDED, action.tool, request_id, data=dict(adapter(action.arguments)), decision=SecurityDecision.ALLOW, executed=True, policy_rule="explicit-review-approval")
            except (TypeError, ValueError) as error:
                result = ToolResult(ToolStatus.FAILED, action.tool, request_id, reason=f"Adapter rejected input: {error}", decision=SecurityDecision.ALLOW, policy_rule="explicit-review-approval")
        self._history.setdefault(request_id, []).append(action)
        self._audit_sink.record(action, result)
        return result
