"""Mandatory Action -> DRISHTI -> Decision -> Adapter boundary."""
from __future__ import annotations
from collections.abc import Callable, Mapping
from typing import Any, Protocol
from app.models import Action, DecisionReason, SecurityDecision, ToolCall, ToolResult, ToolStatus
from app.security.policy import ToolPolicy

class AuditSink(Protocol):
    def record(self, action: Action, result: ToolResult) -> None: ...
class ToolExecutor(Protocol):
    def execute(self, action: Action | ToolCall) -> ToolResult: ...
Adapter = Callable[[Mapping[str, Any]], Mapping[str, Any]]

class EnforcedToolGateway:
    def __init__(self, policy: ToolPolicy, adapters: Mapping[str, Adapter], audit_sink: AuditSink):
        self._policy, self._adapters, self._audit_sink = policy, dict(adapters), audit_sink
    def execute(self, action: Action | ToolCall) -> ToolResult:
        legacy_call = action if isinstance(action, ToolCall) else None
        action = action.to_action() if legacy_call else action
        evaluation = self._policy.evaluate(action)
        if evaluation.decision is not SecurityDecision.ALLOW:
            legacy_reason = None
            if legacy_call:
                if action.tool not in self._policy.allowed_tools:
                    legacy_reason = f"Tool '{action.tool}' is not registered."
                elif DecisionReason.UNAUTHORIZED_AGENT in evaluation.reasons:
                    legacy_reason = f"Actor '{action.agent_id}' is not permitted to use '{action.tool}'."
            result = ToolResult(ToolStatus.DENIED, action.tool, action.request_id, reason=legacy_reason or ", ".join(evaluation.reasons), decision=evaluation.decision, decision_reasons=evaluation.reasons, executed=False)
        elif (adapter := self._adapters.get(action.tool)) is None:
            result = ToolResult(ToolStatus.DENIED, action.tool, action.request_id, reason="UNKNOWN_TOOL", decision=SecurityDecision.BLOCK, executed=False)
        else:
            try:
                result = ToolResult(ToolStatus.SUCCEEDED, action.tool, action.request_id, data=dict(adapter(action.arguments)), decision=SecurityDecision.ALLOW, executed=True)
            except (TypeError, ValueError) as error:
                result = ToolResult(ToolStatus.FAILED, action.tool, action.request_id, reason=f"Synthetic adapter rejected input: {error}", decision=SecurityDecision.ALLOW)
        self._audit_sink.record(action, result)
        return result
