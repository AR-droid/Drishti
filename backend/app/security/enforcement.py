"""The sole boundary between agents and simulated tool implementations."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from app.models import ToolCall, ToolResult, ToolStatus
from app.security.policy import ToolPolicy


class AuditSink(Protocol):
    def record(self, result: ToolResult) -> None: ...


class ToolExecutor(Protocol):
    """Narrow capability injected into agents; adapters never satisfy agent imports."""

    def execute(self, call: ToolCall) -> ToolResult: ...


Adapter = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class EnforcedToolGateway:
    """Validates and audits calls before dispatching to an internal adapter registry."""

    def __init__(self, policy: ToolPolicy, adapters: Mapping[str, Adapter], audit_sink: AuditSink):
        self._policy = policy
        self._adapters = dict(adapters)
        self._audit_sink = audit_sink

    def execute(self, call: ToolCall) -> ToolResult:
        reason = self._policy.denial_reason(call)
        if reason is not None:
            result = ToolResult(ToolStatus.DENIED, call.tool_name, call.request_id, reason=reason)
        else:
            adapter = self._adapters.get(call.tool_name)
            if adapter is None:
                result = ToolResult(
                    ToolStatus.DENIED,
                    call.tool_name,
                    call.request_id,
                    reason=f"Tool '{call.tool_name}' has no enforcement-bound adapter.",
                )
            else:
                try:
                    result = ToolResult(
                        ToolStatus.SUCCEEDED,
                        call.tool_name,
                        call.request_id,
                        data=dict(adapter(call.arguments)),
                    )
                except (TypeError, ValueError) as error:
                    result = ToolResult(
                        ToolStatus.FAILED,
                        call.tool_name,
                        call.request_id,
                        reason=f"Synthetic adapter rejected input: {error}",
                    )
        self._audit_sink.record(result)
        return result
