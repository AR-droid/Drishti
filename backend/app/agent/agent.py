"""Agent facade with no direct access to infrastructure tool adapters."""

from __future__ import annotations

from backend.app.security.enforcement import EnforcementResult, EnforcementService, ToolActionRequest


class Agent:
    """Submit proposed actions exclusively through the enforcement boundary."""

    def __init__(self, enforcement_service: EnforcementService) -> None:
        self._enforcement_service = enforcement_service

    def request_tool_action(self, request: ToolActionRequest) -> EnforcementResult:
        return self._enforcement_service.enforce(request)
