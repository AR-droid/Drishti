"""Persistence implementations selected by the application configuration."""

from typing import Protocol

from app.models import Action, AttackTrace, ToolResult


class AuditStore(Protocol):
    """Minimal persistence boundary used by enforcement and the trace API."""

    def record(self, action: Action | ToolResult, result: ToolResult | None = None) -> None: ...

    def get_trace(self, request_id: str) -> AttackTrace: ...

from .dynamodb import DynamoDBAuditStore
from .local import LocalAuditStore
from .agents import AgentStore

__all__ = ["AuditStore", "DynamoDBAuditStore", "LocalAuditStore", "AgentStore"]
