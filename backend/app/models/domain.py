"""Small, framework-independent domain types used by the backend."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Mapping
from uuid import uuid4


class ToolStatus(StrEnum):
    """The possible outcomes of a tool invocation."""

    SUCCEEDED = "succeeded"
    DENIED = "denied"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool request expressed by an agent, not an adapter invocation."""

    tool_name: str
    arguments: Mapping[str, Any]
    actor_id: str
    request_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ToolResult:
    """A stable, audit-friendly result returned through the enforcement boundary."""

    status: ToolStatus
    tool_name: str
    request_id: str
    data: Mapping[str, Any] = field(default_factory=dict)
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is ToolStatus.SUCCEEDED


@dataclass(frozen=True, slots=True)
class AgentReply:
    """The user-facing outcome of a single agent request."""

    message: str
    tool_result: ToolResult
