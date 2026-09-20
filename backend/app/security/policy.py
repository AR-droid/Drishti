"""Declarative authorization policy for all simulated tool calls."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from app.models import ToolCall


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    """Allow only explicitly named tools and actors for local demonstrations."""

    allowed_tools: frozenset[str]
    actor_tools: Mapping[str, frozenset[str]] = field(default_factory=dict)

    def denial_reason(self, call: ToolCall) -> str | None:
        if call.tool_name not in self.allowed_tools:
            return f"Tool '{call.tool_name}' is not registered."
        permitted = self.actor_tools.get(call.actor_id)
        if permitted is not None and call.tool_name not in permitted:
            return f"Actor '{call.actor_id}' is not permitted to use '{call.tool_name}'."
        return None
