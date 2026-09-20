"""Agent orchestration depends on a narrow enforcement-bound capability."""

from __future__ import annotations

from app.models import AgentReply, ToolCall, ToolStatus
from app.security import ToolExecutor


class DemoAgent:
    """A deterministic agent suitable for local, synthetic demonstrations."""

    def __init__(self, tools: ToolExecutor):
        self._tools = tools

    def lookup_customer(self, actor_id: str, query: str) -> AgentReply:
        result = self._tools.execute(
            ToolCall(tool_name="customer.lookup", arguments={"query": query}, actor_id=actor_id)
        )
        if result.status is ToolStatus.DENIED:
            return AgentReply("I cannot access that customer lookup.", result)
        if not result.ok:
            return AgentReply("The local demo lookup could not be completed.", result)
        customer = result.data["customer"]
        if customer is None:
            return AgentReply("No synthetic customer matched that query.", result)
        return AgentReply(f"Synthetic customer found: {customer['name']}.", result)

    def list_tasks(self, actor_id: str) -> AgentReply:
        result = self._tools.execute(ToolCall(tool_name="tasks.list", arguments={}, actor_id=actor_id))
        if result.ok:
            return AgentReply("Synthetic tasks retrieved.", result)
        return AgentReply("I cannot retrieve those local demo tasks.", result)
