"""Deterministic, action-level policy for the synthetic InvoiceBot."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Mapping
from app.models import Action, DataClassification, DecisionReason, Provenance, SecurityDecision, ToolCall

@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    decision: SecurityDecision
    reasons: tuple[DecisionReason, ...] = ()

@dataclass(frozen=True, slots=True)
class ToolPolicy:
    allowed_tools: frozenset[str]
    actor_tools: Mapping[str, frozenset[str]] = field(default_factory=dict)
    registered_agents: frozenset[str] | None = None
    name: str = "Default Runtime Policy"

    def is_registered(self, agent_id: str) -> bool:
        return self.registered_agents is None or agent_id in self.registered_agents

    def is_authorized(self, agent_id: str, tool: str) -> bool:
        permitted = self.actor_tools.get(agent_id)
        return self.is_registered(agent_id) and (permitted is None or tool in permitted)

    def rule_name(self, action: Action) -> str:
        if action.scope == "ALL_CUSTOMERS": return "Customer Data Protection"
        if action.destination in {"external", "unknown", "unverified"}: return "Verified Destination Required"
        return self.name

    def evaluate(self, action: Action) -> PolicyEvaluation:
        reasons: list[DecisionReason] = []
        if action.tool not in self.allowed_tools: reasons.append(DecisionReason.UNKNOWN_TOOL)
        if not self.is_authorized(action.agent_id, action.tool): reasons.append(DecisionReason.UNAUTHORIZED_AGENT)
        if action.operation.startswith(("delete", "destroy", "remove")): reasons.append(DecisionReason.DESTRUCTIVE_OPERATION)
        if action.scope == "ALL_CUSTOMERS": reasons.append(DecisionReason.EXCESSIVE_SCOPE)
        if action.data_classification is DataClassification.SENSITIVE and action.tool == "query_customer": reasons.append(DecisionReason.SENSITIVE_DATA)
        # Content-derived commands are untrusted data. They cannot broaden the user request.
        if action.provenance in {Provenance.DOCUMENT, Provenance.WEBPAGE, Provenance.EMAIL, Provenance.TOOL_RESULT, Provenance.MCP_TOOL_DESCRIPTION}:
            reasons.append(DecisionReason.UNTRUSTED_PROVENANCE)
        intent = action.user_intent.casefold()
        if action.tool == "query_customer" and "customer" not in intent: reasons.append(DecisionReason.OUTSIDE_USER_INTENT)
        if action.tool == "send_email" and action.destination == "external":
            return PolicyEvaluation(SecurityDecision.REVIEW, (DecisionReason.UNVERIFIED_DESTINATION,)) if not reasons else PolicyEvaluation(SecurityDecision.BLOCK, tuple(dict.fromkeys(reasons)))
        if reasons: return PolicyEvaluation(SecurityDecision.BLOCK, tuple(dict.fromkeys(reasons)))
        return PolicyEvaluation(SecurityDecision.ALLOW)

    def denial_reason(self, call: ToolCall) -> str | None:
        """Compatibility shim for existing ToolCall consumers."""
        result = self.evaluate(call.to_action())
        return None if result.decision is SecurityDecision.ALLOW else ", ".join(result.reasons)
