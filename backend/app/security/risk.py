"""Deterministic, explainable runtime risk analysis shared by local and AWS modes."""
from __future__ import annotations
from dataclasses import dataclass
from app.models import Action, DataClassification, DecisionReason, Provenance

_UNTRUSTED = {Provenance.DOCUMENT, Provenance.WEBPAGE, Provenance.EMAIL, Provenance.TOOL_RESULT, Provenance.MCP_TOOL_DESCRIPTION}
_HIGH_OPS = {"delete", "destroy", "remove", "execute", "export"}
_BROAD = {"ALL_CUSTOMERS", "ALL_FILES", "ENTIRE_DATABASE", "GLOBAL", "EXTERNAL"}

@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    level: str
    flags: tuple[DecisionReason, ...]
    contributions: dict[str, int]

class RuntimeRiskEngine:
    """Weighted rules, not content signatures. Scores are advisory; policy decides."""
    def analyze(self, action: Action, *, known_agent: bool, authorized: bool,
                known_tool: bool, history: tuple[Action, ...] = ()) -> RiskAssessment:
        c: dict[str, int] = {}
        flags: list[DecisionReason] = []
        def add(key: str, points: int, flag: DecisionReason | None = None) -> None:
            c[key] = points
            if flag: flags.append(flag)
        operation = action.operation.casefold()
        if not known_agent or not authorized: add("authorization", 35, DecisionReason.UNAUTHORIZED_AGENT)
        if not known_tool: add("tool_authorization", 35, DecisionReason.UNKNOWN_TOOL)
        if action.scope.upper() in _BROAD: add("scope", 24, DecisionReason.EXCESSIVE_SCOPE)
        if action.provenance in _UNTRUSTED: add("provenance", 20, DecisionReason.UNTRUSTED_PROVENANCE)
        if action.data_classification is DataClassification.SENSITIVE: add("data_sensitivity", 16, DecisionReason.SENSITIVE_DATA)
        if action.destination in {"external", "unknown", "unverified"}: add("destination", 15, DecisionReason.UNVERIFIED_DESTINATION)
        if operation in _HIGH_OPS: add("operation", 24, DecisionReason.DESTRUCTIVE_OPERATION)
        elif operation in {"write", "send"}: add("operation", 8)
        intent = action.user_intent.casefold()
        resource_words = {word for word in action.resource.casefold().replace("_", " ").split() if len(word) > 3}
        if action.tool == "query_customer" and "customer" not in intent: add("intent", 22, DecisionReason.OUTSIDE_USER_INTENT)
        elif resource_words and not any(word in intent for word in resource_words) and action.scope.upper() in _BROAD:
            add("intent", 18, DecisionReason.OUTSIDE_USER_INTENT)
        if history:
            prior_scopes = {item.scope.upper() for item in history}
            prior_ops = {item.operation.casefold() for item in history}
            if action.scope.upper() in _BROAD and not prior_scopes.intersection(_BROAD):
                add("behavioral_deviation", 12, DecisionReason.BEHAVIORAL_DEVIATION)
            if operation in _HIGH_OPS and not prior_ops.intersection(_HIGH_OPS):
                add("privilege_escalation", 12, DecisionReason.PRIVILEGE_ESCALATION)
            if history[-1].provenance in _UNTRUSTED and action.provenance in _UNTRUSTED:
                add("action_chain", 8, DecisionReason.RISKY_ACTION_CHAIN)
        score = min(100, sum(c.values()))
        level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        return RiskAssessment(score, level, tuple(dict.fromkeys(flags)), c)
