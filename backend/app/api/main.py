"""Lightweight FastAPI application over DRISHTI's existing enforcement boundary."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.agent import DemoAgent
from app.models import (
    Action,
    AttackTrace,
    DataClassification,
    Provenance,
    SecurityEvent,
    ToolResult,
)
from app.storage import DynamoDBAuditStore, LocalAuditStore
from app.tools import build_demo_components


class ActionRequest(BaseModel):
    """JSON representation of an action submitted to the enforcement gateway."""

    agent_id: str
    tool: str
    operation: str
    resource: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    scope: str
    user_intent: str
    provenance: Provenance
    data_classification: DataClassification
    destination: str | None = None
    request_id: str | None = None
    timestamp: datetime | None = None

    def to_domain(self) -> Action:
        values: dict[str, Any] = self.model_dump(exclude_none=True)
        values.setdefault("timestamp", datetime.now(UTC))
        return Action(**values)


def _result_response(result: ToolResult) -> dict[str, Any]:
    """Serialize a gateway result without exposing Python enums or dataclasses."""
    return {
        "request_id": result.request_id,
        "tool": result.tool_name,
        "status": result.status.value,
        "decision": result.decision.value if result.decision else None,
        "reasons": [reason.value for reason in result.decision_reasons],
        "executed": result.executed,
        "reason": result.reason,
        "data": dict(result.data),
    }


def _event_response(event: SecurityEvent) -> dict[str, Any]:
    return event.to_dict()


def _trace_response(trace: AttackTrace) -> dict[str, Any]:
    return {"request_id": trace.request_id, "events": [_event_response(event) for event in trace.events]}


def create_app(audit_path: Path | None = None) -> FastAPI:
    """Create an app whose routes share one guarded gateway and audit store."""
    path = audit_path or Path(os.getenv("DRISHTI_AUDIT_PATH", "drishti-audit.jsonl"))
    audit_store = _audit_store(path)
    gateway, audit_store = build_demo_components(path, audit_store)
    demo_agent = DemoAgent(gateway)

    application = FastAPI(title="DRISHTI API", version="0.1.0")
    application.state.gateway = gateway
    application.state.audit_store = audit_store

    @application.post("/api/actions/evaluate")
    def evaluate_action(action_request: ActionRequest) -> dict[str, Any]:
        try:
            action = action_request.to_domain()
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return _result_response(gateway.execute(action))

    @application.get("/api/traces/{request_id}")
    def get_trace(request_id: str) -> dict[str, Any]:
        return _trace_response(audit_store.get_trace(request_id))

    @application.post("/api/demo/safe-invoice")
    def safe_invoice() -> dict[str, Any]:
        results = demo_agent.find_acme_invoice_and_email("verified.user@example.com")
        return {
            "results": [_result_response(result) for result in results],
            "trace": _trace_response(audit_store.get_trace(results[0].request_id)),
        }

    @application.post("/api/demo/malicious-invoice")
    def malicious_invoice() -> dict[str, Any]:
        results = demo_agent.follow_malicious_invoice_instruction()
        return {
            "results": [_result_response(result) for result in results],
            "trace": _trace_response(audit_store.get_trace(results[0].request_id)),
        }

    return application


def _audit_store(path: Path) -> LocalAuditStore | DynamoDBAuditStore:
    """Keep JSONL as the local default; AWS explicitly opts into DynamoDB."""
    if os.getenv("DRISHTI_STORAGE_BACKEND", "local").lower() != "dynamodb":
        return LocalAuditStore(path)
    required = ("SECURITY_EVENTS_TABLE", "ATTACK_TRACES_TABLE", "ACTIONS_TABLE")
    values = {name: os.getenv(name) for name in required}
    if not all(values.values()):
        raise RuntimeError("DynamoDB storage requires SECURITY_EVENTS_TABLE, ATTACK_TRACES_TABLE, and ACTIONS_TABLE")
    return DynamoDBAuditStore(
        security_events_table=values["SECURITY_EVENTS_TABLE"] or "",
        attack_traces_table=values["ATTACK_TRACES_TABLE"] or "",
        actions_table=values["ACTIONS_TABLE"] or "",
    )


app = create_app()
