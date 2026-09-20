"""Lightweight FastAPI application over DRISHTI's existing enforcement boundary."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
import asyncio
import json
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
    run_id: str | None = None
    session_id: str | None = None

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


def _gateway_result(result: ToolResult) -> dict[str, Any]:
    """Full explainable response for protocol gateways."""
    body = _result_response(result)
    body.update({"risk_score": result.risk_score, "risk_level": result.risk_level,
                 "risk_flags": [flag.value for flag in result.risk_flags],
                 "decision_reasons": [reason.value for reason in result.decision_reasons],
                 "policy_rule": result.policy_rule, "execution_status": result.status.value})
    return body


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

    @application.get("/health")
    def health() -> dict[str, str]:
        """Unauthenticated liveness probe; it exposes no policy or audit data."""
        return {"status": "ok", "service": "drishti-security-api"}

    @application.post("/api/actions/evaluate")
    @application.post("/v1/actions/evaluate")
    def evaluate_action(action_request: ActionRequest) -> dict[str, Any]:
        try:
            action = action_request.to_domain()
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return _result_response(gateway.execute(action))

    @application.post("/v1/actions/{request_id}/approve")
    def approve_action(request_id: str) -> dict[str, Any]:
        """Approval endpoint for a human/control-plane review integration."""
        try:
            return _gateway_result(gateway.approve(request_id))
        except KeyError as error:
            raise HTTPException(status_code=404, detail="No pending REVIEW action for request_id") from error

    @application.post("/v1/actions/authorize")
    def authorize_action(action_request: ActionRequest) -> dict[str, Any]:
        """Native-agent pre-execution decision endpoint; it never dispatches tools."""
        try:
            return _gateway_result(gateway.authorize(action_request.to_domain()))
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @application.post("/gateway/tool-call")
    def gateway_tool_call(action_request: ActionRequest) -> dict[str, Any]:
        """Agent-agnostic HTTP integration boundary; never dispatches around core."""
        try:
            return _gateway_result(gateway.execute(action_request.to_domain()))
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @application.post("/mcp")
    def mcp_gateway(message: dict[str, Any]) -> dict[str, Any]:
        """JSON-RPC MCP server surface: tools/call is guarded by this same gateway."""
        method, params, request_id = message.get("method"), message.get("params", {}), message.get("id")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "drishti-mcp-gateway", "version": "0.1.0"}, "capabilities": {"tools": {}}}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [{"name": name, "description": "DRISHTI-protected tool"} for name in sorted(gateway._adapters)]}}
        if method != "tools/call":
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Unsupported MCP method"}}
        meta = params.get("_drishti", {})
        payload = {"agent_id": meta.get("agent_id", "unknown-mcp-agent"), "tool": params.get("name", ""),
                   "operation": meta.get("operation", "execute"), "resource": meta.get("resource", params.get("name", "")),
                   "arguments": params.get("arguments", {}), "scope": meta.get("scope", "UNSPECIFIED"),
                   "user_intent": meta.get("user_intent", "MCP tool request"), "provenance": meta.get("provenance", "agent"),
                   "data_classification": meta.get("data_classification", "internal"), "destination": meta.get("destination"),
                   "request_id": meta.get("request_id")}
        try:
            result = gateway.execute(ActionRequest(**payload).to_domain())
        except (ValueError, TypeError) as error:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": str(error)}}
        body = _gateway_result(result)
        if not result.executed:
            return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": json.dumps(body)}], "isError": True, "_meta": {"drishti": body}}}
        return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": json.dumps(dict(result.data))}], "_meta": {"drishti": body}}}

    @application.get("/api/events")
    async def events() -> StreamingResponse:
        """Backend-derived SSE stream, polling the append-only audit store."""
        async def stream():
            sent = 0
            while True:
                records = audit_store.read_all() if hasattr(audit_store, "read_all") else []
                for record in records[sent:]:
                    decision = str(record.get("decision", ""))
                    event_type = "ACTION_ALLOWED" if decision == "allow" else "ACTION_REVIEW" if decision == "review" else "ACTION_BLOCKED" if decision == "block" else "ACTION_REQUESTED"
                    yield f"event: {event_type}\ndata: {json.dumps(record)}\n\n"
                sent = len(records)
                await asyncio.sleep(1)
        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

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
