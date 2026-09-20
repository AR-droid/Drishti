import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from app.api import create_app


def test_evaluate_action_returns_guarded_decision_and_audited_trace(tmp_path, monkeypatch):
    monkeypatch.setenv("DRISHTI_DEMO_TOKEN", "test-token")
    client = TestClient(create_app(tmp_path / "audit.jsonl"))

    response = client.post(
        "/api/actions/evaluate",
        headers={"Authorization": "Bearer test-token"}, json={
            "agent_id": "invoicebot",
            "tool": "send_email",
            "operation": "send",
            "resource": "invoice",
            "arguments": {"to": "verified.user@example.com"},
            "scope": "VERIFIED_USER",
            "user_intent": "Email my invoice",
            "provenance": "user",
            "data_classification": "confidential",
            "destination": "verified_user",
            "request_id": "api-action-1",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "request_id": "api-action-1", "tool": "send_email", "status": "authorized",
        "decision": "allow", "reasons": [], "executed": False, "reason": None,
        "data": {}, "risk_score": 0, "risk_level": "LOW", "risk_flags": [],
        "decision_reasons": [], "policy_rule": "InvoiceBot Least Privilege", "execution_status": "authorized",
    }
    trace = client.get("/api/traces/api-action-1")
    assert trace.status_code == 200
    assert trace.json()["events"][0]["executed"] is False


def test_safe_invoice_demo_returns_allowed_executed_trace(tmp_path):
    client = TestClient(create_app(tmp_path / "audit.jsonl"))

    response = client.post("/api/demo/safe-invoice")

    assert response.status_code == 200
    body = response.json()
    assert [item["decision"] for item in body["results"]] == ["allow"] * 3
    assert all(item["executed"] for item in body["results"])
    assert len(body["trace"]["events"]) == 3


def test_malicious_invoice_demo_returns_blocked_unexecuted_trace(tmp_path):
    client = TestClient(create_app(tmp_path / "audit.jsonl"))

    response = client.post("/api/demo/malicious-invoice")

    assert response.status_code == 200
    body = response.json()
    assert [item["decision"] for item in body["results"]] == ["block", "block"]
    assert all(not item["executed"] for item in body["results"])
    assert all(event["provenance"] == "document" for event in body["trace"]["events"])
