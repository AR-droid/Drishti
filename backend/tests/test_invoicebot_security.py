from collections.abc import Mapping

import pytest

from app.agent import DemoAgent
from app.models import (
    Action,
    DataClassification,
    DecisionReason,
    Provenance,
    SecurityDecision,
)
from app.security import EnforcedToolGateway, ToolPolicy
from app.storage import LocalAuditStore
from app.tools import build_demo_gateway


class RecordingAdapter:
    """Local adapter double that proves whether the enforcement boundary invoked it."""

    def __init__(self, response: Mapping[str, object]):
        self.response = response
        self.calls: list[Mapping[str, object]] = []

    def __call__(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        self.calls.append(arguments)
        return self.response


def test_legitimate_invoice_flow_is_allowed_and_audited(tmp_path):
    gateway = build_demo_gateway(tmp_path / "audit.jsonl")
    results = DemoAgent(gateway).find_acme_invoice_and_email(
        "verified.user@example.com"
    )

    assert [result.decision for result in results] == [SecurityDecision.ALLOW] * 3
    assert all(result.executed for result in results)
    events = LocalAuditStore(tmp_path / "audit.jsonl").read_all()
    assert [event["provenance"] for event in events] == ["user"] * 3
    assert all(event["executed"] for event in events)


def test_legitimate_invoicebot_actions_are_allowed_and_execute(tmp_path):
    adapters = {
        "search_documents": RecordingAdapter({"documents": []}),
        "read_document": RecordingAdapter({"invoice": {}}),
        "query_customer": RecordingAdapter({"customers": []}),
        "send_email": RecordingAdapter({"sent": True}),
    }
    gateway = EnforcedToolGateway(
        ToolPolicy(frozenset(adapters)),
        adapters,
        LocalAuditStore(tmp_path / "allow.jsonl"),
    )
    actions = [
        Action(
            "invoicebot",
            "search_documents",
            "search",
            "invoices",
            {"query": "Acme"},
            "INVOICES",
            "Find Acme invoices",
            Provenance.USER,
            DataClassification.CONFIDENTIAL,
        ),
        Action(
            "invoicebot",
            "read_document",
            "read",
            "invoice",
            {"invoice_id": "INV-001"},
            "CURRENT_DOCUMENT",
            "Read my Acme invoice",
            Provenance.USER,
            DataClassification.CONFIDENTIAL,
        ),
        Action(
            "invoicebot",
            "query_customer",
            "query",
            "customer",
            {"customer_id": "C-001"},
            "CURRENT_CUSTOMER",
            "Look up my customer record",
            Provenance.USER,
            DataClassification.CONFIDENTIAL,
        ),
        Action(
            "invoicebot",
            "send_email",
            "send",
            "invoice",
            {"to": "verified.user@example.com"},
            "VERIFIED_USER",
            "Email my invoice",
            Provenance.USER,
            DataClassification.CONFIDENTIAL,
            destination="verified_user",
        ),
    ]

    results = [gateway.execute(action) for action in actions]

    assert [result.decision for result in results] == [SecurityDecision.ALLOW] * len(
        actions
    )
    assert all(result.executed for result in results)
    assert all(len(adapter.calls) == 1 for adapter in adapters.values())


def test_legitimate_external_email_requires_review_without_adapter_execution(tmp_path):
    email = RecordingAdapter({"sent": True})
    gateway = EnforcedToolGateway(
        ToolPolicy(frozenset({"send_email"})),
        {"send_email": email},
        LocalAuditStore(tmp_path / "review.jsonl"),
    )
    action = Action(
        "invoicebot",
        "send_email",
        "send",
        "invoice",
        {"to": "outside@example.com"},
        "EXTERNAL",
        "Email the invoice to the requested recipient",
        Provenance.USER,
        DataClassification.CONFIDENTIAL,
        destination="external",
    )
    result = gateway.execute(action)

    assert result.decision is SecurityDecision.REVIEW
    assert result.executed is False
    assert result.decision_reasons == (DecisionReason.UNVERIFIED_DESTINATION,)
    assert email.calls == []


@pytest.mark.parametrize(
    ("action", "expected_reasons"),
    [
        (
            Action(
                "invoicebot",
                "query_customer",
                "query",
                "customer_records",
                {"scope": "ALL_CUSTOMERS"},
                "ALL_CUSTOMERS",
                "Find Mallory Supplies invoice",
                Provenance.DOCUMENT,
                DataClassification.SENSITIVE,
            ),
            {
                DecisionReason.EXCESSIVE_SCOPE,
                DecisionReason.SENSITIVE_DATA,
                DecisionReason.OUTSIDE_USER_INTENT,
                DecisionReason.UNTRUSTED_PROVENANCE,
            },
        ),
        (
            Action(
                "invoicebot",
                "send_email",
                "send",
                "customer_records",
                {"to": "attacker@example.com"},
                "EXTERNAL",
                "Find Mallory Supplies invoice",
                Provenance.DOCUMENT,
                DataClassification.SENSITIVE,
                destination="external",
            ),
            {DecisionReason.UNTRUSTED_PROVENANCE},
        ),
    ],
)
def test_malicious_document_actions_are_blocked_before_adapters(
    tmp_path, action, expected_reasons
):
    adapter = RecordingAdapter({"unexpected": True})
    gateway = EnforcedToolGateway(
        ToolPolicy(frozenset({action.tool})),
        {action.tool: adapter},
        LocalAuditStore(tmp_path / "attack.jsonl"),
    )

    result = gateway.execute(action)

    assert result.decision is SecurityDecision.BLOCK
    assert result.executed is False
    assert expected_reasons <= set(result.decision_reasons)
    assert adapter.calls == []
