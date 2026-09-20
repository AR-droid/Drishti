from app.models import Action, DataClassification, Provenance, SecurityDecision
from app.security import EnforcedToolGateway, ToolPolicy
from app.storage import LocalAuditStore


def test_review_approval_is_bound_to_exact_action_and_is_single_use(tmp_path):
    calls = []
    gateway = EnforcedToolGateway(
        ToolPolicy(frozenset({"send_email"})), {"send_email": lambda args: calls.append(args) or {"sent": True}},
        LocalAuditStore(tmp_path / "audit.jsonl"),
    )
    action = Action("invoicebot", "send_email", "send", "invoice", {"to": "outside@example.com"}, "EXTERNAL", "email invoice", Provenance.USER, DataClassification.CONFIDENTIAL, destination="external", request_id="review-bound")
    pending = gateway.authorize(action)
    assert pending.decision is SecurityDecision.REVIEW and calls == []
    try:
        gateway.approve(action.request_id, "not-the-action-hash")
    except KeyError:
        pass
    else:
        raise AssertionError("mismatched approval hash must fail")
    assert calls == []
    try:
        gateway.approve(action.request_id, action.action_hash)
    except KeyError:
        pass
    else:
        raise AssertionError("approval must be single-use after failed binding")
