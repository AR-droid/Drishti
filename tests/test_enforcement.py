from backend.app.security.enforcement import (
    Decision,
    DeterministicPolicyEvaluator,
    DeterministicRiskEvaluator,
    EnforcementService,
    InMemoryApprovalStore,
    InMemoryAuditLog,
    ToolActionRequest,
    ToolRegistry,
)


class Adapter:
    def __init__(self):
        self.calls = []

    def execute(self, request):
        self.calls.append(request)
        return {"executed": request.action}


def make_service(policy_rules=None, risk_rules=None):
    audit, approvals, registry, adapter = InMemoryAuditLog(), InMemoryApprovalStore(), ToolRegistry(), Adapter()
    registry.register("mail", adapter)
    service = EnforcementService(
        DeterministicPolicyEvaluator(policy_rules),
        DeterministicRiskEvaluator(risk_rules),
        audit,
        approvals,
        registry,
    )
    return service, audit, approvals, adapter


def test_allow_records_audit_and_dispatches_adapter():
    service, audit, approvals, adapter = make_service()
    result = service.enforce(ToolActionRequest("mail", "draft", "agent-1"))
    assert result.decision is Decision.ALLOW
    assert result.output == {"executed": "draft"}
    assert len(adapter.calls) == len(audit.events) == 1
    assert not approvals.pending


def test_review_persists_approval_without_dispatching():
    service, audit, approvals, adapter = make_service(risk_rules={"mail.send": Decision.REVIEW})
    result = service.enforce(ToolActionRequest("mail", "send", "agent-1"))
    assert result.decision is Decision.REVIEW
    assert result.pending_approval == approvals.pending[0]
    assert len(audit.events) == 1
    assert not adapter.calls


def test_block_returns_trace_without_invoking_adapter():
    service, audit, approvals, adapter = make_service(policy_rules={"mail.delete": Decision.BLOCK})
    result = service.enforce(ToolActionRequest("mail", "delete", "agent-1"))
    assert result.decision is Decision.BLOCK
    assert result.trace_event.decision is Decision.BLOCK
    assert len(audit.events) == 1
    assert not approvals.pending
    assert not adapter.calls
