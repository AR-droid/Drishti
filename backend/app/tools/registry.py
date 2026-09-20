"""Composition root: adapters are deliberately reachable only through DRISHTI."""
from __future__ import annotations
from pathlib import Path
from app.security import EnforcedToolGateway, ToolPolicy
from app.storage import LocalAuditStore
from app.tools.adapters import _ADAPTERS


def build_demo_components(audit_path: Path) -> tuple[EnforcedToolGateway, LocalAuditStore]:
    """Build the guarded demo gateway and the audit store it writes to."""
    audit_store = LocalAuditStore(audit_path)
    gateway = EnforcedToolGateway(
        ToolPolicy(
            frozenset(_ADAPTERS),
            {
                "invoicebot": frozenset(_ADAPTERS),
                "demo-user": frozenset(_ADAPTERS),
                "readonly-demo": frozenset({"customer.lookup", "search_documents", "read_document"}),
            },
        ),
        _ADAPTERS,
        audit_store,
    )
    return gateway, audit_store


def build_demo_gateway(audit_path: Path) -> EnforcedToolGateway:
    return build_demo_components(audit_path)[0]
