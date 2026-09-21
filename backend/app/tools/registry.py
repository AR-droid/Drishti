"""Composition root: adapters are deliberately reachable only through DRISHTI."""
from __future__ import annotations
from pathlib import Path
from app.security import EnforcedToolGateway, ToolPolicy
from app.storage import AuditStore, LocalAuditStore
from app.tools.adapters import _ADAPTERS


def build_demo_components(audit_path: Path, audit_store: AuditStore | None = None) -> tuple[EnforcedToolGateway, AuditStore]:
    """Build the guarded demo gateway and the audit store it writes to."""
    audit_store = audit_store or LocalAuditStore(audit_path)
    gateway = EnforcedToolGateway(
        ToolPolicy(
            frozenset(_ADAPTERS),
            {
                "invoicebot": frozenset(_ADAPTERS),
                "demo-user": frozenset(_ADAPTERS),
                "readonly-demo": frozenset({"customer.lookup", "search_documents", "read_document"}),
                # The OpenClaw adapter is an MCP client identity; it receives no
                # direct adapter capability and is authorized only at this gateway.
                "openclaw-local": frozenset(_ADAPTERS),
            },
            # Runtime identities are authenticated at the API boundary. Keeping
            # this open lets credentials provisioned in the Agents table use the
            # same enforcement policy without a redeploy.
            registered_agents=None,
            name="InvoiceBot Least Privilege",
        ),
        _ADAPTERS,
        audit_store,
    )
    return gateway, audit_store


def build_demo_gateway(audit_path: Path) -> EnforcedToolGateway:
    return build_demo_components(audit_path)[0]
