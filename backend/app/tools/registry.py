"""Application composition for enforcement-bound, synthetic demo tools."""

from __future__ import annotations

from pathlib import Path

from app.security import EnforcedToolGateway, ToolPolicy
from app.storage import LocalAuditStore
from app.tools.adapters import _ADAPTERS


def build_demo_gateway(audit_path: Path) -> EnforcedToolGateway:
    """Build the only supported entry point to local simulated tools."""

    policy = ToolPolicy(
        allowed_tools=frozenset(_ADAPTERS),
        actor_tools={
            "demo-user": frozenset({"customer.lookup", "tasks.list"}),
            "readonly-demo": frozenset({"customer.lookup"}),
        },
    )
    return EnforcedToolGateway(policy=policy, adapters=_ADAPTERS, audit_sink=LocalAuditStore(audit_path))
