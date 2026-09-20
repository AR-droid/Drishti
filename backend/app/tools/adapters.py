"""Private synthetic adapters. Register these only through ``build_demo_gateway``."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


# These values are deliberately fictional and must never be connected to real services.
_SYNTHETIC_CUSTOMERS = {
    "aurora": {"customer_id": "demo-001", "name": "Aurora Labs", "health": "green"},
    "beacon": {"customer_id": "demo-002", "name": "Beacon Works", "health": "amber"},
}


def _lookup_customer(arguments: Mapping[str, Any]) -> Mapping[str, Any]:
    query = arguments.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("'query' must be a non-empty string")
    customer = _SYNTHETIC_CUSTOMERS.get(query.casefold())
    return {"customer": customer, "source": "synthetic-local-demo"}


def _list_demo_tasks(arguments: Mapping[str, Any]) -> Mapping[str, Any]:
    owner = arguments.get("owner", "demo-user")
    if not isinstance(owner, str) or not owner.strip():
        raise ValueError("'owner' must be a non-empty string")
    return {
        "owner": owner,
        "tasks": [
            {"id": "demo-task-101", "title": "Review synthetic account brief", "state": "open"},
            {"id": "demo-task-102", "title": "Prepare local demo", "state": "planned"},
        ],
        "source": "synthetic-local-demo",
    }


# This mapping is module-private so callers receive adapters only through the gateway factory.
_ADAPTERS = {"customer.lookup": _lookup_customer, "tasks.list": _list_demo_tasks}
