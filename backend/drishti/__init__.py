"""Python SDK: route agent actions through the DRISHTI enforcement boundary."""
from __future__ import annotations
from collections.abc import Callable, Iterable
import json
from typing import Any
from urllib.request import Request, urlopen
from app.models import Action


class Drishti:
    """Small SDK client for local or cloud DRISHTI gateways.

    The SDK never makes policy decisions.  It sends the normalized action to the
    same backend endpoint used by MCP, and only invokes a supplied executor after
    an ``allow`` response.  In supported deployments protected credentials belong
    to the gateway/tool server, not to the agent process.
    """
    def __init__(self, endpoint: str = "http://127.0.0.1:8000", *, token: str | None = None, timeout: float = 10):
        self.endpoint, self.token, self.timeout = endpoint.rstrip("/"), token, timeout

    def evaluate(self, **action: Any) -> dict[str, Any]:
        request = Request(f"{self.endpoint}/v1/actions/evaluate", data=json.dumps(action, default=str).encode(), method="POST", headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {self.token}"} if self.token else {})})
        with urlopen(request, timeout=self.timeout) as response:  # nosec B310: explicit developer-configured gateway
            return json.loads(response.read())

    def execute(self, *, executor: Callable[..., Any] | None = None, **action: Any) -> dict[str, Any]:
        """Evaluate, then call ``executor`` only for ALLOW responses.

        Remote MCP/HTTP protected tools execute behind the gateway, so callers
        should omit ``executor`` and consume the returned protected-tool result.
        """
        result = self.evaluate(**action)
        if result["decision"] != "allow" or not result["executed"]:
            raise PermissionError(f"DRISHTI {result['decision']}: {result.get('reasons', [])}")
        if executor is not None:
            # For embedded/local adapters, this callable must be a gateway-owned
            # capability. Passing arbitrary direct tool credentials is unsupported.
            result["executor_result"] = executor(**action.get("arguments", {}))
        return result

def protect(tools: Iterable[Callable], gateway, action_factory: Callable[[Callable, tuple, dict], Action]):
    """Return wrapped tools; caller supplies normalized security metadata factory."""
    protected = {}
    for tool in tools:
        def guarded(*args, _tool=tool, **kwargs):
            result = gateway.execute(action_factory(_tool, args, kwargs))
            if not result.executed: raise PermissionError(result.reason or "DRISHTI denied tool execution")
            return result.data
        protected[tool.__name__] = guarded
    return protected
