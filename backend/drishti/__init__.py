"""Python SDK: wrap local callables so every invocation crosses DRISHTI."""
from __future__ import annotations
from collections.abc import Callable, Iterable
from app.models import Action

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
