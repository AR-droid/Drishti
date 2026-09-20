"""Append-only local JSONL storage. It is intentionally limited to synthetic data."""

from __future__ import annotations

import json
from pathlib import Path

from app.models import ToolResult


class LocalAuditStore:
    """Persist tool outcomes on the local filesystem for demo inspection."""

    def __init__(self, path: Path):
        self._path = path

    def record(self, result: ToolResult) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "status": result.status.value,
            "tool_name": result.tool_name,
            "request_id": result.request_id,
            "data": dict(result.data),
            "reason": result.reason,
        }
        with self._path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(document, sort_keys=True) + "\n")

    def read_all(self) -> list[dict[str, object]]:
        if not self._path.exists():
            return []
        with self._path.open(encoding="utf-8") as audit_file:
            return [json.loads(line) for line in audit_file if line.strip()]
