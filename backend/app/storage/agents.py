"""Small workspace-scoped agent registry.

Raw API credentials never enter this store: it retains only their SHA-256 digest.
The JSON file is a hackathon/local implementation; deployed environments use the
existing DynamoDB Agents table.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).isoformat()


class AgentStore:
    def __init__(self, path: Path, table_name: str | None = None, dynamodb_resource: Any | None = None):
        self.path, self.table_name = path, table_name
        if table_name:
            if dynamodb_resource is None:
                import boto3
                dynamodb_resource = boto3.resource("dynamodb")
            self.table = dynamodb_resource.Table(table_name)
        else:
            self.table = None

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _records(self) -> list[dict[str, Any]]:
        if self.table:
            return list(self.table.scan().get("Items", []))
        if not self.path.exists():
            return []
        return json.loads(self.path.read_text())

    def _write(self, records: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(records, indent=2, sort_keys=True))

    def list(self) -> list[dict[str, Any]]:
        return [self.public(record) for record in self._records()]

    def get(self, agent_id: str) -> dict[str, Any] | None:
        if self.table:
            return self.table.get_item(Key={"agent_id": agent_id}).get("Item")
        return next((record for record in self._records() if record["agent_id"] == agent_id), None)

    def create(self, name: str, environment: str, integration: str) -> tuple[dict[str, Any], str]:
        agent_id = "-".join(name.lower().split())
        if not agent_id or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in agent_id):
            raise ValueError("Agent name must use letters, numbers, hyphens, or underscores")
        if self.get(agent_id):
            raise ValueError("An agent with this name already exists")
        token = "drs_live_" + secrets.token_urlsafe(32)
        record = {"agent_id": agent_id, "name": name, "environment": environment,
                  "integration": integration, "status": "not_connected", "credential_digest": self._digest(token),
                  "created_at": _now(), "last_seen": None, "revoked": False}
        if self.table:
            self.table.put_item(Item=record)
        else:
            records = self._records(); records.append(record); self._write(records)
        return record, token

    def rotate(self, agent_id: str) -> tuple[dict[str, Any], str] | None:
        record = self.get(agent_id)
        if not record: return None
        token = "drs_live_" + secrets.token_urlsafe(32)
        record.update({"credential_digest": self._digest(token), "revoked": False})
        self._save(record)
        return record, token

    def revoke(self, agent_id: str) -> dict[str, Any] | None:
        record = self.get(agent_id)
        if not record: return None
        record["revoked"] = True; self._save(record)
        return record

    def authenticate(self, token: str | None, agent_id: str) -> bool:
        record = self.get(agent_id)
        if not token or not record or record.get("revoked"):
            return False
        valid = hmac.compare_digest(self._digest(token), str(record.get("credential_digest", "")))
        if valid:
            record.update({"status": "connected", "last_seen": _now()}); self._save(record)
        return valid

    def _save(self, record: dict[str, Any]) -> None:
        if self.table:
            self.table.put_item(Item=record); return
        records = self._records()
        for index, existing in enumerate(records):
            if existing["agent_id"] == record["agent_id"]: records[index] = record; break
        self._write(records)

    @staticmethod
    def public(record: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in record.items() if key != "credential_digest"}
