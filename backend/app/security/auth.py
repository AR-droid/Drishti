"""Credential authentication for the enforcement boundary.

Credentials are configured as SHA-256 digests so application configuration never
needs to retain a plaintext agent token.  ``DRISHTI_AGENT_TOKENS`` is a
comma-separated ``agent_id:sha256(token)`` mapping.  The local demo may opt in
to one token with ``DRISHTI_DEMO_TOKEN``; production has no implicit credential.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Principal:
    agent_id: str


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def configured_credentials() -> dict[str, str]:
    credentials: dict[str, str] = {}
    for entry in os.getenv("DRISHTI_AGENT_TOKENS", "").split(","):
        if ":" not in entry:
            continue
        agent_id, digest = entry.split(":", 1)
        if agent_id and len(digest) == 64:
            credentials[agent_id] = digest.lower()
    demo_token = os.getenv("DRISHTI_DEMO_TOKEN")
    if demo_token:
        credentials.setdefault("invoicebot", token_digest(demo_token))
        credentials.setdefault("openclaw-local", token_digest(demo_token))
    return credentials


def authenticate(token: str | None, claimed_agent_id: str) -> Principal | None:
    if not token:
        return None
    digest = token_digest(token)
    for agent_id, expected in configured_credentials().items():
        if hmac.compare_digest(digest, expected) and hmac.compare_digest(agent_id, claimed_agent_id):
            return Principal(agent_id)
    return None
