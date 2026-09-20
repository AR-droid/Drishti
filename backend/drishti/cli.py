"""Local DRISHTI runtime command line interface."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from typing import Any

from app.storage import LocalAuditStore


def _home() -> Path:
    return Path(os.getenv("DRISHTI_HOME", Path.home() / ".drishti"))


def _pid_file() -> Path:
    return _home() / "gateway.pid"


def _runtime_url() -> str:
    return os.getenv("DRISHTI_GATEWAY_URL", "http://127.0.0.1:8000")


def _running() -> bool:
    try:
        pid = int(_pid_file().read_text())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError, FileNotFoundError):
        return False


def _openclaw_config() -> Path | None:
    """Discover known local config locations without parsing or mutating them."""
    configured = os.getenv("OPENCLAW_CONFIG")
    candidates = [Path(configured)] if configured else []
    candidates += [Path.home() / ".openclaw" / "config.json", Path.home() / ".config" / "openclaw" / "config.json"]
    return next((path for path in candidates if path.is_file()), None)


def _connect_openclaw() -> int:
    config = _openclaw_config()
    if config is None:
        print("OpenClaw configuration was not found. Set OPENCLAW_CONFIG to its config file, then retry.", file=sys.stderr)
        return 2
    # Do not guess an evolving OpenClaw config schema. Generate a reviewed,
    # secret-free Streamable HTTP MCP entry for the operator to merge.
    integration = _home() / "openclaw-mcp.json"
    integration.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    integration.write_text(json.dumps({"mcpServers": {"drishti": {"transport": "streamable-http", "url": f"{_runtime_url()}/mcp", "headers": {"X-Drishti-Agent-Id": "openclaw-local"}}}}, indent=2) + "\n")
    integration.chmod(0o600)
    print("OpenClaw was detected at:", config)
    print("DRISHTI did not modify it because its MCP schema may differ by OpenClaw version.")
    print("Merge this generated MCP server entry into your OpenClaw configuration, then restart OpenClaw:")
    print(integration)
    print("Protection is active only after OpenClaw calls DRISHTI's /mcp gateway; do not expose protected tool credentials to OpenClaw.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="drishti")
    parser.add_argument("command", choices=["start", "stop", "status", "login", "logout", "connect", "agents", "logs", "policy", "dashboard"])
    parser.add_argument("target", nargs="?")
    parser.add_argument("--port", type=int, default=int(os.getenv("DRISHTI_PORT", "8000")))
    args = parser.parse_args()
    home = _home(); home.mkdir(mode=0o700, parents=True)
    audit = Path(os.getenv("DRISHTI_AUDIT_PATH", home / "audit.jsonl"))
    if args.command == "start":
        if _running(): print(f"Gateway already running at {_runtime_url()}"); return
        process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.api.main:app", "--host", "127.0.0.1", "--port", str(args.port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        _pid_file().write_text(str(process.pid)); _pid_file().chmod(0o600)
        print(f"DRISHTI gateway started at http://127.0.0.1:{args.port}")
    elif args.command == "stop":
        if not _running(): print("Gateway is not running"); return
        os.kill(int(_pid_file().read_text()), signal.SIGTERM); _pid_file().unlink(missing_ok=True); print("DRISHTI gateway stopped")
    elif args.command == "status":
        events = LocalAuditStore(audit).read_all(); counts = {key: sum(event.get("decision") == key for event in events) for key in ("allow", "review", "block")}
        agents = {event.get("agent_id") for event in events if event.get("agent_id")}
        token = (_home() / "credentials.json").exists()
        print(f"Gateway       {'RUNNING' if _running() else 'STOPPED'}\nCloud connection {'AUTHENTICATED' if token else 'NOT LOGGED IN'}\nSecurity engine READY\nConnected agents {len(agents)}\nPolicy state    FAIL-CLOSED\nRecent counts   ALLOW {counts['allow']} / REVIEW {counts['review']} / BLOCK {counts['block']}")
    elif args.command == "login":
        token = os.getenv("DRISHTI_TOKEN")
        if not token: parser.error("login requires DRISHTI_TOKEN in this non-interactive runtime")
        credentials = _home() / "credentials.json"; credentials.write_text(json.dumps({"token": token}) + "\n"); credentials.chmod(0o600); print("DRISHTI local runtime authenticated.")
    elif args.command == "logout":
        (_home() / "credentials.json").unlink(missing_ok=True); print("DRISHTI local credentials removed.")
    elif args.command == "connect":
        if args.target != "openclaw": parser.error("supported target: openclaw")
        raise SystemExit(_connect_openclaw())
    elif args.command == "agents":
        agents = sorted({str(event.get("agent_id")) for event in LocalAuditStore(audit).read_all() if event.get("agent_id")}); print("\n".join(f"{agent} ● OBSERVED THROUGH GATEWAY" for agent in agents) or "No agents observed through the gateway")
    elif args.command == "logs": print("\n".join(json.dumps(event) for event in LocalAuditStore(audit).read_all()[-20:]))
    elif args.command == "policy": print("Default policy: fail closed for unknown tools and agents; REVIEW requires explicit approval; protected tools must be gateway-only.")
    else: print(f"Open the configured dashboard; gateway API: {_runtime_url()}")


if __name__ == "__main__": main()
