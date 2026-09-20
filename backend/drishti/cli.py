"""Local DRISHTI runtime command line interface."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import shutil
from urllib.error import URLError
from urllib.request import Request, urlopen
from typing import Any

from app.storage import LocalAuditStore


def _home() -> Path:
    return Path(os.getenv("DRISHTI_HOME", Path.home() / ".drishti"))


def _pid_file() -> Path:
    return _home() / "gateway.pid"


def _runtime_url() -> str:
    return os.getenv("DRISHTI_ENDPOINT", os.getenv("DRISHTI_GATEWAY_URL", "http://127.0.0.1:8000")).rstrip("/")


def _credentials() -> dict[str, str]:
    path = _home() / "credentials.json"
    if not path.is_file(): return {}
    try: return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError): return {}


def _health_check() -> bool:
    try:
        with urlopen(Request(f"{_runtime_url()}/health"), timeout=5) as response:
            return response.status == 200
    except (URLError, OSError):
        return False


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
    """Install through OpenClaw's CLI; never infer or rewrite its config schema."""
    config = _openclaw_config()
    binary = shutil.which("openclaw")
    if config is None or binary is None:
        missing = []
        if binary is None: missing.append("the `openclaw` executable")
        if config is None: missing.append("an active OpenClaw config (set OPENCLAW_CONFIG if needed)")
        print("Cannot connect OpenClaw: missing " + " and ".join(missing) + ".", file=sys.stderr)
        return 2
    credentials = _credentials()
    if not credentials.get("token"):
        print("Run `drishti login` first; no scoped DRISHTI credential is stored.", file=sys.stderr)
        return 2
    if not _health_check():
        print(f"DRISHTI health check failed at {_runtime_url()}/health; refusing to install a fail-closed plugin.", file=sys.stderr)
        return 3
    plugin = Path(__file__).resolve().parents[2] / "integrations" / "openclaw-plugin"
    try:
        # Ask the real CLI whether this supported installation command exists.
        probe = subprocess.run([binary, "plugins", "install", "--help"], capture_output=True, text=True, timeout=15)
        if probe.returncode != 0:
            print("Installed OpenClaw does not expose `plugins install`; no configuration was changed.", file=sys.stderr)
            return 4
        install = subprocess.run([binary, "plugins", "install", str(plugin)], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"OpenClaw plugin installation failed: {error}", file=sys.stderr); return 4
    if install.returncode != 0:
        print("OpenClaw rejected the DRISHTI plugin; no protection is claimed.", file=sys.stderr)
        print(install.stderr.strip(), file=sys.stderr); return 4
    # Keep credentials only in DRISHTI's mode-0600 store. The plugin config points
    # at an environment variable, so its source-controlled configuration is secret-free.
    integration = _home() / "openclaw-plugin-config.json"
    integration.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    integration.write_text(json.dumps({"endpoint": _runtime_url(), "agentId": "openclaw-local", "credentialEnv": "DRISHTI_OPENCLAW_TOKEN", "failOpen": False}, indent=2) + "\n")
    integration.chmod(0o600)
    listing = subprocess.run([binary, "plugins", "list"], capture_output=True, text=True, timeout=20)
    if listing.returncode != 0 or "drishti" not in (listing.stdout + listing.stderr).casefold():
        print("Plugin install returned success but DRISHTI was not listed as loaded; no protection is claimed.", file=sys.stderr)
        return 5
    print("OpenClaw detected at:", config)
    print("DRISHTI plugin installed and listed by OpenClaw.")
    print("Set DRISHTI_OPENCLAW_TOKEN from your secret manager in the OpenClaw service environment.")
    print("Apply this secret-free plugin configuration using the installed OpenClaw version's documented plugin configuration command:")
    print(integration)
    print("Restart OpenClaw, then run a real ALLOW and BLOCK tool call. Protection is not claimed until that before_tool_call path is verified.")
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
        endpoint = os.getenv("DRISHTI_ENDPOINT", _runtime_url()); credentials = _home() / "credentials.json"; credentials.write_text(json.dumps({"token": token, "endpoint": endpoint}) + "\n"); credentials.chmod(0o600); print("DRISHTI credential saved with mode 0600; token was not printed.")
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
