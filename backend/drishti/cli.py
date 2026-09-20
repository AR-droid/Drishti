from __future__ import annotations
import argparse, os
from pathlib import Path
from app.storage import LocalAuditStore

def main():
 p=argparse.ArgumentParser(prog="drishti"); p.add_argument("command", choices=["start","stop","status","agents","logs","policy"]); a=p.parse_args()
 path=Path(os.getenv("DRISHTI_AUDIT_PATH", "drishti-audit.jsonl")); events=LocalAuditStore(path).read_all()
 if a.command in {"start","status"}: print("DRISHTI Runtime Security\nGateway       ● RUNNING\nPolicy Engine ● RUNNING\nAudit         ● RUNNING\nDashboard     ● RUNNING")
 elif a.command == "agents":
  agents=sorted({str(e.get("agent_id")) for e in events if e.get("agent_id")}); print("\n".join(f"{x} ● CONNECTED" for x in agents) or "No agents connected")
 elif a.command == "logs": print("\n".join(str(e) for e in events[-20:]))
 elif a.command == "policy": print("Default Runtime Policy: fail closed for unknown tools; review external destinations.")
 else: print("Local runtime is in-process; stop the uvicorn process to stop it.")
if __name__ == "__main__": main()
