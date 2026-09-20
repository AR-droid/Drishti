# DRISHTI

> **See. Verify. Control.**

DRISHTI is a runtime authorization boundary for tool-using AI systems. It receives a proposed action from an HTTP client, MCP client, or Python SDK; evaluates deterministic policy and risk signals; and **only then** dispatches a protected tool.

**Data is not authority.** Text from documents, webpages, email, tool results, and MCP descriptions can provide context but never inherits a user's permissions.

## How it works

```text
Agent (HTTP / MCP / SDK)
        │ proposed action + provenance + intent
        ▼
DRISHTI gateway: normalize → authorize → assess risk → decide
        │
  ALLOW │ REVIEW / BLOCK
        ▼      └── audit event; adapter never runs
Protected tool
```

| Decision | Result |
| --- | --- |
| `ALLOW` | The protected adapter may execute and the decision is audited. |
| `REVIEW` | Execution stops pending explicit approval. |
| `BLOCK` | Execution stops before the adapter receives the action. |

DRISHTI does not claim to eliminate prompt injection. It limits the impact of prompt injection by preventing unauthorized actions from reaching protected tools.

## Product experience

The Vite console is a local operations surface for the enforcement gateway. It offers a live backend-derived event stream, safe and malicious InvoiceBot demonstrations, an action inspector with validation, forensic traces, and an append-only audit view. The interface never fabricates security decisions when the gateway is unavailable.

The included `DemoAgent` and fictional InvoiceBot are deterministic local harnesses, not a production LLM integration. Use the HTTP, MCP, or SDK boundary to connect a real tool-calling agent.

## Quick start

### Start the gateway

Requires Python 3.11+.

```bash
cd backend
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
uvicorn app.api.main:app --reload --port 8000
```

Local mode is the default and writes append-only audit events to `drishti-audit.jsonl` unless `DRISHTI_AUDIT_PATH` is set.

### Start the console

In a second terminal, from the repository root:

```bash
npm install
npm run dev
```

Open Vite's printed URL (normally `http://localhost:5173`). The development server proxies `/api` calls to `http://localhost:8000`.

### Verify the boundary

Use the console's demo controls, or run:

```bash
curl -X POST http://localhost:8000/api/demo/safe-invoice
curl -X POST http://localhost:8000/api/demo/malicious-invoice
```

The malicious path uses document provenance and broad customer scope. Its proposed tool call is blocked and the protected adapters do not execute.

## Integrate an agent

### HTTP

`POST /v1/actions/evaluate` (also `/api/actions/evaluate`) returns the decision, reasons, execution status, and request ID. `POST /gateway/tool-call` provides the fuller protocol response. A REVIEW can be approved through `POST /v1/actions/{request_id}/approve`; it never dispatches before approval.

```bash
curl -X POST http://localhost:8000/v1/actions/evaluate \
  -H 'content-type: application/json' \
  -d '{"agent_id":"invoicebot","tool":"query_customer","operation":"query","resource":"customer_records","arguments":{"customer":"Acme Corp"},"scope":"CURRENT_CUSTOMER","user_intent":"Look up Acme Corp","provenance":"user","data_classification":"confidential"}'
```

### Python SDK

```python
from drishti import Drishti

security = Drishti("http://127.0.0.1:8000")
result = security.execute(
    agent_id="invoicebot", tool="query_customer", operation="query",
    resource="customers", arguments={"customer": "Acme Corp"},
    scope="CURRENT_CUSTOMER", user_intent="Look up Acme Corp customer",
    provenance="user", data_classification="confidential",
)
```

The SDK submits to the gateway and has no local policy fallback; it raises `PermissionError` for REVIEW or BLOCK.

### MCP and OpenClaw

`POST /mcp` is a guarded JSON-RPC MCP surface implementing `initialize`, `tools/list`, and `tools/call`. Add action metadata in `params._drishti`: `agent_id`, `operation`, `resource`, `scope`, `user_intent`, `provenance`, `data_classification`, and optional destination/request ID. Every MCP call enters the same `EnforcedToolGateway`; there is no unguarded MCP execution route.

OpenClaw is an MCP client integration target, not a special authorization path:

```bash
export DRISHTI_TOKEN='token supplied by your control plane' # never commit or log it
drishti login
drishti start
drishti connect openclaw
```

`connect openclaw` writes a mode-0600, secret-free `~/.drishti/openclaw-mcp.json` snippet without guessing or rewriting an unknown OpenClaw configuration schema. Keep protected-tool credentials away from the MCP client; protection applies only when calls use DRISHTI's `/mcp` endpoint.

## Decisions, risk, and audit

`RuntimeRiskEngine` calculates a deterministic 0–100 score from fixed signals including authorization, broad scope, untrusted provenance, sensitive data, destination verification, destructive operations, intent mismatch, behavioral deviation, privilege escalation, and risky chains. Levels are LOW `<25`, MEDIUM `<50`, HIGH `<75`, and CRITICAL `>=75`.

The score supports explainability and review; it is not the only block mechanism. Policy and agent/tool authorization are authoritative. Unknown registered tools and unauthorized registered agents block. External or unverified destinations review, or block when combined with another policy violation. Audit records retain request ID, intent, provenance, action, risk assessment, policy decision, reasons, and execution status without storing unnecessary tool payloads.

## Quality checks

```bash
# Frontend, from the repository root
npm run lint
npm run build

# Backend
cd backend
python -m pytest -q
```

## AWS deployment

Set `DRISHTI_MODE=aws` and `DRISHTI_STORAGE_BACKEND=dynamodb`. The SAM template deploys API Gateway HTTP API → Lambda → the same core package, DynamoDB policy/action/event/trace stores, encrypted private S3 artifacts, CloudWatch access logs, X-Ray tracing, and scoped runtime IAM.

```bash
sam build --template-file infra/template.yaml
sam deploy --guided --template-file infra/template.yaml
npm install
VITE_API_URL=https://YOUR_API.execute-api.REGION.amazonaws.com/dev npm run build
```

Deployment credentials are required only for deployment and must never be committed. Point MCP clients to the deployed `/mcp` endpoint and configure the console with the deployed API URL rather than hard-coding an endpoint.

## Production checklist

- Authenticate agents and MCP transport at the gateway.
- Load signed, versioned policy rather than relying solely on code-composed policy.
- Route protected tools through service identities that agents cannot bypass.
- Connect REVIEW to a human approval workflow before permitting automatic execution.
- Restrict audit access and retain only the security metadata your organization needs.

See [`backend/README.md`](backend/README.md) for implementation notes and [`infra/README.md`](infra/README.md) for infrastructure details.
