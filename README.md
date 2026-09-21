# DRISHTI

> **See. Verify. Control.**

DRISHTI is an agent-agnostic runtime authorization layer between AI agents and protected tools. Authenticated callers submit one normalized `Action`; the backend evaluates versioned policy, provenance, scope, intent metadata, and advisory risk, then enforces **ALLOW**, **REVIEW**, or **BLOCK** before a protected adapter runs.

**Data is not authority.** Text from documents, webpages, email, tool results, and MCP descriptions can provide context but never inherits a user's permissions.

## How it works

```text
Agent (HTTP / Python SDK / MCP / OpenClaw)
        │ proposed action + provenance + intent
        ▼
DRISHTI core: authenticate → normalize → authorize → assess risk → decide
        │
  ALLOW │ REVIEW / BLOCK
        ▼      └── audit event; adapter never runs
Protected tool
```

| Decision | Result |
| --- | --- |
| `ALLOW` | The protected adapter may execute. A native runtime receives an authorization only; it reports its own execution separately. |
| `REVIEW` | Execution stops pending explicit approval. |
| `BLOCK` | Execution stops before the adapter receives the action. |

DRISHTI does not claim to eliminate prompt injection. It limits the impact of prompt injection by preventing unauthorized actions from reaching protected tools.

## Product experience

The Vite console is a local operations surface for the enforcement gateway. It includes a product landing page, local-demo signup/sign-in entry (not production authentication), onboarding-style integration guidance, a persistent control-plane workspace, an InvoiceBot workbench, a live backend-derived event stream, action inspector, approvals, forensic traces, protected-tool registry, read-only policy view, integrations, and append-only audit view. The interface never fabricates security decisions when the gateway is unavailable.

The included `DemoAgent` and fictional InvoiceBot are deterministic local harnesses, not a production LLM integration. In the InvoiceBot workspace, your submitted local invoice instruction is sent to the backend and translated into guarded search, read, and (when requested) email actions; the response and timeline are derived from those actual gateway results. It supports the local Acme Corp and Mallory Supplies invoice corpus. Use the HTTP, MCP, or SDK boundary to connect a real tool-calling agent.

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
curl -X POST http://localhost:8000/api/demo/review-invoice
```

The malicious path uses document provenance and broad customer scope. Its proposed tool call is blocked and the protected adapters do not execute.

The review path creates a real pending `send_email` action for an external destination. It does not execute until the existing authenticated `POST /v1/actions/{request_id}/approve` endpoint is called. The console asks for a configured scoped agent credential at approval time and never stores or displays it.

### Console configuration and demo path

Set `VITE_API_URL` only when the frontend must use a deployed API URL; local Vite development uses the same-origin `/api` proxy. No frontend environment variable contains an agent token.

For a complete local InvoiceBot attack demonstration: open `/`, choose **View live demo**, open the InvoiceBot workspace, choose **Attack scenario**, then inspect the blocked action from **Attack Traces** or the activity feed. The trace is backend evidence showing document provenance, broad customer scope, policy reasons, risk metadata, and that the protected tool was never executed. Choose **Review scenario** to create a pending external-delivery action; approving it requires a separately configured `DRISHTI_DEMO_TOKEN` (or `DRISHTI_AGENT_TOKENS` entry) and records the actual result.

## Integrate an agent

### HTTP

`POST /v1/actions/evaluate` (also `/api/actions/evaluate`) is the canonical **pre-execution** endpoint: it does not dispatch a tool. `POST /gateway/tool-call` is the gateway-owned execution endpoint. Both require `Authorization: Bearer TOKEN`; the credential is SHA-256 hashed and mapped to the claimed registered agent by `DRISHTI_AGENT_TOKENS=agent_id:sha256(token)`. A REVIEW can be approved through `POST /v1/actions/{request_id}/approve` with the original `agent_id` and `action_hash`; it never dispatches before approval.

```bash
curl -X POST http://localhost:8000/v1/actions/evaluate \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $DRISHTI_TOKEN" \
  -d '{"agent_id":"invoicebot","tool":"query_customer","operation":"query","resource":"customer_records","arguments":{"customer":"Acme Corp"},"scope":"CURRENT_CUSTOMER","user_intent":"Look up Acme Corp","provenance":"user","data_classification":"confidential"}'
```

### Python SDK

```python
from drishti import Drishti

security = Drishti("http://127.0.0.1:8000", token="scoped-agent-token")
result = security.execute(
    agent_id="invoicebot", tool="query_customer", operation="query",
    resource="customers", arguments={"customer": "Acme Corp"},
    scope="CURRENT_CUSTOMER", user_intent="Look up Acme Corp customer",
    provenance="user", data_classification="confidential",
)
```

The SDK submits to the gateway and has no local policy fallback; it raises `PermissionError` for REVIEW or BLOCK.

### MCP gateway and native OpenClaw plugin

`POST /mcp` is a guarded JSON-RPC MCP **server for the configured DRISHTI adapters**, not a universal upstream proxy. `tools/call` requires the same bearer credential and enters the same `EnforcedToolGateway`; there is no unguarded MCP execution route.

The native package in `integrations/openclaw-plugin` registers OpenClaw's `api.on("before_tool_call", handler)` lifecycle hook. It normalizes only hook-provided metadata and sends it to `/v1/actions/evaluate`; unavailable, malformed, BLOCK, and REVIEW responses return a terminal hook block. It contains no policy engine. An ALLOW returns `undefined`, allowing OpenClaw to invoke the original tool. This is distinct from MCP configuration.

```bash
export DRISHTI_TOKEN='token supplied by your control plane' # never commit or log it
export DRISHTI_OPENCLAW_TOKEN="$DRISHTI_TOKEN"
drishti login
drishti start
drishti connect openclaw
```

Configure the installed plugin with `DRISHTI_BASE_URL`, `DRISHTI_AGENT_ID`, `DRISHTI_TOKEN` (the *environment-variable name*, for example `DRISHTI_OPENCLAW_TOKEN`), and `DRISHTI_FAIL_MODE=closed`. `drishti connect openclaw` validates CLI support, installs the package only through OpenClaw's own CLI, and writes a mode-0600 secret-free configuration suggestion; it never rewrites an unknown OpenClaw config schema.

## Decisions, risk, and audit

`RuntimeRiskEngine` calculates a deterministic 0–100 score from fixed signals including authorization, broad scope, untrusted provenance, sensitive data, destination verification, destructive operations, intent mismatch, behavioral deviation, privilege escalation, and risky chains. Levels are LOW `<25`, MEDIUM `<50`, HIGH `<75`, and CRITICAL `>=75`.

The score is advisory and never silently changes an ALLOW to BLOCK or REVIEW. Policy and agent/tool authorization are authoritative. Unknown tools and unauthorized agents block. External or unverified destinations review, or block when combined with another policy violation. Audit records retain request ID, intent metadata, provenance, action metadata, risk assessment, policy decision, reasons, and execution status without storing raw conversation history.

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

- Set `DRISHTI_AGENT_TOKENS` from a secret manager and use distinct per-agent credentials.
- Load signed, versioned policy rather than relying solely on code-composed policy.
- Route protected tools through service identities that agents cannot bypass.
- Connect REVIEW to a human approval workflow before permitting automatic execution.
- Restrict audit access and retain only the security metadata your organization needs.

See [`backend/README.md`](backend/README.md) for implementation notes and [`infra/README.md`](infra/README.md) for infrastructure details.
