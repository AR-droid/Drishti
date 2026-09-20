# DRISHTI — Dynamic Runtime Inspection & Security for Trusted AI

**SEE. VERIFY. CONTROL.** DRISHTI is an agent-agnostic runtime authorization boundary for tool-using AI systems. It accepts normalized actions from MCP, HTTP/API, and Python SDK integrations, evaluates deterministic security signals, and only then dispatches a protected tool. **Data is not authority:** text from a document, webpage, email, tool result, or MCP tool description never inherits the user's authority.

DRISHTI does not claim to eliminate prompt injection. It limits the impact of prompt injection by preventing unauthorized agent actions from reaching protected tools.

## Architecture

```
Any agent (MCP / HTTP / SDK) -> DRISHTI gateway -> normalized Action
    -> deterministic risk engine + policy -> ALLOW | REVIEW | BLOCK -> protected tool
```

The core is framework-neutral: it contains no framework- or OpenClaw-specific authorization branch. OpenClaw is an MCP integration target only; it has not been tested in this repository.

### Deterministic risk and decisions

`RuntimeRiskEngine` is shared by local execution and the Lambda package. It calculates a 0–100 score from fixed weighted signals: agent/tool authorization (35 each), broad scope (24), untrusted provenance (20), sensitive data (16), unverified destination (15), destructive operation (24), intent mismatch (22), behavioral deviation (12), privilege escalation (12), and risky chains (8). Levels are LOW <25, MEDIUM <50, HIGH <75, CRITICAL >=75. The score is explainability and review input—not the sole block rule. Deterministic policy and authorization remain authoritative.

Unknown registered tools and unauthorized registered agents block. External or unverified destinations review (or block when another policy violation exists). The output includes decision, score, level, flags, policy rule, reasons, and execution status. A BLOCK/REVIEW is never dispatched to an adapter.

## Integration interfaces

* **HTTP:** `POST /v1/actions/evaluate` (and `/gateway/tool-call`) accepts normalized Actions and returns a decision, risk score, flags, reasons, and request ID. `POST /v1/actions/{request_id}/approve` is the explicit approval path for REVIEW; it never dispatches before approval.
* **MCP:** `POST /mcp` is a JSON-RPC MCP surface implementing `initialize`, `tools/list`, and guarded `tools/call`. Put DRISHTI in front of tool adapters and attach action metadata in `params._drishti` (`agent_id`, intent, scope, provenance, classification). Every call enters `EnforcedToolGateway`; there is no unguarded MCP call route.
* **SDK:** `from drishti import Drishti`; the SDK submits to the same gateway policy rather than implementing a divergent client policy. It raises `PermissionError` for REVIEW/BLOCK.
* **SSE:** `GET /api/events` emits backend audit-derived ALLOW/REVIEW/BLOCK events. It does not fabricate frontend events.

The deterministic `DemoAgent` and fictional InvoiceBot remain a local test harness, not a claim of a real LLM agent. Deployers can replace it with a tool-calling agent using the HTTP/MCP boundary. No credentials are required for the local fallback demonstration.

## Attack trace and audit

Events are append-only and keyed by `request_id`; the trace retains user intent, agent, source provenance, action, risk assessment, policy, decision, and execution status. The malicious InvoiceBot flow uses document provenance and requests `ALL_CUSTOMERS`; it is blocked before the customer or email adapter runs.

## Local development

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
uvicorn app.api.main:app --reload --port 8000
# separate terminal
curl -X POST http://localhost:8000/api/demo/safe-invoice
curl -X POST http://localhost:8000/api/demo/malicious-invoice
pytest -q
drishti status
drishti agents
drishti logs
drishti policy
```

Set `DRISHTI_MODE=local` (the default operational mode) and optionally `DRISHTI_AUDIT_PATH`. `drishti start/status` reports in-process runtime components; use the uvicorn process manager to start/stop the server. Agent state is derived from audit activity, so unconnected integrations are never reported as connected.

### OpenClaw (safe MCP adapter workflow)

OpenClaw is an MCP client integration, not a special authorization path. Authenticate
without printing the token, start the gateway, and generate a reviewed MCP entry:

```bash
export DRISHTI_TOKEN='token supplied by your control plane' # never commit or log it
drishti login
drishti start
export OPENCLAW_CONFIG=/path/to/openclaw/config.json  # when not in a conventional location
drishti connect openclaw
```

`connect openclaw` detects a real local configuration and writes a mode-0600,
secret-free `~/.drishti/openclaw-mcp.json` Streamable HTTP MCP snippet. It does not
rewrite OpenClaw configuration because an unknown OpenClaw schema/version cannot be
safely guessed. Merge that exact entry into OpenClaw's MCP configuration and restart
OpenClaw. Never give OpenClaw direct protected-tool credentials: it is protected only
when its calls use DRISHTI's `/mcp` endpoint.

### Custom Python agent

```python
from drishti import Drishti
security = Drishti("http://127.0.0.1:8000")
result = security.execute(agent_id="invoicebot", tool="query_customer", operation="query",
    resource="customers", arguments={"customer": "Acme Corp"}, scope="CURRENT_CUSTOMER",
    user_intent="Look up Acme Corp customer", provenance="user", data_classification="confidential")
```

The SDK has no local policy fallback: a gateway failure does not call an executor.

## AWS mode

Set `DRISHTI_MODE=aws` and `DRISHTI_STORAGE_BACKEND=dynamodb`. The SAM template deploys API Gateway HTTP API -> Lambda -> this same core package, DynamoDB policy/action/event/trace stores, encrypted/versioned private S3 artifacts, JSON CloudWatch access logs, X-Ray tracing, and least-privilege runtime IAM. Amplify Hosting serves the Vite frontend; configure `VITE_API_URL` to the API output rather than committing an endpoint.

```bash
sam build --template-file infra/template.yaml
sam deploy --guided --template-file infra/template.yaml
npm ci && VITE_API_URL=https://YOUR_API.execute-api.REGION.amazonaws.com/dev npm run build
```

Deployment credentials are required only for deployment. Runtime IAM is scoped to the created tables, permitted artifact prefixes, and function log group; credentials are never hard-coded. DynamoDB stores security metadata rather than unnecessary tool payloads. Configure MCP clients to point at the deployed `/mcp` endpoint and supply registered agent metadata.

## Limitations and deployment hardening

Policy configuration is currently code-composed with a DynamoDB persistence abstraction; production deployments should load signed/versioned policies, authenticate agents at the gateway, authenticate MCP transport, and route protected tools through service identities that agents cannot bypass. REVIEW needs an approval workflow integration before automatic execution. No AWS deployment, Amplify deployment, or OpenClaw connection has been performed here.

## Native OpenClaw enforcement (pre-release verification required)

DRISHTI now ships a native package at `integrations/openclaw-plugin`. Unlike the MCP gateway, it registers OpenClaw's `before_tool_call` hook and calls the centralized `POST /v1/actions/authorize` endpoint **before** native OpenClaw executes a tool. The endpoint evaluates the existing `RuntimeRiskEngine` and policy without dispatching DRISHTI's synthetic adapters. An authorization audit event has `executed: false`; DRISHTI does not fabricate a native-tool execution result.

```text
OpenClaw native tool call -> DRISHTI before_tool_call plugin -> /v1/actions/authorize
  -> RuntimeRiskEngine + policy -> ALLOW | REVIEW | BLOCK -> OpenClaw tool runtime
```

The plugin sends `agent_id`, tool identity, operation, resource, arguments, scope, user intent, provenance, classification, destination, `request_id`, `run_id`, and `session_id` when OpenClaw supplies them. It contains no TypeScript policy. A network error, missing credential, malformed response, or non-ALLOW response returns the OpenClaw block result; it never fails open. REVIEW returns a blocking approval-required result and therefore does not execute the tool. Approval resumption must be tested with the installed OpenClaw version before it is represented as a completed approval workflow.

### Connect a real installation

The repository does not include an OpenClaw binary, so no real-installation claim is made by this checkout. On a machine with OpenClaw installed, an active config, and the documented `openclaw plugins install` CLI command:

```bash
cd backend
pip install -e '.[dev]'
export DRISHTI_TOKEN='scoped bearer credential'       # source from a secret manager
export DRISHTI_ENDPOINT='https://YOUR-DRISHTI-API'
drishti login
# start the local API only when DRISHTI_ENDPOINT is local
drishti connect openclaw
```

`connect openclaw` detects both the `openclaw` executable and its active config, refuses to proceed without login and `/health`, asks OpenClaw itself to install the distributable plugin, and verifies it appears in `openclaw plugins list`. It writes only a mode-0600, secret-free configuration template in `~/.drishti/openclaw-plugin-config.json`; it does not guess or modify an unknown OpenClaw configuration schema. Put the indicated `DRISHTI_OPENCLAW_TOKEN` environment variable in the OpenClaw service's secret environment, apply the generated plugin settings using that OpenClaw version's documented configuration command, and restart OpenClaw.

Before considering an instance protected, run and retain the following real-install verification: (1) an allowlisted call is allowed and executes; (2) a dangerous `query_customer` call with `scope=ALL_CUSTOMERS`, document provenance, and sensitive data is BLOCKed and its tool side effect does not occur; (3) a REVIEW call has no side effect before approval; (4) stopping DRISHTI blocks a protected call; and (5) fetch `GET /api/traces/{request_id}` and confirm its request/run/session metadata and `executed: false` enforcement record. The last field reflects what DRISHTI actually knows at the before-tool boundary, not a fabricated post-execution status.

Run package-level checks without OpenClaw using:

```bash
cd integrations/openclaw-plugin
npm test
npm run build
```
