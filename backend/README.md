# Drishti backend

A local-only Python foundation with deterministic synthetic data. The agent receives a
`ToolExecutor` capability, while simulated adapters are private to the tool registry
and are callable only through `EnforcedToolGateway` policy and audit enforcement.

## Security model

DRISHTI evaluates a typed `Action` before every dispatch. An action carries the
agent, tool, operation, resource, arguments, scope, user intent, provenance, data
classification, destination, request ID, and timestamp. Decisions are deterministic:
`ALLOW` dispatches, while `REVIEW` and `BLOCK` stop before the adapter runs.

The local InvoiceBot demonstrates `search_documents`, `read_document`,
`query_customer`, and `send_email`. Document-, webpage-, email-, tool-result-, and
MCP-description-originated content is recorded as provenance **data, not authority**.
Audit JSONL events preserve the action, decision reasons, provenance, classification,
and whether an adapter actually executed, enabling reconstruction of blocked attacks.
`LocalAuditStore.get_trace(request_id)` returns typed `AttackTrace` records; all
InvoiceBot actions in one workflow share a request ID. The malicious demonstration is
recorded as **USER → AGENT → DOCUMENT → DANGEROUS ACTION → DRISHTI → BLOCK → TOOL
NOT EXECUTED**: the document's instruction is provenance data, and both attempted
tool calls have `decision=block` and `executed=false`.

## Development

```bash
cd backend
python -m pytest
```
