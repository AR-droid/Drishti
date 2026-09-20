# DRISHTI OpenClaw plugin

This native plugin registers OpenClaw's `before_tool_call` hook. It sends a normalized Action to `POST /v1/actions/authorize`; it never duplicates DRISHTI policy in JavaScript. Any transport, authentication, response, or timeout failure blocks the call.

Configure through OpenClaw's supported plugin configuration mechanism:

```json
{"endpoint":"https://drishti.example","agentId":"openclaw-prod-01","credentialEnv":"DRISHTI_OPENCLAW_TOKEN","failOpen":false}
```

Export `DRISHTI_OPENCLAW_TOKEN` from a secret manager/service environment, not a checked-in config file. The plugin never logs it. `ALLOW` returns no decision; `BLOCK` returns a before-tool block result; `REVIEW` returns a block result with `approvalRequired`. The exact approval resume operation depends on the installed OpenClaw version and must be verified before treating REVIEW as a completed approval integration.
