# Drishti backend

A local-only Python foundation with deterministic synthetic data. The agent receives a
`ToolExecutor` capability, while simulated adapters are private to the tool registry
and are callable only through `EnforcedToolGateway` policy and audit enforcement.

## Development

```bash
cd backend
python -m pytest
```
