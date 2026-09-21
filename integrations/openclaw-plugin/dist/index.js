/** Native OpenClaw enforcement adapter. It intentionally contains no policy logic. */
import { randomUUID } from "node:crypto";

const PROVENANCE = new Set(["user", "system", "agent", "document", "webpage", "email", "tool_result", "mcp_tool_description"]);
const string = (value, fallback) => typeof value === "string" && value.trim() ? value : fallback;

export function normalizeAction(event, ctx = {}, config = {}) {
  // OpenClaw 2026.9.5 gives hook data directly, not under legacy toolCall/context.
  const metadata = event?._drishti ?? event?.params?._drishti ?? event?.params?.metadata?.drishti ?? {};
  const tool = string(event?.toolName, "unknown_openclaw_tool");
  const provenance = string(metadata.provenance, "agent");
  return {
    agent_id: string(config.agentId ?? ctx.agentId, "unknown-openclaw-agent"),
    tool, operation: string(metadata.operation, "execute"),
    resource: string(metadata.resource ?? tool, tool),
    arguments: event?.params ?? {},
    scope: string(metadata.scope, "UNSPECIFIED"),
    // OpenClaw does not guarantee prompt history in this hook. Unknown is honest.
    user_intent: string(metadata.user_intent ?? ctx.requester?.userIntent, "unknown"),
    provenance: PROVENANCE.has(provenance) ? provenance : "agent",
    data_classification: string(metadata.data_classification, "internal"),
    destination: metadata.destination,
    request_id: string(metadata.request_id ?? event?.toolCallId, randomUUID()),
    run_id: string(event?.runId ?? ctx.runId, undefined),
    session_id: string(ctx.sessionId, undefined)
  };
}

function block(reason) {
  // OpenClaw's before_tool_call contract consumes a blocking result. Keep the
  // decision and request ID in the reason rather than exposing any credential.
  return { block: true, blockReason: `DRISHTI BLOCK: ${reason}` };
}

export function createDrishtiPlugin(api) {
  const config = api.config ?? {};
  const endpointValue = config.DRISHTI_BASE_URL ?? config.endpoint;
  const agentId = config.DRISHTI_AGENT_ID ?? config.agentId;
  const credentialEnv = config.DRISHTI_TOKEN ?? config.credentialEnv;
  if (!endpointValue || !agentId || !credentialEnv) {
    throw new Error("DRISHTI plugin requires DRISHTI_BASE_URL, DRISHTI_AGENT_ID, and DRISHTI_TOKEN (an environment variable name)");
  }
  if ((config.DRISHTI_FAIL_MODE ?? "closed") !== "closed" || config.failOpen === true) throw new Error("DRISHTI fail-open is forbidden for protected tools");
  const endpoint = `${endpointValue.replace(/\/$/, "")}/v1/actions/evaluate`;
  api.on("before_tool_call", async (event, ctx = {}) => {
    const token = process.env[credentialEnv];
    if (!token) return block("missing scoped credential");
    const action = normalizeAction(event, ctx, { ...config, agentId: agentId ?? ctx.agentId });
    let response;
    try {
      response = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify(action), signal: AbortSignal.timeout(config.timeoutMs ?? 5000)
      });
    } catch {
      return block("security service unavailable");
    }
    if (!response.ok) return block(`security service rejected evaluation (${response.status})`);
    let result;
    try { result = await response.json(); } catch { return block("invalid security response"); }
    if (!result || typeof result !== "object" || !["allow", "block", "review"].includes(result.decision)) {
      return block("invalid security response");
    }
    if (result.decision === "allow") return undefined;
    if (result.decision === "review") {
      return { requireApproval: {
        title: "DRISHTI approval required",
        description: result.reason ?? "This protected action requires explicit approval.",
        severity: "warning", pluginId: "drishti", allowedDecisions: ["allow-once", "deny"],
        onResolution: async (decision) => {
          if (decision !== "allow-once") return;
          await fetch(`${endpointValue.replace(/\/$/, "")}/v1/actions/${result.request_id}/approve`, {
            method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
            body: JSON.stringify({ agent_id: action.agent_id, action_hash: result.action_hash })
          });
        }
      }};
    }
    return block(result.reason ?? result.decision_reasons?.join(", ") ?? "blocked");
  });
}

export default createDrishtiPlugin;
