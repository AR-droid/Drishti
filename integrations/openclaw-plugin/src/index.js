/** Native OpenClaw enforcement adapter. It intentionally contains no policy logic. */
import { randomUUID } from "node:crypto";

const PROVENANCE = new Set(["user", "system", "agent", "document", "webpage", "email", "tool_result", "mcp_tool_description"]);
const string = (value, fallback) => typeof value === "string" && value.trim() ? value : fallback;

export function normalizeAction(event, config) {
  const call = event?.toolCall ?? event?.tool_call ?? event ?? {};
  const context = event?.context ?? event?.runContext ?? {};
  const metadata = call._drishti ?? call.metadata?.drishti ?? context._drishti ?? {};
  const tool = string(call.name ?? call.tool ?? event?.tool, "unknown_openclaw_tool");
  const provenance = string(metadata.provenance, "agent");
  return {
    agent_id: config.agentId,
    tool,
    operation: string(metadata.operation ?? call.operation, "execute"),
    resource: string(metadata.resource ?? tool, tool),
    arguments: call.arguments ?? call.input ?? {},
    scope: string(metadata.scope, "UNSPECIFIED"),
    // OpenClaw does not guarantee prompt history in this hook. Unknown is honest.
    user_intent: string(metadata.user_intent ?? context.userIntent ?? context.user_intent, "unknown"),
    provenance: PROVENANCE.has(provenance) ? provenance : "agent",
    data_classification: string(metadata.data_classification, "internal"),
    destination: metadata.destination,
    request_id: string(metadata.request_id ?? event?.requestId ?? context.requestId, randomUUID()),
    run_id: string(event?.runId ?? context.runId, undefined),
    session_id: string(event?.sessionId ?? context.sessionId, undefined)
  };
}

function block(reason, decision = "block") {
  // OpenClaw's before_tool_call contract consumes a blocking result. Keep the
  // decision and request ID in the reason rather than exposing any credential.
  return { block: true, reason: `DRISHTI ${decision.toUpperCase()}: ${reason}` };
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
  api.on("before_tool_call", async (event) => {
    const token = process.env[credentialEnv];
    if (!token) return block("missing scoped credential");
    const action = normalizeAction(event, { ...config, agentId });
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
    if (result.decision === "allow") return undefined;
    if (result.decision === "review") {
      // An approval-capable OpenClaw runtime may render this as approval UI; in
      // every runtime it blocks execution until an explicit continuation occurs.
      return { ...block(result.request_id ?? "approval required", "review"), approvalRequired: true, drishtiRequestId: result.request_id };
    }
    return block(result.reason ?? result.decision_reasons?.join(", ") ?? "blocked", "block");
  });
}

export default createDrishtiPlugin;
