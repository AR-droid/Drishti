import test from "node:test";
import assert from "node:assert/strict";
import { createDrishtiPlugin, normalizeAction } from "../src/index.js";

test("normalizes OpenClaw metadata into the backend Action contract", () => {
  const action = normalizeAction({ toolCall: { name: "query_customer", arguments: { scope: "ALL_CUSTOMERS" }, _drishti: { provenance: "document", scope: "ALL_CUSTOMERS", user_intent: "Find Acme invoice" } }, runId: "run-1", sessionId: "session-1" }, { agentId: "openclaw-local" });
  assert.equal(action.agent_id, "openclaw-local"); assert.equal(action.provenance, "document"); assert.equal(action.run_id, "run-1");
});

test("fails closed when DRISHTI is unavailable", async () => {
  const prior = global.fetch; process.env.DRISHTI_TEST_TOKEN = "secret";
  global.fetch = async () => { throw new Error("offline"); };
  let handler; createDrishtiPlugin({ config: { endpoint: "https://security.invalid", agentId: "openclaw-local", credentialEnv: "DRISHTI_TEST_TOKEN" }, on: (_, fn) => { handler = fn; } });
  const outcome = await handler({ toolCall: { name: "search_documents" } });
  assert.equal(outcome.block, true); assert.match(outcome.reason, /unavailable/); global.fetch = prior;
});

test("allows only an explicit backend ALLOW", async () => {
  const prior = global.fetch; process.env.DRISHTI_TEST_TOKEN = "secret";
  global.fetch = async () => new Response(JSON.stringify({ decision: "allow" }), { status: 200 });
  let handler; createDrishtiPlugin({ config: { endpoint: "https://security.example", agentId: "openclaw-local", credentialEnv: "DRISHTI_TEST_TOKEN" }, on: (_, fn) => { handler = fn; } });
  assert.equal(await handler({ toolCall: { name: "search_documents" } }), undefined); global.fetch = prior;
});
