import test from "node:test";
import assert from "node:assert/strict";
import { createDrishtiPlugin, normalizeAction } from "../src/index.js";

function installPlugin(config = {}) {
  let handler;
  createDrishtiPlugin({
    config: {
      endpoint: "https://security.example/",
      agentId: "openclaw-local",
      credentialEnv: "DRISHTI_TEST_TOKEN",
      ...config
    },
    on: (hook, fn) => {
      assert.equal(hook, "before_tool_call");
      handler = fn;
    }
  });
  assert.ok(handler, "the plugin must register before_tool_call");
  return handler;
}

function mockFetch(t, implementation) {
  const prior = global.fetch;
  global.fetch = implementation;
  t.after(() => { global.fetch = prior; });
}

test("normalizes OpenClaw metadata into the backend Action contract", () => {
  const action = normalizeAction({ toolCall: { name: "query_customer", arguments: { scope: "ALL_CUSTOMERS" }, _drishti: { provenance: "document", scope: "ALL_CUSTOMERS", user_intent: "Find Acme invoice" } }, runId: "run-1", sessionId: "session-1" }, { agentId: "openclaw-local" });
  assert.equal(action.agent_id, "openclaw-local"); assert.equal(action.provenance, "document"); assert.equal(action.run_id, "run-1");
});

test("fails closed when DRISHTI is unavailable", async (t) => {
  process.env.DRISHTI_TEST_TOKEN = "secret";
  mockFetch(t, async () => { throw new Error("offline"); });
  const handler = installPlugin();
  const outcome = await handler({ toolCall: { name: "search_documents" } });
  assert.equal(outcome.block, true); assert.match(outcome.reason, /unavailable/);
});

test("allows only an explicit backend ALLOW at the canonical evaluate endpoint", async (t) => {
  process.env.DRISHTI_TEST_TOKEN = "secret";
  mockFetch(t, async (url, options) => {
    assert.equal(url, "https://security.example/v1/actions/evaluate");
    assert.equal(options.headers.authorization, "Bearer secret");
    return new Response(JSON.stringify({ decision: "allow", request_id: "request-1" }), { status: 200 });
  });
  assert.equal(await installPlugin()({ toolCall: { name: "search_documents" } }), undefined);
});

test("returns a terminal block for backend BLOCK", async (t) => {
  process.env.DRISHTI_TEST_TOKEN = "secret";
  mockFetch(t, async () => new Response(JSON.stringify({ decision: "block", reason: "unauthorized tool" }), { status: 200 }));
  const outcome = await installPlugin()({ toolCall: { name: "delete_customer" } });
  assert.deepEqual(outcome, { block: true, reason: "DRISHTI BLOCK: unauthorized tool" });
});

test("returns a terminal approval block for backend REVIEW", async (t) => {
  process.env.DRISHTI_TEST_TOKEN = "secret";
  mockFetch(t, async () => new Response(JSON.stringify({ decision: "review", request_id: "review-1" }), { status: 200 }));
  const outcome = await installPlugin()({ toolCall: { name: "send_email" } });
  assert.deepEqual(outcome, {
    block: true,
    reason: "DRISHTI REVIEW: review-1",
    approvalRequired: true,
    drishtiRequestId: "review-1"
  });
});

test("fails closed for a malformed backend response", async (t) => {
  process.env.DRISHTI_TEST_TOKEN = "secret";
  mockFetch(t, async () => new Response("null", { status: 200 }));
  const outcome = await installPlugin()({ toolCall: { name: "search_documents" } });
  assert.equal(outcome.block, true);
  assert.match(outcome.reason, /invalid security response/);
});

test("fails closed for an HTTP error", async (t) => {
  process.env.DRISHTI_TEST_TOKEN = "secret";
  mockFetch(t, async () => new Response("Unauthorized", { status: 401 }));
  const outcome = await installPlugin()({ toolCall: { name: "search_documents" } });
  assert.equal(outcome.block, true);
  assert.match(outcome.reason, /rejected evaluation \(401\)/);
});

test("fails closed for a timeout", async (t) => {
  process.env.DRISHTI_TEST_TOKEN = "secret";
  mockFetch(t, async () => { throw new DOMException("timed out", "TimeoutError"); });
  const outcome = await installPlugin({ timeoutMs: 1 })({ toolCall: { name: "search_documents" } });
  assert.equal(outcome.block, true);
  assert.match(outcome.reason, /unavailable/);
});

test("fails closed when the scoped credential is missing", async (t) => {
  delete process.env.DRISHTI_TEST_TOKEN;
  t.after(() => { process.env.DRISHTI_TEST_TOKEN = "secret"; });
  mockFetch(t, async () => { throw new Error("fetch must not run without a credential"); });
  const outcome = await installPlugin()({ toolCall: { name: "search_documents" } });
  assert.deepEqual(outcome, { block: true, reason: "DRISHTI BLOCK: missing scoped credential" });
});
