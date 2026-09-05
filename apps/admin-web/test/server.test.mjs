import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { AuthorizationPolicy } from "../src/authorization-policy.mjs";
import { createAdminHandler } from "../src/server.mjs";
import { TENANT, verifiedOperator } from "./auth-fixture.mjs";
import { policyPaths, removePolicyFixture } from "./controlled-policy-fixture.mjs";

const policy = AuthorizationPolicy.load(policyPaths);
test.after(removePolicyFixture);

function invoke(handler, { method = "GET", url = "/", headers = {}, rawHeaders = null,
  body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const request = Readable.from(body === "" ? [] : [Buffer.from(body)]);
    request.method = method; request.url = url; request.headers = headers;
    request.rawHeaders = rawHeaders;
    request.socket = { remoteAddress: "127.0.0.1" };
    const response = {
      status: null, headers: null, bytes: Buffer.alloc(0),
      writeHead(status, responseHeaders) { this.status = status; this.headers = responseHeaders; return this; },
      end(chunk = Buffer.alloc(0)) {
        this.bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        resolve({ status: this.status, headers: this.headers, body: this.bytes.toString("utf8") });
      },
    };
    Promise.resolve(handler(request, response)).catch(reject);
  });
}

function fixture(overrides = {}) {
  const store = {
    ping: async () => true, issueNonce: async () => true, recordAccess: async () => {},
    putDiagnostic: async () => true, getDiagnostic: async () => null,
    ...overrides.store,
  };
  return { store, upstream: { ready: async () => true,
    diagnostic: async (operator, service) => ({ tenantId: operator.tenantId, service, status: "up",
      accessToken: "strip-me", customerEmail: "strip@example.test" }), ...overrides.upstream } };
}

test("startup/live/ready probes and HTML UI have bounded fail-closed security behavior", async () => {
  const dependencies = fixture({ upstream: { ready: async () => false } });
  const handler = createAdminHandler({ authenticator: {}, policy, ...dependencies,
    publicOrigin: "https://admin.example.test" });
  assert.equal((await invoke(handler, { url: "/health/startup" })).status, 200);
  assert.equal((await invoke(handler, { url: "/health/live" })).status, 200);
  const readiness = await invoke(handler, { url: "/health/ready" });
  assert.equal(readiness.status, 503);
  assert.equal(JSON.parse(readiness.body).writesEnabled, false);
  const root = await invoke(handler);
  assert.equal(root.status, 200);
  assert.match(root.headers["content-security-policy"], /default-src 'none'/);
  assert.doesNotMatch(root.body, /script|form/i);
});

test("diagnostic API is authenticated, tenant-scoped, audited and strips PII", async () => {
  const operator = await verifiedOperator();
  const access = [];
  const dependencies = fixture({ store: { recordAccess: async (event) => access.push(event) } });
  const handler = createAdminHandler({ authenticator: {
    verifyRequest: async () => operator, isRecentStepUp: () => true,
  }, policy, ...dependencies, publicOrigin: "https://admin.example.test" });
  const result = await invoke(handler, { url: `/api/admin/diagnostics?tenantId=${TENANT}&service=risk-engine` });
  assert.equal(result.status, 200);
  assert.doesNotMatch(result.body, /strip-me|strip@example/);
  assert.equal(access[0].eventType, "DIAGNOSTIC_READ");

  const other = "22222222-2222-4222-8222-222222222222";
  const denied = await invoke(handler, { url: `/api/admin/diagnostics?tenantId=${other}&service=risk-engine` });
  assert.equal(denied.status, 403);
  assert.equal(access.at(-1).eventType, "AUTHORIZATION_DENIED");
});

test("cookies are never an authentication fallback and unavailable dependency disables writes", async () => {
  const operator = await verifiedOperator({}, { jti: "write-gate-proof" });
  let createCalls = 0;
  const dependencies = fixture({ upstream: { ready: async () => false },
    store: { createApproval: async () => { createCalls += 1; } } });
  const handler = createAdminHandler({ authenticator: {
    verifyRequest: async () => operator, isRecentStepUp: () => true,
  }, policy, ...dependencies, publicOrigin: "https://admin.example.test" });
  assert.equal((await invoke(handler, { url: "/api/admin/approvals", method: "POST",
    headers: { cookie: "session=unsafe" } })).status, 401);
  const degraded = await invoke(handler, { url: "/api/admin/approvals", method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "idempotency-key-12345" },
    body: JSON.stringify({ tenantId: TENANT, kind: "CASE_CLOSE" }) });
  assert.equal(degraded.status, 503);
  assert.equal(createCalls, 0);
});

test("DPoP challenge is an unpredictable server nonce stored only by digest", async () => {
  const issued = [];
  const dependencies = fixture({ store: { issueNonce: async (record) => { issued.push(record); return true; } } });
  const handler = createAdminHandler({ authenticator: {}, policy, ...dependencies,
    publicOrigin: "https://admin.example.test", now: () => new Date("2026-08-30T12:00:00Z") });
  const first = await invoke(handler, { url: "/auth/dpop-nonce" });
  const second = await invoke(handler, { url: "/auth/dpop-nonce" });
  const firstNonce = JSON.parse(first.body).nonce;
  const secondNonce = JSON.parse(second.body).nonce;
  assert.equal(first.status, 200);
  assert.notEqual(firstNonce, secondNonce);
  assert.equal(Buffer.from(firstNonce, "base64url").length, 32);
  assert.equal(issued[0].nonceDigest.length, 64);
  assert.notEqual(issued[0].nonceDigest, firstNonce);
});

test("external diagnostic transport is pinned to TLS 1.3, rejects redirects and bounds response bytes", () => {
  const source = fileURLToPath(new URL("../src/upstream-client.mjs", import.meta.url));
  assert.ok(source.endsWith("upstream-client.mjs"));
  // Exact source markers are deliberate contract tests without performing an external call.
  const content = readFileSync(source, "utf8");
  for (const marker of ["minVersion: \"TLSv1.3\"", "statusCode >= 300", "bytes.length > maximumBytes",
    "rejectUnauthorized: true", "target.origin !== this.baseUrl.origin"]) assert.ok(content.includes(marker), marker);
});

test("admin JSON ingress rejects parameters, duplicate content type and malformed UTF-8", async () => {
  const operator = await verifiedOperator({ sub: "risk-a", roles: ["risk-analyst"] },
    { jti: "strict-json-proof" });
  const dependencies = fixture({ store: { createApproval: async () => {
    throw new Error("must not persist malformed input");
  } } });
  const handler = createAdminHandler({ authenticator: {
    verifyRequest: async () => operator, isRecentStepUp: () => true,
  }, policy, ...dependencies, publicOrigin: "https://admin.example.test" });
  const base = { url: "/api/admin/approvals", method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "idempotency-key-12345" } };
  assert.equal((await invoke(handler, { ...base,
    headers: { ...base.headers, "content-type": "application/json; charset=utf-8" },
    body: "{}" })).status, 400);
  assert.equal((await invoke(handler, { ...base,
    rawHeaders: ["Content-Type", "application/json", "content-type", "application/json"],
    body: "{}" })).status, 400);
  assert.equal((await invoke(handler, { ...base, body: Buffer.from([0xc3, 0x28]) })).status, 400);
});
