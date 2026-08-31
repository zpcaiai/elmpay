import { randomBytes, randomUUID } from "node:crypto";
import { createApprovalCommand, createDecisionCommand } from "./approval-model.mjs";
import { sha256Hex } from "./canonical-json.mjs";
import { buildDiagnosticView } from "./diagnostics.mjs";
import { DatabaseUnavailableError } from "./postgres-store.mjs";
import { UpstreamUnavailableError } from "./upstream-client.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SERVICE = /^[a-z][a-z0-9-]{1,62}$/;
const APPROVAL_PATH = /^\/api\/admin\/approvals\/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?:\/decisions)?$/;
const CSP = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'; style-src 'none'; img-src 'none'";

const html = Buffer.from(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Elmpay Admin</title></head><body><main><h1>Elmpay privileged operations</h1><p>This boundary requires a corporate IdP ES256 access token and a fresh DPoP proof for every API request.</p><p>Writes require recent phishing-resistant step-up, governed authorization, an independent approver, a live upstream dependency, and durable audit.</p><nav><a href="/health/ready">Readiness</a> <a href="/health/live">Liveness</a></nav></main></body></html>`, "utf8");

function securityHeaders() {
  return {
    "cache-control": "no-store", "content-security-policy": CSP,
    "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "x-frame-options": "DENY",
  };
}

function sendJson(response, status, body, extraHeaders = {}) {
  const bytes = Buffer.from(JSON.stringify(body), "utf8");
  response.writeHead(status, { ...securityHeaders(), "content-type": "application/json",
    "content-length": bytes.length, ...extraHeaders }).end(bytes);
}

function problem(response, status, code, requestId, extraHeaders = {}) {
  sendJson(response, status, { type: "about:blank", title: code, status, requestId }, extraHeaders);
}

async function boundedJson(request, maximumBytes = 32_768) {
  const raw = [];
  for (let index = 0; index < (request.rawHeaders?.length ?? 0); index += 2) {
    if (String(request.rawHeaders[index]).toLowerCase() === "content-type") {
      raw.push(String(request.rawHeaders[index + 1] ?? ""));
    }
  }
  if (raw.length === 0) {
    const fallback = request.headers["content-type"];
    if (typeof fallback === "string") raw.push(fallback);
  }
  if (raw.length !== 1 || raw[0].trim().toLowerCase() !== "application/json") {
    throw new TypeError("JSON content type is required");
  }
  let bytes = Buffer.alloc(0);
  try {
    for await (const source of request) {
      const chunk = Buffer.from(source);
      const previous = bytes;
      bytes = Buffer.concat([previous, chunk]);
      previous.fill(0); chunk.fill(0);
      if (Buffer.isBuffer(source)) source.fill(0);
      if (bytes.length > maximumBytes) throw new TypeError("request body exceeds its bound");
    }
    if (bytes.length === 0) throw new TypeError("request body is required");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = JSON.parse(text);
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new TypeError("request JSON must be an object");
    }
    return value;
  } finally {
    bytes.fill(0);
  }
}

function exactKeys(value, allowed) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new TypeError("request contains an unsupported field");
  return value;
}

class NonceRateLimiter {
  constructor({ maximum = 20, windowMs = 60_000, maximumPeers = 10_000,
    now = () => Date.now() } = {}) {
    this.maximum = maximum; this.windowMs = windowMs; this.maximumPeers = maximumPeers;
    this.now = now; this.entries = new Map();
  }
  allow(key) {
    const now = this.now();
    const entry = this.entries.get(key);
    if (entry === undefined || now - entry.startedAt >= this.windowMs) {
      if (entry === undefined && this.entries.size >= this.maximumPeers) {
        for (const [peer, candidate] of this.entries) {
          if (now - candidate.startedAt >= this.windowMs) this.entries.delete(peer);
        }
        if (this.entries.size >= this.maximumPeers) return false;
      }
      this.entries.set(key, { startedAt: now, count: 1 }); return true;
    }
    if (entry.count >= this.maximum) return false;
    entry.count += 1; return true;
  }
}

function routeName(path) {
  if (path.startsWith("/health/")) return "health";
  if (path === "/auth/dpop-nonce") return "dpop-nonce";
  if (path === "/api/admin/diagnostics") return "diagnostics";
  if (path.startsWith("/api/admin/approvals/")) return path.endsWith("/decisions") ? "approval-decision" : "approval";
  if (path === "/api/admin/approvals") return "approvals";
  return "unknown";
}

export function createAdminHandler({ authenticator, policy, store, upstream, publicOrigin,
  now = () => new Date(), logger, nonceRateLimiter = new NonceRateLimiter(),
  dispatcher = { isHealthy: () => true } }) {
  const authenticate = (request, requestUrl) => authenticator.verifyRequest({
    authorization: request.headers.authorization, dpop: request.headers.dpop,
    method: request.method, absoluteUrl: `${publicOrigin}${requestUrl.pathname}`,
  });

  return async function adminHandler(request, response) {
    const requestId = typeof request.headers["x-request-id"] === "string"
      && /^[A-Za-z0-9._:-]{8,128}$/.test(request.headers["x-request-id"])
      ? request.headers["x-request-id"] : randomUUID();
    let requestUrl;
    try { requestUrl = new URL(request.url, publicOrigin); }
    catch { problem(response, 400, "INVALID_REQUEST", requestId); return; }
    if (!String(request.url).startsWith("/") || requestUrl.origin !== publicOrigin) {
      problem(response, 400, "INVALID_REQUEST", requestId); return;
    }
    const path = requestUrl.pathname;
    let authenticatedOperator = null;
    try {
      if (path === "/") {
        if (request.method !== "GET" || requestUrl.search !== "") {
          problem(response, request.method === "GET" ? 400 : 405,
            request.method === "GET" ? "INVALID_REQUEST" : "METHOD_NOT_ALLOWED", requestId); return;
        }
        response.writeHead(200, { ...securityHeaders(), "content-type": "text/html; charset=utf-8",
          "content-length": html.length }).end(html); return;
      }
      if (path === "/health/startup" || path === "/health/live" || path === "/health/ready") {
        if (request.method !== "GET" || requestUrl.search !== "") { problem(response, 405, "METHOD_NOT_ALLOWED", requestId); return; }
        let ready = true;
        if (path === "/health/ready") {
          try { ready = (await store.ping()) && (await upstream.ready()) && dispatcher.isHealthy(); }
          catch { ready = false; }
        }
        sendJson(response, ready ? 200 : 503, { service: "admin-web",
          status: ready ? "UP" : "NOT_READY", probe: path.slice("/health/".length),
          writesEnabled: path === "/health/ready" ? ready : false }); return;
      }
      if (path === "/auth/dpop-nonce") {
        if (request.method !== "GET" || requestUrl.search !== "") {
          problem(response, 405, "METHOD_NOT_ALLOWED", requestId); return;
        }
        const peer = request.socket?.remoteAddress ?? "unknown";
        if (!nonceRateLimiter.allow(peer)) { problem(response, 429, "RATE_LIMITED", requestId); return; }
        const nonce = randomBytes(32).toString("base64url");
        const expiresAt = new Date(now().getTime() + 120_000).toISOString();
        if (!await store.issueNonce({ nonceDigest: sha256Hex(nonce), expiresAt })) throw new DatabaseUnavailableError();
        sendJson(response, 200, { nonce, expiresAt }, { "dpop-nonce": nonce }); return;
      }
      if (!path.startsWith("/api/admin/")) { problem(response, 404, "NOT_FOUND", requestId); return; }
      if (request.headers.cookie !== undefined) { problem(response, 401, "COOKIE_AUTH_FORBIDDEN", requestId); return; }
      const operator = await authenticate(request, requestUrl);
      authenticatedOperator = operator;

      if (path === "/api/admin/diagnostics") {
        if (request.method !== "GET" || requestUrl.searchParams.size !== 2
            || requestUrl.searchParams.getAll("tenantId").length !== 1
            || requestUrl.searchParams.getAll("service").length !== 1) {
          problem(response, 400, "INVALID_DIAGNOSTIC_REQUEST", requestId); return;
        }
        const tenantId = requestUrl.searchParams.get("tenantId");
        const service = requestUrl.searchParams.get("service");
        if (!UUID.test(tenantId ?? "") || !SERVICE.test(service ?? "")) {
          problem(response, 400, "INVALID_DIAGNOSTIC_REQUEST", requestId); return;
        }
        const authorization = policy.authorizeDiagnostic(operator, tenantId);
        let view; let source; let capturedAt = now().toISOString();
        try {
          view = buildDiagnosticView(operator, await upstream.diagnostic(operator, service));
          if (!await store.putDiagnostic(view, now())) throw new DatabaseUnavailableError();
          source = "LIVE";
        } catch (error) {
          if (!(error instanceof UpstreamUnavailableError)) throw error;
          const cached = await store.getDiagnostic(tenantId, service);
          const captured = new Date(cached?.capturedAt);
          const age = now().getTime() - captured.getTime();
          if (cached === null || !Number.isFinite(captured.getTime()) || age < 0 || age > 900_000) throw error;
          view = buildDiagnosticView(operator, cached.view); source = "STALE_READ_ONLY"; capturedAt = cached.capturedAt;
        }
        await store.recordAccess({ tenantId, actorId: operator.id, eventType: "DIAGNOSTIC_READ",
          resourceId: service, decision: "ALLOW", policyDigest: authorization.policyDigest,
          occurredAt: now().toISOString() });
        sendJson(response, 200, { source, capturedAt, diagnostic: view }); return;
      }

      if (path === "/api/admin/approvals") {
        if (request.method !== "POST" || requestUrl.search !== "") {
          problem(response, 405, "METHOD_NOT_ALLOWED", requestId); return;
        }
        if (!dispatcher.isHealthy() || !await upstream.ready()) throw new UpstreamUnavailableError();
        const body = exactKeys(await boundedJson(request), new Set([
          "tenantId", "projectId", "kind", "operationCode", "targetId", "proposalDigest",
          "reasonCode", "ticketReference", "expiresAt",
        ]));
        const authorization = policy.authorizeAction(operator, body.tenantId, body.kind,
          { requireStepUp: (actor) => authenticator.isRecentStepUp(actor) });
        const command = createApprovalCommand(body, operator, authorization, request.headers["idempotency-key"], now());
        const approval = await store.createApproval(command);
        sendJson(response, 201, { approval }, { location: `/api/admin/approvals/${approval.id}` }); return;
      }

      const match = path.match(APPROVAL_PATH);
      if (match === null || requestUrl.searchParams.size !== 1
          || requestUrl.searchParams.getAll("tenantId").length !== 1
          || !UUID.test(requestUrl.searchParams.get("tenantId") ?? "")) {
        problem(response, 404, "NOT_FOUND", requestId); return;
      }
      const tenantId = requestUrl.searchParams.get("tenantId");
      const current = await store.getApproval(tenantId, match[1]);
      if (current === null) { problem(response, 404, "NOT_FOUND", requestId); return; }
      const authorization = policy.authorizeAction(operator, tenantId, current.kind,
        { requireStepUp: (actor) => authenticator.isRecentStepUp(actor) });
      if (!path.endsWith("/decisions")) {
        if (request.method !== "GET") { problem(response, 405, "METHOD_NOT_ALLOWED", requestId); return; }
        await store.recordAccess({ tenantId, actorId: operator.id, eventType: "APPROVAL_READ",
          resourceId: current.id, decision: "ALLOW", policyDigest: authorization.policyDigest,
          occurredAt: now().toISOString() });
        sendJson(response, 200, { approval: current }); return;
      }
      if (request.method !== "POST") { problem(response, 405, "METHOD_NOT_ALLOWED", requestId); return; }
      if (!dispatcher.isHealthy() || !await upstream.ready()) throw new UpstreamUnavailableError();
      const decision = exactKeys(await boundedJson(request), new Set([
        "status", "expectedVersion", "proposalDigest", "reasonCode", "ticketReference",
      ]));
      const command = createDecisionCommand(current, decision, operator, authorization, now());
      const decided = await store.decideApproval(command);
      sendJson(response, 200, { approval: decided });
    } catch (error) {
      let status = 500; let code = "ADMIN_REQUEST_FAILED";
      if (error?.code === "AUTHENTICATION_FAILED") { status = 401; code = "AUTHENTICATION_REQUIRED"; }
      else if (error?.code === "AUTHENTICATION_CONTROL_UNAVAILABLE") { status = 503; code = "IDENTITY_CONTROL_UNAVAILABLE"; }
      else if (error instanceof TypeError || error instanceof SyntaxError) { status = 400; code = "INVALID_REQUEST"; }
      else if (error instanceof DatabaseUnavailableError || error instanceof UpstreamUnavailableError) {
        status = 503; code = "READ_ONLY_DEGRADED";
      } else if (/optimistic|already used|race|expired/.test(error?.message ?? "")) {
        status = 409; code = "APPROVAL_CONFLICT";
      } else if (/permission|authorized|cross-tenant|separation|step-up|elevation|proposer|privileged role|admin action/.test(error?.message ?? "")) {
        status = 403; code = "AUTHORIZATION_DENIED";
      }
      if (status === 403 && authenticatedOperator !== null) {
        try {
          await store.recordAccess({ tenantId: authenticatedOperator.tenantId,
            actorId: authenticatedOperator.id, eventType: "AUTHORIZATION_DENIED", resourceId: routeName(path),
            decision: "DENY", policyDigest: policy.policyDigest, occurredAt: now().toISOString() });
        } catch {
          status = 503; code = "AUDIT_UNAVAILABLE";
        }
      }
      logger?.event(status >= 500 ? "DEPENDENCY_DEGRADED" : "REQUEST_REJECTED",
        { code, method: request.method ?? "UNKNOWN", route: routeName(path), requestId, status });
      problem(response, status, code, requestId, status === 401 ? { "www-authenticate": "DPoP" } : {});
    }
  };
}
