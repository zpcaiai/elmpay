import { request as httpsRequest } from "node:https";
import { realpathSync } from "node:fs";
import { readControlledFile } from "./controlled-file.mjs";
import { dirname, isAbsolute, sep } from "node:path";
import { buildDiagnosticView } from "./diagnostics.mjs";
import { canonicalJson, sha256Hex } from "./canonical-json.mjs";

const ACTION_KINDS = new Set(["CASE_CLOSE", "LIST_CHANGE", "REFUND_OVERRIDE", "ROLLOUT_APPROVAL"]);

export class UpstreamUnavailableError extends Error {
  constructor() {
    super("admin upstream is unavailable");
    this.code = "UPSTREAM_UNAVAILABLE";
  }
}

export class DispatchOutcomeUnknownError extends Error {
  constructor() { super("admin action outcome is unknown"); this.code = "DISPATCH_OUTCOME_UNKNOWN"; }
}

export class RetryableDispatchError extends Error {
  constructor() { super("admin action dispatch is retryable"); this.code = "DISPATCH_RETRYABLE"; }
}

export class PermanentDispatchError extends Error {
  constructor(code = "UPSTREAM_REJECTED") { super("admin action dispatch was rejected"); this.code = code; }
}

function controlledPem(path, label) {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path`);
  const mountParent = realpathSync(dirname(path));
  const resolved = realpathSync(path);
  if (resolved !== mountParent && !resolved.startsWith(`${mountParent}${sep}`)) {
    throw new Error(`${label} must remain inside its controlled mount`);
  }
  return readControlledFile(resolved, label, 1_048_576);
}

function boundedJsonResponse(response, maximumBytes, allowedStatuses = new Set([200])) {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    let finished = false;
    const fail = (error) => {
      if (finished) return;
      finished = true;
      bytes.fill(0);
      reject(error);
    };
    response.on("data", (chunk) => {
      const source = Buffer.from(chunk);
      if (finished) { source.fill(0); if (Buffer.isBuffer(chunk)) chunk.fill(0); return; }
      const previous = bytes;
      bytes = Buffer.concat([previous, source]);
      previous.fill(0); source.fill(0);
      if (Buffer.isBuffer(chunk)) chunk.fill(0);
      if (bytes.length > maximumBytes) {
        response.destroy();
        fail(new UpstreamUnavailableError());
      }
    });
    response.on("error", () => fail(new UpstreamUnavailableError()));
    response.on("end", () => {
      if (finished) return;
      const contentTypes = [];
      const contentLengths = [];
      const transferEncodings = [];
      const rawHeaders = response.rawHeaders ?? [];
      let headerBytes = 0;
      for (let index = 0; index < rawHeaders.length; index += 2) {
        const name = String(rawHeaders[index] ?? "");
        const value = String(rawHeaders[index + 1] ?? "");
        headerBytes += Buffer.byteLength(name) + Buffer.byteLength(value) + 4;
        if (name.toLowerCase() === "content-type") {
          contentTypes.push(value);
        } else if (name.toLowerCase() === "content-length") {
          contentLengths.push(value);
        } else if (name.toLowerCase() === "transfer-encoding") {
          transferEncodings.push(value);
        }
      }
      if (contentTypes.length === 0 && typeof response.headers["content-type"] === "string") {
        contentTypes.push(response.headers["content-type"]);
      }
      if (contentLengths.length === 0 && typeof response.headers["content-length"] === "string") {
        contentLengths.push(response.headers["content-length"]);
      }
      if (transferEncodings.length === 0 && response.headers["transfer-encoding"] !== undefined) {
        const value = response.headers["transfer-encoding"];
        transferEncodings.push(Array.isArray(value) ? value.join(",") : String(value));
      }
      const declaredLength = contentLengths.length === 1 && /^[0-9]+$/.test(contentLengths[0])
        ? Number(contentLengths[0]) : null;
      if (!allowedStatuses.has(response.statusCode) || contentTypes.length !== 1
          || contentTypes[0].trim().toLowerCase() !== "application/json"
          || rawHeaders.length > 128 || headerBytes > 8192
          || transferEncodings.length !== 0 || contentLengths.length > 1
          || (contentLengths.length === 1
            && (!Number.isSafeInteger(declaredLength) || declaredLength !== bytes.length))) {
        fail(new UpstreamUnavailableError());
        return;
      }
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        const value = JSON.parse(text);
        finished = true;
        resolve(value);
      } catch { fail(new UpstreamUnavailableError()); }
      finally { bytes.fill(0); }
    });
  });
}

export class StrictAdminUpstream {
  constructor({ baseUrl, caPath, certificatePath, privateKeyPath, timeoutMs = 4500,
    maximumBytes = 32_768, request = httpsRequest, now = () => new Date() }) {
    this.baseUrl = new URL(baseUrl);
    if (this.baseUrl.protocol !== "https:" || this.baseUrl.username !== "" || this.baseUrl.password !== ""
        || this.baseUrl.pathname !== "/" || this.baseUrl.search !== ""
        || this.baseUrl.hash !== "") throw new Error("admin upstream must be an origin HTTPS URL");
    this.ca = controlledPem(caPath, "upstream CA");
    this.cert = controlledPem(certificatePath, "upstream client certificate");
    this.key = controlledPem(privateKeyPath, "upstream client private key");
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 5000
        || !Number.isInteger(maximumBytes) || maximumBytes < 1024 || maximumBytes > 32_768) {
      throw new Error("admin upstream bounds are invalid");
    }
    this.timeoutMs = timeoutMs;
    this.maximumBytes = maximumBytes;
    this.request = request;
    this.now = now;
  }

  async ready() {
    try {
      const response = await this.call("/health/ready");
      if (response?.status !== "UP" && response?.status !== "ok") return false;
      const capabilities = await this.call("/internal/admin/actions/capabilities");
      return capabilities?.schemaVersion === 2
        && capabilities.dispatchContract === "elmpay.admin-action.v2"
        && capabilities.receiptContract === "elmpay.admin-action-receipt.v1"
        && Array.isArray(capabilities.actions) && capabilities.actions.length === ACTION_KINDS.size
        && new Set(capabilities.actions).size === ACTION_KINDS.size
        && capabilities.actions.every((action) => ACTION_KINDS.has(action));
    } catch { return false; }
  }

  async diagnostic(operator, service) {
    if (!/^[a-z][a-z0-9-]{1,62}$/.test(service)) throw new TypeError("service name is invalid");
    const path = `/internal/admin/diagnostics?tenantId=${encodeURIComponent(operator.tenantId)}&service=${encodeURIComponent(service)}`;
    const response = await this.call(path, {
      "x-elmpay-operator-subject-digest": await this.subjectDigest(operator.id),
      "x-elmpay-tenant-id": operator.tenantId,
    });
    if (response === null || typeof response !== "object" || Array.isArray(response)
        || response.tenantId !== operator.tenantId || response.service !== service) {
      throw new UpstreamUnavailableError();
    }
    try { return buildDiagnosticView(operator, response); }
    catch { throw new UpstreamUnavailableError(); }
  }

  async subjectDigest(subject) {
    const { createHash } = await import("node:crypto");
    return createHash("sha256").update(subject).digest("hex");
  }

  call(path, headers = {}) {
    const target = new URL(path, this.baseUrl);
    if (target.origin !== this.baseUrl.origin) return Promise.reject(new UpstreamUnavailableError());
    return new Promise((resolve, reject) => {
      const request = this.request(target, {
        method: "GET", ca: this.ca, cert: this.cert, key: this.key, minVersion: "TLSv1.3",
        servername: this.baseUrl.hostname, rejectUnauthorized: true, timeout: this.timeoutMs,
        maxHeaderSize: 8192,
        headers: { accept: "application/json", "cache-control": "no-store", ...headers },
      }, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400) {
          response.destroy();
          reject(new UpstreamUnavailableError());
          return;
        }
        boundedJsonResponse(response, this.maximumBytes).then(resolve, reject);
      });
      request.on("timeout", () => request.destroy(new UpstreamUnavailableError()));
      request.on("error", () => reject(new UpstreamUnavailableError()));
      request.end();
    });
  }

  async dispatchAction(envelope) {
    validateActionDispatchEnvelope(envelope);
    const result = await this.dispatchExchange({ method: "POST", path: "/internal/admin/actions/dispatches",
      body: envelope, headers: { "idempotency-key": envelope.idempotencyKey,
        "x-elmpay-tenant-id": envelope.tenantId } });
    if (result.status === 202) throw new DispatchOutcomeUnknownError();
    if (![200, 201, 409].includes(result.status)) throw new PermanentDispatchError();
    return validateActionReceipt(result.body, envelope, this.now());
  }

  async queryActionReceipt(envelope) {
    validateActionDispatchEnvelope(envelope);
    const result = await this.dispatchExchange({ method: "GET",
      path: `/internal/admin/actions/receipts/${envelope.idempotencyKey}`,
      headers: { "x-elmpay-tenant-id": envelope.tenantId } });
    if (result.status === 404) throw new DispatchOutcomeUnknownError();
    if (result.status === 202) throw new DispatchOutcomeUnknownError();
    if (result.status !== 200) throw new PermanentDispatchError();
    return validateActionReceipt(result.body, envelope, this.now());
  }

  dispatchExchange({ method, path, body = null, headers = {} }) {
    const target = new URL(path, this.baseUrl);
    if (target.origin !== this.baseUrl.origin) return Promise.reject(new PermanentDispatchError());
    const bytes = body === null ? null : Buffer.from(canonicalJson(body), "utf8");
    if (bytes !== null && bytes.length > 16_384) return Promise.reject(new PermanentDispatchError("INVALID_RECEIPT"));
    return new Promise((resolve, reject) => {
      const request = this.request(target, {
        method, ca: this.ca, cert: this.cert, key: this.key, minVersion: "TLSv1.3",
        servername: this.baseUrl.hostname, rejectUnauthorized: true, timeout: this.timeoutMs,
        maxHeaderSize: 8192,
        headers: { accept: "application/json", "cache-control": "no-store", ...headers,
          ...(bytes === null ? {} : { "content-type": "application/json", "content-length": bytes.length }) },
      }, (response) => {
        const status = response.statusCode ?? 0;
        if (status === 408 || status === 429 || status >= 500) {
          response.destroy(); reject(new RetryableDispatchError()); return;
        }
        if ((status >= 300 && status < 400) || (status >= 400 && status < 500 && status !== 409 && status !== 404)) {
          response.destroy(); reject(new PermanentDispatchError()); return;
        }
        if (status === 404) {
          response.destroy(); resolve({ status, body: null }); return;
        }
        boundedJsonResponse(response, 16_384, new Set([200, 201, 202, 409])).then((responseBody) => resolve({ status, body: responseBody }),
          () => reject(new PermanentDispatchError("INVALID_RECEIPT")));
      });
      request.on("timeout", () => request.destroy(new DispatchOutcomeUnknownError()));
      request.on("error", () => reject(new DispatchOutcomeUnknownError()));
      if (bytes === null) request.end();
      else {
        const clear = () => bytes.fill(0);
        request.once("error", clear);
        request.end(bytes, clear);
      }
    });
  }
}

export function validateActionDispatchEnvelope(envelope) {
  const keys = ["schemaVersion", "dispatchId", "tenantId", "projectId", "approvalId", "kind",
    "operationCode", "targetId", "proposalDigest", "policyDigest", "approvalVersion",
    "proposerDigest", "approverDigest",
    "idempotencyKey", "workerId", "fencingToken", "leaseUntil", "approvalExpiresAt"];
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)
      || Object.keys(envelope).length !== keys.length || keys.some((key) => !Object.hasOwn(envelope, key))
      || envelope.schemaVersion !== 2 || !ACTION_KINDS.has(envelope.kind)
      || envelope.approvalVersion !== 2 || envelope.dispatchId !== envelope.approvalId
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(envelope.tenantId ?? "")
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(envelope.projectId ?? "")
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(envelope.approvalId ?? "")
      || !/^[A-Za-z0-9._:@/-]{1,160}$/.test(envelope.targetId ?? "")
      || [envelope.proposalDigest, envelope.policyDigest, envelope.proposerDigest,
        envelope.approverDigest, envelope.idempotencyKey].some((digest) => !/^[0-9a-f]{64}$/.test(digest ?? ""))
      || envelope.proposerDigest === envelope.approverDigest
      || !/^[A-Za-z0-9._:-]{8,128}$/.test(envelope.workerId ?? "")
      || !Number.isSafeInteger(envelope.fencingToken) || envelope.fencingToken < 1
      || !Number.isFinite(new Date(envelope.leaseUntil).getTime())
      || new Date(envelope.leaseUntil) >= new Date(envelope.approvalExpiresAt)
      || !Number.isFinite(new Date(envelope.approvalExpiresAt).getTime())) {
    throw new PermanentDispatchError("INVALID_RECEIPT");
  }
  const operations = {
    CASE_CLOSE: new Set(["CASE_CLOSE"]),
    LIST_CHANGE: new Set(["LIST_ADD", "LIST_REMOVE"]),
    REFUND_OVERRIDE: new Set(["REFUND_OVERRIDE"]),
    ROLLOUT_APPROVAL: new Set(["ROLLOUT_APPROVAL"]),
  };
  if (!operations[envelope.kind].has(envelope.operationCode)) {
    throw new PermanentDispatchError("INVALID_RECEIPT");
  }
}

export function validateActionReceipt(receipt, envelope, now = new Date()) {
  const keys = ["schemaVersion", "receiptId", "idempotencyKey", "approvalId", "proposalDigest", "status", "executedAt"];
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)
      || Object.keys(receipt).length !== keys.length || keys.some((key) => !Object.hasOwn(receipt, key))
      || receipt.schemaVersion !== 1 || receipt.status !== "APPLIED"
      || receipt.idempotencyKey !== envelope.idempotencyKey || receipt.approvalId !== envelope.approvalId
      || receipt.proposalDigest !== envelope.proposalDigest
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(receipt.receiptId ?? "")
      || !Number.isFinite(new Date(receipt.executedAt).getTime())
      || new Date(receipt.executedAt) > new Date(envelope.approvalExpiresAt)
      || new Date(receipt.executedAt).getTime() > now.getTime() + 60_000) {
    throw new PermanentDispatchError("INVALID_RECEIPT");
  }
  return Object.freeze({ ...receipt, receiptDigest: sha256Hex(canonicalJson(receipt)) });
}
