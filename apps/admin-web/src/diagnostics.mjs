import { createHash } from "node:crypto";

const SAFE_FIELDS = new Set([
  "service",
  "status",
  "version",
  "region",
  "errorCode",
  "lastUpdated",
  "latencyMs",
]);

function requireText(value, field) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${field} must be a non-empty string`);
  }
}

function hashReference(value) {
  return createHash("sha256").update(String(value), "utf8").digest("hex");
}

/**
 * Produce an immutable, read-only diagnostic projection. Raw provider payloads,
 * credentials, personal data, mutation links, and unrestricted metadata never
 * cross this boundary.
 */
export function buildDiagnosticView(actor, resource) {
  requireText(actor?.tenantId, "actor.tenantId");
  requireText(resource?.tenantId, "resource.tenantId");
  if (actor.tenantId !== resource.tenantId) {
    throw new Error("cross-tenant diagnostic access is forbidden");
  }
  if (!Array.isArray(actor.scopes) || !actor.scopes.includes("diagnostics:read")) {
    throw new Error("diagnostics:read scope is required");
  }

  const projection = { tenantId: resource.tenantId };
  for (const field of SAFE_FIELDS) {
    if (Object.hasOwn(resource, field)) {
      projection[field] = resource[field];
    }
  }
  if (resource.traceId !== undefined) {
    projection.traceReference = hashReference(resource.traceId);
  }
  if (resource.providerCorrelationId !== undefined) {
    projection.providerReference = hashReference(resource.providerCorrelationId);
  }
  projection.capabilities = Object.freeze(["view", "export-redacted"]);
  return Object.freeze(projection);
}
