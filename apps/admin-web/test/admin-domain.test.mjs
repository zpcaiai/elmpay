import assert from "node:assert/strict";
import test from "node:test";
import { buildDiagnosticView } from "../src/diagnostics.mjs";
import { createApproval, decideApproval } from "../src/approval-model.mjs";

const NOW = new Date("2026-08-26T00:00:00Z");
const PROPOSAL = {
  tenantId: "tenant-a",
  kind: "LIST_CHANGE",
  targetId: "fingerprint-7",
  proposalDigest: "a".repeat(64),
  proposer: "analyst-a",
  reason: "confirmed abuse cluster",
  expiresAt: "2026-08-26T01:00:00Z",
};

test("diagnostic projection strips secrets and hashes external references", () => {
  const view = buildDiagnosticView(
    { tenantId: "tenant-a", scopes: ["diagnostics:read"] },
    {
      tenantId: "tenant-a",
      service: "risk-engine",
      status: "degraded",
      traceId: "trace-secret-value",
      providerCorrelationId: "provider-reference",
      accessToken: "must-not-leak",
      customerEmail: "customer@example.test",
      mutationUrl: "/delete-everything",
    },
  );
  assert.equal(view.service, "risk-engine");
  assert.equal(Object.hasOwn(view, "accessToken"), false);
  assert.equal(Object.hasOwn(view, "customerEmail"), false);
  assert.equal(Object.hasOwn(view, "traceId"), false);
  assert.match(view.traceReference, /^[0-9a-f]{64}$/);
  assert.deepEqual(view.capabilities, ["view", "export-redacted"]);
});

test("approval requires a different phishing-resistant actor and version", () => {
  const approval = createApproval(PROPOSAL, NOW);
  assert.throws(() => decideApproval(
    approval,
    { status: "APPROVED", expectedVersion: 1 },
    { id: "analyst-a", tenantId: "tenant-a", phishingResistant: true, scopes: ["approvals:decide"] },
    new Date("2026-08-26T00:05:00Z"),
  ), /proposer/);

  const decided = decideApproval(
    approval,
    { status: "APPROVED", expectedVersion: 1 },
    { id: "analyst-b", tenantId: "tenant-a", phishingResistant: true, scopes: ["approvals:decide"] },
    new Date("2026-08-26T00:05:00Z"),
  );
  assert.equal(decided.status, "APPROVED");
  assert.equal(decided.version, 2);
  assert.equal(decided.audit[1].previousDigest, decided.audit[0].digest);
});

test("cross-tenant diagnostics and approvals fail closed", () => {
  assert.throws(() => buildDiagnosticView(
    { tenantId: "tenant-b", scopes: ["diagnostics:read"] },
    { tenantId: "tenant-a", service: "risk-engine" },
  ), /cross-tenant/);

  const approval = createApproval(PROPOSAL, NOW);
  assert.throws(() => decideApproval(
    approval,
    { status: "APPROVED", expectedVersion: 1 },
    { id: "analyst-b", tenantId: "tenant-b", phishingResistant: true, scopes: ["approvals:decide"] },
    new Date("2026-08-26T00:05:00Z"),
  ), /cross-tenant/);
});
