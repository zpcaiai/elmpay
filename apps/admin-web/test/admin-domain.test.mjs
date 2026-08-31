import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildDiagnosticView } from "../src/diagnostics.mjs";
import { AuthorizationPolicy } from "../src/authorization-policy.mjs";
import { createApprovalCommand, createDecisionCommand, initialAuditEvent } from "../src/approval-model.mjs";
import { NOW, TENANT, verifiedOperator } from "./auth-fixture.mjs";

const authorizationPath = fileURLToPath(new URL("../../../governance/authorization.json", import.meta.url));
const actionPolicyPath = fileURLToPath(new URL("../security/action-policy.json", import.meta.url));
const policy = AuthorizationPolicy.load({ authorizationPath, actionPolicyPath });

test("diagnostic projection strips secrets, PII and raw references", () => {
  const view = buildDiagnosticView({ tenantId: TENANT }, {
    tenantId: TENANT, service: "risk-engine", status: "degraded", traceId: "trace-secret-value",
    providerCorrelationId: "provider-reference", accessToken: "must-not-leak",
    customerEmail: "customer@example.test", mutationUrl: "/delete-everything",
  });
  assert.equal(view.service, "risk-engine");
  assert.equal(Object.hasOwn(view, "accessToken"), false);
  assert.equal(Object.hasOwn(view, "customerEmail"), false);
  assert.equal(Object.hasOwn(view, "traceId"), false);
  assert.match(view.traceReference, /^[0-9a-f]{64}$/);
  assert.deepEqual(view.capabilities, ["view", "export-redacted"]);
});

test("permissions come from SSOT and tenant and role boundaries are exact", async () => {
  const operator = await verifiedOperator();
  assert.equal(policy.authorizeDiagnostic(operator, TENANT).permission, "payment.read");
  assert.throws(() => policy.authorizeDiagnostic(operator, "22222222-2222-4222-8222-222222222222"), /cross-tenant/);
  assert.throws(() => policy.authorizeAction(operator, TENANT, "LIST_CHANGE", { requireStepUp: () => true }), /permission/);
  const risk = await verifiedOperator({ sub: "risk-a", roles: ["risk-analyst"] }, { jti: "risk-proof" });
  assert.equal(policy.authorizeAction(risk, TENANT, "LIST_CHANGE", { requireStepUp: () => true }).permission, "risk_rule.write");
});

test("conflicting governed roles fail separation of duties", async () => {
  const conflicting = await verifiedOperator({ roles: ["platform-operator", "risk-analyst"] }, { jti: "sod-proof" });
  assert.throws(() => policy.permissionsFor(conflicting), /separation of duties/);
});

test("approval is digest-bound, four-eyes, expiring and optimistic", async () => {
  const proposer = await verifiedOperator({ sub: "risk-a", roles: ["risk-analyst"] }, { jti: "proposal-proof" });
  const approver = await verifiedOperator({ sub: "risk-b", roles: ["risk-analyst"] }, { jti: "decision-proof" });
  const authorization = policy.authorizeAction(proposer, TENANT, "LIST_CHANGE", { requireStepUp: () => true });
  const proposal = { tenantId: TENANT, projectId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    kind: "LIST_CHANGE", operationCode: "LIST_ADD", targetId: "rule-7",
    proposalDigest: "a".repeat(64), reasonCode: "ABUSE_CLUSTER", ticketReference: "SEC-1234",
    expiresAt: new Date(NOW.getTime() + 600_000).toISOString() };
  const command = createApprovalCommand(proposal, proposer, authorization, "idempotency-key-12345", NOW);
  const current = { ...command, lastAuditDigest: initialAuditEvent(command).digest };
  const baseDecision = { status: "APPROVED", expectedVersion: 1, proposalDigest: proposal.proposalDigest,
    reasonCode: "PEER_REVIEWED", ticketReference: "SEC-1234" };
  assert.throws(() => createDecisionCommand(current, baseDecision, proposer, authorization,
    new Date(NOW.getTime() + 10_000)), /proposer/);
  assert.throws(() => createDecisionCommand(current, { ...baseDecision, expectedVersion: 2 }, approver,
    authorization, new Date(NOW.getTime() + 10_000)), /optimistic/);
  assert.throws(() => createDecisionCommand(current, { ...baseDecision, proposalDigest: "b".repeat(64) },
    approver, authorization, new Date(NOW.getTime() + 10_000)), /proposal digest/);
  const decision = createDecisionCommand(current, baseDecision, approver, authorization,
    new Date(NOW.getTime() + 10_000));
  assert.equal(decision.expectedVersion, 1);
  assert.match(decision.auditDigest, /^[0-9a-f]{64}$/);
  assert.throws(() => createDecisionCommand(current, baseDecision, approver, authorization,
    new Date(NOW.getTime() + 700_000)), /expired/);
});

test("sensitive actions require recent step-up and elevation is independently approved", async () => {
  const risk = await verifiedOperator({ sub: "risk-c", roles: ["risk-analyst"] }, { jti: "stepup-proof" });
  assert.throws(() => policy.authorizeAction(risk, TENANT, "LIST_CHANGE", { requireStepUp: () => false }), /step-up/);
  const platform = await verifiedOperator({ elevation: { permission: "config.write", ticket_id: "OPS-7",
    approved_by: "operator-b", expires_at: Math.floor(NOW.getTime() / 1000) + 300,
    approval_digest: "c".repeat(64) } }, { jti: "elevation-proof" });
  assert.equal(policy.authorizeAction(platform, TENANT, "ROLLOUT_APPROVAL",
    { requireStepUp: () => true }).permission, "config.write");
  await assert.rejects(() => verifiedOperator({ elevation: { permission: "config.write", ticket_id: "OPS-7",
    approved_by: "operator-a", expires_at: Math.floor(NOW.getTime() / 1000) + 300,
    approval_digest: "c".repeat(64) } }, { jti: "self-elevation-proof" }), /separation/);
});
