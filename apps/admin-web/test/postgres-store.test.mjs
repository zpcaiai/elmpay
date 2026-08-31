import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PostgresAdminStore } from "../src/postgres-store.mjs";
import { NOW, TENANT } from "./auth-fixture.mjs";

test("DPoP replay consumption is one atomic nonce-and-unique-proof transaction", async () => {
  const calls = [];
  const store = new PostgresAdminStore({ execute: async (sql, input) => {
    calls.push({ sql, input }); return { accepted: true };
  } });
  assert.equal(await store.consumeProof({ tenantId: TENANT, issuer: "https://idp.example.invalid/corp",
    subjectDigest: "a".repeat(64), accessJtiDigest: "b".repeat(64), proofJtiDigest: "c".repeat(64),
    nonceDigest: "d".repeat(64), proofThumbprint: "e".repeat(43),
    proofExpiresAt: new Date(NOW.getTime() + 61_000).toISOString() }), true);
  assert.match(calls[0].sql, /BEGIN;/);
  assert.match(calls[0].sql, /UPDATE admin_dpop_nonce/);
  assert.match(calls[0].sql, /ON CONFLICT DO NOTHING/);
  assert.match(calls[0].sql, /set_config\('app\.tenant_id'/);
  assert.equal(Object.hasOwn(calls[0].input, "subject"), false);
});

test("runtime readiness proves exact fixed role, ACL inventory, RLS and no routine bypass", async () => {
  let statement = "";
  const store = new PostgresAdminStore({ execute: async (sql) => {
    statement = sql; return { ready: true };
  } });
  assert.equal(await store.verifyRuntimeContract(), true);
  for (const marker of ["current_user = 'elmpay_admin_web'",
    "session_user = current_user", "NOT role.rolinherit", "role.rolconfig IS NULL",
    "current_setting('row_security') = 'on'", "NOT has_database_privilege",
    "expected_table", "unexpected_relation_gate", "expected_sequence",
    "routine_gate", "relforcerowsecurity", "app.tenant_id",
    "NOT LIKE '%elmpay.tenant_id%'"]) assert.ok(statement.includes(marker), marker);
});

test("approval decision SQL holds a row lock and enforces version, digest, actor and expiry", async () => {
  let statement = "";
  const store = new PostgresAdminStore({ execute: async (sql) => {
    statement = sql;
    return { approval: { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", tenantId: TENANT, kind: "LIST_CHANGE",
      projectId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", operationCode: "LIST_ADD",
      targetId: "rule-7", proposalDigest: "a".repeat(64), permission: "risk_rule.write",
      resource: "risk_rule", proposer: "risk-a", reasonCode: "ABUSE_CLUSTER", ticketDigest: "b".repeat(64),
      policyDigest: "c".repeat(64), status: "APPROVED", version: 2,
      createdAt: NOW.toISOString(), expiresAt: new Date(NOW.getTime() + 600_000).toISOString(),
      decidedAt: new Date(NOW.getTime() + 10_000).toISOString(), decidedBy: "risk-b",
      lastAuditDigest: "d".repeat(64) }, dispatchQueued: true };
  } });
  await store.decideApproval({ id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", tenantId: TENANT,
    expectedVersion: 1, proposalDigest: "a".repeat(64), status: "APPROVED", decidedBy: "risk-b",
    reasonCode: "PEER_REVIEWED", ticketDigest: "e".repeat(64), decidedAt: NOW.toISOString(),
    previousAuditDigest: "f".repeat(64), auditDigest: "0".repeat(64), dispatch: {} });
  for (const marker of ["FOR UPDATE", "locked.version", "locked.expires_at > clock_timestamp()",
    "locked.proposal_digest", "locked.proposer_id <>", "previousAuditDigest",
    "INSERT INTO admin_action_dispatch", "INSERT INTO admin_dispatch_signal"]) assert.ok(statement.includes(marker), marker);
});

test("migration forces tenant RLS, immutable audit/replay and four-eyes/version invariants", () => {
  const path = fileURLToPath(new URL("../migrations/V018_019__admin_web_runtime.sql", import.meta.url));
  const sql = readFileSync(path, "utf8");
  for (const marker of ["admin_dpop_replay FORCE ROW LEVEL SECURITY",
    "admin_approval FORCE ROW LEVEL SECURITY", "admin_approval_audit FORCE ROW LEVEL SECURITY",
    "admin_access_audit FORCE ROW LEVEL SECURITY", "admin_diagnostic_snapshot FORCE ROW LEVEL SECURITY",
    "admin_action_dispatch FORCE ROW LEVEL SECURITY",
    "decided_by <> proposer_id", "NEW.version <> OLD.version + 1",
    "admin_approval_audit_immutable", "admin_dpop_replay_immutable",
    "admin_action_dispatch_transition_guard", "UNIQUE (tenant_id, request_key_digest)",
    "UNIQUE (tenant_id, idempotency_key)", "receipt_poll_attempts", "outcome_unknown"]) {
    assert.ok(sql.includes(marker), marker);
  }
  assert.equal(sql.includes("idempotency_key char(64) NOT NULL UNIQUE"), false);
  assert.equal(/password|access_token|customer_email|card_pan/i.test(sql), false);
});

test("dispatch claim and result updates use leases, SKIP LOCKED and fencing", async () => {
  const statements = [];
  const store = new PostgresAdminStore({ execute: async (sql) => { statements.push(sql); return null; } });
  assert.equal(await store.claimDispatch("worker-123", 15), null);
  const claimSql = statements[0];
  for (const marker of ["FOR UPDATE SKIP LOCKED", "fencing_token = d.fencing_token + 1",
    "d.lease_until <= clock_timestamp()", "a.status = 'APPROVED'", "a.proposal_digest = d.proposal_digest",
    "APPROVAL_MISMATCH", "APPROVAL_EXPIRED", "MAX_ATTEMPTS",
    "d.state = 'UNKNOWN'", "receipt_poll_attempts", "d.outcome_unknown",
    "dispatch_candidate.previous_state = 'DISPATCHING'"]) assert.ok(claimSql.includes(marker), marker);
  assert.equal(claimSql.includes("d.state IN ('PENDING','RETRY','DISPATCHING') AND NOT d.outcome_unknown"), false);

  const noUpdate = new PostgresAdminStore({ execute: async (sql) => { statements.push(sql); return { updated: false }; } });
  const claim = { tenantId: TENANT, dispatchId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    workerId: "worker-123", fencingToken: 7 };
  assert.equal(await noUpdate.completeDispatch(claim, { receiptDigest: "a".repeat(64),
    receiptId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" }), false);
  assert.ok(statements.at(-1).includes("d.fencing_token = (input.j->>'fencingToken')::bigint"));
});

test("getApproval is null-safe and returns the audit digest loaded from PostgreSQL", async () => {
  const missing = new PostgresAdminStore({ execute: async () => null });
  assert.equal(await missing.getApproval(TENANT, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), null);
  const digest = "d".repeat(64);
  const found = new PostgresAdminStore({ execute: async () => ({
    id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", tenantId: TENANT, kind: "LIST_CHANGE",
    projectId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", operationCode: "LIST_ADD",
    targetId: "rule-7", proposalDigest: "a".repeat(64), permission: "risk_rule.write",
    resource: "risk_rule", proposer: "risk-a", reasonCode: "ABUSE_CLUSTER", ticketDigest: "b".repeat(64),
    policyDigest: "c".repeat(64), status: "PENDING", version: 1, createdAt: NOW.toISOString(),
    expiresAt: new Date(NOW.getTime() + 600_000).toISOString(), decidedAt: null, decidedBy: null,
    lastAuditDigest: digest,
  }) });
  assert.equal((await found.getApproval(TENANT, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).lastAuditDigest, digest);
});
