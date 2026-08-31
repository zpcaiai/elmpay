import { randomUUID } from "node:crypto";
import { canonicalJson, sha256Hex } from "./canonical-json.mjs";
import { assertVerifiedOperator } from "./operator-auth.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TARGET = /^[A-Za-z0-9._:@/-]{1,160}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/;
const TICKET = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}$/;
const OPERATIONS = Object.freeze({
  CASE_CLOSE: new Set(["CASE_CLOSE"]),
  LIST_CHANGE: new Set(["LIST_ADD", "LIST_REMOVE"]),
  REFUND_OVERRIDE: new Set(["REFUND_OVERRIDE"]),
  ROLLOUT_APPROVAL: new Set(["ROLLOUT_APPROVAL"]),
});

function requireText(value, pattern, field) {
  if (typeof value !== "string" || !pattern.test(value)) throw new TypeError(`${field} is invalid`);
  return value;
}

export function createApprovalCommand(proposal, operator, authorization, idempotencyKey, now = new Date()) {
  assertVerifiedOperator(operator);
  const tenantId = requireText(proposal?.tenantId, UUID, "tenantId");
  const projectId = requireText(proposal?.projectId, UUID, "projectId");
  if (tenantId !== operator.tenantId) throw new Error("cross-tenant approval is forbidden");
  if (proposal?.kind !== authorization?.kind) throw new Error("approval kind is not authorized");
  const operationCode = proposal?.operationCode;
  if (!OPERATIONS[proposal?.kind]?.has(operationCode)) {
    throw new TypeError("operationCode is not an exact action mapping");
  }
  const targetId = requireText(proposal?.targetId, TARGET, "targetId");
  const reasonCode = requireText(proposal?.reasonCode, REASON_CODE, "reasonCode");
  const ticketReference = requireText(proposal?.ticketReference, TICKET, "ticketReference");
  if (!/^[0-9a-f]{64}$/.test(proposal?.proposalDigest ?? "")) throw new TypeError("proposalDigest must be a lowercase SHA-256 digest");
  if (typeof idempotencyKey !== "string" || !/^[A-Za-z0-9._:-]{16,128}$/.test(idempotencyKey)) {
    throw new TypeError("a bounded idempotency key is required");
  }
  const expiresAt = new Date(proposal.expiresAt);
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt <= now
      || expiresAt.getTime() - now.getTime() > authorization.approvalTtlSeconds * 1000) {
    throw new TypeError("expiresAt exceeds the governed approval TTL");
  }
  return Object.freeze({
    id: randomUUID(), tenantId, projectId, kind: proposal.kind, operationCode,
    targetId, proposalDigest: proposal.proposalDigest,
    permission: authorization.permission, resource: authorization.resource, proposer: operator.id,
    reasonCode, ticketDigest: sha256Hex(ticketReference), requestKeyDigest: sha256Hex(idempotencyKey),
    policyDigest: authorization.policyDigest, status: "PENDING", version: 1,
    createdAt: now.toISOString(), expiresAt: expiresAt.toISOString(),
  });
}

export function createDecisionCommand(current, decision, operator, authorization, now = new Date()) {
  assertVerifiedOperator(operator);
  if (current.tenantId !== operator.tenantId) throw new Error("cross-tenant approval is forbidden");
  if (current.proposer === operator.id) throw new Error("the proposer cannot decide their own request");
  if (current.kind !== authorization?.kind || current.permission !== authorization.permission
      || current.policyDigest !== authorization.policyDigest) {
    throw new Error("approval no longer matches active authorization policy");
  }
  if (!Number.isSafeInteger(current.version) || current.version < 1
      || !/^[0-9a-f]{64}$/.test(current.lastAuditDigest ?? "")) {
    throw new Error("approval state or audit chain is invalid");
  }
  if (decision?.expectedVersion !== current.version) throw new Error("optimistic version conflict");
  if (decision?.proposalDigest !== current.proposalDigest) throw new Error("decision is not bound to the proposal digest");
  if (!new Set(["APPROVED", "REJECTED"]).has(decision?.status)) throw new TypeError("decision status is invalid");
  if (current.status !== "PENDING" || new Date(current.expiresAt) <= now) throw new Error("approval is not pending or has expired");
  requireText(decision.reasonCode, REASON_CODE, "reasonCode");
  requireText(decision.ticketReference, TICKET, "ticketReference");
  const previousDigest = current.lastAuditDigest;
  const decidedAt = now.toISOString();
  const auditDigest = sha256Hex(canonicalJson({
    approvalId: current.id, projectId: current.projectId, kind: current.kind,
    operationCode: current.operationCode, targetId: current.targetId,
    event: decision.status, actor: operator.id, proposalDigest: current.proposalDigest,
    previousDigest, reasonCode: decision.reasonCode, ticketDigest: sha256Hex(decision.ticketReference),
    version: current.version + 1, decidedAt,
  }));
  const approvalVersion = current.version + 1;
  const dispatch = decision.status === "APPROVED" ? Object.freeze({
    dispatchId: current.id, tenantId: current.tenantId, projectId: current.projectId,
    approvalId: current.id, kind: current.kind, operationCode: current.operationCode,
    targetId: current.targetId, proposalDigest: current.proposalDigest,
    policyDigest: current.policyDigest, approvalVersion,
    proposerDigest: sha256Hex(current.proposer), approverDigest: sha256Hex(operator.id),
    idempotencyKey: sha256Hex(canonicalJson({ approvalId: current.id,
      tenantId: current.tenantId, projectId: current.projectId, kind: current.kind,
      operationCode: current.operationCode, targetId: current.targetId, approvalVersion,
      proposalDigest: current.proposalDigest, policyDigest: current.policyDigest })),
    approvalExpiresAt: current.expiresAt, createdAt: decidedAt,
  }) : null;
  return Object.freeze({
    id: current.id, tenantId: current.tenantId, projectId: current.projectId,
    operationCode: current.operationCode, expectedVersion: current.version,
    proposalDigest: current.proposalDigest, status: decision.status, decidedBy: operator.id,
    reasonCode: decision.reasonCode, ticketDigest: sha256Hex(decision.ticketReference), decidedAt,
    previousAuditDigest: previousDigest, auditDigest, dispatch,
  });
}

export function initialAuditEvent(command) {
  const digest = sha256Hex(canonicalJson({
    approvalId: command.id, event: "PROPOSED", actor: command.proposer,
    projectId: command.projectId, kind: command.kind, operationCode: command.operationCode,
    targetId: command.targetId, proposalDigest: command.proposalDigest,
    reasonCode: command.reasonCode,
    ticketDigest: command.ticketDigest, version: 1, createdAt: command.createdAt,
  }));
  return Object.freeze({ event: "PROPOSED", actor: command.proposer, occurredAt: command.createdAt,
    previousDigest: "0".repeat(64), digest });
}
