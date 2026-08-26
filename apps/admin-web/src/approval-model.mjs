import { createHash, randomUUID } from "node:crypto";

const ALLOWED_KINDS = new Set([
  "CASE_CLOSE",
  "LIST_CHANGE",
  "REFUND_OVERRIDE",
  "ROLLOUT_APPROVAL",
]);

function requireText(value, field) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${field} must be a non-empty string`);
  }
}

function canonicalDigest(value) {
  return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

function freezeApproval(approval) {
  return Object.freeze({ ...approval, audit: Object.freeze([...approval.audit]) });
}

export function createApproval(proposal, now = new Date()) {
  requireText(proposal?.tenantId, "tenantId");
  requireText(proposal?.targetId, "targetId");
  requireText(proposal?.proposer, "proposer");
  requireText(proposal?.reason, "reason");
  if (!ALLOWED_KINDS.has(proposal.kind)) {
    throw new TypeError("unsupported approval kind");
  }
  if (!/^[0-9a-f]{64}$/.test(proposal.proposalDigest ?? "")) {
    throw new TypeError("proposalDigest must be a lowercase SHA-256 digest");
  }
  const expiresAt = new Date(proposal.expiresAt);
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt <= now) {
    throw new TypeError("expiresAt must be a valid future time");
  }
  const createdAt = now.toISOString();
  const base = {
    id: randomUUID(),
    tenantId: proposal.tenantId,
    kind: proposal.kind,
    targetId: proposal.targetId,
    proposalDigest: proposal.proposalDigest,
    reason: proposal.reason,
    proposer: proposal.proposer,
    status: "PENDING",
    version: 1,
    createdAt,
    expiresAt: expiresAt.toISOString(),
    decidedAt: null,
    decidedBy: null,
  };
  const audit = [{
    event: "PROPOSED",
    actor: proposal.proposer,
    at: createdAt,
    digest: canonicalDigest(base),
  }];
  return freezeApproval({ ...base, audit });
}

export function decideApproval(approval, decision, actor, now = new Date()) {
  requireText(actor?.id, "actor.id");
  requireText(actor?.tenantId, "actor.tenantId");
  if (actor.tenantId !== approval.tenantId) {
    throw new Error("cross-tenant approval is forbidden");
  }
  if (actor.id === approval.proposer) {
    throw new Error("the proposer cannot decide their own request");
  }
  if (actor.phishingResistant !== true) {
    throw new Error("phishing-resistant authentication is required");
  }
  if (!Array.isArray(actor.scopes) || !actor.scopes.includes("approvals:decide")) {
    throw new Error("approvals:decide scope is required");
  }
  if (decision?.expectedVersion !== approval.version) {
    throw new Error("optimistic version conflict");
  }
  if (approval.status !== "PENDING") {
    throw new Error("approval is not pending");
  }
  if (new Date(approval.expiresAt) <= now) {
    throw new Error("approval has expired");
  }
  if (!new Set(["APPROVED", "REJECTED"]).has(decision.status)) {
    throw new TypeError("decision status must be APPROVED or REJECTED");
  }
  const decided = {
    ...approval,
    status: decision.status,
    version: approval.version + 1,
    decidedAt: now.toISOString(),
    decidedBy: actor.id,
  };
  const previousDigest = approval.audit.at(-1).digest;
  const event = {
    event: decision.status,
    actor: actor.id,
    at: decided.decidedAt,
    previousDigest,
    digest: canonicalDigest({
      id: approval.id,
      status: decision.status,
      actor: actor.id,
      at: decided.decidedAt,
      previousDigest,
    }),
  };
  return freezeApproval({ ...decided, audit: [...approval.audit, event] });
}
