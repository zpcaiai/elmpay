import { randomUUID } from "node:crypto";
import { DispatchOutcomeUnknownError, PermanentDispatchError,
  RetryableDispatchError } from "./upstream-client.mjs";

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function envelope(claim) {
  return Object.freeze({
    schemaVersion: 2, dispatchId: claim.dispatchId, tenantId: claim.tenantId,
    projectId: claim.projectId, approvalId: claim.approvalId, kind: claim.kind,
    operationCode: claim.operationCode, targetId: claim.targetId,
    proposalDigest: claim.proposalDigest, policyDigest: claim.policyDigest,
    approvalVersion: Number(claim.approvalVersion), proposerDigest: claim.proposerDigest,
    approverDigest: claim.approverDigest, idempotencyKey: claim.idempotencyKey,
    workerId: claim.workerId, fencingToken: Number(claim.fencingToken),
    leaseUntil: claim.leaseUntil,
    approvalExpiresAt: claim.approvalExpiresAt,
  });
}

function nextAttempt(claim, now) {
  const exponent = Math.min(Math.max(Number(claim.attempt) - 1, 0), 8);
  const baseSeconds = Math.min(2 ** exponent, 300);
  const jitterMilliseconds = Number.parseInt(claim.idempotencyKey.slice(0, 4), 16) % 1000;
  return new Date(now.getTime() + baseSeconds * 1000 + jitterMilliseconds).toISOString();
}

function nextReceiptPoll(claim, now) {
  const exponent = Math.min(Math.max(Number(claim.pollAttempt ?? 1) - 1, 0), 4);
  const baseSeconds = Math.min(2 ** exponent, 15);
  const jitterMilliseconds = Number.parseInt(claim.idempotencyKey.slice(4, 8), 16) % 1000;
  return new Date(now.getTime() + baseSeconds * 1000 + jitterMilliseconds).toISOString();
}

export class AdminActionDispatcher {
  constructor({ store, upstream, workerId = `admin-${randomUUID()}`, leaseSeconds = 15,
    pollMilliseconds = 250, now = () => new Date(), wait = sleep, logger = null }) {
    this.store = store; this.upstream = upstream; this.workerId = workerId;
    this.leaseSeconds = leaseSeconds; this.pollMilliseconds = pollMilliseconds;
    this.now = now; this.wait = wait; this.logger = logger;
    this.running = false; this.stopping = false; this.lastHealthyAt = null; this.loopPromise = null;
  }

  start() {
    if (this.running) return;
    this.running = true; this.stopping = false;
    this.loopPromise = this.loop();
  }

  async stop() {
    this.stopping = true;
    await this.loopPromise;
    this.running = false;
  }

  isHealthy() {
    return this.running && !this.stopping && this.lastHealthyAt !== null
      && this.now().getTime() - this.lastHealthyAt.getTime() <= 10_000;
  }

  async loop() {
    while (!this.stopping) {
      try {
        const handled = await this.runOnce();
        this.lastHealthyAt = this.now();
        if (!handled) await this.wait(this.pollMilliseconds);
      } catch {
        this.logger?.event("DEPENDENCY_DEGRADED", { code: "ADMIN_DISPATCH_LOOP_FAILED",
          route: "action-dispatch", status: 503 });
        await this.wait(Math.max(this.pollMilliseconds, 1000));
      }
    }
  }

  async runOnce() {
    const claim = await this.store.claimDispatch(this.workerId, this.leaseSeconds);
    if (claim === null) return false;
    const action = envelope(claim);
    if (new Date(action.approvalExpiresAt) <= this.now()) {
      const updated = await this.store.rescheduleDispatch(claim,
        { state: "FAILED", failureCode: "APPROVAL_EXPIRED" });
      if (!updated) this.logStaleFence();
      return true;
    }
    try {
      let receipt = null;
      if (claim.outcomeUnknown === true) {
        receipt = await this.upstream.queryActionReceipt(action);
        if (receipt === null) throw new DispatchOutcomeUnknownError();
      } else {
        receipt = await this.upstream.dispatchAction(action);
      }
      if (!await this.store.completeDispatch(claim, receipt)) this.logStaleFence();
    } catch (error) {
      let updated;
      if (error instanceof DispatchOutcomeUnknownError) {
        updated = await this.store.rescheduleDispatch(claim, { state: "UNKNOWN", failureCode: "NETWORK_UNKNOWN",
          nextAttemptAt: nextReceiptPoll(claim, this.now()) });
      } else if (error instanceof RetryableDispatchError) {
        const exhausted = Number(claim.attempt) >= 8;
        updated = await this.store.rescheduleDispatch(claim, { state: exhausted ? "FAILED" : "RETRY",
          failureCode: exhausted ? "MAX_ATTEMPTS" : "UPSTREAM_5XX",
          nextAttemptAt: exhausted ? null : nextAttempt(claim, this.now()) });
      } else if (error instanceof PermanentDispatchError) {
        updated = await this.store.rescheduleDispatch(claim, { state: "BLOCKED",
          failureCode: error.code === "INVALID_RECEIPT" ? "INVALID_RECEIPT" : "UPSTREAM_REJECTED" });
      } else {
        updated = await this.store.rescheduleDispatch(claim, { state: "UNKNOWN", failureCode: "NETWORK_UNKNOWN",
          nextAttemptAt: nextAttempt(claim, this.now()) });
      }
      if (!updated) this.logStaleFence();
    }
    return true;
  }

  logStaleFence() {
    this.logger?.event("REQUEST_REJECTED", { code: "ADMIN_DISPATCH_STALE_FENCE",
      route: "action-dispatch", status: 409 });
  }
}
