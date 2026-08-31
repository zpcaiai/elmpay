import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { AdminActionDispatcher } from "../src/action-dispatcher.mjs";
import { DispatchOutcomeUnknownError, PermanentDispatchError, RetryableDispatchError,
  StrictAdminUpstream, validateActionReceipt } from "../src/upstream-client.mjs";
import { NOW, TENANT } from "./auth-fixture.mjs";

const CLAIM = Object.freeze({
  dispatchId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", tenantId: TENANT,
  projectId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  approvalId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", kind: "LIST_CHANGE",
  operationCode: "LIST_ADD", targetId: "rule-7",
  proposalDigest: "a".repeat(64), policyDigest: "b".repeat(64), approvalVersion: 2,
  proposerDigest: "c".repeat(64), approverDigest: "d".repeat(64), idempotencyKey: "e".repeat(64),
  previousState: "PENDING", attempt: 1, outcomeUnknown: false, pollAttempt: 0,
  workerId: "worker-123", fencingToken: 7,
  leaseUntil: new Date(NOW.getTime() + 15_000).toISOString(),
  approvalExpiresAt: new Date(NOW.getTime() + 600_000).toISOString(),
});

const RECEIPT = Object.freeze({ schemaVersion: 1,
  receiptId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", idempotencyKey: CLAIM.idempotencyKey,
  approvalId: CLAIM.approvalId, proposalDigest: CLAIM.proposalDigest, status: "APPLIED",
  executedAt: new Date(NOW.getTime() + 10_000).toISOString(), receiptDigest: "f".repeat(64) });

const ACTION = Object.freeze({ schemaVersion: 2, dispatchId: CLAIM.dispatchId, tenantId: CLAIM.tenantId,
  projectId: CLAIM.projectId, approvalId: CLAIM.approvalId, kind: CLAIM.kind,
  operationCode: CLAIM.operationCode, targetId: CLAIM.targetId,
  proposalDigest: CLAIM.proposalDigest, policyDigest: CLAIM.policyDigest,
  approvalVersion: 2, proposerDigest: CLAIM.proposerDigest, approverDigest: CLAIM.approverDigest,
  idempotencyKey: CLAIM.idempotencyKey, workerId: CLAIM.workerId,
  fencingToken: CLAIM.fencingToken, leaseUntil: CLAIM.leaseUntil,
  approvalExpiresAt: CLAIM.approvalExpiresAt });

function fakeUpstream(status, chunks) {
  const directory = mkdtempSync(join(tmpdir(), "elmpay-admin-upstream-"));
  const controlled = (name) => {
    const path = join(directory, name); writeFileSync(path, "fixture"); chmodSync(path, 0o400); return path;
  };
  let destroyed = false;
  const request = (_target, _options, callback) => {
    const outgoing = new EventEmitter();
    outgoing.write = () => {};
    outgoing.destroy = (error) => { if (error !== undefined) outgoing.emit("error", error); };
    outgoing.end = () => queueMicrotask(() => {
      const response = new PassThrough();
      response.statusCode = status; response.headers = { "content-type": "application/json" };
      const originalDestroy = response.destroy.bind(response);
      response.destroy = (...args) => { destroyed = true; return originalDestroy(...args); };
      callback(response);
      queueMicrotask(() => { for (const chunk of chunks) response.write(chunk); response.end(); });
    });
    return outgoing;
  };
  return { upstream: new StrictAdminUpstream({ baseUrl: "https://admin-actions.example.test",
    caPath: controlled("ca.pem"), certificatePath: controlled("client.pem"),
    privateKeyPath: controlled("client.key"), request, now: () => NOW }),
  wasDestroyed: () => destroyed };
}

function dispatcher({ claim = CLAIM, upstream = {}, store = {} } = {}) {
  const calls = [];
  const runtimeStore = {
    claimDispatch: async () => claim,
    completeDispatch: async (...args) => { calls.push(["complete", ...args]); return true; },
    rescheduleDispatch: async (...args) => { calls.push(["reschedule", ...args]); return true; },
    ...store,
  };
  const runtimeUpstream = {
    dispatchAction: async () => RECEIPT, queryActionReceipt: async () => null, ...upstream,
  };
  return { calls, instance: new AdminActionDispatcher({ store: runtimeStore, upstream: runtimeUpstream,
    workerId: "worker-123", now: () => NOW, wait: async () => {} }) };
}

test("approved action dispatch completes only after a strict upstream receipt", async () => {
  let sent;
  const fixture = dispatcher({ upstream: { dispatchAction: async (action) => { sent = action; return RECEIPT; } } });
  assert.equal(await fixture.instance.runOnce(), true);
  assert.equal(sent.proposalDigest, CLAIM.proposalDigest);
  assert.equal(sent.policyDigest, CLAIM.policyDigest);
  assert.equal(sent.workerId, CLAIM.workerId);
  assert.equal(sent.fencingToken, CLAIM.fencingToken);
  assert.equal(sent.leaseUntil, CLAIM.leaseUntil);
  assert.notEqual(sent.proposerDigest, sent.approverDigest);
  assert.equal(fixture.calls[0][0], "complete");
});

test("crash/unknown recovery queries the same idempotency receipt and never redispatches", async () => {
  let queried = 0; let dispatched = 0;
  const fixture = dispatcher({ claim: { ...CLAIM, previousState: "DISPATCHING", attempt: 8,
    outcomeUnknown: true, pollAttempt: 31 }, upstream: {
    queryActionReceipt: async () => { queried += 1; return RECEIPT; },
    dispatchAction: async () => { dispatched += 1; return RECEIPT; },
  } });
  await fixture.instance.runOnce();
  assert.equal(queried, 1);
  assert.equal(dispatched, 0);
  assert.equal(fixture.calls[0][0], "complete");
});

test("slow owner repeated receipt 202 stays UNKNOWN beyond eight network attempts", async () => {
  for (let pollAttempt = 1; pollAttempt <= 12; pollAttempt += 1) {
    let dispatched = 0;
    const fixture = dispatcher({ claim: { ...CLAIM, previousState: "UNKNOWN", attempt: 8,
      outcomeUnknown: true, pollAttempt }, upstream: {
      queryActionReceipt: async () => { throw new DispatchOutcomeUnknownError(); },
      dispatchAction: async () => { dispatched += 1; return RECEIPT; },
    } });
    await fixture.instance.runOnce();
    assert.equal(dispatched, 0);
    assert.equal(fixture.calls[0][2].state, "UNKNOWN");
    assert.equal(fixture.calls[0][2].failureCode, "NETWORK_UNKNOWN");
    assert.notEqual(fixture.calls[0][2].failureCode, "MAX_ATTEMPTS");
  }
});

test("timeout is UNKNOWN, 5xx is bounded RETRY and invalid/permanent receipt is BLOCKED", async () => {
  const unknown = dispatcher({ upstream: { dispatchAction: async () => { throw new DispatchOutcomeUnknownError(); } } });
  await unknown.instance.runOnce();
  assert.equal(unknown.calls[0][2].state, "UNKNOWN");
  assert.equal(unknown.calls[0][2].failureCode, "NETWORK_UNKNOWN");

  const retry = dispatcher({ upstream: { dispatchAction: async () => { throw new RetryableDispatchError(); } } });
  await retry.instance.runOnce();
  assert.equal(retry.calls[0][2].state, "RETRY");

  const blocked = dispatcher({ upstream: { dispatchAction: async () => { throw new PermanentDispatchError("INVALID_RECEIPT"); } } });
  await blocked.instance.runOnce();
  assert.equal(blocked.calls[0][2].state, "BLOCKED");
  assert.equal(blocked.calls[0][2].failureCode, "INVALID_RECEIPT");
});

test("expired approval never reaches the network and stale fencing cannot overwrite a newer worker", async () => {
  let network = 0;
  const expired = dispatcher({ claim: { ...CLAIM, approvalExpiresAt: new Date(NOW.getTime() - 1).toISOString() },
    upstream: { dispatchAction: async () => { network += 1; return RECEIPT; } } });
  await expired.instance.runOnce();
  assert.equal(network, 0);
  assert.equal(expired.calls[0][2].failureCode, "APPROVAL_EXPIRED");

  let completeAttempts = 0;
  const stale = dispatcher({ store: { completeDispatch: async () => { completeAttempts += 1; return false; } } });
  await stale.instance.runOnce();
  assert.equal(completeAttempts, 1);
  assert.equal(stale.calls.length, 0);
});

test("receipt digest, approval and idempotency mismatches fail closed", () => {
  const rawReceipt = { ...RECEIPT };
  delete rawReceipt.receiptDigest;
  assert.match(validateActionReceipt(rawReceipt, ACTION, NOW).receiptDigest, /^[0-9a-f]{64}$/);
  for (const changed of [{ ...rawReceipt, proposalDigest: "0".repeat(64) },
    { ...rawReceipt, idempotencyKey: "0".repeat(64) }, { ...rawReceipt, approvalId: TENANT }]) {
    assert.throws(() => validateActionReceipt(changed, ACTION, NOW), /rejected/);
  }
});

test("action transport rejects redirects without following them and destroys oversized receipts", async () => {
  const redirect = fakeUpstream(302, []);
  await assert.rejects(() => redirect.upstream.dispatchAction(ACTION), PermanentDispatchError);
  assert.equal(redirect.wasDestroyed(), true);

  const oversized = fakeUpstream(200, [Buffer.alloc(16_385, 0x61)]);
  await assert.rejects(() => oversized.upstream.dispatchAction(ACTION),
    (error) => error instanceof PermanentDispatchError && error.code === "INVALID_RECEIPT");
  assert.equal(oversized.wasDestroyed(), true);
});

test("upstream readiness stays false until a domain consumer advertises the complete action contract", async () => {
  const healthOnly = fakeUpstream(200, [Buffer.from(JSON.stringify({ status: "UP" }))]);
  assert.equal(await healthOnly.upstream.ready(), false);
});

test("parameterized or JSONP upstream media types and unsafe origin bounds fail closed", async () => {
  assert.throws(() => new StrictAdminUpstream({ baseUrl: "https://admin-actions.example.test/prefix",
    caPath: "/missing", certificatePath: "/missing", privateKeyPath: "/missing" }));
  const jsonp = fakeUpstream(200, [Buffer.from("{}")]);
  jsonp.upstream.request = (_target, _options, callback) => {
    const outgoing = new EventEmitter();
    outgoing.write = () => {};
    outgoing.destroy = (error) => { if (error) outgoing.emit("error", error); };
    outgoing.end = () => queueMicrotask(() => {
      const response = new PassThrough();
      response.statusCode = 200;
      response.headers = { "content-type": "application/jsonp" };
      callback(response); response.end("{}");
    });
    return outgoing;
  };
  await assert.rejects(() => jsonp.upstream.dispatchAction(ACTION), PermanentDispatchError);
});

test("upstream response framing rejects duplicate lengths and transfer encoding", async () => {
  const invalid = fakeUpstream(200, [Buffer.from("{}")]);
  invalid.upstream.request = (_target, _options, callback) => {
    const outgoing = new EventEmitter();
    outgoing.write = () => {};
    outgoing.destroy = (error) => { if (error) outgoing.emit("error", error); };
    outgoing.end = () => queueMicrotask(() => {
      const response = new PassThrough();
      response.statusCode = 200;
      response.headers = { "content-type": "application/json", "content-length": "2" };
      response.rawHeaders = ["Content-Type", "application/json",
        "Content-Length", "2", "content-length", "2"];
      callback(response); response.end("{}");
    });
    return outgoing;
  };
  await assert.rejects(() => invalid.upstream.dispatchAction(ACTION), PermanentDispatchError);

  const chunked = fakeUpstream(200, [Buffer.from("{}")]);
  chunked.upstream.request = (_target, _options, callback) => {
    const outgoing = new EventEmitter();
    outgoing.write = () => {};
    outgoing.destroy = (error) => { if (error) outgoing.emit("error", error); };
    outgoing.end = () => queueMicrotask(() => {
      const response = new PassThrough();
      response.statusCode = 200;
      response.headers = { "content-type": "application/json", "transfer-encoding": "chunked" };
      callback(response); response.end("{}");
    });
    return outgoing;
  };
  await assert.rejects(() => chunked.upstream.dispatchAction(ACTION), PermanentDispatchError);
});
