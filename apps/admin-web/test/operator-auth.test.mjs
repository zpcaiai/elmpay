import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { accessClaims, createAccessToken, createProof, createVerifier, NOW, TENANT } from "./auth-fixture.mjs";

const URL = "https://admin.example.test/api/admin/resource";

test("ES256 corporate token and holder-bound DPoP proof produce a verified operator", async () => {
  const seen = [];
  const verifier = createVerifier({ replayStore: { consumeProof: async (proof) => { seen.push(proof); return true; } } });
  const accessToken = createAccessToken();
  const operator = await verifier.verifyRequest({ authorization: `DPoP ${accessToken}`,
    dpop: createProof(accessToken, { url: URL }), method: "GET", absoluteUrl: URL });
  assert.equal(operator.tenantId, TENANT);
  assert.deepEqual(operator.roles, ["platform-operator"]);
  assert.equal(operator.phishingResistant, true);
  assert.match(seen[0].proofJtiDigest, /^[0-9a-f]{64}$/);
  assert.equal(Object.hasOwn(seen[0], "subject"), false);
});

test("caller self-reported permissions and phishing flags are rejected as unsupported signed claims", async () => {
  for (const claim of [{ permissions: ["config.write"] }, { phishingResistant: true }]) {
    const accessToken = createAccessToken(accessClaims(claim));
    await assert.rejects(() => createVerifier().verifyRequest({ authorization: `DPoP ${accessToken}`,
      dpop: createProof(accessToken, { url: URL }), method: "GET", absoluteUrl: URL }), /unsupported field/);
  }
});

test("issuer key, tenant, phishing-resistant AMR, time, and revocation are fail closed", async () => {
  const unknown = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const seconds = Math.floor(NOW.getTime() / 1000);
  const invalid = [
    createAccessToken(accessClaims({ tenant_id: "tenant-a" })),
    createAccessToken(accessClaims({ amr: ["totp"] })),
    createAccessToken(accessClaims({ amr: ["webauthn", "webauthn"] })),
    createAccessToken(accessClaims({ exp: Math.floor(NOW.getTime() / 1000) - 120 })),
    createAccessToken(accessClaims({ iat: seconds + 1, auth_time: seconds + 61 })),
    createAccessToken(accessClaims({ cnf: { jkt: "too-short" } })),
    createAccessToken(accessClaims(), unknown.privateKey),
  ];
  for (const accessToken of invalid) {
    await assert.rejects(() => createVerifier().verifyRequest({ authorization: `DPoP ${accessToken}`,
      dpop: createProof(accessToken, { url: URL }), method: "GET", absoluteUrl: URL }));
  }
  const revoked = createAccessToken();
  await assert.rejects(() => createVerifier({ revoked: new Set(["access-jti-123"]) }).verifyRequest({
    authorization: `DPoP ${revoked}`, dpop: createProof(revoked, { url: URL }), method: "GET", absoluteUrl: URL,
  }), /revoked/);
});

test("DPoP method, URI, access-token hash, nonce, and durable replay are exact", async () => {
  const accessToken = createAccessToken();
  const cases = [
    createProof(accessToken, { url: URL, overrides: { htm: "POST" } }),
    createProof(accessToken, { url: URL, overrides: { htu: `${URL}/other` } }),
    createProof(accessToken, { url: URL, overrides: { ath: "x".repeat(43) } }),
    createProof(accessToken, { url: URL, nonce: "short" }),
  ];
  for (const dpop of cases) {
    await assert.rejects(() => createVerifier().verifyRequest({ authorization: `DPoP ${accessToken}`,
      dpop, method: "GET", absoluteUrl: URL }), /DPoP/);
  }
  await assert.rejects(() => createVerifier({ replayStore: { consumeProof: async () => false } }).verifyRequest({
    authorization: `DPoP ${accessToken}`, dpop: createProof(accessToken, { url: URL }),
    method: "GET", absoluteUrl: URL,
  }), /already used/);
});
