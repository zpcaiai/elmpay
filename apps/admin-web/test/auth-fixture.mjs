import { generateKeyPairSync, sign } from "node:crypto";
import { canonicalJson, sha256Base64Url } from "../src/canonical-json.mjs";
import { OperatorTokenVerifier } from "../src/operator-auth.mjs";

export const NOW = new Date("2026-08-30T12:00:00.000Z");
export const TENANT = "11111111-1111-4111-8111-111111111111";
export const ISSUER = "https://idp.example.invalid/corp";

const idp = generateKeyPairSync("ec", { namedCurve: "P-256" });
const holder = generateKeyPairSync("ec", { namedCurve: "P-256" });
export const idpJwk = { ...idp.publicKey.export({ format: "jwk" }), kid: "corp-key-1", use: "sig", alg: "ES256" };
export const holderJwk = holder.publicKey.export({ format: "jwk" });
export const holderThumbprint = sha256Base64Url(Buffer.from(canonicalJson({
  crv: holderJwk.crv, kty: holderJwk.kty, x: holderJwk.x, y: holderJwk.y,
})));

function jwt(header, payload, privateKey) {
  const first = Buffer.from(JSON.stringify(header)).toString("base64url");
  const second = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign("sha256", Buffer.from(`${first}.${second}`),
    { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return `${first}.${second}.${signature}`;
}

export function accessClaims(overrides = {}) {
  const seconds = Math.floor(NOW.getTime() / 1000);
  return {
    iss: ISSUER, aud: "admin-web", sub: "operator-a", jti: "access-jti-123",
    iat: seconds - 30, nbf: seconds - 30, exp: seconds + 600, auth_time: seconds - 30,
    tenant_id: TENANT, roles: ["platform-operator"], amr: ["webauthn"],
    cnf: { jkt: holderThumbprint }, device_posture: "MANAGED", ...overrides,
  };
}

export function createAccessToken(claims = accessClaims(), key = idp.privateKey) {
  return jwt({ alg: "ES256", kid: "corp-key-1", typ: "at+jwt" }, claims, key);
}

export function createProof(accessToken, { method = "GET", url = "https://admin.example.test/api/admin/resource",
  nonce = Buffer.alloc(32, 7).toString("base64url"), jti = "proof-jti-123", iat,
  key = holder.privateKey, jwk = holderJwk, overrides = {} } = {}) {
  return jwt({ typ: "dpop+jwt", alg: "ES256", jwk }, {
    htm: method, htu: url, iat: iat ?? Math.floor(NOW.getTime() / 1000), jti,
    ath: sha256Base64Url(Buffer.from(accessToken, "ascii")), nonce, ...overrides,
  }, key);
}

export function createVerifier({ replayStore, now = () => NOW, revoked = new Set() } = {}) {
  return new OperatorTokenVerifier({
    issuer: ISSUER, audience: "admin-web", keys: new Map([["corp-key-1", idp.publicKey]]),
    revocationSource: { current: () => revoked },
    replayStore: replayStore ?? { consumeProof: async () => true }, now,
  });
}

export async function verifiedOperator(claimOverrides = {}, proofOverrides = {}) {
  const verifier = createVerifier();
  const accessToken = createAccessToken(accessClaims(claimOverrides));
  const url = proofOverrides.url ?? "https://admin.example.test/api/admin/resource";
  const method = proofOverrides.method ?? "GET";
  return verifier.verifyRequest({ authorization: `DPoP ${accessToken}`,
    dpop: createProof(accessToken, { ...proofOverrides, url, method }), method, absoluteUrl: url });
}
