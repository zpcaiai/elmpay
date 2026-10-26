import { createPublicKey, verify } from "node:crypto";
import { readControlledFile } from "./controlled-file.mjs";
import { canonicalJson, sha256Base64Url, sha256Hex } from "./canonical-json.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OPAQUE = /^[A-Za-z0-9._:@/-]{1,160}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const PHISHING_RESISTANT_AMR = new Set(["webauthn", "hwk", "fido"]);
const FORBIDDEN_AMR = new Set(["sms", "sms-otp", "otp", "totp", "push"]);
const verifiedOperators = new WeakSet();

function failure(message) {
  const error = new Error(message);
  error.code = "AUTHENTICATION_FAILED";
  return error;
}

function controlFailure(message) {
  const error = new Error(message);
  error.code = "AUTHENTICATION_CONTROL_UNAVAILABLE";
  return error;
}

function exactObject(value, allowed, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw failure(`${label} is invalid`);
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw failure(`${label} contains an unsupported field`);
  return value;
}

function decodePart(encoded, label) {
  if (typeof encoded !== "string" || !B64URL.test(encoded)) throw failure(`${label} is not base64url`);
  try {
    const decoded = Buffer.from(encoded, "base64url");
    if (decoded.toString("base64url") !== encoded) throw new Error("non-canonical encoding");
    return decoded;
  } catch {
    throw failure(`${label} is not canonical base64url`);
  }
}

function parseJwt(compact, label) {
  if (typeof compact !== "string" || compact.length > 16_384) throw failure(`${label} is invalid`);
  const parts = compact.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) throw failure(`${label} is invalid`);
  try {
    const header = JSON.parse(decodePart(parts[0], `${label} header`).toString("utf8"));
    const payload = JSON.parse(decodePart(parts[1], `${label} payload`).toString("utf8"));
    const signature = decodePart(parts[2], `${label} signature`);
    return { header, payload, signature, signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, "ascii") };
  } catch (error) {
    if (error?.code === "AUTHENTICATION_FAILED") throw error;
    throw failure(`${label} JSON is invalid`);
  }
}

function requireInteger(value, name) {
  if (!Number.isSafeInteger(value)) throw failure(`${name} must be an integer NumericDate`);
  return value;
}

function requireOpaque(value, name) {
  if (typeof value !== "string" || !OPAQUE.test(value)) throw failure(`${name} is invalid`);
  return value;
}

function parseEs256Jwk(jwk, label) {
  exactObject(jwk, new Set(["kty", "crv", "x", "y", "kid", "use", "alg", "key_ops"]), label);
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || jwk.alg !== "ES256") throw failure(`${label} is not an ES256 P-256 key`);
  if (jwk.d !== undefined || !B64URL.test(jwk.x ?? "") || !B64URL.test(jwk.y ?? "")) throw failure(`${label} is not a public key`);
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  if (x.length !== 32 || y.length !== 32 || x.toString("base64url") !== jwk.x || y.toString("base64url") !== jwk.y) {
    throw failure(`${label} coordinates are invalid`);
  }
  try {
    return {
      canonical: { crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y },
      key: createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" }),
    };
  } catch {
    throw failure(`${label} point is invalid`);
  }
}

function verifyEs256(parsed, key, label) {
  if (parsed.signature.length !== 64 || !verify("sha256", parsed.signingInput,
    { key, dsaEncoding: "ieee-p1363" }, parsed.signature)) throw failure(`${label} signature is invalid`);
}

export function loadCorporateJwks(path) {
  const document = JSON.parse(readControlledFile(path, "corporate JWKS", 1_048_576).toString("utf8"));
  exactObject(document, new Set(["keys"]), "corporate JWKS");
  if (!Array.isArray(document.keys) || document.keys.length === 0 || document.keys.length > 20) {
    throw new Error("corporate JWKS must contain between 1 and 20 keys");
  }
  const keys = new Map();
  for (const jwk of document.keys) {
    requireOpaque(jwk?.kid, "JWKS kid");
    if (jwk.use !== "sig" || (jwk.key_ops !== undefined
        && (!Array.isArray(jwk.key_ops) || jwk.key_ops.length !== 1 || jwk.key_ops[0] !== "verify"))) {
      throw new Error("corporate JWKS keys must be signature verification keys");
    }
    if (keys.has(jwk.kid)) throw new Error("corporate JWKS kid values must be unique");
    keys.set(jwk.kid, parseEs256Jwk(jwk, "corporate JWKS key").key);
  }
  return keys;
}

export class FileRevocationSource {
  constructor({ path, keys, issuer, maximumAgeSeconds = 60 }) {
    this.path = path;
    this.keys = keys;
    this.issuer = issuer;
    this.maximumAgeSeconds = maximumAgeSeconds;
  }

  current(now = new Date()) {
    try {
      const document = JSON.parse(readControlledFile(this.path, "revocation snapshot",
        16 * 1024 * 1024).toString("utf8"));
      exactObject(document, new Set(["schemaVersion", "issuer", "issuedAt", "expiresAt", "revokedJtis", "signature"]), "revocation snapshot");
      if (document.schemaVersion !== 1 || document.issuer !== this.issuer
          || !Array.isArray(document.revokedJtis) || document.revokedJtis.length > 100_000) throw new Error("invalid contract");
      const issuedAt = requireInteger(document.issuedAt, "revocation issuedAt");
      const expiresAt = requireInteger(document.expiresAt, "revocation expiresAt");
      const nowSeconds = Math.floor(now.getTime() / 1000);
      if (issuedAt > nowSeconds + 60 || nowSeconds - issuedAt > this.maximumAgeSeconds || expiresAt <= nowSeconds) {
        throw new Error("stale snapshot");
      }
      const revoked = new Set(document.revokedJtis.map((jti) => requireOpaque(jti, "revoked jti")));
      if (revoked.size !== document.revokedJtis.length) throw new Error("duplicate jti");
      exactObject(document.signature, new Set(["alg", "kid", "value"]), "revocation signature");
      if (document.signature.alg !== "ES256") throw new Error("invalid algorithm");
      const key = this.keys.get(document.signature.kid);
      if (key === undefined) throw new Error("untrusted key");
      const signature = decodePart(document.signature.value, "revocation signature");
      const unsigned = { ...document };
      delete unsigned.signature;
      if (signature.length !== 64 || !verify("sha256", Buffer.from(canonicalJson(unsigned)),
        { key, dsaEncoding: "ieee-p1363" }, signature)) throw new Error("invalid signature");
      return revoked;
    } catch {
      throw controlFailure("revocation control is unavailable");
    }
  }
}

function validateElevation(elevation, subject, tokenExpiry, nowSeconds) {
  if (elevation === undefined) return null;
  exactObject(elevation, new Set(["permission", "ticket_id", "approved_by", "expires_at", "approval_digest"]), "elevation");
  requireOpaque(elevation.permission, "elevation permission");
  requireOpaque(elevation.ticket_id, "elevation ticket_id");
  requireOpaque(elevation.approved_by, "elevation approved_by");
  if (elevation.approved_by === subject) throw failure("elevation violates separation of duties");
  if (!/^[0-9a-f]{64}$/.test(elevation.approval_digest ?? "")) throw failure("elevation approval_digest is invalid");
  const expiry = requireInteger(elevation.expires_at, "elevation expires_at");
  if (expiry <= nowSeconds || expiry > tokenExpiry || expiry - nowSeconds > 3600) throw failure("elevation lifetime is invalid");
  return Object.freeze({ ...elevation });
}

export class OperatorTokenVerifier {
  constructor({ issuer, audience, keys, revocationSource, replayStore, clockSkewSeconds = 60,
    maximumTokenSeconds = 3600, stepUpSeconds = 300, now = () => new Date() }) {
    this.issuer = new URL(issuer).toString().replace(/\/$/, "");
    this.audience = audience;
    this.keys = keys;
    this.revocationSource = revocationSource;
    this.replayStore = replayStore;
    this.clockSkewSeconds = clockSkewSeconds;
    this.maximumTokenSeconds = maximumTokenSeconds;
    this.stepUpSeconds = stepUpSeconds;
    this.now = now;
  }

  async verifyRequest({ authorization, dpop, method, absoluteUrl }) {
    if (typeof authorization !== "string" || !authorization.startsWith("DPoP ")) throw failure("DPoP access token is required");
    const compactAccessToken = authorization.slice(5);
    const access = parseJwt(compactAccessToken, "operator access token");
    exactObject(access.header, new Set(["alg", "kid", "typ"]), "access token header");
    if (access.header.alg !== "ES256" || access.header.typ !== "at+jwt") throw failure("access token protected header is invalid");
    const accessKey = this.keys.get(requireOpaque(access.header.kid, "access token kid"));
    if (accessKey === undefined) throw failure("access token signing key is not trusted");
    verifyEs256(access, accessKey, "access token");

    const claims = exactObject(access.payload, new Set([
      "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "auth_time", "tenant_id", "roles",
      "amr", "cnf", "device_posture", "elevation",
    ]), "access token claims");
    const now = this.now();
    const nowSeconds = Math.floor(now.getTime() / 1000);
    const issuedAt = requireInteger(claims.iat, "iat");
    const notBefore = requireInteger(claims.nbf, "nbf");
    const expiresAt = requireInteger(claims.exp, "exp");
    const authTime = requireInteger(claims.auth_time, "auth_time");
    if (claims.iss !== this.issuer || claims.aud !== this.audience) throw failure("access token issuer or audience is invalid");
    if (issuedAt > nowSeconds + this.clockSkewSeconds || notBefore > nowSeconds + this.clockSkewSeconds
        || expiresAt <= nowSeconds - this.clockSkewSeconds || expiresAt <= issuedAt
        || notBefore > expiresAt || expiresAt - issuedAt > this.maximumTokenSeconds
        || authTime > issuedAt + this.clockSkewSeconds || authTime > nowSeconds + this.clockSkewSeconds) {
      throw failure("access token time claims are invalid");
    }
    const subject = requireOpaque(claims.sub, "sub");
    const accessJti = requireOpaque(claims.jti, "jti");
    if (!UUID.test(claims.tenant_id ?? "")) throw failure("tenant_id is invalid");
    if (!Array.isArray(claims.roles) || claims.roles.length === 0 || claims.roles.length > 8) throw failure("roles are invalid");
    const roles = [...new Set(claims.roles.map((role) => requireOpaque(role, "role")))];
    if (roles.length !== claims.roles.length) throw failure("roles contain duplicates");
    if (!Array.isArray(claims.amr) || claims.amr.length === 0 || claims.amr.length > 8
        || claims.amr.some((methodName) => typeof methodName !== "string" || !OPAQUE.test(methodName))
        || new Set(claims.amr).size !== claims.amr.length
        || !claims.amr.some((methodName) => PHISHING_RESISTANT_AMR.has(methodName))
        || claims.amr.some((methodName) => FORBIDDEN_AMR.has(methodName))) {
      throw failure("phishing-resistant authentication is required");
    }
    if (!new Set(["MANAGED", "ATTESTED"]).has(claims.device_posture)) throw failure("trusted device posture is required");
    exactObject(claims.cnf, new Set(["jkt"]), "cnf");
    if (!B64URL.test(claims.cnf.jkt ?? "") || decodePart(claims.cnf.jkt, "cnf.jkt").length !== 32) {
      throw failure("cnf.jkt is invalid");
    }
    if (this.revocationSource.current(now).has(accessJti)) throw failure("access token is revoked");

    const proof = parseJwt(dpop, "DPoP proof");
    exactObject(proof.header, new Set(["typ", "alg", "jwk"]), "DPoP header");
    if (proof.header.typ !== "dpop+jwt" || proof.header.alg !== "ES256") throw failure("DPoP protected header is invalid");
    if (proof.header.jwk?.kid !== undefined || proof.header.jwk?.use !== undefined
        || proof.header.jwk?.key_ops !== undefined || proof.header.jwk?.alg !== undefined) {
      throw failure("DPoP jwk contains unsupported metadata");
    }
    const proofJwk = parseEs256Jwk({ ...proof.header.jwk, alg: "ES256" }, "DPoP jwk");
    const thumbprint = sha256Base64Url(Buffer.from(canonicalJson(proofJwk.canonical)));
    if (thumbprint !== claims.cnf.jkt) throw failure("DPoP key is not bound to access token");
    verifyEs256(proof, proofJwk.key, "DPoP proof");
    const proofClaims = exactObject(proof.payload, new Set(["htm", "htu", "iat", "jti", "ath", "nonce"]), "DPoP claims");
    const proofIssuedAt = requireInteger(proofClaims.iat, "DPoP iat");
    if (proofClaims.htm !== method.toUpperCase() || proofClaims.htu !== absoluteUrl
        || Math.abs(nowSeconds - proofIssuedAt) > this.clockSkewSeconds
        || proofClaims.ath !== sha256Base64Url(Buffer.from(compactAccessToken, "ascii"))) {
      throw failure("DPoP request binding is invalid");
    }
    const proofJti = requireOpaque(proofClaims.jti, "DPoP jti");
    if (typeof proofClaims.nonce !== "string" || !B64URL.test(proofClaims.nonce)
        || decodePart(proofClaims.nonce, "DPoP nonce").length !== 32) throw failure("DPoP nonce is invalid");
    const accepted = await this.replayStore.consumeProof({
      tenantId: claims.tenant_id, issuer: this.issuer, subjectDigest: sha256Hex(subject),
      accessJtiDigest: sha256Hex(accessJti), proofJtiDigest: sha256Hex(proofJti),
      nonceDigest: sha256Hex(proofClaims.nonce), proofThumbprint: thumbprint,
      proofExpiresAt: new Date((proofIssuedAt + this.clockSkewSeconds + 1) * 1000).toISOString(),
    });
    if (!accepted) throw failure("DPoP proof or nonce was already used");

    const operator = Object.freeze({
      id: subject, tenantId: claims.tenant_id, roles: Object.freeze(roles), accessJti,
      authTime: new Date(authTime * 1000), tokenExpiresAt: new Date(expiresAt * 1000),
      elevation: validateElevation(claims.elevation, subject, expiresAt, nowSeconds),
      phishingResistant: true, devicePosture: claims.device_posture,
    });
    verifiedOperators.add(operator);
    return operator;
  }

  isRecentStepUp(operator) {
    assertVerifiedOperator(operator);
    const ageMilliseconds = this.now().getTime() - operator.authTime.getTime();
    return ageMilliseconds >= -this.clockSkewSeconds * 1000
      && ageMilliseconds <= this.stepUpSeconds * 1000;
  }
}

export function assertVerifiedOperator(operator) {
  if (!verifiedOperators.has(operator)) throw failure("a cryptographically verified operator is required");
  return operator;
}
