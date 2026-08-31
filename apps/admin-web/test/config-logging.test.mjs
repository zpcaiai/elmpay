import assert from "node:assert/strict";
import test from "node:test";
import { chmodSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadProductionConfig } from "../src/config.mjs";
import { SafeLogger } from "../src/safe-logger.mjs";

function fixtureEnvironment() {
  const directory = mkdtempSync(join(tmpdir(), "elmpay-admin-config-"));
  const file = (name, mode = 0o400) => {
    const path = join(directory, name); writeFileSync(path, "fixture"); chmodSync(path, mode); return path;
  };
  const psql = file("psql", 0o500);
  return {
    ADMIN_RUNTIME_MODE: "production", ADMIN_LISTEN_HOST: "0.0.0.0", ADMIN_PORT: "8443",
    ADMIN_PUBLIC_ORIGIN: "https://admin.example.test", ADMIN_IDP_ISSUER: "https://idp.example.invalid/corp",
    ADMIN_IDP_AUDIENCE: "admin-web", ADMIN_IDP_JWKS_FILE: file("jwks.json"),
    ADMIN_IDP_REVOCATION_FILE: file("revocation.json"), ADMIN_AUTHORIZATION_FILE: file("authorization.json"),
    ADMIN_ACTION_POLICY_FILE: file("actions.json"), ADMIN_TLS_CERT_FILE: file("tls.crt"),
    ADMIN_TLS_KEY_FILE: file("tls.key"), ADMIN_PSQL_PATH: psql, ADMIN_PG_SERVICE: "elmpay-admin",
    ADMIN_PG_SERVICE_FILE: file("pg_service.conf"), ADMIN_PG_ROOT_CA_FILE: file("pg-ca.crt"),
    ADMIN_UPSTREAM_ORIGIN: "https://edge.internal.example", ADMIN_UPSTREAM_CA_FILE: file("upstream-ca.crt"),
    ADMIN_UPSTREAM_CERT_FILE: file("upstream.crt"), ADMIN_UPSTREAM_KEY_FILE: file("upstream.key"),
  };
}

test("production configuration requires explicit TLS/trust/database mounts and forbids inline credentials", () => {
  const env = fixtureEnvironment();
  const config = loadProductionConfig(env);
  assert.equal(config.audience, "admin-web");
  assert.equal(config.publicOrigin, "https://admin.example.test");
  assert.throws(() => loadProductionConfig({ ...env, ADMIN_IDP_JWKS_FILE: "relative.json" }), /absolute/);
  chmodSync(env.ADMIN_IDP_JWKS_FILE, 0o600);
  assert.throws(() => loadProductionConfig(env), /read-only/);
  chmodSync(env.ADMIN_IDP_JWKS_FILE, 0o400);
  chmodSync(env.ADMIN_PSQL_PATH, 0o700);
  assert.throws(() => loadProductionConfig(env), /read-only/);
  chmodSync(env.ADMIN_PSQL_PATH, 0o520);
  assert.throws(() => loadProductionConfig(env), /read-only/);
  chmodSync(env.ADMIN_PSQL_PATH, 0o500);
  assert.throws(() => loadProductionConfig({ ...env, PGPASSWORD: "must-not-exist" }), /credentials/);
  assert.throws(() => loadProductionConfig({ ...env, ADMIN_RUNTIME_MODE: "local" }), /production/);
});

test("safe logger refuses secrets, PII and arbitrary caller-controlled fields", () => {
  let output = "";
  const logger = new SafeLogger({ write: (value) => { output += value; } });
  logger.event("REQUEST_REJECTED", { code: "AUTHENTICATION_REQUIRED", status: 401,
    requestId: "request-123", authorization: "DPoP secret", email: "person@example.test",
    tenantId: "11111111-1111-4111-8111-111111111111" });
  assert.match(output, /AUTHENTICATION_REQUIRED/);
  assert.doesNotMatch(output, /secret|person@|tenantId/);
  assert.throws(() => logger.event("CALLER_EVENT", { code: "x" }), /unsupported/);
});

test("configuration permits in-mount Secret rotation symlinks and rejects escape", () => {
  const env = fixtureEnvironment();
  const mount = mkdtempSync(join(tmpdir(), "elmpay-admin-mount-"));
  const revision = join(mount, "..2026_08_30");
  mkdirSync(revision);
  writeFileSync(join(revision, "jwks.json"), "fixture");
  chmodSync(join(revision, "jwks.json"), 0o400);
  symlinkSync("..2026_08_30", join(mount, "..data"));
  symlinkSync("..data/jwks.json", join(mount, "jwks.json"));
  assert.equal(loadProductionConfig({ ...env, ADMIN_IDP_JWKS_FILE: join(mount, "jwks.json") })
    .jwksPath, join(mount, "jwks.json"));

  const outside = mkdtempSync(join(tmpdir(), "elmpay-admin-outside-"));
  writeFileSync(join(outside, "jwks.json"), "fixture");
  chmodSync(join(outside, "jwks.json"), 0o400);
  symlinkSync(join(outside, "jwks.json"), join(mount, "escaped.json"));
  assert.throws(() => loadProductionConfig({ ...env,
    ADMIN_IDP_JWKS_FILE: join(mount, "escaped.json") }), /controlled mount/);
});
