import { dirname, isAbsolute, sep } from "node:path";
import { realpathSync, statSync } from "node:fs";

function required(env, name, pattern = /^.{1,2048}$/) {
  const value = env[name];
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is required and invalid`);
  return value;
}

function controlledFile(env, name, { executable = false, maximumBytes = 1_048_576 } = {}) {
  const path = required(env, name);
  if (!isAbsolute(path)) throw new Error(`${name} must be an absolute path`);
  const resolved = realpathSync(path);
  if (!executable) {
    const mountParent = realpathSync(dirname(path));
    if (resolved !== mountParent && !resolved.startsWith(`${mountParent}${sep}`)) {
      throw new Error(`${name} must remain inside its controlled mount`);
    }
  }
  const stat = statSync(resolved, { throwIfNoEntry: true });
  // Projected credentials must be immutable to the workload.  A packaged
  // executable is different: root-owned 0755 is the normal, safe container
  // image mode, while any group/world-writable executable (or a writable
  // executable owned by the unprivileged runtime user) is rejected.
  const writableExecutable = executable
    && ((stat.mode & 0o022) !== 0 || ((stat.mode & 0o200) !== 0 && stat.uid !== 0));
  const writableCredential = !executable && (stat.mode & 0o222) !== 0;
  if (!stat.isFile() || (!executable && (stat.size < 1 || stat.size > maximumBytes))
      || writableCredential || writableExecutable
      || (executable && (stat.mode & 0o111) === 0)) {
    throw new Error(`${name} must reference a read-only controlled${executable ? " executable" : ""} regular file`);
  }
  return path;
}

function boundedInteger(env, name, fallback, minimum, maximum) {
  const value = Number.parseInt(env[name] ?? String(fallback), 10);
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${name} is outside its allowed range`);
  return value;
}

function exactHttpsOrigin(value, name) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username !== "" || url.password !== ""
      || url.pathname !== "/" || url.search !== "" || url.hash !== "") throw new Error(`${name} must be an HTTPS origin`);
  return url.origin;
}

export function loadProductionConfig(env = process.env) {
  if (env.ADMIN_RUNTIME_MODE !== "production") throw new Error("ADMIN_RUNTIME_MODE must explicitly be production");
  if (env.PGPASSWORD !== undefined || env.ADMIN_DATABASE_URL !== undefined) {
    throw new Error("inline PostgreSQL credentials are forbidden; use a read-only libpq service mount");
  }
  const issuer = required(env, "ADMIN_IDP_ISSUER");
  const issuerUrl = new URL(issuer);
  if (issuerUrl.protocol !== "https:" || issuerUrl.username !== "" || issuerUrl.password !== ""
      || issuerUrl.search !== "" || issuerUrl.hash !== "") {
    throw new Error("ADMIN_IDP_ISSUER must be an HTTPS issuer URL");
  }
  if (required(env, "ADMIN_IDP_AUDIENCE") !== "admin-web") throw new Error("ADMIN_IDP_AUDIENCE must be admin-web");
  return Object.freeze({
    host: required(env, "ADMIN_LISTEN_HOST", /^(?:0\.0\.0\.0|\[::\]|[A-Za-z0-9.-]{1,253})$/),
    port: boundedInteger(env, "ADMIN_PORT", 8443, 1, 65535),
    publicOrigin: exactHttpsOrigin(required(env, "ADMIN_PUBLIC_ORIGIN"), "ADMIN_PUBLIC_ORIGIN"),
    issuer: issuerUrl.toString().replace(/\/$/, ""), audience: "admin-web",
    jwksPath: controlledFile(env, "ADMIN_IDP_JWKS_FILE"),
    revocationPath: controlledFile(env, "ADMIN_IDP_REVOCATION_FILE",
      { maximumBytes: 16 * 1024 * 1024 }),
    authorizationPath: controlledFile(env, "ADMIN_AUTHORIZATION_FILE"),
    actionPolicyPath: controlledFile(env, "ADMIN_ACTION_POLICY_FILE"),
    tlsCertificatePath: controlledFile(env, "ADMIN_TLS_CERT_FILE"),
    tlsPrivateKeyPath: controlledFile(env, "ADMIN_TLS_KEY_FILE"),
    psqlPath: controlledFile(env, "ADMIN_PSQL_PATH", { executable: true }),
    pgService: required(env, "ADMIN_PG_SERVICE", /^[A-Za-z0-9_.-]{1,64}$/),
    pgServiceFile: controlledFile(env, "ADMIN_PG_SERVICE_FILE"),
    pgRootCertificate: controlledFile(env, "ADMIN_PG_ROOT_CA_FILE"),
    upstreamBaseUrl: exactHttpsOrigin(required(env, "ADMIN_UPSTREAM_ORIGIN"), "ADMIN_UPSTREAM_ORIGIN"),
    upstreamCaPath: controlledFile(env, "ADMIN_UPSTREAM_CA_FILE"),
    upstreamCertificatePath: controlledFile(env, "ADMIN_UPSTREAM_CERT_FILE"),
    upstreamPrivateKeyPath: controlledFile(env, "ADMIN_UPSTREAM_KEY_FILE"),
    databaseTimeoutMs: boundedInteger(env, "ADMIN_DATABASE_TIMEOUT_MS", 3000, 100, 5000),
    upstreamTimeoutMs: boundedInteger(env, "ADMIN_UPSTREAM_TIMEOUT_MS", 4500, 100, 5000),
  });
}
