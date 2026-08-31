import { spawn } from "node:child_process";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { dirname, isAbsolute, sep } from "node:path";
import { realpathSync, statSync } from "node:fs";
import { TextDecoder } from "node:util";
import { canonicalJson, sha256Hex } from "./canonical-json.mjs";
import { initialAuditEvent } from "./approval-model.mjs";

const MAX_OUTPUT_BYTES = 65_536;
const MAX_INPUT_BYTES = 262_144;
const MAX_STATEMENT_BYTES = 2_097_152;
const INPUT_MARKER = "__ADMIN_INPUT__";
const DIGEST_PREFIX = "__ADMIN_INPUT_SHA256__=";

export class DatabaseUnavailableError extends Error {
  constructor(message = "admin database is unavailable") {
    super(message);
    this.code = "DATABASE_UNAVAILABLE";
  }
}

function controlledPath(path, label) {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path`);
  const executable = label === "psql executable";
  const resolved = realpathSync(path);
  if (!executable) {
    const mountParent = realpathSync(dirname(path));
    if (resolved !== mountParent && !resolved.startsWith(`${mountParent}${sep}`)) {
      throw new Error(`${label} must remain inside its controlled mount`);
    }
  }
  const stat = statSync(resolved, { throwIfNoEntry: true });
  const writableExecutable = executable
    && ((stat.mode & 0o022) !== 0 || ((stat.mode & 0o200) !== 0 && stat.uid !== 0));
  const writableCredential = !executable && (stat.mode & 0o222) !== 0;
  if (!stat.isFile() || (!executable && (stat.size < 1 || stat.size > 1_048_576))
      || writableCredential || writableExecutable
      || (executable && (stat.mode & 0o111) === 0)) {
    throw new Error(`${label} must be a read-only controlled regular file`);
  }
  return path;
}

export class PsqlRunner {
  constructor({ psqlPath, service, serviceFile, rootCertificate, timeoutMs = 3000 }) {
    this.psqlPath = controlledPath(psqlPath, "psql executable");
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(service ?? "")) throw new Error("PostgreSQL service name is invalid");
    this.service = service;
    this.serviceFile = controlledPath(serviceFile, "PostgreSQL service file");
    this.rootCertificate = controlledPath(rootCertificate, "PostgreSQL root certificate");
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 5000) {
      throw new Error("PostgreSQL timeout must be 100..5000 milliseconds");
    }
    this.timeoutMs = timeoutMs;
  }

  execute(sql, input = {}) {
    if (typeof sql !== "string" || sql.length === 0
        || sql.split(INPUT_MARKER).length !== 2) {
      throw new TypeError("SQL requires exactly one canonical input marker");
    }
    let inputBytes;
    let statementBytes;
    let statementOwnershipTransferred = false;
    try {
      // JavaScript strings produced by canonicalJson/base64 are immutable and cannot be
      // deterministically erased. Mutable source/transport buffers are still bounded and wiped.
      inputBytes = Buffer.from(canonicalJson(input), "utf8");
      if (inputBytes.length === 0 || inputBytes.length > MAX_INPUT_BYTES) {
        throw new TypeError("canonical database input exceeded its bound");
      }
      const encoded = inputBytes.toString("base64");
      const inputDigest = sha256Hex(inputBytes);
      const prelude = `\\set admin_input_base64 '${encoded}'\n\\set admin_input_sha256 '${inputDigest}'`;
      const digestProof = `\nSELECT '${DIGEST_PREFIX}' || encode(sha256(decode(:'admin_input_base64', 'base64')), 'hex');\n`;
      statementBytes = Buffer.from(sql.replace(INPUT_MARKER, prelude) + digestProof, "utf8");
      if (statementBytes.length === 0 || statementBytes.length > MAX_STATEMENT_BYTES) {
        throw new TypeError("database statement exceeded its bound");
      }
      const pending = this.#executeBounded(statementBytes, inputDigest);
      statementOwnershipTransferred = true;
      return pending;
    } finally {
      inputBytes?.fill(0);
      // #executeBounded owns the statement buffer once called and wipes it after the child closes.
      if (statementBytes !== undefined && !statementOwnershipTransferred) {
        statementBytes.fill(0);
      }
    }
  }

  #executeBounded(statementBytes, inputDigest) {
    return new Promise((resolve, reject) => {
      let child;
      let stdout = Buffer.alloc(0);
      let stderrBytes = 0;
      let settled = false;
      let terminalError = null;
      let timer = null;
      const wipeAndDestroy = () => {
        statementBytes.fill(0);
        stdout.fill(0);
        child?.stdin?.destroy();
        child?.stdout?.destroy();
        child?.stderr?.destroy();
      };
      const terminate = (error) => {
        if (terminalError === null) terminalError = error;
        if (child !== undefined && child.exitCode === null && child.signalCode === null) {
          // psql may spawn helpers for password/service resolution.  The child is detached so
          // a timeout closes its whole process group instead of leaving a credential-bearing
          // descendant alive after the request has failed.
          try {
            if (child.pid !== undefined && process.platform !== "win32") {
              process.kill(-child.pid, "SIGKILL");
            } else {
              child.kill("SIGKILL");
            }
          } catch {
            try { child.kill("SIGKILL"); } catch { /* the close event will settle the race */ }
          }
        }
      };
      const settleAfterClose = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        wipeAndDestroy();
        if (error !== null) reject(error); else resolve(value);
      };
      try {
        child = spawn(this.psqlPath, ["--no-psqlrc", "-qAt", "--set=ON_ERROR_STOP=1"], {
          stdio: ["pipe", "pipe", "pipe"],
          detached: process.platform !== "win32",
          env: {
            LANG: "C", LC_ALL: "C", PGAPPNAME: "elmpay-admin-web", PGCONNECT_TIMEOUT: "3",
            PGSERVICE: this.service, PGSERVICEFILE: this.serviceFile, PGSSLMODE: "verify-full",
            PGSSLROOTCERT: this.rootCertificate,
          },
        });
      } catch {
        settleAfterClose(new DatabaseUnavailableError(), null);
        return;
      }
      timer = setTimeout(() => terminate(
        new DatabaseUnavailableError("admin database command timed out")), this.timeoutMs);
      child.stdout.on("data", (source) => {
        const chunk = Buffer.from(source);
        if (stdout.length + chunk.length > MAX_OUTPUT_BYTES) {
          chunk.fill(0);
          if (Buffer.isBuffer(source)) source.fill(0);
          terminate(new DatabaseUnavailableError(
            "admin database response exceeded its bound"));
          return;
        }
        const previous = stdout;
        stdout = Buffer.concat([previous, chunk]);
        previous.fill(0);
        chunk.fill(0);
        if (Buffer.isBuffer(source)) source.fill(0);
      });
      child.stderr.on("data", (source) => {
        const chunk = Buffer.from(source);
        stderrBytes += chunk.length;
        chunk.fill(0);
        if (Buffer.isBuffer(source)) source.fill(0);
        if (stderrBytes > MAX_OUTPUT_BYTES) {
          terminate(new DatabaseUnavailableError(
            "admin database error response exceeded its bound"));
        }
      });
      child.on("error", () => terminate(new DatabaseUnavailableError()));
      child.stdin.on("error", () => terminate(new DatabaseUnavailableError()));
      child.on("close", (code) => {
        if (terminalError !== null || code !== 0 || stderrBytes > MAX_OUTPUT_BYTES) {
          settleAfterClose(terminalError ?? new DatabaseUnavailableError(), null);
          return;
        }
        try {
          const output = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
          if (!output.endsWith("\n") || output.includes("\r")
              || output.split("").some(character => character !== "\n"
                  && (character < " " || character === "\x7f"))) {
            throw new Error("unexpected PostgreSQL result framing");
          }
          const lines = output.slice(0, -1).split("\n");
          if (lines.length < 1 || lines.length > 2
              || lines.at(-1) !== DIGEST_PREFIX + inputDigest) {
            throw new Error("unexpected PostgreSQL result framing");
          }
          const expectedBytes = Buffer.from(inputDigest, "ascii");
          const observedBytes = Buffer.from(lines.at(-1).slice(DIGEST_PREFIX.length), "ascii");
          try {
            if (!timingSafeEqual(observedBytes, expectedBytes)) {
              throw new Error("canonical input digest was not echoed by PostgreSQL");
            }
          } finally {
            expectedBytes.fill(0);
            observedBytes.fill(0);
          }
          const result = lines.length === 1 ? null : JSON.parse(lines[0]);
          if (result !== null && (typeof result !== "object" || Array.isArray(result))) {
            throw new Error("PostgreSQL result must be one JSON object or null");
          }
          settleAfterClose(null, result);
        } catch {
          settleAfterClose(new DatabaseUnavailableError(
            "admin database returned an invalid contract"), null);
        }
      });
      child.stdin.end(statementBytes, () => statementBytes.fill(0));
    });
  }
}

function inputCte() {
  return `${INPUT_MARKER}
WITH input_bytes AS (
  SELECT decode(:'admin_input_base64', 'base64') AS raw,
         :'admin_input_sha256'::text AS expected_digest
), input AS (
  SELECT convert_from(CASE WHEN encode(sha256(raw), 'hex') = expected_digest
    THEN raw ELSE decode('ff', 'hex') END, 'UTF8')::jsonb AS j
  FROM input_bytes
)`;
}

function tenantSetting() {
  return `SET LOCAL search_path = pg_catalog, public;
SELECT set_config('app.tenant_id',
    convert_from(decode(:'admin_input_base64', 'base64'), 'UTF8')::jsonb->>'tenantId', true) AS tenant_setting \\gset`;
}

function normalizeApproval(row) {
  if (row === null) return null;
  return Object.freeze({
    id: row.id, tenantId: row.tenantId, projectId: row.projectId, kind: row.kind,
    operationCode: row.operationCode, targetId: row.targetId,
    proposalDigest: row.proposalDigest, permission: row.permission, resource: row.resource,
    proposer: row.proposer, reasonCode: row.reasonCode, ticketDigest: row.ticketDigest,
    policyDigest: row.policyDigest, status: row.status, version: Number(row.version),
    createdAt: row.createdAt, expiresAt: row.expiresAt, decidedAt: row.decidedAt,
    decidedBy: row.decidedBy, lastAuditDigest: row.lastAuditDigest,
  });
}

const approvalJson = (row) => `jsonb_build_object(
  'id', ${row}.approval_id::text, 'tenantId', ${row}.tenant_id::text,
  'projectId', ${row}.project_id::text, 'kind', ${row}.kind,
  'operationCode', ${row}.operation_code,
  'targetId', ${row}.target_id, 'proposalDigest', ${row}.proposal_digest,
  'permission', ${row}.permission, 'resource', ${row}.resource_type, 'proposer', ${row}.proposer_id,
  'reasonCode', ${row}.reason_code, 'ticketDigest', ${row}.ticket_digest,
  'policyDigest', ${row}.policy_digest, 'status', CASE WHEN ${row}.status = 'PENDING'
    AND ${row}.expires_at <= clock_timestamp() THEN 'EXPIRED' ELSE ${row}.status END,
  'version', ${row}.version, 'createdAt', to_char(${row}.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  'expiresAt', to_char(${row}.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  'decidedAt', CASE WHEN ${row}.decided_at IS NULL THEN NULL ELSE to_char(${row}.decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
  'decidedBy', ${row}.decided_by,
  'lastAuditDigest', (SELECT event_digest FROM admin_approval_audit aa
    WHERE aa.tenant_id = ${row}.tenant_id AND aa.approval_id = ${row}.approval_id
    ORDER BY aa.sequence_no DESC LIMIT 1))`;

export class PostgresAdminStore {
  constructor(runner) { this.runner = runner; }

  async verifyRuntimeContract() {
    const result = await this.runner.execute(`${inputCte()},
expected_table(name, can_select, can_insert, can_update, can_delete) AS (VALUES
  ('admin_dpop_nonce', true, true, true, true),
  ('admin_dpop_replay', true, true, true, true),
  ('admin_dispatch_signal', true, true, true, true),
  ('admin_approval', true, true, true, false),
  ('admin_action_dispatch', true, true, true, false),
  ('admin_diagnostic_snapshot', true, true, true, false),
  ('admin_approval_audit', true, true, false, false),
  ('admin_access_audit', false, true, false, false)
), expected_sequence(name) AS (VALUES
  ('admin_approval_audit_sequence_no_seq'), ('admin_access_audit_sequence_no_seq')
), tenant_table(name) AS (VALUES
  ('admin_dpop_replay'), ('admin_approval'), ('admin_approval_audit'),
  ('admin_access_audit'), ('admin_diagnostic_snapshot'), ('admin_action_dispatch')
), role_gate AS (
  SELECT count(*) = 1 AND bool_and(
      current_user = 'elmpay_admin_web' AND session_user = current_user
      AND role.rolcanlogin AND NOT role.rolinherit AND NOT role.rolsuper
      AND NOT role.rolbypassrls AND NOT role.rolcreaterole AND NOT role.rolcreatedb
      AND NOT role.rolreplication AND role.rolconfig IS NULL
      AND current_setting('search_path') = 'pg_catalog,public,pg_temp'
      AND current_setting('row_security') = 'on'
      AND NOT EXISTS (SELECT 1 FROM pg_auth_members membership
                       WHERE membership.member = role.oid)
      AND NOT has_database_privilege(current_user, current_database(), 'CREATE')
      AND NOT has_database_privilege(current_user, current_database(), 'TEMPORARY')
      AND has_database_privilege(current_user, current_database(), 'CONNECT')
      AND NOT EXISTS (SELECT 1 FROM pg_database database
                       WHERE database.datname = current_database()
                         AND database.datdba = role.oid)
      AND has_schema_privilege(current_user, 'public', 'USAGE')
      AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
      AND NOT EXISTS (
        SELECT 1 FROM pg_namespace namespace
         WHERE namespace.nspname NOT IN ('pg_catalog','information_schema','public')
           AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND (namespace.nspowner = role.oid
             OR has_schema_privilege(current_user, namespace.oid, 'USAGE')
             OR has_schema_privilege(current_user, namespace.oid, 'CREATE')))) AS valid
    FROM pg_roles role WHERE role.rolname = current_user
), table_gate AS (
  SELECT count(*) = (SELECT count(*) FROM expected_table)
     AND bool_and(relation.oid IS NOT NULL
       AND relation.relowner <> role.oid
       AND has_table_privilege(current_user, relation.oid, 'SELECT') = expected.can_select
       AND has_table_privilege(current_user, relation.oid, 'INSERT') = expected.can_insert
       AND has_table_privilege(current_user, relation.oid, 'UPDATE') = expected.can_update
       AND has_table_privilege(current_user, relation.oid, 'DELETE') = expected.can_delete
       AND NOT has_table_privilege(current_user, relation.oid, 'TRUNCATE')
       AND NOT has_table_privilege(current_user, relation.oid, 'REFERENCES')
       AND NOT has_table_privilege(current_user, relation.oid, 'TRIGGER')
       AND NOT has_table_privilege(current_user, relation.oid, 'MAINTAIN')
       AND NOT EXISTS (
         SELECT 1 FROM pg_attribute attribute,
              LATERAL aclexplode(attribute.attacl) acl
          WHERE attribute.attrelid = relation.oid AND attribute.attnum > 0
            AND NOT attribute.attisdropped AND acl.grantee IN (0, role.oid))
       AND NOT EXISTS (
         SELECT 1 FROM aclexplode(COALESCE(
           relation.relacl, acldefault('r', relation.relowner))) acl
          WHERE acl.grantee IN (0, role.oid) AND acl.is_grantable)) AS valid
    FROM expected_table expected
    LEFT JOIN pg_class relation
      ON relation.oid = to_regclass('public.' || expected.name)
    CROSS JOIN pg_roles role WHERE role.rolname = current_user
), unexpected_relation_gate AS (
  SELECT count(*) = 0 AS valid
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_roles role ON role.rolname = current_user
   WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
     AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
     AND relation.relkind IN ('r','p','f','v','m')
     AND NOT (namespace.nspname = 'public' AND relation.relname IN
       (SELECT name FROM expected_table))
     AND (relation.relowner = role.oid
       OR has_table_privilege(current_user, relation.oid, 'SELECT')
       OR has_table_privilege(current_user, relation.oid, 'INSERT')
       OR has_table_privilege(current_user, relation.oid, 'UPDATE')
       OR has_table_privilege(current_user, relation.oid, 'DELETE')
       OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
       OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
       OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
       OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')
       OR EXISTS (SELECT 1 FROM pg_attribute attribute,
                    LATERAL aclexplode(attribute.attacl) acl
                   WHERE attribute.attrelid = relation.oid AND attribute.attnum > 0
                     AND NOT attribute.attisdropped AND acl.grantee IN (0, role.oid)))
), sequence_gate AS (
  SELECT count(*) = (SELECT count(*) FROM expected_sequence)
     AND bool_and(sequence.oid IS NOT NULL
       AND sequence.relowner <> role.oid
       AND has_sequence_privilege(current_user, sequence.oid, 'USAGE')
       AND NOT has_sequence_privilege(current_user, sequence.oid, 'SELECT')
       AND NOT has_sequence_privilege(current_user, sequence.oid, 'UPDATE')
       AND NOT EXISTS (
         SELECT 1 FROM aclexplode(COALESCE(
           sequence.relacl, acldefault('S', sequence.relowner))) acl
          WHERE acl.grantee IN (0, role.oid) AND acl.is_grantable))
     AND NOT EXISTS (
       SELECT 1 FROM pg_class extra
       JOIN pg_namespace namespace ON namespace.oid = extra.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
          AND extra.relkind = 'S'
          AND NOT (namespace.nspname = 'public'
            AND extra.relname IN (SELECT name FROM expected_sequence))
          AND (extra.relowner = role.oid
            OR has_sequence_privilege(current_user, extra.oid, 'USAGE')
            OR has_sequence_privilege(current_user, extra.oid, 'SELECT')
            OR has_sequence_privilege(current_user, extra.oid, 'UPDATE'))) AS valid
    FROM expected_sequence expected
    LEFT JOIN pg_class sequence
      ON sequence.oid = to_regclass('public.' || expected.name)
    CROSS JOIN pg_roles role WHERE role.rolname = current_user
), routine_gate AS (
  SELECT count(*) = 0 AS valid
    FROM pg_proc routine
    JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
    JOIN pg_roles role ON role.rolname = current_user
   WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
     AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
     AND (routine.proowner = role.oid
       OR has_function_privilege(current_user, routine.oid, 'EXECUTE'))
), rls_gate AS (
  SELECT count(*) = (SELECT count(*) FROM tenant_table)
     AND bool_and(relation.relrowsecurity AND relation.relforcerowsecurity)
     AND NOT EXISTS (
       SELECT 1 FROM tenant_table tenant
       JOIN pg_class tenant_relation
         ON tenant_relation.oid = to_regclass('public.' || tenant.name)
        WHERE (SELECT count(*) FROM pg_policy policy
                WHERE policy.polrelid = tenant_relation.oid
                  AND policy.polcmd = '*' AND policy.polroles = ARRAY[0::oid]
                  AND pg_get_expr(policy.polqual, policy.polrelid) LIKE '%app.tenant_id%'
                  AND pg_get_expr(policy.polwithcheck, policy.polrelid)
                        LIKE '%app.tenant_id%'
                  AND pg_get_expr(policy.polqual, policy.polrelid)
                        NOT LIKE '%elmpay.tenant_id%'
                  AND pg_get_expr(policy.polwithcheck, policy.polrelid)
                        NOT LIKE '%elmpay.tenant_id%') <> 1) AS valid
    FROM tenant_table tenant
    JOIN pg_class relation ON relation.oid = to_regclass('public.' || tenant.name)
) SELECT jsonb_build_object('ready',
    (SELECT valid FROM role_gate)
    AND (SELECT valid FROM table_gate)
    AND (SELECT valid FROM unexpected_relation_gate)
    AND (SELECT valid FROM sequence_gate)
    AND (SELECT valid FROM routine_gate)
    AND (SELECT valid FROM rls_gate)) FROM input;`, {});
    if (result?.ready !== true) {
      throw new DatabaseUnavailableError("admin database runtime contract is not exact");
    }
    return true;
  }

  async ping() {
    return this.verifyRuntimeContract();
  }

  async issueNonce({ nonceDigest, expiresAt }) {
    const result = await this.runner.execute(`BEGIN;
SET LOCAL search_path = pg_catalog, public;
${inputCte()}, cleaned AS (
      DELETE FROM admin_dpop_nonce WHERE expires_at < clock_timestamp() - interval '5 minutes'
    ), inserted AS (
      INSERT INTO admin_dpop_nonce (nonce_digest, issued_at, expires_at)
      SELECT j->>'nonceDigest', clock_timestamp(), (j->>'expiresAt')::timestamptz FROM input
      ON CONFLICT DO NOTHING RETURNING nonce_digest
    ) SELECT jsonb_build_object('issued', EXISTS(SELECT 1 FROM inserted)) FROM input;
COMMIT;`, { nonceDigest, expiresAt });
    return result?.issued === true;
  }

  async consumeProof(proof) {
    const result = await this.runner.execute(`BEGIN;
${tenantSetting()}
${inputCte()}, consumed AS (
  UPDATE admin_dpop_nonce n SET consumed_at = clock_timestamp()
  FROM input WHERE n.nonce_digest = input.j->>'nonceDigest' AND n.consumed_at IS NULL
    AND n.expires_at > clock_timestamp() RETURNING n.nonce_digest
), expired_replay AS (
  DELETE FROM admin_dpop_replay r USING input
  WHERE r.tenant_id = (input.j->>'tenantId')::uuid
    AND r.expires_at < clock_timestamp() - interval '5 minutes'
), inserted AS (
  INSERT INTO admin_dpop_replay
    (tenant_id, issuer, subject_digest, access_jti_digest, proof_jti_digest, nonce_digest,
     proof_thumbprint, seen_at, expires_at)
  SELECT (j->>'tenantId')::uuid, j->>'issuer', j->>'subjectDigest', j->>'accessJtiDigest',
    j->>'proofJtiDigest', j->>'nonceDigest', j->>'proofThumbprint', clock_timestamp(),
    (j->>'proofExpiresAt')::timestamptz FROM input, consumed
  ON CONFLICT DO NOTHING RETURNING proof_jti_digest
) SELECT jsonb_build_object('accepted', EXISTS(SELECT 1 FROM inserted)) FROM input;
COMMIT;`, proof);
    return result?.accepted === true;
  }

  async createApproval(command) {
    const audit = initialAuditEvent(command);
    const input = { ...command, audit };
    const result = await this.runner.execute(`BEGIN;
${tenantSetting()}
${inputCte()}, inserted AS (
  INSERT INTO admin_approval
    (approval_id, tenant_id, project_id, kind, operation_code, target_id,
     proposal_digest, permission, resource_type,
     proposer_id, reason_code, ticket_digest, request_key_digest, policy_digest, status,
     version, created_at, expires_at)
  SELECT (j->>'id')::uuid, (j->>'tenantId')::uuid, (j->>'projectId')::uuid,
    j->>'kind', j->>'operationCode', j->>'targetId',
    j->>'proposalDigest', j->>'permission', j->>'resource', j->>'proposer', j->>'reasonCode',
    j->>'ticketDigest', j->>'requestKeyDigest', j->>'policyDigest', 'PENDING', 1,
    (j->>'createdAt')::timestamptz, (j->>'expiresAt')::timestamptz FROM input
  ON CONFLICT (tenant_id, request_key_digest) DO NOTHING RETURNING *
), audited AS (
  INSERT INTO admin_approval_audit
    (tenant_id, approval_id, event_type, actor_id, reason_code, ticket_digest,
     previous_digest, event_digest, occurred_at)
  SELECT tenant_id, approval_id, input.j->'audit'->>'event', input.j->'audit'->>'actor',
    input.j->>'reasonCode', input.j->>'ticketDigest', input.j->'audit'->>'previousDigest',
    input.j->'audit'->>'digest', (input.j->'audit'->>'occurredAt')::timestamptz
  FROM inserted, input RETURNING approval_id
), selected AS (
  SELECT * FROM inserted UNION ALL SELECT a.* FROM admin_approval a, input
    WHERE a.tenant_id = (input.j->>'tenantId')::uuid
      AND a.request_key_digest = input.j->>'requestKeyDigest' LIMIT 1
) SELECT jsonb_build_object('approval', ${approvalJson("selected")},
    'created', EXISTS(SELECT 1 FROM inserted),
    'sameRequest', selected.proposal_digest = input.j->>'proposalDigest'
      AND selected.project_id = (input.j->>'projectId')::uuid
      AND selected.kind = input.j->>'kind'
      AND selected.operation_code = input.j->>'operationCode'
      AND selected.target_id = input.j->>'targetId'
      AND selected.permission = input.j->>'permission' AND selected.resource_type = input.j->>'resource'
      AND selected.proposer_id = input.j->>'proposer' AND selected.reason_code = input.j->>'reasonCode'
      AND selected.ticket_digest = input.j->>'ticketDigest' AND selected.policy_digest = input.j->>'policyDigest'
      AND selected.expires_at = (input.j->>'expiresAt')::timestamptz)
  FROM selected, input;
COMMIT;`, input);
    if (result?.sameRequest !== true) throw new Error("idempotency key was already used for another proposal");
    const approval = normalizeApproval(result.approval);
    return result.created === true && approval.lastAuditDigest === null
      ? Object.freeze({ ...approval, lastAuditDigest: audit.digest }) : approval;
  }

  async getApproval(tenantId, approvalId) {
    const result = await this.runner.execute(`BEGIN;
${tenantSetting()}
${inputCte()} SELECT COALESCE((SELECT ${approvalJson("a")} FROM admin_approval a, input
  WHERE a.tenant_id = (input.j->>'tenantId')::uuid AND a.approval_id = (input.j->>'approvalId')::uuid), 'null'::jsonb);
COMMIT;`, { tenantId, approvalId });
    return normalizeApproval(result);
  }

  async decideApproval(command) {
    const result = await this.runner.execute(`BEGIN;
${tenantSetting()}
${inputCte()}, locked AS (
  SELECT a.* FROM admin_approval a, input WHERE a.tenant_id = (input.j->>'tenantId')::uuid
    AND a.approval_id = (input.j->>'id')::uuid FOR UPDATE
), updated AS (
  UPDATE admin_approval a SET status = input.j->>'status', version = a.version + 1,
    decided_at = (input.j->>'decidedAt')::timestamptz, decided_by = input.j->>'decidedBy',
    decision_reason_code = input.j->>'reasonCode', decision_ticket_digest = input.j->>'ticketDigest'
  FROM input, locked WHERE a.tenant_id = locked.tenant_id AND a.approval_id = locked.approval_id
    AND locked.status = 'PENDING' AND locked.expires_at > clock_timestamp()
    AND locked.version = (input.j->>'expectedVersion')::bigint
    AND locked.project_id = (input.j->>'projectId')::uuid
    AND locked.operation_code = input.j->>'operationCode'
    AND locked.proposal_digest = input.j->>'proposalDigest'
    AND locked.proposer_id <> input.j->>'decidedBy'
    AND (SELECT event_digest FROM admin_approval_audit aa WHERE aa.tenant_id = locked.tenant_id
      AND aa.approval_id = locked.approval_id ORDER BY sequence_no DESC LIMIT 1) = input.j->>'previousAuditDigest'
  RETURNING a.*
), audited AS (
  INSERT INTO admin_approval_audit
    (tenant_id, approval_id, event_type, actor_id, reason_code, ticket_digest,
     previous_digest, event_digest, occurred_at)
  SELECT tenant_id, approval_id, input.j->>'status', input.j->>'decidedBy', input.j->>'reasonCode',
    input.j->>'ticketDigest', input.j->>'previousAuditDigest', input.j->>'auditDigest',
    (input.j->>'decidedAt')::timestamptz FROM updated, input RETURNING approval_id
), dispatched AS (
  INSERT INTO admin_action_dispatch
    (dispatch_id, tenant_id, project_id, approval_id, kind, operation_code,
     target_id, proposal_digest, policy_digest,
     approval_version, proposer_digest, approver_digest, idempotency_key, state, attempts,
     next_attempt_at, fencing_token, approval_expires_at, created_at, updated_at)
  SELECT (d->>'dispatchId')::uuid, (d->>'tenantId')::uuid, (d->>'projectId')::uuid,
    (d->>'approvalId')::uuid, d->>'kind', d->>'operationCode', d->>'targetId',
    d->>'proposalDigest', d->>'policyDigest',
    (d->>'approvalVersion')::bigint, d->>'proposerDigest', d->>'approverDigest',
    d->>'idempotencyKey', 'PENDING', 0, clock_timestamp(), 0,
    (d->>'approvalExpiresAt')::timestamptz, (d->>'createdAt')::timestamptz, clock_timestamp()
  FROM updated, input, LATERAL (SELECT input.j->'dispatch' AS d) dispatch_input
  WHERE input.j->>'status' = 'APPROVED' AND jsonb_typeof(dispatch_input.d) = 'object'
  RETURNING tenant_id
), signaled AS (
  INSERT INTO admin_dispatch_signal (tenant_id, next_attempt_at)
  SELECT tenant_id, clock_timestamp() FROM dispatched
  ON CONFLICT (tenant_id) DO UPDATE
    SET next_attempt_at = LEAST(admin_dispatch_signal.next_attempt_at, EXCLUDED.next_attempt_at)
  RETURNING tenant_id
) SELECT jsonb_build_object(
    'approval', COALESCE((SELECT ${approvalJson("updated")} FROM updated), 'null'::jsonb),
    'dispatchQueued', EXISTS(SELECT 1 FROM dispatched)) FROM input;
COMMIT;`, command);
    if (result?.approval === null) throw new Error("approval decision lost an optimistic-concurrency race or expired");
    if (command.status === "APPROVED" && result.dispatchQueued !== true) {
      throw new Error("approved action dispatch was not durably queued");
    }
    return Object.freeze({ ...normalizeApproval(result.approval), lastAuditDigest: command.auditDigest });
  }

  async claimDispatch(workerId, leaseSeconds = 15) {
    if (!/^[A-Za-z0-9._:-]{8,128}$/.test(workerId) || !Number.isInteger(leaseSeconds)
        || leaseSeconds < 5 || leaseSeconds > 60) throw new TypeError("dispatch lease configuration is invalid");
    return this.runner.execute(`BEGIN;
SET LOCAL search_path = pg_catalog, public;
${inputCte()}, signal_candidate AS (
  SELECT tenant_id FROM admin_dispatch_signal, input
  WHERE next_attempt_at <= clock_timestamp()
    AND (lease_until IS NULL OR lease_until <= clock_timestamp())
  ORDER BY next_attempt_at, tenant_id FOR UPDATE SKIP LOCKED LIMIT 1
), signal_claimed AS (
  UPDATE admin_dispatch_signal s SET lease_owner = input.j->>'workerId',
    lease_until = clock_timestamp() + make_interval(secs => (input.j->>'leaseSeconds')::integer),
    fencing_token = s.fencing_token + 1
  FROM signal_candidate, input WHERE s.tenant_id = signal_candidate.tenant_id
  RETURNING s.tenant_id, s.lease_until, s.fencing_token
), tenant_context AS (
  SELECT set_config('app.tenant_id', (SELECT tenant_id::text FROM signal_claimed), true)
), expired AS (
  UPDATE admin_action_dispatch d SET state = 'FAILED', failure_code = 'APPROVAL_EXPIRED',
    next_attempt_at = NULL, lease_owner = NULL, lease_until = NULL, updated_at = clock_timestamp()
  FROM signal_claimed, tenant_context WHERE d.tenant_id = signal_claimed.tenant_id
    AND d.state IN ('PENDING','RETRY','UNKNOWN','DISPATCHING')
    AND d.approval_expires_at <= clock_timestamp() RETURNING d.dispatch_id
), exhausted AS (
  UPDATE admin_action_dispatch d SET state = 'FAILED', failure_code = 'MAX_ATTEMPTS',
    next_attempt_at = NULL, lease_owner = NULL, lease_until = NULL, updated_at = clock_timestamp()
  FROM signal_claimed, tenant_context WHERE d.tenant_id = signal_claimed.tenant_id
    AND d.state IN ('PENDING','RETRY') AND NOT d.outcome_unknown
    AND d.attempts >= 8
    AND d.approval_expires_at > clock_timestamp() RETURNING d.dispatch_id
), invalidated AS (
  UPDATE admin_action_dispatch d SET state = 'BLOCKED', failure_code = 'APPROVAL_MISMATCH',
    next_attempt_at = NULL, lease_owner = NULL, lease_until = NULL, updated_at = clock_timestamp()
  FROM admin_approval a, signal_claimed, tenant_context
  WHERE d.tenant_id = signal_claimed.tenant_id AND a.tenant_id = d.tenant_id
    AND a.approval_id = d.approval_id AND d.state IN ('PENDING','RETRY','UNKNOWN','DISPATCHING')
    AND d.approval_expires_at > clock_timestamp()
    AND NOT (a.status = 'APPROVED' AND a.version = d.approval_version
      AND a.project_id = d.project_id AND a.kind = d.kind
      AND a.operation_code = d.operation_code AND a.target_id = d.target_id
      AND a.proposal_digest = d.proposal_digest
      AND a.policy_digest = d.policy_digest AND a.expires_at = d.approval_expires_at)
  RETURNING d.dispatch_id
), dispatch_candidate AS (
  SELECT d.*, d.state AS previous_state
  FROM admin_action_dispatch d, admin_approval a, signal_claimed, tenant_context, input
  WHERE d.tenant_id = signal_claimed.tenant_id AND a.tenant_id = d.tenant_id
    AND a.approval_id = d.approval_id AND a.status = 'APPROVED'
    AND a.version = d.approval_version AND a.project_id = d.project_id
    AND a.kind = d.kind AND a.operation_code = d.operation_code
    AND a.target_id = d.target_id
    AND a.proposal_digest = d.proposal_digest AND a.policy_digest = d.policy_digest
    AND a.expires_at = d.approval_expires_at AND d.approval_expires_at > clock_timestamp()
    AND ((d.state IN ('PENDING','RETRY') AND d.attempts < 8
          AND d.next_attempt_at <= clock_timestamp())
      OR (d.state = 'UNKNOWN' AND d.next_attempt_at <= clock_timestamp())
      OR (d.state = 'DISPATCHING' AND d.lease_until <= clock_timestamp()
          AND (d.outcome_unknown OR d.attempts < 8)))
  ORDER BY d.next_attempt_at NULLS FIRST, d.created_at FOR UPDATE SKIP LOCKED LIMIT 1
), dispatch_claimed AS (
  UPDATE admin_action_dispatch d SET state = 'DISPATCHING',
    attempts = d.attempts + CASE WHEN d.outcome_unknown
      OR dispatch_candidate.previous_state = 'DISPATCHING' THEN 0 ELSE 1 END,
    receipt_poll_attempts = d.receipt_poll_attempts
      + CASE WHEN d.outcome_unknown
        OR dispatch_candidate.previous_state = 'DISPATCHING' THEN 1 ELSE 0 END,
    outcome_unknown = d.outcome_unknown
      OR dispatch_candidate.previous_state = 'DISPATCHING',
    lease_owner = input.j->>'workerId', lease_until = signal_claimed.lease_until,
    fencing_token = d.fencing_token + 1, failure_code = NULL, next_attempt_at = NULL,
    updated_at = clock_timestamp()
  FROM dispatch_candidate, signal_claimed, input
  WHERE d.tenant_id = dispatch_candidate.tenant_id AND d.dispatch_id = dispatch_candidate.dispatch_id
  RETURNING d.*, dispatch_candidate.previous_state
), remaining_due AS (
  SELECT min(CASE WHEN d.state = 'DISPATCHING' THEN d.lease_until ELSE d.next_attempt_at END) AS next_attempt_at
  FROM admin_action_dispatch d, signal_claimed, tenant_context
  WHERE d.tenant_id = signal_claimed.tenant_id
    AND d.state IN ('PENDING','RETRY','UNKNOWN','DISPATCHING')
    AND NOT EXISTS (SELECT 1 FROM expired WHERE expired.dispatch_id = d.dispatch_id)
    AND NOT EXISTS (SELECT 1 FROM exhausted WHERE exhausted.dispatch_id = d.dispatch_id)
    AND NOT EXISTS (SELECT 1 FROM invalidated WHERE invalidated.dispatch_id = d.dispatch_id)
    AND NOT EXISTS (SELECT 1 FROM dispatch_claimed WHERE dispatch_claimed.dispatch_id = d.dispatch_id)
), signal_released AS (
  UPDATE admin_dispatch_signal s SET lease_owner = NULL, lease_until = NULL,
    next_attempt_at = remaining_due.next_attempt_at
  FROM signal_claimed, remaining_due WHERE s.tenant_id = signal_claimed.tenant_id
    AND NOT EXISTS (SELECT 1 FROM dispatch_claimed) AND remaining_due.next_attempt_at IS NOT NULL
  RETURNING s.tenant_id
), signal_deleted AS (
  DELETE FROM admin_dispatch_signal s USING signal_claimed, remaining_due
  WHERE s.tenant_id = signal_claimed.tenant_id AND NOT EXISTS (SELECT 1 FROM dispatch_claimed)
    AND remaining_due.next_attempt_at IS NULL RETURNING s.tenant_id
) SELECT COALESCE((SELECT jsonb_build_object(
  'dispatchId', dispatch_id::text, 'tenantId', tenant_id::text,
  'projectId', project_id::text, 'approvalId', approval_id::text,
  'kind', kind, 'operationCode', operation_code, 'targetId', target_id,
  'proposalDigest', proposal_digest,
  'policyDigest', policy_digest, 'approvalVersion', approval_version,
  'proposerDigest', proposer_digest, 'approverDigest', approver_digest,
  'idempotencyKey', idempotency_key, 'previousState', previous_state, 'attempt', attempts,
  'outcomeUnknown', outcome_unknown, 'pollAttempt', receipt_poll_attempts,
  'workerId', lease_owner, 'fencingToken', fencing_token,
  'leaseUntil', to_char(lease_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  'approvalExpiresAt', to_char(approval_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
) FROM dispatch_claimed), 'null'::jsonb) FROM input;
COMMIT;`, { workerId, leaseSeconds });
  }

  async completeDispatch(claim, receipt) {
    const result = await this.runner.execute(`BEGIN;
${tenantSetting()}
${inputCte()}, updated AS (
  UPDATE admin_action_dispatch d SET state = 'SUCCEEDED', receipt_digest = input.j->>'receiptDigest',
    receipt_id_digest = input.j->>'receiptIdDigest', failure_code = NULL, next_attempt_at = NULL,
    lease_owner = NULL, lease_until = NULL, updated_at = clock_timestamp()
  FROM input WHERE d.tenant_id = (input.j->>'tenantId')::uuid
    AND d.dispatch_id = (input.j->>'dispatchId')::uuid AND d.state = 'DISPATCHING'
    AND d.lease_owner = input.j->>'workerId' AND d.fencing_token = (input.j->>'fencingToken')::bigint
  RETURNING d.tenant_id, d.dispatch_id
), other_due AS (
  SELECT min(CASE WHEN d.state = 'DISPATCHING' THEN d.lease_until ELSE d.next_attempt_at END) AS next_attempt_at
  FROM admin_action_dispatch d, input, updated
  WHERE d.tenant_id = updated.tenant_id AND d.dispatch_id <> updated.dispatch_id
    AND d.state IN ('PENDING','RETRY','UNKNOWN','DISPATCHING')
), signal_updated AS (
  UPDATE admin_dispatch_signal s SET next_attempt_at = other_due.next_attempt_at,
    lease_owner = NULL, lease_until = NULL FROM updated, other_due
  WHERE s.tenant_id = updated.tenant_id AND other_due.next_attempt_at IS NOT NULL RETURNING s.tenant_id
), signal_deleted AS (
  DELETE FROM admin_dispatch_signal s USING updated, other_due
  WHERE s.tenant_id = updated.tenant_id AND other_due.next_attempt_at IS NULL RETURNING s.tenant_id
) SELECT jsonb_build_object('updated', EXISTS(SELECT 1 FROM updated)) FROM input;
COMMIT;`, { ...claim, receiptDigest: receipt.receiptDigest,
      receiptIdDigest: sha256Hex(receipt.receiptId) });
    return result?.updated === true;
  }

  async rescheduleDispatch(claim, { state, failureCode, nextAttemptAt = null }) {
    if (!new Set(["RETRY", "UNKNOWN", "BLOCKED", "FAILED"]).has(state)) {
      throw new TypeError("dispatch reschedule state is invalid");
    }
    const result = await this.runner.execute(`BEGIN;
${tenantSetting()}
${inputCte()}, updated AS (
  UPDATE admin_action_dispatch d SET state = input.j->>'state', failure_code = input.j->>'failureCode',
    outcome_unknown = d.outcome_unknown OR input.j->>'state' = 'UNKNOWN',
    next_attempt_at = CASE WHEN input.j->>'nextAttemptAt' IS NULL THEN NULL
      ELSE (input.j->>'nextAttemptAt')::timestamptz END,
    lease_owner = NULL, lease_until = NULL, updated_at = clock_timestamp()
  FROM input WHERE d.tenant_id = (input.j->>'tenantId')::uuid
    AND d.dispatch_id = (input.j->>'dispatchId')::uuid AND d.state = 'DISPATCHING'
    AND d.lease_owner = input.j->>'workerId' AND d.fencing_token = (input.j->>'fencingToken')::bigint
  RETURNING d.tenant_id, d.dispatch_id, d.state, d.next_attempt_at
), due AS (
  SELECT min(candidate.next_attempt_at) AS next_attempt_at FROM (
    SELECT CASE WHEN d.state = 'DISPATCHING' THEN d.lease_until ELSE d.next_attempt_at END
      AS next_attempt_at FROM admin_action_dispatch d, input, updated
      WHERE d.tenant_id = updated.tenant_id AND d.dispatch_id <> updated.dispatch_id
        AND d.state IN ('PENDING','RETRY','UNKNOWN','DISPATCHING')
    UNION ALL
    SELECT next_attempt_at FROM updated WHERE state IN ('RETRY','UNKNOWN')
  ) candidate
), signal_upserted AS (
  INSERT INTO admin_dispatch_signal (tenant_id, next_attempt_at)
  SELECT updated.tenant_id, due.next_attempt_at FROM updated, due WHERE due.next_attempt_at IS NOT NULL
  ON CONFLICT (tenant_id) DO UPDATE SET next_attempt_at = EXCLUDED.next_attempt_at,
    lease_owner = NULL, lease_until = NULL RETURNING tenant_id
), signal_deleted AS (
  DELETE FROM admin_dispatch_signal s USING updated, due
  WHERE s.tenant_id = updated.tenant_id AND due.next_attempt_at IS NULL RETURNING s.tenant_id
) SELECT jsonb_build_object('updated', EXISTS(SELECT 1 FROM updated)) FROM input;
COMMIT;`, { ...claim, state, failureCode, nextAttemptAt });
    return result?.updated === true;
  }

  async recordAccess({ tenantId, actorId, eventType, resourceId, decision, policyDigest, occurredAt }) {
    const eventId = randomUUID();
    const eventDigest = sha256Hex(canonicalJson({ eventId, tenantId, actorDigest: sha256Hex(actorId), eventType,
      resourceDigest: sha256Hex(resourceId), decision, policyDigest, occurredAt }));
    const result = await this.runner.execute(`BEGIN;
${tenantSetting()}
${inputCte()}, inserted AS (
  INSERT INTO admin_access_audit
    (event_id, tenant_id, actor_digest, event_type, resource_digest, decision, policy_digest, event_digest, occurred_at)
  SELECT (j->>'eventId')::uuid, (j->>'tenantId')::uuid, j->>'actorDigest', j->>'eventType', j->>'resourceDigest',
    j->>'decision', j->>'policyDigest', j->>'eventDigest', (j->>'occurredAt')::timestamptz
  FROM input RETURNING event_digest
) SELECT jsonb_build_object('recorded', EXISTS(SELECT 1 FROM inserted)) FROM input;
COMMIT;`, { eventId, tenantId, actorDigest: sha256Hex(actorId), eventType, resourceDigest: sha256Hex(resourceId),
      decision, policyDigest, eventDigest, occurredAt });
    if (result?.recorded !== true) throw new DatabaseUnavailableError("admin access decision was not audited");
  }

  async putDiagnostic(view, now = new Date()) {
    const result = await this.runner.execute(`BEGIN;
${tenantSetting()}
${inputCte()}, upserted AS (
  INSERT INTO admin_diagnostic_snapshot (tenant_id, service_name, safe_projection, captured_at)
  SELECT (j->>'tenantId')::uuid, j->>'service', j->'view', (j->>'capturedAt')::timestamptz FROM input
  ON CONFLICT (tenant_id, service_name) DO UPDATE SET safe_projection = EXCLUDED.safe_projection,
    captured_at = EXCLUDED.captured_at RETURNING service_name
) SELECT jsonb_build_object('stored', EXISTS(SELECT 1 FROM upserted)) FROM input;
COMMIT;`, { tenantId: view.tenantId, service: view.service, view, capturedAt: now.toISOString() });
    return result?.stored === true;
  }

  async getDiagnostic(tenantId, service) {
    return this.runner.execute(`BEGIN;
${tenantSetting()}
${inputCte()} SELECT COALESCE((SELECT jsonb_build_object('view', safe_projection,
  'capturedAt', to_char(captured_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
  FROM admin_diagnostic_snapshot, input WHERE tenant_id = (input.j->>'tenantId')::uuid
    AND service_name = input.j->>'service'), 'null'::jsonb);
COMMIT;`, { tenantId, service });
  }
}
