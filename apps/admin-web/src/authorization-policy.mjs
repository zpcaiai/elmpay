import { readFileSync, statSync } from "node:fs";
import { assertVerifiedOperator } from "./operator-auth.mjs";
import { canonicalJson, sha256Hex } from "./canonical-json.mjs";

const ACTION_KINDS = new Set(["CASE_CLOSE", "LIST_CHANGE", "REFUND_OVERRIDE", "ROLLOUT_APPROVAL"]);

function requireControlledFile(path, label) {
  const stat = statSync(path, { throwIfNoEntry: true });
  if (!stat.isFile() || (stat.mode & 0o222) !== 0) throw new Error(`${label} must be a read-only regular file`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function requireUniqueText(values, label) {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => typeof value !== "string" || value.length === 0)) {
    throw new Error(`${label} must be a non-empty string array`);
  }
  if (new Set(values).size !== values.length) throw new Error(`${label} must be unique`);
  return values;
}

export class AuthorizationPolicy {
  static load({ authorizationPath, actionPolicyPath }) {
    const authorization = requireControlledFile(authorizationPath, "authorization SSOT");
    const actionPolicy = requireControlledFile(actionPolicyPath, "admin action policy");
    return new AuthorizationPolicy({ authorization, actionPolicy,
      policyDigest: sha256Hex(canonicalJson({ authorization, actionPolicy })) });
  }

  constructor({ authorization, actionPolicy, policyDigest = "test-policy" }) {
    if (authorization?.default_decision !== "deny" || !Array.isArray(authorization.roles)
        || !Array.isArray(authorization.permissions) || !Array.isArray(authorization.separation_of_duties)
        || authorization.dual_control?.approver_must_differ_from_requester !== true
        || authorization.dual_control?.approval_bound_to_request_digest !== true
        || !Number.isInteger(authorization.dual_control?.approval_ttl_seconds)
        || authorization.dual_control.approval_ttl_seconds < 1
        || authorization.dual_control.approval_ttl_seconds > 900) {
      throw new Error("authorization SSOT is not fail-closed");
    }
    const permissionIds = authorization.permissions.map((permission) => permission?.id);
    const roleIds = authorization.roles.map((role) => role?.id);
    requireUniqueText(permissionIds, "authorization permission ids");
    requireUniqueText(roleIds, "authorization role ids");
    if (actionPolicy?.schemaVersion !== 1 || actionPolicy.actions === null
        || typeof actionPolicy.actions !== "object" || Array.isArray(actionPolicy.actions)
        || Object.keys(actionPolicy.actions).length !== ACTION_KINDS.size
        || Object.keys(actionPolicy.actions).some((kind) => !ACTION_KINDS.has(kind))) {
      throw new Error("admin action policy is invalid");
    }
    this.policyDigest = policyDigest;
    this.approvalTtlSeconds = authorization.dual_control.approval_ttl_seconds;
    this.roles = new Map();
    this.permissions = new Map(authorization.permissions.map((permission) => [permission.id, permission]));
    this.sod = authorization.separation_of_duties.map((rule) => {
      if (!this.permissions.has(rule?.left) || !this.permissions.has(rule?.right) || rule.left === rule.right) {
        throw new Error("separation-of-duties rule references an invalid permission pair");
      }
      return [rule.left, rule.right];
    });
    const elevatable = authorization.elevation?.elevatable_permissions ?? [];
    if (elevatable.length > 0) requireUniqueText(elevatable, "elevatable permissions");
    if (elevatable.some((permission) => !this.permissions.has(permission))) {
      throw new Error("elevation references an unknown permission");
    }
    this.elevatable = new Set(elevatable);
    for (const role of authorization.roles) {
      if (role.kind !== "human") continue;
      const permissions = requireUniqueText(role.permissions, `permissions for ${role.id}`);
      if (permissions.some((permission) => !this.permissions.has(permission))) throw new Error(`role ${role.id} has an unknown permission`);
      this.roles.set(role.id, Object.freeze({ id: role.id, scope: role.scope,
        privileged: role.privileged === true, permissions: Object.freeze([...permissions]) }));
    }
    this.actions = new Map();
    for (const [kind, action] of Object.entries(actionPolicy.actions)) {
      if (action === null || typeof action !== "object" || Array.isArray(action)
          || Object.keys(action).length !== 5
          || !["permission", "resource", "dualControl", "stepUp", "elevationRequired"]
            .every((key) => Object.hasOwn(action, key))
          || !this.permissions.has(action.permission) || action.resource !== this.permissions.get(action.permission).resource
          || action.dualControl !== true || action.stepUp !== true
          || action.elevationRequired !== this.permissions.get(action.permission).elevation_required) {
        throw new Error(`admin action ${kind} contradicts the authorization SSOT`);
      }
      this.actions.set(kind, Object.freeze({ kind, ...action }));
    }
  }

  permissionsFor(operator) {
    assertVerifiedOperator(operator);
    const roles = operator.roles.map((roleId) => {
      const role = this.roles.get(roleId);
      if (role === undefined || role.privileged !== true) throw new Error("operator role is not an allowed privileged role");
      return role;
    });
    const permissions = new Set(roles.flatMap((role) => role.permissions));
    for (const [left, right] of this.sod) {
      if (permissions.has(left) && permissions.has(right)) throw new Error("operator roles violate separation of duties");
    }
    return permissions;
  }

  authorizeDiagnostic(operator, tenantId) {
    const permissions = this.permissionsFor(operator);
    if (operator.tenantId !== tenantId) throw new Error("cross-tenant diagnostic access is forbidden");
    if (!permissions.has("payment.read") && !permissions.has("audit_log.read")) {
      throw new Error("diagnostic read is not authorized");
    }
    return Object.freeze({ permission: permissions.has("payment.read") ? "payment.read" : "audit_log.read",
      policyDigest: this.policyDigest });
  }

  authorizeAction(operator, tenantId, kind, { requireStepUp }) {
    if (operator.tenantId !== tenantId) throw new Error("cross-tenant admin action is forbidden");
    const action = this.actions.get(kind);
    if (action === undefined) throw new Error("unsupported admin action");
    const permissions = this.permissionsFor(operator);
    const elevated = operator.elevation?.permission === action.permission;
    if (!permissions.has(action.permission) && !(action.elevationRequired && elevated && this.elevatable.has(action.permission))) {
      throw new Error("admin action permission is not granted");
    }
    if (action.elevationRequired && !elevated) throw new Error("admin action requires a bounded elevation");
    if (action.stepUp && !requireStepUp(operator)) throw new Error("recent phishing-resistant step-up is required");
    return Object.freeze({ ...action, policyDigest: this.policyDigest,
      approvalTtlSeconds: this.approvalTtlSeconds });
  }
}
