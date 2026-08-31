"""B16 — zero-trust access architecture.

The claim is that every access is decided on identity, device, context, least
privilege and an audit record — this run, not once at the perimeter. Each rule
here defends one of the ways that collapses back into perimeter security:

* ``ZT_NETWORK_TRUST`` — the moment any list says "requests from this network are
  trusted", the architecture is a firewall with extra JSON. The list must be
  empty, and it is checked for emptiness rather than for good intentions;
* ``ZT_AUDIT_ALLOW_ONLY`` — recording only denials is the most common way an
  audit trail becomes useless: in an investigation you need to know what the
  attacker was *allowed* to do (CTRL-007);
* ``ZT_STATIC_CREDENTIAL`` — a long-lived service account password has no expiry,
  so a leak from three years ago is still a leak today (NN-07);
* ``ZT_FOUR_EYES`` — money-moving and control-changing operations need a second
  person, and "changing the risk rules" is a money-moving operation wearing
  configuration clothes (NN-11);
* ``ZT_TENANT_BINDING`` — if the tenant comes from the request body rather than
  from the credential, cross-tenant access is one edited field away (NN-09).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

POLICY = Path("governance/zero-trust.json")
THREAT = Path("governance/threat-model.json")
TOPOLOGY = Path("governance/service-topology.json")
DATA = Path("governance/data-architecture.json")

PRINCIPAL_ID = re.compile(r"^[a-z][a-z0-9-]*$")
DECISION_ID = re.compile(r"^ZTD-\d{2}$")
AUDIT_EVENT = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")

# Actions that move money or change how money is decided. Both need a second
# person: a risk rule change is a money operation wearing configuration clothes.
HIGH_RISK = {("refund", "approve"), ("risk_rule", "write"),
             ("cross_tenant_data", "read"), ("ledger_entry", "write")}
MAX_HUMAN_SESSION_MINUTES = 120
# Zones we operate ourselves. Mutual TLS is required between any two of them —
# including the edge, which is ours even though the traffic arriving at it is
# not. External parties (a browser, a payment provider, the legacy project, a
# monitoring vendor) cannot present our certificates, so those crossings are
# authenticated some other way and the rule does not apply.
PLATFORM_OPERATED_TRUST = {"trusted", "trusted-egress", "trusted-data", "high-privilege",
                           "crypto", "build", "infrastructure", "untrusted-ingress"}
MAX_WORKLOAD_CERT_MINUTES = 1440


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("zero-trust", "B16")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    where = str(POLICY)
    budget.check(where)
    try:
        policy = load_json(root / POLICY)
    except Exception as exc:
        return [Problem("ZT_UNREADABLE", where,
                        f"cannot read the zero-trust policy: {exc}", "NN-12")]

    problems += expect(SEMVER.match(str(policy.get("schema_version", ""))), "ZT_VERSION_FIELD",
                       where, "schema_version must be semver", "NN-12")
    problems += expect(len(str(policy.get("principle") or "")) >= 20, "ZT_PRINCIPLE", where,
                       "the principle must be stated; 'zero trust' as a slogan means nothing",
                       "NN-12")
    problems += expect(policy.get("deny_by_default") is True, "ZT_DENY_BY_DEFAULT", where,
                       "the model must deny by default; an allow-by-default policy with "
                       "exceptions is a perimeter", "NN-12")

    grants = policy.get("network_location_grants")
    problems += expect(isinstance(grants, list) and not grants, "ZT_NETWORK_TRUST", where,
                       f"network location must grant nothing, got {grants!r}; the moment a "
                       f"network is 'trusted', this is a firewall with extra JSON", "NN-12")

    factors = set(policy.get("required_factors") or [])
    for needed in ("authenticated_identity", "authorisation_policy", "audit_record",
                   "device_posture", "workload_attestation", "phishing_resistant_mfa",
                   "token_audience", "token_holder_binding", "tenant_binding"):
        problems += expect(needed in factors, "ZT_FACTORS", where,
                           f"'{needed}' must be an available access factor", "NN-12")

    problems += _session(policy, where)
    problems += _workload_identity(policy, where)
    problems += _audit(policy, where)

    principal_ids, problems_ = _principals(policy, where, budget)
    problems += problems_
    used, problems_ = _decisions(policy, where, principal_ids, factors, budget)
    problems += problems_

    for pid in sorted(principal_ids):
        problems += expect(pid in used, "ZT_PRINCIPAL_UNUSED", where,
                           f"principal '{pid}' can access nothing; an identity with no decision "
                           f"is either dead weight or an ungoverned back door", "NN-12")

    problems += _zones(policy, root, where, budget)
    problems += _break_glass(policy, root, where)
    problems += _generated(root, budget)
    return problems


def _session(policy: dict, where: str) -> list[Problem]:
    session = policy.get("session") or {}
    problems = list(expect(0 < int(session.get("max_human_session_minutes") or 0)
                           <= MAX_HUMAN_SESSION_MINUTES, "ZT_SESSION", where,
                           f"human sessions must expire within {MAX_HUMAN_SESSION_MINUTES} "
                           f"minutes; an eight-hour token is eight hours of attacker access "
                           f"before anyone notices", "NN-12"))
    problems += expect(0 < int(session.get("revocation_propagation_seconds") or 0) <= 300,
                       "ZT_REVOCATION", where,
                       "revocation must take effect everywhere within minutes; a revocation that "
                       "waits for a token to expire is not a revocation", "NN-12")
    problems += expect(len(str(session.get("policy") or "")) >= 10, "ZT_SESSION", where,
                       "state the session policy", "NN-12")
    return problems


def _workload_identity(policy: dict, where: str) -> list[Problem]:
    workload = policy.get("workload_identity") or {}
    problems = list(expect(workload.get("static_long_lived_credentials_allowed") is False,
                           "ZT_STATIC_CREDENTIAL", where,
                           "long-lived static service credentials must be forbidden; a leak from "
                           "three years ago is still a leak today", "NN-07"))
    problems += expect(workload.get("transport") == "mtls", "ZT_WORKLOAD_IDENTITY", where,
                       "workload identity must be carried by mutual TLS, not by a shared header",
                       "NN-07")
    problems += expect(0 < int(workload.get("max_certificate_minutes") or 0)
                       <= MAX_WORKLOAD_CERT_MINUTES, "ZT_WORKLOAD_IDENTITY", where,
                       f"workload certificates must live at most {MAX_WORKLOAD_CERT_MINUTES} "
                       f"minutes", "NN-07")
    return problems


def _audit(policy: dict, where: str) -> list[Problem]:
    audit = policy.get("audit") or {}
    problems = list(expect(audit.get("every_decision_recorded") is True, "ZT_AUDIT_ALLOW_ONLY",
                           where,
                           "every decision, including every allow, must be recorded; an audit "
                           "trail of denials only tells you nothing about what the attacker "
                           "actually did", "NN-12"))
    problems += expect(audit.get("immutable") is True, "ZT_AUDIT_MUTABLE", where,
                       "the audit trail must be append-only, otherwise the first thing an "
                       "attacker edits is the evidence", "NN-06")
    fields = set(audit.get("required_fields") or [])
    for needed in ("actor", "resource_class", "action", "decision", "reason", "policy_version",
                   "trace_id"):
        problems += expect(needed in fields, "ZT_AUDIT_FIELDS", where,
                           f"audit records must carry '{needed}'", "NN-12")
    return problems


def _principals(policy: dict, where: str, budget: Budget) -> tuple[set, list[Problem]]:
    principals = policy.get("principals")
    if not isinstance(principals, list) or not principals:
        return set(), [Problem("ZT_SHAPE", where, "'principals' must be a non-empty list",
                               "NN-12")]
    kinds = set(policy.get("principal_kinds") or [])
    session_limit = int((policy.get("session") or {}).get("max_human_session_minutes") or 0)
    problems: list[Problem] = []
    ids: set = set()
    for index, principal in enumerate(principals):
        scope = f"{where}#principal[{index}]"
        if not isinstance(principal, dict):
            problems.append(Problem("ZT_SHAPE", scope, "each principal must be an object",
                                    "NN-12"))
            continue
        budget.check(scope)
        pid = principal.get("id")
        scope = f"{where}#{pid}"
        problems += expect(isinstance(pid, str) and PRINCIPAL_ID.match(pid or ""),
                           "ZT_PRINCIPAL_ID", scope,
                           f"principal id '{pid}' must be kebab-case", "NN-12")
        problems += expect(pid not in ids, "ZT_PRINCIPAL_DUPLICATE", scope,
                           f"duplicate principal '{pid}'", "NN-12")
        ids.add(pid)
        problems += expect(principal.get("kind") in kinds, "ZT_PRINCIPAL_KIND", scope,
                           f"kind '{principal.get('kind')}' is not declared", "NN-12")
        problems += expect(bool(principal.get("identity_source")), "ZT_IDENTITY_SOURCE", scope,
                           "every principal must say where its identity comes from; an identity "
                           "with no source cannot be revoked", "NN-12")
        problems += expect(len(str(principal.get("notes") or "")) >= 12, "ZT_PRINCIPAL_NOTES",
                           scope, "say what this principal is and what limits it", "NN-12")

        lifetime = int(principal.get("credential_lifetime_minutes") or 0)
        problems += expect(lifetime > 0, "ZT_CREDENTIAL_LIFETIME", scope,
                           "every credential must expire; 'no expiry' is the default that leaks",
                           "NN-07")
        if principal.get("kind") == "human":
            problems += expect(lifetime <= session_limit, "ZT_CREDENTIAL_LIFETIME", scope,
                               f"a human credential living {lifetime} minutes outlasts the "
                               f"{session_limit}-minute session limit", "NN-12")
        if principal.get("kind") == "workload":
            problems += expect(principal.get("credential") == "mtls_certificate"
                               or "token" in str(principal.get("credential") or ""),
                               "ZT_WORKLOAD_CREDENTIAL", scope,
                               "a workload must authenticate with a short-lived certificate or "
                               "federated token, never with a stored password", "NN-07")
        if pid == "merchant-api-client":
            problems += expect(principal.get("identity_source") == "oidc_authorization_server",
                               "ZT_MERCHANT_CREDENTIAL", scope,
                               "merchant API identity must come from the OIDC authorization "
                               "server, not a static tenant secret", "NN-07")
            problems += expect(principal.get("credential") == "mtls_bound_access_token",
                               "ZT_MERCHANT_CREDENTIAL", scope,
                               "merchant API credentials must be mTLS-bound access tokens",
                               "NN-07")
            problems += expect(0 < lifetime <= 5, "ZT_MERCHANT_CREDENTIAL", scope,
                               "merchant access tokens must expire within five minutes", "NN-07")
    return ids, problems


def _decisions(policy: dict, where: str, principal_ids: set, factors: set,
               budget: Budget) -> tuple[set, list[Problem]]:
    decisions = policy.get("decisions")
    if not isinstance(decisions, list) or not decisions:
        return set(), [Problem("ZT_SHAPE", where, "'decisions' must be a non-empty list",
                               "NN-12")]
    problems: list[Problem] = []
    used: set = set()
    seen: set = set()
    covered_high_risk: set = set()
    for index, entry in enumerate(decisions):
        scope = f"{where}#decision[{index}]"
        if not isinstance(entry, dict):
            problems.append(Problem("ZT_SHAPE", scope, "each decision must be an object",
                                    "NN-12"))
            continue
        budget.check(scope)
        rid = entry.get("id")
        scope = f"{where}#{rid}"
        problems += expect(isinstance(rid, str) and DECISION_ID.match(rid or ""),
                           "ZT_DECISION_ID", scope,
                           f"decision id '{rid}' must look like ZTD-01", "NN-12")
        problems += expect(rid not in seen, "ZT_DECISION_DUPLICATE", scope,
                           f"duplicate decision '{rid}'", "NN-12")
        seen.add(rid)

        principal = entry.get("principal")
        problems += expect(principal in principal_ids, "ZT_DECISION_PRINCIPAL", scope,
                           f"'{principal}' is not a declared principal", "NN-12")
        used.add(principal)

        requirements = entry.get("requirements") or []
        problems += expect(requirements, "ZT_DECISION_REQUIREMENTS", scope,
                           "a decision with no requirements is an allow rule", "NN-12")
        for requirement in requirements:
            problems += expect(requirement in factors, "ZT_DECISION_REQUIREMENTS", scope,
                               f"'{requirement}' is not a declared access factor", "NN-12")
        for mandatory in ("authenticated_identity", "authorisation_policy", "audit_record"):
            problems += expect(mandatory in requirements, "ZT_DECISION_MINIMUM", scope,
                               f"every decision must require '{mandatory}'", "NN-12")

        problems += expect(AUDIT_EVENT.match(str(entry.get("audit_event") or "")),
                           "ZT_DECISION_AUDIT", scope,
                           "every decision must name the audit event it emits", "NN-12")
        problems += expect(len(str(entry.get("notes") or "")) >= 12, "ZT_DECISION_NOTES", scope,
                           "say why this access is allowed at all", "NN-12")

        pair = (entry.get("resource_class"), entry.get("action"))
        if pair in HIGH_RISK:
            covered_high_risk.add(pair)
            problems += expect(entry.get("four_eyes") is True, "ZT_FOUR_EYES", scope,
                               f"{pair[0]}:{pair[1]} moves money or decides how money moves; it "
                               f"needs a second person (NN-11)", "NN-11")
            problems += expect(entry.get("step_up") is True, "ZT_STEP_UP", scope,
                               f"{pair[0]}:{pair[1]} must require step-up authentication", "NN-11")
            problems += expect("justification" in requirements, "ZT_JUSTIFICATION", scope,
                               "a high-risk action must record why it was performed", "NN-11")

        if str(entry.get("principal")) in ("platform-operator", "break-glass"):
            problems += expect("phishing_resistant_mfa" in requirements, "ZT_ADMIN_MFA", scope,
                               "administrative access must be phishing resistant; OTP over SMS "
                               "is a phishing target, not a second factor", "NN-11")
            problems += expect("device_posture" in requirements, "ZT_DEVICE_POSTURE", scope,
                               "administrative access must check the device; a valid credential "
                               "on a compromised laptop is a compromised credential", "NN-11")

        if "tenant" in str(entry.get("resource_class") or ""):
            problems += expect("tenant_binding" in requirements
                               or entry.get("principal") in ("platform-operator", "break-glass"),
                               "ZT_TENANT_BINDING", scope,
                               "tenant-scoped access must bind the tenant to the credential, not "
                               "to the request body; otherwise cross-tenant access is one edited "
                               "field away", "NN-09")

        if entry.get("principal") == "merchant-api-client":
            for required in ("token_audience", "token_holder_binding", "tenant_binding"):
                problems += expect(required in requirements, "ZT_MERCHANT_CREDENTIAL", scope,
                                   f"merchant API decisions must require '{required}'", "NN-07")

    for pair in sorted(HIGH_RISK):
        if pair == ("ledger_entry", "write"):
            continue  # ledger writes are event-driven; B72 owns that decision
        problems += expect(pair in covered_high_risk, "ZT_HIGH_RISK_UNCOVERED", where,
                           f"no decision governs {pair[0]}:{pair[1]}; an ungoverned high-risk "
                           f"action is decided by whoever gets there first", "NN-11")
    return used, problems


def _zones(policy: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    try:
        threat = load_json(root / THREAT)
    except Exception as exc:
        return [Problem("ZT_UNREADABLE", str(THREAT), f"cannot read the threat model: {exc}",
                        "NN-12")]
    boundaries = {b.get("id"): b for b in threat.get("trust_boundaries", [])}
    zones = {z.get("id"): z for z in threat.get("zones", [])}

    rules = policy.get("zone_rules")
    if not isinstance(rules, list) or not rules:
        return [Problem("ZT_SHAPE", where, "'zone_rules' must be a non-empty list", "NN-12")]

    problems: list[Problem] = []
    covered: set = set()
    for rule in rules:
        if not isinstance(rule, dict):
            problems.append(Problem("ZT_SHAPE", where, "each zone rule must be an object",
                                    "NN-12"))
            continue
        bid = rule.get("boundary")
        scope = f"{where}#{bid}"
        budget.check(scope)
        problems += expect(bid in boundaries, "ZT_BOUNDARY_UNKNOWN", scope,
                           f"'{bid}' is not a trust boundary in the threat model", "NN-12")
        covered.add(bid)
        problems += expect(bool(rule.get("requires")), "ZT_BOUNDARY_REQUIREMENTS", scope,
                           "a boundary with no requirements is not a boundary", "NN-12")
        problems += expect("audit_record" in (rule.get("requires") or []),
                           "ZT_BOUNDARY_AUDIT", scope,
                           "crossing a trust boundary must be auditable", "NN-12")
        problems += expect(len(str(rule.get("notes") or "")) >= 10, "ZT_BOUNDARY_NOTES", scope,
                           "say what this boundary is protecting against", "NN-12")

        between = (boundaries.get(bid) or {}).get("between") or []
        ours = [z for z in between
                if str(zones.get(z, {}).get("trust", "")) in PLATFORM_OPERATED_TRUST]
        if between and len(ours) == len(between):
            problems += expect(rule.get("mutual_tls") is True, "ZT_INTERNAL_TRUST", scope,
                               f"'{bid}' runs between zones we operate ourselves {between} and "
                               f"does not require mutual TLS; 'both sides are internal' is "
                               f"exactly the assumption zero trust removes", "NN-12")

    for bid in sorted(boundaries):
        problems += expect(bid in covered, "ZT_BOUNDARY_UNGOVERNED", where,
                           f"trust boundary '{bid}' has no zero-trust rule; an ungoverned "
                           f"boundary is where the perimeter quietly comes back", "NN-12")
    return problems


def _break_glass(policy: dict, root: Path, where: str) -> list[Problem]:
    """The escape hatch B13 declared must be governed here too."""
    try:
        arch = load_json(root / DATA)
    except Exception:
        return []
    hatch = (arch.get("tenancy") or {}).get("escape_hatch") or {}
    role = hatch.get("role")
    if not role:
        return []
    principals = {p.get("id") for p in policy.get("principals") or []
                  if isinstance(p, dict)}
    problems = list(expect("break-glass" in principals, "ZT_BREAK_GLASS_UNGOVERNED", where,
                           f"the data architecture declares a break-glass role '{role}' but the "
                           f"zero-trust policy has no principal for it; the one path that "
                           f"crosses tenants must be the most governed, not the least", "NN-11"))
    decisions = [d for d in policy.get("decisions") or []
                 if isinstance(d, dict) and d.get("principal") == "break-glass"]
    problems += expect(decisions, "ZT_BREAK_GLASS_UNGOVERNED", where,
                       "break-glass access must have an explicit decision rule", "NN-11")
    for entry in decisions:
        problems += expect("time_bound_session" in (entry.get("requirements") or []),
                           "ZT_BREAK_GLASS_UNBOUNDED", where,
                           "break-glass sessions must be time bound", "NN-11")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .ztgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        if not path.is_file():
            problems.append(Problem("ZT_GENERATED_MISSING", rel,
                                    "generated zero-trust artefact is missing; run "
                                    "scripts/render-zerotrust.py", "NN-12"))
            continue
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("ZT_GENERATED", rel,
                                    f"the artefact cannot be derived from the policy: "
                                    f"{type(exc).__name__}: {exc}", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("ZT_GENERATED_DRIFT", rel,
                                    "the generated artefact differs from the policy; run "
                                    "scripts/render-zerotrust.py", "NN-12"))
    return problems
