"""B26 — provider account and credential binding.

The batch brief asks for isolation by tenant, project, environment and provider,
and forbids shared secrets and cross-tenant callbacks. One rule carries the
batch: ``ACCOUNT_CALLBACK_GUESSED``. A provider callback carries the provider's
own identifiers, not ours, so attribution is a lookup — and when the lookup is
ambiguous the only correct answer is "I do not know". Every system that instead
falls back to "closest match by amount and time" works perfectly until two
tenants take the same amount in the same second, at which point it books one
merchant's money against another and there is nothing in the record to show it.

The others are the mistakes this area repeats:

* ``ACCOUNT_SHARED_CREDENTIAL`` — one API key reused across tenants or across
  live and test. It is always introduced for a good reason and it converts one
  leak into every merchant's leak;
* ``ACCOUNT_ACTIVATION_UNPROVEN`` — a binding marked usable because a form was
  submitted. The first real payment then becomes the integration test;
* ``ACCOUNT_SUSPENDED_BLOCKS_CALLBACKS`` — suspending a merchant by switching
  off its callbacks. The money has already left the payer; refusing the callback
  only destroys the platform's own evidence that it arrived;
* ``ACCOUNT_RETURN_PAGE_EVIDENCE`` — treating the browser's return page as proof
  of payment (NN-01). It is a request from the payer's own machine.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

ACCOUNTS = Path("governance/provider-accounts.json")
KEYS = Path("governance/key-management.json")
TENANTS = Path("governance/tenant-registry.json")
CURRENCY = Path("governance/currency-metadata.json")
AUTHZ = Path("governance/authorization.json")
AUDIT = Path("governance/audit-log.json")

CODE = re.compile(r"^[a-z][a-z0-9_]*$")
STATES = ["pending", "active", "suspended", "revoked"]
CAPABILITIES = ("initiate_payment", "receive_callback", "issue_refund", "settle",
                "rotate_credential")
# What must keep working while a binding is suspended: the money is already in
# flight and the platform still has to be able to see it land and give it back.
IN_FLIGHT = ("receive_callback", "issue_refund", "settle")
IDENTITY_FIELDS = {"tenant_id", "project_id", "environment", "provider"}
CREDENTIAL_KINDS = {"signing_key", "api_key", "decryption_key"}
MAX_LEASE_SECONDS = 900
MAX_REPLAY_WINDOW_SECONDS = 900


VALIDATOR = ("provider-accounts", "B26")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(ACCOUNTS)
    budget.check(where)
    try:
        model = load_json(root / ACCOUNTS)
    except Exception as exc:
        return [Problem("ACCOUNT_UNREADABLE", where,
                        f"cannot read the provider account model: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("ACCOUNT_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "ACCOUNT_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "ACCOUNT_PRINCIPLE", where,
                       "say what a binding is and what may never be guessed", "NN-14")
    problems += _binding(model, where)
    problems += _providers(model, root, where, budget)
    problems += _credentials(model, root, where, budget)
    problems += _callback(model, where)
    problems += _quarantine(model, where)
    problems += _activation(model, where)
    problems += _lifecycle(model, where, budget)
    problems += _capabilities(model, where, budget)
    problems += _forbidden(model, where)
    problems += _permission(model, root, where, budget)
    problems += _audit_binding(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _binding(model: dict, where: str) -> list[Problem]:
    binding = model.get("binding")
    if not isinstance(binding, dict):
        return [Problem("ACCOUNT_SHAPE", where, "binding must be an object", "NN-14")]
    identity = set(binding.get("identity_fields") or [])
    problems = list(expect(IDENTITY_FIELDS <= identity, "ACCOUNT_BINDING_DIMENSIONS", where,
                           f"a binding must be scoped by {sorted(IDENTITY_FIELDS - identity)}; "
                           f"anything coarser shares a provider account between things that "
                           f"must not see each other", "NN-07"))
    unique = set(binding.get("unique_key") or [])
    problems += expect(IDENTITY_FIELDS <= unique, "ACCOUNT_BINDING_NOT_UNIQUE", where,
                       "the identity dimensions must form the uniqueness key, or one tenant "
                       "can hold two bindings for the same provider and the callback becomes "
                       "ambiguous by construction", "NN-03")
    immutable = set(binding.get("immutable_fields") or [])
    problems += expect(IDENTITY_FIELDS <= immutable, "ACCOUNT_BINDING_MUTABLE", where,
                       f"{sorted(IDENTITY_FIELDS - immutable)} must be immutable; a mutable "
                       f"binding is a silently movable destination for money", "NN-03")
    problems += expect(binding.get("one_credential_per_binding") is True,
                       "ACCOUNT_MULTI_CREDENTIAL", where,
                       "a binding must hold exactly one credential; two live credentials mean "
                       "revocation misses one", "NN-04")
    problems += expect(len(str(binding.get("notes") or "")) >= 8, "ACCOUNT_BINDING_NOTES", where,
                       "say why these dimensions and why they are immutable", "NN-14")
    return problems


def _providers(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("providers")
    if not isinstance(entries, list) or not entries:
        return [Problem("ACCOUNT_SHAPE", where, "providers must be a non-empty list", "NN-14")]
    budget.check(str(KEYS))
    try:
        keys = load_json(root / KEYS)
        known_keys = {str(k.get("id")) for k in (keys.get("keys") or []) if isinstance(k, dict)}
        provider_keys = {str(p.get("provider")) for p in (keys.get("provider_keys") or [])
                         if isinstance(p, dict)}
    except Exception:
        known_keys, provider_keys = set(), set()
    budget.check(str(TENANTS))
    try:
        tenants = load_json(root / TENANTS)
        environments = {str(e.get("id")) for e in (tenants.get("environments") or [])
                        if isinstance(e, dict)}
    except Exception:
        environments = set()
    budget.check(str(CURRENCY))
    try:
        currency = load_json(root / CURRENCY)
        currencies = {str(c.get("code")) for c in (currency.get("currencies") or [])
                      if isinstance(c, dict)}
    except Exception:
        currencies = set()

    problems: list[Problem] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("ACCOUNT_SHAPE", where, "each provider must be an object",
                                    "NN-12"))
            continue
        pid = str(entry.get("id") or "")
        scope = f"{where}#{pid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(CODE.match(pid)), "ACCOUNT_PROVIDER_ID", scope,
                           f"provider id '{pid}' must be snake_case", "NN-12")
        problems += expect(pid not in seen, "ACCOUNT_PROVIDER_DUPLICATE", scope,
                           f"provider '{pid}' is declared twice", "NN-12")
        seen.add(pid)
        problems += expect(str(entry.get("key_id")) in known_keys, "ACCOUNT_PROVIDER_KEY_UNKNOWN",
                           scope,
                           f"'{pid}' names key '{entry.get('key_id')}', which "
                           f"governance/key-management.json does not define", "NN-04")
        problems += expect(pid in provider_keys, "ACCOUNT_PROVIDER_KEY_UNBOUND", scope,
                           f"'{pid}' has no entry in the B20 provider_keys table, so nothing "
                           f"says how its credential is held", "NN-04")
        problems += expect(entry.get("credential_kind") in CREDENTIAL_KINDS,
                           "ACCOUNT_CREDENTIAL_KIND", scope,
                           f"credential_kind must be one of {sorted(CREDENTIAL_KINDS)}", "NN-04")
        envs = entry.get("environments")
        problems += expect(isinstance(envs, list) and bool(envs), "ACCOUNT_PROVIDER_NO_ENV",
                           scope, f"'{pid}' declares no environment", "NN-07")
        for env in envs or []:
            problems += expect(env in environments, "ACCOUNT_ENV_UNKNOWN", scope,
                               f"environment '{env}' is not defined by the B24 tenant registry",
                               "NN-07")
        settlement = entry.get("settlement_currencies")
        problems += expect(isinstance(settlement, list) and bool(settlement),
                           "ACCOUNT_PROVIDER_NO_CURRENCY", scope,
                           f"'{pid}' settles in no currency", "NN-05")
        for code in settlement or []:
            problems += expect(code in currencies, "ACCOUNT_CURRENCY_UNKNOWN", scope,
                               f"settlement currency '{code}' is not in the versioned currency "
                               f"metadata", "NN-05")
        problems += expect(bool(entry.get("callback_attribution_field")),
                           "ACCOUNT_NO_ATTRIBUTION_FIELD", scope,
                           f"'{pid}' does not say which field in the callback identifies the "
                           f"binding; without one, attribution can only be a guess", "NN-01")
        problems += expect(entry.get("callback_signed") is True, "ACCOUNT_CALLBACK_UNSIGNED",
                           scope,
                           f"'{pid}' callbacks must be signed; an unsigned callback is an "
                           f"anonymous instruction to move money", "NN-01")
        rotation = int(entry.get("credential_rotation_days") or 0)
        problems += expect(0 < rotation <= 365, "ACCOUNT_PROVIDER_ROTATION", scope,
                           f"'{pid}' needs a bounded credential rotation period, got {rotation}",
                           "NN-04")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "ACCOUNT_PROVIDER_NOTES",
                           scope, "say what is specific about this provider", "NN-14")
    return problems


def _credentials(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    credentials = model.get("credentials")
    if not isinstance(credentials, dict):
        return [Problem("ACCOUNT_SHAPE", where, "credentials must be an object", "NN-04")]
    problems = list(expect(credentials.get("plaintext_at_rest") is False,
                           "ACCOUNT_PLAINTEXT_CREDENTIAL", where,
                           "provider credentials must never be stored in plaintext", "NN-04"))
    problems += expect(credentials.get("plaintext_in_logs") is False,
                       "ACCOUNT_PLAINTEXT_CREDENTIAL", where,
                       "provider credentials must never reach logs", "NN-04")
    problems += expect(credentials.get("storage") == "envelope_encrypted",
                       "ACCOUNT_CREDENTIAL_STORAGE", where,
                       "credentials must be envelope encrypted under a KMS key", "NN-04")
    for field in ("shared_across_tenants", "shared_across_environments",
                  "shared_across_projects"):
        problems += expect(credentials.get(field) is False, "ACCOUNT_SHARED_CREDENTIAL", where,
                           f"{field} must be false; one shared credential turns one leak into "
                           f"every merchant's leak", "NN-07")
    lease = int(credentials.get("max_decrypt_lease_seconds") or 0)
    problems += expect(0 < lease <= MAX_LEASE_SECONDS, "ACCOUNT_LEASE_UNBOUNDED", where,
                       f"a decrypted credential must expire within {MAX_LEASE_SECONDS}s, got "
                       f"{lease}s; a key that lives forever in memory is a key that can be "
                       f"exported forever", "NN-04")
    rotation = int(credentials.get("rotation_max_days") or 0)
    problems += expect(0 < rotation <= 365, "ACCOUNT_ROTATION_UNBOUNDED", where,
                       f"credentials must rotate, got {rotation} days", "NN-04")
    overlap = int(credentials.get("rotation_overlap_days") or 0)
    problems += expect(0 < overlap < max(rotation, 1), "ACCOUNT_ROTATION_NO_OVERLAP", where,
                       f"rotation needs an overlap window shorter than the rotation period, got "
                       f"{overlap}/{rotation}; without one, the callbacks in flight at the "
                       f"moment of the switch are dropped, and those callbacks are the "
                       f"platform's only proof it was paid", "NN-04")

    budget.check(str(KEYS))
    try:
        keys = load_json(root / KEYS)
        kek = next((k for k in (keys.get("keys") or [])
                    if isinstance(k, dict) and k.get("id") == "kek-provider-credentials"), {})
        key_rotation = int(kek.get("rotation_days") or 0)
    except Exception:
        key_rotation = 0
    if key_rotation:
        problems += expect(rotation <= key_rotation, "ACCOUNT_ROTATION_SLOWER_THAN_KEY", where,
                           f"credentials rotate every {rotation} days but the key that wraps "
                           f"them rotates every {key_rotation}; the credential would outlive "
                           f"its own protection", "NN-04")
    problems += expect(len(str(credentials.get("notes") or "")) >= 8, "ACCOUNT_CREDENTIAL_NOTES",
                       where, "say why the lease and the overlap are what they are", "NN-14")
    return problems


def _callback(model: dict, where: str) -> list[Problem]:
    callback = model.get("callback")
    if not isinstance(callback, dict):
        return [Problem("ACCOUNT_SHAPE", where, "callback must be an object", "NN-01")]
    problems = list(expect(callback.get("signature_required") is True,
                           "ACCOUNT_CALLBACK_UNSIGNED", where,
                           "every provider callback must be signature-verified", "NN-01"))
    problems += expect(callback.get("attribution_must_be_deterministic") is True,
                       "ACCOUNT_CALLBACK_GUESSED", where,
                       "callback attribution must be a deterministic lookup", "NN-01")
    problems += expect(callback.get("guess_on_ambiguity") is False, "ACCOUNT_CALLBACK_GUESSED",
                       where,
                       "an ambiguous callback must not be resolved by best match; two tenants "
                       "taking the same amount in the same second is not a rare event",
                       "NN-01")
    problems += expect(callback.get("quarantine_on_unattributable") is True,
                       "ACCOUNT_NO_QUARANTINE", where,
                       "an unattributable callback must be quarantined, not dropped and not "
                       "guessed", "NN-01")
    problems += expect(callback.get("cross_tenant_delivery_allowed") is False,
                       "ACCOUNT_CROSS_TENANT_CALLBACK", where,
                       "a callback may never be delivered to a tenant other than the bound one",
                       "NN-07")
    problems += expect(callback.get("client_return_page_is_evidence") is False,
                       "ACCOUNT_RETURN_PAGE_EVIDENCE", where,
                       "the client return page is not evidence of payment; it is a request from "
                       "the payer's own machine", "NN-01")
    window = int(callback.get("replay_window_seconds") or 0)
    problems += expect(0 < window <= MAX_REPLAY_WINDOW_SECONDS, "ACCOUNT_REPLAY_WINDOW", where,
                       f"the accepted callback age must be bounded, got {window}s", "NN-01")
    problems += expect(bool(callback.get("idempotency_key_field")),
                       "ACCOUNT_NO_IDEMPOTENCY_KEY", where,
                       "callbacks must carry a provider event id used as the idempotency key; "
                       "providers retry, and a retry must not book the money twice", "NN-03")
    problems += expect(len(str(callback.get("notes") or "")) >= 8, "ACCOUNT_CALLBACK_NOTES",
                       where, "say what a callback must prove before it is believed", "NN-14")
    return problems


def _quarantine(model: dict, where: str) -> list[Problem]:
    quarantine = model.get("quarantine")
    if not isinstance(quarantine, dict):
        return [Problem("ACCOUNT_NO_QUARANTINE", where,
                        "without a quarantine, an unattributable callback can only be dropped "
                        "or guessed", "NN-01")]
    days = int(quarantine.get("retention_days") or 0)
    problems = list(expect(days > 0, "ACCOUNT_QUARANTINE_UNRETAINED", where,
                           "quarantined callbacks must be retained long enough to investigate",
                           "NN-13"))
    problems += expect(quarantine.get("alert_required") is True, "ACCOUNT_QUARANTINE_SILENT",
                       where,
                       "a quarantine nobody is told about is a deletion with extra steps",
                       "NN-13")
    problems += expect(quarantine.get("auto_replay_allowed") is False,
                       "ACCOUNT_QUARANTINE_AUTO_REPLAY", where,
                       "a quarantined callback must not be replayed automatically; that asks "
                       "the system to make the judgement it just admitted it cannot make",
                       "NN-01")
    problems += expect(quarantine.get("manual_replay_requires_attribution") is True,
                       "ACCOUNT_QUARANTINE_BLIND_REPLAY", where,
                       "a manual replay must state the binding it belongs to", "NN-01")
    return problems


def _activation(model: dict, where: str) -> list[Problem]:
    activation = model.get("activation")
    if not isinstance(activation, dict):
        return [Problem("ACCOUNT_ACTIVATION_UNPROVEN", where,
                        "a binding must not become usable without a proven round trip",
                        "NN-14")]
    problems: list[Problem] = []
    for field, detail in (
            ("test_transaction_required", "a real test transaction"),
            ("callback_roundtrip_required", "a callback that actually came back"),
            ("signature_verification_required", "a signature that actually verified")):
        problems += expect(activation.get(field) is True, "ACCOUNT_ACTIVATION_UNPROVEN", where,
                           f"activation must require {detail}; otherwise the first real payment "
                           f"is the integration test", "NN-14")
    problems += expect(len(str(activation.get("notes") or "")) >= 8, "ACCOUNT_ACTIVATION_NOTES",
                       where, "say what activation proves", "NN-14")
    return problems


def _lifecycle(model: dict, where: str, budget: Budget) -> list[Problem]:
    lifecycle = model.get("lifecycle")
    if not isinstance(lifecycle, dict):
        return [Problem("ACCOUNT_SHAPE", where, "lifecycle must be an object", "NN-14")]
    problems = list(expect(lifecycle.get("states") == STATES, "ACCOUNT_STATES", where,
                           f"states must be exactly {STATES}", "NN-14"))
    problems += expect(lifecycle.get("initial") == "pending", "ACCOUNT_INITIAL_STATE", where,
                       "a new binding starts unproven", "NN-14")
    problems += expect(lifecycle.get("terminal") == ["revoked"], "ACCOUNT_TERMINAL_STATE", where,
                       "revoked is the only terminal state", "NN-14")
    transitions = lifecycle.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        return problems + [Problem("ACCOUNT_SHAPE", where, "transitions must be a non-empty list",
                                   "NN-14")]
    seen: set[tuple[str, str]] = set()
    known = set(STATES)
    for entry in transitions:
        if not isinstance(entry, dict):
            problems.append(Problem("ACCOUNT_SHAPE", where, "each transition must be an object",
                                    "NN-12"))
            continue
        pair = (str(entry.get("from")), str(entry.get("to")))
        budget.check(f"{pair[0]}->{pair[1]}")
        problems += expect(pair[0] in known and pair[1] in known, "ACCOUNT_TRANSITION_UNKNOWN",
                           where, f"transition {pair[0]} -> {pair[1]} names an unknown state",
                           "NN-12")
        problems += expect(pair not in seen, "ACCOUNT_TRANSITION_DUPLICATE", where,
                           f"transition {pair[0]} -> {pair[1]} is declared twice", "NN-12")
        seen.add(pair)
        problems += expect(bool(entry.get("requires")), "ACCOUNT_TRANSITION_UNGUARDED", where,
                           f"transition {pair[0]} -> {pair[1]} has no precondition", "NN-14")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "ACCOUNT_TRANSITION_NOTES",
                           where, f"say why {pair[0]} -> {pair[1]} exists", "NN-14")

    activation = next((t for t in transitions if isinstance(t, dict)
                       and t.get("from") == "pending" and t.get("to") == "active"), None)
    requires = set((activation or {}).get("requires") or [])
    problems += expect({"test_transaction_settled", "callback_roundtrip_verified"} <= requires,
                       "ACCOUNT_ACTIVATION_UNPROVEN", where,
                       "activation must require a settled test transaction and a verified "
                       "callback round trip", "NN-14")
    reinstate = next((t for t in transitions if isinstance(t, dict)
                      and t.get("from") == "suspended" and t.get("to") == "active"), None)
    problems += expect("second_approver" in set((reinstate or {}).get("requires") or []),
                       "ACCOUNT_REINSTATE_SINGLE_PERSON", where,
                       "reinstating a suspended binding must take two people", "NN-03")
    for entry in transitions:
        if isinstance(entry, dict) and entry.get("to") == "revoked":
            needs = set(entry.get("requires") or [])
            problems += expect("in_flight_settled" in needs, "ACCOUNT_REVOKE_BEFORE_SETTLEMENT",
                               where,
                               "revoking before the in-flight transactions settle strands money "
                               "the platform has already taken", "NN-01")
            problems += expect("credential_destroyed" in needs, "ACCOUNT_REVOKE_KEEPS_CREDENTIAL",
                               where, "revocation must destroy the credential", "NN-04")
    reachable = {"pending"}
    for _ in range(len(STATES)):
        for source, target in seen:
            if source in reachable:
                reachable.add(target)
    for state in STATES:
        problems += expect(state in reachable, "ACCOUNT_STATE_UNREACHABLE", where,
                           f"state '{state}' cannot be reached from pending", "NN-12")
    return problems


def _capabilities(model: dict, where: str, budget: Budget) -> list[Problem]:
    rows = model.get("capability_matrix")
    if not isinstance(rows, list) or not rows:
        return [Problem("ACCOUNT_NO_CAPABILITY_MATRIX", where,
                        "without a capability matrix, 'suspended' means whatever each service "
                        "decides it means", "NN-14")]
    problems: list[Problem] = []
    by_state: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            problems.append(Problem("ACCOUNT_SHAPE", where, "each matrix row must be an object",
                                    "NN-12"))
            continue
        state = str(row.get("state") or "")
        budget.check(f"matrix/{state}")
        for capability in CAPABILITIES:
            problems += expect(isinstance(row.get(capability), bool),
                               "ACCOUNT_CAPABILITY_MISSING", where,
                               f"row '{state}' does not answer '{capability}'", "NN-14")
        problems += expect(len(str(row.get("notes") or "")) >= 4, "ACCOUNT_CAPABILITY_NOTES",
                           where, f"say what state '{state}' means in practice", "NN-14")
        if state:
            by_state[state] = row
    for state in STATES:
        problems += expect(state in by_state, "ACCOUNT_CAPABILITY_MISSING", where,
                           f"the matrix has no row for '{state}'", "NN-14")

    pending = by_state.get("pending") or {}
    problems += expect(pending.get("initiate_payment") is not True, "ACCOUNT_PENDING_TAKES_MONEY",
                       where, "an unproven binding must not take real payments", "NN-14")
    suspended = by_state.get("suspended") or {}
    problems += expect(suspended.get("initiate_payment") is not True,
                       "ACCOUNT_SUSPENDED_TAKES_MONEY", where,
                       "a suspended binding must not start new payments", "NN-14")
    problems += expect(suspended.get("receive_callback") is True,
                       "ACCOUNT_SUSPENDED_BLOCKS_CALLBACKS", where,
                       "a suspended binding must keep receiving callbacks; the money has "
                       "already left the payer and the callback is the platform's only proof "
                       "it arrived", "NN-01")
    for capability in IN_FLIGHT:
        problems += expect(suspended.get(capability) is True, "ACCOUNT_SUSPENDED_STRANDS_MONEY",
                           where,
                           f"a suspended binding must still be able to '{capability}'", "NN-01")
    revoked = by_state.get("revoked") or {}
    for capability in CAPABILITIES:
        problems += expect(revoked.get(capability) is not True, "ACCOUNT_REVOKED_ACTIVE", where,
                           f"a revoked binding must not be able to '{capability}'; its "
                           f"credential no longer exists", "NN-04")
    return problems


def _forbidden(model: dict, where: str) -> list[Problem]:
    forbidden = model.get("forbidden")
    if not isinstance(forbidden, dict):
        return [Problem("ACCOUNT_SHAPE", where, "forbidden must be an object", "NN-14")]
    problems: list[Problem] = []
    for field in ("shared_credential_across_tenants", "shared_credential_across_environments",
                  "credential_in_source_or_ci", "callback_without_signature"):
        problems += expect(forbidden.get(field) is True, "ACCOUNT_FORBIDDEN_RELAXED", where,
                           f"'{field}' must stay forbidden", "NN-04")
    problems += expect(forbidden.get("attribution_by_amount_or_time") is True,
                       "ACCOUNT_ATTRIBUTION_HEURISTIC", where,
                       "matching a callback by amount and time must stay forbidden: it works in "
                       "test and books two merchants' money the wrong way round in production",
                       "NN-01")
    problems += expect(len(str(forbidden.get("notes") or "")) >= 8, "ACCOUNT_FORBIDDEN_NOTES",
                       where, "say why the last one looks clever and is not", "NN-14")
    return problems


def _permission(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    permission = str(model.get("rotation_permission") or "")
    budget.check(str(AUTHZ))
    try:
        authz = load_json(root / AUTHZ)
        permissions = {str(p.get("id")): p for p in (authz.get("permissions") or [])
                       if isinstance(p, dict)}
    except Exception:
        permissions = {}
    problems = list(expect(permission in permissions, "ACCOUNT_PERMISSION_UNKNOWN", where,
                           f"credential rotation is guarded by '{permission}', which B19 does "
                           f"not define", "NN-12"))
    entry = permissions.get(permission) or {}
    if entry:
        problems += expect(entry.get("dual_control") is True, "ACCOUNT_ROTATION_SINGLE_PERSON",
                           where,
                           f"'{permission}' must be dual control in B19: rotating a provider "
                           f"credential can silently redirect a merchant's money", "NN-03")
    return problems


def _audit_binding(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    event_class = str(model.get("audit_event_class") or "")
    budget.check(str(AUDIT))
    try:
        audit = load_json(root / AUDIT)
        classes = {str(c.get("id")) for c in (audit.get("event_classes") or [])
                   if isinstance(c, dict)}
    except Exception:
        classes = set()
    return list(expect(event_class in classes, "ACCOUNT_AUDIT_CLASS_UNKNOWN", where,
                       f"binding changes are recorded as '{event_class}', which "
                       f"governance/audit-log.json does not define", "NN-13"))


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .accountsgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("ACCOUNT_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("ACCOUNT_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/provider-accounts.json "
                                    f"but does not exist; run scripts/render-accounts.py",
                                    "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("ACCOUNT_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the model generates", "NN-12"))
    return problems
