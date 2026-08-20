"""B28 — routing rules, canary rollout and configuration versioning.

The batch asks for deterministic priority, cost/success-rate/risk routing,
configuration audit, rollback and simulated evaluation. One rule holds the rest
up: ``ROUTE_NONDETERMINISTIC``. If the same payment under the same configuration
version can come out differently twice, then months later — in a dispute, or
staring at a reconciliation break — nobody can answer why this payment went to
that provider. Every other guarantee in this file is downstream of being able to
replay the decision.

The rest are the mistakes this area repeats:

* ``ROUTE_NO_EXPLORATION`` — routing purely to the best measured success rate is
  self-reinforcing. A provider that receives no traffic can never demonstrate it
  recovered, so one transient dip becomes a permanent outage of that route;
* ``ROUTE_RANDOM_SPLIT`` — splitting a canary on a random number instead of a
  stable hash of the payment. The retry of a payment then lands in the other
  branch, which means a different provider, which is how one payment becomes two
  charges;
* ``ROUTE_ROLLBACK_GATED`` — requiring approval to roll back. Rollout deserves
  two people; rollback deserves none, because an approval gate on rollback is an
  outage length written into the process;
* ``ROUTE_SHADOW_MOVES_MONEY`` — a simulator that can move money eventually
  moves money.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

ROUTING = Path("governance/routing-policy.json")
CAPS = Path("governance/provider-capabilities.json")
ACCOUNTS = Path("governance/provider-accounts.json")
AUTHZ = Path("governance/authorization.json")
AUDIT = Path("governance/audit-log.json")

CODE = re.compile(r"^[a-z][a-z0-9_]*$")
FACTORS = {"success_rate", "cost", "risk"}
TIE_BREAKS = {"lowest_provider_id", "declared_order"}
MAX_CANARY_PERCENT = 50
MAX_ROLLBACK_SECONDS = 300
MIN_EXPLORATION_PERCENT = 1
MIN_RETAINED_VERSIONS = 10


VALIDATOR = ("routing-policy", "B28")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(ROUTING)
    budget.check(where)
    try:
        model = load_json(root / ROUTING)
    except Exception as exc:
        return [Problem("ROUTE_UNREADABLE", where,
                        f"cannot read the routing policy: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("ROUTE_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "ROUTE_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "ROUTE_PRINCIPLE", where,
                       "say what makes a routing decision explainable later", "NN-14")
    problems += _versioning(model, root, where, budget)
    problems += _determinism(model, where)
    problems += _rules(model, root, where, budget)
    problems += _scoring(model, where, budget)
    problems += _canary(model, where)
    problems += _rollback(model, where)
    problems += _simulation(model, where)
    problems += _retry(model, where)
    problems += _audit_binding(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _versioning(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    versioning = model.get("config_versioning")
    if not isinstance(versioning, dict):
        return [Problem("ROUTE_SHAPE", where, "config_versioning must be an object", "NN-13")]
    problems = list(expect(versioning.get("versions_are_immutable") is True,
                           "ROUTE_VERSION_MUTABLE", where,
                           "a published configuration version must be immutable; editing one in "
                           "place makes every decision recorded against it a lie", "NN-13"))
    problems += expect(versioning.get("decision_records_config_version") is True,
                       "ROUTE_DECISION_UNVERSIONED", where,
                       "every routing decision must record the configuration version that "
                       "produced it, or it cannot be replayed or challenged", "NN-13")
    problems += expect(versioning.get("activation_requires_approval") is True,
                       "ROUTE_ACTIVATION_UNAPPROVED", where,
                       "activating a routing configuration moves real money differently and "
                       "must be approved", "NN-03")
    approvers = int(versioning.get("activation_approvers_required") or 0)
    problems += expect(approvers >= 2, "ROUTE_ACTIVATION_SINGLE_PERSON", where,
                       f"activation needs at least two people, got {approvers}", "NN-03")
    retained = int(versioning.get("retain_versions") or 0)
    problems += expect(retained >= MIN_RETAINED_VERSIONS, "ROUTE_HISTORY_TOO_SHORT", where,
                       f"keep at least {MIN_RETAINED_VERSIONS} versions, got {retained}: you "
                       f"can only roll back to a version you still have", "NN-13")
    permission = str(versioning.get("activation_permission") or "")
    budget.check(str(AUTHZ))
    try:
        authz = load_json(root / AUTHZ)
        permissions = {str(p.get("id")): p for p in (authz.get("permissions") or [])
                       if isinstance(p, dict)}
    except Exception:
        permissions = {}
    problems += expect(permission in permissions, "ROUTE_PERMISSION_UNKNOWN", where,
                       f"activation is guarded by '{permission}', which B19 does not define",
                       "NN-12")
    entry = permissions.get(permission) or {}
    if entry:
        problems += expect(entry.get("dual_control") is True, "ROUTE_ACTIVATION_SINGLE_PERSON",
                           where, f"'{permission}' must be dual control in B19", "NN-03")
    problems += expect(len(str(versioning.get("notes") or "")) >= 8, "ROUTE_VERSION_NOTES",
                       where, "say why versions are immutable", "NN-14")
    return problems


def _determinism(model: dict, where: str) -> list[Problem]:
    determinism = model.get("determinism")
    if not isinstance(determinism, dict):
        return [Problem("ROUTE_NONDETERMINISTIC", where,
                        "without a determinism policy, nothing says the same payment routes the "
                        "same way twice", "NN-03")]
    problems = list(expect(determinism.get("same_inputs_same_decision") is True,
                           "ROUTE_NONDETERMINISTIC", where,
                           "the same inputs under the same version must produce the same "
                           "decision", "NN-03"))
    problems += expect(determinism.get("random_selection_allowed") is False,
                       "ROUTE_NONDETERMINISTIC", where,
                       "'pick one at random' is an answer nobody can give in a dispute review",
                       "NN-03")
    problems += expect(determinism.get("replayable") is True, "ROUTE_UNREPLAYABLE", where,
                       "a decision that cannot be replayed cannot be audited", "NN-13")
    problems += expect(determinism.get("tie_break") in TIE_BREAKS, "ROUTE_NO_TIE_BREAK", where,
                       f"tie_break must be one of {sorted(TIE_BREAKS)}; without one, equal "
                       f"scores reintroduce randomness through the back door", "NN-03")
    problems += expect(len(str(determinism.get("notes") or "")) >= 8, "ROUTE_DETERMINISM_NOTES",
                       where, "say what happens on a tie", "NN-14")
    return problems


def _rules(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("rules")
    if not isinstance(entries, list) or not entries:
        return [Problem("ROUTE_NO_RULES", where,
                        "a routing policy with no rules routes nothing and hides that fact "
                        "behind a default", "NN-14")]
    budget.check(str(CAPS))
    try:
        caps = load_json(root / CAPS)
        capability_rows = [r for r in (caps.get("capabilities") or []) if isinstance(r, dict)]
        methods = {str(m.get("id")) for m in (caps.get("payment_methods") or [])
                   if isinstance(m, dict)}
        regions = {str(r.get("region")) for r in (caps.get("region_policy") or [])
                   if isinstance(r, dict)}
    except Exception:
        capability_rows, methods, regions = [], set(), set()
    budget.check(str(ACCOUNTS))
    try:
        accounts = load_json(root / ACCOUNTS)
        providers = {str(p.get("id")) for p in (accounts.get("providers") or [])
                     if isinstance(p, dict)}
    except Exception:
        providers = set()

    def serves(provider: str, method: str, region: str, currency: str) -> bool:
        return any(row.get("provider") == provider and row.get("method") == method
                   and region in (row.get("regions") or [])
                   and currency in (row.get("currencies") or [])
                   for row in capability_rows)

    problems: list[Problem] = []
    seen_ids: set[str] = set()
    seen_priorities: dict[int, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("ROUTE_SHAPE", where, "each rule must be an object",
                                    "NN-12"))
            continue
        rid = str(entry.get("id") or "")
        scope = f"{where}#{rid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(CODE.match(rid)), "ROUTE_RULE_ID", scope,
                           f"rule id '{rid}' must be snake_case", "NN-12")
        problems += expect(rid not in seen_ids, "ROUTE_RULE_DUPLICATE", scope,
                           f"rule '{rid}' is declared twice", "NN-12")
        seen_ids.add(rid)
        priority = entry.get("priority")
        problems += expect(isinstance(priority, int) and priority > 0, "ROUTE_NO_PRIORITY",
                           scope, f"rule '{rid}' needs a positive integer priority", "NN-03")
        if isinstance(priority, int):
            problems += expect(priority not in seen_priorities, "ROUTE_PRIORITY_COLLISION",
                               scope,
                               f"rule '{rid}' shares priority {priority} with "
                               f"'{seen_priorities.get(priority)}'; two rules at the same "
                               f"priority make evaluation order decide the outcome", "NN-03")
            seen_priorities.setdefault(priority, rid)

        when = entry.get("when")
        if not isinstance(when, dict):
            problems.append(Problem("ROUTE_RULE_NO_MATCH", scope,
                                    f"rule '{rid}' matches nothing, so it matches everything",
                                    "NN-14"))
            continue
        region = str(when.get("region") or "")
        method = str(when.get("method") or "")
        currency = str(when.get("currency") or "")
        problems += expect(region in regions, "ROUTE_REGION_UNKNOWN", scope,
                           f"'{region}' is not a region the B27 matrix defines", "NN-12")
        problems += expect(method in methods, "ROUTE_METHOD_UNKNOWN", scope,
                           f"'{method}' is not a payment method the B27 matrix defines",
                           "NN-12")
        problems += expect(bool(currency), "ROUTE_RULE_NO_CURRENCY", scope,
                           f"rule '{rid}' does not pin a currency", "NN-05")
        amount = when.get("max_amount_minor")
        problems += expect(isinstance(amount, int) and amount > 0, "ROUTE_NO_AMOUNT_CEILING",
                           scope,
                           f"rule '{rid}' needs an integer minor-unit ceiling; a rule with no "
                           f"ceiling routes a one-off million the same way as a coffee",
                           "NN-05")

        prefer = entry.get("prefer")
        problems += expect(isinstance(prefer, list) and bool(prefer), "ROUTE_RULE_NO_TARGET",
                           scope, f"rule '{rid}' prefers no provider", "NN-14")
        fallback = entry.get("fallback")
        problems += expect(isinstance(fallback, list), "ROUTE_SHAPE", scope,
                           f"rule '{rid}' must declare a fallback list, even if empty", "NN-12")
        targets = list(prefer or []) + list(fallback or [])
        problems += expect(len(set(targets)) == len(targets), "ROUTE_TARGET_DUPLICATE", scope,
                           f"rule '{rid}' lists a provider twice", "NN-12")
        for provider in targets:
            problems += expect(provider in providers, "ROUTE_PROVIDER_UNKNOWN", scope,
                               f"rule '{rid}' routes to '{provider}', which has no binding in "
                               f"B26", "NN-12")
            if capability_rows:
                problems += expect(serves(str(provider), method, region, currency),
                                   "ROUTE_TARGET_INCAPABLE", scope,
                                   f"rule '{rid}' routes {method}/{region}/{currency} to "
                                   f"'{provider}', which the B27 matrix does not support there; "
                                   f"the rule would produce a payment nobody can take", "NN-14")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "ROUTE_RULE_NOTES", scope,
                           "say why this rule exists and why the fallback list looks like that",
                           "NN-14")
    return problems


def _scoring(model: dict, where: str, budget: Budget) -> list[Problem]:
    scoring = model.get("scoring")
    if not isinstance(scoring, dict):
        return [Problem("ROUTE_SHAPE", where, "scoring must be an object", "NN-14")]
    factors = scoring.get("factors")
    if not isinstance(factors, list) or not factors:
        return [Problem("ROUTE_NO_FACTORS", where,
                        "cost, success rate and risk must all appear, or the policy optimises "
                        "one of them silently", "NN-14")]
    problems: list[Problem] = []
    seen: set[str] = set()
    total = 0
    for entry in factors:
        if not isinstance(entry, dict):
            problems.append(Problem("ROUTE_SHAPE", where, "each factor must be an object",
                                    "NN-12"))
            continue
        fid = str(entry.get("id") or "")
        budget.check(f"factor/{fid}")
        problems += expect(fid in FACTORS, "ROUTE_FACTOR_UNKNOWN", f"{where}#{fid}",
                           f"factor must be one of {sorted(FACTORS)}", "NN-14")
        problems += expect(fid not in seen, "ROUTE_FACTOR_DUPLICATE", f"{where}#{fid}",
                           f"factor '{fid}' is declared twice", "NN-12")
        seen.add(fid)
        weight = entry.get("weight")
        problems += expect(isinstance(weight, int) and weight > 0, "ROUTE_FACTOR_WEIGHT",
                           f"{where}#{fid}", f"factor '{fid}' needs a positive integer weight",
                           "NN-14")
        if isinstance(weight, int):
            total += weight
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "ROUTE_FACTOR_NOTES",
                           f"{where}#{fid}", f"say what '{fid}' measures", "NN-14")
    problems += expect(FACTORS <= seen, "ROUTE_NO_FACTORS", where,
                       f"scoring is missing {sorted(FACTORS - seen)}", "NN-14")
    problems += expect(total == 100, "ROUTE_WEIGHTS_UNNORMALISED", where,
                       f"factor weights must sum to 100, got {total}; weights that do not sum "
                       f"cannot be compared across configuration versions", "NN-12")
    window = int(scoring.get("window_minutes") or 0)
    problems += expect(0 < window <= 1440, "ROUTE_WINDOW_UNBOUNDED", where,
                       f"the measurement window must be bounded, got {window} minutes", "NN-14")
    sample = int(scoring.get("min_sample") or 0)
    problems += expect(sample >= 100, "ROUTE_SAMPLE_TOO_SMALL", where,
                       f"a success rate needs a real sample, got {sample}; on ten payments an "
                       f"unlucky pair condemns a working provider", "NN-14")
    floor = int(scoring.get("exploration_floor_percent") or 0)
    problems += expect(floor >= MIN_EXPLORATION_PERCENT, "ROUTE_NO_EXPLORATION", where,
                       f"routing needs an exploration floor of at least "
                       f"{MIN_EXPLORATION_PERCENT}%, got {floor}%: a provider with no traffic "
                       f"can never show it recovered, so one dip becomes permanent", "NN-14")
    problems += expect(floor <= 50, "ROUTE_EXPLORATION_EXCESSIVE", where,
                       f"an exploration floor of {floor}% sends most traffic somewhere the "
                       f"policy did not choose", "NN-14")
    problems += expect(scoring.get("starvation_guard") is True, "ROUTE_NO_EXPLORATION", where,
                       "the starvation guard is what keeps the exploration floor honest",
                       "NN-14")
    problems += expect(len(str(scoring.get("notes") or "")) >= 8, "ROUTE_SCORING_NOTES", where,
                       "say why the sample size and the floor are what they are", "NN-14")
    return problems


def _canary(model: dict, where: str) -> list[Problem]:
    canary = model.get("canary")
    if not isinstance(canary, dict):
        return [Problem("ROUTE_SHAPE", where, "canary must be an object", "NN-03")]
    problems = list(expect(canary.get("random_split_allowed") is False, "ROUTE_RANDOM_SPLIT",
                           where,
                           "a canary split on a random number puts a payment's retry in the "
                           "other branch, which means a different provider, which is how one "
                           "payment becomes two charges", "NN-03"))
    problems += expect(canary.get("stable_hash") is True, "ROUTE_RANDOM_SPLIT", where,
                       "the split must be a stable hash of the payment key", "NN-03")
    problems += expect(str(canary.get("split_key") or "") == "payment_intent_id",
                       "ROUTE_SPLIT_KEY", where,
                       "the split key must be the payment intent, not the user or the session: "
                       "only the payment is stable across a retry", "NN-03")
    percent = int(canary.get("max_percent") or 0)
    problems += expect(0 < percent <= MAX_CANARY_PERCENT, "ROUTE_CANARY_UNBOUNDED", where,
                       f"a canary must stay a canary, got {percent}%", "NN-14")
    minutes = int(canary.get("min_observation_minutes") or 0)
    problems += expect(minutes > 0, "ROUTE_CANARY_UNOBSERVED", where,
                       "a canary nobody watches for a defined period is just a partial rollout",
                       "NN-14")
    problems += expect(canary.get("auto_promote") is False, "ROUTE_AUTO_PROMOTE", where,
                       "promotion moves all the money and must be a human decision; rollback "
                       "does not, which is why the two are not symmetric", "NN-03")
    problems += expect(canary.get("auto_rollback_on_error_rate") is True,
                       "ROUTE_NO_AUTO_ROLLBACK", where,
                       "automatic rollback on error rate is the safe half of the asymmetry",
                       "NN-14")
    threshold = int(canary.get("error_rate_threshold_percent") or 0)
    problems += expect(0 < threshold <= 10, "ROUTE_ROLLBACK_THRESHOLD", where,
                       f"the automatic rollback threshold must be real and tight, got "
                       f"{threshold}%", "NN-14")
    problems += expect(len(str(canary.get("notes") or "")) >= 8, "ROUTE_CANARY_NOTES", where,
                       "say why the split key is the payment", "NN-14")
    return problems


def _rollback(model: dict, where: str) -> list[Problem]:
    rollback = model.get("rollback")
    if not isinstance(rollback, dict):
        return [Problem("ROUTE_SHAPE", where, "rollback must be an object", "NN-14")]
    problems = list(expect(rollback.get("to_existing_version_only") is True,
                           "ROUTE_ROLLBACK_IS_A_RELEASE", where,
                           "rolling back means switching to a version that already exists; "
                           "'change the config back' is a new release that can fail in a new "
                           "way", "NN-13"))
    problems += expect(rollback.get("requires_approval") is False, "ROUTE_ROLLBACK_GATED", where,
                       "rollout takes two people; rollback takes none. An approval gate on "
                       "rollback is an outage length written into the process", "NN-14")
    seconds = int(rollback.get("max_seconds") or 0)
    problems += expect(0 < seconds <= MAX_ROLLBACK_SECONDS, "ROUTE_ROLLBACK_SLOW", where,
                       f"rollback must complete within {MAX_ROLLBACK_SECONDS}s, got {seconds}s",
                       "NN-14")
    problems += expect(len(str(rollback.get("notes") or "")) >= 8, "ROUTE_ROLLBACK_NOTES", where,
                       "say why rollback is not a release", "NN-14")
    return problems


def _simulation(model: dict, where: str) -> list[Problem]:
    simulation = model.get("simulation")
    if not isinstance(simulation, dict):
        return [Problem("ROUTE_NO_SIMULATION", where,
                        "without a simulation mode, every routing change is evaluated in "
                        "production on real payments", "NN-14")]
    problems = list(expect(simulation.get("shadow_moves_money") is False,
                           "ROUTE_SHADOW_MOVES_MONEY", where,
                           "a simulator that can move money will eventually move money",
                           "NN-01"))
    problems += expect(simulation.get("uses_production_config") is True,
                       "ROUTE_SIMULATION_DETACHED", where,
                       "a simulation against a different configuration proves nothing about "
                       "the one that is live", "NN-14")
    problems += expect(simulation.get("compares_against_live") is True,
                       "ROUTE_SIMULATION_UNCOMPARED", where,
                       "a simulation nobody compares to the live decision is a log file",
                       "NN-14")
    problems += expect(len(str(simulation.get("notes") or "")) >= 8, "ROUTE_SIMULATION_NOTES",
                       where, "say what the shadow may and may not do", "NN-14")
    return problems


def _retry(model: dict, where: str) -> list[Problem]:
    retry = model.get("retry")
    if not isinstance(retry, dict):
        return [Problem("ROUTE_SHAPE", where, "retry must be an object", "NN-03")]
    problems = list(expect(retry.get("reuse_idempotency_key") is True,
                           "ROUTE_RETRY_NEW_KEY", where,
                           "a retry must carry the original idempotency key or it is a second "
                           "payment", "NN-03"))
    problems += expect(retry.get("change_provider_on_retry_allowed") is False,
                       "ROUTE_RETRY_CHANGES_PROVIDER", where,
                       "changing provider on retry is not a retry: the first attempt has no "
                       "final state yet, and both can succeed", "NN-01")
    attempts = int(retry.get("max_attempts") or 0)
    problems += expect(0 < attempts <= 5, "ROUTE_RETRY_UNBOUNDED", where,
                       f"retries must be bounded, got {attempts}", "NN-03")
    backoff = retry.get("backoff_seconds")
    problems += expect(isinstance(backoff, list) and len(backoff) >= attempts - 1,
                       "ROUTE_RETRY_NO_BACKOFF", where,
                       "every retry after the first needs a declared backoff; immediate retries "
                       "turn a provider wobble into a stampede", "NN-14")
    if isinstance(backoff, list) and backoff:
        problems += expect(all(isinstance(v, int) and v > 0 for v in backoff)
                           and list(backoff) == sorted(backoff),
                           "ROUTE_RETRY_NO_BACKOFF", where,
                           "backoff must be positive integers in increasing order", "NN-14")
    problems += expect(len(str(retry.get("notes") or "")) >= 8, "ROUTE_RETRY_NOTES", where,
                       "say what makes a retry a retry", "NN-14")
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
    return list(expect(event_class in classes, "ROUTE_AUDIT_CLASS_UNKNOWN", where,
                       f"routing changes are recorded as '{event_class}', which "
                       f"governance/audit-log.json does not define", "NN-13"))


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .routinggen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("ROUTE_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("ROUTE_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/routing-policy.json "
                                    f"but does not exist; run scripts/render-routing.py",
                                    "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("ROUTE_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the model generates", "NN-12"))
    return problems
