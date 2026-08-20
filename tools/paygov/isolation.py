"""B31 — tenant isolation, verified rather than declared.

The brief asks for *proof* of no cross-tenant leakage across row-level security,
object authorisation, cache keys, message topics, logs and exports. So the
central rule is not about any one of those surfaces: it is
``ISO_PROBE_POSITIVE_ONLY``. A test that asserts "tenant A can see its own data"
proves nothing about isolation, because deleting the filter entirely leaves it
green. Every surface here must name a probe that asserts a *denial*.

The rest are the mistakes this area repeats:

* ``ISO_SURFACE_MISSING`` — securing the database and stopping. The database is
  the surface everyone remembers; the leak arrives through a cache key that
  omitted the tenant, or a topic two tenants share, because "that is not the
  database";
* ``ISO_APPLICATION_FILTER_ONLY`` — isolation implemented as a ``WHERE`` clause
  the next person can delete, with every positive test still passing;
* ``ISO_NO_SESSION_TENANT`` — a query with no tenant context returning
  everything instead of failing. Forgetting the predicate must be an error, not
  a wider result set;
* ``ISO_CONSUMER_TRUSTS_PRODUCER`` — putting the tenant in the message envelope
  and not checking it on the way out, which is the same as not putting it there.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

ISOLATION = Path("governance/tenant-isolation.json")
DATA = Path("governance/data-architecture.json")
TENANTS = Path("governance/tenant-registry.json")
AUTHZ = Path("governance/authorization.json")
AUDIT = Path("governance/audit-log.json")

CODE = re.compile(r"^[a-z][a-z0-9_]*$")
REQUIRED_SURFACES = ("database_rows", "object_storage", "cache", "message_topics", "logs",
                     "exports")
ENFORCEMENT_POINTS = {"database", "storage", "application", "messaging", "observability",
                      "search"}


VALIDATOR = ("tenant-isolation", "B31")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(ISOLATION)
    budget.check(where)
    try:
        model = load_json(root / ISOLATION)
    except Exception as exc:
        return [Problem("ISO_UNREADABLE", where,
                        f"cannot read the isolation model: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("ISO_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "ISO_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "ISO_PRINCIPLE", where,
                       "say what counts as proof of isolation", "NN-14")
    problems += _surfaces(model, where, budget)
    problems += _forced(model, root, where, budget)
    problems += _cache(model, where)
    problems += _messaging(model, where)
    problems += _logs(model, where)
    problems += _exports(model, where)
    problems += _evidence(model, where)
    problems += _cross_batch(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _surfaces(model: dict, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("surfaces")
    if not isinstance(entries, list) or not entries:
        return [Problem("ISO_NO_SURFACES", where,
                        "an isolation model with no declared surfaces protects the one surface "
                        "somebody remembered", "NN-07")]
    problems: list[Problem] = []
    seen: set[str] = set()
    probes: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("ISO_SHAPE", where, "each surface must be an object",
                                    "NN-12"))
            continue
        sid = str(entry.get("id") or "")
        scope = f"{where}#{sid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(CODE.match(sid)), "ISO_SURFACE_ID", scope,
                           f"surface id '{sid}' must be snake_case", "NN-12")
        problems += expect(sid not in seen, "ISO_SURFACE_DUPLICATE", scope,
                           f"surface '{sid}' is declared twice", "NN-12")
        seen.add(sid)
        problems += expect(bool(entry.get("mechanism")), "ISO_NO_MECHANISM", scope,
                           f"'{sid}' does not say how it is isolated", "NN-07")
        problems += expect(entry.get("enforced_at") in ENFORCEMENT_POINTS,
                           "ISO_ENFORCEMENT_POINT", scope,
                           f"enforced_at must be one of {sorted(ENFORCEMENT_POINTS)}", "NN-07")
        problems += expect(entry.get("default") == "deny", "ISO_DEFAULT_ALLOW", scope,
                           f"'{sid}' must default to deny; a surface that defaults to allow "
                           f"leaks the moment somebody forgets a predicate", "NN-07")
        problems += expect(bool(entry.get("tenant_key")), "ISO_NO_TENANT_KEY", scope,
                           f"'{sid}' does not name the field that carries the tenant", "NN-07")
        probe = entry.get("probe")
        if not isinstance(probe, dict):
            problems.append(Problem("ISO_NO_PROBE", scope,
                                    f"'{sid}' has no probe, so its isolation is a claim",
                                    "NN-13"))
            continue
        pid = str(probe.get("id") or "")
        problems += expect(bool(CODE.match(pid)), "ISO_NO_PROBE", scope,
                           f"'{sid}' names no probe", "NN-13")
        problems += expect(pid not in probes, "ISO_PROBE_DUPLICATE", scope,
                           f"probe '{pid}' is used for two surfaces; one probe cannot prove "
                           f"two different denials", "NN-13")
        probes.add(pid)
        problems += expect(probe.get("asserts_denial") is True, "ISO_PROBE_POSITIVE_ONLY",
                           scope,
                           f"'{sid}' probe must assert that another tenant is refused; a probe "
                           f"that only asserts its own access stays green with the filter "
                           f"deleted", "NN-13")
        problems += expect(probe.get("runs_in_ci") is True, "ISO_PROBE_NOT_IN_CI", scope,
                           f"'{sid}' probe must run in CI; a probe run by hand is a probe that "
                           f"stopped running months ago", "NN-13")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "ISO_SURFACE_NOTES", scope,
                           f"say how '{sid}' leaks when it leaks", "NN-14")
    for required in REQUIRED_SURFACES:
        problems += expect(required in seen, "ISO_SURFACE_MISSING", where,
                           f"'{required}' is not covered; it is one of the surfaces that leaks "
                           f"precisely because it is not the database", "NN-07")
    return problems


def _forced(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    forced = model.get("forced_controls")
    if not isinstance(forced, dict):
        return [Problem("ISO_APPLICATION_FILTER_ONLY", where,
                        "without forced controls, isolation is whatever the last query "
                        "remembered to do", "NN-07")]
    problems = list(expect(forced.get("rls_forced_for_table_owner") is True,
                           "ISO_RLS_NOT_FORCED", where,
                           "row-level security must apply to the table owner too; the "
                           "application usually connects as the owner", "NN-07"))
    problems += expect(forced.get("session_tenant_required") is True, "ISO_NO_SESSION_TENANT",
                       where,
                       "a query without a tenant context must fail, not return everything",
                       "NN-07")
    problems += expect(forced.get("application_side_filter_alone_sufficient") is False,
                       "ISO_APPLICATION_FILTER_ONLY", where,
                       "an application-side filter is one line the next person can delete, and "
                       "every positive test still passes afterwards", "NN-07")
    permission = str(forced.get("cross_tenant_permission") or "")
    budget.check(str(AUTHZ))
    try:
        authz = load_json(root / AUTHZ)
        permissions = {str(p.get("id")): p for p in (authz.get("permissions") or [])
                       if isinstance(p, dict)}
    except Exception:
        permissions = {}
    problems += expect(permission in permissions, "ISO_PERMISSION_UNKNOWN", where,
                       f"cross-tenant access is guarded by '{permission}', which B19 does not "
                       f"define", "NN-12")
    entry = permissions.get(permission) or {}
    if entry:
        problems += expect(entry.get("dual_control") is True, "ISO_CROSS_TENANT_SINGLE_PERSON",
                           where, f"'{permission}' must be dual control in B19", "NN-03")
    problems += expect(len(str(forced.get("notes") or "")) >= 8, "ISO_FORCED_NOTES", where,
                       "say what happens to a query with no tenant", "NN-14")
    return problems


def _cache(model: dict, where: str) -> list[Problem]:
    cache = model.get("cache")
    if not isinstance(cache, dict):
        return [Problem("ISO_CACHE_UNSCOPED", where, "cache must be an object", "NN-07")]
    problems = list(expect(cache.get("key_includes_tenant") is True, "ISO_CACHE_UNSCOPED",
                           where,
                           "a cache key without the tenant returns another tenant's data and "
                           "raises no error while doing it", "NN-07"))
    problems += expect(cache.get("shared_namespace_allowed") is False, "ISO_CACHE_SHARED",
                       where, "tenants must not share a cache namespace", "NN-07")
    problems += expect(cache.get("negative_cache_scoped") is True, "ISO_NEGATIVE_CACHE_SHARED",
                       where,
                       "the negative cache must be scoped too: 'not found' for one tenant is "
                       "not 'not found' for another", "NN-07")
    problems += expect(len(str(cache.get("notes") or "")) >= 8, "ISO_CACHE_NOTES", where,
                       "say why the negative cache matters", "NN-14")
    return problems


def _messaging(model: dict, where: str) -> list[Problem]:
    messaging = model.get("messaging")
    if not isinstance(messaging, dict):
        return [Problem("ISO_SHAPE", where, "messaging must be an object", "NN-07")]
    problems = list(expect(messaging.get("tenant_in_envelope") is True, "ISO_TOPIC_UNSCOPED",
                           where, "every message must carry its tenant", "NN-07"))
    problems += expect(messaging.get("consumer_must_verify_tenant") is True,
                       "ISO_CONSUMER_TRUSTS_PRODUCER", where,
                       "the consumer must verify the tenant; a tenant written by the producer "
                       "and never checked is not a control", "NN-07")
    problems += expect(messaging.get("cross_tenant_fanout_allowed") is False,
                       "ISO_CROSS_TENANT_FANOUT", where,
                       "one message must not fan out across tenants", "NN-07")
    problems += expect(len(str(messaging.get("notes") or "")) >= 8, "ISO_MESSAGING_NOTES",
                       where, "say where the check actually happens", "NN-14")
    return problems


def _logs(model: dict, where: str) -> list[Problem]:
    logs = model.get("logs")
    if not isinstance(logs, dict):
        return [Problem("ISO_SHAPE", where, "logs must be an object", "NN-06")]
    problems = list(expect(logs.get("tenant_field_required") is True, "ISO_LOG_UNSCOPED", where,
                           "every log line must carry its tenant, or no query over the logs "
                           "can be scoped", "NN-06"))
    problems += expect(logs.get("payload_redacted") is True, "ISO_LOG_PAYLOAD", where,
                       "an error log containing another tenant's row is a leak nobody will "
                       "notice", "NN-06")
    problems += expect(logs.get("cross_tenant_aggregation_requires_permission") is True,
                       "ISO_LOG_AGGREGATION_UNGATED", where,
                       "aggregating across tenants must require the cross-tenant permission",
                       "NN-03")
    problems += expect(len(str(logs.get("notes") or "")) >= 8, "ISO_LOG_NOTES", where,
                       "say what a cross-tenant log query needs", "NN-14")
    return problems


def _exports(model: dict, where: str) -> list[Problem]:
    exports = model.get("exports")
    if not isinstance(exports, dict):
        return [Problem("ISO_SHAPE", where, "exports must be an object", "NN-07")]
    problems = list(expect(exports.get("filter_in_query") is True, "ISO_EXPORT_FILTER_LATE",
                           where,
                           "the tenant filter must be in the query; filtering after the fetch "
                           "gets optimised into pagination, and the last page brings somebody "
                           "else's rows", "NN-07"))
    problems += expect(exports.get("single_tenant_per_export") is True, "ISO_EXPORT_MULTI_TENANT",
                       where, "one export, one tenant", "NN-07")
    problems += expect(exports.get("row_count_verified") is True, "ISO_EXPORT_UNVERIFIED",
                       where,
                       "verifying the row count is the cheapest way to notice that the filter "
                       "ended up in the wrong place", "NN-13")
    problems += expect(len(str(exports.get("notes") or "")) >= 8, "ISO_EXPORT_NOTES", where,
                       "say why the row count is checked", "NN-14")
    return problems


def _evidence(model: dict, where: str) -> list[Problem]:
    evidence = model.get("evidence")
    if not isinstance(evidence, dict):
        return [Problem("ISO_NO_EVIDENCE_POLICY", where,
                        "without an evidence policy, isolation is a paragraph", "NN-13")]
    problems = list(expect(evidence.get("every_surface_has_probe") is True, "ISO_NO_PROBE",
                           where, "every surface must have a probe", "NN-13"))
    problems += expect(evidence.get("probe_must_assert_denial") is True,
                       "ISO_PROBE_POSITIVE_ONLY", where,
                       "a probe must assert a denial", "NN-13")
    problems += expect(evidence.get("probes_run_in_ci") is True, "ISO_PROBE_NOT_IN_CI", where,
                       "probes must run in CI", "NN-13")
    problems += expect(evidence.get("positive_only_test_is_not_evidence") is True,
                       "ISO_PROBE_POSITIVE_ONLY", where,
                       "say explicitly that a positive-only test is not evidence", "NN-13")
    problems += expect(len(str(evidence.get("notes") or "")) >= 8, "ISO_EVIDENCE_NOTES", where,
                       "say what a positive-only test fails to prove", "NN-14")
    return problems


def _cross_batch(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    budget.check(str(DATA))
    try:
        data = load_json(root / DATA)
        tenancy = data.get("tenancy") or {}
        tables = [t for t in (data.get("tables") or []) if isinstance(t, dict)]
    except Exception:
        tenancy, tables = {}, []
    if tables:
        unscoped = [str(t.get("table")) for t in tables
                    if t.get("tenant_scoped")
                    and not ((t.get("rls") or {}).get("enabled") is True)]
        problems += expect(not unscoped, "ISO_TABLE_WITHOUT_RLS", where,
                           f"B13 declares {unscoped} tenant-scoped without row-level security",
                           "NN-07")
        unforced = [str(t.get("table")) for t in tables
                    if (t.get("rls") or {}).get("enabled")
                    and (t.get("rls") or {}).get("force_for_owner") is not True]
        problems += expect(not unforced, "ISO_RLS_NOT_FORCED", where,
                           f"B13 leaves row-level security unforced for the owner on "
                           f"{unforced}; the application usually connects as the owner",
                           "NN-07")
        problems += expect(bool((tenancy or {}).get("session_setting")),
                           "ISO_NO_SESSION_TENANT", where,
                           "B13 must name the session setting that carries the tenant, or "
                           "there is nothing for a policy predicate to read", "NN-07")
    budget.check(str(TENANTS))
    try:
        tenants = load_json(root / TENANTS)
        isolation = tenants.get("isolation") or {}
    except Exception:
        isolation = {}
    problems += expect(isolation.get("row_level_security_required") is True,
                       "ISO_RLS_NOT_FORCED", where,
                       "B24 must still require row-level security", "NN-07")
    problems += expect(isolation.get("cross_tenant_reference_allowed") is False,
                       "ISO_CROSS_TENANT_REFERENCE", where,
                       "B24 must still forbid cross-tenant references", "NN-07")
    budget.check(str(AUDIT))
    try:
        audit = load_json(root / AUDIT)
        classes = {str(c.get("id")) for c in (audit.get("event_classes") or [])
                   if isinstance(c, dict)}
    except Exception:
        classes = set()
    event_class = str(model.get("audit_event_class") or "")
    problems += expect(event_class in classes, "ISO_AUDIT_CLASS_UNKNOWN", where,
                       f"isolation events are recorded as '{event_class}', which "
                       f"governance/audit-log.json does not define", "NN-13")
    problems += expect(event_class == "data.access", "ISO_AUDIT_CLASS_TOO_WEAK", where,
                       "a cross-tenant read is a data access event and must be recorded as one",
                       "NN-13")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .isolationgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("ISO_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("ISO_GENERATED_MISSING", rel,
                                    f"{rel} is generated from "
                                    f"governance/tenant-isolation.json but does not exist; run "
                                    f"scripts/render-isolation.py", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("ISO_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the model generates", "NN-12"))
    return problems
