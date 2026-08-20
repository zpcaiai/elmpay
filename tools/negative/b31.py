"""B31 negative controls — the four ways isolation becomes a claim."""
from __future__ import annotations

from . import EXIT_PROBLEMS

REL = "governance/tenant-isolation.json"
DATA = "governance/data-architecture.json"
TENANTS = "governance/tenant-registry.json"
AUTHZ = "governance/authorization.json"


def _surface(d, sid):
    return next(s for s in d["surfaces"] if s["id"] == sid)


EXPECTED_CODES = {
    "B31 a probe only asserts its own access": "ISO_PROBE_POSITIVE_ONLY",
    "B31 the policy accepts positive-only tests as evidence": "ISO_PROBE_POSITIVE_ONLY",
    "B31 a surface loses its probe": "ISO_NO_PROBE",
    "B31 probes stop running in CI": "ISO_PROBE_NOT_IN_CI",
    "B31 one probe is reused for two surfaces": "ISO_PROBE_DUPLICATE",
    "B31 the cache surface disappears": "ISO_SURFACE_MISSING",
    "B31 a surface defaults to allow": "ISO_DEFAULT_ALLOW",
    "B31 row-level security spares the table owner": "ISO_RLS_NOT_FORCED",
    "B31 B13 leaves row-level security unforced": "ISO_RLS_NOT_FORCED",
    "B31 a tenant-scoped table loses row-level security": "ISO_TABLE_WITHOUT_RLS",
    "B31 a query with no tenant returns everything": "ISO_NO_SESSION_TENANT",
    "B31 an application-side filter is deemed sufficient": "ISO_APPLICATION_FILTER_ONLY",
    "B31 the cross-tenant permission drops dual control": "ISO_CROSS_TENANT_SINGLE_PERSON",
    "B31 the cache key drops the tenant": "ISO_CACHE_UNSCOPED",
    "B31 tenants share a cache namespace": "ISO_CACHE_SHARED",
    "B31 the negative cache is shared": "ISO_NEGATIVE_CACHE_SHARED",
    "B31 the consumer stops verifying the tenant": "ISO_CONSUMER_TRUSTS_PRODUCER",
    "B31 cross-tenant fanout is allowed": "ISO_CROSS_TENANT_FANOUT",
    "B31 logs lose their tenant field": "ISO_LOG_UNSCOPED",
    "B31 log payloads stop being redacted": "ISO_LOG_PAYLOAD",
    "B31 cross-tenant log aggregation needs no permission": "ISO_LOG_AGGREGATION_UNGATED",
    "B31 the export filter moves out of the query": "ISO_EXPORT_FILTER_LATE",
    "B31 one export may span tenants": "ISO_EXPORT_MULTI_TENANT",
    "B31 the export row count is not verified": "ISO_EXPORT_UNVERIFIED",
    "B31 B24 allows cross-tenant references": "ISO_CROSS_TENANT_REFERENCE",
    "B31 isolation events are recorded as configuration changes": "ISO_AUDIT_CLASS_TOO_WEAK",
    "B31 isolation document hand-edited": "ISO_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B31 a probe only asserts its own access", REL,
     lambda d: _surface(d, "cache")["probe"].__setitem__("asserts_denial", False),
     EXIT_PROBLEMS),
    ("B31 the policy accepts positive-only tests as evidence", REL,
     lambda d: d["evidence"].__setitem__("positive_only_test_is_not_evidence", False),
     EXIT_PROBLEMS),
    ("B31 a surface loses its probe", REL,
     lambda d: _surface(d, "cache")["probe"].__setitem__("id", ""), EXIT_PROBLEMS),
    ("B31 probes stop running in CI", REL,
     lambda d: _surface(d, "logs")["probe"].__setitem__("runs_in_ci", False), EXIT_PROBLEMS),
    ("B31 one probe is reused for two surfaces", REL,
     lambda d: _surface(d, "cache")["probe"].__setitem__(
         "id", _surface(d, "logs")["probe"]["id"]), EXIT_PROBLEMS),
    ("B31 the cache surface disappears", REL,
     lambda d: d.__setitem__("surfaces", [s for s in d["surfaces"] if s["id"] != "cache"]),
     EXIT_PROBLEMS),
    ("B31 a surface defaults to allow", REL,
     lambda d: _surface(d, "cache").__setitem__("default", "allow"), EXIT_PROBLEMS),
    ("B31 row-level security spares the table owner", REL,
     lambda d: d["forced_controls"].__setitem__("rls_forced_for_table_owner", False),
     EXIT_PROBLEMS),
    ("B31 B13 leaves row-level security unforced", DATA,
     lambda d: d["tables"][0]["rls"].__setitem__("force_for_owner", False), EXIT_PROBLEMS),
    ("B31 a tenant-scoped table loses row-level security", DATA,
     lambda d: d["tables"][0]["rls"].__setitem__("enabled", False), EXIT_PROBLEMS),
    ("B31 a query with no tenant returns everything", REL,
     lambda d: d["forced_controls"].__setitem__("session_tenant_required", False),
     EXIT_PROBLEMS),
    ("B31 an application-side filter is deemed sufficient", REL,
     lambda d: d["forced_controls"].__setitem__("application_side_filter_alone_sufficient",
                                                True), EXIT_PROBLEMS),
    ("B31 the cross-tenant permission drops dual control", AUTHZ,
     lambda d: next(p for p in d["permissions"] if p["id"] == "cross_tenant_data.read")
     .__setitem__("dual_control", False), EXIT_PROBLEMS),
    ("B31 the cache key drops the tenant", REL,
     lambda d: d["cache"].__setitem__("key_includes_tenant", False), EXIT_PROBLEMS),
    ("B31 tenants share a cache namespace", REL,
     lambda d: d["cache"].__setitem__("shared_namespace_allowed", True), EXIT_PROBLEMS),
    ("B31 the negative cache is shared", REL,
     lambda d: d["cache"].__setitem__("negative_cache_scoped", False), EXIT_PROBLEMS),
    ("B31 the consumer stops verifying the tenant", REL,
     lambda d: d["messaging"].__setitem__("consumer_must_verify_tenant", False),
     EXIT_PROBLEMS),
    ("B31 cross-tenant fanout is allowed", REL,
     lambda d: d["messaging"].__setitem__("cross_tenant_fanout_allowed", True), EXIT_PROBLEMS),
    ("B31 logs lose their tenant field", REL,
     lambda d: d["logs"].__setitem__("tenant_field_required", False), EXIT_PROBLEMS),
    ("B31 log payloads stop being redacted", REL,
     lambda d: d["logs"].__setitem__("payload_redacted", False), EXIT_PROBLEMS),
    ("B31 cross-tenant log aggregation needs no permission", REL,
     lambda d: d["logs"].__setitem__("cross_tenant_aggregation_requires_permission", False),
     EXIT_PROBLEMS),
    ("B31 the export filter moves out of the query", REL,
     lambda d: d["exports"].__setitem__("filter_in_query", False), EXIT_PROBLEMS),
    ("B31 one export may span tenants", REL,
     lambda d: d["exports"].__setitem__("single_tenant_per_export", False), EXIT_PROBLEMS),
    ("B31 the export row count is not verified", REL,
     lambda d: d["exports"].__setitem__("row_count_verified", False), EXIT_PROBLEMS),
    ("B31 B24 allows cross-tenant references", TENANTS,
     lambda d: d["isolation"].__setitem__("cross_tenant_reference_allowed", True),
     EXIT_PROBLEMS),
    ("B31 isolation events are recorded as configuration changes", REL,
     lambda d: d.__setitem__("audit_event_class", "config.change"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B31 isolation document hand-edited",
     "docs/tenancy/TENANT_ISOLATION.md", "隔离必须**被证明**", "隔离已经做好了", EXIT_PROBLEMS),
]
