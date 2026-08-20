"""B31 / AT-B31-01 — tenant isolation, proven rather than declared.

``test_a_positive_only_test_passes_while_the_data_leaks`` is the test this batch
exists for. It builds a database whose row-level security is not forced for the
table owner, shows that the ordinary "tenant A can see its own rows" assertion
still passes, and then shows tenant A reading tenant B's row. That is why every
surface here must name a probe that asserts a denial.

``test_the_cache_key_carries_the_tenant`` covers the surface that actually
leaks. Everybody remembers the database.
"""
from __future__ import annotations

import json

from libs.isolation.reference import probes as P
from tools.paygov import isolation, isolationgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/tenant-isolation.json"


def _surface(model, sid):
    return next(s for s in model["surfaces"] if s["id"] == sid)


class IsolationHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = isolation.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("tenant-isolation", registry.names())

    def test_every_surface_that_leaks_is_covered(self):
        ids = {s["id"] for s in self.fixture.read(REL)["surfaces"]}
        for required in isolation.REQUIRED_SURFACES:
            self.assertIn(required, ids, required)

    def test_every_surface_denies_by_default_and_names_a_tenant_key(self):
        for surface in self.fixture.read(REL)["surfaces"]:
            self.assertEqual(surface["default"], "deny", surface["id"])
            self.assertTrue(surface["tenant_key"], surface["id"])
            self.assertIn(surface["enforced_at"], isolation.ENFORCEMENT_POINTS, surface["id"])

    def test_every_probe_asserts_a_denial_and_runs_in_ci(self):
        for surface in self.fixture.read(REL)["surfaces"]:
            self.assertTrue(surface["probe"]["asserts_denial"], surface["id"])
            self.assertTrue(surface["probe"]["runs_in_ci"], surface["id"])

    def test_probes_are_not_reused_across_surfaces(self):
        surfaces = self.fixture.read(REL)["surfaces"]
        probes = [s["probe"]["id"] for s in surfaces]
        self.assertEqual(len(set(probes)), len(probes))

    def test_every_declared_probe_exists_and_passes(self):
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        results = P.run_probes(model)
        self.assertEqual(set(results), {s["id"] for s in model["surfaces"]})
        self.assertTrue(all(results.values()))

    def test_forced_controls_make_a_missing_predicate_an_error(self):
        forced = self.fixture.read(REL)["forced_controls"]
        self.assertTrue(forced["rls_forced_for_table_owner"])
        self.assertTrue(forced["session_tenant_required"])
        self.assertFalse(forced["application_side_filter_alone_sufficient"])

    def test_the_cross_tenant_permission_is_dual_control_in_b19(self):
        model = self.fixture.read(REL)
        authz = self.fixture.read("governance/authorization.json")
        permission = next(p for p in authz["permissions"]
                          if p["id"] == model["forced_controls"]["cross_tenant_permission"])
        self.assertTrue(permission["dual_control"])

    def test_every_tenant_scoped_table_has_forced_row_level_security(self):
        data = self.fixture.read("governance/data-architecture.json")
        for table in data["tables"]:
            if table.get("tenant_scoped"):
                self.assertTrue(table["rls"]["enabled"], table["table"])
                self.assertTrue(table["rls"]["force_for_owner"], table["table"])

    def test_b13_names_the_session_setting(self):
        tenancy = self.fixture.read("governance/data-architecture.json")["tenancy"]
        self.assertTrue(tenancy["session_setting"])

    def test_b24_still_forbids_cross_tenant_references(self):
        isolation_block = self.fixture.read("governance/tenant-registry.json")["isolation"]
        self.assertTrue(isolation_block["row_level_security_required"])
        self.assertFalse(isolation_block["cross_tenant_reference_allowed"])

    def test_the_cache_and_the_negative_cache_are_both_scoped(self):
        cache = self.fixture.read(REL)["cache"]
        self.assertTrue(cache["key_includes_tenant"])
        self.assertFalse(cache["shared_namespace_allowed"])
        self.assertTrue(cache["negative_cache_scoped"])

    def test_the_consumer_verifies_the_tenant(self):
        messaging = self.fixture.read(REL)["messaging"]
        self.assertTrue(messaging["tenant_in_envelope"])
        self.assertTrue(messaging["consumer_must_verify_tenant"])
        self.assertFalse(messaging["cross_tenant_fanout_allowed"])

    def test_logs_carry_a_tenant_and_are_redacted(self):
        logs = self.fixture.read(REL)["logs"]
        self.assertTrue(logs["tenant_field_required"])
        self.assertTrue(logs["payload_redacted"])
        self.assertTrue(logs["cross_tenant_aggregation_requires_permission"])

    def test_exports_filter_in_the_query_and_verify_the_count(self):
        exports = self.fixture.read(REL)["exports"]
        self.assertTrue(exports["filter_in_query"])
        self.assertTrue(exports["single_tenant_per_export"])
        self.assertTrue(exports["row_count_verified"])

    def test_isolation_events_are_data_access_events(self):
        audit = self.fixture.read("governance/audit-log.json")
        model = self.fixture.read(REL)
        self.assertEqual(model["audit_event_class"], "data.access")
        self.assertIn(model["audit_event_class"], {c["id"] for c in audit["event_classes"]})


class IsolationGeneratedArtefacts(FixtureTestCase):
    def _validate(self):
        return isolation.validate(self.fixture.root, Budget(seconds=60).start())

    def test_generated_artefacts_match_the_model(self):
        for rel, content in isolationgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_carries_every_surface_and_probe(self):
        contract = json.loads(isolationgen.contract_json(REAL_ROOT))
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        self.assertEqual({s["id"] for s in contract["surfaces"]},
                         {s["id"] for s in model["surfaces"]})
        for surface in contract["surfaces"]:
            self.assertTrue(surface["probe"]["asserts_denial"])

    def test_document_shows_every_surface(self):
        text = isolationgen.isolation_markdown(REAL_ROOT)
        for surface in isolation.REQUIRED_SURFACES:
            self.assertIn(surface, text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/tenancy/TENANT_ISOLATION.md", "hand written\n")
        self.assertIn("ISO_GENERATED_DRIFT", self.codes(self._validate()))

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/tenancy/isolation.json")
        self.assertIn("ISO_GENERATED_MISSING", self.codes(self._validate()))

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("surfaces", [{"id": "x"}]))
        self.assertIn("ISO_GENERATED", self.codes(self._validate()))


class IsolationGateRejects(FixtureTestCase):
    def _validate(self):
        return isolation.validate(self.fixture.root, Budget(seconds=60).start())

    def _assert(self, code):
        self.assertIn(code, self.codes(self._validate()))

    def _mutate(self, fn, code, rel=REL):
        self.fixture.mutate(rel, fn)
        self._assert(code)

    # -- shape ------------------------------------------------------------
    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self._assert("ISO_UNREADABLE")

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [1])
        self._assert("ISO_SHAPE")

    def test_rejects_a_bad_schema_version(self):
        self._mutate(lambda d: d.__setitem__("schema_version", "one"), "ISO_VERSION_FIELD")

    def test_rejects_a_missing_principle(self):
        self._mutate(lambda d: d.__setitem__("principle", ""), "ISO_PRINCIPLE")

    def test_rejects_a_non_object_surface(self):
        self._mutate(lambda d: d["surfaces"].append("cache"), "ISO_SHAPE")

    def test_rejects_a_non_object_messaging_block(self):
        self._mutate(lambda d: d.__setitem__("messaging", []), "ISO_SHAPE")

    def test_rejects_a_non_object_logs_block(self):
        self._mutate(lambda d: d.__setitem__("logs", []), "ISO_SHAPE")

    def test_rejects_a_non_object_exports_block(self):
        self._mutate(lambda d: d.__setitem__("exports", []), "ISO_SHAPE")

    # -- surfaces ---------------------------------------------------------
    def test_rejects_a_model_with_no_surfaces(self):
        self._mutate(lambda d: d.__setitem__("surfaces", []), "ISO_NO_SURFACES")

    def test_rejects_a_non_snake_case_surface_id(self):
        self._mutate(lambda d: _surface(d, "cache").__setitem__("id", "Cache Layer"),
                     "ISO_SURFACE_ID")

    def test_rejects_a_duplicate_surface(self):
        self._mutate(lambda d: d["surfaces"].append(dict(_surface(d, "cache"))),
                     "ISO_SURFACE_DUPLICATE")

    def test_rejects_a_surface_with_no_mechanism(self):
        self._mutate(lambda d: _surface(d, "cache").__setitem__("mechanism", ""),
                     "ISO_NO_MECHANISM")

    def test_rejects_an_unknown_enforcement_point(self):
        self._mutate(lambda d: _surface(d, "cache").__setitem__("enforced_at", "vibes"),
                     "ISO_ENFORCEMENT_POINT")

    def test_rejects_a_surface_that_defaults_to_allow(self):
        self._mutate(lambda d: _surface(d, "cache").__setitem__("default", "allow"),
                     "ISO_DEFAULT_ALLOW")

    def test_rejects_a_surface_with_no_tenant_key(self):
        self._mutate(lambda d: _surface(d, "cache").__setitem__("tenant_key", ""),
                     "ISO_NO_TENANT_KEY")

    def test_rejects_a_surface_with_no_probe(self):
        self._mutate(lambda d: _surface(d, "cache").__setitem__("probe", []), "ISO_NO_PROBE")

    def test_rejects_a_probe_with_no_id(self):
        self._mutate(lambda d: _surface(d, "cache")["probe"].__setitem__("id", ""),
                     "ISO_NO_PROBE")

    def test_rejects_one_probe_used_for_two_surfaces(self):
        self._mutate(lambda d: _surface(d, "cache")["probe"].__setitem__(
            "id", _surface(d, "logs")["probe"]["id"]), "ISO_PROBE_DUPLICATE")

    def test_rejects_a_probe_that_only_asserts_its_own_access(self):
        self._mutate(lambda d: _surface(d, "cache")["probe"].__setitem__("asserts_denial",
                                                                         False),
                     "ISO_PROBE_POSITIVE_ONLY")

    def test_rejects_a_probe_that_does_not_run_in_ci(self):
        self._mutate(lambda d: _surface(d, "cache")["probe"].__setitem__("runs_in_ci", False),
                     "ISO_PROBE_NOT_IN_CI")

    def test_rejects_an_unexplained_surface(self):
        self._mutate(lambda d: _surface(d, "cache").__setitem__("notes", ""),
                     "ISO_SURFACE_NOTES")

    def test_rejects_dropping_a_surface_that_leaks(self):
        self._mutate(lambda d: d.__setitem__(
            "surfaces", [s for s in d["surfaces"] if s["id"] != "cache"]),
            "ISO_SURFACE_MISSING")

    # -- forced controls --------------------------------------------------
    def test_rejects_a_missing_forced_controls_block(self):
        self._mutate(lambda d: d.__setitem__("forced_controls", []),
                     "ISO_APPLICATION_FILTER_ONLY")

    def test_rejects_row_level_security_that_spares_the_owner(self):
        self._mutate(lambda d: d["forced_controls"].__setitem__("rls_forced_for_table_owner",
                                                                False),
                     "ISO_RLS_NOT_FORCED")

    def test_rejects_a_query_with_no_tenant_returning_everything(self):
        self._mutate(lambda d: d["forced_controls"].__setitem__("session_tenant_required",
                                                                False),
                     "ISO_NO_SESSION_TENANT")

    def test_rejects_application_side_filtering_as_the_only_control(self):
        self._mutate(lambda d: d["forced_controls"].__setitem__(
            "application_side_filter_alone_sufficient", True), "ISO_APPLICATION_FILTER_ONLY")

    def test_rejects_an_unknown_cross_tenant_permission(self):
        self._mutate(lambda d: d["forced_controls"].__setitem__("cross_tenant_permission",
                                                                "made.up"),
                     "ISO_PERMISSION_UNKNOWN")

    def test_rejects_a_cross_tenant_permission_without_dual_control(self):
        self.fixture.mutate("governance/authorization.json",
                            lambda d: next(p for p in d["permissions"]
                                           if p["id"] == "cross_tenant_data.read")
                            .__setitem__("dual_control", False))
        self._assert("ISO_CROSS_TENANT_SINGLE_PERSON")

    def test_rejects_unexplained_forced_controls(self):
        self._mutate(lambda d: d["forced_controls"].__setitem__("notes", ""),
                     "ISO_FORCED_NOTES")

    # -- cache, messaging, logs, exports ----------------------------------
    def test_rejects_a_cache_key_without_the_tenant(self):
        self._mutate(lambda d: d["cache"].__setitem__("key_includes_tenant", False),
                     "ISO_CACHE_UNSCOPED")

    def test_rejects_a_shared_cache_namespace(self):
        self._mutate(lambda d: d["cache"].__setitem__("shared_namespace_allowed", True),
                     "ISO_CACHE_SHARED")

    def test_rejects_a_shared_negative_cache(self):
        self._mutate(lambda d: d["cache"].__setitem__("negative_cache_scoped", False),
                     "ISO_NEGATIVE_CACHE_SHARED")

    def test_rejects_an_unexplained_cache_policy(self):
        self._mutate(lambda d: d["cache"].__setitem__("notes", ""), "ISO_CACHE_NOTES")

    def test_rejects_a_message_without_a_tenant(self):
        self._mutate(lambda d: d["messaging"].__setitem__("tenant_in_envelope", False),
                     "ISO_TOPIC_UNSCOPED")

    def test_rejects_a_consumer_that_trusts_the_producer(self):
        self._mutate(lambda d: d["messaging"].__setitem__("consumer_must_verify_tenant", False),
                     "ISO_CONSUMER_TRUSTS_PRODUCER")

    def test_rejects_cross_tenant_fanout(self):
        self._mutate(lambda d: d["messaging"].__setitem__("cross_tenant_fanout_allowed", True),
                     "ISO_CROSS_TENANT_FANOUT")

    def test_rejects_an_unexplained_messaging_policy(self):
        self._mutate(lambda d: d["messaging"].__setitem__("notes", ""), "ISO_MESSAGING_NOTES")

    def test_rejects_logs_without_a_tenant_field(self):
        self._mutate(lambda d: d["logs"].__setitem__("tenant_field_required", False),
                     "ISO_LOG_UNSCOPED")

    def test_rejects_unredacted_log_payloads(self):
        self._mutate(lambda d: d["logs"].__setitem__("payload_redacted", False),
                     "ISO_LOG_PAYLOAD")

    def test_rejects_ungated_cross_tenant_log_aggregation(self):
        self._mutate(lambda d: d["logs"].__setitem__(
            "cross_tenant_aggregation_requires_permission", False),
            "ISO_LOG_AGGREGATION_UNGATED")

    def test_rejects_an_unexplained_log_policy(self):
        self._mutate(lambda d: d["logs"].__setitem__("notes", ""), "ISO_LOG_NOTES")

    def test_rejects_filtering_an_export_after_the_fetch(self):
        self._mutate(lambda d: d["exports"].__setitem__("filter_in_query", False),
                     "ISO_EXPORT_FILTER_LATE")

    def test_rejects_a_multi_tenant_export(self):
        self._mutate(lambda d: d["exports"].__setitem__("single_tenant_per_export", False),
                     "ISO_EXPORT_MULTI_TENANT")

    def test_rejects_an_export_nobody_counts(self):
        self._mutate(lambda d: d["exports"].__setitem__("row_count_verified", False),
                     "ISO_EXPORT_UNVERIFIED")

    def test_rejects_an_unexplained_export_policy(self):
        self._mutate(lambda d: d["exports"].__setitem__("notes", ""), "ISO_EXPORT_NOTES")

    # -- evidence and cross-batch -----------------------------------------
    def test_rejects_a_missing_evidence_policy(self):
        self._mutate(lambda d: d.__setitem__("evidence", []), "ISO_NO_EVIDENCE_POLICY")

    def test_rejects_surfaces_without_probes_in_policy(self):
        self._mutate(lambda d: d["evidence"].__setitem__("every_surface_has_probe", False),
                     "ISO_NO_PROBE")

    def test_rejects_a_policy_that_accepts_positive_only_tests(self):
        self._mutate(lambda d: d["evidence"].__setitem__("positive_only_test_is_not_evidence",
                                                         False),
                     "ISO_PROBE_POSITIVE_ONLY")

    def test_rejects_probes_that_do_not_run_in_ci(self):
        self._mutate(lambda d: d["evidence"].__setitem__("probes_run_in_ci", False),
                     "ISO_PROBE_NOT_IN_CI")

    def test_rejects_an_unexplained_evidence_policy(self):
        self._mutate(lambda d: d["evidence"].__setitem__("notes", ""), "ISO_EVIDENCE_NOTES")

    def test_rejects_a_tenant_scoped_table_without_row_level_security(self):
        self.fixture.mutate("governance/data-architecture.json",
                            lambda d: d["tables"][0]["rls"].__setitem__("enabled", False))
        self._assert("ISO_TABLE_WITHOUT_RLS")

    def test_rejects_row_level_security_unforced_in_b13(self):
        self.fixture.mutate("governance/data-architecture.json",
                            lambda d: d["tables"][0]["rls"].__setitem__("force_for_owner",
                                                                        False))
        self._assert("ISO_RLS_NOT_FORCED")

    def test_rejects_b13_without_a_session_setting(self):
        self.fixture.mutate("governance/data-architecture.json",
                            lambda d: d["tenancy"].__setitem__("session_setting", ""))
        self._assert("ISO_NO_SESSION_TENANT")

    def test_rejects_b24_allowing_cross_tenant_references(self):
        self.fixture.mutate("governance/tenant-registry.json",
                            lambda d: d["isolation"].__setitem__(
                                "cross_tenant_reference_allowed", True))
        self._assert("ISO_CROSS_TENANT_REFERENCE")

    def test_rejects_an_unknown_audit_class(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "isolation.vanished"),
                     "ISO_AUDIT_CLASS_UNKNOWN")

    def test_rejects_recording_a_cross_tenant_read_as_something_weaker(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "config.change"),
                     "ISO_AUDIT_CLASS_TOO_WEAK")


class IsolationProbesReferenceModel(FixtureTestCase):
    MODEL = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))

    def world(self):
        database = P.Database()
        a = P.Session(principal="svc", tenant_id="ten_a")
        b = P.Session(principal="svc", tenant_id="ten_b")
        database.insert(a, P.Row("ten_a", "row_a", {"amount_minor": 100}))
        database.insert(b, P.Row("ten_b", "row_b", {"amount_minor": 200}))
        return database, a, b

    def breached(self, fn, code):
        with self.assertRaises(P.IsolationBreach) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    # -- the point of the batch -------------------------------------------
    def test_a_positive_only_test_passes_while_the_data_leaks(self):
        weak = P.Database(force_for_owner=False)
        owner = P.Session(principal="app", tenant_id="ten_a", is_table_owner=True)
        weak.insert(owner, P.Row("ten_a", "row_a", {}))
        weak.insert(P.Session(principal="app", tenant_id="ten_b"), P.Row("ten_b", "row_b", {}))
        rows = weak.select(owner)
        # The assertion a positive-only test would make:
        self.assertTrue(any(r.id == "row_a" for r in rows))
        # ...and the leak it does not notice:
        self.assertTrue(any(r.tenant_id == "ten_b" for r in rows))

    def test_every_probe_in_the_model_exists_and_denies(self):
        results = P.run_probes(self.MODEL)
        self.assertTrue(all(results.values()))

    def test_a_surface_naming_a_missing_probe_is_refused(self):
        model = json.loads(json.dumps(self.MODEL))
        model["surfaces"][0]["probe"]["id"] = "probe_that_does_not_exist"
        self.breached(lambda: P.run_probes(model), P.PROBE_MISSING)

    def test_a_probe_that_fails_to_deny_is_reported(self):
        model = json.loads(json.dumps(self.MODEL))
        model["surfaces"] = [{"id": "always_open", "probe": {"id": "always_open_probe"}}]
        P.PROBES["always_open_probe"] = lambda world: False
        try:
            self.breached(lambda: P.run_probes(model), P.PROBE_DID_NOT_DENY)
        finally:
            P.PROBES.pop("always_open_probe")

    # -- database ---------------------------------------------------------
    def test_a_query_with_no_tenant_fails(self):
        database, _, _ = self.world()
        self.breached(lambda: database.select(P.Session(principal="cron")),
                      P.NO_TENANT_CONTEXT)

    def test_a_cross_tenant_read_is_refused(self):
        database, a, _ = self.world()
        self.breached(lambda: database.get(a, "row_b"), P.CROSS_TENANT_READ)
        self.assertEqual(database.get(a, "row_a").id, "row_a")

    def test_a_cross_tenant_write_is_refused(self):
        database, a, _ = self.world()
        self.breached(lambda: database.insert(a, P.Row("ten_b", "row_x", {})),
                      P.CROSS_TENANT_WRITE)

    def test_the_cross_tenant_grant_is_the_only_way_to_see_everything(self):
        database, a, _ = self.world()
        self.assertEqual(len(database.select(a)), 1)
        granted = P.Session(principal="ops", tenant_id="ten_a", cross_tenant_granted=True)
        self.assertEqual(len(database.select(granted)), 2)

    # -- the surfaces everybody forgets -----------------------------------
    def test_the_cache_key_carries_the_tenant(self):
        cache = P.Cache()
        cache.put("ten_a", "user", "u1", value="A")
        cache.put("ten_b", "user", "u1", value="B")
        self.assertEqual(cache.get("ten_a", "user", "u1"), "A")
        self.assertEqual(cache.get("ten_b", "user", "u1"), "B")
        self.breached(lambda: cache.put(None, "user", "u1", value="X"), P.CACHE_KEY_UNSCOPED)

    def test_the_negative_cache_is_scoped_too(self):
        cache = P.Cache()
        key = cache.put_negative("ten_a", "obj", "o1")
        self.assertTrue(key.startswith("ten_a:"))
        self.assertIsNone(cache.get("ten_b", "obj", "o1"))

    def test_a_message_without_a_tenant_cannot_be_published(self):
        bus = P.MessageBus()
        self.breached(lambda: bus.publish(P.Message("payments", None, {})),
                      P.TOPIC_TENANT_MISSING)

    def test_the_consumer_checks_the_tenant(self):
        bus = P.MessageBus()
        message = bus.publish(P.Message("payments", "ten_a", {"id": "p1"}))
        self.breached(lambda: bus.consume(message, consumer_tenant="ten_b"),
                      P.CONSUMER_TENANT_MISMATCH)
        self.assertEqual(bus.consume(message, consumer_tenant="ten_a"), {"id": "p1"})

    def test_a_log_line_needs_a_tenant_and_only_its_own_rows(self):
        logger = P.Logger()
        self.breached(lambda: logger.log(tenant_id=None, message="x"), P.LOG_TENANT_MISSING)
        self.breached(lambda: logger.log(tenant_id="ten_a", message="failed",
                                         rows=(P.Row("ten_b", "row_b", {}),)),
                      P.LOG_FOREIGN_ROW)
        self.assertEqual(logger.log(tenant_id="ten_a", message="ok",
                                    rows=(P.Row("ten_a", "row_a", {}),))["rows"], ("row_a",))

    def test_an_export_is_one_tenant_filtered_in_the_query_and_counted(self):
        database, a, _ = self.world()
        exporter = P.Exporter(database)
        self.breached(lambda: exporter.export(a, tenants=("ten_a", "ten_b")),
                      P.EXPORT_MULTI_TENANT)
        self.breached(lambda: exporter.export(a, tenants=("ten_a",), filter_in_query=False),
                      P.EXPORT_FILTER_LATE)
        self.assertEqual([r.id for r in exporter.export(a, tenants=("ten_a",))], ["row_a"])

    def test_the_row_count_check_catches_a_filter_in_the_wrong_place(self):
        database, a, _ = self.world()
        exporter = P.Exporter(database)
        leaked = [P.Row("ten_a", "row_a", {}), P.Row("ten_b", "row_b", {})]
        self.breached(lambda: exporter.verify_row_count(leaked, "ten_a"), P.CROSS_TENANT_READ)

    def test_object_storage_is_prefix_scoped(self):
        store = P.ObjectStore()
        store.put("ten_a", "invoice.pdf", b"a")
        store.put("ten_b", "invoice.pdf", b"b")
        session = P.Session(principal="svc", tenant_id="ten_a")
        self.breached(lambda: store.get(session, "ten_b/invoice.pdf"), P.OBJECT_PREFIX_DENIED)
        self.assertEqual(store.get(session, "ten_a/invoice.pdf"), b"a")

    def test_a_background_job_must_be_bound_to_a_tenant(self):
        database, _, _ = self.world()
        runner = P.JobRunner(database)
        self.breached(lambda: runner.run(P.Job(name="nightly")), P.JOB_TENANT_MISSING)
        self.assertEqual(runner.run(P.Job(name="nightly", tenant_id="ten_a")), ["row_a"])
