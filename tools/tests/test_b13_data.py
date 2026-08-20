"""B13 / AT-B13-01 — data ownership, partitioning, tenancy, retention and archival.

Two mistakes make row-level security decorative, and both are tested from both
sides — the gate refusing them, and the reference model showing what they cost:

* RLS without ``FORCE`` leaves the table owner exempt, and operational scripts
  run as the owner. ``test_without_force_the_owner_sees_every_tenant``
  reproduces the leak so ``DATA_RLS_FORCE`` is provably worth having.
* a session with no tenant must be refused, not treated as "all tenants".

``DATA_EVENTING_TABLE`` earns its place: it found a real inconsistency on first
run — B12's inbox named ``inbox_event``, a table no module owns. The registry's
real one is ``provider_webhook_inbox``, owned by ``webhook-ingress``.
"""
from __future__ import annotations

from tools.paygov import data, datagen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class DataArchitectureHappyPath(FixtureTestCase):
    def test_real_architecture_passes(self):
        problems = data.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("data-architecture", registry.names())

    def test_every_owned_table_has_an_architecture_entry(self):
        arch = self.fixture.read("governance/data-architecture.json")
        registry = self.fixture.read("governance/module-registry.json")
        owned = {t for m in registry["modules"] for t in m.get("owned_tables", [])}
        self.assertEqual({t["table"] for t in arch["tables"]}, owned)

    def test_ownership_agrees_with_the_module_registry(self):
        arch = self.fixture.read("governance/data-architecture.json")
        registry = self.fixture.read("governance/module-registry.json")
        owner_of = {t: m["name"] for m in registry["modules"]
                    for t in m.get("owned_tables", [])}
        for table in arch["tables"]:
            self.assertEqual(table["owner"], owner_of[table["table"]], table["table"])

    def test_every_tenant_scoped_table_forces_row_level_security(self):
        arch = self.fixture.read("governance/data-architecture.json")
        scoped = [t for t in arch["tables"] if t["tenant_scoped"]]
        self.assertGreaterEqual(len(scoped), 30)
        for table in scoped:
            self.assertTrue(table["rls"]["enabled"], table["table"])
            self.assertTrue(table["rls"]["force_for_owner"], table["table"])
            self.assertIn("tenant_id", table["rls"]["predicate"], table["table"])

    def test_every_exemption_from_tenant_isolation_is_justified(self):
        arch = self.fixture.read("governance/data-architecture.json")
        for table in arch["tables"]:
            if not table["tenant_scoped"]:
                self.assertTrue(table["rls"].get("reason"), table["table"])

    def test_tenant_scoping_agrees_with_the_domain_model(self):
        arch = self.fixture.read("governance/data-architecture.json")
        domain = self.fixture.read("governance/domain-model.json")
        scoped = {e["table"]: e["tenant_scoped"] for e in domain["entities"]}
        for table in arch["tables"]:
            if table["table"] in scoped:
                self.assertEqual(table["tenant_scoped"], scoped[table["table"]], table["table"])

    def test_movement_tables_are_append_only(self):
        arch = self.fixture.read("governance/data-architecture.json")
        for table in arch["tables"]:
            if table["table"] in data.MOVEMENT_TABLES:
                self.assertEqual(table["mutability"], "append_only", table["table"])

    def test_every_mutable_ledger_family_table_justifies_itself(self):
        arch = self.fixture.read("governance/data-architecture.json")
        for table in arch["tables"]:
            if (data.LEDGER_FAMILY.match(table["table"])
                    and table["table"] not in data.MOVEMENT_TABLES
                    and table["mutability"] != "append_only"):
                self.assertTrue(table.get("mutability_reason"), table["table"])

    def test_every_tenant_table_indexes_and_shards_on_tenant_first(self):
        arch = self.fixture.read("governance/data-architecture.json")
        for table in arch["tables"]:
            if table["tenant_scoped"]:
                self.assertEqual(table["shard_key"][0], "tenant_id", table["table"])
                leads = [i for i in table["indexes"] if i["columns"][0] == "tenant_id"]
                self.assertTrue(leads, table["table"])

    def test_financial_tables_are_retained_for_at_least_seven_years(self):
        arch = self.fixture.read("governance/data-architecture.json")
        for table in arch["tables"]:
            if data.LEDGER_FAMILY.match(table["table"]) or table["table"] in (
                    "payment_intent", "refund", "dispute", "recon_run", "recon_exception"):
                self.assertGreaterEqual(table["retention"]["cold_days"],
                                        data.FINANCIAL_FLOOR_DAYS, table["table"])

    def test_retention_tiers_are_non_decreasing(self):
        arch = self.fixture.read("governance/data-architecture.json")
        for table in arch["tables"]:
            retention = table["retention"]
            self.assertLessEqual(retention["hot_days"], retention["warm_days"], table["table"])
            self.assertLessEqual(retention["warm_days"], retention["cold_days"], table["table"])

    def test_every_personal_column_has_a_deletion_strategy(self):
        arch = self.fixture.read("governance/data-architecture.json")
        allowed = set(arch["deletion_strategies"])
        found = 0
        for table in arch["tables"]:
            if table.get("personal_columns"):
                found += 1
                self.assertIn(table["deletion_strategy"], allowed, table["table"])
        self.assertGreater(found, 0)

    def test_the_eventing_tables_really_exist_and_are_owned_as_declared(self):
        """The cross-check that caught B12 naming a table nobody owns."""
        arch = self.fixture.read("governance/data-architecture.json")
        catalog = self.fixture.read("governance/event-catalog.json")
        owner_of = {t["table"]: t["owner"] for t in arch["tables"]}
        for section in ("outbox", "inbox"):
            block = catalog[section]
            self.assertIn(block["table"], owner_of, section)
            self.assertEqual(owner_of[block["table"]], block["owner"], section)

    def test_the_break_glass_path_exists_and_is_constrained(self):
        arch = self.fixture.read("governance/data-architecture.json")
        hatch = arch["tenancy"]["escape_hatch"]
        self.assertTrue(hatch["role"])
        self.assertTrue(hatch["requires_audit_event"])
        self.assertTrue(hatch["requires_second_approver"])
        self.assertLessEqual(hatch["max_session_minutes"], 240)

    def test_generated_artefacts_match_the_architecture(self):
        for rel, content in datagen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_generated_rls_ddl_forces_the_policy_on_every_tenant_table(self):
        sql = datagen.rls_sql(REAL_ROOT)
        arch = self.fixture.read("governance/data-architecture.json")
        for table in arch["tables"]:
            if table["tenant_scoped"]:
                self.assertIn(f"ALTER TABLE {table['table']} FORCE ROW LEVEL SECURITY;", sql)
                self.assertIn(f"CREATE POLICY {table['rls']['policy']} ON {table['table']}", sql)

    def test_generated_rls_ddl_revokes_writes_on_append_only_tables(self):
        sql = datagen.rls_sql(REAL_ROOT)
        arch = self.fixture.read("governance/data-architecture.json")
        for table in arch["tables"]:
            if table["mutability"] == "append_only":
                self.assertIn(f"REVOKE UPDATE, DELETE ON {table['table']} FROM PUBLIC;", sql)


class DataGateRejects(FixtureTestCase):
    REL = "governance/data-architecture.json"

    def _validate(self):
        return data.validate(self.fixture.root, Budget(seconds=60).start())

    def _table(self, d, name):
        return next(t for t in d["tables"] if t["table"] == name)

    def test_rejects_unreadable_architecture(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("DATA_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("DATA_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_an_empty_table_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("tables", []))
        self.assertIn("DATA_SHAPE", self.codes(self._validate()))

    def test_rejects_removing_the_mutability_kinds(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("mutability_kinds", ["mutable"]))
        self.assertIn("DATA_SHAPE", self.codes(self._validate()))

    def test_rejects_removing_the_partition_kinds(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("partition_kinds", []))
        self.assertIn("DATA_SHAPE", self.codes(self._validate()))

    def test_rejects_removing_the_deletion_strategies(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("deletion_strategies", []))
        self.assertIn("DATA_SHAPE", self.codes(self._validate()))

    def test_rejects_renaming_the_tenant_column(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["tenancy"].__setitem__("tenant_column", "org_id"))
        problems = self._validate()
        self.assertIn("DATA_TENANCY", self.codes(problems))
        self.assertIn("NN-09", self.rules(problems))

    def test_rejects_dropping_the_session_setting(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["tenancy"].__setitem__("session_setting", ""))
        self.assertIn("DATA_TENANCY", self.codes(self._validate()))

    def test_rejects_an_unwritten_tenancy_policy(self):
        self.fixture.mutate(self.REL, lambda d: d["tenancy"].__setitem__("policy", ""))
        self.assertIn("DATA_TENANCY", self.codes(self._validate()))

    def test_rejects_removing_the_break_glass_role(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["tenancy"]["escape_hatch"].__setitem__("role", ""))
        problems = self._validate()
        self.assertIn("DATA_BREAK_GLASS", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_unaudited_break_glass_access(self):
        self.fixture.mutate(self.REL, lambda d: d["tenancy"]["escape_hatch"].__setitem__(
            "requires_audit_event", False))
        self.assertIn("DATA_BREAK_GLASS", self.codes(self._validate()))

    def test_rejects_single_approver_break_glass(self):
        self.fixture.mutate(self.REL, lambda d: d["tenancy"]["escape_hatch"].__setitem__(
            "requires_second_approver", False))
        self.assertIn("DATA_BREAK_GLASS", self.codes(self._validate()))

    def test_rejects_a_break_glass_session_that_never_expires(self):
        self.fixture.mutate(self.REL, lambda d: d["tenancy"]["escape_hatch"].__setitem__(
            "max_session_minutes", 0))
        self.assertIn("DATA_BREAK_GLASS", self.codes(self._validate()))

    def test_rejects_an_archive_without_an_integrity_manifest(self):
        self.fixture.mutate(self.REL, lambda d: d["archive"].__setitem__("integrity", ""))
        self.assertIn("DATA_ARCHIVE_POLICY", self.codes(self._validate()))

    def test_rejects_an_archive_without_a_destination_scheme(self):
        self.fixture.mutate(self.REL, lambda d: d["archive"].__setitem__("target_scheme", ""))
        self.assertIn("DATA_ARCHIVE_POLICY", self.codes(self._validate()))

    def test_rejects_an_unwritten_archive_policy(self):
        self.fixture.mutate(self.REL, lambda d: d["archive"].__setitem__("policy", ""))
        self.assertIn("DATA_ARCHIVE_POLICY", self.codes(self._validate()))

    def test_rejects_a_shard_key_that_is_not_the_tenant(self):
        self.fixture.mutate(self.REL, lambda d: d["sharding"].__setitem__("key", "created_at"))
        self.assertIn("DATA_SHARDING", self.codes(self._validate()))

    def test_rejects_an_unstated_sharding_stance(self):
        self.fixture.mutate(self.REL, lambda d: d["sharding"].__setitem__("policy", ""))
        self.assertIn("DATA_SHARDING", self.codes(self._validate()))

    def test_rejects_a_tenant_table_without_row_level_security(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "payment_intent")["rls"]
                            .__setitem__("enabled", False))
        problems = self._validate()
        self.assertIn("DATA_RLS_MISSING", self.codes(problems))
        self.assertIn("NN-09", self.rules(problems))

    def test_rejects_row_level_security_that_is_not_forced(self):
        """The exemption applies to the owner, and scripts run as the owner."""
        self.fixture.mutate(self.REL, lambda d: self._table(d, "payment_intent")["rls"]
                            .__setitem__("force_for_owner", False))
        self.assertIn("DATA_RLS_FORCE", self.codes(self._validate()))

    def test_rejects_a_policy_predicate_that_ignores_the_tenant(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "payment_intent")["rls"]
                            .__setitem__("predicate", "true"))
        self.assertIn("DATA_RLS_PREDICATE", self.codes(self._validate()))

    def test_rejects_an_unnamed_policy(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "payment_intent")["rls"].__setitem__(
                                "policy", ""))
        self.assertIn("DATA_RLS_MISSING", self.codes(self._validate()))

    def test_rejects_an_unjustified_isolation_exemption(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "tenant")["rls"].__setitem__("reason", ""))
        self.assertIn("DATA_RLS_EXEMPTION", self.codes(self._validate()))

    def test_rejects_a_non_tenant_table_leaving_rls_ambiguous(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "tenant")["rls"].pop("enabled"))
        self.assertIn("DATA_RLS_MISSING", self.codes(self._validate()))

    def test_rejects_tenant_scoping_that_disagrees_with_the_domain_model(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "payment_intent").__setitem__(
            "tenant_scoped", False))
        self.assertIn("DATA_TENANT_FLAG", self.codes(self._validate()))

    def test_rejects_an_undeclared_tenant_flag(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "job_run").__setitem__("tenant_scoped", "y"))
        self.assertIn("DATA_TENANT_FLAG", self.codes(self._validate()))

    def test_rejects_a_mutable_ledger_entry(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "ledger_entry").__setitem__(
            "mutability", "mutable"))
        problems = self._validate()
        self.assertIn("DATA_LEDGER_MUTABLE", self.codes(problems))
        self.assertIn("NN-06", self.rules(problems))

    def test_rejects_an_unjustified_mutable_ledger_family_table(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "ledger_account").pop("mutability_reason"))
        self.assertIn("DATA_LEDGER_MUTABLE_UNJUSTIFIED", self.codes(self._validate()))

    def test_rejects_an_unknown_mutability(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "job_run").__setitem__(
            "mutability", "sort_of"))
        self.assertIn("DATA_MUTABILITY", self.codes(self._validate()))

    def test_rejects_a_table_owned_by_the_wrong_module(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "payment_intent").__setitem__(
            "owner", "risk-engine"))
        problems = self._validate()
        self.assertIn("DATA_OWNER", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_a_table_no_module_owns(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "job_run").__setitem__(
            "table", "mystery_table"))
        self.assertIn("DATA_TABLE_UNKNOWN", self.codes(self._validate()))

    def test_rejects_a_bad_table_name(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "job_run").__setitem__("table", "Job Run"))
        self.assertIn("DATA_TABLE_NAME", self.codes(self._validate()))

    def test_rejects_a_duplicate_table_entry(self):
        self.fixture.mutate(self.REL, lambda d: d["tables"].append(
            dict(self._table(d, "job_run"))))
        self.assertIn("DATA_TABLE_DUPLICATE", self.codes(self._validate()))

    def test_rejects_dropping_a_table_from_the_architecture(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "tables", [t for t in d["tables"] if t["table"] != "job_run"]))
        self.assertIn("DATA_TABLE_UNSPECIFIED", self.codes(self._validate()))

    def test_rejects_an_unknown_partition_kind(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "job_run")["partition"]
                            .__setitem__("kind", "vibes"))
        self.assertIn("DATA_PARTITION", self.codes(self._validate()))

    def test_rejects_a_partitioned_table_without_a_key(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "job_run")["partition"].pop("key"))
        self.assertIn("DATA_PARTITION", self.codes(self._validate()))

    def test_rejects_range_partitioning_without_an_interval(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "job_run")["partition"]
                            .__setitem__("interval", ""))
        self.assertIn("DATA_PARTITION", self.codes(self._validate()))

    def test_rejects_an_unexplained_partitioning_decision(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "job_run")["partition"].__setitem__(
                                "reason", ""))
        self.assertIn("DATA_PARTITION_REASON", self.codes(self._validate()))

    def test_rejects_retention_tiers_that_go_backwards(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "job_run")["retention"]
                            .__setitem__("cold_days", 1))
        self.assertIn("DATA_RETENTION_ORDER", self.codes(self._validate()))

    def test_rejects_archiving_before_the_hot_window_expires(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "payment_intent")["retention"]
                            .__setitem__("archive_after_days", 1))
        self.assertIn("DATA_RETENTION_ORDER", self.codes(self._validate()))

    def test_rejects_shortening_financial_retention(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "ledger_entry")["retention"]
                            .update({"hot_days": 30, "warm_days": 60, "cold_days": 90,
                                     "archive_after_days": 90}))
        problems = self._validate()
        self.assertIn("DATA_RETENTION_FLOOR", self.codes(problems))
        self.assertIn("NN-06", self.rules(problems))

    def test_rejects_archival_with_nowhere_to_go(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "job_run")["retention"]
                            .__setitem__("archive_target", ""))
        self.assertIn("DATA_ARCHIVE_TARGET", self.codes(self._validate()))

    def test_rejects_a_table_with_no_indexes(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "job_run").__setitem__("indexes", []))
        self.assertIn("DATA_INDEX", self.codes(self._validate()))

    def test_rejects_a_nameless_index(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "job_run")["indexes"][0]
                            .__setitem__("name", "Job Run Idx"))
        self.assertIn("DATA_INDEX", self.codes(self._validate()))

    def test_rejects_an_index_with_no_columns(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "job_run")["indexes"][0]
                            .__setitem__("columns", []))
        self.assertIn("DATA_INDEX", self.codes(self._validate()))

    def test_rejects_a_tenant_table_whose_index_does_not_lead_with_tenant(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "payment_intent")["indexes"][0]
                            .__setitem__("columns", ["created_at", "tenant_id"]))
        self.assertIn("DATA_INDEX_TENANT", self.codes(self._validate()))

    def test_rejects_a_tenant_table_that_could_not_be_sharded_by_tenant(self):
        self.fixture.mutate(self.REL, lambda d: self._table(d, "payment_intent").__setitem__(
            "shard_key", ["created_at"]))
        self.assertIn("DATA_SHARD_KEY", self.codes(self._validate()))

    def test_rejects_personal_data_with_no_deletion_strategy(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "merchant").pop("deletion_strategy"))
        problems = self._validate()
        self.assertIn("DATA_DELETION_STRATEGY", self.codes(problems))
        self.assertIn("NN-14", self.rules(problems))

    def test_rejects_a_table_entry_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["tables"].append("job_run"))
        self.assertIn("DATA_SHAPE", self.codes(self._validate()))

    def test_rejects_an_index_that_is_not_an_object(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._table(d, "job_run")["indexes"].append("idx"))
        self.assertIn("DATA_SHAPE", self.codes(self._validate()))

    def test_rejects_an_eventing_table_that_does_not_exist(self):
        """The cross-check that caught B12 naming a table nobody owns."""
        self.fixture.mutate("governance/event-catalog.json",
                            lambda d: d["inbox"].__setitem__("table", "inbox_event"))
        problems = self._validate()
        self.assertIn("DATA_EVENTING_TABLE", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_an_eventing_table_owned_by_the_wrong_module(self):
        self.fixture.mutate("governance/event-catalog.json",
                            lambda d: d["outbox"].__setitem__("owner", "risk-engine"))
        self.assertIn("DATA_EVENTING_OWNER", self.codes(self._validate()))

    def test_rejects_missing_generated_artefacts(self):
        self.fixture.remove("contracts/sql/rls.sql")
        self.assertIn("DATA_GENERATED_MISSING", self.codes(self._validate()))

    def test_rejects_a_hand_edited_generated_artefact(self):
        path = self.fixture.root / "contracts/sql/rls.sql"
        path.write_text(path.read_text(encoding="utf-8").replace(
            "FORCE ROW LEVEL SECURITY", "-- FORCE ROW LEVEL SECURITY"), encoding="utf-8")
        self.assertIn("DATA_GENERATED_DRIFT", self.codes(self._validate()))

    def test_fails_closed_when_the_artefacts_cannot_be_generated(self):
        """A gate must turn a broken architecture into a finding, not into a crash."""
        self.fixture.mutate(self.REL, lambda d: self._table(d, "job_run").pop("retention"))
        self.assertIn("DATA_GENERATED", self.codes(self._validate()))


class TenantIsolationReference(FixtureTestCase):
    """What the DDL claims, executed — because there is no database here."""

    A, B = "tenant-a", "tenant-b"

    def setUp(self):
        super().setUp()
        from libs.tenancy.reference import isolation
        self.isolation = isolation
        self.arch = self.fixture.read("governance/data-architecture.json")

    def _seeded(self, spec):
        table = self.isolation.build(spec)
        table.rows.extend([{"tenant_id": self.A, "id": "row-a"},
                           {"tenant_id": self.B, "id": "row-b"}])
        return table

    def test_no_tenant_scoped_table_leaks_across_tenants(self):
        scoped = [t for t in self.arch["tables"] if t["tenant_scoped"]]
        self.assertGreaterEqual(len(scoped), 30)
        for spec in scoped:
            table = self._seeded(spec)
            self.assertEqual([r["id"] for r in table.select("app_user", tenant=self.A)],
                             ["row-a"], spec["table"])

    def test_a_write_for_another_tenant_is_rejected(self):
        table = self._seeded(next(t for t in self.arch["tables"] if t["table"] == "payment_intent"))
        with self.assertRaises(self.isolation.NotPermitted):
            table.insert("app_user", {"tenant_id": self.B, "id": "row-c"}, tenant=self.A)

    def test_a_session_without_a_tenant_is_refused_not_widened(self):
        table = self._seeded(next(t for t in self.arch["tables"] if t["table"] == "payment_intent"))
        with self.assertRaises(self.isolation.TenantNotSet):
            table.select("app_user", tenant=None)

    def test_without_force_the_owner_sees_every_tenant(self):
        """Reproduces the leak DATA_RLS_FORCE exists to prevent."""
        table = self.isolation.Table(
            name="payment_intent", owner_role="app_owner",
            policy=self.isolation.Policy(name="weak", force_for_owner=False))
        table.rows.extend([{"tenant_id": self.A, "id": "row-a"},
                           {"tenant_id": self.B, "id": "row-b"}])
        self.assertEqual(len(table.select("app_owner", tenant=self.A)), 2)

    def test_with_force_the_owner_is_confined_like_everyone_else(self):
        table = self.isolation.Table(
            name="payment_intent", owner_role="app_owner",
            policy=self.isolation.Policy(name="strong", force_for_owner=True))
        table.rows.extend([{"tenant_id": self.A, "id": "row-a"},
                           {"tenant_id": self.B, "id": "row-b"}])
        self.assertEqual([r["id"] for r in table.select("app_owner", tenant=self.A)], ["row-a"])

    def test_append_only_tables_refuse_update_and_delete(self):
        append_only = [t for t in self.arch["tables"] if t["mutability"] == "append_only"]
        self.assertGreaterEqual(len(append_only), 10)
        for spec in append_only:
            table = self._seeded(spec)
            with self.assertRaises(self.isolation.NotPermitted, msg=spec["table"]):
                table.update("app_user", {"id": "row-a"}, {"id": "x"}, tenant=self.A)
            with self.assertRaises(self.isolation.NotPermitted, msg=spec["table"]):
                table.delete("app_user", {"id": "row-a"}, tenant=self.A)

    def test_mutable_tables_still_only_touch_their_own_tenant(self):
        mutable = [t for t in self.arch["tables"]
                   if t["mutability"] == "mutable" and t["tenant_scoped"]]
        for spec in mutable:
            table = self._seeded(spec)
            self.assertEqual(table.delete("app_user", {"id": "row-b"}, tenant=self.A), 0,
                             spec["table"])
            self.assertEqual(table.update("app_user", {"id": "row-b"}, {"id": "x"},
                                          tenant=self.A), 0, spec["table"])

    def test_break_glass_crosses_tenants_which_is_why_it_is_audited(self):
        table = self._seeded(next(t for t in self.arch["tables"] if t["table"] == "payment_intent"))
        self.assertEqual(len(table.select("platform_break_glass")), 2)
