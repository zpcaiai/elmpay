"""B15 / AT-B15-01 — migrating an existing project onto the payment platform.

The principle is one sentence — business orders stay put, only payment facts and
payment actions move — and every rule here defends a way it gets lost.

The two that matter most are tested from both sides, gate and reference model:

* ``MIG_DOUBLE_CHARGE`` — "dual write" is the phrase under which a project
  accidentally calls the provider twice. In the model the provider is a counter,
  and ``test_every_phase_calls_the_provider_exactly_once`` runs all four phases
  against it.
* ``MIG_ROLLBACK_DESTRUCTIVE`` — a rollback that discards the other side's
  records is a second migration performed under pressure.
  ``test_rolling_all_the_way_back_preserves_every_payment_fact`` walks the phases
  forward and back and counts.
"""
from __future__ import annotations

from tools.paygov import miggen, migration
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class MigrationPlanHappyPath(FixtureTestCase):
    def test_real_plan_passes(self):
        problems = migration.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("migration-plan", registry.names())

    def test_business_order_concepts_never_become_platform_tables(self):
        plan = self.fixture.read("governance/migration-plan.json")
        domain = self.fixture.read("governance/domain-model.json")
        tables = {e["table"] for e in domain["entities"]}
        self.assertGreaterEqual(len(plan["ownership"]["legacy_owns"]), 5)
        for name in plan["ownership"]["legacy_owns"]:
            self.assertNotIn(name, tables, name)

    def test_every_platform_owned_concept_is_a_real_table(self):
        plan = self.fixture.read("governance/migration-plan.json")
        domain = self.fixture.read("governance/domain-model.json")
        tables = {e["table"] for e in domain["entities"]}
        for name in plan["ownership"]["platform_owns"]:
            self.assertIn(name, tables, name)

    def test_the_two_systems_are_bound_only_by_external_reference(self):
        plan = self.fixture.read("governance/migration-plan.json")
        binding = plan["ownership"]["binding"]
        self.assertEqual(binding["field"], "external_reference")
        self.assertEqual(set(binding["uniqueness"]), {"project_id", "external_reference"})

    def test_the_platform_never_reaches_into_the_legacy_database(self):
        plan = self.fixture.read("governance/migration-plan.json")
        self.assertIs(plan["legacy_database_access"]["allowed"], False)

    def test_every_adapter_operation_exists_in_the_api_contract(self):
        plan = self.fixture.read("governance/migration-plan.json")
        contract = self.fixture.read("governance/api-contract.json")
        operations = {o["id"] for o in contract["operations"]}
        self.assertGreaterEqual(len(plan["adapter"]["operations"]), 3)
        for entry in plan["adapter"]["operations"]:
            self.assertIn(entry["platform_operation"], operations)
            self.assertEqual(entry["idempotency_source"], "external_reference")

    def test_no_adapter_field_carries_order_line_data(self):
        plan = self.fixture.read("governance/migration-plan.json")
        for entry in plan["adapter"]["operations"]:
            for field in entry["passes_through"]:
                for term in migration.BUSINESS_TERMS:
                    self.assertNotIn(term, field.lower(), f"{entry['legacy_action']}:{field}")

    def test_dual_write_means_one_provider_call(self):
        plan = self.fixture.read("governance/migration-plan.json")
        self.assertEqual(plan["dual_write"]["provider_calls_per_payment"], 1)

    def test_divergence_detection_compares_the_amount(self):
        plan = self.fixture.read("governance/migration-plan.json")
        detection = plan["dual_write"]["divergence_detection"]
        self.assertIn("amount_minor", detection["compare_fields"])
        self.assertGreater(detection["window_minutes"], 0)
        self.assertTrue(detection["abort_rule"])

    def test_phases_advance_and_never_go_sideways(self):
        plan = self.fixture.read("governance/migration-plan.json")
        modes = [p["write_mode"] for p in plan["phases"]]
        self.assertEqual(modes, [m for m in migration.WRITE_MODES if m in modes])
        self.assertEqual(modes[0], "legacy_only")
        self.assertEqual(modes[-1], "platform_only")

    def test_exactly_one_system_is_authoritative_in_every_phase(self):
        plan = self.fixture.read("governance/migration-plan.json")
        for phase in plan["phases"]:
            self.assertIn(phase["authoritative_for_payment_facts"], migration.AUTHORITIES)

    def test_every_phase_has_criteria_evidence_and_a_safe_rollback(self):
        plan = self.fixture.read("governance/migration-plan.json")
        for phase in plan["phases"]:
            self.assertTrue(phase["entry_criteria"], phase["id"])
            self.assertTrue(phase["exit_criteria"], phase["id"])
            self.assertTrue(phase["evidence_gate"], phase["id"])
            self.assertIs(phase["rollback"]["payment_facts_preserved"], True, phase["id"])

    def test_the_backfill_is_idempotent_resumable_and_read_only(self):
        plan = self.fixture.read("governance/migration-plan.json")
        backfill = plan["backfill"]
        self.assertIs(backfill["idempotent"], True)
        self.assertIs(backfill["resumable"], True)
        self.assertIs(backfill["read_only_on_legacy"], True)
        self.assertTrue(any("sum" in m for m in backfill["verification"]["method"]))

    def test_cutover_is_per_project_with_a_fast_kill_switch(self):
        plan = self.fixture.read("governance/migration-plan.json")
        self.assertEqual(plan["cutover"]["granularity"], "project")
        switch = plan["cutover"]["kill_switch"]
        self.assertLessEqual(switch["max_activation_seconds"], 300)
        self.assertIs(switch["requires_audit_event"], True)

    def test_generated_artefacts_match_the_plan(self):
        for rel, content in miggen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)


class MigrationGateRejects(FixtureTestCase):
    REL = "governance/migration-plan.json"

    def _validate(self):
        return migration.validate(self.fixture.root, Budget(seconds=60).start())

    def _phase(self, d, pid):
        return next(p for p in d["phases"] if p["id"] == pid)

    def test_rejects_unreadable_plan(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("MIG_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("MIG_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_dropping_the_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("MIG_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_an_empty_ownership_split(self):
        self.fixture.mutate(self.REL, lambda d: d["ownership"].__setitem__("legacy_owns", []))
        self.assertIn("MIG_OWNERSHIP", self.codes(self._validate()))

    def test_rejects_an_empty_platform_side(self):
        self.fixture.mutate(self.REL, lambda d: d["ownership"].__setitem__("platform_owns", []))
        self.assertIn("MIG_OWNERSHIP", self.codes(self._validate()))

    def test_rejects_a_concept_owned_by_both_systems(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["ownership"]["platform_owns"].append("business_order"))
        self.assertIn("MIG_OWNERSHIP_OVERLAP", self.codes(self._validate()))

    def test_rejects_a_legacy_concept_that_became_a_platform_table(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["ownership"]["legacy_owns"].append("payment_intent"))
        problems = self._validate()
        self.assertIn("MIG_LEGACY_IN_PLATFORM", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_a_platform_concept_with_no_table(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["ownership"]["platform_owns"].append("wormhole"))
        self.assertIn("MIG_PLATFORM_MISSING", self.codes(self._validate()))

    def test_rejects_binding_by_anything_other_than_the_order_reference(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["ownership"]["binding"].__setitem__("field", "order_id"))
        self.assertIn("MIG_BINDING", self.codes(self._validate()))

    def test_rejects_a_binding_that_is_not_unique_per_project(self):
        self.fixture.mutate(self.REL, lambda d: d["ownership"]["binding"].__setitem__(
            "uniqueness", ["external_reference"]))
        self.assertIn("MIG_BINDING", self.codes(self._validate()))

    def test_rejects_giving_the_platform_legacy_database_access(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["legacy_database_access"].__setitem__("allowed", True))
        problems = self._validate()
        self.assertIn("MIG_LEGACY_DB_ACCESS", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_an_unexplained_legacy_access_policy(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["legacy_database_access"].__setitem__("policy", ""))
        self.assertIn("MIG_LEGACY_DB_ACCESS", self.codes(self._validate()))

    def test_rejects_an_ownerless_adapter(self):
        self.fixture.mutate(self.REL, lambda d: d["adapter"].__setitem__("owner", ""))
        self.assertIn("MIG_ADAPTER_OWNER", self.codes(self._validate()))

    def test_rejects_moving_the_adapter_into_the_platform_repository(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["adapter"].__setitem__("location", "平台仓库 services/"))
        self.assertIn("MIG_ADAPTER_LOCATION", self.codes(self._validate()))

    def test_rejects_an_adapter_operation_that_is_not_in_the_api(self):
        self.fixture.mutate(self.REL, lambda d: d["adapter"]["operations"][0].__setitem__(
            "platform_operation", "teleport_payment"))
        self.assertIn("MIG_ADAPTER_OPERATION", self.codes(self._validate()))

    def test_rejects_an_adapter_that_invents_its_own_idempotency_key(self):
        self.fixture.mutate(self.REL, lambda d: d["adapter"]["operations"][0].__setitem__(
            "idempotency_source", "uuid4()"))
        problems = self._validate()
        self.assertIn("MIG_ADAPTER_IDEMPOTENCY", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_an_adapter_passing_order_line_data(self):
        self.fixture.mutate(self.REL, lambda d: d["adapter"]["operations"][0]["passes_through"]
                            .append("sku_list"))
        problems = self._validate()
        self.assertIn("MIG_ADAPTER_LEAK", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_emptying_the_adapter_forbidden_list(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["adapter"].__setitem__("forbidden_passthrough", []))
        self.assertIn("MIG_ADAPTER_FORBIDDEN_LIST", self.codes(self._validate()))

    def test_rejects_an_adapter_with_no_operations(self):
        self.fixture.mutate(self.REL, lambda d: d["adapter"].__setitem__("operations", []))
        self.assertIn("MIG_ADAPTER_OPERATIONS", self.codes(self._validate()))

    def test_rejects_an_adapter_operation_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["adapter"]["operations"].append("refund"))
        self.assertIn("MIG_SHAPE", self.codes(self._validate()))

    def test_rejects_two_provider_calls_per_payment(self):
        """The whole point of the batch, stated as a number."""
        self.fixture.mutate(self.REL, lambda d: d["dual_write"].__setitem__(
            "provider_calls_per_payment", 2))
        problems = self._validate()
        self.assertIn("MIG_DOUBLE_CHARGE", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_dual_write_without_divergence_detection(self):
        self.fixture.mutate(self.REL, lambda d: d["dual_write"]["divergence_detection"]
                            .__setitem__("compare_fields", []))
        self.assertIn("MIG_DIVERGENCE", self.codes(self._validate()))

    def test_rejects_divergence_detection_that_ignores_the_amount(self):
        self.fixture.mutate(self.REL, lambda d: d["dual_write"]["divergence_detection"]
                            .__setitem__("compare_fields", ["status"]))
        problems = self._validate()
        self.assertIn("MIG_DIVERGENCE", self.codes(problems))
        self.assertIn("NN-05", self.rules(problems))

    def test_rejects_a_divergence_budget_with_no_abort_rule(self):
        self.fixture.mutate(self.REL, lambda d: d["dual_write"]["divergence_detection"]
                            .__setitem__("abort_rule", ""))
        self.assertIn("MIG_DIVERGENCE_ABORT", self.codes(self._validate()))

    def test_rejects_an_unbounded_divergence_budget(self):
        self.fixture.mutate(self.REL, lambda d: d["dual_write"]["divergence_detection"]
                            .__setitem__("budget_pct", 50))
        self.assertIn("MIG_DIVERGENCE", self.codes(self._validate()))

    def test_rejects_an_unwritten_dual_write_policy(self):
        self.fixture.mutate(self.REL, lambda d: d["dual_write"].__setitem__("policy", ""))
        self.assertIn("MIG_DUAL_WRITE_POLICY", self.codes(self._validate()))

    def test_rejects_a_non_idempotent_backfill(self):
        self.fixture.mutate(self.REL, lambda d: d["backfill"].__setitem__("idempotent", False))
        self.assertIn("MIG_BACKFILL", self.codes(self._validate()))

    def test_rejects_a_backfill_that_cannot_resume(self):
        self.fixture.mutate(self.REL, lambda d: d["backfill"].__setitem__("resumable", False))
        self.assertIn("MIG_BACKFILL", self.codes(self._validate()))

    def test_rejects_a_backfill_that_writes_to_the_legacy_system(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["backfill"].__setitem__("read_only_on_legacy", False))
        problems = self._validate()
        self.assertIn("MIG_BACKFILL_WRITES", self.codes(problems))
        self.assertIn("NN-06", self.rules(problems))

    def test_rejects_verification_by_sampling_alone(self):
        self.fixture.mutate(self.REL, lambda d: d["backfill"]["verification"].__setitem__(
            "method", ["random_sample_1000"]))
        self.assertIn("MIG_BACKFILL_VERIFICATION", self.codes(self._validate()))

    def test_rejects_verification_with_no_tolerance(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["backfill"]["verification"].__setitem__("tolerance", ""))
        self.assertIn("MIG_BACKFILL_VERIFICATION", self.codes(self._validate()))

    def test_rejects_a_global_cutover(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["cutover"].__setitem__("granularity", "global"))
        self.assertIn("MIG_CUTOVER_GRANULARITY", self.codes(self._validate()))

    def test_rejects_a_kill_switch_that_takes_a_deploy(self):
        self.fixture.mutate(self.REL, lambda d: d["cutover"]["kill_switch"].__setitem__(
            "max_activation_seconds", 7200))
        self.assertIn("MIG_KILL_SWITCH", self.codes(self._validate()))

    def test_rejects_an_unaudited_kill_switch(self):
        self.fixture.mutate(self.REL, lambda d: d["cutover"]["kill_switch"].__setitem__(
            "requires_audit_event", False))
        problems = self._validate()
        self.assertIn("MIG_KILL_SWITCH", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_a_kill_switch_with_no_scope(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["cutover"]["kill_switch"].__setitem__("scope", ""))
        self.assertIn("MIG_KILL_SWITCH", self.codes(self._validate()))

    def test_rejects_an_empty_phase_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("phases", []))
        self.assertIn("MIG_SHAPE", self.codes(self._validate()))

    def test_rejects_a_phase_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["phases"].append("P4"))
        self.assertIn("MIG_SHAPE", self.codes(self._validate()))

    def test_rejects_duplicate_phase_ids(self):
        self.fixture.mutate(self.REL, lambda d: d["phases"].append(dict(self._phase(d, "P3"))))
        self.assertIn("MIG_PHASE_DUPLICATE", self.codes(self._validate()))

    def test_rejects_an_unknown_write_mode(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._phase(d, "P1").__setitem__("write_mode", "vibes"))
        self.assertIn("MIG_WRITE_MODE", self.codes(self._validate()))

    def test_rejects_phases_that_go_backwards(self):
        self.fixture.mutate(self.REL, lambda d: self._phase(d, "P2").__setitem__(
            "write_mode", "legacy_only"))
        self.assertIn("MIG_PHASE_ORDER", self.codes(self._validate()))

    def test_rejects_a_plan_that_does_not_start_from_legacy_only(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "phases", [p for p in d["phases"] if p["id"] != "P0"]))
        self.assertIn("MIG_PHASE_ORDER", self.codes(self._validate()))

    def test_rejects_a_plan_that_never_reaches_platform_only(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "phases", [p for p in d["phases"] if p["id"] != "P3"]))
        self.assertIn("MIG_PHASE_ORDER", self.codes(self._validate()))

    def test_rejects_an_undeclared_authority(self):
        self.fixture.mutate(self.REL, lambda d: self._phase(d, "P1").__setitem__(
            "authoritative_for_payment_facts", "both"))
        self.assertIn("MIG_AUTHORITY", self.codes(self._validate()))

    def test_rejects_the_platform_being_authoritative_before_it_writes(self):
        self.fixture.mutate(self.REL, lambda d: self._phase(d, "P0").__setitem__(
            "authoritative_for_payment_facts", "platform"))
        self.assertIn("MIG_AUTHORITY", self.codes(self._validate()))

    def test_rejects_the_legacy_system_staying_authoritative_at_the_end(self):
        self.fixture.mutate(self.REL, lambda d: self._phase(d, "P3").__setitem__(
            "authoritative_for_payment_facts", "legacy"))
        self.assertIn("MIG_AUTHORITY", self.codes(self._validate()))

    def test_rejects_a_phase_with_no_exit_criteria(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._phase(d, "P1").__setitem__("exit_criteria", []))
        self.assertIn("MIG_PHASE_CRITERIA", self.codes(self._validate()))

    def test_rejects_a_phase_with_no_entry_criteria(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._phase(d, "P1").__setitem__("entry_criteria", []))
        self.assertIn("MIG_PHASE_CRITERIA", self.codes(self._validate()))

    def test_rejects_advancing_a_phase_without_evidence(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._phase(d, "P1").__setitem__("evidence_gate", []))
        problems = self._validate()
        self.assertIn("MIG_PHASE_EVIDENCE", self.codes(problems))
        self.assertIn("NN-12", self.rules(problems))

    def test_rejects_a_phase_with_no_stated_purpose(self):
        self.fixture.mutate(self.REL, lambda d: self._phase(d, "P1").__setitem__("notes", ""))
        self.assertIn("MIG_PHASE_NOTES", self.codes(self._validate()))

    def test_rejects_a_destructive_rollback(self):
        self.fixture.mutate(self.REL, lambda d: self._phase(d, "P2")["rollback"].__setitem__(
            "payment_facts_preserved", False))
        problems = self._validate()
        self.assertIn("MIG_ROLLBACK_DESTRUCTIVE", self.codes(problems))
        self.assertIn("NN-06", self.rules(problems))

    def test_rejects_a_phase_with_no_rollback_action(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._phase(d, "P2")["rollback"].__setitem__("action", ""))
        self.assertIn("MIG_ROLLBACK", self.codes(self._validate()))

    def test_rejects_a_rollback_with_no_justification(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._phase(d, "P2")["rollback"].__setitem__("reason", ""))
        self.assertIn("MIG_ROLLBACK", self.codes(self._validate()))

    def test_rejects_missing_generated_artefacts(self):
        self.fixture.remove("contracts/migration/plan.json")
        self.assertIn("MIG_GENERATED_MISSING", self.codes(self._validate()))

    def test_rejects_a_hand_edited_runbook(self):
        path = self.fixture.root / "docs/migration/MIGRATION_RUNBOOK.md"
        path.write_text(path.read_text(encoding="utf-8").replace(
            "external_reference", "order_id"), encoding="utf-8")
        self.assertIn("MIG_GENERATED_DRIFT", self.codes(self._validate()))

    def test_fails_closed_when_the_runbook_cannot_be_generated(self):
        """A gate must turn a broken plan into a finding, not into a crash."""
        self.fixture.mutate(self.REL, lambda d: self._phase(d, "P1").pop("name"))
        self.assertIn("MIG_GENERATED", self.codes(self._validate()))


class DualWriteReference(FixtureTestCase):
    """One provider call per payment, and a rollback that keeps every fact."""

    def setUp(self):
        super().setUp()
        from libs.migration.reference import dualwrite
        self.dw = dualwrite

    def test_every_phase_calls_the_provider_exactly_once(self):
        for index, phase in enumerate(self.dw.PHASES):
            job = self.dw.Migration()
            for _ in range(index):
                job.advance()
            job.pay("proj-1", "ord-1", 19999, "CNY")
            self.assertEqual(job.provider.calls["ord-1"], 1, phase)

    def test_dual_write_phases_write_two_records_for_one_charge(self):
        for phase in ("dual_write_legacy_authoritative", "dual_write_platform_authoritative"):
            job = self.dw.Migration()
            while job.phase != phase:
                job.advance()
            job.pay("proj-1", "ord-1", 19999, "CNY")
            self.assertEqual(len(job.legacy.rows), 1)
            self.assertEqual(len(job.platform.rows), 1)
            self.assertEqual(job.provider.calls["ord-1"], 1)

    def test_a_second_charge_for_the_same_payment_is_refused(self):
        job = self.dw.Migration()
        job.advance()
        job.pay("proj-1", "ord-1", 19999, "CNY")
        with self.assertRaises(self.dw.DoubleCharge):
            job.provider.charge("ord-1")

    def test_rolling_all_the_way_back_preserves_every_payment_fact(self):
        job = self.dw.Migration()
        for index in range(1, len(self.dw.PHASES)):
            job.advance()
            job.pay("proj-1", f"ord-{index}", 100 * index, "CNY")
        before = (len(job.legacy.rows), len(job.platform.rows))
        while job.phase != self.dw.PHASES[0]:
            job.rollback()
        self.assertEqual((len(job.legacy.rows), len(job.platform.rows)), before)

    def test_authority_follows_the_phase(self):
        job = self.dw.Migration()
        self.assertEqual(job.authority, "legacy")
        job.advance()
        self.assertEqual(job.authority, "legacy")
        job.advance()
        self.assertEqual(job.authority, "platform")
        job.advance()
        self.assertEqual(job.authority, "platform")

    def test_order_line_data_cannot_reach_either_store(self):
        for store in (self.dw.Store("platform"), self.dw.Store("legacy")):
            for leaky in ("sku", "item_count", "shipping_address", "product_name"):
                with self.assertRaises(self.dw.BusinessDataLeak, msg=leaky):
                    store.write("proj-1", "ord-1", {leaky: "x"})

    def test_a_divergence_in_the_amount_is_detected(self):
        job = self.dw.Migration()
        job.advance()
        job.pay("proj-1", "ord-1", 19999, "CNY")
        self.assertEqual(job.divergences(), [])
        job.platform.rows[("proj-1", "ord-1")]["amount_minor"] = 1
        found = job.divergences()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["fields"], ["amount_minor"])

    def _source(self, count: int = 30):
        return [{"legacy_payment_id": f"lp-{i:04d}", "project": "proj-1",
                 "external_reference": f"ord-{i}", "amount_minor": 100 * (i + 1),
                 "currency": "CNY" if i % 2 == 0 else "JPY", "status": "captured"}
                for i in range(count)]

    def test_the_backfill_is_idempotent(self):
        job = self.dw.Backfill(self._source(), self.dw.Store("platform"))
        job.run()
        writes = job.writes
        job.checkpoint = ""
        job.run()
        self.assertEqual(job.writes, writes)

    def test_the_backfill_resumes_from_its_checkpoint(self):
        clean = self.dw.Backfill(self._source(), self.dw.Store("platform"))
        clean.run()
        crashed = self.dw.Backfill(self._source(), self.dw.Store("platform"))
        with self.assertRaises(RuntimeError):
            crashed.run(crash_after=10)
        self.assertTrue(crashed.checkpoint)
        crashed.run()
        self.assertEqual(crashed.target.rows, clean.target.rows)

    def test_backfill_verification_checks_totals_not_just_counts(self):
        target = self.dw.Store("platform")
        job = self.dw.Backfill(self._source(), target)
        job.run()
        self.assertTrue(job.verify()["count_ok"])
        self.assertTrue(job.verify()["totals_ok"])
        first = next(iter(target.rows.values()))
        first["amount_minor"] += 1
        self.assertTrue(job.verify()["count_ok"])
        self.assertFalse(job.verify()["totals_ok"])
