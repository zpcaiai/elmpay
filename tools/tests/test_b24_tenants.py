"""B24 / AT-B24-01 — organisation, tenant, project and environment registry.

``test_suspension_stops_new_money_not_money_in_flight`` is the test this batch
exists for. "Suspend this merchant" reads like one boolean, and implementing it
as one boolean strands every payer who has already paid: their money left, the
refund path is the only way back, and it was just switched off along with
everything else. The capability matrix makes that distinction explicit and the
gate refuses a matrix that gets it wrong.

``test_a_live_credential_is_refused_in_test`` covers the other classic: an
environment separation with one convenient exception, which eventually meets
real money.
"""
from __future__ import annotations

import json

from libs.registry.reference import tenants as R
from tools.paygov import tenants, tenantsgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


def _model(root=REAL_ROOT) -> dict:
    return json.loads((root / "governance/tenant-registry.json").read_text(encoding="utf-8"))


class TenantRegistryHappyPath(FixtureTestCase):
    def test_real_registry_passes(self):
        problems = tenants.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("tenant-registry", registry.names())

    def test_the_hierarchy_is_four_levels_in_order(self):
        model = self.fixture.read("governance/tenant-registry.json")
        self.assertEqual([h["level"] for h in model["hierarchy"]], tenants.LEVELS)
        self.assertIsNone(model["hierarchy"][0]["parent"])

    def test_identifiers_are_opaque_and_immutable(self):
        identifier = self.fixture.read("governance/tenant-registry.json")["identifier"]
        self.assertTrue(identifier["opaque"])
        self.assertTrue(identifier["immutable"])
        import re
        pattern = re.compile(identifier["pattern"])
        self.assertTrue(pattern.match("ten_0123456789abcdef"))
        self.assertFalse(pattern.match("ten_acme-corp"))

    def test_environments_share_nothing(self):
        model = self.fixture.read("governance/tenant-registry.json")
        for entry in model["environments"]:
            self.assertEqual(entry["shares_keys_with"], [], entry["id"])
            self.assertEqual(entry["shares_data_with"], [], entry["id"])
        self.assertEqual(sum(1 for e in model["environments"] if e["handles_real_money"]), 1)

    def test_b21_also_forbids_sharing_keys_across_environments(self):
        certs = self.fixture.read("governance/certificates.json")
        self.assertIs(certs["forbidden"]["shared_key_across_environments"], False)

    def test_a_tenant_starts_in_draft_and_ends_closed(self):
        lifecycle = self.fixture.read("governance/tenant-registry.json")["lifecycle"]
        self.assertEqual(lifecycle["initial"], "draft")
        self.assertEqual(lifecycle["terminal"], ["closed"])
        self.assertEqual(lifecycle["states"], tenants.STATES)

    def test_activation_requires_kyb(self):
        lifecycle = self.fixture.read("governance/tenant-registry.json")["lifecycle"]
        activation = next(t for t in lifecycle["transitions"]
                          if t["from"] == "draft" and t["to"] == "active")
        self.assertIn("kyb_verified", activation["requires"])

    def test_reinstating_a_suspended_tenant_needs_two_people(self):
        lifecycle = self.fixture.read("governance/tenant-registry.json")["lifecycle"]
        back = next(t for t in lifecycle["transitions"]
                    if t["from"] == "suspended" and t["to"] == "active")
        self.assertIn("second_approver", back["requires"])

    def test_closing_requires_settlement_then_destruction(self):
        lifecycle = self.fixture.read("governance/tenant-registry.json")["lifecycle"]
        close = next(t for t in lifecycle["transitions"] if t["to"] == "closed")
        self.assertIn("settlement_complete", close["requires"])
        self.assertIn("kek_destroyed", close["requires"])

    def test_suspension_keeps_money_in_flight_moving(self):
        model = self.fixture.read("governance/tenant-registry.json")
        for state in ("suspended", "offboarding"):
            row = next(r for r in model["capability_matrix"] if r["state"] == state)
            self.assertFalse(row["accept_payments"], state)
            for capability in tenants.IN_FLIGHT:
                self.assertTrue(row[capability], f"{state}/{capability}")

    def test_a_closed_tenant_can_do_nothing(self):
        model = self.fixture.read("governance/tenant-registry.json")
        row = next(r for r in model["capability_matrix"] if r["state"] == "closed")
        for capability in tenants.CAPABILITIES:
            self.assertFalse(row[capability], capability)

    def test_isolation_rests_on_three_things(self):
        model = self.fixture.read("governance/tenant-registry.json")
        keys = self.fixture.read("governance/key-management.json")
        isolation = model["isolation"]
        self.assertTrue(isolation["row_level_security_required"])
        self.assertFalse(isolation["cross_tenant_reference_allowed"])
        kek = next(k for k in keys["keys"] if k["id"] == isolation["per_tenant_kek"])
        self.assertTrue(kek["tenant_scoped"])

    def test_quotas_have_defaults_and_ceilings(self):
        model = self.fixture.read("governance/tenant-registry.json")
        for quota in model["quotas"]:
            self.assertGreater(quota["default"], 0, quota["id"])
            self.assertGreaterEqual(quota["hard_ceiling"], quota["default"], quota["id"])
            self.assertIn(quota["scope"], tenants.QUOTA_SCOPES)

    def test_offboarding_keeps_the_platforms_own_record(self):
        offboarding = self.fixture.read("governance/tenant-registry.json")["offboarding"]
        self.assertTrue(offboarding["ledger_retained"])
        self.assertTrue(offboarding["audit_retained"])
        self.assertTrue(offboarding["settlement_must_complete_first"])
        self.assertGreater(offboarding["grace_period_days"], 0)

    def test_lifecycle_changes_map_to_a_real_audit_class(self):
        model = self.fixture.read("governance/tenant-registry.json")
        audit = self.fixture.read("governance/audit-log.json")
        self.assertIn(model["audit_event_class"], {c["id"] for c in audit["event_classes"]})


class TenantGeneratedArtefacts(FixtureTestCase):
    def test_generated_artefacts_match_the_registry(self):
        for rel, content in tenantsgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_carries_the_capability_matrix(self):
        contract = json.loads(tenantsgen.contract_json(REAL_ROOT))
        states = {row["state"] for row in contract["capability_matrix"]}
        self.assertEqual(states, set(tenants.STATES))

    def test_document_shows_every_state(self):
        text = tenantsgen.tenants_markdown(REAL_ROOT)
        for state in tenants.STATES:
            self.assertIn(state, text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/tenancy/TENANT_REGISTRY.md", "hand written\n")
        codes = self.codes(tenants.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("TENANT_GENERATED_DRIFT", codes)

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/tenancy/registry.json")
        codes = self.codes(tenants.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("TENANT_GENERATED_MISSING", codes)

    def test_unrenderable_registry_fails_closed(self):
        self.fixture.mutate("governance/tenant-registry.json",
                            lambda d: d.__setitem__("quotas", [{"id": "x"}]))
        codes = self.codes(tenants.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("TENANT_GENERATED", codes)


class TenantGateRejects(FixtureTestCase):
    REL = "governance/tenant-registry.json"

    def _validate(self):
        return tenants.validate(self.fixture.root, Budget(seconds=60).start())

    def _row(self, d, state):
        return next(r for r in d["capability_matrix"] if r["state"] == state)

    def _transition(self, d, source, target):
        return next(t for t in d["lifecycle"]["transitions"]
                    if t["from"] == source and t["to"] == target)

    def test_rejects_unreadable_registry(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("TENANT_UNREADABLE", self.codes(self._validate()))

    def test_rejects_non_object_registry(self):
        self.fixture.write(self.REL, [1])
        self.assertIn("TENANT_SHAPE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("TENANT_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_missing_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("TENANT_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_a_reordered_hierarchy(self):
        self.fixture.mutate(self.REL, lambda d: d["hierarchy"].reverse())
        self.assertIn("TENANT_HIERARCHY", self.codes(self._validate()))

    def test_rejects_a_duplicate_id_prefix(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["hierarchy"][1].__setitem__("id_prefix", "org"))
        self.assertIn("TENANT_PREFIX", self.codes(self._validate()))

    def test_rejects_a_level_without_notes(self):
        self.fixture.mutate(self.REL, lambda d: d["hierarchy"][1].__setitem__("notes", ""))
        self.assertIn("TENANT_LEVEL_NOTES", self.codes(self._validate()))

    def test_rejects_readable_identifiers(self):
        self.fixture.mutate(self.REL, lambda d: d["identifier"].__setitem__("opaque", False))
        self.assertIn("TENANT_ID_NOT_OPAQUE", self.codes(self._validate()))

    def test_rejects_mutable_identifiers(self):
        self.fixture.mutate(self.REL, lambda d: d["identifier"].__setitem__("immutable", False))
        self.assertIn("TENANT_ID_MUTABLE", self.codes(self._validate()))

    def test_rejects_an_identifier_pattern_that_does_not_compile(self):
        self.fixture.mutate(self.REL, lambda d: d["identifier"].__setitem__("pattern", "([a-z"))
        self.assertIn("TENANT_ID_PATTERN", self.codes(self._validate()))

    def test_rejects_environments_sharing_keys(self):
        self.fixture.mutate(self.REL, lambda d: next(
            e for e in d["environments"] if e["id"] == "test")
            .__setitem__("shares_keys_with", ["live"]))
        self.assertIn("TENANT_ENV_SHARES_KEYS", self.codes(self._validate()))

    def test_rejects_environments_sharing_data(self):
        self.fixture.mutate(self.REL, lambda d: next(
            e for e in d["environments"] if e["id"] == "test")
            .__setitem__("shares_data_with", ["live"]))
        self.assertIn("TENANT_ENV_SHARES_DATA", self.codes(self._validate()))

    def test_rejects_two_environments_handling_real_money(self):
        self.fixture.mutate(self.REL, lambda d: next(
            e for e in d["environments"] if e["id"] == "test")
            .__setitem__("handles_real_money", True))
        self.assertIn("TENANT_ENV_MONEY", self.codes(self._validate()))

    def test_rejects_b21_allowing_shared_environment_keys(self):
        self.fixture.mutate("governance/certificates.json",
                            lambda d: d["forbidden"].__setitem__(
                                "shared_key_across_environments", True))
        self.assertIn("TENANT_ENV_SHARES_KEYS", self.codes(self._validate()))

    def test_rejects_starting_active(self):
        self.fixture.mutate(self.REL, lambda d: d["lifecycle"].__setitem__("initial", "active"))
        self.assertIn("TENANT_INITIAL_STATE", self.codes(self._validate()))

    def test_rejects_changing_the_state_set(self):
        self.fixture.mutate(self.REL, lambda d: d["lifecycle"].__setitem__(
            "states", ["draft", "active"]))
        self.assertIn("TENANT_STATES", self.codes(self._validate()))

    def test_rejects_an_unguarded_transition(self):
        self.fixture.mutate(self.REL, lambda d: self._transition(d, "active", "suspended")
                            .__setitem__("requires", []))
        self.assertIn("TENANT_TRANSITION_UNGUARDED", self.codes(self._validate()))

    def test_rejects_a_transition_to_an_unknown_state(self):
        self.fixture.mutate(self.REL, lambda d: self._transition(d, "active", "suspended")
                            .__setitem__("to", "paused"))
        self.assertIn("TENANT_TRANSITION_UNKNOWN", self.codes(self._validate()))

    def test_rejects_a_duplicate_transition(self):
        self.fixture.mutate(self.REL, lambda d: d["lifecycle"]["transitions"].append(
            dict(self._transition(d, "active", "suspended"))))
        self.assertIn("TENANT_TRANSITION_DUPLICATE", self.codes(self._validate()))

    def test_rejects_activation_without_kyb(self):
        self.fixture.mutate(self.REL, lambda d: self._transition(d, "draft", "active")
                            .__setitem__("requires", ["contract_signed"]))
        self.assertIn("TENANT_ACTIVATION_UNVERIFIED", self.codes(self._validate()))

    def test_rejects_single_person_reinstatement(self):
        self.fixture.mutate(self.REL, lambda d: self._transition(d, "suspended", "active")
                            .__setitem__("requires", ["reason", "actor"]))
        self.assertIn("TENANT_UNSUSPEND_SINGLE_PERSON", self.codes(self._validate()))

    def test_rejects_closing_before_settlement(self):
        self.fixture.mutate(self.REL, lambda d: self._transition(d, "offboarding", "closed")
                            .__setitem__("requires", ["kek_destroyed"]))
        self.assertIn("TENANT_CLOSE_BEFORE_SETTLEMENT", self.codes(self._validate()))

    def test_rejects_closing_without_destroying_the_key(self):
        self.fixture.mutate(self.REL, lambda d: self._transition(d, "offboarding", "closed")
                            .__setitem__("requires", ["settlement_complete"]))
        self.assertIn("TENANT_CLOSE_WITHOUT_SHREDDING", self.codes(self._validate()))

    def test_rejects_an_unreachable_state(self):
        self.fixture.mutate(self.REL, lambda d: d["lifecycle"].__setitem__(
            "transitions", [t for t in d["lifecycle"]["transitions"]
                            if t["from"] != "draft"]))
        self.assertIn("TENANT_STATE_UNREACHABLE", self.codes(self._validate()))

    def test_rejects_removing_the_capability_matrix(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("capability_matrix", []))
        self.assertIn("TENANT_NO_CAPABILITY_MATRIX", self.codes(self._validate()))

    def test_rejects_a_suspended_tenant_that_cannot_refund(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._row(d, "suspended").__setitem__("issue_refunds",
                                                                            False))
        self.assertIn("TENANT_SUSPENDED_BLOCKS_REFUNDS", self.codes(self._validate()))

    def test_rejects_a_suspended_tenant_that_ignores_callbacks(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._row(d, "suspended").__setitem__("receive_webhooks",
                                                                            False))
        self.assertIn("TENANT_SUSPENDED_BLOCKS_REFUNDS", self.codes(self._validate()))

    def test_rejects_a_suspended_tenant_that_still_takes_payments(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._row(d, "suspended").__setitem__("accept_payments",
                                                                            True))
        self.assertIn("TENANT_SUSPENDED_TAKES_MONEY", self.codes(self._validate()))

    def test_rejects_a_draft_tenant_that_takes_payments(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._row(d, "draft").__setitem__("accept_payments", True))
        self.assertIn("TENANT_DRAFT_TAKES_MONEY", self.codes(self._validate()))

    def test_rejects_a_closed_tenant_that_can_still_read(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._row(d, "closed").__setitem__("read_data", True))
        self.assertIn("TENANT_CLOSED_ACTIVE", self.codes(self._validate()))

    def test_rejects_a_missing_capability_row(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "capability_matrix", [r for r in d["capability_matrix"]
                                  if r["state"] != "offboarding"]))
        self.assertIn("TENANT_CAPABILITY_MISSING", self.codes(self._validate()))

    def test_rejects_an_undecided_capability(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._row(d, "active").__setitem__("settle", "maybe"))
        self.assertIn("TENANT_CAPABILITY_MISSING", self.codes(self._validate()))

    def test_rejects_allowing_cross_tenant_references(self):
        self.fixture.mutate(self.REL, lambda d: d["isolation"].__setitem__(
            "cross_tenant_reference_allowed", True))
        self.assertIn("TENANT_CROSS_REFERENCE", self.codes(self._validate()))

    def test_rejects_dropping_row_level_security(self):
        self.fixture.mutate(self.REL, lambda d: d["isolation"].__setitem__(
            "row_level_security_required", False))
        self.assertIn("TENANT_NO_RLS", self.codes(self._validate()))

    def test_rejects_a_kek_that_is_not_tenant_scoped(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["isolation"].__setitem__("per_tenant_kek",
                                                                 "kek-provider-credentials"))
        self.assertIn("TENANT_KEK_NOT_SCOPED", self.codes(self._validate()))

    def test_rejects_a_kek_b20_does_not_manage(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["isolation"].__setitem__("per_tenant_kek", "ghost"))
        self.assertIn("TENANT_KEK_UNKNOWN", self.codes(self._validate()))

    def test_rejects_removing_all_quotas(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("quotas", []))
        self.assertIn("TENANT_NO_QUOTAS", self.codes(self._validate()))

    def test_rejects_a_ceiling_below_the_default(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["quotas"][0].__setitem__("hard_ceiling", 1))
        self.assertIn("TENANT_QUOTA_CEILING", self.codes(self._validate()))

    def test_rejects_a_quota_with_an_unknown_scope(self):
        self.fixture.mutate(self.REL, lambda d: d["quotas"][0].__setitem__("scope", "galaxy"))
        self.assertIn("TENANT_QUOTA_SCOPE", self.codes(self._validate()))

    def test_rejects_a_duplicate_quota(self):
        self.fixture.mutate(self.REL, lambda d: d["quotas"].append(dict(d["quotas"][0])))
        self.assertIn("TENANT_QUOTA_DUPLICATE", self.codes(self._validate()))

    def test_rejects_offboarding_that_forgets_the_ledger(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["offboarding"].__setitem__("ledger_retained", False))
        self.assertIn("TENANT_LEDGER_NOT_RETAINED", self.codes(self._validate()))

    def test_rejects_offboarding_that_forgets_the_audit_trail(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["offboarding"].__setitem__("audit_retained", False))
        self.assertIn("TENANT_AUDIT_NOT_RETAINED", self.codes(self._validate()))

    def test_rejects_destruction_without_a_grace_period(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["offboarding"].__setitem__("grace_period_days", 0))
        self.assertIn("TENANT_NO_GRACE_PERIOD", self.codes(self._validate()))

    def test_rejects_an_audit_class_b23_does_not_define(self):
        self.fixture.mutate(self.REL,
                            lambda d: d.__setitem__("audit_event_class", "tenant.vanished"))
        self.assertIn("TENANT_AUDIT_CLASS_UNKNOWN", self.codes(self._validate()))

    def test_rejects_more_than_one_terminal_state(self):
        self.fixture.mutate(self.REL, lambda d: d["lifecycle"].__setitem__(
            "terminal", ["closed", "suspended"]))
        self.assertIn("TENANT_TERMINAL_STATE", self.codes(self._validate()))

    def test_rejects_a_transition_without_notes(self):
        self.fixture.mutate(self.REL, lambda d: self._transition(d, "active", "suspended")
                            .__setitem__("notes", ""))
        self.assertIn("TENANT_TRANSITION_NOTES", self.codes(self._validate()))

    def test_rejects_a_capability_row_without_notes(self):
        self.fixture.mutate(self.REL, lambda d: self._row(d, "active").__setitem__("notes", ""))
        self.assertIn("TENANT_CAPABILITY_NOTES", self.codes(self._validate()))

    def test_rejects_a_quota_without_a_default(self):
        self.fixture.mutate(self.REL, lambda d: d["quotas"][0].__setitem__("default", 0))
        self.assertIn("TENANT_QUOTA_DEFAULT", self.codes(self._validate()))

    def test_rejects_a_quota_without_notes(self):
        self.fixture.mutate(self.REL, lambda d: d["quotas"][0].__setitem__("notes", ""))
        self.assertIn("TENANT_QUOTA_NOTES", self.codes(self._validate()))

    def test_missing_cross_check_inputs_do_not_crash_the_gate(self):
        self.fixture.write("governance/key-management.json", "{ broken",
                                                                          encoding="utf-8")
        codes = self.codes(self._validate())
        self.assertIn("TENANT_KEK_UNKNOWN", codes)

    def test_budget_exhaustion_is_reraised(self):
        from tools.paygov.errors import BudgetExceeded
        with self.assertRaises(BudgetExceeded):
            tenants.validate(self.fixture.root, Budget(seconds=0).start())


class RegistryReference(FixtureTestCase):
    """The executable registry: lifecycle, capabilities, boundaries, quotas."""

    def setUp(self):
        super().setUp()
        self.model = _model()
        self.registry = R.Registry(self.model)
        self.tenant = "ten_0000000000000001"
        self.registry.register(self.tenant, "org_0000000000000001")

    def _activate(self):
        self.registry.transition(self.tenant, R.ACTIVE,
                                 satisfied={"kyb_verified", "contract_signed"}, actor="ops")

    def _refuses(self, fn, code):
        with self.assertRaises(R.RegistryRefused) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)

    def test_a_draft_tenant_cannot_take_payments(self):
        self.assertFalse(self.registry.may(self.tenant, "accept_payments"))
        self._refuses(lambda: self.registry.require(self.tenant, "accept_payments"),
                      R.DENY_NOT_ALLOWED)

    def test_activation_without_kyb_is_refused(self):
        self._refuses(lambda: self.registry.transition(self.tenant, R.ACTIVE,
                                                       satisfied={"contract_signed"},
                                                       actor="ops"), R.DENY_REQUIREMENT)

    def test_activation_with_kyb_succeeds(self):
        self._activate()
        self.assertTrue(self.registry.may(self.tenant, "accept_payments"))
        self.assertEqual(self.registry.tenants[self.tenant].history[-1]["to"], R.ACTIVE)

    def test_suspension_stops_new_money_not_money_in_flight(self):
        self._activate()
        self.registry.transition(self.tenant, R.SUSPENDED, satisfied={"reason", "actor"},
                                 actor="risk")
        self.assertFalse(self.registry.may(self.tenant, "accept_payments"))
        for capability in ("issue_refunds", "receive_webhooks", "settle"):
            self.assertTrue(self.registry.may(self.tenant, capability), capability)

    def test_reinstatement_needs_a_second_approver(self):
        self._activate()
        self.registry.transition(self.tenant, R.SUSPENDED, satisfied={"reason", "actor"},
                                 actor="risk")
        self._refuses(lambda: self.registry.transition(self.tenant, R.ACTIVE,
                                                       satisfied={"reason", "actor"},
                                                       actor="ops"), R.DENY_REQUIREMENT)
        self.registry.transition(self.tenant, R.ACTIVE,
                                 satisfied={"reason", "actor", "second_approver"}, actor="ops")
        self.assertTrue(self.registry.may(self.tenant, "accept_payments"))

    def test_closing_before_settlement_is_refused(self):
        self._activate()
        self.registry.transition(self.tenant, R.OFFBOARDING,
                                 satisfied={"reason", "actor", "second_approver"}, actor="ops")
        self._refuses(lambda: self.registry.transition(
            self.tenant, R.CLOSED,
            satisfied={"retention_period_started", "kek_destroyed"}, actor="ops"),
            R.DENY_REQUIREMENT)

    def test_closing_destroys_the_key_and_every_capability(self):
        self._activate()
        self.registry.transition(self.tenant, R.OFFBOARDING,
                                 satisfied={"reason", "actor", "second_approver"}, actor="ops")
        self.registry.transition(self.tenant, R.CLOSED,
                                 satisfied={"settlement_complete", "retention_period_started",
                                            "kek_destroyed"}, actor="ops")
        self.assertTrue(self.registry.tenants[self.tenant].kek_destroyed)
        for capability in ("accept_payments", "issue_refunds", "receive_webhooks",
                           "settle", "read_data"):
            self.assertFalse(self.registry.may(self.tenant, capability), capability)

    def test_an_illegal_transition_is_refused(self):
        self._refuses(lambda: self.registry.transition(self.tenant, R.CLOSED,
                                                       satisfied=set(), actor="ops"),
                      R.DENY_TRANSITION)

    def test_an_unknown_tenant_is_refused(self):
        self._refuses(lambda: self.registry.may("ten_nope", "settle"), R.DENY_UNKNOWN_STATE)

    def test_a_live_credential_is_refused_in_test(self):
        credential = R.Credential(id="k", tenant_id=self.tenant, project_id="prj_1",
                                  environment="live")
        self._refuses(lambda: self.registry.credential_valid(credential,
                                                             tenant_id=self.tenant,
                                                             environment="test"),
                      R.DENY_WRONG_ENVIRONMENT)
        self.assertEqual(self.registry.credential_valid(credential, tenant_id=self.tenant,
                                                        environment="live"), "OK")

    def test_another_tenants_credential_is_refused(self):
        credential = R.Credential(id="k", tenant_id="ten_other", project_id="prj_1",
                                  environment="live")
        self._refuses(lambda: self.registry.credential_valid(credential,
                                                             tenant_id=self.tenant,
                                                             environment="live"),
                      R.DENY_CROSS_TENANT)

    def test_only_live_handles_real_money(self):
        self.assertTrue(self.registry.handles_real_money("live"))
        self.assertFalse(self.registry.handles_real_money("test"))
        self._refuses(lambda: self.registry.handles_real_money("staging"),
                      R.DENY_WRONG_ENVIRONMENT)

    def test_quotas_are_enforced_per_scope(self):
        quota = self.model["quotas"][0]
        for _ in range(quota["default"]):
            self.registry.consume("prj_1", quota["id"])
        self._refuses(lambda: self.registry.consume("prj_1", quota["id"]), R.DENY_QUOTA)
        self.assertEqual(self.registry.consume("prj_2", quota["id"]), 1)

    def test_a_custom_limit_cannot_exceed_the_hard_ceiling(self):
        quota = self.model["quotas"][0]
        self._refuses(lambda: self.registry.consume("prj_9", quota["id"],
                                                    limit=quota["hard_ceiling"] + 1),
                      R.DENY_QUOTA)

    def test_an_unknown_quota_is_refused(self):
        self._refuses(lambda: self.registry.consume("prj_1", "imaginary"), R.DENY_QUOTA)

    def test_resetting_a_quota_clears_usage(self):
        quota = self.model["quotas"][0]
        self.registry.consume("prj_1", quota["id"])
        self.registry.reset("prj_1", quota["id"])
        self.assertEqual(self.registry.consume("prj_1", quota["id"]), 1)

    def test_history_records_every_transition_with_its_actor(self):
        self._activate()
        self.registry.transition(self.tenant, R.SUSPENDED, satisfied={"reason", "actor"},
                                 actor="risk-analyst")
        history = self.registry.tenants[self.tenant].history
        self.assertEqual([h["to"] for h in history], [R.ACTIVE, R.SUSPENDED])
        self.assertEqual(history[-1]["actor"], "risk-analyst")
