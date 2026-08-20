"""B30 / AT-B30-01 — merchant onboarding as a resumable four-eyes workflow.

``test_a_resumed_case_does_not_repeat_a_completed_side_effect`` is the test this
batch exists for. Resumability is not a convenience: a workflow that cannot
resume is finished by hand, and at that moment every approval recorded above it
stops meaning anything.

``test_changing_the_payout_account_invalidates_the_approval`` is the other one.
Approve, then edit, then go live is the bypass that leaves an audit trail
reading as a correctly approved onboarding.
"""
from __future__ import annotations

import json

from libs.onboarding.reference import workflow as W
from tools.paygov import onboarding, onboardinggen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/onboarding-workflow.json"
HOUR = 1000


def _step(model, sid):
    return next(s for s in model["steps"] if s["id"] == sid)


class OnboardingHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = onboarding.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("onboarding-workflow", registry.names())

    def test_every_required_step_exists_in_order(self):
        model = self.fixture.read(REL)
        ids = [s["id"] for s in sorted(model["steps"], key=lambda s: s["order"])]
        for required in onboarding.REQUIRED_STEPS:
            self.assertIn(required, ids)
        self.assertLess(ids.index("approve"), ids.index("go_live"))
        self.assertLess(ids.index("set_limits"), ids.index("go_live"))

    def test_every_step_is_idempotent_resumable_and_evidenced(self):
        for step in self.fixture.read(REL)["steps"]:
            self.assertTrue(step["idempotent"], step["id"])
            self.assertTrue(step["resumable"], step["id"])
            self.assertTrue(step["evidence_required"], step["id"])
            self.assertIsInstance(step["has_side_effect"], bool, step["id"])

    def test_approval_is_four_eyes_bound_and_expiring(self):
        approval = self.fixture.read(REL)["approval"]
        self.assertGreaterEqual(approval["eyes_required"], 2)
        self.assertTrue(approval["approver_differs_from_requester"])
        self.assertTrue(approval["bound_to_digest"])
        self.assertTrue(onboarding.DIGEST_FIELDS <= set(approval["digest_fields"]))
        self.assertGreater(approval["expires_hours"], 0)
        self.assertLessEqual(approval["expires_hours"], onboarding.MAX_APPROVAL_HOURS)
        self.assertTrue(approval["reapproval_required_on_change"])

    def test_the_approval_permission_is_dual_control_in_b19(self):
        model = self.fixture.read(REL)
        authz = self.fixture.read("governance/authorization.json")
        permission = next(p for p in authz["permissions"]
                          if p["id"] == model["approval"]["permission"])
        self.assertTrue(permission["dual_control"])

    def test_there_is_no_manual_completion_path(self):
        resumption = self.fixture.read(REL)["resumption"]
        self.assertFalse(resumption["manual_completion_allowed"])
        self.assertFalse(resumption["replay_completed_side_effects"])
        self.assertTrue(resumption["state_persisted"])
        self.assertTrue(resumption["resume_from_last_completed_step"])
        self.assertLessEqual(resumption["max_resume_days"], onboarding.MAX_RESUME_DAYS)

    def test_domain_proof_is_single_use_expiring_and_not_wildcard(self):
        domain = self.fixture.read(REL)["domain_verification"]
        self.assertIn(domain["method"], onboarding.DOMAIN_METHODS)
        self.assertTrue(domain["token_single_use"])
        self.assertGreater(domain["token_expires_hours"], 0)
        self.assertFalse(domain["wildcard_allowed"])

    def test_callback_verification_refuses_the_dangerous_shapes(self):
        callback = self.fixture.read(REL)["callback_verification"]
        self.assertTrue(callback["roundtrip_required"])
        self.assertTrue(callback["signature_required"])
        self.assertTrue(callback["https_required"])
        self.assertFalse(callback["private_address_allowed"])

    def test_credentials_cannot_be_read_back(self):
        credentials = self.fixture.read(REL)["credentials"]
        self.assertFalse(credentials["echo_back_allowed"])
        self.assertTrue(credentials["import_once"])
        self.assertTrue(credentials["stored_via_binding"])

    def test_limits_exist_before_the_merchant_can_take_money(self):
        limits = self.fixture.read(REL)["limits"]
        self.assertTrue(limits["must_be_set_before_go_live"])
        self.assertTrue(limits["raise_requires_approval"])

    def test_limit_defaults_come_from_the_b25_risk_levels(self):
        model = self.fixture.read(REL)
        if model["limits"]["default_from_risk_level"]:
            merchant = self.fixture.read("governance/merchant-profile.json")
            self.assertTrue({r["id"] for r in merchant["risk_levels"]})

    def test_stopping_is_easier_than_starting(self):
        suspension = self.fixture.read(REL)["suspension"]
        self.assertEqual(suspension["approvals_required"], 1)
        self.assertTrue(suspension["immediate"])
        self.assertGreaterEqual(suspension["reinstatement_approvals_required"], 2)

    def test_go_live_still_needs_the_b26_round_trip(self):
        accounts = self.fixture.read("governance/provider-accounts.json")
        self.assertTrue(accounts["activation"]["callback_roundtrip_required"])

    def test_onboarding_events_map_to_a_real_audit_class(self):
        audit = self.fixture.read("governance/audit-log.json")
        self.assertIn(self.fixture.read(REL)["audit_event_class"],
                      {c["id"] for c in audit["event_classes"]})


class OnboardingGeneratedArtefacts(FixtureTestCase):
    def _validate(self):
        return onboarding.validate(self.fixture.root, Budget(seconds=60).start())

    def test_generated_artefacts_match_the_model(self):
        for rel, content in onboardinggen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_orders_the_steps(self):
        contract = json.loads(onboardinggen.contract_json(REAL_ROOT))
        orders = [s["order"] for s in contract["steps"]]
        self.assertEqual(orders, sorted(orders))

    def test_document_shows_every_step(self):
        text = onboardinggen.onboarding_markdown(REAL_ROOT)
        for step in onboarding.REQUIRED_STEPS:
            self.assertIn(step, text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/onboarding/ONBOARDING_WORKFLOW.md", "hand written\n")
        self.assertIn("ONB_GENERATED_DRIFT", self.codes(self._validate()))

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/onboarding/workflow.json")
        self.assertIn("ONB_GENERATED_MISSING", self.codes(self._validate()))

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("steps", [{"id": "x", "order": 1}]))
        self.assertIn("ONB_GENERATED", self.codes(self._validate()))


class OnboardingGateRejects(FixtureTestCase):
    def _validate(self):
        return onboarding.validate(self.fixture.root, Budget(seconds=60).start())

    def _assert(self, code):
        self.assertIn(code, self.codes(self._validate()))

    def _mutate(self, fn, code, rel=REL):
        self.fixture.mutate(rel, fn)
        self._assert(code)

    # -- shape ------------------------------------------------------------
    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self._assert("ONB_UNREADABLE")

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [1])
        self._assert("ONB_SHAPE")

    def test_rejects_a_bad_schema_version(self):
        self._mutate(lambda d: d.__setitem__("schema_version", "one"), "ONB_VERSION_FIELD")

    def test_rejects_a_missing_principle(self):
        self._mutate(lambda d: d.__setitem__("principle", ""), "ONB_PRINCIPLE")

    def test_rejects_a_non_object_step(self):
        self._mutate(lambda d: d["steps"].append("go_live"), "ONB_SHAPE")

    def test_rejects_a_non_object_domain_block(self):
        self._mutate(lambda d: d.__setitem__("domain_verification", []), "ONB_SHAPE")

    def test_rejects_a_non_object_callback_block(self):
        self._mutate(lambda d: d.__setitem__("callback_verification", []), "ONB_SHAPE")

    def test_rejects_a_non_object_credentials_block(self):
        self._mutate(lambda d: d.__setitem__("credentials", []), "ONB_SHAPE")

    def test_rejects_a_non_object_limits_block(self):
        self._mutate(lambda d: d.__setitem__("limits", []), "ONB_SHAPE")

    def test_rejects_a_non_object_suspension_block(self):
        self._mutate(lambda d: d.__setitem__("suspension", []), "ONB_SHAPE")

    # -- steps ------------------------------------------------------------
    def test_rejects_a_workflow_with_no_steps(self):
        self._mutate(lambda d: d.__setitem__("steps", []), "ONB_NO_STEPS")

    def test_rejects_a_non_snake_case_step_id(self):
        self._mutate(lambda d: _step(d, "go_live").__setitem__("id", "Go Live"),
                     "ONB_STEP_ID")

    def test_rejects_a_duplicate_step(self):
        self._mutate(lambda d: d["steps"].append({**_step(d, "go_live"), "order": 99}),
                     "ONB_STEP_DUPLICATE")

    def test_rejects_a_step_with_no_order(self):
        self._mutate(lambda d: _step(d, "go_live").__setitem__("order", 0),
                     "ONB_STEP_NO_ORDER")

    def test_rejects_two_steps_at_one_position(self):
        self._mutate(lambda d: _step(d, "go_live").__setitem__(
            "order", _step(d, "approve")["order"]), "ONB_STEP_ORDER_COLLISION")

    def test_rejects_a_step_that_does_not_say_if_it_has_a_side_effect(self):
        self._mutate(lambda d: _step(d, "go_live").__setitem__("has_side_effect", "maybe"),
                     "ONB_STEP_EFFECT_UNSTATED")

    def test_rejects_a_non_idempotent_step(self):
        self._mutate(lambda d: _step(d, "go_live").__setitem__("idempotent", False),
                     "ONB_STEP_NOT_IDEMPOTENT")

    def test_rejects_a_step_that_cannot_be_resumed(self):
        self._mutate(lambda d: _step(d, "go_live").__setitem__("resumable", False),
                     "ONB_STEP_NOT_RESUMABLE")

    def test_rejects_a_step_that_produces_no_evidence(self):
        self._mutate(lambda d: _step(d, "go_live").__setitem__("evidence_required", ""),
                     "ONB_STEP_NO_EVIDENCE")

    def test_rejects_an_unexplained_step(self):
        self._mutate(lambda d: _step(d, "go_live").__setitem__("notes", ""), "ONB_STEP_NOTES")

    def test_rejects_a_missing_required_step(self):
        self._mutate(lambda d: d.__setitem__(
            "steps", [s for s in d["steps"] if s["id"] != "verify_domain"]),
            "ONB_STEP_MISSING")

    def test_rejects_approval_after_go_live(self):
        self._mutate(lambda d: _step(d, "approve").__setitem__("order", 999),
                     "ONB_APPROVAL_AFTER_GO_LIVE")

    def test_rejects_an_approval_step_that_requires_no_approval(self):
        self._mutate(lambda d: _step(d, "approve").__setitem__("requires_approval", False),
                     "ONB_APPROVAL_UNBOUND")

    def test_rejects_setting_limits_after_go_live(self):
        self._mutate(lambda d: _step(d, "set_limits").__setitem__("order", 999),
                     "ONB_LIMITS_AFTER_GO_LIVE")

    # -- approval ---------------------------------------------------------
    def test_rejects_a_missing_approval_policy(self):
        self._mutate(lambda d: d.__setitem__("approval", []), "ONB_APPROVAL_UNBOUND")

    def test_rejects_single_eye_approval(self):
        self._mutate(lambda d: d["approval"].__setitem__("eyes_required", 1), "ONB_SINGLE_EYE")

    def test_rejects_self_approval(self):
        self._mutate(lambda d: d["approval"].__setitem__("approver_differs_from_requester",
                                                         False), "ONB_SELF_APPROVAL")

    def test_rejects_an_approval_that_is_not_bound_to_content(self):
        self._mutate(lambda d: d["approval"].__setitem__("bound_to_digest", False),
                     "ONB_APPROVAL_UNBOUND")

    def test_rejects_a_digest_that_omits_the_payout_account(self):
        self._mutate(lambda d: d["approval"].__setitem__("digest_fields",
                                                         ["tenant_id", "provider"]),
                     "ONB_DIGEST_INCOMPLETE")

    def test_rejects_an_approval_that_never_expires(self):
        self._mutate(lambda d: d["approval"].__setitem__("expires_hours", 0),
                     "ONB_APPROVAL_NEVER_EXPIRES")

    def test_rejects_an_approval_that_survives_a_change(self):
        self._mutate(lambda d: d["approval"].__setitem__("reapproval_required_on_change",
                                                         False),
                     "ONB_APPROVAL_SURVIVES_CHANGE")

    def test_rejects_an_unknown_approval_permission(self):
        self._mutate(lambda d: d["approval"].__setitem__("permission", "made.up"),
                     "ONB_PERMISSION_UNKNOWN")

    def test_rejects_an_approval_permission_without_dual_control(self):
        self.fixture.mutate("governance/authorization.json",
                            lambda d: next(p for p in d["permissions"]
                                           if p["id"] == "config.write")
                            .__setitem__("dual_control", False))
        self._assert("ONB_SINGLE_EYE")

    def test_rejects_an_unexplained_approval_policy(self):
        self._mutate(lambda d: d["approval"].__setitem__("notes", ""), "ONB_APPROVAL_NOTES")

    # -- resumption -------------------------------------------------------
    def test_rejects_a_missing_resumption_policy(self):
        self._mutate(lambda d: d.__setitem__("resumption", []), "ONB_NOT_RESUMABLE")

    def test_rejects_state_that_does_not_survive_a_restart(self):
        self._mutate(lambda d: d["resumption"].__setitem__("state_persisted", False),
                     "ONB_NOT_RESUMABLE")

    def test_rejects_restarting_from_the_beginning(self):
        self._mutate(lambda d: d["resumption"].__setitem__("resume_from_last_completed_step",
                                                           False), "ONB_NOT_RESUMABLE")

    def test_rejects_replaying_completed_side_effects(self):
        self._mutate(lambda d: d["resumption"].__setitem__("replay_completed_side_effects",
                                                           True), "ONB_REPLAYS_SIDE_EFFECTS")

    def test_rejects_a_manual_completion_path(self):
        self._mutate(lambda d: d["resumption"].__setitem__("manual_completion_allowed", True),
                     "ONB_MANUAL_COMPLETION")

    def test_rejects_a_half_finished_case_that_never_expires(self):
        self._mutate(lambda d: d["resumption"].__setitem__("max_resume_days", 0),
                     "ONB_RESUME_UNBOUNDED")

    def test_rejects_an_unexplained_resumption_policy(self):
        self._mutate(lambda d: d["resumption"].__setitem__("notes", ""),
                     "ONB_RESUMPTION_NOTES")

    # -- verification -----------------------------------------------------
    def test_rejects_an_unknown_domain_verification_method(self):
        self._mutate(lambda d: d["domain_verification"].__setitem__("method", "email"),
                     "ONB_DOMAIN_METHOD")

    def test_rejects_a_reusable_domain_token(self):
        self._mutate(lambda d: d["domain_verification"].__setitem__("token_single_use", False),
                     "ONB_DOMAIN_TOKEN_REUSABLE")

    def test_rejects_a_domain_token_that_never_expires(self):
        self._mutate(lambda d: d["domain_verification"].__setitem__("token_expires_hours", 0),
                     "ONB_DOMAIN_TOKEN_ETERNAL")

    def test_rejects_wildcard_domain_proof(self):
        self._mutate(lambda d: d["domain_verification"].__setitem__("wildcard_allowed", True),
                     "ONB_DOMAIN_WILDCARD")

    def test_rejects_an_unexplained_domain_policy(self):
        self._mutate(lambda d: d["domain_verification"].__setitem__("notes", ""),
                     "ONB_DOMAIN_NOTES")

    def test_rejects_a_callback_proven_by_typing_a_url(self):
        self._mutate(lambda d: d["callback_verification"].__setitem__("roundtrip_required",
                                                                      False),
                     "ONB_CALLBACK_UNPROVEN")

    def test_rejects_an_unsigned_verification_callback(self):
        self._mutate(lambda d: d["callback_verification"].__setitem__("signature_required",
                                                                      False),
                     "ONB_CALLBACK_UNSIGNED")

    def test_rejects_a_plaintext_callback_endpoint(self):
        self._mutate(lambda d: d["callback_verification"].__setitem__("https_required", False),
                     "ONB_CALLBACK_PLAINTEXT")

    def test_rejects_a_callback_pointing_at_a_private_address(self):
        self._mutate(lambda d: d["callback_verification"].__setitem__(
            "private_address_allowed", True), "ONB_CALLBACK_SSRF")

    def test_rejects_an_unexplained_callback_policy(self):
        self._mutate(lambda d: d["callback_verification"].__setitem__("notes", ""),
                     "ONB_CALLBACK_NOTES")

    # -- credentials, limits, suspension ----------------------------------
    def test_rejects_reading_back_an_imported_credential(self):
        self._mutate(lambda d: d["credentials"].__setitem__("echo_back_allowed", True),
                     "ONB_CREDENTIAL_ECHO")

    def test_rejects_storing_a_second_copy_on_reimport(self):
        self._mutate(lambda d: d["credentials"].__setitem__("import_once", False),
                     "ONB_CREDENTIAL_REIMPORT")

    def test_rejects_credentials_stored_outside_the_binding(self):
        self._mutate(lambda d: d["credentials"].__setitem__("stored_via_binding", False),
                     "ONB_CREDENTIAL_SIDE_PATH")

    def test_rejects_an_unexplained_credential_policy(self):
        self._mutate(lambda d: d["credentials"].__setitem__("notes", ""),
                     "ONB_CREDENTIAL_NOTES")

    def test_rejects_going_live_without_limits(self):
        self._mutate(lambda d: d["limits"].__setitem__("must_be_set_before_go_live", False),
                     "ONB_NO_LIMITS_AT_GO_LIVE")

    def test_rejects_raising_a_limit_without_approval(self):
        self._mutate(lambda d: d["limits"].__setitem__("raise_requires_approval", False),
                     "ONB_LIMIT_RAISE_UNGATED")

    def test_rejects_defaults_from_risk_levels_that_do_not_exist(self):
        self.fixture.mutate("governance/merchant-profile.json",
                            lambda d: d.__setitem__("risk_levels", []))
        self._assert("ONB_RISK_LEVELS_UNKNOWN")

    def test_rejects_an_unexplained_limit_policy(self):
        self._mutate(lambda d: d["limits"].__setitem__("notes", ""), "ONB_LIMIT_NOTES")

    def test_rejects_requiring_approval_to_suspend(self):
        self._mutate(lambda d: d["suspension"].__setitem__("approvals_required", 2),
                     "ONB_SUSPEND_NEEDS_APPROVAL")

    def test_rejects_a_delayed_suspension(self):
        self._mutate(lambda d: d["suspension"].__setitem__("immediate", False),
                     "ONB_SUSPEND_DELAYED")

    def test_rejects_single_person_reinstatement(self):
        self._mutate(lambda d: d["suspension"].__setitem__(
            "reinstatement_approvals_required", 1), "ONB_REINSTATE_SINGLE_PERSON")

    def test_rejects_an_unexplained_suspension_policy(self):
        self._mutate(lambda d: d["suspension"].__setitem__("notes", ""),
                     "ONB_SUSPENSION_NOTES")

    def test_rejects_an_unknown_audit_class(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "onboarding.vanished"),
                     "ONB_AUDIT_CLASS_UNKNOWN")

    def test_rejects_go_live_that_b26_would_not_require_a_round_trip_for(self):
        self.fixture.mutate("governance/provider-accounts.json",
                            lambda d: d["activation"].__setitem__(
                                "callback_roundtrip_required", False))
        self._assert("ONB_GO_LIVE_UNPROVEN")


class WorkflowReferenceModel(FixtureTestCase):
    MODEL = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))

    def flow(self) -> W.Workflow:
        return W.Workflow(self.MODEL)

    def payload(self) -> dict:
        return {"tenant_id": "ten_1", "provider": "stripe",
                "payout_account": "acct_original", "limits": {},
                "domains": ["shop.example.com"]}

    def case(self, flow: W.Workflow, hour: int = HOUR) -> W.Case:
        return flow.start("case_1", tenant_id="ten_1", provider="stripe", requester="ops",
                          payload=self.payload(), hour=hour)

    def through_limits(self, flow: W.Workflow, case: W.Case, hour: int = HOUR) -> None:
        flow.import_credentials(case, "kms://binding/1", hour=hour)
        flow.verify_domain(case, "shop.example.com", "tok_1", issued_at_hour=hour, hour=hour)
        flow.verify_callback(case, "https://shop.example.com/hook", roundtrip_id="rt_1",
                             signature_valid=True, hour=hour)
        flow.set_limits(case, {"daily_limit_minor": 100000}, hour=hour)

    def refused(self, fn, code):
        with self.assertRaises(W.WorkflowRefused) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    # -- ordering and idempotence -----------------------------------------
    def test_steps_run_in_order(self):
        flow = self.flow()
        case = self.case(flow)
        self.refused(lambda: flow.execute(case, "go_live", evidence="x", hour=HOUR),
                     W.OUT_OF_ORDER)
        self.refused(lambda: flow.execute(case, "make_coffee", evidence="x", hour=HOUR),
                     W.UNKNOWN_STEP)

    def test_a_step_with_no_evidence_is_refused(self):
        flow = self.flow()
        case = self.case(flow)
        self.refused(lambda: flow.execute(case, "import_credentials", evidence="", hour=HOUR),
                     W.NO_EVIDENCE)

    def test_a_resumed_case_does_not_repeat_a_completed_side_effect(self):
        flow = self.flow()
        case = self.case(flow)
        flow.import_credentials(case, "kms://binding/1", hour=HOUR)
        self.assertEqual(flow.side_effect_count(case, "import_credentials"), 1)
        # Resume: the next step is the one after the last completed step, and
        # re-running the completed one changes nothing.
        self.assertEqual(flow.resume(case, HOUR), "verify_domain")
        self.assertEqual(flow.execute(case, "import_credentials", evidence="x", hour=HOUR),
                         "ALREADY_DONE")
        self.assertEqual(flow.side_effect_count(case, "import_credentials"), 1)

    def test_reimporting_returns_the_same_reference(self):
        flow = self.flow()
        case = self.case(flow)
        first = flow.import_credentials(case, "kms://binding/1", hour=HOUR)
        self.assertEqual(flow.import_credentials(case, "kms://binding/2", hour=HOUR), first)

    def test_an_imported_credential_cannot_be_read_back(self):
        flow = self.flow()
        case = self.case(flow)
        flow.import_credentials(case, "kms://binding/1", hour=HOUR)
        self.refused(lambda: flow.read_credential(case), W.CREDENTIAL_NOT_READABLE)

    def test_there_is_no_manual_completion(self):
        flow = self.flow()
        case = self.case(flow)
        self.refused(lambda: flow.force_complete(case), W.MANUAL_COMPLETION)

    def test_a_half_finished_case_expires(self):
        flow = self.flow()
        case = self.case(flow, hour=0)
        hours = self.MODEL["resumption"]["max_resume_days"] * 24 + 1
        self.refused(lambda: flow.resume(case, hours), W.CASE_EXPIRED)
        self.assertEqual(case.state, W.EXPIRED)

    def test_the_next_step_is_none_when_everything_is_done(self):
        flow = self.flow()
        case = self.case(flow)
        self.through_limits(flow, case)
        flow.approve(case, approvers=("risk", "finance"), hour=HOUR)
        flow.go_live(case, hour=HOUR)
        self.assertIsNone(flow.next_step(case))

    # -- verification ------------------------------------------------------
    def test_a_wildcard_domain_proof_is_refused(self):
        flow = self.flow()
        case = self.case(flow)
        flow.import_credentials(case, "kms://binding/1", hour=HOUR)
        self.refused(lambda: flow.verify_domain(case, "*.example.com", "tok",
                                                issued_at_hour=HOUR, hour=HOUR),
                     W.DOMAIN_WILDCARD)

    def test_a_domain_token_is_single_use_and_expires(self):
        flow = self.flow()
        case = self.case(flow)
        flow.import_credentials(case, "kms://binding/1", hour=HOUR)
        flow.verify_domain(case, "shop.example.com", "tok_1", issued_at_hour=HOUR, hour=HOUR)
        self.refused(lambda: flow.verify_domain(case, "other.example.com", "tok_1",
                                                issued_at_hour=HOUR, hour=HOUR),
                     W.DOMAIN_TOKEN_USED)
        fresh = self.flow()
        other = self.case(fresh)
        fresh.import_credentials(other, "kms://binding/1", hour=HOUR)
        self.refused(lambda: fresh.verify_domain(other, "shop.example.com", "tok_2",
                                                 issued_at_hour=0, hour=HOUR),
                     W.DOMAIN_TOKEN_EXPIRED)

    def test_a_callback_must_be_https_and_public(self):
        flow = self.flow()
        case = self.case(flow)
        flow.import_credentials(case, "kms://binding/1", hour=HOUR)
        flow.verify_domain(case, "shop.example.com", "tok_1", issued_at_hour=HOUR, hour=HOUR)
        self.refused(lambda: flow.verify_callback(case, "http://shop.example.com/hook",
                                                  roundtrip_id="rt", signature_valid=True,
                                                  hour=HOUR), W.CALLBACK_NOT_HTTPS)
        for host in ("169.254.169.254", "127.0.0.1", "10.0.0.5", "192.168.1.1", "localhost"):
            self.refused(lambda h=host: flow.verify_callback(case, f"https://{h}/hook",
                                                             roundtrip_id="rt",
                                                             signature_valid=True, hour=HOUR),
                         W.CALLBACK_PRIVATE_ADDRESS)

    def test_a_callback_needs_a_verified_round_trip(self):
        flow = self.flow()
        case = self.case(flow)
        flow.import_credentials(case, "kms://binding/1", hour=HOUR)
        flow.verify_domain(case, "shop.example.com", "tok_1", issued_at_hour=HOUR, hour=HOUR)
        self.refused(lambda: flow.verify_callback(case, "https://shop.example.com/hook",
                                                  roundtrip_id="rt", signature_valid=False,
                                                  hour=HOUR), W.NO_EVIDENCE)

    def test_empty_limits_are_refused(self):
        flow = self.flow()
        case = self.case(flow)
        flow.import_credentials(case, "kms://binding/1", hour=HOUR)
        flow.verify_domain(case, "shop.example.com", "tok_1", issued_at_hour=HOUR, hour=HOUR)
        flow.verify_callback(case, "https://shop.example.com/hook", roundtrip_id="rt_1",
                             signature_valid=True, hour=HOUR)
        self.refused(lambda: flow.set_limits(case, {}, hour=HOUR), W.NO_LIMITS)

    # -- approval ----------------------------------------------------------
    def test_the_requester_cannot_approve_and_one_approver_is_not_enough(self):
        flow = self.flow()
        case = self.case(flow)
        self.through_limits(flow, case)
        self.refused(lambda: flow.approve(case, approvers=("ops", "risk"), hour=HOUR),
                     W.SELF_APPROVAL)
        self.refused(lambda: flow.approve(case, approvers=("risk",), hour=HOUR),
                     W.NOT_ENOUGH_EYES)
        self.refused(lambda: flow.approve(case, approvers=("risk", "risk"), hour=HOUR),
                     W.NOT_ENOUGH_EYES)

    def test_changing_the_payout_account_invalidates_the_approval(self):
        flow = self.flow()
        case = self.case(flow)
        self.through_limits(flow, case)
        flow.approve(case, approvers=("risk", "finance"), hour=HOUR)
        self.assertTrue(flow.approval_valid(case, HOUR))
        flow.amend(case, payout_account="acct_attacker")
        self.assertIsNone(case.approval)
        self.refused(lambda: flow.go_live(case, hour=HOUR), W.NOT_APPROVED)

    def test_a_tampered_payload_is_caught_at_go_live(self):
        flow = self.flow()
        case = self.case(flow)
        self.through_limits(flow, case)
        flow.approve(case, approvers=("risk", "finance"), hour=HOUR)
        case.payload["payout_account"] = "acct_attacker"      # bypassing amend()
        self.refused(lambda: flow.go_live(case, hour=HOUR), W.APPROVAL_STALE)

    def test_an_approval_expires(self):
        flow = self.flow()
        case = self.case(flow)
        self.through_limits(flow, case)
        flow.approve(case, approvers=("risk", "finance"), hour=HOUR)
        later = HOUR + self.MODEL["approval"]["expires_hours"] + 1
        self.assertFalse(flow.approval_valid(case, later))
        self.refused(lambda: flow.go_live(case, hour=later), W.APPROVAL_EXPIRED)

    def test_an_unrelated_change_keeps_the_approval(self):
        flow = self.flow()
        case = self.case(flow)
        self.through_limits(flow, case)
        flow.approve(case, approvers=("risk", "finance"), hour=HOUR)
        flow.amend(case, support_email="help@example.com")
        self.assertIsNotNone(case.approval)

    # -- go live and stop --------------------------------------------------
    def test_go_live_needs_every_step_and_a_valid_approval(self):
        flow = self.flow()
        case = self.case(flow)
        self.refused(lambda: flow.go_live(case, hour=HOUR), W.OUT_OF_ORDER)
        self.through_limits(flow, case)
        self.refused(lambda: flow.go_live(case, hour=HOUR), W.NOT_APPROVED)
        flow.approve(case, approvers=("risk", "finance"), hour=HOUR)
        self.assertEqual(flow.go_live(case, hour=HOUR), "LIVE")
        self.assertEqual(case.state, W.COMPLETE)
        self.refused(lambda: flow.go_live(case, hour=HOUR), W.ALREADY_LIVE)

    def test_stopping_takes_one_person_and_restarting_takes_two(self):
        flow = self.flow()
        case = self.case(flow)
        self.through_limits(flow, case)
        flow.approve(case, approvers=("risk", "finance"), hour=HOUR)
        flow.go_live(case, hour=HOUR)
        self.assertEqual(flow.suspend(case, actor="risk", hour=HOUR), W.SUSPENDED)
        self.refused(lambda: flow.reinstate(case, actor="risk", approvers=("risk",),
                                            hour=HOUR), W.NOT_ENOUGH_EYES)
        self.assertEqual(flow.reinstate(case, actor="ops", approvers=("risk", "finance"),
                                        hour=HOUR), W.COMPLETE)
        self.refused(lambda: flow.reinstate(case, actor="ops", approvers=("risk", "finance"),
                                            hour=HOUR), W.NOT_SUSPENDED)

    def test_the_digest_covers_only_the_declared_fields(self):
        payload = self.payload()
        fields = list(self.MODEL["approval"]["digest_fields"])
        before = W.digest_of(payload, fields)
        payload["support_email"] = "help@example.com"
        self.assertEqual(W.digest_of(payload, fields), before)
        payload["payout_account"] = "acct_attacker"
        self.assertNotEqual(W.digest_of(payload, fields), before)
