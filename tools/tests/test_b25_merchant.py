"""B25 / AT-B25-01 — merchant profile and KYB metadata.

``test_the_platform_cannot_call_itself_a_verifier`` is the test this batch
exists for. The brief says the platform manages business data but does not
replace a licensed verifier, and the cheapest way to violate that is a boolean
column named ``verified`` that our own code sets. The gate refuses a model in
which a verification status can exist without naming an external authority, a
decision reference and an expiry.

``test_a_payout_account_change_holds_settlement_without_stopping_payments``
covers the other half. Changing the payout account is the first move of an
account takeover, so it must hold the outbound leg — but suspending the whole
merchant strands every payer whose money has already left and whose order has
not shipped. Holding only settlement keeps the funds on the platform.
"""
from __future__ import annotations

import json

from libs.merchant.reference import profile as P
from tools.paygov import merchant, merchantgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/merchant-profile.json"
DAY = 1000


def _doc(model, did):
    return next(d for d in model["documents"] if d["id"] == did)


def _entity(model, kid):
    return next(e for e in model["entity_kinds"] if e["id"] == kid)


def _change(model, cid):
    return next(c for c in model["material_changes"] if c["id"] == cid)


def _risk(model, rid):
    return next(r for r in model["risk_levels"] if r["id"] == rid)


class MerchantProfileHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = merchant.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("merchant-profile", registry.names())

    def test_the_platform_cannot_call_itself_a_verifier(self):
        verification = self.fixture.read(REL)["verification"]
        self.assertFalse(verification["platform_is_licensed_verifier"])
        self.assertTrue(verification["authority_required"])
        for field in ("authority", "decision_reference", "decided_at", "valid_until"):
            self.assertIn(field, verification["authority_fields"])

    def test_verification_expires(self):
        verification = self.fixture.read(REL)["verification"]
        self.assertGreater(verification["max_validity_days"], 0)
        self.assertLessEqual(verification["max_validity_days"], 1095)

    def test_self_attestation_is_limited_to_display_fields(self):
        allowed = set(self.fixture.read(REL)["verification"]["self_attestation_allowed_for"])
        self.assertFalse(allowed & {"legal_name", "ubo", "payout_account", "country"})

    def test_every_document_expires(self):
        for document in self.fixture.read(REL)["documents"]:
            self.assertGreater(document["expires_days"], 0, document["id"])
            self.assertLessEqual(document["expires_days"], 1095, document["id"])

    def test_the_payout_account_proof_expires_first(self):
        model = self.fixture.read(REL)
        proof = _doc(model, "bank_account_proof")["expires_days"]
        for document in model["documents"]:
            self.assertLessEqual(proof, document["expires_days"], document["id"])

    def test_every_entity_kind_proves_its_payout_account(self):
        for entry in self.fixture.read(REL)["entity_kinds"]:
            self.assertIn("bank_account_proof", entry["required_documents"], entry["id"])

    def test_a_company_must_declare_its_owners(self):
        self.assertIn("ubo_declaration", _entity(self.fixture.read(REL), "company")
                      ["required_documents"])

    def test_ownership_is_pierced_not_glanced_at(self):
        ubo = self.fixture.read(REL)["ubo"]
        self.assertLessEqual(ubo["ownership_threshold_percent"], 25)
        self.assertGreaterEqual(ubo["max_ownership_depth"], 3)
        self.assertTrue(ubo["requires_identity_document"])
        self.assertTrue(ubo["screening_required"])

    def test_a_sanctions_hit_neither_approves_nor_rejects(self):
        screening = self.fixture.read(REL)["screening"]
        self.assertFalse(screening["auto_approve_on_hit"])
        self.assertTrue(screening["hit_requires_human_review"])
        self.assertGreater(screening["rescreen_interval_days"], 0)

    def test_something_is_prohibited(self):
        categories = self.fixture.read(REL)["business_categories"]
        prohibited = [c for c in categories if c["risk"] == "prohibited"]
        self.assertTrue(prohibited)
        for entry in prohibited:
            self.assertFalse(entry["allowed"], entry["code"])

    def test_settlement_currencies_exist_in_the_currency_metadata(self):
        known = {c["code"] for c in
                 self.fixture.read("governance/currency-metadata.json")["currencies"]}
        for region in self.fixture.read(REL)["operating_regions"]:
            for code in region["settlement_currencies"]:
                self.assertIn(code, known, region["code"])

    def test_higher_risk_never_buys_a_better_deal(self):
        model = self.fixture.read(REL)
        order = [r for r in merchant.RISK_ORDER]
        for lower, higher in zip(order, order[1:]):
            self.assertGreaterEqual(_risk(model, lower)["daily_limit_minor"],
                                    _risk(model, higher)["daily_limit_minor"])
            self.assertLessEqual(_risk(model, lower)["settlement_delay_days"],
                                 _risk(model, higher)["settlement_delay_days"])

    def test_high_risk_onboarding_needs_two_people(self):
        self.assertGreaterEqual(_risk(self.fixture.read(REL), "high")["approvers_required"], 2)

    def test_both_takeover_steps_reopen_verification(self):
        model = self.fixture.read(REL)
        for cid in merchant.TAKEOVER_CHANGES:
            self.assertTrue(_change(model, cid)["requires_reverification"], cid)
        self.assertTrue(_change(model, "payout_account_change")["holds_settlement"])

    def test_the_payout_account_permission_is_dual_control_in_b19(self):
        authz = self.fixture.read("governance/authorization.json")
        change = _change(self.fixture.read(REL), "payout_account_change")
        permission = next(p for p in authz["permissions"] if p["id"] == change["permission"])
        self.assertTrue(permission["dual_control"])

    def test_retention_survives_offboarding_but_stays_encrypted(self):
        retention = self.fixture.read(REL)["retention"]
        self.assertGreaterEqual(retention["after_offboarding_days"],
                                merchant.REGULATORY_RETENTION_DAYS)
        self.assertTrue(retention["documents_encrypted"])
        self.assertTrue(retention["minimise_to_declared_purpose"])

    def test_retention_stays_within_the_data_models_longest_lifetime(self):
        data = self.fixture.read("governance/data-architecture.json")
        longest = max(t["retention"]["cold_days"] for t in data["tables"])
        self.assertLessEqual(self.fixture.read(REL)["retention"]["after_offboarding_days"],
                             longest)

    def test_the_tenant_key_is_still_destroyed_at_closure(self):
        offboarding = self.fixture.read("governance/tenant-registry.json")["offboarding"]
        self.assertTrue(offboarding["kek_destruction_required"])

    def test_a_rejection_can_be_appealed_to_someone_else(self):
        appeal = self.fixture.read(REL)["appeal"]
        self.assertTrue(appeal["available"])
        self.assertTrue(appeal["decision_must_state_reasons"])
        self.assertTrue(appeal["reviewer_must_differ_from_decider"])
        self.assertGreater(appeal["response_days"], 0)

    def test_profile_decisions_map_to_a_real_audit_class(self):
        audit = self.fixture.read("governance/audit-log.json")
        self.assertIn(self.fixture.read(REL)["audit_event_class"],
                      {c["id"] for c in audit["event_classes"]})


class MerchantGeneratedArtefacts(FixtureTestCase):
    def test_generated_artefacts_match_the_model(self):
        for rel, content in merchantgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_carries_every_document(self):
        contract = json.loads(merchantgen.contract_json(REAL_ROOT))
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        self.assertEqual({d["id"] for d in contract["documents"]},
                         {d["id"] for d in model["documents"]})

    def test_document_shows_every_material_change(self):
        text = merchantgen.merchant_markdown(REAL_ROOT)
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        for change in model["material_changes"]:
            self.assertIn(change["id"], text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/merchant/MERCHANT_PROFILE.md", "hand written\n")
        self.assertIn("MERCHANT_GENERATED_DRIFT", self.codes(self._validate()))

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/merchant/profile-model.json")
        self.assertIn("MERCHANT_GENERATED_MISSING", self.codes(self._validate()))

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("documents", [{"id": "x"}]))
        self.assertIn("MERCHANT_GENERATED", self.codes(self._validate()))

    def _validate(self):
        return merchant.validate(self.fixture.root, Budget(seconds=60).start())


class MerchantGateRejects(FixtureTestCase):
    def _validate(self):
        return merchant.validate(self.fixture.root, Budget(seconds=60).start())

    def _assert(self, code):
        self.assertIn(code, self.codes(self._validate()))

    def _mutate(self, fn, code, rel=REL):
        self.fixture.mutate(rel, fn)
        self._assert(code)

    # -- shape ------------------------------------------------------------
    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self._assert("MERCHANT_UNREADABLE")

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [1])
        self._assert("MERCHANT_SHAPE")

    def test_rejects_a_non_object_verification_block(self):
        self._mutate(lambda d: d.__setitem__("verification", []), "MERCHANT_SHAPE")

    def test_rejects_a_non_object_ubo_block(self):
        self._mutate(lambda d: d.__setitem__("ubo", []), "MERCHANT_SHAPE")

    def test_rejects_a_non_object_screening_block(self):
        self._mutate(lambda d: d.__setitem__("screening", []), "MERCHANT_SHAPE")

    def test_rejects_a_non_object_retention_block(self):
        self._mutate(lambda d: d.__setitem__("retention", []), "MERCHANT_SHAPE")

    def test_rejects_an_empty_document_list(self):
        self._mutate(lambda d: d.__setitem__("documents", []), "MERCHANT_SHAPE")

    def test_rejects_an_empty_entity_kind_list(self):
        self._mutate(lambda d: d.__setitem__("entity_kinds", []), "MERCHANT_SHAPE")

    def test_rejects_an_empty_category_list(self):
        self._mutate(lambda d: d.__setitem__("business_categories", []), "MERCHANT_SHAPE")

    def test_rejects_an_empty_region_list(self):
        self._mutate(lambda d: d.__setitem__("operating_regions", []), "MERCHANT_SHAPE")

    def test_rejects_an_empty_risk_level_list(self):
        self._mutate(lambda d: d.__setitem__("risk_levels", []), "MERCHANT_SHAPE")

    def test_rejects_a_bad_schema_version(self):
        self._mutate(lambda d: d.__setitem__("schema_version", "one"), "MERCHANT_VERSION_FIELD")

    def test_rejects_a_missing_principle(self):
        self._mutate(lambda d: d.__setitem__("principle", ""), "MERCHANT_PRINCIPLE")

    # -- the central claim ------------------------------------------------
    def test_rejects_a_platform_that_declares_itself_a_verifier(self):
        self._mutate(lambda d: d["verification"].__setitem__(
            "platform_is_licensed_verifier", True), "MERCHANT_SELF_VERIFIED")

    def test_rejects_a_verification_that_needs_no_authority(self):
        self._mutate(lambda d: d["verification"].__setitem__("authority_required", False),
                     "MERCHANT_SELF_VERIFIED")

    def test_rejects_an_authority_record_without_an_expiry(self):
        self._mutate(lambda d: d["verification"].__setitem__(
            "authority_fields", ["authority", "decision_reference", "decided_at"]),
            "MERCHANT_AUTHORITY_INCOMPLETE")

    def test_rejects_a_verification_that_never_expires(self):
        self._mutate(lambda d: d["verification"].__setitem__("max_validity_days", 0),
                     "MERCHANT_VERIFICATION_FOREVER")

    def test_rejects_self_attesting_a_verified_fact(self):
        self._mutate(lambda d: d["verification"]["self_attestation_allowed_for"]
                     .append("legal_name"), "MERCHANT_SELF_ATTESTED_FACT")

    # -- documents --------------------------------------------------------
    def test_rejects_a_non_snake_case_document_id(self):
        self._mutate(lambda d: d["documents"][0].__setitem__("id", "Business Licence"),
                     "MERCHANT_DOC_ID")

    def test_rejects_a_duplicate_document(self):
        self._mutate(lambda d: d["documents"].append(dict(d["documents"][0])),
                     "MERCHANT_DOC_DUPLICATE")

    def test_rejects_a_document_that_verifies_nothing(self):
        self._mutate(lambda d: d["documents"][0].__setitem__("verifies", ""),
                     "MERCHANT_DOC_PURPOSE")

    def test_rejects_a_document_without_an_issuer(self):
        self._mutate(lambda d: d["documents"][0].__setitem__("issuer", ""),
                     "MERCHANT_DOC_ISSUER")

    def test_rejects_an_unstated_pii_flag(self):
        self._mutate(lambda d: d["documents"][0].__setitem__("contains_pii", "no"),
                     "MERCHANT_DOC_PII_FLAG")

    def test_rejects_an_unexplained_document(self):
        self._mutate(lambda d: d["documents"][0].__setitem__("notes", ""),
                     "MERCHANT_DOC_NOTES")

    def test_rejects_a_document_that_never_expires(self):
        self._mutate(lambda d: d["documents"][0].__setitem__("expires_days", 0),
                     "MERCHANT_DOC_NO_EXPIRY")

    def test_rejects_an_account_proof_that_outlives_the_other_documents(self):
        self._mutate(lambda d: _doc(d, "bank_account_proof").__setitem__("expires_days", 400),
                     "MERCHANT_ACCOUNT_PROOF_STALE")

    def test_rejects_a_non_object_document(self):
        self._mutate(lambda d: d["documents"].append("business_licence"), "MERCHANT_SHAPE")

    # -- entity kinds -----------------------------------------------------
    def test_rejects_a_duplicate_entity_kind(self):
        self._mutate(lambda d: d["entity_kinds"].append(dict(d["entity_kinds"][0])),
                     "MERCHANT_ENTITY_DUPLICATE")

    def test_rejects_an_entity_kind_that_needs_no_documents(self):
        self._mutate(lambda d: d["entity_kinds"][0].__setitem__("required_documents", []),
                     "MERCHANT_ENTITY_NO_DOCUMENTS")

    def test_rejects_a_requirement_for_an_unknown_document(self):
        self._mutate(lambda d: d["entity_kinds"][0]["required_documents"].append("passport"),
                     "MERCHANT_ENTITY_DOC_UNKNOWN")

    def test_rejects_an_entity_kind_that_never_proves_its_payout_account(self):
        self._mutate(lambda d: _entity(d, "company").__setitem__(
            "required_documents", ["business_licence", "ubo_declaration", "director_identity"]),
            "MERCHANT_ENTITY_NO_ACCOUNT_PROOF")

    def test_rejects_an_unexplained_entity_kind(self):
        self._mutate(lambda d: d["entity_kinds"][0].__setitem__("notes", ""),
                     "MERCHANT_ENTITY_NOTES")

    def test_rejects_a_company_that_hides_its_owners(self):
        self._mutate(lambda d: _entity(d, "company").__setitem__(
            "required_documents", ["business_licence", "director_identity",
                                   "bank_account_proof"]),
            "MERCHANT_COMPANY_NO_UBO")

    def test_rejects_a_non_object_entity_kind(self):
        self._mutate(lambda d: d["entity_kinds"].append("company"), "MERCHANT_SHAPE")

    # -- ownership and screening ------------------------------------------
    def test_rejects_a_beneficial_owner_threshold_above_25_percent(self):
        self._mutate(lambda d: d["ubo"].__setitem__("ownership_threshold_percent", 50),
                     "MERCHANT_UBO_THRESHOLD")

    def test_rejects_shallow_ownership_tracing(self):
        self._mutate(lambda d: d["ubo"].__setitem__("max_ownership_depth", 1),
                     "MERCHANT_UBO_DEPTH")

    def test_rejects_an_unidentified_beneficial_owner(self):
        self._mutate(lambda d: d["ubo"].__setitem__("requires_identity_document", False),
                     "MERCHANT_UBO_NO_ID")

    def test_rejects_unscreened_beneficial_owners(self):
        self._mutate(lambda d: d["ubo"].__setitem__("screening_required", False),
                     "MERCHANT_UBO_NO_SCREENING")

    def test_rejects_partial_screening(self):
        self._mutate(lambda d: d["screening"].__setitem__("lists", ["sanctions"]),
                     "MERCHANT_SCREENING_INCOMPLETE")

    def test_rejects_screening_only_at_signup(self):
        self._mutate(lambda d: d["screening"].__setitem__("rescreen_interval_days", 0),
                     "MERCHANT_SCREENING_ONCE")

    def test_rejects_auto_approving_a_sanctions_hit(self):
        self._mutate(lambda d: d["screening"].__setitem__("auto_approve_on_hit", True),
                     "MERCHANT_SANCTIONS_AUTO")

    def test_rejects_a_screening_hit_that_never_reaches_a_human(self):
        self._mutate(lambda d: d["screening"].__setitem__("hit_requires_human_review", False),
                     "MERCHANT_SANCTIONS_AUTO")

    # -- categories and regions -------------------------------------------
    def test_rejects_a_non_snake_case_category(self):
        self._mutate(lambda d: d["business_categories"][0].__setitem__("code", "Retail Goods"),
                     "MERCHANT_CATEGORY_CODE")

    def test_rejects_a_duplicate_category(self):
        self._mutate(lambda d: d["business_categories"].append(
            dict(d["business_categories"][0])), "MERCHANT_CATEGORY_DUPLICATE")

    def test_rejects_an_unknown_risk_band(self):
        self._mutate(lambda d: d["business_categories"][0].__setitem__("risk", "extreme"),
                     "MERCHANT_CATEGORY_RISK")

    def test_rejects_an_unexplained_category(self):
        self._mutate(lambda d: d["business_categories"][0].__setitem__("notes", ""),
                     "MERCHANT_CATEGORY_NOTES")

    def test_rejects_a_prohibited_category_that_is_still_allowed(self):
        self._mutate(lambda d: next(c for c in d["business_categories"]
                                    if c["risk"] == "prohibited").__setitem__("allowed", True),
                     "MERCHANT_PROHIBITED_CATEGORY_ALLOWED")

    def test_rejects_a_platform_that_prohibits_nothing(self):
        self._mutate(lambda d: d.__setitem__(
            "business_categories", [c for c in d["business_categories"]
                                    if c["risk"] != "prohibited"]),
            "MERCHANT_NO_PROHIBITED_LIST")

    def test_rejects_a_non_object_category(self):
        self._mutate(lambda d: d["business_categories"].append("retail_goods"), "MERCHANT_SHAPE")

    def test_rejects_a_lowercase_region_code(self):
        self._mutate(lambda d: d["operating_regions"][0].__setitem__("code", "cn"),
                     "MERCHANT_REGION_CODE")

    def test_rejects_a_duplicate_region(self):
        self._mutate(lambda d: d["operating_regions"].append(dict(d["operating_regions"][0])),
                     "MERCHANT_REGION_DUPLICATE")

    def test_rejects_a_region_with_no_settlement_currency(self):
        self._mutate(lambda d: d["operating_regions"][0].__setitem__(
            "settlement_currencies", []), "MERCHANT_REGION_NO_CURRENCY")

    def test_rejects_a_currency_the_money_model_does_not_know(self):
        self._mutate(lambda d: d["operating_regions"][0].__setitem__(
            "settlement_currencies", ["XYZ"]), "MERCHANT_CURRENCY_UNKNOWN")

    def test_rejects_an_unstated_local_entity_rule(self):
        self._mutate(lambda d: d["operating_regions"][0].__setitem__(
            "requires_local_entity", "yes"), "MERCHANT_REGION_ENTITY_RULE")

    def test_rejects_an_unexplained_region(self):
        self._mutate(lambda d: d["operating_regions"][0].__setitem__("notes", ""),
                     "MERCHANT_REGION_NOTES")

    def test_rejects_a_non_object_region(self):
        self._mutate(lambda d: d["operating_regions"].append("CN"), "MERCHANT_SHAPE")

    # -- risk levels ------------------------------------------------------
    def test_rejects_an_invented_risk_level(self):
        self._mutate(lambda d: d["risk_levels"][0].__setitem__("id", "tiny"),
                     "MERCHANT_RISK_LEVEL")

    def test_rejects_a_risk_level_without_limits(self):
        self._mutate(lambda d: d["risk_levels"][0].__setitem__("daily_limit_minor", 0),
                     "MERCHANT_RISK_NO_LIMIT")

    def test_rejects_a_risk_level_without_a_settlement_delay(self):
        self._mutate(lambda d: d["risk_levels"][0].__setitem__("settlement_delay_days", -1),
                     "MERCHANT_RISK_NO_DELAY")

    def test_rejects_a_risk_level_nobody_approves(self):
        self._mutate(lambda d: d["risk_levels"][0].__setitem__("approvers_required", 0),
                     "MERCHANT_RISK_NO_APPROVER")

    def test_rejects_one_person_onboarding_a_high_risk_merchant(self):
        self._mutate(lambda d: _risk(d, "high").__setitem__("approvers_required", 1),
                     "MERCHANT_HIGH_RISK_SINGLE_APPROVER")

    def test_rejects_higher_risk_buying_a_higher_daily_limit(self):
        self._mutate(lambda d: _risk(d, "high").__setitem__("daily_limit_minor", 10 ** 12),
                     "MERCHANT_RISK_LIMITS_INVERTED")

    def test_rejects_higher_risk_buying_faster_settlement(self):
        self._mutate(lambda d: _risk(d, "high").__setitem__("settlement_delay_days", 0),
                     "MERCHANT_RISK_DELAY_INVERTED")

    def test_rejects_an_unexplained_risk_level(self):
        self._mutate(lambda d: d["risk_levels"][0].__setitem__("notes", ""),
                     "MERCHANT_RISK_NOTES")

    def test_rejects_a_non_object_risk_level(self):
        self._mutate(lambda d: d["risk_levels"].append("low"), "MERCHANT_SHAPE")

    # -- material changes -------------------------------------------------
    def test_rejects_a_model_with_no_change_triggers(self):
        self._mutate(lambda d: d.__setitem__("material_changes", []),
                     "MERCHANT_NO_CHANGE_TRIGGERS")

    def test_rejects_a_duplicate_change(self):
        self._mutate(lambda d: d["material_changes"].append(dict(d["material_changes"][0])),
                     "MERCHANT_CHANGE_DUPLICATE")

    def test_rejects_a_material_change_that_does_not_reopen_verification(self):
        self._mutate(lambda d: d["material_changes"][0].__setitem__(
            "requires_reverification", False), "MERCHANT_CHANGE_NO_REVERIFY")

    def test_rejects_a_change_guarded_by_an_unknown_permission(self):
        self._mutate(lambda d: d["material_changes"][0].__setitem__("permission", "made.up"),
                     "MERCHANT_CHANGE_PERMISSION_UNKNOWN")

    def test_rejects_an_unexplained_change(self):
        self._mutate(lambda d: d["material_changes"][0].__setitem__("notes", ""),
                     "MERCHANT_CHANGE_NOTES")

    def test_rejects_a_payout_account_change_that_keeps_paying_out(self):
        self._mutate(lambda d: _change(d, "payout_account_change").__setitem__(
            "holds_settlement", False), "MERCHANT_ACCOUNT_CHANGE_NO_HOLD")

    def test_rejects_a_payout_account_change_one_person_can_make(self):
        self.fixture.mutate("governance/authorization.json",
                            lambda d: next(p for p in d["permissions"]
                                           if p["id"] == "payout_account.write")
                            .__setitem__("dual_control", False))
        self._assert("MERCHANT_ACCOUNT_CHANGE_SINGLE_PERSON")

    def test_rejects_a_missing_takeover_trigger(self):
        self._mutate(lambda d: d.__setitem__(
            "material_changes", [c for c in d["material_changes"] if c["id"] != "ubo_change"]),
            "MERCHANT_CHANGE_MISSING")

    def test_rejects_a_non_object_change(self):
        self._mutate(lambda d: d["material_changes"].append("ubo_change"), "MERCHANT_SHAPE")

    # -- retention, appeal, audit -----------------------------------------
    def test_rejects_retention_shorter_than_the_regulator_requires(self):
        self._mutate(lambda d: d["retention"].__setitem__("after_offboarding_days", 30),
                     "MERCHANT_RETENTION_SHORT")

    def test_rejects_plaintext_kyb_documents(self):
        self._mutate(lambda d: d["retention"].__setitem__("documents_encrypted", False),
                     "MERCHANT_DOCS_PLAINTEXT")

    def test_rejects_collection_beyond_the_declared_purpose(self):
        self._mutate(lambda d: d["retention"].__setitem__("minimise_to_declared_purpose", False),
                     "MERCHANT_NO_MINIMISATION")

    def test_rejects_retention_beyond_the_data_models_longest_lifetime(self):
        self._mutate(lambda d: d["retention"].__setitem__("after_offboarding_days", 10 ** 6),
                     "MERCHANT_RETENTION_BEYOND_DATA")

    def test_rejects_retention_that_cannot_be_shredded(self):
        self.fixture.mutate("governance/tenant-registry.json",
                            lambda d: d["offboarding"].__setitem__(
                                "kek_destruction_required", False))
        self._assert("MERCHANT_RETENTION_UNSHREDDABLE")

    def test_rejects_a_decision_that_cannot_be_appealed(self):
        self._mutate(lambda d: d["appeal"].__setitem__("available", False), "MERCHANT_NO_APPEAL")

    def test_rejects_a_missing_appeal_block(self):
        self._mutate(lambda d: d.__setitem__("appeal", []), "MERCHANT_NO_APPEAL")

    def test_rejects_an_unexplained_rejection(self):
        self._mutate(lambda d: d["appeal"].__setitem__("decision_must_state_reasons", False),
                     "MERCHANT_DECISION_UNEXPLAINED")

    def test_rejects_an_appeal_reviewed_by_the_original_decider(self):
        self._mutate(lambda d: d["appeal"].__setitem__(
            "reviewer_must_differ_from_decider", False), "MERCHANT_APPEAL_SELF_REVIEW")

    def test_rejects_an_appeal_with_no_deadline(self):
        self._mutate(lambda d: d["appeal"].__setitem__("response_days", 0),
                     "MERCHANT_APPEAL_UNBOUNDED")

    def test_rejects_an_unknown_audit_class(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "merchant.vanished"),
                     "MERCHANT_AUDIT_CLASS_UNKNOWN")


class MerchantReferenceModel(FixtureTestCase):
    MODEL = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))

    def engine(self) -> P.Onboarding:
        return P.Onboarding(self.MODEL)

    def documents(self, day=DAY, account_proof_day=None):
        return (P.Document("business_licence", day - 30, "registry"),
                P.Document("ubo_declaration", day - 30, "merchant"),
                P.Document("director_identity", day - 30, "government"),
                P.Document("bank_account_proof",
                           day - 30 if account_proof_day is None else account_proof_day, "bank"))

    def owners(self, **overrides):
        base = dict(id="ubo_1", percent=60.0, depth=2, has_identity_document=True,
                    screened_on=DAY - 10, screening_hit=False)
        base.update(overrides)
        return (P.Owner(**base),)

    def authority(self, day=DAY) -> P.Authority:
        return P.Authority("hk-companies-registry", "CR-2026-000188", day - 5, day + 700)

    def onboarded(self, engine=None, *, risk="low", docs=None, people=None, mid="mch_1"):
        engine = engine or self.engine()
        engine.register(mid, entity_kind="company", category="retail_goods", region="HK",
                        risk=risk)
        for document in (self.documents() if docs is None else docs):
            engine.attach(mid, document)
        engine.set_owners(mid, self.owners() if people is None else people)
        return engine

    def refused(self, fn, code):
        with self.assertRaises(P.ProfileRefused) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    # -- the central claim ------------------------------------------------
    def test_the_platform_cannot_mark_itself_verified(self):
        engine = self.onboarded()
        self.refused(lambda: engine.mark_verified("mch_1"), P.DENY_SELF_VERIFIED)

    def test_a_decision_without_an_authority_is_refused(self):
        engine = self.onboarded()
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=None, decider="ops",
                                           approvers=("risk",)), P.DENY_SELF_VERIFIED)

    def test_an_incomplete_authority_record_is_refused(self):
        engine = self.onboarded()
        self.refused(lambda: engine.decide(
            "mch_1", today=DAY, authority=P.Authority("", "CR-1", DAY - 5, DAY + 700),
            decider="ops", approvers=("risk",)), P.DENY_AUTHORITY_INCOMPLETE)

    def test_an_expired_authority_record_is_refused(self):
        engine = self.onboarded()
        self.refused(lambda: engine.decide(
            "mch_1", today=DAY, authority=P.Authority("hk", "CR-1", DAY - 800, DAY - 100),
            decider="ops", approvers=("risk",)), P.DENY_AUTHORITY_EXPIRED)

    def test_an_authority_record_that_lasts_too_long_is_refused(self):
        engine = self.onboarded()
        limit = self.MODEL["verification"]["max_validity_days"]
        self.refused(lambda: engine.decide(
            "mch_1", today=DAY, authority=P.Authority("hk", "CR-1", DAY, DAY + limit + 1),
            decider="ops", approvers=("risk",)), P.DENY_VALIDITY_TOO_LONG)

    def test_a_complete_authority_record_verifies(self):
        engine = self.onboarded()
        merchant_record = engine.decide("mch_1", today=DAY, authority=self.authority(),
                                        decider="ops", approvers=("risk",))
        self.assertEqual(merchant_record.status, P.VERIFIED)
        self.assertTrue(engine.verification_current("mch_1", DAY))
        self.assertFalse(engine.verification_current("mch_1", DAY + 1000))

    # -- evidence ---------------------------------------------------------
    def test_only_display_fields_may_be_self_attested(self):
        engine = self.onboarded()
        self.refused(lambda: engine.attest("mch_1", "legal_name", "X"), P.DENY_NOT_ATTESTABLE)
        self.assertEqual(engine.attest("mch_1", "display_name", "店").attested["display_name"],
                         "店")

    def test_an_unknown_document_is_refused(self):
        engine = self.onboarded()
        self.refused(lambda: engine.attach("mch_1", P.Document("passport", DAY, "gov")),
                     P.DENY_UNKNOWN)

    def test_an_incomplete_file_cannot_be_submitted(self):
        engine = self.engine()
        engine.register("mch_bare", entity_kind="company", category="retail_goods", region="HK")
        self.refused(lambda: engine.submit("mch_bare", DAY), P.DENY_DOCUMENT_MISSING)

    def test_a_complete_file_can_be_submitted(self):
        engine = self.onboarded()
        self.assertEqual(engine.submit("mch_1", DAY).status, P.PENDING_REVIEW)

    def test_an_expired_account_proof_is_no_evidence_at_all(self):
        engine = self.onboarded(docs=self.documents(account_proof_day=DAY - 200))
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=self.authority(),
                                           decider="ops", approvers=("risk",)),
                     P.DENY_DOCUMENT_EXPIRED)

    def test_missing_and_stale_documents_are_reported_separately(self):
        engine = self.onboarded(docs=self.documents(account_proof_day=DAY - 200)[:3]
                                + (P.Document("bank_account_proof", DAY - 200, "bank"),))
        missing, stale = engine.missing_documents("mch_1", DAY)
        self.assertEqual(missing, ())
        self.assertEqual(stale, ("bank_account_proof",))

    def test_an_unknown_merchant_is_refused(self):
        self.refused(lambda: self.engine().get("mch_nope"), P.DENY_UNKNOWN)

    def test_an_unknown_entity_kind_region_or_risk_is_refused(self):
        engine = self.engine()
        self.refused(lambda: engine.register("m", entity_kind="trust",
                                             category="retail_goods", region="HK"),
                     P.DENY_UNKNOWN)
        self.refused(lambda: engine.register("m", entity_kind="company",
                                             category="retail_goods", region="ZZ"),
                     P.DENY_UNKNOWN)
        self.refused(lambda: engine.register("m", entity_kind="company",
                                             category="retail_goods", region="HK", risk="none"),
                     P.DENY_UNKNOWN)
        self.refused(lambda: engine.register("m", entity_kind="company",
                                             category="fireworks", region="HK"),
                     P.DENY_UNKNOWN)

    # -- ownership and screening ------------------------------------------
    def test_ownership_deeper_than_the_model_allows_is_refused(self):
        depth = self.MODEL["ubo"]["max_ownership_depth"] + 1
        engine = self.onboarded(people=self.owners(depth=depth))
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=self.authority(),
                                           decider="ops", approvers=("risk",)),
                     P.DENY_UBO_DEPTH)

    def test_a_company_with_nobody_above_the_threshold_is_refused(self):
        engine = self.onboarded(people=(P.Owner("a", 10.0, 1, screened_on=DAY),
                                        P.Owner("b", 10.0, 1, screened_on=DAY)))
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=self.authority(),
                                           decider="ops", approvers=("risk",)),
                     P.DENY_UBO_INCOMPLETE)

    def test_an_unidentified_beneficial_owner_is_refused(self):
        engine = self.onboarded(people=self.owners(has_identity_document=False))
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=self.authority(),
                                           decider="ops", approvers=("risk",)),
                     P.DENY_UBO_INCOMPLETE)

    def test_an_individual_needs_no_cap_table(self):
        engine = self.engine()
        engine.register("mch_p", entity_kind="individual", category="retail_goods", region="HK")
        for document in (P.Document("director_identity", DAY - 30, "government"),
                         P.Document("bank_account_proof", DAY - 30, "bank")):
            engine.attach("mch_p", document)
        self.assertEqual(engine.require_ownership("mch_p", DAY), "OK")

    def test_screening_that_was_never_run_is_refused(self):
        engine = self.onboarded(people=self.owners(screened_on=None))
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=self.authority(),
                                           decider="ops", approvers=("risk",)),
                     P.DENY_SCREENING_STALE)

    def test_screening_older_than_the_interval_is_refused(self):
        stale = DAY - self.MODEL["screening"]["rescreen_interval_days"] - 1
        engine = self.onboarded(people=self.owners(screened_on=stale))
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=self.authority(),
                                           decider="ops", approvers=("risk",)),
                     P.DENY_SCREENING_STALE)

    def test_a_screening_hit_blocks_approval(self):
        engine = self.onboarded(people=self.owners(screening_hit=True))
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=self.authority(),
                                           decider="ops", approvers=("risk",)),
                     P.DENY_SCREENING_HIT)

    def test_a_screening_hit_parks_the_file_for_a_human(self):
        engine = self.onboarded(people=self.owners(screening_hit=True))
        self.assertEqual(engine.screen("mch_1", DAY), P.MANUAL_REVIEW)
        self.assertEqual(engine.get("mch_1").history[-1]["event"], "screening_hit")

    def test_a_clean_screen_leaves_the_status_alone(self):
        engine = self.onboarded()
        engine.decide("mch_1", today=DAY, authority=self.authority(), decider="ops",
                      approvers=("risk",))
        self.assertEqual(engine.screen("mch_1", DAY), P.VERIFIED)

    # -- decisions --------------------------------------------------------
    def test_a_prohibited_category_cannot_be_registered(self):
        prohibited = next(c for c in self.MODEL["business_categories"]
                          if c["risk"] == "prohibited")
        self.refused(lambda: self.engine().register("m", entity_kind="company",
                                                    category=prohibited["code"], region="HK"),
                     P.DENY_PROHIBITED_CATEGORY)

    def test_a_decider_cannot_be_their_own_approver(self):
        engine = self.onboarded()
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=self.authority(),
                                           decider="ops", approvers=("ops",)),
                     P.DENY_SELF_APPROVAL)

    def test_high_risk_needs_two_approvers(self):
        engine = self.onboarded(risk="high")
        self.refused(lambda: engine.decide("mch_1", today=DAY, authority=self.authority(),
                                           decider="ops", approvers=("risk",)),
                     P.DENY_APPROVERS)
        self.assertEqual(engine.decide("mch_1", today=DAY, authority=self.authority(),
                                       decider="ops",
                                       approvers=("risk", "compliance")).status, P.VERIFIED)

    def test_a_rejection_must_state_reasons(self):
        engine = self.onboarded()
        self.refused(lambda: engine.reject("mch_1", decider="ops", reasons=(), today=DAY),
                     P.DENY_NO_REASONS)
        self.assertEqual(engine.reject("mch_1", decider="ops", reasons=("不一致",),
                                       today=DAY).status, P.REJECTED)

    def test_an_appeal_cannot_be_reviewed_by_the_decider(self):
        engine = self.onboarded()
        engine.reject("mch_1", decider="ops", reasons=("不一致",), today=DAY)
        self.refused(lambda: engine.appeal("mch_1", reviewer="ops", today=DAY),
                     P.DENY_SELF_APPROVAL)
        self.assertEqual(engine.appeal("mch_1", reviewer="compliance", today=DAY).status,
                         P.MANUAL_REVIEW)

    # -- change of circumstance -------------------------------------------
    def test_a_payout_account_change_holds_settlement_without_stopping_payments(self):
        engine = self.onboarded()
        engine.decide("mch_1", today=DAY, authority=self.authority(), decider="ops",
                      approvers=("risk",))
        engine.apply_change("mch_1", "payout_account_change", actor="attacker",
                            permissions={"payout_account.write"}, today=DAY)
        self.assertEqual(engine.reverification_pending("mch_1"), ("payout_account_change",))
        self.refused(lambda: engine.settle("mch_1", "HKD", today=DAY), P.DENY_SETTLEMENT_HELD)
        # The money already on its way must still be collectable, or the payers
        # of a merchant under review pay for goods that can never be shipped.
        self.assertEqual(engine.accept_payment("mch_1", 1000, today=DAY), 1000)

    def test_the_requester_cannot_lift_their_own_hold(self):
        engine = self.onboarded()
        engine.decide("mch_1", today=DAY, authority=self.authority(), decider="ops",
                      approvers=("risk",))
        engine.apply_change("mch_1", "payout_account_change", actor="attacker",
                            permissions={"payout_account.write"}, today=DAY)
        self.refused(lambda: engine.release_hold("mch_1", actor="attacker", today=DAY),
                     P.DENY_SELF_APPROVAL)
        self.refused(lambda: engine.release_hold("mch_1", actor="ops", today=DAY),
                     P.DENY_REVERIFICATION_REQUIRED)

    def test_reverification_lifts_the_hold(self):
        engine = self.onboarded()
        engine.decide("mch_1", today=DAY, authority=self.authority(), decider="ops",
                      approvers=("risk",))
        engine.apply_change("mch_1", "payout_account_change", actor="attacker",
                            permissions={"payout_account.write"}, today=DAY)
        engine.decide("mch_1", today=DAY, authority=self.authority(), decider="ops",
                      approvers=("risk",))
        self.assertEqual(engine.reverification_pending("mch_1"), ())
        self.assertEqual(engine.settle("mch_1", "HKD", today=DAY),
                         DAY + self.MODEL["risk_levels"][0]["settlement_delay_days"])

    def test_a_change_that_does_not_hold_settlement_does_not_hold_settlement(self):
        engine = self.onboarded()
        engine.decide("mch_1", today=DAY, authority=self.authority(), decider="ops",
                      approvers=("risk",))
        engine.apply_change("mch_1", "ubo_change", actor="ops",
                            permissions={"config.write"}, today=DAY)
        self.assertEqual(engine.reverification_pending("mch_1"), ("ubo_change",))
        self.assertGreater(engine.settle("mch_1", "HKD", today=DAY), DAY)

    def test_a_change_needs_its_permission(self):
        engine = self.onboarded()
        self.refused(lambda: engine.apply_change("mch_1", "ubo_change", actor="support",
                                                 permissions=set(), today=DAY),
                     P.DENY_PERMISSION)
        self.refused(lambda: engine.apply_change("mch_1", "moon_phase_change", actor="ops",
                                                 permissions={"config.write"}, today=DAY),
                     P.DENY_UNKNOWN)

    # -- money ------------------------------------------------------------
    def test_an_unverified_merchant_cannot_take_money(self):
        engine = self.onboarded()
        self.refused(lambda: engine.accept_payment("mch_1", 100, today=DAY),
                     P.DENY_REVERIFICATION_REQUIRED)

    def test_limits_are_enforced_per_transaction_and_per_day(self):
        engine = self.onboarded()
        engine.decide("mch_1", today=DAY, authority=self.authority(), decider="ops",
                      approvers=("risk",))
        limits = engine.limits("mch_1")
        self.refused(lambda: engine.accept_payment("mch_1", limits["single_limit_minor"] + 1,
                                                   today=DAY), P.DENY_LIMIT)
        taken = 0
        while taken + limits["single_limit_minor"] <= limits["daily_limit_minor"]:
            engine.accept_payment("mch_1", limits["single_limit_minor"], today=DAY)
            taken += limits["single_limit_minor"]
        self.refused(lambda: engine.accept_payment("mch_1", limits["single_limit_minor"],
                                                   today=DAY), P.DENY_LIMIT)
        self.assertEqual(engine.accept_payment("mch_1", 100, today=DAY + 1), 100)

    def test_a_region_only_settles_its_own_currencies(self):
        engine = self.onboarded()
        engine.decide("mch_1", today=DAY, authority=self.authority(), decider="ops",
                      approvers=("risk",))
        self.refused(lambda: engine.settle("mch_1", "EUR", today=DAY), P.DENY_CURRENCY)

    def test_settlement_stops_when_the_authority_record_expires(self):
        engine = self.onboarded()
        engine.decide("mch_1", today=DAY, authority=self.authority(), decider="ops",
                      approvers=("risk",))
        self.refused(lambda: engine.settle("mch_1", "HKD", today=DAY + 1000),
                     P.DENY_REVERIFICATION_REQUIRED)

    def test_the_purge_day_follows_the_retention_period(self):
        self.assertEqual(self.engine().purge_day(DAY),
                         DAY + self.MODEL["retention"]["after_offboarding_days"])
