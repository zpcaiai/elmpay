"""B32 / AT-B32-01 — the payment intent's immutable amount snapshot.

``test_the_amount_cannot_be_changed_by_any_route`` is the test this batch exists
for. It closes every door at once: the snapshot is a frozen dataclass, ``amend``
refuses the snapshot fields by name, and there is no privileged caller. A payer
authorises one number, and an editable number means "what they agreed to" and
"what was taken" are allowed to differ with nothing in the record to show it.

``test_one_business_order_may_have_one_live_intent`` covers the cheapest double
charge there is.
"""
from __future__ import annotations

import dataclasses
import json

from libs.intent.reference import intent as I
from tools.paygov import intent, intentgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/payment-intent.json"
MINUTE = 10_000


class PaymentIntentHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = intent.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("payment-intent", registry.names())

    def test_the_amount_snapshot_is_immutable_and_complete(self):
        snapshot = self.fixture.read(REL)["amount_snapshot"]
        self.assertTrue(snapshot["immutable"])
        self.assertTrue(snapshot["change_requires_new_intent"])
        self.assertTrue(intent.SNAPSHOT_FIELDS <= set(snapshot["fields"]))
        self.assertTrue(snapshot["minor_units_only"])
        self.assertEqual(snapshot["exponent_source"], "governance/currency-metadata.json")

    def test_the_snapshot_fields_exist_on_the_b08_entity(self):
        domain = self.fixture.read("governance/domain-model.json")
        entity = next(e for e in domain["entities"] if e["name"] == "PaymentIntent")
        known = {f["name"] for f in entity["fields"]}
        self.assertTrue(set(self.fixture.read(REL)["amount_snapshot"]["fields"]) <= known)

    def test_the_lifecycle_is_exactly_the_b10_machine(self):
        model = self.fixture.read(REL)
        machines = self.fixture.read("governance/state-machines.json")
        machine = next(m for m in machines["machines"] if m["entity"] == "PaymentIntent")
        self.assertEqual(model["lifecycle"]["states"], machine["states"])
        self.assertEqual(model["lifecycle"]["initial"], machine["initial"])
        self.assertEqual(model["lifecycle"]["terminal"], machine["terminal"])
        self.assertEqual(model["lifecycle"]["success_states"],
                         machines["success_states"]["PaymentIntent"])

    def test_expiry_is_bounded_recorded_and_not_extendable(self):
        expiry = self.fixture.read(REL)["expiry"]
        self.assertGreater(expiry["default_minutes"], 0)
        self.assertLessEqual(expiry["default_minutes"], expiry["max_minutes"])
        self.assertLessEqual(expiry["max_minutes"], intent.MAX_EXPIRY_MINUTES)
        self.assertTrue(expiry["recorded_at_creation"])
        self.assertFalse(expiry["extension_allowed"])
        self.assertFalse(expiry["expired_can_be_confirmed"])
        self.assertEqual(expiry["expiry_actor"], "scheduler")

    def test_confirmation_is_idempotent_and_evidence_based(self):
        confirmation = self.fixture.read(REL)["confirmation"]
        self.assertTrue(confirmation["idempotency_key_required"])
        self.assertTrue({"tenant_id", "intent_id"} <= set(confirmation["key_unique_per"]))
        self.assertTrue(confirmation["single_success"])
        self.assertTrue(confirmation["concurrent_confirmations_serialized"])
        self.assertFalse(confirmation["client_return_page_is_evidence"])
        self.assertTrue(intent.AUTHORITATIVE_SOURCES
                        <= set(confirmation["authoritative_sources"]))

    def test_methods_are_frozen_at_creation_and_may_only_narrow(self):
        methods = self.fixture.read(REL)["method_constraints"]
        self.assertTrue(methods["snapshot_at_creation"])
        self.assertTrue(methods["confirm_method_must_be_in_snapshot"])
        self.assertFalse(methods["widen_after_creation_allowed"])
        self.assertEqual(methods["source"], "governance/provider-capabilities.json")

    def test_the_business_order_stays_with_the_project(self):
        order = self.fixture.read(REL)["order_link"]
        self.assertEqual(order["owner"], "originating_project")
        self.assertTrue(intent.ORDER_FIELDS <= set(order["reference_fields"]))
        self.assertTrue(order["unique_live_intent_per_order"])
        self.assertFalse(order["stores_order_content"])
        self.assertTrue(intent.FORBIDDEN_ORDER_CONTENT <= set(order["forbidden_fields"]))

    def test_the_b08_entity_carries_no_order_content(self):
        domain = self.fixture.read("governance/domain-model.json")
        entity = next(e for e in domain["entities"] if e["name"] == "PaymentIntent")
        known = {f["name"] for f in entity["fields"]}
        forbidden = set(self.fixture.read(REL)["order_link"]["forbidden_fields"])
        self.assertEqual(known & forbidden, set())
        self.assertIn("external_reference", known)

    def test_the_amount_invariants_hold_the_ledger_together(self):
        invariants = self.fixture.read(REL)["amount_invariants"]
        self.assertTrue(invariants["captured_cannot_exceed_amount"])
        self.assertTrue(invariants["refunded_cannot_exceed_captured"])
        self.assertTrue(invariants["negative_amounts_forbidden"])
        self.assertFalse(invariants["zero_amount_intent_allowed"])

    def test_the_client_reference_carries_no_credential(self):
        secret = self.fixture.read(REL)["client_secret"]
        self.assertFalse(secret["contains_credentials"])
        self.assertTrue(secret["scoped_to_single_intent"])
        self.assertTrue(secret["expires_with_intent"])

    def test_intent_events_are_money_events(self):
        audit = self.fixture.read("governance/audit-log.json")
        model = self.fixture.read(REL)
        self.assertEqual(model["audit_event_class"], "money.movement")
        self.assertIn(model["audit_event_class"], {c["id"] for c in audit["event_classes"]})


class IntentGeneratedArtefacts(FixtureTestCase):
    def _validate(self):
        return intent.validate(self.fixture.root, Budget(seconds=60).start())

    def test_generated_artefacts_match_the_model(self):
        for rel, content in intentgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_keeps_the_state_order(self):
        contract = json.loads(intentgen.contract_json(REAL_ROOT))
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        self.assertEqual(contract["lifecycle"]["states"], model["lifecycle"]["states"])

    def test_document_shows_every_state(self):
        text = intentgen.intent_markdown(REAL_ROOT)
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        for state in model["lifecycle"]["states"]:
            self.assertIn(state, text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/payment/PAYMENT_INTENT.md", "hand written\n")
        self.assertIn("INTENT_GENERATED_DRIFT", self.codes(self._validate()))

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/payment/intent.json")
        self.assertIn("INTENT_GENERATED_MISSING", self.codes(self._validate()))

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("expiry", {"default_minutes": 1}))
        self.assertIn("INTENT_GENERATED", self.codes(self._validate()))


class IntentGateRejects(FixtureTestCase):
    def _validate(self):
        return intent.validate(self.fixture.root, Budget(seconds=60).start())

    def _assert(self, code):
        self.assertIn(code, self.codes(self._validate()))

    def _mutate(self, fn, code, rel=REL):
        self.fixture.mutate(rel, fn)
        self._assert(code)

    # -- shape ------------------------------------------------------------
    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self._assert("INTENT_UNREADABLE")

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [1])
        self._assert("INTENT_SHAPE")

    def test_rejects_a_bad_schema_version(self):
        self._mutate(lambda d: d.__setitem__("schema_version", "one"),
                     "INTENT_VERSION_FIELD")

    def test_rejects_a_missing_principle(self):
        self._mutate(lambda d: d.__setitem__("principle", ""), "INTENT_PRINCIPLE")

    def test_rejects_a_non_object_lifecycle(self):
        self._mutate(lambda d: d.__setitem__("lifecycle", []), "INTENT_SHAPE")

    def test_rejects_a_non_object_method_block(self):
        self._mutate(lambda d: d.__setitem__("method_constraints", []), "INTENT_SHAPE")

    def test_rejects_a_non_object_invariant_block(self):
        self._mutate(lambda d: d.__setitem__("amount_invariants", []), "INTENT_SHAPE")

    def test_rejects_a_non_object_client_secret_block(self):
        self._mutate(lambda d: d.__setitem__("client_secret", []), "INTENT_SHAPE")

    # -- the amount snapshot ----------------------------------------------
    def test_rejects_a_missing_snapshot_policy(self):
        self._mutate(lambda d: d.__setitem__("amount_snapshot", []),
                     "INTENT_AMOUNT_MUTABLE")

    def test_rejects_a_mutable_amount(self):
        self._mutate(lambda d: d["amount_snapshot"].__setitem__("immutable", False),
                     "INTENT_AMOUNT_MUTABLE")

    def test_rejects_editing_instead_of_recreating(self):
        self._mutate(lambda d: d["amount_snapshot"].__setitem__("change_requires_new_intent",
                                                                False),
                     "INTENT_AMOUNT_MUTABLE")

    def test_rejects_a_snapshot_without_the_currency(self):
        self._mutate(lambda d: d["amount_snapshot"].__setitem__("fields", ["amount_minor"]),
                     "INTENT_SNAPSHOT_INCOMPLETE")

    def test_rejects_amounts_outside_minor_units(self):
        self._mutate(lambda d: d["amount_snapshot"].__setitem__("minor_units_only", False),
                     "INTENT_AMOUNT_NOT_MINOR")

    def test_rejects_a_second_precision_table(self):
        self._mutate(lambda d: d["amount_snapshot"].__setitem__("exponent_source",
                                                                "code/constants.py"),
                     "INTENT_EXPONENT_SOURCE")

    def test_rejects_a_snapshot_field_the_entity_does_not_have(self):
        self._mutate(lambda d: d["amount_snapshot"]["fields"].append("tip_minor"),
                     "INTENT_FIELD_UNKNOWN")

    def test_rejects_an_unexplained_snapshot(self):
        self._mutate(lambda d: d["amount_snapshot"].__setitem__("notes", ""),
                     "INTENT_SNAPSHOT_NOTES")

    # -- lifecycle --------------------------------------------------------
    def test_rejects_states_that_diverge_from_b10(self):
        self._mutate(lambda d: d["lifecycle"]["states"].append("half_paid"),
                     "INTENT_STATES_DIVERGE")

    def test_rejects_a_different_initial_state(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("initial", "authorized"),
                     "INTENT_STATES_DIVERGE")

    def test_rejects_different_terminal_states(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("terminal", ["captured"]),
                     "INTENT_STATES_DIVERGE")

    def test_rejects_disagreeing_about_what_counts_as_paid(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("success_states", ["captured"]),
                     "INTENT_SUCCESS_DIVERGE")

    def test_rejects_a_lifecycle_with_no_source(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("source", "our heads"),
                     "INTENT_LIFECYCLE_UNSOURCED")

    def test_rejects_b10_being_changed_underneath(self):
        self.fixture.mutate("governance/state-machines.json",
                            lambda d: next(m for m in d["machines"]
                                           if m["entity"] == "PaymentIntent")["states"]
                            .append("half_paid"))
        self._assert("INTENT_STATES_DIVERGE")

    def test_rejects_an_unexplained_lifecycle(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("notes", ""),
                     "INTENT_LIFECYCLE_NOTES")

    # -- expiry -----------------------------------------------------------
    def test_rejects_an_intent_that_never_expires(self):
        self._mutate(lambda d: d["expiry"].__setitem__("default_minutes", 0),
                     "INTENT_NO_EXPIRY")

    def test_rejects_an_expiry_beyond_a_day(self):
        self._mutate(lambda d: d["expiry"].__setitem__("max_minutes", 100000),
                     "INTENT_EXPIRY_TOO_LONG")

    def test_rejects_computing_the_expiry_on_read(self):
        self._mutate(lambda d: d["expiry"].__setitem__("recorded_at_creation", False),
                     "INTENT_EXPIRY_LATE")

    def test_rejects_extending_an_expiry(self):
        self._mutate(lambda d: d["expiry"].__setitem__("extension_allowed", True),
                     "INTENT_EXPIRY_EXTENDABLE")

    def test_rejects_confirming_an_expired_intent(self):
        self._mutate(lambda d: d["expiry"].__setitem__("expired_can_be_confirmed", True),
                     "INTENT_EXPIRED_LIVES")

    def test_rejects_discovering_expiry_on_the_next_request(self):
        self._mutate(lambda d: d["expiry"].__setitem__("expiry_actor", "api"),
                     "INTENT_EXPIRY_LAZY")

    def test_rejects_an_unexplained_expiry(self):
        self._mutate(lambda d: d["expiry"].__setitem__("notes", ""), "INTENT_EXPIRY_NOTES")

    # -- confirmation -----------------------------------------------------
    def test_rejects_a_missing_confirmation_policy(self):
        self._mutate(lambda d: d.__setitem__("confirmation", []), "INTENT_NO_IDEMPOTENCY")

    def test_rejects_confirmation_without_an_idempotency_key(self):
        self._mutate(lambda d: d["confirmation"].__setitem__("idempotency_key_required",
                                                             False),
                     "INTENT_NO_IDEMPOTENCY")

    def test_rejects_a_globally_scoped_idempotency_key(self):
        self._mutate(lambda d: d["confirmation"].__setitem__("key_unique_per", ["intent_id"]),
                     "INTENT_IDEMPOTENCY_SCOPE")

    def test_rejects_an_intent_that_may_succeed_twice(self):
        self._mutate(lambda d: d["confirmation"].__setitem__("single_success", False),
                     "INTENT_MULTI_SUCCESS")

    def test_rejects_unserialised_concurrent_confirmations(self):
        self._mutate(lambda d: d["confirmation"].__setitem__(
            "concurrent_confirmations_serialized", False), "INTENT_CONCURRENT_CONFIRM")

    def test_rejects_the_return_page_as_evidence(self):
        self._mutate(lambda d: d["confirmation"].__setitem__("client_return_page_is_evidence",
                                                             True),
                     "INTENT_RETURN_PAGE_EVIDENCE")

    def test_rejects_dropping_an_authoritative_source(self):
        self._mutate(lambda d: d["confirmation"].__setitem__("authoritative_sources",
                                                             ["verified_provider_event"]),
                     "INTENT_NO_AUTHORITATIVE_SOURCE")

    def test_rejects_an_unexplained_confirmation_policy(self):
        self._mutate(lambda d: d["confirmation"].__setitem__("notes", ""),
                     "INTENT_CONFIRMATION_NOTES")

    # -- methods ----------------------------------------------------------
    def test_rejects_methods_that_are_not_frozen(self):
        self._mutate(lambda d: d["method_constraints"].__setitem__("snapshot_at_creation",
                                                                   False),
                     "INTENT_METHODS_UNFROZEN")

    def test_rejects_confirming_with_a_method_outside_the_snapshot(self):
        self._mutate(lambda d: d["method_constraints"].__setitem__(
            "confirm_method_must_be_in_snapshot", False), "INTENT_METHODS_UNFROZEN")

    def test_rejects_widening_the_methods_afterwards(self):
        self._mutate(lambda d: d["method_constraints"].__setitem__(
            "widen_after_creation_allowed", True), "INTENT_METHODS_WIDENED")

    def test_rejects_a_method_source_that_is_not_the_matrix(self):
        self._mutate(lambda d: d["method_constraints"].__setitem__("source", "code"),
                     "INTENT_METHODS_UNSOURCED")

    def test_rejects_a_capability_matrix_with_no_methods(self):
        self.fixture.mutate("governance/provider-capabilities.json",
                            lambda d: d.__setitem__("payment_methods", []))
        self._assert("INTENT_METHODS_UNSOURCED")

    def test_rejects_an_unexplained_method_policy(self):
        self._mutate(lambda d: d["method_constraints"].__setitem__("notes", ""),
                     "INTENT_METHOD_NOTES")

    # -- order link -------------------------------------------------------
    def test_rejects_a_missing_order_policy(self):
        self._mutate(lambda d: d.__setitem__("order_link", []), "INTENT_OWNS_ORDER")

    def test_rejects_the_platform_owning_the_order(self):
        self._mutate(lambda d: d["order_link"].__setitem__("owner", "payment_platform"),
                     "INTENT_OWNS_ORDER")

    def test_rejects_storing_order_content(self):
        self._mutate(lambda d: d["order_link"].__setitem__("stores_order_content", True),
                     "INTENT_OWNS_ORDER")

    def test_rejects_an_incomplete_order_reference(self):
        self._mutate(lambda d: d["order_link"].__setitem__("reference_fields",
                                                           ["external_reference"]),
                     "INTENT_ORDER_REFERENCE")

    def test_rejects_two_live_intents_for_one_order(self):
        self._mutate(lambda d: d["order_link"].__setitem__("unique_live_intent_per_order",
                                                           False),
                     "INTENT_ORDER_NOT_UNIQUE")

    def test_rejects_a_forbidden_list_that_omits_the_usual_suspects(self):
        self._mutate(lambda d: d["order_link"].__setitem__("forbidden_fields", ["cart"]),
                     "INTENT_ORDER_CONTENT_ALLOWED")

    def test_rejects_order_content_that_reached_the_entity(self):
        self.fixture.mutate("governance/domain-model.json",
                            lambda d: next(e for e in d["entities"]
                                           if e["name"] == "PaymentIntent")["fields"]
                            .append({"name": "customer_email", "type": "string",
                                     "nullable": True, "semantics": ""}))
        self._assert("INTENT_ORDER_CONTENT_ALLOWED")

    def test_rejects_an_unexplained_order_policy(self):
        self._mutate(lambda d: d["order_link"].__setitem__("notes", ""),
                     "INTENT_ORDER_NOTES")

    # -- invariants, client secret, audit ---------------------------------
    def test_rejects_capturing_more_than_the_snapshot(self):
        self._mutate(lambda d: d["amount_invariants"].__setitem__(
            "captured_cannot_exceed_amount", False), "INTENT_OVER_CAPTURE")

    def test_rejects_refunding_more_than_captured(self):
        self._mutate(lambda d: d["amount_invariants"].__setitem__(
            "refunded_cannot_exceed_captured", False), "INTENT_OVER_REFUND")

    def test_rejects_negative_amounts(self):
        self._mutate(lambda d: d["amount_invariants"].__setitem__(
            "negative_amounts_forbidden", False), "INTENT_NEGATIVE_AMOUNT")

    def test_rejects_zero_amount_intents(self):
        self._mutate(lambda d: d["amount_invariants"].__setitem__(
            "zero_amount_intent_allowed", True), "INTENT_ZERO_AMOUNT")

    def test_rejects_an_unexplained_invariant_block(self):
        self._mutate(lambda d: d["amount_invariants"].__setitem__("notes", ""),
                     "INTENT_INVARIANT_NOTES")

    def test_rejects_a_client_reference_carrying_a_credential(self):
        self._mutate(lambda d: d["client_secret"].__setitem__("contains_credentials", True),
                     "INTENT_CLIENT_SECRET_CREDENTIAL")

    def test_rejects_a_client_reference_valid_for_more_than_one_intent(self):
        self._mutate(lambda d: d["client_secret"].__setitem__("scoped_to_single_intent",
                                                              False),
                     "INTENT_CLIENT_SECRET_BROAD")

    def test_rejects_a_client_reference_that_outlives_the_intent(self):
        self._mutate(lambda d: d["client_secret"].__setitem__("expires_with_intent", False),
                     "INTENT_CLIENT_SECRET_ETERNAL")

    def test_rejects_an_unexplained_client_secret_policy(self):
        self._mutate(lambda d: d["client_secret"].__setitem__("notes", ""),
                     "INTENT_CLIENT_SECRET_NOTES")

    def test_rejects_an_unknown_audit_class(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "intent.vanished"),
                     "INTENT_AUDIT_CLASS_UNKNOWN")

    def test_rejects_recording_an_intent_as_a_configuration_change(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "config.change"),
                     "INTENT_AUDIT_CLASS_TOO_WEAK")


class IntentReferenceModel(FixtureTestCase):
    MODEL = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
    CAPS = json.loads((REAL_ROOT / "governance/provider-capabilities.json")
                      .read_text(encoding="utf-8"))
    CUR = json.loads((REAL_ROOT / "governance/currency-metadata.json")
                     .read_text(encoding="utf-8"))

    def service(self) -> I.Intents:
        return I.Intents(self.MODEL, {c["code"] for c in self.CUR["currencies"]},
                         {m["id"] for m in self.CAPS["payment_methods"]})

    def make(self, intents, intent_id="pi_1", ref="order_1", amount=10000, currency="EUR",
             methods=("card", "paypal_wallet"), minute=MINUTE, **kw):
        return intents.create(intent_id, tenant_id="ten_1", project_id="prj_1",
                              external_reference=ref, amount_minor=amount,
                              currency=currency, allowed_methods=methods,
                              now_minute=minute, **kw)

    def refused(self, fn, code):
        with self.assertRaises(I.IntentRefused) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    # -- the property -----------------------------------------------------
    def test_the_amount_cannot_be_changed_by_any_route(self):
        intents = self.service()
        record = self.make(intents)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.snapshot.amount_minor = 1
        self.refused(lambda: intents.amend(record, amount_minor=99), I.AMOUNT_IMMUTABLE)
        self.refused(lambda: intents.amend(record, currency="USD"), I.AMOUNT_IMMUTABLE)
        # The supported route: a second intent, which is what it actually is.
        self.assertEqual(self.make(intents, intent_id="pi_2", ref="order_2",
                                   amount=99).amount_minor, 99)

    def test_a_non_snapshot_field_can_still_be_amended(self):
        intents = self.service()
        record = self.make(intents)
        self.assertEqual(intents.amend(record, client_secret_ref="cs_new").client_secret_ref,
                         "cs_new")

    def test_one_business_order_may_have_one_live_intent(self):
        intents = self.service()
        self.make(intents)
        self.refused(lambda: self.make(intents, intent_id="pi_dup", ref="order_1"),
                     I.DUPLICATE_LIVE_INTENT)

    def test_a_terminal_intent_frees_its_order(self):
        intents = self.service()
        record = self.make(intents)
        intents.expire(record, now_minute=record.snapshot.expires_at_minute,
                       actor="scheduler")
        self.assertEqual(self.make(intents, intent_id="pi_2", ref="order_1").id, "pi_2")

    # -- creation ---------------------------------------------------------
    def test_creation_refuses_the_amounts_that_cause_incidents(self):
        intents = self.service()
        self.refused(lambda: self.make(intents, amount=10.5), I.AMOUNT_NOT_INTEGER)
        self.refused(lambda: self.make(intents, amount=True), I.AMOUNT_NOT_INTEGER)
        self.refused(lambda: self.make(intents, amount=0), I.AMOUNT_NOT_POSITIVE)
        self.refused(lambda: self.make(intents, amount=-1), I.AMOUNT_NOT_POSITIVE)

    def test_creation_refuses_an_unknown_currency_or_method(self):
        intents = self.service()
        self.refused(lambda: self.make(intents, currency="XYZ"), I.CURRENCY_UNKNOWN)
        self.refused(lambda: self.make(intents, methods=("crypto",)), I.METHOD_NOT_ALLOWED)

    def test_creation_refuses_order_content(self):
        intents = self.service()
        for name in self.MODEL["order_link"]["forbidden_fields"]:
            self.refused(lambda n=name: self.make(intents, **{n: "x"}),
                         I.ORDER_CONTENT_FORBIDDEN)

    def test_creation_refuses_an_expiry_beyond_the_maximum(self):
        intents = self.service()
        self.refused(lambda: self.make(
            intents, expires_in_minutes=self.MODEL["expiry"]["max_minutes"] + 1),
            I.EXPIRY_TOO_LONG)

    def test_an_unknown_intent_is_refused(self):
        self.refused(lambda: self.service().get("pi_nope"), I.UNKNOWN_INTENT)

    # -- expiry -----------------------------------------------------------
    def test_the_expiry_cannot_be_extended(self):
        intents = self.service()
        record = self.make(intents)
        self.refused(lambda: intents.extend_expiry(record, 60), I.EXPIRY_NOT_EXTENDABLE)
        self.refused(lambda: intents.amend(record, expires_at_minute=10 ** 9),
                     I.EXPIRY_NOT_EXTENDABLE)

    def test_an_expired_intent_cannot_be_confirmed(self):
        intents = self.service()
        record = self.make(intents)
        expires = record.snapshot.expires_at_minute
        self.refused(lambda: intents.confirm(record, method="card", idempotency_key="k",
                                             now_minute=expires), I.INTENT_EXPIRED)

    def test_only_the_scheduler_expires_an_intent(self):
        intents = self.service()
        record = self.make(intents)
        expires = record.snapshot.expires_at_minute
        self.refused(lambda: intents.expire(record, now_minute=expires, actor="api"),
                     I.NOT_SCHEDULER)
        self.refused(lambda: intents.expire(record, now_minute=MINUTE, actor="scheduler"),
                     I.ILLEGAL_TRANSITION)
        self.assertEqual(intents.expire(record, now_minute=expires,
                                        actor="scheduler").state, I.EXPIRED)

    # -- confirmation -----------------------------------------------------
    def test_confirmation_needs_a_key_and_is_idempotent(self):
        intents = self.service()
        record = self.make(intents)
        self.refused(lambda: intents.confirm(record, method="card", idempotency_key="",
                                             now_minute=MINUTE), I.NO_IDEMPOTENCY_KEY)
        first = intents.confirm(record, method="card", idempotency_key="k1",
                                now_minute=MINUTE)
        self.assertEqual(intents.confirm(record, method="card", idempotency_key="k1",
                                         now_minute=MINUTE), first)
        self.refused(lambda: intents.confirm(record, method="card", idempotency_key="k2",
                                             now_minute=MINUTE), I.IDEMPOTENCY_KEY_REUSED)

    def test_a_method_outside_the_snapshot_is_refused(self):
        intents = self.service()
        record = self.make(intents)
        self.refused(lambda: intents.confirm(record, method="wechat_pay",
                                             idempotency_key="k", now_minute=MINUTE),
                     I.METHOD_NOT_ALLOWED)

    def test_methods_may_narrow_but_never_widen(self):
        intents = self.service()
        record = self.make(intents)
        self.refused(lambda: intents.narrow_methods(record, ("card", "wechat_pay")),
                     I.METHOD_WIDENED)
        self.assertEqual(intents.narrow_methods(record, ("card",)).snapshot.allowed_methods,
                         ("card",))
        self.assertEqual(record.amount_minor, 10000)

    def test_a_terminal_intent_cannot_be_confirmed(self):
        intents = self.service()
        record = self.make(intents)
        intents.expire(record, now_minute=record.snapshot.expires_at_minute,
                       actor="scheduler")
        self.refused(lambda: intents.confirm(record, method="card", idempotency_key="k",
                                             now_minute=MINUTE), I.ALREADY_TERMINAL)

    # -- state and amounts ------------------------------------------------
    def test_success_never_comes_from_the_browser(self):
        intents = self.service()
        record = self.make(intents)
        self.refused(lambda: intents.succeed_from_return_page(record),
                     I.RETURN_PAGE_NOT_EVIDENCE)
        self.refused(lambda: intents.transition(record, I.AUTHORIZED,
                                                source="client_return_page"),
                     I.UNTRUSTED_SOURCE)
        self.assertEqual(intents.transition(record, I.AUTHORIZED,
                                            source="verified_provider_event").state,
                         I.AUTHORIZED)

    def test_an_illegal_transition_is_refused(self):
        intents = self.service()
        record = self.make(intents)
        self.refused(lambda: intents.transition(record, I.CAPTURED,
                                                source="verified_provider_event"),
                     I.ILLEGAL_TRANSITION)

    def test_capture_and_refund_respect_the_snapshot(self):
        intents = self.service()
        record = self.make(intents)
        intents.transition(record, I.AUTHORIZED, source="verified_provider_event")
        self.refused(lambda: intents.capture(record, 10001,
                                             source="verified_provider_event"),
                     I.OVER_CAPTURE)
        self.refused(lambda: intents.capture(record, 0, source="verified_provider_event"),
                     I.AMOUNT_NOT_POSITIVE)
        self.assertEqual(intents.capture(record, 10000,
                                         source="verified_provider_event"), 10000)
        self.refused(lambda: intents.refund(record, 10001), I.OVER_REFUND)
        self.assertEqual(intents.refund(record, 4000), 4000)
