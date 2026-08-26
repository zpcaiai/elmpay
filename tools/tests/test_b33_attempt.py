"""B33 / AT-B33-01 — one immutable attempt per provider call.

``test_a_timeout_blocks_the_next_attempt_until_it_is_resolved`` is the test this
batch exists for. A timed-out call has an unknown outcome — the money may
already have moved — and the "obvious" retry is the standard way a payment
system charges twice.

``test_a_retryable_failure_is_not_a_settled_intent`` covers the distinction the
runtime proof forced out into the open: an attempt's terminal state ends that
call, not the intent.
"""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

from libs.attempt.reference import attempt as A
from tools.paygov import attempt, attemptgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/payment-attempt.json"
NOW = 1_700_000_000
TENANT = "tenant_acme"


def _class(model, cid):
    return next(c for c in model["outcome_classes"] if c["id"] == cid)


def _mapping(model, provider, code):
    return next(e for e in model["error_taxonomy"]
                if e["provider"] == provider and e["provider_code"] == code)


class AttemptModelHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = attempt.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("payment-attempt", registry.names())

    def test_an_attempt_is_immutable_and_one_per_call(self):
        block = self.fixture.read(REL)["attempt"]
        self.assertTrue(block["immutable"])
        self.assertTrue(block["one_per_provider_call"])
        self.assertTrue(block["reuse_on_retry_forbidden"])
        self.assertTrue(block["sequence_monotonic_per_intent"])
        self.assertTrue(attempt.REQUIRED_FIELDS <= set(block["required_fields"]))

    def test_tenant_and_concurrency_boundaries_are_explicit(self):
        model = self.fixture.read(REL)
        self.assertTrue(model["tenant_scope"]["tenant_id_required"])
        self.assertEqual(model["tenant_scope"]["lookup_key"],
                         attempt.TENANT_LOOKUP_KEY)
        self.assertTrue(model["tenant_scope"]["external_ids_never_used_as_internal_ids"])
        self.assertTrue(model["concurrency"]["atomic_start"])
        self.assertEqual(model["concurrency"]["conflict_key"],
                         attempt.CONCURRENCY_KEY)
        self.assertEqual(model["concurrency"]["concurrent_duplicate_policy"],
                         "reject_without_provider_call")

    def test_reference_runtime_does_not_claim_production_storage_or_audit(self):
        runtime = self.fixture.read(REL)["reference_runtime"]
        self.assertTrue(runtime["process_local_lock"])
        self.assertFalse(runtime["durable_storage"])
        self.assertFalse(runtime["database_unique_constraint"])
        self.assertFalse(runtime["runtime_audit_sink"])
        self.assertFalse(runtime["b32_replacement_confirmation_integrated"])
        self.assertFalse(runtime["production_ready"])

    def test_deployable_runtime_is_separate_durable_and_not_certified_by_local_tests(self):
        runtime = self.fixture.read(REL)["deployable_runtime"]
        self.assertTrue(runtime["durable_storage"])
        self.assertTrue(runtime["database_unique_constraint"])
        self.assertTrue(runtime["transactional_outbox"])
        self.assertTrue(runtime["tenant_rls"])
        self.assertTrue(runtime["b32_confirmation_integrated"])
        self.assertTrue(runtime["unknown_query_recovery"])
        self.assertFalse(runtime["local_tests_are_certification"])

    def test_the_request_is_stored_as_a_digest(self):
        record = self.fixture.read(REL)["request_record"]
        self.assertTrue(record["store_digest_not_payload"])
        self.assertEqual(record["digest_algorithm"], "sha256")
        self.assertTrue(attempt.REDACTED <= set(record["redacted_fields"]))
        self.assertFalse(record["payload_replayable"])

    def test_the_response_is_normalised_and_never_stored_raw(self):
        record = self.fixture.read(REL)["response_record"]
        self.assertTrue(record["store_summary_not_payload"])
        self.assertEqual(record["digest_algorithm"], "sha256")
        self.assertTrue(attempt.RESPONSE_EVIDENCE_FIELDS <=
                        set(record["required_evidence_fields"]))
        self.assertTrue(attempt.RESPONSE_FORBIDDEN_FIELDS <= set(record["forbidden_fields"]))
        self.assertFalse(record["payload_replayable"])

    def test_all_four_outcome_classes_exist(self):
        model = self.fixture.read(REL)
        self.assertEqual({c["id"] for c in model["outcome_classes"]},
                         attempt.REQUIRED_CLASSES)
        self.assertTrue(all(isinstance(c["settles_intent"], bool)
                            for c in model["outcome_classes"]))

    def test_unknown_is_not_final_and_not_retryable(self):
        model = self.fixture.read(REL)
        unknown = _class(model, "unknown")
        self.assertFalse(unknown["final"])
        self.assertFalse(unknown["retry_allowed"])
        self.assertTrue(unknown["requires_resolution"])

    def test_a_definitive_decline_is_not_retried(self):
        failed = _class(self.fixture.read(REL), "failed_final")
        self.assertFalse(failed["retry_allowed"])
        self.assertFalse(failed["settles_intent"])

    def test_a_timeout_is_unknown_and_blocks_the_retry(self):
        timeout = self.fixture.read(REL)["timeout"]
        self.assertEqual(timeout["classified_as"], "unknown")
        self.assertFalse(timeout["retry_before_resolution_allowed"])
        self.assertTrue(attempt.RESOLUTION_METHODS <= set(timeout["resolution_methods"]))
        self.assertLessEqual(timeout["max_resolution_hours"], attempt.MAX_RESOLUTION_HOURS)

    def test_a_retry_opens_a_new_attempt_with_the_same_key(self):
        retry = self.fixture.read(REL)["retry"]
        self.assertTrue(retry["new_attempt_required"])
        self.assertTrue(retry["reuse_idempotency_key"])
        self.assertTrue(retry["only_for_retryable"])
        self.assertEqual(retry["replacement_request_allowed_after"], ["failed_final"])
        self.assertTrue(retry["replacement_request_requires_new_idempotency_key"])
        self.assertTrue(retry["replacement_request_requires_customer_action"])
        self.assertLessEqual(retry["max_attempts_per_intent"], attempt.MAX_ATTEMPTS)
        self.assertEqual(retry["backoff_seconds"], sorted(retry["backoff_seconds"]))

    def test_an_unmapped_provider_code_is_unknown(self):
        self.assertEqual(self.fixture.read(REL)["unmapped_code_class"], "unknown")

    def test_every_bound_provider_has_an_error_mapping(self):
        providers = {p["id"] for p in
                     self.fixture.read("governance/provider-accounts.json")["providers"]}
        mapped = {e["provider"] for e in self.fixture.read(REL)["error_taxonomy"]}
        self.assertEqual(providers - mapped, set())

    def test_already_paid_is_classified_as_success(self):
        self.assertEqual(_mapping(self.fixture.read(REL), "wechat", "ORDERPAID")
                         ["outcome_class"], "succeeded")

    def test_provider_codes_name_their_source_namespace(self):
        model = self.fixture.read(REL)
        stripe = _mapping(model, "stripe", "card_declined")
        paypal = _mapping(model, "paypal", "INSTRUMENT_DECLINED")
        apple = _mapping(model, "apple_pay", "DECRYPT_FAILED")
        self.assertEqual(stripe["code_namespace"], "stripe.error.code")
        self.assertEqual(paypal["code_namespace"], "paypal.details.issue")
        self.assertEqual(paypal["outcome_class"], "failed_final")
        self.assertEqual(apple["code_namespace"], "adapter.normalized")

    def test_a_final_attempt_is_never_overwritten(self):
        finality = self.fixture.read(REL)["finality"]
        self.assertTrue(finality["final_attempt_immutable"])
        self.assertTrue(finality["intent_outcome_from_final_attempt"])
        self.assertTrue(finality["failed_attempt_does_not_settle_intent"])
        self.assertTrue(finality["contradicting_later_event_opens_reconciliation"])
        self.assertFalse(finality["contradicting_later_event_overwrites"])

    def test_the_lifecycle_is_exactly_the_b10_machine(self):
        model = self.fixture.read(REL)
        machines = self.fixture.read("governance/state-machines.json")
        machine = next(m for m in machines["machines"] if m["entity"] == "PaymentAttempt")
        self.assertEqual(model["lifecycle"]["states"], machine["states"])
        self.assertEqual(model["lifecycle"]["initial"], machine["initial"])
        self.assertEqual(model["lifecycle"]["terminal"], machine["terminal"])
        self.assertNotIn("unknown", machine["terminal"])

    def test_b10_only_settles_a_declined_intent_for_an_explicit_b33_class(self):
        machines = self.fixture.read("governance/state-machines.json")["machines"]
        intent = next(m for m in machines if m["entity"] == "PaymentIntent")
        declines = [t for t in intent["transitions"]
                    if t["event"] == "provider.declined" and t["to"] == "failed"]
        expected = {"source": "governance/payment-attempt.json#outcome_classes",
                    "field": "settles_intent", "equals": True}
        self.assertTrue(declines)
        self.assertTrue(all(t["requires_outcome_property"] == expected for t in declines))

    def test_b32_still_refuses_the_return_page(self):
        confirmation = self.fixture.read("governance/payment-intent.json")["confirmation"]
        self.assertFalse(confirmation["client_return_page_is_evidence"])

    def test_attempt_events_are_money_events(self):
        audit = self.fixture.read("governance/audit-log.json")
        model = self.fixture.read(REL)
        self.assertEqual(model["audit_event_class"], "money.movement")
        self.assertIn(model["audit_event_class"], {c["id"] for c in audit["event_classes"]})


class AttemptGeneratedArtefacts(FixtureTestCase):
    def _validate(self):
        return attempt.validate(self.fixture.root, Budget(seconds=60).start())

    def test_generated_artefacts_match_the_model(self):
        for rel, content in attemptgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_carries_every_mapping(self):
        contract = json.loads(attemptgen.contract_json(REAL_ROOT))
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        self.assertEqual({(e["provider"], e["provider_code"])
                          for e in contract["error_taxonomy"]},
                         {(e["provider"], e["provider_code"])
                          for e in model["error_taxonomy"]})
        self.assertEqual({(e["provider"], e["code_namespace"], e["provider_code"])
                          for e in contract["error_taxonomy"]},
                         {(e["provider"], e["code_namespace"], e["provider_code"])
                          for e in model["error_taxonomy"]})

    def test_document_shows_every_outcome_class(self):
        text = attemptgen.attempt_markdown(REAL_ROOT)
        for name in attempt.REQUIRED_CLASSES:
            self.assertIn(name, text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/payment/PAYMENT_ATTEMPT.md", "hand written\n")
        self.assertIn("ATTEMPT_GENERATED_DRIFT", self.codes(self._validate()))

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/payment/attempt.json")
        self.assertIn("ATTEMPT_GENERATED_MISSING", self.codes(self._validate()))

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("attempt", {"immutable": True}))
        self.assertIn("ATTEMPT_GENERATED", self.codes(self._validate()))


class AttemptGateRejects(FixtureTestCase):
    def _validate(self):
        return attempt.validate(self.fixture.root, Budget(seconds=60).start())

    def _assert(self, code):
        self.assertIn(code, self.codes(self._validate()))

    def _mutate(self, fn, code, rel=REL):
        self.fixture.mutate(rel, fn)
        self._assert(code)

    # -- shape ------------------------------------------------------------
    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self._assert("ATTEMPT_UNREADABLE")

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [1])
        self._assert("ATTEMPT_SHAPE")

    def test_rejects_a_bad_schema_version(self):
        self._mutate(lambda d: d.__setitem__("schema_version", "one"),
                     "ATTEMPT_VERSION_FIELD")

    def test_rejects_a_missing_principle(self):
        self._mutate(lambda d: d.__setitem__("principle", ""), "ATTEMPT_PRINCIPLE")

    def test_rejects_a_non_object_retry_block(self):
        self._mutate(lambda d: d.__setitem__("retry", []), "ATTEMPT_SHAPE")

    def test_rejects_a_non_object_lifecycle(self):
        self._mutate(lambda d: d.__setitem__("lifecycle", []), "ATTEMPT_SHAPE")

    def test_rejects_a_non_object_outcome_class(self):
        self._mutate(lambda d: d["outcome_classes"].append("unknown"), "ATTEMPT_SHAPE")

    def test_rejects_a_non_object_mapping(self):
        self._mutate(lambda d: d["error_taxonomy"].append("stripe"), "ATTEMPT_SHAPE")

    # -- the attempt ------------------------------------------------------
    def test_rejects_a_missing_attempt_policy(self):
        self._mutate(lambda d: d.__setitem__("attempt", []), "ATTEMPT_REUSED")

    def test_rejects_a_mutable_attempt(self):
        self._mutate(lambda d: d["attempt"].__setitem__("immutable", False),
                     "ATTEMPT_MUTABLE")

    def test_rejects_reusing_an_attempt_on_retry(self):
        self._mutate(lambda d: d["attempt"].__setitem__("reuse_on_retry_forbidden", False),
                     "ATTEMPT_REUSED")

    def test_rejects_more_than_one_call_per_attempt(self):
        self._mutate(lambda d: d["attempt"].__setitem__("one_per_provider_call", False),
                     "ATTEMPT_REUSED")

    def test_rejects_attempts_with_no_sequence(self):
        self._mutate(lambda d: d["attempt"].__setitem__("sequence_monotonic_per_intent",
                                                        False),
                     "ATTEMPT_NO_SEQUENCE")

    def test_rejects_an_attempt_without_the_request_digest(self):
        self._mutate(lambda d: d["attempt"].__setitem__("required_fields",
                                                        ["intent_id", "provider"]),
                     "ATTEMPT_FIELD_MISSING")

    def test_rejects_an_unexplained_attempt_policy(self):
        self._mutate(lambda d: d["attempt"].__setitem__("notes", ""), "ATTEMPT_NOTES")

    # -- tenant boundary, concurrency and reference limits ---------------
    def test_rejects_a_missing_tenant_scope(self):
        self._mutate(lambda d: d.__setitem__("tenant_scope", []),
                     "ATTEMPT_TENANT_SCOPE_MISSING")

    def test_rejects_an_optional_tenant_id(self):
        self._mutate(lambda d: d["tenant_scope"].__setitem__("tenant_id_required", False),
                     "ATTEMPT_TENANT_ID_OPTIONAL")

    def test_rejects_an_unscoped_tenant_lookup(self):
        self._mutate(lambda d: d["tenant_scope"].__setitem__("lookup_key", ["intent_id"]),
                     "ATTEMPT_TENANT_LOOKUP_UNSCOPED")

    def test_rejects_mixing_external_and_internal_ids(self):
        self._mutate(lambda d: d["tenant_scope"].__setitem__(
            "external_ids_never_used_as_internal_ids", False), "ATTEMPT_ID_NAMESPACE_MIXED")

    def test_rejects_an_unexplained_tenant_scope(self):
        self._mutate(lambda d: d["tenant_scope"].__setitem__("notes", ""),
                     "ATTEMPT_TENANT_SCOPE_NOTES")

    def test_rejects_a_missing_concurrency_policy(self):
        self._mutate(lambda d: d.__setitem__("concurrency", []),
                     "ATTEMPT_CONCURRENCY_MISSING")

    def test_rejects_a_non_atomic_start(self):
        self._mutate(lambda d: d["concurrency"].__setitem__("atomic_start", False),
                     "ATTEMPT_START_NOT_ATOMIC")

    def test_rejects_a_concurrency_key_without_tenant(self):
        self._mutate(lambda d: d["concurrency"].__setitem__("conflict_key", ["intent_id"]),
                     "ATTEMPT_CONCURRENCY_UNSCOPED")

    def test_rejects_a_racing_duplicate_that_can_call_the_provider(self):
        self._mutate(lambda d: d["concurrency"].__setitem__(
            "concurrent_duplicate_policy", "allow"), "ATTEMPT_CONCURRENT_DUPLICATE_CALL")

    def test_rejects_an_unexplained_concurrency_policy(self):
        self._mutate(lambda d: d["concurrency"].__setitem__("notes", ""),
                     "ATTEMPT_CONCURRENCY_NOTES")

    def test_rejects_missing_reference_limit_disclosure(self):
        self._mutate(lambda d: d.__setitem__("reference_runtime", []),
                     "ATTEMPT_REFERENCE_LIMITS_MISSING")

    def test_rejects_an_unstated_process_local_lock(self):
        self._mutate(lambda d: d["reference_runtime"].__setitem__("process_local_lock", False),
                     "ATTEMPT_REFERENCE_LOCK_UNSTATED")

    def test_rejects_reference_production_overclaims(self):
        for field in ("durable_storage", "database_unique_constraint", "runtime_audit_sink",
                      "production_ready"):
            with self.subTest(field=field):
                self.fixture.mutate(
                    REL, lambda d, field=field: d["reference_runtime"].__setitem__(field, True))
                self._assert("ATTEMPT_REFERENCE_OVERCLAIM")
                self.fixture.restore()

    def test_rejects_claiming_b32_replacement_is_integrated(self):
        self._mutate(lambda d: d["reference_runtime"].__setitem__(
            "b32_replacement_confirmation_integrated", True),
            "ATTEMPT_B32_REPLACEMENT_OVERCLAIM")

    def test_rejects_unexplained_reference_limits(self):
        self._mutate(lambda d: d["reference_runtime"].__setitem__("notes", ""),
                     "ATTEMPT_REFERENCE_LIMITS_NOTES")

    def test_rejects_missing_deployable_runtime(self):
        self._mutate(lambda d: d.pop("deployable_runtime"),
                     "ATTEMPT_DEPLOYABLE_RUNTIME_MISSING")

    def test_rejects_local_tests_as_certification(self):
        self._mutate(lambda d: d["deployable_runtime"].__setitem__(
            "local_tests_are_certification", True),
            "ATTEMPT_LOCAL_TEST_CERTIFICATION_OVERCLAIM")

    def test_rejects_an_unbound_deployable_implementation(self):
        self._mutate(lambda d: d["deployable_runtime"].__setitem__(
            "implementation", "services/payment-core"),
            "ATTEMPT_DEPLOYABLE_RUNTIME_UNBOUND")

    def test_rejects_an_unbound_deployable_migration(self):
        self._mutate(lambda d: d["deployable_runtime"].__setitem__(
            "migration", "apps/edge-gateway/src/main/resources/db/migration/V999.sql"),
            "ATTEMPT_DEPLOYABLE_MIGRATION_UNBOUND")

    def test_rejects_a_missing_deployable_runtime_control(self):
        self._mutate(lambda d: d["deployable_runtime"].__setitem__(
            "tenant_rls", False),
            "ATTEMPT_DEPLOYABLE_CONTROL_MISSING")

    def test_rejects_unexplained_deployable_runtime(self):
        self._mutate(lambda d: d["deployable_runtime"].__setitem__("notes", ""),
                     "ATTEMPT_DEPLOYABLE_RUNTIME_NOTES")

    # -- request record ---------------------------------------------------
    def test_rejects_storing_the_payload(self):
        self._mutate(lambda d: d["request_record"].__setitem__("store_digest_not_payload",
                                                               False),
                     "ATTEMPT_STORES_PAYLOAD")

    def test_rejects_a_missing_record_policy(self):
        self._mutate(lambda d: d.__setitem__("request_record", []),
                     "ATTEMPT_STORES_PAYLOAD")

    def test_rejects_a_weak_digest(self):
        self._mutate(lambda d: d["request_record"].__setitem__("digest_algorithm", "md5"),
                     "ATTEMPT_WEAK_DIGEST")

    def test_rejects_an_incomplete_redaction_list(self):
        self._mutate(lambda d: d["request_record"].__setitem__("redacted_fields", ["pan"]),
                     "ATTEMPT_UNREDACTED")

    def test_rejects_a_replayable_request_record(self):
        self._mutate(lambda d: d["request_record"].__setitem__("payload_replayable", True),
                     "ATTEMPT_REPLAYABLE")

    def test_rejects_an_unexplained_record_policy(self):
        self._mutate(lambda d: d["request_record"].__setitem__("notes", ""),
                     "ATTEMPT_RECORD_NOTES")

    # -- response record --------------------------------------------------
    def test_rejects_a_missing_response_record_policy(self):
        self._mutate(lambda d: d.__setitem__("response_record", []),
                     "ATTEMPT_RESPONSE_PAYLOAD_STORED")

    def test_rejects_storing_the_raw_provider_response(self):
        self._mutate(lambda d: d["response_record"].__setitem__(
            "store_summary_not_payload", False), "ATTEMPT_RESPONSE_PAYLOAD_STORED")

    def test_rejects_a_weak_response_digest(self):
        self._mutate(lambda d: d["response_record"].__setitem__("digest_algorithm", "md5"),
                     "ATTEMPT_RESPONSE_WEAK_DIGEST")

    def test_rejects_missing_response_evidence(self):
        self._mutate(lambda d: d["response_record"].__setitem__(
            "required_evidence_fields", ["provider_code"]),
            "ATTEMPT_RESPONSE_EVIDENCE_MISSING")

    def test_rejects_an_incomplete_response_forbidden_list(self):
        self._mutate(lambda d: d["response_record"].__setitem__("forbidden_fields", ["pan"]),
                     "ATTEMPT_RESPONSE_UNREDACTED")

    def test_rejects_a_replayable_response_record(self):
        self._mutate(lambda d: d["response_record"].__setitem__("payload_replayable", True),
                     "ATTEMPT_RESPONSE_REPLAYABLE")

    def test_rejects_an_unexplained_response_policy(self):
        self._mutate(lambda d: d["response_record"].__setitem__("notes", ""),
                     "ATTEMPT_RESPONSE_NOTES")

    def test_rejects_a_raw_response_field_on_the_attempt(self):
        self._mutate(lambda d: d["attempt"]["required_fields"].append("raw_response"),
                     "ATTEMPT_RESPONSE_PAYLOAD_STORED")

    # -- outcome classes --------------------------------------------------
    def test_rejects_a_model_with_no_classes(self):
        self._mutate(lambda d: d.__setitem__("outcome_classes", []), "ATTEMPT_NO_CLASSES")

    def test_rejects_a_missing_class(self):
        self._mutate(lambda d: d.__setitem__(
            "outcome_classes", [c for c in d["outcome_classes"] if c["id"] != "unknown"]),
            "ATTEMPT_NO_CLASSES")

    def test_rejects_a_non_snake_case_class_id(self):
        self._mutate(lambda d: _class(d, "unknown").__setitem__("id", "Unknown Result"),
                     "ATTEMPT_CLASS_ID")

    def test_rejects_a_duplicate_class(self):
        self._mutate(lambda d: d["outcome_classes"].append(dict(_class(d, "unknown"))),
                     "ATTEMPT_CLASS_DUPLICATE")

    def test_rejects_an_unstated_class_property(self):
        self._mutate(lambda d: _class(d, "unknown").__setitem__("final", "maybe"),
                     "ATTEMPT_CLASS_UNSTATED")

    def test_rejects_unknown_being_final(self):
        self._mutate(lambda d: _class(d, "unknown").__setitem__("final", True),
                     "ATTEMPT_UNKNOWN_IS_FINAL")

    def test_rejects_retrying_an_unknown(self):
        self._mutate(lambda d: _class(d, "unknown").__setitem__("retry_allowed", True),
                     "ATTEMPT_UNKNOWN_RETRYABLE")

    def test_rejects_an_unknown_that_needs_no_resolution(self):
        self._mutate(lambda d: _class(d, "unknown").__setitem__("requires_resolution", False),
                     "ATTEMPT_UNKNOWN_UNRESOLVED")

    def test_rejects_retrying_a_definitive_decline(self):
        self._mutate(lambda d: _class(d, "failed_final").__setitem__("retry_allowed", True),
                     "ATTEMPT_FINAL_RETRYABLE")

    def test_rejects_a_known_failure_that_does_not_end_its_attempt(self):
        self._mutate(lambda d: _class(d, "failed_retryable").__setitem__("final", False),
                     "ATTEMPT_KNOWN_OUTCOME_NOT_FINAL")

    def test_rejects_a_failure_that_settles_the_intent(self):
        self._mutate(lambda d: _class(d, "failed_final").__setitem__("settles_intent", True),
                     "ATTEMPT_FAILURE_SETTLES_INTENT")

    def test_rejects_a_success_that_is_not_final(self):
        self._mutate(lambda d: _class(d, "succeeded").__setitem__("final", False),
                     "ATTEMPT_SUCCESS_NOT_FINAL")

    def test_rejects_a_success_that_does_not_settle_the_intent(self):
        self._mutate(lambda d: _class(d, "succeeded").__setitem__("settles_intent", False),
                     "ATTEMPT_SUCCESS_NOT_INTENT_FINAL")

    def test_rejects_an_unexplained_class(self):
        self._mutate(lambda d: _class(d, "unknown").__setitem__("notes", ""),
                     "ATTEMPT_CLASS_NOTES")

    # -- timeout and retry ------------------------------------------------
    def test_rejects_a_missing_timeout_policy(self):
        self._mutate(lambda d: d.__setitem__("timeout", []), "ATTEMPT_TIMEOUT_IS_FAILURE")

    def test_rejects_treating_a_timeout_as_a_failure(self):
        self._mutate(lambda d: d["timeout"].__setitem__("classified_as", "failed_retryable"),
                     "ATTEMPT_TIMEOUT_IS_FAILURE")

    def test_rejects_retrying_before_resolution(self):
        self._mutate(lambda d: d["timeout"].__setitem__("retry_before_resolution_allowed",
                                                        True),
                     "ATTEMPT_UNKNOWN_RETRYABLE")

    def test_rejects_dropping_a_resolution_method(self):
        self._mutate(lambda d: d["timeout"].__setitem__("resolution_methods",
                                                        ["provider_query"]),
                     "ATTEMPT_NO_RESOLUTION")

    def test_rejects_an_unknown_that_may_linger(self):
        self._mutate(lambda d: d["timeout"].__setitem__("max_resolution_hours", 0),
                     "ATTEMPT_RESOLUTION_UNBOUNDED")

    def test_rejects_an_unexplained_timeout_policy(self):
        self._mutate(lambda d: d["timeout"].__setitem__("notes", ""),
                     "ATTEMPT_TIMEOUT_NOTES")

    def test_rejects_a_retry_that_writes_over_the_attempt(self):
        self._mutate(lambda d: d["retry"].__setitem__("new_attempt_required", False),
                     "ATTEMPT_REUSED")

    def test_rejects_a_retry_with_a_new_idempotency_key(self):
        self._mutate(lambda d: d["retry"].__setitem__("reuse_idempotency_key", False),
                     "ATTEMPT_NEW_KEY_ON_RETRY")

    def test_rejects_retrying_anything_that_is_not_retryable(self):
        self._mutate(lambda d: d["retry"].__setitem__("only_for_retryable", False),
                     "ATTEMPT_FINAL_RETRYABLE")

    def test_rejects_an_undefined_replacement_request_scope(self):
        self._mutate(lambda d: d["retry"].__setitem__(
            "replacement_request_allowed_after", []), "ATTEMPT_REPLACEMENT_SCOPE")

    def test_rejects_reusing_the_old_key_for_a_replacement_request(self):
        self._mutate(lambda d: d["retry"].__setitem__(
            "replacement_request_requires_new_idempotency_key", False),
            "ATTEMPT_REPLACEMENT_REUSES_KEY")

    def test_rejects_an_automatic_funding_source_replacement(self):
        self._mutate(lambda d: d["retry"].__setitem__(
            "replacement_request_requires_customer_action", False),
            "ATTEMPT_REPLACEMENT_NO_CUSTOMER_ACTION")

    def test_rejects_unbounded_retries(self):
        self._mutate(lambda d: d["retry"].__setitem__("max_attempts_per_intent", 0),
                     "ATTEMPT_RETRY_UNBOUNDED")

    def test_rejects_retries_with_no_backoff(self):
        self._mutate(lambda d: d["retry"].__setitem__("backoff_seconds", []),
                     "ATTEMPT_NO_BACKOFF")

    def test_rejects_an_unexplained_retry_policy(self):
        self._mutate(lambda d: d["retry"].__setitem__("notes", ""), "ATTEMPT_RETRY_NOTES")

    # -- taxonomy ---------------------------------------------------------
    def test_rejects_a_model_with_no_taxonomy(self):
        self._mutate(lambda d: d.__setitem__("error_taxonomy", []), "ATTEMPT_NO_TAXONOMY")

    def test_rejects_a_mapping_for_an_unbound_provider(self):
        self._mutate(lambda d: _mapping(d, "stripe", "card_declined").__setitem__("provider",
                                                                                  "klarna"),
                     "ATTEMPT_PROVIDER_UNKNOWN")

    def test_rejects_a_mapping_with_no_code(self):
        self._mutate(lambda d: _mapping(d, "stripe", "card_declined").__setitem__(
            "provider_code", ""), "ATTEMPT_CODE_MISSING")

    def test_rejects_a_mapping_without_a_code_namespace(self):
        self._mutate(lambda d: _mapping(d, "stripe", "card_declined").__setitem__(
            "code_namespace", ""), "ATTEMPT_CODE_NAMESPACE")

    def test_rejects_conflating_stripe_error_and_decline_codes(self):
        self._mutate(lambda d: _mapping(d, "stripe", "card_declined").__setitem__(
            "code_namespace", "paypal.details.issue"), "ATTEMPT_CODE_NAMESPACE")

    def test_rejects_the_same_code_mapped_twice(self):
        self._mutate(lambda d: d["error_taxonomy"].append(
            dict(_mapping(d, "stripe", "card_declined"))), "ATTEMPT_CODE_DUPLICATE")

    def test_rejects_a_mapping_to_an_undeclared_class(self):
        self._mutate(lambda d: _mapping(d, "stripe", "card_declined").__setitem__(
            "outcome_class", "probably_fine"), "ATTEMPT_CLASS_UNKNOWN")

    def test_rejects_an_unmapped_code_that_is_not_unknown(self):
        self._mutate(lambda d: d.__setitem__("unmapped_code_class", "failed_final"),
                     "ATTEMPT_UNMAPPED_IS_SUCCESS")

    def test_rejects_a_provider_with_no_mapping_at_all(self):
        self._mutate(lambda d: d.__setitem__(
            "error_taxonomy", [e for e in d["error_taxonomy"] if e["provider"] != "paypal"]),
            "ATTEMPT_PROVIDER_UNMAPPED")

    def test_rejects_an_unexplained_mapping(self):
        self._mutate(lambda d: _mapping(d, "stripe", "card_declined").__setitem__("notes",
                                                                                   ""),
                     "ATTEMPT_MAPPING_NOTES")

    # -- finality and lifecycle -------------------------------------------
    def test_rejects_a_missing_finality_policy(self):
        self._mutate(lambda d: d.__setitem__("finality", []), "ATTEMPT_FINAL_OVERWRITTEN")

    def test_rejects_a_mutable_final_attempt(self):
        self._mutate(lambda d: d["finality"].__setitem__("final_attempt_immutable", False),
                     "ATTEMPT_FINAL_MUTABLE")

    def test_rejects_an_intent_outcome_set_independently(self):
        self._mutate(lambda d: d["finality"].__setitem__("intent_outcome_from_final_attempt",
                                                         False),
                     "ATTEMPT_INTENT_UNLINKED")

    def test_rejects_a_failed_attempt_settling_the_intent(self):
        self._mutate(lambda d: d["finality"].__setitem__(
            "failed_attempt_does_not_settle_intent", False),
            "ATTEMPT_FAILURE_SETTLES_INTENT")

    def test_rejects_ignoring_a_contradicting_event(self):
        self._mutate(lambda d: d["finality"].__setitem__(
            "contradicting_later_event_opens_reconciliation", False),
            "ATTEMPT_CONTRADICTION_IGNORED")

    def test_rejects_overwriting_a_final_attempt(self):
        self._mutate(lambda d: d["finality"].__setitem__(
            "contradicting_later_event_overwrites", True), "ATTEMPT_FINAL_OVERWRITTEN")

    def test_rejects_an_unexplained_finality_policy(self):
        self._mutate(lambda d: d["finality"].__setitem__("notes", ""),
                     "ATTEMPT_FINALITY_NOTES")

    def test_rejects_states_that_diverge_from_b10(self):
        self._mutate(lambda d: d["lifecycle"]["states"].append("maybe"),
                     "ATTEMPT_STATES_DIVERGE")

    def test_rejects_b10_settling_every_provider_decline(self):
        def unguard(d):
            machine = next(m for m in d["machines"] if m["entity"] == "PaymentIntent")
            next(t for t in machine["transitions"]
                 if t["event"] == "provider.declined").pop("requires_outcome_property")
        self._mutate(unguard, "ATTEMPT_INTENT_DECLINE_UNSCOPED",
                     rel="governance/state-machines.json")

    def test_rejects_success_states_that_diverge(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("success_states",
                                                          ["succeeded", "pending"]),
                     "ATTEMPT_SUCCESS_DIVERGE")

    def test_rejects_a_lifecycle_with_no_source(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("source", "our heads"),
                     "ATTEMPT_LIFECYCLE_UNSOURCED")

    def test_rejects_b10_making_unknown_terminal(self):
        self.fixture.mutate("governance/state-machines.json",
                            lambda d: next(m for m in d["machines"]
                                           if m["entity"] == "PaymentAttempt")["terminal"]
                            .append("unknown"))
        self._assert("ATTEMPT_UNKNOWN_IS_FINAL")

    def test_rejects_b32_accepting_the_return_page(self):
        self.fixture.mutate("governance/payment-intent.json",
                            lambda d: d["confirmation"].__setitem__(
                                "client_return_page_is_evidence", True))
        self._assert("ATTEMPT_RETURN_PAGE_EVIDENCE")

    def test_rejects_an_unexplained_lifecycle(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("notes", ""),
                     "ATTEMPT_LIFECYCLE_NOTES")

    def test_rejects_an_unknown_audit_class(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "attempt.vanished"),
                     "ATTEMPT_AUDIT_CLASS_UNKNOWN")

    def test_rejects_recording_a_provider_call_as_a_config_change(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "config.change"),
                     "ATTEMPT_AUDIT_CLASS_TOO_WEAK")


class AttemptReferenceModel(FixtureTestCase):
    MODEL = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
    ACC = json.loads((REAL_ROOT / "governance/provider-accounts.json")
                     .read_text(encoding="utf-8"))

    def service(self) -> A.Attempts:
        return A.Attempts(self.MODEL, {p["id"] for p in self.ACC["providers"]})

    def request(self) -> dict:
        return {"amount_minor": 10000, "currency": "EUR", "pan": "4242424242424242",
                "cvv": "123", "credential": "sk_live_x"}

    def refused(self, fn, code):
        with self.assertRaises(A.AttemptRefused) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    # -- the property -----------------------------------------------------
    def test_a_timeout_blocks_the_next_attempt_until_it_is_resolved(self):
        attempts = self.service()
        first = attempts.start("pi_1", tenant_id=TENANT, provider="stripe", request=self.request(),
                               idempotency_key="k", now=NOW)
        self.assertEqual(attempts.timed_out(first, tenant_id=TENANT, now=NOW + 30), A.UNKNOWN_CLASS)
        self.assertFalse(first.is_final)
        # The money may already have moved, so there is no second call.
        self.refused(lambda: attempts.start("pi_1", tenant_id=TENANT, provider="stripe",
                                            request=self.request(), idempotency_key="k",
                                            now=NOW + 60), A.UNRESOLVED_UNKNOWN)
        self.assertEqual(attempts.resolve(first, tenant_id=TENANT, method="provider_query",
                                          provider_code="card_declined", now=NOW + 60),
                         A.FAILED_FINAL)

    def test_a_retryable_failure_is_not_a_settled_intent(self):
        attempts = self.service()
        first = attempts.start("pi_2", tenant_id=TENANT, provider="stripe", request=self.request(),
                               idempotency_key="k", now=NOW)
        attempts.record(first, tenant_id=TENANT, provider_code="rate_limit", now=NOW + 1)
        # The attempt is over (B10 makes `failed` terminal) but the intent is not.
        self.assertTrue(first.is_final)
        self.assertIsNone(attempts.intent_outcome(TENANT, "pi_2"))
        self.refused(lambda: attempts.start(
            "pi_2", tenant_id=TENANT, provider="stripe", request=self.request(),
            idempotency_key="new-k", replacement_request=True, now=NOW + 2),
            A.REPLACEMENT_NOT_ALLOWED)
        second = attempts.start("pi_2", tenant_id=TENANT, provider="stripe", request=self.request(),
                                idempotency_key="k", now=NOW + 2)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(first.outcome_class, A.FAILED_RETRYABLE)

    # -- the record -------------------------------------------------------
    def test_the_digest_excludes_the_redacted_fields(self):
        attempts = self.service()
        record = attempts.start("pi_3", tenant_id=TENANT, provider="stripe", request=self.request(),
                                idempotency_key="k", now=NOW)
        self.assertEqual(len(record.request_digest), 64)
        self.assertEqual(record.request_digest,
                         A.digest({"amount_minor": 10000, "currency": "EUR"},
                                  tuple(self.MODEL["request_record"]["redacted_fields"])))

    def test_the_payload_cannot_be_read_back(self):
        attempts = self.service()
        record = attempts.start("pi_4", tenant_id=TENANT, provider="stripe", request=self.request(),
                                idempotency_key="k", now=NOW)
        self.refused(lambda: attempts.stored_request(record, tenant_id=TENANT), A.PAYLOAD_NOT_STORED)

    def test_the_response_is_a_safe_summary_with_a_digest(self):
        attempts = self.service()
        record = attempts.start("pi_response", tenant_id=TENANT, provider="stripe", request=self.request(),
                                idempotency_key="k", provider_request_id="req_safe_1",
                                now=NOW)
        self.refused(lambda: attempts.stored_response(record, tenant_id=TENANT), A.RESPONSE_NOT_RECORDED)
        attempts.record(record, tenant_id=TENANT, provider_code="card_declined",
                        provider_transaction_id="txn_safe_1", now=NOW + 1)
        summary = attempts.stored_response(record, tenant_id=TENANT)
        self.assertEqual(summary["provider_request_id"], "req_safe_1")
        self.assertEqual(summary["provider_transaction_id"], "txn_safe_1")
        self.assertEqual(summary["provider_code"], "card_declined")
        self.assertEqual(len(summary["response_digest"]), 64)
        self.assertEqual(set(summary), {"provider", "provider_request_id",
                                       "provider_transaction_id", "provider_code_namespace",
                                       "provider_code", "outcome_class", "response_digest"})
        self.assertTrue(set(summary).isdisjoint(self.MODEL["response_record"]["forbidden_fields"]))

    def test_provider_request_ids_are_present_and_unique(self):
        attempts = self.service()
        generated = attempts.start("pi_request_1", tenant_id=TENANT, provider="stripe", request=self.request(),
                                   idempotency_key="k1", now=NOW)
        self.assertTrue(generated.provider_request_id)
        explicit = attempts.start("pi_request_2", tenant_id=TENANT, provider="stripe", request=self.request(),
                                  idempotency_key="k2", provider_request_id="req_unique",
                                  now=NOW)
        self.assertEqual(explicit.provider_request_id, "req_unique")
        self.refused(lambda: attempts.start(
            "pi_request_3", tenant_id=TENANT, provider="stripe", request=self.request(),
            idempotency_key="k3",
            provider_request_id="req_unique", now=NOW), A.PROVIDER_REQUEST_ID_REUSED)
        self.refused(lambda: attempts.start(
            "pi_request_4", tenant_id=TENANT, provider="stripe", request=self.request(),
            idempotency_key="k4",
            provider_request_id="", now=NOW), A.PROVIDER_REQUEST_ID_REQUIRED)

    def test_provider_transaction_ids_are_unique_when_present(self):
        attempts = self.service()
        first = attempts.start("pi_txn_1", tenant_id=TENANT, provider="stripe", request=self.request(),
                               idempotency_key="k1", now=NOW)
        attempts.record(first, tenant_id=TENANT, provider_code="card_declined",
                        provider_transaction_id="txn_unique", now=NOW + 1)
        second = attempts.start("pi_txn_2", tenant_id=TENANT, provider="stripe", request=self.request(),
                                idempotency_key="k2", now=NOW + 2)
        self.refused(lambda: attempts.record(
            second, tenant_id=TENANT, provider_code="card_declined",
            provider_transaction_id="txn_unique",
            now=NOW + 3), A.PROVIDER_TRANSACTION_ID_REUSED)

    def test_an_unknown_provider_is_refused(self):
        attempts = self.service()
        self.refused(lambda: attempts.start("pi_5", tenant_id=TENANT, provider="klarna", request={},
                                            idempotency_key="k", now=NOW),
                     A.UNKNOWN_PROVIDER)

    def test_tenant_id_is_required_and_equal_intent_ids_are_isolated(self):
        attempts = self.service()
        self.refused(lambda: attempts.start(
            "pi_shared", tenant_id="", provider="stripe", request=self.request(),
            idempotency_key="k", now=NOW), A.TENANT_ID_REQUIRED)
        first = attempts.start(
            "pi_shared", tenant_id="tenant_one", provider="stripe", request=self.request(),
            idempotency_key="k", provider_request_id="req_shared", now=NOW)
        second = attempts.start(
            "pi_shared", tenant_id="tenant_two", provider="stripe", request=self.request(),
            idempotency_key="k", provider_request_id="req_shared", now=NOW)
        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.sequence, 1)
        self.assertNotEqual(first.id, second.id)
        self.assertNotIn(first.intent_id, first.id)
        self.assertNotIn(first.tenant_id, first.id)
        self.assertEqual(attempts.for_intent("tenant_one", "pi_shared"), [first])
        self.assertEqual(attempts.for_intent("tenant_two", "pi_shared"), [second])
        self.refused(lambda: attempts.stored_response(first, tenant_id="tenant_two"),
                     A.TENANT_MISMATCH)
        self.refused(lambda: setattr(first, "tenant_id", "tenant_two"),
                     A.ATTEMPT_IDENTITY_IMMUTABLE)

    def test_concurrent_duplicate_starts_create_exactly_one_attempt(self):
        attempts = self.service()
        workers = 12
        barrier = threading.Barrier(workers)

        def race(index):
            barrier.wait()
            try:
                attempts.start(
                    "pi_race", tenant_id=TENANT, provider="stripe", request=self.request(),
                    idempotency_key="k", provider_request_id=f"req_race_{index}", now=NOW)
                return "created"
            except A.AttemptRefused as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(race, range(workers)))
        self.assertEqual(results.count("created"), 1)
        self.assertEqual(results.count(A.NOT_RETRYABLE), workers - 1)
        self.assertEqual(len(attempts.for_intent(TENANT, "pi_race")), 1)

    # -- classification ---------------------------------------------------
    def test_an_unmapped_code_is_unknown(self):
        attempts = self.service()
        self.assertEqual(attempts.classify("stripe", "brand_new_code"), A.UNKNOWN_CLASS)
        self.assertEqual(attempts.classify("stripe", None), A.UNKNOWN_CLASS)
        self.assertEqual(attempts.classify("stripe", "card_declined",
                                           "stripe.decline_code"), A.UNKNOWN_CLASS)

    def test_paypal_instrument_declined_allows_a_new_instrument(self):
        attempts = self.service()
        first = attempts.start("pi_paypal", tenant_id=TENANT, provider="paypal",
                               request=self.request(), idempotency_key="old-key", now=NOW)
        self.assertEqual(attempts.record(
            first, tenant_id=TENANT, provider_code="INSTRUMENT_DECLINED",
            code_namespace="paypal.details.issue", now=NOW + 1), A.FAILED_FINAL)
        self.assertIsNone(attempts.intent_outcome(TENANT, "pi_paypal"))
        second = attempts.start(
            "pi_paypal", tenant_id=TENANT, provider="paypal", request=self.request(),
            idempotency_key="new-key", replacement_request=True, now=NOW + 2)
        self.assertEqual(second.sequence, 2)

    def test_b32_replacement_confirmation_is_an_explicit_integration_gap(self):
        from libs.intent.reference import intent as I

        model = json.loads((REAL_ROOT / "governance/payment-intent.json")
                           .read_text(encoding="utf-8"))
        intents = I.Intents(model, {"EUR"}, {"card"})
        payment = intents.create(
            "pi_b32_seam", tenant_id=TENANT, project_id="project_a",
            external_reference="order_a", amount_minor=1000, currency="EUR",
            allowed_methods=("card",), now_minute=100)
        intents.confirm(payment, method="card", idempotency_key="old-key", now_minute=101)
        with self.assertRaises(I.IntentRefused) as ctx:
            intents.confirm(payment, method="card", idempotency_key="replacement-key",
                            now_minute=102)
        self.assertEqual(ctx.exception.code, I.IDEMPOTENCY_KEY_REUSED)
        self.assertFalse(self.MODEL["reference_runtime"]
                         ["b32_replacement_confirmation_integrated"])

    def test_already_paid_is_success_not_an_error(self):
        self.assertEqual(self.service().classify("wechat", "ORDERPAID"), A.SUCCESS)

    def test_a_declared_system_error_is_unknown(self):
        self.assertEqual(self.service().classify("wechat", "SYSTEMERROR"), A.UNKNOWN_CLASS)

    # -- retries ----------------------------------------------------------
    def test_a_definitive_decline_ends_the_request_not_the_intent(self):
        attempts = self.service()
        first = attempts.start("pi_6", tenant_id=TENANT, provider="stripe", request=self.request(),
                               idempotency_key="k", now=NOW)
        attempts.record(first, tenant_id=TENANT, provider_code="card_declined", now=NOW + 1)
        self.assertTrue(first.is_final)
        self.assertIsNone(attempts.intent_outcome(TENANT, "pi_6"))
        self.refused(lambda: attempts.start("pi_6", tenant_id=TENANT, provider="stripe",
                                            request=self.request(), idempotency_key="k",
                                            now=NOW + 2), A.NOT_RETRYABLE)
        self.refused(lambda: attempts.start(
            "pi_6", tenant_id=TENANT, provider="stripe", request=self.request(),
            idempotency_key="k", replacement_request=True, now=NOW + 2),
            A.KEY_REUSED_FOR_REPLACEMENT)
        replacement = attempts.start(
            "pi_6", tenant_id=TENANT, provider="stripe", request=self.request(),
            idempotency_key="k-new", replacement_request=True, now=NOW + 2)
        self.assertEqual(replacement.sequence, 2)

    def test_a_successfully_settled_intent_takes_no_further_attempts(self):
        attempts = self.service()
        first = attempts.start("pi_settled", tenant_id=TENANT, provider="wechat",
                               request=self.request(), idempotency_key="k", now=NOW)
        attempts.record(first, tenant_id=TENANT, provider_code="ORDERPAID", now=NOW + 1)
        self.refused(lambda: attempts.start(
            "pi_settled", tenant_id=TENANT, provider="wechat", request=self.request(),
            idempotency_key="k-new", replacement_request=True, now=NOW + 2),
            A.ATTEMPT_IS_FINAL)

    def test_a_retry_must_carry_the_original_key(self):
        attempts = self.service()
        first = attempts.start("pi_7", tenant_id=TENANT, provider="stripe", request=self.request(),
                               idempotency_key="k", now=NOW)
        attempts.record(first, tenant_id=TENANT, provider_code="rate_limit", now=NOW + 1)
        self.refused(lambda: attempts.start("pi_7", tenant_id=TENANT, provider="stripe",
                                            request=self.request(), idempotency_key="k2",
                                            now=NOW + 2), A.KEY_CHANGED)

    def test_retries_are_bounded(self):
        attempts = self.service()
        for index in range(self.MODEL["retry"]["max_attempts_per_intent"]):
            record = attempts.start("pi_8", tenant_id=TENANT, provider="stripe", request=self.request(),
                                    idempotency_key="k", now=NOW + index)
            attempts.record(record, tenant_id=TENANT, provider_code="rate_limit", now=NOW + index + 1)
        self.refused(lambda: attempts.start("pi_8", tenant_id=TENANT, provider="stripe",
                                            request=self.request(), idempotency_key="k",
                                            now=NOW + 100), A.RETRIES_EXHAUSTED)

    # -- resolution -------------------------------------------------------
    def test_resolution_needs_a_declared_method_and_a_deadline(self):
        attempts = self.service()
        record = attempts.start("pi_9", tenant_id=TENANT, provider="stripe", request=self.request(),
                                idempotency_key="k", now=NOW)
        attempts.timed_out(record, tenant_id=TENANT, now=NOW + 1)
        self.refused(lambda: attempts.resolve(record, tenant_id=TENANT, method="ask_support",
                                              provider_code="card_declined", now=NOW + 2),
                     A.RESOLUTION_METHOD_UNKNOWN)
        overdue = NOW + (self.MODEL["timeout"]["max_resolution_hours"] + 2) * 3600
        self.refused(lambda: attempts.resolve(record, tenant_id=TENANT, method="provider_query",
                                              provider_code="card_declined", now=overdue),
                     A.RESOLUTION_OVERDUE)

    def test_a_resolution_that_is_still_unknown_does_not_resolve(self):
        attempts = self.service()
        record = attempts.start("pi_10", tenant_id=TENANT, provider="stripe", request=self.request(),
                                idempotency_key="k", now=NOW)
        attempts.timed_out(record, tenant_id=TENANT, now=NOW + 1)
        self.refused(lambda: attempts.resolve(record, tenant_id=TENANT, method="provider_query",
                                              provider_code="never_seen", now=NOW + 2),
                     A.UNRESOLVED_UNKNOWN)
        self.assertTrue(record.is_unknown)

    def test_only_an_unknown_can_be_resolved(self):
        attempts = self.service()
        record = attempts.start("pi_11", tenant_id=TENANT, provider="stripe", request=self.request(),
                                idempotency_key="k", now=NOW)
        attempts.record(record, tenant_id=TENANT, provider_code="card_declined", now=NOW + 1)
        self.refused(lambda: attempts.resolve(record, tenant_id=TENANT, method="provider_query",
                                              provider_code="card_declined", now=NOW + 2),
                     A.NOT_UNKNOWN)

    # -- finality ---------------------------------------------------------
    def test_a_late_contradicting_event_opens_a_break_and_changes_nothing(self):
        attempts = self.service()
        record = attempts.start("pi_12", tenant_id=TENANT, provider="wechat", request=self.request(),
                                idempotency_key="k", now=NOW)
        attempts.record(record, tenant_id=TENANT, provider_code="ORDERPAID", now=NOW + 1)
        self.assertEqual(attempts.intent_outcome(TENANT, "pi_12"), A.SUCCESS)
        item = attempts.observe_late_event(record, tenant_id=TENANT, later_outcome=A.FAILED_FINAL,
                                           now=NOW + 100)
        self.assertIsNotNone(item)
        self.assertEqual(record.outcome_class, A.SUCCESS)
        self.assertEqual(len(attempts.reconciliations_for_tenant(TENANT)), 1)
        self.assertIsNone(attempts.observe_late_event(record, tenant_id=TENANT, later_outcome=A.SUCCESS,
                                                      now=NOW + 101))

    def test_direct_assignment_cannot_rewrite_a_final_attempt(self):
        attempts = self.service()
        record = attempts.start("pi_immutable", tenant_id=TENANT, provider="wechat", request=self.request(),
                                idempotency_key="k", now=NOW)
        attempts.record(record, tenant_id=TENANT, provider_code="ORDERPAID",
                        provider_transaction_id="wx_txn_immutable", now=NOW + 1)
        before = (record.state, record.outcome_class, record.provider_code_namespace,
                  record.provider_code,
                  record.provider_transaction_id, record.response_digest, record.finished_at)
        for field, value in (("state", A.FAILED), ("outcome_class", A.FAILED_FINAL),
                             ("provider_code_namespace", "adapter.normalized"),
                             ("provider_code", "SYSTEMERROR"),
                             ("provider_transaction_id", "rewritten"),
                             ("response_digest", "0" * 64), ("finished_at", NOW + 999)):
            self.refused(lambda field=field, value=value: setattr(record, field, value),
                         A.ATTEMPT_IS_FINAL)
        self.assertEqual(before, (record.state, record.outcome_class,
                                  record.provider_code_namespace, record.provider_code,
                                  record.provider_transaction_id, record.response_digest,
                                  record.finished_at))

    def test_an_illegal_transition_is_refused(self):
        attempts = self.service()
        record = attempts.start("pi_13", tenant_id=TENANT, provider="stripe", request=self.request(),
                                idempotency_key="k", now=NOW)
        attempts.record(record, tenant_id=TENANT, provider_code="card_declined", now=NOW + 1)
        self.refused(lambda: attempts.transition(record, A.UNKNOWN, tenant_id=TENANT), A.ATTEMPT_IS_FINAL)
