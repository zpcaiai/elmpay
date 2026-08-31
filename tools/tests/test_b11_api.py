"""B11 / AT-B11-01 — API contract, error semantics and compatibility model.

Most payment integration incidents are contract incidents, so most of these
tests are about the contract refusing to let a plausible-looking change through:

* ``API_MUTATION_NOT_IDEMPOTENT`` — the rule that stands between a retried
  timeout and a second charge (NN-04);
* ``API_TRANSITION_ACTOR`` — an API that lets a merchant drive a transition
  reserved for verified provider events is a way to declare yourself paid
  (NN-03), and it is the same control as B10's ``STATE_UNTRUSTED_SUCCESS``
  seen from the other side;
* ``API_TRANSITION_KEY_MISMATCH`` — two different notions of "the same request"
  is exactly one too many;
* ``API_BREAKING_*`` — compatibility measured against a recorded baseline
  instead of against somebody's memory.
"""
from __future__ import annotations

import json

from tools.paygov import api, apigen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class ApiContractHappyPath(FixtureTestCase):
    def test_real_contract_passes(self):
        problems = api.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("api-contract", registry.names())

    def test_every_write_operation_requires_an_idempotency_key(self):
        contract = self.fixture.read("governance/api-contract.json")
        writes = [o for o in contract["operations"] if o["method"] in api.WRITE_METHODS]
        self.assertTrue(writes)
        for operation in writes:
            self.assertTrue(operation["idempotency"]["required"], operation["id"])

    def test_no_read_operation_pretends_to_be_idempotent(self):
        contract = self.fixture.read("governance/api-contract.json")
        for operation in contract["operations"]:
            if operation["method"] == "GET":
                self.assertIsNone(operation.get("idempotency"), operation["id"])

    def test_every_list_operation_is_cursor_paginated(self):
        contract = self.fixture.read("governance/api-contract.json")
        lists = [o for o in contract["operations"] if o.get("pagination")]
        self.assertGreaterEqual(len(lists), 3)
        for operation in lists:
            self.assertEqual(operation["pagination"]["style"], "cursor")
            self.assertTrue(operation["pagination"]["stable_sort"])

    def test_operations_agree_with_the_state_machines_they_drive(self):
        contract = self.fixture.read("governance/api-contract.json")
        model = self.fixture.read("governance/state-machines.json")
        index = {(m["name"], t["event"]): t
                 for m in model["machines"] for t in m["transitions"]}
        driving = [o for o in contract["operations"] if o.get("drives_transition")]
        self.assertGreaterEqual(len(driving), 4)
        for operation in driving:
            key = (operation["drives_transition"]["machine"],
                   operation["drives_transition"]["event"])
            transition = index[key]
            self.assertEqual(transition["actor"], operation["actor"], operation["id"])
            self.assertEqual(transition["idempotency"], operation["idempotency"]["scope"],
                             operation["id"])

    def test_no_merchant_facing_operation_drives_a_provider_transition(self):
        """The API-side statement of 'the browser is not proof' (NN-03)."""
        contract = self.fixture.read("governance/api-contract.json")
        for operation in contract["operations"]:
            if operation["actor"] in ("merchant", "customer"):
                transition = operation.get("drives_transition")
                if transition:
                    self.assertNotIn("provider.", transition["event"], operation["id"])

    def test_the_webhook_endpoint_verifies_a_signature_before_anything_else(self):
        contract = self.fixture.read("governance/api-contract.json")
        webhook = next(o for o in contract["operations"] if o["auth"] == "provider_signature")
        self.assertTrue(webhook["signature"]["required"])
        self.assertEqual(webhook["signature"]["algorithm"], "hmac-sha256")
        self.assertLessEqual(webhook["signature"]["tolerance_seconds"], 600)
        self.assertGreaterEqual(webhook["signature"]["replay_window_hours"], 1)

    def test_public_operations_require_oauth2_and_mtls_holder_binding(self):
        contract = self.fixture.read("governance/api-contract.json")
        schemes = {entry["id"]: entry for entry in contract["auth_schemes"]}
        oauth = schemes["oauth2_mtls"]
        self.assertEqual(oauth["type"], "oauth2_mtls")
        self.assertEqual(oauth["token_type"], "at+jwt")
        self.assertEqual(oauth["holder_binding"], "mtls-x5t#S256")
        public = [operation for operation in contract["operations"]
                  if operation["actor"] != "provider-event"]
        self.assertTrue(public)
        for operation in public:
            self.assertEqual(operation["auth"], "oauth2_mtls", operation["id"])
            self.assertTrue(operation["required_scopes"], operation["id"])

    def test_openapi_ands_oauth2_scopes_with_mutual_tls(self):
        document = json.loads(apigen.openapi_json(REAL_ROOT))
        schemes = document["components"]["securitySchemes"]
        self.assertEqual(schemes["OAuth2"]["type"], "oauth2")
        self.assertEqual(schemes["MutualTLS"]["type"], "mutualTLS")
        create = document["paths"]["/v1/payment_intents"]["post"]
        self.assertEqual(create["security"], [{
            "OAuth2": ["payments.write"], "MutualTLS": []}])

    def test_no_error_message_can_leak_a_credential_or_a_pan(self):
        contract = self.fixture.read("governance/api-contract.json")
        for entry in contract["errors"]:
            for token in api.LEAKY:
                self.assertNotIn(token, entry["safe_message"].lower(), entry["code"])

    def test_only_transport_level_failures_are_marked_retryable(self):
        contract = self.fixture.read("governance/api-contract.json")
        for entry in contract["errors"]:
            if entry["retryable"]:
                self.assertIn(entry["http_status"], api.RETRYABLE_STATUS, entry["code"])

    def test_a_provider_timeout_is_retryable_and_never_a_failure(self):
        contract = self.fixture.read("governance/api-contract.json")
        timeout = next(e for e in contract["errors"] if e["code"] == "provider_timeout")
        self.assertTrue(timeout["retryable"])
        self.assertIn("不要", timeout["remedy"])

    def test_money_on_the_wire_is_integer_minor_units(self):
        document = json.loads(apigen.openapi_json(REAL_ROOT))
        money = document["components"]["schemas"]["Money"]
        self.assertEqual(money["properties"]["amount_minor"]["type"], "integer")
        self.assertEqual(money["properties"]["amount_minor"]["format"], "int64")
        self.assertNotIn("number", json.dumps(money))

    def test_generated_artefacts_match_the_contract(self):
        for rel, content in apigen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)

    def test_generated_artefacts_carry_a_banner(self):
        for rel in apigen.TARGETS:
            self.assertIn("GENERATED FILE", (REAL_ROOT / rel).read_text(encoding="utf-8"), rel)

    def test_openapi_declares_every_operation_and_its_errors(self):
        contract = self.fixture.read("governance/api-contract.json")
        document = json.loads(apigen.openapi_json(REAL_ROOT))
        declared = {op["operationId"]
                    for item in document["paths"].values() for op in item.values()}
        self.assertEqual(declared, {o["id"] for o in contract["operations"]})

    def test_the_baseline_covers_the_current_major(self):
        contract = self.fixture.read("governance/api-contract.json")
        baseline = self.fixture.read("contracts/api/openapi.baseline.json")
        self.assertEqual(baseline["major"], contract["versioning"]["current_major"])
        self.assertEqual(set(baseline["operations"]), {o["id"] for o in contract["operations"]})


class ApiGateRejects(FixtureTestCase):
    REL = "governance/api-contract.json"

    def _validate(self):
        return api.validate(self.fixture.root, Budget(seconds=60).start())

    def _op(self, data, oid):
        return next(o for o in data["operations"] if o["id"] == oid)

    def _sync(self):
        """Regenerate the fixture's artefacts so only the rule under test can fire."""
        for rel, content in apigen.render_all(self.fixture.root).items():
            self.fixture.write(rel, content)

    def test_rejects_unreadable_contract(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("API_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("API_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_an_empty_operation_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("operations", []))
        self.assertIn("API_SHAPE", self.codes(self._validate()))

    def test_rejects_an_empty_error_catalogue(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("errors", []))
        self.assertIn("API_SHAPE", self.codes(self._validate()))

    def test_rejects_header_versioning(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["versioning"].__setitem__("scheme", "header"))
        self.assertIn("API_VERSIONING", self.codes(self._validate()))

    def test_rejects_a_short_parallel_support_window(self):
        self.fixture.mutate(self.REL, lambda d: d["versioning"].__setitem__(
            "minimum_parallel_support_months", 3))
        self.assertIn("API_VERSIONING", self.codes(self._validate()))

    def test_rejects_a_short_deprecation_notice(self):
        self.fixture.mutate(self.REL, lambda d: d["versioning"]["deprecation"].__setitem__(
            "notice_days", 30))
        self.assertIn("API_DEPRECATION", self.codes(self._validate()))

    def test_rejects_a_deprecated_operation_without_a_replacement(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "get_refund").__setitem__(
            "deprecated", {"sunset": "2027-01-01"}))
        self.assertIn("API_DEPRECATION", self.codes(self._validate()))

    def test_rejects_dropping_the_w3c_trace_header(self):
        self.fixture.mutate(self.REL, lambda d: d["trace"].__setitem__(
            "required_headers", ["X-Request-Id"]))
        self.assertIn("API_TRACE", self.codes(self._validate()))

    def test_rejects_offset_pagination_policy(self):
        self.fixture.mutate(self.REL, lambda d: d["pagination"].__setitem__("style", "offset"))
        self.assertIn("API_PAGINATION_POLICY", self.codes(self._validate()))

    def test_rejects_unforbidding_offset_parameters(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["pagination"].__setitem__("forbidden_params", []))
        self.assertIn("API_PAGINATION_POLICY", self.codes(self._validate()))

    def test_rejects_an_absurd_page_limit(self):
        self.fixture.mutate(self.REL, lambda d: d["pagination"].__setitem__("max_limit", 100000))
        self.assertIn("API_PAGINATION_POLICY", self.codes(self._validate()))

    def test_rejects_an_operation_paginating_past_the_contract_bound(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "list_refunds")["pagination"]
                            .__setitem__("max_limit", 5000))
        self.assertIn("API_PAGINATION", self.codes(self._validate()))

    def test_rejects_cursor_pagination_without_a_stable_sort(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "list_refunds")["pagination"]
                            .__setitem__("stable_sort", ""))
        self.assertIn("API_PAGINATION", self.codes(self._validate()))

    def test_rejects_decimal_money_on_the_wire(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["money_shape"].__setitem__("amount_type", "decimal"))
        problems = self._validate()
        self.assertIn("API_MONEY_SHAPE", self.codes(problems))
        self.assertIn("NN-05", self.rules(problems))

    def test_rejects_an_amount_field_that_hides_its_unit(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["money_shape"].__setitem__("amount_field", "amount"))
        self.assertIn("API_MONEY_SHAPE", self.codes(self._validate()))

    def test_rejects_an_amount_without_a_currency(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["money_shape"].__setitem__("currency_field", "ccy"))
        self.assertIn("API_MONEY_SHAPE", self.codes(self._validate()))

    def test_rejects_a_write_operation_without_an_idempotency_key(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._op(d, "create_refund").pop("idempotency"))
        problems = self._validate()
        self.assertIn("API_MUTATION_NOT_IDEMPOTENT", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_an_idempotency_record_that_expires_too_soon(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "create_refund")["idempotency"]
                            .__setitem__("retention_hours", 1))
        self.assertIn("API_IDEMPOTENCY_RETENTION", self.codes(self._validate()))

    def test_rejects_a_key_conflict_that_maps_to_no_error(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "create_refund")["idempotency"]
                            .__setitem__("conflict_error", "shrug"))
        self.assertIn("API_IDEMPOTENCY_CONFLICT", self.codes(self._validate()))

    def test_rejects_a_read_operation_carrying_an_idempotency_key(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "get_refund").__setitem__(
            "idempotency", {"required": True, "header": "Idempotency-Key", "scope": "x",
                            "conflict_error": "idempotency_key_reuse", "retention_hours": 168}))
        self.assertIn("API_READ_IDEMPOTENCY", self.codes(self._validate()))

    def test_rejects_an_operation_driving_a_transition_that_does_not_exist(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "cancel_refund").__setitem__(
            "drives_transition", {"machine": "refund", "event": "merchant.teleport"}))
        self.assertIn("API_TRANSITION_UNKNOWN", self.codes(self._validate()))

    def test_rejects_an_idempotency_scope_that_disagrees_with_the_transition(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "cancel_refund")["idempotency"]
                            .__setitem__("scope", "something_else"))
        problems = self._validate()
        self.assertIn("API_TRANSITION_KEY_MISMATCH", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_exposing_a_provider_transition_to_the_merchant(self):
        """The 'declare yourself paid' attack, blocked from the API side."""
        self.fixture.mutate(self.REL, lambda d: self._op(d, "capture_payment_intent").__setitem__(
            "drives_transition", {"machine": "payment-intent", "event": "provider.captured"}))
        problems = self._validate()
        self.assertIn("API_TRANSITION_ACTOR", self.codes(problems))
        self.assertIn("NN-03", self.rules(problems))

    def test_rejects_an_operation_with_an_undeclared_auth_scheme(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._op(d, "get_refund").__setitem__("auth", "vibes"))
        self.assertIn("API_AUTH", self.codes(self._validate()))

    def test_rejects_static_api_key_as_production_auth(self):
        self.fixture.mutate(self.REL, lambda d: d["auth_schemes"].append({
            "id": "api_key", "type": "api_key", "description": "static"}))
        self.assertIn("API_STATIC_KEY_FORBIDDEN", self.codes(self._validate()))

    def test_rejects_oauth_without_mtls_holder_binding(self):
        self.fixture.mutate(self.REL, lambda d: next(
            scheme for scheme in d["auth_schemes"] if scheme["id"] == "oauth2_mtls")
            .__setitem__("holder_binding", "none"))
        self.assertIn("API_AUTH_SCHEME", self.codes(self._validate()))

    def test_rejects_an_undeclared_oauth_scope(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "get_refund").__setitem__(
            "required_scopes", ["platform.root"]))
        self.assertIn("API_AUTH_SCOPE", self.codes(self._validate()))

    def test_rejects_a_provider_callback_claiming_oauth_scopes(self):
        self.fixture.mutate(self.REL, lambda d: self._op(
            d, "receive_provider_event").__setitem__("required_scopes", ["payments.write"]))
        self.assertIn("API_AUTH_SCOPE", self.codes(self._validate()))

    def test_rejects_provider_signature_auth_for_a_merchant_actor(self):
        def mutate(document):
            operation = self._op(document, "get_refund")
            operation["auth"] = "provider_signature"
            operation.pop("required_scopes")
            operation["signature"] = {
                "required": True,
                "header": "X-Payment-Signature",
                "timestamp_header": "X-Payment-Timestamp",
                "algorithm": "hmac-sha256",
                "tolerance_seconds": 300,
                "replay_window_hours": 24,
            }
        self.fixture.mutate(self.REL, mutate)
        self.assertIn("API_AUTH_ACTOR", self.codes(self._validate()))

    def test_rejects_a_webhook_that_does_not_verify_its_signature(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._op(d, "receive_provider_event").pop("signature"))
        problems = self._validate()
        self.assertIn("API_SIGNATURE", self.codes(problems))
        self.assertIn("NN-08", self.rules(problems))

    def test_rejects_an_unbounded_signature_timestamp_window(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "receive_provider_event")["signature"]
                            .__setitem__("tolerance_seconds", 0))
        self.assertIn("API_SIGNATURE", self.codes(self._validate()))

    def test_rejects_a_weak_signature_algorithm(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "receive_provider_event")["signature"]
                            .__setitem__("algorithm", "md5"))
        self.assertIn("API_SIGNATURE", self.codes(self._validate()))

    def test_rejects_a_missing_replay_window(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "receive_provider_event")["signature"]
                            .__setitem__("replay_window_hours", 0))
        self.assertIn("API_SIGNATURE", self.codes(self._validate()))

    def test_rejects_a_normal_operation_claiming_a_provider_signature(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "get_refund").__setitem__(
            "signature", {"required": True}))
        self.assertIn("API_SIGNATURE", self.codes(self._validate()))

    def test_rejects_a_non_snake_case_operation_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._op(d, "get_refund").__setitem__("id", "GetRefund"))
        self.assertIn("API_OPERATION_ID", self.codes(self._validate()))

    def test_rejects_two_operations_with_the_same_id(self):
        self.fixture.mutate(self.REL, lambda d: d["operations"].append(
            dict(self._op(d, "get_refund"), path="/v1/refunds/{refund_id}/copy")))
        self.assertIn("API_OPERATION_DUPLICATE", self.codes(self._validate()))

    def test_rejects_two_operations_on_the_same_route(self):
        self.fixture.mutate(self.REL, lambda d: d["operations"].append(
            dict(self._op(d, "get_refund"), id="get_refund_again")))
        self.assertIn("API_ROUTE_DUPLICATE", self.codes(self._validate()))

    def test_rejects_a_path_without_a_version(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._op(d, "get_refund").__setitem__("path", "/refunds"))
        self.assertIn("API_PATH", self.codes(self._validate()))

    def test_rejects_an_operation_without_a_summary(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._op(d, "get_refund").__setitem__("summary", ""))
        self.assertIn("API_SUMMARY", self.codes(self._validate()))

    def test_rejects_an_operation_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["operations"].append("get_refund"))
        self.assertIn("API_SHAPE", self.codes(self._validate()))

    def test_rejects_an_error_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["errors"].append("boom"))
        self.assertIn("API_SHAPE", self.codes(self._validate()))

    def test_rejects_missing_auth_schemes(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("auth_schemes", []))
        self.assertIn("API_SHAPE", self.codes(self._validate()))

    def test_rejects_an_undeclared_error_code_on_an_operation(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._op(d, "get_refund")["errors"].append("mystery"))
        self.assertIn("API_ERROR_UNKNOWN", self.codes(self._validate()))

    def test_rejects_an_error_nobody_can_return(self):
        self.fixture.mutate(self.REL, lambda d: d["errors"].append(
            {"code": "lonely_error", "http_status": 400, "retryable": False,
             "category": "client", "safe_message": "从来不会发生的错误", "remedy": "无需处理"}))
        self.assertIn("API_ERROR_UNUSED", self.codes(self._validate()))

    def test_rejects_a_non_snake_case_error_code(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["errors"][0].__setitem__("code", "InvalidRequest"))
        self.assertIn("API_ERROR_CODE", self.codes(self._validate()))

    def test_rejects_a_duplicate_error_code(self):
        self.fixture.mutate(self.REL, lambda d: d["errors"].append(dict(d["errors"][0])))
        self.assertIn("API_ERROR_DUPLICATE", self.codes(self._validate()))

    def test_rejects_an_error_with_an_unlisted_http_status(self):
        self.fixture.mutate(self.REL, lambda d: d["errors"][0].__setitem__("http_status", 418))
        self.assertIn("API_ERROR_STATUS", self.codes(self._validate()))

    def test_rejects_an_error_that_does_not_say_whether_to_retry(self):
        self.fixture.mutate(self.REL, lambda d: d["errors"][0].__setitem__("retryable", "maybe"))
        self.assertIn("API_ERROR_STATUS", self.codes(self._validate()))

    def test_rejects_marking_a_hard_decline_retryable(self):
        self.fixture.mutate(self.REL, lambda d: next(
            e for e in d["errors"] if e["code"] == "permission_denied")
            .__setitem__("retryable", True))
        problems = self._validate()
        self.assertIn("API_ERROR_RETRYABLE", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_an_error_without_a_message(self):
        self.fixture.mutate(self.REL, lambda d: d["errors"][0].__setitem__("safe_message", ""))
        self.assertIn("API_ERROR_MESSAGE", self.codes(self._validate()))

    def test_rejects_an_error_message_that_leaks_card_data(self):
        self.fixture.mutate(self.REL, lambda d: d["errors"][0].__setitem__(
            "safe_message", "卡号 4111111111111111 被拒绝"))
        problems = self._validate()
        self.assertIn("API_ERROR_LEAK", self.codes(problems))
        self.assertIn("NN-14", self.rules(problems))

    def test_rejects_an_error_without_a_remedy(self):
        self.fixture.mutate(self.REL, lambda d: d["errors"][0].__setitem__("remedy", ""))
        self.assertIn("API_ERROR_REMEDY", self.codes(self._validate()))

    def test_rejects_a_missing_compatibility_baseline(self):
        self.fixture.remove("contracts/api/openapi.baseline.json")
        self.assertIn("API_BASELINE_MISSING", self.codes(self._validate()))

    def test_rejects_an_unreadable_baseline(self):
        self.fixture.write("contracts/api/openapi.baseline.json", "{ broken", encoding="utf-8")
        self.assertIn("API_BASELINE_UNREADABLE", self.codes(self._validate()))

    def test_rejects_a_baseline_recorded_for_a_different_major(self):
        self.fixture.mutate("contracts/api/openapi.baseline.json",
                            lambda d: d.__setitem__("major", 2))
        self.assertIn("API_BASELINE_MAJOR", self.codes(self._validate()))

    def test_rejects_removing_an_operation_inside_a_stable_major(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "operations", [o for o in d["operations"] if o["id"] != "get_refund"]))
        self._sync()
        self.assertIn("API_BREAKING_REMOVAL", self.codes(self._validate()))

    def test_rejects_moving_an_operation_to_a_new_route(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "get_refund").__setitem__(
            "path", "/v1/refund_records/{refund_id}"))
        self._sync()
        self.assertIn("API_BREAKING_ROUTE", self.codes(self._validate()))

    def test_rejects_quietly_dropping_an_idempotency_guarantee(self):
        def weaken(d):
            self._op(d, "create_refund")["idempotency"]["required"] = False
        self.fixture.mutate(self.REL, weaken)
        self._sync()
        codes = self.codes(self._validate())
        self.assertIn("API_BREAKING_IDEMPOTENCY", codes)

    def test_rejects_quietly_dropping_a_declared_error_code(self):
        self.fixture.mutate(self.REL, lambda d: self._op(d, "get_refund").__setitem__(
            "errors", ["internal_error"]))
        self._sync()
        self.assertIn("API_BREAKING_ERRORS", self.codes(self._validate()))

    def test_rejects_changing_recorded_auth_inside_a_stable_major(self):
        baseline = "contracts/api/openapi.baseline.json"
        self.fixture.mutate(baseline, lambda d: d["operations"]["get_refund"].update({
            "auth": "oauth2_mtls", "required_scopes": ["payments.read"]}))
        self.fixture.mutate(self.REL, lambda d: self._op(d, "get_refund").__setitem__(
            "auth", "provider_signature"))
        self._sync()
        self.assertIn("API_BREAKING_AUTH", self.codes(self._validate()))

    def test_rejects_adding_a_required_scope_inside_a_stable_major(self):
        baseline = "contracts/api/openapi.baseline.json"
        self.fixture.mutate(baseline, lambda d: d["operations"]["get_refund"].update({
            "auth": "oauth2_mtls", "required_scopes": ["payments.read"]}))
        self.fixture.mutate(self.REL, lambda d: self._op(d, "get_refund").__setitem__(
            "required_scopes", ["payments.read", "financial.read"]))
        self._sync()
        self.assertIn("API_BREAKING_AUTH_SCOPE", self.codes(self._validate()))

    def test_rejects_missing_generated_artefacts(self):
        self.fixture.remove("contracts/api/openapi.json")
        self.assertIn("API_GENERATED_MISSING", self.codes(self._validate()))

    def test_rejects_a_hand_edited_openapi_document(self):
        path = self.fixture.root / "contracts/api/openapi.json"
        path.write_text(path.read_text(encoding="utf-8").replace(
            "starting_after", "offset"), encoding="utf-8")
        self.assertIn("API_GENERATED_DRIFT", self.codes(self._validate()))

    def test_fails_closed_when_the_artefacts_cannot_be_generated(self):
        """A gate must turn a broken contract into a finding, not into a crash."""
        self.fixture.mutate(self.REL, lambda d: self._op(d, "get_refund").pop("errors"))
        codes = self.codes(self._validate())
        self.assertIn("API_GENERATED", codes)


class TransitionVectors(FixtureTestCase):
    """B10 left the vectors open until the API pinned the event names. Here they are."""

    def setUp(self):
        super().setUp()
        from libs.statemachine.reference import machine as ref
        self.ref = ref
        self.machines = ref.load(REAL_ROOT / "governance/state-machines.json")
        self.vectors = json.loads(
            (REAL_ROOT / "contracts/api/transition-vectors.json").read_text(encoding="utf-8"))

    def test_the_vectors_are_not_empty(self):
        self.assertGreaterEqual(len(self.vectors["accepted"]), 5)
        self.assertGreaterEqual(len(self.vectors["rejected"]), 5)

    def test_every_accepted_vector_lands_on_the_declared_state(self):
        for vector in self.vectors["accepted"]:
            instance = self.ref.Instance(self.machines[vector["machine"]], state=vector["from"])
            self.assertEqual(instance.apply(vector["event"], vector["actor"], "t1"),
                             vector["expected_to"], vector)

    def test_every_accepted_vector_survives_a_replay_unchanged(self):
        for vector in self.vectors["accepted"]:
            instance = self.ref.Instance(self.machines[vector["machine"]], state=vector["from"])
            instance.apply(vector["event"], vector["actor"], "t1")
            before = list(instance.history)
            self.assertEqual(instance.apply(vector["event"], vector["actor"], "t1"),
                             vector["expected_to"], vector)
            self.assertEqual(instance.history, before, vector)

    def test_every_rejected_vector_is_rejected_for_the_declared_reason(self):
        for vector in self.vectors["rejected"]:
            instance = self.ref.Instance(self.machines[vector["machine"]], state=vector["from"])
            with self.assertRaises(self.ref.TransitionRejected, msg=vector) as raised:
                instance.apply(vector["event"], vector["actor"], "t1")
            self.assertEqual(raised.exception.code, vector["expected_rejection"], vector)

    def test_the_vectors_cover_every_operation_that_drives_a_transition(self):
        contract = self.fixture.read("governance/api-contract.json")
        driving = {o["id"] for o in contract["operations"] if o.get("drives_transition")}
        self.assertEqual({v["operation"] for v in self.vectors["accepted"]}, driving)

    def test_a_transition_legal_from_two_states_gets_two_vectors(self):
        """The collapsing-index bug this file exists to keep fixed."""
        counts = {}
        for vector in self.vectors["accepted"]:
            counts[(vector["machine"], vector["event"])] = \
                counts.get((vector["machine"], vector["event"]), 0) + 1
        self.assertTrue(any(count > 1 for count in counts.values()), counts)
