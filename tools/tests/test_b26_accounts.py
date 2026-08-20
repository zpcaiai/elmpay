"""B26 / AT-B26-01 — provider account and credential binding.

``test_two_bindings_that_match_are_quarantined_not_guessed`` is the test this
batch exists for. When a provider callback matches more than one binding, every
convenient fallback — closest amount, nearest timestamp, most recent binding —
books one merchant's money against another, and nothing in the record shows
which way round it went. The model has three answers and no fourth.

``test_a_suspended_binding_still_receives_callbacks`` is the other one. Turning
off a suspended merchant's callbacks looks like containment; what it actually
does is destroy the platform's own proof that money it already holds arrived.
"""
from __future__ import annotations

import json

from libs.provider.reference import binding as B
from tools.paygov import accounts, accountsgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/provider-accounts.json"
NOW = 1_700_000_000


def _provider(model, pid):
    return next(p for p in model["providers"] if p["id"] == pid)


def _row(model, state):
    return next(r for r in model["capability_matrix"] if r["state"] == state)


def _transition(model, source, target):
    return next(t for t in model["lifecycle"]["transitions"]
                if t["from"] == source and t["to"] == target)


class ProviderAccountsHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = accounts.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("provider-accounts", registry.names())

    def test_a_binding_is_scoped_by_four_dimensions(self):
        binding = self.fixture.read(REL)["binding"]
        for field in accounts.IDENTITY_FIELDS:
            self.assertIn(field, binding["identity_fields"], field)
            self.assertIn(field, binding["unique_key"], field)
            self.assertIn(field, binding["immutable_fields"], field)

    def test_a_binding_holds_exactly_one_credential(self):
        self.assertTrue(self.fixture.read(REL)["binding"]["one_credential_per_binding"])

    def test_every_provider_names_a_key_the_key_model_defines(self):
        keys = self.fixture.read("governance/key-management.json")
        known = {k["id"] for k in keys["keys"]}
        bound = {p["provider"] for p in keys["provider_keys"]}
        for provider in self.fixture.read(REL)["providers"]:
            self.assertIn(provider["key_id"], known, provider["id"])
            self.assertIn(provider["id"], bound, provider["id"])

    def test_every_provider_environment_exists_in_the_tenant_registry(self):
        environments = {e["id"] for e in
                        self.fixture.read("governance/tenant-registry.json")["environments"]}
        for provider in self.fixture.read(REL)["providers"]:
            for env in provider["environments"]:
                self.assertIn(env, environments, provider["id"])

    def test_every_settlement_currency_exists_in_the_currency_metadata(self):
        known = {c["code"] for c in
                 self.fixture.read("governance/currency-metadata.json")["currencies"]}
        for provider in self.fixture.read(REL)["providers"]:
            for code in provider["settlement_currencies"]:
                self.assertIn(code, known, provider["id"])

    def test_every_provider_says_how_a_callback_is_attributed(self):
        for provider in self.fixture.read(REL)["providers"]:
            self.assertTrue(provider["callback_attribution_field"], provider["id"])
            self.assertTrue(provider["callback_signed"], provider["id"])

    def test_credentials_are_never_shared_and_never_plaintext(self):
        credentials = self.fixture.read(REL)["credentials"]
        self.assertFalse(credentials["plaintext_at_rest"])
        self.assertFalse(credentials["plaintext_in_logs"])
        for field in ("shared_across_tenants", "shared_across_environments",
                      "shared_across_projects"):
            self.assertFalse(credentials[field], field)

    def test_a_decrypted_credential_expires(self):
        credentials = self.fixture.read(REL)["credentials"]
        self.assertGreater(credentials["max_decrypt_lease_seconds"], 0)
        self.assertLessEqual(credentials["max_decrypt_lease_seconds"],
                             accounts.MAX_LEASE_SECONDS)

    def test_rotation_has_an_overlap_and_is_not_slower_than_its_key(self):
        credentials = self.fixture.read(REL)["credentials"]
        keys = self.fixture.read("governance/key-management.json")
        kek = next(k for k in keys["keys"] if k["id"] == "kek-provider-credentials")
        self.assertGreater(credentials["rotation_overlap_days"], 0)
        self.assertLess(credentials["rotation_overlap_days"], credentials["rotation_max_days"])
        self.assertLessEqual(credentials["rotation_max_days"], kek["rotation_days"])

    def test_a_callback_is_never_guessed(self):
        callback = self.fixture.read(REL)["callback"]
        self.assertTrue(callback["signature_required"])
        self.assertTrue(callback["attribution_must_be_deterministic"])
        self.assertFalse(callback["guess_on_ambiguity"])
        self.assertTrue(callback["quarantine_on_unattributable"])
        self.assertFalse(callback["cross_tenant_delivery_allowed"])
        self.assertFalse(callback["client_return_page_is_evidence"])

    def test_callbacks_are_idempotent_and_time_bounded(self):
        callback = self.fixture.read(REL)["callback"]
        self.assertTrue(callback["idempotency_key_field"])
        self.assertGreater(callback["replay_window_seconds"], 0)
        self.assertLessEqual(callback["replay_window_seconds"],
                             accounts.MAX_REPLAY_WINDOW_SECONDS)

    def test_quarantine_alerts_and_never_replays_itself(self):
        quarantine = self.fixture.read(REL)["quarantine"]
        self.assertGreater(quarantine["retention_days"], 0)
        self.assertTrue(quarantine["alert_required"])
        self.assertFalse(quarantine["auto_replay_allowed"])
        self.assertTrue(quarantine["manual_replay_requires_attribution"])

    def test_activation_needs_a_real_round_trip(self):
        activation = self.fixture.read(REL)["activation"]
        for field in ("test_transaction_required", "callback_roundtrip_required",
                      "signature_verification_required"):
            self.assertTrue(activation[field], field)
        self.assertEqual(sorted(_transition(self.fixture.read(REL), "pending", "active")
                                ["requires"]),
                         ["callback_roundtrip_verified", "test_transaction_settled"])

    def test_reinstating_a_binding_takes_two_people(self):
        self.assertIn("second_approver",
                      _transition(self.fixture.read(REL), "suspended", "active")["requires"])

    def test_revocation_settles_first_then_destroys(self):
        model = self.fixture.read(REL)
        for transition in model["lifecycle"]["transitions"]:
            if transition["to"] == "revoked":
                self.assertIn("in_flight_settled", transition["requires"])
                self.assertIn("credential_destroyed", transition["requires"])

    def test_a_suspended_binding_keeps_the_money_in_flight_moving(self):
        row = _row(self.fixture.read(REL), "suspended")
        self.assertFalse(row["initiate_payment"])
        for capability in accounts.IN_FLIGHT:
            self.assertTrue(row[capability], capability)

    def test_a_revoked_binding_can_do_nothing(self):
        row = _row(self.fixture.read(REL), "revoked")
        for capability in accounts.CAPABILITIES:
            self.assertFalse(row[capability], capability)

    def test_rotation_is_dual_control_in_b19(self):
        model = self.fixture.read(REL)
        authz = self.fixture.read("governance/authorization.json")
        permission = next(p for p in authz["permissions"]
                          if p["id"] == model["rotation_permission"])
        self.assertTrue(permission["dual_control"])

    def test_binding_changes_map_to_a_real_audit_class(self):
        audit = self.fixture.read("governance/audit-log.json")
        self.assertIn(self.fixture.read(REL)["audit_event_class"],
                      {c["id"] for c in audit["event_classes"]})

    def test_heuristic_attribution_stays_forbidden(self):
        forbidden = self.fixture.read(REL)["forbidden"]
        self.assertTrue(forbidden["attribution_by_amount_or_time"])
        self.assertTrue(forbidden["shared_credential_across_tenants"])
        self.assertTrue(forbidden["shared_credential_across_environments"])
        self.assertTrue(forbidden["credential_in_source_or_ci"])
        self.assertTrue(forbidden["callback_without_signature"])


class ProviderAccountGeneratedArtefacts(FixtureTestCase):
    def _validate(self):
        return accounts.validate(self.fixture.root, Budget(seconds=60).start())

    def test_generated_artefacts_match_the_model(self):
        for rel, content in accountsgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_carries_every_provider(self):
        contract = json.loads(accountsgen.contract_json(REAL_ROOT))
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        self.assertEqual({p["id"] for p in contract["providers"]},
                         {p["id"] for p in model["providers"]})

    def test_document_shows_every_state(self):
        text = accountsgen.accounts_markdown(REAL_ROOT)
        for state in accounts.STATES:
            self.assertIn(state, text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/provider/PROVIDER_ACCOUNTS.md", "hand written\n")
        self.assertIn("ACCOUNT_GENERATED_DRIFT", self.codes(self._validate()))

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/provider/account-binding.json")
        self.assertIn("ACCOUNT_GENERATED_MISSING", self.codes(self._validate()))

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("providers", [{"id": "x"}]))
        self.assertIn("ACCOUNT_GENERATED", self.codes(self._validate()))


class ProviderAccountGateRejects(FixtureTestCase):
    def _validate(self):
        return accounts.validate(self.fixture.root, Budget(seconds=60).start())

    def _assert(self, code):
        self.assertIn(code, self.codes(self._validate()))

    def _mutate(self, fn, code, rel=REL):
        self.fixture.mutate(rel, fn)
        self._assert(code)

    # -- shape ------------------------------------------------------------
    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self._assert("ACCOUNT_UNREADABLE")

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [1])
        self._assert("ACCOUNT_SHAPE")

    def test_rejects_a_bad_schema_version(self):
        self._mutate(lambda d: d.__setitem__("schema_version", "one"), "ACCOUNT_VERSION_FIELD")

    def test_rejects_a_missing_principle(self):
        self._mutate(lambda d: d.__setitem__("principle", ""), "ACCOUNT_PRINCIPLE")

    def test_rejects_a_non_object_binding_block(self):
        self._mutate(lambda d: d.__setitem__("binding", []), "ACCOUNT_SHAPE")

    def test_rejects_a_non_object_credentials_block(self):
        self._mutate(lambda d: d.__setitem__("credentials", []), "ACCOUNT_SHAPE")

    def test_rejects_a_non_object_callback_block(self):
        self._mutate(lambda d: d.__setitem__("callback", []), "ACCOUNT_SHAPE")

    def test_rejects_a_non_object_lifecycle_block(self):
        self._mutate(lambda d: d.__setitem__("lifecycle", []), "ACCOUNT_SHAPE")

    def test_rejects_a_non_object_forbidden_block(self):
        self._mutate(lambda d: d.__setitem__("forbidden", []), "ACCOUNT_SHAPE")

    def test_rejects_an_empty_provider_list(self):
        self._mutate(lambda d: d.__setitem__("providers", []), "ACCOUNT_SHAPE")

    def test_rejects_a_non_object_provider(self):
        self._mutate(lambda d: d["providers"].append("wechat"), "ACCOUNT_SHAPE")

    def test_rejects_an_empty_transition_list(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("transitions", []), "ACCOUNT_SHAPE")

    def test_rejects_a_non_object_transition(self):
        self._mutate(lambda d: d["lifecycle"]["transitions"].append("pending->active"),
                     "ACCOUNT_SHAPE")

    def test_rejects_a_non_object_matrix_row(self):
        self._mutate(lambda d: d["capability_matrix"].append("active"), "ACCOUNT_SHAPE")

    # -- the binding ------------------------------------------------------
    def test_rejects_a_binding_that_ignores_the_environment(self):
        self._mutate(lambda d: d["binding"].__setitem__(
            "identity_fields", ["tenant_id", "project_id", "provider"]),
            "ACCOUNT_BINDING_DIMENSIONS")

    def test_rejects_a_uniqueness_key_coarser_than_the_binding(self):
        self._mutate(lambda d: d["binding"].__setitem__("unique_key", ["tenant_id"]),
                     "ACCOUNT_BINDING_NOT_UNIQUE")

    def test_rejects_a_mutable_binding(self):
        self._mutate(lambda d: d["binding"].__setitem__("immutable_fields", ["provider"]),
                     "ACCOUNT_BINDING_MUTABLE")

    def test_rejects_two_credentials_on_one_binding(self):
        self._mutate(lambda d: d["binding"].__setitem__("one_credential_per_binding", False),
                     "ACCOUNT_MULTI_CREDENTIAL")

    def test_rejects_an_unexplained_binding(self):
        self._mutate(lambda d: d["binding"].__setitem__("notes", ""), "ACCOUNT_BINDING_NOTES")

    # -- providers --------------------------------------------------------
    def test_rejects_a_non_snake_case_provider_id(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("id", "WeChat Pay"),
                     "ACCOUNT_PROVIDER_ID")

    def test_rejects_a_duplicate_provider(self):
        self._mutate(lambda d: d["providers"].append(dict(d["providers"][0])),
                     "ACCOUNT_PROVIDER_DUPLICATE")

    def test_rejects_a_key_the_key_model_does_not_define(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("key_id", "kek-imaginary"),
                     "ACCOUNT_PROVIDER_KEY_UNKNOWN")

    def test_rejects_a_provider_with_no_entry_in_the_key_model(self):
        self.fixture.mutate("governance/key-management.json",
                            lambda d: d.__setitem__(
                                "provider_keys", [p for p in d["provider_keys"]
                                                  if p["provider"] != "wechat"]))
        self._assert("ACCOUNT_PROVIDER_KEY_UNBOUND")

    def test_rejects_an_unknown_credential_kind(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("credential_kind", "password"),
                     "ACCOUNT_CREDENTIAL_KIND")

    def test_rejects_a_provider_with_no_environment(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("environments", []),
                     "ACCOUNT_PROVIDER_NO_ENV")

    def test_rejects_an_environment_the_tenant_registry_does_not_define(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("environments",
                                                             ["live", "staging"]),
                     "ACCOUNT_ENV_UNKNOWN")

    def test_rejects_a_provider_with_no_settlement_currency(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("settlement_currencies", []),
                     "ACCOUNT_PROVIDER_NO_CURRENCY")

    def test_rejects_a_currency_the_money_model_does_not_know(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("settlement_currencies", ["XYZ"]),
                     "ACCOUNT_CURRENCY_UNKNOWN")

    def test_rejects_a_provider_that_does_not_say_how_to_attribute_a_callback(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("callback_attribution_field", ""),
                     "ACCOUNT_NO_ATTRIBUTION_FIELD")

    def test_rejects_an_unsigned_provider_callback(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("callback_signed", False),
                     "ACCOUNT_CALLBACK_UNSIGNED")

    def test_rejects_a_provider_credential_that_never_rotates(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("credential_rotation_days", 0),
                     "ACCOUNT_PROVIDER_ROTATION")

    def test_rejects_an_unexplained_provider(self):
        self._mutate(lambda d: d["providers"][0].__setitem__("notes", ""),
                     "ACCOUNT_PROVIDER_NOTES")

    # -- credentials ------------------------------------------------------
    def test_rejects_plaintext_credentials_at_rest(self):
        self._mutate(lambda d: d["credentials"].__setitem__("plaintext_at_rest", True),
                     "ACCOUNT_PLAINTEXT_CREDENTIAL")

    def test_rejects_credentials_in_logs(self):
        self._mutate(lambda d: d["credentials"].__setitem__("plaintext_in_logs", True),
                     "ACCOUNT_PLAINTEXT_CREDENTIAL")

    def test_rejects_credentials_stored_outside_an_envelope(self):
        self._mutate(lambda d: d["credentials"].__setitem__("storage", "database_column"),
                     "ACCOUNT_CREDENTIAL_STORAGE")

    def test_rejects_a_credential_shared_across_tenants(self):
        self._mutate(lambda d: d["credentials"].__setitem__("shared_across_tenants", True),
                     "ACCOUNT_SHARED_CREDENTIAL")

    def test_rejects_a_credential_shared_across_environments(self):
        self._mutate(lambda d: d["credentials"].__setitem__("shared_across_environments", True),
                     "ACCOUNT_SHARED_CREDENTIAL")

    def test_rejects_a_decrypted_credential_that_never_expires(self):
        self._mutate(lambda d: d["credentials"].__setitem__("max_decrypt_lease_seconds", 0),
                     "ACCOUNT_LEASE_UNBOUNDED")

    def test_rejects_a_credential_that_never_rotates(self):
        self._mutate(lambda d: d["credentials"].__setitem__("rotation_max_days", 0),
                     "ACCOUNT_ROTATION_UNBOUNDED")

    def test_rejects_rotation_without_an_overlap(self):
        self._mutate(lambda d: d["credentials"].__setitem__("rotation_overlap_days", 0),
                     "ACCOUNT_ROTATION_NO_OVERLAP")

    def test_rejects_a_credential_that_outlives_the_key_wrapping_it(self):
        self.fixture.mutate("governance/key-management.json",
                            lambda d: next(k for k in d["keys"]
                                           if k["id"] == "kek-provider-credentials")
                            .__setitem__("rotation_days", 30))
        self._assert("ACCOUNT_ROTATION_SLOWER_THAN_KEY")

    def test_rejects_unexplained_credential_rules(self):
        self._mutate(lambda d: d["credentials"].__setitem__("notes", ""),
                     "ACCOUNT_CREDENTIAL_NOTES")

    # -- callbacks --------------------------------------------------------
    def test_rejects_unsigned_callbacks(self):
        self._mutate(lambda d: d["callback"].__setitem__("signature_required", False),
                     "ACCOUNT_CALLBACK_UNSIGNED")

    def test_rejects_nondeterministic_attribution(self):
        self._mutate(lambda d: d["callback"].__setitem__(
            "attribution_must_be_deterministic", False), "ACCOUNT_CALLBACK_GUESSED")

    def test_rejects_guessing_on_ambiguity(self):
        self._mutate(lambda d: d["callback"].__setitem__("guess_on_ambiguity", True),
                     "ACCOUNT_CALLBACK_GUESSED")

    def test_rejects_dropping_an_unattributable_callback(self):
        self._mutate(lambda d: d["callback"].__setitem__("quarantine_on_unattributable", False),
                     "ACCOUNT_NO_QUARANTINE")

    def test_rejects_cross_tenant_delivery(self):
        self._mutate(lambda d: d["callback"].__setitem__("cross_tenant_delivery_allowed", True),
                     "ACCOUNT_CROSS_TENANT_CALLBACK")

    def test_rejects_the_return_page_as_evidence(self):
        self._mutate(lambda d: d["callback"].__setitem__("client_return_page_is_evidence", True),
                     "ACCOUNT_RETURN_PAGE_EVIDENCE")

    def test_rejects_an_unbounded_replay_window(self):
        self._mutate(lambda d: d["callback"].__setitem__("replay_window_seconds", 0),
                     "ACCOUNT_REPLAY_WINDOW")

    def test_rejects_callbacks_without_an_idempotency_key(self):
        self._mutate(lambda d: d["callback"].__setitem__("idempotency_key_field", ""),
                     "ACCOUNT_NO_IDEMPOTENCY_KEY")

    def test_rejects_unexplained_callback_rules(self):
        self._mutate(lambda d: d["callback"].__setitem__("notes", ""), "ACCOUNT_CALLBACK_NOTES")

    # -- quarantine -------------------------------------------------------
    def test_rejects_a_missing_quarantine(self):
        self._mutate(lambda d: d.__setitem__("quarantine", []), "ACCOUNT_NO_QUARANTINE")

    def test_rejects_a_quarantine_that_keeps_nothing(self):
        self._mutate(lambda d: d["quarantine"].__setitem__("retention_days", 0),
                     "ACCOUNT_QUARANTINE_UNRETAINED")

    def test_rejects_a_silent_quarantine(self):
        self._mutate(lambda d: d["quarantine"].__setitem__("alert_required", False),
                     "ACCOUNT_QUARANTINE_SILENT")

    def test_rejects_automatic_replay(self):
        self._mutate(lambda d: d["quarantine"].__setitem__("auto_replay_allowed", True),
                     "ACCOUNT_QUARANTINE_AUTO_REPLAY")

    def test_rejects_a_replay_that_names_no_binding(self):
        self._mutate(lambda d: d["quarantine"].__setitem__(
            "manual_replay_requires_attribution", False), "ACCOUNT_QUARANTINE_BLIND_REPLAY")

    # -- activation and lifecycle -----------------------------------------
    def test_rejects_a_missing_activation_block(self):
        self._mutate(lambda d: d.__setitem__("activation", []), "ACCOUNT_ACTIVATION_UNPROVEN")

    def test_rejects_activation_without_a_test_transaction(self):
        self._mutate(lambda d: d["activation"].__setitem__("test_transaction_required", False),
                     "ACCOUNT_ACTIVATION_UNPROVEN")

    def test_rejects_activation_without_a_callback_round_trip(self):
        self._mutate(lambda d: _transition(d, "pending", "active").__setitem__(
            "requires", ["test_transaction_settled"]), "ACCOUNT_ACTIVATION_UNPROVEN")

    def test_rejects_an_unexplained_activation(self):
        self._mutate(lambda d: d["activation"].__setitem__("notes", ""),
                     "ACCOUNT_ACTIVATION_NOTES")

    def test_rejects_renamed_states(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("states",
                                                          ["draft", "live", "off", "gone"]),
                     "ACCOUNT_STATES")

    def test_rejects_a_binding_that_starts_active(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("initial", "active"),
                     "ACCOUNT_INITIAL_STATE")

    def test_rejects_a_second_terminal_state(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__("terminal", ["revoked", "suspended"]),
                     "ACCOUNT_TERMINAL_STATE")

    def test_rejects_a_transition_to_an_unknown_state(self):
        self._mutate(lambda d: d["lifecycle"]["transitions"].append(
            {"from": "active", "to": "archived", "requires": ["x"], "notes": "nope"}),
            "ACCOUNT_TRANSITION_UNKNOWN")

    def test_rejects_a_duplicate_transition(self):
        self._mutate(lambda d: d["lifecycle"]["transitions"].append(
            dict(_transition(d, "pending", "active"))), "ACCOUNT_TRANSITION_DUPLICATE")

    def test_rejects_an_unguarded_transition(self):
        self._mutate(lambda d: _transition(d, "active", "suspended").__setitem__("requires", []),
                     "ACCOUNT_TRANSITION_UNGUARDED")

    def test_rejects_an_unexplained_transition(self):
        self._mutate(lambda d: _transition(d, "active", "suspended").__setitem__("notes", ""),
                     "ACCOUNT_TRANSITION_NOTES")

    def test_rejects_one_person_reinstating_a_binding(self):
        self._mutate(lambda d: _transition(d, "suspended", "active").__setitem__(
            "requires", ["reason", "actor"]), "ACCOUNT_REINSTATE_SINGLE_PERSON")

    def test_rejects_revoking_before_the_in_flight_transactions_settle(self):
        self._mutate(lambda d: _transition(d, "suspended", "revoked").__setitem__(
            "requires", ["credential_destroyed"]), "ACCOUNT_REVOKE_BEFORE_SETTLEMENT")

    def test_rejects_revocation_that_keeps_the_credential(self):
        self._mutate(lambda d: _transition(d, "suspended", "revoked").__setitem__(
            "requires", ["in_flight_settled"]), "ACCOUNT_REVOKE_KEEPS_CREDENTIAL")

    def test_rejects_an_unreachable_state(self):
        self._mutate(lambda d: d["lifecycle"].__setitem__(
            "transitions", [t for t in d["lifecycle"]["transitions"]
                            if t["to"] != "suspended"]), "ACCOUNT_STATE_UNREACHABLE")

    # -- capability matrix ------------------------------------------------
    def test_rejects_a_missing_capability_matrix(self):
        self._mutate(lambda d: d.__setitem__("capability_matrix", []),
                     "ACCOUNT_NO_CAPABILITY_MATRIX")

    def test_rejects_a_matrix_row_that_answers_nothing(self):
        self._mutate(lambda d: _row(d, "active").__setitem__("settle", "maybe"),
                     "ACCOUNT_CAPABILITY_MISSING")

    def test_rejects_an_unexplained_matrix_row(self):
        self._mutate(lambda d: _row(d, "active").__setitem__("notes", ""),
                     "ACCOUNT_CAPABILITY_NOTES")

    def test_rejects_a_pending_binding_that_takes_money(self):
        self._mutate(lambda d: _row(d, "pending").__setitem__("initiate_payment", True),
                     "ACCOUNT_PENDING_TAKES_MONEY")

    def test_rejects_a_suspended_binding_that_takes_money(self):
        self._mutate(lambda d: _row(d, "suspended").__setitem__("initiate_payment", True),
                     "ACCOUNT_SUSPENDED_TAKES_MONEY")

    def test_rejects_a_suspended_binding_with_its_callbacks_switched_off(self):
        self._mutate(lambda d: _row(d, "suspended").__setitem__("receive_callback", False),
                     "ACCOUNT_SUSPENDED_BLOCKS_CALLBACKS")

    def test_rejects_a_suspended_binding_that_cannot_refund(self):
        self._mutate(lambda d: _row(d, "suspended").__setitem__("issue_refund", False),
                     "ACCOUNT_SUSPENDED_STRANDS_MONEY")

    def test_rejects_a_revoked_binding_that_still_works(self):
        self._mutate(lambda d: _row(d, "revoked").__setitem__("receive_callback", True),
                     "ACCOUNT_REVOKED_ACTIVE")

    # -- forbidden, permission, audit -------------------------------------
    def test_rejects_relaxing_a_forbidden_rule(self):
        self._mutate(lambda d: d["forbidden"].__setitem__(
            "shared_credential_across_tenants", False), "ACCOUNT_FORBIDDEN_RELAXED")

    def test_rejects_attribution_by_amount_and_time(self):
        self._mutate(lambda d: d["forbidden"].__setitem__(
            "attribution_by_amount_or_time", False), "ACCOUNT_ATTRIBUTION_HEURISTIC")

    def test_rejects_unexplained_prohibitions(self):
        self._mutate(lambda d: d["forbidden"].__setitem__("notes", ""),
                     "ACCOUNT_FORBIDDEN_NOTES")

    def test_rejects_an_unknown_rotation_permission(self):
        self._mutate(lambda d: d.__setitem__("rotation_permission", "made.up"),
                     "ACCOUNT_PERMISSION_UNKNOWN")

    def test_rejects_single_person_credential_rotation(self):
        self.fixture.mutate("governance/authorization.json",
                            lambda d: next(p for p in d["permissions"]
                                           if p["id"] == "config.write")
                            .__setitem__("dual_control", False))
        self._assert("ACCOUNT_ROTATION_SINGLE_PERSON")

    def test_rejects_an_unknown_audit_class(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "binding.vanished"),
                     "ACCOUNT_AUDIT_CLASS_UNKNOWN")


class ProviderAccountReferenceModel(FixtureTestCase):
    MODEL = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
    SECRET_A = b"tenant-a-secret"
    SECRET_B = b"tenant-b-secret"

    def registry(self) -> B.Bindings:
        return B.Bindings(self.MODEL)

    def binding(self, tenant="ten_1", project="prj_1", environment="live", provider="wechat",
                mid="mch_provider_1", endpoint="ep_1") -> B.Binding:
        return B.Binding(tenant_id=tenant, project_id=project, environment=environment,
                         provider=provider, provider_merchant_id=mid, endpoint_id=endpoint)

    def credential(self, secret=None, cid="cred_1") -> B.Credential:
        return B.Credential(id=cid, secret=secret or self.SECRET_A, issued_at=NOW - 86400,
                            rotates_after=90)

    def callback(self, secret=None, *, mid="mch_provider_1", event="evt_1", provider="wechat",
                 environment="live", sent_at=NOW, source="provider", amount=9900) -> B.Callback:
        payload = {"amount_minor": amount, "currency": "CNY", "event": event}
        return B.Callback(provider=provider, environment=environment, provider_event_id=event,
                          payload=payload, signature=B.sign(secret or self.SECRET_A, payload),
                          sent_at=sent_at,
                          attribution={"provider_merchant_id": mid, "endpoint_id": "ep_1"},
                          source=source)

    def live(self, registry=None, **overrides) -> tuple[B.Bindings, B.Binding]:
        registry = registry or self.registry()
        entry = registry.bind(self.binding(**overrides))
        registry.install(entry, self.credential())
        registry.activate(entry, test_transaction_settled=True,
                          callback_roundtrip_verified=True, actor="ops")
        return registry, entry

    def refused(self, fn, code):
        with self.assertRaises(B.BindingRefused) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    # -- attribution ------------------------------------------------------
    def test_a_normal_callback_is_attributed_and_delivered(self):
        registry, _ = self.live()
        self.assertEqual(registry.deliver(self.callback(), now=NOW), "DELIVERED")

    def test_a_provider_retry_does_not_book_the_money_twice(self):
        registry, _ = self.live()
        registry.deliver(self.callback(), now=NOW)
        self.assertEqual(registry.deliver(self.callback(), now=NOW), "DUPLICATE")

    def test_two_bindings_that_match_are_quarantined_not_guessed(self):
        registry = self.registry()
        left = registry.bind(self.binding(tenant="ten_1", mid="shared_mid"))
        right = registry.bind(self.binding(tenant="ten_2", mid="shared_mid"))
        registry.install(left, self.credential())
        registry.install(right, self.credential(self.SECRET_B, "cred_2"))
        for entry in (left, right):
            registry.activate(entry, test_transaction_settled=True,
                              callback_roundtrip_verified=True, actor="ops")
        self.refused(lambda: registry.deliver(self.callback(mid="shared_mid"), now=NOW),
                     B.ATTRIBUTION_AMBIGUOUS)
        # Neither merchant was credited, and the reason is on the record.
        self.assertEqual(registry.delivered, {})
        self.assertEqual(registry.quarantine[-1].reason, B.ATTRIBUTION_AMBIGUOUS)

    def test_an_unattributable_callback_is_quarantined(self):
        registry, _ = self.live()
        self.refused(lambda: registry.deliver(self.callback(mid="nobody"), now=NOW),
                     B.ATTRIBUTION_NONE)
        self.assertEqual(registry.quarantine[-1].reason, B.ATTRIBUTION_NONE)

    def test_a_callback_without_the_attribution_field_matches_nothing(self):
        registry, _ = self.live()
        blind = B.Callback(provider="wechat", environment="live", provider_event_id="evt_blind",
                           payload={}, signature="", sent_at=NOW, attribution={})
        self.assertEqual(registry.candidates(blind), [])

    def test_a_callback_for_an_unknown_provider_matches_nothing(self):
        registry, _ = self.live()
        self.assertEqual(registry.candidates(self.callback(provider="klarna")), [])

    def test_the_same_provider_id_in_another_environment_is_a_different_binding(self):
        registry, _ = self.live()
        self.refused(lambda: registry.deliver(self.callback(environment="test"), now=NOW),
                     B.ATTRIBUTION_NONE)

    def test_a_quarantined_callback_is_never_replayed_blind(self):
        registry, entry = self.live()
        self.refused(lambda: registry.deliver(self.callback(mid="nobody"), now=NOW),
                     B.ATTRIBUTION_NONE)
        held = registry.quarantine[-1]
        self.refused(lambda: registry.replay(held, binding=None, now=NOW), B.DENY_BLIND_REPLAY)
        self.assertEqual(registry.replay(held, binding=entry, now=NOW), "DELIVERED")
        self.assertEqual(registry.quarantine, [])

    def test_a_replayed_duplicate_is_still_a_duplicate(self):
        registry, entry = self.live()
        registry.deliver(self.callback(), now=NOW)
        self.refused(lambda: registry.deliver(self.callback(mid="nobody", event="evt_1"),
                                              now=NOW), B.ATTRIBUTION_NONE)
        self.assertEqual(registry.replay(registry.quarantine[-1], binding=entry, now=NOW),
                         "DUPLICATE")

    # -- signatures and freshness -----------------------------------------
    def test_a_bad_signature_is_refused(self):
        registry, _ = self.live()
        self.refused(lambda: registry.deliver(self.callback(b"wrong"), now=NOW),
                     B.SIGNATURE_INVALID)

    def test_another_tenants_credential_cannot_sign_this_binding(self):
        registry, _ = self.live()
        self.refused(lambda: registry.deliver(self.callback(self.SECRET_B), now=NOW),
                     B.SIGNATURE_INVALID)

    def test_a_stale_callback_is_refused(self):
        registry, _ = self.live()
        window = self.MODEL["callback"]["replay_window_seconds"]
        self.refused(lambda: registry.deliver(self.callback(sent_at=NOW - window - 1), now=NOW),
                     B.CALLBACK_STALE)

    def test_the_client_return_page_is_not_evidence(self):
        registry, _ = self.live()
        self.refused(lambda: registry.deliver(self.callback(source="client_return_page"),
                                              now=NOW), B.DENY_RETURN_PAGE)

    def test_a_callback_is_never_delivered_to_another_tenant(self):
        registry, _ = self.live()
        self.refused(lambda: registry.deliver(self.callback(), now=NOW, to_tenant="ten_2"),
                     B.DENY_CROSS_TENANT)

    # -- bindings ---------------------------------------------------------
    def test_a_binding_cannot_be_edited_in_place(self):
        registry, entry = self.live()
        for field in ("tenant_id", "project_id", "environment", "provider",
                      "provider_merchant_id"):
            self.refused(lambda f=field: registry.rebind(entry, **{f: "changed"}),
                         B.DENY_IMMUTABLE)

    def test_a_mutable_field_can_still_be_changed(self):
        registry, entry = self.live()
        self.assertEqual(registry.rebind(entry, endpoint_id="ep_2").endpoint_id, "ep_2")

    def test_one_tenant_cannot_hold_two_bindings_for_one_provider(self):
        registry, _ = self.live()
        self.refused(lambda: registry.bind(self.binding()), B.DENY_DUPLICATE_BINDING)

    def test_an_unknown_provider_or_environment_cannot_be_bound(self):
        registry = self.registry()
        self.refused(lambda: registry.bind(self.binding(provider="klarna")), B.DENY_UNKNOWN)
        self.refused(lambda: registry.bind(self.binding(environment="staging")), B.DENY_UNKNOWN)

    def test_a_binding_can_be_looked_up_by_its_key(self):
        registry, entry = self.live()
        self.assertIs(registry.get("ten_1", "prj_1", "live", "wechat"), entry)
        self.refused(lambda: registry.get("ten_9", "prj_1", "live", "wechat"), B.DENY_UNKNOWN)

    def test_one_credential_cannot_serve_two_bindings(self):
        registry, _ = self.live()
        other = registry.bind(self.binding(tenant="ten_2", mid="mch_provider_2"))
        self.refused(lambda: registry.install(other, self.credential(cid="cred_dup")),
                     B.DENY_SHARED_CREDENTIAL)

    # -- lifecycle --------------------------------------------------------
    def test_a_pending_binding_cannot_take_payments(self):
        registry = self.registry()
        entry = registry.bind(self.binding())
        self.assertFalse(registry.may(entry, "initiate_payment"))
        self.refused(lambda: registry.require(entry, "initiate_payment"), B.DENY_NOT_ALLOWED)

    def test_activation_needs_a_real_round_trip(self):
        registry = self.registry()
        entry = registry.bind(self.binding())
        registry.install(entry, self.credential())
        self.refused(lambda: registry.activate(entry, test_transaction_settled=True,
                                               callback_roundtrip_verified=False, actor="ops"),
                     B.DENY_REQUIREMENT)
        self.assertEqual(registry.activate(entry, test_transaction_settled=True,
                                           callback_roundtrip_verified=True,
                                           actor="ops").state, B.ACTIVE)

    def test_an_undeclared_transition_is_refused(self):
        registry, entry = self.live()
        self.refused(lambda: registry.transition(entry, B.PENDING, satisfied=set(),
                                                 actor="ops"), B.DENY_TRANSITION)

    def test_an_unknown_capability_is_refused(self):
        registry, entry = self.live()
        self.refused(lambda: registry.may(entry, "print_money"), B.DENY_UNKNOWN)

    def test_a_suspended_binding_still_receives_callbacks(self):
        registry, entry = self.live()
        registry.transition(entry, B.SUSPENDED, satisfied={"reason", "actor"}, actor="risk")
        self.refused(lambda: registry.require(entry, "initiate_payment"), B.DENY_NOT_ALLOWED)
        # The payer's money already left. Refusing the callback would only
        # destroy the platform's own proof that it arrived.
        self.assertEqual(registry.deliver(self.callback(), now=NOW), "DELIVERED")
        self.assertTrue(registry.may(entry, "issue_refund"))
        self.assertTrue(registry.may(entry, "settle"))

    def test_reinstating_needs_a_second_approver(self):
        registry, entry = self.live()
        registry.transition(entry, B.SUSPENDED, satisfied={"reason", "actor"}, actor="risk")
        self.refused(lambda: registry.transition(entry, B.ACTIVE,
                                                 satisfied={"reason", "actor"}, actor="ops"),
                     B.DENY_REQUIREMENT)
        self.assertEqual(registry.transition(
            entry, B.ACTIVE, satisfied={"reason", "actor", "second_approver"},
            actor="ops").state, B.ACTIVE)

    def test_revocation_settles_first_and_destroys_the_credential(self):
        registry, entry = self.live()
        self.refused(lambda: registry.transition(
            entry, B.REVOKED, satisfied={"credential_destroyed", "second_approver"},
            actor="ops"), B.DENY_REQUIREMENT)
        registry.transition(entry, B.REVOKED,
                            satisfied={"in_flight_settled", "credential_destroyed",
                                       "second_approver"}, actor="ops")
        self.assertIsNone(entry.credential)
        self.refused(lambda: registry.deliver(self.callback(), now=NOW),
                     B.DENY_CREDENTIAL_DESTROYED)

    # -- credentials ------------------------------------------------------
    def test_rotation_takes_two_people(self):
        registry, entry = self.live()
        self.refused(lambda: registry.rotate(entry, self.credential(b"new", "cred_new"),
                                             now=NOW, actor="ops", approver="ops"),
                     B.DENY_SELF_APPROVAL)

    def test_the_overlap_window_keeps_the_callbacks_in_flight(self):
        registry, entry = self.live()
        registry.rotate(entry, self.credential(b"new", "cred_new"), now=NOW, actor="ops",
                        approver="sec")
        self.assertEqual(registry.deliver(self.callback(b"new", event="evt_new"), now=NOW),
                         "DELIVERED")
        self.assertEqual(registry.deliver(self.callback(event="evt_old"), now=NOW), "DELIVERED")

    def test_the_old_credential_dies_when_the_overlap_ends(self):
        registry, entry = self.live()
        registry.rotate(entry, self.credential(b"new", "cred_new"), now=NOW, actor="ops",
                        approver="sec")
        after = NOW + self.MODEL["credentials"]["rotation_overlap_days"] * 86400 + 1
        self.refused(lambda: registry.deliver(self.callback(event="evt_late", sent_at=after),
                                              now=after), B.SIGNATURE_INVALID)

    def test_a_decrypted_credential_expires(self):
        registry, entry = self.live()
        secret, expires = registry.lease(entry, now=NOW)
        self.assertEqual(secret, self.SECRET_A)
        self.assertEqual(expires - NOW, self.MODEL["credentials"]["max_decrypt_lease_seconds"])
        self.assertEqual(registry.use_lease(expires, now=NOW), "OK")
        self.refused(lambda: registry.use_lease(expires, now=expires), B.DENY_LEASE_EXPIRED)

    def test_a_revoked_binding_has_nothing_left_to_lease(self):
        registry, entry = self.live()
        registry.transition(entry, B.REVOKED,
                            satisfied={"in_flight_settled", "credential_destroyed",
                                       "second_approver"}, actor="ops")
        self.refused(lambda: registry.lease(entry, now=NOW), B.DENY_CREDENTIAL_DESTROYED)
