"""B17 / AT-B17-01 — customer, administrator and service identity.

B16 said every access needs an authenticated identity. These tests are about
what an identity *is*, and they are organised around theft rather than around
features:

* ``test_a_stolen_token_is_useless_without_the_holder_key`` presents a perfectly
  valid token with someone else's key. That single test is the reason token
  binding exists; without it, every log line and every crash report is a
  credential.
* ``test_alg_none_is_rejected_before_anything_else`` checks the decision *order*,
  not just the outcome — the classic bypass is letting the token choose how it
  is verified.
* ``ID_RECOVERY_SMS`` and ``ID_RECOVERY_DOWNGRADE`` exist because account
  recovery is designed to work when the real owner has lost everything, which is
  exactly the attacker's situation. A recovery path weaker than the primary
  factor *is* the account's security level.
"""
from __future__ import annotations

from tools.paygov import identity, idgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class IdentityHappyPath(FixtureTestCase):
    def test_real_identity_model_passes(self):
        problems = identity.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("identity", registry.names())

    def test_unbound_bearer_tokens_are_forbidden(self):
        model = self.fixture.read("governance/identity.json")
        self.assertIs(model["bearer_tokens_allowed"], False)
        self.assertIs(model["session_binding"]["required"], True)
        for token in model["tokens"]:
            self.assertIn(token["binding"], model["binding_methods"], token["id"])

    def test_no_provider_accepts_none_or_symmetric_algorithms(self):
        model = self.fixture.read("governance/identity.json")
        forbidden = set(model["forbidden_algorithms"])
        self.assertIn("none", forbidden)
        for provider in model["providers"]:
            self.assertFalse(set(provider["algorithms"]) & forbidden, provider["id"])

    def test_only_authorization_code_with_pkce_is_allowed(self):
        model = self.fixture.read("governance/identity.json")
        oauth = model["oauth"]
        self.assertEqual(oauth["allowed_flows"], ["authorization_code"])
        self.assertIn("implicit", oauth["forbidden_flows"])
        self.assertIn("resource_owner_password", oauth["forbidden_flows"])
        self.assertIs(oauth["pkce_required"], True)
        self.assertEqual(oauth["pkce_method"], "S256")

    def test_machine_oauth_is_mtls_bound_client_credentials_without_static_secret(self):
        model = self.fixture.read("governance/identity.json")
        machine = model["machine_oauth"]
        self.assertEqual(machine["allowed_flows"], ["client_credentials"])
        self.assertIs(machine["static_client_secret_allowed"], False)
        self.assertEqual(machine["client_authentication"], "mtls")
        self.assertEqual(machine["access_token_binding"], "mtls")
        self.assertLessEqual(machine["maximum_token_minutes"], 5)
        binding = next(item for item in model["principal_bindings"]
                       if item["principal"] == "merchant-api-client")
        self.assertEqual(binding["provider"], "merchant-authorization-server")
        self.assertEqual(binding["token"], "merchant-api-access")

    def test_redirect_uris_match_exactly(self):
        model = self.fixture.read("governance/identity.json")
        self.assertEqual(model["oauth"]["redirect_uri_matching"], "exact")

    def test_every_token_expires_and_can_be_revoked(self):
        model = self.fixture.read("governance/identity.json")
        self.assertGreaterEqual(len(model["tokens"]), 5)
        for token in model["tokens"]:
            self.assertGreater(token["lifetime_minutes"], 0, token["id"])
            self.assertLessEqual(token["lifetime_minutes"],
                                 identity.MAX_ACCESS_TOKEN_MINUTES, token["id"])
            self.assertIs(token["revocable"], True, token["id"])

    def test_revocation_is_checked_on_every_request(self):
        model = self.fixture.read("governance/identity.json")
        revocation = model["revocation"]
        self.assertIs(revocation["check_on_every_request"], True)
        self.assertLessEqual(revocation["propagation_seconds"], 300)

    def test_every_token_audience_belongs_to_its_provider(self):
        model = self.fixture.read("governance/identity.json")
        providers = {p["id"]: p for p in model["providers"]}
        for token in model["tokens"]:
            self.assertIn(token["audience"], providers[token["provider"]]["audiences"],
                          token["id"])

    def test_every_zero_trust_principal_has_an_identity(self):
        model = self.fixture.read("governance/identity.json")
        zt = self.fixture.read("governance/zero-trust.json")
        bound = {b["principal"] for b in model["principal_bindings"]}
        self.assertEqual(bound, {p["id"] for p in zt["principals"]})

    def test_human_tokens_do_not_outlive_the_zero_trust_session(self):
        model = self.fixture.read("governance/identity.json")
        zt = self.fixture.read("governance/zero-trust.json")
        limit = zt["session"]["max_human_session_minutes"]
        kinds = {p["id"]: p["kind"] for p in zt["principals"]}
        tokens = {t["id"]: t for t in model["tokens"]}
        for binding in model["principal_bindings"]:
            if kinds[binding["principal"]] == "human":
                self.assertLessEqual(tokens[binding["token"]]["lifetime_minutes"], limit,
                                     binding["principal"])

    def test_no_recovery_path_is_sms_only_or_a_downgrade(self):
        model = self.fixture.read("governance/identity.json")
        self.assertGreaterEqual(len(model["recovery"]), 3)
        for entry in model["recovery"]:
            self.assertIs(entry["sms_only_allowed"], False, entry["subject"])
            self.assertIs(entry["requires_same_or_stronger_factor"], True, entry["subject"])
            self.assertTrue(entry["notify_channels"], entry["subject"])

    def test_high_privilege_recovery_has_a_cooling_off_period(self):
        model = self.fixture.read("governance/identity.json")
        for entry in model["recovery"]:
            if entry["subject"] in identity.HIGH_PRIVILEGE_SUBJECTS:
                self.assertGreaterEqual(entry["delay_hours"], 24, entry["subject"])

    def test_no_service_account_may_hold_a_static_secret(self):
        model = self.fixture.read("governance/identity.json")
        self.assertIs(model["service_accounts"]["static_secrets_allowed"], False)
        self.assertEqual(model["service_accounts"]["issuance"], "workload_identity_only")

    def test_generated_artefacts_match_the_model(self):
        for rel, content in idgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)


class IdentityGateRejects(FixtureTestCase):
    REL = "governance/identity.json"

    def _validate(self):
        return identity.validate(self.fixture.root, Budget(seconds=60).start())

    def _provider(self, d, pid):
        return next(p for p in d["providers"] if p["id"] == pid)

    def _token(self, d, tid):
        return next(t for t in d["tokens"] if t["id"] == tid)

    def _recovery(self, d, subject):
        return next(r for r in d["recovery"] if r["subject"] == subject)

    def test_rejects_unreadable_model(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("ID_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("ID_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_dropping_the_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("ID_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_allowing_bearer_tokens(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("bearer_tokens_allowed", True))
        problems = self._validate()
        self.assertIn("ID_BEARER_TOKEN", self.codes(problems))
        self.assertIn("NN-07", self.rules(problems))

    def test_rejects_removing_none_from_the_forbidden_algorithms(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "forbidden_algorithms", ["HS256"]))
        self.assertIn("ID_FORBIDDEN_ALGORITHM", self.codes(self._validate()))

    def test_rejects_allowing_symmetric_signing(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("forbidden_algorithms", ["none"]))
        self.assertIn("ID_FORBIDDEN_ALGORITHM", self.codes(self._validate()))

    def test_rejects_a_provider_accepting_a_forbidden_algorithm(self):
        self.fixture.mutate(self.REL, lambda d: self._provider(d, "customer-idp")["algorithms"]
                            .append("HS256"))
        self.assertIn("ID_FORBIDDEN_ALGORITHM", self.codes(self._validate()))

    def test_rejects_the_implicit_flow(self):
        self.fixture.mutate(self.REL, lambda d: d["oauth"].__setitem__(
            "allowed_flows", ["authorization_code", "implicit"]))
        self.assertIn("ID_FLOW", self.codes(self._validate()))

    def test_rejects_unforbidding_the_password_flow(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["oauth"].__setitem__("forbidden_flows", []))
        self.assertIn("ID_FORBIDDEN_FLOW", self.codes(self._validate()))

    def test_rejects_dropping_pkce(self):
        self.fixture.mutate(self.REL, lambda d: d["oauth"].__setitem__("pkce_required", False))
        self.assertIn("ID_PKCE", self.codes(self._validate()))

    def test_rejects_plain_pkce(self):
        self.fixture.mutate(self.REL, lambda d: d["oauth"].__setitem__("pkce_method", "plain"))
        self.assertIn("ID_PKCE", self.codes(self._validate()))

    def test_rejects_prefix_matching_redirect_uris(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["oauth"].__setitem__("redirect_uri_matching", "prefix"))
        problems = self._validate()
        self.assertIn("ID_REDIRECT_MATCH", self.codes(problems))
        self.assertIn("NN-10", self.rules(problems))

    def test_rejects_dropping_state_or_nonce(self):
        self.fixture.mutate(self.REL, lambda d: d["oauth"].__setitem__("state_required", False))
        self.assertIn("ID_CSRF", self.codes(self._validate()))

    def test_rejects_slow_revocation(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["revocation"].__setitem__("propagation_seconds", 86400))
        self.assertIn("ID_REVOCATION_DEADLINE", self.codes(self._validate()))

    def test_rejects_checking_revocation_only_at_login(self):
        self.fixture.mutate(self.REL, lambda d: d["revocation"].__setitem__(
            "check_on_every_request", False))
        self.assertIn("ID_REVOCATION_CHECK", self.codes(self._validate()))

    def test_rejects_an_unnamed_revocation_mechanism(self):
        self.fixture.mutate(self.REL, lambda d: d["revocation"].__setitem__("mechanism", ""))
        self.assertIn("ID_REVOCATION_DEADLINE", self.codes(self._validate()))

    def test_rejects_making_binding_optional(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["session_binding"].__setitem__("required", False))
        self.assertIn("ID_BINDING_REQUIRED", self.codes(self._validate()))

    def test_rejects_an_invented_binding_method(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["session_binding"].__setitem__("methods", ["cookie"]))
        self.assertIn("ID_BINDING_METHOD", self.codes(self._validate()))

    def test_rejects_machine_oauth_static_client_secret(self):
        self.fixture.mutate(self.REL, lambda d: d["machine_oauth"].__setitem__(
            "static_client_secret_allowed", True))
        self.assertIn("ID_MACHINE_STATIC_SECRET", self.codes(self._validate()))

    def test_rejects_a_machine_password_flow(self):
        self.fixture.mutate(self.REL, lambda d: d["machine_oauth"].__setitem__(
            "allowed_flows", ["password"]))
        self.assertIn("ID_MACHINE_FLOW", self.codes(self._validate()))

    def test_rejects_unbound_machine_oauth_tokens(self):
        self.fixture.mutate(self.REL, lambda d: d["machine_oauth"].__setitem__(
            "access_token_binding", "bearer"))
        self.assertIn("ID_MACHINE_BINDING", self.codes(self._validate()))

    def test_rejects_long_lived_machine_oauth_tokens(self):
        self.fixture.mutate(self.REL, lambda d: d["machine_oauth"].__setitem__(
            "maximum_token_minutes", 60))
        self.assertIn("ID_MACHINE_LIFETIME", self.codes(self._validate()))

    def test_rejects_static_service_account_secrets(self):
        self.fixture.mutate(self.REL, lambda d: d["service_accounts"].__setitem__(
            "static_secrets_allowed", True))
        problems = self._validate()
        self.assertIn("ID_STATIC_SERVICE_ACCOUNT", self.codes(problems))
        self.assertIn("NN-07", self.rules(problems))

    def test_rejects_issuing_service_credentials_some_other_way(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["service_accounts"].__setitem__("issuance", "manual"))
        self.assertIn("ID_STATIC_SERVICE_ACCOUNT", self.codes(self._validate()))

    def test_rejects_an_empty_provider_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("providers", []))
        self.assertIn("ID_SHAPE", self.codes(self._validate()))

    def test_rejects_a_provider_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["providers"].append("customer-idp"))
        self.assertIn("ID_SHAPE", self.codes(self._validate()))

    def test_rejects_a_bad_provider_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._provider(d, "customer-idp").__setitem__("id", "IDP"))
        self.assertIn("ID_PROVIDER_ID", self.codes(self._validate()))

    def test_rejects_a_duplicate_provider(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["providers"].append(dict(self._provider(d, "ci-oidc"))))
        self.assertIn("ID_PROVIDER_DUPLICATE", self.codes(self._validate()))

    def test_rejects_a_plaintext_issuer(self):
        self.fixture.mutate(self.REL, lambda d: self._provider(d, "customer-idp").__setitem__(
            "issuer", "http://idp.example.invalid"))
        self.assertIn("ID_ISSUER", self.codes(self._validate()))

    def test_rejects_a_provider_with_no_audience(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._provider(d, "ci-oidc").__setitem__("audiences", []))
        self.assertIn("ID_AUDIENCE", self.codes(self._validate()))

    def test_rejects_a_provider_with_no_algorithms(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._provider(d, "ci-oidc").__setitem__("algorithms", []))
        self.assertIn("ID_ALGORITHM", self.codes(self._validate()))

    def test_rejects_keys_that_never_rotate(self):
        self.fixture.mutate(self.REL, lambda d: self._provider(
            d, "customer-idp").__setitem__("jwks_rotation_days", 3650))
        self.assertIn("ID_KEY_ROTATION", self.codes(self._validate()))

    def test_rejects_a_provider_issuing_day_long_tokens(self):
        self.fixture.mutate(self.REL, lambda d: self._provider(
            d, "customer-idp").__setitem__("max_token_minutes", 1440))
        self.assertIn("ID_TOKEN_LIFETIME", self.codes(self._validate()))

    def test_rejects_an_unbounded_clock_skew(self):
        self.fixture.mutate(self.REL, lambda d: self._provider(
            d, "customer-idp").__setitem__("clock_skew_seconds", 86400))
        self.assertIn("ID_CLOCK_SKEW", self.codes(self._validate()))

    def test_rejects_a_provider_with_no_explanation(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._provider(d, "ci-oidc").__setitem__("notes", ""))
        self.assertIn("ID_PROVIDER_NOTES", self.codes(self._validate()))

    def test_rejects_an_empty_token_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("tokens", []))
        self.assertIn("ID_SHAPE", self.codes(self._validate()))

    def test_rejects_a_token_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["tokens"].append("payer-session"))
        self.assertIn("ID_SHAPE", self.codes(self._validate()))

    def test_rejects_a_bad_token_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._token(d, "payer-session").__setitem__("id", "Payer"))
        self.assertIn("ID_TOKEN_ID", self.codes(self._validate()))

    def test_rejects_a_duplicate_token(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["tokens"].append(dict(self._token(d, "payer-session"))))
        self.assertIn("ID_TOKEN_DUPLICATE", self.codes(self._validate()))

    def test_rejects_an_unknown_token_kind(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._token(d, "payer-session").__setitem__("kind", "magic"))
        self.assertIn("ID_TOKEN_KIND", self.codes(self._validate()))

    def test_rejects_a_token_from_an_unknown_provider(self):
        self.fixture.mutate(self.REL, lambda d: self._token(d, "payer-session").__setitem__(
            "provider", "some-idp"))
        self.assertIn("ID_TOKEN_PROVIDER", self.codes(self._validate()))

    def test_rejects_a_token_whose_audience_its_provider_never_issues(self):
        self.fixture.mutate(self.REL, lambda d: self._token(d, "payer-session").__setitem__(
            "audience", "admin-web"))
        self.assertIn("ID_AUDIENCE", self.codes(self._validate()))

    def test_rejects_a_token_outliving_its_provider_maximum(self):
        self.fixture.mutate(self.REL, lambda d: self._token(d, "payer-session").__setitem__(
            "lifetime_minutes", 59))
        self.assertIn("ID_TOKEN_LIFETIME", self.codes(self._validate()))

    def test_rejects_an_unbound_token(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._token(d, "payer-session").__setitem__("binding", ""))
        self.assertIn("ID_BEARER_TOKEN", self.codes(self._validate()))

    def test_rejects_an_irrevocable_token(self):
        self.fixture.mutate(self.REL, lambda d: self._token(
            d, "payer-session").__setitem__("revocable", False))
        self.assertIn("ID_TOKEN_REVOCABLE", self.codes(self._validate()))

    def test_rejects_a_token_with_no_explanation(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._token(d, "payer-session").__setitem__("notes", ""))
        self.assertIn("ID_TOKEN_NOTES", self.codes(self._validate()))

    def test_rejects_an_empty_recovery_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("recovery", []))
        self.assertIn("ID_SHAPE", self.codes(self._validate()))

    def test_rejects_a_recovery_entry_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["recovery"].append("customer"))
        self.assertIn("ID_SHAPE", self.codes(self._validate()))

    def test_rejects_a_duplicate_recovery_subject(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["recovery"].append(dict(self._recovery(d, "customer"))))
        self.assertIn("ID_RECOVERY_SUBJECT", self.codes(self._validate()))

    def test_rejects_a_recovery_path_with_no_method(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._recovery(d, "customer").__setitem__("methods", []))
        self.assertIn("ID_RECOVERY_METHOD", self.codes(self._validate()))

    def test_rejects_recovery_that_accepts_a_weaker_factor(self):
        """A recovery weaker than the primary factor is the real security level."""
        self.fixture.mutate(self.REL, lambda d: self._recovery(
            d, "platform-operator").__setitem__("requires_same_or_stronger_factor", False))
        problems = self._validate()
        self.assertIn("ID_RECOVERY_DOWNGRADE", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_sms_only_recovery(self):
        """SIM swap turns a phone number into an account takeover."""
        self.fixture.mutate(self.REL, lambda d: self._recovery(
            d, "platform-operator").__setitem__("sms_only_allowed", True))
        self.assertIn("ID_RECOVERY_SMS", self.codes(self._validate()))

    def test_rejects_silent_recovery(self):
        self.fixture.mutate(self.REL, lambda d: self._recovery(
            d, "customer").__setitem__("notify_channels", []))
        self.assertIn("ID_RECOVERY_NOTIFY", self.codes(self._validate()))

    def test_rejects_instant_recovery_of_a_high_privilege_account(self):
        self.fixture.mutate(self.REL, lambda d: self._recovery(
            d, "platform-operator").__setitem__("delay_hours", 0))
        self.assertIn("ID_RECOVERY_DELAY", self.codes(self._validate()))

    def test_rejects_a_recovery_path_with_no_rationale(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._recovery(d, "customer").__setitem__("notes", ""))
        self.assertIn("ID_RECOVERY_NOTES", self.codes(self._validate()))

    def test_rejects_leaving_the_highest_privilege_account_without_recovery(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "recovery", [r for r in d["recovery"] if r["subject"] != "platform-operator"]))
        self.assertIn("ID_RECOVERY_UNCOVERED", self.codes(self._validate()))

    def test_rejects_a_zero_trust_principal_with_no_identity(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "principal_bindings",
            [b for b in d["principal_bindings"] if b["principal"] != "payer"]))
        problems = self._validate()
        self.assertIn("ID_PRINCIPAL_UNBACKED", self.codes(problems))
        self.assertIn("NN-07", self.rules(problems))

    def test_rejects_a_binding_to_an_unknown_provider(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["principal_bindings"][0].__setitem__("provider", "nope"))
        self.assertIn("ID_PRINCIPAL_PROVIDER", self.codes(self._validate()))

    def test_rejects_a_binding_to_an_unknown_token(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["principal_bindings"][0].__setitem__("token", "nope"))
        self.assertIn("ID_PRINCIPAL_TOKEN", self.codes(self._validate()))

    def test_rejects_binding_merchant_api_to_the_internal_workload_ca(self):
        def mutate(document):
            binding = next(item for item in document["principal_bindings"]
                           if item["principal"] == "merchant-api-client")
            binding["provider"] = "workload-ca"
            binding["token"] = "workload-cert"
        self.fixture.mutate(self.REL, mutate)
        self.assertIn("ID_MERCHANT_API_BINDING", self.codes(self._validate()))

    def test_rejects_binding_a_principal_nobody_declared(self):
        self.fixture.mutate(self.REL, lambda d: d["principal_bindings"].append(
            {"principal": "ghost", "provider": "ci-oidc", "token": "ci-cloud-token"}))
        self.assertIn("ID_PRINCIPAL_UNKNOWN", self.codes(self._validate()))

    def test_rejects_a_human_token_outliving_the_zero_trust_session(self):
        def widen(d):
            self._provider(d, "corporate-idp")["max_token_minutes"] = 60
            self._token(d, "operator-session")["lifetime_minutes"] = 60
        self.fixture.mutate(self.REL, widen)
        self.fixture.mutate("governance/zero-trust.json",
                            lambda d: d["session"].__setitem__("max_human_session_minutes", 30))
        self.assertIn("ID_LIFETIME_EXCEEDS_SESSION", self.codes(self._validate()))

    def test_rejects_missing_generated_artefacts(self):
        self.fixture.remove("contracts/security/identity.json")
        self.assertIn("ID_GENERATED_MISSING", self.codes(self._validate()))

    def test_rejects_a_hand_edited_generated_artefact(self):
        path = self.fixture.root / "docs/security/IDENTITY.md"
        path.write_text(path.read_text(encoding="utf-8").replace(
            "authorization_code", "implicit"), encoding="utf-8")
        self.assertIn("ID_GENERATED_DRIFT", self.codes(self._validate()))

    def test_fails_closed_when_the_contract_cannot_be_generated(self):
        """A gate must turn a broken model into a finding, not into a crash."""
        self.fixture.mutate(self.REL,
                            lambda d: self._provider(d, "ci-oidc").pop("clock_skew_seconds"))
        self.assertIn("ID_GENERATED", self.codes(self._validate()))


class TokenVerifierReference(FixtureTestCase):
    """A token policy is a list of promises; this is the code that keeps them."""

    NOW = 1_000_000

    def setUp(self):
        super().setUp()
        from libs.identity.reference import tokens
        self.tk = tokens
        self.model = self.fixture.read("governance/identity.json")
        self.providers = {p["id"]: p for p in self.model["providers"]}

    def _verifier(self, spec):
        verifier = self.tk.Verifier.for_provider(self.providers[spec["provider"]], self.model)
        verifier.audiences = frozenset({spec["audience"]})
        return verifier

    def _token(self, spec, **overrides):
        provider = self.providers[spec["provider"]]
        kwargs = {"issuer": provider["issuer"], "audience": spec["audience"],
                  "subject": "s1", "algorithm": provider["algorithms"][0],
                  "issued_at": self.NOW - 60,
                  "expires_at": self.NOW + spec["lifetime_minutes"] * 60,
                  "binding": spec["binding"], "holder_key": "key-a",
                  "token_id": spec["id"]}
        kwargs.update(overrides)
        return self.tk.Token(**kwargs)

    def _reject_code(self, spec, token, key="key-a"):
        with self.assertRaises(self.tk.TokenRejected) as raised:
            self._verifier(spec).verify(token, now=self.NOW, presented_key=key)
        return raised.exception.code

    def test_every_declared_token_verifies_on_its_happy_path(self):
        for spec in self.model["tokens"]:
            token = self._verifier(spec).verify(self._token(spec), now=self.NOW,
                                                presented_key="key-a")
            self.assertEqual(token.subject, "s1", spec["id"])

    def test_alg_none_is_rejected_before_anything_else(self):
        """Checked first on purpose: the classic bypass is letting the token choose."""
        for spec in self.model["tokens"]:
            broken = self._token(spec, algorithm="none", signature_valid=False,
                                 audience="wrong", expires_at=0)
            self.assertEqual(self._reject_code(spec, broken), "FORBIDDEN_ALGORITHM", spec["id"])

    def test_symmetric_algorithms_are_rejected(self):
        for spec in self.model["tokens"]:
            self.assertEqual(self._reject_code(spec, self._token(spec, algorithm="HS256")),
                             "FORBIDDEN_ALGORITHM", spec["id"])

    def test_a_token_for_another_audience_is_rejected(self):
        for spec in self.model["tokens"]:
            other = "someone-elses-audience"
            self.assertEqual(self._reject_code(spec, self._token(spec, audience=other)),
                             "WRONG_AUDIENCE", spec["id"])

    def test_a_token_from_another_issuer_is_rejected(self):
        for spec in self.model["tokens"]:
            self.assertEqual(
                self._reject_code(spec, self._token(spec, issuer="https://evil.invalid")),
                "WRONG_ISSUER", spec["id"])

    def test_an_expired_token_is_rejected_outside_the_skew(self):
        for spec in self.model["tokens"]:
            skew = self.providers[spec["provider"]]["clock_skew_seconds"]
            self.assertEqual(
                self._reject_code(spec, self._token(spec, expires_at=self.NOW - skew - 1)),
                "EXPIRED", spec["id"])

    def test_a_token_just_inside_the_skew_is_still_accepted(self):
        for spec in self.model["tokens"]:
            skew = self.providers[spec["provider"]]["clock_skew_seconds"]
            token = self._token(spec, expires_at=self.NOW - skew + 1)
            self._verifier(spec).verify(token, now=self.NOW, presented_key="key-a")

    def test_an_unbound_token_is_rejected(self):
        for spec in self.model["tokens"]:
            self.assertEqual(
                self._reject_code(spec, self._token(spec, binding="", holder_key="")),
                "UNBOUND_TOKEN", spec["id"])

    def test_a_stolen_token_is_useless_without_the_holder_key(self):
        """The reason token binding exists, stated as a test."""
        for spec in self.model["tokens"]:
            self.assertEqual(self._reject_code(spec, self._token(spec), key="key-stolen"),
                             "WRONG_HOLDER", spec["id"])

    def test_a_bad_signature_is_rejected(self):
        for spec in self.model["tokens"]:
            self.assertEqual(
                self._reject_code(spec, self._token(spec, signature_valid=False)),
                "BAD_SIGNATURE", spec["id"])

    def test_a_token_issued_in_the_future_is_rejected(self):
        for spec in self.model["tokens"]:
            skew = self.providers[spec["provider"]]["clock_skew_seconds"]
            self.assertEqual(
                self._reject_code(spec, self._token(spec, issued_at=self.NOW + skew + 10)),
                "NOT_YET_VALID", spec["id"])

    def test_revocation_takes_effect_on_the_next_verification(self):
        for spec in self.model["tokens"]:
            verifier = self._verifier(spec)
            token = self._token(spec)
            verifier.verify(token, now=self.NOW, presented_key="key-a")
            verifier.revoke(spec["id"])
            with self.assertRaises(self.tk.TokenRejected) as raised:
                verifier.verify(token, now=self.NOW, presented_key="key-a")
            self.assertEqual(raised.exception.code, "REVOKED", spec["id"])
