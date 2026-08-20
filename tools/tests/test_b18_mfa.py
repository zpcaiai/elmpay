"""B18 / AT-B18-01 — phishing-resistant MFA and WebAuthn.

B16 named a factor called ``phishing_resistant_mfa``; B17 said its real strength
was this batch's problem. Here it is, and the whole thing rests on one property:
**the authenticator signs over the origin it saw**.

``test_a_phishing_origin_is_rejected`` is the test that matters. A phishing site
can copy the page pixel for pixel, relay a genuine challenge, and convince the
user of anything — and still cannot produce an assertion whose origin says ours.
That is why a six-digit code can never be classified the same way: a person can
be talked into reading digits to a stranger, but cannot be talked into changing
what the browser told the security key.

``MFA_MISCLASSIFIED`` guards the one edit that would make every other rule here
decorative: marking SMS or TOTP as phishing resistant.
"""
from __future__ import annotations

from tools.paygov import mfa, mfagen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class MfaPolicyHappyPath(FixtureTestCase):
    def test_real_policy_passes(self):
        problems = mfa.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("mfa", registry.names())

    def test_only_webauthn_is_classified_phishing_resistant(self):
        policy = self.fixture.read("governance/mfa.json")
        self.assertEqual(set(policy["phishing_resistant_classes"]), {"webauthn"})
        for entry in policy["authenticators"]:
            if entry["kind"] in mfa.RELAYABLE_KINDS:
                self.assertFalse(entry["phishing_resistant"], entry["id"])
                self.assertFalse(entry["origin_bound"], entry["id"])
                self.assertFalse(entry["allowed_as_sole_factor"], entry["id"])
            if entry["kind"] == "webauthn":
                self.assertTrue(entry["phishing_resistant"], entry["id"])
                self.assertTrue(entry["origin_bound"], entry["id"])

    def test_webauthn_parameters_are_strict(self):
        policy = self.fixture.read("governance/mfa.json")
        web = policy["webauthn"]
        self.assertEqual(web["user_verification"], "required")
        self.assertTrue(web["challenge_single_use"])
        self.assertTrue(web["sign_count_regression_is_clone"])
        self.assertGreaterEqual(web["challenge_bytes"], 16)
        self.assertLessEqual(web["challenge_ttl_seconds"], 300)
        self.assertNotEqual(web["attestation"], "none")
        for origin in web["allowed_origins"]:
            self.assertTrue(origin.startswith("https://"), origin)

    def test_step_up_is_bound_to_the_operation(self):
        policy = self.fixture.read("governance/mfa.json")
        step_up = policy["step_up"]
        self.assertTrue(step_up["required_for_high_risk"])
        self.assertTrue(step_up["transaction_binding"])
        self.assertLessEqual(step_up["max_age_seconds"], 900)

    def test_no_fallback_may_downgrade_the_factor(self):
        policy = self.fixture.read("governance/mfa.json")
        self.assertIs(policy["fallback"]["downgrade_allowed"], False)

    def test_privileged_roles_only_accept_phishing_resistant_authenticators(self):
        policy = self.fixture.read("governance/mfa.json")
        by_id = {a["id"]: a for a in policy["authenticators"]}
        covered = 0
        for entry in policy["requirements"]:
            if entry["role"] not in mfa.PRIVILEGED_ROLES:
                continue
            covered += 1
            self.assertEqual(entry["required_class"], "phishing_resistant", entry["role"])
            for aid in entry["allowed_authenticators"]:
                self.assertTrue(by_id[aid]["phishing_resistant"], f"{entry['role']}:{aid}")
            self.assertGreaterEqual(entry["minimum_registered_authenticators"], 2, entry["role"])
            self.assertTrue(entry["step_up_actions"], entry["role"])
        self.assertEqual(covered, len(mfa.PRIVILEGED_ROLES))

    def test_break_glass_requires_a_roaming_key(self):
        """A platform authenticator dies with the device it lives on."""
        policy = self.fixture.read("governance/mfa.json")
        entry = next(r for r in policy["requirements"] if r["role"] == "break-glass")
        self.assertEqual(entry["allowed_authenticators"], ["webauthn-roaming"])
        self.assertIn("webauthn-platform", entry["forbidden_authenticators"])

    def test_sms_is_forbidden_everywhere_it_matters(self):
        policy = self.fixture.read("governance/mfa.json")
        for entry in policy["requirements"]:
            if entry["role"] in mfa.PRIVILEGED_ROLES:
                self.assertNotIn("sms-otp", entry["allowed_authenticators"], entry["role"])

    def test_privileged_recovery_paths_cannot_bypass_this_policy(self):
        identity = self.fixture.read("governance/identity.json")
        for entry in identity["recovery"]:
            if entry["subject"] in mfa.PRIVILEGED_ROLES:
                self.assertIs(entry["sms_only_allowed"], False, entry["subject"])
                self.assertIs(entry["requires_same_or_stronger_factor"], True, entry["subject"])

    def test_enrolment_requires_two_authenticators_and_notifies(self):
        policy = self.fixture.read("governance/mfa.json")
        enrolment = policy["enrolment"]
        self.assertGreaterEqual(enrolment["minimum_authenticators_for_privileged"], 2)
        self.assertTrue(enrolment["verified_before_activation"])
        self.assertTrue(enrolment["notify_on_registration"])

    def test_attempts_are_rate_limited_and_push_fatigue_is_addressed(self):
        policy = self.fixture.read("governance/mfa.json")
        limits = policy["rate_limiting"]
        self.assertLessEqual(limits["max_attempts_per_hour"], 60)
        self.assertGreater(limits["lockout_seconds"], 0)
        self.assertTrue(limits["push_fatigue_protection"])

    def test_generated_artefacts_match_the_policy(self):
        for rel, content in mfagen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)


class MfaGateRejects(FixtureTestCase):
    REL = "governance/mfa.json"

    def _validate(self):
        return mfa.validate(self.fixture.root, Budget(seconds=60).start())

    def _auth(self, d, aid):
        return next(a for a in d["authenticators"] if a["id"] == aid)

    def _role(self, d, role):
        return next(r for r in d["requirements"] if r["role"] == role)

    def test_rejects_unreadable_policy(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("MFA_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("MFA_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_dropping_the_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("MFA_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_calling_otp_phishing_resistant(self):
        """The one edit that would make every other rule here decorative."""
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "phishing_resistant_classes", ["webauthn", "otp"]))
        problems = self._validate()
        self.assertIn("MFA_RESISTANT_CLASS", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_marking_sms_as_phishing_resistant(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._auth(d, "sms-otp").__setitem__(
                                "phishing_resistant", True))
        self.assertIn("MFA_MISCLASSIFIED", self.codes(self._validate()))

    def test_rejects_claiming_an_otp_is_origin_bound(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._auth(d, "totp").__setitem__("origin_bound", True))
        self.assertIn("MFA_MISCLASSIFIED", self.codes(self._validate()))

    def test_rejects_letting_an_otp_stand_alone(self):
        self.fixture.mutate(self.REL, lambda d: self._auth(d, "totp").__setitem__(
            "allowed_as_sole_factor", True))
        self.assertIn("MFA_SOLE_FACTOR", self.codes(self._validate()))

    def test_rejects_a_webauthn_authenticator_that_is_not_origin_bound(self):
        self.fixture.mutate(self.REL, lambda d: self._auth(
            d, "webauthn-roaming").__setitem__("origin_bound", False))
        self.assertIn("MFA_ORIGIN_BINDING", self.codes(self._validate()))

    def test_rejects_an_undeclared_phishing_classification(self):
        self.fixture.mutate(self.REL, lambda d: self._auth(
            d, "webauthn-roaming").__setitem__("phishing_resistant", "yes"))
        self.assertIn("MFA_AUTH_CLASSIFICATION", self.codes(self._validate()))

    def test_rejects_dropping_the_relying_party_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["webauthn"].__setitem__("relying_party_id", ""))
        self.assertIn("MFA_RP_ID", self.codes(self._validate()))

    def test_rejects_removing_the_allowed_origins(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["webauthn"].__setitem__("allowed_origins", []))
        self.assertIn("MFA_ORIGIN", self.codes(self._validate()))

    def test_rejects_a_plaintext_origin(self):
        self.fixture.mutate(self.REL, lambda d: d["webauthn"]["allowed_origins"]
                            .append("http://pay.example.invalid"))
        self.assertIn("MFA_ORIGIN", self.codes(self._validate()))

    def test_rejects_making_user_verification_optional(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["webauthn"].__setitem__("user_verification",
                                                                "discouraged"))
        self.assertIn("MFA_USER_VERIFICATION", self.codes(self._validate()))

    def test_rejects_a_short_challenge(self):
        self.fixture.mutate(self.REL, lambda d: d["webauthn"].__setitem__("challenge_bytes", 4))
        self.assertIn("MFA_CHALLENGE", self.codes(self._validate()))

    def test_rejects_a_long_lived_challenge(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["webauthn"].__setitem__("challenge_ttl_seconds", 86400))
        self.assertIn("MFA_CHALLENGE", self.codes(self._validate()))

    def test_rejects_a_reusable_challenge(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["webauthn"].__setitem__("challenge_single_use", False))
        self.assertIn("MFA_CHALLENGE_REPLAY", self.codes(self._validate()))

    def test_rejects_ignoring_the_signature_counter(self):
        self.fixture.mutate(self.REL, lambda d: d["webauthn"].__setitem__(
            "sign_count_regression_is_clone", False))
        self.assertIn("MFA_SIGN_COUNT", self.codes(self._validate()))

    def test_rejects_disabling_attestation(self):
        self.fixture.mutate(self.REL, lambda d: d["webauthn"].__setitem__("attestation", "none"))
        self.assertIn("MFA_ATTESTATION", self.codes(self._validate()))

    def test_rejects_an_unaccepted_algorithm(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["webauthn"].__setitem__("allowed_algorithms", [-65535]))
        self.assertIn("MFA_ALGORITHM", self.codes(self._validate()))

    def test_rejects_dropping_step_up_for_high_risk(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["step_up"].__setitem__("required_for_high_risk", False))
        self.assertIn("MFA_STEP_UP", self.codes(self._validate()))

    def test_rejects_a_step_up_that_is_not_bound_to_the_operation(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["step_up"].__setitem__("transaction_binding", False))
        problems = self._validate()
        self.assertIn("MFA_NO_TRANSACTION_BINDING", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_an_all_day_step_up(self):
        self.fixture.mutate(self.REL, lambda d: d["step_up"].__setitem__("max_age_seconds",
                                                                         86400))
        self.assertIn("MFA_STEP_UP", self.codes(self._validate()))

    def test_rejects_a_downgrading_fallback(self):
        """'Use SMS if your key is not to hand' makes SMS the real security level."""
        self.fixture.mutate(self.REL,
                            lambda d: d["fallback"].__setitem__("downgrade_allowed", True))
        self.assertIn("MFA_DOWNGRADE_FALLBACK", self.codes(self._validate()))

    def test_rejects_an_unwritten_fallback_policy(self):
        self.fixture.mutate(self.REL, lambda d: d["fallback"].__setitem__("policy", ""))
        self.assertIn("MFA_DOWNGRADE_FALLBACK", self.codes(self._validate()))

    def test_rejects_privileged_enrolment_with_a_single_authenticator(self):
        self.fixture.mutate(self.REL, lambda d: d["enrolment"].__setitem__(
            "minimum_authenticators_for_privileged", 1))
        self.assertIn("MFA_SINGLE_AUTHENTICATOR", self.codes(self._validate()))

    def test_rejects_activating_an_unverified_authenticator(self):
        self.fixture.mutate(self.REL, lambda d: d["enrolment"].__setitem__(
            "verified_before_activation", False))
        self.assertIn("MFA_ENROLMENT", self.codes(self._validate()))

    def test_rejects_silent_enrolment(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["enrolment"].__setitem__("notify_on_registration", False))
        self.assertIn("MFA_ENROLMENT", self.codes(self._validate()))

    def test_rejects_unlimited_attempts(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["rate_limiting"].__setitem__("max_attempts_per_hour",
                                                                     100000))
        self.assertIn("MFA_RATE_LIMIT", self.codes(self._validate()))

    def test_rejects_a_lockout_of_zero(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["rate_limiting"].__setitem__("lockout_seconds", 0))
        self.assertIn("MFA_RATE_LIMIT", self.codes(self._validate()))

    def test_rejects_ignoring_push_fatigue(self):
        self.fixture.mutate(self.REL, lambda d: d["rate_limiting"].__setitem__(
            "push_fatigue_protection", False))
        self.assertIn("MFA_PUSH_FATIGUE", self.codes(self._validate()))

    def test_rejects_an_empty_authenticator_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("authenticators", []))
        self.assertIn("MFA_SHAPE", self.codes(self._validate()))

    def test_rejects_an_authenticator_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["authenticators"].append("totp"))
        self.assertIn("MFA_SHAPE", self.codes(self._validate()))

    def test_rejects_a_bad_authenticator_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._auth(d, "totp").__setitem__("id", "TOTP"))
        self.assertIn("MFA_AUTH_ID", self.codes(self._validate()))

    def test_rejects_a_duplicate_authenticator(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["authenticators"].append(dict(self._auth(d, "totp"))))
        self.assertIn("MFA_AUTH_DUPLICATE", self.codes(self._validate()))

    def test_rejects_an_unknown_authenticator_kind(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._auth(d, "totp").__setitem__("kind", "telepathy"))
        self.assertIn("MFA_AUTH_KIND", self.codes(self._validate()))

    def test_rejects_an_authenticator_with_no_explanation(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._auth(d, "totp").__setitem__("notes", ""))
        self.assertIn("MFA_AUTH_NOTES", self.codes(self._validate()))

    def test_rejects_an_empty_requirement_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("requirements", []))
        self.assertIn("MFA_SHAPE", self.codes(self._validate()))

    def test_rejects_a_requirement_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["requirements"].append("payer"))
        self.assertIn("MFA_SHAPE", self.codes(self._validate()))

    def test_rejects_a_duplicate_role(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["requirements"].append(dict(self._role(d, "payer"))))
        self.assertIn("MFA_ROLE", self.codes(self._validate()))

    def test_rejects_a_role_with_no_rationale(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._role(d, "payer").__setitem__("notes", ""))
        self.assertIn("MFA_ROLE_NOTES", self.codes(self._validate()))

    def test_rejects_a_reference_to_an_unknown_authenticator(self):
        self.fixture.mutate(self.REL, lambda d: self._role(d, "payer")["allowed_authenticators"]
                            .append("mind-reading"))
        self.assertIn("MFA_UNKNOWN_AUTHENTICATOR", self.codes(self._validate()))

    def test_rejects_an_authenticator_both_allowed_and_forbidden(self):
        self.fixture.mutate(self.REL, lambda d: self._role(d, "payer")["forbidden_authenticators"]
                            .append("totp"))
        self.assertIn("MFA_ROLE", self.codes(self._validate()))

    def test_rejects_a_role_that_cannot_authenticate_at_all(self):
        self.fixture.mutate(self.REL, lambda d: self._role(d, "payer").__setitem__(
            "allowed_authenticators", []))
        self.assertIn("MFA_ROLE", self.codes(self._validate()))

    def test_rejects_downgrading_a_privileged_role(self):
        self.fixture.mutate(self.REL, lambda d: self._role(
            d, "platform-operator").__setitem__("required_class", "any"))
        self.assertIn("MFA_PRIVILEGED_CLASS", self.codes(self._validate()))

    def test_rejects_letting_an_operator_use_sms(self):
        self.fixture.mutate(self.REL, lambda d: self._role(
            d, "platform-operator")["allowed_authenticators"].append("sms-otp"))
        problems = self._validate()
        self.assertIn("MFA_WEAK_FOR_PRIVILEGED", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_a_privileged_role_with_one_authenticator(self):
        self.fixture.mutate(self.REL, lambda d: self._role(
            d, "platform-operator").__setitem__("minimum_registered_authenticators", 1))
        self.assertIn("MFA_SINGLE_AUTHENTICATOR", self.codes(self._validate()))

    def test_rejects_a_privileged_role_with_no_step_up_actions(self):
        self.fixture.mutate(self.REL, lambda d: self._role(
            d, "platform-operator").__setitem__("step_up_actions", []))
        self.assertIn("MFA_STEP_UP", self.codes(self._validate()))

    def test_rejects_leaving_a_privileged_role_ungoverned(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "requirements", [r for r in d["requirements"] if r["role"] != "break-glass"]))
        self.assertIn("MFA_ROLE_UNCOVERED", self.codes(self._validate()))

    def test_rejects_a_recovery_path_that_bypasses_this_policy(self):
        """Recovery is how MFA gets bypassed, so B17's paths are checked here too."""
        self.fixture.mutate("governance/identity.json", lambda d: next(
            r for r in d["recovery"] if r["subject"] == "platform-operator")
            .__setitem__("sms_only_allowed", True))
        problems = self._validate()
        self.assertIn("MFA_RECOVERY_BYPASS", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_removing_the_zero_trust_factor_this_policy_backs(self):
        self.fixture.mutate("governance/zero-trust.json", lambda d: d.__setitem__(
            "required_factors", [f for f in d["required_factors"]
                                 if f != "phishing_resistant_mfa"]))
        self.assertIn("MFA_FACTOR_UNBACKED", self.codes(self._validate()))

    def test_rejects_missing_generated_artefacts(self):
        self.fixture.remove("contracts/security/mfa-matrix.json")
        self.assertIn("MFA_GENERATED_MISSING", self.codes(self._validate()))

    def test_rejects_a_hand_edited_generated_artefact(self):
        path = self.fixture.root / "docs/security/MFA.md"
        path.write_text(path.read_text(encoding="utf-8").replace(
            "webauthn-roaming", "sms-otp"), encoding="utf-8")
        self.assertIn("MFA_GENERATED_DRIFT", self.codes(self._validate()))

    def test_fails_closed_when_the_matrix_cannot_be_generated(self):
        """A gate must turn a broken policy into a finding, not into a crash."""
        self.fixture.mutate(self.REL, lambda d: self._auth(d, "totp").pop("origin_bound"))
        self.assertIn("MFA_GENERATED", self.codes(self._validate()))


class WebAuthnCeremonyReference(FixtureTestCase):
    """Phishing resistance is a property; this is the code that makes it one."""

    def setUp(self):
        super().setUp()
        from libs.mfa.reference import webauthn
        self.wa = webauthn
        self.policy = self.fixture.read("governance/mfa.json")

    def _party(self, counter: int = 0):
        rp = self.wa.RelyingParty.from_policy(self.policy)
        rp.register("cred-1", counter)
        return rp

    def _assertion(self, rp, challenge, **overrides):
        kwargs = {"credential_id": "cred-1", "origin": sorted(rp.allowed_origins)[0],
                  "relying_party_id": rp.relying_party_id, "challenge": challenge,
                  "user_verified": True, "sign_count": 1}
        kwargs.update(overrides)
        return self.wa.Assertion(**kwargs)

    def _code(self, rp, a, **kwargs):
        with self.assertRaises(self.wa.CeremonyRejected) as raised:
            rp.verify(a, **kwargs)
        return raised.exception.code

    def test_a_legitimate_assertion_is_accepted(self):
        rp = self._party()
        rp.issue_challenge("c1")
        self.assertEqual(rp.verify(self._assertion(rp, "c1")).credential_id, "cred-1")

    def test_a_phishing_origin_is_rejected(self):
        """The test this entire batch exists for."""
        rp = self._party()
        rp.issue_challenge("c1")
        for origin in ("https://pay-example.invalid.attacker.com",
                       "https://pay.example.invalid.evil.co",
                       "https://paypal.example.invalid",
                       "http://pay.example.invalid"):
            self.assertEqual(self._code(rp, self._assertion(rp, "c1", origin=origin)),
                             "WRONG_ORIGIN", origin)

    def test_a_wrong_relying_party_id_is_rejected(self):
        rp = self._party()
        rp.issue_challenge("c1")
        self.assertEqual(
            self._code(rp, self._assertion(rp, "c1", relying_party_id="evil.invalid")),
            "WRONG_RP_ID")

    def test_a_replayed_assertion_is_rejected(self):
        rp = self._party()
        rp.issue_challenge("c1")
        rp.verify(self._assertion(rp, "c1"))
        self.assertEqual(self._code(rp, self._assertion(rp, "c1", sign_count=2)),
                         "REPLAYED_CHALLENGE")

    def test_a_challenge_we_never_issued_is_rejected(self):
        rp = self._party()
        self.assertEqual(self._code(rp, self._assertion(rp, "never-issued")),
                         "UNKNOWN_CHALLENGE")

    def test_an_expired_challenge_is_rejected(self):
        rp = self._party()
        rp.issue_challenge("c1", expires_at=10)
        self.assertEqual(self._code(rp, self._assertion(rp, "c1"), now=1000),
                         "STALE_CHALLENGE")

    def test_a_missing_user_verification_flag_is_rejected(self):
        rp = self._party()
        rp.issue_challenge("c1")
        self.assertEqual(self._code(rp, self._assertion(rp, "c1", user_verified=False)),
                         "NO_USER_VERIFICATION")

    def test_a_regressing_signature_counter_means_a_clone(self):
        rp = self._party(counter=10)
        rp.issue_challenge("c1")
        self.assertEqual(self._code(rp, self._assertion(rp, "c1", sign_count=5)),
                         "CLONED_AUTHENTICATOR")

    def test_an_advancing_signature_counter_is_accepted(self):
        rp = self._party(counter=10)
        rp.issue_challenge("c1")
        self.assertEqual(rp.verify(self._assertion(rp, "c1", sign_count=11)).sign_count, 11)

    def test_an_unregistered_credential_is_rejected(self):
        rp = self._party()
        rp.issue_challenge("c1")
        self.assertEqual(self._code(rp, self._assertion(rp, "c1", credential_id="other")),
                         "UNKNOWN_CREDENTIAL")

    def test_a_bad_signature_is_rejected(self):
        rp = self._party()
        rp.issue_challenge("c1")
        self.assertEqual(self._code(rp, self._assertion(rp, "c1", signature_valid=False)),
                         "BAD_SIGNATURE")

    def test_an_unaccepted_algorithm_is_rejected(self):
        rp = self._party()
        rp.issue_challenge("c1")
        self.assertEqual(self._code(rp, self._assertion(rp, "c1", algorithm=-65535)),
                         "BAD_ALGORITHM")

    def test_a_step_up_bound_to_another_operation_is_rejected(self):
        rp = self._party()
        rp.issue_challenge("c1")
        wanted = self.wa.transaction_hash("refund.approve", "rf_1")
        other = self.wa.transaction_hash("refund.approve", "rf_2")
        self.assertEqual(
            self._code(rp, self._assertion(rp, "c1", transaction_hash=other),
                       expect_transaction=wanted),
            "TRANSACTION_NOT_BOUND")

    def test_a_step_up_bound_to_this_operation_is_accepted(self):
        rp = self._party()
        rp.issue_challenge("c1")
        wanted = self.wa.transaction_hash("refund.approve", "rf_1")
        verified = rp.verify(self._assertion(rp, "c1", transaction_hash=wanted),
                             expect_transaction=wanted)
        self.assertEqual(verified.transaction_hash, wanted)
