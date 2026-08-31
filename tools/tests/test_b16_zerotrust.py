"""B16 / AT-B16-01 — zero-trust access architecture.

Zero trust is easy to claim and easy to lose. The tests are organised around the
specific ways it collapses back into perimeter security:

* ``test_network_location_changes_nothing`` runs every declared decision twice —
  once labelled "corporate-vpn", once "public-internet" — and asserts the
  verdicts are identical. That test is the whole architecture in one assertion.
* ``test_every_required_factor_is_load_bearing`` removes each requirement of
  each rule, one at a time, and asserts the request is denied. A requirement
  that can be dropped without changing the answer is decoration.
* ``ZT_AUDIT_ALLOW_ONLY`` — recording only denials is the most common way an
  audit trail becomes useless; the model returns the audit record as part of the
  verdict so a caller cannot forget it.
"""
from __future__ import annotations

from tools.paygov import zerotrust, ztgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class ZeroTrustHappyPath(FixtureTestCase):
    def test_real_policy_passes(self):
        problems = zerotrust.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("zero-trust", registry.names())

    def test_network_location_grants_nothing(self):
        policy = self.fixture.read("governance/zero-trust.json")
        self.assertEqual(policy["network_location_grants"], [])
        self.assertIs(policy["deny_by_default"], True)

    def test_every_trust_boundary_has_a_rule(self):
        policy = self.fixture.read("governance/zero-trust.json")
        threat = self.fixture.read("governance/threat-model.json")
        governed = {r["boundary"] for r in policy["zone_rules"]}
        self.assertEqual(governed, {b["id"] for b in threat["trust_boundaries"]})

    def test_internal_to_internal_boundaries_still_require_mutual_tls(self):
        policy = self.fixture.read("governance/zero-trust.json")
        threat = self.fixture.read("governance/threat-model.json")
        zones = {z["id"]: z["trust"] for z in threat["zones"]}
        boundaries = {b["id"]: b for b in threat["trust_boundaries"]}
        checked = 0
        for rule in policy["zone_rules"]:
            between = boundaries[rule["boundary"]]["between"]
            if all(zones[z] in zerotrust.PLATFORM_OPERATED_TRUST for z in between):
                checked += 1
                self.assertTrue(rule["mutual_tls"], rule["boundary"])
        self.assertGreaterEqual(checked, 3)

    def test_every_boundary_crossing_is_audited(self):
        policy = self.fixture.read("governance/zero-trust.json")
        for rule in policy["zone_rules"]:
            self.assertIn("audit_record", rule["requires"], rule["boundary"])

    def test_no_static_long_lived_credentials(self):
        policy = self.fixture.read("governance/zero-trust.json")
        workload = policy["workload_identity"]
        self.assertIs(workload["static_long_lived_credentials_allowed"], False)
        self.assertEqual(workload["transport"], "mtls")
        for principal in policy["principals"]:
            self.assertGreater(principal["credential_lifetime_minutes"], 0, principal["id"])

    def test_merchant_api_uses_short_lived_mtls_bound_oidc_tokens(self):
        policy = self.fixture.read("governance/zero-trust.json")
        principal = next(p for p in policy["principals"]
                         if p["id"] == "merchant-api-client")
        self.assertEqual(principal["identity_source"], "oidc_authorization_server")
        self.assertEqual(principal["credential"], "mtls_bound_access_token")
        self.assertLessEqual(principal["credential_lifetime_minutes"], 5)
        decisions = [d for d in policy["decisions"]
                     if d["principal"] == "merchant-api-client"]
        self.assertTrue(decisions)
        for entry in decisions:
            self.assertIn("token_audience", entry["requirements"])
            self.assertIn("token_holder_binding", entry["requirements"])

    def test_human_credentials_do_not_outlast_the_session_limit(self):
        policy = self.fixture.read("governance/zero-trust.json")
        limit = policy["session"]["max_human_session_minutes"]
        for principal in policy["principals"]:
            if principal["kind"] == "human":
                self.assertLessEqual(principal["credential_lifetime_minutes"], limit,
                                     principal["id"])

    def test_every_decision_requires_identity_policy_and_audit(self):
        policy = self.fixture.read("governance/zero-trust.json")
        self.assertGreaterEqual(len(policy["decisions"]), 8)
        for entry in policy["decisions"]:
            for mandatory in ("authenticated_identity", "authorisation_policy", "audit_record"):
                self.assertIn(mandatory, entry["requirements"], entry["id"])

    def test_high_risk_actions_require_four_eyes_and_step_up(self):
        policy = self.fixture.read("governance/zero-trust.json")
        found = 0
        for entry in policy["decisions"]:
            if (entry["resource_class"], entry["action"]) in zerotrust.HIGH_RISK:
                found += 1
                self.assertTrue(entry["four_eyes"], entry["id"])
                self.assertTrue(entry["step_up"], entry["id"])
                self.assertIn("justification", entry["requirements"], entry["id"])
        self.assertGreaterEqual(found, 3)

    def test_administrative_access_is_phishing_resistant(self):
        policy = self.fixture.read("governance/zero-trust.json")
        for entry in policy["decisions"]:
            if entry["principal"] in ("platform-operator", "break-glass"):
                self.assertIn("phishing_resistant_mfa", entry["requirements"], entry["id"])
                self.assertIn("device_posture", entry["requirements"], entry["id"])

    def test_tenant_scoped_access_binds_the_tenant_to_the_credential(self):
        policy = self.fixture.read("governance/zero-trust.json")
        for entry in policy["decisions"]:
            if "tenant" in entry["resource_class"] and entry["principal"] not in (
                    "platform-operator", "break-glass"):
                self.assertIn("tenant_binding", entry["requirements"], entry["id"])

    def test_the_break_glass_role_declared_in_b13_is_governed_here(self):
        policy = self.fixture.read("governance/zero-trust.json")
        arch = self.fixture.read("governance/data-architecture.json")
        self.assertTrue(arch["tenancy"]["escape_hatch"]["role"])
        self.assertIn("break-glass", {p["id"] for p in policy["principals"]})
        entries = [d for d in policy["decisions"] if d["principal"] == "break-glass"]
        self.assertTrue(entries)
        for entry in entries:
            self.assertIn("time_bound_session", entry["requirements"])
            self.assertTrue(entry["four_eyes"])

    def test_every_decision_and_every_allow_is_audited(self):
        policy = self.fixture.read("governance/zero-trust.json")
        self.assertIs(policy["audit"]["every_decision_recorded"], True)
        self.assertIs(policy["audit"]["immutable"], True)

    def test_generated_artefacts_match_the_policy(self):
        for rel, content in ztgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)


class ZeroTrustGateRejects(FixtureTestCase):
    REL = "governance/zero-trust.json"

    def _validate(self):
        return zerotrust.validate(self.fixture.root, Budget(seconds=60).start())

    def _decision(self, d, rid):
        return next(x for x in d["decisions"] if x["id"] == rid)

    def _principal(self, d, pid):
        return next(x for x in d["principals"] if x["id"] == pid)

    def test_rejects_unreadable_policy(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("ZT_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("ZT_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_dropping_the_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("ZT_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_allow_by_default(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("deny_by_default", False))
        self.assertIn("ZT_DENY_BY_DEFAULT", self.codes(self._validate()))

    def test_rejects_trusting_a_network(self):
        """The single change that turns this back into a firewall."""
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "network_location_grants", [{"cidr": "10.0.0.0/8", "grants": "internal_api"}]))
        self.assertIn("ZT_NETWORK_TRUST", self.codes(self._validate()))

    def test_rejects_removing_an_access_factor(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "required_factors", ["authenticated_identity"]))
        self.assertIn("ZT_FACTORS", self.codes(self._validate()))

    def test_rejects_an_eight_hour_session(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["session"].__setitem__("max_human_session_minutes", 480))
        self.assertIn("ZT_SESSION", self.codes(self._validate()))

    def test_rejects_slow_revocation(self):
        self.fixture.mutate(self.REL, lambda d: d["session"].__setitem__(
            "revocation_propagation_seconds", 86400))
        self.assertIn("ZT_REVOCATION", self.codes(self._validate()))

    def test_rejects_an_unwritten_session_policy(self):
        self.fixture.mutate(self.REL, lambda d: d["session"].__setitem__("policy", ""))
        self.assertIn("ZT_SESSION", self.codes(self._validate()))

    def test_rejects_allowing_static_service_credentials(self):
        self.fixture.mutate(self.REL, lambda d: d["workload_identity"].__setitem__(
            "static_long_lived_credentials_allowed", True))
        problems = self._validate()
        self.assertIn("ZT_STATIC_CREDENTIAL", self.codes(problems))
        self.assertIn("NN-07", self.rules(problems))

    def test_rejects_carrying_workload_identity_in_a_header(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["workload_identity"].__setitem__("transport", "header"))
        self.assertIn("ZT_WORKLOAD_IDENTITY", self.codes(self._validate()))

    def test_rejects_year_long_workload_certificates(self):
        self.fixture.mutate(self.REL, lambda d: d["workload_identity"].__setitem__(
            "max_certificate_minutes", 525600))
        self.assertIn("ZT_WORKLOAD_IDENTITY", self.codes(self._validate()))

    def test_rejects_auditing_only_denials(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["audit"].__setitem__("every_decision_recorded", False))
        self.assertIn("ZT_AUDIT_ALLOW_ONLY", self.codes(self._validate()))

    def test_rejects_a_mutable_audit_trail(self):
        self.fixture.mutate(self.REL, lambda d: d["audit"].__setitem__("immutable", False))
        problems = self._validate()
        self.assertIn("ZT_AUDIT_MUTABLE", self.codes(problems))
        self.assertIn("NN-06", self.rules(problems))

    def test_rejects_audit_records_without_a_reason(self):
        self.fixture.mutate(self.REL, lambda d: d["audit"].__setitem__(
            "required_fields", ["actor", "action"]))
        self.assertIn("ZT_AUDIT_FIELDS", self.codes(self._validate()))

    def test_rejects_an_empty_principal_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principals", []))
        self.assertIn("ZT_SHAPE", self.codes(self._validate()))

    def test_rejects_a_principal_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["principals"].append("payer"))
        self.assertIn("ZT_SHAPE", self.codes(self._validate()))

    def test_rejects_a_bad_principal_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._principal(d, "payer").__setitem__("id", "Payer"))
        self.assertIn("ZT_PRINCIPAL_ID", self.codes(self._validate()))

    def test_rejects_a_duplicate_principal(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["principals"].append(dict(self._principal(d, "payer"))))
        self.assertIn("ZT_PRINCIPAL_DUPLICATE", self.codes(self._validate()))

    def test_rejects_an_unknown_principal_kind(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._principal(d, "payer").__setitem__("kind", "ghost"))
        self.assertIn("ZT_PRINCIPAL_KIND", self.codes(self._validate()))

    def test_rejects_an_identity_with_no_source(self):
        self.fixture.mutate(self.REL, lambda d: self._principal(
            d, "service-workload").__setitem__("identity_source", ""))
        self.assertIn("ZT_IDENTITY_SOURCE", self.codes(self._validate()))

    def test_rejects_a_principal_with_no_explanation(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._principal(d, "payer").__setitem__("notes", ""))
        self.assertIn("ZT_PRINCIPAL_NOTES", self.codes(self._validate()))

    def test_rejects_a_credential_that_never_expires(self):
        self.fixture.mutate(self.REL, lambda d: self._principal(
            d, "service-workload").__setitem__("credential_lifetime_minutes", 0))
        problems = self._validate()
        self.assertIn("ZT_CREDENTIAL_LIFETIME", self.codes(problems))
        self.assertIn("NN-07", self.rules(problems))

    def test_rejects_a_human_credential_outlasting_the_session(self):
        self.fixture.mutate(self.REL, lambda d: self._principal(
            d, "platform-operator").__setitem__("credential_lifetime_minutes", 100))
        self.assertIn("ZT_CREDENTIAL_LIFETIME", self.codes(self._validate()))

    def test_rejects_a_workload_authenticating_with_a_password(self):
        self.fixture.mutate(self.REL, lambda d: self._principal(
            d, "service-workload").__setitem__("credential", "service_account_password"))
        self.assertIn("ZT_WORKLOAD_CREDENTIAL", self.codes(self._validate()))

    def test_rejects_a_static_merchant_api_credential(self):
        self.fixture.mutate(self.REL, lambda d: self._principal(
            d, "merchant-api-client").update({
                "identity_source": "tenant_api_key",
                "credential": "http_signature",
                "credential_lifetime_minutes": 90,
            }))
        self.assertIn("ZT_MERCHANT_CREDENTIAL", self.codes(self._validate()))

    def test_rejects_a_principal_that_can_access_nothing(self):
        self.fixture.mutate(self.REL, lambda d: d["principals"].append(
            {"id": "ghost-principal", "kind": "human", "home_zone": "Z07",
             "identity_source": "corporate_idp", "credential": "webauthn",
             "credential_lifetime_minutes": 30, "rotation_days": 0,
             "notes": "从来不出现在任何判定里的主体"}))
        self.assertIn("ZT_PRINCIPAL_UNUSED", self.codes(self._validate()))

    def test_rejects_an_empty_decision_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("decisions", []))
        self.assertIn("ZT_SHAPE", self.codes(self._validate()))

    def test_rejects_a_decision_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["decisions"].append("ZTD-99"))
        self.assertIn("ZT_SHAPE", self.codes(self._validate()))

    def test_rejects_a_bad_decision_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._decision(d, "ZTD-01").__setitem__("id", "one"))
        self.assertIn("ZT_DECISION_ID", self.codes(self._validate()))

    def test_rejects_a_duplicate_decision(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["decisions"].append(dict(self._decision(d, "ZTD-01"))))
        self.assertIn("ZT_DECISION_DUPLICATE", self.codes(self._validate()))

    def test_rejects_a_decision_for_an_unknown_principal(self):
        self.fixture.mutate(self.REL, lambda d: self._decision(d, "ZTD-01").__setitem__(
            "principal", "the-intern"))
        self.assertIn("ZT_DECISION_PRINCIPAL", self.codes(self._validate()))

    def test_rejects_a_decision_with_no_requirements(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._decision(d, "ZTD-01").__setitem__("requirements", []))
        self.assertIn("ZT_DECISION_REQUIREMENTS", self.codes(self._validate()))

    def test_rejects_an_undeclared_requirement(self):
        self.fixture.mutate(self.REL, lambda d: self._decision(d, "ZTD-01")["requirements"]
                            .append("good_vibes"))
        self.assertIn("ZT_DECISION_REQUIREMENTS", self.codes(self._validate()))

    def test_rejects_a_decision_that_skips_the_audit_record(self):
        self.fixture.mutate(self.REL, lambda d: self._decision(d, "ZTD-01").__setitem__(
            "requirements", ["authenticated_identity", "authorisation_policy"]))
        self.assertIn("ZT_DECISION_MINIMUM", self.codes(self._validate()))

    def test_rejects_a_decision_with_no_audit_event(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._decision(d, "ZTD-01").__setitem__("audit_event", ""))
        self.assertIn("ZT_DECISION_AUDIT", self.codes(self._validate()))

    def test_rejects_a_decision_with_no_rationale(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._decision(d, "ZTD-01").__setitem__("notes", ""))
        self.assertIn("ZT_DECISION_NOTES", self.codes(self._validate()))

    def test_rejects_single_approver_refunds(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._decision(d, "ZTD-05").__setitem__("four_eyes", False))
        problems = self._validate()
        self.assertIn("ZT_FOUR_EYES", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_a_high_risk_action_without_step_up(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._decision(d, "ZTD-06").__setitem__("step_up", False))
        self.assertIn("ZT_STEP_UP", self.codes(self._validate()))

    def test_rejects_a_high_risk_action_with_no_justification(self):
        self.fixture.mutate(self.REL, lambda d: self._decision(d, "ZTD-05").__setitem__(
            "requirements", ["authenticated_identity", "authorisation_policy", "audit_record",
                             "device_posture", "phishing_resistant_mfa"]))
        self.assertIn("ZT_JUSTIFICATION", self.codes(self._validate()))

    def test_rejects_dropping_a_high_risk_action_from_governance(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "decisions", [x for x in d["decisions"] if x["id"] != "ZTD-06"]))
        self.assertIn("ZT_HIGH_RISK_UNCOVERED", self.codes(self._validate()))

    def test_rejects_admin_access_without_phishing_resistant_mfa(self):
        self.fixture.mutate(self.REL, lambda d: self._decision(d, "ZTD-04").__setitem__(
            "requirements", ["authenticated_identity", "authorisation_policy", "audit_record",
                             "device_posture", "justification"]))
        self.assertIn("ZT_ADMIN_MFA", self.codes(self._validate()))

    def test_rejects_admin_access_without_device_posture(self):
        self.fixture.mutate(self.REL, lambda d: self._decision(d, "ZTD-04").__setitem__(
            "requirements", ["authenticated_identity", "authorisation_policy", "audit_record",
                             "phishing_resistant_mfa", "justification"]))
        self.assertIn("ZT_DEVICE_POSTURE", self.codes(self._validate()))

    def test_rejects_tenant_access_bound_to_the_request_body(self):
        self.fixture.mutate(self.REL, lambda d: self._decision(d, "ZTD-02").__setitem__(
            "requirements", ["authenticated_identity", "authorisation_policy", "audit_record",
                             "request_signature"]))
        problems = self._validate()
        self.assertIn("ZT_TENANT_BINDING", self.codes(problems))
        self.assertIn("NN-09", self.rules(problems))

    def test_rejects_merchant_access_without_token_holder_binding(self):
        self.fixture.mutate(self.REL, lambda d: self._decision(
            d, "ZTD-02")["requirements"].remove("token_holder_binding"))
        self.assertIn("ZT_MERCHANT_CREDENTIAL", self.codes(self._validate()))

    def test_rejects_an_empty_zone_rule_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("zone_rules", []))
        self.assertIn("ZT_SHAPE", self.codes(self._validate()))

    def test_rejects_a_zone_rule_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["zone_rules"].append("TB-01"))
        self.assertIn("ZT_SHAPE", self.codes(self._validate()))

    def test_rejects_a_rule_for_an_unknown_boundary(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["zone_rules"][0].__setitem__("boundary", "TB-99"))
        self.assertIn("ZT_BOUNDARY_UNKNOWN", self.codes(self._validate()))

    def test_rejects_a_boundary_with_no_requirements(self):
        self.fixture.mutate(self.REL, lambda d: d["zone_rules"][0].__setitem__("requires", []))
        self.assertIn("ZT_BOUNDARY_REQUIREMENTS", self.codes(self._validate()))

    def test_rejects_an_unaudited_boundary_crossing(self):
        self.fixture.mutate(self.REL, lambda d: d["zone_rules"][0].__setitem__(
            "requires", ["authenticated_identity"]))
        self.assertIn("ZT_BOUNDARY_AUDIT", self.codes(self._validate()))

    def test_rejects_an_unexplained_boundary(self):
        self.fixture.mutate(self.REL, lambda d: d["zone_rules"][0].__setitem__("notes", ""))
        self.assertIn("ZT_BOUNDARY_NOTES", self.codes(self._validate()))

    def test_rejects_dropping_mutual_tls_between_internal_zones(self):
        """'Both sides are internal' is exactly the assumption zero trust removes."""
        self.fixture.mutate(self.REL, lambda d: next(
            r for r in d["zone_rules"] if r["boundary"] == "TB-08")
            .__setitem__("mutual_tls", False))
        self.assertIn("ZT_INTERNAL_TRUST", self.codes(self._validate()))

    def test_rejects_leaving_a_boundary_ungoverned(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "zone_rules", [r for r in d["zone_rules"] if r["boundary"] != "TB-07"]))
        self.assertIn("ZT_BOUNDARY_UNGOVERNED", self.codes(self._validate()))

    def test_rejects_an_ungoverned_break_glass_role(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "principals", [p for p in d["principals"] if p["id"] != "break-glass"]))
        problems = self._validate()
        self.assertIn("ZT_BREAK_GLASS_UNGOVERNED", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_an_unbounded_break_glass_session(self):
        self.fixture.mutate(self.REL, lambda d: self._decision(d, "ZTD-07").__setitem__(
            "requirements", ["authenticated_identity", "authorisation_policy", "audit_record",
                             "device_posture", "phishing_resistant_mfa", "justification"]))
        self.assertIn("ZT_BREAK_GLASS_UNBOUNDED", self.codes(self._validate()))

    def test_rejects_missing_generated_artefacts(self):
        self.fixture.remove("contracts/security/zero-trust-matrix.json")
        self.assertIn("ZT_GENERATED_MISSING", self.codes(self._validate()))

    def test_rejects_a_hand_edited_generated_artefact(self):
        path = self.fixture.root / "docs/security/ZERO_TRUST.md"
        path.write_text(path.read_text(encoding="utf-8").replace(
            "默认拒绝", "默认允许"), encoding="utf-8")
        self.assertIn("ZT_GENERATED_DRIFT", self.codes(self._validate()))

    def test_fails_closed_when_the_matrix_cannot_be_generated(self):
        """A gate must turn a broken policy into a finding, not into a crash."""
        self.fixture.mutate(self.REL, lambda d: self._principal(d, "payer").pop("home_zone"))
        self.assertIn("ZT_GENERATED", self.codes(self._validate()))


class PolicyDecisionPointReference(FixtureTestCase):
    """The architecture is only as real as the thing that says no."""

    def setUp(self):
        super().setUp()
        from libs.zerotrust.reference import decision
        self.zt = decision
        self.policy = self.fixture.read("governance/zero-trust.json")
        self.pdp = decision.PolicyDecisionPoint.from_policy(self.policy)

    def _happy(self, rule, **overrides):
        kwargs = {"principal": rule["principal"], "resource_class": rule["resource_class"],
                  "action": rule["action"], "factors": frozenset(rule["requirements"]),
                  "requester": "alice", "step_up_completed": bool(rule["step_up"]),
                  "approver": "bob" if rule["four_eyes"] else ""}
        kwargs.update(overrides)
        return self.zt.Context(**kwargs)

    def test_every_declared_decision_permits_its_own_happy_path(self):
        for rule in self.policy["decisions"]:
            self.assertTrue(self.pdp.decide(self._happy(rule)).allowed, rule["id"])

    def test_every_required_factor_is_load_bearing(self):
        for rule in self.policy["decisions"]:
            for requirement in rule["requirements"]:
                factors = frozenset(set(rule["requirements"]) - {requirement})
                verdict = self.pdp.decide(self._happy(rule, factors=factors))
                self.assertFalse(verdict.allowed, f"{rule['id']}:{requirement}")

    def test_an_unmatched_request_is_denied_by_default(self):
        verdict = self.pdp.decide(self.zt.Context(
            "payer", "ledger_entry", "write", frozenset(self.policy["required_factors"])))
        self.assertFalse(verdict.allowed)
        self.assertIn("denied by default", verdict.reasons[0])

    def test_network_location_changes_nothing(self):
        """The whole architecture, in one assertion."""
        for rule in self.policy["decisions"]:
            inside = self.pdp.decide(self._happy(rule, network="corporate-vpn"))
            outside = self.pdp.decide(self._happy(rule, network="public-internet"))
            self.assertEqual(inside.allowed, outside.allowed, rule["id"])
            bare_in = self.pdp.decide(
                self._happy(rule, factors=frozenset(), network="corporate-vpn"))
            bare_out = self.pdp.decide(
                self._happy(rule, factors=frozenset(), network="public-internet"))
            self.assertFalse(bare_in.allowed, rule["id"])
            self.assertFalse(bare_out.allowed, rule["id"])

    def test_an_expired_session_is_denied_even_with_every_factor(self):
        limit = self.policy["session"]["max_human_session_minutes"]
        for rule in self.policy["decisions"]:
            verdict = self.pdp.decide(self._happy(rule, session_age_minutes=limit + 1))
            self.assertFalse(verdict.allowed, rule["id"])

    def test_a_four_eyes_action_cannot_be_self_approved(self):
        for rule in self.policy["decisions"]:
            if not rule["four_eyes"]:
                continue
            self.assertFalse(
                self.pdp.decide(self._happy(rule, requester="alice", approver="alice")).allowed,
                rule["id"])
            self.assertFalse(self.pdp.decide(self._happy(rule, approver="")).allowed, rule["id"])

    def test_a_step_up_action_is_denied_without_step_up(self):
        for rule in self.policy["decisions"]:
            if rule["step_up"]:
                self.assertFalse(
                    self.pdp.decide(self._happy(rule, step_up_completed=False)).allowed,
                    rule["id"])

    def test_every_verdict_carries_a_complete_audit_record(self):
        required = set(self.policy["audit"]["required_fields"])
        for rule in self.policy["decisions"]:
            for verdict in (self.pdp.decide(self._happy(rule)),
                            self.pdp.decide(self._happy(rule, factors=frozenset()))):
                self.assertTrue(required <= set(verdict.audit), rule["id"])
                self.assertTrue(verdict.audit["reason"], rule["id"])

    def test_allows_and_denies_are_both_logged(self):
        for rule in self.policy["decisions"]:
            self.pdp.decide(self._happy(rule))
            self.pdp.decide(self._happy(rule, factors=frozenset()))
        decisions = [r["decision"] for r in self.pdp.audit_log]
        self.assertIn("allow", decisions)
        self.assertIn("deny", decisions)
        self.assertEqual(len(self.pdp.audit_log), len(decisions))
