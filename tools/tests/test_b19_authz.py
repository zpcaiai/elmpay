"""B19 / AT-B19-01 — authorisation, separation of duties and time-boxed elevation.

Three tests here carry the batch.

``test_the_maker_cannot_be_the_checker`` is the one an attacker cares about:
holding both halves of a money flow — or simply approving the thing you asked
for — is how a single compromised account becomes a loss, and it is also the
control most often waived "just this once" in a real operations team.

``test_an_approval_is_bound_to_this_request`` covers the subtler version: the
approval is genuine, signed off by the right person, still inside its window,
and belongs to a *different* payout. Without digest binding it is a reusable
token that says "somebody approved something".

``test_privileged_roles_are_backed_everywhere`` is the backfill B16, B17 and B18
each recorded as a known gap: declaring a role privileged here is what forces a
phishing-resistant MFA requirement, an account-recovery path and a zero-trust
principal to actually exist for it.
"""
from __future__ import annotations

import json

from libs.authz.reference import decision as D
from tools.paygov import authz, authzgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

NOW = 1_760_000_000


def _model(root=REAL_ROOT) -> D.Model:
    return D.Model(json.loads((root / "governance/authorization.json").read_text(encoding="utf-8")))


class AuthzModelHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = authz.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("authz", registry.names())

    def test_default_decision_is_deny(self):
        model = self.fixture.read("governance/authorization.json")
        self.assertEqual(model["default_decision"], "deny")

    def test_every_money_permission_requires_two_people(self):
        model = self.fixture.read("governance/authorization.json")
        for perm in model["permissions"]:
            if perm["sensitivity"] == "money" and perm["verb"] in {"approve", "adjust", "write"}:
                self.assertTrue(perm["dual_control"], perm["id"])

    def test_every_dual_control_money_permission_appears_in_a_sod_rule(self):
        model = self.fixture.read("governance/authorization.json")
        paired = {side for rule in model["separation_of_duties"]
                  for side in (rule["left"], rule["right"])}
        for perm in model["permissions"]:
            if perm["sensitivity"] == "money" and perm["dual_control"]:
                self.assertIn(perm["id"], paired)

    def test_no_role_holds_both_sides_of_a_separation_rule(self):
        model = self.fixture.read("governance/authorization.json")
        for role in model["roles"]:
            held = set(role["permissions"])
            for rule in model["separation_of_duties"]:
                self.assertFalse({rule["left"], rule["right"]} <= held,
                                 f"{role['id']} holds both sides of {rule['id']}")

    def test_card_data_is_readable_by_nobody(self):
        model = self.fixture.read("governance/authorization.json")
        for rule in model["field_rules"]:
            if rule["field"] in authz.NEVER_READABLE:
                self.assertTrue(rule["never_readable"], rule["field"])
                self.assertEqual(rule["readable_by"], [], rule["field"])

    def test_no_standing_privileged_access(self):
        model = self.fixture.read("governance/authorization.json")
        elev = model["elevation"]
        self.assertFalse(elev["standing_privileged_access"])
        self.assertTrue(elev["auto_revoke"])
        self.assertTrue(elev["requires_ticket_reference"])
        self.assertLessEqual(elev["max_duration_minutes"], 240)
        granted = {p for role in model["roles"] for p in role["permissions"]}
        for perm in model["permissions"]:
            if perm["elevation_required"]:
                self.assertNotIn(perm["id"], granted, perm["id"])

    def test_break_glass_is_shorter_and_reviewed(self):
        model = self.fixture.read("governance/authorization.json")
        elev = model["elevation"]
        glass = elev["break_glass"]
        self.assertLessEqual(glass["max_duration_minutes"], elev["max_duration_minutes"])
        self.assertGreater(glass["post_use_review_hours"], 0)
        self.assertGreaterEqual(len(glass["notify_channels"]), 2)

    def test_auditor_cannot_be_elevated(self):
        model = self.fixture.read("governance/authorization.json")
        self.assertIn("auditor", model["elevation"]["non_elevatable_roles"])

    def test_privileged_roles_are_backed_everywhere(self):
        model = self.fixture.read("governance/authorization.json")
        mfa = self.fixture.read("governance/mfa.json")
        identity = self.fixture.read("governance/identity.json")
        zt = self.fixture.read("governance/zero-trust.json")
        requirements = {r["role"]: r for r in mfa["requirements"]}
        recovery = {r["subject"] for r in identity["recovery"]}
        principals = {p["id"] for p in zt["principals"]}
        privileged = [r for r in model["roles"] if r["privileged"]]
        self.assertGreaterEqual(len(privileged), 3)
        for role in privileged:
            self.assertIn(role["id"], requirements, role["id"])
            self.assertEqual(requirements[role["id"]]["required_class"], "phishing_resistant")
            self.assertIn(role["id"], recovery, role["id"])
        for role in model["roles"]:
            self.assertIn(role["zero_trust_principal"], principals, role["id"])

    def test_audit_records_allow_and_deny(self):
        model = self.fixture.read("governance/authorization.json")
        audit = model["audit"]
        self.assertTrue(audit["record_every_decision"])
        self.assertTrue(audit["record_denials"])
        self.assertTrue(audit["include_rule_version"])
        self.assertTrue(audit["immutable"])


class AuthzGeneratedArtefacts(FixtureTestCase):
    def test_generated_artefacts_match_the_model(self):
        for rel, content in authzgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_matrix_lists_privileged_roles(self):
        matrix = json.loads(authzgen.matrix_json(REAL_ROOT))
        self.assertIn("break-glass", matrix["privileged_roles"])
        self.assertEqual(matrix["default_decision"], "deny")

    def test_document_names_every_role_and_permission(self):
        text = authzgen.authz_markdown(REAL_ROOT)
        model = json.loads((REAL_ROOT / "governance/authorization.json").read_text(
            encoding="utf-8"))
        for role in model["roles"]:
            self.assertIn(role["id"], text)
        for perm in model["permissions"]:
            self.assertIn(perm["id"], text)

    def test_drift_is_reported(self):
        rel = "docs/security/AUTHORIZATION.md"
        self.fixture.write(rel, "hand written\n")
        codes = self.codes(authz.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("AUTHZ_GENERATED_DRIFT", codes)

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/security/authorization-matrix.json")
        codes = self.codes(authz.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("AUTHZ_GENERATED_MISSING", codes)

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate("governance/authorization.json",
                            lambda d: d.__setitem__("roles", [{"id": "x"}]))
        codes = self.codes(authz.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("AUTHZ_GENERATED", codes)


class AuthzGateRejects(FixtureTestCase):
    REL = "governance/authorization.json"

    def _validate(self):
        return authz.validate(self.fixture.root, Budget(seconds=60).start())

    def _role(self, d, rid):
        return next(r for r in d["roles"] if r["id"] == rid)

    def _perm(self, d, pid):
        return next(p for p in d["permissions"] if p["id"] == pid)

    def _field(self, d, name):
        return next(f for f in d["field_rules"] if f["field"] == name)

    def test_rejects_unreadable_model(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("AUTHZ_UNREADABLE", self.codes(self._validate()))

    def test_rejects_non_object_model(self):
        self.fixture.write(self.REL, [1, 2, 3])
        self.assertIn("AUTHZ_SHAPE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("AUTHZ_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_missing_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("AUTHZ_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_allow_by_default(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("default_decision", "allow"))
        self.assertIn("AUTHZ_DEFAULT_DECISION", self.codes(self._validate()))

    def test_rejects_bad_permission_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._perm(d, "payment.read").__setitem__("id", "Payment"))
        self.assertIn("AUTHZ_PERMISSION_ID", self.codes(self._validate()))

    def test_rejects_duplicate_permission(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["permissions"].append(dict(self._perm(d, "payment.read"))))
        self.assertIn("AUTHZ_PERMISSION_DUPLICATE", self.codes(self._validate()))

    def test_rejects_unknown_permission_scope(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._perm(d, "payment.read").__setitem__("scope", "vibes"))
        self.assertIn("AUTHZ_PERMISSION_SCOPE", self.codes(self._validate()))

    def test_rejects_unknown_sensitivity(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._perm(d, "payment.read").__setitem__("sensitivity",
                                                                                "spicy"))
        self.assertIn("AUTHZ_PERMISSION_SENSITIVITY", self.codes(self._validate()))

    def test_rejects_permission_without_notes(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._perm(d, "payment.read").__setitem__("notes", ""))
        self.assertIn("AUTHZ_PERMISSION_NOTES", self.codes(self._validate()))

    def test_rejects_money_permission_without_dual_control(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._perm(d, "payout.approve").__setitem__("dual_control",
                                                                                  False))
        self.assertIn("AUTHZ_MONEY_NO_DUAL_CONTROL", self.codes(self._validate()))

    def test_rejects_permission_nobody_can_hold(self):
        self.fixture.mutate(self.REL, lambda d: d["permissions"].append(
            {"id": "ghost.read", "resource": "ghost", "verb": "read", "scope": "tenant",
             "sensitivity": "normal", "dual_control": False, "elevation_required": False,
             "notes": "无人持有的权限，等于一条无人执行的规则。"}))
        self.assertIn("AUTHZ_PERMISSION_UNUSED", self.codes(self._validate()))

    def test_rejects_bad_role_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._role(d, "auditor").__setitem__("id", "Auditor"))
        self.assertIn("AUTHZ_ROLE_ID", self.codes(self._validate()))

    def test_rejects_duplicate_role(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["roles"].append(dict(self._role(d, "auditor"))))
        self.assertIn("AUTHZ_ROLE_DUPLICATE", self.codes(self._validate()))

    def test_rejects_unknown_role_kind(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._role(d, "auditor").__setitem__("kind", "robot"))
        self.assertIn("AUTHZ_ROLE_KIND", self.codes(self._validate()))

    def test_rejects_unknown_role_scope(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._role(d, "auditor").__setitem__("scope", "galaxy"))
        self.assertIn("AUTHZ_ROLE_SCOPE", self.codes(self._validate()))

    def test_rejects_implicit_privilege_flag(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._role(d, "auditor").__setitem__("privileged", "no"))
        self.assertIn("AUTHZ_ROLE_PRIVILEGED_FLAG", self.codes(self._validate()))

    def test_rejects_role_without_notes(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._role(d, "auditor").__setitem__("notes", ""))
        self.assertIn("AUTHZ_ROLE_NOTES", self.codes(self._validate()))

    def test_rejects_grant_of_unknown_permission(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._role(d, "auditor")["permissions"].append("ghost.read"))
        self.assertIn("AUTHZ_ROLE_PERMISSION_UNKNOWN", self.codes(self._validate()))

    def test_rejects_bad_field_name(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._field(d, "customer_email").__setitem__("field",
                                                                                   "Customer"))
        self.assertIn("AUTHZ_FIELD_NAME", self.codes(self._validate()))

    def test_rejects_duplicate_field_rule(self):
        self.fixture.mutate(self.REL, lambda d: d["field_rules"].append(
            dict(self._field(d, "customer_email"))))
        self.assertIn("AUTHZ_FIELD_DUPLICATE", self.codes(self._validate()))

    def test_rejects_field_without_classification(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._field(d, "customer_email").__setitem__(
                                "classification", ""))
        self.assertIn("AUTHZ_FIELD_CLASSIFICATION", self.codes(self._validate()))

    def test_rejects_field_without_notes(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._field(d, "customer_email").__setitem__("notes", ""))
        self.assertIn("AUTHZ_FIELD_NOTES", self.codes(self._validate()))

    def test_rejects_unknown_field_reader(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._field(d, "customer_email")["readable_by"].append(
                                "ghost-role"))
        self.assertIn("AUTHZ_FIELD_READER_UNKNOWN", self.codes(self._validate()))

    def test_rejects_readable_card_pan(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._field(d, "card_pan").__setitem__("never_readable",
                                                                             False))
        self.assertIn("AUTHZ_FIELD_PAN_READABLE", self.codes(self._validate()))

    def test_rejects_a_role_being_allowed_to_read_pan(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._field(d, "card_pan")["readable_by"].append("auditor"))
        self.assertIn("AUTHZ_FIELD_PAN_READABLE", self.codes(self._validate()))

    def test_rejects_unmasked_pii(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._field(d, "customer_email").__setitem__(
                                "masked_by_default", False))
        self.assertIn("AUTHZ_FIELD_MASK", self.codes(self._validate()))

    def test_rejects_ungoverned_card_data(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "field_rules", [f for f in d["field_rules"] if f["field"] != "card_cvv"]))
        self.assertIn("AUTHZ_FIELD_UNGOVERNED", self.codes(self._validate()))

    def test_rejects_bad_sod_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["separation_of_duties"][0].__setitem__("id", "sod1"))
        self.assertIn("AUTHZ_SOD_ID", self.codes(self._validate()))

    def test_rejects_duplicate_sod_rule(self):
        self.fixture.mutate(self.REL, lambda d: d["separation_of_duties"].append(
            dict(d["separation_of_duties"][0])))
        self.assertIn("AUTHZ_SOD_DUPLICATE", self.codes(self._validate()))

    def test_rejects_sod_rule_without_notes(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["separation_of_duties"][0].__setitem__("notes", ""))
        self.assertIn("AUTHZ_SOD_NOTES", self.codes(self._validate()))

    def test_rejects_sod_rule_naming_unknown_permission(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["separation_of_duties"][0].__setitem__("left",
                                                                               "ghost.read"))
        self.assertIn("AUTHZ_SOD_UNKNOWN_PERMISSION", self.codes(self._validate()))

    def test_rejects_a_role_holding_both_sides(self):
        self.fixture.mutate(self.REL, lambda d: self._role(d, "merchant-finance")["permissions"]
                            .append("refund.request"))
        self.assertIn("AUTHZ_SOD_VIOLATION", self.codes(self._validate()))

    def test_rejects_dropping_a_separation_rule(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "separation_of_duties",
            [s for s in d["separation_of_duties"] if s["id"] != "SOD-02"]))
        self.assertIn("AUTHZ_SOD_MISSING", self.codes(self._validate()))

    def test_rejects_zero_approvals(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["dual_control"].__setitem__("minimum_approvals", 0))
        self.assertIn("AUTHZ_DUAL_APPROVALS", self.codes(self._validate()))

    def test_rejects_self_approval(self):
        self.fixture.mutate(self.REL, lambda d: d["dual_control"].__setitem__(
            "approver_must_differ_from_requester", False))
        self.assertIn("AUTHZ_DUAL_SELF_APPROVAL", self.codes(self._validate()))

    def test_rejects_approvals_that_never_expire(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["dual_control"].__setitem__("approval_ttl_seconds", 0))
        self.assertIn("AUTHZ_DUAL_TTL", self.codes(self._validate()))

    def test_rejects_unbound_approvals(self):
        self.fixture.mutate(self.REL, lambda d: d["dual_control"].__setitem__(
            "approval_bound_to_request_digest", False))
        self.assertIn("AUTHZ_DUAL_BINDING", self.codes(self._validate()))

    def test_rejects_standing_privileged_access(self):
        self.fixture.mutate(self.REL, lambda d: d["elevation"].__setitem__(
            "standing_privileged_access", True))
        self.assertIn("AUTHZ_STANDING_PRIVILEGE", self.codes(self._validate()))

    def test_rejects_all_day_elevation(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["elevation"].__setitem__("max_duration_minutes", 1440))
        self.assertIn("AUTHZ_ELEVATION_DURATION", self.codes(self._validate()))

    def test_rejects_unapproved_elevation(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["elevation"].__setitem__("requires_approval", False))
        self.assertIn("AUTHZ_ELEVATION_APPROVAL", self.codes(self._validate()))

    def test_rejects_self_approved_elevation(self):
        self.fixture.mutate(self.REL, lambda d: d["elevation"].__setitem__(
            "approver_must_differ_from_requester", False))
        self.assertIn("AUTHZ_ELEVATION_APPROVAL", self.codes(self._validate()))

    def test_rejects_elevation_without_a_ticket(self):
        self.fixture.mutate(self.REL, lambda d: d["elevation"].__setitem__(
            "requires_ticket_reference", False))
        self.assertIn("AUTHZ_ELEVATION_TICKET", self.codes(self._validate()))

    def test_rejects_elevation_that_is_not_auto_revoked(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["elevation"].__setitem__("auto_revoke", False))
        self.assertIn("AUTHZ_ELEVATION_AUTO_REVOKE", self.codes(self._validate()))

    def test_rejects_unknown_elevatable_permission(self):
        self.fixture.mutate(self.REL, lambda d: d["elevation"]["elevatable_permissions"]
                            .append("ghost.read"))
        self.assertIn("AUTHZ_ELEVATION_UNKNOWN_PERMISSION", self.codes(self._validate()))

    def test_rejects_elevation_only_permission_held_standing(self):
        self.fixture.mutate(self.REL, lambda d: self._role(d, "platform-operator")["permissions"]
                            .append("config.write"))
        self.assertIn("AUTHZ_STANDING_ELEVATED", self.codes(self._validate()))

    def test_rejects_unknown_non_elevatable_role(self):
        self.fixture.mutate(self.REL, lambda d: d["elevation"]["non_elevatable_roles"]
                            .append("ghost-role"))
        self.assertIn("AUTHZ_ELEVATION_UNKNOWN_ROLE", self.codes(self._validate()))

    def test_rejects_an_elevatable_auditor(self):
        self.fixture.mutate(self.REL, lambda d: d["elevation"].__setitem__(
            "non_elevatable_roles",
            [r for r in d["elevation"]["non_elevatable_roles"] if r != "auditor"]))
        self.assertIn("AUTHZ_AUDITOR_ELEVATABLE", self.codes(self._validate()))

    def test_rejects_break_glass_outlasting_ordinary_elevation(self):
        self.fixture.mutate(self.REL, lambda d: d["elevation"]["break_glass"].__setitem__(
            "max_duration_minutes", 600))
        self.assertIn("AUTHZ_BREAK_GLASS_DURATION", self.codes(self._validate()))

    def test_rejects_unreviewed_break_glass(self):
        self.fixture.mutate(self.REL, lambda d: d["elevation"]["break_glass"].__setitem__(
            "post_use_review_hours", 0))
        self.assertIn("AUTHZ_BREAK_GLASS_REVIEW", self.codes(self._validate()))

    def test_rejects_quiet_break_glass(self):
        self.fixture.mutate(self.REL, lambda d: d["elevation"]["break_glass"].__setitem__(
            "notify_channels", ["email"]))
        self.assertIn("AUTHZ_BREAK_GLASS_NOTIFY", self.codes(self._validate()))

    def test_rejects_unlogged_decisions(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["audit"].__setitem__("record_every_decision", False))
        self.assertIn("AUTHZ_AUDIT_DECISIONS", self.codes(self._validate()))

    def test_rejects_unlogged_denials(self):
        self.fixture.mutate(self.REL, lambda d: d["audit"].__setitem__("record_denials", False))
        self.assertIn("AUTHZ_AUDIT_DENIALS", self.codes(self._validate()))

    def test_rejects_audit_without_rule_version(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["audit"].__setitem__("include_rule_version", False))
        self.assertIn("AUTHZ_AUDIT_RULE_VERSION", self.codes(self._validate()))

    def test_rejects_mutable_audit_trail(self):
        self.fixture.mutate(self.REL, lambda d: d["audit"].__setitem__("immutable", False))
        self.assertIn("AUTHZ_AUDIT_IMMUTABLE", self.codes(self._validate()))

    def test_rejects_a_model_with_no_privileged_role(self):
        def strip(d):
            for role in d["roles"]:
                role["privileged"] = False
        self.fixture.mutate(self.REL, strip)
        self.assertIn("AUTHZ_NO_PRIVILEGED_ROLE", self.codes(self._validate()))

    def test_rejects_privileged_role_without_phishing_resistant_mfa(self):
        self.fixture.mutate("governance/mfa.json", lambda d: next(
            r for r in d["requirements"] if r["role"] == "merchant-admin").__setitem__(
            "required_class", "any"))
        self.assertIn("AUTHZ_ROLE_NO_MFA", self.codes(self._validate()))

    def test_rejects_privileged_role_with_no_mfa_requirement_at_all(self):
        self.fixture.mutate("governance/mfa.json", lambda d: d.__setitem__(
            "requirements", [r for r in d["requirements"] if r["role"] != "risk-analyst"]))
        self.assertIn("AUTHZ_ROLE_NO_MFA", self.codes(self._validate()))

    def test_rejects_privileged_role_without_a_recovery_path(self):
        self.fixture.mutate("governance/identity.json", lambda d: d.__setitem__(
            "recovery", [r for r in d["recovery"] if r["subject"] != "break-glass"]))
        self.assertIn("AUTHZ_ROLE_NO_RECOVERY", self.codes(self._validate()))

    def test_rejects_role_without_a_zero_trust_principal(self):
        self.fixture.mutate(self.REL, lambda d: self._role(d, "auditor").__setitem__(
            "zero_trust_principal", "nobody"))
        self.assertIn("AUTHZ_ROLE_NO_ZT_PRINCIPAL", self.codes(self._validate()))

    def test_missing_cross_check_inputs_do_not_crash_the_gate(self):
        self.fixture.write("governance/mfa.json", "{ broken", encoding="utf-8")
        codes = self.codes(self._validate())
        self.assertIn("AUTHZ_ROLE_NO_MFA", codes)

    def test_budget_exhaustion_is_reraised(self):
        from tools.paygov.errors import BudgetExceeded
        with self.assertRaises(BudgetExceeded):
            authz.validate(self.fixture.root, Budget(seconds=0).start())


class AuthzDecisionFunction(FixtureTestCase):
    """The executable model: what it allows, what it refuses, and in what order."""

    def setUp(self):
        super().setUp()
        self.model = _model()
        self.finance = D.Principal(id="bob", role="merchant-finance", tenant="t-1")
        self.admin = D.Principal(id="alice", role="merchant-admin", tenant="t-1")
        self.support = D.Principal(id="sam", role="support-agent", tenant="t-1")
        self.operator = D.Principal(id="opal", role="platform-operator", tenant="platform")

    def _refund(self, created_by="alice", tenant="t-1"):
        return D.Resource(id="rfd-1", tenant=tenant, created_by=created_by)

    def _approval(self, approver="carol", role="merchant-finance", digest="digest-1",
                  issued_at=NOW - 60):
        return D.Approval(approver=approver, approver_role=role, request_digest=digest,
                          issued_at=issued_at)

    def _approve_refund(self, principal=None, **overrides):
        request = dict(permission="refund.approve", tenant="t-1", now=NOW, digest="digest-1",
                       resource=self._refund(), approval=self._approval())
        request.update(overrides)
        return D.decide(self.model, principal or self.finance, D.Request(**request))

    def test_the_happy_path_is_allowed(self):
        decision = self._approve_refund()
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, D.ALLOW)

    def test_the_maker_cannot_be_the_checker(self):
        # Same person, two ways: approving your own request, and executing the
        # approval of a thing you created. Both are the same failure.
        self.assertEqual(self._approve_refund(approval=self._approval(approver="bob")).reason,
                         D.DENY_SELF_APPROVAL)
        self.assertEqual(self._approve_refund(resource=self._refund(created_by="bob")).reason,
                         D.DENY_SEPARATION_OF_DUTIES)

    def test_an_approval_is_bound_to_this_request(self):
        replayed = self._approve_refund(digest="digest-2")
        self.assertEqual(replayed.reason, D.DENY_APPROVAL_NOT_BOUND)

    def test_an_approval_expires(self):
        self.assertEqual(self._approve_refund(
            approval=self._approval(issued_at=NOW - 4000)).reason, D.DENY_APPROVAL_EXPIRED)

    def test_an_approval_from_the_future_is_rejected(self):
        self.assertEqual(self._approve_refund(
            approval=self._approval(issued_at=NOW + 600)).reason, D.DENY_APPROVAL_EXPIRED)

    def test_the_approver_must_be_able_to_do_the_thing(self):
        self.assertEqual(self._approve_refund(
            approval=self._approval(approver="sam", role="support-agent")).reason,
            D.DENY_APPROVER_NOT_PERMITTED)

    def test_money_movement_without_any_approval_is_refused(self):
        self.assertEqual(self._approve_refund(approval=None).reason, D.DENY_MISSING_APPROVAL)

    def test_unknown_permission_is_denied(self):
        decision = D.decide(self.model, self.finance,
                            D.Request(permission="ghost.read", tenant="t-1", now=NOW))
        self.assertEqual(decision.reason, D.DENY_UNKNOWN_PERMISSION)

    def test_unknown_role_is_denied(self):
        ghost = D.Principal(id="g", role="ghost-role", tenant="t-1")
        decision = D.decide(self.model, ghost,
                            D.Request(permission="payment.read", tenant="t-1", now=NOW))
        self.assertEqual(decision.reason, D.DENY_UNKNOWN_ROLE)

    def test_a_permission_that_was_never_granted_is_denied(self):
        decision = D.decide(self.model, self.support,
                            D.Request(permission="payout.approve", tenant="t-1", now=NOW))
        self.assertEqual(decision.reason, D.DENY_NOT_GRANTED)

    def test_tenant_boundary_holds(self):
        decision = D.decide(self.model, self.finance,
                            D.Request(permission="payment.read", tenant="t-2", now=NOW))
        self.assertEqual(decision.reason, D.DENY_CROSS_TENANT)

    def test_object_ownership_is_checked_even_inside_the_right_tenant(self):
        self.assertEqual(self._approve_refund(resource=self._refund(tenant="t-2")).reason,
                         D.DENY_OBJECT_OWNERSHIP)

    def test_a_platform_role_still_cannot_read_across_tenants_without_the_permission(self):
        decision = D.decide(self.model, self.operator,
                            D.Request(permission="payment.read", tenant="t-9", now=NOW))
        self.assertEqual(decision.reason, D.DENY_CROSS_TENANT)

    def test_cross_tenant_read_works_only_through_elevation(self):
        grant = self.model.grant_elevation(requester=self.operator,
                                           permission="cross_tenant_data.read",
                                           approver="ivan", ticket="SEC-1", minutes=30, now=NOW)
        elevated = D.Principal(id="opal", role="platform-operator", tenant="platform",
                               elevations=(grant,))
        decision = D.decide(self.model, elevated,
                            D.Request(permission="payment.read", tenant="t-9", now=NOW))
        self.assertTrue(decision.allowed, decision.reason)

    def test_card_data_is_never_returned(self):
        decision = D.decide(self.model, self.admin,
                            D.Request(permission="customer_pii.read", tenant="t-1", now=NOW,
                                      resource=D.Resource(id="c", tenant="t-1"),
                                      fields=("customer_email", "card_pan")))
        self.assertEqual(decision.reason, D.DENY_FORBIDDEN_FIELD)
        self.assertFalse(decision.allowed)

    def test_fields_come_back_masked_by_default(self):
        decision = D.decide(self.model, self.support,
                            D.Request(permission="payment.read", tenant="t-1", now=NOW,
                                      resource=D.Resource(id="p", tenant="t-1"),
                                      fields=("customer_email", "bank_account_number")))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.masked_fields, ("bank_account_number",))

    def test_the_declared_reader_sees_the_full_field(self):
        decision = D.decide(self.model, self.finance,
                            D.Request(permission="bank_account.read", tenant="t-1", now=NOW,
                                      resource=D.Resource(id="a", tenant="t-1"),
                                      fields=("bank_account_number",)))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.masked_fields, ())

    def test_unknown_fields_are_ignored_not_leaked(self):
        decision = D.decide(self.model, self.support,
                            D.Request(permission="payment.read", tenant="t-1", now=NOW,
                                      resource=D.Resource(id="p", tenant="t-1"),
                                      fields=("not_a_field",)))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.masked_fields, ())

    def test_every_decision_is_auditable(self):
        allow = self._approve_refund()
        deny = self._approve_refund(approval=None)
        for decision in (allow, deny):
            self.assertEqual(decision.audit["rule_version"], self.model.version)
            self.assertEqual(decision.audit["principal"], "bob")
            self.assertIn(decision.audit["decision"], {"allow", "deny"})
        self.assertEqual(deny.audit["reason"], D.DENY_MISSING_APPROVAL)

    def test_elevation_is_required_expiring_and_revocable(self):
        request = D.Request(permission="config.write", tenant="platform", now=NOW, digest="d",
                            approval=D.Approval(approver="ivan",
                                                approver_role="platform-operator",
                                                request_digest="d", issued_at=NOW - 10))
        self.assertEqual(D.decide(self.model, self.operator, request).reason, D.DENY_NOT_GRANTED)
        grant = self.model.grant_elevation(requester=self.operator, permission="config.write",
                                           approver="ivan", ticket="OPS-1", minutes=30, now=NOW)
        elevated = D.Principal(id="opal", role="platform-operator", tenant="platform",
                               elevations=(grant,))
        allowed = D.decide(self.model, elevated, request)
        self.assertTrue(allowed.allowed, allowed.reason)
        self.assertEqual(allowed.audit["elevation_ticket"], "OPS-1")
        later = D.Request(permission="config.write", tenant="platform", now=NOW + 4000,
                          digest="d", approval=D.Approval(approver="ivan",
                                                          approver_role="platform-operator",
                                                          request_digest="d",
                                                          issued_at=NOW + 3999))
        self.assertEqual(D.decide(self.model, elevated, later).reason, D.DENY_ELEVATION_EXPIRED)
        revoked = D.Principal(id="opal", role="platform-operator", tenant="platform",
                              elevations=(D.Elevation(permission="config.write",
                                                      approved_by="ivan", ticket="OPS-1",
                                                      expires_at=NOW + 1800, revoked=True),))
        self.assertEqual(D.decide(self.model, revoked, request).reason, D.DENY_ELEVATION_REVOKED)

    def test_a_standing_grant_of_an_elevation_only_permission_is_refused_at_runtime(self):
        document = json.loads((REAL_ROOT / "governance/authorization.json").read_text(
            encoding="utf-8"))
        for role in document["roles"]:
            if role["id"] == "platform-operator":
                role["permissions"].append("config.write")
        model = D.Model(document)
        decision = D.decide(model, self.operator,
                            D.Request(permission="config.write", tenant="platform", now=NOW))
        self.assertEqual(decision.reason, D.DENY_ELEVATION_REQUIRED)

    def test_illegal_elevations_are_refused_at_grant_time(self):
        cases = [
            ("too long", dict(minutes=600)),
            ("self approved", dict(approver="opal")),
            ("no ticket", dict(ticket="")),
            ("not elevatable", dict(permission="refund.approve")),
            ("unknown permission", dict(permission="ghost.read")),
            ("zero minutes", dict(minutes=0)),
        ]
        for label, override in cases:
            args = dict(requester=self.operator, permission="config.write", approver="ivan",
                        ticket="OPS-1", minutes=30, now=NOW)
            args.update(override)
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    self.model.grant_elevation(**args)

    def test_the_auditor_can_never_be_elevated(self):
        auditor = D.Principal(id="ann", role="auditor", tenant="platform")
        with self.assertRaises(ValueError):
            self.model.grant_elevation(requester=auditor, permission="config.write",
                                       approver="ivan", ticket="OPS-1", minutes=10, now=NOW)

    def test_break_glass_gets_a_shorter_leash(self):
        glass = D.Principal(id="gus", role="break-glass", tenant="platform")
        limit = self.model.elevation["break_glass"]["max_duration_minutes"]
        with self.assertRaises(ValueError):
            self.model.grant_elevation(requester=glass, permission="cross_tenant_data.read",
                                       approver="ivan", ticket="SEC-1", minutes=limit + 1,
                                       now=NOW)
        grant = self.model.grant_elevation(requester=glass, permission="cross_tenant_data.read",
                                           approver="ivan", ticket="SEC-1", minutes=limit,
                                           now=NOW)
        self.assertEqual(grant.expires_at, NOW + limit * 60)

    def test_conflicting_permissions_are_derived_from_the_model(self):
        self.assertIn("refund.request", self.model.conflicting("refund.approve"))
        self.assertIn("payout_account.write", self.model.conflicting("payout.approve"))
        self.assertEqual(self.model.conflicting("payment.read"), set())

    def test_a_role_holding_both_sides_is_refused_at_runtime_too(self):
        document = json.loads((REAL_ROOT / "governance/authorization.json").read_text(
            encoding="utf-8"))
        for role in document["roles"]:
            if role["id"] == "merchant-finance":
                role["permissions"].append("refund.request")
        model = D.Model(document)
        decision = D.decide(model, self.finance,
                            D.Request(permission="refund.approve", tenant="t-1", now=NOW,
                                      digest="digest-1", resource=self._refund(),
                                      approval=self._approval()))
        self.assertEqual(decision.reason, D.DENY_SEPARATION_OF_DUTIES)

    def test_may_approve_covers_elevation_only_permissions(self):
        self.assertTrue(self.model.may_approve("platform-operator", "config.write"))
        self.assertFalse(self.model.may_approve("support-agent", "config.write"))
        self.assertFalse(self.model.may_approve("auditor", "config.write"))
        self.assertTrue(self.model.may_approve("merchant-finance", "refund.approve"))
