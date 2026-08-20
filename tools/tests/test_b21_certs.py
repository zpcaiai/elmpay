"""B21 / AT-B21-01 — key, certificate and domain lifecycle.

``test_both_versions_verify_during_the_overlap`` is the test this batch is for.
Rotation is the operation everyone postpones, and the reason they postpone it is
that a naive implementation cuts off every holder of the old material at the
same instant. The overlap window is what turns rotation from an outage into a
routine, and it is also the thing most easily dropped from a config file.

``test_revocation_beats_the_overlap_window`` is its counterweight: "it is still
inside its window" must never be a reason to accept a revoked credential.

The gate rules mirror the way this fails in production — not broken maths, but
an expiry date nobody was warned about, a renewal margin too small to act on, a
seven-day certificate renewed by hand, or a domain with no CAA record so any CA
on earth may issue for it.
"""
from __future__ import annotations

import json

from libs.pki.reference import lifecycle as L
from tools.paygov import certs, certsgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


def _model(root=REAL_ROOT) -> dict:
    return json.loads((root / "governance/certificates.json").read_text(encoding="utf-8"))


class CertificateModelHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = certs.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("certificates", registry.names())

    def test_the_lifecycle_covers_revocation_and_recovery(self):
        model = self.fixture.read("governance/certificates.json")
        self.assertEqual(model["lifecycle_stages"], certs.STAGES)
        self.assertIn("revoke", model["lifecycle_stages"])
        self.assertIn("recover", model["lifecycle_stages"])

    def test_every_material_has_a_margin_and_an_overlap(self):
        model = self.fixture.read("governance/certificates.json")
        for entry in model["materials"]:
            self.assertGreater(entry["renew_before_days"], 0, entry["id"])
            self.assertGreater(entry["overlap_days"], 0, entry["id"])
            self.assertLess(entry["renew_before_days"], entry["validity_days"], entry["id"])
            self.assertLessEqual(entry["overlap_days"], entry["validity_days"], entry["id"])

    def test_short_lived_material_renews_itself(self):
        model = self.fixture.read("governance/certificates.json")
        for entry in model["materials"]:
            if entry["validity_days"] <= certs.SHORT_LIVED_DAYS:
                self.assertTrue(entry["automated_renewal"], entry["id"])

    def test_manual_renewal_gets_a_human_sized_margin(self):
        model = self.fixture.read("governance/certificates.json")
        for entry in model["materials"]:
            if not entry["automated_renewal"]:
                self.assertGreaterEqual(entry["renew_before_days"], 30, entry["id"])

    def test_every_material_can_be_revoked(self):
        model = self.fixture.read("governance/certificates.json")
        for entry in model["materials"]:
            self.assertTrue(entry["revocation"], entry["id"])

    def test_every_domain_is_locked_signed_and_caa_bound(self):
        model = self.fixture.read("governance/certificates.json")
        for entry in model["domains"]:
            self.assertTrue(entry["registrar_lock"], entry["name"])
            self.assertTrue(entry["dnssec"], entry["name"])
            self.assertTrue(entry["caa_records"], entry["name"])
            self.assertGreaterEqual(entry["renew_before_days"], 30, entry["name"])

    def test_the_internal_domain_does_not_trust_public_cas(self):
        model = self.fixture.read("governance/certificates.json")
        internal = next(d for d in model["domains"] if d["purpose"] == "internal")
        self.assertNotIn("public_ca", internal["caa_records"])

    def test_alerting_escalates_and_watches_transparency_logs(self):
        model = self.fixture.read("governance/certificates.json")
        alerting = model["alerting"]
        self.assertGreaterEqual(len(alerting["channels"]), 2)
        self.assertLessEqual(alerting["escalate_after_failed_renewals"], 3)
        self.assertTrue(alerting["certificate_transparency_monitoring"])
        self.assertTrue(alerting["alert_on_unexpected_issuer"])

    def test_recovery_is_rehearsed_bounded_and_quorate(self):
        model = self.fixture.read("governance/certificates.json")
        recovery = model["recovery"]
        self.assertTrue(recovery["rehearsed"])
        self.assertLessEqual(recovery["rehearsal_interval_days"], 365)
        self.assertLessEqual(recovery["max_recovery_hours"], 24)
        self.assertTrue(recovery["quorum_required"])
        self.assertTrue(recovery["offline_backup_of_ca"])

    def test_every_material_names_a_managed_key(self):
        model = self.fixture.read("governance/certificates.json")
        keys = self.fixture.read("governance/key-management.json")
        managed = {k["id"] for k in keys["keys"]}
        for entry in model["materials"]:
            self.assertIn(entry["key_id"], managed, entry["id"])

    def test_hsm_backed_provider_keys_all_have_an_expiry_date(self):
        model = self.fixture.read("governance/certificates.json")
        keys = self.fixture.read("governance/key-management.json")
        subjects = " ".join(m["subject"] + " " + m["id"] for m in model["materials"])
        for entry in keys["provider_keys"]:
            if entry["material"] == "hsm_backed":
                self.assertIn(entry["provider"].split("-")[0], subjects, entry["provider"])


class CertificateGeneratedArtefacts(FixtureTestCase):
    def test_generated_artefacts_match_the_model(self):
        for rel, content in certsgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_inventory_lists_every_material_and_domain(self):
        inventory = json.loads(certsgen.inventory_json(REAL_ROOT))
        model = _model()
        self.assertEqual({m["id"] for m in inventory["materials"]},
                         {m["id"] for m in model["materials"]})
        self.assertEqual({d["name"] for d in inventory["domains"]},
                         {d["name"] for d in model["domains"]})

    def test_document_names_every_material(self):
        text = certsgen.certs_markdown(REAL_ROOT)
        for entry in _model()["materials"]:
            self.assertIn(entry["id"], text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/security/CERTIFICATE_LIFECYCLE.md", "hand written\n")
        codes = self.codes(certs.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("CERT_GENERATED_DRIFT", codes)

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/security/certificate-inventory.json")
        codes = self.codes(certs.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("CERT_GENERATED_MISSING", codes)

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate("governance/certificates.json",
                            lambda d: d.__setitem__("materials", [{"id": "x"}]))
        codes = self.codes(certs.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("CERT_GENERATED", codes)


class CertificateGateRejects(FixtureTestCase):
    REL = "governance/certificates.json"

    def _validate(self):
        return certs.validate(self.fixture.root, Budget(seconds=60).start())

    def _material(self, d, mid):
        return next(m for m in d["materials"] if m["id"] == mid)

    def _domain(self, d, name):
        return next(x for x in d["domains"] if x["name"] == name)

    def test_rejects_unreadable_model(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("CERT_UNREADABLE", self.codes(self._validate()))

    def test_rejects_non_object_model(self):
        self.fixture.write(self.REL, [1])
        self.assertIn("CERT_SHAPE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "v1"))
        self.assertIn("CERT_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_missing_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("CERT_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_a_lifecycle_that_stops_before_revocation(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "lifecycle_stages", ["generate", "distribute", "activate", "overlap", "rotate"]))
        self.assertIn("CERT_STAGES", self.codes(self._validate()))

    def test_rejects_bad_material_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._material(d, "edge-tls").__setitem__("id", "Edge"))
        self.assertIn("CERT_ID", self.codes(self._validate()))

    def test_rejects_duplicate_material(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["materials"].append(dict(self._material(d, "edge-tls"))))
        self.assertIn("CERT_DUPLICATE", self.codes(self._validate()))

    def test_rejects_unknown_material_kind(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._material(d, "edge-tls").__setitem__("kind", "vibes"))
        self.assertIn("CERT_KIND", self.codes(self._validate()))

    def test_rejects_unowned_material(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._material(d, "edge-tls").__setitem__("owner", ""))
        self.assertIn("CERT_OWNER", self.codes(self._validate()))

    def test_rejects_material_without_notes(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._material(d, "edge-tls").__setitem__("notes", ""))
        self.assertIn("CERT_NOTES", self.codes(self._validate()))

    def test_rejects_material_with_no_revocation_route(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._material(d, "edge-tls").__setitem__("revocation", ""))
        self.assertIn("CERT_NO_REVOCATION", self.codes(self._validate()))

    def test_rejects_material_with_no_validity(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._material(d, "edge-tls").__setitem__("validity_days", 0))
        self.assertIn("CERT_NO_VALIDITY", self.codes(self._validate()))

    def test_rejects_a_margin_too_small_to_act_on(self):
        self.fixture.mutate(self.REL, lambda d: self._material(d, "edge-tls").__setitem__(
            "renew_before_days", 2))
        self.assertIn("CERT_RENEW_MARGIN", self.codes(self._validate()))

    def test_rejects_no_margin_at_all(self):
        self.fixture.mutate(self.REL, lambda d: self._material(d, "edge-tls").__setitem__(
            "renew_before_days", 0))
        self.assertIn("CERT_RENEW_MARGIN", self.codes(self._validate()))

    def test_rejects_a_margin_longer_than_the_lifetime(self):
        self.fixture.mutate(self.REL, lambda d: self._material(d, "edge-tls").__setitem__(
            "renew_before_days", 120))
        self.assertIn("CERT_RENEW_MARGIN", self.codes(self._validate()))

    def test_rejects_rotation_without_an_overlap(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._material(d, "edge-tls").__setitem__("overlap_days", 0))
        self.assertIn("CERT_NO_OVERLAP", self.codes(self._validate()))

    def test_rejects_an_overlap_longer_than_the_material(self):
        self.fixture.mutate(self.REL, lambda d: self._material(d, "edge-tls").__setitem__(
            "overlap_days", 200))
        self.assertIn("CERT_OVERLAP_TOO_LONG", self.codes(self._validate()))

    def test_rejects_hand_renewed_short_lived_material(self):
        self.fixture.mutate(self.REL, lambda d: self._material(d, "internal-mtls").__setitem__(
            "automated_renewal", False))
        self.assertIn("CERT_MANUAL_SHORT_LIVED", self.codes(self._validate()))

    def test_rejects_a_manual_renewal_with_an_automation_sized_margin(self):
        def shrink(d):
            entry = self._material(d, "provider-signing-wechat")
            entry["renew_before_days"] = 20
        self.fixture.mutate(self.REL, shrink)
        self.assertIn("CERT_MANUAL_MARGIN", self.codes(self._validate()))

    def test_rejects_a_domain_without_a_registrar_lock(self):
        self.fixture.mutate(self.REL, lambda d: self._domain(d, "pay.example.invalid")
                            .__setitem__("registrar_lock", False))
        self.assertIn("DOMAIN_NO_LOCK", self.codes(self._validate()))

    def test_rejects_a_domain_without_dnssec(self):
        self.fixture.mutate(self.REL, lambda d: self._domain(d, "pay.example.invalid")
                            .__setitem__("dnssec", False))
        self.assertIn("DOMAIN_NO_DNSSEC", self.codes(self._validate()))

    def test_rejects_a_domain_without_caa(self):
        self.fixture.mutate(self.REL, lambda d: self._domain(d, "pay.example.invalid")
                            .__setitem__("caa_records", []))
        self.assertIn("DOMAIN_NO_CAA", self.codes(self._validate()))

    def test_rejects_a_domain_with_no_renewal_schedule(self):
        self.fixture.mutate(self.REL, lambda d: self._domain(d, "pay.example.invalid")
                            .__setitem__("expires_in_days", 0))
        self.assertIn("DOMAIN_NO_RENEWAL", self.codes(self._validate()))

    def test_rejects_a_last_minute_domain_renewal(self):
        self.fixture.mutate(self.REL, lambda d: self._domain(d, "pay.example.invalid")
                            .__setitem__("renew_before_days", 3))
        self.assertIn("DOMAIN_RENEW_MARGIN", self.codes(self._validate()))

    def test_rejects_a_duplicate_domain(self):
        self.fixture.mutate(self.REL, lambda d: d["domains"].append(
            dict(self._domain(d, "pay.example.invalid"))))
        self.assertIn("DOMAIN_DUPLICATE", self.codes(self._validate()))

    def test_rejects_an_unowned_domain(self):
        self.fixture.mutate(self.REL, lambda d: self._domain(d, "pay.example.invalid")
                            .__setitem__("owner", ""))
        self.assertIn("DOMAIN_OWNER", self.codes(self._validate()))

    def test_rejects_a_single_alert_channel(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["alerting"].__setitem__("channels", ["email"]))
        self.assertIn("CERT_ALERT_CHANNELS", self.codes(self._validate()))

    def test_rejects_silent_renewal_retries(self):
        self.fixture.mutate(self.REL, lambda d: d["alerting"].__setitem__(
            "escalate_after_failed_renewals", 99))
        self.assertIn("CERT_NO_ESCALATION", self.codes(self._validate()))

    def test_rejects_dropping_transparency_monitoring(self):
        self.fixture.mutate(self.REL, lambda d: d["alerting"].__setitem__(
            "certificate_transparency_monitoring", False))
        self.assertIn("CERT_NO_CT_MONITORING", self.codes(self._validate()))

    def test_rejects_ignoring_unexpected_issuers(self):
        self.fixture.mutate(self.REL, lambda d: d["alerting"].__setitem__(
            "alert_on_unexpected_issuer", False))
        self.assertIn("CERT_NO_ISSUER_ALERT", self.codes(self._validate()))

    def test_rejects_an_unrehearsed_recovery_path(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["recovery"].__setitem__("rehearsed", False))
        self.assertIn("CERT_UNREHEARSED_RECOVERY", self.codes(self._validate()))

    def test_rejects_a_rehearsal_that_never_comes_round(self):
        self.fixture.mutate(self.REL, lambda d: d["recovery"].__setitem__(
            "rehearsal_interval_days", 3650))
        self.assertIn("CERT_REHEARSAL_INTERVAL", self.codes(self._validate()))

    def test_rejects_an_unbounded_recovery_objective(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["recovery"].__setitem__("max_recovery_hours", 0))
        self.assertIn("CERT_RECOVERY_TIME", self.codes(self._validate()))

    def test_rejects_recovery_without_a_quorum(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["recovery"].__setitem__("quorum_required", False))
        self.assertIn("CERT_RECOVERY_QUORUM", self.codes(self._validate()))

    def test_rejects_missing_ca_backup(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["recovery"].__setitem__("offline_backup_of_ca", False))
        self.assertIn("CERT_NO_CA_BACKUP", self.codes(self._validate()))

    def test_rejects_self_signed_certificates_at_the_edge(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["forbidden"].__setitem__("self_signed_at_edge", True))
        self.assertIn("CERT_SELF_SIGNED_EDGE", self.codes(self._validate()))

    def test_rejects_sharing_keys_between_environments(self):
        self.fixture.mutate(self.REL, lambda d: d["forbidden"].__setitem__(
            "shared_key_across_environments", True))
        self.assertIn("CERT_SHARED_ENVIRONMENT_KEY", self.codes(self._validate()))

    def test_rejects_material_outside_the_key_hierarchy(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._material(d, "edge-tls").__setitem__("key_id", "ghost"))
        self.assertIn("CERT_KEY_UNMANAGED", self.codes(self._validate()))

    def test_rejects_dropping_an_hsm_backed_provider(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "materials", [m for m in d["materials"] if "apple" not in m["id"]]))
        self.assertIn("CERT_PROVIDER_UNTRACKED", self.codes(self._validate()))

    def test_rejects_a_signing_key_that_outlives_its_identity_rotation(self):
        def slow(d):
            entry = self._material(d, "provider-signing-wechat")
            entry["subject"] = "customer-idp"
            entry["validity_days"] = 3650
            entry["renew_before_days"] = 60
            entry["overlap_days"] = 30
        self.fixture.mutate(self.REL, slow)
        self.assertIn("CERT_ROTATION_SLOWER_THAN_IDENTITY", self.codes(self._validate()))

    def test_missing_cross_check_inputs_do_not_crash_the_gate(self):
        self.fixture.write("governance/key-management.json", "{ broken",
                                                                          encoding="utf-8")
        codes = self.codes(self._validate())
        self.assertIn("CERT_KEY_UNMANAGED", codes)

    def test_budget_exhaustion_is_reraised(self):
        from tools.paygov.errors import BudgetExceeded
        with self.assertRaises(BudgetExceeded):
            certs.validate(self.fixture.root, Budget(seconds=0).start())

    def test_rejects_a_domain_without_notes(self):
        self.fixture.mutate(self.REL, lambda d: next(
            x for x in d["domains"] if x["name"] == "pay.example.invalid")
            .__setitem__("notes", ""))
        self.assertIn("DOMAIN_NOTES", self.codes(self._validate()))

    def test_rejects_a_warning_threshold_below_the_renewal_margin(self):
        # The warning ratio governs short-lived automated material; if it fires
        # later than the renewal itself, the alert is decoration.
        self.fixture.mutate(self.REL,
                            lambda d: d["alerting"].__setitem__("expiry_warning_ratio", 0.9))
        self.assertIn("CERT_ALERT_THRESHOLD", self.codes(self._validate()))

    def test_rejects_a_nonsense_warning_threshold(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["alerting"].__setitem__("expiry_warning_ratio", 0))
        self.assertIn("CERT_ALERT_THRESHOLD", self.codes(self._validate()))


class LifecycleReference(FixtureTestCase):
    """The executable lifecycle: rotation, overlap, revocation, escalation."""

    def setUp(self):
        super().setUp()
        self.model = _model()
        self.estate = L.Estate(self.model)
        self.estate.issue_all(day=0)
        self.token = self.estate.materials["token-signing"]

    def _refuses(self, fn, code):
        with self.assertRaises(L.LifecycleError) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)

    def test_a_fresh_material_is_ok_then_due_then_expired(self):
        validity = self.token.validity_days
        margin = self.token.renew_before_days
        self.assertEqual(self.token.status(1), L.OK)
        self.assertEqual(self.token.status(validity - margin), L.RENEW_DUE)
        self.assertEqual(self.token.status(validity), L.EXPIRED)

    def test_both_versions_verify_during_the_overlap(self):
        day = self.token.validity_days - self.token.renew_before_days
        new = self.token.rotate(day)
        self.assertEqual(self.token.accepting(day), [1, new.serial])
        self.assertEqual(self.estate.verify("token-signing", 1, day), L.OK)
        self.assertEqual(self.estate.verify("token-signing", new.serial, day), L.OK)

    def test_the_old_version_stops_when_the_overlap_ends(self):
        day = self.token.validity_days - self.token.renew_before_days
        self.token.rotate(day)
        end = day + self.token.overlap_days
        self.assertEqual(self.estate.verify("token-signing", 1, end - 1), L.OK)
        self._refuses(lambda: self.estate.verify("token-signing", 1, end), L.EXPIRED)

    def test_an_overlap_never_outlives_the_material_itself(self):
        edge = self.estate.materials["edge-tls"]
        edge.rotate(edge.validity_days - 1)
        self._refuses(lambda: self.estate.verify("edge-tls", 1, edge.validity_days), L.EXPIRED)

    def test_revocation_beats_the_overlap_window(self):
        webhook = self.estate.materials["webhook-verification"]
        webhook.rotate(10)
        self.assertEqual(self.estate.verify("webhook-verification", 1, 11), L.OK)
        webhook.revoke(1, 11)
        self._refuses(lambda: self.estate.verify("webhook-verification", 1, 11), L.REVOKED)

    def test_revocation_is_scoped_to_one_version(self):
        webhook = self.estate.materials["webhook-verification"]
        webhook.rotate(10)
        webhook.revoke(1, 11)
        self.assertEqual(self.estate.verify("webhook-verification", 2, 11), L.OK)

    def test_revoking_an_unknown_version_is_refused(self):
        self._refuses(lambda: self.token.revoke(99, 1), L.UNKNOWN)

    def test_verifying_an_unknown_material_is_refused(self):
        self._refuses(lambda: self.estate.verify("ghost", 1, 1), L.UNKNOWN)

    def test_verifying_an_unissued_serial_is_refused(self):
        self._refuses(lambda: self.estate.verify("token-signing", 7, 1), L.UNKNOWN)

    def test_a_material_that_was_never_issued_has_no_current_version(self):
        orphan = L.Material(id="orphan", validity_days=10, renew_before_days=3,
                            overlap_days=1, automated_renewal=True, issuer="self")
        self._refuses(orphan.current, L.UNKNOWN)
        self.assertEqual(orphan.status(0), L.UNKNOWN)

    def test_renewal_failures_escalate_and_reset(self):
        escalate = self.estate.escalate_after
        results = [self.estate.renewal_failed("internal-mtls") for _ in range(escalate)]
        self.assertEqual(results[:-1], [False] * (escalate - 1))
        self.assertTrue(results[-1])
        self.estate.materials["internal-mtls"].record_renewal_success()
        self.assertEqual(self.estate.materials["internal-mtls"].failed_renewals, 0)

    def test_the_due_list_names_what_needs_attention(self):
        day = self.token.validity_days - self.token.renew_before_days
        self.assertIn("token-signing", self.estate.due(day))
        self.assertEqual(self.estate.due(1), [])

    def test_an_unauthorised_issuer_is_refused_for_the_internal_domain(self):
        self._refuses(
            lambda: self.estate.accept_issued_certificate("internal.pay.example.invalid",
                                                          "public_ca"),
            L.UNAUTHORISED_ISSUER)

    def test_the_authorised_issuer_is_accepted(self):
        self.assertEqual(
            self.estate.accept_issued_certificate("pay.example.invalid", "public_ca"), L.OK)

    def test_an_unknown_domain_is_refused(self):
        self._refuses(lambda: self.estate.accept_issued_certificate("evil.invalid", "public_ca"),
                      L.UNKNOWN)

    def test_domain_status_tracks_its_own_expiry(self):
        domain = self.estate.domains["pay.example.invalid"]
        self.assertEqual(domain.status(1), L.OK)
        self.assertEqual(domain.status(domain.expires_day - domain.renew_before_days),
                         L.RENEW_DUE)
        self.assertEqual(domain.status(domain.expires_day), L.EXPIRED)

    def test_recovery_requires_a_quorum(self):
        self._refuses(lambda: self.estate.recover(approvals=1, quorum=2), "QUORUM_NOT_MET")
        self.assertEqual(self.estate.recover(approvals=2, quorum=2), L.OK)

    def test_an_unrehearsed_recovery_path_is_refused(self):
        model = json.loads(json.dumps(self.model))
        model["recovery"]["rehearsed"] = False
        estate = L.Estate(model)
        with self.assertRaises(L.LifecycleError) as caught:
            estate.recover(approvals=3, quorum=2)
        self.assertEqual(caught.exception.code, "UNREHEARSED")

    def test_a_version_is_not_accepted_before_it_is_issued(self):
        later = self.token.issue(100)
        self.assertNotIn(later.serial, self.token.accepting(50))
        self.assertIn(later.serial, self.token.accepting(101))

    def test_rotation_can_be_repeated_without_reviving_older_versions(self):
        first = self.token.rotate(10)
        second = self.token.rotate(20)
        accepting = self.token.accepting(20)
        self.assertIn(second.serial, accepting)
        self.assertIn(first.serial, accepting)
        self.assertNotIn(1, self.token.accepting(10 + self.token.overlap_days))
