"""B23 / AT-B23-01 — non-repudiation and tamper-evident logging.

Two tests carry this batch, and they say opposite things on purpose.

``test_a_forger_who_recomputes_one_hash_still_breaks_the_next_link`` is the
positive claim: an attacker with write access who edits a record and dutifully
recomputes its hash still cannot make the chain verify, because the record after
it commits to the old value.

``test_tail_truncation_is_undetectable_without_an_anchor`` is the honest one. A
hash chain cannot detect its own tail being removed — that is a property of the
construction, not a defect in this implementation — so the batch ships an
anchoring mechanism and reports the size of the window that stays deniable
instead of pretending it is zero. A control that overstates itself is worse than
one that names its limit.
"""
from __future__ import annotations

import json

from libs.audit.reference import chain as C
from tools.paygov import audit, auditgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


def _policy(root=REAL_ROOT) -> dict:
    return json.loads((root / "governance/audit-log.json").read_text(encoding="utf-8"))


def _ledger(count: int = 5, tenant: str = "t-1") -> C.Ledger:
    ledger = C.Ledger(tenant_id=tenant)
    for index in range(count):
        ledger.append(occurred_at=1000 + index * 10, event_class="authz.decision",
                      actor=f"user-{index}", action="refund.approve", decision="allow",
                      rule_version="1.0.0", payload={"amount_minor": 100 + index})
    return ledger


class AuditPolicyHappyPath(FixtureTestCase):
    def test_real_policy_passes(self):
        problems = audit.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("audit-log", registry.names())

    def test_the_chain_hashes_sequence_and_predecessor(self):
        chain = self.fixture.read("governance/audit-log.json")["hash_chain"]
        self.assertIn(chain["algorithm"], audit.STRONG_HASHES)
        self.assertTrue(chain["includes_previous_hash"])
        self.assertTrue(chain["includes_sequence"])
        self.assertTrue(chain["per_tenant_chain"])
        self.assertTrue(chain["canonical_serialisation"])

    def test_anchoring_is_required_and_bounded(self):
        anchoring = self.fixture.read("governance/audit-log.json")["anchoring"]
        self.assertTrue(anchoring["required"])
        self.assertLessEqual(anchoring["interval_minutes"], 1440)
        self.assertTrue(anchoring["witness"])
        self.assertGreaterEqual(anchoring["anchor_retention_days"], 365)

    def test_the_anchor_key_is_managed_by_b20(self):
        policy = self.fixture.read("governance/audit-log.json")
        keys = self.fixture.read("governance/key-management.json")
        self.assertIn(policy["anchoring"]["signed_by_key"], {k["id"] for k in keys["keys"]})

    def test_records_carry_the_rule_version_and_forbid_card_data(self):
        records = self.fixture.read("governance/audit-log.json")["records"]
        self.assertLessEqual(audit.MINIMUM_FIELDS, set(records["required_fields"]))
        self.assertLessEqual(audit.NEVER_LOGGED, set(records["forbidden_fields"]))
        self.assertTrue(records["records_denials"])

    def test_every_dual_control_action_is_audited(self):
        policy = self.fixture.read("governance/audit-log.json")
        authz = self.fixture.read("governance/authorization.json")
        audited = set(policy["audited_actions"])
        for permission in authz["permissions"]:
            if permission["dual_control"] or permission["elevation_required"]:
                self.assertIn(permission["id"], audited)

    def test_storage_is_append_only_and_separately_credentialed(self):
        storage = self.fixture.read("governance/audit-log.json")["storage"]
        self.assertTrue(storage["append_only"])
        self.assertTrue(storage["worm_backend"])
        self.assertTrue(storage["separate_credentials_from_application"])
        self.assertTrue(storage["delete_requires_key_destruction"])

    def test_personal_data_can_be_erased_without_losing_the_proof(self):
        policy = self.fixture.read("governance/audit-log.json")
        redaction = policy["redaction"]
        self.assertTrue(redaction["payload_crypto_shredding"])
        self.assertTrue(redaction["content_hash_retained"])
        self.assertTrue(redaction["shredding_preserves_chain"])
        self.assertTrue(any(c["contains_pii"] for c in policy["event_classes"]))

    def test_the_reader_is_the_non_elevatable_auditor(self):
        policy = self.fixture.read("governance/audit-log.json")
        authz = self.fixture.read("governance/authorization.json")
        reader = policy["access"]["reader_role"]
        self.assertIn(reader, {r["id"] for r in authz["roles"]})
        self.assertIn(reader, authz["elevation"]["non_elevatable_roles"])
        self.assertTrue(policy["access"]["access_is_itself_audited"])

    def test_verification_is_rehearsed_and_independently_runnable(self):
        verification = self.fixture.read("governance/audit-log.json")["verification"]
        self.assertTrue(verification["rehearsed"])
        self.assertLessEqual(verification["rehearsal_interval_days"], 365)
        self.assertTrue(verification["independent_verifier"])

    def test_money_records_outlive_the_data_they_describe(self):
        policy = self.fixture.read("governance/audit-log.json")
        data = self.fixture.read("governance/data-architecture.json")
        floors = [t["retention"]["cold_days"] for t in data["tables"]
                  if t["mutability"] == "append_only"]
        money = next(c for c in policy["event_classes"] if c["id"] == "money.movement")
        self.assertGreaterEqual(money["retention_days"], max(floors))


class AuditGeneratedArtefacts(FixtureTestCase):
    def test_generated_artefacts_match_the_policy(self):
        for rel, content in auditgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_lists_every_event_class(self):
        contract = json.loads(auditgen.contract_json(REAL_ROOT))
        self.assertEqual({c["id"] for c in contract["event_classes"]},
                         {c["id"] for c in _policy()["event_classes"]})

    def test_document_states_the_deniable_window(self):
        text = auditgen.audit_markdown(REAL_ROOT)
        self.assertIn("可被否认窗口", text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/security/AUDIT_LOG.md", "hand written\n")
        codes = self.codes(audit.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("AUDIT_GENERATED_DRIFT", codes)

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/security/audit-contract.json")
        codes = self.codes(audit.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("AUDIT_GENERATED_MISSING", codes)

    def test_unrenderable_policy_fails_closed(self):
        self.fixture.mutate("governance/audit-log.json",
                            lambda d: d.__setitem__("event_classes", [{"id": "x.y"}]))
        codes = self.codes(audit.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("AUDIT_GENERATED", codes)


class AuditGateRejects(FixtureTestCase):
    REL = "governance/audit-log.json"

    def _validate(self):
        return audit.validate(self.fixture.root, Budget(seconds=60).start())

    def _class(self, d, cid):
        return next(c for c in d["event_classes"] if c["id"] == cid)

    def test_rejects_unreadable_policy(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("AUDIT_UNREADABLE", self.codes(self._validate()))

    def test_rejects_non_object_policy(self):
        self.fixture.write(self.REL, [1])
        self.assertIn("AUDIT_SHAPE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("AUDIT_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_missing_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("AUDIT_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_removing_the_chain(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("hash_chain", None))
        self.assertIn("AUDIT_NO_CHAIN", self.codes(self._validate()))

    def test_rejects_a_weak_chain_hash(self):
        self.fixture.mutate(self.REL, lambda d: d["hash_chain"].__setitem__("algorithm", "MD5"))
        self.assertIn("AUDIT_WEAK_HASH", self.codes(self._validate()))

    def test_rejects_dropping_the_previous_hash(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["hash_chain"].__setitem__("includes_previous_hash", False))
        self.assertIn("AUDIT_NO_CHAIN", self.codes(self._validate()))

    def test_rejects_dropping_the_sequence(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["hash_chain"].__setitem__("includes_sequence", False))
        self.assertIn("AUDIT_NO_SEQUENCE", self.codes(self._validate()))

    def test_rejects_one_shared_chain_for_every_tenant(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["hash_chain"].__setitem__("per_tenant_chain", False))
        self.assertIn("AUDIT_SHARED_CHAIN", self.codes(self._validate()))

    def test_rejects_an_unspecified_serialisation(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["hash_chain"].__setitem__("canonical_serialisation", ""))
        self.assertIn("AUDIT_NO_CANONICAL_FORM", self.codes(self._validate()))

    def test_rejects_dropping_anchoring(self):
        self.fixture.mutate(self.REL, lambda d: d["anchoring"].__setitem__("required", False))
        self.assertIn("AUDIT_NO_ANCHOR", self.codes(self._validate()))

    def test_rejects_an_unbounded_anchor_interval(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["anchoring"].__setitem__("interval_minutes", 100000))
        self.assertIn("AUDIT_ANCHOR_INTERVAL", self.codes(self._validate()))

    def test_rejects_anchors_nobody_else_holds(self):
        self.fixture.mutate(self.REL, lambda d: d["anchoring"].__setitem__("witness", ""))
        self.assertIn("AUDIT_NO_WITNESS", self.codes(self._validate()))

    def test_rejects_unsigned_anchors(self):
        self.fixture.mutate(self.REL, lambda d: d["anchoring"].__setitem__("signed_by_key", ""))
        self.assertIn("AUDIT_ANCHOR_UNSIGNED", self.codes(self._validate()))

    def test_rejects_an_anchor_key_outside_the_key_hierarchy(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["anchoring"].__setitem__("signed_by_key", "ghost"))
        self.assertIn("AUDIT_ANCHOR_KEY_UNMANAGED", self.codes(self._validate()))

    def test_rejects_anchors_that_expire_before_the_records(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["anchoring"].__setitem__("anchor_retention_days", 30))
        self.assertIn("AUDIT_ANCHOR_RETENTION", self.codes(self._validate()))

    def test_rejects_dropping_the_rule_version_field(self):
        self.fixture.mutate(self.REL, lambda d: d["records"].__setitem__(
            "required_fields", [f for f in d["records"]["required_fields"]
                                if f != "rule_version"]))
        self.assertIn("AUDIT_MISSING_FIELD", self.codes(self._validate()))

    def test_rejects_allowing_card_data_in_the_log(self):
        self.fixture.mutate(self.REL, lambda d: d["records"].__setitem__(
            "forbidden_fields", ["password"]))
        self.assertIn("AUDIT_FORBIDDEN_FIELD", self.codes(self._validate()))

    def test_rejects_not_recording_denials(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["records"].__setitem__("records_denials", False))
        self.assertIn("AUDIT_NO_DENIALS", self.codes(self._validate()))

    def test_rejects_anonymous_actors(self):
        self.fixture.mutate(self.REL, lambda d: d["records"].__setitem__(
            "actor_must_be_resolvable", False))
        self.assertIn("AUDIT_ANONYMOUS_ACTOR", self.codes(self._validate()))

    def test_rejects_a_bad_event_class_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._class(d, "key.use").__setitem__("id", "KeyUse"))
        self.assertIn("AUDIT_CLASS_ID", self.codes(self._validate()))

    def test_rejects_a_duplicate_event_class(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["event_classes"].append(dict(self._class(d, "key.use"))))
        self.assertIn("AUDIT_CLASS_DUPLICATE", self.codes(self._validate()))

    def test_rejects_an_event_class_without_a_source(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._class(d, "key.use").__setitem__("source", ""))
        self.assertIn("AUDIT_CLASS_SOURCE", self.codes(self._validate()))

    def test_rejects_an_implicit_pii_flag(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._class(d, "key.use").__setitem__("contains_pii", "no"))
        self.assertIn("AUDIT_PII_FLAG", self.codes(self._validate()))

    def test_rejects_an_event_class_without_notes(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._class(d, "key.use").__setitem__("notes", ""))
        self.assertIn("AUDIT_CLASS_NOTES", self.codes(self._validate()))

    def test_rejects_short_retention(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._class(d, "key.use").__setitem__("retention_days", 30))
        self.assertIn("AUDIT_RETENTION_SHORT", self.codes(self._validate()))

    def test_rejects_audit_records_shorter_lived_than_the_data(self):
        self.fixture.mutate(self.REL, lambda d: self._class(d, "money.movement")
                            .__setitem__("retention_days", 400))
        self.assertIn("AUDIT_RETENTION_BELOW_DATA", self.codes(self._validate()))

    def test_rejects_mutable_storage(self):
        self.fixture.mutate(self.REL, lambda d: d["storage"].__setitem__("append_only", False))
        self.assertIn("AUDIT_MUTABLE_STORAGE", self.codes(self._validate()))

    def test_rejects_dropping_worm_storage(self):
        self.fixture.mutate(self.REL, lambda d: d["storage"].__setitem__("worm_backend", False))
        self.assertIn("AUDIT_NO_WORM", self.codes(self._validate()))

    def test_rejects_the_application_being_able_to_delete_the_log(self):
        self.fixture.mutate(self.REL, lambda d: d["storage"].__setitem__(
            "separate_credentials_from_application", False))
        self.assertIn("AUDIT_SHARED_CREDENTIALS", self.codes(self._validate()))

    def test_rejects_plain_deletion(self):
        self.fixture.mutate(self.REL, lambda d: d["storage"].__setitem__(
            "delete_requires_key_destruction", False))
        self.assertIn("AUDIT_DELETABLE", self.codes(self._validate()))

    def test_rejects_removing_crypto_shredding(self):
        self.fixture.mutate(self.REL, lambda d: d["redaction"].__setitem__(
            "payload_crypto_shredding", False))
        codes = self.codes(self._validate())
        self.assertIn("AUDIT_NO_SHREDDING", codes)
        self.assertIn("AUDIT_PII_UNSHREDDABLE", codes)

    def test_rejects_shredding_that_destroys_the_proof(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["redaction"].__setitem__("content_hash_retained", False))
        self.assertIn("AUDIT_SHRED_LOSES_PROOF", self.codes(self._validate()))

    def test_rejects_shredding_that_breaks_the_chain(self):
        self.fixture.mutate(self.REL, lambda d: d["redaction"].__setitem__(
            "shredding_preserves_chain", False))
        self.assertIn("AUDIT_SHRED_BREAKS_CHAIN", self.codes(self._validate()))

    def test_rejects_an_unnamed_time_source(self):
        self.fixture.mutate(self.REL, lambda d: d["clock"].__setitem__("source", ""))
        self.assertIn("AUDIT_CLOCK_SOURCE", self.codes(self._validate()))

    def test_rejects_unbounded_clock_skew(self):
        self.fixture.mutate(self.REL, lambda d: d["clock"].__setitem__("max_skew_seconds", 86400))
        self.assertIn("AUDIT_CLOCK_SKEW", self.codes(self._validate()))

    def test_rejects_a_reader_who_can_write(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["access"].__setitem__("reader_cannot_write", False))
        self.assertIn("AUDIT_READER_WRITES", self.codes(self._validate()))

    def test_rejects_an_elevatable_reader(self):
        self.fixture.mutate(self.REL, lambda d: d["access"].__setitem__(
            "reader_cannot_be_elevated", False))
        self.assertIn("AUDIT_READER_ELEVATABLE", self.codes(self._validate()))

    def test_rejects_a_reader_role_b19_does_not_define(self):
        self.fixture.mutate(self.REL, lambda d: d["access"].__setitem__("reader_role", "ghost"))
        self.assertIn("AUDIT_READER_UNKNOWN", self.codes(self._validate()))

    def test_rejects_a_reader_b19_allows_to_be_elevated(self):
        self.fixture.mutate("governance/authorization.json", lambda d: d["elevation"].__setitem__(
            "non_elevatable_roles",
            [r for r in d["elevation"]["non_elevatable_roles"] if r != "auditor"]))
        self.assertIn("AUDIT_READER_ELEVATABLE", self.codes(self._validate()))

    def test_rejects_unlogged_audit_access(self):
        self.fixture.mutate(self.REL, lambda d: d["access"].__setitem__(
            "access_is_itself_audited", False))
        self.assertIn("AUDIT_ACCESS_UNLOGGED", self.codes(self._validate()))

    def test_rejects_an_unrehearsed_verifier(self):
        self.fixture.mutate(self.REL, lambda d: d["verification"].__setitem__("rehearsed", False))
        self.assertIn("AUDIT_UNREHEARSED", self.codes(self._validate()))

    def test_rejects_a_rehearsal_that_never_comes_round(self):
        self.fixture.mutate(self.REL, lambda d: d["verification"].__setitem__(
            "rehearsal_interval_days", 3650))
        self.assertIn("AUDIT_REHEARSAL_INTERVAL", self.codes(self._validate()))

    def test_rejects_a_verifier_only_we_can_run(self):
        self.fixture.mutate(self.REL, lambda d: d["verification"].__setitem__(
            "independent_verifier", False))
        self.assertIn("AUDIT_NO_INDEPENDENT_VERIFIER", self.codes(self._validate()))

    def test_rejects_dropping_a_money_action_from_the_audited_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "audited_actions", [a for a in d["audited_actions"] if a != "payout.approve"]))
        self.assertIn("AUDIT_ACTION_UNLOGGED", self.codes(self._validate()))

    def test_rejects_auditing_an_action_that_does_not_exist(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["audited_actions"].append("unicorn.summon"))
        self.assertIn("AUDIT_ACTION_UNKNOWN", self.codes(self._validate()))

    def test_missing_cross_check_inputs_do_not_crash_the_gate(self):
        self.fixture.write("governance/authorization.json", "{ broken",
                                                                         encoding="utf-8")
        codes = self.codes(self._validate())
        self.assertIn("AUDIT_READER_UNKNOWN", codes)

    def test_budget_exhaustion_is_reraised(self):
        from tools.paygov.errors import BudgetExceeded
        with self.assertRaises(BudgetExceeded):
            audit.validate(self.fixture.root, Budget(seconds=0).start())


class ChainReference(FixtureTestCase):
    """The executable chain: what it detects, and the one thing it cannot."""

    def test_a_clean_chain_verifies(self):
        self.assertEqual(_ledger().verify(), (C.OK, None))

    def test_editing_a_payload_is_detected(self):
        ledger = _ledger()
        victim = ledger.records[2]
        ledger.records[2] = C.Record(**{**victim.__dict__, "payload": {"amount_minor": 999}})
        self.assertEqual(ledger.verify()[0], C.MODIFIED)

    def test_editing_a_header_field_is_detected(self):
        ledger = _ledger()
        victim = ledger.records[1]
        ledger.records[1] = C.Record(**{**victim.__dict__, "actor": "mallory"})
        self.assertEqual(ledger.verify()[0], C.MODIFIED)

    def test_a_forger_who_recomputes_one_hash_still_breaks_the_next_link(self):
        ledger = _ledger()
        victim = ledger.records[2]
        rebuilt = C.Record(**{**victim.__dict__, "actor": "mallory", "record_hash": ""})
        ledger.records[2] = C.Record(**{**rebuilt.__dict__,
                                        "record_hash": rebuilt.recompute()})
        status, sequence = ledger.verify()
        self.assertEqual(status, C.LINK_BROKEN)
        self.assertEqual(sequence, 4)

    def test_deleting_a_record_is_detected(self):
        ledger = _ledger()
        del ledger.records[2]
        self.assertIn(ledger.verify()[0], {C.SEQUENCE_BROKEN, C.LINK_BROKEN})

    def test_reordering_records_is_detected(self):
        ledger = _ledger()
        ledger.records[1], ledger.records[2] = ledger.records[2], ledger.records[1]
        self.assertIn(ledger.verify()[0], {C.SEQUENCE_BROKEN, C.LINK_BROKEN})

    def test_tail_truncation_is_undetectable_without_an_anchor(self):
        # Not a defect being papered over: a hash chain has no way to know how
        # long it was supposed to be. This test exists so the limit is stated
        # in code rather than discovered during an incident.
        ledger = _ledger()
        ledger.records = ledger.records[:3]
        self.assertEqual(ledger.verify(), (C.OK, None))

    def test_an_anchor_makes_tail_truncation_detectable(self):
        ledger = _ledger()
        ledger.anchor(at=2000)
        ledger.records = ledger.records[:3]
        self.assertEqual(ledger.verify()[0], C.TRUNCATED)

    def test_a_forged_anchor_is_detected(self):
        ledger = _ledger()
        ledger.anchor(at=2000)
        ledger.anchors[0] = C.Anchor(sequence=5, head_hash="0" * 64, at=2000, mac="00")
        self.assertEqual(ledger.verify()[0], C.ANCHOR_INVALID)

    def test_an_anchor_over_a_modified_head_is_detected(self):
        ledger = _ledger()
        ledger.anchor(at=2000)
        victim = ledger.records[4]
        rebuilt = C.Record(**{**victim.__dict__, "actor": "mallory", "record_hash": ""})
        ledger.records[4] = C.Record(**{**rebuilt.__dict__,
                                        "record_hash": rebuilt.recompute()})
        self.assertEqual(ledger.verify()[0], C.MODIFIED)

    def test_the_deniable_window_is_reported_honestly(self):
        ledger = _ledger()
        self.assertEqual(ledger.deniable_window(5000), 5000)
        ledger.anchor(at=4000)
        self.assertEqual(ledger.deniable_window(5000), 1000)
        self.assertEqual(ledger.deniable_window(4000), 0)

    def test_shredding_keeps_the_record_and_the_proof(self):
        ledger = _ledger()
        ledger.anchor(at=2000)
        before = ledger.records[1].record_hash
        record = ledger.shred(2)
        self.assertIsNone(record.payload)
        self.assertEqual(record.record_hash, before)
        self.assertEqual(ledger.verify(), (C.OK, None))
        self.assertEqual(record.payload_hash, C.content_hash({"amount_minor": 101}))

    def test_shredding_an_unknown_record_is_refused(self):
        with self.assertRaises(C.AuditRefused):
            _ledger().shred(99)

    def test_forbidden_fields_are_refused_at_write_time(self):
        ledger = C.Ledger(tenant_id="t-9")
        for field in C.NEVER_LOGGED:
            with self.subTest(field=field):
                with self.assertRaises(C.AuditRefused) as caught:
                    ledger.append(occurred_at=1, event_class="data.access", actor="a",
                                  action="x", decision="allow", rule_version="1.0.0",
                                  payload={field: "secret"})
                self.assertEqual(caught.exception.code, C.FORBIDDEN_FIELD)

    def test_a_backwards_clock_is_refused(self):
        ledger = _ledger()
        with self.assertRaises(C.AuditRefused) as caught:
            ledger.append(occurred_at=1, event_class="authz.decision", actor="a",
                          action="refund.approve", decision="allow", rule_version="1.0.0",
                          payload={})
        self.assertEqual(caught.exception.code, C.CLOCK_REVERSED)

    def test_the_same_instant_is_allowed(self):
        ledger = _ledger()
        last = ledger.records[-1].occurred_at
        record = ledger.append(occurred_at=last, event_class="authz.decision", actor="a",
                               action="refund.approve", decision="allow", rule_version="1.0.0",
                               payload={})
        self.assertEqual(record.sequence, 6)
        self.assertEqual(ledger.verify(), (C.OK, None))

    def test_canonical_serialisation_is_key_order_independent(self):
        self.assertEqual(C.content_hash({"a": 1, "b": 2}), C.content_hash({"b": 2, "a": 1}))
        self.assertNotEqual(C.content_hash({"a": 1}), C.content_hash({"a": 2}))

    def test_chains_of_different_tenants_are_independent(self):
        first = _ledger(tenant="t-1")
        second = _ledger(tenant="t-2")
        self.assertNotEqual(first.records[0].record_hash, second.records[0].record_hash)
        self.assertEqual(second.verify(), (C.OK, None))

    def test_a_record_proof_states_whether_it_is_anchored(self):
        ledger = _ledger()
        self.assertFalse(ledger.proof(1)["anchored"])
        ledger.anchor(at=2000)
        proof = ledger.proof(1)
        self.assertTrue(proof["anchored"])
        self.assertEqual(proof["header"]["sequence"], 1)

    def test_a_proof_for_an_unknown_record_is_refused(self):
        with self.assertRaises(C.AuditRefused):
            _ledger().proof(42)

    def test_an_empty_ledger_verifies_and_can_be_anchored(self):
        ledger = C.Ledger(tenant_id="t-empty")
        self.assertEqual(ledger.verify(), (C.OK, None))
        anchor = ledger.anchor(at=10)
        self.assertEqual(anchor.sequence, 0)
        self.assertEqual(ledger.verify(), (C.OK, None))
