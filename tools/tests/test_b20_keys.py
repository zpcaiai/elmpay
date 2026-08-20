"""B20 / AT-B20-01 — KMS, HSM, envelope encryption and key lifecycle.

The test that carries this batch is
``test_a_ciphertext_cannot_be_moved_to_another_tenant``. An attacker who can
write rows — a broken query, a bad import job, an insider — copies tenant A's
encrypted bank account into tenant B's record. If the ciphertext were bound to
nothing, tenant B would open it and read A's account number. Two independent
mechanisms refuse: the wrapped data key does not unwrap under B's KEK, and even
where the KEK is shared, the additional authenticated data names tenant A.

``test_destroying_a_tenant_key_destroys_the_data`` is the other one worth
reading. In a system with backups, deleting rows deletes nothing; destroying
the key is the only deletion that can be demonstrated.

The gate rules mirror the ways this gets given away quietly: an exportable root
key, a data key stored unwrapped, a nonce reused under one key version, or a
field that B19 classifies as sensitive and nobody encrypts.
"""
from __future__ import annotations

import json

from libs.kms.reference import envelope as E
from tools.paygov import keys as keys_module, keysgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

NOW = 1_760_000_000


def _policy(root=REAL_ROOT) -> dict:
    return json.loads((root / "governance/key-management.json").read_text(encoding="utf-8"))


class KeyPolicyHappyPath(FixtureTestCase):
    def test_real_policy_passes(self):
        problems = keys_module.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("key-management", registry.names())

    def test_root_key_never_leaves_the_hsm(self):
        policy = self.fixture.read("governance/key-management.json")
        self.assertTrue(policy["hsm"]["required_for_root"])
        self.assertFalse(policy["hsm"]["root_key_exportable"])
        for key in policy["keys"]:
            self.assertFalse(key["exportable"], key["id"])
            if key["class"] == "root":
                self.assertEqual(key["storage"], "hsm")
                self.assertTrue(key["dual_control"])
                self.assertEqual(key["protects_fields"], [])

    def test_root_operations_need_a_quorum(self):
        policy = self.fixture.read("governance/key-management.json")
        m, n = policy["hsm"]["quorum_m_of_n"]
        self.assertGreater(m, 1)
        self.assertLessEqual(m, n)

    def test_the_envelope_binds_tenant_purpose_and_version(self):
        policy = self.fixture.read("governance/key-management.json")
        env = policy["envelope"]
        self.assertTrue(env["aad_required"])
        self.assertLessEqual({"tenant_id", "purpose", "key_id"}, set(env["aad_fields"]))
        self.assertTrue(env["nonce_reuse_forbidden"])
        self.assertGreaterEqual(env["nonce_bytes"], 12)
        self.assertEqual(env["data_key_per"], "record")
        self.assertFalse(env["store_unwrapped_data_key"])
        self.assertLessEqual(env["plaintext_data_key_ttl_seconds"], 900)

    def test_every_data_key_is_wrapped_by_a_kek(self):
        policy = self.fixture.read("governance/key-management.json")
        by_id = {k["id"]: k for k in policy["keys"]}
        for key in policy["keys"]:
            if key["class"] == "dek":
                self.assertIn(key["wrapped_by"], by_id, key["id"])
                self.assertIn(by_id[key["wrapped_by"]]["class"], {"kek", "root"})
                self.assertEqual(key["storage"], "envelope")

    def test_rotation_rewraps_rather_than_rewrites(self):
        policy = self.fixture.read("governance/key-management.json")
        rot = policy["rotation"]
        self.assertEqual(rot["re_encrypt_strategy"], "rewrap_data_keys")
        self.assertGreater(rot["overlap_window_days"], 0)
        self.assertLessEqual(rot["emergency_rotation_hours"], 24)
        self.assertLessEqual(rot["kek_days"], 365)

    def test_the_application_never_holds_key_material(self):
        policy = self.fixture.read("governance/key-management.json")
        access = policy["access"]
        self.assertFalse(access["application_holds_key_material"])
        self.assertTrue(access["decrypt_only_through_broker"])
        self.assertTrue(access["key_use_audited"])
        self.assertTrue(access["audit_includes_key_version"])

    def test_crypto_shredding_is_the_deletion_story(self):
        policy = self.fixture.read("governance/key-management.json")
        dest = policy["destruction"]
        self.assertTrue(dest["crypto_shredding"])
        self.assertTrue(dest["tenant_offboarding_destroys_kek"])
        self.assertTrue(dest["destroyed_key_is_unrecoverable"])

    def test_broken_primitives_are_banned(self):
        policy = self.fixture.read("governance/key-management.json")
        banned = {a.upper() for a in policy["forbidden"]["algorithms"]}
        for algorithm in ("DES", "3DES", "RC4", "MD5", "SHA1", "AES-ECB"):
            self.assertIn(algorithm, banned)
        self.assertGreaterEqual(policy["forbidden"]["minimum_rsa_bits"], 2048)

    def test_every_provider_key_is_accounted_for(self):
        policy = self.fixture.read("governance/key-management.json")
        identity = self.fixture.read("governance/identity.json")
        project = self.fixture.read("governance/project-config.json")
        declared = {p["provider"] for p in policy["provider_keys"]}
        for provider in [p["id"] for p in identity["providers"]]:
            self.assertIn(provider, declared)
        for channel in project["providers"]:
            self.assertIn(channel, declared)

    def test_every_sensitive_field_has_a_key(self):
        policy = self.fixture.read("governance/key-management.json")
        authz = self.fixture.read("governance/authorization.json")
        protected = {f for k in policy["keys"] for f in k["protects_fields"]}
        for rule in authz["field_rules"]:
            if rule["classification"] in keys_module.PROTECTED_CLASSIFICATIONS:
                if rule["never_readable"]:
                    self.assertNotIn(rule["field"], protected, rule["field"])
                else:
                    self.assertIn(rule["field"], protected, rule["field"])


class KeyGeneratedArtefacts(FixtureTestCase):
    def test_generated_artefacts_match_the_policy(self):
        for rel, content in keysgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_inventory_lists_the_hierarchy(self):
        inventory = json.loads(keysgen.inventory_json(REAL_ROOT))
        classes = {k["class"] for k in inventory["keys"]}
        self.assertEqual(classes, {"root", "kek", "dek"})

    def test_document_names_every_key_and_provider(self):
        text = keysgen.keys_markdown(REAL_ROOT)
        policy = _policy()
        for key in policy["keys"]:
            self.assertIn(key["id"], text)
        for provider in policy["provider_keys"]:
            self.assertIn(provider["provider"], text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/security/KEY_MANAGEMENT.md", "hand written\n")
        codes = self.codes(keys_module.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("KEY_GENERATED_DRIFT", codes)

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/security/key-inventory.json")
        codes = self.codes(keys_module.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("KEY_GENERATED_MISSING", codes)

    def test_unrenderable_policy_fails_closed(self):
        self.fixture.mutate("governance/key-management.json",
                            lambda d: d.__setitem__("keys", [{"id": "x"}]))
        codes = self.codes(keys_module.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("KEY_GENERATED", codes)


class KeyGateRejects(FixtureTestCase):
    REL = "governance/key-management.json"

    def _validate(self):
        return keys_module.validate(self.fixture.root, Budget(seconds=60).start())

    def _key(self, d, kid):
        return next(k for k in d["keys"] if k["id"] == kid)

    def _provider(self, d, pid):
        return next(p for p in d["provider_keys"] if p["provider"] == pid)

    def test_rejects_unreadable_policy(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("KEY_UNREADABLE", self.codes(self._validate()))

    def test_rejects_non_object_policy(self):
        self.fixture.write(self.REL, [1])
        self.assertIn("KEY_SHAPE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "1"))
        self.assertIn("KEY_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_missing_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("KEY_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_software_root_key(self):
        self.fixture.mutate(self.REL, lambda d: d["hsm"].__setitem__("required_for_root", False))
        self.assertIn("KEY_HSM_REQUIRED", self.codes(self._validate()))

    def test_rejects_low_fips_level(self):
        self.fixture.mutate(self.REL, lambda d: d["hsm"].__setitem__("fips_140_level", 1))
        self.assertIn("KEY_HSM_LEVEL", self.codes(self._validate()))

    def test_rejects_exportable_root_key(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["hsm"].__setitem__("root_key_exportable", True))
        self.assertIn("KEY_EXPORTABLE_ROOT", self.codes(self._validate()))

    def test_rejects_unattested_hsm(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["hsm"].__setitem__("attestation_required", False))
        self.assertIn("KEY_HSM_ATTESTATION", self.codes(self._validate()))

    def test_rejects_single_person_root_access(self):
        self.fixture.mutate(self.REL, lambda d: d["hsm"].__setitem__("quorum_m_of_n", [1, 3]))
        self.assertIn("KEY_QUORUM", self.codes(self._validate()))

    def test_rejects_non_aead_data_key_algorithm(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["envelope"].__setitem__("data_key_algorithm", "AES-256-CBC"))
        self.assertIn("KEY_ALGORITHM", self.codes(self._validate()))

    def test_rejects_one_data_key_for_a_whole_table(self):
        self.fixture.mutate(self.REL, lambda d: d["envelope"].__setitem__("data_key_per", "table"))
        self.assertIn("KEY_DEK_SCOPE", self.codes(self._validate()))

    def test_rejects_short_nonce(self):
        self.fixture.mutate(self.REL, lambda d: d["envelope"].__setitem__("nonce_bytes", 8))
        self.assertIn("KEY_NONCE_SIZE", self.codes(self._validate()))

    def test_rejects_permitted_nonce_reuse(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["envelope"].__setitem__("nonce_reuse_forbidden", False))
        self.assertIn("KEY_NONCE_REUSE", self.codes(self._validate()))

    def test_rejects_dropping_aad(self):
        self.fixture.mutate(self.REL, lambda d: d["envelope"].__setitem__("aad_required", False))
        self.assertIn("KEY_AAD_MISSING", self.codes(self._validate()))

    def test_rejects_aad_that_omits_the_tenant(self):
        self.fixture.mutate(self.REL, lambda d: d["envelope"].__setitem__(
            "aad_fields", ["purpose", "key_id"]))
        self.assertIn("KEY_AAD_MISSING", self.codes(self._validate()))

    def test_rejects_long_lived_plaintext_data_key(self):
        self.fixture.mutate(self.REL, lambda d: d["envelope"].__setitem__(
            "plaintext_data_key_ttl_seconds", 86400))
        self.assertIn("KEY_PLAINTEXT_TTL", self.codes(self._validate()))

    def test_rejects_storing_the_unwrapped_data_key(self):
        self.fixture.mutate(self.REL, lambda d: d["envelope"].__setitem__(
            "store_unwrapped_data_key", True))
        self.assertIn("KEY_UNWRAPPED_STORED", self.codes(self._validate()))

    def test_rejects_bad_key_id(self):
        self.fixture.mutate(self.REL, lambda d: self._key(d, "kek-pii").__setitem__("id", "KEK"))
        self.assertIn("KEY_ID", self.codes(self._validate()))

    def test_rejects_duplicate_key(self):
        self.fixture.mutate(self.REL, lambda d: d["keys"].append(dict(self._key(d, "kek-pii"))))
        self.assertIn("KEY_DUPLICATE", self.codes(self._validate()))

    def test_rejects_unknown_key_class(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "kek-pii").__setitem__("class", "magic"))
        self.assertIn("KEY_CLASS", self.codes(self._validate()))

    def test_rejects_unknown_storage(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "kek-pii").__setitem__("storage", "usb"))
        self.assertIn("KEY_STORAGE", self.codes(self._validate()))

    def test_rejects_exportable_key(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "kek-pii").__setitem__("exportable", True))
        self.assertIn("KEY_EXPORTABLE", self.codes(self._validate()))

    def test_rejects_key_without_notes(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "kek-pii").__setitem__("notes", ""))
        self.assertIn("KEY_NOTES", self.codes(self._validate()))

    def test_rejects_key_that_never_rotates(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "kek-pii").__setitem__("rotation_days", 0))
        self.assertIn("KEY_ROTATION_MISSING", self.codes(self._validate()))

    def test_rejects_root_key_outside_the_hsm(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "root-hsm").__setitem__("storage", "kms"))
        self.assertIn("KEY_ROOT_STORAGE", self.codes(self._validate()))

    def test_rejects_root_key_without_dual_control(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "root-hsm").__setitem__("dual_control", False))
        self.assertIn("KEY_ROOT_DUAL_CONTROL", self.codes(self._validate()))

    def test_rejects_root_key_encrypting_data_directly(self):
        self.fixture.mutate(self.REL, lambda d: self._key(d, "root-hsm").__setitem__(
            "protects_fields", ["customer_email"]))
        self.assertIn("KEY_ROOT_DIRECT_USE", self.codes(self._validate()))

    def test_rejects_data_key_stored_outside_the_envelope(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "dek-pii").__setitem__("storage", "kms"))
        self.assertIn("KEY_DEK_STORAGE", self.codes(self._validate()))

    def test_rejects_data_key_with_no_wrapper(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "dek-pii").__setitem__("wrapped_by", ""))
        self.assertIn("KEY_DEK_UNWRAPPED", self.codes(self._validate()))

    def test_rejects_unknown_wrapper(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "dek-pii").__setitem__("wrapped_by", "ghost"))
        self.assertIn("KEY_WRAPPER_UNKNOWN", self.codes(self._validate()))

    def test_rejects_data_key_wrapping_another_data_key(self):
        self.fixture.mutate(self.REL, lambda d: self._key(d, "dek-pii").__setitem__(
            "wrapped_by", "dek-financial"))
        self.assertIn("KEY_WRAPPER_CLASS", self.codes(self._validate()))

    def test_rejects_upside_down_rotation(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "dek-pii").__setitem__("rotation_days", 365))
        self.assertIn("KEY_ROTATION_INVERTED", self.codes(self._validate()))

    def test_rejects_a_hierarchy_with_no_kek(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "keys", [k for k in d["keys"] if k["class"] != "kek"]))
        self.assertIn("KEY_NO_KEK", self.codes(self._validate()))

    def test_rejects_yearly_plus_kek_rotation(self):
        self.fixture.mutate(self.REL, lambda d: d["rotation"].__setitem__("kek_days", 3650))
        self.assertIn("KEY_ROTATION_PERIOD", self.codes(self._validate()))

    def test_rejects_rotation_without_overlap(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["rotation"].__setitem__("overlap_window_days", 0))
        self.assertIn("KEY_ROTATION_OVERLAP", self.codes(self._validate()))

    def test_rejects_full_re_encryption_strategy(self):
        self.fixture.mutate(self.REL, lambda d: d["rotation"].__setitem__(
            "re_encrypt_strategy", "rewrite_every_record"))
        self.assertIn("KEY_REENCRYPT_STRATEGY", self.codes(self._validate()))

    def test_rejects_slow_emergency_rotation(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["rotation"].__setitem__("emergency_rotation_hours", 720))
        self.assertIn("KEY_EMERGENCY_ROTATION", self.codes(self._validate()))

    def test_rejects_application_holding_key_material(self):
        self.fixture.mutate(self.REL, lambda d: d["access"].__setitem__(
            "application_holds_key_material", True))
        self.assertIn("KEY_APP_HOLDS_MATERIAL", self.codes(self._validate()))

    def test_rejects_bypassing_the_broker(self):
        self.fixture.mutate(self.REL, lambda d: d["access"].__setitem__(
            "decrypt_only_through_broker", False))
        self.assertIn("KEY_BROKER_BYPASS", self.codes(self._validate()))

    def test_rejects_unaudited_key_use(self):
        self.fixture.mutate(self.REL, lambda d: d["access"].__setitem__("key_use_audited", False))
        self.assertIn("KEY_USE_UNAUDITED", self.codes(self._validate()))

    def test_rejects_audit_without_key_version(self):
        self.fixture.mutate(self.REL, lambda d: d["access"].__setitem__(
            "audit_includes_key_version", False))
        self.assertIn("KEY_AUDIT_VERSION", self.codes(self._validate()))

    def test_rejects_single_person_root_operations(self):
        self.fixture.mutate(self.REL, lambda d: d["access"].__setitem__(
            "dual_control_for_root_operations", False))
        self.assertIn("KEY_ROOT_DUAL_CONTROL", self.codes(self._validate()))

    def test_rejects_dropping_crypto_shredding(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["destruction"].__setitem__("crypto_shredding", False))
        self.assertIn("KEY_NO_SHREDDING", self.codes(self._validate()))

    def test_rejects_recoverable_destruction(self):
        self.fixture.mutate(self.REL, lambda d: d["destruction"].__setitem__(
            "destroyed_key_is_unrecoverable", False))
        self.assertIn("KEY_SHRED_RECOVERABLE", self.codes(self._validate()))

    def test_rejects_unbanning_broken_primitives(self):
        self.fixture.mutate(self.REL, lambda d: d["forbidden"].__setitem__(
            "algorithms", [a for a in d["forbidden"]["algorithms"] if a != "MD5"]))
        self.assertIn("KEY_WEAK_ALGORITHM_ALLOWED", self.codes(self._validate()))

    def test_rejects_small_rsa_floor(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["forbidden"].__setitem__("minimum_rsa_bits", 1024))
        self.assertIn("KEY_RSA_SIZE", self.codes(self._validate()))

    def test_rejects_allowing_hardcoded_keys(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["forbidden"].__setitem__("hardcoded_key_material", True))
        self.assertIn("KEY_HARDCODED", self.codes(self._validate()))

    def test_rejects_keys_in_logs(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["forbidden"].__setitem__("plaintext_key_in_logs", True))
        self.assertIn("KEY_IN_LOGS", self.codes(self._validate()))

    def test_rejects_a_key_using_a_banned_algorithm(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._key(d, "kek-pii").__setitem__("algorithm", "3DES"))
        self.assertIn("KEY_WEAK_ALGORITHM", self.codes(self._validate()))

    def test_rejects_duplicate_provider(self):
        self.fixture.mutate(self.REL, lambda d: d["provider_keys"].append(
            dict(self._provider(d, "stripe"))))
        self.assertIn("KEY_PROVIDER_DUPLICATE", self.codes(self._validate()))

    def test_rejects_unknown_provider_material(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._provider(d, "stripe").__setitem__("material", "note"))
        self.assertIn("KEY_PROVIDER_MATERIAL", self.codes(self._validate()))

    def test_rejects_provider_pointing_at_an_unknown_key(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._provider(d, "stripe").__setitem__("key_id", "ghost"))
        self.assertIn("KEY_PROVIDER_KEY_UNKNOWN", self.codes(self._validate()))

    def test_rejects_provider_without_notes(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._provider(d, "stripe").__setitem__("notes", ""))
        self.assertIn("KEY_PROVIDER_NOTES", self.codes(self._validate()))

    def test_rejects_weak_provider_signing_algorithm(self):
        self.fixture.mutate(self.REL, lambda d: self._provider(d, "wechat").__setitem__(
            "signing_algorithm", "RSA-1024-PSS"))
        self.assertIn("KEY_RSA_SIZE", self.codes(self._validate()))

    def test_rejects_a_channel_with_no_managed_key(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "provider_keys", [p for p in d["provider_keys"] if p["provider"] != "alipay"]))
        self.assertIn("KEY_PROVIDER_UNMANAGED", self.codes(self._validate()))

    def test_rejects_an_identity_provider_with_no_managed_key(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "provider_keys", [p for p in d["provider_keys"] if p["provider"] != "workload-ca"]))
        self.assertIn("KEY_PROVIDER_UNMANAGED", self.codes(self._validate()))

    def test_rejects_an_unencrypted_sensitive_field(self):
        self.fixture.mutate(self.REL, lambda d: self._key(d, "dek-pii").__setitem__(
            "protects_fields", ["customer_email"]))
        self.assertIn("KEY_FIELD_UNPROTECTED", self.codes(self._validate()))

    def test_rejects_encrypting_a_field_we_promised_never_to_store(self):
        self.fixture.mutate(self.REL, lambda d: self._key(d, "dek-pii")["protects_fields"]
                            .append("card_pan"))
        self.assertIn("KEY_NEVER_STORED_ENCRYPTED", self.codes(self._validate()))

    def test_a_new_sensitive_field_must_be_encrypted(self):
        self.fixture.mutate("governance/authorization.json", lambda d: d["field_rules"].append(
            {"field": "tax_identifier", "classification": "pii", "never_readable": False,
             "masked_by_default": True, "readable_by": [],
             "notes": "新增的敏感字段：如果没有密钥保护它，备份被拿走时它就是明文。"}))
        self.assertIn("KEY_FIELD_UNPROTECTED", self.codes(self._validate()))

    def test_missing_cross_check_inputs_do_not_crash_the_gate(self):
        # An unreadable cross-check input must degrade to "cannot check that",
        # never to a crash and never to a silent pass of what it *can* check.
        self.fixture.write("governance/identity.json", "{ broken", encoding="utf-8")
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "provider_keys", [p for p in d["provider_keys"] if p["provider"] != "alipay"]))
        codes = self.codes(self._validate())
        self.assertIn("KEY_PROVIDER_UNMANAGED", codes)

    def test_budget_exhaustion_is_reraised(self):
        from tools.paygov.errors import BudgetExceeded
        with self.assertRaises(BudgetExceeded):
            keys_module.validate(self.fixture.root, Budget(seconds=0).start())


class EnvelopeReference(FixtureTestCase):
    """The executable model: what the broker refuses, and why."""

    def setUp(self):
        super().setUp()
        self.policy = _policy()
        self.broker = E.KeyBroker(self.policy)
        self.secret = b"6222-0000-1111-2222"

    def _seal(self, tenant="t-a", purpose="tenant_data", nonce=b"nonce-000001", now=NOW):
        return self.broker.encrypt(self.secret, tenant_id=tenant, purpose=purpose, now=now,
                                   nonce=nonce)

    def _refuses(self, fn, code):
        with self.assertRaises(E.CryptoRefused) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)

    def test_round_trip(self):
        env = self._seal()
        self.assertEqual(self.broker.decrypt(env, tenant_id="t-a", purpose="tenant_data",
                                             now=NOW), self.secret)

    def test_the_ciphertext_does_not_contain_the_plaintext(self):
        env = self._seal()
        self.assertNotIn(self.secret, env.ciphertext)
        self.assertNotEqual(env.ciphertext, self.secret)

    def test_a_ciphertext_cannot_be_moved_to_another_tenant(self):
        env = self._seal()
        moved = E.Envelope(**{**env.__dict__, "tenant_id": "t-b"})
        # Per-tenant KEK: the data key itself will not unwrap.
        self._refuses(lambda: self.broker.decrypt(moved, tenant_id="t-b",
                                                  purpose="tenant_data", now=NOW),
                      E.WRAP_INVALID)

    def test_aad_alone_stops_the_move_when_the_kek_is_shared(self):
        env = self.broker.encrypt(b"api key", tenant_id="t-a", purpose="provider_credential",
                                  now=NOW, nonce=b"nonce-000002")
        moved = E.Envelope(**{**env.__dict__, "tenant_id": "t-b"})
        self._refuses(lambda: self.broker.decrypt(moved, tenant_id="t-b",
                                                  purpose="provider_credential", now=NOW),
                      E.AUTH_FAILED)

    def test_decrypting_with_the_wrong_purpose_fails(self):
        env = self._seal()
        self._refuses(lambda: self.broker.decrypt(env, tenant_id="t-a", purpose="pii", now=NOW),
                      E.WRAP_INVALID)

    def test_a_single_flipped_bit_is_rejected(self):
        env = self._seal()
        torn = E.Envelope(**{**env.__dict__,
                             "ciphertext": bytes([env.ciphertext[0] ^ 1]) + env.ciphertext[1:]})
        self._refuses(lambda: self.broker.decrypt(torn, tenant_id="t-a", purpose="tenant_data",
                                                  now=NOW), E.AUTH_FAILED)

    def test_a_forged_tag_is_rejected(self):
        env = self._seal()
        forged = E.Envelope(**{**env.__dict__, "tag": bytes(32)})
        self._refuses(lambda: self.broker.decrypt(forged, tenant_id="t-a", purpose="tenant_data",
                                                  now=NOW), E.AUTH_FAILED)

    def test_the_refusal_does_not_say_which_attack_it_was(self):
        # An AEAD cannot distinguish "moved" from "edited"; claiming otherwise
        # would be inventing information, and would leak it to the attacker.
        env = self.broker.encrypt(b"api key", tenant_id="t-a", purpose="provider_credential",
                                  now=NOW, nonce=b"nonce-000003")
        moved = E.Envelope(**{**env.__dict__, "tenant_id": "t-b"})
        torn = E.Envelope(**{**env.__dict__,
                             "ciphertext": bytes([env.ciphertext[0] ^ 1]) + env.ciphertext[1:]})
        codes = set()
        for candidate, tenant in ((moved, "t-b"), (torn, "t-a")):
            with self.assertRaises(E.CryptoRefused) as caught:
                self.broker.decrypt(candidate, tenant_id=tenant,
                                    purpose="provider_credential", now=NOW)
            codes.add(caught.exception.code)
        self.assertEqual(codes, {E.AUTH_FAILED})

    def test_nonce_reuse_is_refused(self):
        self._seal(nonce=b"nonce-000009")
        self._refuses(lambda: self.broker.encrypt(b"second record", tenant_id="t-a",
                                                  purpose="tenant_data", now=NOW,
                                                  nonce=b"nonce-000009"), E.NONCE_REUSE)

    def test_a_fresh_nonce_is_fine(self):
        self._seal(nonce=b"nonce-000010")
        env = self.broker.encrypt(b"second record", tenant_id="t-a", purpose="tenant_data",
                                  now=NOW, nonce=b"nonce-000011")
        self.assertEqual(self.broker.decrypt(env, tenant_id="t-a", purpose="tenant_data",
                                             now=NOW), b"second record")

    def test_a_short_nonce_is_refused(self):
        self._refuses(lambda: self.broker.encrypt(b"x", tenant_id="t-a", purpose="tenant_data",
                                                  now=NOW, nonce=b"short"), E.AUTH_FAILED)

    def test_the_data_key_is_leased_not_owned(self):
        lease = self.broker.lease(purpose="tenant_data", tenant_id="t-a", now=NOW)
        ttl = self.policy["envelope"]["plaintext_data_key_ttl_seconds"]
        self.assertEqual(lease.expires_at, NOW + ttl)
        self.assertEqual(lease.material(NOW + ttl - 1), lease.plaintext)
        self._refuses(lambda: lease.material(NOW + ttl), E.LEASE_EXPIRED)

    def test_each_record_gets_its_own_data_key(self):
        first = self._seal(nonce=b"nonce-000021")
        second = self.broker.encrypt(self.secret, tenant_id="t-a", purpose="tenant_data",
                                     now=NOW, nonce=b"nonce-000022")
        self.assertNotEqual(first.wrapped_data_key, second.wrapped_data_key)

    def test_rotation_creates_a_new_version_and_keeps_the_old_one_briefly(self):
        env = self._seal()
        version = self.broker.rotate(env.key_id, NOW)
        self.assertEqual(version, env.key_version + 1)
        self.assertEqual(self.broker.decrypt(env, tenant_id="t-a", purpose="tenant_data",
                                             now=NOW + 60), self.secret)

    def test_rewrapping_does_not_touch_the_ciphertext(self):
        env = self._seal()
        self.broker.rotate(env.key_id, NOW)
        rewrapped = self.broker.rewrap(env, NOW)
        self.assertEqual(rewrapped.ciphertext, env.ciphertext)
        self.assertNotEqual(rewrapped.wrapped_data_key, env.wrapped_data_key)
        self.assertEqual(self.broker.decrypt(rewrapped, tenant_id="t-a", purpose="tenant_data",
                                             now=NOW + 60), self.secret)

    def test_the_old_version_stops_working_after_the_overlap_window(self):
        env = self._seal()
        self.broker.rotate(env.key_id, NOW)
        after = NOW + self.policy["rotation"]["overlap_window_days"] * 86400 + 1
        self._refuses(lambda: self.broker.decrypt(env, tenant_id="t-a", purpose="tenant_data",
                                                  now=after), E.KEY_VERSION_RETIRED)

    def test_destroying_a_tenant_key_destroys_the_data(self):
        env = self._seal(tenant="t-z", nonce=b"nonce-000031")
        self.assertEqual(self.broker.decrypt(env, tenant_id="t-z", purpose="tenant_data",
                                             now=NOW), self.secret)
        self.broker.destroy(self.broker.kek_for("tenant_data"), tenant_id="t-z")
        self._refuses(lambda: self.broker.decrypt(env, tenant_id="t-z", purpose="tenant_data",
                                                  now=NOW), E.KEY_DESTROYED)

    def test_destruction_is_scoped_to_one_tenant(self):
        kept = self._seal(tenant="t-y", nonce=b"nonce-000032")
        self.broker.destroy(self.broker.kek_for("tenant_data"), tenant_id="t-z")
        self.assertEqual(self.broker.decrypt(kept, tenant_id="t-y", purpose="tenant_data",
                                             now=NOW), self.secret)

    def test_unknown_purpose_and_key_are_refused(self):
        self._refuses(lambda: self.broker.kek_for("astrology"), E.UNKNOWN_KEY)
        self._refuses(lambda: self.broker.rotate("ghost-key", NOW), E.UNKNOWN_KEY)

    def test_a_future_key_version_is_refused(self):
        env = self._seal()
        ahead = E.Envelope(**{**env.__dict__, "key_version": env.key_version + 5})
        self._refuses(lambda: self.broker.decrypt(ahead, tenant_id="t-a", purpose="tenant_data",
                                                  now=NOW), E.UNKNOWN_KEY)

    def test_every_use_is_audited_with_its_key_version(self):
        env = self._seal()
        self.broker.decrypt(env, tenant_id="t-a", purpose="tenant_data", now=NOW)
        actions = [row["action"] for row in self.broker.audit]
        self.assertIn("encrypt", actions)
        self.assertIn("decrypt", actions)
        for row in self.broker.audit:
            if row["action"] in {"encrypt", "decrypt"}:
                self.assertIsNotNone(row["key_version"])

    def test_refused_decryptions_are_audited_too(self):
        env = self._seal()
        forged = E.Envelope(**{**env.__dict__, "tag": bytes(32)})
        with self.assertRaises(E.CryptoRefused):
            self.broker.decrypt(forged, tenant_id="t-a", purpose="tenant_data", now=NOW)
        self.assertTrue(any(row["action"] == "decrypt-refused" for row in self.broker.audit))

    def test_the_aad_separator_prevents_field_confusion(self):
        # ("ab", "c") and ("a", "bc") must not produce the same authenticated data.
        self.assertNotEqual(E._aad("ab", "c", "k", 1), E._aad("a", "bc", "k", 1))
        self.assertNotEqual(E._aad("t", "p", "k", 1), E._aad("t", "p", "k", 2))
