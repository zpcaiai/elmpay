"""B07 / AT-B07-01 — single source of truth registry."""
from __future__ import annotations

from tools.paygov import ssot
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class SsotHappyPath(FixtureTestCase):
    def test_real_registry_passes(self):
        problems = ssot.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_b07_validators_are_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertTrue({"ssot", "traceability"} <= set(registry.names()))

    def test_every_governance_file_is_registered(self):
        registered = {s["path"] for s in
                      self.fixture.read("governance/ssot-registry.json")["sources"]}
        on_disk = {p.relative_to(REAL_ROOT).as_posix()
                   for p in (REAL_ROOT / "governance").glob("*.json")}
        self.assertEqual(on_disk - registered, set())

    def test_every_source_names_an_owner_and_a_validator(self):
        from tools.paygov import registry
        registry.load_all()
        known = set(registry.names())
        for source in self.fixture.read("governance/ssot-registry.json")["sources"]:
            self.assertTrue(source["owner"].strip(), source["id"])
            self.assertIn(source["validator"], known, source["id"])

    def test_no_generated_file_has_two_generators(self):
        generated = [g for s in self.fixture.read("governance/ssot-registry.json")["sources"]
                     for g in s["generates"]]
        self.assertEqual(len(generated), len(set(generated)))


class SsotRejects(FixtureTestCase):
    REL = "governance/ssot-registry.json"

    def _validate(self):
        return ssot.validate(self.fixture.root, Budget(seconds=60).start())

    def test_rejects_unregistered_governance_file(self):
        self.fixture.write("governance/rogue-config.json", {"schema_version": "1.0.0"})
        self.assertIn("SSOT_UNREGISTERED", self.codes(self._validate()))

    def test_rejects_unknown_validator(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["sources"][0].__setitem__("validator", "nope"))
        self.assertIn("SSOT_VALIDATOR", self.codes(self._validate()))

    def test_rejects_source_without_owner(self):
        self.fixture.mutate(self.REL, lambda d: d["sources"][1].__setitem__("owner", ""))
        problems = self._validate()
        self.assertIn("SSOT_OWNER", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_missing_registered_file(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["sources"][2].__setitem__("path", "governance/gone.json"))
        self.assertIn("SSOT_MISSING", self.codes(self._validate()))

    def test_rejects_two_generators_for_one_file(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["sources"][0]
                            .__setitem__("generates", ["docs/security/THREAT_MODEL.md"]))
        self.assertIn("SSOT_DOUBLE_GENERATOR", self.codes(self._validate()))

    def test_rejects_generated_file_without_banner(self):
        path = self.fixture.root / "docs/security/THREAT_MODEL.md"
        path.write_text("# hand written\n", encoding="utf-8")
        self.assertIn("SSOT_BANNER", self.codes(self._validate()))

    def test_rejects_generated_file_registered_as_a_source(self):
        self.fixture.mutate(self.REL, lambda d: d["sources"].append(
            {"id": "matrix", "path": "docs/traceability/MATRIX.md", "batch": "B07",
             "owner": "payment-platform-architecture", "validator": "traceability",
             "generates": []}))
        self.assertIn("SSOT_GENERATED_IS_SOURCE", self.codes(self._validate()))

    def test_rejects_invalid_batch_reference(self):
        self.fixture.mutate(self.REL, lambda d: d["sources"][0].__setitem__("batch", "B900"))
        self.assertIn("SSOT_BATCH", self.codes(self._validate()))


class RegistryOwnershipIsDerived(FixtureTestCase):
    """The SSOT registry is no longer pinned to B07's artefact digest.

    It grows once per batch by construction, so pinning it meant B07's evidence
    expired every batch and dragged the whole programme through a re-baseline.
    What replaces the pin is a consistency rule: an entry cannot claim a batch
    that disagrees with the validator module's own declaration.
    """

    def test_every_entry_agrees_with_its_validator_module(self):
        from tools.paygov import registry
        registry.load_all()
        document = self.fixture.read("governance/ssot-registry.json")
        for source in document["sources"]:
            self.assertEqual(source["batch"], registry.batch_of(source["validator"]),
                             source["id"])

    def test_a_mislabelled_entry_is_rejected(self):
        self.fixture.mutate("governance/ssot-registry.json", lambda d: next(
            s for s in d["sources"] if s["id"] == "mfa").__setitem__("batch", "B03"))
        codes = self.codes(ssot.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("SSOT_BATCH_MISMATCH", codes)

    def test_the_registry_is_not_listed_as_a_b07_artefact(self):
        import json
        listing = json.loads(
            (REAL_ROOT / "evidence/B07/artifacts.json").read_text(encoding="utf-8"))
        self.assertNotIn("governance/ssot-registry.json", listing)
