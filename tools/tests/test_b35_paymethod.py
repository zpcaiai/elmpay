"""B35 — payment method abstraction and token references.

Two of this batch's rules cannot be reached by the negative-control harness:
``PMETHOD_HARDCODED_LIST`` and ``PMETHOD_CATALOG_UNBOUND`` both need real source
files, and the disposable repository that harness builds carries governance and
contracts but not every source tree. They are covered here instead, against a
fixture that writes the implementation stubs it needs.

Every fixture regenerates the contract from its own (possibly mutated) model, so
a baseline is clean by construction and a scenario fails for its own reason
rather than for drift it did not intend to cause.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.paygov.paymethod import validate
from tools.paygov.paymethodgen import render_all
from tools.paygov.repo import Budget

ROOT = Path(__file__).resolve().parents[2]
MODEL = "governance/payment-method.json"
KEYS = "governance/key-management.json"
CONTRACT = "contracts/payment-method/sensitive-fields.json"


def _codes(root: Path) -> set[str]:
    return {problem.code for problem in validate(root, Budget().start())}


class PaymentMethodCatalogue(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="b35-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        for rel in (MODEL, KEYS):
            destination = self.root / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, destination)
        self._derive()
        self._implementations(bound=True, literals=())

    # -- fixture helpers --------------------------------------------------
    def _derive(self) -> None:
        """Rebuild the projections from whatever model the fixture now holds."""
        # Both projections, including the Java one. The implementation stubs below
        # create the Java package directory, and the validator checks a projection
        # whenever its directory exists — so skipping it here would make every
        # scenario fail for drift it did not cause.
        for rel, content in render_all(self.root).items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def _model(self) -> dict:
        return json.loads((self.root / MODEL).read_text(encoding="utf-8"))

    def _write_model(self, model: dict) -> None:
        (self.root / MODEL).write_text(
            json.dumps(model, ensure_ascii=False, indent=2), encoding="utf-8")
        self._derive()

    def _mutate(self, change) -> set[str]:
        model = self._model()
        change(model)
        self._write_model(model)
        return _codes(self.root)

    def _implementations(self, *, bound: bool, literals: tuple[str, ...]) -> None:
        model = self._model()
        for rel in model["conformance"]["derived_implementations"]:
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            body = ["// derived implementation stub"]
            if bound:
                body.append("uses SensitiveFieldCatalog.denied(name)")
            for name in literals:
                body.append(f'  "{name}",')
            path.write_text("\n".join(body) + "\n", encoding="utf-8")

    # -- baseline ---------------------------------------------------------
    def test_the_shipped_catalogue_is_clean(self) -> None:
        self.assertEqual(_codes(self.root), set())

    def test_the_real_repository_is_clean(self) -> None:
        self.assertEqual(_codes(ROOT), set())

    # -- shape ------------------------------------------------------------
    def test_a_missing_model_is_unreadable(self) -> None:
        (self.root / MODEL).unlink()
        self.assertIn("PMETHOD_UNREADABLE", _codes(self.root))

    def test_a_model_that_is_not_an_object_is_refused(self) -> None:
        (self.root / MODEL).write_text("[]", encoding="utf-8")
        self.assertIn("PMETHOD_SHAPE", _codes(self.root))

    def test_the_schema_version_must_be_semver(self) -> None:
        self.assertIn("PMETHOD_VERSION_FIELD",
                      self._mutate(lambda m: m.__setitem__("schema_version", "1")))

    def test_the_principle_must_say_something(self) -> None:
        self.assertIn("PMETHOD_PRINCIPLE",
                      self._mutate(lambda m: m.__setitem__("principle", "")))

    # -- the catalogue itself ---------------------------------------------
    def test_every_required_family_must_be_forbidden(self) -> None:
        def drop(model: dict) -> None:
            model["forbidden_fields"] = [
                f for f in model["forbidden_fields"] if f["canonical"] != "pin"]
        self.assertIn("PMETHOD_FAMILY_MISSING", self._mutate(drop))

    def test_a_spelling_this_repository_used_may_not_be_dropped(self) -> None:
        """`card_pan` is the exact name that walked past a guard watching `pan`."""
        def drop(model: dict) -> None:
            family = next(f for f in model["forbidden_fields"] if f["canonical"] == "pan")
            family["aliases"] = [a for a in family["aliases"] if a != "card_pan"]
        self.assertIn("PMETHOD_ALIAS_GAP", self._mutate(drop))

    def test_comparison_must_be_case_insensitive(self) -> None:
        self.assertIn("PMETHOD_NORMALIZATION_WEAK",
                      self._mutate(lambda m: m["normalization"].__setitem__("lowercase", False)))

    def test_separators_must_be_stripped_before_comparison(self) -> None:
        self.assertIn("PMETHOD_NORMALIZATION_WEAK",
                      self._mutate(lambda m: m["normalization"].__setitem__(
                          "strip_characters", [" "])))

    # -- custody ----------------------------------------------------------
    def test_the_platform_may_not_hold_what_it_forbids(self) -> None:
        self.assertIn("PMETHOD_CUSTODY_CLAIMED",
                      self._mutate(lambda m: m["custody"]["platform_holds"].append("cvv")))

    def test_the_provider_is_the_vault(self) -> None:
        self.assertIn("PMETHOD_CUSTODY_CLAIMED",
                      self._mutate(lambda m: m["custody"].__setitem__(
                          "vault_holder", "platform")))

    # -- token reference --------------------------------------------------
    def test_an_address_is_not_a_token(self) -> None:
        self.assertIn("PMETHOD_TOKEN_SCHEME",
                      self._mutate(lambda m: m["token_reference"]["schemes"].append("https")))

    def test_the_token_body_may_not_be_parsed(self) -> None:
        self.assertIn("PMETHOD_TOKEN_SCHEME",
                      self._mutate(lambda m: m["token_reference"].__setitem__("opaque", False)))

    def test_a_token_belongs_to_the_provider_that_issued_it(self) -> None:
        self.assertIn("PMETHOD_TOKEN_NOT_PROVIDER_SCOPED",
                      self._mutate(lambda m: m["token_reference"].__setitem__(
                          "provider_scoped", False)))

    # -- fingerprint ------------------------------------------------------
    def test_an_unkeyed_fingerprint_is_not_one_way(self) -> None:
        self.assertIn("PMETHOD_FINGERPRINT_REVERSIBLE",
                      self._mutate(lambda m: m["fingerprint"].__setitem__("keyed", False)))

    def test_a_fingerprint_may_not_cross_tenants(self) -> None:
        self.assertIn("PMETHOD_FINGERPRINT_CROSS_TENANT",
                      self._mutate(lambda m: m["fingerprint"].__setitem__(
                          "tenant_scoped", False)))

    def test_the_fingerprint_key_comes_from_key_management(self) -> None:
        self.assertIn("PMETHOD_KEY_SOURCE",
                      self._mutate(lambda m: m["fingerprint"].__setitem__(
                          "key_source", "governance/payment-method.json")))

    # -- display, retention, scope ----------------------------------------
    def test_a_forbidden_field_may_not_be_displayable(self) -> None:
        self.assertIn("PMETHOD_DISPLAY_FIELD_UNSAFE",
                      self._mutate(lambda m: m["display_allowlist"].append("cvv")))

    def test_retention_must_be_bounded(self) -> None:
        self.assertIn("PMETHOD_RETENTION_UNBOUNDED",
                      self._mutate(lambda m: m["retention"].__setitem__("bounded", False)))

    def test_retention_may_not_be_a_century(self) -> None:
        self.assertIn("PMETHOD_RETENTION_UNBOUNDED",
                      self._mutate(lambda m: m["retention"].__setitem__(
                          "fingerprint_days", 36500)))

    def test_references_are_tenant_scoped(self) -> None:
        self.assertIn("PMETHOD_TENANT_UNSCOPED",
                      self._mutate(lambda m: m["tenant_scope"].__setitem__(
                          "tenant_id_required", False)))

    def test_referencing_a_method_is_audited(self) -> None:
        self.assertIn("PMETHOD_UNAUDITED",
                      self._mutate(lambda m: m.__setitem__("audit_event", "")))

    # -- the rules the negative-control harness cannot reach ---------------
    def test_an_implementation_that_ignores_the_catalogue_is_unbound(self) -> None:
        self._implementations(bound=False, literals=())
        self.assertIn("PMETHOD_CATALOG_UNBOUND", _codes(self.root))

    def test_declaring_no_implementation_is_unbound(self) -> None:
        self.assertIn("PMETHOD_CATALOG_UNBOUND",
                      self._mutate(lambda m: m["conformance"].__setitem__(
                          "derived_implementations", [])))

    def test_a_second_copy_of_the_list_is_refused(self) -> None:
        """The defect this batch exists to prevent from coming back."""
        self._implementations(bound=True, literals=("pan", "cvv", "track2"))
        self.assertIn("PMETHOD_HARDCODED_LIST", _codes(self.root))

    def test_two_copied_names_are_not_yet_a_copy(self) -> None:
        """A rule that fires on any mention would be routed around within a week."""
        self._implementations(bound=True, literals=("pan", "cvv"))
        self.assertNotIn("PMETHOD_HARDCODED_LIST", _codes(self.root))

    def test_a_hand_edited_projection_is_drift(self) -> None:
        path = self.root / CONTRACT
        path.write_text(path.read_text(encoding="utf-8").replace(
            "normalized_names", "normalised_names", 1), encoding="utf-8")
        self.assertIn("PMETHOD_GENERATED_DRIFT", _codes(self.root))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
