"""B08 / AT-B08-01 — payment domain model and ubiquitous language.

The model is where the programme's money and tenancy rules are cheapest to
enforce: a monetary field typed as anything but integer minor units, or a
tenant-scoped entity without ``tenant_id``, is caught here rather than in a
reconciliation exception six months later.
"""
from __future__ import annotations

import json

from tools.paygov import domain, domaingen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class DomainModelHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = domain.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("domain-model", registry.names())

    def test_batch_mandated_entities_are_modelled(self):
        model = self.fixture.read("governance/domain-model.json")
        names = {e["name"] for e in model["entities"]}
        for required in ("Tenant", "Project", "Merchant", "PaymentIntent", "PaymentAttempt",
                         "Refund", "Dispute", "Subscription", "LedgerAccount",
                         "LedgerTransaction", "LedgerEntry", "ReconciliationRun",
                         "ReconciliationException"):
            self.assertIn(required, names, required)

    def test_every_monetary_field_uses_integer_minor_units(self):
        model = self.fixture.read("governance/domain-model.json")
        monetary = [(e["name"], f["name"]) for e in model["entities"] for f in e["fields"]
                    if domain.MONEY_FIELD.search(f["name"]) and not f["name"].endswith("_ref")]
        self.assertTrue(monetary)
        for entity, field in monetary:
            declared = next(f for e in model["entities"] if e["name"] == entity
                            for f in e["fields"] if f["name"] == field)
            self.assertEqual(declared["type"], "money_minor", f"{entity}.{field}")

    def test_no_floating_point_type_exists_in_the_type_system(self):
        model = self.fixture.read("governance/domain-model.json")
        for forbidden in ("float", "double", "decimal"):
            self.assertNotIn(forbidden, model["type_system"])
            self.assertIn(forbidden, model["forbidden_types"])

    def test_every_tenant_scoped_entity_carries_tenant_id(self):
        model = self.fixture.read("governance/domain-model.json")
        for entity in model["entities"]:
            if entity["tenant_scoped"]:
                self.assertIn("tenant_id", [f["name"] for f in entity["fields"]], entity["name"])

    def test_entity_tables_match_the_module_registry(self):
        model = self.fixture.read("governance/domain-model.json")
        owned = {m["name"]: set(m["owned_tables"])
                 for m in self.fixture.read("governance/module-registry.json")["modules"]}
        for entity in model["entities"]:
            self.assertIn(entity["table"], owned[entity["module"]], entity["name"])

    def test_payment_intent_is_bound_to_the_business_order_by_reference_only(self):
        model = self.fixture.read("governance/domain-model.json")
        intent = next(e for e in model["entities"] if e["name"] == "PaymentIntent")
        names = {f["name"] for f in intent["fields"]}
        self.assertIn("external_reference", names)
        for forbidden in ("sku", "quantity", "item_name", "shipping_address"):
            self.assertNotIn(forbidden, names)

    def test_generated_schema_is_deterministic_and_banner_marked(self):
        first = domaingen.render_all(REAL_ROOT)
        self.assertEqual(first, domaingen.render_all(REAL_ROOT))
        self.assertIn("GENERATED FILE", first["contracts/sql/schema.sql"])

    def test_generated_schema_encodes_money_and_tenant_constraints(self):
        sql = domaingen.schema_sql(REAL_ROOT)
        self.assertIn("amount_minor bigint NOT NULL", sql)
        self.assertIn("CONSTRAINT payment_intent_amount_minor_positive", sql)
        self.assertIn("ALTER TABLE payment_intent ENABLE ROW LEVEL SECURITY;", sql)
        self.assertNotIn("double precision", sql)
        self.assertNotIn("numeric", sql)


class DomainModelRejects(FixtureTestCase):
    REL = "governance/domain-model.json"

    def _validate(self):
        return domain.validate(self.fixture.root, Budget(seconds=60).start())

    def _entity(self, data, name):
        return next(e for e in data["entities"] if e["name"] == name)

    def _field(self, data, entity, field):
        return next(f for f in self._entity(data, entity)["fields"] if f["name"] == field)

    def test_rejects_floating_point_money(self):
        self.fixture.mutate(self.REL, lambda d: d["type_system"].append("float") or
                            self._field(d, "PaymentIntent", "amount_minor")
                            .__setitem__("type", "float"))
        problems = self._validate()
        self.assertIn("DOMAIN_MONEY_TYPE", self.codes(problems))
        self.assertIn("NN-05", self.rules(problems))

    def test_rejects_a_type_outside_the_type_system(self):
        self.fixture.mutate(self.REL, lambda d: self._field(d, "Refund", "amount_minor")
                            .__setitem__("type", "bigdecimal"))
        self.assertIn("DOMAIN_TYPE", self.codes(self._validate()))

    def test_rejects_a_forbidden_type_in_the_type_system(self):
        self.fixture.mutate(self.REL, lambda d: (d["type_system"].append("decimal"),
                                                 self._field(d, "Refund", "currency")
                                                 .__setitem__("type", "decimal")))
        self.assertIn("DOMAIN_FORBIDDEN_TYPE", self.codes(self._validate()))

    def test_rejects_tenant_scoped_entity_without_tenant_id(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "PaymentIntent").__setitem__(
            "fields", [f for f in self._entity(d, "PaymentIntent")["fields"]
                       if f["name"] != "tenant_id"]))
        problems = self._validate()
        self.assertIn("DOMAIN_TENANT_SCOPE", self.codes(problems))
        self.assertIn("NN-09", self.rules(problems))

    def test_rejects_business_order_field(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "PaymentIntent")["fields"].append(
            {"name": "item_quantity", "type": "int32", "nullable": False, "semantics": "x"}))
        problems = self._validate()
        self.assertIn("DOMAIN_BUSINESS_FIELD", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_table_not_owned_by_the_declared_module(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Refund")
                            .__setitem__("module", "risk-engine"))
        self.assertIn("DOMAIN_TABLE_OWNERSHIP", self.codes(self._validate()))

    def test_rejects_unknown_owning_module(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Refund")
                            .__setitem__("module", "ghost"))
        self.assertIn("DOMAIN_MODULE", self.codes(self._validate()))

    def test_rejects_two_entities_sharing_a_table(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Dispute")
                            .__setitem__("table", "refund"))
        self.assertIn("DOMAIN_TABLE_CONFLICT", self.codes(self._validate()))

    def test_rejects_non_snake_case_table(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Dispute")
                            .__setitem__("table", "Dispute"))
        self.assertIn("DOMAIN_TABLE", self.codes(self._validate()))

    def test_rejects_non_pascal_case_entity_name(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Dispute")
                            .__setitem__("name", "dispute"))
        self.assertIn("DOMAIN_NAME", self.codes(self._validate()))

    def test_rejects_entity_without_invariants(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Dispute")
                            .__setitem__("invariants", []))
        self.assertIn("DOMAIN_INVARIANT", self.codes(self._validate()))

    def test_rejects_entity_without_purpose(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Dispute")
                            .__setitem__("purpose", "x"))
        self.assertIn("DOMAIN_PURPOSE", self.codes(self._validate()))

    def test_rejects_duplicate_field_names(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Dispute")["fields"].append(
            dict(self._entity(d, "Dispute")["fields"][0])))
        self.assertIn("DOMAIN_FIELD", self.codes(self._validate()))

    def test_rejects_identity_field_that_does_not_exist(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Dispute")
                            .__setitem__("identity", ["ghost_id"]))
        self.assertIn("DOMAIN_IDENTITY", self.codes(self._validate()))

    def test_rejects_reference_to_an_unknown_entity(self):
        self.fixture.mutate(self.REL, lambda d: self._field(d, "Refund", "payment_intent_id")
                            .__setitem__("target", "Ghost"))
        self.assertIn("DOMAIN_REFERENCE", self.codes(self._validate()))

    def test_rejects_enum_without_values(self):
        self.fixture.mutate(self.REL, lambda d: self._field(d, "Refund", "reason")
                            .__setitem__("enum", []))
        self.assertIn("DOMAIN_ENUM", self.codes(self._validate()))

    def test_rejects_state_missing_from_the_state_field(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Refund")["states"].append("open"))
        self.assertIn("DOMAIN_STATE", self.codes(self._validate()))

    def test_rejects_entity_without_a_glossary_term(self):
        self.fixture.mutate("governance/glossary.json", lambda d: d.__setitem__(
            "terms", [t for t in d["terms"] if t["term_en"] != "Dispute"]))
        self.assertIn("DOMAIN_GLOSSARY", self.codes(self._validate()))

    def test_rejects_unreadable_model(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("DOMAIN_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("DOMAIN_VERSION", self.codes(self._validate()))

    def test_rejects_malformed_model_shape(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("entities", []))
        self.assertIn("DOMAIN_SHAPE", self.codes(self._validate()))

    def test_rejects_entity_without_fields(self):
        self.fixture.mutate(self.REL, lambda d: self._entity(d, "Dispute").__setitem__("fields", []))
        self.assertIn("DOMAIN_SHAPE", self.codes(self._validate()))


class GlossaryRejects(FixtureTestCase):
    REL = "governance/glossary.json"

    def _validate(self):
        return domain.validate(self.fixture.root, Budget(seconds=60).start())

    def test_rejects_duplicate_term(self):
        self.fixture.mutate(self.REL, lambda d: d["terms"].append(dict(d["terms"][0])))
        self.assertIn("DOMAIN_GLOSSARY_DUPLICATE", self.codes(self._validate()))

    def test_rejects_term_without_chinese_name(self):
        self.fixture.mutate(self.REL, lambda d: d["terms"][0].__setitem__("term_cn", ""))
        self.assertIn("DOMAIN_GLOSSARY_TERM", self.codes(self._validate()))

    def test_rejects_unknown_term_kind(self):
        self.fixture.mutate(self.REL, lambda d: d["terms"][0].__setitem__("kind", "misc"))
        self.assertIn("DOMAIN_GLOSSARY_KIND", self.codes(self._validate()))

    def test_rejects_empty_glossary(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("terms", []))
        self.assertIn("DOMAIN_GLOSSARY_SHAPE", self.codes(self._validate()))
