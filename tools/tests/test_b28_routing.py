"""B28 / AT-B28-01 — routing rules, canary rollout and configuration versions.

``test_the_same_payment_routes_the_same_way_under_the_same_version`` is the test
this batch exists for. Routing is only defensible if it can be replayed, because
the question "why did this payment go to that provider" is always asked later —
during a dispute, or looking at a reconciliation break — when the configuration
has already moved on.

``test_a_starved_provider_keeps_its_exploration_floor`` is the other one.
Routing to the best measured success rate is self-reinforcing: the provider that
stops receiving traffic can never produce the sample that would show it
recovered, so one bad afternoon becomes a permanently dead route.
"""
from __future__ import annotations

import json

from libs.routing.reference import router as R
from tools.paygov import routing, routinggen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/routing-policy.json"


def _rule(model, rid):
    return next(r for r in model["rules"] if r["id"] == rid)


def _factor(model, fid):
    return next(f for f in model["scoring"]["factors"] if f["id"] == fid)


class RoutingPolicyHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = routing.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("routing-policy", registry.names())

    def test_configuration_versions_are_immutable_and_recorded(self):
        versioning = self.fixture.read(REL)["config_versioning"]
        self.assertTrue(versioning["versions_are_immutable"])
        self.assertTrue(versioning["decision_records_config_version"])
        self.assertGreaterEqual(versioning["retain_versions"],
                                routing.MIN_RETAINED_VERSIONS)

    def test_activation_takes_two_people_and_a_dual_control_permission(self):
        model = self.fixture.read(REL)
        authz = self.fixture.read("governance/authorization.json")
        self.assertTrue(model["config_versioning"]["activation_requires_approval"])
        self.assertGreaterEqual(model["config_versioning"]["activation_approvers_required"], 2)
        permission = next(p for p in authz["permissions"]
                          if p["id"] == model["config_versioning"]["activation_permission"])
        self.assertTrue(permission["dual_control"])

    def test_routing_is_deterministic_and_replayable(self):
        determinism = self.fixture.read(REL)["determinism"]
        self.assertTrue(determinism["same_inputs_same_decision"])
        self.assertFalse(determinism["random_selection_allowed"])
        self.assertTrue(determinism["replayable"])
        self.assertIn(determinism["tie_break"], routing.TIE_BREAKS)

    def test_every_rule_has_a_unique_priority(self):
        rules = self.fixture.read(REL)["rules"]
        priorities = [r["priority"] for r in rules]
        self.assertEqual(len(set(priorities)), len(priorities))

    def test_every_rule_pins_an_amount_ceiling(self):
        for rule in self.fixture.read(REL)["rules"]:
            self.assertGreater(rule["when"]["max_amount_minor"], 0, rule["id"])

    def test_every_routing_target_can_actually_serve_the_combination(self):
        caps = self.fixture.read("governance/provider-capabilities.json")
        for rule in self.fixture.read(REL)["rules"]:
            when = rule["when"]
            for provider in rule["prefer"] + rule["fallback"]:
                self.assertTrue(
                    any(row["provider"] == provider and row["method"] == when["method"]
                        and when["region"] in row["regions"]
                        and when["currency"] in row["currencies"]
                        for row in caps["capabilities"]),
                    f"{rule['id']}/{provider}")

    def test_every_routing_target_has_a_binding(self):
        providers = {p["id"] for p in
                     self.fixture.read("governance/provider-accounts.json")["providers"]}
        for rule in self.fixture.read(REL)["rules"]:
            for provider in rule["prefer"] + rule["fallback"]:
                self.assertIn(provider, providers, rule["id"])

    def test_scoring_covers_cost_success_and_risk_and_sums_to_100(self):
        scoring = self.fixture.read(REL)["scoring"]
        self.assertEqual({f["id"] for f in scoring["factors"]}, routing.FACTORS)
        self.assertEqual(sum(f["weight"] for f in scoring["factors"]), 100)

    def test_success_rate_needs_a_real_sample_and_an_exploration_floor(self):
        scoring = self.fixture.read(REL)["scoring"]
        self.assertGreaterEqual(scoring["min_sample"], 100)
        self.assertGreaterEqual(scoring["exploration_floor_percent"],
                                routing.MIN_EXPLORATION_PERCENT)
        self.assertTrue(scoring["starvation_guard"])

    def test_the_canary_splits_on_the_payment_with_a_stable_hash(self):
        canary = self.fixture.read(REL)["canary"]
        self.assertEqual(canary["split_key"], "payment_intent_id")
        self.assertTrue(canary["stable_hash"])
        self.assertFalse(canary["random_split_allowed"])
        self.assertLessEqual(canary["max_percent"], routing.MAX_CANARY_PERCENT)

    def test_promotion_is_manual_and_rollback_is_automatic(self):
        canary = self.fixture.read(REL)["canary"]
        self.assertFalse(canary["auto_promote"])
        self.assertTrue(canary["auto_rollback_on_error_rate"])
        self.assertGreater(canary["error_rate_threshold_percent"], 0)

    def test_rollback_is_a_switch_not_a_release_and_is_not_gated(self):
        rollback = self.fixture.read(REL)["rollback"]
        self.assertTrue(rollback["to_existing_version_only"])
        self.assertFalse(rollback["requires_approval"])
        self.assertLessEqual(rollback["max_seconds"], routing.MAX_ROLLBACK_SECONDS)

    def test_the_shadow_cannot_move_money(self):
        simulation = self.fixture.read(REL)["simulation"]
        self.assertFalse(simulation["shadow_moves_money"])
        self.assertTrue(simulation["uses_production_config"])
        self.assertTrue(simulation["compares_against_live"])

    def test_a_retry_keeps_its_key_and_its_provider(self):
        retry = self.fixture.read(REL)["retry"]
        self.assertTrue(retry["reuse_idempotency_key"])
        self.assertFalse(retry["change_provider_on_retry_allowed"])
        self.assertGreaterEqual(len(retry["backoff_seconds"]), retry["max_attempts"] - 1)
        self.assertEqual(retry["backoff_seconds"], sorted(retry["backoff_seconds"]))

    def test_routing_changes_map_to_a_real_audit_class(self):
        audit = self.fixture.read("governance/audit-log.json")
        self.assertIn(self.fixture.read(REL)["audit_event_class"],
                      {c["id"] for c in audit["event_classes"]})


class RoutingGeneratedArtefacts(FixtureTestCase):
    def _validate(self):
        return routing.validate(self.fixture.root, Budget(seconds=60).start())

    def test_generated_artefacts_match_the_model(self):
        for rel, content in routinggen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_orders_rules_by_priority(self):
        contract = json.loads(routinggen.contract_json(REAL_ROOT))
        priorities = [r["priority"] for r in contract["rules"]]
        self.assertEqual(priorities, sorted(priorities))

    def test_document_shows_every_rule(self):
        text = routinggen.routing_markdown(REAL_ROOT)
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        for rule in model["rules"]:
            self.assertIn(rule["id"], text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/routing/ROUTING_POLICY.md", "hand written\n")
        self.assertIn("ROUTE_GENERATED_DRIFT", self.codes(self._validate()))

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/routing/policy.json")
        self.assertIn("ROUTE_GENERATED_MISSING", self.codes(self._validate()))

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("rules", [{"id": "x", "priority": 1}]))
        self.assertIn("ROUTE_GENERATED", self.codes(self._validate()))


class RoutingGateRejects(FixtureTestCase):
    def _validate(self):
        return routing.validate(self.fixture.root, Budget(seconds=60).start())

    def _assert(self, code):
        self.assertIn(code, self.codes(self._validate()))

    def _mutate(self, fn, code, rel=REL):
        self.fixture.mutate(rel, fn)
        self._assert(code)

    # -- shape ------------------------------------------------------------
    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self._assert("ROUTE_UNREADABLE")

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [1])
        self._assert("ROUTE_SHAPE")

    def test_rejects_a_bad_schema_version(self):
        self._mutate(lambda d: d.__setitem__("schema_version", "one"), "ROUTE_VERSION_FIELD")

    def test_rejects_a_missing_principle(self):
        self._mutate(lambda d: d.__setitem__("principle", ""), "ROUTE_PRINCIPLE")

    def test_rejects_a_non_object_versioning_block(self):
        self._mutate(lambda d: d.__setitem__("config_versioning", []), "ROUTE_SHAPE")

    def test_rejects_a_non_object_scoring_block(self):
        self._mutate(lambda d: d.__setitem__("scoring", []), "ROUTE_SHAPE")

    def test_rejects_a_non_object_canary_block(self):
        self._mutate(lambda d: d.__setitem__("canary", []), "ROUTE_SHAPE")

    def test_rejects_a_non_object_rollback_block(self):
        self._mutate(lambda d: d.__setitem__("rollback", []), "ROUTE_SHAPE")

    def test_rejects_a_non_object_retry_block(self):
        self._mutate(lambda d: d.__setitem__("retry", []), "ROUTE_SHAPE")

    def test_rejects_a_non_object_rule(self):
        self._mutate(lambda d: d["rules"].append("eu_cards"), "ROUTE_SHAPE")

    def test_rejects_a_non_object_factor(self):
        self._mutate(lambda d: d["scoring"]["factors"].append("cost"), "ROUTE_SHAPE")

    def test_rejects_a_rule_without_a_fallback_list(self):
        self._mutate(lambda d: _rule(d, "eu_cards").pop("fallback"), "ROUTE_SHAPE")

    # -- versioning -------------------------------------------------------
    def test_rejects_editable_configuration_versions(self):
        self._mutate(lambda d: d["config_versioning"].__setitem__("versions_are_immutable",
                                                                  False),
                     "ROUTE_VERSION_MUTABLE")

    def test_rejects_decisions_that_do_not_record_their_version(self):
        self._mutate(lambda d: d["config_versioning"].__setitem__(
            "decision_records_config_version", False), "ROUTE_DECISION_UNVERSIONED")

    def test_rejects_unapproved_activation(self):
        self._mutate(lambda d: d["config_versioning"].__setitem__(
            "activation_requires_approval", False), "ROUTE_ACTIVATION_UNAPPROVED")

    def test_rejects_single_person_activation(self):
        self._mutate(lambda d: d["config_versioning"].__setitem__(
            "activation_approvers_required", 1), "ROUTE_ACTIVATION_SINGLE_PERSON")

    def test_rejects_an_activation_permission_without_dual_control(self):
        self.fixture.mutate("governance/authorization.json",
                            lambda d: next(p for p in d["permissions"]
                                           if p["id"] == "config.write")
                            .__setitem__("dual_control", False))
        self._assert("ROUTE_ACTIVATION_SINGLE_PERSON")

    def test_rejects_an_unknown_activation_permission(self):
        self._mutate(lambda d: d["config_versioning"].__setitem__("activation_permission",
                                                                  "made.up"),
                     "ROUTE_PERMISSION_UNKNOWN")

    def test_rejects_keeping_too_few_versions_to_roll_back_to(self):
        self._mutate(lambda d: d["config_versioning"].__setitem__("retain_versions", 2),
                     "ROUTE_HISTORY_TOO_SHORT")

    def test_rejects_unexplained_versioning(self):
        self._mutate(lambda d: d["config_versioning"].__setitem__("notes", ""),
                     "ROUTE_VERSION_NOTES")

    # -- determinism ------------------------------------------------------
    def test_rejects_a_missing_determinism_policy(self):
        self._mutate(lambda d: d.__setitem__("determinism", []), "ROUTE_NONDETERMINISTIC")

    def test_rejects_routing_that_may_differ_between_runs(self):
        self._mutate(lambda d: d["determinism"].__setitem__("same_inputs_same_decision", False),
                     "ROUTE_NONDETERMINISTIC")

    def test_rejects_random_selection(self):
        self._mutate(lambda d: d["determinism"].__setitem__("random_selection_allowed", True),
                     "ROUTE_NONDETERMINISTIC")

    def test_rejects_an_unreplayable_decision(self):
        self._mutate(lambda d: d["determinism"].__setitem__("replayable", False),
                     "ROUTE_UNREPLAYABLE")

    def test_rejects_a_missing_tie_break(self):
        self._mutate(lambda d: d["determinism"].__setitem__("tie_break", "whatever"),
                     "ROUTE_NO_TIE_BREAK")

    def test_rejects_unexplained_determinism(self):
        self._mutate(lambda d: d["determinism"].__setitem__("notes", ""),
                     "ROUTE_DETERMINISM_NOTES")

    # -- rules ------------------------------------------------------------
    def test_rejects_a_policy_with_no_rules(self):
        self._mutate(lambda d: d.__setitem__("rules", []), "ROUTE_NO_RULES")

    def test_rejects_a_non_snake_case_rule_id(self):
        self._mutate(lambda d: _rule(d, "eu_cards").__setitem__("id", "EU Cards"),
                     "ROUTE_RULE_ID")

    def test_rejects_a_duplicate_rule(self):
        self._mutate(lambda d: d["rules"].append({**_rule(d, "eu_cards"), "priority": 99}),
                     "ROUTE_RULE_DUPLICATE")

    def test_rejects_a_rule_without_a_priority(self):
        self._mutate(lambda d: _rule(d, "eu_cards").__setitem__("priority", 0),
                     "ROUTE_NO_PRIORITY")

    def test_rejects_two_rules_at_the_same_priority(self):
        self._mutate(lambda d: _rule(d, "eu_cards").__setitem__(
            "priority", _rule(d, "hk_cards")["priority"]), "ROUTE_PRIORITY_COLLISION")

    def test_rejects_a_rule_that_matches_nothing(self):
        self._mutate(lambda d: _rule(d, "eu_cards").__setitem__("when", "always"),
                     "ROUTE_RULE_NO_MATCH")

    def test_rejects_a_rule_for_a_region_the_matrix_does_not_define(self):
        self._mutate(lambda d: _rule(d, "eu_cards")["when"].__setitem__("region", "US"),
                     "ROUTE_REGION_UNKNOWN")

    def test_rejects_a_rule_for_a_method_the_matrix_does_not_define(self):
        self._mutate(lambda d: _rule(d, "eu_cards")["when"].__setitem__("method", "crypto"),
                     "ROUTE_METHOD_UNKNOWN")

    def test_rejects_a_rule_that_pins_no_currency(self):
        self._mutate(lambda d: _rule(d, "eu_cards")["when"].__setitem__("currency", ""),
                     "ROUTE_RULE_NO_CURRENCY")

    def test_rejects_a_rule_with_no_amount_ceiling(self):
        self._mutate(lambda d: _rule(d, "eu_cards")["when"].__setitem__("max_amount_minor", 0),
                     "ROUTE_NO_AMOUNT_CEILING")

    def test_rejects_a_rule_that_prefers_nobody(self):
        self._mutate(lambda d: _rule(d, "eu_cards").__setitem__("prefer", []),
                     "ROUTE_RULE_NO_TARGET")

    def test_rejects_a_rule_listing_a_provider_twice(self):
        self._mutate(lambda d: _rule(d, "eu_cards").__setitem__("fallback", ["stripe"]),
                     "ROUTE_TARGET_DUPLICATE")

    def test_rejects_a_target_with_no_binding(self):
        self._mutate(lambda d: _rule(d, "eu_cards").__setitem__("prefer", ["klarna"]),
                     "ROUTE_PROVIDER_UNKNOWN")

    def test_rejects_a_target_the_capability_matrix_cannot_serve(self):
        self._mutate(lambda d: _rule(d, "eu_cards").__setitem__("prefer", ["wechat"]),
                     "ROUTE_TARGET_INCAPABLE")

    def test_rejects_an_unexplained_rule(self):
        self._mutate(lambda d: _rule(d, "eu_cards").__setitem__("notes", ""),
                     "ROUTE_RULE_NOTES")

    # -- scoring ----------------------------------------------------------
    def test_rejects_scoring_with_no_factors(self):
        self._mutate(lambda d: d["scoring"].__setitem__("factors", []), "ROUTE_NO_FACTORS")

    def test_rejects_a_missing_factor(self):
        self._mutate(lambda d: d["scoring"].__setitem__(
            "factors", [f for f in d["scoring"]["factors"] if f["id"] != "risk"]),
            "ROUTE_NO_FACTORS")

    def test_rejects_an_unknown_factor(self):
        self._mutate(lambda d: _factor(d, "cost").__setitem__("id", "vibes"),
                     "ROUTE_FACTOR_UNKNOWN")

    def test_rejects_a_duplicate_factor(self):
        self._mutate(lambda d: d["scoring"]["factors"].append(dict(_factor(d, "cost"))),
                     "ROUTE_FACTOR_DUPLICATE")

    def test_rejects_a_factor_with_no_weight(self):
        self._mutate(lambda d: _factor(d, "cost").__setitem__("weight", 0),
                     "ROUTE_FACTOR_WEIGHT")

    def test_rejects_weights_that_do_not_sum_to_100(self):
        self._mutate(lambda d: _factor(d, "cost").__setitem__("weight", 31),
                     "ROUTE_WEIGHTS_UNNORMALISED")

    def test_rejects_an_unexplained_factor(self):
        self._mutate(lambda d: _factor(d, "cost").__setitem__("notes", ""),
                     "ROUTE_FACTOR_NOTES")

    def test_rejects_an_unbounded_measurement_window(self):
        self._mutate(lambda d: d["scoring"].__setitem__("window_minutes", 0),
                     "ROUTE_WINDOW_UNBOUNDED")

    def test_rejects_judging_a_provider_on_ten_payments(self):
        self._mutate(lambda d: d["scoring"].__setitem__("min_sample", 10),
                     "ROUTE_SAMPLE_TOO_SMALL")

    def test_rejects_routing_with_no_exploration_floor(self):
        self._mutate(lambda d: d["scoring"].__setitem__("exploration_floor_percent", 0),
                     "ROUTE_NO_EXPLORATION")

    def test_rejects_dropping_the_starvation_guard(self):
        self._mutate(lambda d: d["scoring"].__setitem__("starvation_guard", False),
                     "ROUTE_NO_EXPLORATION")

    def test_rejects_an_exploration_floor_that_eats_the_policy(self):
        self._mutate(lambda d: d["scoring"].__setitem__("exploration_floor_percent", 60),
                     "ROUTE_EXPLORATION_EXCESSIVE")

    def test_rejects_unexplained_scoring(self):
        self._mutate(lambda d: d["scoring"].__setitem__("notes", ""), "ROUTE_SCORING_NOTES")

    # -- canary -----------------------------------------------------------
    def test_rejects_a_random_canary_split(self):
        self._mutate(lambda d: d["canary"].__setitem__("random_split_allowed", True),
                     "ROUTE_RANDOM_SPLIT")

    def test_rejects_an_unstable_hash(self):
        self._mutate(lambda d: d["canary"].__setitem__("stable_hash", False),
                     "ROUTE_RANDOM_SPLIT")

    def test_rejects_splitting_on_anything_but_the_payment(self):
        self._mutate(lambda d: d["canary"].__setitem__("split_key", "user_id"),
                     "ROUTE_SPLIT_KEY")

    def test_rejects_a_canary_that_is_not_a_canary(self):
        self._mutate(lambda d: d["canary"].__setitem__("max_percent", 90),
                     "ROUTE_CANARY_UNBOUNDED")

    def test_rejects_a_canary_nobody_observes(self):
        self._mutate(lambda d: d["canary"].__setitem__("min_observation_minutes", 0),
                     "ROUTE_CANARY_UNOBSERVED")

    def test_rejects_automatic_promotion(self):
        self._mutate(lambda d: d["canary"].__setitem__("auto_promote", True),
                     "ROUTE_AUTO_PROMOTE")

    def test_rejects_dropping_automatic_rollback(self):
        self._mutate(lambda d: d["canary"].__setitem__("auto_rollback_on_error_rate", False),
                     "ROUTE_NO_AUTO_ROLLBACK")

    def test_rejects_a_rollback_threshold_that_never_fires(self):
        self._mutate(lambda d: d["canary"].__setitem__("error_rate_threshold_percent", 80),
                     "ROUTE_ROLLBACK_THRESHOLD")

    def test_rejects_an_unexplained_canary(self):
        self._mutate(lambda d: d["canary"].__setitem__("notes", ""), "ROUTE_CANARY_NOTES")

    # -- rollback, simulation, retry --------------------------------------
    def test_rejects_rollback_by_editing_the_configuration_back(self):
        self._mutate(lambda d: d["rollback"].__setitem__("to_existing_version_only", False),
                     "ROUTE_ROLLBACK_IS_A_RELEASE")

    def test_rejects_gating_rollback_behind_an_approval(self):
        self._mutate(lambda d: d["rollback"].__setitem__("requires_approval", True),
                     "ROUTE_ROLLBACK_GATED")

    def test_rejects_a_slow_rollback(self):
        self._mutate(lambda d: d["rollback"].__setitem__("max_seconds", 3600),
                     "ROUTE_ROLLBACK_SLOW")

    def test_rejects_an_unexplained_rollback(self):
        self._mutate(lambda d: d["rollback"].__setitem__("notes", ""), "ROUTE_ROLLBACK_NOTES")

    def test_rejects_a_missing_simulation_mode(self):
        self._mutate(lambda d: d.__setitem__("simulation", []), "ROUTE_NO_SIMULATION")

    def test_rejects_a_shadow_that_can_move_money(self):
        self._mutate(lambda d: d["simulation"].__setitem__("shadow_moves_money", True),
                     "ROUTE_SHADOW_MOVES_MONEY")

    def test_rejects_a_simulation_against_a_different_configuration(self):
        self._mutate(lambda d: d["simulation"].__setitem__("uses_production_config", False),
                     "ROUTE_SIMULATION_DETACHED")

    def test_rejects_a_simulation_nobody_compares(self):
        self._mutate(lambda d: d["simulation"].__setitem__("compares_against_live", False),
                     "ROUTE_SIMULATION_UNCOMPARED")

    def test_rejects_an_unexplained_simulation(self):
        self._mutate(lambda d: d["simulation"].__setitem__("notes", ""),
                     "ROUTE_SIMULATION_NOTES")

    def test_rejects_a_retry_with_a_new_key(self):
        self._mutate(lambda d: d["retry"].__setitem__("reuse_idempotency_key", False),
                     "ROUTE_RETRY_NEW_KEY")

    def test_rejects_a_retry_that_changes_provider(self):
        self._mutate(lambda d: d["retry"].__setitem__("change_provider_on_retry_allowed", True),
                     "ROUTE_RETRY_CHANGES_PROVIDER")

    def test_rejects_unbounded_retries(self):
        self._mutate(lambda d: d["retry"].__setitem__("max_attempts", 0),
                     "ROUTE_RETRY_UNBOUNDED")

    def test_rejects_retries_with_no_backoff(self):
        self._mutate(lambda d: d["retry"].__setitem__("backoff_seconds", []),
                     "ROUTE_RETRY_NO_BACKOFF")

    def test_rejects_a_backoff_that_shrinks(self):
        self._mutate(lambda d: d["retry"].__setitem__("backoff_seconds", [25, 5, 1]),
                     "ROUTE_RETRY_NO_BACKOFF")

    def test_rejects_an_unexplained_retry_policy(self):
        self._mutate(lambda d: d["retry"].__setitem__("notes", ""), "ROUTE_RETRY_NOTES")

    def test_rejects_an_unknown_audit_class(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "routing.vanished"),
                     "ROUTE_AUDIT_CLASS_UNKNOWN")


class RouterReferenceModel(FixtureTestCase):
    MODEL = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
    CAPS = json.loads((REAL_ROOT / "governance/provider-capabilities.json")
                      .read_text(encoding="utf-8"))

    def router(self) -> R.Router:
        router = R.Router(self.MODEL, self.CAPS)
        router.publish("v1", self.MODEL["rules"])
        router.activate("v1", approvers=("risk", "ops"), actor="release")
        return router

    def payment(self, intent="pi_0001", region="EU", method="card", currency="EUR",
                amount=5000, key="idem_0001") -> R.Payment:
        return R.Payment(intent_id=intent, region=region, method=method, currency=currency,
                         amount_minor=amount, idempotency_key=key)

    def scores(self, **overrides) -> dict:
        base = {"stripe": {"success_rate": 9800, "cost": 7000, "risk": 9000, "sample": 5000},
                "paypal": {"success_rate": 9500, "cost": 8000, "risk": 8000, "sample": 5000},
                "wechat": {"success_rate": 9900, "cost": 9000, "risk": 9500, "sample": 5000},
                "alipay": {"success_rate": 9900, "cost": 9000, "risk": 9500, "sample": 5000}}
        base.update(overrides)
        return base

    def two_target_router(self) -> R.Router:
        router = R.Router(self.MODEL, self.CAPS)
        router.publish("m1", [{"id": "eu_cards", "priority": 10,
                               "when": {"region": "EU", "method": "card", "currency": "EUR",
                                        "max_amount_minor": 2000000},
                               "prefer": ["stripe"], "fallback": ["paypal"], "notes": "x"}])
        router.activate("m1", approvers=("risk", "ops"), actor="release")
        return router

    def refused(self, fn, code):
        with self.assertRaises(R.RoutingRefused) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    # -- determinism ------------------------------------------------------
    def test_the_same_payment_routes_the_same_way_under_the_same_version(self):
        router = self.router()
        first = router.route(self.payment(), self.scores())
        second = router.route(self.payment(), self.scores())
        self.assertEqual((first.provider, first.rule_id, first.config_version),
                         (second.provider, second.rule_id, second.config_version))
        # And the recorded decision replays months later against its own version.
        self.assertTrue(router.replay(self.payment(), self.scores(), first))

    def test_a_decision_carries_its_version_and_its_reasons(self):
        decision = self.router().route(self.payment(), self.scores())
        self.assertEqual(decision.config_version, "v1")
        self.assertTrue(any(r.startswith("rule=") for r in decision.reasons))
        self.assertTrue(any(r.startswith("score=") for r in decision.reasons))

    def test_a_tie_is_broken_by_provider_id_not_by_chance(self):
        router = self.two_target_router()
        tied = {"stripe": {"success_rate": 10000, "cost": 10000, "risk": 10000},
                "paypal": {"success_rate": 10000, "cost": 10000, "risk": 10000}}
        self.assertEqual(router.rank(["stripe", "paypal"], tied)[0], "paypal")
        self.assertEqual(router.rank(["paypal", "stripe"], tied)[0], "paypal")

    def test_an_unroutable_payment_is_refused_not_guessed(self):
        router = self.router()
        self.refused(lambda: router.route(self.payment(region="SG", currency="USD"),
                                          self.scores()), R.UNROUTABLE)

    def test_an_amount_above_the_ceiling_is_refused(self):
        router = self.router()
        self.refused(lambda: router.route(self.payment(amount=10 ** 9), self.scores()),
                     R.AMOUNT_ABOVE_CEILING)

    def test_routing_against_an_unknown_version_is_refused(self):
        router = self.router()
        self.refused(lambda: router.route(self.payment(), self.scores(), version="v9"),
                     R.UNKNOWN_VERSION)

    # -- versions ---------------------------------------------------------
    def test_a_published_version_cannot_be_republished(self):
        router = self.router()
        self.refused(lambda: router.publish("v1", self.MODEL["rules"]), R.VERSION_IMMUTABLE)

    def test_activation_needs_two_approvers_who_are_not_the_actor(self):
        router = self.router()
        router.publish("v2", self.MODEL["rules"])
        self.refused(lambda: router.activate("v2", approvers=("ops",), actor="ops"),
                     R.SELF_APPROVAL)
        self.refused(lambda: router.activate("v2", approvers=("ops",), actor="release"),
                     R.NOT_APPROVED)
        self.refused(lambda: router.activate("v9", approvers=("ops", "risk"), actor="release"),
                     R.UNKNOWN_VERSION)
        self.assertEqual(router.activate("v2", approvers=("ops", "risk"), actor="release"),
                         "v2")

    def test_rollback_switches_to_the_previous_version_without_approval(self):
        router = self.router()
        router.publish("v2", self.MODEL["rules"])
        router.activate("v2", approvers=("ops", "risk"), actor="release")
        self.assertEqual(router.rollback(), "v1")
        self.assertEqual(router.route(self.payment(), self.scores()).config_version, "v1")

    def test_rollback_with_no_previous_version_is_refused(self):
        router = self.router()
        self.refused(router.rollback, R.NO_PREVIOUS_VERSION)

    def test_rules_of_an_unknown_version_are_refused(self):
        self.refused(lambda: self.router().rules("v9"), R.UNKNOWN_VERSION)

    # -- exploration ------------------------------------------------------
    def test_a_starved_provider_keeps_its_exploration_floor(self):
        router = self.two_target_router()
        floor = self.MODEL["scoring"]["exploration_floor_percent"]
        share = router.allocation(["stripe", "paypal"], self.scores())
        self.assertEqual(share["paypal"], floor)
        self.assertEqual(share["stripe"], 100 - floor)
        # Even at a measured success rate of zero: without traffic it can never
        # produce the sample that would show it recovered.
        dead = router.allocation(["stripe", "paypal"],
                                 self.scores(paypal={"success_rate": 0, "cost": 0,
                                                     "risk": 0, "sample": 5000}))
        self.assertEqual(dead["paypal"], floor)

    def test_a_single_candidate_takes_everything(self):
        router = self.two_target_router()
        self.assertEqual(router.allocation(["stripe"], self.scores()), {"stripe": 100})
        self.assertEqual(router.allocation([], self.scores()), {})

    def test_a_small_sample_is_not_enough_to_judge_a_provider(self):
        router = self.two_target_router()
        self.assertFalse(router.has_enough_sample(
            "paypal", self.scores(paypal={"success_rate": 10000, "sample": 3})))
        self.assertTrue(router.has_enough_sample("paypal", self.scores()))

    def test_a_float_score_is_refused(self):
        # Not pedantry: a weighted sum of binary floats can order two providers
        # differently on two machines, which breaks replay.
        router = self.two_target_router()
        self.refused(lambda: router.score("stripe", {"stripe": {"success_rate": 0.98}}),
                     R.SCORE_NOT_INTEGER)

    def test_scoring_weights_the_declared_factors(self):
        router = self.two_target_router()
        self.assertGreater(router.score("stripe", self.scores()),
                           router.score("paypal", self.scores()))
        self.assertEqual(router.score("unknown", self.scores()), 0)

    # -- canary -----------------------------------------------------------
    def test_a_payment_always_lands_in_the_same_canary_branch(self):
        router = self.router()
        percent = self.MODEL["canary"]["max_percent"]
        for index in range(50):
            intent = f"pi_{index:04d}"
            first = router.branch(self.payment(intent=intent), percent)
            self.assertEqual(router.branch(self.payment(intent=intent), percent), first)

    def test_a_retry_stays_in_its_branch(self):
        router = self.router()
        percent = self.MODEL["canary"]["max_percent"]
        # Same payment, different idempotency key material: still the same branch.
        self.assertEqual(router.branch(self.payment(intent="pi_0001"), percent),
                         router.branch(self.payment(intent="pi_0001", key="retry"), percent))

    def test_the_canary_actually_splits_traffic(self):
        router = self.router()
        percent = self.MODEL["canary"]["max_percent"]
        branches = [router.branch(self.payment(intent=f"pi_{i:04d}"), percent)
                    for i in range(300)]
        self.assertGreater(branches.count("canary"), 0)
        self.assertGreater(branches.count("stable"), 0)

    def test_a_canary_above_the_ceiling_is_refused(self):
        router = self.router()
        self.refused(lambda: router.branch(self.payment(),
                                           self.MODEL["canary"]["max_percent"] + 1),
                     R.CANARY_TOO_LARGE)

    def test_an_unsupported_split_key_is_refused(self):
        model = json.loads(json.dumps(self.MODEL))
        model["canary"]["split_key"] = "user_id"
        router = R.Router(model, self.CAPS)
        self.refused(lambda: router.split_value(self.payment()), R.UNKNOWN_SPLIT_KEY)

    def test_the_bucket_is_a_stable_hash(self):
        self.assertEqual(R.stable_bucket("pi_0001"), R.stable_bucket("pi_0001"))
        self.assertLess(R.stable_bucket("pi_0001"), 100)

    # -- simulation and retries -------------------------------------------
    def test_the_shadow_decides_but_cannot_send(self):
        router = self.router()
        decision = router.simulate(self.payment(), self.scores(), version="v1")
        self.refused(lambda: router.execute(decision, shadow=True), R.SHADOW_CANNOT_MOVE_MONEY)
        self.assertEqual(router.execute(decision, shadow=False), "SENT")

    def test_a_retry_keeps_its_key_and_its_provider(self):
        router = self.router()
        decision = router.route(self.payment(), self.scores())
        attempt = R.Attempt(payment=self.payment(), decision=decision)
        self.refused(lambda: router.retry(attempt, self.payment(key="other")),
                     R.RETRY_KEY_CHANGED)
        self.refused(lambda: router.retry(attempt, self.payment(), provider="paypal"),
                     R.RETRY_PROVIDER_CHANGED)
        self.assertEqual(router.retry(attempt, self.payment()).count, 2)

    def test_retries_are_bounded_and_back_off(self):
        router = self.router()
        decision = router.route(self.payment(), self.scores())
        attempt = R.Attempt(payment=self.payment(), decision=decision)
        for _ in range(self.MODEL["retry"]["max_attempts"] - 1):
            router.retry(attempt, self.payment())
        self.refused(lambda: router.retry(attempt, self.payment()), R.RETRIES_EXHAUSTED)
        self.assertLess(router.backoff(2), router.backoff(3))
