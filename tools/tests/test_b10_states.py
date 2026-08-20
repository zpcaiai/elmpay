"""B10 / AT-B10-01 — payment state machines and business invariants.

B08 said which states exist. These tests are about what may change into what,
who is allowed to say so, and what must be true for the change to be replayable.

The rules worth staring at:

* ``STATE_UNTRUSTED_SUCCESS`` — a success state written by anything other than a
  verified provider event or a server-side query. This is the single rule that
  stands between the platform and "the browser came back to /success, so we
  shipped the goods" (NN-03, AC-01).
* ``STATE_IDEMPOTENCY`` — a transition with no idempotency key. Webhooks are
  retried by design; a transition that cannot recognise a replay is a duplicate
  capture waiting for a bad afternoon (NN-04, CTRL-003).
* ``STATE_UNDECLARED_COMPENSATION`` — an edge that walks progress backwards
  without admitting it. Undoing a state is a money movement; it has to be
  labelled so the ledger and the audit trail can find it.
"""
from __future__ import annotations

from tools.paygov import states, stategen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class StateModelHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = states.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("state-machines", registry.names())

    def test_every_entity_with_states_has_a_machine(self):
        model = self.fixture.read("governance/state-machines.json")
        domain = self.fixture.read("governance/domain-model.json")
        with_states = {e["name"] for e in domain["entities"] if e.get("states")}
        modelled = {m["entity"] for m in model["machines"]}
        self.assertEqual(with_states, modelled)

    def test_batch_mandated_machines_exist(self):
        model = self.fixture.read("governance/state-machines.json")
        names = {m["name"] for m in model["machines"]}
        for required in ("payment-intent", "refund", "subscription", "dispute",
                         "reconciliation-run"):
            self.assertIn(required, names)

    def test_every_transition_declares_a_guard_and_an_idempotency_key(self):
        model = self.fixture.read("governance/state-machines.json")
        total = 0
        for machine in model["machines"]:
            for tr in machine["transitions"]:
                total += 1
                self.assertTrue(tr["guard"].strip(), tr)
                self.assertTrue(states.IDEMPOTENCY.match(tr["idempotency"]), tr)
        self.assertGreaterEqual(total, 40)

    def test_success_states_are_only_written_by_trusted_actors(self):
        model = self.fixture.read("governance/state-machines.json")
        trusted = {a["id"] for a in model["actors"] if a.get("trusted_for_success")}
        self.assertEqual(trusted, {"provider-event", "reconciliation"})
        for machine in model["machines"]:
            success = set(model["success_states"].get(machine["entity"], []))
            for tr in machine["transitions"]:
                if tr["to"] in success:
                    self.assertIn(tr["actor"], trusted, tr)

    def test_no_client_actor_can_reach_a_success_state(self):
        """The redirect-is-not-proof rule, stated as a test rather than a slogan."""
        model = self.fixture.read("governance/state-machines.json")
        for machine in model["machines"]:
            success = set(model["success_states"].get(machine["entity"], []))
            for tr in machine["transitions"]:
                if tr["actor"] in ("customer", "merchant"):
                    self.assertNotIn(tr["to"], success, tr)

    def test_timeout_does_not_mean_failure(self):
        """AC-01: an ambiguous attempt must land in 'unknown', never in 'failed'."""
        model = self.fixture.read("governance/state-machines.json")
        attempt = next(m for m in model["machines"] if m["name"] == "payment-attempt")
        timeout = next(t for t in attempt["transitions"] if t["event"] == "network.timeout")
        self.assertEqual(timeout["to"], "unknown")
        self.assertNotIn("unknown", attempt["terminal"])
        resolvers = {t["actor"] for t in attempt["transitions"] if t["from"] == "unknown"}
        self.assertEqual(resolvers, {"reconciliation"})

    def test_every_state_is_reachable_and_every_non_terminal_state_can_progress(self):
        model = self.fixture.read("governance/state-machines.json")
        for machine in model["machines"]:
            edges = {s: set() for s in machine["states"]}
            for tr in machine["transitions"]:
                edges[tr["from"]].add(tr["to"])
            reachable = states._reach(machine["initial"], edges)
            for state in machine["states"]:
                if state != machine["initial"]:
                    self.assertIn(state, reachable, f"{machine['name']}:{state}")
                if state in machine["terminal"]:
                    self.assertFalse(edges[state], f"{machine['name']}:{state}")
                else:
                    self.assertTrue(edges[state], f"{machine['name']}:{state}")

    def test_refund_cannot_be_undone_once_the_money_left(self):
        model = self.fixture.read("governance/state-machines.json")
        refund = next(m for m in model["machines"] if m["name"] == "refund")
        self.assertNotIn("succeeded", [t["from"] for t in refund["transitions"]])

    def test_generated_document_matches_the_model(self):
        rendered = stategen.states_markdown(REAL_ROOT)
        on_disk = (REAL_ROOT / "docs/domain/STATE_MACHINES.md").read_text(encoding="utf-8")
        self.assertEqual(rendered, on_disk)

    def test_generated_document_carries_the_banner_and_every_transition(self):
        rendered = stategen.states_markdown(REAL_ROOT)
        self.assertIn("GENERATED FILE", rendered)
        model = self.fixture.read("governance/state-machines.json")
        for machine in model["machines"]:
            self.assertIn(machine["name"], rendered)
            for tr in machine["transitions"]:
                self.assertIn(tr["event"], rendered)


class StateGateRejects(FixtureTestCase):
    REL = "governance/state-machines.json"

    def _validate(self):
        return states.validate(self.fixture.root, Budget(seconds=60).start())

    def _machine(self, data, name):
        return next(m for m in data["machines"] if m["name"] == name)

    def test_rejects_unreadable_model(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("STATE_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("STATE_VERSION", self.codes(self._validate()))

    def test_rejects_empty_machine_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("machines", []))
        self.assertIn("STATE_SHAPE", self.codes(self._validate()))

    def test_rejects_a_model_with_no_trusted_actor(self):
        def strip(d):
            for actor in d["actors"]:
                actor["trusted_for_success"] = False
        self.fixture.mutate(self.REL, strip)
        self.assertIn("STATE_SHAPE", self.codes(self._validate()))

    def test_rejects_a_success_state_written_by_the_merchant(self):
        """The core control: only verified provider evidence may assert success."""
        self.fixture.mutate(self.REL, lambda d: next(
            t for t in self._machine(d, "payment-intent")["transitions"]
            if t["to"] == "captured").__setitem__("actor", "merchant"))
        problems = self._validate()
        self.assertIn("STATE_UNTRUSTED_SUCCESS", self.codes(problems))
        self.assertIn("NN-03", self.rules(problems))

    def test_rejects_a_success_state_written_by_the_customer(self):
        self.fixture.mutate(self.REL, lambda d: next(
            t for t in self._machine(d, "payment-intent")["transitions"]
            if t["to"] == "authorized").__setitem__("actor", "customer"))
        self.assertIn("STATE_UNTRUSTED_SUCCESS", self.codes(self._validate()))

    def test_rejects_a_transition_without_an_idempotency_key(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "payment-intent")["transitions"][0].pop("idempotency"))
        problems = self._validate()
        self.assertIn("STATE_IDEMPOTENCY", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_a_malformed_idempotency_key(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund")["transitions"][0].__setitem__("idempotency", "Refund ID!"))
        self.assertIn("STATE_IDEMPOTENCY", self.codes(self._validate()))

    def test_rejects_a_backwards_edge_that_does_not_admit_it(self):
        self.fixture.mutate(self.REL, lambda d: next(
            t for t in self._machine(d, "subscription")["transitions"]
            if t["from"] == "past_due" and t["to"] == "active").__setitem__("kind", "forward"))
        problems = self._validate()
        self.assertIn("STATE_UNDECLARED_COMPENSATION", self.codes(problems))
        self.assertIn("NN-06", self.rules(problems))

    def test_rejects_a_compensating_edge_with_no_effects(self):
        self.fixture.mutate(self.REL, lambda d: next(
            t for t in self._machine(d, "subscription")["transitions"]
            if t["from"] == "past_due" and t["to"] == "active").__setitem__("effects", []))
        self.assertIn("STATE_COMPENSATION_WITHOUT_EFFECT", self.codes(self._validate()))

    def test_rejects_an_unreachable_state(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(d, "dispute")["transitions"].remove(
            next(t for t in self._machine(d, "dispute")["transitions"] if t["to"] == "won")))
        self.assertIn("STATE_UNREACHABLE", self.codes(self._validate()))

    def test_rejects_a_non_terminal_dead_end(self):
        def strand(d):
            machine = self._machine(d, "reconciliation-exception")
            machine["transitions"] = [t for t in machine["transitions"]
                                      if t["from"] != "investigating"]
        self.fixture.mutate(self.REL, strand)
        self.assertIn("STATE_DEAD_END", self.codes(self._validate()))

    def test_rejects_a_terminal_state_that_still_moves(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(d, "refund")["transitions"].append(
            {"from": "succeeded", "to": "canceled", "event": "operator.undo",
             "actor": "operator", "kind": "compensating", "guard": "运营手工撤销退款",
             "effects": ["写入审计事件"], "idempotency": "refund_id"}))
        self.assertIn("STATE_TERMINAL_EXIT", self.codes(self._validate()))

    def test_rejects_a_missing_terminal_state(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._machine(d, "dispute").__setitem__("terminal", []))
        self.assertIn("STATE_TERMINAL", self.codes(self._validate()))

    def test_rejects_an_initial_state_outside_the_state_set(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._machine(d, "refund").__setitem__("initial", "limbo"))
        self.assertIn("STATE_INITIAL", self.codes(self._validate()))

    def test_rejects_states_that_disagree_with_the_domain_model(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "dispute")["states"].append("appealed"))
        self.assertIn("STATE_SET", self.codes(self._validate()))

    def test_rejects_a_machine_for_an_unknown_entity(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund").__setitem__("entity", "Wormhole"))
        self.assertIn("STATE_ENTITY", self.codes(self._validate()))

    def test_rejects_an_entity_left_without_a_machine(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "machines", [m for m in d["machines"] if m["name"] != "dispute"]))
        self.assertIn("STATE_MACHINE_COVERAGE", self.codes(self._validate()))

    def test_rejects_two_machines_with_the_same_name(self):
        self.fixture.mutate(self.REL, lambda d: d["machines"].append(
            dict(self._machine(d, "refund"))))
        self.assertIn("STATE_DUPLICATE_MACHINE", self.codes(self._validate()))

    def test_rejects_a_non_kebab_machine_name(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._machine(d, "refund").__setitem__("name", "Refund"))
        self.assertIn("STATE_NAME", self.codes(self._validate()))

    def test_rejects_an_undeclared_actor(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund")["transitions"][0].__setitem__("actor", "the-intern"))
        self.assertIn("STATE_ACTOR", self.codes(self._validate()))

    def test_rejects_an_actor_that_drives_nothing(self):
        self.fixture.mutate(self.REL, lambda d: d["actors"].append(
            {"id": "ghost", "description": "从不出现的参与者", "trusted_for_success": False}))
        self.assertIn("STATE_ACTOR_UNUSED", self.codes(self._validate()))

    def test_rejects_an_unknown_transition_kind(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund")["transitions"][0].__setitem__("kind", "vibes"))
        self.assertIn("STATE_KIND", self.codes(self._validate()))

    def test_rejects_a_transition_without_a_guard(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund")["transitions"][0].__setitem__("guard", ""))
        self.assertIn("STATE_GUARD", self.codes(self._validate()))

    def test_rejects_a_malformed_event_name(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund")["transitions"][0].__setitem__("event", "RefundApproved"))
        self.assertIn("STATE_EVENT", self.codes(self._validate()))

    def test_rejects_a_transition_to_an_unknown_state(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund")["transitions"][0].__setitem__("to", "vanished"))
        self.assertIn("STATE_TRANSITION_STATE", self.codes(self._validate()))

    def test_rejects_a_self_loop(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund")["transitions"][0].__setitem__("to", "requested"))
        self.assertIn("STATE_SELF_LOOP", self.codes(self._validate()))

    def test_rejects_the_same_event_having_two_outcomes(self):
        def fork(d):
            machine = self._machine(d, "refund")
            first = dict(machine["transitions"][0])
            first["to"] = "canceled"
            machine["transitions"].append(first)
        self.fixture.mutate(self.REL, fork)
        self.assertIn("STATE_NONDETERMINISTIC", self.codes(self._validate()))

    def test_rejects_a_machine_with_no_rationale(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._machine(d, "refund").__setitem__("notes", ""))
        self.assertIn("STATE_NOTES", self.codes(self._validate()))

    def test_rejects_a_machine_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["machines"].append("refund"))
        self.assertIn("STATE_SHAPE", self.codes(self._validate()))

    def test_rejects_a_transition_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund")["transitions"].append("approve it"))
        self.assertIn("STATE_SHAPE", self.codes(self._validate()))

    def test_rejects_a_missing_generated_document(self):
        self.fixture.remove("docs/domain/STATE_MACHINES.md")
        self.assertIn("STATE_DOC_MISSING", self.codes(self._validate()))

    def test_rejects_a_hand_edited_generated_document(self):
        path = self.fixture.root / "docs/domain/STATE_MACHINES.md"
        path.write_text(path.read_text(encoding="utf-8").replace(
            "provider.authorized", "browser.came_back"), encoding="utf-8")
        self.assertIn("STATE_DOC_DRIFT", self.codes(self._validate()))

    def test_fails_closed_when_the_document_cannot_be_generated(self):
        """A gate must turn a broken model into a finding, not into a crash."""
        self.fixture.mutate(self.REL, lambda d: self._machine(
            d, "refund").__setitem__("terminal", "succeeded"))
        codes = self.codes(self._validate())
        self.assertTrue({"STATE_DOC", "STATE_TERMINAL"} & codes, codes)

    def test_rejects_a_missing_domain_model(self):
        self.fixture.remove("governance/domain-model.json")
        self.assertIn("STATE_UNREADABLE", self.codes(self._validate()))


class StateInterpreter(FixtureTestCase):
    """The model is only worth having if something can execute it."""

    def setUp(self):
        super().setUp()
        from libs.statemachine.reference import machine as ref
        self.ref = ref
        self.machines = ref.load(REAL_ROOT / "governance/state-machines.json")

    def _intent(self):
        return self.ref.Instance(self.machines["payment-intent"])

    def test_a_card_payment_walks_created_to_captured(self):
        intent = self._intent()
        self.assertEqual(intent.state, "created")
        intent.apply("provider.action_required", "provider-event", "e1")
        intent.apply("provider.authorized", "provider-event", "e2")
        self.assertEqual(intent.apply("provider.captured", "provider-event", "e3"), "captured")
        self.assertTrue(intent.is_terminal)

    def test_a_replayed_webhook_is_a_no_op(self):
        intent = self._intent()
        intent.apply("provider.authorized", "provider-event", "e1")
        intent.apply("provider.captured", "provider-event", "e2")
        before = list(intent.history)
        self.assertEqual(intent.apply("provider.captured", "provider-event", "e2"), "captured")
        self.assertEqual(intent.history, before)

    def test_a_replay_of_the_terminal_event_does_not_raise(self):
        """Providers retry the last webhook too; the answer must stay the same."""
        intent = self._intent()
        intent.apply("provider.authorized", "provider-event", "e1")
        intent.apply("provider.captured", "provider-event", "e2")
        for _ in range(5):
            self.assertEqual(intent.apply("provider.captured", "provider-event", "e2"), "captured")

    def test_a_different_token_for_the_same_event_is_not_a_replay(self):
        intent = self._intent()
        intent.apply("provider.authorized", "provider-event", "e1")
        intent.apply("provider.captured", "provider-event", "e2")
        with self.assertRaises(self.ref.TransitionRejected) as raised:
            intent.apply("provider.captured", "provider-event", "different-token")
        self.assertEqual(raised.exception.code, "TERMINAL")

    def test_an_event_not_allowed_in_this_state_is_rejected(self):
        with self.assertRaises(self.ref.TransitionRejected) as raised:
            self._intent().apply("provider.captured", "provider-event", "e1")
        self.assertEqual(raised.exception.code, "EVENT_NOT_ALLOWED")

    def test_the_merchant_cannot_impersonate_a_provider_event(self):
        intent = self._intent()
        intent.apply("provider.authorized", "provider-event", "e1")
        with self.assertRaises(self.ref.TransitionRejected) as raised:
            intent.apply("provider.captured", "merchant", "e2")
        self.assertEqual(raised.exception.code, "WRONG_ACTOR")

    def test_an_untrusted_actor_cannot_write_success_even_if_the_table_says_so(self):
        """Defence in depth against a doctored transition table."""
        from dataclasses import replace
        machine = self.machines["payment-intent"]
        doctored = replace(machine, transitions=tuple(
            replace(t, actor="merchant") if t.event == "provider.captured" else t
            for t in machine.transitions))
        instance = self.ref.Instance(doctored)
        instance.apply("provider.authorized", "provider-event", "e1")
        with self.assertRaises(self.ref.TransitionRejected) as raised:
            instance.apply("provider.captured", "merchant", "e2")
        self.assertEqual(raised.exception.code, "UNTRUSTED_SUCCESS")

    def test_a_timeout_lands_in_unknown_and_reconciliation_resolves_it(self):
        attempt = self.ref.Instance(self.machines["payment-attempt"])
        attempt.apply("network.timeout", "system", "a1")
        self.assertEqual(attempt.state, "unknown")
        self.assertFalse(attempt.is_terminal)
        attempt.apply("reconciliation.matched_success", "reconciliation", "r1")
        self.assertEqual(attempt.state, "succeeded")

    def test_a_succeeded_refund_cannot_be_walked_back(self):
        refund = self.ref.Instance(self.machines["refund"])
        refund.apply("operator.approve", "operator", "r1")
        refund.apply("provider.accepted", "provider-event", "r2")
        refund.apply("provider.refunded", "provider-event", "r3")
        with self.assertRaises(self.ref.TransitionRejected):
            refund.apply("merchant.cancel_refund", "merchant", "r4")

    def test_every_machine_can_reach_a_terminal_state(self):
        for name, machine in self.machines.items():
            reachable, frontier = {machine.initial}, [machine.initial]
            while frontier:
                state = frontier.pop()
                for tr in machine.transitions:
                    if tr.source == state and tr.target not in reachable:
                        reachable.add(tr.target)
                        frontier.append(tr.target)
            self.assertTrue(reachable & machine.terminal, name)

    def test_the_interpreter_loads_every_machine_in_the_model(self):
        model = self.fixture.read("governance/state-machines.json")
        self.assertEqual(set(self.machines), {m["name"] for m in model["machines"]})
