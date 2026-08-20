"""B12 / AT-B12-01 — event catalogue, outbox and inbox.

The batch's claim is an exactly-once *business effect* on an at-least-once
transport. Nothing about that is self-evident, so it is tested from two sides:

* the catalogue gate refuses the designs that quietly break it — publishing
  before committing, deduplicating without a payload hash, ordering on a
  timestamp instead of a revision, an event carrying a PAN;
* the reference implementation is run under the failures the pattern exists for
  — crash before commit, broker outage, permanent failure, duplicate delivery,
  reordering, and the same id arriving with a different body.

``EVENT_SUCCESS_UNPUBLISHED`` earns its place: it found two real gaps in the
first draft of this catalogue (``payment-attempt`` reached ``succeeded`` twice
without publishing anything, so the ledger would never have heard about it).
"""
from __future__ import annotations

from tools.paygov import eventgen, events
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class EventCatalogHappyPath(FixtureTestCase):
    def test_real_catalog_passes(self):
        problems = events.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("event-catalog", registry.names())

    def test_transport_is_at_least_once_and_effect_is_effectively_once(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        self.assertEqual(catalog["delivery"]["transport_guarantee"], "at_least_once")
        self.assertEqual(catalog["delivery"]["business_guarantee"], "effectively_once")

    def test_the_outbox_shares_the_state_change_transaction(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        self.assertTrue(catalog["outbox"]["same_transaction_as_state_change"])
        self.assertIn("aggregate_id", catalog["outbox"]["unique_key"])
        self.assertIn("revision", catalog["outbox"]["unique_key"])

    def test_the_inbox_deduplicates_and_records_a_payload_hash(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        self.assertEqual(set(catalog["inbox"]["unique_key"]), {"source", "source_event_id"})
        self.assertTrue(catalog["inbox"]["payload_hash_field"])
        self.assertGreaterEqual(catalog["inbox"]["retention_hours"], 168)

    def test_ordering_is_based_on_a_revision_not_a_timestamp(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        self.assertEqual(catalog["ordering"]["sequence_field"], "revision")
        self.assertGreater(catalog["ordering"]["revision_gap_limit"], 0)

    def test_every_event_names_the_transition_that_produces_it(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        model = self.fixture.read("governance/state-machines.json")
        index = {(m["name"], t["event"]) for m in model["machines"] for t in m["transitions"]}
        self.assertGreaterEqual(len(catalog["events"]), 10)
        for event in catalog["events"]:
            emitted = event["emitted_by"]
            self.assertIn((emitted["machine"], emitted["event"]), index, event["name"])

    def test_every_success_transition_publishes_an_event(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        model = self.fixture.read("governance/state-machines.json")
        published = {(e["emitted_by"]["machine"], e["emitted_by"]["event"])
                     for e in catalog["events"]}
        for machine in model["machines"]:
            success = set(model["success_states"].get(machine["entity"], []))
            for transition in machine["transitions"]:
                if transition["to"] in success:
                    self.assertIn((machine["name"], transition["event"]), published,
                                  f"{machine['name']}:{transition['event']}")

    def test_no_event_payload_carries_card_data(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        forbidden = set(catalog["forbidden_payload_fields"])
        for event in catalog["events"]:
            for field in event["fields"]:
                self.assertNotIn(field["name"], forbidden, event["name"])

    def test_every_payload_field_is_classified(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        allowed = set(catalog["classifications"])
        for event in catalog["events"]:
            for field in event["fields"]:
                self.assertIn(field["classification"], allowed, f"{event['name']}.{field['name']}")

    def test_every_monetary_field_is_integer_minor_units_with_a_currency(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        for event in catalog["events"]:
            names = {f["name"] for f in event["fields"]}
            for field in event["fields"]:
                if events.MONEY_FIELD.search(field["name"]):
                    self.assertEqual(field["type"], "int64", event["name"])
                    self.assertTrue(field["name"].endswith("_minor"), event["name"])
                    self.assertIn("currency", names, event["name"])

    def test_every_event_is_produced_by_a_service_that_exists(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        registry = self.fixture.read("governance/module-registry.json")
        services = {m["name"] for m in registry["modules"] if m["layer"] == "service"}
        for event in catalog["events"]:
            self.assertIn(event["producer"], services, event["name"])

    def test_every_event_has_a_consumer_and_every_consumer_declares_its_tolerance(self):
        catalog = self.fixture.read("governance/event-catalog.json")
        tolerances = set(catalog["ordering"]["tolerances"])
        subscribed = {name for c in catalog["consumers"] for name in c["subscribes"]}
        for event in catalog["events"]:
            self.assertIn(event["name"], subscribed, event["name"])
        for consumer in catalog["consumers"]:
            self.assertIn(consumer["order_tolerance"], tolerances, consumer["module"])

    def test_generated_artefacts_match_the_catalogue(self):
        for rel, content in eventgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)


class EventGateRejects(FixtureTestCase):
    REL = "governance/event-catalog.json"

    def _validate(self):
        return events.validate(self.fixture.root, Budget(seconds=60).start())

    def _event(self, data, name):
        return next(e for e in data["events"] if e["name"] == name)

    def test_rejects_unreadable_catalogue(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("EVENT_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("EVENT_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_an_empty_event_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("events", []))
        self.assertIn("EVENT_SHAPE", self.codes(self._validate()))

    def test_rejects_an_empty_consumer_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("consumers", []))
        self.assertIn("EVENT_SHAPE", self.codes(self._validate()))

    def test_rejects_claiming_exactly_once_transport(self):
        self.fixture.mutate(self.REL, lambda d: d["delivery"].__setitem__(
            "transport_guarantee", "exactly_once"))
        problems = self._validate()
        self.assertIn("EVENT_DELIVERY", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_dropping_the_effectively_once_business_guarantee(self):
        self.fixture.mutate(self.REL, lambda d: d["delivery"].__setitem__(
            "business_guarantee", "best_effort"))
        self.assertIn("EVENT_DELIVERY", self.codes(self._validate()))

    def test_rejects_publishing_outside_the_state_change_transaction(self):
        """The failure the outbox pattern exists to prevent."""
        self.fixture.mutate(self.REL, lambda d: d["outbox"].__setitem__(
            "same_transaction_as_state_change", False))
        problems = self._validate()
        self.assertIn("OUTBOX_NOT_TRANSACTIONAL", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_an_outbox_without_a_unique_key(self):
        self.fixture.mutate(self.REL, lambda d: d["outbox"].__setitem__("unique_key", []))
        self.assertIn("OUTBOX_UNIQUE_KEY", self.codes(self._validate()))

    def test_rejects_an_outbox_without_a_table(self):
        self.fixture.mutate(self.REL, lambda d: d["outbox"].__setitem__("table", "Outbox Events"))
        self.assertIn("OUTBOX_SHAPE", self.codes(self._validate()))

    def test_rejects_publish_before_commit_dispatch(self):
        self.fixture.mutate(self.REL, lambda d: d["outbox"]["dispatch"].__setitem__(
            "mode", "publish_then_commit"))
        self.assertIn("OUTBOX_DISPATCH", self.codes(self._validate()))

    def test_rejects_a_fixed_retry_loop(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["outbox"]["dispatch"].__setitem__("backoff", "fixed"))
        self.assertIn("OUTBOX_DISPATCH", self.codes(self._validate()))

    def test_rejects_giving_up_after_one_blip(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["outbox"]["dispatch"].__setitem__("max_attempts", 1))
        self.assertIn("OUTBOX_DISPATCH", self.codes(self._validate()))

    def test_rejects_a_backoff_ceiling_below_its_floor(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["outbox"]["dispatch"].__setitem__("max_delay_ms", 1))
        self.assertIn("OUTBOX_DISPATCH", self.codes(self._validate()))

    def test_rejects_dropping_the_dead_letter_destination(self):
        self.fixture.mutate(self.REL, lambda d: d["outbox"]["dispatch"].__setitem__(
            "dead_letter_table", ""))
        self.assertIn("OUTBOX_DEAD_LETTER", self.codes(self._validate()))

    def test_rejects_an_inbox_that_does_not_deduplicate(self):
        self.fixture.mutate(self.REL, lambda d: d["inbox"].__setitem__("unique_key", ["source"]))
        self.assertIn("INBOX_UNIQUE_KEY", self.codes(self._validate()))

    def test_rejects_an_inbox_without_a_payload_hash(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["inbox"].__setitem__("payload_hash_field", ""))
        self.assertIn("INBOX_PAYLOAD_HASH", self.codes(self._validate()))

    def test_rejects_an_inbox_that_forgets_before_the_provider_stops_resending(self):
        self.fixture.mutate(self.REL, lambda d: d["inbox"].__setitem__("retention_hours", 1))
        self.assertIn("INBOX_RETENTION", self.codes(self._validate()))

    def test_rejects_an_inbox_conflict_with_no_error(self):
        self.fixture.mutate(self.REL, lambda d: d["inbox"].__setitem__("conflict_error", ""))
        self.assertIn("INBOX_CONFLICT", self.codes(self._validate()))

    def test_rejects_an_inbox_without_a_table(self):
        self.fixture.mutate(self.REL, lambda d: d["inbox"].__setitem__("table", "Inbox!"))
        self.assertIn("INBOX_SHAPE", self.codes(self._validate()))

    def test_rejects_ordering_by_timestamp(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["ordering"].__setitem__("sequence_field", "occurred_at"))
        self.assertIn("EVENT_ORDERING", self.codes(self._validate()))

    def test_rejects_an_unbounded_reorder_buffer(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["ordering"].__setitem__("revision_gap_limit", 0))
        self.assertIn("EVENT_ORDERING", self.codes(self._validate()))

    def test_rejects_removing_all_ordering_tolerances(self):
        self.fixture.mutate(self.REL, lambda d: d["ordering"].__setitem__("tolerances", []))
        self.assertIn("EVENT_ORDERING", self.codes(self._validate()))

    def test_rejects_a_short_event_version_parallel_window(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["versioning"].__setitem__("parallel_days", 7))
        self.assertIn("EVENT_VERSION_POLICY", self.codes(self._validate()))

    def test_rejects_an_unwritten_version_policy(self):
        self.fixture.mutate(self.REL, lambda d: d["versioning"].__setitem__("policy", ""))
        self.assertIn("EVENT_VERSION_POLICY", self.codes(self._validate()))

    def test_rejects_an_envelope_without_a_revision(self):
        self.fixture.mutate(self.REL, lambda d: d["envelope"].__setitem__(
            "required_fields", ["event_id", "event_name", "payload"]))
        self.assertIn("EVENT_ENVELOPE", self.codes(self._validate()))

    def test_rejects_an_envelope_without_a_tenant(self):
        self.fixture.mutate(self.REL, lambda d: d["envelope"].__setitem__(
            "required_fields", [f for f in d["envelope"]["required_fields"]
                                if f != "tenant_id"]))
        problems = self._validate()
        self.assertIn("EVENT_TENANT", self.codes(problems))
        self.assertIn("NN-09", self.rules(problems))

    def test_rejects_an_event_not_partitioned_by_tenant(self):
        self.fixture.mutate(self.REL, lambda d: self._event(
            d, "refund.succeeded").__setitem__("partition_key", "provider"))
        self.assertIn("EVENT_TENANT", self.codes(self._validate()))

    def test_rejects_a_pan_in_an_event_payload(self):
        self.fixture.mutate(self.REL, lambda d: self._event(d, "refund.succeeded")["fields"]
                            .append({"name": "pan", "type": "string",
                                     "classification": "restricted"}))
        problems = self._validate()
        self.assertIn("EVENT_FORBIDDEN_FIELD", self.codes(problems))
        self.assertIn("NN-02", self.rules(problems))

    def test_rejects_emptying_the_forbidden_field_list(self):
        self.fixture.mutate(self.REL,
                            lambda d: d.__setitem__("forbidden_payload_fields", []))
        self.assertIn("EVENT_FORBIDDEN_LIST", self.codes(self._validate()))

    def test_rejects_removing_all_classifications(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("classifications", []))
        self.assertIn("EVENT_SHAPE", self.codes(self._validate()))

    def test_rejects_an_unclassified_field(self):
        self.fixture.mutate(self.REL, lambda d: self._event(
            d, "refund.succeeded")["fields"][0].__setitem__("classification", "whatever"))
        self.assertIn("EVENT_CLASSIFICATION", self.codes(self._validate()))

    def test_rejects_a_floating_point_amount(self):
        self.fixture.mutate(self.REL, lambda d: next(
            f for f in self._event(d, "refund.succeeded")["fields"]
            if f["name"] == "amount_minor").__setitem__("type", "double"))
        problems = self._validate()
        self.assertIn("EVENT_MONEY_TYPE", self.codes(problems))
        self.assertIn("NN-05", self.rules(problems))

    def test_rejects_an_amount_without_a_currency(self):
        self.fixture.mutate(self.REL, lambda d: self._event(d, "refund.succeeded").__setitem__(
            "fields", [f for f in self._event(d, "refund.succeeded")["fields"]
                       if f["name"] != "currency"]))
        self.assertIn("EVENT_MONEY_CURRENCY", self.codes(self._validate()))

    def test_rejects_a_success_transition_that_publishes_nothing(self):
        """The rule that found two real gaps in the first draft."""
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "events", [e for e in d["events"] if e["name"] != "payment_intent.captured"]))
        problems = self._validate()
        self.assertIn("EVENT_SUCCESS_UNPUBLISHED", self.codes(problems))
        self.assertIn("NN-06", self.rules(problems))

    def test_rejects_an_undeclared_cross_aggregate_emission(self):
        """A run may legitimately create an exception — but not by accident."""
        self.fixture.mutate(self.REL, lambda d: self._event(
            d, "reconciliation.exception_opened").pop("cross_aggregate_reason"))
        self.assertIn("EVENT_TRANSITION_AGGREGATE", self.codes(self._validate()))

    def test_rejects_an_event_with_no_cause(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._event(d, "refund.failed").pop("emitted_by"))
        self.assertIn("EVENT_TRANSITION_MISSING", self.codes(self._validate()))

    def test_rejects_an_event_citing_a_transition_that_does_not_exist(self):
        self.fixture.mutate(self.REL, lambda d: self._event(d, "refund.failed").__setitem__(
            "emitted_by", {"machine": "refund", "event": "provider.teleported"}))
        self.assertIn("EVENT_TRANSITION_UNKNOWN", self.codes(self._validate()))

    def test_rejects_a_bad_event_name(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._event(d, "refund.failed").__setitem__("name", "Boom"))
        self.assertIn("EVENT_NAME", self.codes(self._validate()))

    def test_rejects_a_duplicate_event(self):
        self.fixture.mutate(self.REL, lambda d: d["events"].append(
            dict(self._event(d, "refund.failed"))))
        self.assertIn("EVENT_DUPLICATE", self.codes(self._validate()))

    def test_rejects_a_zero_event_version(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._event(d, "refund.failed").__setitem__("version", 0))
        self.assertIn("EVENT_VERSION", self.codes(self._validate()))

    def test_rejects_a_producer_that_is_not_a_module(self):
        self.fixture.mutate(self.REL, lambda d: self._event(d, "refund.failed").__setitem__(
            "producer", "some-team"))
        self.assertIn("EVENT_PRODUCER", self.codes(self._validate()))

    def test_rejects_a_library_publishing_facts(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._event(d, "refund.failed").__setitem__("producer",
                                                                                  "money"))
        problems = self._validate()
        self.assertIn("EVENT_PRODUCER", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_an_unknown_aggregate(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._event(d, "refund.failed").__setitem__("aggregate",
                                                                                  "Wormhole"))
        self.assertIn("EVENT_AGGREGATE", self.codes(self._validate()))

    def test_rejects_a_short_retention(self):
        self.fixture.mutate(self.REL, lambda d: self._event(
            d, "refund.failed").__setitem__("retention_days", 30))
        problems = self._validate()
        self.assertIn("EVENT_RETENTION", self.codes(problems))
        self.assertIn("NN-06", self.rules(problems))

    def test_rejects_an_ordering_key_that_is_nowhere(self):
        self.fixture.mutate(self.REL, lambda d: self._event(
            d, "refund.failed").__setitem__("ordering_key", "vibes"))
        self.assertIn("EVENT_ORDERING_KEY", self.codes(self._validate()))

    def test_rejects_an_event_with_no_fields(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._event(d, "refund.failed").__setitem__("fields", []))
        self.assertIn("EVENT_SHAPE", self.codes(self._validate()))

    def test_rejects_a_bad_field_name(self):
        self.fixture.mutate(self.REL, lambda d: self._event(
            d, "refund.failed")["fields"][0].__setitem__("name", "Refund Id"))
        self.assertIn("EVENT_FIELD", self.codes(self._validate()))

    def test_rejects_a_duplicate_field(self):
        self.fixture.mutate(self.REL, lambda d: self._event(d, "refund.failed")["fields"]
                            .append(dict(self._event(d, "refund.failed")["fields"][0])))
        self.assertIn("EVENT_FIELD_DUPLICATE", self.codes(self._validate()))

    def test_rejects_an_event_nobody_consumes(self):
        self.fixture.mutate(self.REL, lambda d: [
            c.__setitem__("subscribes", [s for s in c["subscribes"]
                                         if s != "subscription.past_due"])
            for c in d["consumers"]])
        self.assertIn("EVENT_UNCONSUMED", self.codes(self._validate()))

    def test_rejects_an_event_declaring_no_consumers(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._event(d, "refund.failed").__setitem__("consumers", []))
        self.assertIn("EVENT_NO_CONSUMER", self.codes(self._validate()))

    def test_rejects_a_consumer_that_is_not_a_module(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["consumers"][0].__setitem__("module", "some-team"))
        self.assertIn("EVENT_CONSUMER_MODULE", self.codes(self._validate()))

    def test_rejects_a_duplicate_consumer(self):
        self.fixture.mutate(self.REL, lambda d: d["consumers"].append(dict(d["consumers"][0])))
        self.assertIn("EVENT_CONSUMER_DUPLICATE", self.codes(self._validate()))

    def test_rejects_a_consumer_that_has_not_thought_about_reordering(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["consumers"][0].__setitem__("order_tolerance", "hope"))
        self.assertIn("EVENT_ORDER_TOLERANCE", self.codes(self._validate()))

    def test_rejects_a_consumer_without_an_apply_policy(self):
        self.fixture.mutate(self.REL, lambda d: d["consumers"][0].__setitem__("policy", ""))
        self.assertIn("EVENT_ORDER_TOLERANCE", self.codes(self._validate()))

    def test_rejects_a_consumer_subscribing_to_nothing(self):
        self.fixture.mutate(self.REL, lambda d: d["consumers"][0].__setitem__("subscribes", []))
        self.assertIn("EVENT_CONSUMER_EMPTY", self.codes(self._validate()))

    def test_rejects_a_subscription_to_an_unknown_event(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["consumers"][0]["subscribes"].append("ghost.happened"))
        self.assertIn("EVENT_SUBSCRIPTION_UNKNOWN", self.codes(self._validate()))

    def test_rejects_an_event_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["events"].append("refund.failed"))
        self.assertIn("EVENT_SHAPE", self.codes(self._validate()))

    def test_rejects_a_consumer_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["consumers"].append("ledger-service"))
        self.assertIn("EVENT_SHAPE", self.codes(self._validate()))

    def test_rejects_a_field_that_is_not_an_object(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._event(d, "refund.failed")["fields"].append("boom"))
        self.assertIn("EVENT_SHAPE", self.codes(self._validate()))

    def test_rejects_missing_generated_artefacts(self):
        self.fixture.remove("contracts/events/catalog.json")
        self.assertIn("EVENT_GENERATED_MISSING", self.codes(self._validate()))

    def test_rejects_a_hand_edited_generated_artefact(self):
        path = self.fixture.root / "docs/events/EVENT_CATALOG.md"
        path.write_text(path.read_text(encoding="utf-8").replace(
            "at_least_once", "exactly_once"), encoding="utf-8")
        self.assertIn("EVENT_GENERATED_DRIFT", self.codes(self._validate()))

    def test_fails_closed_when_the_artefacts_cannot_be_generated(self):
        """A gate must turn a broken catalogue into a finding, not into a crash."""
        self.fixture.mutate(self.REL,
                            lambda d: self._event(d, "refund.failed").pop("retention_days"))
        self.assertIn("EVENT_GENERATED", self.codes(self._validate()))


class EventingReference(FixtureTestCase):
    """At-least-once transport, exactly-once business effect — run, not asserted."""

    def setUp(self):
        super().setUp()
        from libs.eventing.reference import eventing
        self.eventing = eventing

    def _captured(self):
        store, broker = self.eventing.Store(), self.eventing.Broker()
        store.transact("PaymentIntent", "pi_1", 1, "authorized", "payment_intent.authorized",
                       {"amount_minor": 19999, "currency": "CNY"})
        store.transact("PaymentIntent", "pi_1", 2, "captured", "payment_intent.captured",
                       {"amount_minor": 19999, "currency": "CNY"})
        return store, broker

    def test_a_crash_before_commit_leaves_neither_state_nor_event(self):
        store = self.eventing.Store()
        with self.assertRaises(self.eventing.CommitFailed):
            store.transact("PaymentIntent", "pi_1", 1, "authorized", "payment_intent.authorized",
                           {"amount_minor": 1}, crash_before_commit=True)
        self.assertEqual(store.state, {})
        self.assertEqual(store.outbox, [])

    def test_a_broker_outage_delays_but_does_not_lose(self):
        store, broker = self._captured()
        broker.fail_next = 2
        self.assertEqual(self.eventing.Dispatcher(store, broker).run_once()["published"], 0)
        self.assertEqual(self.eventing.Dispatcher(store, broker).run_once()["published"], 2)

    def test_a_permanent_failure_dead_letters_instead_of_vanishing(self):
        store, broker = self._captured()
        broker.fail_next = 10_000
        dispatcher = self.eventing.Dispatcher(store, broker, max_attempts=3)
        for _ in range(3):
            dispatcher.run_once()
        self.assertEqual(len(store.dead_letters), 2)
        self.assertFalse(any(row.published for row in store.dead_letters))

    def test_duplicate_delivery_produces_one_business_effect(self):
        store, broker = self._captured()
        self.eventing.Dispatcher(store, broker).run_once()
        consumer = self.eventing.RevisionGuardedConsumer()
        for _ in range(3):
            for row in broker.delivered:
                consumer.handle("payment-core", row)
        self.assertEqual(len(consumer.effects), 2)
        self.assertEqual(consumer.duplicates, 4)

    def test_reordered_delivery_converges_on_the_latest_revision(self):
        store, broker = self._captured()
        self.eventing.Dispatcher(store, broker).run_once()
        consumer = self.eventing.RevisionGuardedConsumer()
        for row in reversed(broker.delivered):
            consumer.handle("payment-core", row)
        self.assertEqual(consumer.applied[("PaymentIntent", "pi_1")], 2)
        self.assertEqual(consumer.stale, 1)

    def test_the_same_event_id_with_a_different_body_is_a_contradiction(self):
        inbox = self.eventing.Inbox()
        self.assertTrue(inbox.accept("wechat", "evt_1", {"amount_minor": 19999}))
        self.assertFalse(inbox.accept("wechat", "evt_1", {"amount_minor": 19999}))
        with self.assertRaises(self.eventing.PayloadConflict):
            inbox.accept("wechat", "evt_1", {"amount_minor": 1})

    def test_the_unique_key_stops_a_retried_producer_writing_twice(self):
        store, _ = self._captured()
        with self.assertRaises(ValueError):
            store.transact("PaymentIntent", "pi_1", 2, "captured", "payment_intent.captured",
                           {"amount_minor": 19999, "currency": "CNY"})

    def test_two_tenants_do_not_share_a_revision_line(self):
        store = self.eventing.Store()
        store.transact("PaymentIntent", "pi_a", 1, "captured", "payment_intent.captured", {})
        store.transact("PaymentIntent", "pi_b", 1, "captured", "payment_intent.captured", {})
        self.assertEqual(len(store.outbox), 2)
