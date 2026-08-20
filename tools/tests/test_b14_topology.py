"""B14 / AT-B14-01 — service decomposition, runtime dependencies and isolation.

The module registry (B00) is a build-time statement. This is the runtime one,
and the rules that matter are the ones that turn architecture diagrams into
arithmetic:

* ``TOPO_BUDGET_EXCEEDED`` — a caller whose budget is smaller than the sum of
  its synchronous timeouts has decorative timeouts; what actually fires is the
  upstream deadline, and the work is abandoned mid-flight.
* ``TOPO_SYNC_CYCLE`` — two services in a synchronous cycle cannot be deployed,
  scaled or recovered independently. They are one service with two names.
* ``TOPO_CONNECTOR_RETRY`` / ``TOPO_CONNECTOR_DEGRADATION`` — retrying a
  *mutating* provider call is how one payment becomes two, and treating its
  timeout as a decline is what makes the customer pay twice (AC-01). A read-only
  query has the opposite answer, which is why the operation kind is declared.
* ``TOPO_FOREIGN_KEY_CROSS_MODULE`` — checked against the generated DDL rather
  than the model, because what breaks a service split is the constraint that
  reaches the database. It found 16 real cross-module foreign keys on first run
  and changed how B08 generates the schema.
"""
from __future__ import annotations

from tools.paygov import topogen, topology
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class TopologyHappyPath(FixtureTestCase):
    def test_real_topology_passes(self):
        problems = topology.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("service-topology", registry.names())

    def test_every_deployable_module_has_a_topology_entry(self):
        topo = self.fixture.read("governance/service-topology.json")
        registry = self.fixture.read("governance/module-registry.json")
        deployable = {m["name"] for m in registry["modules"]
                      if m["layer"] in ("service", "app")}
        self.assertEqual({s["module"] for s in topo["services"]}, deployable)

    def test_no_synchronous_cycle_exists(self):
        topo = self.fixture.read("governance/service-topology.json")
        by_name = {s["name"]: s for s in topo["services"]}
        edges = {n: {d["target"] for d in s["dependencies"]
                     if d["kind"] == "sync" and d["target"] in by_name}
                 for n, s in by_name.items()}

        def reaches(start, target, seen=None):
            seen = seen or set()
            for nxt in edges.get(start, ()):
                if nxt == target:
                    return True
                if nxt not in seen and reaches(nxt, target, seen | {nxt}):
                    return True
            return False

        for name in by_name:
            self.assertFalse(reaches(name, name), name)

    def test_every_caller_budget_covers_its_synchronous_timeouts(self):
        topo = self.fixture.read("governance/service-topology.json")
        for service in topo["services"]:
            ungrouped, groups = 0, {}
            for dependency in service["dependencies"]:
                if dependency["kind"] != "sync":
                    continue
                group = dependency.get("exclusive_group")
                if group:
                    groups[group] = max(groups.get(group, 0), dependency["timeout_ms"])
                else:
                    ungrouped += dependency["timeout_ms"]
            self.assertLessEqual(ungrouped + sum(groups.values()),
                                 service["request_budget_ms"], service["name"])

    def test_every_caller_allows_its_callee_at_least_its_own_budget(self):
        topo = self.fixture.read("governance/service-topology.json")
        by_name = {s["name"]: s for s in topo["services"]}
        for service in topo["services"]:
            for dependency in service["dependencies"]:
                callee = by_name.get(dependency["target"])
                if callee and dependency["kind"] == "sync":
                    self.assertGreaterEqual(dependency["timeout_ms"],
                                            callee["request_budget_ms"],
                                            f"{service['name']}->{dependency['target']}")

    def test_every_synchronous_dependency_is_isolated(self):
        topo = self.fixture.read("governance/service-topology.json")
        count = 0
        for service in topo["services"]:
            for dependency in service["dependencies"]:
                if dependency["kind"] != "sync":
                    continue
                count += 1
                self.assertGreater(dependency["timeout_ms"], 0)
                self.assertTrue(dependency["circuit_breaker"])
                self.assertGreater(dependency["bulkhead"]["max_concurrent"], 0)
                self.assertIn(dependency["failure_mode"], topology.FAILURE_MODES)
        self.assertGreaterEqual(count, 15)

    def test_mutating_connector_calls_are_never_retried(self):
        topo = self.fixture.read("governance/service-topology.json")
        registry = self.fixture.read("governance/module-registry.json")
        connectors = {m["name"] for m in registry["modules"] if m["layer"] == "connector"}
        mutating = 0
        for service in topo["services"]:
            for dependency in service["dependencies"]:
                if dependency["target"] in connectors \
                        and dependency.get("operation") == "mutating":
                    mutating += 1
                    self.assertEqual(dependency["retries"], 0, service["name"])
                    self.assertIn("unknown", dependency["degradation"], service["name"])
        self.assertGreaterEqual(mutating, 5)

    def test_the_ledger_is_never_on_the_synchronous_payment_path(self):
        """A slow ledger must not be able to become a failed payment."""
        topo = self.fixture.read("governance/service-topology.json")
        core = next(s for s in topo["services"] if s["name"] == "payment-core")
        ledger = next(d for d in core["dependencies"] if d["target"] == "ledger-service")
        self.assertEqual(ledger["kind"], "async")

    def test_tier_one_dependencies_fail_closed_unless_they_are_the_provider(self):
        topo = self.fixture.read("governance/service-topology.json")
        for service in topo["services"]:
            if service["criticality"] != "tier1":
                continue
            for dependency in service["dependencies"]:
                if dependency["kind"] != "sync":
                    continue
                if dependency.get("operation") in ("mutating", "query"):
                    self.assertEqual(dependency["failure_mode"], "degrade", service["name"])
                else:
                    self.assertEqual(dependency["failure_mode"], "fail_closed", service["name"])

    def test_the_config_service_is_a_leaf(self):
        """Its availability multiplies into everyone else's, so it depends on nothing."""
        topo = self.fixture.read("governance/service-topology.json")
        config = next(s for s in topo["services"] if s["name"] == "merchant-config")
        self.assertEqual(config["dependencies"], [])

    def test_published_and_consumed_events_agree_with_the_catalogue(self):
        topo = self.fixture.read("governance/service-topology.json")
        catalog = self.fixture.read("governance/event-catalog.json")
        producers = {e["name"]: e["producer"] for e in catalog["events"]}
        consumers = {c["module"]: set(c["subscribes"]) for c in catalog["consumers"]}
        for service in topo["services"]:
            for name in service.get("publishes", []):
                self.assertEqual(producers[name], service["module"], name)
            for name in service.get("consumes", []):
                self.assertIn(name, consumers.get(service["module"], set()), name)

    def test_the_generated_schema_has_no_cross_module_foreign_key(self):
        """B13 left this open; the DDL is where it actually matters."""
        problems = topology._foreign_keys(REAL_ROOT, "test")
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_the_generated_schema_still_creates_intra_module_foreign_keys(self):
        """Dropping the cross-module ones must not have dropped them all."""
        sql = (REAL_ROOT / "contracts/sql/schema.sql").read_text(encoding="utf-8")
        self.assertGreater(sql.count("FOREIGN KEY"), 5)
        self.assertIn("跨模块引用", sql)

    def test_generated_artefacts_match_the_topology(self):
        for rel, content in topogen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)


class TopologyGateRejects(FixtureTestCase):
    REL = "governance/service-topology.json"

    def _validate(self):
        return topology.validate(self.fixture.root, Budget(seconds=60).start())

    def _svc(self, d, name):
        return next(s for s in d["services"] if s["name"] == name)

    def _dep(self, d, service, target):
        return next(x for x in self._svc(d, service)["dependencies"] if x["target"] == target)

    def test_rejects_unreadable_topology(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("TOPO_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("TOPO_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_an_empty_service_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("services", []))
        self.assertIn("TOPO_SHAPE", self.codes(self._validate()))

    def test_rejects_an_absurd_sync_depth_limit(self):
        self.fixture.mutate(self.REL, lambda d: d["policy"].__setitem__("max_sync_depth", 40))
        self.assertIn("TOPO_POLICY", self.codes(self._validate()))

    def test_rejects_a_money_path_that_fails_open(self):
        self.fixture.mutate(self.REL, lambda d: d["policy"].__setitem__(
            "money_path_failure_mode", "fail_open"))
        self.assertIn("TOPO_POLICY", self.codes(self._validate()))

    def test_rejects_shared_database_access(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["policy"].__setitem__("database_access", "shared"))
        problems = self._validate()
        self.assertIn("TOPO_POLICY", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_an_unwritten_budget_rule(self):
        self.fixture.mutate(self.REL, lambda d: d["policy"].__setitem__("sync_budget_rule", ""))
        self.assertIn("TOPO_POLICY", self.codes(self._validate()))

    def test_rejects_a_synchronous_cycle(self):
        """merchant-config calling back into payment-core makes them one service."""
        self.fixture.mutate(self.REL, lambda d: self._svc(d, "merchant-config")["dependencies"]
                            .append({"target": "payment-core", "kind": "sync",
                                     "reason": "回头查支付状态", "timeout_ms": 100,
                                     "retries": 0, "failure_mode": "fail_closed",
                                     "circuit_breaker": {"error_rate_threshold_pct": 50,
                                                         "open_seconds": 30},
                                     "bulkhead": {"max_concurrent": 10},
                                     "degradation": "拒绝请求"}))
        problems = self._validate()
        self.assertIn("TOPO_SYNC_CYCLE", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_a_budget_smaller_than_its_own_timeouts(self):
        self.fixture.mutate(self.REL, lambda d: self._svc(d, "payment-core").__setitem__(
            "request_budget_ms", 400))
        self.assertIn("TOPO_BUDGET_EXCEEDED", self.codes(self._validate()))

    def test_rejects_a_timeout_larger_than_the_callers_own_budget(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("timeout_ms", 9000))
        self.assertIn("TOPO_TIMEOUT_BUDGET", self.codes(self._validate()))

    def test_rejects_a_timeout_tighter_than_the_callee_budget(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("timeout_ms", 50))
        problems = self._validate()
        self.assertIn("TOPO_TIMEOUT_TOO_TIGHT", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_a_synchronous_call_with_no_timeout(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("timeout_ms", 0))
        self.assertIn("TOPO_TIMEOUT", self.codes(self._validate()))

    def test_rejects_a_synchronous_call_with_no_circuit_breaker(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("circuit_breaker", {}))
        self.assertIn("TOPO_CIRCUIT_BREAKER", self.codes(self._validate()))

    def test_rejects_a_breaker_with_no_threshold(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            ["circuit_breaker"].__setitem__("error_rate_threshold_pct", 0))
        self.assertIn("TOPO_CIRCUIT_BREAKER", self.codes(self._validate()))

    def test_rejects_a_breaker_with_no_cooldown(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            ["circuit_breaker"].__setitem__("open_seconds", 0))
        self.assertIn("TOPO_CIRCUIT_BREAKER", self.codes(self._validate()))

    def test_rejects_a_synchronous_call_with_no_bulkhead(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("bulkhead", {}))
        self.assertIn("TOPO_BULKHEAD", self.codes(self._validate()))

    def test_rejects_undeclared_retries(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .pop("retries"))
        self.assertIn("TOPO_RETRY", self.codes(self._validate()))

    def test_rejects_retrying_a_mutating_connector_call(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "stripe")
                            .__setitem__("retries", 2))
        problems = self._validate()
        self.assertIn("TOPO_CONNECTOR_RETRY", self.codes(problems))
        self.assertIn("NN-04", self.rules(problems))

    def test_rejects_treating_a_provider_timeout_as_a_decline(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "stripe")
                            .__setitem__("degradation", "判定为失败并通知商户"))
        problems = self._validate()
        self.assertIn("TOPO_CONNECTOR_DEGRADATION", self.codes(problems))
        self.assertIn("NN-03", self.rules(problems))

    def test_rejects_a_connector_call_that_does_not_say_what_it_does(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._dep(d, "payment-core", "stripe").pop("operation"))
        self.assertIn("TOPO_CONNECTOR_OPERATION", self.codes(self._validate()))

    def test_rejects_a_mutating_connector_call_that_fails_closed(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "stripe")
                            .__setitem__("failure_mode", "fail_closed"))
        self.assertIn("TOPO_FAILURE_MODE", self.codes(self._validate()))

    def test_rejects_a_tier_one_dependency_that_fails_open(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("failure_mode", "fail_open"))
        problems = self._validate()
        self.assertIn("TOPO_FAIL_OPEN", self.codes(problems))

    def test_rejects_an_undeclared_failure_mode(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("failure_mode", "shrug"))
        self.assertIn("TOPO_FAILURE_MODE", self.codes(self._validate()))

    def test_rejects_a_dependency_with_no_stated_failure_behaviour(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("degradation", ""))
        self.assertIn("TOPO_DEGRADATION", self.codes(self._validate()))

    def test_rejects_a_dependency_with_no_reason(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("reason", ""))
        self.assertIn("TOPO_DEP_REASON", self.codes(self._validate()))

    def test_rejects_an_unknown_call_kind(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("kind", "telepathy"))
        self.assertIn("TOPO_CALL_KIND", self.codes(self._validate()))

    def test_rejects_a_dependency_on_a_module_that_does_not_exist(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("target", "vibes-service"))
        self.assertIn("TOPO_DEP_UNKNOWN", self.codes(self._validate()))

    def test_rejects_a_runtime_edge_the_module_registry_does_not_know_about(self):
        self.fixture.mutate(self.REL, lambda d: self._dep(d, "payment-core", "risk-engine")
                            .__setitem__("target", "reconciliation-service"))
        problems = self._validate()
        self.assertIn("TOPO_DEP_UNDECLARED", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_a_service_for_a_module_that_is_not_deployable(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._svc(d, "risk-engine").__setitem__("module", "money"))
        self.assertIn("TOPO_MODULE", self.codes(self._validate()))

    def test_rejects_dropping_a_deployable_module_from_the_topology(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "services", [s for s in d["services"] if s["name"] != "admin-web"]))
        self.assertIn("TOPO_SERVICE_MISSING", self.codes(self._validate()))

    def test_rejects_a_duplicate_service(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["services"].append(dict(self._svc(d, "admin-web"))))
        self.assertIn("TOPO_DUPLICATE", self.codes(self._validate()))

    def test_rejects_a_non_kebab_service_name(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._svc(d, "admin-web").__setitem__("name", "AdminWeb"))
        self.assertIn("TOPO_NAME", self.codes(self._validate()))

    def test_rejects_an_unknown_runtime_kind(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._svc(d, "admin-web").__setitem__("runtime", "magic"))
        self.assertIn("TOPO_RUNTIME", self.codes(self._validate()))

    def test_rejects_an_unknown_criticality_tier(self):
        self.fixture.mutate(self.REL, lambda d: self._svc(d, "admin-web").__setitem__(
            "criticality", "tier9"))
        self.assertIn("TOPO_CRITICALITY", self.codes(self._validate()))

    def test_rejects_a_service_with_no_stated_boundary_rationale(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._svc(d, "admin-web").__setitem__("notes", ""))
        self.assertIn("TOPO_NOTES", self.codes(self._validate()))

    def test_rejects_a_service_with_no_slo(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._svc(d, "admin-web").__setitem__("slo", {}))
        self.assertIn("TOPO_SLO", self.codes(self._validate()))

    def test_rejects_a_service_with_no_request_budget(self):
        self.fixture.mutate(self.REL, lambda d: self._svc(d, "admin-web").__setitem__(
            "request_budget_ms", 0))
        self.assertIn("TOPO_BUDGET", self.codes(self._validate()))

    def test_rejects_a_sync_chain_deeper_than_the_declared_limit(self):
        self.fixture.mutate(self.REL, lambda d: d["policy"].__setitem__("max_sync_depth", 1))
        self.assertIn("TOPO_SYNC_DEPTH", self.codes(self._validate()))

    def test_rejects_publishing_an_event_the_catalogue_does_not_have(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._svc(d, "payment-core")["publishes"].append("ghost.x"))
        self.assertIn("TOPO_EVENT_UNKNOWN", self.codes(self._validate()))

    def test_rejects_publishing_someone_elses_event(self):
        self.fixture.mutate(self.REL, lambda d: self._svc(d, "payment-core")["publishes"]
                            .append("reconciliation.exception_opened"))
        self.assertIn("TOPO_EVENT_PRODUCER", self.codes(self._validate()))

    def test_rejects_consuming_an_event_without_a_subscription(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._svc(d, "risk-engine")["consumes"]
                            .append("refund.succeeded"))
        self.assertIn("TOPO_EVENT_SUBSCRIPTION", self.codes(self._validate()))

    def test_rejects_reading_another_services_tables(self):
        self.fixture.mutate(self.REL, lambda d: self._svc(d, "risk-engine").__setitem__(
            "reads_tables", ["payment_intent"]))
        problems = self._validate()
        self.assertIn("TOPO_TABLE_ACCESS", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_a_service_that_is_not_an_object(self):
        self.fixture.mutate(self.REL, lambda d: d["services"].append("admin-web"))
        self.assertIn("TOPO_SHAPE", self.codes(self._validate()))

    def test_rejects_a_dependency_that_is_not_an_object(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._svc(d, "payment-core")["dependencies"].append("risk"))
        self.assertIn("TOPO_SHAPE", self.codes(self._validate()))

    def test_rejects_dependencies_that_are_not_a_list(self):
        self.fixture.mutate(self.REL, lambda d: self._svc(d, "admin-web").__setitem__(
            "dependencies", "edge-gateway"))
        self.assertIn("TOPO_SHAPE", self.codes(self._validate()))

    def test_rejects_a_cross_module_foreign_key_in_the_generated_schema(self):
        path = self.fixture.root / "contracts/sql/schema.sql"
        text = path.read_text(encoding="utf-8").replace(
            "    CONSTRAINT payment_intent_pk PRIMARY KEY (id)",
            "    CONSTRAINT payment_intent_pk PRIMARY KEY (id),\n"
            "    CONSTRAINT payment_intent_tenant_id_fk "
            "FOREIGN KEY (tenant_id) REFERENCES tenant (id)")
        path.write_text(text, encoding="utf-8")
        problems = self._validate()
        self.assertIn("TOPO_FOREIGN_KEY_CROSS_MODULE", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_a_missing_generated_schema(self):
        self.fixture.remove("contracts/sql/schema.sql")
        self.assertIn("TOPO_SCHEMA_MISSING", self.codes(self._validate()))

    def test_rejects_missing_generated_artefacts(self):
        self.fixture.remove("contracts/topology/graph.json")
        self.assertIn("TOPO_GENERATED_MISSING", self.codes(self._validate()))

    def test_rejects_a_hand_edited_generated_artefact(self):
        path = self.fixture.root / "docs/architecture/SERVICE_TOPOLOGY.md"
        path.write_text(path.read_text(encoding="utf-8").replace(
            "fail_closed", "fail_open"), encoding="utf-8")
        self.assertIn("TOPO_GENERATED_DRIFT", self.codes(self._validate()))

    def test_fails_closed_when_the_artefacts_cannot_be_generated(self):
        """A gate must turn a broken topology into a finding, not into a crash."""
        self.fixture.mutate(self.REL, lambda d: self._svc(d, "admin-web").pop("slo"))
        self.assertIn("TOPO_GENERATED", self.codes(self._validate()))
