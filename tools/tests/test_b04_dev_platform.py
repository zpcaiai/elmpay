"""B04 / AT-B04-01 — offline, reproducible local development platform."""
from __future__ import annotations

from tools.paygov import devgen, devplatform
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class DevPlatformHappyPath(FixtureTestCase):
    def test_real_platform_passes(self):
        problems = devplatform.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_b04_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("dev-platform", registry.names())

    def test_required_services_are_present(self):
        doc = self.fixture.read("governance/dev-platform.json")
        ids = {s["id"] for s in doc["services"]}
        for required in ("postgres", "kafka", "redis", "keycloak", "minio"):
            self.assertIn(required, ids)

    def test_every_enabled_provider_has_a_simulator(self):
        doc = self.fixture.read("governance/dev-platform.json")
        project = self.fixture.read("governance/project-config.json")
        enabled = {name for name, cfg in project["providers"].items() if cfg.get("enabled")}
        simulated = {s["provider"] for s in doc["simulators"]}
        self.assertEqual(enabled - simulated, set())

    def test_all_images_are_digest_pinned(self):
        doc = self.fixture.read("governance/dev-platform.json")
        catalog = {e["id"]: e for e in
                   self.fixture.read("governance/version-catalog.json")["entries"]}
        for service in doc["services"]:
            entry = catalog[service["image_ref"]]
            self.assertEqual(entry["pin_type"], "digest", service["id"])

    def test_generated_compose_binds_ports_to_loopback_only(self):
        compose = devgen.compose_yaml(REAL_ROOT)
        for line in compose.splitlines():
            stripped = line.strip()
            if stripped.startswith('- "') and stripped.count(":") >= 2:
                self.assertIn("127.0.0.1", stripped)

    def test_generated_compose_has_no_privileged_containers(self):
        compose = devgen.compose_yaml(REAL_ROOT)
        self.assertNotIn("privileged: true", compose)
        self.assertNotIn("network_mode: host", compose)
        self.assertIn("no-new-privileges:true", compose)

    def test_env_example_contains_no_real_values(self):
        text = devgen.env_example(REAL_ROOT)
        self.assertIn("change-me", text)
        for marker in ("sk_live", "-----BEGIN", "AKIA"):
            self.assertNotIn(marker, text)

    def test_generation_is_deterministic(self):
        self.assertEqual(devgen.render_all(REAL_ROOT), devgen.render_all(REAL_ROOT))

    def test_every_service_declares_a_healthcheck(self):
        doc = self.fixture.read("governance/dev-platform.json")
        for service in doc["services"] + doc["simulators"]:
            self.assertTrue(service["healthcheck"].strip(), service["id"])


class DevPlatformRejects(FixtureTestCase):
    REL = "governance/dev-platform.json"

    def _validate(self):
        return devplatform.validate(self.fixture.root, Budget(seconds=60).start())

    def test_rejects_inline_password(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["services"][0]["environment"]
                            .__setitem__("POSTGRES_PASSWORD", "correct-horse-battery"))
        problems = self._validate()
        self.assertIn("DEV_INLINE_SECRET", self.codes(problems))
        self.assertIn("NN-07", self.rules(problems))

    def test_rejects_undeclared_secret_variable(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["services"][0]["environment"]
                            .__setitem__("POSTGRES_PASSWORD", "${UNDECLARED_PASSWORD}"))
        self.assertIn("DEV_INLINE_SECRET", self.codes(self._validate()))

    def test_rejects_production_marker_in_environment(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["services"][0]["environment"]
                            .__setitem__("POSTGRES_DB", "elmpay-production"))
        self.assertIn("DEV_PRODUCTION_VALUE", self.codes(self._validate()))

    def test_rejects_non_synthetic_data_classification(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["services"][0].__setitem__("data_classification", "real"))
        problems = self._validate()
        self.assertIn("DEV_DATA_CLASS", self.codes(problems))
        self.assertIn("NN-02", self.rules(problems))

    def test_rejects_production_environment_target(self):
        self.fixture.mutate(self.REL, lambda d: d["environments"].append("production"))
        self.assertIn("DEV_ENVIRONMENT", self.codes(self._validate()))

    def test_rejects_allowing_real_card_data(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["forbidden_in_environments"]
                            .__setitem__("real_card_data", True))
        self.assertIn("DEV_FORBIDDEN", self.codes(self._validate()))

    def test_rejects_missing_required_service(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["services"].__setitem__(
                                slice(None), [s for s in d["services"] if s["id"] != "kafka"]))
        self.assertIn("DEV_REQUIRED_SERVICE", self.codes(self._validate()))

    def test_rejects_missing_simulator_for_enabled_provider(self):
        self.fixture.mutate(self.REL, lambda d: d["simulators"].pop(0))
        self.assertIn("DEV_SIMULATOR_MISSING", self.codes(self._validate()))

    def test_rejects_host_port_conflict(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["services"][1]["ports"].append(
                                {"host": d["services"][0]["ports"][0]["host"],
                                 "container": "9999"}))
        self.assertIn("DEV_PORT_CONFLICT", self.codes(self._validate()))

    def test_rejects_service_without_healthcheck(self):
        self.fixture.mutate(self.REL, lambda d: d["services"][2].__setitem__("healthcheck", ""))
        self.assertIn("DEV_HEALTHCHECK", self.codes(self._validate()))

    def test_rejects_image_outside_the_version_catalogue(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["services"][0].__setitem__("image_ref", "some-image"))
        self.assertIn("DEV_IMAGE", self.codes(self._validate()))

    def test_rejects_undeclared_volume(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["services"][0]["volumes"].append("ghost:/data"))
        self.assertIn("DEV_VOLUME", self.codes(self._validate()))

    def test_rejects_hand_edited_compose(self):
        path = self.fixture.root / "platform/dev/compose.yaml"
        path.write_text(path.read_text(encoding="utf-8")
                        .replace("127.0.0.1:5432:5432", "0.0.0.0:5432:5432"), encoding="utf-8")
        self.assertIn("DEV_DRIFT", self.codes(self._validate()))

    def test_rejects_missing_generated_file(self):
        (self.fixture.root / "platform/dev/compose.yaml").unlink()
        self.assertIn("DEV_MISSING", self.codes(self._validate()))

    def test_rejects_simulator_without_build_context(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["simulators"][0].__setitem__("build_context",
                                                                     "platform/dev/nope"))
        self.assertIn("DEV_BUILD_CONTEXT", self.codes(self._validate()))
