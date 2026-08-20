"""B03 / AT-B03-01 — reproducible toolchain baseline.

Everything here exists to make one property mechanical: the dependency closure
of a commit cannot change without a reviewed change to the version catalogue.
"""
from __future__ import annotations

import os
import hashlib

from tools.paygov import buildgen, toolchain
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class ToolchainHappyPath(FixtureTestCase):
    def test_real_catalogue_passes(self):
        problems = toolchain.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_b03_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("toolchain", registry.names())

    def test_java_baseline_is_25(self):
        doc = self.fixture.read("governance/version-catalog.json")
        jdk = next(e for e in doc["entries"] if e["id"] == "jdk")
        self.assertTrue(jdk["version"].startswith("25."))

    def test_spring_boot_baseline_is_4_1(self):
        doc = self.fixture.read("governance/version-catalog.json")
        boot = next(e for e in doc["entries"] if e["id"] == "spring-boot")
        self.assertTrue(boot["version"].startswith("4.1."))

    def test_every_module_has_exactly_one_build_system(self):
        doc = self.fixture.read("governance/version-catalog.json")
        registry = self.fixture.read("governance/module-registry.json")
        assigned = [n for names in doc["modules_by_build_system"].values() for n in names]
        self.assertEqual(sorted(assigned), sorted({m["name"] for m in registry["modules"]}))
        self.assertEqual(len(assigned), len(set(assigned)))

    def test_container_images_are_digest_pinned(self):
        doc = self.fixture.read("governance/version-catalog.json")
        images = [e for e in doc["entries"] if e["category"] == "container"]
        self.assertTrue(images)
        for image in images:
            self.assertEqual(image["pin_type"], "digest")
            self.assertTrue(image["digest"].startswith("sha256:"))

    def test_generation_is_deterministic(self):
        self.assertEqual(buildgen.render_all(REAL_ROOT), buildgen.render_all(REAL_ROOT))

    def test_settings_includes_every_gradle_module(self):
        text = (REAL_ROOT / "settings.gradle.kts").read_text(encoding="utf-8")
        doc = self.fixture.read("governance/version-catalog.json")
        registry = {m["name"]: m["path"] for m in
                    self.fixture.read("governance/module-registry.json")["modules"]}
        for name in doc["modules_by_build_system"]["gradle"]:
            self.assertIn(f'include(":{registry[name].replace("/", ":")}")', text)

    def test_generated_build_files_carry_the_banner(self):
        for content in buildgen.render_all(REAL_ROOT).values():
            self.assertIn("GENERATED FILE", content)

    def test_default_version_catalog_is_not_imported_twice(self):
        text = (REAL_ROOT / "settings.gradle.kts").read_text(encoding="utf-8")
        self.assertNotIn('create("libs")', text)

    def test_gradle_wrapper_is_pinned_and_executable(self):
        wrapper = REAL_ROOT / "gradlew"
        properties = (REAL_ROOT / "gradle" / "wrapper" /
                      "gradle-wrapper.properties").read_text(encoding="utf-8")
        self.assertTrue(wrapper.is_file())
        self.assertTrue(os.access(wrapper, os.X_OK))
        self.assertIn("gradle-9.2.1-bin.zip", properties)
        self.assertIn(
            "distributionSha256Sum="
            "72f44c9f8ebcb1af43838f45ee5c4aa9c5444898b3468ab3f4af7b6076c5bc3f",
            properties,
        )
        self.assertEqual(
            hashlib.sha256(wrapper.read_bytes()).hexdigest(),
            "b2fe376b143a459ba5d0bd290dc89beed5399fc6d159cd1214bd642ea94bcf07",
        )
        self.assertEqual(
            hashlib.sha256((REAL_ROOT / "gradlew.bat").read_bytes()).hexdigest(),
            "9386e790d58b9368ca8e034536a5baa688643d51cb37bfa462503d36fd0291a6",
        )
        jar = REAL_ROOT / "gradle" / "wrapper" / "gradle-wrapper.jar"
        self.assertEqual(
            hashlib.sha256(jar.read_bytes()).hexdigest(),
            "423cb469ccc0ecc31f0e4e1c309976198ccb734cdcbb7029d4bda0f18f57e8d9",
        )


class ToolchainRejects(FixtureTestCase):
    REL = "governance/version-catalog.json"

    def _validate(self):
        return toolchain.validate(self.fixture.root, Budget(seconds=60).start())

    def _entry(self, data, eid):
        return next(e for e in data["entries"] if e["id"] == eid)

    def test_rejects_latest_tag(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "redis").__setitem__("version", "latest"))
        self.assertIn("TOOLCHAIN_FLOATING", self.codes(self._validate()))

    def test_rejects_snapshot(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "spring-boot")
                            .__setitem__("version", "4.1.4-SNAPSHOT"))
        self.assertIn("TOOLCHAIN_FLOATING", self.codes(self._validate()))

    def test_rejects_gradle_dynamic_version(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "grpc-java").__setitem__("version", "1.72.+"))
        self.assertIn("TOOLCHAIN_FLOATING", self.codes(self._validate()))

    def test_rejects_maven_range(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "junit").__setitem__("version", "[5.13,6.0)"))
        self.assertIn("TOOLCHAIN_FLOATING", self.codes(self._validate()))

    def test_accepts_semver_build_metadata(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "jdk").__setitem__("version", "25.0.5+9"))
        self.assertNotIn("TOOLCHAIN_FLOATING", self.codes(self._validate()))

    def test_rejects_container_without_digest(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "redis-image").__setitem__("digest", ""))
        self.assertIn("TOOLCHAIN_DIGEST", self.codes(self._validate()))

    def test_rejects_gradle_distribution_without_digest(self):
        self.fixture.mutate(
            self.REL,
            lambda d: self._entry(d, "gradle").__setitem__("digest", ""),
        )
        self.assertIn("TOOLCHAIN_DIGEST", self.codes(self._validate()))

    def test_rejects_missing_gradle_wrapper_launcher(self):
        fixture = self.new_fixture()
        fixture.remove("gradlew")
        self.assertIn(
            "TOOLCHAIN_WRAPPER",
            self.codes(toolchain.validate(fixture.root, Budget(seconds=60).start())),
        )

    def test_rejects_non_executable_gradle_wrapper_launcher(self):
        fixture = self.new_fixture()
        (fixture.root / "gradlew").chmod(0o644)
        self.assertIn(
            "TOOLCHAIN_WRAPPER",
            self.codes(toolchain.validate(fixture.root, Budget(seconds=60).start())),
        )

    def test_rejects_corrupt_gradle_wrapper_jar(self):
        fixture = self.new_fixture()
        fixture.write("gradle/wrapper/gradle-wrapper.jar", b"not a jar")
        self.assertIn(
            "TOOLCHAIN_WRAPPER",
            self.codes(toolchain.validate(fixture.root, Budget(seconds=60).start())),
        )

    def test_rejects_container_pinned_by_tag_only(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "kafka-image").__setitem__("pin_type", "exact"))
        self.assertIn("TOOLCHAIN_PIN", self.codes(self._validate()))

    def test_rejects_entry_without_owner(self):
        self.fixture.mutate(self.REL, lambda d: self._entry(d, "flyway").__setitem__("owner", ""))
        self.assertIn("TOOLCHAIN_METADATA", self.codes(self._validate()))

    def test_rejects_entry_without_upgrade_policy(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "kafka").__setitem__("upgrade_policy", ""))
        self.assertIn("TOOLCHAIN_METADATA", self.codes(self._validate()))

    def test_rejects_module_without_build_system(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["modules_by_build_system"]["gradle"].remove("ledger-service"))
        self.assertIn("TOOLCHAIN_BUILD_SYSTEM", self.codes(self._validate()))

    def test_rejects_module_claimed_twice(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["modules_by_build_system"]["node"].append("payment-core"))
        self.assertIn("TOOLCHAIN_BUILD_SYSTEM", self.codes(self._validate()))

    def test_rejects_java_downgrade(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "jdk").__setitem__("version", "21.0.10"))
        self.assertIn("TOOLCHAIN_JDK", self.codes(self._validate()))

    def test_rejects_missing_required_category(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["required_categories"].append("hsm"))
        self.assertIn("TOOLCHAIN_CATEGORY", self.codes(self._validate()))

    def test_rejects_hand_edited_build_file(self):
        path = self.fixture.root / "build.gradle.kts"
        path.write_text(path.read_text(encoding="utf-8")
                        .replace("JavaLanguageVersion.of(25)", "JavaLanguageVersion.of(21)"),
                        encoding="utf-8")
        self.assertIn("BUILD_DRIFT", self.codes(self._validate()))

    def test_rejects_missing_generated_build_file(self):
        self.fixture.remove("gradle/libs.versions.toml")
        self.assertIn("BUILD_MISSING", self.codes(self._validate()))

    def test_rejects_unverified_catalogue_without_a_note(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("verification_note", ""))
        self.assertIn("TOOLCHAIN_VERIFICATION", self.codes(self._validate()))
