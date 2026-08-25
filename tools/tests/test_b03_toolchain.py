"""B03 / AT-B03-01 — reproducible toolchain baseline.

Everything here exists to make one property mechanical: the dependency closure
of a commit cannot change without a reviewed change to the version catalogue.
"""
from __future__ import annotations

import os
import hashlib

from tools.paygov import buildgen, nvdfeed, toolchain
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
        self.assertIn("gradlePluginPortal()", text)
        self.assertIn("mavenCentral()", text)

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

    def test_security_build_plugins_are_catalogue_pinned(self):
        text = (REAL_ROOT / "build.gradle.kts").read_text(encoding="utf-8")
        catalog = self.fixture.read("governance/version-catalog.json")
        entries = {entry["id"]: entry for entry in catalog["entries"]}
        self.assertIn(
            f'id("org.owasp.dependencycheck") version '
            f'"{entries["owasp-dependency-check"]["version"]}"',
            text,
        )
        self.assertIn(
            f'id("org.cyclonedx.bom") version "{entries["cyclonedx-gradle"]["version"]}"',
            text,
        )
        self.assertIn('failBuildOnCVSS.set(0.0f)', text)
        self.assertIn('jsonOutput.set(layout.buildDirectory.file("reports/bom.json"))', text)
        self.assertIn("xmlOutput.unsetConvention()", text)

    def test_only_declared_gradle_leaf_modules_can_emit_jars(self):
        text = (REAL_ROOT / "build.gradle.kts").read_text(encoding="utf-8")
        catalog = self.fixture.read("governance/version-catalog.json")
        registry = {
            module["name"]: module["path"]
            for module in self.fixture.read("governance/module-registry.json")["modules"]
        }
        expected = {
            ":" + registry[name].replace("/", ":")
            for name in catalog["modules_by_build_system"]["gradle"]
        }
        self.assertIn("base", text)
        self.assertNotIn("    java\n", text)
        self.assertIn("if (path !in javaModulePaths) return@subprojects", text)
        self.assertIn('tasks.register("test")', text)
        for project in expected:
            self.assertEqual(text.count(f'    "{project}"'), 1)
        for aggregator in ('":"', '":apps"', '":connectors"', '":libs"', '":services"'):
            self.assertNotIn(f'    {aggregator}', text)


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

    def _edit_build(self, find: str, replace: str) -> None:
        path = self.fixture.root / "build.gradle.kts"
        text = path.read_text(encoding="utf-8")
        assert find in text, find
        self.fixture.write("build.gradle.kts", text.replace(find, replace, 1))

    def test_rejects_a_foreign_nvd_data_feed(self):
        self._edit_build(nvdfeed.DATAFEED_URL,
                         "https://mirror.example.invalid/nvdcve-{0}.json.gz")
        self.assertIn("TOOLCHAIN_SECURITY_DATAFEED", self.codes(self._validate()))

    def test_rejects_a_credential_override_on_the_keyless_feed(self):
        # A key on a keyless mirror is how a scan silently starts talking to
        # something other than the reviewed feed.
        self._edit_build("        datafeedUrl.set(",
                         '        apiKey.set("smuggled")\n        datafeedUrl.set(')
        self.assertIn("TOOLCHAIN_SECURITY_DATAFEED", self.codes(self._validate()))

    def test_rejects_a_second_nvd_source(self):
        self._edit_build("    nvd {", "    nvd {\n    }\n    nvd {")
        self.assertIn("TOOLCHAIN_SECURITY_DATAFEED", self.codes(self._validate()))

    def test_rejects_a_datafeed_policy_that_drifts_from_the_reviewed_one(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._entry(d, "owasp-dependency-check")
                            ["datafeed_policy"].__setitem__("max_age_hours", 24 * 30))
        self.assertIn("TOOLCHAIN_SECURITY_DATAFEED", self.codes(self._validate()))

    def test_rejects_unverified_catalogue_without_a_note(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("verification_note", ""))
        self.assertIn("TOOLCHAIN_VERIFICATION", self.codes(self._validate()))


class KotlinLexing(FixtureTestCase):
    """The build-file checks read Kotlin as text, so the lexing must be right.

    Both helpers used to treat the file as characters with no notion of a
    string literal. Stripping ``//`` to end of line cut every URL in half —
    ``datafeedUrl.set("https://…")`` became ``datafeedUrl.set("https:`` — so a
    correctly generated build file could never satisfy the governed-feed
    assertion, and anything after a ``//`` inside a literal was equally
    invisible to the checks that require a token to be *absent*. The brace walk
    had the matching blind spot: a brace inside a literal counted as a block
    delimiter.
    """

    def test_a_url_inside_a_string_survives_comment_stripping(self):
        source = 'datafeedUrl.set("https://example.test/nvdcve-{0}.json.gz")\n'
        self.assertEqual(toolchain._without_kotlin_comments(source), source)

    def test_a_real_line_comment_is_still_removed(self):
        self.assertEqual(
            toolchain._without_kotlin_comments('a()\n// failBuildOnCVSS.set(0.0f)\nb()\n'),
            'a()\n\nb()\n')

    def test_a_trailing_comment_is_removed_without_touching_the_code(self):
        self.assertEqual(
            toolchain._without_kotlin_comments('url.set("https://x/y") // note\n'),
            'url.set("https://x/y") \n')

    def test_a_block_comment_is_removed_but_one_inside_a_string_is_kept(self):
        self.assertEqual(toolchain._without_kotlin_comments('a()/* gone */b()'), 'a()b()')
        self.assertEqual(toolchain._without_kotlin_comments('s("/* kept */")'), 's("/* kept */")')

    def test_escaped_quotes_do_not_end_the_literal(self):
        source = 's("a\\"// still inside\\"b") // gone\n'
        self.assertEqual(toolchain._without_kotlin_comments(source),
                         's("a\\"// still inside\\"b") \n')

    def test_a_commented_out_control_cannot_satisfy_an_invariant(self):
        # The reason the stripper exists at all; the fix must not weaken it.
        stripped = toolchain._without_kotlin_comments(
            'dependencyCheck {\n    // failBuildOnCVSS.set(0.0f)\n}\n')
        self.assertNotIn("failBuildOnCVSS", stripped)

    def test_block_walk_ignores_braces_inside_string_literals(self):
        bodies = toolchain._kotlin_blocks('nvd {\n    url.set("a{b")\n}\nafter()\n', r"\bnvd")
        self.assertEqual(len(bodies), 1)
        self.assertIn('url.set("a{b")', bodies[0])
        self.assertNotIn("after()", bodies[0])

    def test_the_generated_build_file_keeps_its_governed_feed_url(self):
        # End to end: the property that was actually broken on the real file.
        code = toolchain._without_kotlin_comments(
            (REAL_ROOT / "build.gradle.kts").read_text(encoding="utf-8"))
        self.assertIn(f'datafeedUrl.set("{nvdfeed.DATAFEED_URL}")', code)


class ToolchainInterpreter(FixtureTestCase):
    """The Python that runs the toolchain is part of the toolchain.

    Everything else in the delivery path is pinned — JDK, Gradle, Node,
    Postgres, even the channel simulators' Python — but for a long time the
    interpreter that executes every batch's evidence commands was not. Two
    agents drifted onto 3.10 and 3.14, and code using ``datetime.UTC`` (3.11+)
    landed: on the older environment that single import took the entire
    validator registry down, so ``verify-all`` raised instead of returning a
    verdict. A pin nobody can violate is what these rules add.
    """

    REL = "governance/version-catalog.json"

    def _validate(self):
        return toolchain.validate(self.fixture.root, Budget(seconds=90).start())

    def _interpreter(self, data):
        return next(e for e in data["entries"] if e["id"] == "python-toolchain")

    def test_the_real_catalogue_pins_the_toolchain_interpreter(self):
        self.assertNotIn("TOOLCHAIN_INTERPRETER", self.codes(self._validate()))
        self.assertNotIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(self._validate()))

    def test_rejects_a_catalogue_without_the_interpreter(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "entries", [e for e in d["entries"] if e["id"] != "python-toolchain"]))
        self.assertIn("TOOLCHAIN_INTERPRETER", self.codes(self._validate()))

    def test_rejects_a_missing_compatibility_floor(self):
        self.fixture.mutate(self.REL, lambda d: self._interpreter(d).pop("minimum_supported"))
        self.assertIn("TOOLCHAIN_INTERPRETER", self.codes(self._validate()))

    def test_rejects_a_floor_newer_than_the_reference_interpreter(self):
        self.fixture.mutate(self.REL, lambda d: self._interpreter(d)
                            .__setitem__("minimum_supported", "3.99"))
        self.assertIn("TOOLCHAIN_INTERPRETER", self.codes(self._validate()))

    def test_rejects_an_empty_above_floor_list(self):
        self.fixture.mutate(self.REL, lambda d: self._interpreter(d)
                            .__setitem__("above_floor_symbols", []))
        self.assertIn("TOOLCHAIN_INTERPRETER", self.codes(self._validate()))

    def test_rejects_a_declared_symbol_that_is_not_above_the_floor(self):
        # A list padded with symbols the floor already has would look thorough
        # while proving nothing.
        self.fixture.mutate(self.REL, lambda d: self._interpreter(d)["above_floor_symbols"]
                            .append({"symbol": "json.loads", "added_in": "3.0"}))
        self.assertIn("TOOLCHAIN_INTERPRETER", self.codes(self._validate()))

    def test_rejects_the_historical_regression(self):
        # The exact line that broke the gate, reintroduced.
        self.fixture.write("scripts/regression-probe.py",
                           "from datetime import UTC, datetime\n\nprint(datetime.now(UTC))\n")
        problems = self._validate()
        self.assertIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(problems))
        self.assertTrue(any("datetime.UTC" in p.message for p in problems))

    def test_rejects_an_above_floor_symbol_reached_by_attribute(self):
        self.fixture.write("scripts/regression-attr.py",
                           "import datetime\n\nprint(datetime.UTC)\n")
        self.assertIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(self._validate()))

    def test_rejects_an_above_floor_symbol_reached_through_module_alias(self):
        self.fixture.write("scripts/regression-module-alias.py",
                           "import datetime as dt\n\nprint(dt.UTC)\n")
        problems = self._validate()
        self.assertIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(problems))
        self.assertTrue(any("datetime.UTC" in p.message for p in problems))

    def test_alias_reuse_cannot_overwrite_an_earlier_module_candidate(self):
        self.fixture.write(
            "scripts/regression-module-alias-collision.py",
            "import datetime as x\nprint(x.UTC)\nimport itertools as x\n",
        )
        problems = self._validate()
        self.assertIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(problems))
        self.assertTrue(any("datetime.UTC" in p.message for p in problems))

    def test_rejects_an_aliased_from_import_of_an_above_floor_symbol(self):
        self.fixture.write("scripts/regression-from-alias.py",
                           "from datetime import UTC as timezone_utc\n\n"
                           "print(timezone_utc)\n")
        problems = self._validate()
        self.assertIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(problems))
        self.assertTrue(any("datetime.UTC" in p.message for p in problems))

    def test_scan_cache_is_bound_to_content_not_size_and_mtime(self):
        rel = "scripts/regression-cache.py"
        safe = "import datetime\nprint(datetime.max)\n"
        above_floor = "import datetime\nprint(datetime.UTC)\n"
        self.assertEqual(len(safe.encode("utf-8")), len(above_floor.encode("utf-8")))

        self.fixture.write(rel, safe)
        self.assertNotIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(self._validate()))
        path = self.fixture.root / rel
        original = path.stat()

        self.fixture.write(rel, above_floor)
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        restored = path.stat()
        self.assertEqual(restored.st_size, original.st_size)
        self.assertEqual(restored.st_mtime_ns, original.st_mtime_ns)

        problems = self._validate()
        self.assertIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(problems))
        self.assertTrue(any("datetime.UTC" in p.message for p in problems))

    def test_rejects_an_above_floor_module_import(self):
        self.fixture.write("scripts/regression-tomllib.py", "import tomllib\n")
        self.assertIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(self._validate()))

    def test_rejects_syntax_newer_than_the_floor(self):
        self.fixture.write(
            "scripts/regression-syntax.py",
            "try:\n    pass\nexcept* ValueError:\n    pass\n")
        self.assertIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(self._validate()))

    def test_does_not_fire_on_the_words_alone(self):
        # Prose and unrelated identifiers must not trip the rule, or the next
        # person works around it instead of fixing anything.
        self.fixture.write(
            "scripts/regression-prose.py",
            '"""Timestamps are UTC; see datetime.UTC notes for the batched case."""\n'
            "UTC = 'utc'\n"
            "batched = []\n"
            "print(UTC, batched)\n")
        self.assertNotIn("TOOLCHAIN_PYTHON_FLOOR", self.codes(self._validate()))
