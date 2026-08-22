"""Independent tests for the consent-gated keyless signing pipeline.

Executable tests use local fake artifacts and a fake Cosign process. They do
not request OIDC credentials or publish anything to Fulcio/Rekor.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.paygov import ci, cigen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


OPT_IN = "ELMPAY_PUBLIC_SIGSTORE_METADATA_DISCLOSURE_OPT_IN"
WORKFLOW_REF = "zpcaiai/elmpay/.github/workflows/ci.yml@refs/heads/main"


def _job(workflow: str, job_id: str) -> str:
    lines = workflow.splitlines(keepends=True)
    start = next(index for index, line in enumerate(lines)
                 if line == f"  {job_id}:\n")
    end = next((index for index, line in enumerate(lines[start + 1:], start + 1)
                if line.startswith("  ") and not line.startswith("    ")), len(lines))
    return "".join(lines[start:end])


def _projects() -> list[str]:
    catalog = json.loads((REAL_ROOT / "governance/version-catalog.json").read_text())
    registry = json.loads((REAL_ROOT / "governance/module-registry.json").read_text())
    paths = {module["name"]: module["path"] for module in registry["modules"]}
    return [paths[name] for name in catalog["modules_by_build_system"]["gradle"]]


def _github_environment() -> dict[str, str]:
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": "zpcaiai/elmpay",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_REPOSITORY_ID": "111",
        "GITHUB_REPOSITORY_OWNER_ID": "222",
        "RUNNER_ENVIRONMENT": "github-hosted",
    }


def _write_jar(path: Path, payload: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        if payload:
            archive.writestr("com/elmpay/Reference.class", b"test-bytecode-placeholder")


class SigningWorkflowRendering(unittest.TestCase):
    def test_oidc_is_global_none_and_write_only_in_sign_job(self):
        workflow = cigen.workflow(REAL_ROOT)
        global_permissions = workflow.split("jobs:", 1)[0]
        self.assertIn("  id-token: none", global_permissions)
        self.assertNotIn("id-token: write", global_permissions)
        self.assertEqual(workflow.count("id-token: write"), 1)
        self.assertIn("      id-token: write", _job(workflow, "sign"))

    def test_signing_is_exactly_pinned_and_trusted_main_push_only(self):
        sign = _job(cigen.workflow(REAL_ROOT), "sign")
        self.assertIn(
            "if: github.event_name == 'push' && "
            "github.repository == 'zpcaiai/elmpay' && "
            "github.ref == 'refs/heads/main' && "
            f"vars.{OPT_IN} == 'true'",
            sign,
        )
        self.assertIn(
            "actions/download-artifact@"
            "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c  # v8.0.1", sign)
        self.assertIn(
            "sigstore/cosign-installer@"
            "6f9f17788090df1f26f669e9d70d6ae9567deba6  # v4.1.2", sign)
        self.assertIn("cosign-release: 'v3.0.6'", sign)
        self.assertNotIn("actions/setup-java", sign)
        self.assertNotIn("gradle/actions/setup-gradle", sign)

    def test_manifested_build_and_sbom_are_downloaded_fail_closed(self):
        workflow = cigen.workflow(REAL_ROOT)
        sign = _job(workflow, "sign")
        self.assertIn("name: build-artifacts\n          path: build/signing-inputs", sign)
        self.assertIn("name: sbom-artifacts\n          path: build/reports", sign)
        build = _job(workflow, "build")
        self.assertIn("scripts/stage-signing-artifacts.sh", build)
        self.assertIn("build/signing-inputs/", build)
        for job_id in ("build", "dependency-scan", "sbom", "sign"):
            self.assertIn("if-no-files-found: error", _job(workflow, job_id), job_id)

    def test_terminal_gate_uses_env_and_has_distinct_validation_path(self):
        gate = _job(cigen.workflow(REAL_ROOT), "release-gate")
        self.assertIn(f"ELMPAY_SIGNING_OPT_IN: ${{{{ vars.{OPT_IN} }}}}", gate)
        self.assertIn("RELEASE_ONLY_STAGES=(sign evidence-archive)", gate)
        self.assertIn("validated-not-release-eligible: validation succeeded", gate)
        self.assertNotIn("${{", gate.split("        run: |\n", 1)[1])

    def test_scripts_have_shebang_and_claim_only_build_l1_blob_signing(self):
        for script in (cigen.stage_signing_artifacts_script(REAL_ROOT),
                       cigen.sign_script(REAL_ROOT)):
            self.assertTrue(script.startswith("#!/usr/bin/env bash\n"))
        script = cigen.sign_script(REAL_ROOT)
        self.assertIn("cosign sign-blob --yes", script)
        self.assertIn("cosign attest-blob --yes", script)
        self.assertIn("cosign verify-blob-attestation \\", script)
        self.assertIn("--check-claims=true", script)
        self.assertIn("https://slsa.dev/provenance/v1", script)
        self.assertIn("SLSA Build L1", script)
        self.assertIn("not claim container-image signing", script)
        self.assertNotIn("cosign sign --", script)


class ArtifactStagingScript(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="elmpay-stage-test-")
        self.root = Path(self.temporary.name)
        self.script = self.root / "scripts/stage-signing-artifacts.sh"
        self.script.parent.mkdir(parents=True)
        self.script.write_text(cigen.stage_signing_artifacts_script(REAL_ROOT))
        self.script.chmod(0o755)
        self.projects = _projects()
        for project in self.projects:
            _write_jar(self.root / project / "build/libs" / f"{Path(project).name}.jar")
        self.environment = os.environ.copy()
        self.environment.update(_github_environment())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", str(self.script)], cwd=self.root,
                              env=self.environment, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False)

    def test_stages_all_20_gradle_leaf_projects_with_paths_hashes_and_source(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.projects), 20)
        stage = self.root / "build/signing-inputs"
        manifest_path = stage / "artifact-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["projects"], self.projects)
        self.assertEqual(manifest["source"]["git_sha"], "a" * 40)
        self.assertEqual(manifest["source"]["run_id"], "12345")
        self.assertEqual(len(manifest["artifacts"]), 20)
        for entry in manifest["artifacts"]:
            staged = stage / entry["path"]
            self.assertTrue(staged.is_file(), entry["path"])
            self.assertEqual(hashlib.sha256(staged.read_bytes()).hexdigest(), entry["sha256"])
        digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        self.assertEqual((stage / "artifact-manifest.sha256").read_text(),
                         f"{digest}  artifact-manifest.json\n")

    def test_missing_declared_project_jar_fails_without_partial_stage(self):
        project = self.projects[-1]
        (self.root / project / "build/libs" / f"{Path(project).name}.jar").unlink()
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no JAR artifact found for declared Gradle project", result.stderr)
        self.assertFalse((self.root / "build/signing-inputs").exists())


class GeneratedSigningScript(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="elmpay-signing-test-")
        self.root = Path(self.temporary.name)
        scripts = self.root / "scripts"
        scripts.mkdir(parents=True)
        self.script = scripts / "sign-artifacts.sh"
        self.script.write_text(cigen.sign_script(REAL_ROOT))
        self.script.chmod(0o755)
        stage_script = scripts / "stage-signing-artifacts.sh"
        stage_script.write_text(cigen.stage_signing_artifacts_script(REAL_ROOT))
        stage_script.chmod(0o755)
        self.environment = os.environ.copy()
        self.environment.update(_github_environment())
        self.projects = _projects()
        for project in self.projects:
            _write_jar(self.root / project / "build/libs" / f"{Path(project).name}.jar")
        staged = subprocess.run(["bash", str(stage_script)], cwd=self.root,
                                env=self.environment, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
        if staged.returncode:
            self.fail(staged.stderr)
        self.stage = self.root / "build/signing-inputs"
        self.manifest = self.stage / "artifact-manifest.json"
        self.manifest_sha = self.stage / "artifact-manifest.sha256"
        manifest = json.loads(self.manifest.read_text())
        self.jars = [self.stage / entry["path"] for entry in manifest["artifacts"]]
        self.jar = self.jars[0]
        (self.root / "build/reports").mkdir(parents=True)
        self.sbom = self.root / "build/reports/bom.json"
        self.sbom.write_text(
            '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}\n')

        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        self.cosign_log = self.root / "cosign.log"
        fake = fake_bin / "cosign"
        fake.write_text("""#!/usr/bin/env python3
import base64, json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ["FAKE_COSIGN_LOG"]).open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
command = args[0]
if command == "version":
    print("GitVersion:    v3.0.6")
elif command == "sign-blob":
    Path(args[args.index("--bundle") + 1]).write_text(json.dumps({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "messageSignature": {"signature": "ZmFrZQ=="},
        "verificationMaterial": {"tlogEntries": [{}]}}))
elif command == "attest-blob":
    statement = Path(args[args.index("--statement") + 1]).read_bytes()
    if os.environ.get("FAKE_COSIGN_CORRUPT_STATEMENT") == "true":
        statement = b"{}"
    Path(args[args.index("--bundle") + 1]).write_text(json.dumps({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json",
          "payload": base64.b64encode(statement).decode(),
          "signatures": [{"sig": "ZmFrZQ=="}]},
        "verificationMaterial": {"tlogEntries": [{}]}}))
elif command in {"verify-blob", "verify-blob-attestation"}:
    print(json.dumps({"verified": True}))
else:
    raise SystemExit(f"unexpected fake cosign command: {command}")
""")
        fake.chmod(0o755)
        self.environment.update({
            "PATH": f"{fake_bin}{os.pathsep}{self.environment['PATH']}",
            "FAKE_COSIGN_LOG": str(self.cosign_log),
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.invalid/request",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-only-placeholder",
            OPT_IN: "true",
        })

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = self.environment.copy()
        env.update(overrides)
        return subprocess.run(["bash", str(self.script)], cwd=self.root, env=env,
                              text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False)

    def _calls(self) -> list[list[str]]:
        if not self.cosign_log.exists():
            return []
        return [json.loads(line) for line in self.cosign_log.read_text().splitlines()]

    def _rehash_manifest(self) -> None:
        manifest = json.loads(self.manifest.read_text())
        relative = self.jar.relative_to(self.stage).as_posix()
        entry = next(item for item in manifest["artifacts"] if item["path"] == relative)
        entry["sha256"] = hashlib.sha256(self.jar.read_bytes()).hexdigest()
        self.manifest.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
        digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.manifest_sha.write_text(f"{digest}  artifact-manifest.json\n")

    def test_emits_and_self_verifies_exact_subjects_and_slsa_fields(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        subject_paths = self.jars + [self.manifest, self.manifest_sha, self.sbom]
        self.assertIn(f"{len(subject_paths)} blob subject(s)", result.stdout)
        signatures = self.root / "build/signatures"
        provenance = self.root / "build/provenance.intoto.jsonl"
        envelope = json.loads(provenance.read_text())
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        expected = {path.relative_to(self.root).as_posix():
                    hashlib.sha256(path.read_bytes()).hexdigest() for path in subject_paths}
        actual = {item["name"]: item["digest"]["sha256"]
                  for item in statement["subject"]}
        self.assertEqual(actual, expected)
        definition = statement["predicate"]["buildDefinition"]
        self.assertEqual(definition["externalParameters"], {
            "workflow": {"ref": "refs/heads/main",
                         "repository": "https://github.com/zpcaiai/elmpay",
                         "path": ".github/workflows/ci.yml"},
            "vars": {OPT_IN: "true"},
        })
        self.assertEqual(definition["resolvedDependencies"], [{
            "uri": "git+https://github.com/zpcaiai/elmpay@refs/heads/main",
            "digest": {"gitCommit": "a" * 40},
        }])
        self.assertEqual(statement["predicate"]["runDetails"]["builder"]["id"],
                         f"https://github.com/{WORKFLOW_REF}")
        self.assertNotIn("startedOn", json.dumps(statement))
        self.assertNotIn("finishedOn", json.dumps(statement))
        for relative, digest in expected.items():
            stem = hashlib.sha256(relative.encode()).hexdigest()
            self.assertEqual((signatures / f"{stem}.sha256").read_text(),
                             f"{digest}  {relative}\n")
            for suffix in ("blob.sigstore.json", "blob.verify.log",
                           "provenance.verify.log"):
                self.assertTrue((signatures / f"{stem}.{suffix}").is_file())
        commands = [call[0] for call in self._calls()]
        for command, count in (("sign-blob", len(subject_paths)),
                               ("attest-blob", 1),
                               ("verify-blob", len(subject_paths)),
                               ("verify-blob-attestation", len(subject_paths))):
            self.assertEqual(commands.count(command), count)

    def test_manifest_only_jar_is_refused(self):
        _write_jar(self.jar, payload=False)
        self._rehash_manifest()
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no payload entry outside META-INF", result.stderr)
        self.assertNotIn("sign-blob", [call[0] for call in self._calls()])

    def test_manifest_sha_path_set_and_run_binding_tampering_fail(self):
        self.manifest.write_text(self.manifest.read_text() + " ")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest SHA-256 sidecar does not match", result.stderr)

    def test_unmanifested_staged_jar_fails(self):
        _write_jar(self.stage / "extra/build/libs/extra.jar")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("path set differs from manifest", result.stderr)

    def test_wrong_run_binding_and_invalid_sbom_fail_before_signing(self):
        manifest = json.loads(self.manifest.read_text())
        manifest["source"]["run_id"] = "other"
        self.manifest.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
        digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.manifest_sha.write_text(f"{digest}  artifact-manifest.json\n")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source identity does not match", result.stderr)

    def test_invalid_cyclonedx_sbom_fails_before_signing(self):
        self.sbom.write_text('{"bomFormat":"other"}\n')
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a CycloneDX document", result.stderr)
        self.assertNotIn("sign-blob", [call[0] for call in self._calls()])

    def test_opt_in_and_trusted_context_are_required_before_cosign(self):
        for override in ({OPT_IN: "false"}, {"GITHUB_REF": "refs/heads/fork"}):
            with self.subTest(override=override):
                result = self._run(**override)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self._calls(), [])

    def test_mismatched_signed_dsse_payload_fails_closed(self):
        result = self._run(FAKE_COSIGN_CORRUPT_STATEMENT="true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signed DSSE payload does not match", result.stderr)
        self.assertFalse((self.root / "build/signatures").exists())


class ReleaseGateScript(unittest.TestCase):
    def setUp(self) -> None:
        doc = json.loads((REAL_ROOT / "governance/ci-pipeline.json").read_text())
        self.required = doc["required_stages"]
        self.release_only = set(doc["signing_policy"]["validation_only_skipped_stages"])
        self.script = cigen.release_gate_script(REAL_ROOT)
        self.environment = os.environ.copy()
        self.environment.update({
            "ELMPAY_GATE_EVENT_NAME": "pull_request",
            "ELMPAY_GATE_REPOSITORY": "zpcaiai/elmpay",
            "ELMPAY_GATE_REF": "refs/pull/7/merge",
        })
        for stage in self.required:
            key = "ELMPAY_NEEDS_" + stage.upper().replace("-", "_")
            self.environment[key] = "skipped" if stage in self.release_only else "success"

    def _run(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = self.environment.copy()
        env.update(overrides)
        return subprocess.run(["bash", "-c", self.script], env=env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def test_pr_and_manual_validate_without_becoming_release_eligible(self):
        for event in ("pull_request", "workflow_dispatch"):
            with self.subTest(event=event):
                result = self._run(ELMPAY_GATE_EVENT_NAME=event)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("validated-not-release-eligible", result.stdout)
                self.assertNotIn("release-eligible: trusted", result.stdout)

    def test_trusted_main_requires_opt_in_and_all_release_stages(self):
        release = {"ELMPAY_GATE_EVENT_NAME": "push",
                   "ELMPAY_GATE_REF": "refs/heads/main"}
        for stage in self.release_only:
            release["ELMPAY_NEEDS_" + stage.upper().replace("-", "_")] = "success"
        self.assertNotEqual(self._run(**release).returncode, 0)
        accepted = self._run(ELMPAY_SIGNING_OPT_IN="true", **release)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("release-eligible: trusted main push", accepted.stdout)

    def test_validation_rejects_unexpected_signing_or_failed_gate(self):
        unexpected = self._run(ELMPAY_NEEDS_SIGN="success")
        self.assertNotEqual(unexpected.returncode, 0)
        self.assertIn("release-only stage 'sign' unexpectedly ran", unexpected.stderr)
        failed = self._run(ELMPAY_NEEDS_DEPENDENCY_SCAN="failure")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("required stage 'dependency-scan' was 'failure'", failed.stderr)

    def test_shell_metacharacters_in_opt_in_are_not_executed(self):
        with tempfile.TemporaryDirectory(prefix="gate-injection-") as directory:
            marker = Path(directory) / "executed"
            release = {"ELMPAY_GATE_EVENT_NAME": "push",
                       "ELMPAY_GATE_REF": "refs/heads/main",
                       "ELMPAY_SIGNING_OPT_IN": f"true$(touch {marker})"}
            for stage in self.release_only:
                release["ELMPAY_NEEDS_" + stage.upper().replace("-", "_")] = "success"
            result = self._run(**release)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())


class SigningGovernanceRejects(FixtureTestCase):
    REL = "governance/ci-pipeline.json"

    @staticmethod
    def _stage(data, stage_id):
        return next(stage for stage in data["stages"] if stage["id"] == stage_id)

    def _validate(self):
        return ci.validate(self.fixture.root, Budget(seconds=60).start())

    def test_rejects_permissions_policy_and_action_weakening(self):
        cases = [
            (lambda data: data.__setitem__("runner", "self-hosted"),
             "CI_RUNNER"),
            (lambda data: data["permissions"].__setitem__("issues", "write"),
             "CI_PERMISSIONS"),
            (lambda data: data["signing_policy"]["job_permissions"].__setitem__(
                "contents", "write"), "CI_SIGNING_PERMISSIONS"),
            (lambda data: data["signing_policy"].__setitem__(
                "trusted_repository", "fork/elmpay"), "CI_SIGNING_POLICY"),
            (lambda data: next(action for action in data["actions"]
                               if action["name"] == "sigstore/cosign-installer")
             .__setitem__("ref", "0" * 40), "CI_SIGNING_ACTION"),
        ]
        for mutation, code in cases:
            with self.subTest(code=code):
                self.fixture.mutate(self.REL, mutation)
                self.assertIn(code, self.codes(self._validate()))
                self.fixture.restore()

    def test_rejects_input_command_output_and_claim_weakening(self):
        cases = [
            (lambda data: self._stage(data, "sign")["needs"].remove("secret-scan"),
             "CI_SIGNING_INPUT"),
            (lambda data: self._stage(data, "sign").__setitem__("commands", ["true"]),
             "CI_SIGNING_COMMAND"),
            (lambda data: self._stage(data, "sign")["artifacts"].remove(
                "build/provenance.intoto.jsonl"), "CI_SIGNING_OUTPUT"),
            (lambda data: self._stage(data, "sign").__setitem__(
                "purpose", "Sign a container image at SLSA Build L2"),
             "CI_SIGNING_CLAIM"),
        ]
        for mutation, code in cases:
            with self.subTest(code=code):
                self.fixture.mutate(self.REL, mutation)
                self.assertIn(code, self.codes(self._validate()))
                self.fixture.restore()

    def test_rejects_missing_signing_stage(self):
        self.fixture.mutate(
            self.REL,
            lambda data: data["stages"].__setitem__(
                slice(None),
                [stage for stage in data["stages"] if stage["id"] != "sign"],
            ),
        )
        self.assertIn("CI_SIGNING_STAGE", self.codes(self._validate()))

    def test_module_path_cannot_inject_into_generated_shell(self):
        marker = self.fixture.root / "build/path-injection-ran"
        malicious = f"libs/money'; touch {marker}; #"
        self.fixture.mutate(
            "governance/module-registry.json",
            lambda data: next(module for module in data["modules"]
                              if module["name"] == "money")
            .__setitem__("path", malicious),
        )
        stage = cigen.stage_signing_artifacts_script(self.fixture.root)
        sign = cigen.sign_script(self.fixture.root)
        self.assertNotIn(malicious, stage)
        self.assertNotIn(malicious, sign)
        self.assertIn("STAGING_PROJECTS_B64=", stage)
        self.assertIn("EXPECTED_PROJECTS_B64=", sign)

        script = self.fixture.root / "scripts/stage-signing-artifacts.sh"
        script.write_text(stage, encoding="utf-8")
        script.chmod(0o755)
        environment = os.environ.copy()
        environment.update(_github_environment())
        result = subprocess.run(
            ["bash", str(script)], cwd=self.fixture.root, env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe Gradle artifact project path", result.stderr)
        self.assertFalse(marker.exists())

    def test_rejects_required_stage_and_signing_chain_bypasses(self):
        cases = [
            (lambda data: data["required_stages"].remove("dependency-scan"),
             "CI_REQUIRED_STAGE"),
            (lambda data: data["required_stages"].remove("sign"),
             "CI_SIGNING_REQUIRED"),
            (lambda data: self._stage(data, "sign").__setitem__("fail_closed", False),
             "CI_SIGNING_REQUIRED"),
            (lambda data: self._stage(data, "evidence-archive")["needs"].remove("sign"),
             "CI_SIGNING_CHAIN"),
        ]
        for mutation, code in cases:
            with self.subTest(code=code):
                self.fixture.mutate(self.REL, mutation)
                self.assertIn(code, self.codes(self._validate()))
                self.fixture.restore()

    def test_rejects_missing_artifacts_including_dependency_report(self):
        for stage_id in ("build", "dependency-scan", "sbom", "sign"):
            with self.subTest(stage=stage_id):
                self.fixture.mutate(self.REL, lambda data, sid=stage_id:
                                    self._stage(data, sid).__setitem__(
                                        "if_no_files_found", "warn"))
                self.assertIn("CI_ARTIFACT_MISSING", self.codes(self._validate()))
                self.fixture.restore()

    def test_rejects_terminal_context_or_expression_in_shell_source(self):
        doc = self.fixture.read(self.REL)
        original = cigen.workflow(self.fixture.root)
        broken_context = original.replace(
            "ELMPAY_GATE_EVENT_NAME: ${{ github.event_name }}",
            "ELMPAY_GATE_EVENT: ${{ github.event_name }}", 1)
        problems = ci._terminal_gate(broken_context, doc, ".github/workflows/ci.yml")
        self.assertIn("CI_RELEASE_GATE_CONTEXT", self.codes(problems))
        injected = original.replace(
            "          set -euo pipefail",
            f"          set -euo pipefail\n          echo ${{{{ vars.{OPT_IN} }}}}", 1)
        problems = ci._terminal_gate(injected, doc, ".github/workflows/ci.yml")
        self.assertIn("CI_RELEASE_GATE_INJECTION", self.codes(problems))


if __name__ == "__main__":
    unittest.main()
