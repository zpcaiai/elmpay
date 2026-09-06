from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError, read_json, sha256_json  # noqa: E402
import elmpay_runtime.oci as OCI  # noqa: E402
from elmpay_runtime.kubernetes import render_workloads  # noqa: E402
from elmpay_runtime.oci import (  # noqa: E402
    admission_policy_digest,
    product_image_manifest_digest,
    resolve_base_images,
    validate_product_image_manifest,
    validate_product_release_index,
)


PIPELINE_SPEC = importlib.util.spec_from_file_location(
    "elmpay_product_image_pipeline", ROOT / "scripts/product-image-pipeline.py"
)
assert PIPELINE_SPEC is not None and PIPELINE_SPEC.loader is not None
PIPELINE = importlib.util.module_from_spec(PIPELINE_SPEC)
PIPELINE_SPEC.loader.exec_module(PIPELINE)


class ProductOciSourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = read_json(ROOT / "platform/oci/product-images.json")
        self.workloads = read_json(ROOT / "platform/kubernetes/workload-policy.json")
        self.admission = read_json(
            ROOT / "platform/kubernetes/image-admission-policy.json"
        )

    def test_manifest_covers_all_six_workloads_and_real_launchers(self) -> None:
        validate_product_image_manifest(ROOT, self.manifest, self.workloads)
        self.assertEqual(
            [service["name"] for service in self.workloads["services"]],
            [image["name"] for image in self.manifest["images"]],
        )
        self.assertEqual(6, len(self.manifest["images"]))
        java_classes = {
            image["name"]: image["mainClasses"]
            for image in self.manifest["images"] if image["kind"] == "java-install-dist"
        }
        self.assertEqual(2, len(java_classes["edge-gateway"]))
        self.assertEqual([
            "com.elmpay.scheduler.WorkerSchedulerApplication",
            "com.elmpay.scheduler.data.PartitionMaintenanceApplication",
            "com.elmpay.scheduler.data.ArchiveReceiptVerifierApplication",
            "com.elmpay.scheduler.data.ArchiveDetachAuthorizationVerifierApplication",
            "com.elmpay.scheduler.data.ArchivePartitionDetacherApplication",
        ], java_classes["worker-scheduler"])
        self.assertEqual(1, len(java_classes["risk-engine"]))
        self.assertEqual(1, len(java_classes["webhook-processor"]))
        launcher = (ROOT / "platform/oci/java-main").read_text(encoding="utf-8")
        self.assertEqual(
            OCI.CANONICAL_JAVA_LAUNCHER_DIGEST,
            hashlib.sha256(launcher.encode("utf-8")).hexdigest(),
        )
        self.assertIn("ALLOWED_MAIN_CLASSES_FILE", launcher)
        self.assertNotIn("ELMPAY_JAVA_ALLOWED_MAIN_CLASSES", launcher)
        self.assertNotIn("com.elmpay.*", launcher)
        images = {
            service["name"]: f"registry.example/{service['name']}@sha256:" + "a" * 64
            for service in self.workloads["services"]
        }
        rendered = render_workloads(self.workloads, images)
        migration = next(
            item for item in rendered["items"]
            if item["kind"] == "Job" and item["metadata"]["name"] == "database-migrator"
        )
        container = migration["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(["/opt/elmpay/bin/java-main"], container["command"])
        self.assertEqual(
            ["com.elmpay.gateway.DatabaseMigrationApplication"], container["args"]
        )

    def test_unresolved_or_placeholder_base_image_blocks(self) -> None:
        with self.assertRaises(ValidationError):
            resolve_base_images(self.manifest, {})
        environment = {
            value["inputEnvironment"]: "registry.example/base@sha256:" + "0" * 64
            for value in self.manifest["baseImages"]
        }
        with self.assertRaises(ValidationError):
            resolve_base_images(self.manifest, environment)

    def test_missing_webhook_application_packaging_is_rejected(self) -> None:
        generated = ROOT / "build.gradle.kts"
        original = generated.read_text(encoding="utf-8")
        self.assertIn('project(":services:webhook-ingress")', original)
        mutated = deepcopy(self.manifest)
        webhook = next(image for image in mutated["images"] if image["name"] == "webhook-processor")
        webhook["mainClasses"] = ["com.elmpay.webhook.ingress.MissingApplication"]
        with self.assertRaises(ValidationError):
            validate_product_image_manifest(ROOT, mutated, self.workloads)

    def test_containerfile_instruction_or_context_expansion_is_rejected(self) -> None:
        relative = Path("platform/oci/checkout-web.Containerfile")
        canonical = (ROOT / relative).read_text(encoding="utf-8")
        declared = next(
            image["containerfileContractDigest"] for image in self.manifest["images"]
            if image["name"] == "checkout-web"
        )
        OCI._validate_containerfile_contract(relative, canonical, declared)
        for injected in (
            "\nCOPY . /tmp/undeclared\n",
            "\nADD https://example.invalid/payload /tmp/payload\n",
            "\nRUN --mount=type=secret,id=token true\n",
            "\nFROM scratch AS unreviewed\n",
            '\nENTRYPOINT ["/bin/false"]\n',
        ):
            with self.subTest(injected=injected.strip()), self.assertRaises(ValidationError):
                OCI._validate_containerfile_contract(relative, canonical + injected, declared)

    def test_java_policy_directory_is_read_only_and_traversable(self) -> None:
        containerfile = (ROOT / "platform/oci/java-runtime.Containerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "chmod 0555 /opt/elmpay/bin /opt/elmpay/etc",
            containerfile,
        )
        self.assertNotIn("chmod 0444 /opt/elmpay/bin", containerfile)
        self.assertNotIn("chmod 0444 /opt/elmpay/etc", containerfile)

    def test_dockerignore_is_exact_digest_bound(self) -> None:
        mutated = deepcopy(self.manifest)
        mutated["contextPolicy"]["dockerignoreDigest"] = "0" * 64
        with self.assertRaises(ValidationError):
            validate_product_image_manifest(ROOT, mutated, self.workloads)


class ProductOciReleaseIndexTest(unittest.TestCase):
    def setUp(self) -> None:
        self.product = read_json(ROOT / "platform/oci/product-images.json")
        self.admission = read_json(
            ROOT / "platform/kubernetes/image-admission-policy.json"
        )
        self.images = {
            image["name"]: f"ghcr.io/zpcaiai/elmpay/{image['name']}@sha256:"
            + f"{index + 1:064x}"
            for index, image in enumerate(self.product["images"])
        }
        self.index = {
            "schemaVersion": 1,
            "productImageManifestDigest": product_image_manifest_digest(self.product),
            "admissionPolicyDigest": admission_policy_digest(self.admission),
            "sourceCommit": "c" * 40,
            "artifactDigest": "a" * 64,
            "targetPlatform": "linux/amd64",
            "evidenceToolchain": {
                "build": {
                    "name": "docker-buildx", "version": "v0.30.1",
                    "executableDigest": "7" * 64,
                },
                "scan": {
                    "name": "trivy", "version": "v0.67.2",
                    "executableDigest": "8" * 64,
                },
                "scanDatabaseDigest": "9" * 64,
                "publish": {
                    "name": "skopeo", "version": "v1.20.0",
                    "executableDigest": "f" * 64,
                },
                "sign": {
                    "name": "cosign", "version": "v3.0.6",
                    "executableDigest": "a" * 64,
                },
            },
            "buildIndexDigest": "b" * 64,
            "scanIndexDigest": "c" * 64,
            "publicationIndexDigest": "d" * 64,
            "signatureIndexDigest": "e" * 64,
            "images": [{
                "name": name,
                "reference": reference,
                "imageDigest": reference.rsplit("@sha256:", 1)[1],
                "baseImage": "registry.example/base@sha256:" + "b" * 64,
                "artifactDigest": "1" * 64,
                "containerfileDigest": "2" * 64,
                "runtimeInspectionDigest": "9" * 64,
                "sbomDigest": "3" * 64,
                "sbomAttestedPredicateDigest": "7" * 64,
                "provenanceDigest": "4" * 64,
                "provenanceAttestedPredicateDigest": "8" * 64,
                "scanReportDigest": "5" * 64,
                "signatureBundleDigest": "6" * 64,
                "status": "SIGNED_SCANNED_VERIFIED",
            } for name, reference in self.images.items()],
        }
        self.release = {
            "commitSha": "c" * 40,
            "artifactDigest": "a" * 64,
            "productImageManifestDigest": self.index["productImageManifestDigest"],
            "imageAdmissionPolicyDigest": self.index["admissionPolicyDigest"],
            "productImageIndexDigest": sha256_json(self.index),
            "images": self.images,
        }

    def test_exact_final_index_is_release_bound(self) -> None:
        validate_product_release_index(
            self.product, self.admission, self.index, self.release
        )

    def test_scan_signature_or_image_drift_blocks(self) -> None:
        for field, value in (
            ("scanReportDigest", "0" * 64),
            ("signatureBundleDigest", "0" * 64),
            ("reference", "ghcr.io/zpcaiai/elmpay/other@sha256:" + "1" * 64),
        ):
            index = deepcopy(self.index)
            index["images"][0][field] = value
            release = {**self.release, "productImageIndexDigest": sha256_json(index)}
            with self.assertRaises(ValidationError):
                validate_product_release_index(
                    self.product, self.admission, index, release
                )

    def test_unpinned_evidence_tool_or_index_blocks(self) -> None:
        for mutator in (
            lambda index: index["evidenceToolchain"]["sign"].update(
                {"executableDigest": "0" * 64}
            ),
            lambda index: index.update({"scanIndexDigest": "0" * 64}),
        ):
            index = deepcopy(self.index)
            mutator(index)
            release = {**self.release, "productImageIndexDigest": sha256_json(index)}
            with self.assertRaises(ValidationError):
                validate_product_release_index(
                    self.product, self.admission, index, release
                )


class ProductOciEvidenceDocumentTest(unittest.TestCase):
    @staticmethod
    def _layer(entries: list[tuple[str, bytes, int]]) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, content, mode in entries:
                info = tarfile.TarInfo(name)
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return output.getvalue()

    def test_merged_rootfs_whiteout_removes_required_runtime_path(self) -> None:
        base = self._layer([("usr/bin/java", b"runtime", 0o755)])
        whiteout = self._layer([("usr/bin/.wh.java", b"", 0o000)])
        requirements = {
            "executables": ["/usr/bin/java"], "files": [], "directories": [],
            "atLeastOne": [],
        }
        with self.assertRaises(ValidationError):
            PIPELINE._merged_rootfs_inspection(
                [(hashlib.sha256(base).hexdigest(), base),
                 (hashlib.sha256(whiteout).hexdigest(), whiteout)],
                requirements,
            )

    def test_durable_journal_corruption_and_truncation_are_rejected(self) -> None:
        expected = {"schemaVersion": 1, "name": "edge-gateway"}
        valid = {**expected, "publicationAction": "COPIED_SCANNED_OCI_ARCHIVE"}
        PIPELINE._validate_durable_publication_receipt(valid, expected)
        for corrupted in (
            {**valid, "name": "other"},
            {**valid, "publicationAction": "RESUMED_FROM_DURABLE_RECEIPT"},
        ):
            with self.assertRaises(ValidationError):
                PIPELINE._validate_durable_publication_receipt(corrupted, expected)
        for encoded in (b'{"schemaVersion":1', b'{"a":1,"a":2}'):
            with self.assertRaises(ValidationError):
                PIPELINE._strict_json_bytes(encoded, "publication journal")

    def test_publication_snapshot_tamper_is_digest_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.tar"
            snapshot = root / "snapshot.tar"
            source.write_bytes(b"exact scanned archive")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            PIPELINE._snapshot_regular_file(source, snapshot, digest)
            snapshot.chmod(0o600)
            snapshot.write_bytes(b"tampered")
            with self.assertRaises(ValidationError):
                PIPELINE._bound_evidence_file(
                    root, Path("snapshot.tar"), "publication snapshot", digest
                )

    def test_exact_build_context_snapshot_rejects_tamper_and_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "declared.txt"
            source.write_bytes(b"declared build input")
            expected = {Path("declared.txt"): {
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "size": source.stat().st_size,
                "mode": source.stat().st_mode & 0o777,
            }}
            PIPELINE._validate_build_context_snapshot(root, expected)
            source.write_bytes(b"tampered build input")
            with self.assertRaises(ValidationError):
                PIPELINE._validate_build_context_snapshot(root, expected)
            source.write_bytes(b"declared build input")
            (root / "undeclared.txt").write_bytes(b"must never enter image context")
            with self.assertRaises(ValidationError):
                PIPELINE._validate_build_context_snapshot(root, expected)

    def test_external_tool_stdout_overflow_is_killed_fail_closed(self) -> None:
        command = [
            sys.executable, "-c",
            "import os; os.write(1, b'x' * (4 * 1024 * 1024 + 65536))",
        ]
        with self.assertRaises(ValidationError):
            PIPELINE._run(command, stdout=subprocess.PIPE, timeout=30)

    def test_external_tool_timeout_and_orphaned_capture_child_are_killed(self) -> None:
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            PIPELINE._run(
                [sys.executable, "-c", "import time; time.sleep(30)"], timeout=1
            )
        self.assertLess(time.monotonic() - started, 5)

        parent = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])"
        )
        started = time.monotonic()
        completed = PIPELINE._run([sys.executable, "-c", parent], timeout=5)
        self.assertEqual(0, completed.returncode)
        self.assertLess(time.monotonic() - started, 5)

    def test_external_tool_process_group_permission_error_fails_closed(self) -> None:
        with mock.patch.object(
            PIPELINE.os,
            "killpg",
            side_effect=PermissionError(1, "operation not permitted"),
        ):
            with self.assertRaisesRegex(
                ValidationError, "process group termination was denied"
            ):
                PIPELINE._run(
                    [sys.executable, "-c", "raise SystemExit(0)"], timeout=5
                )

    def test_partial_publication_resume_recopies_only_a_missing_exact_tag(self) -> None:
        expected = "a" * 64
        self.assertEqual(
            (True, "RECOPIED_MISSING_TAG_FROM_EXACT_SNAPSHOT"),
            PIPELINE._publication_resume_decision(True, None, expected),
        )
        self.assertEqual(
            (False, "RESUMED_FROM_DURABLE_RECEIPT"),
            PIPELINE._publication_resume_decision(True, expected, expected),
        )
        with self.assertRaises(ValidationError):
            PIPELINE._publication_resume_decision(True, "b" * 64, expected)

    def test_full_image_sbom_requires_packages_and_exact_subject(self) -> None:
        digest = "a" * 64
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {
                "type": "container",
                "bom-ref": f"pkg:oci/edge-gateway@sha256:{digest}",
                "name": "edge-gateway",
                "version": f"sha256:{digest}",
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": [
                    {"name": "elmpay:coverage", "value": "full-image-package-inventory"},
                    {"name": "elmpay:scanner-output-digest", "value": "b" * 64},
                    {"name": "elmpay:scanner-database-digest", "value": "c" * 64},
                    {"name": "elmpay:base-image", "value": "registry.example/base@sha256:" + "d" * 64},
                ],
            }},
            "components": [{
                "type": "library", "bom-ref": "pkg:deb/example@1",
                "name": "example", "purl": "pkg:deb/example@1",
            }],
        }
        PIPELINE._validate_full_image_sbom(
            document, "edge-gateway", digest,
            "registry.example/base@sha256:" + "d" * 64, "test SBOM"
        )
        file_only = deepcopy(document)
        file_only["components"][0].pop("purl")
        with self.assertRaises(ValidationError):
            PIPELINE._validate_full_image_sbom(
                file_only, "edge-gateway", digest,
                "registry.example/base@sha256:" + "d" * 64, "test SBOM"
            )
        wrong_subject = deepcopy(document)
        wrong_subject["metadata"]["component"]["hashes"][0]["content"] = "d" * 64
        with self.assertRaises(ValidationError):
            PIPELINE._validate_full_image_sbom(
                wrong_subject, "edge-gateway", digest,
                "registry.example/base@sha256:" + "d" * 64, "test SBOM"
            )

    def test_product_manifest_requires_digest_pinned_cosign_input(self) -> None:
        manifest = read_json(ROOT / "platform/oci/product-images.json")
        signature_tool = manifest["evidence"]["signatureTool"]
        self.assertEqual("ELMPAY_COSIGN_SHA256", signature_tool["executableDigestInputEnvironment"])
        source = (ROOT / "scripts/product-image-pipeline.py").read_text(encoding="utf-8")
        self.assertIn("_verified_tool(\n        \"cosign\"", source)
        self.assertIn("_validate_signature_index", source)
        self.assertIn("_reverify_registry_signatures(", source)
        self.assertIn("scan-sources", source)

if __name__ == "__main__":
    unittest.main()
