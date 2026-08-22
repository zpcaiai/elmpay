from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REAL_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "archive_evidence_under_test", REAL_ROOT / "scripts" / "archive-evidence.py"
)
assert SPEC and SPEC.loader
archive_evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive_evidence)


class EvidenceArchiveSafety(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="archive-evidence-test-")
        self.root = Path(self.temporary.name)
        (self.root / "evidence").mkdir()
        self.root_patch = mock.patch.object(archive_evidence, "ROOT", self.root)
        self.root_patch.start()

    def tearDown(self) -> None:
        self.root_patch.stop()
        self.temporary.cleanup()

    def test_archive_manifest_exactly_matches_regular_members_and_is_deterministic(self):
        first = self.root / "evidence" / "B05" / "runtime" / "result.json"
        second = self.root / "evidence" / "completion" / "B05.json"
        first.parent.mkdir(parents=True)
        second.parent.mkdir(parents=True)
        first.write_text('{"ok":true}\n', encoding="utf-8")
        second.write_text('{"status":"blocked"}\n', encoding="utf-8")

        with mock.patch.object(archive_evidence, "git_head", return_value="a" * 40):
            first_out = archive_evidence.resolve_output("build/one/evidence.tar.gz")
            result = archive_evidence.create_archive(first_out, ["B05"], [], None)
            second_out = archive_evidence.resolve_output("build/two/evidence.tar.gz")
            second_result = archive_evidence.create_archive(second_out, ["B05"], [], None)

        self.assertEqual(result["bundle_sha256"], second_result["bundle_sha256"])
        with archive_evidence.tarfile.open(first_out, "r:gz") as bundle:
            members = bundle.getmembers()
            self.assertEqual(
                [member.name for member in members],
                ["MANIFEST.json", "evidence/B05/runtime/result.json",
                 "evidence/completion/B05.json"],
            )
            self.assertTrue(all(member.isfile() for member in members))
            manifest_stream = bundle.extractfile("MANIFEST.json")
            self.assertIsNotNone(manifest_stream)
            manifest = json.load(manifest_stream)
            self.assertEqual(manifest["file_count"], 2)
            self.assertEqual(manifest["commit_sha"], "a" * 40)
            for entry in manifest["files"]:
                stream = bundle.extractfile(entry["path"])
                self.assertIsNotNone(stream)
                content = stream.read()
                self.assertEqual(len(content), entry["bytes"])
                self.assertEqual(hashlib.sha256(content).hexdigest(), entry["sha256"])

    def test_rejects_file_and_directory_symlinks_anywhere_under_evidence(self):
        outside = self.root / "outside"
        outside.mkdir()
        target = outside / "target.txt"
        target.write_text("not evidence\n", encoding="utf-8")

        file_link = self.root / "evidence" / "linked.txt"
        file_link.symlink_to(target)
        with self.assertRaisesRegex(archive_evidence.ArchiveSafetyError, "symlink"):
            archive_evidence.evidence_files()
        file_link.unlink()

        directory_link = self.root / "evidence" / "linked-directory"
        directory_link.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(archive_evidence.ArchiveSafetyError, "symlink"):
            archive_evidence.evidence_files()

    def test_main_rejects_unsafe_evidence_before_running_batch_validation(self):
        outside = self.root / "outside.txt"
        outside.write_text("not evidence\n", encoding="utf-8")
        (self.root / "evidence" / "linked.txt").symlink_to(outside)
        argv = ["archive-evidence.py", "--out", "build/evidence.tar.gz", "--allow-empty"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(archive_evidence, "validate") as validate, \
             mock.patch("builtins.print"):
            self.assertEqual(archive_evidence.main(), 3)
            validate.assert_not_called()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_rejects_non_regular_evidence_nodes(self):
        fifo = self.root / "evidence" / "runtime.pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(archive_evidence.ArchiveSafetyError, "non-regular"):
            archive_evidence.evidence_files()

    def test_rejects_output_escape_symlink_and_non_regular_target(self):
        outside = self.root / "outside"
        outside.mkdir()
        with self.assertRaisesRegex(archive_evidence.ArchiveSafetyError, "below"):
            archive_evidence.resolve_output(str(outside / "bundle.tar.gz"))
        with self.assertRaisesRegex(archive_evidence.ArchiveSafetyError, "traversal"):
            archive_evidence.resolve_output("build/../outside.tar.gz")

        build = self.root / "build"
        target = outside / "existing.tar.gz"
        target.write_bytes(b"outside")
        (build / "linked.tar.gz").symlink_to(target)
        with self.assertRaisesRegex(archive_evidence.ArchiveSafetyError, "non-symlink"):
            archive_evidence.resolve_output("build/linked.tar.gz")

        (build / "directory.tar.gz").mkdir()
        with self.assertRaisesRegex(archive_evidence.ArchiveSafetyError, "regular file"):
            archive_evidence.resolve_output("build/directory.tar.gz")

    def test_rejects_symlinked_output_parent(self):
        outside = self.root / "outside"
        outside.mkdir()
        build = self.root / "build"
        build.mkdir()
        (build / "linked-parent").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(archive_evidence.ArchiveSafetyError):
            archive_evidence.resolve_output("build/linked-parent/bundle.tar.gz")

    def test_failed_verification_does_not_publish_or_leave_temporary_output(self):
        evidence = self.root / "evidence" / "B05" / "result.txt"
        evidence.parent.mkdir(parents=True)
        evidence.write_text("complete\n", encoding="utf-8")
        out = archive_evidence.resolve_output("build/evidence.tar.gz")
        out.write_bytes(b"previous-valid-output")

        with mock.patch.object(archive_evidence, "git_head", return_value="b" * 40), \
             mock.patch.object(archive_evidence, "_verify_archive",
                               side_effect=archive_evidence.ArchiveSafetyError("broken")):
            with self.assertRaisesRegex(archive_evidence.ArchiveSafetyError, "broken"):
                archive_evidence.create_archive(out, ["B05"], [], None)

        self.assertEqual(out.read_bytes(), b"previous-valid-output")
        self.assertEqual(list(out.parent.glob(".evidence-archive.*")), [])


if __name__ == "__main__":
    unittest.main()
