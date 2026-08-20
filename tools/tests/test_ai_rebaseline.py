"""Focused tests for the import-safe ``.ai/rebaseline.py`` operator CLI."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


REAL_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "elmpay_ai_rebaseline", REAL_ROOT / ".ai" / "rebaseline.py"
)
rebaseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rebaseline)


class RebaselineFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ai-rebaseline-test-")
        self.root = Path(self.temporary.name).resolve()
        self.order = ["B00", "B01", "B127"]
        self.write_json(
            ".payment-platform/skill-package/manifest.json",
            {"batches": [{"id": batch, "depends_on": []} for batch in self.order]},
        )
        self.write_json(
            "governance/project-config.json",
            {
                "evidence": {
                    "executor": "implementation-agent",
                    "reviewer": "Independent Human",
                    "environment": "test",
                }
            },
        )
        for batch in self.order:
            self.legacy_batch(batch)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def write_json(self, relative: str, payload) -> Path:
        return self.write(relative, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    def legacy_commands(self, batch: str) -> list[dict]:
        return [
            {
                "purpose": "environment fingerprint",
                "expect": 0,
                "command": "python3 scripts/environment.py",
                "save_to": "runtime/environment.txt",
            },
            {
                "purpose": "regression suite",
                "expect": 0,
                "command": (
                    f"python3 scripts/test-summary.py --out evidence/{batch}/test-results/summary.json "
                    f"--log evidence/{batch}/test-results/unittest.log"
                ),
                "save_to": "test-results/summary.log",
            },
            {
                "purpose": "negative controls",
                "expect": 0,
                "command": "python3 scripts/negative-controls.py",
                "save_to": "security/negative-controls.log",
            },
        ]

    def legacy_batch(self, batch: str) -> None:
        self.write_json(
            f"evidence/{batch}/commands.spec.json",
            {"batch": batch, "commands": self.legacy_commands(batch)},
        )
        self.write_json(
            f"evidence/{batch}/traceability.json",
            {
                "batch_id": batch,
                "requirements": [{"id": f"{batch}-R1"}],
                "code": [{"ref": "artifact.txt"}],
                "tests": [{"ref": "artifact.txt"}],
                "controls": [{"id": "NN-12"}],
                "evidence": [
                    {
                        "path": f"evidence/{batch}/test-results/summary.json",
                        "kind": "test-summary",
                    },
                    {
                        "path": f"evidence/{batch}/security/negative-controls.log",
                        "kind": "security",
                        "owner": "preserved",
                    },
                ],
            },
        )
        artifact = self.write(f"artifacts/{batch}.txt", f"artifact for {batch}\n")
        self.write_json(
            f"evidence/{batch}/artifacts.json",
            [artifact.relative_to(self.root).as_posix()],
        )
        self.write(
            f"_to_delete/stale-negative-control-logs/{batch}-negative-controls.log",
            f"legacy negative evidence for {batch}\n",
        )

    def binding(self, batches: list[str] | None = None, head: str = "a" * 40):
        return rebaseline.current_binding(self.root, batches or self.order, head=head)

    def migrate(self, batch: str = "B00", shards: int = 3, dry_run: bool = False):
        plan = rebaseline.prepare_batch_migration(self.root, batch, shards)
        result = rebaseline.apply_batch_migration(self.root, plan, dry_run=dry_run)
        return plan, result

    def materialize_negative_shards(self, batch: str, count: int) -> None:
        for index in range(1, count + 1):
            self.write(
                f"evidence/{batch}/security/negative-controls-{index}of{count}.log",
                f"shard={index}/{count} scenarios=2 failures=0\n",
            )

    def command_records(self, batch: str, count: int | None = None) -> None:
        commands = rebaseline.read_commands(self.root, batch)
        if count is not None:
            commands = commands[:count]
        spec_digest = rebaseline.sha256_file(
            self.root / f"evidence/{batch}/commands.spec.json"
        )
        records = []
        for index, entry in enumerate(commands):
            output = f"recorded output {index}\n".encode()
            saved = self.write(f"evidence/{batch}/{entry['save_to']}", output)
            output_digest = rebaseline.sha256_bytes(output)
            record = {
                "spec_index": index,
                "spec_sha256": spec_digest,
                "command": entry["command"],
                "expected_exit_code": entry.get("expect", 0),
                "exit_code": entry.get("expect", 0),
                "output_sha256": output_digest,
                "output_bytes": len(output),
                "saved_to": entry["save_to"],
                "saved_output_sha256": rebaseline.sha256_file(saved),
            }
            produced = []
            for relative in rebaseline._declared_command_outputs(batch, entry):
                target = self.root / relative
                payload = target.read_bytes()
                produced.append({
                    "path": relative,
                    "fresh": True,
                    "sha256": rebaseline.sha256_bytes(payload),
                    "bytes": len(payload),
                })
            if produced:
                record["produced_outputs"] = produced
            records.append(record)
        self.write(
            f"evidence/{batch}/commands.ndjson",
            "".join(json.dumps(record) + "\n" for record in records),
        )

    def clean_legacy_summary(self, batch: str) -> None:
        self.write_json(
            f"evidence/{batch}/test-results/summary.json",
            {"run": 2, "passed": 2, "failed": 0, "skipped_critical": 0},
        )


class StateBindingTests(RebaselineFixture):
    def test_state_is_bound_to_repo_head_manifest_range_and_every_spec(self):
        binding = self.binding()
        self.assertEqual(set(binding["command_spec_sha256"]), set(self.order))
        state = rebaseline.new_state(binding)
        rebaseline.save_state(self.root, state)
        self.assertEqual(rebaseline.load_state(self.root, binding, self.order), state)

        changed = self.root / "evidence/B01/commands.spec.json"
        changed.write_text(changed.read_text(encoding="utf-8") + " ", encoding="utf-8")
        live = self.binding()
        with self.assertRaises(rebaseline.StaleState):
            rebaseline.load_state(self.root, live, self.order)

    def test_changed_head_or_range_is_stale(self):
        state = rebaseline.new_state(self.binding())
        rebaseline.save_state(self.root, state)
        with self.assertRaises(rebaseline.StaleState):
            rebaseline.load_state(self.root, self.binding(head="b" * 40), self.order)
        subset = self.order[:2]
        with self.assertRaises(rebaseline.StaleState):
            rebaseline.load_state(self.root, self.binding(subset), subset)

    def test_atomic_state_write_replaces_and_cleans_its_temporary(self):
        target = rebaseline.state_path(self.root)
        rebaseline.atomic_write_json(target, {"old": True})
        with mock.patch.object(rebaseline.os, "replace", wraps=os.replace) as replaced:
            rebaseline.atomic_write_json(target, {"new": True})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"new": True})
        self.assertEqual(replaced.call_count, 1)
        self.assertEqual(list(target.parent.glob(f".{target.name}.*")), [])

    def test_failed_atomic_replace_leaves_previous_state_intact(self):
        target = rebaseline.state_path(self.root)
        rebaseline.atomic_write_json(target, {"old": True})
        with mock.patch.object(rebaseline.os, "replace", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                rebaseline.atomic_write_json(target, {"new": True})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"old": True})
        self.assertEqual(list(target.parent.glob(f".{target.name}.*")), [])

    def test_lock_contention_is_nonblocking(self):
        with rebaseline.state_lock(self.root):
            with self.assertRaises(rebaseline.LockBusy):
                with rebaseline.state_lock(self.root):
                    self.fail("second lock unexpectedly succeeded")


class RangeAndParserTests(RebaselineFixture):
    def test_padded_and_three_digit_ids_normalize_against_manifest(self):
        self.assertEqual(rebaseline.normalize_batch_id("B000", self.order), "B00")
        self.assertEqual(rebaseline.normalize_batch_id("B0127", self.order), "B127")
        self.assertEqual(
            rebaseline.resolve_range(self.root, "B000", "B0127"),
            self.order,
        )

    def test_reverse_unknown_and_missing_spec_ranges_fail(self):
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.resolve_range(self.root, "B127", "B00")
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.resolve_range(self.root, "B999", "B999")
        (self.root / "evidence/B01/commands.spec.json").unlink()
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.resolve_range(self.root, "B00", "B127")

    def test_parser_is_strict_and_validates_window_and_shards(self):
        parser = rebaseline.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["resume", "--unknown"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["resume", "--window-seconds", "10"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["resume", "--launch-window-seconds", "0"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["migrate-shards", "--shards", "1"])
        parsed = parser.parse_args(
            ["resume", "--from", "B000", "--to", "B0127", "--launch-window-seconds", "12.5", "--dry-run"]
        )
        self.assertEqual(parsed.launch_window_seconds, 12.5)
        self.assertTrue(parsed.dry_run)

    def test_status_and_reset_dry_run_do_not_destroy_state(self):
        state = rebaseline.new_state(self.binding())
        rebaseline.save_state(self.root, state)
        stdout = io.StringIO()
        with mock.patch.object(rebaseline, "git_head", return_value="a" * 40):
            with contextlib.redirect_stdout(stdout):
                code = rebaseline.main(["status", "--dry-run"], root=self.root)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["state"], "present")

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = rebaseline.main(["reset", "--dry-run"], root=self.root)
        self.assertEqual(code, 0)
        self.assertTrue(rebaseline.state_path(self.root).is_file())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rebaseline.main(["reset"], root=self.root), 0)
        self.assertFalse(rebaseline.state_path(self.root).exists())


class MigrationTests(RebaselineFixture):
    def test_migration_is_idempotent_and_recovers_missing_legacy_log(self):
        spec = self.root / "evidence/B00/commands.spec.json"
        before = spec.read_bytes()
        plan, result = self.migrate("B00", 3)
        self.assertNotEqual(spec.read_bytes(), before)
        self.assertIn("rewrite evidence/B00/commands.spec.json", result["actions"])
        recovered = self.root / "evidence/B00/security/negative-controls.log"
        backup = self.root / "_to_delete/stale-negative-control-logs/B00-negative-controls.log"
        self.assertEqual(recovered.read_bytes(), backup.read_bytes())
        self.assertTrue(backup.is_file(), "recovery must copy, never move")
        first = spec.read_bytes()

        second_plan, second = self.migrate("B00", 3)
        self.assertFalse(second_plan["spec"]["changed"])
        self.assertEqual(second["actions"], ["already canonical"])
        self.assertEqual(spec.read_bytes(), first)
        self.assertEqual(len(plan["spec"]["outputs"]["negative_logs"]), 3)

    def test_dry_run_changes_neither_spec_nor_recovery_target(self):
        spec = self.root / "evidence/B00/commands.spec.json"
        before = spec.read_bytes()
        _, result = self.migrate("B00", 4, dry_run=True)
        self.assertEqual(spec.read_bytes(), before)
        self.assertFalse((self.root / "evidence/B00/security/negative-controls.log").exists())
        self.assertTrue(result["dry_run"])

    def test_malformed_partial_shards_are_rejected_without_a_write(self):
        plan, _ = self.migrate("B00", 3)
        spec = self.root / "evidence/B00/commands.spec.json"
        payload = json.loads(spec.read_text(encoding="utf-8"))
        payload["commands"] = [
            command
            for command in payload["commands"]
            if "negative-controls.py --shard 2/3" not in command["command"]
        ]
        self.write_json("evidence/B00/commands.spec.json", payload)
        malformed = spec.read_bytes()
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.prepare_batch_migration(self.root, "B00", 3)
        self.assertEqual(spec.read_bytes(), malformed)
        self.assertTrue(plan["spec"]["changed"])

    def test_mismatched_batch_identities_are_rejected_before_migration(self):
        spec = self.root / "evidence/B00/commands.spec.json"
        payload = json.loads(spec.read_text(encoding="utf-8"))
        payload["batch"] = "B01"
        self.write_json("evidence/B00/commands.spec.json", payload)
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.prepare_batch_migration(self.root, "B00", 3)

        payload["batch"] = "B00"
        self.write_json("evidence/B00/commands.spec.json", payload)
        trace = self.root / "evidence/B00/traceability.json"
        trace_payload = json.loads(trace.read_text(encoding="utf-8"))
        trace_payload["batch_id"] = "B01"
        self.write_json("evidence/B00/traceability.json", trace_payload)
        before = trace.read_bytes()
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.prepare_batch_migration(self.root, "B00", 3)
        self.assertEqual(trace.read_bytes(), before)

    def test_mixed_denominators_incomplete_tests_and_partial_trace_are_rejected(self):
        self.migrate("B00", 3)
        spec = self.root / "evidence/B00/commands.spec.json"
        canonical = json.loads(spec.read_text(encoding="utf-8"))

        mixed = json.loads(json.dumps(canonical))
        for command in mixed["commands"]:
            command["command"] = command["command"].replace(
                "negative-controls.py --shard 2/3",
                "negative-controls.py --shard 2/4",
            )
        self.write_json("evidence/B00/commands.spec.json", mixed)
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.prepare_batch_migration(self.root, "B00", 3)

        incomplete = json.loads(json.dumps(canonical))
        incomplete["commands"] = [
            command for command in incomplete["commands"]
            if not (
                "scripts/test-summary.py" in command["command"]
                and "--shard 2/3" in command["command"]
            )
        ]
        self.write_json("evidence/B00/commands.spec.json", incomplete)
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.prepare_batch_migration(self.root, "B00", 3)

        self.write_json("evidence/B00/commands.spec.json", canonical)
        trace_path = self.root / "evidence/B00/traceability.json"
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        for entry in trace["evidence"]:
            if entry["path"].endswith("negative-controls.log"):
                entry["path"] = "evidence/B00/security/negative-controls-1of3.log"
        self.write_json("evidence/B00/traceability.json", trace)
        before = trace_path.read_bytes()
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.prepare_batch_migration(self.root, "B00", 3)
        self.assertEqual(trace_path.read_bytes(), before)

    def test_trace_finalization_waits_for_every_shard_and_is_idempotent(self):
        self.migrate("B00", 3)
        trace = self.root / "evidence/B00/traceability.json"
        before = trace.read_bytes()
        for index in (1, 2):
            self.write(
                f"evidence/B00/security/negative-controls-{index}of3.log",
                f"shard={index}/3 scenarios=2 failures=0\n",
            )
        with self.assertRaises(rebaseline.RebaselineError):
            rebaseline.finalize_traceability(self.root, "B00")
        self.assertEqual(trace.read_bytes(), before)

        self.write(
            "evidence/B00/security/negative-controls-3of3.log",
            "shard=3/3 scenarios=2 failures=0\n",
        )
        result = rebaseline.finalize_traceability(self.root, "B00")
        self.assertTrue(result["changed"])
        doc = json.loads(trace.read_text(encoding="utf-8"))
        negative = [entry for entry in doc["evidence"] if "negative-controls" in entry["path"]]
        self.assertEqual(
            [entry["path"] for entry in negative],
            [f"evidence/B00/security/negative-controls-{i}of3.log" for i in (1, 2, 3)],
        )
        self.assertTrue(all(entry["owner"] == "preserved" for entry in negative))
        finalized = trace.read_bytes()
        again = rebaseline.finalize_traceability(self.root, "B00")
        self.assertFalse(again["changed"])
        self.assertEqual(trace.read_bytes(), finalized)

    def test_new_batch_needs_no_dishonest_legacy_trace_placeholder(self):
        self.migrate("B127", 3)
        trace = self.root / "evidence/B127/traceability.json"
        doc = json.loads(trace.read_text(encoding="utf-8"))
        doc["evidence"] = [
            entry for entry in doc["evidence"] if "negative-controls" not in entry["path"]
        ]
        self.write_json("evidence/B127/traceability.json", doc)
        plan = rebaseline.prepare_batch_migration(self.root, "B127", 3)
        self.assertEqual(plan["trace"]["phase"], "staged-new-batch")
        self.materialize_negative_shards("B127", 3)
        ready_plan = rebaseline.prepare_batch_migration(self.root, "B127", 3)
        self.assertEqual(ready_plan["trace"]["phase"], "staged-new-batch")
        self.assertIsNone(ready_plan["trace"]["recovery"])
        self.assertNotIn(b"negative-controls", trace.read_bytes())
        result = rebaseline.finalize_traceability(self.root, "B127")
        self.assertEqual(result["phase"], "ready-to-finalize-new-batch")


class ResumeAndReviewTests(RebaselineFixture):
    def test_dry_run_uses_command_level_finish_ranges_without_writing_state(self):
        batches = ["B00"]
        with mock.patch.object(rebaseline, "git_head", return_value="a" * 40), \
                mock.patch.object(rebaseline, "live_validate", return_value=False):
            result = rebaseline.resume_range(
                self.root, batches, launch_window_seconds=10, dry_run=True
            )
        action = result["actions"][-1]
        self.assertIn("0:1", action["argv"])
        self.assertIn("--record-only", action["argv"])
        self.assertIn("scripts/finish-batch.py", action["argv"])
        self.assertNotIn("--append", action["argv"])
        self.assertFalse(rebaseline.state_path(self.root).exists())

        binding = self.binding(batches)
        state = rebaseline.new_state(binding)
        state["progress"]["command_index"] = 1
        rebaseline.save_state(self.root, state)
        with mock.patch.object(rebaseline, "git_head", return_value="a" * 40), \
                mock.patch.object(rebaseline, "live_validate", return_value=False):
            result = rebaseline.resume_range(
                self.root, batches, launch_window_seconds=10, dry_run=True
            )
        self.assertIn("--append", result["actions"][-1]["argv"])
        self.assertIn("1:2", result["actions"][-1]["argv"])

    def test_live_validator_is_the_only_skip_authority(self):
        review = self.root / "evidence/B00/review.json"
        with mock.patch.object(rebaseline, "git_head", return_value="a" * 40), \
                mock.patch.object(rebaseline, "live_validate", return_value=True) as validate, \
                mock.patch.object(rebaseline, "validate_review_attestation", return_value=review), \
                mock.patch.object(rebaseline, "verify_precompletion", return_value={"commands": 3}):
            result = rebaseline.resume_range(
                self.root, ["B00"], launch_window_seconds=10, dry_run=True
            )
        self.assertEqual(result["status"], "all-done")
        self.assertEqual(result["actions"][0]["action"], "skip-live-valid")
        self.assertEqual(result["actions"][0]["review"], "evidence/B00/review.json")
        validate.assert_called_once_with(self.root, "B00")

    def test_live_valid_completion_without_review_is_still_review_blocked(self):
        with mock.patch.object(rebaseline, "git_head", return_value="a" * 40), \
                mock.patch.object(rebaseline, "live_validate", return_value=True):
            with self.assertRaises(rebaseline.ReviewBlocked):
                rebaseline.resume_range(
                    self.root, ["B00"], launch_window_seconds=10, dry_run=True
                )

    def test_interrupted_recording_reconciles_an_exact_transcript_prefix(self):
        batch = "B00"
        self.command_records(batch, count=1)
        state = rebaseline.new_state(self.binding([batch]))
        state["progress"]["command_started"] = True
        rebaseline.save_state(self.root, state)
        with mock.patch.object(rebaseline, "git_head", return_value="a" * 40), \
                mock.patch.object(rebaseline, "live_validate", return_value=False), \
                mock.patch.object(rebaseline.time, "monotonic", side_effect=[0, 0, 20]):
            result = rebaseline.resume_range(
                self.root, [batch], launch_window_seconds=10, dry_run=False
            )
        self.assertEqual(result["status"], "paused")
        self.assertEqual(result["actions"][0]["action"], "recover-interrupted-command")
        saved = json.loads(rebaseline.state_path(self.root).read_text(encoding="utf-8"))
        self.assertEqual(saved["progress"]["command_index"], 1)
        self.assertFalse(saved["progress"]["command_started"])

    def test_missing_review_blocks_without_touching_trace_or_completion(self):
        batch = "B00"
        self.clean_legacy_summary(batch)
        self.command_records(batch)
        binding = self.binding([batch])
        state = rebaseline.new_state(binding)
        state["progress"]["command_index"] = len(rebaseline.read_commands(self.root, batch))
        rebaseline.save_state(self.root, state)
        trace = self.root / f"evidence/{batch}/traceability.json"
        before = trace.read_bytes()
        with mock.patch.object(rebaseline, "git_head", return_value="a" * 40), \
                mock.patch.object(rebaseline, "live_validate", return_value=False):
            with self.assertRaises(rebaseline.ReviewBlocked):
                rebaseline.resume_range(
                    self.root, [batch], launch_window_seconds=10, dry_run=False
                )
        self.assertEqual(trace.read_bytes(), before)
        self.assertFalse((self.root / f"evidence/completion/{batch}.json").exists())
        saved = json.loads(rebaseline.state_path(self.root).read_text(encoding="utf-8"))
        self.assertEqual(saved["progress"]["command_index"], len(self.legacy_commands(batch)))

    def test_untracked_review_and_finish_failure_leave_trace_unchanged(self):
        batch = "B00"
        self.migrate(batch, 3)
        self.materialize_negative_shards(batch, 3)
        binding = self.binding([batch])
        state = rebaseline.new_state(binding)
        state["progress"]["command_index"] = len(rebaseline.read_commands(self.root, batch))
        rebaseline.save_state(self.root, state)
        trace = self.root / f"evidence/{batch}/traceability.json"
        before = trace.read_bytes()
        trace_plan = rebaseline.plan_traceability_finalization(self.root, batch)
        review = {
            "schema_version": "1.0.0",
            "batch_id": batch,
            "decision": "approved",
            "reviewer": "Independent Human",
            "executor": "implementation-agent",
            "reviewed_at": "2026-08-20T12:00:00+08:00",
            "scope": "independent review of current evidence inputs",
            "notes": "approved after reviewing the exact bound files",
            "bindings": rebaseline.expected_review_binding(
                self.root,
                batch,
                binding,
                traceability_sha256=trace_plan["sha256"],
            ),
        }
        review_path = self.write_json(f"evidence/{batch}/review.json", review)
        with mock.patch.object(rebaseline, "review_is_git_tracked", return_value=True):
            self.assertEqual(
                rebaseline.validate_review_attestation(
                    self.root,
                    batch,
                    binding,
                    traceability_sha256=trace_plan["sha256"],
                ),
                review_path,
            )
        self.assertEqual(trace.read_bytes(), before)
        with mock.patch.object(rebaseline, "git_head", return_value="a" * 40), \
                mock.patch.object(rebaseline, "live_validate", return_value=False), \
                mock.patch.object(rebaseline, "verify_precompletion", return_value={"commands": 9}):
            with self.assertRaises(rebaseline.ReviewBlocked):
                rebaseline.resume_range(
                    self.root, [batch], launch_window_seconds=10, dry_run=False
                )
        self.assertEqual(trace.read_bytes(), before)

        with mock.patch.object(rebaseline, "git_head", return_value="a" * 40), \
                mock.patch.object(rebaseline, "live_validate", return_value=False), \
                mock.patch.object(rebaseline, "verify_precompletion", return_value={"commands": 9}), \
                mock.patch.object(rebaseline, "validate_review_attestation", return_value=review_path), \
                mock.patch.object(
                    rebaseline,
                    "_run_finish",
                    side_effect=rebaseline.RebaselineError("injected finish refusal"),
                ):
            with self.assertRaises(rebaseline.RebaselineError):
                rebaseline.resume_range(
                    self.root, [batch], launch_window_seconds=10, dry_run=False
                )
        self.assertEqual(trace.read_bytes(), before)
        self.assertFalse((self.root / f"evidence/completion/{batch}.json").exists())

    def test_attestation_binds_exact_current_inputs(self):
        batch = "B00"
        binding = self.binding([batch])
        expected = rebaseline.expected_review_binding(self.root, batch, binding)
        self.assertEqual(expected["traceability_sha256"], rebaseline.sha256_file(
            self.root / f"evidence/{batch}/traceability.json"
        ))
        review = {
            "schema_version": "1.0.0",
            "batch_id": batch,
            "decision": "approved",
            "reviewer": "Independent Human",
            "executor": "implementation-agent",
            "reviewed_at": "2026-08-20T12:00:00+08:00",
            "scope": "independent review of current evidence inputs",
            "notes": "approved after reviewing the exact bound files",
            "bindings": expected,
        }
        path = self.write_json(f"evidence/{batch}/review.json", review)
        with self.assertRaises(rebaseline.ReviewBlocked):
            rebaseline.validate_review_attestation(self.root, batch, binding)
        with mock.patch.object(rebaseline, "review_is_git_tracked", return_value=True):
            self.assertEqual(
                rebaseline.validate_review_attestation(self.root, batch, binding), path
            )
        self.write(f"artifacts/{batch}.txt", "changed after review\n")
        with mock.patch.object(rebaseline, "review_is_git_tracked", return_value=True):
            with self.assertRaises(rebaseline.ReviewBlocked):
                rebaseline.validate_review_attestation(self.root, batch, binding)

    def test_symlink_escaped_review_is_review_blocked_without_a_traceback(self):
        batch = "B00"
        binding = self.binding([batch])
        outside = tempfile.NamedTemporaryFile(prefix="escaped-review-", delete=False)
        outside.close()
        self.addCleanup(lambda: Path(outside.name).unlink(missing_ok=True))
        Path(outside.name).write_text("{}\n", encoding="utf-8")
        path = self.root / f"evidence/{batch}/review.json"
        path.symlink_to(outside.name)
        with self.assertRaises(rebaseline.ReviewBlocked):
            rebaseline.validate_review_attestation(self.root, batch, binding)


if __name__ == "__main__":
    unittest.main()
