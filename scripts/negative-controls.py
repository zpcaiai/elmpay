#!/usr/bin/env python3
"""Runtime proof that the governance gate fails closed.

The unit tests exercise individual validators. This script goes one step
further: it corrupts copies of the whole governance surface and asserts the
*shipped CLI's* exit code, because "the validator returned a Problem" and "the
build fails" are different claims.

Two execution modes, on purpose:

* every scenario runs through ``cli.main(argv)`` in this process — the same
  function ``python3 -m tools.paygov.cli`` calls, returning the same exit code;
* a small fixed sample additionally runs as a real subprocess, covering all
  three exit classes (0 pass, 2 governance problems, 3 could not complete), so
  the ``main() -> sys.exit()`` wiring and module entry point stay proven.

The split exists because the honest proof is per-scenario and there are now
160+ of them: paying ~0.8s of interpreter start-up each turned this script into
the single most expensive step of every batch re-baseline. What is *not*
traded away is which rule fired — every scenario still asserts its expected
rule code, not merely a non-zero exit.

``--shard I/N`` runs the I-th of N disjoint slices of the same scenario set.
The scenario count grows by roughly 30 per batch and the execution environment
caps a single step at 45 seconds, so past a certain programme size no amount of
tuning keeps one invocation inside the window. Sharding changes how the proof
is *recorded*, not how much of it runs: the slices partition the set exactly,
each rebuilds and re-checks its own clean baseline, and B06's evidence
validator refuses a batch whose command spec declares an incomplete 1..N set,
so a dropped shard fails the build instead of quietly shrinking the proof.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
WORKERS = max(2, min(8, (os.cpu_count() or 2)))
# RAM-backed scratch when available: the fixtures are transient and the mount
# holding the repository is both slow and quota-limited.
SCRATCH = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None

# Discovered, not enumerated — same reasoning as tools/tests/support.py: editing
# this list in every batch invalidated the artefact hash of the batch that owns
# this file and forced a full programme re-baseline each time.
def _discovered() -> tuple:
    found: list[str] = []
    for pattern in ("governance/*.json", "contracts/**/*.json", "contracts/**/*.sql",
                    "libs/**/*.py"):
        for path in sorted(ROOT.glob(pattern)):
            if path.is_file():
                found.append(path.relative_to(ROOT).as_posix())
    return tuple(dict.fromkeys(found))


COPIED = _discovered() + (
    "gradlew",
    "gradlew.bat",
    "gradle/libs.versions.toml",
    "gradle/wrapper/gradle-wrapper.jar",
    "gradle/wrapper/gradle-wrapper.properties",
    "settings.gradle.kts",
    "build.gradle.kts",
    ".tool-versions",
    "platform/toolchain/versions.env",
    "platform/dev/compose.yaml",
    "platform/dev/.env.example",
    "platform/dev/README.md",
    "platform/dev/simulators/wechat/Dockerfile",
    "platform/dev/simulators/alipay/Dockerfile",
    "platform/dev/simulators/stripe/Dockerfile",
    "platform/dev/simulators/paypal/Dockerfile",
    "platform/dev/simulators/apple-pay/Dockerfile",
    ".github/workflows/ci.yml",
    "scripts/stage-signing-artifacts.sh",
    "scripts/sign-artifacts.sh",
    "docs/charter/PROGRAM_CHARTER.md",
    "docs/charter/RISK_ACCEPTANCE_POLICY.md",
    "docs/charter/DELIVERY_MODEL.md",
    "docs/requirements/REQUIREMENTS_BASELINE.md",
    "docs/requirements/SERVICE_BOUNDARIES.md",
    ".payment-platform/skill-package/policies/non-negotiables.md",
    ".payment-platform/skill-package/security/THREAT_MODEL.md",
    ".payment-platform/skill-package/manifest.json",
    ".payment-platform/skill-package/compliance/controls-matrix.csv",
)

# Whole trees, discovered rather than enumerated. A hand-written list of doc
# directories meant every batch that added one had to edit this file — and this
# file is an artefact of B00, so that edit invalidated B00 and cascaded a full
# programme re-baseline. Same reasoning as the governance/contracts globs above.
COPIED_DIRS = ("docs", "contracts", "evidence")

from tools.negative import EXIT_OK, EXIT_PROBLEMS, EXIT_ERROR  # noqa: E402
# Scenarios are discovered from tools/negative/, one module per batch. Inline
# scenarios made this file — an artefact of B00 — change in every batch, which
# invalidated B00's evidence and cascaded a full programme re-baseline.
from tools.negative import load as load_scenarios  # noqa: E402

EXPECTED_CODES, SCENARIOS, TEXT_SCENARIOS = load_scenarios()


# Every rejection scenario must name the rule code it expects to fire.
# Asserting only on the process exit code is not a control: an unrelated
# breakage makes every scenario "pass" while proving nothing. An independent
# review observed exactly that happening on a drifted working tree.
def _snapshot() -> dict[str, bytes]:
    """Read every fixture input once.

    48 scenarios each need their own mutable copy; re-reading the evidence tree
    from the mount per scenario made this proof too slow to run on every batch.
    """
    blobs: dict[str, bytes] = {}
    for rel in COPIED:
        blobs[rel] = (ROOT / rel).read_bytes()
    for rel in COPIED_DIRS:
        for path in sorted((ROOT / rel).rglob("*")):
            if path.is_file():
                blobs[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    # The module validator requires real boundary content because empty
    # directories are not version-controlled. Carry one real, non-empty file
    # per declared module into the disposable repository; synthesising marker
    # files here would make the negative baseline prove a different tree.
    registry = json.loads(
        (ROOT / "governance" / "module-registry.json").read_text("utf-8"))
    for module in registry["modules"]:
        base = ROOT / module["path"]
        candidates = sorted(path for path in base.rglob("*")
                            if path.is_file() and path.stat().st_size > 0)
        if candidates:
            path = candidates[0]
            blobs[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    for path in sorted((ROOT / "tools" / "tests").glob("*.py")):
        blobs[f"tools/tests/{path.name}"] = path.read_bytes()
    blobs["scripts/negative-controls.py"] = (ROOT / "scripts/negative-controls.py").read_bytes()

    completion = ROOT / "evidence" / "completion"
    if completion.is_dir():
        for path in sorted(completion.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            referenced = [a["path"] for a in data.get("artifacts", [])]
            declared = ROOT / "evidence" / path.stem / "artifacts.json"
            if declared.is_file():
                referenced += json.loads(declared.read_text(encoding="utf-8"))
            trace = ROOT / "evidence" / path.stem / "traceability.json"
            if trace.is_file():
                doc = json.loads(trace.read_text(encoding="utf-8"))
                referenced += [e.get("ref") for e in doc.get("code", []) + doc.get("tests", [])]
                referenced += [e.get("path") for e in doc.get("evidence", [])]
            for rel in [r for r in referenced if r]:
                source = ROOT / rel
                if source.is_file() and rel not in blobs:
                    blobs[rel] = source.read_bytes()
    return blobs


_SNAPSHOT = _snapshot()
_MODULE_PATHS = tuple(m["path"] for m in json.loads(
    (ROOT / "governance/module-registry.json").read_text("utf-8"))["modules"])
_SIMULATOR_PATHS = tuple(s["build_context"] for s in json.loads(
    (ROOT / "governance/dev-platform.json").read_text("utf-8"))["simulators"])


def build(tmp: Path) -> Path:
    root = tmp / "repo"
    (root / "tools" / "paygov").mkdir(parents=True)
    (root / "tools" / "tests").mkdir(parents=True)
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    for rel, blob in _SNAPSHOT.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(blob)
    (root / "gradlew").chmod(0o755)
    for path in _MODULE_PATHS + _SIMULATOR_PATHS:
        (root / path).mkdir(parents=True, exist_ok=True)
    return root


def patch(root: Path, rel: str, mutate) -> None:
    path = root / rel
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def gate_subprocess(root: Path, extra: list[str] | None = None) -> tuple[int, str]:
    """The real thing: a separate interpreter running the shipped entry point."""
    cmd = [sys.executable, "-m", "tools.paygov.cli", "verify-all", "--repo", str(root)]
    proc = subprocess.run(cmd + (extra or []), cwd=ROOT, capture_output=True, text=True)
    return proc.returncode, proc.stdout


def gate(root: Path, extra: list[str] | None = None) -> tuple[int, str]:
    """Same function ``main()`` calls, same exit code, no interpreter start-up.

    ``cli.run`` is the whole gate: it loads the validator registry, runs every
    validator against *root* and returns ``(exit_code, report)``. ``main()``
    only adds argument parsing and a ``print``. Calling it directly is
    thread-safe because validators are pure readers, and the catalogue caches
    are keyed by repository root — every scenario has its own.
    """
    from tools.paygov import cli as _cli

    budget = 30.0
    if extra and "--budget-seconds" in extra:
        budget = float(extra[extra.index("--budget-seconds") + 1])
    try:
        return _cli.run([], root, budget)
    except Exception as exc:  # noqa: BLE001 - a crash here must never read as "passed"
        return EXIT_ERROR, json.dumps({"ok": False, "problems": [
            {"code": "HARNESS_CRASHED", "where": str(root), "message": str(exc)}]})


def _codes(output: str) -> set[str]:
    try:
        return {p["code"] for p in json.loads(output).get("problems", [])}
    except Exception:
        return set()


_WORKER_ROOT: Path | None = None


def _worker_root(tmp: Path) -> Path:
    """One fixture per worker process, reused and restored between scenarios.

    Materialising ~1000 files for each of 240 scenarios dominated this script's
    wall-clock, and it also defeated the gate's own identity-keyed caches: a
    fresh tree means fresh mtimes, so every file looked new every time. Every
    scenario touches exactly one file, so a worker builds the tree once and puts
    that file back afterwards. The restore is byte-exact and runs in a
    ``finally``; if it ever fails, the tree is discarded rather than reused,
    because a half-restored fixture would silently change what the next
    scenario is testing.
    """
    global _WORKER_ROOT
    if _WORKER_ROOT is None:
        _WORKER_ROOT = build(tmp / f"worker-{os.getpid()}")
    return _WORKER_ROOT


@contextlib.contextmanager
def _restored(root: Path, rel: str):
    global _WORKER_ROOT
    path = root / rel
    original = path.read_bytes()
    try:
        yield path
    finally:
        try:
            path.write_bytes(original)
        except OSError:
            _WORKER_ROOT = None


def _json_case(tmp: Path, index: int, spec) -> tuple[str, int, int, set[str]]:
    name, rel, mutate, expected = spec
    root = _worker_root(tmp)
    with _restored(root, rel):
        patch(root, rel, mutate)
        code, output = gate(root)
    return name, code, expected, _codes(output)


def _text_case(tmp: Path, index: int, spec) -> tuple[str, int, int, set[str]]:
    name, rel, find, replace, expected = spec
    root = _worker_root(tmp)
    with _restored(root, rel) as path:
        path.write_text(path.read_text(encoding="utf-8").replace(find, replace), encoding="utf-8")
        code, output = gate(root)
    return name, code, expected, _codes(output)


def _json_case_at(item: tuple[str, int]) -> tuple[str, int, int, set[str]]:
    tmpdir, index = item
    return _json_case(Path(tmpdir), index, SCENARIOS[index])


def _text_case_at(item: tuple[str, int]) -> tuple[str, int, int, set[str]]:
    tmpdir, index = item
    return _text_case(Path(tmpdir), index, TEXT_SCENARIOS[index])


def _rejections(json_indices: list[int], text_indices: list[int]) -> int:
    return (sum(1 for i in json_indices if SCENARIOS[i][3] == EXIT_PROBLEMS)
            + sum(1 for i in text_indices if TEXT_SCENARIOS[i][4] == EXIT_PROBLEMS))


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prove that the payment-platform governance gate fails closed.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--shard",
        metavar="I/N",
        help="run the I-th of N disjoint scenario slices (1 <= I <= N)",
    )
    return parser


def _parse_shard(argv: list[str]) -> tuple[int, int]:
    """``--shard I/N`` -> (I, N), 1-based. Absent means the whole set."""
    parser = _argument_parser()
    raw = parser.parse_args(argv).shard
    if raw is None:
        return 1, 1

    parts = raw.split("/")
    if (len(parts) != 2
            or any(not part.isascii() or not part.isdigit() for part in parts)):
        parser.error(f"--shard {raw}: expected I/N with 1 <= I <= N")
    index, count = (int(part) for part in parts)
    if count < 1 or not 1 <= index <= count:
        parser.error(f"--shard {raw}: expected I/N with 1 <= I <= N")
    return index, count


def _slice(total: int, offset: int, index: int, count: int) -> list[int]:
    """Interleaved partition, so every shard carries a similar mix of costs.

    ``offset`` is the position of this list inside the concatenated scenario
    set, which keeps the two lists from both piling their first elements onto
    shard 1.
    """
    return [i for i in range(total) if (i + offset) % count == index - 1]


def main(argv: list[str] | None = None) -> int:
    shard, shards = _parse_shard(list(sys.argv[1:] if argv is None else argv))
    failures = []
    with tempfile.TemporaryDirectory(prefix="paygov-negative-", dir=SCRATCH) as tmpdir:
        tmp = Path(tmpdir)

        # The baseline must be clean BEFORE anything else runs. If it is not,
        # every rejection scenario would "pass" for the wrong reason, so this
        # aborts instead of reporting 45 meaningless successes.
        baseline_root = build(tmp / "baseline")
        code, output = gate(baseline_root)
        print(f"[baseline    ] shard={shard}/{shards} exit={code} expected={EXIT_OK}")
        if code != EXIT_OK:
            print(f"  baseline problems: {sorted(_codes(output))}")
            print("\nABORTED: the unmutated fixture does not pass the gate, so no rejection "
                  "scenario can prove anything.")
            return 1

        # Scenarios are independent; running them concurrently keeps the proof
        # affordable enough to execute on every batch. Results are printed in
        # declaration order so the log stays deterministic.
        # Processes, not threads: the gate is pure Python and CPU-bound, so
        # threads would serialise on the GIL. Only the *index* crosses the
        # boundary — the scenario mutations are lambdas, which fork inherits but
        # pickle cannot carry.
        with ProcessPoolExecutor(max_workers=WORKERS,
                                 mp_context=multiprocessing.get_context("fork")) as pool:
            json_indices = _slice(len(SCENARIOS), 0, shard, shards)
            text_indices = _slice(len(TEXT_SCENARIOS), len(SCENARIOS), shard, shards)
            json_results = list(pool.map(_json_case_at,
                                         [(str(tmp), i) for i in json_indices],
                                         chunksize=4))
            text_results = list(pool.map(_text_case_at,
                                         [(str(tmp), i) for i in text_indices],
                                         chunksize=2))

        for name, code, expected, codes in json_results + text_results:
            wanted = EXPECTED_CODES.get(name)
            exit_ok = code == expected
            code_ok = wanted is None or wanted in codes
            registered = wanted is not None or expected != EXIT_PROBLEMS
            status = "OK " if (exit_ok and code_ok and registered) else "FAIL"
            detail = f"exit={code} expected={expected}"
            if wanted:
                detail += f" code={wanted}{'' if code_ok else ' NOT-FIRED'}"
            print(f"[{status}] {name}: {detail}")
            if not exit_ok:
                failures.append(f"{name}: wrong exit code")
            if not code_ok:
                failures.append(f"{name}: expected rule {wanted} did not fire; got {sorted(codes)}")
            if not registered:
                failures.append(f"{name}: rejection scenario has no expected rule code registered")

        # The fixed tail — budget exhaustion and the three subprocess exit
        # classes — is per-run, not per-scenario, so it rides on the last shard
        # rather than being paid N times. The evidence validator requires the
        # full 1..N set, so "last shard" is not an escape hatch.
        if shard != shards:
            print()
            print(f"shard={shard}/{shards} "
                  f"scenarios={len(json_results) + len(text_results) + 1} "
                  f"rejection_scenarios={_rejections(json_indices, text_indices)} "
                  f"baseline_timeout_and_subprocess=1 failures={len(failures)}")
            for failure in failures:
                print(f"  UNCAUGHT: {failure}")
            return 0 if not failures else 1

        timeout_root = build(tmp / "timeout")
        code, out = gate(timeout_root, ["--budget-seconds", "0"])
        status = "OK " if code == EXIT_ERROR else "FAIL"
        print(f"[{status}] exhausted budget fails closed: exit={code} expected={EXIT_ERROR}")
        if code != EXIT_ERROR or '"ok": true' in out:
            failures.append("timeout did not fail closed")

        # A fixed sample re-runs through the shipped entry point in a real
        # subprocess. In-process calls prove which rule fired; these prove that
        # `python3 -m tools.paygov.cli` actually exits with that code — all
        # three classes, because a gate that finds everything and exits 0 is
        # not a gate.
        clean = build(tmp / "sample-clean")
        broken = build(tmp / "sample-broken")
        patch(broken, "governance/authorization.json",
              lambda d: d.__setitem__("default_decision", "allow"))
        for label, root, extra, expected in (
                ("subprocess pass", clean, None, EXIT_OK),
                ("subprocess governance problem", broken, None, EXIT_PROBLEMS),
                ("subprocess budget exhausted", clean, ["--budget-seconds", "0"], EXIT_ERROR)):
            code, _ = gate_subprocess(root, extra)
            print(f"[{'OK ' if code == expected else 'FAIL'}] {label}: exit={code} "
                  f"expected={expected}")
            if code != expected:
                failures.append(f"{label}: shipped CLI exited {code}, expected {expected}")

    print()
    print(f"shard={shard}/{shards} "
          f"scenarios={len(json_results) + len(text_results) + 5} "
          f"rejection_scenarios={_rejections(json_indices, text_indices)} "
          f"baseline_timeout_and_subprocess=5 failures={len(failures)}")
    for failure in failures:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
