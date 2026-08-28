#!/usr/bin/env python3
"""Run the governance test suite and emit a machine-readable summary.

``skipped_critical`` is reported separately from ordinary skips: the batch gate
rejects any completion whose critical tests were skipped, so the number has to
be produced by the runner rather than asserted by a human.

The suite is executed one *test class* per process. That is not premature
optimisation: by B32 a single-process run took ~42 s against a 45 s ceiling on
one execution step in this environment, and a batch that cannot run its own
regression suite cannot produce evidence. Splitting per module was the first
fix; it stopped working once one module (``test_b06_orchestration``) grew to
37 s on its own, because module-level parallelism can never finish sooner than
its slowest module. Classes are the next natural unit — each one already
builds and tears down its own fixture, so nothing is shared to race on.
``--workers 1`` restores the sequential behaviour if a failure ever needs to be
reproduced without concurrency.

The unit list is derived from the same loader unittest discovery uses, and
``tools/tests/test_b00_repo_hygiene.py`` asserts that the union of the units
equals what plain discovery collects — so a class can never quietly drop out of
the regression evidence by being renamed or by failing to import.

``--shard I/N`` runs the I-th of N disjoint slices and writes a partial summary;
``--merge`` combines them into the summary the completion file consumes. The
suite grows by roughly 90 tests per batch, so parallelism alone eventually stops
being enough against a fixed per-step ceiling. What keeps sharding honest is the
merge: each partial records the units it ran, and the merge refuses unless their
union is exactly ``discovered_units()``. A dropped or duplicated shard fails the
build rather than producing a smaller summary that still looks green.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import re
import tempfile
import unittest
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Every governance test is treated as critical: none of them are optional, so a
# skip in any of them must block the batch rather than be silently tolerated.
CRITICAL_PREFIXES = ("test_",)
SHARD_LABEL = re.compile(r"^([1-9][0-9]*)/([1-9][0-9]*)$")


def discovered_modules() -> list[str]:
    """Every test module unittest discovery would collect."""
    return sorted(f"tools.tests.{path.stem}"
                  for path in (ROOT / "tools" / "tests").glob("test_*.py"))


def _classes(suite) -> list[str]:
    """``module.Class`` for every test case in a loaded suite, in order."""
    names: list[str] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            names += _classes(item)
        else:
            names.append(f"{type(item).__module__}.{type(item).__qualname__}")
    return list(dict.fromkeys(names))


def discovered_units() -> list[str]:
    """The work units: one ``module.Class`` per process.

    A module that fails to import must still be a unit under its own name, so
    the loader reproduces the failure inside the worker and it lands in the
    summary instead of vanishing from the run.

    That needs two guards, not one. ``loadTestsFromName`` raises for some
    breakages, but for an ImportError it does not raise at all: it substitutes
    ``unittest.loader._FailedTest``, whose module is ``unittest.loader`` rather
    than ours. Recording that name collapsed every broken module onto a single
    unit — and a worker asked to load ``unittest.loader._FailedTest`` builds an
    empty suite that passes, so four import failures reported as zero. Found by
    ``TestSummarySharding.test_shards_partition_the_unit_list``, which noticed
    the duplicate before anything noticed the silence.
    """
    import sys

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    loader = unittest.TestLoader()
    units: list[str] = []
    for module in discovered_modules():
        try:
            found = _classes(loader.loadTestsFromName(module))
        except Exception:
            found = []
        if any(name.startswith("unittest.") for name in found):
            found = []
        units += found or [module]
    return units


def _slice(units: list[str], index: int, count: int) -> list[str]:
    """Interleaved partition, so each shard gets a similar mix of costs."""
    return [unit for i, unit in enumerate(units) if i % count == index - 1]


def _parse_shard(raw: str | None) -> tuple[int, int]:
    if not raw:
        return 1, 1
    index, _, count = raw.partition("/")
    index, count = int(index), int(count)
    if count < 1 or not 1 <= index <= count:
        raise SystemExit(f"--shard {raw}: expected I/N with 1 <= I <= N")
    return index, count


def _atomic_json(path: Path, payload: dict) -> None:
    """Replace a summary only after the complete JSON is durable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def _merge_error(note: str, **details) -> int:
    print(json.dumps({"ok": False, "note": note, **details},
                     ensure_ascii=False, indent=2))
    return 1


def _part_problem(part: dict, path: str) -> str | None:
    required_counts = ("run", "passed", "failed", "skipped", "skipped_critical")
    for key in required_counts:
        value = part.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return f"{path}: {key} must be a non-negative integer"
    for key in ("units", "failures", "errors"):
        value = part.get(key)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            return f"{path}: {key} must be an array of strings"
    if part["failed"] != len(part["failures"]) + len(part["errors"]):
        return f"{path}: failed count does not match failures and errors"
    if part["passed"] != part["run"] - part["failed"] - part["skipped"]:
        return f"{path}: run/passed/failed/skipped counts do not reconcile"
    if part["skipped_critical"] > part["skipped"]:
        return f"{path}: skipped_critical exceeds skipped"
    return None


def _merge(paths: list[str], out: Path, log: str | None) -> int:
    """Combine one exact ``1..N`` partition, refusing stale or forged parts."""
    parts: list[dict] = []
    try:
        for path in paths:
            value = json.loads((ROOT / path).read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                return _merge_error("shard summary is not an object", path=path)
            problem = _part_problem(value, path)
            if problem:
                return _merge_error(problem)
            parts.append(value)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _merge_error("shard summary is unreadable", error=str(exc))

    labels: list[tuple[int, int]] = []
    for path, part in zip(paths, parts):
        label = part.get("shard")
        match = SHARD_LABEL.fullmatch(label) if isinstance(label, str) else None
        if match is None:
            return _merge_error("every shard summary must declare shard=I/N", path=path)
        index, total = int(match.group(1)), int(match.group(2))
        if index > total:
            return _merge_error("shard index is outside its partition", path=path,
                                shard=label)
        if part.get("shards") != total:
            return _merge_error("shard summary must declare shards=N", path=path,
                                expected=total, actual=part.get("shards"))
        labels.append((index, total))

    denominators = {total for _, total in labels}
    if len(denominators) != 1:
        return _merge_error("shard summaries mix partition sizes",
                            denominators=sorted(denominators))
    total = next(iter(denominators))
    indices = [index for index, _ in labels]
    duplicates = sorted({index for index in indices if indices.count(index) > 1})
    if duplicates:
        return _merge_error("shard summaries repeat indices", duplicated_shards=duplicates)
    if len(parts) != total:
        return _merge_error("wrong number of shard summaries", expected=total,
                            actual=len(parts))
    missing_indices = sorted(set(range(1, total + 1)) - set(indices))
    if missing_indices:
        return _merge_error("shard summaries do not cover 1..N",
                            missing_shards=missing_indices)

    expected = discovered_units()
    by_index = {index: part for (index, _), part in zip(labels, parts)}
    for index in range(1, total + 1):
        expected_slice = _slice(expected, index, total)
        actual_slice = by_index[index]["units"]
        if actual_slice != expected_slice:
            return _merge_error("shard metadata does not match its exact unit slice",
                                shard=f"{index}/{total}",
                                missing_units=sorted(set(expected_slice) - set(actual_slice)),
                                extra_units=sorted(set(actual_slice) - set(expected_slice)))

    # Merge in logical shard order, not caller order. Caller order is allowed to
    # vary; the metadata, exact slices and unique 1..N set are the authority.
    parts = [by_index[index] for index in range(1, total + 1)]
    failures = [name for part in parts for name in part["failures"]]
    errors = [name for part in parts for name in part["errors"]]
    run = sum(part["run"] for part in parts)
    skipped = sum(part["skipped"] for part in parts)
    summary = {
        "run": run,
        "passed": run - len(failures) - len(errors) - skipped,
        "failed": len(failures) + len(errors),
        "skipped": skipped,
        "skipped_critical": sum(part["skipped_critical"] for part in parts),
        "failures": failures,
        "errors": errors,
        "shards": total,
    }
    _atomic_json(out, summary)
    if log:
        # Concatenate the shards' verbose logs rather than replacing them with a
        # summary: the per-test log is what a reviewer reads when a run is
        # disputed, and it must not get thinner because the run was split.
        target = ROOT / log
        chunks = []
        for part in parts:
            source = part.get("log_path")
            if source:
                try:
                    source_path = (ROOT / source).resolve(strict=False)
                    source_path.relative_to(ROOT.resolve())
                except (OSError, ValueError):
                    return _merge_error("shard log path escapes the repository", path=source)
                if source_path.is_file():
                    chunks.append(f"########## {source} ##########\n"
                                  + source_path.read_text(encoding="utf-8"))
        chunks.append(f"########## merged {len(parts)} shards ##########\n"
                      + json.dumps(summary, ensure_ascii=False, indent=2))
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp",
                                    dir=target.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(chunks) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, target)
        except BaseException:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass
            raise
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["failed"] == 0 and summary["skipped_critical"] == 0 else 1


def _run_module(module: str) -> dict:
    import sys

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(module)
    stream = StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    return {
        "module": module,
        "run": result.testsRun,
        "failures": [str(case) for case, _ in result.failures],
        "errors": [str(case) for case, _ in result.errors],
        "skipped": [str(case) for case, _ in result.skipped],
        "log": stream.getvalue(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite-root", choices=("tools/tests",), default="tools/tests",
                        help="explicit governed discovery root; only tools/tests is accepted")
    parser.add_argument("--out", required=True)
    parser.add_argument("--log", help="also write the verbose runner log here")
    parser.add_argument("--workers", type=int, default=0,
                        help="class-level parallelism; 1 forces a sequential run")
    parser.add_argument("--shard", help="I/N — run only the I-th of N disjoint slices")
    parser.add_argument("--merge", nargs="+", metavar="SUMMARY",
                        help="combine shard summaries into --out")
    args = parser.parse_args()

    if args.merge:
        return _merge(args.merge, ROOT / args.out, args.log)

    shard, shards = _parse_shard(args.shard)
    modules = _slice(discovered_units(), shard, shards)
    workers = args.workers or min(len(modules), (multiprocessing.cpu_count() or 2))
    if workers > 1:
        # Import the shared fixture support *before* forking. It reads ~230
        # repository files into memory, and this repository lives on a slow
        # network-backed mount: paying that once in the parent and inheriting it
        # through fork is worth more than the parallelism itself.
        import sys as _sys
        if str(ROOT) not in _sys.path:
            _sys.path.insert(0, str(ROOT))
        import tools.tests.support  # noqa: F401
        context = multiprocessing.get_context("fork")
        with context.Pool(processes=workers) as pool:
            results = pool.map(_run_module, modules)
    else:
        results = [_run_module(module) for module in modules]

    run = sum(r["run"] for r in results)
    failures = [name for r in results for name in r["failures"]]
    errors = [name for r in results for name in r["errors"]]
    skipped = [name for r in results for name in r["skipped"]]
    skipped_critical = sum(
        1 for name in skipped
        if name.split(" ")[0].startswith(CRITICAL_PREFIXES) or "tools.tests." in name
    )

    summary = {
        "units": modules,
        "shard": f"{shard}/{shards}",
        "shards": shards,
        "log_path": args.log,
        "run": run,
        "passed": run - len(failures) - len(errors) - len(skipped),
        "failed": len(failures) + len(errors),
        "skipped": len(skipped),
        "skipped_critical": skipped_critical,
        "failures": failures,
        "errors": errors,
    }
    out = ROOT / args.out
    _atomic_json(out, summary)
    if args.log:
        log = ROOT / args.log
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("\n".join(f"===== {r['module']} =====\n{r['log']}"
                                 for r in results), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["failed"] == 0 and summary["skipped_critical"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
