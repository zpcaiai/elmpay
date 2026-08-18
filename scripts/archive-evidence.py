#!/usr/bin/env python3
"""Validate and archive the batch evidence tree as an immutable bundle.

The bundle is what an auditor receives. It contains every ``evidence/`` file
plus a manifest binding each file to its SHA-256 and the archive to the commit
it was produced from. The script refuses to write a bundle when any completed
batch fails validation: an archive that contains invalid evidence is worse than
no archive, because it looks authoritative.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ".payment-platform/skill-package/scripts/orchestrate.py"
MANIFEST_NAME = "MANIFEST.json"
MANIFEST_SOURCE = ROOT / ".payment-platform/skill-package/manifest.json"


def batch_order() -> list[str]:
    return [b["id"] for b in
            json.loads(MANIFEST_SOURCE.read_text(encoding="utf-8"))["batches"]]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def completed_batches() -> list[str]:
    directory = ROOT / "evidence" / "completion"
    if not directory.is_dir():
        return []
    return sorted(p.stem for p in directory.glob("*.json"))


def validate(batch: str) -> tuple[bool, str]:
    proc = subprocess.run([sys.executable, ORCHESTRATOR, "validate", batch, "--repo", "."],
                          cwd=ROOT, text=True, capture_output=True)
    return proc.returncode == 0, proc.stdout.strip()


def git_head() -> str:
    proc = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                          text=True, capture_output=True)
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--allow-empty", action="store_true")
    parser.add_argument("--up-to", metavar="BATCH",
                        help="only cover batches that precede BATCH in manifest order; used while "
                             "a batch is producing its own evidence, when later batches are "
                             "legitimately stale")
    parser.add_argument("--exclude-batch", action="append", default=[],
                        help="skip validation for a batch whose completion file is being "
                             "re-issued in this same run; the exclusion is recorded in the "
                             "manifest so an auditor can see it")
    args = parser.parse_args()

    batches = completed_batches()
    if args.up_to:
        order = batch_order()
        if args.up_to not in order:
            print(f"unknown batch {args.up_to}", file=sys.stderr)
            return 3
        limit = order.index(args.up_to)
        allowed = set(order[:limit])
        skipped_later = [b for b in batches if b not in allowed]
        batches = [b for b in batches if b in allowed]
        for batch in skipped_later:
            print(f"  [LATER] {batch}: after {args.up_to} in manifest order, out of scope")
    if not batches and not args.allow_empty:
        print("no completed batches to archive", file=sys.stderr)
        return 3

    excluded = sorted(set(args.exclude_batch))
    for batch in excluded:
        print(f"  [SKIP] {batch}: excluded by --exclude-batch (recorded in the manifest)")

    invalid = []
    for batch in batches:
        if batch in excluded:
            continue
        ok, _ = validate(batch)
        print(f"  [{'OK ' if ok else 'FAIL'}] {batch}")
        if not ok:
            invalid.append(batch)
    if invalid:
        print(f"refusing to archive: {len(invalid)} batch(es) do not validate: {invalid}",
              file=sys.stderr)
        return 2

    files = sorted(p for p in (ROOT / "evidence").rglob("*") if p.is_file())
    manifest = {
        "commit_sha": git_head(),
        "batches": batches,
        "scope_up_to": args.up_to,
        "excluded_from_validation": excluded,
        "file_count": len(files),
        "files": [{"path": p.relative_to(ROOT).as_posix(), "sha256": sha256(p),
                   "bytes": p.stat().st_size} for p in files],
    }
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    manifest_path = out.parent / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
                             + "\n", encoding="utf-8")

    with tarfile.open(out, "w:gz") as archive:
        archive.add(manifest_path, arcname=MANIFEST_NAME)
        for path in files:
            archive.add(path, arcname=path.relative_to(ROOT).as_posix())

    print(json.dumps({"bundle": args.out, "batches": len(batches),
                      "excluded_from_validation": excluded,
                      "files": len(files), "commit_sha": manifest["commit_sha"],
                      "bundle_sha256": sha256(out)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
