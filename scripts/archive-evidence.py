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
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ".payment-platform/skill-package/scripts/orchestrate.py"
MANIFEST_NAME = "MANIFEST.json"
MANIFEST_SOURCE = ROOT / ".payment-platform/skill-package/manifest.json"


class ArchiveSafetyError(RuntimeError):
    """The requested archive would cross or weaken the evidence boundary."""


def batch_order() -> list[str]:
    return [b["id"] for b in
            json.loads(MANIFEST_SOURCE.read_text(encoding="utf-8"))["batches"]]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _ensure_real_directories(path: Path, stop: Path) -> None:
    """Create missing parents without traversing links or non-directories."""
    relative = path.relative_to(stop)
    current = stop
    for part in relative.parts:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ArchiveSafetyError(f"output parent must be a real directory: {current}")


def resolve_output(value: str) -> Path:
    """Resolve an archive target strictly below the repository's real build dir."""
    build = ROOT / "build"
    if build.exists() or build.is_symlink():
        mode = build.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ArchiveSafetyError(f"repository build path must be a real directory: {build}")
    else:
        build.mkdir(mode=0o755)

    build_real = build.resolve(strict=True)
    requested = Path(value)
    if ".." in requested.parts:
        raise ArchiveSafetyError("--out must not contain parent-directory traversal")
    lexical = requested if requested.is_absolute() else ROOT / requested
    if lexical.is_symlink():
        raise ArchiveSafetyError("--out must be absent or an existing non-symlink regular file")
    resolved = lexical.resolve(strict=False)
    if resolved == build_real or not _inside(resolved, build_real):
        raise ArchiveSafetyError("--out must name a file below the repository build directory")

    parent = lexical.parent
    parent_base = next((candidate for candidate in (build, build_real)
                        if _inside(parent, candidate)), None)
    if parent_base is None:
        raise ArchiveSafetyError("--out must be lexically below the repository build directory")
    _ensure_real_directories(parent, parent_base)
    if parent.resolve(strict=True) != resolved.parent:
        raise ArchiveSafetyError("--out parent resolves through an unexpected path")

    if lexical.exists() or lexical.is_symlink():
        mode = lexical.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise ArchiveSafetyError("--out must be absent or an existing non-symlink regular file")
    return resolved


def evidence_files() -> list[Path]:
    """Return a stable inventory while rejecting links and special filesystem nodes."""
    evidence = ROOT / "evidence"
    if not evidence.exists() and not evidence.is_symlink():
        return []
    root_mode = evidence.lstat().st_mode
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise ArchiveSafetyError(f"evidence root must be a real directory: {evidence}")
    evidence_real = evidence.resolve(strict=True)
    files: list[Path] = []

    def visit(directory: Path) -> None:
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                path = Path(entry.path)
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):
                    raise ArchiveSafetyError(f"symlink is forbidden in evidence: {path}")
                if stat.S_ISDIR(mode):
                    resolved = path.resolve(strict=True)
                    if not _inside(resolved, evidence_real):
                        raise ArchiveSafetyError(f"evidence directory escapes its root: {path}")
                    visit(path)
                elif stat.S_ISREG(mode):
                    resolved = path.resolve(strict=True)
                    if not _inside(resolved, evidence_real):
                        raise ArchiveSafetyError(f"evidence file escapes its root: {path}")
                    files.append(path)
                else:
                    raise ArchiveSafetyError(f"non-regular filesystem node is forbidden: {path}")

    visit(evidence)
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def _copy_regular_file(source: Path, destination: Path) -> tuple[str, int]:
    """Snapshot one regular file without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ArchiveSafetyError(f"evidence changed to a non-regular file: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(descriptor, "rb", closefd=False) as incoming, destination.open("xb") as outgoing:
            for chunk in iter(lambda: incoming.read(1 << 20), b""):
                outgoing.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after or size != after.st_size:
            raise ArchiveSafetyError(f"evidence changed while it was being archived: {source}")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.mode = 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _write_archive(path: Path, manifest_bytes: bytes, snapshot: Path,
                   entries: list[dict]) -> None:
    with path.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                archive.addfile(_tar_info(MANIFEST_NAME, len(manifest_bytes)),
                                fileobj=io.BytesIO(manifest_bytes))
                for entry in entries:
                    source = snapshot / entry["path"]
                    with source.open("rb") as stream:
                        archive.addfile(_tar_info(entry["path"], entry["bytes"]), stream)
        raw.flush()
        os.fsync(raw.fileno())


def _verify_archive(path: Path, manifest_bytes: bytes, entries: list[dict]) -> None:
    expected_names = [MANIFEST_NAME] + [entry["path"] for entry in entries]
    expected = {entry["path"]: entry for entry in entries}
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if [member.name for member in members] != expected_names:
            raise ArchiveSafetyError("archive member set differs from the evidence manifest")
        for member in members:
            if not member.isfile() or member.issym() or member.islnk():
                raise ArchiveSafetyError(f"archive contains a non-regular member: {member.name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ArchiveSafetyError(f"archive member cannot be read: {member.name}")
            digest = hashlib.sha256()
            size = 0
            content = bytearray() if member.name == MANIFEST_NAME else None
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                digest.update(chunk)
                size += len(chunk)
                if content is not None:
                    content.extend(chunk)
            if member.name == MANIFEST_NAME:
                if bytes(content) != manifest_bytes:
                    raise ArchiveSafetyError("archive manifest differs from the generated manifest")
                continue
            entry = expected[member.name]
            if size != entry["bytes"] or digest.hexdigest() != entry["sha256"]:
                raise ArchiveSafetyError(f"archive member digest mismatch: {member.name}")


def create_archive(out: Path, batches: list[str], excluded: list[str],
                   scope_up_to: str | None) -> dict:
    """Snapshot, manifest, verify and atomically publish one evidence bundle."""
    out = resolve_output(str(out))
    files = evidence_files()
    temporary = Path(tempfile.mkdtemp(prefix=".evidence-archive.", dir=out.parent))
    try:
        snapshot = temporary / "snapshot"
        entries: list[dict] = []
        for source in files:
            relative = source.relative_to(ROOT).as_posix()
            digest, size = _copy_regular_file(source, snapshot / relative)
            entries.append({"path": relative, "sha256": digest, "bytes": size})
        manifest = {
            "commit_sha": git_head(),
            "batches": batches,
            "scope_up_to": scope_up_to,
            "excluded_from_validation": excluded,
            "file_count": len(entries),
            "files": entries,
        }
        manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
                          + "\n").encode("utf-8")
        candidate = temporary / "bundle.tar.gz"
        _write_archive(candidate, manifest_bytes, snapshot, entries)
        _verify_archive(candidate, manifest_bytes, entries)
        os.replace(candidate, out)
        return {"manifest": manifest, "bundle_sha256": sha256(out)}
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


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

    try:
        out = resolve_output(args.out)
    except (ArchiveSafetyError, OSError) as exc:
        print(f"unsafe evidence archive output: {exc}", file=sys.stderr)
        return 3

    try:
        # Inventory before reading completion names so a linked completion
        # directory cannot influence which validator commands are executed.
        evidence_files()
        batches = completed_batches()
    except (ArchiveSafetyError, OSError) as exc:
        print(f"refusing to inspect unsafe evidence: {exc}", file=sys.stderr)
        return 3
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

    try:
        result = create_archive(out, batches, excluded, args.up_to)
    except (ArchiveSafetyError, OSError, tarfile.TarError) as exc:
        print(f"refusing to archive unsafe or inconsistent evidence: {exc}", file=sys.stderr)
        return 3

    print(json.dumps({"bundle": args.out, "batches": len(batches),
                      "excluded_from_validation": excluded,
                      "files": result["manifest"]["file_count"],
                      "commit_sha": result["manifest"]["commit_sha"],
                      "bundle_sha256": result["bundle_sha256"]},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
