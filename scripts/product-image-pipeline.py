#!/usr/bin/env python3
"""Build and verify the six production OCI images without inventing evidence.

`source-gate` is a local/static check.  `build`, `scan`, `sign-registry` and
`finalize` are separate execution phases so a missing scanner, OIDC identity,
registry image or evidence file blocks instead of being represented as a pass.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import (  # noqa: E402
    ValidationError,
    canonical_json,
    read_json,
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from elmpay_runtime.oci import (  # noqa: E402
    ADMISSION_POLICY_PATH,
    CANONICAL_JAVA_LAUNCHER_DIGEST,
    PRODUCT_MANIFEST_PATH,
    admission_policy_digest,
    product_image_manifest_digest,
    resolve_base_images,
    validate_admission_policy,
    validate_product_image_manifest,
    validate_product_release_index,
)


WORKLOAD_POLICY = Path("platform/kubernetes/workload-policy.json")
PIPELINE_POLICY = Path("governance/ci-pipeline.json")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
OCI_IMAGE = re.compile(r"^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$")
MAX_FILES = 100_000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 4 * 1024 * 1024
GITHUB_WORKFLOW_REF = "zpcaiai/elmpay/.github/workflows/ci.yml@refs/heads/main"


def _documents() -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    manifest = require_mapping(read_json(ROOT / PRODUCT_MANIFEST_PATH), "product manifest")
    workloads = require_mapping(read_json(ROOT / WORKLOAD_POLICY), "workload policy")
    admission = require_mapping(read_json(ROOT / ADMISSION_POLICY_PATH), "admission policy")
    validate_product_image_manifest(ROOT, manifest, workloads)
    validate_admission_policy(admission)
    return manifest, workloads, admission


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(value: object, field: str) -> Path:
    text = require_text(value, field)
    path = Path(text)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValidationError(f"{field} must stay within the repository")
    return path


def _tree_entries(paths: Iterable[Path]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[Path] = set()
    total = 0
    root = ROOT.resolve(strict=True)
    for requested in paths:
        candidate = ROOT / requested
        if candidate.is_symlink() or not candidate.exists():
            raise ValidationError(f"product artifact is missing or a symlink: {requested}")
        candidates = [candidate] if candidate.is_file() else sorted(candidate.rglob("*"))
        for path in candidates:
            if path.is_dir():
                continue
            if path.is_symlink() or not path.is_file():
                raise ValidationError(f"non-regular product artifact is forbidden: {path}")
            resolved = path.resolve(strict=True)
            if root not in resolved.parents or resolved in seen:
                raise ValidationError("product artifact escapes or overlaps its declared source")
            seen.add(resolved)
            stat = resolved.stat()
            if stat.st_size > MAX_FILE_BYTES:
                raise ValidationError(f"product artifact file is too large: {path}")
            total += stat.st_size
            if total > MAX_TOTAL_BYTES or len(seen) > MAX_FILES:
                raise ValidationError("product artifact inventory exceeds the bounded limit")
            entries.append({
                "path": str(resolved.relative_to(root)),
                "sha256": _sha256(resolved),
                "size": stat.st_size,
                "mode": stat.st_mode & 0o777,
            })
    return sorted(entries, key=lambda value: value["path"])


def _directory_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_dir():
        raise ValidationError("scanner database path must be a regular directory")
    root = path.resolve(strict=True)
    entries: list[dict[str, Any]] = []
    total = 0
    for candidate in sorted(root.rglob("*")):
        # Check symlinks before is_dir/is_file: pathlib follows them, and a
        # symlinked directory must never be silently omitted from the digest.
        if candidate.is_symlink():
            raise ValidationError(f"non-regular scanner database entry: {candidate}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise ValidationError(f"non-regular scanner database entry: {candidate}")
        stat = candidate.stat()
        if stat.st_size > MAX_FILE_BYTES:
            raise ValidationError("scanner database file exceeds the bounded size")
        total += stat.st_size
        if total > MAX_TOTAL_BYTES or len(entries) >= MAX_FILES:
            raise ValidationError("scanner database exceeds the bounded inventory")
        entries.append({
            "path": str(candidate.relative_to(root)),
            "sha256": _sha256(candidate),
            "size": stat.st_size,
        })
    if not entries:
        raise ValidationError("scanner database directory is empty")
    return sha256_json(entries)


def _safe_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    allowed = {
        "PATH", "JAVA_HOME", "GRADLE_USER_HOME", "TMPDIR", "LANG", "LC_ALL",
        "HOME", "USER", "LOGNAME", "DOCKER_CONFIG", "REGISTRY_AUTH_FILE",
        "XDG_RUNTIME_DIR",
    }
    result = {key: value for key, value in os.environ.items() if key in allowed}
    result.setdefault("LANG", "C.UTF-8")
    result.setdefault("LC_ALL", "C.UTF-8")
    if extra:
        result.update(extra)
    return result


def _sigstore_environment() -> dict[str, str]:
    """Expose only the ambient GitHub OIDC inputs required by keyless Cosign."""

    result = _safe_environment()
    for key in (
        "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_REF",
        "GITHUB_SHA", "GITHUB_WORKFLOW_REF", "RUNNER_ENVIRONMENT",
    ):
        value = os.environ.get(key)
        if value:
            result[key] = value
    return result


def _run(
    command: Sequence[str], *, environment: Mapping[str, str] | None = None,
    stdout: int | None = subprocess.PIPE, check: bool = True, timeout: int = 3600,
) -> subprocess.CompletedProcess[bytes]:
    """Run a tool in its own process group with bounded captured diagnostics."""

    if stdout is None:
        stdout = subprocess.PIPE
    if stdout not in {subprocess.PIPE, subprocess.DEVNULL}:
        raise ValidationError("external tool stdout must be captured or discarded")
    process: subprocess.Popen[bytes] | None = None
    output = bytearray()
    errors = bytearray()
    overflow = threading.Event()
    termination_denied = threading.Event()
    threads: list[threading.Thread] = []

    def terminate_group() -> None:
        if process is None:
            return
        try:
            # The group can outlive its leader when a child inherited one of
            # the capture pipes.  Killing only while Popen.poll() is None would
            # leak that child and leave a collector blocked forever.
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            # A fast-exiting group leader can race with PID/process-group reuse
            # under heavy host load.  Never leak the raw OS exception and,
            # more importantly, never report the tool as successful when its
            # descendants could not be proven stopped.
            termination_denied.set()

    def collect(stream: Any, destination: bytearray) -> None:
        try:
            while True:
                block = stream.read(64 * 1024)
                if not block:
                    return
                remaining = MAX_TOOL_OUTPUT_BYTES - len(destination)
                if remaining > 0:
                    destination.extend(block[:remaining])
                if len(block) > remaining:
                    overflow.set()
                    terminate_group()
        finally:
            stream.close()

    try:
        process = subprocess.Popen(
            list(command), cwd=ROOT, env=dict(environment or _safe_environment()),
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        if process.stdout is not None:
            threads.append(threading.Thread(
                target=collect, args=(process.stdout, output), daemon=True
            ))
        if process.stderr is None:
            raise ValidationError("external tool stderr capture was not created")
        threads.append(threading.Thread(
            target=collect, args=(process.stderr, errors), daemon=True
        ))
        for thread in threads:
            thread.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            terminate_group()
            process.wait()
            for thread in threads:
                thread.join(timeout=5)
            raise subprocess.TimeoutExpired(
                list(command), timeout, output=bytes(output), stderr=bytes(errors)
            ) from exc
        # A successful/failed tool leader must not leave background children
        # holding capture pipes or mutating release inputs after this call.
        terminate_group()
        for thread in threads:
            thread.join(timeout=5)
            if thread.is_alive():
                terminate_group()
        if any(thread.is_alive() for thread in threads):
            if process.poll() is None:
                process.wait()
            for thread in threads:
                thread.join(timeout=5)
            if any(thread.is_alive() for thread in threads):
                raise ValidationError("external tool output collector did not terminate")
    finally:
        terminate_group()
        if process is not None and process.poll() is None:
            process.wait()
        for stream in (
            None if process is None else process.stdout,
            None if process is None else process.stderr,
        ):
            if stream is not None and not stream.closed:
                stream.close()
    if termination_denied.is_set():
        raise ValidationError("external tool process group termination was denied")
    if overflow.is_set():
        raise ValidationError("external tool output exceeded the bounded diagnostic limit")
    stdout_bytes = bytes(output) if stdout == subprocess.PIPE else None
    stderr_bytes = bytes(errors)
    completed = subprocess.CompletedProcess(
        list(command), returncode, stdout=stdout_bytes, stderr=stderr_bytes
    )
    if check and returncode != 0:
        raise subprocess.CalledProcessError(
            returncode, list(command), output=stdout_bytes, stderr=stderr_bytes
        )
    return completed


def _verified_tool(name: str, version: str, expected_digest: str) -> str:
    executable = shutil.which(name, path=os.environ.get("PATH", ""))
    if executable is None:
        raise ValidationError(f"required product-image tool is unavailable: {name}")
    resolved = Path(executable).resolve(strict=True)
    if not DIGEST.fullmatch(expected_digest) or expected_digest == "0" * 64 \
            or _sha256(resolved) != expected_digest:
        raise ValidationError(f"{name} executable digest does not match the release input")
    if name == "docker":
        command = [str(resolved), "buildx", "version"]
    elif name == "cosign":
        command = [str(resolved), "version"]
    else:
        command = [str(resolved), "--version"]
    completed = _run(command, stdout=subprocess.PIPE, timeout=30)
    output = ((completed.stdout or b"") + (completed.stderr or b"")).decode(
        "utf-8", errors="strict"
    )
    if not version or version not in output:
        raise ValidationError(f"{name} version does not match the release input")
    return str(resolved)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValidationError(f"stale temporary output exists: {temporary}")
    data = canonical_json(value) + b"\n"
    with temporary.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def _strict_json_bytes(data: bytes, field: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError(f"duplicate JSON key in {field}: {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            data.decode("utf-8"), object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValidationError(f"non-finite JSON number in {field}: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{field} is not strict UTF-8 JSON") from exc


def _single_cosign_document(output: bytes, field: str) -> Mapping[str, Any]:
    parsed = _strict_json_bytes(output.strip(), field)
    if isinstance(parsed, list):
        if len(parsed) != 1:
            raise ValidationError(f"{field} must contain exactly one verified payload")
        parsed = parsed[0]
    document = require_mapping(parsed, field)
    if "payload" not in document:
        return document
    payload_text = require_text(document.get("payload"), f"{field}.payload")
    try:
        payload = base64.b64decode(payload_text, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"{field} payload is not canonical base64") from exc
    if base64.b64encode(payload).decode("ascii") != payload_text:
        raise ValidationError(f"{field} payload is not canonical base64")
    return require_mapping(_strict_json_bytes(payload, f"{field} statement"), f"{field} statement")


def _validate_cosign_signature_output(output: bytes, reference: str) -> None:
    payload = _single_cosign_document(output, "verified Cosign image signature")
    critical = require_mapping(
        payload.get("critical", payload.get("Critical")), "Cosign signature critical"
    )
    image = require_mapping(
        critical.get("image", critical.get("Image")), "Cosign signature image"
    )
    identity = require_mapping(
        critical.get("identity", critical.get("Identity")), "Cosign signature identity"
    )
    repository, digest = reference.rsplit("@sha256:", 1)
    observed_digest = image.get("docker-manifest-digest", image.get("Docker-manifest-digest"))
    observed_reference = identity.get("docker-reference", identity.get("Docker-reference"))
    if observed_digest != f"sha256:{digest}" or observed_reference not in {repository, reference}:
        raise ValidationError("verified Cosign signature payload has the wrong image subject")


def _validate_cosign_attestation_output(
    output: bytes,
    reference: str,
    predicate_type: str,
    predicate: Mapping[str, Any],
) -> str:
    statement = _single_cosign_document(output, "verified Cosign attestation")
    return _validate_attestation_statement(
        statement, reference, predicate_type, predicate
    )


def _validate_attestation_statement(
    statement: Mapping[str, Any], reference: str, predicate_type: str,
    predicate: Mapping[str, Any],
) -> str:
    if statement.get("_type") not in {
        "https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"
    } or statement.get("predicateType") != predicate_type:
        raise ValidationError("verified Cosign attestation statement/predicate type is invalid")
    subjects = [
        require_mapping(value, "attestation subject")
        for value in require_list(statement.get("subject"), "attestation subjects")
    ]
    repository, digest = reference.rsplit("@sha256:", 1)
    if len(subjects) != 1 or subjects[0].get("name") != repository \
            or require_mapping(subjects[0].get("digest"), "attestation subject digest") \
            != {"sha256": digest}:
        raise ValidationError("verified Cosign attestation has the wrong registry subject")
    observed_predicate = require_mapping(statement.get("predicate"), "attestation predicate")
    expected_digest = sha256_json(predicate)
    if sha256_json(observed_predicate) != expected_digest:
        raise ValidationError("verified Cosign attestation predicate differs from the local evidence")
    return expected_digest


def _validate_sigstore_bundle(
    path: Path, *, attestation: bool
) -> Mapping[str, Any] | None:
    bundle = require_mapping(read_json(path), "Sigstore bundle")
    if bundle.get("mediaType") \
            != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise ValidationError("Sigstore bundle media type is not the governed v0.3 format")
    material = require_mapping(bundle.get("verificationMaterial"), "Sigstore verification material")
    entries = require_list(material.get("tlogEntries"), "Sigstore transparency log entries")
    if not entries or any(not isinstance(value, dict) for value in entries):
        raise ValidationError("Sigstore bundle has no transparency log inclusion material")
    for raw in entries:
        entry = require_mapping(raw, "Sigstore transparency log entry")
        proof = require_mapping(entry.get("inclusionProof"), "Sigstore inclusion proof")
        promise = require_mapping(entry.get("inclusionPromise"), "Sigstore inclusion promise")
        hashes = require_list(proof.get("hashes"), "Sigstore inclusion hashes")
        checkpoint = require_mapping(proof.get("checkpoint"), "Sigstore checkpoint")
        log_index = entry.get("logIndex")
        integrated_time = entry.get("integratedTime")
        tree_size = proof.get("treeSize")
        if isinstance(log_index, bool) or not isinstance(log_index, int) or log_index < 0 \
                or isinstance(integrated_time, bool) or not isinstance(integrated_time, int) \
                or integrated_time < 1 \
                or isinstance(tree_size, bool) or not isinstance(tree_size, int) \
                or tree_size < 1 \
                or any(not isinstance(value, str) for value in hashes) \
                or not isinstance(proof.get("rootHash"), str) \
                or not isinstance(checkpoint.get("envelope"), str) \
                or not isinstance(promise.get("signedEntryTimestamp"), str):
            raise ValidationError("Sigstore transparency log proof is incomplete")
    required_payload = "dsseEnvelope" if attestation else "messageSignature"
    payload = bundle.get(required_payload)
    if not isinstance(payload, dict):
        raise ValidationError(f"Sigstore bundle has no {required_payload}")
    if not attestation:
        return None
    envelope = require_mapping(payload, "Sigstore DSSE envelope")
    encoded = require_text(envelope.get("payload"), "Sigstore DSSE payload")
    if envelope.get("payloadType") != "application/vnd.in-toto+json" \
            or not require_list(envelope.get("signatures"), "Sigstore DSSE signatures"):
        raise ValidationError("Sigstore DSSE envelope type/signatures are invalid")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError) as exc:
        raise ValidationError("Sigstore DSSE payload is not canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise ValidationError("Sigstore DSSE payload is not canonical base64")
    return require_mapping(
        _strict_json_bytes(decoded, "Sigstore DSSE statement"),
        "Sigstore DSSE statement",
    )


def _regular_evidence_file(path: Path, field: str) -> Path:
    """Resolve a bounded regular evidence file without following any symlink."""

    candidate = path.absolute()
    if candidate.is_symlink() or not candidate.is_file():
        raise ValidationError(f"{field} is missing, a symlink or not a regular file")
    resolved = candidate.resolve(strict=True)
    if resolved.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ValidationError(f"{field} exceeds the bounded evidence size")
    return resolved


def _bound_evidence_file(
    root: Path, value: object, field: str, expected_digest: object
) -> Path:
    relative = _safe_relative(value, field)
    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValidationError(f"{field} contains a symlink")
    resolved = _regular_evidence_file(candidate, field)
    if resolved != root and root not in resolved.parents:
        raise ValidationError(f"{field} escapes its build evidence directory")
    if not isinstance(expected_digest, str) or not DIGEST.fullmatch(expected_digest) \
            or expected_digest == "0" * 64 or _sha256(resolved) != expected_digest:
        raise ValidationError(f"{field} digest mismatch")
    return resolved


def _snapshot_regular_file(source: Path, destination: Path, expected_digest: str) -> None:
    """Create one read-only, hash-verified publication snapshot without path races."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    digest = hashlib.sha256()
    total = 0
    with os.fdopen(descriptor, "rb", closefd=True) as reader:
        initial = os.fstat(reader.fileno())
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > MAX_TOTAL_BYTES:
            raise ValidationError("publication source is not a bounded regular file")
        with destination.open("xb") as writer:
            for block in iter(lambda: reader.read(1024 * 1024), b""):
                total += len(block)
                if total > MAX_TOTAL_BYTES:
                    raise ValidationError("publication source exceeds the bounded size")
                writer.write(block)
                digest.update(block)
            writer.flush()
            os.fsync(writer.fileno())
        final = os.fstat(reader.fileno())
    if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) \
            != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns) \
            or total != initial.st_size or digest.hexdigest() != expected_digest:
        raise ValidationError("publication source changed while creating its exact snapshot")
    destination.chmod(0o400)


def _build_context_sources(
    artifact_manifest: Mapping[str, Any],
) -> dict[Path, dict[str, int | str]]:
    """Return the exact aggregate-artifact file set used as build context."""

    sources: dict[Path, dict[str, int | str]] = {}

    def add(
        raw_path: object,
        raw_digest: object,
        *,
        size: object | None = None,
        mode: object | None = None,
    ) -> None:
        relative = _safe_relative(raw_path, "build context source")
        if not isinstance(raw_digest, str) or not DIGEST.fullmatch(raw_digest) \
                or raw_digest == "0" * 64:
            raise ValidationError("build context source digest is invalid")
        document: dict[str, int | str] = {"sha256": raw_digest}
        if size is not None:
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise ValidationError("build context source size is invalid")
            document["size"] = size
        if mode is not None:
            if isinstance(mode, bool) or not isinstance(mode, int) \
                    or not 0 <= mode <= 0o777:
                raise ValidationError("build context source mode is invalid")
            document["mode"] = mode
        prior = sources.get(relative)
        if prior is not None and prior != document:
            # Repeated files must have one aggregate-artifact identity; never
            # permit last-writer-wins context assembly.
            raise ValidationError(f"conflicting build context source binding: {relative}")
        sources[relative] = document

    context = require_mapping(
        artifact_manifest.get("contextPolicy"), "artifact context policy"
    )
    add(context.get("path"), context.get("sha256"))
    for raw in require_list(artifact_manifest.get("images"), "artifact images"):
        image = require_mapping(raw, "artifact image")
        for raw_entry in require_list(image.get("includedFiles"), "included files"):
            entry = require_mapping(raw_entry, "included file")
            add(
                entry.get("path"), entry.get("sha256"),
                size=entry.get("size"), mode=entry.get("mode"),
            )
        containerfile = require_mapping(image.get("containerfile"), "containerfile")
        add(containerfile.get("path"), containerfile.get("sha256"))
        for raw_runtime in require_list(image.get("runtimeInputs"), "runtime inputs"):
            runtime = require_mapping(raw_runtime, "runtime input")
            add(runtime.get("path"), runtime.get("sha256"))
    if not sources or len(sources) > MAX_FILES:
        raise ValidationError("build context source inventory is empty or too large")
    return sources


def _copy_build_context_source(
    relative: Path,
    expected: Mapping[str, int | str],
    destination_root: Path,
) -> None:
    """Copy one source through a stable O_NOFOLLOW descriptor into a new tree."""

    source = ROOT / relative
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ValidationError(f"build context source cannot be opened safely: {relative}") from exc
    digest = hashlib.sha256()
    total = 0
    destination = destination_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(descriptor, "rb", closefd=True) as reader:
        initial = os.fstat(reader.fileno())
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > MAX_FILE_BYTES:
            raise ValidationError(f"build context source is not a bounded regular file: {relative}")
        with destination.open("xb") as writer:
            for block in iter(lambda: reader.read(1024 * 1024), b""):
                total += len(block)
                if total > MAX_FILE_BYTES:
                    raise ValidationError(f"build context source exceeds the file bound: {relative}")
                writer.write(block)
                digest.update(block)
            writer.flush()
            os.fsync(writer.fileno())
        final = os.fstat(reader.fileno())
    stable_identity = (
        initial.st_dev, initial.st_ino, initial.st_size,
        initial.st_mtime_ns, initial.st_ctime_ns,
    ) == (
        final.st_dev, final.st_ino, final.st_size,
        final.st_mtime_ns, final.st_ctime_ns,
    )
    if not stable_identity or total != initial.st_size \
            or digest.hexdigest() != expected.get("sha256") \
            or ("size" in expected and total != expected["size"]) \
            or ("mode" in expected and initial.st_mode & 0o777 != expected["mode"]):
        raise ValidationError(f"build context source changed or differs from evidence: {relative}")
    destination.chmod(initial.st_mode & 0o777)


def _validate_build_context_snapshot(
    destination_root: Path,
    expected: Mapping[Path, Mapping[str, int | str]],
) -> None:
    """Fail closed if the exact local build snapshot is altered or gains files."""

    if destination_root.is_symlink() or not destination_root.is_dir():
        raise ValidationError("build context snapshot is missing or unsafe")
    observed: set[Path] = set()
    total = 0
    for candidate in sorted(destination_root.rglob("*")):
        if candidate.is_symlink():
            raise ValidationError("build context snapshot contains a symlink")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise ValidationError("build context snapshot contains a non-regular entry")
        relative = candidate.relative_to(destination_root)
        binding = expected.get(relative)
        if binding is None:
            raise ValidationError(f"build context snapshot contains an undeclared file: {relative}")
        details = candidate.stat()
        total += details.st_size
        if total > MAX_TOTAL_BYTES or len(observed) >= MAX_FILES \
                or _sha256(candidate) != binding.get("sha256") \
                or ("size" in binding and details.st_size != binding["size"]) \
                or ("mode" in binding and details.st_mode & 0o777 != binding["mode"]):
            raise ValidationError(f"build context snapshot binding changed: {relative}")
        observed.add(relative)
    if observed != set(expected):
        raise ValidationError("build context snapshot file inventory is incomplete")


def _snapshot_build_context(
    artifact_manifest: Mapping[str, Any], destination_root: Path
) -> dict[Path, dict[str, int | str]]:
    if destination_root.exists() or destination_root.is_symlink():
        raise ValidationError("build context snapshot destination must be new")
    destination_root.mkdir(parents=True)
    sources = _build_context_sources(artifact_manifest)
    for relative, binding in sorted(sources.items(), key=lambda item: str(item[0])):
        _copy_build_context_source(relative, binding, destination_root)
    destination_root.chmod(0o755)
    for directory in sorted(
        (value for value in destination_root.rglob("*") if value.is_dir()),
        key=lambda value: len(value.parts), reverse=True,
    ):
        directory.chmod(0o755)
    _validate_build_context_snapshot(destination_root, sources)
    return sources


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _registry_tag_digest(
    skopeo: str, repository: str, tag: str, environment: Mapping[str, str]
) -> str | None:
    listing = _run(
        [skopeo, "list-tags", f"docker://{repository}"],
        environment=environment, stdout=subprocess.PIPE,
    )
    document = require_mapping(
        _strict_json_bytes(listing.stdout or b"", "registry tag listing"),
        "registry tag listing",
    )
    tags = require_list(document.get("Tags"), "registry tags")
    if len(tags) > MAX_FILES or any(not isinstance(value, str) for value in tags) \
            or len(tags) != len(set(tags)):
        raise ValidationError("registry tag listing is invalid or exceeds the safe bound")
    if tag not in tags:
        return None
    inspected = _run([
        skopeo, "inspect", "--format", "{{.Digest}}", f"docker://{repository}:{tag}",
    ], environment=environment, stdout=subprocess.PIPE)
    observed = (inspected.stdout or b"").decode("ascii", errors="strict").strip()
    if not observed.startswith("sha256:") \
            or not DIGEST.fullmatch(observed.removeprefix("sha256:")):
        raise ValidationError("registry tag did not resolve to an exact sha256 digest")
    return observed.removeprefix("sha256:")


def _publication_resume_decision(
    receipt_exists: bool, remote_digest: str | None, expected_digest: str
) -> tuple[bool, str]:
    if remote_digest is not None and remote_digest != expected_digest:
        raise ValidationError("immutable digest tag points to another OCI subject")
    if remote_digest is None:
        return True, (
            "RECOPIED_MISSING_TAG_FROM_EXACT_SNAPSHOT"
            if receipt_exists else "COPIED_SCANNED_OCI_ARCHIVE"
        )
    return False, (
        "RESUMED_FROM_DURABLE_RECEIPT"
        if receipt_exists else "RECONCILED_EXISTING_EXACT_DIGEST"
    )


def _validate_durable_publication_receipt(
    observed: Mapping[str, Any], expected: Mapping[str, Any]
) -> None:
    action = observed.get("publicationAction")
    exact = dict(expected)
    exact["publicationAction"] = action
    if action not in {
        "COPIED_SCANNED_OCI_ARCHIVE", "RECONCILED_EXISTING_EXACT_DIGEST"
    } or observed != exact:
        raise ValidationError("durable publication receipt is corrupt or subject-unbound")


def _cyclonedx_package_components(document: Mapping[str, Any], field: str) -> list[Mapping[str, Any]]:
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise ValidationError(f"{field} must be CycloneDX 1.6")
    raw_components = require_list(document.get("components"), f"{field}.components")
    components = [require_mapping(value, f"{field}.component") for value in raw_components]
    if not components:
        raise ValidationError(f"{field} has no package inventory")
    references = [require_text(value.get("bom-ref"), f"{field}.component.bom-ref") for value in components]
    if len(references) != len(set(references)):
        raise ValidationError(f"{field} component references are not unique")
    packages = [
        value for value in components
        if isinstance(value.get("purl"), str) and str(value["purl"]).startswith("pkg:")
    ]
    if not packages:
        raise ValidationError(f"{field} has no package-level components")
    return components


def _validate_full_image_sbom(
    document: Mapping[str, Any], name: str, image_digest: str, base_image: str, field: str
) -> Mapping[str, Any]:
    components = _cyclonedx_package_components(document, field)
    metadata = require_mapping(document.get("metadata"), f"{field}.metadata")
    subject = require_mapping(metadata.get("component"), f"{field}.metadata.component")
    expected_ref = f"pkg:oci/{name}@sha256:{image_digest}"
    hashes = require_list(subject.get("hashes"), f"{field}.metadata.component.hashes")
    if subject.get("type") != "container" or subject.get("name") != name \
            or subject.get("bom-ref") != expected_ref \
            or subject.get("version") != f"sha256:{image_digest}" \
            or {value.get("content") for value in hashes if isinstance(value, dict) \
                and value.get("alg") == "SHA-256"} != {image_digest}:
        raise ValidationError(f"{field} is not bound to the exact OCI subject")
    property_documents = [
        require_mapping(value, f"{field}.subject.property")
        for value in require_list(subject.get("properties"), f"{field}.subject.properties")
    ]
    property_names = [
        require_text(value.get("name"), f"{field}.subject.property.name")
        for value in property_documents
    ]
    if len(property_names) != len(set(property_names)):
        raise ValidationError(f"{field} subject properties are not unique")
    properties = {str(value["name"]): value.get("value") for value in property_documents}
    if properties.get("elmpay:coverage") != "full-image-package-inventory" \
            or not isinstance(properties.get("elmpay:scanner-output-digest"), str) \
            or not DIGEST.fullmatch(str(properties["elmpay:scanner-output-digest"])) \
            or properties.get("elmpay:scanner-output-digest") == "0" * 64 \
            or not isinstance(properties.get("elmpay:scanner-database-digest"), str) \
            or not DIGEST.fullmatch(str(properties["elmpay:scanner-database-digest"])) \
            or properties.get("elmpay:scanner-database-digest") == "0" * 64 \
            or properties.get("elmpay:base-image") != base_image \
            or OCI_IMAGE.fullmatch(base_image) is None:
        raise ValidationError(f"{field} full-image scanner binding is incomplete")
    del components
    return properties


def _validate_bound_scan_report(
    document: Mapping[str, Any], name: str, image_digest: str,
    scanner: Mapping[str, Any], database_digest: str,
) -> None:
    if document.get("schemaVersion") != 1 \
            or document.get("subject") != f"ghcr.io/zpcaiai/elmpay/{name}@sha256:{image_digest}" \
            or document.get("scanner") != scanner \
            or document.get("databaseDigest") != database_digest \
            or document.get("status") != "COMPLETE_NO_HIGH_OR_CRITICAL" \
            or not isinstance(document.get("rawReportDigest"), str) \
            or not DIGEST.fullmatch(str(document["rawReportDigest"])) \
            or not require_list(document.get("results"), "bound scan results"):
        raise ValidationError(f"{name} bound vulnerability report is incomplete")


def _expected_image_entrypoint(image: Mapping[str, Any]) -> list[str]:
    if image.get("kind") == "java-install-dist":
        return [require_text(image.get("entrypoint"), "Java image entrypoint")]
    name = require_text(image.get("name"), "Node image name")
    return [
        require_text(image.get("entrypoint"), "Node image entrypoint"),
        "src/main.mjs" if name == "admin-web" else "src/server.mjs",
    ]


def _layer_diff_id(data: bytes, field: str) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                total += len(block)
                if total > MAX_TOTAL_BYTES:
                    raise ValidationError(f"{field} uncompressed layer exceeds the bounded size")
                digest.update(block)
    except (OSError, EOFError) as exc:
        raise ValidationError(f"{field} is not a valid complete gzip layer") from exc
    return digest.hexdigest()


def _validate_layer_tar(data: bytes, field: str) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as layer:
            seen: set[str] = set()
            total = 0
            for position, member in enumerate(layer.getmembers()):
                if position >= MAX_FILES:
                    raise ValidationError(f"{field} has too many filesystem entries")
                if member.isdir() and member.name in {".", "./"}:
                    continue
                name = member.name.removeprefix("./")
                canonical = name.rstrip("/") if member.isdir() else name
                normalized = PurePosixPath(canonical)
                if not canonical or canonical.startswith("/") or ".." in normalized.parts \
                        or str(normalized) != canonical or canonical in seen:
                    raise ValidationError(f"{field} contains duplicate or unsafe paths")
                seen.add(canonical)
                if member.isdev() or member.isfifo() or not (
                    member.isfile() or member.isdir() or member.issym() or member.islnk()
                ):
                    raise ValidationError(f"{field} contains an unsupported filesystem entry")
                if member.isfile():
                    total += member.size
                    if member.size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                        raise ValidationError(f"{field} filesystem content exceeds the bounded size")
                if member.issym() or member.islnk():
                    target = member.linkname
                    if not target:
                        raise ValidationError(f"{field} contains an unsafe link target")
                    absolute_target = target.startswith("/")
                    target_path = PurePosixPath(target.removeprefix("/"))
                    base = (
                        PurePosixPath()
                        if absolute_target or member.islnk()
                        else normalized.parent
                    )
                    resolved_parts: list[str] = []
                    for part in (*base.parts, *target_path.parts):
                        if part in {"", "."}:
                            continue
                        if part == "..":
                            if not resolved_parts:
                                raise ValidationError(f"{field} contains an escaping link target")
                            resolved_parts.pop()
                        else:
                            resolved_parts.append(part)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ValidationError(f"{field} is not a valid OCI filesystem layer") from exc


def _normalized_rootfs_path(raw: str, base: Sequence[str] = ()) -> str:
    if not raw or "\x00" in raw:
        raise ValidationError("OCI rootfs path/link is empty or contains NUL")
    parts: list[str] = [] if raw.startswith("/") else list(base)
    for part in PurePosixPath(raw.removeprefix("/")).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise ValidationError("OCI rootfs path/link escapes the image root")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise ValidationError("OCI rootfs path/link resolves to the image root")
    return "/".join(parts)


def _runtime_requirements(
    product_manifest: Mapping[str, Any], image: Mapping[str, Any]
) -> dict[str, Any]:
    bases = {
        require_text(value.get("id"), "base image.id"): value
        for value in (
            require_mapping(raw, "base image")
            for raw in require_list(product_manifest.get("baseImages"), "base images")
        )
    }
    name = require_text(image.get("name"), "product image.name")
    base = bases[require_text(image.get("baseImage"), f"{name}.baseImage")]
    executables = {
        require_text(value, f"{name} required runtime path")
        for value in require_list(base.get("requiredPaths"), "base required paths")
    }
    executables.add(require_text(image.get("entrypoint"), f"{name}.entrypoint"))
    files: set[str] = set()
    directories: set[str] = set()
    at_least_one: list[dict[str, str]] = []
    if image.get("kind") == "java-install-dist":
        files.update({
            "/opt/elmpay/etc/default-main-class",
            "/opt/elmpay/etc/allowed-main-classes",
        })
        directories.add("/opt/elmpay/app/lib")
        at_least_one.append({
            "prefix": "/opt/elmpay/app/lib/", "suffix": ".jar", "kind": "file"
        })
    else:
        files.add("/opt/elmpay/app/package.json")
        files.add(
            "/opt/elmpay/app/src/main.mjs"
            if name == "admin-web" else "/opt/elmpay/app/src/server.mjs"
        )
    return {
        "executables": sorted(executables),
        "files": sorted(files),
        "directories": sorted(directories),
        "atLeastOne": at_least_one,
    }


def _mode_allows(entry: Mapping[str, Any], mask: int) -> bool:
    mode = int(entry["mode"])
    if entry.get("uid") == 10001:
        return bool(mode & (mask << 6))
    if entry.get("gid") == 10001:
        return bool(mode & (mask << 3))
    return bool(mode & mask)


def _merged_rootfs_inspection(
    layer_blobs: Sequence[tuple[str, bytes]], requirements: Mapping[str, Any]
) -> dict[str, Any]:
    filesystem: dict[str, dict[str, Any]] = {}
    for layer_index, (layer_digest, layer_bytes) in enumerate(layer_blobs):
        with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:gz") as layer:
            members = layer.getmembers()
            normal_members: list[tuple[str, tarfile.TarInfo]] = []
            for member in members:
                if member.isdir() and member.name in {".", "./"}:
                    continue
                canonical = member.name.removeprefix("./").rstrip("/") \
                    if member.isdir() else member.name.removeprefix("./")
                path = _normalized_rootfs_path(canonical)
                basename = PurePosixPath(path).name
                parent = str(PurePosixPath(path).parent)
                parent = "" if parent == "." else parent
                if basename == ".wh..wh..opq":
                    if not member.isfile() or member.size != 0:
                        raise ValidationError("OCI opaque whiteout is not an empty regular file")
                    prefix = parent + "/" if parent else ""
                    for existing in list(filesystem):
                        if existing.startswith(prefix) \
                                and int(filesystem[existing]["layerIndex"]) < layer_index:
                            del filesystem[existing]
                    continue
                if basename.startswith(".wh."):
                    if not member.isfile() or member.size != 0 or basename == ".wh.":
                        raise ValidationError("OCI whiteout is not an exact empty regular file")
                    target_name = basename.removeprefix(".wh.")
                    target = f"{parent}/{target_name}" if parent else target_name
                    for existing in list(filesystem):
                        if existing == target or existing.startswith(target + "/"):
                            del filesystem[existing]
                    continue
                normal_members.append((path, member))
            for path, member in normal_members:
                if not member.isdir():
                    for existing in list(filesystem):
                        if existing.startswith(path + "/"):
                            del filesystem[existing]
                kind = (
                    "file" if member.isfile() else "directory" if member.isdir()
                    else "symlink" if member.issym() else "hardlink"
                )
                entry: dict[str, Any] = {
                    "path": "/" + path,
                    "kind": kind,
                    "mode": member.mode & 0o7777,
                    "uid": member.uid,
                    "gid": member.gid,
                    "layerDigest": layer_digest,
                    "layerIndex": layer_index,
                }
                if member.issym():
                    entry["linkTarget"] = member.linkname
                elif member.islnk():
                    entry["linkTarget"] = "/" + _normalized_rootfs_path(member.linkname)
                filesystem[path] = entry

    def resolve(raw_path: str) -> tuple[str, Mapping[str, Any]]:
        pending = list(PurePosixPath(raw_path.removeprefix("/")).parts)
        resolved: list[str] = []
        hops = 0
        while pending:
            part = pending.pop(0)
            candidate = "/".join((*resolved, part))
            entry = filesystem.get(candidate)
            if entry is not None and entry.get("kind") == "symlink":
                hops += 1
                if hops > 40:
                    raise ValidationError("OCI rootfs symlink chain exceeds the safe bound")
                target = require_text(entry.get("linkTarget"), "OCI symlink target")
                target_path = _normalized_rootfs_path(target, resolved)
                resolved = []
                pending = [*PurePosixPath(target_path).parts, *pending]
            else:
                resolved.append(part)
        final_path = "/".join(resolved)
        entry = filesystem.get(final_path)
        while entry is not None and entry.get("kind") == "hardlink":
            hops += 1
            if hops > 40:
                raise ValidationError("OCI rootfs hardlink chain exceeds the safe bound")
            final_path = _normalized_rootfs_path(
                require_text(entry.get("linkTarget"), "OCI hardlink target")
            )
            entry = filesystem.get(final_path)
        if entry is None:
            raise ValidationError(f"required runtime path is absent after layer merge: {raw_path}")
        return "/" + final_path, entry

    observations: list[dict[str, Any]] = []
    for path in require_list(requirements.get("executables"), "runtime executables"):
        requested = require_text(path, "runtime executable")
        resolved_path, entry = resolve(requested)
        if entry.get("kind") != "file" or not _mode_allows(entry, 0o1):
            raise ValidationError(f"required runtime executable is not executable: {requested}")
        observations.append({
            "path": requested, "resolvedPath": resolved_path, "kind": "executable",
            "mode": entry["mode"], "uid": entry["uid"], "gid": entry["gid"],
            "layerDigest": entry["layerDigest"],
        })
    for path in require_list(requirements.get("files"), "runtime files"):
        requested = require_text(path, "runtime file")
        resolved_path, entry = resolve(requested)
        if entry.get("kind") != "file" or not _mode_allows(entry, 0o4):
            raise ValidationError(f"required runtime file is not readable: {requested}")
        observations.append({
            "path": requested, "resolvedPath": resolved_path, "kind": "readable-file",
            "mode": entry["mode"], "uid": entry["uid"], "gid": entry["gid"],
            "layerDigest": entry["layerDigest"],
        })
    for path in require_list(requirements.get("directories"), "runtime directories"):
        requested = require_text(path, "runtime directory")
        resolved_path, entry = resolve(requested)
        if entry.get("kind") != "directory" or not _mode_allows(entry, 0o5):
            raise ValidationError(f"required runtime directory is not readable: {requested}")
        observations.append({
            "path": requested, "resolvedPath": resolved_path, "kind": "readable-directory",
            "mode": entry["mode"], "uid": entry["uid"], "gid": entry["gid"],
            "layerDigest": entry["layerDigest"],
        })
    for raw_rule in require_list(requirements.get("atLeastOne"), "runtime match rules"):
        rule = require_mapping(raw_rule, "runtime match rule")
        prefix = require_text(rule.get("prefix"), "runtime match prefix")
        suffix = require_text(rule.get("suffix"), "runtime match suffix")
        if rule.get("kind") != "file":
            raise ValidationError("runtime match kind is unsupported")
        matches = []
        for path in sorted(filesystem):
            absolute = "/" + path
            if absolute.startswith(prefix) and absolute.endswith(suffix):
                resolved_path, entry = resolve(absolute)
                if entry.get("kind") == "file" and _mode_allows(entry, 0o4):
                    matches.append(resolved_path)
        if not matches:
            raise ValidationError(f"required runtime file set is empty: {prefix}*{suffix}")
        observations.append({
            "path": prefix + "*" + suffix, "kind": "readable-file-set",
            "matchCount": len(matches), "matchesDigest": sha256_json(matches),
        })
    inventory = [
        {key: value for key, value in filesystem[path].items() if key != "layerIndex"}
        for path in sorted(filesystem)
    ]
    return {
        "schemaVersion": 1,
        "requirements": requirements,
        "observations": observations,
        "mergedFilesystemDigest": sha256_json(inventory),
        "status": "VERIFIED_MERGED_ROOTFS_STATIC",
    }


def _oci_image_digest(
    archive: Path, *, expected_entrypoint: Sequence[str] | None = None,
    runtime_requirements: Mapping[str, Any] | None = None,
) -> tuple[str, Mapping[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor_fd = os.open(archive, flags)
    except OSError as exc:
        raise ValidationError("OCI archive is missing, a symlink or unreadable") from exc
    try:
        with os.fdopen(descriptor_fd, "rb", closefd=True) as raw_archive:
            initial_stat = os.fstat(raw_archive.fileno())
            if not stat.S_ISREG(initial_stat.st_mode) or initial_stat.st_size > MAX_TOTAL_BYTES:
                raise ValidationError("OCI archive is not a bounded regular file")
            with tarfile.open(fileobj=raw_archive, mode="r:*") as bundle:
                members: dict[str, tarfile.TarInfo] = {}
                total = 0
                for position, member in enumerate(bundle.getmembers()):
                    if position >= MAX_FILES:
                        raise ValidationError("OCI archive contains too many entries")
                    name = member.name
                    canonical_name = name.rstrip("/") if member.isdir() else name
                    normalized = PurePosixPath(canonical_name)
                    if not canonical_name or canonical_name.startswith("/") \
                            or ".." in normalized.parts or str(normalized) != canonical_name \
                            or canonical_name in members:
                        raise ValidationError("OCI archive contains duplicate or unsafe paths")
                    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                        raise ValidationError("OCI archive contains a non-regular top-level entry")
                    if not (member.isfile() or member.isdir()):
                        raise ValidationError("OCI archive contains an unsupported entry type")
                    if member.isfile():
                        total += member.size
                        if member.size > MAX_TOTAL_BYTES or total > MAX_TOTAL_BYTES:
                            raise ValidationError("OCI archive content exceeds the bounded size")
                    members[canonical_name] = member

                def read_member(
                    name: str, field: str, maximum: int = MAX_TOTAL_BYTES
                ) -> bytes:
                    member = members.get(name)
                    if member is None or not member.isfile() \
                            or isinstance(member.size, bool) or member.size < 1 \
                            or member.size > maximum:
                        raise ValidationError(f"{field} is missing or has an invalid size")
                    stream = bundle.extractfile(member)
                    if stream is None:
                        raise ValidationError(f"{field} cannot be read")
                    data = stream.read(maximum + 1)
                    if len(data) != member.size or len(data) > maximum:
                        raise ValidationError(f"{field} content size mismatch")
                    return data

                index = require_mapping(
                    _strict_json_bytes(
                        read_member("index.json", "OCI index.json", 1_048_576),
                        "OCI index.json",
                    ),
                    "OCI index",
                )
                if set(index) - {"schemaVersion", "mediaType", "manifests", "annotations"} \
                        or index.get("schemaVersion") != 2 \
                        or index.get("mediaType") \
                        != "application/vnd.oci.image.index.v1+json":
                    raise ValidationError("OCI index schema/media type is invalid")
                layout = require_mapping(
                    _strict_json_bytes(
                        read_member("oci-layout", "OCI layout", 4096), "OCI layout"
                    ),
                    "OCI layout",
                )
                if layout != {"imageLayoutVersion": "1.0.0"}:
                    raise ValidationError("OCI archive layout version is invalid")
                manifests = require_list(index.get("manifests"), "OCI manifests")
                if len(manifests) != 1:
                    raise ValidationError("OCI archive must contain exactly one runnable manifest")
                image_descriptor = require_mapping(manifests[0], "OCI manifest descriptor")
                if set(image_descriptor) - {"mediaType", "digest", "size", "platform", "annotations"} \
                        or image_descriptor.get("mediaType") \
                        != "application/vnd.oci.image.manifest.v1+json":
                    raise ValidationError("OCI manifest descriptor media type/shape is invalid")
                platform = require_mapping(
                    image_descriptor.get("platform"), "OCI manifest platform"
                )
                if platform != {"architecture": "amd64", "os": "linux"}:
                    raise ValidationError("OCI archive platform is not exact linux/amd64")

                def validate_annotations(value: Mapping[str, Any], field: str) -> None:
                    if "annotations" not in value:
                        return
                    annotations = require_mapping(value.get("annotations"), f"{field}.annotations")
                    if any(not isinstance(key, str) or not isinstance(item, str)
                           for key, item in annotations.items()):
                        raise ValidationError(f"{field} annotations must be exact text pairs")

                def descriptor_blob(
                    value: Mapping[str, Any], field: str, media_type: str, maximum: int
                ) -> tuple[str, bytes]:
                    if set(value) - {"mediaType", "digest", "size", "annotations"} \
                            or value.get("mediaType") != media_type:
                        raise ValidationError(f"{field} media type/shape is invalid")
                    validate_annotations(value, field)
                    size_value = value.get("size")
                    if isinstance(size_value, bool) or not isinstance(size_value, int) \
                            or size_value < 1 or size_value > maximum:
                        raise ValidationError(f"{field} descriptor size is invalid")
                    value_digest = require_text(value.get("digest"), f"{field}.digest")
                    if not value_digest.startswith("sha256:") \
                            or not DIGEST.fullmatch(value_digest.removeprefix("sha256:")):
                        raise ValidationError(f"{field} digest is invalid")
                    hex_digest = value_digest.removeprefix("sha256:")
                    data = read_member(f"blobs/sha256/{hex_digest}", f"{field} blob", maximum)
                    if hashlib.sha256(data).hexdigest() != hex_digest \
                            or size_value != len(data):
                        raise ValidationError(f"{field} digest/size mismatch")
                    return hex_digest, data

                validate_annotations(index, "OCI index")
                validate_annotations(image_descriptor, "OCI manifest descriptor")
                descriptor_size = image_descriptor.get("size")
                if isinstance(descriptor_size, bool) or not isinstance(descriptor_size, int) \
                        or descriptor_size < 1 or descriptor_size > 16 * 1024 * 1024:
                    raise ValidationError("OCI manifest descriptor size is invalid")
                manifest_digest_text = require_text(
                    image_descriptor.get("digest"), "OCI manifest digest"
                )
                if not manifest_digest_text.startswith("sha256:") \
                        or not DIGEST.fullmatch(
                            manifest_digest_text.removeprefix("sha256:")
                        ):
                    raise ValidationError("OCI manifest digest is invalid")
                manifest_digest = manifest_digest_text.removeprefix("sha256:")
                manifest_bytes = read_member(
                    f"blobs/sha256/{manifest_digest}", "OCI manifest blob",
                    16 * 1024 * 1024,
                )
                if hashlib.sha256(manifest_bytes).hexdigest() != manifest_digest \
                        or descriptor_size != len(manifest_bytes):
                    raise ValidationError("OCI manifest descriptor digest/size mismatch")
                manifest = require_mapping(
                    _strict_json_bytes(manifest_bytes, "OCI manifest"), "OCI manifest"
                )
                if set(manifest) - {"schemaVersion", "mediaType", "config", "layers", "annotations"} \
                        or manifest.get("schemaVersion") != 2 \
                        or manifest.get("mediaType") \
                        != "application/vnd.oci.image.manifest.v1+json":
                    raise ValidationError("OCI manifest schema/media type is invalid")
                validate_annotations(manifest, "OCI manifest")
                config = require_mapping(manifest.get("config"), "OCI config descriptor")
                layers = [
                    require_mapping(value, "OCI layer descriptor")
                    for value in require_list(manifest.get("layers"), "OCI layers")
                ]
                if not layers:
                    raise ValidationError("OCI image has no filesystem layers")
                config_digest, config_bytes = descriptor_blob(
                    config, "OCI config", "application/vnd.oci.image.config.v1+json",
                    16 * 1024 * 1024,
                )
                layer_blobs = [
                    descriptor_blob(
                        layer, f"OCI layer[{position}]",
                        "application/vnd.oci.image.layer.v1.tar+gzip", MAX_FILE_BYTES,
                    )
                    for position, layer in enumerate(layers)
                ]
                image_config = require_mapping(
                    _strict_json_bytes(config_bytes, "OCI config"), "OCI config"
                )
                runtime = require_mapping(image_config.get("config"), "OCI runtime config")
                rootfs = require_mapping(image_config.get("rootfs"), "OCI rootfs")
                diff_ids = require_list(rootfs.get("diff_ids"), "OCI rootfs.diff_ids")
                if image_config.get("os") != "linux" \
                        or image_config.get("architecture") != "amd64" \
                        or runtime.get("User") != "10001:10001" \
                        or rootfs.get("type") != "layers" \
                        or len(diff_ids) != len(layer_blobs):
                    raise ValidationError("OCI config platform/user/rootfs binding is invalid")
                if expected_entrypoint is not None \
                        and runtime.get("Entrypoint") != list(expected_entrypoint):
                    raise ValidationError(
                        "OCI config entrypoint differs from the product manifest"
                    )
                for position, ((_, layer_bytes), diff_id) in enumerate(
                    zip(layer_blobs, diff_ids, strict=True)
                ):
                    expected_diff = require_text(diff_id, f"OCI diff_id[{position}]")
                    _validate_layer_tar(layer_bytes, f"OCI layer[{position}]")
                    actual_diff = _layer_diff_id(layer_bytes, f"OCI layer[{position}]")
                    if expected_diff != f"sha256:{actual_diff}":
                        raise ValidationError("OCI layer uncompressed diff-id mismatch")
                expected_files = {
                    "index.json", "oci-layout", f"blobs/sha256/{manifest_digest}",
                    f"blobs/sha256/{config_digest}",
                    *(f"blobs/sha256/{digest_value}" for digest_value, _ in layer_blobs),
                }
                actual_files = {
                    name for name, member in members.items() if member.isfile()
                }
                actual_directories = {
                    name for name, member in members.items() if member.isdir()
                }
                if actual_files != expected_files \
                        or actual_directories - {"blobs", "blobs/sha256"}:
                    raise ValidationError(
                        "OCI archive contains missing, unreferenced or non-sha256 content"
                    )
            final_stat = os.fstat(raw_archive.fileno())
            if (
                final_stat.st_dev, final_stat.st_ino, final_stat.st_size,
                final_stat.st_mtime_ns, final_stat.st_ctime_ns,
            ) != (
                initial_stat.st_dev, initial_stat.st_ino, initial_stat.st_size,
                initial_stat.st_mtime_ns, initial_stat.st_ctime_ns,
            ):
                raise ValidationError("OCI archive changed while its descriptor chain was read")
            if runtime_requirements is None:
                raise ValidationError("OCI runtime filesystem requirements are missing")
            inspection = _merged_rootfs_inspection(layer_blobs, runtime_requirements)
            return manifest_digest, {
                **inspection,
                "imageDigest": manifest_digest,
                "layerDigests": [digest_value for digest_value, _ in layer_blobs],
            }
    except (tarfile.TarError, EOFError) as exc:
        raise ValidationError("OCI archive is not a complete valid tar layout") from exc


def _application_inventory(name: str, image_digest: str, base_image: str,
                           entries: list[dict[str, Any]]) -> dict[str, Any]:
    serial_seed = hashlib.sha256(f"{name}:{image_digest}".encode()).hexdigest()
    components = [{
        "type": "file",
        "bom-ref": f"file:{entry['sha256']}:{entry['path']}",
        "name": entry["path"],
        "hashes": [{"alg": "SHA-256", "content": entry["sha256"]}],
        "properties": [
            {"name": "elmpay:file-size", "value": str(entry["size"])},
            {"name": "elmpay:file-mode", "value": oct(entry["mode"])},
        ],
    } for entry in entries]
    subject = f"pkg:oci/{name}@sha256:{image_digest}"
    base_digest = base_image.rsplit("@sha256:", 1)[1]
    base_ref = f"pkg:oci/base@sha256:{base_digest}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial_seed[:8]}-{serial_seed[8:12]}-4{serial_seed[13:16]}-a{serial_seed[17:20]}-{serial_seed[20:32]}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "container",
                "bom-ref": subject,
                "name": name,
                "version": f"sha256:{image_digest}",
                "hashes": [{"alg": "SHA-256", "content": image_digest}],
                "properties": [
                    {"name": "elmpay:base-image", "value": base_image},
                    {"name": "elmpay:coverage", "value": "partial-application-files-only"},
                    {"name": "elmpay:not-a-full-image-sbom", "value": "true"},
                ],
            }
        },
        "components": [
            {
                "type": "container", "bom-ref": base_ref, "name": "base-image",
                "version": f"sha256:{base_digest}",
                "hashes": [{"alg": "SHA-256", "content": base_digest}],
            },
            *components,
        ],
        "dependencies": [{"ref": subject, "dependsOn": [base_ref, *[
            component["bom-ref"] for component in components
        ]]}],
    }


def _validate_application_inventory(
    document: Mapping[str, Any], name: str, image_digest: str, base_image: str
) -> None:
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise ValidationError(f"{name} application inventory format is invalid")
    metadata = require_mapping(document.get("metadata"), f"{name} inventory metadata")
    subject = require_mapping(metadata.get("component"), f"{name} inventory subject")
    properties = {
        value.get("name"): value.get("value")
        for value in (
            require_mapping(raw, f"{name} inventory property")
            for raw in require_list(subject.get("properties"), f"{name} inventory properties")
        )
    }
    expected_ref = f"pkg:oci/{name}@sha256:{image_digest}"
    if subject.get("type") != "container" or subject.get("bom-ref") != expected_ref \
            or subject.get("name") != name or subject.get("version") != f"sha256:{image_digest}" \
            or properties != {
                "elmpay:base-image": base_image,
                "elmpay:coverage": "partial-application-files-only",
                "elmpay:not-a-full-image-sbom": "true",
            }:
        raise ValidationError(f"{name} partial application inventory is mislabeled or unbound")


def _validate_artifact_manifest(
    document: Mapping[str, Any],
    product_manifest: Mapping[str, Any],
    build: Mapping[str, Any],
) -> None:
    if set(document) != {
        "schemaVersion", "productImageManifestDigest", "contextPolicy", "images"
    } \
            or document.get("schemaVersion") != 1 \
            or document.get("productImageManifestDigest") \
            != build.get("productImageManifestDigest") \
            or sha256_json(document) != build.get("artifactDigest"):
        raise ValidationError("canonical aggregate artifact manifest binding is invalid")
    context_policy = require_mapping(document.get("contextPolicy"), "artifact context policy")
    governed_context = require_mapping(
        product_manifest.get("contextPolicy"), "product context policy"
    )
    if context_policy != {
        "path": governed_context.get("dockerignore"),
        "sha256": governed_context.get("dockerignoreDigest"),
    }:
        raise ValidationError("aggregate artifact context allowlist binding is invalid")
    materials = [
        require_mapping(value, "artifact manifest image")
        for value in require_list(document.get("images"), "artifact manifest images")
    ]
    planned = [
        require_mapping(value, "planned image")
        for value in require_list(product_manifest.get("images"), "planned images")
    ]
    built = {
        require_text(value.get("name"), "build image.name"): value
        for value in (
            require_mapping(raw, "build image")
            for raw in require_list(build.get("images"), "build images")
        )
    }
    if [value.get("name") for value in materials] != [value.get("name") for value in planned]:
        raise ValidationError("aggregate artifact image inventory/order differs from the product manifest")
    for material, image in zip(materials, planned, strict=True):
        if set(material) != {"name", "includedFiles", "containerfile", "runtimeInputs"}:
            raise ValidationError("aggregate artifact image shape is invalid")
        name = require_text(material.get("name"), "artifact image.name")
        entries = [
            require_mapping(value, f"{name} artifact file")
            for value in require_list(material.get("includedFiles"), f"{name} included files")
        ]
        paths: list[str] = []
        for entry in entries:
            if set(entry) != {"path", "sha256", "size", "mode"}:
                raise ValidationError(f"{name} artifact file shape is invalid")
            path = require_text(entry.get("path"), f"{name} artifact path")
            digest = entry.get("sha256")
            if Path(path).is_absolute() or ".." in Path(path).parts \
                    or not isinstance(digest, str) or not DIGEST.fullmatch(digest) \
                    or isinstance(entry.get("size"), bool) or not isinstance(entry.get("size"), int) \
                    or int(entry["size"]) < 0 \
                    or isinstance(entry.get("mode"), bool) or not isinstance(entry.get("mode"), int):
                raise ValidationError(f"{name} artifact file binding is invalid")
            paths.append(path)
        if not entries or paths != sorted(paths) or len(paths) != len(set(paths)) \
                or sha256_json(entries) != built[name].get("artifactDigest"):
            raise ValidationError(f"{name} artifact file inventory/digest is invalid")
        containerfile = require_mapping(material.get("containerfile"), f"{name} containerfile")
        if containerfile != {
            "path": image.get("containerfile"),
            "sha256": built[name].get("containerfileDigest"),
        }:
            raise ValidationError(f"{name} containerfile is not aggregate-artifact-bound")
        runtime_inputs = require_list(material.get("runtimeInputs"), f"{name} runtime inputs")
        expected_runtime = [] if image.get("kind") != "java-install-dist" else [{
            "path": "platform/oci/java-main",
            "sha256": CANONICAL_JAVA_LAUNCHER_DIGEST,
        }]
        if runtime_inputs != expected_runtime:
            raise ValidationError(f"{name} runtime build inputs are not exact")


def _validate_provenance(
    document: Mapping[str, Any],
    manifest: Mapping[str, Any],
    build: Mapping[str, Any],
    image: Mapping[str, Any],
    planned: Mapping[str, Any],
) -> None:
    name = require_text(image.get("name"), "build image.name")
    definition = require_mapping(document.get("buildDefinition"), f"{name} provenance buildDefinition")
    details = require_mapping(document.get("runDetails"), f"{name} provenance runDetails")
    if set(document) != {"buildDefinition", "runDetails"} \
            or set(definition) != {"buildType", "externalParameters", "resolvedDependencies"} \
            or definition.get("buildType") \
            != "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1":
        raise ValidationError(f"{name} provenance shape/build type is invalid")
    expected_parameters = {
        "targetPlatform": build["targetPlatform"],
        "sourceCommit": build["sourceCommit"],
        "sourceDateEpoch": build["sourceDateEpoch"],
        "aggregateArtifactDigest": build["artifactDigest"],
        "buildTool": build["buildTool"],
    }
    if definition.get("externalParameters") != expected_parameters:
        raise ValidationError(f"{name} provenance build inputs differ from the build index")
    expected_dependencies = [
        {"uri": "git+https://github.com/zpcaiai/elmpay",
         "digest": {"gitCommit": build["sourceCommit"]}},
        {"uri": image["baseImage"],
         "digest": {"sha256": str(image["baseImage"]).rsplit("@sha256:", 1)[1]}},
        {"uri": str(PRODUCT_MANIFEST_PATH),
         "digest": {"sha256": build["productImageManifestDigest"]}},
        {"uri": str(manifest["contextPolicy"]["dockerignore"]),
         "digest": {"sha256": manifest["contextPolicy"]["dockerignoreDigest"]}},
        {"uri": str(planned["containerfile"]),
         "digest": {"sha256": image["containerfileDigest"]}},
        {"uri": f"artifact:{name}", "digest": {"sha256": image["artifactDigest"]}},
        {"uri": f"runtime-filesystem-inspection:{name}",
         "digest": {"sha256": image["runtimeInspectionDigest"]}},
        {"uri": "artifact:elmpay-product-tree",
         "digest": {"sha256": build["artifactDigest"]}},
        {"uri": f"pkg:generic/docker-buildx@{build['buildTool']['version']}",
         "digest": {"sha256": build["buildTool"]["executableDigest"]}},
    ]
    if definition.get("resolvedDependencies") != expected_dependencies:
        raise ValidationError(f"{name} provenance resolved dependencies are not exact")
    if set(details) != {"builder", "metadata"} \
            or details.get("builder") != {
                "id": "https://github.com/zpcaiai/elmpay/.github/workflows/ci.yml"
            } \
            or details.get("metadata") != {
                "invocationId": f"urn:elmpay:{build['sourceCommit']}:{name}"
            }:
        raise ValidationError(f"{name} provenance builder/invocation binding is invalid")


def command_source_gate(_args: argparse.Namespace) -> int:
    manifest, _workloads, admission = _documents()
    print(json.dumps({
        "allowed": True,
        "status": "SOURCE_VALIDATED_EXECUTION_NOT_RUN",
        "productImageManifestDigest": product_image_manifest_digest(manifest),
        "admissionPolicyDigest": admission_policy_digest(admission),
        "imageCount": len(require_list(manifest.get("images"), "images")),
        "certificationStatus": "NOT_CERTIFIED",
    }, sort_keys=True, separators=(",", ":")))
    return 0


def command_build(args: argparse.Namespace) -> int:
    manifest, _workloads, admission = _documents()
    if COMMIT.fullmatch(args.source_commit) is None or DIGEST.fullmatch(args.artifact_digest) is None:
        raise ValidationError("build requires exact source commit and aggregate artifact digest")
    if args.artifact_digest == "0" * 64:
        raise ValidationError("aggregate artifact digest cannot be the placeholder digest")
    if args.source_date_epoch < 1:
        raise ValidationError("SOURCE_DATE_EPOCH must be a positive integer")
    bases = resolve_base_images(manifest, os.environ)
    engine = require_mapping(manifest.get("buildEngine"), "buildEngine")
    build_tool_version = require_text(
        os.environ.get(str(engine["versionInputEnvironment"])), "buildx version input"
    )
    build_tool_digest = require_text(
        os.environ.get(str(engine["executableDigestInputEnvironment"])),
        "docker digest input",
    )
    docker = _verified_tool(
        "docker",
        build_tool_version,
        build_tool_digest,
    )
    out = args.out.resolve()
    build_root = (ROOT / "build").resolve()
    if out == build_root or build_root not in out.parents or out.exists() or out.is_symlink():
        raise ValidationError("build output must be a new directory beneath build/")
    out.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="product-images.", dir=out.parent))
    plan_digest = product_image_manifest_digest(manifest)
    try:
        images = [require_mapping(value, "image") for value in require_list(manifest["images"], "images")]
        prepared: set[tuple[str, ...]] = set()
        build_environment = _safe_environment({"SOURCE_DATE_EPOCH": str(args.source_date_epoch)})
        for image in images:
            command = tuple(require_text(value, "prepare command") for value in require_list(
                image.get("prepareCommand"), "prepareCommand"
            ))
            if command and command not in prepared:
                _run(command, environment=build_environment)
                prepared.add(command)

        prepared_images: dict[str, dict[str, Any]] = {}
        artifact_images: list[dict[str, Any]] = []
        launcher_path = Path("platform/oci/java-main")
        launcher_digest = CANONICAL_JAVA_LAUNCHER_DIGEST
        for image in images:
            name = require_text(image.get("name"), "image.name")
            included = [
                _safe_relative(value, f"{name}.includedPaths")
                for value in require_list(image.get("includedPaths"), f"{name}.includedPaths")
            ]
            entries = _tree_entries(included)
            containerfile = _safe_relative(image.get("containerfile"), f"{name}.containerfile")
            containerfile_digest = require_text(
                image.get("containerfileContractDigest"),
                f"{name}.containerfileContractDigest",
            )
            runtime_inputs = []
            if image.get("kind") == "java-install-dist":
                runtime_inputs.append({"path": str(launcher_path), "sha256": launcher_digest})
            material = {
                "name": name,
                "includedFiles": entries,
                "containerfile": {"path": str(containerfile), "sha256": containerfile_digest},
                "runtimeInputs": runtime_inputs,
            }
            artifact_images.append(material)
            prepared_images[name] = {
                "entries": entries,
                "artifactDigest": sha256_json(entries),
                "containerfile": containerfile,
                "containerfileDigest": containerfile_digest,
            }
        artifact_manifest = {
            "schemaVersion": 1,
            "productImageManifestDigest": plan_digest,
            "contextPolicy": {
                "path": manifest["contextPolicy"]["dockerignore"],
                "sha256": manifest["contextPolicy"]["dockerignoreDigest"],
            },
            "images": artifact_images,
        }
        calculated_artifact_digest = sha256_json(artifact_manifest)
        if calculated_artifact_digest != args.artifact_digest:
            raise ValidationError(
                "supplied aggregate artifact digest differs from the canonical product tree"
            )
        artifact_manifest_path = work / "artifact-manifest.json"
        _write_json(artifact_manifest_path, artifact_manifest)
        context_root = work / ".exact-build-context"
        context_sources = _snapshot_build_context(artifact_manifest, context_root)

        result_images: list[dict[str, Any]] = []
        for image in images:
            name = require_text(image.get("name"), "image.name")
            prepared_image = prepared_images[name]
            entries = prepared_image["entries"]
            artifact_digest = prepared_image["artifactDigest"]
            containerfile = prepared_image["containerfile"]
            containerfile_digest = prepared_image["containerfileDigest"]
            base = bases[require_text(image.get("baseImage"), f"{name}.baseImage")]
            archive = work / "oci" / f"{name}.tar"
            archive.parent.mkdir(parents=True, exist_ok=True)
            _validate_build_context_snapshot(context_root, context_sources)
            context_containerfile = context_root / containerfile
            build_command = [
                docker, "buildx", "build", "--progress=plain", "--network=none",
                "--platform", str(manifest["targetPlatform"]), "--provenance=false", "--sbom=false",
                "--file", str(context_containerfile), "--build-arg", f"BASE_IMAGE={base}",
                "--build-arg", f"SOURCE_COMMIT={args.source_commit}",
                "--build-arg", f"SOURCE_DATE_EPOCH={args.source_date_epoch}",
                "--build-arg", f"PRODUCT_IMAGE_MANIFEST_DIGEST={plan_digest}",
            ]
            if image.get("kind") == "java-install-dist":
                build_command += [
                    "--build-arg", f"APP_DIRECTORY={image['artifactPath']}",
                    "--build-arg", f"MAIN_CLASS_FILE={image['mainClassFile']}",
                    "--build-arg", f"MAIN_CLASS_ALLOWLIST={image['mainClassAllowlist']}",
                ]
            build_command += [
                "--output", f"type=oci,dest={archive},compression=gzip,force-compression=true",
                str(context_root),
            ]
            _run(build_command, environment=build_environment)
            _validate_build_context_snapshot(context_root, context_sources)
            image_digest, runtime_inspection = _oci_image_digest(
                archive, expected_entrypoint=_expected_image_entrypoint(image),
                runtime_requirements=_runtime_requirements(manifest, image),
            )
            reference = f"{manifest['registry']}/{name}@sha256:{image_digest}"
            runtime_inspection_path = work / "runtime-inspection" / f"{name}.json"
            _write_json(runtime_inspection_path, runtime_inspection)
            runtime_inspection_digest = _sha256(runtime_inspection_path)
            inventory = _application_inventory(name, image_digest, base, entries)
            inventory_path = work / "application-inventory" / f"{name}.cdx.json"
            _write_json(inventory_path, inventory)
            predicate = {
                "buildDefinition": {
                    "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
                    "externalParameters": {
                        "targetPlatform": manifest["targetPlatform"],
                        "sourceCommit": args.source_commit,
                        "sourceDateEpoch": args.source_date_epoch,
                        "aggregateArtifactDigest": calculated_artifact_digest,
                        "buildTool": {
                            "name": "docker-buildx", "version": build_tool_version,
                            "executableDigest": build_tool_digest,
                        },
                    },
                    "resolvedDependencies": [
                        {"uri": "git+https://github.com/zpcaiai/elmpay", "digest": {"gitCommit": args.source_commit}},
                        {"uri": base, "digest": {"sha256": base.rsplit("@sha256:", 1)[1]}},
                        {"uri": str(PRODUCT_MANIFEST_PATH), "digest": {"sha256": plan_digest}},
                        {"uri": str(manifest["contextPolicy"]["dockerignore"]),
                         "digest": {"sha256": manifest["contextPolicy"]["dockerignoreDigest"]}},
                        {"uri": str(containerfile), "digest": {"sha256": containerfile_digest}},
                        {"uri": f"artifact:{name}", "digest": {"sha256": artifact_digest}},
                        {"uri": f"runtime-filesystem-inspection:{name}",
                         "digest": {"sha256": runtime_inspection_digest}},
                        {"uri": "artifact:elmpay-product-tree",
                         "digest": {"sha256": calculated_artifact_digest}},
                        {"uri": f"pkg:generic/docker-buildx@{build_tool_version}",
                         "digest": {"sha256": build_tool_digest}},
                    ],
                },
                "runDetails": {
                    "builder": {"id": "https://github.com/zpcaiai/elmpay/.github/workflows/ci.yml"},
                    "metadata": {"invocationId": f"urn:elmpay:{args.source_commit}:{name}"},
                },
            }
            provenance_path = work / "provenance" / f"{name}.slsa.json"
            _write_json(provenance_path, predicate)
            result_images.append({
                "name": name,
                "reference": reference,
                "imageDigest": image_digest,
                "baseImage": base,
                "archive": str(archive.relative_to(work)),
                "archiveDigest": _sha256(archive),
                "artifactDigest": artifact_digest,
                "containerfileDigest": containerfile_digest,
                "runtimeInspection": str(runtime_inspection_path.relative_to(work)),
                "runtimeInspectionDigest": runtime_inspection_digest,
                "applicationInventory": str(inventory_path.relative_to(work)),
                "applicationInventoryDigest": _sha256(inventory_path),
                "provenance": str(provenance_path.relative_to(work)),
                "provenanceDigest": _sha256(provenance_path),
                "status": "BUILT_APPLICATION_INVENTORY_PROVENANCE_SCAN_SIGN_NOT_RUN",
            })
        _validate_build_context_snapshot(context_root, context_sources)
        shutil.rmtree(context_root)
        build_index = {
            "schemaVersion": 1,
            "productImageManifestDigest": plan_digest,
            "admissionPolicyDigest": admission_policy_digest(admission),
            "sourceCommit": args.source_commit,
            "artifactDigest": args.artifact_digest,
            "artifactManifest": str(artifact_manifest_path.relative_to(work)),
            "artifactManifestDigest": _sha256(artifact_manifest_path),
            "sourceDateEpoch": args.source_date_epoch,
            "targetPlatform": manifest["targetPlatform"],
            "buildTool": {
                "name": "docker-buildx", "version": build_tool_version,
                "executableDigest": build_tool_digest,
            },
            "images": result_images,
            "status": "BUILT_SCAN_SIGN_NOT_RUN",
        }
        _write_json(work / "build-index.json", build_index)
        work.replace(out)
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise
    print(json.dumps({
        "allowed": True, "status": "BUILT_SCAN_SIGN_NOT_RUN",
        "buildIndex": str(out / "build-index.json"), "certificationStatus": "NOT_CERTIFIED",
    }, sort_keys=True, separators=(",", ":")))
    return 0


def _load_build_index(path: Path) -> Mapping[str, Any]:
    path = _regular_evidence_file(path, "product build index")
    index = require_mapping(read_json(path), "product build index")
    if index.get("schemaVersion") != 1 or index.get("status") != "BUILT_SCAN_SIGN_NOT_RUN":
        raise ValidationError("product build index is missing or unresolved")
    manifest, _workloads, admission = _documents()
    if set(index) != {
        "schemaVersion", "productImageManifestDigest", "admissionPolicyDigest",
        "sourceCommit", "artifactDigest", "artifactManifest", "artifactManifestDigest",
        "sourceDateEpoch", "targetPlatform",
        "buildTool", "images", "status",
    }:
        raise ValidationError("product build index has unknown or missing fields")
    if index.get("productImageManifestDigest") != product_image_manifest_digest(manifest) \
            or index.get("admissionPolicyDigest") != admission_policy_digest(admission):
        raise ValidationError("product build index policy binding mismatch")
    build_tool = require_mapping(index.get("buildTool"), "product build tool")
    if build_tool.get("name") != "docker-buildx" \
            or not isinstance(build_tool.get("version"), str) \
            or not str(build_tool["version"]).strip() \
            or not isinstance(build_tool.get("executableDigest"), str) \
            or not DIGEST.fullmatch(str(build_tool["executableDigest"])) \
            or build_tool.get("executableDigest") == "0" * 64:
        raise ValidationError("product build tool evidence is invalid")
    if not isinstance(index.get("sourceCommit"), str) \
            or COMMIT.fullmatch(str(index["sourceCommit"])) is None \
            or not isinstance(index.get("artifactDigest"), str) \
            or DIGEST.fullmatch(str(index["artifactDigest"])) is None \
            or index.get("artifactDigest") == "0" * 64 \
            or isinstance(index.get("sourceDateEpoch"), bool) \
            or not isinstance(index.get("sourceDateEpoch"), int) \
            or int(index["sourceDateEpoch"]) < 1 \
            or index.get("targetPlatform") != manifest.get("targetPlatform"):
        raise ValidationError("product build source/artifact/time/platform binding is invalid")
    artifact_manifest_path = _bound_evidence_file(
        path.parent.resolve(strict=True), index.get("artifactManifest"),
        "aggregate artifact manifest", index.get("artifactManifestDigest"),
    )
    _validate_artifact_manifest(
        require_mapping(read_json(artifact_manifest_path), "aggregate artifact manifest"),
        manifest, index,
    )
    root = path.parent.resolve(strict=True)
    planned_images = [
        require_mapping(value, "planned product image")
        for value in require_list(manifest.get("images"), "planned product images")
    ]
    build_images = [
        require_mapping(value, "build image")
        for value in require_list(index.get("images"), "build images")
    ]
    if [value.get("name") for value in build_images] != [
        value.get("name") for value in planned_images
    ]:
        raise ValidationError("product build image inventory/order differs from the manifest")
    for raw, planned in zip(build_images, planned_images, strict=True):
        image = require_mapping(raw, "build image")
        if set(image) != {
            "name", "reference", "imageDigest", "baseImage", "archive", "archiveDigest",
            "artifactDigest", "containerfileDigest", "applicationInventory",
            "applicationInventoryDigest", "runtimeInspection", "runtimeInspectionDigest",
            "provenance", "provenanceDigest", "status",
        } or image.get("status") != "BUILT_APPLICATION_INVENTORY_PROVENANCE_SCAN_SIGN_NOT_RUN":
            raise ValidationError("product build image evidence shape/status is invalid")
        name = require_text(image.get("name"), "build image.name")
        image_digest = require_text(image.get("imageDigest"), f"{name}.imageDigest")
        if not DIGEST.fullmatch(image_digest) or image_digest == "0" * 64 \
                or image.get("reference") != f"{manifest['registry']}/{name}@sha256:{image_digest}" \
                or not isinstance(image.get("baseImage"), str) \
                or OCI_IMAGE.fullmatch(str(image["baseImage"])) is None \
                or str(image["baseImage"]).endswith("0" * 64):
            raise ValidationError(f"{name} build image subject/base binding is invalid")
        for digest_field in (
            "archiveDigest", "artifactDigest", "containerfileDigest",
            "applicationInventoryDigest", "runtimeInspectionDigest", "provenanceDigest",
        ):
            digest_value = image.get(digest_field)
            if not isinstance(digest_value, str) or not DIGEST.fullmatch(digest_value) \
                    or digest_value == "0" * 64:
                raise ValidationError(f"{name} {digest_field} is invalid")
        for field, digest_field in (
            ("archive", "archiveDigest"),
            ("applicationInventory", "applicationInventoryDigest"),
            ("runtimeInspection", "runtimeInspectionDigest"),
            ("provenance", "provenanceDigest"),
        ):
            _bound_evidence_file(
                root, image.get(field), f"build image.{field}",
                image.get(digest_field),
            )
        archive = _bound_evidence_file(
            root, image.get("archive"), f"{name} OCI archive",
            image.get("archiveDigest"),
        )
        observed_digest, observed_inspection = _oci_image_digest(
            archive, expected_entrypoint=_expected_image_entrypoint(planned),
            runtime_requirements=_runtime_requirements(manifest, planned),
        )
        if observed_digest != image.get("imageDigest"):
            raise ValidationError("product OCI archive subject changed after build")
        inspection = _bound_evidence_file(
            root, image.get("runtimeInspection"), f"{name} runtime inspection",
            image.get("runtimeInspectionDigest"),
        )
        if require_mapping(read_json(inspection), f"{name} runtime inspection") \
                != observed_inspection:
            raise ValidationError("product OCI merged-rootfs inspection changed after build")
        provenance = _bound_evidence_file(
            root, image.get("provenance"), f"{name} provenance", image.get("provenanceDigest")
        )
        _validate_provenance(
            require_mapping(read_json(provenance), f"{name} provenance"),
            manifest, index, image, planned,
        )
        inventory = _bound_evidence_file(
            root, image.get("applicationInventory"), f"{name} application inventory",
            image.get("applicationInventoryDigest"),
        )
        _validate_application_inventory(
            require_mapping(read_json(inventory), f"{name} application inventory"),
            name, image_digest, require_text(image.get("baseImage"), "baseImage"),
        )
    return index


def command_scan(args: argparse.Namespace) -> int:
    manifest, _workloads, _admission = _documents()
    build_index_path = _regular_evidence_file(args.build_index, "product build index")
    build_root = build_index_path.parent
    index = _load_build_index(build_index_path)
    tool = require_mapping(require_mapping(manifest.get("evidence"), "evidence").get("scanTool"), "scanTool")
    scanner_version = require_text(
        os.environ.get(str(tool["versionInputEnvironment"])), "Trivy version input"
    )
    scanner_digest = require_text(
        os.environ.get(str(tool["executableDigestInputEnvironment"])), "Trivy digest input"
    )
    trivy = _verified_tool(
        "trivy",
        scanner_version,
        scanner_digest,
    )
    cache_input = Path(require_text(
        os.environ.get(str(tool["cacheDirectoryEnvironment"])), "Trivy cache input"
    ))
    if cache_input.is_symlink() or not cache_input.is_dir():
        raise ValidationError("Trivy cache must be a regular non-symlink directory")
    cache = cache_input.resolve(strict=True)
    expected_database = require_text(os.environ.get(str(tool["databaseDigestInputEnvironment"])), "Trivy DB digest input")
    if not DIGEST.fullmatch(expected_database) or expected_database == "0" * 64 \
            or _directory_digest(cache) != expected_database:
        raise ValidationError("Trivy database digest does not match the release input")
    out = args.out.resolve()
    if out.exists() or out.is_symlink() or out.parent != build_root:
        raise ValidationError("scan index must be a new sibling of the build index")
    reports = out.parent / "scan"
    scan_sources = out.parent / "scan-sources"
    if reports.exists() or reports.is_symlink() \
            or scan_sources.exists() or scan_sources.is_symlink():
        raise ValidationError("stale product image scan directory or snapshot exists")
    reports.mkdir()
    scan_sources.mkdir()
    results: list[dict[str, Any]] = []
    environment = _safe_environment({
        "TRIVY_CACHE_DIR": str(cache), "TRIVY_SKIP_DB_UPDATE": "true",
        "TRIVY_SKIP_JAVA_DB_UPDATE": "true",
    })
    planned_images = {
        require_text(value.get("name"), "product image.name"): value
        for value in (
            require_mapping(raw, "product image")
            for raw in require_list(manifest.get("images"), "product images")
        )
    }
    scan_archives: dict[str, Path] = {}
    # Materialize and validate all immutable scan inputs before Trivy runs.
    # Publication later consumes these same digest-bound bytes, never a live
    # build output that could have changed after analysis.
    for raw in require_list(index.get("images"), "build images"):
        image = require_mapping(raw, "build image")
        name = require_text(image.get("name"), "image.name")
        source = _bound_evidence_file(
            build_root, image.get("archive"), f"{name} OCI archive",
            image.get("archiveDigest"),
        )
        snapshot = scan_sources / f"{name}.tar"
        _snapshot_regular_file(source, snapshot, str(image["archiveDigest"]))
        image_digest, _inspection = _oci_image_digest(
            snapshot, expected_entrypoint=_expected_image_entrypoint(planned_images[name]),
            runtime_requirements=_runtime_requirements(manifest, planned_images[name]),
        )
        if image_digest != image.get("imageDigest"):
            raise ValidationError(f"{name} scan snapshot has the wrong OCI subject")
        scan_archives[name] = snapshot
    _fsync_directory(scan_sources)
    for raw in require_list(index.get("images"), "build images"):
        image = require_mapping(raw, "build image")
        name = require_text(image.get("name"), "image.name")
        raw_report = reports / f"{name}.trivy.json"
        report = reports / f"{name}.image-scan.json"
        raw_sbom = reports / f"{name}.trivy.cdx.json"
        bound_sbom = reports / f"{name}.image.cdx.json"
        archive = _bound_evidence_file(
            build_root, scan_archives[name].relative_to(build_root),
            f"{name} exact scan archive", image.get("archiveDigest")
        )
        completed = _run([
            trivy, "image", "--input", str(archive), "--format", "json", "--output", str(raw_report),
            "--skip-db-update", "--skip-java-db-update", "--exit-code", "1",
            "--severity", "HIGH,CRITICAL",
        ], environment=environment, stdout=subprocess.DEVNULL, timeout=1800, check=False)
        if completed.returncode != 0:
            raise ValidationError(f"product image vulnerability scan failed: {name}")
        observed_digest, _inspection = _oci_image_digest(
            archive, expected_entrypoint=_expected_image_entrypoint(planned_images[name]),
            runtime_requirements=_runtime_requirements(manifest, planned_images[name]),
        )
        if _sha256(archive) != image.get("archiveDigest") \
                or observed_digest != image.get("imageDigest"):
            raise ValidationError(f"{name} scan archive changed during vulnerability analysis")
        document = require_mapping(read_json(raw_report), f"{name} Trivy report")
        report_results = require_list(document.get("Results"), f"{name} Trivy Results")
        if not report_results:
            raise ValidationError(f"product image vulnerability scan returned no analyzable results: {name}")
        vulnerabilities = [
            value for result in report_results
            for value in require_list(require_mapping(result, "Trivy result").get("Vulnerabilities", []),
                                      "Trivy vulnerabilities")
        ]
        blocking = [value for value in vulnerabilities if require_mapping(value, "vulnerability").get("Severity") in {"HIGH", "CRITICAL"}]
        if blocking:
            raise ValidationError(f"product image has blocking vulnerabilities: {name}")
        if _directory_digest(cache) != expected_database:
            raise ValidationError("Trivy database changed during vulnerability analysis")
        scanner = {
            "name": "trivy", "version": scanner_version,
            "executableDigest": scanner_digest,
        }
        bound_report = {
            "schemaVersion": 1,
            "subject": require_text(image.get("reference"), f"{name} image reference"),
            "scanner": scanner,
            "databaseDigest": expected_database,
            "rawReportDigest": _sha256(raw_report),
            "results": report_results,
            "status": "COMPLETE_NO_HIGH_OR_CRITICAL",
        }
        _validate_bound_scan_report(
            bound_report, name, require_text(image.get("imageDigest"), "imageDigest"),
            scanner, expected_database,
        )
        _write_json(report, bound_report)
        sbom_completed = _run([
            trivy, "image", "--input", str(archive), "--format", "cyclonedx",
            "--output", str(raw_sbom), "--skip-db-update", "--skip-java-db-update",
        ], environment=environment, stdout=subprocess.DEVNULL, timeout=1800, check=False)
        if sbom_completed.returncode != 0:
            raise ValidationError(f"full product image SBOM generation failed: {name}")
        observed_digest, _inspection = _oci_image_digest(
            archive, expected_entrypoint=_expected_image_entrypoint(planned_images[name]),
            runtime_requirements=_runtime_requirements(manifest, planned_images[name]),
        )
        if _sha256(archive) != image.get("archiveDigest") \
                or observed_digest != image.get("imageDigest"):
            raise ValidationError(f"{name} scan archive changed during SBOM generation")
        if _directory_digest(cache) != expected_database:
            raise ValidationError("Trivy database changed during full-image SBOM generation")
        scanned_sbom = require_mapping(read_json(raw_sbom), f"{name} Trivy CycloneDX")
        components = _cyclonedx_package_components(
            scanned_sbom, f"{name} Trivy full-image SBOM"
        )
        raw_sbom_digest = _sha256(raw_sbom)
        subject = f"pkg:oci/{name}@sha256:{image['imageDigest']}"
        metadata = dict(require_mapping(scanned_sbom.get("metadata", {}), "SBOM metadata"))
        scanner_subject = metadata.get("component")
        component_documents = [dict(value) for value in components]
        dependency_documents = [
            dict(require_mapping(value, "SBOM dependency"))
            for value in require_list(scanned_sbom.get("dependencies", []), "SBOM dependencies")
        ]
        scanner_subject_ref: str | None = None
        if isinstance(scanner_subject, dict) and isinstance(scanner_subject.get("bom-ref"), str):
            scanner_subject_ref = str(scanner_subject["bom-ref"])
            component_refs = {str(value.get("bom-ref")) for value in component_documents}
            if scanner_subject_ref != subject and scanner_subject_ref not in component_refs:
                component_documents.append(dict(scanner_subject))
        metadata["component"] = {
            "type": "container", "bom-ref": subject, "name": name,
            "version": f"sha256:{image['imageDigest']}",
            "hashes": [{"alg": "SHA-256", "content": image["imageDigest"]}],
            "properties": [
                {"name": "elmpay:coverage", "value": "full-image-package-inventory"},
                {"name": "elmpay:scanner-output-digest", "value": raw_sbom_digest},
                {"name": "elmpay:scanner-database-digest", "value": expected_database},
                {"name": "elmpay:base-image", "value": image["baseImage"]},
            ],
        }
        root_dependencies = [] if scanner_subject_ref in (None, subject) else [scanner_subject_ref]
        if not root_dependencies:
            root_dependencies = [
                str(value["bom-ref"]) for value in component_documents
                if isinstance(value.get("bom-ref"), str) and value.get("bom-ref") != subject
            ]
        bound_document = {
            **scanned_sbom,
            "metadata": metadata,
            "components": component_documents,
            "dependencies": [
                {"ref": subject, "dependsOn": sorted(set(root_dependencies))},
                *[value for value in dependency_documents if value.get("ref") != subject],
            ],
        }
        _validate_full_image_sbom(
            bound_document, name, require_text(image.get("imageDigest"), "imageDigest"),
            require_text(image.get("baseImage"), "baseImage"),
            f"{name} bound full-image SBOM",
        )
        _write_json(bound_sbom, bound_document)
        results.append({
            "name": name, "imageDigest": image["imageDigest"],
            "scanArchive": str(archive.relative_to(build_root)),
            "scanArchiveDigest": image["archiveDigest"],
            "report": str(report.relative_to(build_root)),
            "reportDigest": _sha256(report), "databaseDigest": expected_database,
            "sbom": str(bound_sbom.relative_to(build_root)),
            "sbomDigest": _sha256(bound_sbom), "rawSbomDigest": raw_sbom_digest,
            "status": "COMPLETE_NO_HIGH_OR_CRITICAL",
        })
    if _directory_digest(cache) != expected_database:
        raise ValidationError("Trivy database changed before scan evidence finalization")
    _write_json(out, {
        "schemaVersion": 1,
        "buildIndexDigest": _sha256(build_index_path),
        "scanner": {
            "name": "trivy", "version": scanner_version,
            "executableDigest": scanner_digest,
        },
        "databaseDigest": expected_database,
        "images": results,
        "status": "VERIFIED",
    })
    if _directory_digest(cache) != expected_database:
        raise ValidationError("Trivy database changed while scan evidence was finalized")
    return 0


def command_publish(args: argparse.Namespace) -> int:
    """Publish only the already-scanned OCI archive with digest preservation."""

    manifest, _workloads, _admission = _documents()
    build_index_path = _regular_evidence_file(args.build_index, "product build index")
    build_root = build_index_path.parent
    index = _load_build_index(build_index_path)
    scan_index_path = _regular_evidence_file(args.scan_index, "product scan index")
    _scan_index, scans = _validate_scan_index(scan_index_path, build_index_path, index)
    trusted = {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": "zpcaiai/elmpay", "GITHUB_REF": "refs/heads/main",
    }
    if any(os.environ.get(key) != value for key, value in trusted.items()):
        raise ValidationError("product image publication requires the trusted main GitHub context")
    if os.environ.get("GITHUB_SHA") != index.get("sourceCommit") \
            or os.environ.get("GITHUB_WORKFLOW_REF") != GITHUB_WORKFLOW_REF:
        raise ValidationError("product image publication source/workflow binding mismatch")
    publication_policy = require_mapping(manifest.get("publicationTool"), "publicationTool")
    publication_version = require_text(
        os.environ.get(str(publication_policy["versionInputEnvironment"])),
        "Skopeo version input",
    )
    publication_digest = require_text(
        os.environ.get(str(publication_policy["executableDigestInputEnvironment"])),
        "Skopeo executable digest input",
    )
    skopeo = _verified_tool("skopeo", publication_version, publication_digest)
    publication_tool = {
        "name": "skopeo", "version": publication_version,
        "executableDigest": publication_digest,
    }
    by_name = _exact_by_name(index, "build images")
    output = args.out.resolve()
    receipts = build_root / "publication-receipts"
    sources = build_root / "publication-sources"
    if output.exists() or output.is_symlink() or output.parent != build_root:
        raise ValidationError("publication index must be a new build-index sibling")
    expected_names = {str(value["name"]) for value in manifest["images"]}
    for directory, suffix in ((receipts, ".json"), (sources, ".tar")):
        if directory.is_symlink() or directory.exists() and not directory.is_dir():
            raise ValidationError("publication journal/snapshot path is unsafe")
        directory.mkdir(exist_ok=True)
        for candidate in directory.iterdir():
            expected = candidate.stem in expected_names and candidate.suffix == suffix
            if not expected or candidate.is_symlink() or not candidate.is_file():
                raise ValidationError("publication journal/snapshot inventory is not exact")
    # Snapshot and validate every scanned source before the first registry mutation.
    archives: dict[str, Path] = {}
    for raw in require_list(manifest.get("images"), "product images"):
        image = require_mapping(raw, "product image")
        name = require_text(image.get("name"), "image.name")
        built = by_name.get(name)
        scanned = scans.get(name)
        if built is None or scanned is None \
                or scanned.get("imageDigest") != built.get("imageDigest"):
            raise ValidationError(f"product image has no exact completed scan: {name}")
        archive = _bound_evidence_file(
            build_root, scanned.get("scanArchive"), f"{name} exact scan archive",
            scanned.get("scanArchiveDigest"),
        )
        if scanned.get("scanArchiveDigest") != built.get("archiveDigest"):
            raise ValidationError(f"{name} scan archive differs from the built OCI archive")
        snapshot = sources / f"{name}.tar"
        if snapshot.exists():
            _bound_evidence_file(
                build_root, snapshot.relative_to(build_root),
                f"{name} publication snapshot", built.get("archiveDigest"),
            )
        else:
            _snapshot_regular_file(archive, snapshot, str(built["archiveDigest"]))
            _fsync_directory(sources)
        observed_digest, _inspection = _oci_image_digest(
            snapshot, expected_entrypoint=_expected_image_entrypoint(image),
            runtime_requirements=_runtime_requirements(manifest, image),
        )
        if observed_digest != built.get("imageDigest"):
            raise ValidationError(f"{name} inspected OCI subject changed before publication")
        archives[name] = snapshot
    environment = _safe_environment()
    published: list[dict[str, Any]] = []
    for raw in require_list(manifest.get("images"), "product images"):
        image = require_mapping(raw, "product image")
        name = require_text(image.get("name"), "image.name")
        built = by_name[name]
        archive = archives[name]
        observed_digest, _inspection = _oci_image_digest(
            archive, expected_entrypoint=_expected_image_entrypoint(image),
            runtime_requirements=_runtime_requirements(manifest, image),
        )
        if _sha256(archive) != built.get("archiveDigest") \
                or observed_digest != built.get("imageDigest"):
            raise ValidationError(f"{name} OCI archive changed during publication preflight")
        repository = f"{manifest['registry']}/{name}"
        tag_name = f"sha256-{built['imageDigest']}"
        tag = f"{repository}:{tag_name}"
        receipt = receipts / f"{name}.json"
        existing_receipt: Mapping[str, Any] | None = None
        if receipt.exists():
            existing_receipt = require_mapping(
                read_json(_regular_evidence_file(receipt, f"{name} publication receipt")),
                f"{name} publication receipt",
            )
        remote_digest = _registry_tag_digest(skopeo, repository, tag_name, environment)
        should_copy, action = _publication_resume_decision(
            existing_receipt is not None, remote_digest, str(built["imageDigest"])
        )
        if should_copy:
            _run([
                skopeo, "copy", "--preserve-digests", "--retry-times", "0",
                f"oci-archive:{archive}", f"docker://{tag}",
            ], environment=environment, stdout=subprocess.DEVNULL)
            after_digest, _inspection = _oci_image_digest(
                archive, expected_entrypoint=_expected_image_entrypoint(image),
                runtime_requirements=_runtime_requirements(manifest, image),
            )
            if _sha256(archive) != built.get("archiveDigest") \
                    or after_digest != built.get("imageDigest"):
                raise ValidationError("publication snapshot changed during registry copy")
            remote_digest = _registry_tag_digest(skopeo, repository, tag_name, environment)
        if remote_digest != built["imageDigest"]:
            raise ValidationError("registry did not expose the exact digest-preserved subject")
        receipt_document = {
            "schemaVersion": 1,
            "name": name,
            "sourceArchiveDigest": built["archiveDigest"],
            "publicationArchive": str(archive.relative_to(build_root)),
            "publicationArchiveDigest": built["archiveDigest"],
            "sourceImageDigest": built["imageDigest"],
            "destinationTag": tag,
            "destinationReference": built["reference"],
            "observedRegistryDigest": remote_digest,
            "scanReportDigest": scans[name]["reportDigest"],
            "sbomDigest": scans[name]["sbomDigest"],
            "publicationTool": publication_tool,
            "publicationAction": action,
            "status": "PUBLISHED_EXACT_DIGEST",
        }
        if existing_receipt is None:
            _write_json(receipt, receipt_document)
            _fsync_directory(receipts)
        else:
            expected_receipt = dict(receipt_document)
            del expected_receipt["publicationAction"]
            _validate_durable_publication_receipt(existing_receipt, expected_receipt)
        published.append({
            "name": name, "reference": built["reference"], "imageDigest": built["imageDigest"],
            "receipt": str(receipt.relative_to(build_root)),
            "receiptDigest": _sha256(receipt), "status": "PUBLISHED_EXACT_DIGEST",
        })
    if set(by_name) != {str(value["name"]) for value in published}:
        raise ValidationError("published image set differs from the build index")
    for name, built in by_name.items():
        if _registry_tag_digest(
            skopeo, f"{manifest['registry']}/{name}",
            f"sha256-{built['imageDigest']}", environment,
        ) != built["imageDigest"]:
            raise ValidationError("registry digest tag changed before publication finalization")
    _write_json(output, {
        "schemaVersion": 1,
        "buildIndexDigest": _sha256(build_index_path),
        "scanIndexDigest": _sha256(scan_index_path),
        "sourceCommit": index["sourceCommit"],
        "publicationTool": publication_tool,
        "images": published,
        "status": "VERIFIED",
    })
    _fsync_directory(build_root)
    return 0


def _validate_scan_index(
    path: Path, build_index_path: Path, build: Mapping[str, Any]
) -> tuple[Mapping[str, Any], dict[str, Mapping[str, Any]]]:
    path = _regular_evidence_file(path, "product scan index")
    root = build_index_path.parent
    if path.parent != root:
        raise ValidationError("product scan index must be a build-index sibling")
    document = require_mapping(read_json(path), "scan index")
    if set(document) != {
        "schemaVersion", "buildIndexDigest", "scanner", "databaseDigest", "images", "status"
    } or document.get("schemaVersion") != 1 or document.get("status") != "VERIFIED" \
            or document.get("buildIndexDigest") != _sha256(build_index_path):
        raise ValidationError("full-image scan/SBOM evidence is missing or build-unbound")
    scanner = require_mapping(document.get("scanner"), "scan index scanner")
    if set(scanner) != {"name", "version", "executableDigest"} \
            or scanner.get("name") != "trivy" \
            or not isinstance(scanner.get("version"), str) or not str(scanner["version"]).strip() \
            or not isinstance(scanner.get("executableDigest"), str) \
            or not DIGEST.fullmatch(str(scanner["executableDigest"])) \
            or scanner.get("executableDigest") == "0" * 64:
        raise ValidationError("scan index scanner evidence is invalid")
    database_digest = require_text(document.get("databaseDigest"), "scan database digest")
    if not DIGEST.fullmatch(database_digest) or database_digest == "0" * 64:
        raise ValidationError("scan database digest is invalid")
    scans = _exact_by_name(document, "scan images")
    built = _exact_by_name(build, "build images")
    if set(scans) != set(built):
        raise ValidationError("scan image set differs from the build index")
    manifest, _workloads, _admission = _documents()
    planned_images = {
        require_text(value.get("name"), "planned product image.name"): value
        for value in (
            require_mapping(raw, "planned product image")
            for raw in require_list(manifest.get("images"), "planned product images")
        )
    }
    if set(planned_images) != set(built):
        raise ValidationError("scan/build image set differs from the product manifest")
    for name, image in scans.items():
        if set(image) != {
            "name", "imageDigest", "scanArchive", "scanArchiveDigest",
            "report", "reportDigest", "databaseDigest", "sbom", "sbomDigest",
            "rawSbomDigest", "status",
        } or image.get("imageDigest") != built[name].get("imageDigest") \
                or image.get("scanArchiveDigest") != built[name].get("archiveDigest") \
                or image.get("databaseDigest") != database_digest \
                or image.get("status") != "COMPLETE_NO_HIGH_OR_CRITICAL" \
                or not isinstance(image.get("rawSbomDigest"), str) \
                or not DIGEST.fullmatch(str(image["rawSbomDigest"])):
            raise ValidationError(f"{name} scan evidence is incomplete or subject-unbound")
        scan_archive = _bound_evidence_file(
            root, image.get("scanArchive"), f"{name} exact scan archive",
            image.get("scanArchiveDigest"),
        )
        planned = planned_images[name]
        archive_image_digest, _inspection = _oci_image_digest(
            scan_archive, expected_entrypoint=_expected_image_entrypoint(planned),
            runtime_requirements=_runtime_requirements(manifest, planned),
        )
        if archive_image_digest != image.get("imageDigest"):
            raise ValidationError(f"{name} scan archive OCI subject is not exact")
        report = _bound_evidence_file(
            root, image.get("report"), f"{name} bound scan report", image.get("reportDigest")
        )
        _validate_bound_scan_report(
            require_mapping(read_json(report), f"{name} bound scan report"),
            name, require_text(image.get("imageDigest"), "imageDigest"),
            scanner, database_digest,
        )
        sbom = _bound_evidence_file(
            root, image.get("sbom"), f"{name} full-image SBOM", image.get("sbomDigest")
        )
        properties = _validate_full_image_sbom(
            require_mapping(read_json(sbom), f"{name} full-image SBOM"),
            name, require_text(image.get("imageDigest"), "imageDigest"),
            require_text(built[name].get("baseImage"), "baseImage"),
            f"{name} full-image SBOM",
        )
        if properties.get("elmpay:scanner-output-digest") != image.get("rawSbomDigest") \
                or properties.get("elmpay:scanner-database-digest") != database_digest:
            raise ValidationError(f"{name} SBOM scanner/database digest binding mismatch")
    return document, scans


def _validate_publication_index(
    path: Path, build_index_path: Path, scan_index_path: Path,
    build: Mapping[str, Any], scans: Mapping[str, Mapping[str, Any]],
) -> tuple[Mapping[str, Any], dict[str, Mapping[str, Any]]]:
    path = _regular_evidence_file(path, "product publication index")
    manifest, _workloads, _admission = _documents()
    planned = {
        require_text(value.get("name"), "product image.name"): value
        for value in (
            require_mapping(raw, "product image")
            for raw in require_list(manifest.get("images"), "product images")
        )
    }
    if path.parent != build_index_path.parent:
        raise ValidationError("product publication index must be a build-index sibling")
    document = require_mapping(read_json(path), "publication index")
    if set(document) != {
        "schemaVersion", "buildIndexDigest", "scanIndexDigest", "sourceCommit", "publicationTool",
        "images", "status"
    } or document.get("schemaVersion") != 1 or document.get("status") != "VERIFIED" \
            or document.get("buildIndexDigest") != _sha256(build_index_path) \
            or document.get("scanIndexDigest") != _sha256(scan_index_path) \
            or document.get("sourceCommit") != build.get("sourceCommit"):
        raise ValidationError("publication index is missing or build-unbound")
    tool = require_mapping(document.get("publicationTool"), "publication tool")
    if set(tool) != {"name", "version", "executableDigest"} \
            or tool.get("name") != "skopeo" \
            or not isinstance(tool.get("version"), str) or not str(tool["version"]).strip() \
            or not isinstance(tool.get("executableDigest"), str) \
            or not DIGEST.fullmatch(str(tool["executableDigest"])) \
            or tool.get("executableDigest") == "0" * 64:
        raise ValidationError("publication tool evidence is invalid")
    published = _exact_by_name(document, "published images")
    built = _exact_by_name(build, "build images")
    if set(published) != set(built):
        raise ValidationError("publication image set differs from the build index")
    for name, image in published.items():
        if set(image) != {"name", "reference", "imageDigest", "receipt", "receiptDigest", "status"} \
                or image.get("reference") != built[name].get("reference") \
                or image.get("imageDigest") != built[name].get("imageDigest") \
                or image.get("status") != "PUBLISHED_EXACT_DIGEST":
            raise ValidationError(f"{name} publication evidence is incomplete or subject-unbound")
        receipt = _bound_evidence_file(
            build_index_path.parent, image.get("receipt"), f"{name} publication receipt",
            image.get("receiptDigest"),
        )
        publication_archive = _bound_evidence_file(
            build_index_path.parent,
            require_mapping(read_json(receipt), f"{name} publication receipt").get(
                "publicationArchive"
            ),
            f"{name} publication archive", built[name]["archiveDigest"],
        )
        archive_image_digest, _inspection = _oci_image_digest(
            publication_archive,
            expected_entrypoint=_expected_image_entrypoint(planned[name]),
            runtime_requirements=_runtime_requirements(manifest, planned[name]),
        )
        if archive_image_digest != built[name]["imageDigest"]:
            raise ValidationError(f"{name} publication archive subject is not exact")
        expected_receipt = {
            "schemaVersion": 1,
            "name": name,
            "sourceArchiveDigest": built[name]["archiveDigest"],
            "publicationArchive": f"publication-sources/{name}.tar",
            "publicationArchiveDigest": built[name]["archiveDigest"],
            "sourceImageDigest": built[name]["imageDigest"],
            "destinationTag": (
                f"{manifest['registry']}/{name}:sha256-{built[name]['imageDigest']}"
            ),
            "destinationReference": built[name]["reference"],
            "observedRegistryDigest": built[name]["imageDigest"],
            "scanReportDigest": scans[name]["reportDigest"],
            "sbomDigest": scans[name]["sbomDigest"],
            "publicationTool": tool,
            "status": "PUBLISHED_EXACT_DIGEST",
        }
        observed_receipt = require_mapping(
            read_json(receipt), f"{name} publication receipt"
        )
        _validate_durable_publication_receipt(observed_receipt, expected_receipt)
    return document, published


def command_sign_registry(args: argparse.Namespace) -> int:
    build_index_path = _regular_evidence_file(args.build_index, "product build index")
    build_root = build_index_path.parent
    index = _load_build_index(build_index_path)
    manifest, _workloads, _admission = _documents()
    scan_index_path = _regular_evidence_file(args.scan_index, "product scan index")
    scan_index, scans = _validate_scan_index(scan_index_path, build_index_path, index)
    publication_path = _regular_evidence_file(args.publish_index, "publication index")
    publication, published = _validate_publication_index(
        publication_path, build_index_path, scan_index_path, index, scans
    )
    trusted = {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": "zpcaiai/elmpay", "GITHUB_REF": "refs/heads/main",
    }
    if any(os.environ.get(key) != value for key, value in trusted.items()):
        raise ValidationError("registry image signing requires the trusted main GitHub context")
    if os.environ.get("GITHUB_SHA") != index.get("sourceCommit") \
            or os.environ.get("GITHUB_WORKFLOW_REF") != GITHUB_WORKFLOW_REF:
        raise ValidationError("registry image signing source/workflow binding mismatch")
    if any(not os.environ.get(key) for key in (
        "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
    )):
        raise ValidationError("registry image signing requires GitHub OIDC token inputs")
    if os.environ.get("ELMPAY_PUBLIC_SIGSTORE_METADATA_DISCLOSURE_OPT_IN") != "true":
        raise ValidationError("public Sigstore metadata disclosure was not opted in")
    pipeline = require_mapping(read_json(ROOT / PIPELINE_POLICY), "CI pipeline")
    expected_release = require_text(
        require_mapping(pipeline.get("signing_policy"), "signing policy").get("cosign_release"),
        "cosign release",
    )
    signature_tool = require_mapping(
        require_mapping(manifest.get("evidence"), "evidence").get("signatureTool"),
        "signatureTool",
    )
    supplied_version = require_text(
        os.environ.get(str(signature_tool["versionInputEnvironment"])),
        "Cosign version release input",
    )
    if supplied_version != expected_release:
        raise ValidationError("cosign release differs from the governed signing policy")
    cosign = _verified_tool(
        "cosign", supplied_version,
        require_text(
            os.environ.get(str(signature_tool["executableDigestInputEnvironment"])),
            "Cosign executable digest release input",
        ),
    )
    scan_tool = require_mapping(
        require_mapping(manifest.get("evidence"), "evidence").get("scanTool"),
        "scanTool",
    )
    expected_scanner = {
        "name": "trivy",
        "version": os.environ.get(str(scan_tool["versionInputEnvironment"])),
        "executableDigest": os.environ.get(
            str(scan_tool["executableDigestInputEnvironment"])
        ),
    }
    if scan_index.get("scanner") != expected_scanner \
            or scan_index.get("databaseDigest") != os.environ.get(
                str(scan_tool["databaseDigestInputEnvironment"])
            ):
        raise ValidationError("scan tool/database differs from the protected signing inputs")
    publication_policy = require_mapping(manifest.get("publicationTool"), "publicationTool")
    expected_publication_tool = {
        "name": "skopeo",
        "version": os.environ.get(str(publication_policy["versionInputEnvironment"])),
        "executableDigest": os.environ.get(
            str(publication_policy["executableDigestInputEnvironment"])
        ),
    }
    if publication.get("publicationTool") != expected_publication_tool:
        raise ValidationError("publication tool differs from the protected signing inputs")
    output = args.out.resolve()
    if output.exists() or output.is_symlink() or output.parent != build_root:
        raise ValidationError("signature index must be a new sibling of the build index")
    bundles = output.parent / "registry-signatures"
    if bundles.exists() or bundles.is_symlink():
        raise ValidationError("stale registry signature directory exists")
    bundles.mkdir()
    identity = "https://github.com/zpcaiai/elmpay/.github/workflows/ci.yml@refs/heads/main"
    issuer = "https://token.actions.githubusercontent.com"
    evidence_policy = require_mapping(manifest.get("evidence"), "product image evidence")
    sbom_predicate_type = require_text(
        evidence_policy.get("sbomPredicateType"), "SBOM predicate type"
    )
    provenance_predicate_type = require_text(
        evidence_policy.get("provenancePredicateType"), "provenance predicate type"
    )
    planned_images = {
        require_text(value.get("name"), "product image.name"): value
        for value in (
            require_mapping(raw, "product image")
            for raw in require_list(manifest.get("images"), "product images")
        )
    }
    results: list[dict[str, Any]] = []
    for raw in require_list(index.get("images"), "build images"):
        image = require_mapping(raw, "build image")
        name = require_text(image.get("name"), "image.name")
        reference = require_text(image.get("reference"), "image.reference")
        published_image = published.get(name)
        if published_image is None or published_image.get("reference") != reference \
                or published_image.get("imageDigest") != image.get("imageDigest") \
                or published_image.get("status") != "PUBLISHED_EXACT_DIGEST":
            raise ValidationError("registry signing subject was not published at the scanned digest")
        scanned = scans.get(name)
        if scanned is None or scanned.get("imageDigest") != image.get("imageDigest") \
                or scanned.get("status") != "COMPLETE_NO_HIGH_OR_CRITICAL":
            raise ValidationError("registry signing image has no exact completed scan")
        sbom = _bound_evidence_file(
            build_root, scanned.get("sbom"), f"{name} full-image SBOM",
            scanned.get("sbomDigest"),
        )
        sbom_document = require_mapping(read_json(sbom), f"{name} full-image SBOM")
        _validate_full_image_sbom(
            sbom_document,
            name, require_text(image.get("imageDigest"), "imageDigest"),
            require_text(image.get("baseImage"), "baseImage"),
            f"{name} full-image SBOM",
        )
        provenance = _bound_evidence_file(
            build_root, image.get("provenance"), f"{name} provenance",
            image.get("provenanceDigest"),
        )
        provenance_document = require_mapping(read_json(provenance), f"{name} provenance")
        _validate_provenance(
            provenance_document, manifest, index, image, planned_images[name]
        )
        signature_bundle = bundles / f"{name}.signature.json"
        sbom_bundle = bundles / f"{name}.sbom-attestation.json"
        provenance_bundle = bundles / f"{name}.provenance-attestation.json"
        environment = _sigstore_environment()
        _run([cosign, "sign", "--yes", "--new-bundle-format=true", "--bundle", str(signature_bundle), reference], environment=environment)
        _run([cosign, "attest", "--yes", "--new-bundle-format=true", "--type", sbom_predicate_type,
              "--predicate", str(sbom), "--bundle", str(sbom_bundle), reference], environment=environment)
        _run([cosign, "attest", "--yes", "--new-bundle-format=true", "--type", provenance_predicate_type,
              "--predicate", str(provenance), "--bundle", str(provenance_bundle), reference], environment=environment)
        _validate_sigstore_bundle(signature_bundle, attestation=False)
        _validate_sigstore_bundle(sbom_bundle, attestation=True)
        _validate_sigstore_bundle(provenance_bundle, attestation=True)
        signature_verification = _run([
            cosign, "verify", "--certificate-identity", identity,
            "--certificate-oidc-issuer", issuer, "--bundle", str(signature_bundle),
            "--output=json", reference,
        ], environment=environment, stdout=subprocess.PIPE)
        _validate_cosign_signature_output(signature_verification.stdout, reference)
        predicate_digests: dict[str, str] = {}
        for evidence_name, attestation_type, bundle, predicate_document in (
            ("sbom", sbom_predicate_type, sbom_bundle, sbom_document),
            ("provenance", provenance_predicate_type, provenance_bundle, provenance_document),
        ):
            verification = _run([
                cosign, "verify-attestation", "--certificate-identity", identity,
                "--certificate-oidc-issuer", issuer, "--type", attestation_type,
                "--bundle", str(bundle), "--output=json", reference,
            ], environment=environment, stdout=subprocess.PIPE)
            predicate_digests[evidence_name] = _validate_cosign_attestation_output(
                verification.stdout, reference, attestation_type, predicate_document
            )
        bundle_digests = {
            "signature": _sha256(signature_bundle), "sbom": _sha256(sbom_bundle),
            "provenance": _sha256(provenance_bundle),
        }
        results.append({
            "name": name, "imageDigest": image["imageDigest"],
            "sbomDigest": scanned["sbomDigest"], "provenanceDigest": image["provenanceDigest"],
            "sbomPredicateDigest": predicate_digests["sbom"],
            "provenancePredicateDigest": predicate_digests["provenance"],
            "bundles": {
                "signature": {
                    "path": str(signature_bundle.relative_to(build_root)),
                    "digest": bundle_digests["signature"],
                },
                "sbom": {
                    "path": str(sbom_bundle.relative_to(build_root)),
                    "digest": bundle_digests["sbom"],
                },
                "provenance": {
                    "path": str(provenance_bundle.relative_to(build_root)),
                    "digest": bundle_digests["provenance"],
                },
            },
            "bundleDigest": sha256_json(bundle_digests), "issuer": issuer, "identity": identity,
            "transparencyLogIncluded": True, "status": "VERIFIED",
        })
    if set(published) != {str(value["name"]) for value in results} or set(scans) != set(published):
        raise ValidationError("published/signature image inventory differs")
    _write_json(output, {
        "schemaVersion": 1,
        "buildIndexDigest": _sha256(build_index_path),
        "scanIndexDigest": _sha256(scan_index_path),
        "publicationIndexDigest": _sha256(publication_path),
        "publicationTool": publication["publicationTool"],
        "signer": {
            "name": "cosign", "version": supplied_version,
            "executableDigest": os.environ.get(
                str(signature_tool["executableDigestInputEnvironment"])
            ),
        },
        "images": results,
        "status": "VERIFIED",
    })
    return 0


def _exact_by_name(index: Mapping[str, Any], field: str) -> dict[str, Mapping[str, Any]]:
    values = [require_mapping(value, field) for value in require_list(index.get("images"), field)]
    result = {require_text(value.get("name"), f"{field}.name"): value for value in values}
    if len(result) != len(values):
        raise ValidationError(f"{field} names must be unique")
    return result


def _validate_signature_index(
    path: Path,
    build_index_path: Path,
    scan_index_path: Path,
    build: Mapping[str, Any],
    scans: Mapping[str, Mapping[str, Any]],
) -> tuple[Mapping[str, Any], dict[str, Mapping[str, Any]]]:
    path = _regular_evidence_file(path, "product signature index")
    root = build_index_path.parent
    manifest, _workloads, _admission = _documents()
    evidence_policy = require_mapping(manifest.get("evidence"), "product image evidence")
    if path.parent != root:
        raise ValidationError("product signature index must be a build-index sibling")
    document = require_mapping(read_json(path), "signature index")
    if set(document) != {
        "schemaVersion", "buildIndexDigest", "scanIndexDigest",
        "publicationIndexDigest", "publicationTool", "signer", "images", "status",
    } or document.get("schemaVersion") != 1 or document.get("status") != "VERIFIED" \
            or document.get("buildIndexDigest") != _sha256(build_index_path) \
            or document.get("scanIndexDigest") != _sha256(scan_index_path) \
            or not isinstance(document.get("publicationIndexDigest"), str) \
            or not DIGEST.fullmatch(str(document["publicationIndexDigest"])):
        raise ValidationError("signature index is missing or evidence-index-unbound")
    publication_tool = require_mapping(
        document.get("publicationTool"), "signature index publication tool"
    )
    if set(publication_tool) != {"name", "version", "executableDigest"} \
            or publication_tool.get("name") != "skopeo" \
            or not isinstance(publication_tool.get("version"), str) \
            or not str(publication_tool["version"]).strip() \
            or not isinstance(publication_tool.get("executableDigest"), str) \
            or not DIGEST.fullmatch(str(publication_tool["executableDigest"])) \
            or publication_tool.get("executableDigest") == "0" * 64:
        raise ValidationError("signature index publication tool evidence is invalid")
    signer = require_mapping(document.get("signer"), "signature index signer")
    if set(signer) != {"name", "version", "executableDigest"} \
            or signer.get("name") != "cosign" \
            or not isinstance(signer.get("version"), str) or not str(signer["version"]).strip() \
            or not isinstance(signer.get("executableDigest"), str) \
            or not DIGEST.fullmatch(str(signer["executableDigest"])) \
            or signer.get("executableDigest") == "0" * 64:
        raise ValidationError("signature tool evidence is invalid")
    signatures = _exact_by_name(document, "signature images")
    built = _exact_by_name(build, "build images")
    if set(signatures) != set(built) or set(signatures) != set(scans):
        raise ValidationError("signature image set differs from build/scan evidence")
    expected_identity = (
        "https://github.com/zpcaiai/elmpay/.github/workflows/ci.yml@refs/heads/main"
    )
    expected_issuer = "https://token.actions.githubusercontent.com"
    for name, signed in signatures.items():
        if set(signed) != {
            "name", "imageDigest", "sbomDigest", "provenanceDigest",
            "sbomPredicateDigest", "provenancePredicateDigest", "bundles",
            "bundleDigest", "issuer", "identity", "transparencyLogIncluded", "status",
        } or signed.get("imageDigest") != built[name].get("imageDigest") \
                or signed.get("sbomDigest") != scans[name].get("sbomDigest") \
                or signed.get("provenanceDigest") != built[name].get("provenanceDigest") \
                or not isinstance(signed.get("sbomPredicateDigest"), str) \
                or not DIGEST.fullmatch(str(signed["sbomPredicateDigest"])) \
                or not isinstance(signed.get("provenancePredicateDigest"), str) \
                or not DIGEST.fullmatch(str(signed["provenancePredicateDigest"])) \
                or signed.get("issuer") != expected_issuer \
                or signed.get("identity") != expected_identity \
                or signed.get("transparencyLogIncluded") is not True \
                or signed.get("status") != "VERIFIED":
            raise ValidationError(f"{name} registry signature evidence is incomplete")
        bundles = require_mapping(signed.get("bundles"), f"{name} signature bundles")
        if set(bundles) != {"signature", "sbom", "provenance"}:
            raise ValidationError(f"{name} signature bundle inventory is incomplete")
        digests: dict[str, str] = {}
        statements: dict[str, Mapping[str, Any]] = {}
        for kind, raw in bundles.items():
            bundle = require_mapping(raw, f"{name}.{kind} bundle")
            if set(bundle) != {"path", "digest"}:
                raise ValidationError(f"{name}.{kind} bundle shape is invalid")
            bundle_path = _bound_evidence_file(
                root, bundle.get("path"), f"{name}.{kind} bundle", bundle.get("digest")
            )
            statement = _validate_sigstore_bundle(
                bundle_path, attestation=kind != "signature"
            )
            if statement is not None:
                statements[kind] = statement
            digests[kind] = require_text(bundle.get("digest"), f"{name}.{kind} digest")
        if signed.get("bundleDigest") != sha256_json(digests):
            raise ValidationError(f"{name} signature bundle aggregate digest mismatch")
        sbom = _bound_evidence_file(
            root, scans[name].get("sbom"), f"{name} full-image SBOM",
            scans[name].get("sbomDigest"),
        )
        provenance = _bound_evidence_file(
            root, built[name].get("provenance"), f"{name} provenance",
            built[name].get("provenanceDigest"),
        )
        sbom_document = require_mapping(read_json(sbom), f"{name} full-image SBOM")
        provenance_document = require_mapping(read_json(provenance), f"{name} provenance")
        sbom_predicate_digest = _validate_attestation_statement(
            statements["sbom"], require_text(built[name].get("reference"), "image reference"),
            require_text(evidence_policy.get("sbomPredicateType"), "SBOM predicate type"),
            sbom_document,
        )
        provenance_predicate_digest = _validate_attestation_statement(
            statements["provenance"],
            require_text(built[name].get("reference"), "image reference"),
            require_text(
                evidence_policy.get("provenancePredicateType"),
                "provenance predicate type",
            ),
            provenance_document,
        )
        if signed.get("sbomPredicateDigest") != sbom_predicate_digest \
                or signed.get("provenancePredicateDigest") \
                != provenance_predicate_digest:
            raise ValidationError(f"{name} attested predicate digest changed")
    return document, signatures


def _reverify_registry_signatures(
    cosign: str,
    build_root: Path,
    build: Mapping[str, Any],
    scans: Mapping[str, Mapping[str, Any]],
    signatures: Mapping[str, Mapping[str, Any]],
    manifest: Mapping[str, Any],
) -> None:
    """Cryptographically reverify every bundle during finalization.

    Parsing a DSSE payload and tlog-shaped JSON is not evidence that Sigstore
    accepted its certificate/signature.  Finalization therefore repeats
    Cosign verification with the exact pinned executable and compares the
    verified subjects and predicates with the local digest-bound evidence.
    """

    identity = "https://github.com/zpcaiai/elmpay/.github/workflows/ci.yml@refs/heads/main"
    issuer = "https://token.actions.githubusercontent.com"
    evidence_policy = require_mapping(manifest.get("evidence"), "product image evidence")
    predicate_types = {
        "sbom": require_text(
            evidence_policy.get("sbomPredicateType"), "SBOM predicate type"
        ),
        "provenance": require_text(
            evidence_policy.get("provenancePredicateType"), "provenance predicate type"
        ),
    }
    built = _exact_by_name(build, "build images")
    environment = _safe_environment()
    for name, signed in signatures.items():
        image = built[name]
        reference = require_text(image.get("reference"), f"{name} image reference")
        bundles = require_mapping(signed.get("bundles"), f"{name} signature bundles")
        signature_binding = require_mapping(
            bundles.get("signature"), f"{name} signature bundle"
        )
        signature_bundle = _bound_evidence_file(
            build_root, signature_binding.get("path"), f"{name} signature bundle",
            signature_binding.get("digest"),
        )
        verified_signature = _run([
            cosign, "verify", "--certificate-identity", identity,
            "--certificate-oidc-issuer", issuer, "--bundle", str(signature_bundle),
            "--output=json", reference,
        ], environment=environment, stdout=subprocess.PIPE)
        _validate_cosign_signature_output(verified_signature.stdout or b"", reference)
        predicates = {
            "sbom": require_mapping(
                read_json(_bound_evidence_file(
                    build_root, scans[name].get("sbom"), f"{name} full-image SBOM",
                    scans[name].get("sbomDigest"),
                )),
                f"{name} full-image SBOM",
            ),
            "provenance": require_mapping(
                read_json(_bound_evidence_file(
                    build_root, image.get("provenance"), f"{name} provenance",
                    image.get("provenanceDigest"),
                )),
                f"{name} provenance",
            ),
        }
        for kind in ("sbom", "provenance"):
            binding = require_mapping(bundles.get(kind), f"{name}.{kind} bundle")
            bundle = _bound_evidence_file(
                build_root, binding.get("path"), f"{name}.{kind} bundle",
                binding.get("digest"),
            )
            verification = _run([
                cosign, "verify-attestation", "--certificate-identity", identity,
                "--certificate-oidc-issuer", issuer, "--type", predicate_types[kind],
                "--bundle", str(bundle), "--output=json", reference,
            ], environment=environment, stdout=subprocess.PIPE)
            observed_digest = _validate_cosign_attestation_output(
                verification.stdout or b"", reference, predicate_types[kind],
                predicates[kind],
            )
            if observed_digest != signed.get(f"{kind}PredicateDigest"):
                raise ValidationError(
                    f"{name} cryptographically verified {kind} predicate digest changed"
                )


def command_finalize(args: argparse.Namespace) -> int:
    manifest, _workloads, admission = _documents()
    build_index_path = _regular_evidence_file(args.build_index, "product build index")
    build_root = build_index_path.parent
    build = _load_build_index(build_index_path)
    scan_index_path = _regular_evidence_file(args.scan_index, "product scan index")
    scan, scans = _validate_scan_index(scan_index_path, build_index_path, build)
    publication_index_path = _regular_evidence_file(
        args.publish_index, "product publication index"
    )
    publication, published = _validate_publication_index(
        publication_index_path, build_index_path, scan_index_path, build, scans
    )
    signature_index_path = _regular_evidence_file(
        args.signature_index, "product signature index"
    )
    signature, signatures = _validate_signature_index(
        signature_index_path, build_index_path, scan_index_path, build, scans
    )
    if signature.get("publicationIndexDigest") != _sha256(publication_index_path) \
            or signature.get("publicationTool") != publication.get("publicationTool") \
            or set(published) != set(signatures):
        raise ValidationError("signature index is not bound to the exact publication index")
    pipeline = require_mapping(read_json(ROOT / PIPELINE_POLICY), "CI pipeline")
    expected_release = require_text(
        require_mapping(pipeline.get("signing_policy"), "signing policy").get(
            "cosign_release"
        ),
        "cosign release",
    )
    signature_policy = require_mapping(
        require_mapping(manifest.get("evidence"), "product image evidence").get(
            "signatureTool"
        ),
        "signatureTool",
    )
    protected_signer = {
        "name": "cosign",
        "version": require_text(
            os.environ.get(str(signature_policy["versionInputEnvironment"])),
            "Cosign version release input",
        ),
        "executableDigest": require_text(
            os.environ.get(str(signature_policy["executableDigestInputEnvironment"])),
            "Cosign executable digest release input",
        ),
    }
    if protected_signer["version"] != expected_release \
            or signature.get("signer") != protected_signer:
        raise ValidationError("finalization Cosign input differs from the signed release policy")
    cosign = _verified_tool(
        "cosign", protected_signer["version"], protected_signer["executableDigest"]
    )
    _reverify_registry_signatures(
        cosign, build_root, build, scans, signatures, manifest
    )
    final_images: list[dict[str, Any]] = []
    for raw in require_list(build.get("images"), "build images"):
        image = require_mapping(raw, "build image")
        name = require_text(image.get("name"), "image.name")
        scanned = scans.get(name)
        signed = signatures.get(name)
        if scanned is None or signed is None or scanned.get("imageDigest") != image.get("imageDigest") \
                or signed.get("imageDigest") != image.get("imageDigest"):
            raise ValidationError("scan/signature subject does not match the built image")
        if scanned.get("status") != "COMPLETE_NO_HIGH_OR_CRITICAL" \
                or signed.get("status") != "VERIFIED" \
                or signed.get("sbomDigest") != scanned.get("sbomDigest") \
                or signed.get("provenanceDigest") != image.get("provenanceDigest") \
                or signed.get("transparencyLogIncluded") is not True:
            raise ValidationError("product image scan/signature evidence is incomplete")
        sbom = _bound_evidence_file(
            build_root, scanned.get("sbom"), f"{name} full-image SBOM",
            scanned.get("sbomDigest"),
        )
        _validate_full_image_sbom(
            require_mapping(read_json(sbom), f"{name} full-image SBOM"),
            name, require_text(image.get("imageDigest"), "imageDigest"),
            require_text(image.get("baseImage"), "baseImage"),
            f"{name} full-image SBOM",
        )
        provenance = _bound_evidence_file(
            build_root, image.get("provenance"), f"{name} provenance",
            image.get("provenanceDigest"),
        )
        del provenance
        final_images.append({
            "name": name, "reference": image["reference"], "imageDigest": image["imageDigest"],
            "baseImage": image["baseImage"], "artifactDigest": image["artifactDigest"],
            "containerfileDigest": image["containerfileDigest"],
            "runtimeInspectionDigest": image["runtimeInspectionDigest"],
            "sbomDigest": require_text(scanned.get("sbomDigest"), "full-image SBOM digest"),
            "sbomAttestedPredicateDigest": signed["sbomPredicateDigest"],
            "provenanceDigest": image["provenanceDigest"],
            "provenanceAttestedPredicateDigest": signed["provenancePredicateDigest"],
            "scanReportDigest": require_text(scanned.get("reportDigest"), "scan report digest"),
            "signatureBundleDigest": require_text(signed.get("bundleDigest"), "signature bundle digest"),
            "status": "SIGNED_SCANNED_VERIFIED",
        })
    if set(scans) != {str(value["name"]) for value in final_images} \
            or set(signatures) != set(scans):
        raise ValidationError("scan/signature inventory does not exactly match product images")
    final = {
        "schemaVersion": 1,
        "productImageManifestDigest": product_image_manifest_digest(manifest),
        "admissionPolicyDigest": admission_policy_digest(admission),
        "sourceCommit": build["sourceCommit"], "artifactDigest": build["artifactDigest"],
        "targetPlatform": build["targetPlatform"],
        "evidenceToolchain": {
            "build": build["buildTool"],
            "scan": scan["scanner"],
            "scanDatabaseDigest": scan["databaseDigest"],
            "publish": signature["publicationTool"],
            "sign": signature["signer"],
        },
        "buildIndexDigest": _sha256(build_index_path),
        "scanIndexDigest": _sha256(scan_index_path),
        "publicationIndexDigest": _sha256(publication_index_path),
        "signatureIndexDigest": _sha256(signature_index_path),
        "images": final_images,
    }
    output = args.out.resolve()
    if output.exists() or output.is_symlink() or output.parent != build_root:
        raise ValidationError("final product release index must be a new build-index sibling")
    _write_json(output, final)
    print(json.dumps({
        "allowed": True, "status": "LOCAL_PIPELINE_EVIDENCE_READY_EXTERNAL_ADMISSION_NOT_RUN",
        "productImageIndexDigest": sha256_json(final), "certificationStatus": "NOT_CERTIFIED",
    }, sort_keys=True, separators=(",", ":")))
    return 0


def command_verify_release(args: argparse.Namespace) -> int:
    manifest, _workloads, admission = _documents()
    index = require_mapping(read_json(args.release_index), "release index")
    release = require_mapping(read_json(args.release_manifest), "release manifest")
    validate_product_release_index(manifest, admission, index, release)
    print(json.dumps({
        "allowed": True, "status": "BOUND_EXTERNAL_ADMISSION_NOT_RUN",
        "certificationStatus": "NOT_CERTIFIED",
    }, sort_keys=True, separators=(",", ":")))
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("source-gate").set_defaults(handler=command_source_gate)
    build = commands.add_parser("build")
    build.add_argument("--source-commit", required=True)
    build.add_argument("--artifact-digest", required=True)
    build.add_argument("--source-date-epoch", type=int, required=True)
    build.add_argument("--out", type=Path, default=ROOT / "build/product-images")
    build.set_defaults(handler=command_build)
    scan = commands.add_parser("scan")
    scan.add_argument("--build-index", type=Path, required=True)
    scan.add_argument("--out", type=Path, required=True)
    scan.set_defaults(handler=command_scan)
    publish = commands.add_parser("publish")
    publish.add_argument("--build-index", type=Path, required=True)
    publish.add_argument("--scan-index", type=Path, required=True)
    publish.add_argument("--out", type=Path, required=True)
    publish.set_defaults(handler=command_publish)
    sign = commands.add_parser("sign-registry")
    sign.add_argument("--build-index", type=Path, required=True)
    sign.add_argument("--publish-index", type=Path, required=True)
    sign.add_argument("--scan-index", type=Path, required=True)
    sign.add_argument("--out", type=Path, required=True)
    sign.set_defaults(handler=command_sign_registry)
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--build-index", type=Path, required=True)
    finalize.add_argument("--scan-index", type=Path, required=True)
    finalize.add_argument("--publish-index", type=Path, required=True)
    finalize.add_argument("--signature-index", type=Path, required=True)
    finalize.add_argument("--out", type=Path, required=True)
    finalize.set_defaults(handler=command_finalize)
    verify = commands.add_parser("verify-release")
    verify.add_argument("--release-index", type=Path, required=True)
    verify.add_argument("--release-manifest", type=Path, required=True)
    verify.set_defaults(handler=command_verify_release)
    return value


def main() -> int:
    try:
        args = parser().parse_args()
        return int(args.handler(args))
    except (KeyError, OSError, subprocess.SubprocessError, TypeError, ValueError, ValidationError) as exc:
        print(json.dumps({
            "allowed": False, "status": "BLOCKED", "reason": str(exc),
            "certificationStatus": "NOT_CERTIFIED",
        }, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
