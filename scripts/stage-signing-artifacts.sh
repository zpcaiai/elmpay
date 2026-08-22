#!/usr/bin/env bash
# GENERATED FILE — do not edit by hand.
# Source of truth: governance/ci-pipeline.json
# Regenerate with: python3 scripts/render-ci.py

# Stage JARs only from the exact Gradle project inventory.  The manifest keeps
# original repository-relative paths and hashes; the signing job never selects
# subjects by recursively globbing an untrusted download.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STAGING_ROOT="${ROOT}/build/signing-inputs"
for variable in GITHUB_ACTIONS GITHUB_REPOSITORY GITHUB_SHA GITHUB_RUN_ID \
                GITHUB_RUN_ATTEMPT GITHUB_WORKFLOW_REF RUNNER_ENVIRONMENT; do
  if [[ ! -v "${variable}" || -z "${!variable}" ]]; then
    echo "required artifact staging environment '${variable}' is missing" >&2
    exit 1
  fi
done
if [[ "${GITHUB_ACTIONS}" != 'true' || "${RUNNER_ENVIRONMENT}" != 'github-hosted' ]]; then
  echo 'artifact staging is restricted to a GitHub-hosted Actions runner' >&2
  exit 1
fi
if [[ -e "${STAGING_ROOT}" ]]; then
  echo 'stale signing-input staging directory exists' >&2
  exit 1
fi

STAGING_PROJECTS_B64='WyJsaWJzL21vbmV5IiwibGlicy9kb21haW4tZXZlbnRzIiwibGlicy9pZGVtcG90ZW5jeSIsImxpYnMvYXVkaXQiLCJsaWJzL3NlY3VyaXR5IiwibGlicy9vYnNlcnZhYmlsaXR5IiwiY29ubmVjdG9ycy93ZWNoYXQtcGF5IiwiY29ubmVjdG9ycy9hbGlwYXkiLCJjb25uZWN0b3JzL3N0cmlwZSIsImNvbm5lY3RvcnMvcGF5cGFsIiwiY29ubmVjdG9ycy9hcHBsZS1wYXkiLCJzZXJ2aWNlcy9wYXltZW50LWNvcmUiLCJzZXJ2aWNlcy93ZWJob29rLWluZ3Jlc3MiLCJzZXJ2aWNlcy93ZWJob29rLWRlbGl2ZXJ5Iiwic2VydmljZXMvbWVyY2hhbnQtY29uZmlnIiwic2VydmljZXMvcmlzay1lbmdpbmUiLCJzZXJ2aWNlcy9sZWRnZXItc2VydmljZSIsInNlcnZpY2VzL3JlY29uY2lsaWF0aW9uLXNlcnZpY2UiLCJzZXJ2aWNlcy93b3JrZXItc2NoZWR1bGVyIiwiYXBwcy9lZGdlLWdhdGV3YXkiXQ==' \
STAGING_PROJECT_SOURCE='governance/version-catalog.json#modules_by_build_system.gradle' \
STAGING_ROOT="${STAGING_ROOT}" REPOSITORY_ROOT="${ROOT}" python3 - <<'PY'
import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

root = Path(os.environ["REPOSITORY_ROOT"]).resolve()
final = Path(os.environ["STAGING_ROOT"])
projects = json.loads(base64.b64decode(
    os.environ["STAGING_PROJECTS_B64"], validate=True).decode("utf-8"))
if not isinstance(projects, list) or not projects or len(projects) != len(set(projects)):
    raise SystemExit("Gradle artifact project inventory is empty or duplicated")
project_pattern = re.compile(
    r"^(?:apps|connectors|libs|services)/[a-z0-9]+(?:-[a-z0-9]+)*$")

build = root / "build"
build.mkdir(parents=True, exist_ok=True)
work = Path(tempfile.mkdtemp(prefix="signing-stage.", dir=build))
stage = work / "signing-inputs"
stage.mkdir()
entries = []
try:
    for project in projects:
        if not isinstance(project, str) or not project_pattern.fullmatch(project):
            raise SystemExit(f"unsafe Gradle artifact project path: {project}")
        project_path = Path(project)
        if project_path.is_absolute() or ".." in project_path.parts:
            raise SystemExit(f"unsafe Gradle artifact project path: {project}")
        library_dir = root / project_path / "build" / "libs"
        cursor = root
        for part in (*project_path.parts, "build", "libs"):
            cursor /= part
            if cursor.is_symlink():
                raise SystemExit(f"symlink is forbidden in Gradle artifact path: {project}")
        try:
            library_dir.resolve(strict=False).relative_to(root)
        except ValueError as exc:
            raise SystemExit(f"Gradle artifact project escapes repository: {project}") from exc
        candidates = sorted(library_dir.glob("*.jar")) if library_dir.is_dir() else []
        if not candidates:
            raise SystemExit(f"no JAR artifact found for declared Gradle project: {project}")
        for source in candidates:
            if source.is_symlink() or not source.is_file() or source.stat().st_size == 0:
                raise SystemExit(f"JAR artifact must be a non-empty regular file: {source}")
            relative = source.relative_to(root).as_posix()
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            entries.append({"path": relative, "sha256": digest})

    manifest = {
        "schema_version": "1.0.0",
        "project_source": os.environ["STAGING_PROJECT_SOURCE"],
        "projects": projects,
        "source": {
            "repository": os.environ["GITHUB_REPOSITORY"],
            "git_sha": os.environ["GITHUB_SHA"],
            "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
            "runner_environment": os.environ["RUNNER_ENVIRONMENT"],
        },
        "artifacts": sorted(entries, key=lambda item: item["path"]),
    }
    manifest_path = stage / "artifact-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (stage / "artifact-manifest.sha256").write_text(
        f"{manifest_digest}  artifact-manifest.json\n", encoding="utf-8")
    os.replace(stage, final)
finally:
    shutil.rmtree(work, ignore_errors=True)

print(f"staged {len(entries)} JAR artifact(s) from {len(projects)} declared Gradle projects")
PY
