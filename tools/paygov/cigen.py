"""B05 — generate the CI workflow from the pipeline declaration.

The workflow is generated so that the stage graph, the pinned action digests
and the fail-closed flags cannot be edited in YAML without the declaration —
and therefore the gate — moving with them.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from .repo import Budget, load_json

PIPELINE = Path("governance/ci-pipeline.json")
CATALOG = Path("governance/version-catalog.json")
MODULE_REGISTRY = Path("governance/module-registry.json")
BANNER = ("# GENERATED FILE — do not edit by hand.\n"
          "# Source of truth: governance/ci-pipeline.json\n"
          "# Regenerate with: python3 scripts/render-ci.py\n")
SCRIPT_BANNER = "#!/usr/bin/env bash\n" + BANNER


def _quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _artifact_projects(root: Path, budget: Budget) -> list[str]:
    catalog = load_json(root / CATALOG, budget)
    registry = load_json(root / MODULE_REGISTRY, budget)
    paths = {module["name"]: module["path"] for module in registry["modules"]}
    return [paths[name] for name in catalog["modules_by_build_system"]["gradle"]]


def _result_environment(stage_id: str) -> str:
    return "ELMPAY_NEEDS_" + stage_id.upper().replace("-", "_")


def _release_gate_script(doc: dict) -> str:
    signing = doc["signing_policy"]
    required = doc["required_stages"]
    release_only = signing["validation_only_skipped_stages"]
    non_release = [stage for stage in required if stage not in set(release_only)]
    template = r'''set -euo pipefail

TRUSTED_EVENT="@@TRUSTED_EVENT@@"
TRUSTED_REPOSITORY="@@TRUSTED_REPOSITORY@@"
TRUSTED_REF="@@TRUSTED_REF@@"
REQUIRED_STAGES=(@@REQUIRED_STAGES@@)
RELEASE_ONLY_STAGES=(@@RELEASE_ONLY_STAGES@@)
NON_RELEASE_REQUIRED_STAGES=(@@NON_RELEASE_REQUIRED_STAGES@@)

for variable in ELMPAY_GATE_EVENT_NAME ELMPAY_GATE_REPOSITORY ELMPAY_GATE_REF; do
  if [[ ! -v "${variable}" || -z "${!variable}" ]]; then
    echo "release gate blocked: required context '${variable}' is missing" >&2
    exit 1
  fi
done

stage_result() {
  local stage="$1"
  local variable="ELMPAY_NEEDS_${stage^^}"
  variable="${variable//-/_}"
  if [[ ! -v "${variable}" || -z "${!variable}" ]]; then
    echo "release gate blocked: result for '${stage}' is missing" >&2
    return 1
  fi
  printf '%s' "${!variable}"
}

if [[ "${ELMPAY_GATE_EVENT_NAME}" == "${TRUSTED_EVENT}" &&
      "${ELMPAY_GATE_REPOSITORY}" == "${TRUSTED_REPOSITORY}" &&
      "${ELMPAY_GATE_REF}" == "${TRUSTED_REF}" ]]; then
  if [[ "${ELMPAY_SIGNING_OPT_IN:-}" != 'true' ]]; then
    echo 'release gate blocked: public Sigstore metadata disclosure was not explicitly opted in' >&2
    exit 1
  fi
  for stage in "${REQUIRED_STAGES[@]}"; do
    result="$(stage_result "${stage}")"
    if [[ "${result}" != 'success' ]]; then
      echo "release gate blocked: required stage '${stage}' was '${result}'" >&2
      exit 1
    fi
  done
  for variable in ELMPAY_RELEASE_MANIFEST_B64 ELMPAY_RELEASE_TRUST_B64 \
                  ELMPAY_EXTERNAL_EVIDENCE_B64 ELMPAY_EXTERNAL_TRUST_B64 \
                  ELMPAY_PRODUCT_IMAGE_INDEX_B64 \
                  ELMPAY_GATE_SHA; do
    if [[ ! -v "${variable}" || -z "${!variable}" ]]; then
      echo "release gate blocked: protected evidence input '${variable}' is missing" >&2
      exit 1
    fi
  done
  python3 scripts/ci-release-evidence-gate.py
  echo 'release-eligible: trusted main push, all required stages and signed external evidence succeeded'
  exit 0
fi

for stage in "${RELEASE_ONLY_STAGES[@]}"; do
  result="$(stage_result "${stage}")"
  if [[ "${result}" != 'skipped' ]]; then
    echo "validation gate blocked: release-only stage '${stage}' unexpectedly ran as '${result}'" >&2
    exit 1
  fi
done
for stage in "${NON_RELEASE_REQUIRED_STAGES[@]}"; do
  result="$(stage_result "${stage}")"
  if [[ "${result}" != 'success' ]]; then
    echo "validation gate blocked: required stage '${stage}' was '${result}'" >&2
    exit 1
  fi
done
echo '@@VALIDATION_ONLY_OUTCOME@@: validation succeeded; signing and release evidence were intentionally skipped'
'''
    replacements = {
        "@@TRUSTED_EVENT@@": signing["trusted_event"],
        "@@TRUSTED_REPOSITORY@@": signing["trusted_repository"],
        "@@TRUSTED_REF@@": signing["trusted_ref"],
        "@@REQUIRED_STAGES@@": " ".join(required),
        "@@RELEASE_ONLY_STAGES@@": " ".join(release_only),
        "@@NON_RELEASE_REQUIRED_STAGES@@": " ".join(non_release),
        "@@VALIDATION_ONLY_OUTCOME@@": signing["validation_only_outcome"],
    }
    for marker, value in replacements.items():
        template = template.replace(marker, str(value))
    return template


def release_gate_script(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    return _release_gate_script(load_json(root / PIPELINE, budget))


def workflow(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = load_json(root / PIPELINE, budget)
    signing = doc["signing_policy"]
    cache_policy = doc["gradle_cache_policy"]
    entries = {e["id"]: e for e in load_json(root / CATALOG, budget)["entries"]}
    actions = {a["name"]: a for a in doc["actions"]}
    java_version = entries["jdk"]["version"].split("+", 1)[0]
    node_version = entries["node"]["version"]
    dart_version = entries["dart-sdk"]["version"]
    go_version = entries["go-toolchain"]["version"]
    dotnet_version = entries["dotnet-sdk"]["version"]
    python_reference = entries["python-toolchain"]["version"]
    python_floor = entries["python-toolchain"]["minimum_supported"]

    lines = [BANNER, "name: ci", "", "on:"]
    push = doc["triggers"]["push"]
    lines += ["  push:", "    branches:"] + [f"      - {b}" for b in push]
    lines += ["  pull_request:", "    branches:"] + \
             [f"      - {b}" for b in doc["triggers"]["pull_request"]]
    if doc["triggers"].get("workflow_dispatch"):
        lines.append("  workflow_dispatch: {}")

    lines += ["", "permissions:"]
    for key in sorted(doc["permissions"]):
        lines.append(f'  {key}: {doc["permissions"][key]}')

    lines += ["", "concurrency:",
              "  group: ci-${{ github.ref }}",
              "  cancel-in-progress: false",
              "",
              "defaults:", "  run:", "    shell: bash", "", "jobs:"]

    checkout = actions["actions/checkout"]
    setup_java = actions["actions/setup-java"]
    setup_node = actions["actions/setup-node"]
    setup_python = actions["actions/setup-python"]
    setup_dart = actions["dart-lang/setup-dart"]
    setup_go = actions["actions/setup-go"]
    setup_dotnet = actions["actions/setup-dotnet"]
    setup_gradle = actions["gradle/actions/setup-gradle"]
    cache_restore = actions[cache_policy["dependency_data_restore_action"]]
    cache_save = actions[cache_policy["dependency_data_save_action"]]
    upload = actions["actions/upload-artifact"]
    download = actions["actions/download-artifact"]
    cosign_installer = actions["sigstore/cosign-installer"]

    sign_condition = (
        f"github.event_name == '{signing['trusted_event']}' && "
        f"github.repository == '{signing['trusted_repository']}' && "
        f"github.ref == '{signing['trusted_ref']}' && "
        f"vars.{signing['public_sigstore_opt_in_variable']} == 'true'"
    )

    for stage in doc["stages"]:
        lines += [f'  {stage["id"]}:',
                  f'    name: {_quote(stage["name"])}',
                  f'    runs-on: {stage.get("runner", doc["runner"])}',
                  f'    timeout-minutes: {stage["timeout_minutes"]}']
        if stage["needs"]:
            lines.append("    needs: [" + ", ".join(stage["needs"]) + "]")
        if stage["id"] == "sign":
            lines.append(f"    if: {sign_condition}")
            lines.append("    permissions:")
            for key in sorted(signing["job_permissions"]):
                lines.append(f'      {key}: {signing["job_permissions"][key]}')
        lines += ["    steps:",
                  f'      - uses: {checkout["name"]}@{checkout["ref"]}  # {checkout["version_comment"]}',
                  "        with:",
                  "          persist-credentials: false",
                  f'      - uses: {setup_python["name"]}@{setup_python["ref"]}  # {setup_python["version_comment"]}',
                  "        with:",
                  f'          python-version: {_quote(python_floor if stage["id"] == "python-floor" else python_reference)}']
        if stage["id"] == "unit-test":
            lines += [
                f'      - uses: {setup_node["name"]}@{setup_node["ref"]}  # {setup_node["version_comment"]}',
                "        with:",
                f'          node-version: {_quote(node_version)}',
                f'      - uses: {setup_go["name"]}@{setup_go["ref"]}  # {setup_go["version_comment"]}',
                "        with:",
                f'          go-version: {_quote(go_version)}',
                "          cache: false",
                f'      - uses: {setup_dotnet["name"]}@{setup_dotnet["ref"]}  # {setup_dotnet["version_comment"]}',
                "        with:",
                f'          dotnet-version: {_quote(dotnet_version)}',
            ]
        if stage["id"] == "flutter-sdk-test":
            lines += [
                f'      - uses: {setup_dart["name"]}@{setup_dart["ref"]}  # {setup_dart["version_comment"]}',
                "        with:",
                f'          sdk: {_quote(dart_version)}',
            ]
        if stage["id"] == "sign":
            for item in signing["downloads"]:
                lines += [
                    f'      - uses: {download["name"]}@{download["ref"]}  # {download["version_comment"]}',
                    "        with:",
                    f'          name: {item["name"]}',
                    f'          path: {item["path"]}',
                ]
            lines += [
                f'      - uses: {cosign_installer["name"]}@{cosign_installer["ref"]}  # {cosign_installer["version_comment"]}',
                "        with:",
                f'          cosign-release: {_quote(signing["cosign_release"])}',
            ]
        elif stage["id"] not in {"ios-sdk-test", "flutter-sdk-test"}:
            if stage["id"] == cache_policy["writer_stage"]:
                cache_read_only = (
                    "${{ github.event_name != '" + cache_policy["trusted_event"]
                    + "' || github.repository != '" + cache_policy["trusted_repository"]
                    + "' || github.ref != '" + cache_policy["trusted_ref"] + "' }}"
                )
            else:
                cache_read_only = "true"
            lines += [
                f'      - uses: {setup_java["name"]}@{setup_java["ref"]}  # {setup_java["version_comment"]}',
                "        with:",
                "          distribution: temurin",
                f'          java-version: {_quote(java_version)}',
                f'      - uses: {setup_gradle["name"]}@{setup_gradle["ref"]}  # {setup_gradle["version_comment"]}',
                "        with:",
                f"          cache-read-only: {cache_read_only}",
            ]
            if stage["id"] == cache_policy["dependency_data_stage"]:
                lines += [
                    f'      - uses: {cache_restore["name"]}@{cache_restore["ref"]}  # {cache_restore["version_comment"]}',
                    "        id: dependency-check-cache",
                    "        with:",
                    f'          path: {cache_policy["dependency_data_cache_path"]}',
                    f'          key: {cache_policy["dependency_data_cache_key"]}',
                    "          restore-keys: |",
                    f'            {cache_policy["dependency_data_restore_key"]}',
                ]
        for index, command in enumerate(stage["commands"], 1):
            step_name = f'{stage["purpose"]} ({index}/{len(stage["commands"])})'
            lines.append(f'      - name: {_quote(step_name)}')
            if stage["id"] == "sign":
                lines += [
                    "        env:",
                    f'          {signing["public_sigstore_opt_in_variable"]}: '
                    f'${{{{ vars.{signing["public_sigstore_opt_in_variable"]} }}}}',
                ]
            lines += ["        run: |", f'          {command}']
        if stage["id"] == cache_policy["dependency_data_stage"]:
            save_condition = (
                "success() && github.event_name == '" + cache_policy["trusted_event"]
                + "' && github.repository == '" + cache_policy["trusted_repository"]
                + "' && github.ref == '" + cache_policy["trusted_ref"] + "'"
            )
            lines += [
                f'      - uses: {cache_save["name"]}@{cache_save["ref"]}  # {cache_save["version_comment"]}',
                f"        if: {save_condition}",
                "        with:",
                f'          path: {cache_policy["dependency_data_cache_path"]}',
                "          key: ${{ steps.dependency-check-cache.outputs.cache-primary-key }}",
            ]
        if stage["artifacts"]:
            lines += [f'      - uses: {upload["name"]}@{upload["ref"]}  # {upload["version_comment"]}',
                      "        if: always()",
                      "        with:",
                      f'          name: {stage["id"]}-artifacts',
                      "          path: |"]
            for artifact in stage["artifacts"]:
                lines.append(f"            {artifact}")
            lines.append(f'          if-no-files-found: {stage.get("if_no_files_found", "warn")}')
        lines.append("")

    lines += ["  release-gate:",
              "    name: 'Terminal release / validation gate (fail closed)'",
              f'    runs-on: {doc["runner"]}',
              "    timeout-minutes: 10",
              "    needs: [" + ", ".join(doc["required_stages"]) + "]",
              "    if: always()",
              "    steps:",
              f'      - uses: {checkout["name"]}@{checkout["ref"]}  # {checkout["version_comment"]}',
              "        with:",
              "          persist-credentials: false",
              f'      - uses: {setup_python["name"]}@{setup_python["ref"]}  # {setup_python["version_comment"]}',
              "        with:",
              f'          python-version: {_quote(python_reference)}',
              "      - name: 'Enforce release context or validation-only context'",
              "        # Per-stage checks replace contains(needs.*.result, 'failure').",
              "        # Per-stage diagnostics replace join(needs.*.result, ',').",
              "        env:",
              "          ELMPAY_GATE_EVENT_NAME: ${{ github.event_name }}",
              "          ELMPAY_GATE_REPOSITORY: ${{ github.repository }}",
              "          ELMPAY_GATE_REF: ${{ github.ref }}",
              "          ELMPAY_GATE_SHA: ${{ github.sha }}",
              "          ELMPAY_RELEASE_MANIFEST_B64: ${{ secrets.ELMPAY_RELEASE_MANIFEST_B64 }}",
              "          ELMPAY_RELEASE_TRUST_B64: ${{ secrets.ELMPAY_RELEASE_TRUST_B64 }}",
              "          ELMPAY_EXTERNAL_EVIDENCE_B64: ${{ secrets.ELMPAY_EXTERNAL_EVIDENCE_B64 }}",
              "          ELMPAY_EXTERNAL_TRUST_B64: ${{ secrets.ELMPAY_EXTERNAL_TRUST_B64 }}",
              "          ELMPAY_PRODUCT_IMAGE_INDEX_B64: ${{ secrets.ELMPAY_PRODUCT_IMAGE_INDEX_B64 }}",
              f'          ELMPAY_SIGNING_OPT_IN: '
              f'${{{{ vars.{signing["public_sigstore_opt_in_variable"]} }}}}']
    for stage_id in doc["required_stages"]:
        lines.append(
            f"          {_result_environment(stage_id)}: "
            f"${{{{ needs[{_quote(stage_id)}].result }}}}"
        )
    lines.append("        run: |")
    for script_line in _release_gate_script(doc).rstrip().splitlines():
        lines.append(f"          {script_line}" if script_line else "")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def stage_signing_artifacts_script(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = load_json(root / PIPELINE, budget)
    projects = _artifact_projects(root, budget)
    signing = doc["signing_policy"]
    template = r'''
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

STAGING_PROJECTS_B64='@@PROJECTS_B64@@' \
STAGING_PROJECT_SOURCE='@@PROJECT_SOURCE@@' \
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
    r"^(?:(?:apps|connectors|libs|services)/[a-z0-9]+(?:-[a-z0-9]+)*|"
    r"sdks/mobile/android)$")

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
'''
    replacements = {
        "@@PROJECTS_B64@@": base64.b64encode(
            json.dumps(projects, separators=(",", ":")).encode("utf-8")
        ).decode("ascii"),
        "@@PROJECT_SOURCE@@": signing["artifact_project_source"],
    }
    for marker, value in replacements.items():
        template = template.replace(marker, str(value))
    return SCRIPT_BANNER + template


def sign_script(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = load_json(root / PIPELINE, budget)
    signing = doc["signing_policy"]
    projects = _artifact_projects(root, budget)
    template = r'''
# Keylessly sign the exact JAR and SBOM blobs transferred from earlier jobs,
# then emit and verify SLSA Build L1 provenance. This script deliberately does
# not claim container-image signing or a SLSA level above Build L1.
#
# Public Fulcio/Rekor use exposes repository and provenance metadata. The
# workflow therefore runs this script only after an explicit repository-variable
# opt-in and grants OIDC only to that trusted main-branch signing job.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TRUSTED_EVENT="@@TRUSTED_EVENT@@"
TRUSTED_REPOSITORY="@@TRUSTED_REPOSITORY@@"
TRUSTED_REF="@@TRUSTED_REF@@"
TRUSTED_WORKFLOW="@@TRUSTED_WORKFLOW@@"
OPT_IN_VARIABLE="@@OPT_IN_VARIABLE@@"
COSIGN_RELEASE="@@COSIGN_RELEASE@@"
OIDC_ISSUER="@@OIDC_ISSUER@@"
PREDICATE_TYPE="@@PREDICATE_TYPE@@"
BUILD_TYPE="@@BUILD_TYPE@@"
PROJECT_SOURCE="@@PROJECT_SOURCE@@"
EXPECTED_PROJECTS_B64='@@PROJECTS_B64@@'
MANIFEST_RELATIVE="@@MANIFEST@@"
MANIFEST_SHA_RELATIVE="@@MANIFEST_SHA@@"

required_environment=(
  GITHUB_ACTIONS GITHUB_EVENT_NAME GITHUB_REPOSITORY GITHUB_REF GITHUB_SHA
  GITHUB_WORKFLOW_REF GITHUB_SERVER_URL GITHUB_RUN_ID GITHUB_RUN_ATTEMPT
  GITHUB_REPOSITORY_ID GITHUB_REPOSITORY_OWNER_ID RUNNER_ENVIRONMENT
  ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN
)
for required in "${required_environment[@]}"; do
  if [[ ! -v "${required}" || -z "${!required}" ]]; then
    echo "required signing environment '${required}' is missing" >&2
    exit 1
  fi
done

if [[ "${GITHUB_ACTIONS}" != 'true' ||
      "${RUNNER_ENVIRONMENT}" != 'github-hosted' ||
      "${GITHUB_EVENT_NAME}" != "${TRUSTED_EVENT}" ||
      "${GITHUB_REPOSITORY}" != "${TRUSTED_REPOSITORY}" ||
      "${GITHUB_REF}" != "${TRUSTED_REF}" ]]; then
  echo 'refusing to sign outside the trusted main push context' >&2
  exit 1
fi

expected_workflow_ref="${TRUSTED_REPOSITORY}/${TRUSTED_WORKFLOW}@${TRUSTED_REF}"
if [[ "${GITHUB_WORKFLOW_REF}" != "${expected_workflow_ref}" ]]; then
  echo "workflow identity '${GITHUB_WORKFLOW_REF}' is not trusted" >&2
  exit 1
fi

if [[ ! -v "${OPT_IN_VARIABLE}" || "${!OPT_IN_VARIABLE}" != 'true' ]]; then
  echo "public Sigstore metadata disclosure is not opted in via ${OPT_IN_VARIABLE}" >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo 'cosign is required; refusing to emit an unsigned artefact' >&2
  exit 1
fi
installed_cosign="$(cosign version 2>&1 | sed -n 's/^[[:space:]]*GitVersion:[[:space:]]*//p' | head -n 1 | tr -d '\r')"
if [[ "${installed_cosign}" != "${COSIGN_RELEASE}" ]]; then
  echo "cosign ${COSIGN_RELEASE} is required; found '${installed_cosign:-unknown}'" >&2
  exit 1
fi

FINAL_SIGNATURES="${ROOT}/build/signatures"
FINAL_PROVENANCE="${ROOT}/build/provenance.intoto.jsonl"
if [[ -e "${FINAL_SIGNATURES}" || -e "${FINAL_PROVENANCE}" ]]; then
  echo 'stale signing output exists; refusing to mix evidence from different runs' >&2
  exit 1
fi

WORK="$(mktemp -d "${ROOT}/build/signing-work.XXXXXX")"
cleanup() {
  if [[ -n "${WORK:-}" && "${WORK}" == "${ROOT}"/build/signing-work.* && -d "${WORK}" ]]; then
    rm -rf -- "${WORK}"
  fi
}
trap cleanup EXIT
OUT="${WORK}/signatures"
mkdir -p "${OUT}"
STATEMENT="${OUT}/provenance.statement.json"
PROVENANCE_BUNDLE="${OUT}/provenance.sigstore.json"
PROVENANCE_JSONL="${WORK}/provenance.intoto.jsonl"
SUBJECTS_NUL="${WORK}/subjects.nul"

SIGNING_ROOT="${ROOT}" SIGNING_STATEMENT="${STATEMENT}" \
SIGNING_SUBJECTS_NUL="${SUBJECTS_NUL}" EXPECTED_PROJECTS_B64="${EXPECTED_PROJECTS_B64}" \
PROJECT_SOURCE="${PROJECT_SOURCE}" MANIFEST_RELATIVE="${MANIFEST_RELATIVE}" \
MANIFEST_SHA_RELATIVE="${MANIFEST_SHA_RELATIVE}" OPT_IN_VARIABLE="${OPT_IN_VARIABLE}" \
PREDICATE_TYPE="${PREDICATE_TYPE}" BUILD_TYPE="${BUILD_TYPE}" python3 - <<'PY'
import base64
import hashlib
import json
import os
import re
import zipfile
from pathlib import Path, PurePosixPath

root = Path(os.environ["SIGNING_ROOT"]).resolve()
manifest_path = root / os.environ["MANIFEST_RELATIVE"]
manifest_sha_path = root / os.environ["MANIFEST_SHA_RELATIVE"]
stage_root = manifest_path.parent
sbom = root / "build/reports/bom.json"
expected_projects = json.loads(base64.b64decode(
    os.environ["EXPECTED_PROJECTS_B64"], validate=True).decode("utf-8"))

def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

for required in (manifest_path, manifest_sha_path, sbom):
    if required.is_symlink() or not required.is_file() or required.stat().st_size == 0:
        raise SystemExit(f"required signing input is missing, empty or a symlink: {required}")

sidecar = manifest_sha_path.read_text(encoding="utf-8")
match = re.fullmatch(r"([0-9a-f]{64})  artifact-manifest\.json\n?", sidecar)
if not match or match.group(1) != hash_file(manifest_path):
    raise SystemExit("artifact manifest SHA-256 sidecar does not match the manifest")

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("schema_version") != "1.0.0":
    raise SystemExit("unsupported artifact manifest schema")
if manifest.get("project_source") != os.environ["PROJECT_SOURCE"]:
    raise SystemExit("artifact manifest project source does not match governance")
if manifest.get("projects") != expected_projects:
    raise SystemExit("artifact manifest project inventory does not match governance")
expected_source = {
    "repository": os.environ["GITHUB_REPOSITORY"],
    "git_sha": os.environ["GITHUB_SHA"],
    "run_id": os.environ["GITHUB_RUN_ID"],
    "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
    "runner_environment": os.environ["RUNNER_ENVIRONMENT"],
}
if manifest.get("source") != expected_source:
    raise SystemExit("artifact manifest source identity does not match this workflow run")
entries = manifest.get("artifacts")
if not isinstance(entries, list) or not entries:
    raise SystemExit("artifact manifest contains no JAR subjects")
if entries != sorted(entries, key=lambda item: str(item.get("path", ""))):
    raise SystemExit("artifact manifest entries must be sorted by path")

declared_paths = []
jar_paths = []
for entry in entries:
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
        raise SystemExit("artifact manifest entry has an invalid shape")
    relative = PurePosixPath(entry["path"])
    if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".jar":
        raise SystemExit(f"unsafe or non-JAR artifact manifest path: {relative}")
    matching_projects = [project for project in expected_projects
                         if relative.parent == PurePosixPath(project) / "build" / "libs"]
    if len(matching_projects) != 1:
        raise SystemExit(f"manifest path is outside a declared Gradle project: {relative}")
    if not re.fullmatch(r"[0-9a-f]{64}", str(entry["sha256"])):
        raise SystemExit(f"invalid SHA-256 in artifact manifest: {relative}")
    path = stage_root / Path(*relative.parts)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f"manifested JAR is missing, empty or a symlink: {relative}")
    if hash_file(path) != entry["sha256"]:
        raise SystemExit(f"manifest SHA-256 mismatch for: {relative}")
    declared_paths.append(relative.as_posix())
    jar_paths.append(path)

if len(declared_paths) != len(set(declared_paths)):
    raise SystemExit("artifact manifest contains duplicate paths")
for project in expected_projects:
    prefix = PurePosixPath(project) / "build" / "libs"
    if not any(PurePosixPath(path).parent == prefix for path in declared_paths):
        raise SystemExit(f"artifact manifest omits declared Gradle project: {project}")

actual_files = set()
for path in stage_root.rglob("*"):
    if path.is_symlink():
        raise SystemExit(f"symlink is forbidden in staged signing inputs: {path}")
    if path.is_file():
        actual_files.add(path.relative_to(stage_root).as_posix())
expected_files = set(declared_paths) | {
    manifest_path.name,
    manifest_sha_path.name,
}
if actual_files != expected_files:
    missing = sorted(expected_files - actual_files)
    extra = sorted(actual_files - expected_files)
    raise SystemExit(f"staged artifact path set differs from manifest; missing={missing}, extra={extra}")

for jar in jar_paths:
    try:
        with zipfile.ZipFile(jar) as archive:
            corrupt = archive.testzip()
            if corrupt is not None:
                raise SystemExit(f"JAR contains a corrupt ZIP entry: {jar}: {corrupt}")
            payload = [info for info in archive.infolist()
                       if not info.is_dir()
                       and info.filename.upper() != "META-INF"
                       and not info.filename.upper().startswith("META-INF/")]
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise SystemExit(f"JAR is not a valid non-empty ZIP: {jar}") from exc
    if not payload:
        raise SystemExit(f"JAR has no payload entry outside META-INF: {jar}")

try:
    sbom_document = json.loads(sbom.read_text(encoding="utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError) as exc:
    raise SystemExit("SBOM is not valid UTF-8 CycloneDX JSON") from exc
if not isinstance(sbom_document, dict) or sbom_document.get("bomFormat") != "CycloneDX":
    raise SystemExit("SBOM JSON is not a CycloneDX document")

subject_paths = jar_paths + [manifest_path, manifest_sha_path, sbom]
subjects = []
for path in subject_paths:
    resolved = path.resolve(strict=True)
    try:
        name = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise SystemExit(f"subject escapes repository: {resolved}") from exc
    subjects.append({"name": name, "digest": {"sha256": hash_file(resolved)}})

workflow_ref = os.environ["GITHUB_WORKFLOW_REF"]
prefix = os.environ["GITHUB_REPOSITORY"] + "/"
if not workflow_ref.startswith(prefix) or "@" not in workflow_ref:
    raise SystemExit("GITHUB_WORKFLOW_REF is not a repository workflow reference")
workflow_path, workflow_revision = workflow_ref[len(prefix):].rsplit("@", 1)
if workflow_revision != os.environ["GITHUB_REF"]:
    raise SystemExit("workflow revision does not match the signed source ref")

server = os.environ["GITHUB_SERVER_URL"].rstrip("/")
repository = os.environ["GITHUB_REPOSITORY"]
statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": sorted(subjects, key=lambda item: item["name"]),
    "predicateType": os.environ["PREDICATE_TYPE"],
    "predicate": {
        "buildDefinition": {
            "buildType": os.environ["BUILD_TYPE"],
            "externalParameters": {
                "workflow": {
                    "ref": workflow_revision,
                    "repository": f"{server}/{repository}",
                    "path": workflow_path,
                },
                "vars": {os.environ["OPT_IN_VARIABLE"]: "true"},
            },
            "internalParameters": {
                "github": {
                    "event_name": os.environ["GITHUB_EVENT_NAME"],
                    "repository_id": os.environ["GITHUB_REPOSITORY_ID"],
                    "repository_owner_id": os.environ["GITHUB_REPOSITORY_OWNER_ID"],
                }
            },
            "resolvedDependencies": [{
                "uri": f"git+{server}/{repository}@{os.environ['GITHUB_REF']}",
                "digest": {"gitCommit": os.environ["GITHUB_SHA"]},
            }],
        },
        "runDetails": {
            "builder": {
                "id": f"{server}/{workflow_ref}"
            },
            "metadata": {
                "invocationId": (
                    f"{server}/{repository}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
                    f"/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}"
                )
            },
        },
    },
}
Path(os.environ["SIGNING_STATEMENT"]).write_text(
    json.dumps(statement, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
with Path(os.environ["SIGNING_SUBJECTS_NUL"]).open("wb") as stream:
    for path in subject_paths:
        stream.write(os.fsencode(path) + b"\0")
PY

artifacts=()
while IFS= read -r -d '' artifact; do
  artifacts+=("${artifact}")
done < "${SUBJECTS_NUL}"
if (( ${#artifacts[@]} == 0 )); then
  echo 'validated artifact manifest produced no signing subjects' >&2
  exit 1
fi

certificate_identity="https://github.com/${GITHUB_WORKFLOW_REF}"
for artifact in "${artifacts[@]}"; do
  relative="${artifact#"${ROOT}"/}"
  if [[ "${relative}" == "${artifact}" || "${relative}" == /* ]]; then
    echo "subject path is not repository-relative: ${artifact}" >&2
    exit 1
  fi
  safe_name="$(printf '%s' "${relative}" | sha256sum | awk '{print $1}')"
  digest="$(sha256sum "${artifact}" | awk '{print $1}')"
  printf '%s  %s\n' "${digest}" "${relative}" > "${OUT}/${safe_name}.sha256"
  (cd "${ROOT}" && sha256sum --check "${OUT}/${safe_name}.sha256" >/dev/null)
  cosign sign-blob --yes --new-bundle-format=true \
    --bundle "${OUT}/${safe_name}.blob.sigstore.json" \
    "${artifact}" >/dev/null
  test -s "${OUT}/${safe_name}.blob.sigstore.json"
done

cosign attest-blob --yes --new-bundle-format=true \
  --statement "${STATEMENT}" \
  --bundle "${PROVENANCE_BUNDLE}" \
  "${artifacts[0]}" >/dev/null
test -s "${PROVENANCE_BUNDLE}"

SIGNING_STATEMENT="${STATEMENT}" SIGNING_BUNDLE="${PROVENANCE_BUNDLE}" \
SIGNING_JSONL="${PROVENANCE_JSONL}" python3 - <<'PY'
import base64
import json
import os
from pathlib import Path

statement = json.loads(Path(os.environ["SIGNING_STATEMENT"]).read_text(encoding="utf-8"))
bundle = json.loads(Path(os.environ["SIGNING_BUNDLE"]).read_text(encoding="utf-8"))
envelope = bundle.get("dsseEnvelope")
if not isinstance(envelope, dict) or not envelope.get("signatures"):
    raise SystemExit("Sigstore bundle does not contain a signed DSSE envelope")
if envelope.get("payloadType") != "application/vnd.in-toto+json":
    raise SystemExit("Sigstore bundle DSSE payload type is not in-toto JSON")
payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
if payload != statement:
    raise SystemExit("signed DSSE payload does not match the generated SLSA statement")
Path(os.environ["SIGNING_JSONL"]).write_text(
    json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

for artifact in "${artifacts[@]}"; do
  relative="${artifact#"${ROOT}"/}"
  if [[ "${relative}" == "${artifact}" || "${relative}" == /* ]]; then
    echo "subject path is not repository-relative: ${artifact}" >&2
    exit 1
  fi
  safe_name="$(printf '%s' "${relative}" | sha256sum | awk '{print $1}')"
  cosign verify-blob \
    --new-bundle-format=true \
    --bundle "${OUT}/${safe_name}.blob.sigstore.json" \
    --certificate-identity "${certificate_identity}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    --certificate-github-workflow-repository "${GITHUB_REPOSITORY}" \
    --certificate-github-workflow-ref "${GITHUB_REF}" \
    --certificate-github-workflow-sha "${GITHUB_SHA}" \
    --certificate-github-workflow-trigger "${GITHUB_EVENT_NAME}" \
    "${artifact}" > "${OUT}/${safe_name}.blob.verify.log" 2>&1
  test -s "${OUT}/${safe_name}.blob.verify.log"
  cosign verify-blob-attestation \
    --new-bundle-format=true \
    --check-claims=true \
    --bundle "${PROVENANCE_BUNDLE}" \
    --type slsaprovenance1 \
    --certificate-identity "${certificate_identity}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    --certificate-github-workflow-repository "${GITHUB_REPOSITORY}" \
    --certificate-github-workflow-ref "${GITHUB_REF}" \
    --certificate-github-workflow-sha "${GITHUB_SHA}" \
    --certificate-github-workflow-trigger "${GITHUB_EVENT_NAME}" \
    "${artifact}" > "${OUT}/${safe_name}.provenance.verify.log" 2>&1
  test -s "${OUT}/${safe_name}.provenance.verify.log"
done

test -s "${PROVENANCE_JSONL}"
mv "${OUT}" "${FINAL_SIGNATURES}"
mv "${PROVENANCE_JSONL}" "${FINAL_PROVENANCE}"
echo "signed and self-verified ${#artifacts[@]} blob subject(s) with SLSA Build L1 provenance"
'''
    replacements = {
        "@@TRUSTED_EVENT@@": signing["trusted_event"],
        "@@TRUSTED_REPOSITORY@@": signing["trusted_repository"],
        "@@TRUSTED_REF@@": signing["trusted_ref"],
        "@@TRUSTED_WORKFLOW@@": signing["trusted_workflow"],
        "@@OPT_IN_VARIABLE@@": signing["public_sigstore_opt_in_variable"],
        "@@COSIGN_RELEASE@@": signing["cosign_release"],
        "@@OIDC_ISSUER@@": signing["oidc_issuer"],
        "@@PREDICATE_TYPE@@": signing["predicate_type"],
        "@@BUILD_TYPE@@": signing["build_type"],
        "@@PROJECT_SOURCE@@": signing["artifact_project_source"],
        "@@PROJECTS_B64@@": base64.b64encode(
            json.dumps(projects, separators=(",", ":")).encode("utf-8")
        ).decode("ascii"),
        "@@MANIFEST@@": signing["artifact_manifest"],
        "@@MANIFEST_SHA@@": signing["artifact_manifest_sha256"],
    }
    for marker, value in replacements.items():
        template = template.replace(marker, str(value))
    return SCRIPT_BANNER + template


TARGETS = {
    ".github/workflows/ci.yml": workflow,
    "scripts/stage-signing-artifacts.sh": stage_signing_artifacts_script,
    "scripts/sign-artifacts.sh": sign_script,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
