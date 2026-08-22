#!/usr/bin/env bash
# GENERATED FILE — do not edit by hand.
# Source of truth: governance/ci-pipeline.json
# Regenerate with: python3 scripts/render-ci.py

# Keylessly sign the exact JAR and SBOM blobs transferred from earlier jobs,
# then emit and verify SLSA Build L1 provenance. This script deliberately does
# not claim container-image signing or a SLSA level above Build L1.
#
# Public Fulcio/Rekor use exposes repository and provenance metadata. The
# workflow therefore runs this script only after an explicit repository-variable
# opt-in and grants OIDC only to that trusted main-branch signing job.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TRUSTED_EVENT="push"
TRUSTED_REPOSITORY="zpcaiai/elmpay"
TRUSTED_REF="refs/heads/main"
TRUSTED_WORKFLOW=".github/workflows/ci.yml"
OPT_IN_VARIABLE="ELMPAY_PUBLIC_SIGSTORE_METADATA_DISCLOSURE_OPT_IN"
COSIGN_RELEASE="v3.0.6"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
PREDICATE_TYPE="https://slsa.dev/provenance/v1"
BUILD_TYPE="https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
PROJECT_SOURCE="governance/version-catalog.json#modules_by_build_system.gradle"
EXPECTED_PROJECTS_B64='WyJsaWJzL21vbmV5IiwibGlicy9kb21haW4tZXZlbnRzIiwibGlicy9pZGVtcG90ZW5jeSIsImxpYnMvYXVkaXQiLCJsaWJzL3NlY3VyaXR5IiwibGlicy9vYnNlcnZhYmlsaXR5IiwiY29ubmVjdG9ycy93ZWNoYXQtcGF5IiwiY29ubmVjdG9ycy9hbGlwYXkiLCJjb25uZWN0b3JzL3N0cmlwZSIsImNvbm5lY3RvcnMvcGF5cGFsIiwiY29ubmVjdG9ycy9hcHBsZS1wYXkiLCJzZXJ2aWNlcy9wYXltZW50LWNvcmUiLCJzZXJ2aWNlcy93ZWJob29rLWluZ3Jlc3MiLCJzZXJ2aWNlcy93ZWJob29rLWRlbGl2ZXJ5Iiwic2VydmljZXMvbWVyY2hhbnQtY29uZmlnIiwic2VydmljZXMvcmlzay1lbmdpbmUiLCJzZXJ2aWNlcy9sZWRnZXItc2VydmljZSIsInNlcnZpY2VzL3JlY29uY2lsaWF0aW9uLXNlcnZpY2UiLCJzZXJ2aWNlcy93b3JrZXItc2NoZWR1bGVyIiwiYXBwcy9lZGdlLWdhdGV3YXkiXQ=='
MANIFEST_RELATIVE="build/signing-inputs/artifact-manifest.json"
MANIFEST_SHA_RELATIVE="build/signing-inputs/artifact-manifest.sha256"

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
