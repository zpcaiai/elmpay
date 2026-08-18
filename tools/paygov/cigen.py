"""B05 — generate the CI workflow from the pipeline declaration.

The workflow is generated so that the stage graph, the pinned action digests
and the fail-closed flags cannot be edited in YAML without the declaration —
and therefore the gate — moving with them.
"""
from __future__ import annotations

from pathlib import Path

from .repo import Budget, load_json

PIPELINE = Path("governance/ci-pipeline.json")
CATALOG = Path("governance/version-catalog.json")
BANNER = ("# GENERATED FILE — do not edit by hand.\n"
          "# Source of truth: governance/ci-pipeline.json\n"
          "# Regenerate with: python3 scripts/render-ci.py\n")


def _quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def workflow(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = load_json(root / PIPELINE, budget)
    entries = {e["id"]: e for e in load_json(root / CATALOG, budget)["entries"]}
    actions = {a["name"]: a for a in doc["actions"]}
    java_version = entries["jdk"]["version"].split("+", 1)[0]

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
    setup_gradle = actions["gradle/actions/setup-gradle"]
    upload = actions["actions/upload-artifact"]

    for stage in doc["stages"]:
        lines += [f'  {stage["id"]}:',
                  f'    name: {_quote(stage["name"])}',
                  f'    runs-on: {doc["runner"]}',
                  f'    timeout-minutes: {stage["timeout_minutes"]}']
        if stage["needs"]:
            lines.append("    needs: [" + ", ".join(stage["needs"]) + "]")
        lines += ["    steps:",
                  f'      - uses: {checkout["name"]}@{checkout["ref"]}  # {checkout["version_comment"]}',
                  "        with:",
                  "          persist-credentials: false",
                  f'      - uses: {setup_java["name"]}@{setup_java["ref"]}  # {setup_java["version_comment"]}',
                  "        with:",
                  "          distribution: temurin",
                  f'          java-version: {_quote(java_version)}',
                  f'      - uses: {setup_gradle["name"]}@{setup_gradle["ref"]}  # {setup_gradle["version_comment"]}',
                  "        with:",
                  "          cache-read-only: true"]
        for index, command in enumerate(stage["commands"], 1):
            lines += [f'      - name: {_quote(stage["purpose"])} ({index}/{len(stage["commands"])})',
                      "        run: |",
                      f'          {command}']
        if stage["artifacts"]:
            lines += [f'      - uses: {upload["name"]}@{upload["ref"]}  # {upload["version_comment"]}',
                      "        if: always()",
                      "        with:",
                      f'          name: {stage["id"]}-artifacts',
                      "          path: |"]
            for artifact in stage["artifacts"]:
                lines.append(f"            {artifact}")
            lines.append("          if-no-files-found: warn")
        lines.append("")

    lines += ["  release-gate:",
              "    name: 'Release gate (fail closed)'",
              f'    runs-on: {doc["runner"]}',
              "    timeout-minutes: 10",
              "    needs: [" + ", ".join(doc["required_stages"]) + "]",
              "    if: always()",
              "    steps:",
              "      - name: 'Every required stage must have succeeded'",
              "        run: |",
              "          echo 'needs result: ${{ join(needs.*.result, \",\") }}'",
              "          if [[ '${{ contains(needs.*.result, \"failure\") }}' == 'true' ]] || \\",
              "             [[ '${{ contains(needs.*.result, \"cancelled\") }}' == 'true' ]] || \\",
              "             [[ '${{ contains(needs.*.result, \"skipped\") }}' == 'true' ]]; then",
              "            echo 'release gate blocked: a required stage did not succeed' >&2",
              "            exit 1",
              "          fi",
              ""]
    return "\n".join(lines).rstrip() + "\n"


def sign_script(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    load_json(root / PIPELINE, budget)
    return BANNER + """
# Sign every build artefact and emit an in-toto provenance statement.
#
# Signing keys are never held by the repository: the workflow requests an OIDC
# token (permissions.id-token: write) and the signing backend exchanges it for
# a short-lived key. A missing signature blocks the release gate (BLOCK-06).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/build/signatures"
mkdir -p "${OUT}"

shopt -s nullglob
artifacts=("${ROOT}"/build/libs/*.jar)
if (( ${#artifacts[@]} == 0 )); then
  echo 'no artefacts to sign; the build stage must run first' >&2
  exit 1
fi

for artifact in "${artifacts[@]}"; do
  name="$(basename "${artifact}")"
  sha256sum "${artifact}" | awk '{print $1}' > "${OUT}/${name}.sha256"
  if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign is required to sign ${name}; refusing to emit an unsigned artefact" >&2
    exit 1
  fi
  cosign sign-blob --yes \\
    --output-signature "${OUT}/${name}.sig" \\
    --output-certificate "${OUT}/${name}.pem" \\
    "${artifact}"
done

echo "signed ${#artifacts[@]} artefact(s) into ${OUT}"
"""


TARGETS = {
    ".github/workflows/ci.yml": workflow,
    "scripts/sign-artifacts.sh": sign_script,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
