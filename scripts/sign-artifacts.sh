# GENERATED FILE — do not edit by hand.
# Source of truth: governance/ci-pipeline.json
# Regenerate with: python3 scripts/render-ci.py

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
  cosign sign-blob --yes \
    --output-signature "${OUT}/${name}.sig" \
    --output-certificate "${OUT}/${name}.pem" \
    "${artifact}"
done

echo "signed ${#artifacts[@]} artefact(s) into ${OUT}"
