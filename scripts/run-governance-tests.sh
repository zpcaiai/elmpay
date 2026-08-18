#!/usr/bin/env bash
# Runs the full governance gate and writes machine-readable evidence.
#   usage: scripts/run-governance-tests.sh <BATCH_ID>
set -euo pipefail

BATCH="${1:?usage: run-governance-tests.sh <BATCH_ID>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/evidence/${BATCH}"
mkdir -p "${OUT}/test-results" "${OUT}/runtime" "${OUT}/security"
cd "${ROOT}"

python3 -m unittest discover -s tools/tests -t . -v \
  > "${OUT}/test-results/unittest.log" 2>&1
python3 -m tools.paygov.cli verify-all --repo . \
  > "${OUT}/security/governance-report.json"
python3 -m tools.paygov.cli list-validators --repo . \
  > "${OUT}/runtime/validators.txt"
echo "wrote ${OUT}"
