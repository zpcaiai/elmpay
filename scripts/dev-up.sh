#!/usr/bin/env bash
# Bring the local development platform up (or down) and wait for health.
#
#   scripts/dev-up.sh          start and wait until every service is healthy
#   scripts/dev-up.sh --down   stop and remove containers (volumes are kept)
#
# The compose file is generated from governance/dev-platform.json; this script
# refuses to run against a drifted file so that what starts locally is what the
# governance gate checked.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="${ROOT}/platform/dev"
TIMEOUT_SECONDS="${DEV_UP_TIMEOUT:-300}"

cd "${ROOT}"
python3 scripts/render-dev-platform.py --check

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run the local platform" >&2
  exit 3
fi

if [[ "${1:-}" == "--down" ]]; then
  docker compose -f "${COMPOSE_DIR}/compose.yaml" down
  exit 0
fi

if [[ ! -f "${COMPOSE_DIR}/.env" ]]; then
  echo "missing ${COMPOSE_DIR}/.env — copy .env.example and set local synthetic values" >&2
  exit 3
fi

docker compose -f "${COMPOSE_DIR}/compose.yaml" --env-file "${COMPOSE_DIR}/.env" up -d --build

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
while true; do
  unhealthy=$(docker compose -f "${COMPOSE_DIR}/compose.yaml" ps --format json \
              | python3 -c 'import json,sys
rows=[json.loads(l) for l in sys.stdin if l.strip()]
print(" ".join(r["Service"] for r in rows if r.get("Health") not in ("healthy", "")))')
  if [[ -z "${unhealthy}" ]]; then
    echo "all services healthy"
    break
  fi
  if (( $(date +%s) > deadline )); then
    echo "timed out waiting for: ${unhealthy}" >&2
    docker compose -f "${COMPOSE_DIR}/compose.yaml" ps
    exit 1
  fi
  sleep 3
done
