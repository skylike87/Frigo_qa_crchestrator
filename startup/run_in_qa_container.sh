#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
QA_DIR="${ROOT}/.qa"
COMPOSE_FILE="${QA_DIR}/containers/compose.qa.yml"

if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "ERROR: compose file not found: ${COMPOSE_FILE}" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker command not found." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose command not available." >&2
  exit 1
fi

if [[ $# -eq 0 ]]; then
  docker compose -f "${COMPOSE_FILE}" run --rm qa-runner bash
else
  docker compose -f "${COMPOSE_FILE}" run --rm qa-runner bash -lc "$*"
fi
