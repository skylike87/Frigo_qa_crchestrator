#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="${QA_IMAGE_NAME:-frigo-qa-runner:local}"
WORKSPACE_DIR="${WORKSPACE_DIR:-${ROOT}}"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker command not found." >&2
  exit 1
fi

if [[ ! -d "${WORKSPACE_DIR}" ]]; then
  echo "ERROR: workspace directory not found: ${WORKSPACE_DIR}" >&2
  exit 1
fi

TTY_ARGS=()
if [[ -t 0 && -t 1 ]]; then
  TTY_ARGS=(-it)
fi

if [[ $# -eq 0 ]]; then
  docker run --rm "${TTY_ARGS[@]}" \
    -e CI=true \
    -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    -v "${WORKSPACE_DIR}:/workspace" \
    -w /workspace \
    "${IMAGE_NAME}" bash
else
  docker run --rm "${TTY_ARGS[@]}" \
    -e CI=true \
    -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    -v "${WORKSPACE_DIR}:/workspace" \
    -w /workspace \
    "${IMAGE_NAME}" bash -lc "$*"
fi
