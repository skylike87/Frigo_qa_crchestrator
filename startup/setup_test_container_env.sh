#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="${ROOT}/containers/Dockerfile.qa"
IMAGE_NAME="${QA_IMAGE_NAME:-frigo-qa-runner:local}"
NO_CACHE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-cache)
      NO_CACHE=true
      shift
      ;;
    -h|--help)
      cat <<EOF
Usage: bash startup/setup_test_container_env.sh [--no-cache]

Build QA test container image before cloning/pulling target workspaces.

Env:
  QA_IMAGE_NAME  Docker image tag (default: frigo-qa-runner:local)
EOF
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker command not found." >&2
  exit 1
fi

if [[ ! -f "${DOCKERFILE}" ]]; then
  echo "ERROR: Dockerfile not found: ${DOCKERFILE}" >&2
  exit 1
fi

BUILD_ARGS=()
if [[ "${NO_CACHE}" == "true" ]]; then
  BUILD_ARGS+=(--no-cache)
fi

echo "[startup] building image: ${IMAGE_NAME}"
docker build "${BUILD_ARGS[@]}" -f "${DOCKERFILE}" -t "${IMAGE_NAME}" "${ROOT}"
echo "[startup] build complete: ${IMAGE_NAME}"
