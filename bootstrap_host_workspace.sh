#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
QA_DIR="${ROOT}/.qa"
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
PLAYWRIGHT_DIR="${ROOT}/playwright"
PLAYWRIGHT_TEST_DIR="${PLAYWRIGHT_DIR}/test"
CONTAINER_RUNTIME_DIR="${QA_DIR}/runtime/container"
LOCAL_PLAYWRIGHT_INSTALL=false
CONTAINER_SETUP=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-playwright-install)
      LOCAL_PLAYWRIGHT_INSTALL=true
      shift
      ;;
    --skip-container-setup)
      CONTAINER_SETUP=false
      shift
      ;;
    -h|--help)
      cat <<EOF
Usage: bash .qa/scripts/bootstrap_host_workspace.sh [options]

Options:
  --with-playwright-install  Install @playwright/test locally in host ./playwright
  --skip-container-setup     Skip container runtime setup/validation
  -h, --help                 Show this help
EOF
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ ! -d "${QA_DIR}" ]]; then
  echo "ERROR: .qa directory not found at ${QA_DIR}" >&2
  echo "Place this repository at <host-workspace>/.qa (submodule/link/copy) first." >&2
  exit 1
fi

if [[ "${SCRIPT_PATH}" != "${QA_DIR}/scripts/"* ]]; then
  echo "ERROR: bootstrap script must run from .qa/scripts." >&2
  echo "Current: ${SCRIPT_PATH}" >&2
  echo "Expected prefix: ${QA_DIR}/scripts/" >&2
  exit 1
fi

mkdir -p \
  "${ROOT}/docs/ops/work_orders" \
  "${ROOT}/docs/reports" \
  "${ROOT}/docs/testplans" \
  "${PLAYWRIGHT_TEST_DIR}" \
  "${QA_DIR}/output" \
  "${QA_DIR}/runtime" \
  "${QA_DIR}/db" \
  "${CONTAINER_RUNTIME_DIR}"

if [[ -f "${QA_DIR}/db/schema.sql" && ! -f "${QA_DIR}/db/qa_history.db" ]]; then
  python3 "${QA_DIR}/startup/init_history_db.py" --db-path "${QA_DIR}/db/qa_history.db"
fi

if [[ "${LOCAL_PLAYWRIGHT_INSTALL}" == "true" ]]; then
  if ! command -v npm >/dev/null 2>&1; then
    echo "ERROR: npm is required to install @playwright/test in ${PLAYWRIGHT_DIR}" >&2
    exit 1
  fi
  if [[ ! -f "${PLAYWRIGHT_DIR}/package.json" ]]; then
    (
      cd "${PLAYWRIGHT_DIR}"
      npm init -y >/dev/null
    )
  fi
  if [[ ! -d "${PLAYWRIGHT_DIR}/node_modules/@playwright/test" ]]; then
    (
      cd "${PLAYWRIGHT_DIR}"
      npm install -D @playwright/test
    )
  fi
fi

if [[ "${CONTAINER_SETUP}" == "true" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required for container setup. Install Docker Desktop/Colima or use --skip-container-setup." >&2
    exit 1
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: docker compose is required. Install compose plugin or use --skip-container-setup." >&2
    exit 1
  fi
  docker compose -f "${QA_DIR}/containers/compose.qa.yml" config >/dev/null
fi

cat <<EOF
Bootstrap complete.
- host root: ${ROOT}
- qa module: ${QA_DIR}
- playwright root: ${PLAYWRIGHT_DIR}
- playwright test dir: ${PLAYWRIGHT_TEST_DIR}
- local playwright install: ${LOCAL_PLAYWRIGHT_INSTALL}
- container setup: ${CONTAINER_SETUP}

Next:
1) Put input docs under docs/ops/work_orders and audit docs path.
2) (Container) run command:
   bash .qa/startup/run_in_qa_container.sh "flutter --version && node --version && npx playwright --version"
3) Run dry-run:
   python .qa/scripts/graph.py --workflow agentic_qa_flow --dev-docs <work_order.md> --audit-docs <audit.md> --out .qa/output/graph_dry_run.json --dry-run
EOF
