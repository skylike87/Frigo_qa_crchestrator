# .qa Submodule Migration Guide

This repository is designed to be mounted at `<host-workspace>/.qa`.

## 1) Recommended: Git submodule

From the host workspace root:

```bash
git submodule add https://github.com/skylike87/Frigo_qa_crchestrator.git .qa
git submodule update --init --recursive
```

## 2) Alternative: Symbolic link

If this repo is cloned elsewhere:

```bash
ln -s /absolute/path/to/Frigo_qa_crchestrator .qa
```

## 3) Alternative: Copy

```bash
cp -R /absolute/path/to/Frigo_qa_crchestrator .qa
```

## Host bootstrap (required once)

Run this from host workspace root:

```bash
bash .qa/scripts/bootstrap_host_workspace.sh
```

Optional flags:

```bash
# Local install (host) for @playwright/test
bash .qa/scripts/bootstrap_host_workspace.sh --with-playwright-install

# If Docker is unavailable for now
bash .qa/scripts/bootstrap_host_workspace.sh --skip-container-setup
```

What it does:
- Creates required host directories (`docs/ops/work_orders`, `docs/reports`, `docs/testplans`, `playwright/test`)
- Ensures `.qa/output`, `.qa/runtime`, `.qa/db` exist
- Initializes `.qa/db/qa_history.db` from `.qa/db/schema.sql` if missing
- Validates `.qa` placement (must be mounted at host `/.qa`)
- Prepares container runtime config (`.qa/containers/compose.qa.yml`)
- Optional: installs host `@playwright/test` only when `--with-playwright-install` is used

## Container execution

Run commands inside QA container:

```bash
bash .qa/startup/run_in_qa_container.sh "flutter --version && node --version && npx playwright --version"
```

Open interactive shell:

```bash
bash .qa/startup/run_in_qa_container.sh
```

## Verification

```bash
python .qa/scripts/graph.py \
  --workflow agentic_qa_flow \
  --dev-docs docs/ops/work_orders/<work_order>.md \
  --audit-docs docs/standards/DEFINITION_OF_DONE.md \
  --out .qa/output/graph_dry_run.json \
  --dry-run
```
