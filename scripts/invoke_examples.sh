#!/usr/bin/env bash
set -euo pipefail

# Example 1: dry-run validation
python .qa/scripts/run_qa.py \
  --workflow pr_validation \
  --work-order docs/ops/work_orders/sto0006_pr14_ui-ux-polish-iteration-v2.md \
  --report docs/reports/sto0006_pr14_ui-ux-polish-iteration-v2_report.md \
  --changed-files lib/features/fridge/presentation/pages/home_dashboard_page.dart,lib/core/db/daos/fridge_items_dao.dart \
  --out .qa/output/example_dry_run.json \
  --dry-run

# Example 2: live run (requires OPENAI_API_KEY)
# python .qa/scripts/run_qa.py \
#   --workflow pr_validation \
#   --work-order docs/ops/work_orders/sto0006_pr14_ui-ux-polish-iteration-v2.md \
#   --report docs/reports/sto0006_pr14_ui-ux-polish-iteration-v2_report.md \
#   --out .qa/output/example_live_run.json
