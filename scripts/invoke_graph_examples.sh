#!/usr/bin/env bash
set -euo pipefail

# One-shot Devstral2 (Vibe CLI programmatic mode)
# python .qa/scripts/run_devstral2_once.py \
#   --prompt "코드베이스를 분석해서 요약해줘" \
#   --max-turns 1 \
#   --output json \
#   --out .qa/output/devstral2_once.json

# One-shot Codex (headless/quiet mode)
# python .qa/scripts/run_codex_once.py \
#   --prompt "코드 리뷰를 수행하고 JSON으로 반환해줘" \
#   --model gpt-5.3-codex \
#   --sandbox read-only \
#   --ask-for-approval never \
#   --output-schema-file .qa/configs/codex_script_packet_schema.json \
#   --out .qa/output/codex_once.json

# Same task across Codex lineup
# python .qa/scripts/run_model_matrix.py \
#   --group codex \
#   --prompt "코드 리뷰를 수행하고 JSON으로 반환해줘" \
#   --out-dir .qa/output/matrix

# Same task across GPT-5.x lineup
# python .qa/scripts/run_model_matrix.py \
#   --group gpt5x \
#   --prompt "코드 리뷰를 수행하고 JSON으로 반환해줘" \
#   --out-dir .qa/output/matrix

python .qa/scripts/graph.py \
  --workflow agentic_qa_flow \
  --dev-docs docs/ops/work_orders/sto0006_pr14_ui-ux-polish-iteration-v2.md \
  --audit-docs docs/standards/DEFINITION_OF_DONE.md \
  --changed-files lib/features/fridge/presentation/pages/home_dashboard_page.dart,lib/core/db/daos/fridge_items_dao.dart \
  --out .qa/output/graph_dry_run.json \
  --dry-run

# Live run (requires OPENAI_API_KEY)
# python .qa/scripts/graph.py \
#   --workflow agentic_qa_flow \
#   --dev-docs docs/ops/work_orders/sto0006_pr14_ui-ux-polish-iteration-v2.md \
#   --audit-docs docs/standards/DEFINITION_OF_DONE.md \
#   --out .qa/output/graph_live_run.json
