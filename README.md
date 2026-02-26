# QA Agentic Orchestration (.qa)

This directory defines a LangChain/LangGraph QA orchestration for the flow you designed.

## Persona Set (mapped from your diagram)

- `test_architect_mistral`: Requirements decomposition + seed tests + golden data baseline.
- `test_architect2_deepseek_r1`: Adversarial/edge-case inference.
- `clerk_gemini_fast`: Consolidated core spec packet (scenario, AOM mapping, risk/security matrix).
- `decision_maker_gpt5x`: Final testcase approval + PII/security guardrail filtering.
- `testplan_generator_glm5`: User-facing UI/component test plan writing.
- `test_scripter_codex`: Executable script/spec generation.
- `tester_routing_agent`: Final QA gate owner (script execution, final report, testplan quality follow-up control).

## Workflow Graph

- Workflow file: `.qa/workflows/agentic_qa_flow.yaml`
- Runtime graph: `.qa/scripts/graph.py`

Main path:

1. Test Architect (Mistral)
2. Test Architect2 (DeepSeek-R1)
3. Clerk (Gemini Fast)
4. Decision Maker (GPT-5x)
5. Testplan Generator (GLM-5)
6. Test Scripter (Codex)
7. Tester (Routing Agent)

## Test Automation Rule

- End-to-end/UI automation in this QA flow is Playwright-based.
- Script generation node (`test_scripter_codex`) must output Playwright TypeScript tests and execution commands.
- Execution node (`tester_routing_agent`) validates/runs Playwright command set and reports evidence.
- Tester node is the process-control gate for downstream quality:
  - run generated scripts
  - publish final test report
  - verify testplan generator output quality
  - rerun testplan generator or force-terminate when non-recoverable

## Agent Document Assignment

- Persona files now define:
  - `required_documents`
  - `optional_documents`
- `graph.py` loads these per agent and injects assigned docs into each node prompt.
- Build-first policy is enabled:
  - Missing assigned docs are recorded in `doc_assignment.missing_required/missing_optional`
  - Execution continues (no hard stop), so you can improve docs incrementally.

## GLM-5 via Kilo Code CLI

- `testplan_generator_glm5` is routed to Kilo Code CLI in graph runtime.
- Routing trigger: persona `model_hint` contains `glm-5`/`glm5`.
- Execution mode:
  - `kilocode run --auto --format json --model kilo/z-ai/glm-5:free "<prompt>"`
  - `KILOCODE_MODEL`/`KILO_PROVIDER` are set from config.
- Scope restriction:
  - `testplan_generator_glm5` runs with working directory fixed to `docs/testplans/`.
  - Prompt policy blocks read/write outside `docs/testplans/`.
- Routing safety rule:
  - Routing agents scan Kilo Code outputs for suspicious behavior (e.g. `sudo`, sandbox escape/destructive command patterns).
  - If detected, packet status is set to `blocked_by_security_rule`.
- Config entry: `.qa/configs/model_config.yaml -> kilocode_cli`

## PII Guardrail (Decision Node)

- Schema: `.qa/configs/decision_packet_schema.json`
- Enforced in `graph.py` at `decision_maker_gpt5x` node.
- Current policy:
  - Validate required decision fields.
  - Scan `approved_testcase_bundle` for PII patterns (email/phone/SSN/card/API key).
  - Auto-mask detected values.
  - Set `guardrail_filter_result.status` to `BLOCK` when shape/PII violations exist.
  - If `BLOCK`, downstream `testplan_generator_glm5` and `test_scripter_codex` are skipped.

## Devstral2 One-shot Entrypoint (Vibe CLI)

- Script: `.qa/scripts/run_devstral2_once.py`
- Purpose: call Vibe CLI in programmatic mode (`--prompt`) for a single non-interactive answer.
- Default flags:
  - `--output json`
  - `--max-turns 1`

Example:

```bash
python .qa/scripts/run_devstral2_once.py \
  --prompt "코드베이스를 분석해서 요약해줘" \
  --max-turns 1 \
  --output json \
  --out .qa/output/devstral2_once.json
```

Notes:

- This script is designed for shell/subprocess integration (LangChain tool runner).
- It returns normalized JSON with `assistant_text` and `assistant_json` for downstream parsing.
- In graph mode, personas whose `model_hint` includes `mistral`/`devstral` are routed to Vibe CLI automatically.

## Codex Headless Entrypoint + Endpoint Setup

- Script: `.qa/scripts/run_codex_once.py`
- Purpose: call Codex CLI in non-interactive mode (`codex exec`) for a single one-shot response.
- Default quiet-mode flags:
  - `--ask-for-approval never`
  - `--sandbox read-only`
  - `--output-schema-file .qa/configs/codex_script_packet_schema.json`

Example:

```bash
python .qa/scripts/run_codex_once.py \
  --prompt "코드 리뷰를 수행하고 결과를 JSON으로 줘" \
  --model gpt-5 \
  --sandbox read-only \
  --ask-for-approval never \
  --output-schema-file .qa/configs/codex_script_packet_schema.json \
  --out .qa/output/codex_once.json
```

Endpoint override example:

```bash
python .qa/scripts/run_codex_once.py \
  --prompt "테스트 스크립트를 생성해줘" \
  --base-url "https://example-endpoint/v1" \
  --api-key "$OPENAI_API_KEY"
```

Graph routing:

- `.qa/configs/model_config.yaml` now supports `codex_cli` settings.
- In graph mode, personas whose `model_hint` includes `codex` are routed to Codex CLI automatically.
- Current target persona: `test_scripter_codex`.

## Codex + GPT-5.x Variant Repetition

- Variant presets are defined in `.qa/configs/model_config.yaml` under:
  - `model_variants.codex`
  - `model_variants.gpt5x`
- Run the same one-shot task for all models in a group:

```bash
python .qa/scripts/run_model_matrix.py \
  --group codex \
  --prompt "코드 리뷰를 수행하고 결과를 JSON으로 줘" \
  --out-dir .qa/output/matrix
```

```bash
python .qa/scripts/run_model_matrix.py \
  --group gpt5x \
  --prompt "코드 리뷰를 수행하고 결과를 JSON으로 줘" \
  --out-dir .qa/output/matrix
```

- Each model result is saved as a separate JSON file in the output directory.

## Run

### Dry run

```bash
python .qa/scripts/graph.py \
  --workflow agentic_qa_flow \
  --dev-docs docs/ops/work_orders/sto0006_pr14_ui-ux-polish-iteration-v2.md \
  --audit-docs docs/standards/DEFINITION_OF_DONE.md \
  --out .qa/output/graph_dry_run.json \
  --dry-run
```

### Live run

```bash
export GLOBAL_DEEPSEEK_KEY=your_key
export DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
python .qa/scripts/graph.py \
  --workflow agentic_qa_flow \
  --dev-docs <dev_doc_path> \
  --audit-docs <audit_doc_path> \
  --out .qa/output/graph_live_run.json
```

## Notes

- `graph.py` is the orchestration entrypoint aligned with your flow.
- Output is saved under `.qa/output/*.json`.
- Existing `run_qa.py` can remain for simple single-shot orchestration if needed.

## History DB (SQLite)

- Purpose: persist agent progress and generated reports independently from LangChain runtime.
- Database file: `.qa/db/qa_history.db`
- Schema file: `.qa/db/schema.sql`
- Init command:

```bash
python .qa/scripts/init_history_db.py --db-path .qa/db/qa_history.db
```

- Sidecar layer:
  - Runtime module: `.qa/scripts/history_sidecar.py`
  - Graph integration: `graph.py` calls sidecar APIs only (`start_run`, `start_agent`, `finish_agent`, `log_event`, `finish_run`)
  - Feature logic and DB persistence are separated so history layer can evolve independently.

- Sidecar config:
  - File: `.qa/configs/history_db.yaml`
  - Example:
    - `enabled: true`
    - `db_path: .qa/db/qa_history.db`

- Core tables:
  - `qa_runs`: workflow run unit and top-level status
  - `qa_agent_runs`: per-agent execution status and I/O payload snapshot
  - `qa_reports`: report artifacts generated by agents
  - `qa_status_events`: timeline/event log for progress history
  - `qa_agents`: agent registry (seeded from `.qa/personas/*.yaml`)
