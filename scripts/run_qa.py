#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
QA_DIR = ROOT / ".qa"


@dataclass
class RunInput:
    workflow: str
    work_order: Path
    report: Path
    changed_files: list[str]
    out: Path
    dry_run: bool


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def parse_args() -> RunInput:
    parser = argparse.ArgumentParser(description="Run QA orchestration workflow")
    parser.add_argument("--workflow", required=True, help="Workflow id (e.g. pr_validation)")
    parser.add_argument("--work-order", required=True, help="Path to active Work Order markdown")
    parser.add_argument("--report", required=True, help="Path to target report markdown")
    parser.add_argument(
        "--changed-files",
        default="",
        help="Comma-separated changed file paths for focused QA",
    )
    parser.add_argument(
        "--out",
        default=str(QA_DIR / "output" / "qa_result.json"),
        help="Output JSON path",
    )
    parser.add_argument("--dry-run", action="store_true", help="Skip LLM call and only validate input")

    args = parser.parse_args()
    changed_files = [p.strip() for p in args.changed_files.split(",") if p.strip()]

    return RunInput(
        workflow=args.workflow,
        work_order=(ROOT / args.work_order).resolve() if not args.work_order.startswith("/") else Path(args.work_order),
        report=(ROOT / args.report).resolve() if not args.report.startswith("/") else Path(args.report),
        changed_files=changed_files,
        out=(ROOT / args.out).resolve() if not args.out.startswith("/") else Path(args.out),
        dry_run=args.dry_run,
    )


def resolve_workflow_file(workflow_id: str) -> Path:
    candidate = QA_DIR / "workflows" / f"{workflow_id}.yaml"
    if candidate.exists():
        return candidate

    for wf in (QA_DIR / "workflows").glob("*.yaml"):
        data = load_yaml(wf)
        if data.get("id") == workflow_id:
            return wf

    raise FileNotFoundError(f"Workflow not found: {workflow_id}")


def build_prompt(run_input: RunInput, workflow: dict[str, Any], model_cfg: dict[str, Any]) -> tuple[str, str]:
    system_prompt = read_text(QA_DIR / "prompts" / "system" / "qa_orchestrator.txt")
    if not system_prompt:
        system_prompt = (
            "You are a QA orchestrator. Stay within scope, use evidence, "
            "and return JSON only with pass_fail/summary/required_fixes/risk_highlights/next_checks."
        )

    payload = {
        "workflow": workflow,
        "model_config": model_cfg,
        "work_order_path": str(run_input.work_order),
        "work_order": read_text(run_input.work_order),
        "report_path": str(run_input.report),
        "report": read_text(run_input.report),
        "changed_files": run_input.changed_files,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    human_prompt = (
        "Use these inputs to produce QA orchestration output. "
        "If evidence is missing, set FAIL and explain required checks.\n\n"
        + json.dumps(payload, ensure_ascii=True, indent=2)
    )
    return system_prompt, human_prompt


def resolve_endpoint_config(model_cfg: dict[str, Any]) -> tuple[str, str]:
    endpoint_cfg = model_cfg.get("endpoint", {})
    if not isinstance(endpoint_cfg, dict):
        endpoint_cfg = {}
    api_key_env = str(endpoint_cfg.get("api_key_env", "OPENAI_API_KEY")).strip() or "OPENAI_API_KEY"
    base_url_env = str(endpoint_cfg.get("base_url_env", "OPENAI_BASE_URL")).strip() or "OPENAI_BASE_URL"
    return api_key_env, base_url_env


def invoke_orchestrator(system_prompt: str, human_prompt: str, model_cfg: dict[str, Any]) -> dict[str, Any]:
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_openai import ChatOpenAI

    api_key_env, base_url_env = resolve_endpoint_config(model_cfg)
    api_key = os.getenv(api_key_env, "")
    base_url = os.getenv(base_url_env, "")
    endpoint_cfg = model_cfg.get("endpoint", {})
    if isinstance(endpoint_cfg, dict):
        if not base_url:
            base_url = str(endpoint_cfg.get("base_url", "")).strip()
        if not api_key:
            api_key = str(endpoint_cfg.get("api_key", "")).strip()

    model = ChatOpenAI(
        model=model_cfg.get("model", "gpt-4.1-mini"),
        temperature=float(model_cfg.get("temperature", 0.1)),
        max_tokens=int(model_cfg.get("max_tokens", 1800)),
        timeout=int(model_cfg.get("timeout_seconds", 60)),
        api_key=api_key or None,
        base_url=base_url or None,
    )

    resp = model.invoke(
        [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt),
        ]
    )

    text = resp.content if isinstance(resp.content, str) else str(resp.content)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "pass_fail": "FAIL",
            "summary": "Model response was not valid JSON.",
            "required_fixes": ["Ensure orchestrator returns strict JSON output."],
            "risk_highlights": ["Automation parser failed due to invalid output format."],
            "next_checks": ["Inspect raw response and update prompt constraints."],
            "raw_response": text,
        }


def main() -> None:
    run_input = parse_args()

    workflow_file = resolve_workflow_file(run_input.workflow)
    workflow = load_yaml(workflow_file)
    model_cfg = load_yaml(QA_DIR / "configs" / "model_config.yaml")

    result: dict[str, Any] = {
        "meta": {
            "workflow": run_input.workflow,
            "workflow_file": str(workflow_file),
            "work_order": str(run_input.work_order),
            "report": str(run_input.report),
            "changed_files": run_input.changed_files,
            "dry_run": run_input.dry_run,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        }
    }

    if run_input.dry_run:
        api_key_env, _ = resolve_endpoint_config(model_cfg)
        result["result"] = {
            "pass_fail": "FAIL",
            "summary": "Dry run only: no model invocation executed.",
            "required_fixes": ["Run without --dry-run for actual QA decision."],
            "risk_highlights": ["No QA decision was produced."],
            "next_checks": [f"Set {api_key_env} and run full workflow."],
        }
    else:
        api_key_env, _ = resolve_endpoint_config(model_cfg)
        endpoint_cfg = model_cfg.get("endpoint", {})
        fallback_api_key = ""
        if isinstance(endpoint_cfg, dict):
            fallback_api_key = str(endpoint_cfg.get("api_key", "")).strip()
        if not os.getenv(api_key_env) and not fallback_api_key:
            raise RuntimeError(f"{api_key_env} is required unless --dry-run is used")

        system_prompt, human_prompt = build_prompt(run_input, workflow, model_cfg)
        result["result"] = invoke_orchestrator(system_prompt, human_prompt, model_cfg)

    run_input.out.parent.mkdir(parents=True, exist_ok=True)
    run_input.out.write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
