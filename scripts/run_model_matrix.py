#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
QA_DIR = ROOT / ".qa"


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def safe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text, "parse_error": True}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run same headless Codex task across model variants")
    p.add_argument("--group", required=True, choices=["codex", "gpt5x"], help="Model variant group")
    p.add_argument("--prompt", required=True, help="Prompt for all models in the group")
    p.add_argument("--sandbox", default="", help="Override sandbox mode")
    p.add_argument("--ask-for-approval", default="", help="Override approval mode")
    p.add_argument("--output-schema-file", default="", help="Override schema path")
    p.add_argument("--out-dir", default=str(QA_DIR / "output" / "matrix"), help="Output directory")
    p.add_argument("--codex-command", default="", help="Override codex command")
    p.add_argument("--base-url", default="", help="Optional endpoint base URL")
    p.add_argument("--api-key", default="", help="Optional API key override")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    model_cfg = load_yaml(QA_DIR / "configs" / "model_config.yaml")
    codex_cfg = model_cfg.get("codex_cli", {})
    variants = model_cfg.get("model_variants", {}).get(args.group, [])
    if not isinstance(variants, list) or not variants:
        raise RuntimeError(f"No model variants found for group: {args.group}")

    out_dir = (ROOT / args.out_dir).resolve() if not str(args.out_dir).startswith("/") else Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    command = str(args.codex_command or codex_cfg.get("command", "codex"))
    sandbox = str(args.sandbox or codex_cfg.get("sandbox", "read-only"))
    approval = str(args.ask_for_approval or codex_cfg.get("ask_for_approval", "never"))
    schema = str(args.output_schema_file or codex_cfg.get("output_schema_file", "")).strip()
    base_url_env = str(codex_cfg.get("endpoint", {}).get("base_url_env", "OPENAI_BASE_URL"))
    api_key_env = str(codex_cfg.get("endpoint", {}).get("api_key_env", "OPENAI_API_KEY"))

    summary: dict[str, Any] = {
        "group": args.group,
        "models": variants,
        "generated_files": [],
    }

    for model_name in variants:
        cmd = [
            command,
            "exec",
            args.prompt,
            "-m",
            str(model_name),
            "--ask-for-approval",
            approval,
            "--sandbox",
            sandbox,
        ]
        if schema:
            resolved_schema = (ROOT / schema).resolve() if not schema.startswith("/") else Path(schema)
            cmd.extend(["--output-schema-file", str(resolved_schema)])

        env = os.environ.copy()
        if args.base_url:
            env[base_url_env] = args.base_url
        if args.api_key:
            env[api_key_env] = args.api_key

        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, check=False, env=env)
        stdout = (proc.stdout or "").strip()
        payload = {
            "ok": proc.returncode == 0,
            "provider": "codex_cli",
            "model": model_name,
            "returncode": proc.returncode,
            "stderr": (proc.stderr or "").strip(),
            "assistant_text": stdout,
            "assistant_json": safe_json(stdout),
        }
        out_file = out_dir / f"{args.group}_{str(model_name).replace('.', '_')}.json"
        out_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        summary["generated_files"].append(str(out_file))

    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
