#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any


def safe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text, "parse_error": True}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="One-shot Codex call via headless exec mode")
    p.add_argument("--prompt", required=True, help="Prompt for one-shot answer")
    p.add_argument("--model", default="gpt-5.3-codex", help="Codex or GPT-5.x model name")
    p.add_argument("--sandbox", default="read-only", help="Sandbox mode")
    p.add_argument("--ask-for-approval", default="never", help="Approval behavior")
    p.add_argument("--output-schema-file", default="", help="Optional JSON schema file path")
    p.add_argument("--codex-command", default="codex", help="Codex CLI executable")
    p.add_argument("--base-url", default="", help="Optional endpoint base URL")
    p.add_argument("--base-url-env", default="OPENAI_BASE_URL", help="Env name used for base URL")
    p.add_argument("--api-key", default="", help="Optional API key override")
    p.add_argument("--api-key-env", default="OPENAI_API_KEY", help="Env name used for API key")
    p.add_argument("--out", default="", help="Optional path to save normalized JSON result")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    cmd = [
        args.codex_command,
        "exec",
        args.prompt,
        "-m",
        args.model,
        "--sandbox",
        args.sandbox,
    ]
    if args.output_schema_file:
        cmd.extend(["--output-schema", args.output_schema_file])

    env = os.environ.copy()
    if args.base_url:
        env[args.base_url_env] = args.base_url
    if args.api_key:
        env[args.api_key_env] = args.api_key

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)

    stdout = (proc.stdout or "").strip()
    parsed = safe_json(stdout)

    normalized: dict[str, Any] = {
        "ok": proc.returncode == 0,
        "provider": "codex_cli",
        "returncode": proc.returncode,
        "cmd": cmd,
        "stderr": (proc.stderr or "").strip(),
        "assistant_json": parsed if isinstance(parsed, dict) else {},
        "assistant_text": stdout,
        "raw_payload": parsed,
    }

    out = json.dumps(normalized, ensure_ascii=True, indent=2)
    print(out)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out, encoding="utf-8")


if __name__ == "__main__":
    main()
