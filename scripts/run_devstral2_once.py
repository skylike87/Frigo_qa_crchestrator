#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


def safe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text, "parse_error": True}


def extract_assistant_text(payload: Any) -> str:
    if isinstance(payload, list):
        for msg in reversed(payload):
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                content = msg.get("content")
                if isinstance(content, str):
                    return content
        return ""

    if not isinstance(payload, dict):
        return ""

    messages = payload.get("messages")
    if isinstance(messages, list):
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                content = msg.get("content")
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    parts = []
                    for p in content:
                        if isinstance(p, dict) and isinstance(p.get("text"), str):
                            parts.append(p["text"])
                    return "\n".join(parts).strip()
    if isinstance(payload.get("assistant"), str):
        return payload["assistant"]
    if isinstance(payload.get("output"), str):
        return payload["output"]
    return ""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="One-shot Devstral2 call via Vibe CLI programmatic mode")
    p.add_argument("--prompt", required=True, help="Prompt for one-shot answer")
    p.add_argument("--output", default="json", choices=["json", "streaming"], help="Vibe output format")
    p.add_argument("--max-turns", type=int, default=1, help="Assistant max turns")
    p.add_argument("--max-price", type=float, default=None, help="Optional price cap")
    p.add_argument("--enabled-tools", action="append", default=[], help="Repeatable tool allowlist")
    p.add_argument("--vibe-command", default="vibe", help="Vibe CLI executable")
    p.add_argument("--out", default="", help="Optional path to save normalized JSON result")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    cmd = [
        args.vibe_command,
        "--prompt",
        args.prompt,
        "--output",
        args.output,
        "--max-turns",
        str(args.max_turns),
    ]
    if args.max_price is not None:
        cmd.extend(["--max-price", str(args.max_price)])
    for tool in args.enabled_tools:
        cmd.extend(["--enabled-tools", str(tool)])

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    normalized: dict[str, Any] = {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "cmd": cmd,
        "stderr": (proc.stderr or "").strip(),
    }

    stdout = (proc.stdout or "").strip()
    payload = safe_json(stdout)
    normalized["raw_payload"] = payload

    assistant_text = extract_assistant_text(payload)
    normalized["assistant_text"] = assistant_text if assistant_text else stdout
    normalized["assistant_json"] = safe_json(assistant_text) if assistant_text else {}

    out = json.dumps(normalized, ensure_ascii=True, indent=2)
    print(out)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out, encoding="utf-8")


if __name__ == "__main__":
    main()
