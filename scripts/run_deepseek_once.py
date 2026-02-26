#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from langchain_openai import ChatOpenAI


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="One-shot DeepSeek-R1 call via OpenAI-compatible LangChain client")
    p.add_argument("--prompt", required=True, help="Prompt for one-shot answer")
    p.add_argument("--model", default="deepseek-reasoner", help="DeepSeek model name")
    p.add_argument("--api-key", default="", help="Optional API key override")
    p.add_argument("--api-key-env", default="GLOBAL_DEEPSEEK_KEY", help="Env name used for API key")
    p.add_argument("--base-url", default="", help="Optional endpoint base URL")
    p.add_argument("--base-url-env", default="DEEPSEEK_BASE_URL", help="Env name used for base URL")
    p.add_argument("--temperature", type=float, default=0.0, help="Sampling temperature")
    p.add_argument("--max-tokens", type=int, default=1800, help="Max completion tokens")
    p.add_argument("--timeout", type=int, default=120, help="Timeout seconds")
    p.add_argument("--out", default="", help="Optional path to save normalized JSON result")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    api_key = args.api_key.strip() or os.getenv(args.api_key_env, "").strip()
    if not api_key:
        raise RuntimeError(f"Missing API key: set {args.api_key_env} or pass --api-key")

    base_url = args.base_url.strip() or os.getenv(args.base_url_env, "").strip() or "https://api.deepseek.com/v1"

    model = ChatOpenAI(
        model=args.model,
        api_key=api_key,
        base_url=base_url,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        timeout=args.timeout,
    )

    response = model.invoke(args.prompt)
    content = response.content if isinstance(response.content, str) else str(response.content)

    normalized: dict[str, Any] = {
        "ok": True,
        "provider": "deepseek",
        "model": args.model,
        "base_url": base_url,
        "prompt": args.prompt,
        "assistant_text": content,
    }

    out = json.dumps(normalized, ensure_ascii=False, indent=2)
    print(out)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out, encoding="utf-8")


if __name__ == "__main__":
    main()
