#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI


ROOT = Path(__file__).resolve().parents[3]
QA_DIR = ROOT / ".qa"
SECURITY_DIR = QA_DIR / "security"
DOC_LIMIT = 12000
VALID_REFERENCES = ("MAS", "LLM", "API")


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def clip(text: str, limit: int = DOC_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[TRUNCATED_TO_{limit}_CHARS]"


def safe_json(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {"raw": data}
    except Exception:
        return {"raw": text, "parse_error": True}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run OWASP reference security review workflow for MAS/LLM/API"
    )
    p.add_argument(
        "--reference-name",
        default="",
        help="OWASP reference slug (MAS, LLM, API). If omitted, runs all.",
    )
    p.add_argument(
        "--attack-name",
        default="",
        help="Deprecated alias of --reference-name.",
    )
    p.add_argument(
        "--all",
        action="store_true",
        help="Run all references (MAS, LLM, API).",
    )
    p.add_argument(
        "--run-date-utc", default="", help="Run date token (default: YYYYMMDD UTC)"
    )
    p.add_argument(
        "--workflow",
        default=str(SECURITY_DIR / "workflows" / "attack_security_review.yaml"),
    )
    p.add_argument(
        "--collector-persona",
        default=str(SECURITY_DIR / "agent" / "personas" / "context_collector_gpt5.yaml"),
    )
    p.add_argument(
        "--reviewer-persona",
        default=str(SECURITY_DIR / "agent" / "personas" / "security_reviewer_codex.yaml"),
    )
    p.add_argument(
        "--collector-prompt",
        default=str(SECURITY_DIR / "agent" / "prompts" / "context_collector_task_prompt.md"),
    )
    p.add_argument(
        "--reviewer-prompt",
        default=str(SECURITY_DIR / "agent" / "prompts" / "security_reviewer_task_prompt.md"),
    )
    p.add_argument(
        "--feedback-template",
        default=str(SECURITY_DIR / "templates" / "security_feedback_template.md"),
    )
    p.add_argument(
        "--report-template",
        default=str(SECURITY_DIR / "templates" / "security_report_template.md"),
    )
    p.add_argument("--model-config", default=str(QA_DIR / "configs" / "model_config.yaml"))
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--out", default="", help="Optional output json path")
    return p.parse_args()


def render_template(template: str, mapping: dict[str, str]) -> str:
    out = template
    for k, v in mapping.items():
        out = out.replace("{" + k + "}", v)
    return out


def call_collector_gpt(
    reference_name: str,
    owasp_ref_path: Path,
    collector_persona: dict[str, Any],
    collector_prompt_text: str,
    dry_run: bool,
) -> dict[str, Any]:
    if dry_run:
        return {
            "reference_name": reference_name,
            "owasp_reference_path": str(owasp_ref_path.relative_to(ROOT)),
            "reference_summary": f"Dry-run summary for {reference_name}",
            "evidence_inventory": [],
            "candidate_hotspots": [],
            "risk_hypothesis_list": [
                {
                    "hypothesis": "Dry-run: potential vulnerability candidate should be reviewed in source.",
                    "preconditions": ["Feature path reachable by user input"],
                    "possible_impact": "Unknown",
                    "confidence": "low",
                }
            ],
            "assumptions_and_gaps": ["Dry-run mode: model invocation skipped."],
        }

    model = str(collector_persona.get("model", "gpt-5"))
    prompt = (
        f"{collector_prompt_text}\n\n"
        f"reference_name: {reference_name}\n"
        f"owasp_reference_path: {owasp_ref_path.relative_to(ROOT)}\n"
        f"repository_root: {ROOT}\n\n"
        "Below is the OWASP reference content:\n"
        f"{clip(read_text(owasp_ref_path))}\n\n"
        "Return JSON object only."
    )

    llm = ChatOpenAI(model=model, temperature=0.1, timeout=120)
    resp = llm.invoke(
        [
            SystemMessage(content="You are a security context collector. Return JSON only."),
            HumanMessage(content=prompt),
        ]
    )
    return safe_json(str(resp.content))


def candidate_lines_from_context(context_packet: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    risks = context_packet.get("risk_hypothesis_list")
    if isinstance(risks, list):
        for item in risks[:12]:
            if isinstance(item, dict):
                hyp = str(item.get("hypothesis", "")).strip()
                imp = str(item.get("possible_impact", "")).strip()
                conf = str(item.get("confidence", "")).strip()
                if hyp:
                    extra = f" (impact: {imp}, confidence: {conf})" if imp or conf else ""
                    lines.append(f"- {hyp}{extra}")
            elif isinstance(item, str) and item.strip():
                lines.append(f"- {item.strip()}")
    if not lines:
        lines.append("- No candidate vulnerabilities extracted. Manual review required.")
    return lines


def assumptions_lines(context_packet: dict[str, Any]) -> list[str]:
    out: list[str] = []
    raw = context_packet.get("assumptions_and_gaps")
    if isinstance(raw, list):
        out = [f"- {str(x).strip()}" for x in raw if str(x).strip()][:12]
    if not out:
        out = ["- No explicit assumptions returned by collector."]
    return out


def build_initial_feedback(
    feedback_template_text: str,
    reference_name: str,
    run_date_utc: str,
    context_packet: dict[str, Any],
) -> str:
    _ = feedback_template_text
    candidates = "\n".join(candidate_lines_from_context(context_packet))
    assumptions = "\n".join(assumptions_lines(context_packet))
    return (
        f"# Security Feedback - {reference_name}\n\n"
        "## OWASP Reference Summary\n"
        f"- Reference: `.qa/ref/owasp/{reference_name}.md`\n"
        f"- Date (UTC): {run_date_utc}\n\n"
        "## Candidate Vulnerabilities (Initial)\n"
        f"{candidates}\n\n"
        "## Assumptions and Gaps\n"
        f"{assumptions}\n\n"
        "---\n\n"
        "## Reviewer Assessment (Pending)\n"
        "- Reviewer output will be appended below.\n"
    )


def call_reviewer_codex(
    reviewer_persona: dict[str, Any],
    reviewer_prompt_text: str,
    model_cfg: dict[str, Any],
    reference_name: str,
    owasp_ref_path: Path,
    feedback_path: Path,
    context_packet: dict[str, Any],
    dry_run: bool,
) -> str:
    if dry_run:
        return (
            "## Detailed Findings (Severity Ordered)\n"
            "- ID: DRY-001\n"
            "- Severity: Low\n"
            "- Title: Dry-run placeholder finding\n"
            "- Evidence: N/A (dry-run)\n\n"
            "## Evidence Map\n"
            "- dry-run\n\n"
            "## Recommended Fixes\n"
            "- Execute without --dry-run to generate real findings.\n\n"
            "## Validation Checklist\n"
            "- [ ] Re-run in live mode\n\n"
            "## Residual Risks\n"
            "- Assessment incomplete in dry-run mode.\n"
        )

    codex_cfg = model_cfg.get("codex_cli", {}) if isinstance(model_cfg, dict) else {}
    model = str(reviewer_persona.get("model", codex_cfg.get("model", "gpt-5.3-codex")))
    command = str(codex_cfg.get("command", "codex"))
    sandbox = str(codex_cfg.get("sandbox", "read-only"))
    approval = str(codex_cfg.get("ask_for_approval", "never"))

    full_prompt = (
        f"{reviewer_prompt_text}\n\n"
        f"reference_name: {reference_name}\n"
        f"owasp_reference_path: {owasp_ref_path.relative_to(ROOT)}\n"
        f"feedback_file: {feedback_path.relative_to(ROOT)}\n\n"
        "Current feedback file content:\n"
        f"{clip(read_text(feedback_path))}\n\n"
        "Collector context_packet JSON:\n"
        f"{clip(json.dumps(context_packet, ensure_ascii=False, indent=2))}\n\n"
        "Task: Generate only markdown text to append under reviewer sections.\n"
        "Do not rewrite collector sections."
    )

    cmd = [
        command,
        "exec",
        "-c",
        f"ask_for_approval='{approval}'",
        "-m",
        model,
        "--sandbox",
        sandbox,
        "--",
        "-",
    ]

    env = os.environ.copy()
    env["HOME"] = "/tmp"
    env["CODEX_LOG_DIR"] = "/tmp"

    endpoint_cfg = codex_cfg.get("endpoint", {}) if isinstance(codex_cfg, dict) else {}
    if isinstance(endpoint_cfg, dict):
        base_url = str(endpoint_cfg.get("base_url", "")).strip()
        base_url_env = (
            str(endpoint_cfg.get("base_url_env", "OPENAI_BASE_URL")).strip()
            or "OPENAI_BASE_URL"
        )
        api_key = str(endpoint_cfg.get("api_key", "")).strip()
        api_key_env = (
            str(endpoint_cfg.get("api_key_env", "OPENAI_API_KEY")).strip()
            or "OPENAI_API_KEY"
        )
        if base_url:
            env[base_url_env] = base_url
        if api_key:
            env[api_key_env] = api_key

    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        input=full_prompt,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"codex reviewer failed: rc={proc.returncode} stderr={proc.stderr.strip()}"
        )

    out = (proc.stdout or "").strip()
    parsed = safe_json(out)
    if isinstance(parsed, dict) and not parsed.get("parse_error"):
        for key in ("assistant_text", "markdown", "report", "text"):
            val = parsed.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return out


def append_reviewer_feedback(feedback_path: Path, reviewer_markdown: str) -> None:
    existing = read_text(feedback_path).rstrip() + "\n\n"
    marker = "## Reviewer Assessment (Pending)"
    if marker in existing:
        existing = existing.replace(
            marker + "\n- Reviewer output will be appended below.\n\n",
            "",
        )
    block = "## Reviewer Assessment\n\n" + reviewer_markdown.strip() + "\n"
    write_text(feedback_path, existing + block)


def compute_scores(text: str) -> dict[str, int]:
    low = len(re.findall(r"severity\s*:\s*low", text, flags=re.I))
    med = len(re.findall(r"severity\s*:\s*medium", text, flags=re.I))
    high = len(re.findall(r"severity\s*:\s*high", text, flags=re.I))
    crit = len(re.findall(r"severity\s*:\s*critical", text, flags=re.I))

    exploitability = max(0, 100 - (crit * 30 + high * 20 + med * 10 + low * 4))
    impact = max(0, 100 - (crit * 35 + high * 22 + med * 10 + low * 3))

    evidence_count = len(
        re.findall(
            r"\b(?:lib|android|ios|web|linux|macos|windows|docs|test)/[^\s:]+",
            text,
        )
    )
    coverage_confidence = min(100, 40 + evidence_count * 5)

    has_fix = bool(re.search(r"recommended fix|recommended fixes|mitigation", text, flags=re.I))
    remediation = 80 if has_fix else 45

    overall = int(
        round(
            exploitability * 0.30
            + impact * 0.30
            + coverage_confidence * 0.20
            + remediation * 0.20
        )
    )

    return {
        "overall": max(0, min(100, overall)),
        "exploitability": exploitability,
        "impact": impact,
        "coverage_confidence": coverage_confidence,
        "remediation_readiness": remediation,
        "critical_count": crit,
        "high_count": high,
        "medium_count": med,
        "low_count": low,
        "evidence_count": evidence_count,
    }


def residual_risk_level(scores: dict[str, int]) -> str:
    if scores["critical_count"] > 0:
        return "high"
    if scores["high_count"] > 1:
        return "high"
    if scores["high_count"] == 1 or scores["medium_count"] >= 3:
        return "medium"
    return "low"


def final_feedback_line(scores: dict[str, int], risk_level: str) -> str:
    return (
        f"Overall score {scores['overall']}/100. "
        f"Severity counts C/H/M/L={scores['critical_count']}/{scores['high_count']}/{scores['medium_count']}/{scores['low_count']}. "
        f"Residual risk is {risk_level}."
    )


def generate_report(
    report_template_text: str,
    reference_name: str,
    run_date_utc: str,
    feedback_rel: str,
    scores: dict[str, int],
    final_feedback: str,
) -> str:
    rendered = render_template(
        report_template_text,
        {
            "run_date_utc": run_date_utc,
            "reference_name": reference_name,
            "score": str(scores["overall"]),
            "exploitability_score": str(scores["exploitability"]),
            "impact_score": str(scores["impact"]),
            "coverage_confidence_score": str(scores["coverage_confidence"]),
            "remediation_readiness_score": str(scores["remediation_readiness"]),
            "final_feedback": final_feedback,
        },
    )
    rendered = rendered.replace("docs/security_feedback/owasp/{reference_name}.md", feedback_rel)
    return rendered


def normalize_targets(args: argparse.Namespace) -> list[str]:
    ref = (args.reference_name or "").strip().upper()
    legacy = (args.attack_name or "").strip().upper()
    chosen = ref or legacy

    if args.all:
        return list(VALID_REFERENCES)
    if chosen:
        if chosen not in VALID_REFERENCES:
            raise SystemExit(
                f"invalid reference name: {chosen} (allowed: {', '.join(VALID_REFERENCES)})"
            )
        return [chosen]
    return list(VALID_REFERENCES)


def process_reference(
    *,
    reference_name: str,
    run_date_utc: str,
    collector_persona: dict[str, Any],
    reviewer_persona: dict[str, Any],
    model_cfg: dict[str, Any],
    collector_prompt_text: str,
    reviewer_prompt_text: str,
    feedback_template_text: str,
    report_template_text: str,
    dry_run: bool,
) -> dict[str, Any]:
    owasp_ref = ROOT / ".qa" / "ref" / "owasp" / f"{reference_name}.md"
    if not owasp_ref.exists():
        raise SystemExit(f"owasp reference not found: {owasp_ref}")

    feedback_path = ROOT / "docs" / "security_feedback" / "owasp" / f"{reference_name}.md"
    report_path = (
        ROOT
        / "docs"
        / "report"
        / "security"
        / f"security_report_{reference_name}_{run_date_utc}.md"
    )

    context_packet = call_collector_gpt(
        reference_name=reference_name,
        owasp_ref_path=owasp_ref,
        collector_persona=collector_persona,
        collector_prompt_text=collector_prompt_text,
        dry_run=dry_run,
    )

    initial_feedback = build_initial_feedback(
        feedback_template_text=feedback_template_text,
        reference_name=reference_name,
        run_date_utc=run_date_utc,
        context_packet=context_packet,
    )
    write_text(feedback_path, initial_feedback)

    reviewer_markdown = call_reviewer_codex(
        reviewer_persona=reviewer_persona,
        reviewer_prompt_text=reviewer_prompt_text,
        model_cfg=model_cfg,
        reference_name=reference_name,
        owasp_ref_path=owasp_ref,
        feedback_path=feedback_path,
        context_packet=context_packet,
        dry_run=dry_run,
    )
    append_reviewer_feedback(feedback_path, reviewer_markdown)

    final_feedback_text = read_text(feedback_path)
    scores = compute_scores(final_feedback_text)
    risk_level = residual_risk_level(scores)
    final_feedback = final_feedback_line(scores, risk_level)

    report_text = generate_report(
        report_template_text=report_template_text,
        reference_name=reference_name,
        run_date_utc=run_date_utc,
        feedback_rel=str(feedback_path.relative_to(ROOT)),
        scores=scores,
        final_feedback=final_feedback,
    )
    write_text(report_path, report_text)

    result = {
        "ok": True,
        "reference_name": reference_name,
        "run_date_utc": run_date_utc,
        "owasp_reference": str(owasp_ref.relative_to(ROOT)),
        "feedback_file": str(feedback_path.relative_to(ROOT)),
        "report_file": str(report_path.relative_to(ROOT)),
        "scores": scores,
        "residual_risk_level": risk_level,
        "final_feedback": final_feedback,
        "dry_run": dry_run,
    }
    out_path = ROOT / ".qa" / "output" / "security" / f"{reference_name}_{run_date_utc}.json"
    write_text(out_path, json.dumps(result, ensure_ascii=False, indent=2))
    return result


def main() -> None:
    args = parse_args()
    run_date_utc = args.run_date_utc.strip() or datetime.now(timezone.utc).strftime("%Y%m%d")
    targets = normalize_targets(args)

    workflow = load_yaml(Path(args.workflow))
    _ = workflow
    collector_persona = load_yaml(Path(args.collector_persona))
    reviewer_persona = load_yaml(Path(args.reviewer_persona))
    model_cfg = load_yaml(Path(args.model_config))
    collector_prompt_text = read_text(Path(args.collector_prompt))
    reviewer_prompt_text = read_text(Path(args.reviewer_prompt))
    feedback_template_text = read_text(Path(args.feedback_template))
    report_template_text = read_text(Path(args.report_template))

    results: list[dict[str, Any]] = []
    for reference_name in targets:
        results.append(
            process_reference(
                reference_name=reference_name,
                run_date_utc=run_date_utc,
                collector_persona=collector_persona,
                reviewer_persona=reviewer_persona,
                model_cfg=model_cfg,
                collector_prompt_text=collector_prompt_text,
                reviewer_prompt_text=reviewer_prompt_text,
                feedback_template_text=feedback_template_text,
                report_template_text=report_template_text,
                dry_run=bool(args.dry_run),
            )
        )

    payload: dict[str, Any] = {
        "ok": True,
        "workflow": str(Path(args.workflow)),
        "run_date_utc": run_date_utc,
        "targets": targets,
        "results": results,
        "dry_run": bool(args.dry_run),
    }

    if args.out:
        out_path = Path(args.out)
        if not out_path.is_absolute():
            out_path = (ROOT / out_path).resolve()
    else:
        joined = "_".join(targets)
        out_path = ROOT / ".qa" / "output" / "security" / f"{joined}_{run_date_utc}.json"
    write_text(out_path, json.dumps(payload, ensure_ascii=False, indent=2))
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
