#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

import yaml
from history_sidecar import HistorySidecarConfig, QAHistorySidecar

ROOT = Path(__file__).resolve().parents[2]
QA_DIR = ROOT / ".qa"
DECISION_SCHEMA_PATH = QA_DIR / "configs" / "decision_packet_schema.json"
DOC_CHAR_LIMIT = 12000


class QAState(TypedDict, total=False):
    run_id: str
    dry_run: bool
    workflow_id: str
    dev_docs: str
    audit_docs: str
    dev_docs_path: str
    audit_docs_path: str
    changed_files: list[str]
    architecture_packet: dict[str, Any]
    adversarial_packet: dict[str, Any]
    clerk_packet: dict[str, Any]
    decision_preflight: dict[str, Any]
    decision_packet: dict[str, Any]
    testplan_routing_packet: dict[str, Any]
    script_routing_packet: dict[str, Any]
    testplan_packet: dict[str, Any]
    script_packet: dict[str, Any]
    execution_packet: dict[str, Any]
    tester_gate_decision: dict[str, Any]


@dataclass
class Args:
    workflow: str
    dev_docs: Path
    audit_docs: Path
    changed_files: list[str]
    out: Path
    dry_run: bool


def parse_args() -> Args:
    parser = argparse.ArgumentParser(description="Run agentic QA graph")
    parser.add_argument("--workflow", default="agentic_qa_flow", help="Workflow id")
    parser.add_argument("--dev-docs", required=True, help="Path to dev-side documentation input")
    parser.add_argument("--audit-docs", required=True, help="Path to audit/policy documentation input")
    parser.add_argument("--changed-files", default="", help="Comma-separated changed files")
    parser.add_argument("--out", default=str(QA_DIR / "output" / "graph_result.json"), help="Output JSON path")
    parser.add_argument("--dry-run", action="store_true", help="Run graph without LLM calls")
    args = parser.parse_args()

    changed = [x.strip() for x in args.changed_files.split(",") if x.strip()]
    dev_docs = (ROOT / args.dev_docs).resolve() if not args.dev_docs.startswith("/") else Path(args.dev_docs)
    audit_docs = (ROOT / args.audit_docs).resolve() if not args.audit_docs.startswith("/") else Path(args.audit_docs)
    out = (ROOT / args.out).resolve() if not args.out.startswith("/") else Path(args.out)
    return Args(args.workflow, dev_docs, audit_docs, changed, out, args.dry_run)


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_history_sidecar() -> QAHistorySidecar:
    cfg_path = QA_DIR / "configs" / "history_db.yaml"
    cfg_data = load_yaml(cfg_path) if cfg_path.exists() else {}
    enabled = bool(cfg_data.get("enabled", False))
    db_path_raw = str(cfg_data.get("db_path", str(QA_DIR / "db" / "qa_history.db"))).strip()
    db_path = (ROOT / db_path_raw).resolve() if not db_path_raw.startswith("/") else Path(db_path_raw)
    return QAHistorySidecar(HistorySidecarConfig(enabled=enabled, db_path=db_path))


def agent_status_from_packet(packet: dict[str, Any]) -> str:
    raw = str(packet.get("status", "")).strip().lower()
    if raw in {"dry_run", "success", "ok", "pass", "passed"}:
        return "success"
    if raw in {"blocked", "blocked_by_guardrail", "blocked_by_security_rule"}:
        return "blocked"
    if raw in {"skipped"}:
        return "skipped"
    if packet.get("error"):
        return "failed"
    if raw in {"fail", "failed", "error"}:
        return "failed"
    return "success"


def load_workflow(workflow_id: str) -> dict[str, Any]:
    wf_path = QA_DIR / "workflows" / f"{workflow_id}.yaml"
    if not wf_path.exists():
        raise FileNotFoundError(f"Workflow file not found: {wf_path}")
    return load_yaml(wf_path)


def load_persona(persona_id: str) -> dict[str, Any]:
    file_path = QA_DIR / "personas" / f"{persona_id}.yaml"
    if not file_path.exists():
        raise FileNotFoundError(f"Persona file not found: {file_path}")
    return load_yaml(file_path)


def clip_text(text: str, limit: int = DOC_CHAR_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[TRUNCATED_TO_{limit}_CHARS]"


def _to_rel_label(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def _latest_files(dir_path: Path, pattern: str, limit: int) -> list[Path]:
    files = [p for p in dir_path.glob(pattern) if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:limit]


def _find_active_work_order() -> Path | None:
    work_orders_dir = ROOT / "docs" / "ops" / "work_orders"
    if not work_orders_dir.exists():
        return None
    latest = _latest_files(work_orders_dir, "*.md", 1)
    return latest[0] if latest else None


def _extract_report_path_from_work_order(work_order_text: str) -> str:
    # Supports formats like: "- Report: path" and "- **Report**: `path`"
    m = re.search(
        r"^\s*-\s*(?:\*\*)?Report(?:\*\*)?\s*:\s*`?([^`\n]+)`?\s*$",
        work_order_text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    return (m.group(1).strip() if m else "")


def _extract_story_id_from_work_order(work_order_text: str) -> str:
    m = re.search(
        r"^\s*-\s*(?:\*\*)?Story(?:\*\*)?\s*:\s*`?([A-Za-z0-9_-]+)`?\s*$",
        work_order_text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    return (m.group(1).strip().lower() if m else "")


def detect_current_story_id(state: QAState) -> str:
    for key in ("dev_docs_path", "audit_docs_path"):
        raw = str(state.get(key, "")).strip()
        if not raw:
            continue
        m = re.search(r"(sto\d{4})", raw, flags=re.IGNORECASE)
        if m:
            return m.group(1).lower()

    active = _find_active_work_order()
    if active and active.exists():
        story = _extract_story_id_from_work_order(read_text(active))
        if story:
            return story
        m = re.search(r"(sto\d{4})", active.name, flags=re.IGNORECASE)
        if m:
            return m.group(1).lower()
    return ""


def _sanitize_report_token(raw: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_-]+", "_", raw.strip())
    token = token.strip("_").lower()
    return token


def _extract_report_token_from_report_ref(report_ref: str) -> str:
    ref = report_ref.strip().strip("/")
    if not ref:
        return ""

    parts = list(Path(ref).parts)
    lower_parts = [p.lower() for p in parts]
    for i in range(len(lower_parts) - 2):
        if lower_parts[i] == "docs" and lower_parts[i + 1] == "reports" and lower_parts[i + 2] == "qa":
            if i + 3 < len(parts):
                return _sanitize_report_token(parts[i + 3])

    p = Path(ref)
    fallback = p.stem if p.suffix else p.name
    return _sanitize_report_token(fallback)


def resolve_vibe_report_output_dir(state: QAState) -> Path:
    active = _find_active_work_order()
    if active and active.exists():
        report_ref = _extract_report_path_from_work_order(read_text(active))
        token = _extract_report_token_from_report_ref(report_ref) if report_ref else ""
        if token:
            return ROOT / "docs" / "reports" / "qa" / token

    path_hint = " ".join([str(state.get("dev_docs_path", "")), str(state.get("audit_docs_path", ""))])
    m = re.search(r"((?:sto|story)\d{4}_pr\d+)", path_hint, flags=re.IGNORECASE)
    if m:
        token = _sanitize_report_token(m.group(1))
        if token:
            return ROOT / "docs" / "reports" / "qa" / token

    story = detect_current_story_id(state) or "story0000"
    run_id = str(state.get("run_id", "")).replace("qa-", "pr")
    token = _sanitize_report_token(f"{story}_{run_id}") or "story0000_pr00"
    return ROOT / "docs" / "reports" / "qa" / token


def _resolve_document_ref(doc_ref: str, state: QAState) -> tuple[dict[str, str], list[str]]:
    ref = doc_ref.strip()
    if not ref:
        return {}, ["<empty_doc_ref>"]

    if ref == "@active_work_order":
        active = _find_active_work_order()
        if not active:
            return {}, [ref]
        label = _to_rel_label(active)
        return {label: clip_text(read_text(active))}, []

    if ref == "@linked_report":
        active = _find_active_work_order()
        if not active:
            return {}, [ref]
        report_ref = _extract_report_path_from_work_order(read_text(active))
        if not report_ref:
            return {}, [f"{ref} (missing Report field in active work order)"]
        report_path = (ROOT / report_ref).resolve() if not report_ref.startswith("/") else Path(report_ref)
        if not report_path.exists():
            return {}, [f"{ref} -> {report_ref}"]
        label = _to_rel_label(report_path)
        return {label: clip_text(read_text(report_path))}, []

    if ref.startswith("@recent_reports:"):
        raw = ref.split(":", 1)[1].strip()
        try:
            count = max(1, min(int(raw), 10))
        except ValueError:
            return {}, [f"{ref} (invalid count)"]
        reports_dir = ROOT / "docs" / "reports"
        latest_reports = _latest_files(reports_dir, "*.md", count) if reports_dir.exists() else []
        if not latest_reports:
            return {}, [ref]
        loaded = {_to_rel_label(p): clip_text(read_text(p)) for p in latest_reports}
        return loaded, []

    path = ROOT / ref
    if path.exists():
        return {ref: clip_text(read_text(path))}, []
    return {}, [ref]


def resolve_assigned_documents(persona: dict[str, Any], state: QAState) -> dict[str, Any]:
    required = [str(x) for x in persona.get("required_documents", [])]
    optional = [str(x) for x in persona.get("optional_documents", [])]

    docs: dict[str, str] = {}
    missing_required: list[str] = []
    missing_optional: list[str] = []

    for doc_ref in required:
        loaded_docs, missing = _resolve_document_ref(doc_ref, state)
        docs.update(loaded_docs)
        missing_required.extend(missing)

    for doc_ref in optional:
        loaded_docs, missing = _resolve_document_ref(doc_ref, state)
        docs.update(loaded_docs)
        missing_optional.extend(missing)

    docs["__runtime_dev_docs__"] = clip_text(state.get("dev_docs", ""))
    docs["__runtime_audit_docs__"] = clip_text(state.get("audit_docs", ""))

    return {
        "documents": docs,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        # Build-first policy: don't fail on missing docs; report and continue.
        "proceed_on_missing": True,
    }


def safe_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text, "parse_error": True}


def load_decision_schema() -> dict[str, Any]:
    if not DECISION_SCHEMA_PATH.exists():
        return {}
    with DECISION_SCHEMA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_decision_packet_shape(packet: dict[str, Any]) -> list[str]:
    schema = load_decision_schema()
    required = schema.get("required", [])
    errors: list[str] = []
    for key in required:
        if key not in packet:
            errors.append(f"missing required field: {key}")
    if "approved_testcase_bundle" in packet and not isinstance(packet.get("approved_testcase_bundle"), (dict, list, str)):
        errors.append("approved_testcase_bundle must be object/array/string")
    if "pii_masking_rules" in packet and not isinstance(packet.get("pii_masking_rules"), list):
        errors.append("pii_masking_rules must be array")
    if "guardrail_filter_result" in packet and not isinstance(packet.get("guardrail_filter_result"), dict):
        errors.append("guardrail_filter_result must be object")
    return errors


PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{4}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{20,})\b")),
]

KILOCODE_SECURITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("privilege_escalation_sudo", re.compile(r"\bsudo\b", re.IGNORECASE)),
    ("privilege_escalation_su", re.compile(r"\bsu\s+-?\b", re.IGNORECASE)),
    ("dangerous_permission_change", re.compile(r"\bchmod\s+777\b", re.IGNORECASE)),
    ("root_ownership_change", re.compile(r"\bchown\s+root\b", re.IGNORECASE)),
    ("destructive_root_delete", re.compile(r"\brm\s+-rf\s+/\b", re.IGNORECASE)),
    ("sudoers_modification", re.compile(r"/etc/sudoers", re.IGNORECASE)),
    ("shell_pipe_exec", re.compile(r"\b(?:curl|wget)\b[^\n]{0,120}\|\s*(?:sh|bash)\b", re.IGNORECASE)),
]


def redact_text(text: str) -> str:
    out = text
    out = PII_PATTERNS[0][1].sub("[REDACTED_EMAIL]", out)
    out = PII_PATTERNS[1][1].sub("[REDACTED_PHONE]", out)
    out = PII_PATTERNS[2][1].sub("[REDACTED_SSN]", out)
    out = PII_PATTERNS[3][1].sub("[REDACTED_CARD]", out)
    out = PII_PATTERNS[4][1].sub("[REDACTED_API_KEY]", out)
    return out


def sanitize_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [sanitize_obj(v) for v in value]
    if isinstance(value, dict):
        return {k: sanitize_obj(v) for k, v in value.items()}
    return value


def scan_pii(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, str):
        for label, pattern in PII_PATTERNS:
            if pattern.search(value):
                findings.append(f"{label} detected at {path}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            findings.extend(scan_pii(item, f"{path}[{i}]"))
    elif isinstance(value, dict):
        for k, v in value.items():
            findings.extend(scan_pii(v, f"{path}.{k}"))
    return findings


def enforce_decision_guardrails(packet: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(packet, dict):
        packet = {"raw_packet": str(packet)}

    packet.setdefault("approved_testcase_bundle", {})
    packet.setdefault(
        "pii_masking_rules",
        [
            "Mask email as [REDACTED_EMAIL]",
            "Mask phone as [REDACTED_PHONE]",
            "Mask SSN as [REDACTED_SSN]",
            "Mask card number as [REDACTED_CARD]",
            "Mask API key as [REDACTED_API_KEY]",
        ],
    )
    packet.setdefault("guardrail_filter_result", {})

    shape_errors = validate_decision_packet_shape(packet)
    pii_findings = scan_pii(packet.get("approved_testcase_bundle"))
    blocked = len(shape_errors) > 0 or len(pii_findings) > 0

    if pii_findings:
        packet["approved_testcase_bundle"] = sanitize_obj(packet.get("approved_testcase_bundle"))

    packet["guardrail_filter_result"] = {
        "status": "BLOCK" if blocked else "PASS",
        "shape_errors": shape_errors,
        "pii_findings": pii_findings,
        "final_filtered_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    return packet


def _collect_text_fragments(value: Any, bag: list[str], limit: int = 5000) -> None:
    if len(" ".join(bag)) >= limit:
        return
    if isinstance(value, str):
        bag.append(value[:1000])
        return
    if isinstance(value, list):
        for item in value:
            _collect_text_fragments(item, bag, limit=limit)
            if len(" ".join(bag)) >= limit:
                return
        return
    if isinstance(value, dict):
        for v in value.values():
            _collect_text_fragments(v, bag, limit=limit)
            if len(" ".join(bag)) >= limit:
                return


def detect_kilocode_security_violations(state: QAState) -> list[str]:
    findings: list[str] = []
    candidate_keys = ("testplan_packet",)
    for key in candidate_keys:
        packet = state.get(key)
        if not isinstance(packet, dict):
            continue
        if str(packet.get("provider", "")).strip() != "kilocode_cli":
            continue

        fragments: list[str] = []
        _collect_text_fragments(packet.get("assistant_text"), fragments)
        _collect_text_fragments(packet.get("raw_stdout"), fragments)
        _collect_text_fragments(packet.get("events"), fragments)
        haystack = "\n".join(fragments)
        for label, pattern in KILOCODE_SECURITY_PATTERNS:
            if pattern.search(haystack):
                findings.append(f"{key}: {label}")
    return findings


def _packet_json(packet: dict[str, Any]) -> str:
    return json.dumps(packet, ensure_ascii=False, indent=2)


def _kilocode_pidfile_path() -> Path:
    runtime_dir = QA_DIR / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    return runtime_dir / "kilocode_testplan.pid.json"


def _write_kilocode_pidfile(pid: int, cwd: str, story_id: str) -> None:
    payload = {
        "pid": int(pid),
        "cwd": cwd,
        "story_id": story_id,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    _kilocode_pidfile_path().write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_kilocode_pidfile() -> dict[str, Any] | None:
    path = _kilocode_pidfile_path()
    if not path.exists():
        return None
    try:
        data = safe_json(path.read_text(encoding="utf-8"))
    except OSError:
        return None
    if isinstance(data, dict) and not data.get("parse_error"):
        return data
    return None


def _clear_kilocode_pidfile() -> None:
    path = _kilocode_pidfile_path()
    if path.exists():
        path.unlink(missing_ok=True)


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _terminate_pid(pid: int) -> bool:
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except OSError:
        return False


def persist_architecture_report(sidecar: QAHistorySidecar, run_id: str, packet: dict[str, Any]) -> dict[str, Any]:
    if not run_id:
        return {"saved": False, "reason": "missing_run_id"}
    if not isinstance(packet, dict):
        return {"saved": False, "reason": "invalid_packet"}
    if sidecar.enabled:
        row_id = sidecar.save_report(
            run_id=run_id,
            agent_id="test_architect_mistral",
            report_type="architecture_packet",
            title="Architecture packet generated by Test Architect (Devstral2/Mistral)",
            path=f"db://qa_reports/{run_id}/architecture_packet",
            content_text=_packet_json(packet),
        )
        return {"saved": row_id is not None, "row_id": row_id}
    return {"saved": False, "reason": "sidecar_disabled"}


def persist_decision_report(sidecar: QAHistorySidecar, run_id: str, packet: dict[str, Any]) -> dict[str, Any]:
    if not run_id:
        return {"saved": False, "reason": "missing_run_id"}
    if not isinstance(packet, dict):
        return {"saved": False, "reason": "invalid_packet"}
    if sidecar.enabled:
        row_id = sidecar.save_report(
            run_id=run_id,
            agent_id="decision_maker_gpt5x",
            report_type="decision_packet",
            title="Decision packet generated by Decision Maker (GPT-5x)",
            path=f"db://qa_reports/{run_id}/decision_packet",
            content_text=_packet_json(packet),
        )
        return {"saved": row_id is not None, "row_id": row_id}
    return {"saved": False, "reason": "sidecar_disabled"}


def persist_script_report(sidecar: QAHistorySidecar, run_id: str, packet: dict[str, Any]) -> dict[str, Any]:
    if not run_id:
        return {"saved": False, "reason": "missing_run_id"}
    if not isinstance(packet, dict):
        return {"saved": False, "reason": "invalid_packet"}
    story_id = str(packet.get("story_id", "")).strip().lower() or "unknown_story"
    if sidecar.enabled:
        row_id = sidecar.save_report(
            run_id=run_id,
            agent_id="test_scripter_codex",
            report_type="script_packet",
            title="Script packet generated by Test Scripter (Codex)",
            path=f"db://qa_reports/{run_id}/script_packet?story_id={story_id}",
            content_text=_packet_json(packet),
        )
        return {"saved": row_id is not None, "row_id": row_id}
    return {"saved": False, "reason": "sidecar_disabled"}


def persist_adversarial_report_by_clerk(sidecar: QAHistorySidecar, run_id: str, packet: dict[str, Any]) -> dict[str, Any]:
    if not run_id:
        return {"saved": False, "reason": "missing_run_id"}
    if not isinstance(packet, dict):
        return {"saved": False, "reason": "invalid_packet"}
    if sidecar.enabled:
        row_id = sidecar.save_report(
            run_id=run_id,
            agent_id="clerk_routing_agent",
            report_type="adversarial_packet",
            title="Adversarial packet persisted by Clerk (Routing Agent)",
            path=f"db://qa_reports/{run_id}/adversarial_packet",
            content_text=_packet_json(packet),
        )
        return {"saved": row_id is not None, "row_id": row_id}
    return {"saved": False, "reason": "sidecar_disabled"}


def build_clerk_merge_packet(state: QAState, sidecar: QAHistorySidecar) -> dict[str, Any]:
    run_id = str(state.get("run_id", ""))
    story_id = detect_current_story_id(state)

    runtime_adversarial = state.get("adversarial_packet") or {}
    write_trace = persist_adversarial_report_by_clerk(
        sidecar=sidecar,
        run_id=run_id,
        packet=runtime_adversarial if isinstance(runtime_adversarial, dict) else {"raw": str(runtime_adversarial)},
    )

    arch_latest = sidecar.get_latest_report(run_id=run_id, report_type="architecture_packet") if run_id else None
    adv_latest = sidecar.get_latest_report(run_id=run_id, report_type="adversarial_packet") if run_id else None

    architecture_from_db: dict[str, Any] | None = None
    if arch_latest and isinstance(arch_latest.get("content_text"), str):
        parsed = safe_json(str(arch_latest["content_text"]))
        if isinstance(parsed, dict) and not parsed.get("parse_error"):
            architecture_from_db = parsed

    adversarial_from_db: dict[str, Any] | None = None
    if adv_latest and isinstance(adv_latest.get("content_text"), str):
        parsed = safe_json(str(adv_latest["content_text"]))
        if isinstance(parsed, dict) and not parsed.get("parse_error"):
            adversarial_from_db = parsed

    architecture_packet = architecture_from_db or state.get("architecture_packet") or {}
    adversarial_packet = adversarial_from_db or runtime_adversarial or {}
    summary = "Merged architecture+adversarial reports from SQLite sidecar." if architecture_from_db and adversarial_from_db else (
        "Merged packets using SQLite + runtime fallbacks."
    )

    merged_packet = {
        "provider": "routing_agent",
        "status": "merged_ready",
        "summary": summary,
        "story_id": story_id,
        "handoff_target": "decision_maker_gpt5x",
        "sqlite_write_trace": write_trace,
        "db_lookup": {
            "enabled": sidecar.enabled,
            "run_id": run_id,
            "architecture": {
                "report_type": "architecture_packet",
                "found": bool(arch_latest),
                "report_id": arch_latest.get("id") if arch_latest else None,
                "report_path": arch_latest.get("path") if arch_latest else None,
                "report_created_at": arch_latest.get("created_at") if arch_latest else None,
            },
            "adversarial": {
                "report_type": "adversarial_packet",
                "found": bool(adv_latest),
                "report_id": adv_latest.get("id") if adv_latest else None,
                "report_path": adv_latest.get("path") if adv_latest else None,
                "report_created_at": adv_latest.get("created_at") if adv_latest else None,
            },
        },
        "merged_architect_packet": {
            "architecture_packet": architecture_packet,
            "adversarial_packet": adversarial_packet,
            "routing_note": "Use merged architect reports as primary decision input.",
        },
    }
    if sidecar.enabled and run_id:
        clerk_report_id = sidecar.save_report(
            run_id=run_id,
            agent_id="clerk_routing_agent",
            report_type="clerk_packet",
            title="Merged clerk packet for decision preflight",
            path=f"db://qa_reports/{run_id}/clerk_packet",
            content_text=_packet_json(merged_packet),
        )
        merged_packet["sqlite_clerk_store"] = {
            "saved": clerk_report_id is not None,
            "row_id": clerk_report_id,
        }
    else:
        merged_packet["sqlite_clerk_store"] = {
            "saved": False,
            "reason": "sidecar_disabled_or_missing_run_id",
        }
    return merged_packet


def build_decision_preflight_context(state: QAState, sidecar: QAHistorySidecar) -> dict[str, Any]:
    run_id = str(state.get("run_id", ""))
    story_id = detect_current_story_id(state)

    checks: dict[str, Any] = {}
    for rel in ("lib", "docs", "test"):
        p = ROOT / rel
        checks[rel] = {"exists": p.exists(), "is_dir": p.is_dir()}
    checks["lib_dart_file_count"] = len(list((ROOT / "lib").rglob("*.dart"))) if (ROOT / "lib").exists() else 0

    changed_files = [str(x) for x in state.get("changed_files", [])]
    changed_files_check = []
    for rel in changed_files:
        p = ROOT / rel
        changed_files_check.append({"path": rel, "exists": p.exists()})

    latest_clerk = sidecar.get_latest_report(run_id=run_id, report_type="clerk_packet") if run_id else None
    clerk_packet = None
    if latest_clerk and isinstance(latest_clerk.get("content_text"), str):
        parsed = safe_json(str(latest_clerk["content_text"]))
        if isinstance(parsed, dict) and not parsed.get("parse_error"):
            clerk_packet = parsed

    clerk_story_id = ""
    if isinstance(clerk_packet, dict):
        clerk_story_id = str(clerk_packet.get("story_id", "")).strip().lower()
    story_match = bool(story_id) and bool(clerk_story_id) and story_id == clerk_story_id

    return {
        "status": "ready_for_decision",
        "run_id": run_id,
        "story_id": story_id,
        "codebase_check": {
            "root": str(ROOT),
            "paths": checks,
            "changed_files": changed_files_check,
        },
        "sqlite_lookup": {
            "enabled": sidecar.enabled,
            "target_report_type": "clerk_packet",
            "found": bool(latest_clerk),
            "report_id": latest_clerk.get("id") if latest_clerk else None,
            "report_path": latest_clerk.get("path") if latest_clerk else None,
            "report_created_at": latest_clerk.get("created_at") if latest_clerk else None,
            "clerk_story_id": clerk_story_id,
            "story_match": story_match if story_id else None,
        },
        "clerk_packet_for_decision": clerk_packet if isinstance(clerk_packet, dict) else {},
    }


def build_testplan_routing_packet(state: QAState, sidecar: QAHistorySidecar) -> dict[str, Any]:
    run_id = str(state.get("run_id", ""))
    story_id = detect_current_story_id(state)
    story_token = story_id if story_id else "sto000x"
    target_rel_path = f"docs/testplans/{story_token}_testplan.md"

    decision_latest = sidecar.get_latest_report(run_id=run_id, report_type="decision_packet") if run_id else None
    clerk_latest = sidecar.get_latest_report(run_id=run_id, report_type="clerk_packet") if run_id else None

    decision_packet: dict[str, Any] = {}
    if decision_latest and isinstance(decision_latest.get("content_text"), str):
        parsed = safe_json(str(decision_latest["content_text"]))
        if isinstance(parsed, dict) and not parsed.get("parse_error"):
            decision_packet = parsed

    clerk_packet: dict[str, Any] = {}
    if clerk_latest and isinstance(clerk_latest.get("content_text"), str):
        parsed = safe_json(str(clerk_latest["content_text"]))
        if isinstance(parsed, dict) and not parsed.get("parse_error"):
            clerk_packet = parsed

    return {
        "provider": "routing_agent",
        "status": "ready_for_testplan",
        "story_id": story_id,
        "handoff_target": "testplan_generator_glm5",
        "target_testplan_path": target_rel_path,
        "sqlite_lookup_trace": {
            "enabled": sidecar.enabled,
            "run_id": run_id,
            "decision_packet": {
                "found": bool(decision_latest),
                "report_id": decision_latest.get("id") if decision_latest else None,
                "report_path": decision_latest.get("path") if decision_latest else None,
                "report_created_at": decision_latest.get("created_at") if decision_latest else None,
            },
            "clerk_packet": {
                "found": bool(clerk_latest),
                "report_id": clerk_latest.get("id") if clerk_latest else None,
                "report_path": clerk_latest.get("path") if clerk_latest else None,
                "report_created_at": clerk_latest.get("created_at") if clerk_latest else None,
            },
        },
        "handoff_payload": {
            "decision_packet": decision_packet or state.get("decision_packet", {}),
            "clerk_packet": clerk_packet or state.get("clerk_packet", {}),
            "target_testplan_path": target_rel_path,
            "routing_note": "Use this SQLite-routed payload as primary testplan input.",
        },
    }


def build_script_routing_packet(state: QAState, sidecar: QAHistorySidecar) -> dict[str, Any]:
    run_id = str(state.get("run_id", ""))
    story_id = detect_current_story_id(state)
    story_token = story_id if story_id else "sto000x"

    decision_latest = sidecar.get_latest_report(run_id=run_id, report_type="decision_packet") if run_id else None
    clerk_latest = sidecar.get_latest_report(run_id=run_id, report_type="clerk_packet") if run_id else None

    decision_packet: dict[str, Any] = {}
    if decision_latest and isinstance(decision_latest.get("content_text"), str):
        parsed = safe_json(str(decision_latest["content_text"]))
        if isinstance(parsed, dict) and not parsed.get("parse_error"):
            decision_packet = parsed

    clerk_packet: dict[str, Any] = {}
    if clerk_latest and isinstance(clerk_latest.get("content_text"), str):
        parsed = safe_json(str(clerk_latest["content_text"]))
        if isinstance(parsed, dict) and not parsed.get("parse_error"):
            clerk_packet = parsed

    return {
        "provider": "routing_agent",
        "status": "ready_for_scripter",
        "story_id": story_id,
        "handoff_target": "test_scripter_codex",
        "dispatch_policy": {
            "wait_for_testplan_completion": False,
            "dispatch_order": ["testplan_generator_glm5", "test_scripter_codex"],
        },
        "authoring_mode": "story_only",
        "target_script_directory": "scripts/qa",
        "target_script_pattern": f"{story_token}_*.spec.ts",
        "playwright_context_root": "test/playwright",
        "sqlite_lookup_trace": {
            "enabled": sidecar.enabled,
            "run_id": run_id,
            "decision_packet": {
                "found": bool(decision_latest),
                "report_id": decision_latest.get("id") if decision_latest else None,
                "report_path": decision_latest.get("path") if decision_latest else None,
                "report_created_at": decision_latest.get("created_at") if decision_latest else None,
            },
            "clerk_packet": {
                "found": bool(clerk_latest),
                "report_id": clerk_latest.get("id") if clerk_latest else None,
                "report_path": clerk_latest.get("path") if clerk_latest else None,
                "report_created_at": clerk_latest.get("created_at") if clerk_latest else None,
            },
        },
        "handoff_payload": {
            "decision_packet": decision_packet or state.get("decision_packet", {}),
            "clerk_packet": clerk_packet or state.get("clerk_packet", {}),
            "authoring_mode": "story_only",
            "target_script_directory": "scripts/qa",
            "target_script_pattern": f"{story_token}_*.spec.ts",
            "playwright_context_root": "test/playwright",
            "routing_note": "Dispatched right after testplan assignment; do not wait for testplan completion.",
        },
    }


def _normalize_command_list(value: Any) -> list[str]:
    if isinstance(value, str):
        cmd = value.strip()
        return [cmd] if cmd else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
        return out
    return []


def _evaluate_testplan_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "exists": False,
            "ready": False,
            "size_bytes": 0,
            "line_count": 0,
            "reason": "missing_file",
            "quality_checks": {
                "target_testplan_file_exists_for_current_story": False,
                "mandatory_sections_present": False,
                "p0_cases_present_and_executable": False,
                "acceptance_criteria_traceability_present": False,
            },
        }
    text = read_text(path)
    lower = text.lower()
    size = len(text.encode("utf-8"))
    lines = len(text.splitlines())
    required_sections = (
        ("Purpose", ("purpose", "목적")),
        ("Scope", ("scope", "범위")),
        ("Prerequisites", ("prerequisites", "사전", "준비사항")),
        ("Step-by-Step", ("step-by-step", "step by step", "절차", "테스트 케이스")),
        ("How to Record Results", ("how to record results", "결과 기록")),
        ("Exit and Success Criteria", ("exit and success criteria", "성공 기준", "종료 기준")),
    )
    missing_sections = [label for label, aliases in required_sections if not any(alias in lower for alias in aliases)]
    has_p0 = bool(re.search(r"\bp0\b", text, flags=re.IGNORECASE))
    has_traceability = any(tok in lower for tok in ("acceptance criteria", "traceability", "ac ", "ac:", "인수 기준"))
    quality_checks = {
        "target_testplan_file_exists_for_current_story": True,
        "mandatory_sections_present": len(missing_sections) == 0,
        "p0_cases_present_and_executable": has_p0,
        "acceptance_criteria_traceability_present": has_traceability,
    }
    ready = size >= 500 and lines >= 20 and all(bool(v) for v in quality_checks.values())
    return {
        "exists": True,
        "ready": ready,
        "size_bytes": size,
        "line_count": lines,
        "missing_sections": missing_sections,
        "quality_checks": quality_checks,
    }


def _build_testplan_quality_verdict(check: dict[str, Any]) -> dict[str, Any]:
    checks = check.get("quality_checks") if isinstance(check, dict) else {}
    checks = checks if isinstance(checks, dict) else {}
    failed_checks = [k for k, v in checks.items() if not bool(v)]
    return {
        "status": "pass" if check.get("ready") else "fail",
        "failed_checks": failed_checks,
        "quality_checks": checks,
        "target_ready": bool(check.get("ready")),
    }


def _post_tester_testplan_followup(state: QAState, sidecar: QAHistorySidecar, dry_run: bool) -> dict[str, Any]:
    story_id = detect_current_story_id(state) or "sto000x"
    routing_packet = state.get("testplan_routing_packet") if isinstance(state.get("testplan_routing_packet"), dict) else {}
    target_rel = str(routing_packet.get("target_testplan_path", "")).strip() or f"docs/testplans/{story_id}_testplan.md"
    target_path = (ROOT / target_rel).resolve()
    check_before = _evaluate_testplan_file(target_path)
    verdict_before = _build_testplan_quality_verdict(check_before)

    action = "none"
    rerun_attempted = False
    rerun_result: dict[str, Any] | None = None
    terminal_reason_code = ""
    process_control_action_log: list[dict[str, Any]] = []
    security_findings = detect_kilocode_security_violations(state)

    pid_info = _read_kilocode_pidfile()
    pid_running = False
    pid_killed = False
    if isinstance(pid_info, dict):
        pid = int(pid_info.get("pid", 0) or 0)
        if pid > 0:
            pid_running = _pid_is_running(pid)
            # If doc already ready but Kilo Code still alive, stop stale worker.
            if pid_running and check_before.get("ready") and not dry_run:
                pid_killed = _terminate_pid(pid)
                action = "kill_stale_kilocode"
                if pid_killed:
                    _clear_kilocode_pidfile()
                process_control_action_log.append(
                    {
                        "action": "kill_stale_kilocode",
                        "performed": bool(pid_killed),
                        "reason": "testplan_already_ready",
                    }
                )

    if security_findings and not dry_run:
        action = "force_terminate_due_to_security"
        terminal_reason_code = "suspicious_behavior_detected"
        if pid_running and isinstance(pid_info, dict):
            pid = int(pid_info.get("pid", 0) or 0)
            if pid > 0:
                pid_killed = _terminate_pid(pid)
                if pid_killed:
                    _clear_kilocode_pidfile()
        process_control_action_log.append(
            {
                "action": "force_terminate_process",
                "performed": True,
                "reason": terminal_reason_code,
                "security_findings": security_findings,
            }
        )
    elif not check_before.get("ready"):
        if not dry_run and not pid_running:
            persona = load_persona("testplan_generator_glm5")
            assigned_docs = resolve_assigned_documents(persona, state)
            model_cfg = load_yaml(QA_DIR / "configs" / "model_config.yaml")
            rerun_result = call_kilocode_cli(persona, state, model_cfg, assigned_docs)
            rerun_attempted = True
            action = "rerun_testplan_generator"
            process_control_action_log.append(
                {
                    "action": "rerun_testplan_generator",
                    "performed": True,
                    "reason": "missing_or_incomplete_testplan",
                    "rerun_error": rerun_result.get("error") if isinstance(rerun_result, dict) else None,
                }
            )
        elif dry_run:
            action = "dry_run_no_action"
            process_control_action_log.append(
                {
                    "action": "skip_runtime_remediation",
                    "performed": False,
                    "reason": "dry_run",
                }
            )
        elif pid_running:
            action = "wait_or_kill_running_kilocode"
            process_control_action_log.append(
                {
                    "action": "defer_until_running_process_finishes",
                    "performed": False,
                    "reason": "kilocode_already_running",
                }
            )

    check_after = _evaluate_testplan_file(target_path)
    verdict_after = _build_testplan_quality_verdict(check_after)

    gate_status = "pass"
    gate_action = "continue"
    if terminal_reason_code:
        gate_status = "force_terminated"
        gate_action = "stop"
    elif not check_after.get("ready"):
        if dry_run:
            gate_status = "pending_manual_check"
            gate_action = "manual_review"
        elif rerun_attempted:
            gate_status = "force_terminated"
            gate_action = "stop"
            if isinstance(rerun_result, dict) and rerun_result.get("error"):
                terminal_reason_code = "rerun_failed"
            elif not check_after.get("exists"):
                terminal_reason_code = "output_missing_after_rerun"
            else:
                terminal_reason_code = "output_stale_or_incomplete"
            process_control_action_log.append(
                {
                    "action": "force_terminate_process",
                    "performed": True,
                    "reason": terminal_reason_code,
                }
            )
        else:
            gate_status = "needs_rerun"
            gate_action = "rerun_testplan_generator"

    tester_gate_decision = {
        "status": gate_status,
        "action": gate_action,
        "reason_code": terminal_reason_code,
    }

    return {
        "story_id": story_id,
        "target_testplan_path": target_rel,
        "check_before": check_before,
        "quality_verdict_before": verdict_before,
        "check_after": check_after,
        "testplan_quality_verdict": verdict_after,
        "kilocode_pid": pid_info,
        "kilocode_running": pid_running,
        "kilocode_killed": pid_killed,
        "rerun_attempted": rerun_attempted,
        "rerun_result": rerun_result,
        "security_findings": security_findings,
        "process_control_action_log": process_control_action_log,
        "tester_gate_decision": tester_gate_decision,
        "action": action,
    }


def build_tester_execution_packet(state: QAState, sidecar: QAHistorySidecar, dry_run: bool) -> dict[str, Any]:
    run_id = str(state.get("run_id", ""))
    story_id = detect_current_story_id(state) or "sto000x"
    script_pattern = f"{story_id}_*.spec.ts"
    script_dir = ROOT / "scripts" / "qa"
    playwright_root = ROOT / "test" / "playwright"

    latest_script = sidecar.get_latest_report_by_story(
        run_id=run_id,
        report_type="script_packet",
        story_id=story_id,
    ) if run_id else None

    script_packet: dict[str, Any] = {}
    if latest_script and isinstance(latest_script.get("content_text"), str):
        parsed = safe_json(str(latest_script["content_text"]))
        if isinstance(parsed, dict) and not parsed.get("parse_error"):
            script_packet = parsed

    commands = _normalize_command_list(script_packet.get("playwright_execution_commands"))
    if not commands:
        commands = [f"npx playwright test ../../scripts/qa/{script_pattern}"]

    script_files = sorted(str(p.relative_to(ROOT)) for p in script_dir.glob(script_pattern) if p.is_file())
    execution_results: list[dict[str, Any]] = []
    error_logs: list[str] = []

    if dry_run:
        result_status = "dry_run"
        execution_results.append(
            {
                "command": commands[0] if commands else "",
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "dry_run": True,
            }
        )
    elif not script_files:
        result_status = "failed"
        error_logs.append(f"No script file matched pattern {script_pattern} under scripts/qa.")
    elif not playwright_root.exists():
        result_status = "failed"
        error_logs.append("Playwright context root test/playwright does not exist.")
    else:
        failures = 0
        for raw_cmd in commands:
            if not raw_cmd.strip():
                continue
            try:
                cmd_parts = shlex.split(raw_cmd)
            except ValueError:
                cmd_parts = [raw_cmd]
            proc = subprocess.run(
                cmd_parts,
                cwd=str(playwright_root),
                capture_output=True,
                text=True,
                check=False,
            )
            stdout = (proc.stdout or "").strip()
            stderr = (proc.stderr or "").strip()
            execution_results.append(
                {
                    "command": raw_cmd,
                    "returncode": proc.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                }
            )
            if proc.returncode != 0:
                failures += 1
                if stderr:
                    error_logs.append(stderr)
        result_status = "passed" if failures == 0 else "failed"

    pass_count = sum(1 for x in execution_results if x.get("returncode") == 0 or x.get("dry_run"))
    fail_count = sum(1 for x in execution_results if isinstance(x.get("returncode"), int) and x.get("returncode") != 0)
    error_text = "\n\n".join(x for x in error_logs if x).strip()

    testplan_followup = _post_tester_testplan_followup(state, sidecar, dry_run)
    testplan_gate = testplan_followup.get("tester_gate_decision", {}) if isinstance(testplan_followup, dict) else {}
    testplan_gate_status = str(testplan_gate.get("status", "pass")).strip()
    qa_verdict = "pass" if result_status in {"passed", "dry_run"} and testplan_gate_status in {"pass", "pending_manual_check"} else "fail"
    tester_gate_decision = {
        "qa_verdict": qa_verdict,
        "script_execution_status": result_status,
        "testplan_gate_status": testplan_gate_status,
        "action": testplan_gate.get("action", "continue"),
        "reason_code": testplan_gate.get("reason_code", ""),
    }

    packet: dict[str, Any] = {
        "provider": "routing_agent",
        "status": result_status,
        "story_id": story_id,
        "script_packet_lookup": {
            "enabled": sidecar.enabled,
            "found": bool(latest_script),
            "report_id": latest_script.get("id") if latest_script else None,
            "report_path": latest_script.get("path") if latest_script else None,
            "report_created_at": latest_script.get("created_at") if latest_script else None,
        },
        "script_execution": {
            "script_directory": "scripts/qa",
            "script_pattern": script_pattern,
            "matched_scripts": script_files,
            "playwright_context_root": "test/playwright",
            "commands": commands,
            "results": execution_results,
        },
        "error_log": error_text,
        "final_test_report": {
            "qa_verdict": qa_verdict,
            "script_result_status": result_status,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "evidence": {
                "script_execution_results": len(execution_results),
                "has_error_log": bool(error_text),
            },
        },
        "testplan_followup": testplan_followup,
        "testplan_quality_verdict": testplan_followup.get("testplan_quality_verdict", {}),
        "process_control_action_log": testplan_followup.get("process_control_action_log", []),
        "tester_gate_decision": tester_gate_decision,
    }

    if sidecar.enabled and run_id:
        row_id = sidecar.save_final_test_record(
            run_id=run_id,
            story_id=story_id,
            script_report_id=latest_script.get("id") if latest_script else None,
            script_report_path=str(latest_script.get("path")) if latest_script else None,
            executed_from="test/playwright",
            script_glob=script_pattern,
            commands=commands,
            result_status=result_status,
            pass_count=pass_count,
            fail_count=fail_count,
            error_log=error_text,
            result_payload=packet,
        )
        packet["sqlite_final_test_store"] = {"saved": row_id is not None, "row_id": row_id}
    else:
        packet["sqlite_final_test_store"] = {"saved": False, "reason": "sidecar_disabled_or_missing_run_id"}

    return packet


def resolve_model_name(persona: dict[str, Any], model_cfg: dict[str, Any], default_model: str) -> str:
    explicit = str(persona.get("model", "")).strip()
    if explicit:
        return explicit

    hint = str(persona.get("model_hint", "")).lower()
    mapping = model_cfg.get("routing", {}).get("model_by_hint", {})
    if isinstance(mapping, dict):
        for token, model_name in mapping.items():
            if str(token).lower() in hint and str(model_name).strip():
                return str(model_name).strip()

    return default_model


def resolve_endpoint_config(model_cfg: dict[str, Any]) -> tuple[str, str, str, str]:
    endpoint_cfg = model_cfg.get("endpoint", {})
    if not isinstance(endpoint_cfg, dict):
        endpoint_cfg = {}

    api_key_env = str(endpoint_cfg.get("api_key_env", "OPENAI_API_KEY")).strip() or "OPENAI_API_KEY"
    base_url_env = str(endpoint_cfg.get("base_url_env", "OPENAI_BASE_URL")).strip() or "OPENAI_BASE_URL"
    api_key = os.getenv(api_key_env, "") or str(endpoint_cfg.get("api_key", "")).strip()
    base_url = os.getenv(base_url_env, "") or str(endpoint_cfg.get("base_url", "")).strip()
    return api_key_env, base_url_env, api_key, base_url


def call_llm(
    persona: dict[str, Any],
    state: QAState,
    assigned_docs: dict[str, Any],
    model_cfg: dict[str, Any],
) -> dict[str, Any]:
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_openai import ChatOpenAI

    model_name = resolve_model_name(persona, model_cfg, str(model_cfg.get("model", "gpt-5-mini")))
    prompt_template = read_text(QA_DIR / "prompts" / "system" / "agentic_template.txt")

    mission_lines = persona.get("mission", [])
    mission = "\n".join(f"- {m}" for m in mission_lines)
    docs = "\n".join(f"- {d}" for d in persona.get("documentation_to_produce", []))

    system_prompt = prompt_template.format(
        persona_name=persona.get("name", persona.get("id", "unknown")),
        persona_role=persona.get("role", ""),
        persona_mission=mission,
        documentation_to_produce=docs,
    )

    human_payload = {
        "workflow": state.get("workflow_id"),
        "run_id": state.get("run_id"),
        "assigned_documents": assigned_docs.get("documents", {}),
        "missing_docs": {
            "required": assigned_docs.get("missing_required", []),
            "optional": assigned_docs.get("missing_optional", []),
        },
        "policy": {
            "proceed_on_missing_docs": bool(assigned_docs.get("proceed_on_missing", True)),
            "execution_policy": persona.get("execution_policy", {}),
        },
        "inputs": {
            "dev_docs": state.get("dev_docs", ""),
            "audit_docs": state.get("audit_docs", ""),
            "changed_files": state.get("changed_files", []),
        },
        "intermediate": {
            "architecture_packet": state.get("architecture_packet"),
            "adversarial_packet": state.get("adversarial_packet"),
            "clerk_packet": state.get("clerk_packet"),
            "decision_preflight": state.get("decision_preflight"),
            "decision_packet": state.get("decision_packet"),
            "testplan_routing_packet": state.get("testplan_routing_packet"),
            "script_routing_packet": state.get("script_routing_packet"),
            "testplan_packet": state.get("testplan_packet"),
            "script_packet": state.get("script_packet"),
        },
    }

    _, _, api_key, base_url = resolve_endpoint_config(model_cfg)
    model = ChatOpenAI(
        model=model_name,
        temperature=float(model_cfg.get("temperature", 0.1)),
        max_tokens=int(model_cfg.get("max_tokens", 1800)),
        timeout=int(model_cfg.get("timeout_seconds", 60)),
        api_key=api_key or None,
        base_url=base_url or None,
    )
    resp = model.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content="Return JSON only.\n\n" + json.dumps(human_payload, ensure_ascii=True, indent=2)),
    ])
    content = resp.content if isinstance(resp.content, str) else str(resp.content)
    return safe_json(content)


def parse_vibe_cli_response(stdout: str) -> dict[str, Any]:
    payload = safe_json(stdout)
    if not isinstance(payload, dict):
        return {"raw": stdout, "parse_error": True}

    assistant_text = ""
    messages = payload.get("messages")
    if isinstance(messages, list):
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                content = msg.get("content")
                if isinstance(content, str):
                    assistant_text = content
                elif isinstance(content, list):
                    text_parts = []
                    for part in content:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            text_parts.append(part["text"])
                    assistant_text = "\n".join(text_parts).strip()
                break

    if not assistant_text and isinstance(payload.get("assistant"), str):
        assistant_text = payload["assistant"]
    if not assistant_text and isinstance(payload.get("output"), str):
        assistant_text = payload["output"]

    if assistant_text:
        parsed = safe_json(assistant_text)
        if isinstance(parsed, dict):
            parsed["provider"] = "vibe_cli"
            return parsed
        return {"provider": "vibe_cli", "assistant_text": assistant_text}

    payload["provider"] = "vibe_cli"
    return payload


def should_use_vibe_cli(persona: dict[str, Any], model_cfg: dict[str, Any]) -> bool:
    hint = str(persona.get("model_hint", "")).lower()
    hints = model_cfg.get("routing", {}).get("use_vibe_for_model_hints", ["mistral", "devstral"])
    return any(token in hint for token in hints)


def should_use_codex_cli(persona: dict[str, Any], model_cfg: dict[str, Any]) -> bool:
    hint = str(persona.get("model_hint", "")).lower()
    hints = model_cfg.get("routing", {}).get("use_codex_cli_for_model_hints", ["codex"])
    return any(token in hint for token in hints)


def should_use_kilocode_cli(persona: dict[str, Any], model_cfg: dict[str, Any]) -> bool:
    hint = str(persona.get("model_hint", "")).lower()
    hints = model_cfg.get("routing", {}).get("use_kilocode_cli_for_model_hints", ["glm-5", "glm5"])
    return any(token in hint for token in hints)


def resolve_vibe_sandbox_mode(vibe_cfg: dict[str, Any]) -> str:
    raw = str(vibe_cfg.get("sandbox", "read-only")).strip().lower()
    if raw in {"read-only", "workspace-write", "danger-full-access"}:
        return raw
    return "read-only"


def resolve_vibe_enabled_tools(vibe_cfg: dict[str, Any], sandbox_mode: str) -> tuple[list[str], bool]:
    raw_tools = vibe_cfg.get("enabled_tools", [])
    if not isinstance(raw_tools, list):
        raw_tools = []
    tools = [str(t).strip() for t in raw_tools if str(t).strip()]

    # In read-only mode, enforce an explicit read-only allowlist unless one is provided.
    if sandbox_mode == "read-only":
        if tools:
            return tools, True
        return ["read_file", "grep", "bash", "task", "todo"], True

    # For write/full-access modes, allow full toolset by default.
    # If enabled_tools is explicitly provided, treat it as an allowlist.
    return tools, bool(tools)


def call_vibe_cli(
    persona: dict[str, Any],
    state: QAState,
    model_cfg: dict[str, Any],
    assigned_docs: dict[str, Any],
) -> dict[str, Any]:
    prompt_template = read_text(QA_DIR / "prompts" / "system" / "agentic_template.txt")
    mission_lines = persona.get("mission", [])
    mission = "\n".join(f"- {m}" for m in mission_lines)
    docs = "\n".join(f"- {d}" for d in persona.get("documentation_to_produce", []))

    system_prompt = prompt_template.format(
        persona_name=persona.get("name", persona.get("id", "unknown")),
        persona_role=persona.get("role", ""),
        persona_mission=mission,
        documentation_to_produce=docs,
    )

    human_payload = {
        "workflow": state.get("workflow_id"),
        "run_id": state.get("run_id"),
        "assigned_documents": assigned_docs.get("documents", {}),
        "missing_docs": {
            "required": assigned_docs.get("missing_required", []),
            "optional": assigned_docs.get("missing_optional", []),
        },
        "policy": {
            "proceed_on_missing_docs": bool(assigned_docs.get("proceed_on_missing", True)),
        },
        "inputs": {
            "dev_docs": state.get("dev_docs", ""),
            "audit_docs": state.get("audit_docs", ""),
            "changed_files": state.get("changed_files", []),
        },
        "intermediate": {
            "architecture_packet": state.get("architecture_packet"),
            "adversarial_packet": state.get("adversarial_packet"),
            "clerk_packet": state.get("clerk_packet"),
            "decision_packet": state.get("decision_packet"),
            "testplan_routing_packet": state.get("testplan_routing_packet"),
            "script_routing_packet": state.get("script_routing_packet"),
            "testplan_packet": state.get("testplan_packet"),
            "script_packet": state.get("script_packet"),
        },
    }
    report_dir = resolve_vibe_report_output_dir(state)
    report_dir_rel = _to_rel_label(report_dir)
    report_policy = (
        "Report output policy:\n"
        f"- Create directory: {report_dir_rel}\n"
        f"- Save at least one markdown report file (*.md) inside {report_dir_rel}\n"
        "- Perform this write directly via available tools before final answer\n"
        "- Include `report_output_dir` and `report_files` in the final JSON response\n"
    )
    before_files = set()
    if report_dir.exists():
        before_files = {str(p.resolve()) for p in report_dir.rglob("*.md") if p.is_file()}

    full_prompt = (
        f"{system_prompt}\n\n{report_policy}\nReturn JSON only.\n\n"
        + json.dumps(human_payload, ensure_ascii=True, indent=2)
    )

    vibe_cfg = model_cfg.get("vibe_cli", {})
    cmd = [
        str(vibe_cfg.get("command", "vibe")),
        "--prompt",
        full_prompt,
        "--output",
        str(vibe_cfg.get("output", "json")),
        "--max-turns",
        str(vibe_cfg.get("max_turns", 1)),
    ]

    max_price = vibe_cfg.get("max_price")
    if max_price is not None:
        cmd.extend(["--max-price", str(max_price)])

    sandbox_mode = resolve_vibe_sandbox_mode(vibe_cfg)
    enabled_tools, enforce_allowlist = resolve_vibe_enabled_tools(vibe_cfg, sandbox_mode)
    if enforce_allowlist:
        for tool_name in enabled_tools:
            cmd.extend(["--enabled-tools", str(tool_name)])

    env = os.environ.copy()
    env["VIBE_LOG_DIR"] = "/tmp"
    env["HOME"] = "/tmp"
    env["VIBE_SANDBOX_MODE"] = sandbox_mode
    
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        return {
            "provider": "vibe_cli",
            "error": "vibe_cli_failed",
            "returncode": proc.returncode,
            "stderr": (proc.stderr or "").strip(),
            "stdout": (proc.stdout or "").strip(),
            "sandbox_mode": sandbox_mode,
            "enabled_tools": enabled_tools,
            "tool_allowlist_enforced": enforce_allowlist,
            "report_output_dir": report_dir_rel,
        }
    report_files = [str(p.resolve()) for p in report_dir.rglob("*.md")] if report_dir.exists() else []
    if not report_files:
        return {
            "provider": "vibe_cli",
            "error": "vibe_report_missing",
            "stderr": f"No markdown report saved under {report_dir_rel}",
            "stdout": (proc.stdout or "").strip(),
            "sandbox_mode": sandbox_mode,
            "enabled_tools": enabled_tools,
            "tool_allowlist_enforced": enforce_allowlist,
            "report_output_dir": report_dir_rel,
        }

    report_files_rel = sorted(_to_rel_label(Path(p)) for p in report_files)
    new_files_rel = sorted(
        _to_rel_label(Path(p))
        for p in report_files
        if p not in before_files
    )

    packet = parse_vibe_cli_response(proc.stdout)
    if isinstance(packet, dict):
        packet["sandbox_mode"] = sandbox_mode
        packet["enabled_tools"] = enabled_tools
        packet["tool_allowlist_enforced"] = enforce_allowlist
        packet["report_output_dir"] = report_dir_rel
        packet["report_files"] = report_files_rel
        packet["new_report_files"] = new_files_rel
    return packet


def call_codex_cli(
    persona: dict[str, Any],
    state: QAState,
    model_cfg: dict[str, Any],
    assigned_docs: dict[str, Any],
) -> dict[str, Any]:
    prompt_template = read_text(QA_DIR / "prompts" / "system" / "agentic_template.txt")
    mission_lines = persona.get("mission", [])
    mission = "\n".join(f"- {m}" for m in mission_lines)
    docs = "\n".join(f"- {d}" for d in persona.get("documentation_to_produce", []))

    system_prompt = prompt_template.format(
        persona_name=persona.get("name", persona.get("id", "unknown")),
        persona_role=persona.get("role", ""),
        persona_mission=mission,
        documentation_to_produce=docs,
    )

    human_payload = {
        "workflow": state.get("workflow_id"),
        "run_id": state.get("run_id"),
        "assigned_documents": assigned_docs.get("documents", {}),
        "missing_docs": {
            "required": assigned_docs.get("missing_required", []),
            "optional": assigned_docs.get("missing_optional", []),
        },
        "policy": {
            "proceed_on_missing_docs": bool(assigned_docs.get("proceed_on_missing", True)),
        },
        "inputs": {
            "dev_docs": state.get("dev_docs", ""),
            "audit_docs": state.get("audit_docs", ""),
            "changed_files": state.get("changed_files", []),
        },
        "intermediate": {
            "architecture_packet": state.get("architecture_packet"),
            "adversarial_packet": state.get("adversarial_packet"),
            "clerk_packet": state.get("clerk_packet"),
            "decision_packet": state.get("decision_packet"),
            "testplan_routing_packet": state.get("testplan_routing_packet"),
            "script_routing_packet": state.get("script_routing_packet"),
            "testplan_packet": state.get("testplan_packet"),
            "script_packet": state.get("script_packet"),
        },
    }
    persona_id = str(persona.get("id", "")).strip()
    story_only_mode = persona_id == "test_scripter_codex"
    script_routing_packet = state.get("script_routing_packet") if isinstance(state.get("script_routing_packet"), dict) else {}
    target_script_dir = str(script_routing_packet.get("target_script_directory", "")).strip() or "scripts/qa"
    target_script_pattern = str(script_routing_packet.get("target_script_pattern", "")).strip() or "sto00X_*.spec.ts"
    playwright_root = str(script_routing_packet.get("playwright_context_root", "")).strip() or "test/playwright"
    access_policy = (
        "파일 접근 정책: scripts/qa 디렉토리 내부에서만 테스트 스크립트를 생성/수정하라. "
        "scripts/qa 외 경로에는 파일 생성/수정을 시도하지 마라. "
        f"스토리 온리 규칙을 준수해 파일명은 반드시 {target_script_pattern} 패턴을 따라라. "
        f"실행 컨텍스트는 {playwright_root} 기준으로 Playwright를 사용하라."
        if story_only_mode
        else "파일 접근 정책: 현재 리포지토리 범위 내에서만 작업."
    )
    full_prompt = (
        "에이전트로서 다음 태스크를 수행하라. 계획->실행->검증 순서로 답하라.\n"
        + access_policy
        + "\n\n"
        + f"{system_prompt}\n\nReturn JSON only.\n\n"
        + json.dumps(human_payload, ensure_ascii=True, indent=2)
    )

    codex_cfg = model_cfg.get("codex_cli", {})
    model_name = resolve_model_name(persona, model_cfg, str(codex_cfg.get("model", "gpt-5.3-codex")))
    sandbox_mode = str(codex_cfg.get("sandbox", "read-only"))
    if story_only_mode:
        sandbox_mode = "workspace-write"
    cmd = [
        str(codex_cfg.get("command", "codex")),
        "exec",
        "-c", f"ask_for_approval='{codex_cfg.get('ask_for_approval', 'never')}'",
        "-m",
        model_name,
        "--sandbox",
        sandbox_mode,
    ]

    schema_path = codex_cfg.get("output_schema_file")
    if isinstance(schema_path, str) and schema_path.strip():
        resolved_schema = (ROOT / schema_path).resolve() if not schema_path.startswith("/") else Path(schema_path)
        cmd.extend(["--output-schema", str(resolved_schema)])

    extra_args = codex_cfg.get("extra_args", [])
    if isinstance(extra_args, list):
        for arg in extra_args:
            cmd.append(str(arg))

    cmd.extend(["--", "-"])

    env = os.environ.copy()
    env["HOME"] = "/tmp"
    env["CODEX_LOG_DIR"] = "/tmp"
    endpoint_cfg = codex_cfg.get("endpoint", {})
    if isinstance(endpoint_cfg, dict):
        base_url = str(endpoint_cfg.get("base_url", "")).strip()
        base_url_env = str(endpoint_cfg.get("base_url_env", "OPENAI_BASE_URL")).strip() or "OPENAI_BASE_URL"
        api_key = str(endpoint_cfg.get("api_key", "")).strip()
        api_key_env = str(endpoint_cfg.get("api_key_env", "OPENAI_API_KEY")).strip() or "OPENAI_API_KEY"
        if base_url:
            env[base_url_env] = base_url
        if api_key:
            env[api_key_env] = api_key

    try:
        proc = subprocess.run(
            cmd,
            cwd=str((ROOT / target_script_dir).resolve()) if story_only_mode else str(ROOT),
            input=full_prompt,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except Exception as e:
        return {
            "provider": "codex_cli",
            "error": "codex_cli_failed",
            "returncode": -1,
            "stderr": str(e),
            "stdout": "",
            "cmd": cmd,
        }
    if proc.returncode != 0:
        return {
            "provider": "codex_cli",
            "error": "codex_cli_failed",
            "returncode": proc.returncode,
            "stderr": (proc.stderr or "").strip(),
            "stdout": (proc.stdout or "").strip(),
            "cmd": cmd,
        }

    stdout = (proc.stdout or "").strip()
    parsed = safe_json(stdout)
    if isinstance(parsed, dict):
        parsed["provider"] = "codex_cli"
        return parsed
    return {
        "provider": "codex_cli",
        "assistant_text": stdout,
        "raw_payload": parsed,
    }


def call_kilocode_cli(
    persona: dict[str, Any],
    state: QAState,
    model_cfg: dict[str, Any],
    assigned_docs: dict[str, Any],
) -> dict[str, Any]:
    prompt_template = read_text(QA_DIR / "prompts" / "system" / "agentic_template.txt")
    mission_lines = persona.get("mission", [])
    mission = "\n".join(f"- {m}" for m in mission_lines)
    docs = "\n".join(f"- {d}" for d in persona.get("documentation_to_produce", []))

    system_prompt = prompt_template.format(
        persona_name=persona.get("name", persona.get("id", "unknown")),
        persona_role=persona.get("role", ""),
        persona_mission=mission,
        documentation_to_produce=docs,
    )

    human_payload = {
        "workflow": state.get("workflow_id"),
        "run_id": state.get("run_id"),
        "assigned_documents": assigned_docs.get("documents", {}),
        "missing_docs": {
            "required": assigned_docs.get("missing_required", []),
            "optional": assigned_docs.get("missing_optional", []),
        },
        "policy": {
            "proceed_on_missing_docs": bool(assigned_docs.get("proceed_on_missing", True)),
        },
        "inputs": {
            "dev_docs": state.get("dev_docs", ""),
            "audit_docs": state.get("audit_docs", ""),
            "changed_files": state.get("changed_files", []),
        },
        "intermediate": {
            "architecture_packet": state.get("architecture_packet"),
            "adversarial_packet": state.get("adversarial_packet"),
            "clerk_packet": state.get("clerk_packet"),
            "decision_packet": state.get("decision_packet"),
            "testplan_routing_packet": state.get("testplan_routing_packet"),
            "script_routing_packet": state.get("script_routing_packet"),
            "testplan_packet": state.get("testplan_packet"),
            "script_packet": state.get("script_packet"),
        },
    }

    persona_id = str(persona.get("id", "")).strip()
    docs_only_mode = persona_id == "testplan_generator_glm5"
    routing_packet = state.get("testplan_routing_packet") if isinstance(state.get("testplan_routing_packet"), dict) else {}
    target_plan_path = str(routing_packet.get("target_testplan_path", "")).strip()
    if not target_plan_path and docs_only_mode:
        story_token = detect_current_story_id(state) or "sto000x"
        target_plan_path = f"docs/testplans/{story_token}_testplan.md"
    access_policy = (
        "파일 접근 정책: docs/testplans 디렉토리 내부만 조회/수정 가능. "
        "docs/testplans 외 경로는 조회/수정/생성/삭제를 시도하지 마라. "
        f"산출물은 반드시 {target_plan_path} 경로에 markdown으로 생성/갱신하라."
        if docs_only_mode
        else "파일 접근 정책: 현재 리포지토리 범위 내에서만 작업."
    )
    full_prompt = (
        "에이전트로서 다음 태스크를 수행하라. 계획->실행->검증 순서로 답하라.\n"
        + access_policy
        + "\n\n"
        + f"{system_prompt}\n\nReturn JSON only.\n\n"
        + json.dumps(human_payload, ensure_ascii=True, indent=2)
    )

    kilo_cfg = model_cfg.get("kilocode_cli", {})
    model_name = resolve_model_name(persona, model_cfg, str(kilo_cfg.get("model", "glm-5-free")))
    cmd = [str(kilo_cfg.get("command", "kilocode"))]
    subcommand = str(kilo_cfg.get("subcommand", "run")).strip()
    if subcommand:
        cmd.append(subcommand)
    if bool(kilo_cfg.get("auto", True)):
        cmd.append("--auto")
    fmt = str(kilo_cfg.get("format", "json")).strip()
    if fmt:
        cmd.extend(["--format", fmt])
    provider_env = str(kilo_cfg.get("provider_env", "KILO_PROVIDER")).strip()
    provider_value = str(kilo_cfg.get("provider_value", "kilo")).strip()
    model_env = str(kilo_cfg.get("model_env", "KILOCODE_MODEL")).strip()
    cli_model = model_name
    if "/" not in cli_model and provider_value:
        cli_model = f"{provider_value}/{cli_model}"
    cmd.extend(["--model", cli_model])

    timeout = kilo_cfg.get("timeout")
    timeout_flag = str(kilo_cfg.get("timeout_flag", "")).strip()
    if timeout is not None and timeout_flag:
        cmd.extend([timeout_flag, str(timeout)])

    run_cwd = str((ROOT / "docs" / "testplans").resolve()) if docs_only_mode else str(ROOT)

    import tempfile
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, dir=run_cwd) as tf:
        tf.write(full_prompt)
        prompt_file = tf.name

    extra_args = kilo_cfg.get("extra_args", [])
    if isinstance(extra_args, list):
        for arg in extra_args:
            cmd.append(str(arg))

    cmd.extend(["--file", prompt_file, "Please execute the instructions in the attached file."])

    env = os.environ.copy()
    if provider_env and provider_value:
        env[provider_env] = provider_value
    if model_env:
        env[model_env] = cli_model
    if docs_only_mode:
        docs_root = str((ROOT / "docs" / "testplans").resolve())
        env["KILOCODE_SANDBOX_PATH"] = docs_root
        env["KILOCODE_TOOL_WHITELIST"] = "read,write"

    try:
        popen = subprocess.Popen(
            cmd,
            cwd=run_cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        if docs_only_mode:
            _write_kilocode_pidfile(popen.pid, run_cwd, detect_current_story_id(state))
        stdout_raw, stderr_raw = popen.communicate()
        proc_returncode = int(popen.returncode or 0)
        try:
            os.remove(prompt_file)
        except Exception:
            pass
    except FileNotFoundError:
        return {
            "provider": "kilocode_cli",
            "error": "kilocode_not_found",
            "stderr": "kilocode command not found in PATH.",
            "cmd": cmd,
            "cwd": run_cwd,
        }
    finally:
        if docs_only_mode:
            _clear_kilocode_pidfile()

    if proc_returncode != 0:
        return {
            "provider": "kilocode_cli",
            "error": "kilocode_cli_failed",
            "returncode": proc_returncode,
            "stderr": (stderr_raw or "").strip(),
            "stdout": (stdout_raw or "").strip(),
            "cmd": cmd,
            "cwd": run_cwd,
        }

    stdout = (stdout_raw or "").strip()
    parsed = safe_json(stdout)
    if isinstance(parsed, dict) and not parsed.get("parse_error"):
        parsed["provider"] = "kilocode_cli"
        return parsed

    events: list[dict[str, Any]] = []
    assistant_parts: list[str] = []
    for line in stdout.splitlines():
        row = line.strip()
        if not row:
            continue
        event = safe_json(row)
        if isinstance(event, dict) and not event.get("parse_error"):
            events.append(event)
            role = str(event.get("role", "")).lower()
            content = event.get("content")
            if role == "assistant" and isinstance(content, str):
                assistant_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        assistant_parts.append(part["text"])
                    elif isinstance(part, str):
                        assistant_parts.append(part)
        elif row.startswith("{") and row.endswith("}"):
            assistant_parts.append(row)

    assistant_text = "\n".join(x for x in assistant_parts if x).strip()
    if events:
        return {
            "provider": "kilocode_cli",
            "assistant_text": assistant_text or stdout,
            "events": events,
            "raw_stdout": stdout,
            "cwd": run_cwd,
        }

    return {
        "provider": "kilocode_cli",
        "assistant_text": stdout,
        "raw_payload": parsed,
        "cwd": run_cwd,
    }


def node_fn(persona_id: str, packet_key: str, sidecar: QAHistorySidecar):
    def _run(state: QAState) -> QAState:
        run_id = str(state.get("run_id", ""))
        if run_id:
            sidecar.start_agent(
                run_id=run_id,
                agent_id=persona_id,
                packet_key=packet_key,
                input_payload={"changed_files": state.get("changed_files", [])},
            )

        if persona_id in ("testplan_generator_glm5", "test_scripter_codex"):
            decision = state.get("decision_packet") or {}
            guardrail = decision.get("guardrail_filter_result") if isinstance(decision, dict) else {}
            if isinstance(guardrail, dict) and guardrail.get("status") == "BLOCK":
                packet = {
                    "persona": persona_id,
                    "status": "blocked_by_guardrail",
                    "summary": "Skipped because decision guardrail status is BLOCK.",
                    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                }
                if run_id:
                    sidecar.finish_agent(
                        run_id=run_id,
                        agent_id=persona_id,
                        status="blocked",
                        output_payload=packet,
                    )
                return {
                    packet_key: packet
                }

        try:
            persona = load_persona(persona_id)
            assigned_docs = resolve_assigned_documents(persona, state)
            if persona_id == "decision_maker_gpt5x":
                state["decision_preflight"] = build_decision_preflight_context(state, sidecar)

            if persona_id == "clerk_routing_agent":
                packet = build_clerk_merge_packet(state, sidecar)
                packet["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
                packet["doc_assignment"] = {
                    "required": persona.get("required_documents", []),
                    "optional": persona.get("optional_documents", []),
                    "missing_required": assigned_docs.get("missing_required", []),
                    "missing_optional": assigned_docs.get("missing_optional", []),
                }
            elif persona_id == "testplan_routing_agent":
                testplan_packet = build_testplan_routing_packet(state, sidecar)
                script_packet = build_script_routing_packet(state, sidecar)
                generated_at_utc = datetime.now(timezone.utc).isoformat()
                shared_doc_assignment = {
                    "required": persona.get("required_documents", []),
                    "optional": persona.get("optional_documents", []),
                    "missing_required": assigned_docs.get("missing_required", []),
                    "missing_optional": assigned_docs.get("missing_optional", []),
                }
                testplan_packet["generated_at_utc"] = generated_at_utc
                testplan_packet["doc_assignment"] = shared_doc_assignment
                script_packet["generated_at_utc"] = generated_at_utc
                script_packet["doc_assignment"] = shared_doc_assignment

                packet = {
                    "provider": "routing_agent",
                    "status": "dispatch_ready",
                    "summary": "Assigned testplan generator first, then assigned test scripter without waiting for testplan completion.",
                    "dispatch_order": ["testplan_generator_glm5", "test_scripter_codex"],
                    "wait_for_testplan_completion": False,
                    "testplan_routing_packet": testplan_packet,
                    "script_routing_packet": script_packet,
                    "generated_at_utc": generated_at_utc,
                    "doc_assignment": shared_doc_assignment,
                }
            elif persona_id == "tester_routing_agent":
                packet = build_tester_execution_packet(
                    state=state,
                    sidecar=sidecar,
                    dry_run=bool(state.get("dry_run", False)),
                )
                packet["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
                packet["doc_assignment"] = {
                    "required": persona.get("required_documents", []),
                    "optional": persona.get("optional_documents", []),
                    "missing_required": assigned_docs.get("missing_required", []),
                    "missing_optional": assigned_docs.get("missing_optional", []),
                }
            elif state.get("dry_run", False):
                packet = {
                    "persona": persona.get("name", persona_id),
                    "packet": packet_key,
                    "status": "dry_run",
                    "summary": f"{persona_id} executed in dry-run mode.",
                    "doc_assignment": {
                        "required": persona.get("required_documents", []),
                        "optional": persona.get("optional_documents", []),
                        "missing_required": assigned_docs.get("missing_required", []),
                        "missing_optional": assigned_docs.get("missing_optional", []),
                    },
                    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                }
            else:
                model_cfg = load_yaml(QA_DIR / "configs" / "model_config.yaml")
                if "routing_agent" in persona.get("model_hint", "").lower():
                    security_findings = detect_kilocode_security_violations(state)
                    if security_findings:
                        packet = {
                            "provider": "routing_agent",
                            "status": "blocked_by_security_rule",
                            "summary": "Blocked due to suspicious Kilo Code behavior (privilege/sandbox policy).",
                            "security_findings": security_findings,
                        }
                    else:
                        packet = {
                            "provider": "routing_agent",
                            "status": "pending_manual_intervention",
                            "assistant_text": f"Routing Agent ({persona.get('name', persona_id)}) needs to handle this step based on intermediate packets.",
                        }
                elif should_use_codex_cli(persona, model_cfg):
                    packet = call_codex_cli(persona, state, model_cfg, assigned_docs)
                elif should_use_vibe_cli(persona, model_cfg):
                    packet = call_vibe_cli(persona, state, model_cfg, assigned_docs)
                elif should_use_kilocode_cli(persona, model_cfg):
                    packet = call_kilocode_cli(persona, state, model_cfg, assigned_docs)
                else:
                    api_key_env, _, api_key, _ = resolve_endpoint_config(model_cfg)
                    if not api_key:
                        raise RuntimeError(f"{api_key_env} is required for non-vibe graph execution")
                    packet = call_llm(persona, state, assigned_docs, model_cfg)
                packet["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
                packet["doc_assignment"] = {
                    "required": persona.get("required_documents", []),
                    "optional": persona.get("optional_documents", []),
                    "missing_required": assigned_docs.get("missing_required", []),
                    "missing_optional": assigned_docs.get("missing_optional", []),
                }

            if persona_id == "test_architect_mistral":
                packet["sqlite_report_store"] = persist_architecture_report(
                    sidecar=sidecar,
                    run_id=run_id,
                    packet=packet,
                )
            if persona_id == "test_scripter_codex":
                packet.setdefault("story_id", detect_current_story_id(state))
            if persona_id == "decision_maker_gpt5x":
                packet["decision_preflight"] = state.get("decision_preflight", {})

            if persona_id == "decision_maker_gpt5x":
                packet = enforce_decision_guardrails(packet)
                packet["sqlite_report_store"] = persist_decision_report(
                    sidecar=sidecar,
                    run_id=run_id,
                    packet=packet,
                )
            if persona_id == "test_scripter_codex":
                packet["sqlite_report_store"] = persist_script_report(
                    sidecar=sidecar,
                    run_id=run_id,
                    packet=packet,
                )
            if run_id:
                sidecar.finish_agent(
                    run_id=run_id,
                    agent_id=persona_id,
                    status=agent_status_from_packet(packet),
                    output_payload=packet,
                )
            if persona_id == "testplan_routing_agent":
                return {
                    packet_key: packet.get("testplan_routing_packet", {}),
                    "script_routing_packet": packet.get("script_routing_packet", {}),
                }
            if persona_id == "tester_routing_agent":
                return {
                    packet_key: packet,
                    "tester_gate_decision": packet.get("tester_gate_decision", {}),
                }
            return {packet_key: packet}
        except Exception as e:
            if run_id:
                sidecar.finish_agent(
                    run_id=run_id,
                    agent_id=persona_id,
                    status="failed",
                    output_payload={},
                    error_text=str(e),
                )
                sidecar.log_event(
                    run_id=run_id,
                    agent_id=persona_id,
                    event_type="agent_error",
                    status="failed",
                    message=str(e),
                )
            raise

    return _run


def build_graph(_: dict[str, Any], sidecar: QAHistorySidecar):
    try:
        from langgraph.graph import END, StateGraph
    except ModuleNotFoundError:
        return None

    graph = StateGraph(QAState)

    graph.add_node("test_architect_mistral", node_fn("test_architect_mistral", "architecture_packet", sidecar))
    graph.add_node("test_architect2_deepseek_r1", node_fn("test_architect2_deepseek_r1", "adversarial_packet", sidecar))
    graph.add_node("clerk_routing_agent", node_fn("clerk_routing_agent", "clerk_packet", sidecar))
    graph.add_node("decision_maker_gpt5x", node_fn("decision_maker_gpt5x", "decision_packet", sidecar))
    graph.add_node("testplan_routing_agent", node_fn("testplan_routing_agent", "testplan_routing_packet", sidecar))
    graph.add_node("testplan_generator_glm5", node_fn("testplan_generator_glm5", "testplan_packet", sidecar))
    graph.add_node("test_scripter_codex", node_fn("test_scripter_codex", "script_packet", sidecar))
    graph.add_node("tester_routing_agent", node_fn("tester_routing_agent", "execution_packet", sidecar))

    graph.set_entry_point("test_architect_mistral")

    graph.add_edge("test_architect_mistral", "test_architect2_deepseek_r1")
    graph.add_edge("test_architect2_deepseek_r1", "clerk_routing_agent")
    graph.add_edge("clerk_routing_agent", "decision_maker_gpt5x")
    graph.add_edge("decision_maker_gpt5x", "testplan_routing_agent")
    graph.add_edge("testplan_routing_agent", "testplan_generator_glm5")
    graph.add_edge("testplan_routing_agent", "test_scripter_codex")
    graph.add_edge("test_scripter_codex", "tester_routing_agent")
    graph.add_edge("tester_routing_agent", END)

    return graph.compile()


def run_fallback_graph(initial_state: QAState, sidecar: QAHistorySidecar) -> QAState:
    state: QAState = dict(initial_state)
    order = [
        ("test_architect_mistral", "architecture_packet"),
        ("test_architect2_deepseek_r1", "adversarial_packet"),
        ("clerk_routing_agent", "clerk_packet"),
        ("decision_maker_gpt5x", "decision_packet"),
        ("testplan_routing_agent", "testplan_routing_packet"),
        ("test_scripter_codex", "script_packet"),
        ("testplan_generator_glm5", "testplan_packet"),
        ("tester_routing_agent", "execution_packet"),
    ]
    for persona_id, packet_key in order:
        update = node_fn(persona_id, packet_key, sidecar)(state)
        state.update(update)
    return state


def main() -> None:
    args = parse_args()
    workflow = load_workflow(args.workflow)
    sidecar = load_history_sidecar()
    app = build_graph(workflow, sidecar)

    initial_state: QAState = {
        "run_id": datetime.now(timezone.utc).strftime("qa-%Y%m%d-%H%M%S"),
        "dry_run": args.dry_run,
        "workflow_id": workflow.get("id", args.workflow),
        "dev_docs": read_text(args.dev_docs),
        "audit_docs": read_text(args.audit_docs),
        "dev_docs_path": str(args.dev_docs),
        "audit_docs_path": str(args.audit_docs),
        "changed_files": args.changed_files,
    }

    run_id = str(initial_state["run_id"])
    sidecar.start_run(
        run_id=run_id,
        workflow_id=str(initial_state["workflow_id"]),
        dev_docs_path=str(initial_state["dev_docs_path"]),
        audit_docs_path=str(initial_state["audit_docs_path"]),
        changed_files=list(initial_state.get("changed_files", [])),
        meta={"dry_run": bool(args.dry_run)},
    )
    sidecar.log_event(
        run_id=run_id,
        event_type="run_started",
        status="running",
        message="QA graph run started.",
    )

    final_state: QAState = {}
    run_status = "running"
    run_error: str | None = None
    try:
        if app is None:
            final_state = run_fallback_graph(initial_state, sidecar)
        else:
            final_state = app.invoke(initial_state)
        run_status = "success"
    except Exception as e:
        run_status = "failed"
        run_error = str(e)
        sidecar.log_event(
            run_id=run_id,
            event_type="run_failed",
            status="failed",
            message=str(e),
        )

    result = {
        "meta": {
            "workflow": workflow.get("id", args.workflow),
            "description": workflow.get("description", ""),
            "dry_run": args.dry_run,
            "dev_docs_path": str(args.dev_docs),
            "audit_docs_path": str(args.audit_docs),
            "changed_files": args.changed_files,
            "doc_assignment_policy": "build_first_proceed_on_missing",
            "history_sidecar": {
                "enabled": sidecar.enabled,
                "db_path": str(sidecar.db_path),
            },
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "result": final_state,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True, indent=2))
    sidecar.log_event(
        run_id=run_id,
        event_type="run_completed",
        status=run_status,
        message="QA graph run completed.",
        payload={"output_path": str(args.out)},
    )
    sidecar.finish_run(
        run_id=run_id,
        status=run_status,
        meta={"dry_run": bool(args.dry_run), "output_path": str(args.out), "error": run_error},
    )
    if run_error:
        raise RuntimeError(run_error)


if __name__ == "__main__":
    main()
