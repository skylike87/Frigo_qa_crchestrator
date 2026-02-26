#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
from hashlib import sha256
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False)


@dataclass
class HistorySidecarConfig:
    enabled: bool
    db_path: Path


class QAHistorySidecar:
    def __init__(self, cfg: HistorySidecarConfig):
        self._cfg = cfg

    @property
    def enabled(self) -> bool:
        return self._cfg.enabled

    @property
    def db_path(self) -> Path:
        return self._cfg.db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._cfg.db_path))
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def start_run(
        self,
        *,
        run_id: str,
        workflow_id: str,
        dev_docs_path: str,
        audit_docs_path: str,
        changed_files: list[str],
        trigger_source: str = "manual",
        meta: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO qa_runs (
                  run_id, workflow_id, started_at, ended_at, status,
                  trigger_source, dev_docs_path, audit_docs_path,
                  changed_files_json, meta_json
                ) VALUES (
                  ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'running',
                  ?, ?, ?, ?, ?
                )
                """,
                (
                    run_id,
                    workflow_id,
                    trigger_source,
                    dev_docs_path,
                    audit_docs_path,
                    _json_dumps(changed_files),
                    _json_dumps(meta or {}),
                ),
            )
            conn.commit()

    def finish_run(self, *, run_id: str, status: str, meta: dict[str, Any] | None = None) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE qa_runs
                SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    status = ?,
                    meta_json = ?
                WHERE run_id = ?
                """,
                (status, _json_dumps(meta or {}), run_id),
            )
            conn.commit()

    def start_agent(
        self,
        *,
        run_id: str,
        agent_id: str,
        packet_key: str,
        input_payload: dict[str, Any] | None = None,
        attempt: int = 1,
    ) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO qa_agent_runs (
                  run_id, agent_id, packet_key, attempt, started_at, status, input_json
                ) VALUES (
                  ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'running', ?
                )
                ON CONFLICT(run_id, agent_id, attempt) DO UPDATE SET
                  packet_key = excluded.packet_key,
                  started_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                  ended_at = NULL,
                  status = 'running',
                  input_json = excluded.input_json,
                  output_json = '{}',
                  error_text = NULL
                """,
                (run_id, agent_id, packet_key, attempt, _json_dumps(input_payload or {})),
            )
            conn.commit()

    def finish_agent(
        self,
        *,
        run_id: str,
        agent_id: str,
        status: str,
        output_payload: dict[str, Any] | None = None,
        error_text: str | None = None,
        attempt: int = 1,
    ) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE qa_agent_runs
                SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    status = ?,
                    output_json = ?,
                    error_text = ?
                WHERE run_id = ? AND agent_id = ? AND attempt = ?
                """,
                (status, _json_dumps(output_payload or {}), error_text, run_id, agent_id, attempt),
            )
            conn.commit()

    def log_event(
        self,
        *,
        run_id: str,
        event_type: str,
        status: str | None = None,
        message: str | None = None,
        payload: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO qa_status_events (
                  run_id, agent_id, event_type, status, message, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (run_id, agent_id, event_type, status, message, _json_dumps(payload or {})),
            )
            conn.commit()

    def save_report(
        self,
        *,
        run_id: str,
        agent_id: str | None,
        report_type: str,
        title: str | None,
        path: str,
        content_text: str,
    ) -> int | None:
        if not self.enabled:
            return None
        content_hash = sha256(content_text.encode("utf-8")).hexdigest()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO qa_reports (
                  run_id, agent_id, report_type, title, path, content_hash, content_text
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, agent_id, report_type, title, path, content_hash, content_text),
            )
            conn.commit()
            row_id = cur.lastrowid
        return int(row_id) if row_id is not None else None

    def get_latest_report(
        self,
        *,
        run_id: str,
        report_type: str,
    ) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, run_id, agent_id, report_type, title, path, content_hash, content_text, created_at
                FROM qa_reports
                WHERE run_id = ? AND report_type = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (run_id, report_type),
            ).fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "run_id": row[1],
            "agent_id": row[2],
            "report_type": row[3],
            "title": row[4],
            "path": row[5],
            "content_hash": row[6],
            "content_text": row[7],
            "created_at": row[8],
        }

    def get_latest_report_by_story(
        self,
        *,
        run_id: str,
        report_type: str,
        story_id: str,
    ) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        story = story_id.strip().lower()
        if not story:
            return self.get_latest_report(run_id=run_id, report_type=report_type)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, run_id, agent_id, report_type, title, path, content_hash, content_text, created_at
                FROM qa_reports
                WHERE run_id = ? AND report_type = ? AND path LIKE ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (run_id, report_type, f"%story_id={story}%"),
            ).fetchone()
        if not row:
            return self.get_latest_report(run_id=run_id, report_type=report_type)
        return {
            "id": row[0],
            "run_id": row[1],
            "agent_id": row[2],
            "report_type": row[3],
            "title": row[4],
            "path": row[5],
            "content_hash": row[6],
            "content_text": row[7],
            "created_at": row[8],
        }

    def ensure_final_test_table(self) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS final_test (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  run_id TEXT NOT NULL,
                  story_id TEXT NOT NULL,
                  agent_id TEXT NOT NULL DEFAULT 'tester_routing_agent',
                  script_report_id INTEGER,
                  script_report_path TEXT,
                  executed_from TEXT,
                  script_glob TEXT,
                  command_json TEXT NOT NULL DEFAULT '[]',
                  result_status TEXT NOT NULL
                    CHECK (result_status IN ('pending', 'dry_run', 'passed', 'failed', 'error', 'blocked', 'skipped')),
                  pass_count INTEGER NOT NULL DEFAULT 0,
                  fail_count INTEGER NOT NULL DEFAULT 0,
                  error_log TEXT,
                  result_json TEXT NOT NULL DEFAULT '{}',
                  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                  FOREIGN KEY (run_id) REFERENCES qa_runs (run_id) ON DELETE CASCADE,
                  FOREIGN KEY (script_report_id) REFERENCES qa_reports (id) ON DELETE SET NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_final_test_run_story
                ON final_test (run_id, story_id, id DESC)
                """
            )
            conn.commit()

    def save_final_test_record(
        self,
        *,
        run_id: str,
        story_id: str,
        script_report_id: int | None,
        script_report_path: str | None,
        executed_from: str,
        script_glob: str,
        commands: list[str],
        result_status: str,
        pass_count: int,
        fail_count: int,
        error_log: str,
        result_payload: dict[str, Any] | None,
    ) -> int | None:
        if not self.enabled:
            return None
        self.ensure_final_test_table()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO final_test (
                  run_id, story_id, agent_id, script_report_id, script_report_path,
                  executed_from, script_glob, command_json, result_status,
                  pass_count, fail_count, error_log, result_json
                ) VALUES (?, ?, 'tester_routing_agent', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    story_id,
                    script_report_id,
                    script_report_path,
                    executed_from,
                    script_glob,
                    _json_dumps(commands),
                    result_status,
                    int(pass_count),
                    int(fail_count),
                    error_log,
                    _json_dumps(result_payload or {}),
                ),
            )
            conn.commit()
            row_id = cur.lastrowid
        return int(row_id) if row_id is not None else None
