#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
QA_DIR = ROOT / ".qa"
DEFAULT_DB_PATH = QA_DIR / "db" / "qa_history.db"
SCHEMA_PATH = QA_DIR / "db" / "schema.sql"
PERSONAS_DIR = QA_DIR / "personas"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Initialize QA history sqlite database")
    p.add_argument("--db-path", default=str(DEFAULT_DB_PATH), help="Target sqlite file path")
    return p.parse_args()


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def apply_schema(conn: sqlite3.Connection, schema_path: Path) -> None:
    sql = schema_path.read_text(encoding="utf-8")
    conn.executescript(sql)


def seed_agents(conn: sqlite3.Connection) -> int:
    count = 0
    for persona_file in sorted(PERSONAS_DIR.glob("*.yaml")):
        persona = load_yaml(persona_file)
        agent_id = str(persona.get("id", "")).strip()
        if not agent_id:
            continue
        agent_name = str(persona.get("name", agent_id)).strip() or agent_id
        model_hint = str(persona.get("model_hint", "")).strip()
        role = str(persona.get("role", "")).strip()

        conn.execute(
            """
            INSERT INTO qa_agents (agent_id, agent_name, model_hint, role, is_active)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(agent_id) DO UPDATE SET
              agent_name = excluded.agent_name,
              model_hint = excluded.model_hint,
              role = excluded.role,
              is_active = 1,
              updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            """,
            (agent_id, agent_name, model_hint, role),
        )
        count += 1
    return count


def main() -> None:
    args = parse_args()
    db_path = Path(args.db_path)
    if not db_path.is_absolute():
        db_path = (ROOT / db_path).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        apply_schema(conn, SCHEMA_PATH)
        seeded = seed_agents(conn)
        conn.commit()
        table_count = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'qa_%'"
        ).fetchone()[0]

    print(f"Initialized: {db_path}")
    print(f"QA tables: {table_count}")
    print(f"Seeded agents: {seeded}")


if __name__ == "__main__":
    main()
