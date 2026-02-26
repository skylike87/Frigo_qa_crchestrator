PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS qa_runs (
  run_id TEXT PRIMARY KEY,
  workflow_id TEXT NOT NULL,
  started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  ended_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'running', 'success', 'failed', 'blocked', 'cancelled')),
  trigger_source TEXT NOT NULL DEFAULT 'manual',
  dev_docs_path TEXT,
  audit_docs_path TEXT,
  changed_files_json TEXT NOT NULL DEFAULT '[]',
  meta_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS qa_agents (
  agent_id TEXT PRIMARY KEY,
  agent_name TEXT NOT NULL,
  model_hint TEXT,
  role TEXT,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS qa_agent_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  packet_key TEXT,
  attempt INTEGER NOT NULL DEFAULT 1,
  started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  ended_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'running', 'success', 'failed', 'blocked', 'skipped', 'cancelled')),
  input_json TEXT NOT NULL DEFAULT '{}',
  output_json TEXT NOT NULL DEFAULT '{}',
  error_text TEXT,
  FOREIGN KEY (run_id) REFERENCES qa_runs (run_id) ON DELETE CASCADE,
  FOREIGN KEY (agent_id) REFERENCES qa_agents (agent_id) ON DELETE RESTRICT,
  UNIQUE (run_id, agent_id, attempt)
);

CREATE TABLE IF NOT EXISTS qa_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  agent_id TEXT,
  report_type TEXT NOT NULL,
  title TEXT,
  path TEXT NOT NULL,
  content_hash TEXT,
  content_text TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (run_id) REFERENCES qa_runs (run_id) ON DELETE CASCADE,
  FOREIGN KEY (agent_id) REFERENCES qa_agents (agent_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS qa_status_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  agent_id TEXT,
  event_type TEXT NOT NULL,
  status TEXT,
  message TEXT,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (run_id) REFERENCES qa_runs (run_id) ON DELETE CASCADE,
  FOREIGN KEY (agent_id) REFERENCES qa_agents (agent_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_qa_runs_status_started
  ON qa_runs (status, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_qa_agent_runs_run
  ON qa_agent_runs (run_id, id);

CREATE INDEX IF NOT EXISTS idx_qa_agent_runs_agent
  ON qa_agent_runs (agent_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_qa_reports_run
  ON qa_reports (run_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_qa_status_events_run
  ON qa_status_events (run_id, created_at DESC);

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
);

CREATE INDEX IF NOT EXISTS idx_final_test_run_story
  ON final_test (run_id, story_id, id DESC);

INSERT OR IGNORE INTO schema_migrations (version, name)
VALUES (1, 'init_qa_history_schema');

INSERT OR IGNORE INTO schema_migrations (version, name)
VALUES (2, 'add_final_test_table');
