"""
Knowledge Base
==============
SQLite-backed store for all facts discovered during a recon run, plus
a record of which modules have already executed against which hosts
(for resumability / idempotency).

Every fact stored follows this envelope:

    {
        "type": "port | technology | credential | finding | directory | ...",
        "host": "10.0.0.5",
        "source_tool": "whatweb",
        "timestamp": "2026-08-01T12:00:00Z",
        "data": { ... tool-specific payload ... }
    }

`data` is stored as a JSON blob so any tool can emit whatever shape of
payload makes sense for that fact type, without a schema migration.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS facts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,
    host        TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    data        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_facts_host_type ON facts(host, type);

CREATE TABLE IF NOT EXISTS modules_run (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT NOT NULL,
    module      TEXT NOT NULL,
    status      TEXT NOT NULL,   -- running | success | failed
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE(host, module)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class KnowledgeBase:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Facts
    # ------------------------------------------------------------------

    def add_fact(
        self,
        fact_type: str,
        host: str,
        source_tool: str,
        data: dict[str, Any],
        timestamp: Optional[str] = None,
    ) -> int:
        """Insert a single fact. Returns the new row id."""
        ts = timestamp or _now()
        cur = self._conn.execute(
            "INSERT INTO facts (type, host, source_tool, timestamp, data) "
            "VALUES (?, ?, ?, ?, ?)",
            (fact_type, host, source_tool, ts, json.dumps(data)),
        )
        self._conn.commit()
        return cur.lastrowid

    def add_facts(self, facts: list[dict[str, Any]]) -> None:
        """
        Bulk insert. Each dict must have keys: type, host, source_tool, data
        (timestamp optional).
        """
        for f in facts:
            self.add_fact(
                fact_type=f["type"],
                host=f["host"],
                source_tool=f["source_tool"],
                data=f["data"],
                timestamp=f.get("timestamp"),
            )

    def get_facts(
        self,
        host: Optional[str] = None,
        fact_type: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Query facts, optionally filtered by host and/or type."""
        query = "SELECT * FROM facts WHERE 1=1"
        params: list[Any] = []
        if host is not None:
            query += " AND host = ?"
            params.append(host)
        if fact_type is not None:
            query += " AND type = ?"
            params.append(fact_type)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_fact(r) for r in rows]

    def get_all_facts(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM facts").fetchall()
        return [self._row_to_fact(r) for r in rows]

    @staticmethod
    def _row_to_fact(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "type": row["type"],
            "host": row["host"],
            "source_tool": row["source_tool"],
            "timestamp": row["timestamp"],
            "data": json.loads(row["data"]),
        }

    # ------------------------------------------------------------------
    # Module run tracking (idempotency / resumability)
    # ------------------------------------------------------------------

    def has_run(self, host: str, module: str) -> bool:
        row = self._conn.execute(
            "SELECT status FROM modules_run WHERE host = ? AND module = ?",
            (host, module),
        ).fetchone()
        return row is not None and row["status"] == "success"

    def mark_running(self, host: str, module: str) -> None:
        self._conn.execute(
            "INSERT INTO modules_run (host, module, status, started_at) "
            "VALUES (?, ?, 'running', ?) "
            "ON CONFLICT(host, module) DO UPDATE SET "
            "status='running', started_at=excluded.started_at, finished_at=NULL",
            (host, module, _now()),
        )
        self._conn.commit()

    def mark_finished(self, host: str, module: str, success: bool) -> None:
        self._conn.execute(
            "UPDATE modules_run SET status = ?, finished_at = ? "
            "WHERE host = ? AND module = ?",
            ("success" if success else "failed", _now(), host, module),
        )
        self._conn.commit()

    def module_status(self, host: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM modules_run WHERE host = ?", (host,)
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "KnowledgeBase":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
