"""
SQLite 持久化 — 历史记录存储、趋势分析和 diff 对比
"""
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional


def _default_db_path() -> str:
    return os.path.join(os.getcwd(), ".ai-redteam", "history.db")


def _ensure_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT UNIQUE NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            model TEXT NOT NULL,
            preset TEXT NOT NULL,
            total_probes INTEGER DEFAULT 0,
            passed INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0,
            score REAL DEFAULT 0.0,
            status TEXT DEFAULT 'running'
        );
        CREATE TABLE IF NOT EXISTS probe_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            probe_id TEXT NOT NULL,
            category TEXT NOT NULL,
            vector TEXT NOT NULL,
            severity TEXT NOT NULL,
            template TEXT,
            payload TEXT,
            response TEXT,
            score REAL DEFAULT 0.0,
            passed INTEGER DEFAULT 0,
            error TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs(run_id)
        );
        CREATE INDEX IF NOT EXISTS idx_probe_results_run ON probe_results(run_id);
        CREATE INDEX IF NOT EXISTS idx_probe_results_cat ON probe_results(category);
        CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at DESC);
    """)
    conn.commit()
    return conn


class HistoryStorage:
    """SQLite 持久化存储"""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or _default_db_path()
        self.conn = _ensure_db(self.db_path)

    def start_run(self, run_id: str, model: str, preset: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO runs (run_id, started_at, model, preset, status) VALUES (?, ?, ?, ?, 'running')",
            (run_id, now, model, preset),
        )
        self.conn.commit()

    def end_run(self, run_id: str, total: int, passed: int, failed: int, score: float) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "UPDATE runs SET finished_at=?, total_probes=?, passed=?, failed=?, score=?, status='completed' WHERE run_id=?",
            (now, total, passed, failed, score, run_id),
        )
        self.conn.commit()

    def save_probe_result(self, run_id: str, result: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO probe_results (run_id, probe_id, category, vector, severity, template, payload, response, score, passed, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                result.get("probe_id", ""),
                result.get("category", ""),
                result.get("vector", ""),
                result.get("severity", ""),
                result.get("template", ""),
                result.get("payload", ""),
                result.get("response", ""),
                result.get("score", 0.0),
                1 if result.get("passed", False) else 0,
                result.get("error"),
                now,
            ),
        )
        self.conn.commit()

    def get_history(self, limit: int = 20) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_run_probes(self, run_id: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM probe_results WHERE run_id=? ORDER BY created_at", (run_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def diff_runs(self, run_id_a: str, run_id_b: str) -> dict:
        a = {r["probe_id"]: r for r in self.get_run_probes(run_id_a)}
        b = {r["probe_id"]: r for r in self.get_run_probes(run_id_b)}

        all_ids = set(a.keys()) | set(b.keys())
        added = []
        removed = []
        changed = []
        unchanged = 0

        for pid in all_ids:
            if pid not in a and pid in b:
                added.append(b[pid])
            elif pid in a and pid not in b:
                removed.append(a[pid])
            elif a[pid]["passed"] != b[pid]["passed"]:
                changed.append({"probe_id": pid, "before": a[pid], "after": b[pid]})
            else:
                unchanged += 1

        return {
            "run_a": run_id_a,
            "run_b": run_id_b,
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": unchanged,
            "details": {"added": added, "removed": removed, "changed": changed},
        }

    def get_trend(self, days: int = 30, category: Optional[str] = None) -> List[dict]:
        query = """
            SELECT r.run_id, r.started_at, r.model, r.total_probes, r.passed, r.failed, r.score
            FROM runs r WHERE r.status='completed'
            AND r.started_at >= datetime('now', ? || ' days')
            ORDER BY r.started_at ASC
        """
        rows = self.conn.execute(query, (str(-days),)).fetchall()
        trend = []
        for row in rows:
            entry = dict(row)
            if category:
                probes = self.get_run_probes(row["run_id"])
                entry["category_passed"] = sum(1 for p in probes if p["category"] == category and p["passed"])
                entry["category_total"] = sum(1 for p in probes if p["category"] == category)
            trend.append(entry)
        return trend

    def close(self) -> None:
        self.conn.close()


# 单例
_storage: Optional[HistoryStorage] = None


def get_storage(db_path: Optional[str] = None) -> HistoryStorage:
    global _storage
    if _storage is None:
        _storage = HistoryStorage(db_path)
    return _storage
