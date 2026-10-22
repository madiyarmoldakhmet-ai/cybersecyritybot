"""
Persistent Audit Metrics for Commit Guardian.
Stores one row per webhook audit in a local SQLite database so the observability
dashboard survives restarts and needs no external database service.
"""

import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.core.config import settings

logger = logging.getLogger("aegis.metrics_store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       TEXT    NOT NULL,
    status           TEXT    NOT NULL,
    repo_name        TEXT    NOT NULL,
    commit_sha       TEXT    NOT NULL,
    branch           TEXT    NOT NULL DEFAULT '',
    total_findings   INTEGER NOT NULL DEFAULT 0,
    critical         INTEGER NOT NULL DEFAULT 0,
    high             INTEGER NOT NULL DEFAULT 0,
    medium           INTEGER NOT NULL DEFAULT 0,
    low              INTEGER NOT NULL DEFAULT 0,
    scan_seconds     REAL    NOT NULL DEFAULT 0,
    ai_seconds       REAL    NOT NULL DEFAULT 0,
    ai_generated     INTEGER NOT NULL DEFAULT 0,
    report_name      TEXT,
    error            TEXT
);
CREATE INDEX IF NOT EXISTS idx_audits_created_at ON audits (created_at);
"""


@dataclass
class DashboardMetrics:
    total_scans: int = 0
    failed_scans: int = 0
    critical_found: int = 0
    high_found: int = 0
    total_findings: int = 0
    repos_monitored: int = 0
    avg_ai_seconds: Optional[float] = None
    avg_scan_seconds: Optional[float] = None
    recent: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_scans": self.total_scans,
            "failed_scans": self.failed_scans,
            "critical_found": self.critical_found,
            "high_found": self.high_found,
            "total_findings": self.total_findings,
            "repos_monitored": self.repos_monitored,
            "avg_ai_seconds": self.avg_ai_seconds,
            "avg_scan_seconds": self.avg_scan_seconds,
            "recent": self.recent,
        }


class MetricsStore:
    """Thread-safe SQLite store for audit outcomes."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def record_audit(
        self,
        repo_name: str,
        commit_sha: str,
        branch: str,
        severity_counts: Dict[str, int],
        total_findings: int,
        scan_seconds: float,
        ai_seconds: float,
        ai_generated: bool,
        report_name: Optional[str] = None,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO audits (created_at, status, repo_name, commit_sha, branch, total_findings,
                                       critical, high, medium, low, scan_seconds, ai_seconds, ai_generated, report_name)
                   VALUES (?, 'completed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    self._now(), repo_name, commit_sha, branch, total_findings,
                    severity_counts.get("CRITICAL", 0), severity_counts.get("HIGH", 0),
                    severity_counts.get("MEDIUM", 0), severity_counts.get("LOW", 0),
                    float(scan_seconds), float(ai_seconds), int(ai_generated), report_name,
                ),
            )

    def record_failure(self, repo_name: str, commit_sha: str, branch: str, error: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO audits (created_at, status, repo_name, commit_sha, branch, error)
                   VALUES (?, 'failed', ?, ?, ?, ?)""",
                (self._now(), repo_name, commit_sha, branch, error[:500]),
            )

    def summary(self, recent_limit: int = 10) -> DashboardMetrics:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """SELECT
                       COUNT(*) FILTER (WHERE status = 'completed')                       AS total_scans,
                       COUNT(*) FILTER (WHERE status = 'failed')                          AS failed_scans,
                       COALESCE(SUM(critical), 0)                                         AS critical_found,
                       COALESCE(SUM(high), 0)                                             AS high_found,
                       COALESCE(SUM(total_findings), 0)                                   AS total_findings,
                       COUNT(DISTINCT repo_name)                                          AS repos_monitored,
                       AVG(ai_seconds)   FILTER (WHERE status = 'completed' AND ai_generated = 1) AS avg_ai_seconds,
                       AVG(scan_seconds) FILTER (WHERE status = 'completed')              AS avg_scan_seconds
                   FROM audits"""
            ).fetchone()
            recent = conn.execute(
                """SELECT created_at, status, repo_name, commit_sha, branch, total_findings, critical, high,
                          medium, low, ai_seconds, ai_generated, report_name
                   FROM audits ORDER BY id DESC LIMIT ?""",
                (recent_limit,),
            ).fetchall()

        def rounded(value: Optional[float]) -> Optional[float]:
            return round(value, 2) if value is not None else None

        return DashboardMetrics(
            total_scans=row["total_scans"],
            failed_scans=row["failed_scans"],
            critical_found=row["critical_found"],
            high_found=row["high_found"],
            total_findings=row["total_findings"],
            repos_monitored=row["repos_monitored"],
            avg_ai_seconds=rounded(row["avg_ai_seconds"]),
            avg_scan_seconds=rounded(row["avg_scan_seconds"]),
            recent=[dict(r) for r in recent],
        )


_store: Optional[MetricsStore] = None


def get_metrics_store() -> MetricsStore:
    """Return the process-wide store, reopening it if the configured path changed."""
    global _store
    if _store is None or _store.db_path != Path(settings.metrics_db_path):
        _store = MetricsStore(settings.metrics_db_path)
    return _store
