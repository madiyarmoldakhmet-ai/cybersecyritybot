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

CREATE TABLE IF NOT EXISTS finding_appeals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT    NOT NULL,
    repo_name     TEXT    NOT NULL,
    finding_key   TEXT    NOT NULL,
    finding_title TEXT    NOT NULL,
    severity      TEXT    NOT NULL DEFAULT 'MEDIUM',
    status        TEXT    NOT NULL DEFAULT 'false_positive',
    reason        TEXT    NOT NULL DEFAULT '',
    reviewer      TEXT    NOT NULL DEFAULT 'security-engineer'
);
CREATE INDEX IF NOT EXISTS idx_appeals_repo ON finding_appeals (repo_name);
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
    appeals_count: int = 0
    recent: List[Dict[str, Any]] = field(default_factory=list)
    recent_appeals: List[Dict[str, Any]] = field(default_factory=list)

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
            "appeals_count": self.appeals_count,
            "recent": self.recent,
            "recent_appeals": self.recent_appeals,
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

    def record_appeal(
        self,
        repo_name: str,
        finding_key: str,
        finding_title: str,
        severity: str = "MEDIUM",
        status: str = "false_positive",
        reason: str = "",
        reviewer: str = "security-engineer",
    ) -> Dict[str, Any]:
        """Persist a human-in-the-loop false-positive or accepted-risk appeal."""
        created_at = self._now()
        clean_status = status if status in {"false_positive", "accepted_risk", "open"} else "false_positive"
        clean_sev = severity.upper()[:16] if severity else "MEDIUM"
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO finding_appeals
                       (created_at, repo_name, finding_key, finding_title, severity, status, reason, reviewer)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    created_at,
                    repo_name[:200],
                    finding_key[:200],
                    finding_title[:300],
                    clean_sev,
                    clean_status,
                    reason[:500],
                    reviewer[:100],
                ),
            )
            appeal_id = int(cur.lastrowid)
        return {
            "id": appeal_id,
            "created_at": created_at,
            "repo_name": repo_name[:200],
            "finding_key": finding_key[:200],
            "finding_title": finding_title[:300],
            "severity": clean_sev,
            "status": clean_status,
            "reason": reason[:500],
            "reviewer": reviewer[:100],
        }

    def list_appeals(self, repo_name: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if repo_name:
                rows = conn.execute(
                    """SELECT id, created_at, repo_name, finding_key, finding_title, severity, status, reason, reviewer
                       FROM finding_appeals WHERE repo_name = ? ORDER BY id DESC LIMIT ?""",
                    (repo_name, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id, created_at, repo_name, finding_key, finding_title, severity, status, reason, reviewer
                       FROM finding_appeals ORDER BY id DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def delete_appeal(self, appeal_id: int) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM finding_appeals WHERE id = ?", (int(appeal_id),))
            return cur.rowcount > 0

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
            appeals_count = conn.execute("SELECT COUNT(*) FROM finding_appeals").fetchone()[0]
            recent_appeals = conn.execute(
                """SELECT id, created_at, repo_name, finding_key, finding_title, severity, status, reason, reviewer
                   FROM finding_appeals ORDER BY id DESC LIMIT 10"""
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
            appeals_count=int(appeals_count),
            recent=[dict(r) for r in recent],
            recent_appeals=[dict(r) for r in recent_appeals],
        )


_store: Optional[MetricsStore] = None


def get_metrics_store() -> MetricsStore:
    """Return the process-wide store, reopening it if the configured path changed."""
    global _store
    if _store is None or _store.db_path != Path(settings.metrics_db_path):
        _store = MetricsStore(settings.metrics_db_path)
    return _store
