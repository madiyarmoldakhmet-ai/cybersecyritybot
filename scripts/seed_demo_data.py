"""
Idempotent Demo Seeder for Commit Guardian Observability Dashboard.
Populates clearly labeled `demo/*` Kazakhstan sector audits and one sample
Human-in-the-Loop false-positive appeal when the local SQLite database is empty,
so fresh deployments and stage demos never show an empty screen.
"""

import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis.core.config import settings
from aegis.core.metrics_store import MetricsStore

DEMO_AUDITS = [
    {
        "repo_name": "demo/kz-fintech-app",
        "commit_sha": "c4f9a21e88b0",
        "branch": "main",
        "severity_counts": {"CRITICAL": 6, "HIGH": 5, "MEDIUM": 5, "LOW": 1},
        "total_findings": 17,
        "scan_seconds": 4.4,
        "ai_seconds": 3.8,
        "ai_generated": True,
    },
    {
        "repo_name": "demo/egov-gateway-kz",
        "commit_sha": "8d12e04f31aa",
        "branch": "release/2.4",
        "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 1},
        "total_findings": 4,
        "scan_seconds": 3.1,
        "ai_seconds": 2.9,
        "ai_generated": True,
    },
    {
        "repo_name": "demo/medtech-clinic-api",
        "commit_sha": "5a90b77c2d11",
        "branch": "feat/iin-masking",
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "total_findings": 0,
        "scan_seconds": 2.3,
        "ai_seconds": 0.0,
        "ai_generated": False,
    },
]


def seed_demo_database(db_path: Optional[Path] = None, force: bool = False) -> int:
    """Populate demo rows if the database is empty (or force=True). Returns inserted audit count."""
    store = MetricsStore(Path(db_path) if db_path else Path(settings.metrics_db_path))
    summary = store.summary()
    if summary.total_scans > 0 and not force:
        return 0

    for item in DEMO_AUDITS:
        store.record_audit(
            repo_name=item["repo_name"],
            commit_sha=item["commit_sha"],
            branch=item["branch"],
            severity_counts=item["severity_counts"],
            total_findings=item["total_findings"],
            scan_seconds=item["scan_seconds"],
            ai_seconds=item["ai_seconds"],
            ai_generated=item["ai_generated"],
            report_name=None,
        )

    if store.summary().appeals_count == 0:
        store.record_appeal(
            repo_name="demo/egov-gateway-kz",
            finding_key="bandit.B108::export_job.py::19",
            finding_title="Temp directory inside isolated container volume",
            severity="MEDIUM",
            status="false_positive",
            reason="Подтверждено AppSec: каталог смонтирован как tmpfs с правами 0700.",
            reviewer="appsec-lead",
        )
    return len(DEMO_AUDITS)


if __name__ == "__main__":
    inserted = seed_demo_database()
    if inserted:
        print(f"Seeded {inserted} demo KZ audits into {settings.metrics_db_path}")
    else:
        print(f"Database already has audit records ({settings.metrics_db_path}); skipping seed.")
