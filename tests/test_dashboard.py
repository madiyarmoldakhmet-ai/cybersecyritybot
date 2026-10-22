"""
Unit tests for Commit Guardian observability: SQLite metrics store and the /dashboard page.
"""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core.config import settings
from aegis.core.metrics_store import MetricsStore, get_metrics_store


@pytest.fixture
def store(tmp_path, monkeypatch) -> MetricsStore:
    monkeypatch.setattr(settings, "metrics_db_path", tmp_path / "metrics.db")
    return get_metrics_store()


def record(store: MetricsStore, repo: str, critical: int = 0, high: int = 0, ai: float = 0.0, ai_generated: bool = True):
    store.record_audit(
        repo_name=repo, commit_sha="a1f9c3e0b2d4", branch="main",
        severity_counts={"CRITICAL": critical, "HIGH": high, "MEDIUM": 1},
        total_findings=critical + high + 1, scan_seconds=3.0, ai_seconds=ai,
        ai_generated=ai_generated, report_name="report.pdf",
    )


def test_metrics_aggregation(store):
    record(store, "gov/portal", critical=2, high=1, ai=4.0)
    record(store, "gov/portal", critical=1, ai=6.0)
    record(store, "gov/tax", ai=0.0, ai_generated=False)  # Ollama offline: excluded from the AI average
    store.record_failure("gov/tax", "deadbeef", "main", "git clone failed")

    m = store.summary()
    assert m.total_scans == 3
    assert m.failed_scans == 1
    assert m.critical_found == 3
    assert m.high_found == 1
    assert m.repos_monitored == 2
    assert m.avg_ai_seconds == 5.0
    assert m.avg_scan_seconds == 3.0
    assert m.recent[0]["status"] == "failed"


def test_metrics_persist_across_restarts(tmp_path):
    db = tmp_path / "metrics.db"
    record(MetricsStore(db), "gov/portal", critical=1, ai=2.0)
    assert MetricsStore(db).summary().total_scans == 1


def test_empty_store_has_no_ai_average(store):
    m = store.summary()
    assert m.total_scans == 0
    assert m.avg_ai_seconds is None


@pytest.mark.asyncio
async def test_dashboard_page_and_json(store):
    from web.api import app

    record(store, "gov/portal", critical=2, high=1, ai=4.25)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        page = await client.get("/dashboard")
        data = await client.get("/api/v1/dashboard/metrics")

    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    assert "script-src 'nonce-" in page.headers["content-security-policy"]
    body = page.text
    assert 'id="total_scans">1<' in body
    assert 'id="critical_found">2<' in body
    assert "4.2 с" in body
    # Air-gapped: the page must not pull anything from the internet
    assert "https://" not in body and "http://" not in body

    assert data.status_code == 200
    payload = data.json()
    assert payload["total_scans"] == 1
    assert payload["critical_found"] == 2
    assert payload["avg_ai_seconds"] == 4.25
    assert payload["llm_mode"].startswith("Ollama")


@pytest.mark.asyncio
async def test_dashboard_escapes_untrusted_repo_names(store):
    from web.api import app

    record(store, '<script>alert("x")</script>/repo')

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        page = await client.get("/dashboard")

    assert '<script>alert("x")</script>' not in page.text
    assert "&lt;script&gt;" in page.text


@pytest.mark.asyncio
async def test_production_server_exposes_webhook_and_dashboard(store):
    # The Docker image runs aegis_server.main, so the webhook must be reachable there too
    from aegis_server.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        ping = await client.post("/api/v1/webhook/github", headers={"X-GitHub-Event": "ping"}, json={"zen": "ok"})
        page = await client.get("/dashboard")
        data = await client.get("/api/v1/dashboard/metrics")

    assert ping.status_code in (200, 202) and ping.json()["status"] == "ok"
    assert page.status_code == 200 and "Мониторинг безопасности" in page.text
    assert data.status_code == 200 and data.json()["total_scans"] == 0
