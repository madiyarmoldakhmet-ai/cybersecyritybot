"""
Adversarial & Worst-Case Jury Stress Test Suite for Commit Guardian.
Tests edge cases that routinely break hackathon/competition demos:
- non-UTF8 / binary files & empty directories
- Zip Slip path traversal uploads
- huge single-line minified blobs
- concurrent demo scans, chat requests, and ROI calculations
- LLM broken Python syntax rejected by deterministic ast.parse() post-validation
- Human-in-the-Loop FP appeal lifecycle, score recalculation & XSS escaping on /dashboard
- ALLOW_CLOUD_LLM=false stripping adversarial cloud API keys
- SecretScanner working reliably inside temp_scans/
- Idempotent demo database seeding
"""

import asyncio
import io
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from aegis.ai.remediation_engine import RemediationEngine
from aegis.core.config import Settings, settings
from aegis.core.metrics_store import MetricsStore, get_metrics_store
from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.risk_model import assess_risk, estimate_roi
from aegis.scanners.sast_scanner import SASTScanner
from aegis.scanners.secret_scanner import SecretScanner
from aegis.scanners.security_score import calculate_score, get_grade
from scripts.seed_demo_data import seed_demo_database


@pytest.mark.asyncio
async def test_corrupt_binary_and_empty_repo_resilience(tmp_path: Path):
    empty_dir = tmp_path / "empty_repo"
    empty_dir.mkdir()
    empty_res = await SASTScanner().scan(empty_dir)
    assert empty_res.total_findings == 0
    assert calculate_score(empty_res.findings) == 100
    assert get_grade(100)[0] == "A+"
    assert assess_risk(empty_res.findings).total_kzt == 0

    corrupt_dir = tmp_path / "corrupt_repo"
    corrupt_dir.mkdir()
    (corrupt_dir / "broken.py").write_bytes(b"\xff\xfe\x00\x00not valid utf8 \x80\x90def broken(:\n")
    (corrupt_dir / "minified.js").write_text("var a=1;" * 25000, encoding="utf-8")
    res = await SASTScanner().scan(corrupt_dir)
    assert res is not None
    assert isinstance(res.total_findings, int)


@pytest.mark.asyncio
async def test_zip_slip_upload_is_blocked():
    from aegis_server.main import app

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../escaped_evil.py", "print('pwned')\n")
    buf.seek(0)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/api/scan/upload",
            files={"file": ("evil.zip", buf.getvalue(), "application/zip")},
        )
    assert resp.status_code == 400
    assert "error" in resp.json()


@pytest.mark.asyncio
async def test_secret_scanner_detects_secrets_inside_temp_scans_path(tmp_path: Path):
    nested = tmp_path / "temp_scans" / "web_scans" / "demo_123" / "app"
    nested.mkdir(parents=True)
    # Build synthetic Stripe-like token at runtime (avoid placeholder substrings like abcdef)
    synth = "sk_live_" + "9xKmNpQrStUvWxYz23456789AB"
    (nested / "config.py").write_text(f'STRIPE_KEY = "{synth}"\n', encoding="utf-8")

    findings = await SecretScanner().scan(nested)
    assert len(findings) == 1
    assert "Stripe" in findings[0].title
    assert synth not in (findings[0].code_snippet or "")


@pytest.mark.asyncio
async def test_llm_broken_python_patch_is_rejected_by_ast_parse():
    finding = VulnerabilityFinding(
        id="sql-test",
        scanner=ScannerType.CUSTOM,
        title="SQL Injection in wallet lookup",
        description="Dynamic SQL query",
        severity=Severity.CRITICAL,
        file_path="wallet.py",
        line_start=12,
        cwe=["CWE-89"],
        code_snippet='cursor.execute(f"SELECT * FROM wallets WHERE iin = {iin}")',
    )
    broken_llm_json = (
        '{"explanation_ru": "SQLi", "impact_analysis": "Leak", '
        '"remediation_steps": ["Use params"], '
        '"fixed_code": "def broken_syntax(::: ???", "confidence_score": 0.99}'
    )
    engine = RemediationEngine()
    with patch.object(engine, "_query_ollama", new=AsyncMock(return_value=broken_llm_json)):
        result = await engine.analyze_and_remediate(finding)

    assert result.syntax_validated is True
    assert "ast.parse()" in (result.validation_note or "")
    assert "cursor.execute" in result.fixed_code
    assert "def broken_syntax" not in result.fixed_code


@pytest.mark.asyncio
async def test_appeal_lifecycle_score_recalc_and_xss_escaping(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(settings, "metrics_db_path", tmp_path / "appeals.db")
    get_metrics_store()

    from aegis_server.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        create_resp = await client.post(
            "/api/v1/findings/appeal",
            json={
                "repo_name": '<script>alert("xss")</script>/kz-bank',
                "finding_key": "rule-1::app.py::10",
                "finding_title": "<b>Possible FP</b>",
                "severity": "CRITICAL",
                "status": "false_positive",
                "reason": '<img src=x onerror="alert(1)"> Verified safe',
                "reviewer": "qa-reviewer",
                "remaining_severities": ["HIGH", "MEDIUM"],
            },
        )
        assert create_resp.status_code == 200
        body = create_resp.json()
        assert body["status"] == "recorded"
        # 100 - 10 (HIGH) - 3 (MEDIUM) = 87 -> Grade A
        assert body["adjusted_score"] == 87
        assert body["adjusted_grade"] == "A"
        appeal_id = body["appeal"]["id"]

        list_resp = await client.get("/api/v1/findings/appeals")
        assert list_resp.status_code == 200
        assert list_resp.json()["count"] == 1

        dash = await client.get("/dashboard")
        assert dash.status_code == 200
        assert '<script>alert("xss")</script>' not in dash.text
        assert '<img src=x onerror="alert(1)">' not in dash.text
        assert "&lt;script&gt;" in dash.text
        assert 'id="appeals_count">1<' in dash.text

        del_resp = await client.delete(f"/api/v1/findings/appeal/{appeal_id}")
        assert del_resp.status_code == 200
        assert (await client.get("/api/v1/findings/appeals")).json()["count"] == 0


@pytest.mark.asyncio
async def test_concurrent_roi_chat_and_demo_requests():
    from aegis_server.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        r_roi, r_chat1, r_chat2 = await asyncio.gather(
            client.post("/api/v1/risk/roi", json={"team_size": 20, "prevented_risk_kzt": 8_650_000}),
            client.post("/api/chat", json={"message": "Оцени риск в тенге (КоАП РК)"}),
            client.post("/api/chat", json={"message": "Самоисцеление и Git-секреты"}),
        )

    assert r_roi.status_code == 200
    roi = r_roi.json()
    assert roi["guardian_monthly_kzt"] == 190_000
    assert roi["monthly_savings_kzt"] == 610_000
    assert roi["roi_multiple"] >= 4.0

    assert r_chat1.status_code == 200 and "КоАП" in r_chat1.json()["reply"]
    assert r_chat2.status_code == 200 and "Машина времени Git" in r_chat2.json()["reply"]


def test_air_gapped_mode_strips_adversarial_cloud_keys():
    cfg = Settings(
        allow_cloud_llm=False,
        llm_provider="gemini",
        gemini_api_key="injected-gemini-key",
        openrouter_api_key="injected-openrouter-key",
    )
    assert cfg.air_gapped is True
    assert cfg.llm_provider.value == "ollama"
    assert cfg.gemini_api_key is None
    assert cfg.openrouter_api_key is None


def test_roi_bounds_and_seeder_idempotency(tmp_path: Path):
    small = estimate_roi(team_size=5)
    enterprise = estimate_roi(team_size=60)
    assert small.recommended_tier == "PILOT / STARTER"
    assert enterprise.recommended_tier == "ENTERPRISE GOV/FIN"
    assert enterprise.annual_savings_kzt > small.annual_savings_kzt

    db = tmp_path / "seed_test.db"
    first = seed_demo_database(db_path=db)
    second = seed_demo_database(db_path=db)
    assert first == 3
    assert second == 0
    m = MetricsStore(db).summary()
    assert m.total_scans == 3
    assert m.appeals_count == 1


@pytest.mark.asyncio
async def test_telegram_parity_chat_commands_and_reports_feed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(settings, "metrics_db_path", tmp_path / "parity.db")
    store = get_metrics_store()
    store.record_audit(
        repo_name="demo/kz-fintech-app",
        commit_sha="abcdef1234567890",
        branch="main",
        severity_counts={"CRITICAL": 2, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
        total_findings=3,
        scan_seconds=4.2,
        ai_seconds=0.0,
        ai_generated=False,
        report_name="20261120T150000Z_abcdef123456.pdf",
    )

    from aegis_server.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. /api/v1/reports returns audited commits with direct PDF/MD URLs
        rep = await client.get("/api/v1/reports?limit=10")
        assert rep.status_code == 200
        rdata = rep.json()
        assert rdata["total_scans"] == 1
        assert len(rdata["audits"]) == 1
        assert rdata["audits"][0]["pdf_url"].endswith(".pdf")
        assert rdata["audits"][0]["md_url"].endswith(".md")

        # 2. /verify owner/repo works in web chat just like Telegram bot
        ver = await client.post("/api/chat", json={"message": "/verify octocat/hello-world"})
        assert ver.status_code == 200
        assert "cybersec-verify-" in ver.json()["reply"]

        # 3. Bare owner/repo in web chat triggers repo scan just like Telegram bot
        bare = await client.post("/api/chat", json={"message": "octocat/hello-world"})
        assert bare.status_code == 200
        assert bare.json().get("action") == "SCAN"
        assert bare.json().get("github_url") == "https://github.com/octocat/hello-world"

