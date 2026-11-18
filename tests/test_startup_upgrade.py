"""
Regression tests for Commit Guardian startup upgrades:
- .aegis.yml policy enforcement in SASTScanner (custom_rules, ignore_paths, severity_threshold)
- 1-click demo audit endpoint (/api/scan/demo) + compliance PDF/MD report serving (/api/v1/reports/...)
- Path traversal protection & local_path production guard
- Offline rule-based remediation fallback
- Telegram PDF compliance delivery & GitHub PR audit comment posting
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.ai.remediation_engine import RemediationEngine
from aegis.core.config import settings
from aegis.core.metrics_store import get_metrics_store
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.sast_scanner import SASTScanner


@pytest.mark.asyncio
async def test_sast_applies_aegis_yml_custom_rules_and_ignores(tmp_path: Path):
    (tmp_path / ".aegis.yml").write_text(
        """
ignore_paths:
  - "ignored_dir/**"
ignore_rules:
  - dynamic-code-eval
severity_threshold: HIGH
ai_filter: false
custom_rules:
  - id: unmasked-kz-iin-log
    pattern: "logger\\\\.info\\\\([^)]*\\\\biin\\\\b"
    title: "Unmasked IIN logged"
    severity: HIGH
    cwe: ["CWE-532"]
""",
        encoding="utf-8",
    )
    (tmp_path / "service.py").write_text(
        "import logging\n"
        "logger = logging.getLogger('app')\n"
        "def f(iin, expr):\n"
        "    logger.info(f'iin={iin}')\n"
        "    return eval(expr)\n",
        encoding="utf-8",
    )
    ignored = tmp_path / "ignored_dir"
    ignored.mkdir()
    (ignored / "skip.py").write_text("logger.info(f'iin={iin}')\n", encoding="utf-8")

    result = await SASTScanner().scan(tmp_path)
    ids = {f.id for f in result.findings}
    files = {f.file_path for f in result.findings}

    assert "unmasked-kz-iin-log" in ids
    assert "dynamic-code-eval" not in ids  # ignored by ignore_rules
    assert all(not fp.startswith("ignored_dir/") for fp in files)


@pytest.mark.asyncio
async def test_demo_scan_endpoint_generates_reports_and_dashboard_links(tmp_path: Path, monkeypatch):
    from aegis_server.main import app

    monkeypatch.setattr(settings, "scan_output_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "metrics_db_path", tmp_path / "metrics.db")
    monkeypatch.setattr(settings, "report_pdf_enabled", True)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        demo = await client.post("/api/scan/demo")
        assert demo.status_code == 200
        payload = demo.json()
        assert payload["status"] == "success"
        assert payload["total_findings"] >= 4
        assert payload["security_score"] < 50
        assert payload["grade"] in {"D", "F"}
        assert payload["report_pdf_url"].startswith("/api/v1/reports/")
        assert payload["report_md_url"].startswith("/api/v1/reports/")

        pdf_resp = await client.get(payload["report_pdf_url"])
        md_resp = await client.get(payload["report_md_url"])
        dash_resp = await client.get("/dashboard")
        bad_report = await client.get("/api/v1/reports/demo__kz-fintech-app/secret.txt")

    assert pdf_resp.status_code == 200 and pdf_resp.content[:5] == b"%PDF-"
    assert md_resp.status_code == 200 and "Commit Guardian" in md_resp.text
    assert bad_report.status_code == 400
    assert dash_resp.status_code == 200
    assert payload["report_pdf_url"] in dash_resp.text
    assert "https://" not in dash_resp.text and "http://" not in dash_resp.text
    assert get_metrics_store().summary().total_scans == 1


@pytest.mark.asyncio
async def test_local_path_blocked_in_production(monkeypatch):
    from web.api import app

    monkeypatch.setattr(settings, "environment", "production")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post("/api/v1/scan/sast", json={"local_path": "/etc"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_remediation_fallback_when_ollama_offline():
    finding = VulnerabilityFinding(
        id="sql-injection-dynamic-query",
        scanner=ScannerType.CUSTOM,
        title="Dynamic SQL Injection",
        description="Unsafe SQL concat",
        severity=Severity.CRITICAL,
        file_path="payment_gateway.py",
        line_start=18,
        cwe=["CWE-89"],
    )
    engine = RemediationEngine()
    with patch.object(engine, "_query_ollama", AsyncMock(side_effect=ConnectionError("Ollama down"))):
        res = await engine.analyze_and_remediate(finding, code_context="cursor.execute('SELECT * ' + uid)")

    assert res.confidence_score > 0.5
    assert "параметризованный" in res.remediation_steps[0].lower()
    assert "?" in res.fixed_code


@pytest.mark.asyncio
async def test_bot_delivers_score_and_pdf_report(tmp_path: Path, monkeypatch):
    from bot.main import _deliver_scan_result

    monkeypatch.setattr(settings, "scan_output_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "metrics_db_path", tmp_path / "metrics.db")
    monkeypatch.setattr(settings, "report_pdf_enabled", True)

    result = SASTScanResult(
        target_path=str(tmp_path),
        total_findings=1,
        findings_by_severity={Severity.CRITICAL: 1},
        findings=[
            VulnerabilityFinding(
                id="sqli-1",
                scanner=ScannerType.CUSTOM,
                title="SQL Injection",
                description="Dynamic SQL",
                severity=Severity.CRITICAL,
                file_path="app.py",
                line_start=10,
                cwe=["CWE-89"],
            )
        ],
        duration_seconds=0.4,
    )

    msg = MagicMock()
    msg.from_user = MagicMock(username="madiyar", id=42)
    msg.reply_document = AsyncMock()
    status_msg = MagicMock()
    status_msg.edit_text = AsyncMock()

    await _deliver_scan_result(msg, status_msg, result, "owner/repo", "deadbeef1234")

    edited = status_msg.edit_text.await_args.args[0]
    assert "Security Score" in edited
    assert "75/100" in edited
    msg.reply_document.assert_awaited_once()


@pytest.mark.asyncio
async def test_webhook_posts_github_pr_comment_when_token_set(monkeypatch):
    from web.webhook import post_github_pr_comment

    monkeypatch.setattr(settings, "github_token", "real_looking_pat_token")
    posted = {}

    class DummyResp:
        status_code = 201

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, headers=None, json=None):
            posted["url"] = url
            posted["body"] = json["body"]
            return DummyResp()

    res = SASTScanResult(
        target_path="/tmp/x",
        total_findings=1,
        findings_by_severity={Severity.HIGH: 1},
        findings=[
            VulnerabilityFinding(
                id="r-1",
                scanner=ScannerType.CUSTOM,
                title="Eval Call",
                description="Unsafe eval",
                severity=Severity.HIGH,
                file_path="app.py",
                line_start=5,
                cwe=["CWE-95"],
            )
        ],
    )

    with patch("web.webhook.httpx.AsyncClient", return_value=DummyClient()):
        ok = await post_github_pr_comment("gov/portal", 7, "abc12345", res, 90, "A+", "Риск умеренный.")

    assert ok is True
    assert posted["url"].endswith("/repos/gov/portal/issues/7/comments")
    assert "90/100 (A+)" in posted["body"]


def test_parse_chat_payload_supports_text_context_and_reset():
    from aegis_server.main import _parse_chat_payload

    assert _parse_chat_payload("  привет  ") == (False, "привет", "")
    assert _parse_chat_payload("{invalid-json") == (False, "{invalid-json", "")
    assert _parse_chat_payload('{"reset": true}') == (True, "", "")

    reset, text, note = _parse_chat_payload(
        '{"message": "Как починить SQLi?", "scan_context": {"repo_name": "demo/kz", "security_score": 40, "grade": "F", "total_findings": 1, "findings": [{"severity": "CRITICAL", "title": "SQL Injection", "file_path": "pay.py", "line_start": 18, "cwe": ["CWE-89"]}]}}'
    )
    assert reset is False
    assert text == "Как починить SQLi?"
    assert "demo/kz" in note and "40/100 (F)" in note and "SQL Injection (pay.py:18, CWE-89)" in note


def test_ownership_parser_and_signed_proof_tokens():
    from aegis.core.verifier import OwnershipVerifier

    assert OwnershipVerifier.parse_github_repo("https://github.com/vercel/next.js.git") == "vercel/next.js"
    assert OwnershipVerifier.parse_github_repo("https://github.com/owner/my.app/tree/main") == "owner/my.app"

    ch_repo = OwnershipVerifier.issue_challenge("https://github.com/kz-bank/core-api")
    assert ch_repo["target_type"] == "github"
    assert ch_repo["target"] == "kz-bank/core-api"
    assert ch_repo["challenge_code"].startswith("cybersec-verify-")

    ch_domain = OwnershipVerifier.issue_challenge("https://pay.kaspi-demo.kz/login", "domain")
    assert ch_domain["target_type"] == "domain"
    assert ch_domain["target"] == "pay.kaspi-demo.kz"

    proof = OwnershipVerifier.create_proof_token("kz-bank/core-api", "commit_challenge", "madiyar")
    assert OwnershipVerifier.verify_proof_token(proof, "https://github.com/kz-bank/core-api") is not None
    assert OwnershipVerifier.verify_proof_token(proof, "https://github.com/other/repo") is None


@pytest.mark.asyncio
async def test_ownership_verification_endpoints_and_strict_gate():
    from aegis.core.verifier import OwnershipVerifier
    from aegis_server.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        ch_resp = await client.post("/api/v1/verify/challenge", json={"target": "owner/app.py"})
        assert ch_resp.status_code == 200
        code = ch_resp.json()["challenge_code"]

        with patch.object(
            OwnershipVerifier,
            "verify_commit_challenge",
            AsyncMock(return_value=(True, f"Код подтверждения найден: {code}")),
        ):
            verify_resp = await client.post(
                "/api/v1/verify/ownership",
                json={"target": "owner/app.py", "method": "challenge", "challenge_code": code},
            )
        assert verify_resp.status_code == 200
        vdata = verify_resp.json()
        assert vdata["verified"] is True and vdata["proof_token"]

        blocked_sast = await client.post(
            "/api/v1/scan/sast",
            json={"repo_url": "https://github.com/owner/app.py", "require_ownership": True},
        )
        assert blocked_sast.status_code == 403

        blocked_dast = await client.post(
            "/api/v1/scan/dast",
            json={"target_url": "https://example.kz", "require_ownership": True},
        )
        assert blocked_dast.status_code == 403


@pytest.mark.asyncio
async def test_sca_scanner_strips_extras_comments_and_tracks_lines(tmp_path: Path):
    from aegis.scanners.sca_scanner import SCAScanner

    req = tmp_path / "requirements.txt"
    req.write_text("# comment\nuvicorn[standard]>=0.30.0  # web server\nfastapi==0.111.0; python_version>='3.9'\n")

    captured_batches = []

    class DummyResp:
        status_code = 200

        @staticmethod
        def json():
            return {"results": [{}, {}]}

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, json=None):
            captured_batches.extend(json["queries"])
            return DummyResp()

    with patch("aegis.scanners.sca_scanner.httpx.AsyncClient", return_value=DummyClient()):
        findings = await SCAScanner().scan(tmp_path)

    assert findings == []
    assert [q["package"]["name"] for q in captured_batches] == ["uvicorn", "fastapi"]
    assert [q["version"] for q in captured_batches] == ["0.30.0", "0.111.0"]
