"""
Regression tests for security hardening, unified server routes, safe archive extraction,
taint engine fixes, Telegram formatting, and SAST/DAST integration.
"""

import io
import sys
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core.archive_utils import MAX_EXTRACTED_BYTES, safe_extract_zip
from aegis.core.config import settings
from aegis.scanners.http_dast import HTTPSecurityScanner
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.sast_scanner import SASTScanner
from aegis.scanners.taint_engine import TaintEngine


def test_safe_extract_zip_rejects_traversal(tmp_path: Path):
    bad_zip = tmp_path / "traversal.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../escape.txt", "pwned")

    with pytest.raises(ValueError, match="Unsafe path"):
        safe_extract_zip(bad_zip, tmp_path / "out")


def test_safe_extract_zip_extracts_valid_files(tmp_path: Path):
    good_zip = tmp_path / "ok.zip"
    with zipfile.ZipFile(good_zip, "w") as zf:
        zf.writestr("app/main.py", "print('hello')\n")

    out_dir = tmp_path / "out"
    count = safe_extract_zip(good_zip, out_dir)
    assert count == 1
    assert (out_dir / "app" / "main.py").read_text() == "print('hello')\n"


def test_taint_engine_handles_same_name_and_async(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "async def handler(request):\n"
        "    x = request.args.get('q')\n"
        "    helper(x)\n"
        "def helper(v):\n"
        "    cursor.execute(f'SELECT * FROM t WHERE x={v}')\n"
    )
    (tmp_path / "b.py").write_text(
        "def helper():\n"
        "    return 1\n"
    )

    findings = TaintEngine(str(tmp_path)).analyze()
    assert len(findings) >= 1
    assert any("handler()" in " ".join(f.taint_path) and "helper()" in " ".join(f.taint_path) for f in findings)


@pytest.mark.asyncio
async def test_sast_detects_multiline_sqli_and_runs_taint(tmp_path: Path):
    (tmp_path / "vuln.py").write_text(
        "def get_user(uid):\n"
        "    q = 'SELECT * FROM users WHERE id = ' + uid\n"
        "    cursor.execute(q)\n"
    )
    result = await SASTScanner().scan(tmp_path)
    assert result.total_findings >= 1
    assert any(f.id == "sql-injection-dynamic-query" for f in result.findings)


@pytest.mark.asyncio
async def test_production_server_exposes_health_and_upload(tmp_path: Path):
    from aegis_server.main import app

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.py", "def f(expr):\n    return eval(expr)\n")
    buf.seek(0)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        health = await client.get("/health")
        upload = await client.post(
            "/api/scan/upload",
            files={"file": ("code.zip", buf.getvalue(), "application/zip")},
        )

    assert health.status_code == 200
    assert health.json()["status"] == "healthy"
    assert upload.status_code == 200
    payload = upload.json()
    assert isinstance(payload["vulnerabilities"], list)
    assert payload["total_findings"] >= 1
    assert len(payload["vulnerabilities"]) == payload["total_findings"]


def test_http_dast_information_disclosure():
    scanner = HTTPSecurityScanner()
    headers = httpx.Headers({"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.3"})
    findings = scanner._check_information_disclosure("http://testserver/", headers)
    assert len(findings) == 2
    assert {f.id for f in findings} == {"dast.info-disclosure-server", "dast.info-disclosure-x-powered-by"}


def test_bot_summary_and_auth(monkeypatch):
    from bot.main import _format_scan_summary, _is_authorized_user

    monkeypatch.setattr(settings, "allowed_telegram_users", [111, 222])
    assert _is_authorized_user(111) is True
    assert _is_authorized_user(999) is False

    res = SASTScanResult(
        target_path="/tmp/x",
        total_findings=1,
        findings_by_severity={Severity.CRITICAL: 1},
        findings=[
            VulnerabilityFinding(
                id="test-1",
                scanner=ScannerType.CUSTOM,
                title="SQLi in user_id <script>",
                description="desc",
                severity=Severity.CRITICAL,
                file_path="api/users_v2.py",
                line_start=42,
            )
        ],
        duration_seconds=0.5,
    )
    summary = _format_scan_summary(res)
    assert "Найдено уязвимостей: <b>1</b>" in summary
    assert "&lt;script&gt;" in summary
    assert "api/users_v2.py:42" in summary


@pytest.mark.asyncio
async def test_webhook_alert_escapes_html_and_underscores(monkeypatch):
    from web.webhook import send_telegram_alert

    monkeypatch.setattr(settings, "telegram_bot_token", "123456:TEST_TOKEN")
    sent = {}

    class DummySession:
        async def close(self):
            return None

    class DummyBot:
        def __init__(self, token):
            self.session = DummySession()

        async def send_message(self, **kwargs):
            sent.update(kwargs)

    scan_res = SASTScanResult(
        target_path="/tmp/x",
        total_findings=1,
        findings_by_severity={Severity.CRITICAL: 1},
        findings=[
            VulnerabilityFinding(
                id="sqli",
                scanner=ScannerType.CUSTOM,
                title="SQLi_in_user_id",
                description="bad_sql",
                severity=Severity.CRITICAL,
                file_path="api/get_user_by_id.py",
                line_start=12,
                recommendation="Use parameterized_query <T>",
            )
        ],
    )

    with patch("web.webhook.Bot", DummyBot):
        await send_telegram_alert(
            chat_id=12345,
            repo_name="org/my_repo",
            commit_sha="abcdef123456",
            author="dev_user",
            branch="feat/test_branch",
            scan_result=scan_res,
            report_name="report_v1.pdf",
        )

    assert sent["parse_mode"] == "HTML"
    assert "api/get_user_by_id.py" in sent["text"]
    assert "&lt;T&gt;" in sent["text"]
