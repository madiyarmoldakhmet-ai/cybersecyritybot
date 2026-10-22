"""
Unit tests for Commit Guardian compliance reporting:
local AI summary, Markdown/PDF report rendering, and the webhook audit pipeline.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.ai.audit_summarizer import AuditSummarizer, AuditSummary
from aegis.core.config import settings
from aegis.reporting import AuditReport, AuditReportWriter
from aegis.reporting.audit_report import render_markdown
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding

COMMIT_SHA = "c7dcd6547f0a4ea010a9fd0cb5573ad810bbc701"


def make_finding(rule_id: str, severity: Severity, title: str, file_path: str, line: int) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id=rule_id,
        scanner=ScannerType.SEMGREP,
        title=title,
        description=f"{title} detected",
        severity=severity,
        file_path=file_path,
        line_start=line,
        code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        cwe=["CWE-89"] if "SQL" in title else [],
    )


def make_scan(findings) -> SASTScanResult:
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return SASTScanResult(
        target_path="/tmp/scan",
        total_findings=len(findings),
        findings_by_severity=counts,
        findings=findings,
        duration_seconds=3.4,
        scanners_run=[ScannerType.SEMGREP, ScannerType.BANDIT],
    )


SCAN = make_scan([
    make_finding("python.lang.security.audit.formatted-sql-query", Severity.CRITICAL, "SQL Injection", "api/users.py", 42),
    make_finding("generic.secrets.hardcoded-api-key", Severity.HIGH, "Hardcoded API key | token", "config/settings.py", 7),
    make_finding("python.flask.debug-enabled", Severity.MEDIUM, "Debug mode enabled", "app.py", 3),
])


class FakeCompletions:
    def __init__(self, content=None, error=None):
        self.content, self.error, self.calls = content, error, 0

    async def create(self, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self.content))])


def fake_client(content=None, error=None):
    completions = FakeCompletions(content, error)
    return SimpleNamespace(chat=SimpleNamespace(completions=completions)), completions


@pytest.mark.asyncio
async def test_summarizer_uses_local_model():
    client, completions = fake_client(content="Риск критический: SQL-инъекция в api/users.py.")
    summary = await AuditSummarizer(client=client, model="qwen2.5-coder:14b").summarize(SCAN, "gov/portal", COMMIT_SHA)

    assert completions.calls == 1
    assert summary.ai_generated is True
    assert summary.model == "qwen2.5-coder:14b"
    assert "SQL-инъекция" in summary.text
    assert summary.duration_seconds >= 0


@pytest.mark.asyncio
async def test_summarizer_falls_back_when_ollama_unreachable():
    client, _ = fake_client(error=ConnectionError("connection refused"))
    summary = await AuditSummarizer(client=client).summarize(SCAN, "gov/portal", COMMIT_SHA)

    assert summary.ai_generated is False
    assert "критический" in summary.text
    assert "SQL Injection" in summary.text


@pytest.mark.asyncio
async def test_clean_scan_skips_llm():
    client, completions = fake_client(content="should not be used")
    summary = await AuditSummarizer(client=client).summarize(make_scan([]), "gov/portal", COMMIT_SHA)

    assert completions.calls == 0
    assert summary.ai_generated is False
    assert "не обнаружено" in summary.text


def build_report(repo_name: str = "gov/portal") -> AuditReport:
    summary = AuditSummary(text="Риск критический.", model="qwen2.5-coder:14b", duration_seconds=4.2, ai_generated=True)
    return AuditReport.from_scan(
        SCAN, summary, repo_name=repo_name, commit_sha=COMMIT_SHA, branch="main", author="dev",
        commit_url=f"https://github.com/{repo_name}/commit/{COMMIT_SHA}",
    )


def test_markdown_report_contains_required_fields():
    report = build_report()
    md = render_markdown(report)

    assert report.timestamp_utc in md
    assert "gov/portal" in md
    assert COMMIT_SHA in md
    assert "python.lang.security.audit.formatted-sql-query" in md
    assert "generic.secrets.hardcoded-api-key" in md
    assert "Риск критический." in md
    assert "**CRITICAL**" in md
    # Pipes inside findings must not break the Markdown table
    assert "Hardcoded API key \\| token" in md
    # Rules are listed most severe first
    assert md.index("formatted-sql-query") < md.index("debug-enabled")


def test_writer_creates_markdown_and_pdf(tmp_path):
    paths = AuditReportWriter(output_dir=tmp_path, pdf_enabled=True).write(build_report())

    assert paths.markdown.is_file()
    assert paths.markdown.read_text(encoding="utf-8").startswith("# Commit Guardian")
    assert paths.pdf is not None and paths.pdf.is_file()
    assert paths.pdf.read_bytes()[:5] == b"%PDF-"
    assert paths.markdown.name.endswith(f"_{COMMIT_SHA[:12]}.md")


def test_writer_sanitizes_untrusted_repo_name(tmp_path):
    report = build_report(repo_name="../../etc/passwd")
    report.commit_sha = "../../evil"
    paths = AuditReportWriter(output_dir=tmp_path, pdf_enabled=False).write(report)

    assert paths.markdown.resolve().is_relative_to(tmp_path.resolve())
    assert ".." not in paths.markdown.relative_to(tmp_path).parts


@pytest.mark.asyncio
async def test_guardian_audit_writes_report_and_alerts(tmp_path, monkeypatch):
    import web.webhook as webhook

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return b"", b""

    class FakeAegisEngine:
        async def scan(self, path):
            return make_scan(SCAN.findings[:1])

    class FakeSASTScanner:
        async def scan(self, path):
            return make_scan(SCAN.findings[1:])

    class FakeSummarizer:
        async def summarize(self, scan_result, repo_name, commit_sha):
            return AuditSummary(text="Локальное заключение.", model="qwen2.5-coder:14b", duration_seconds=1.5, ai_generated=True)

    monkeypatch.setattr(settings, "scan_output_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "temp_clone_dir", tmp_path / "clones")
    monkeypatch.setattr(settings, "default_telegram_chat_id", 12345)
    monkeypatch.setattr(settings, "report_pdf_enabled", False)
    monkeypatch.setattr(webhook, "AuditSummarizer", FakeSummarizer)

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=FakeProc())), \
         patch("aegis.scanners.aegis_runner.AegisEngine", FakeAegisEngine), \
         patch("aegis.scanners.sast_scanner.SASTScanner", FakeSASTScanner), \
         patch.object(webhook, "send_telegram_alert", AsyncMock()) as alert:
        result = await webhook.process_guardian_audit(
            repo_name="gov/portal",
            clone_url="https://github.com/gov/portal.git",
            commit_sha=COMMIT_SHA,
            author="dev",
            branch="main",
        )

    assert result.total_findings == 3
    reports = list((tmp_path / "reports").rglob("*.md"))
    assert len(reports) == 1
    content = reports[0].read_text(encoding="utf-8")
    assert "Локальное заключение." in content and COMMIT_SHA in content
    alert.assert_awaited_once()
    assert alert.await_args.kwargs["report_name"] == reports[0].name


@pytest.mark.asyncio
async def test_guardian_audit_fails_loudly_when_clone_fails(tmp_path, monkeypatch):
    import web.webhook as webhook

    class FailedProc:
        returncode = 128

        async def communicate(self):
            return b"", b"fatal: repository not found"

    monkeypatch.setattr(settings, "scan_output_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "temp_clone_dir", tmp_path / "clones")

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=FailedProc())):
        with pytest.raises(RuntimeError, match="git clone failed"):
            await webhook.process_guardian_audit(
                repo_name="gov/portal", clone_url="https://github.com/gov/portal.git",
                commit_sha=COMMIT_SHA, author="dev", branch="main",
            )

    # No report may claim a clean audit for code that was never scanned
    assert not list((tmp_path / "reports").rglob("*.md"))
