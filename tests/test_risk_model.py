"""Financial risk in tenge (ст. 79 КоАП РК)."""

import pytest

from aegis.reporting.audit_report import render_markdown, AuditReport
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.risk_model import RiskSettings, assess_risk, classify, format_kzt


def _f(id_, sev, cwe=(), scanner=ScannerType.CUSTOM, title="t", snippet=""):
    return VulnerabilityFinding(id=id_, scanner=scanner, title=title, description="d", severity=sev,
                                file_path="app.py", line_start=3, cwe=list(cwe), code_snippet=snippet)


def test_classification():
    assert classify(_f("unmasked-kz-iin-log", Severity.HIGH, ["CWE-532"])) == "pii_leak"
    assert classify(_f("sqli", Severity.CRITICAL, ["CWE-89"])) == "data_access"
    assert classify(_f("sqli", Severity.CRITICAL, ["CWE-89"], snippet="WHERE iin = ...")) == "pii_leak"
    assert classify(_f("s", Severity.CRITICAL, scanner=ScannerType.GIT_HISTORY)) == "credential"
    assert classify(_f("ssl", Severity.HIGH, ["CWE-295"])) == "transport"
    assert classify(_f("x", Severity.LOW, ["CWE-1004"], title="cookie flag")) is None


def test_no_impacting_findings_means_zero_risk():
    risk = assess_risk([_f("x", Severity.LOW, ["CWE-1004"])])
    assert risk.total_kzt == 0
    assert "не выявлен" in risk.headline


def test_severe_finding_uses_fine_ceiling_and_incident_cost():
    cfg = RiskSettings(mrp_kzt=4325, records_at_risk=1000, cost_per_record_kzt=2000)
    risk = assess_risk([_f("sqli", Severity.CRITICAL, ["CWE-89"]), _f("ssl", Severity.HIGH, ["CWE-295"])], cfg)
    assert risk.regulatory_kzt == 2000 * 4325 == 8_650_000
    assert risk.incident_kzt == 2_000_000
    assert risk.total_kzt == 10_650_000
    # CRITICAL weighs twice as much as HIGH
    shares = {r.finding_id: r.risk_kzt for r in risk.top_findings}
    assert shares["sqli"] == pytest.approx(2 * shares["ssl"], abs=1)
    assert sum(shares.values()) == pytest.approx(risk.total_kzt, abs=2)


def test_medium_only_uses_fine_floor_and_no_incident():
    cfg = RiskSettings(records_at_risk=1000, cost_per_record_kzt=2000)
    risk = assess_risk([_f("ssl", Severity.MEDIUM, ["CWE-295"])], cfg)
    assert risk.regulatory_kzt == 30 * 4325
    assert risk.incident_kzt == 0


def test_format_and_markdown_section():
    assert format_kzt(8650000) == "8 650 000 ₸"
    from aegis.ai.audit_summarizer import AuditSummary
    findings = [_f("sqli", Severity.CRITICAL, ["CWE-89"])]
    scan = SASTScanResult(target_path=".", total_findings=1, findings=findings, findings_by_severity={Severity.CRITICAL: 1})
    summary = AuditSummary(text="ok", model="rule-based", ai_generated=False, duration_seconds=0.0)
    report = AuditReport.from_scan(scan, summary, "o/r", "abc", "main", "dev", risk=assess_risk(findings))
    md = render_markdown(report)
    assert "## Финансовый риск (₸)" in md and "8 650 000 ₸" in md and "КоАП" in md


def test_incident_cost_only_when_records_are_exposed():
    cfg = RiskSettings(records_at_risk=1000, cost_per_record_kzt=2000)
    leaked_token = _f("g", Severity.CRITICAL, scanner=ScannerType.GIT_HISTORY)
    risk = assess_risk([leaked_token], cfg)
    assert risk.regulatory_kzt == 8_650_000 and risk.incident_kzt == 0
