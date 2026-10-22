import pytest
from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.security_score import calculate_score, get_grade, generate_badge_url


def finding(title: str, severity: Severity, cwe: str = "") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id=title.lower(), scanner=ScannerType.SEMGREP, title=title, description=title,
        severity=severity, file_path="app.py", cwe=[cwe] if cwe else [],
    )

def test_calculate_score():
    findings = [
        finding("SQLi", Severity.CRITICAL, "CWE-89"),
        finding("XSS", Severity.HIGH, "CWE-79"),
        finding("Info", Severity.INFO),
    ]
    # 100 - 25 - 10 = 65
    score = calculate_score(findings)
    assert score == 65
    
    grade, color, rec = get_grade(score)
    assert grade == "C"

def test_score_floor():
    findings = [finding("Crit", Severity.CRITICAL, "CWE-1")] * 5
    # 100 - 125 = -25 -> floored to 0
    score = calculate_score(findings)
    assert score == 0
    grade, color, rec = get_grade(score)
    assert grade == "F"

def test_badge_url():
    url = generate_badge_url(65, "C")
    assert "Aegis_Security_Score-65" in url
    assert "orange" in url
