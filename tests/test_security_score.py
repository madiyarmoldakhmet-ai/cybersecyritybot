import pytest
from aegis.scanners.models import VulnerabilityFinding, Severity
from aegis.scanners.security_score import calculate_score, get_grade, generate_badge_url

def test_calculate_score():
    findings = [
        VulnerabilityFinding(title="SQLi", severity=Severity.CRITICAL, file_path="app.py", cwe="CWE-89"),
        VulnerabilityFinding(title="XSS", severity=Severity.HIGH, file_path="app.py", cwe="CWE-79"),
        VulnerabilityFinding(title="Info", severity=Severity.INFO, file_path="app.py", cwe=""),
    ]
    # 100 - 25 - 10 = 65
    score = calculate_score(findings)
    assert score == 65
    
    grade, color, rec = get_grade(score)
    assert grade == "C"

def test_score_floor():
    findings = [VulnerabilityFinding(title="Crit", severity=Severity.CRITICAL, file_path="app.py", cwe="CWE-1")] * 5
    # 100 - 125 = -25 -> floored to 0
    score = calculate_score(findings)
    assert score == 0
    grade, color, rec = get_grade(score)
    assert grade == "F"

def test_badge_url():
    url = generate_badge_url(65, "C")
    assert "Aegis_Security_Score-65" in url
    assert "orange" in url
