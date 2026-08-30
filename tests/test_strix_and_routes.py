"""
Unit and integration tests for RouteExtractor, Strix Multi-Agent Engine, and DAST Scanner.
"""

import asyncio
from pathlib import Path
import pytest

from strix.scanners.models import ScannerType, Severity, VulnerabilityFinding
from strix.scanners.route_extractor import RouteExtractor
from strix.scanners.vuln_classifier import VulnCategory, classify_vulnerability
from strix.scanners.dast_scanner import DASTScanner


def test_route_extractor_discovery(tmp_path: Path):
    """Test AST-based route discovery on Python FastAPI and Flask code."""
    sample_code = '''
from fastapi import FastAPI, Depends, Query

app = FastAPI()

def get_current_user():
    return {"user": "admin"}

@app.get("/api/v1/users/{user_id}")
async def get_user_profile(user_id: int, user: dict = Depends(get_current_user)):
    return {"id": user_id}

@app.post("/api/v1/raw-query")
def execute_sql(q: str):
    import sqlite3
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{q}'")
    return {"status": "ok"}
'''
    py_file = tmp_path / "routes_test.py"
    py_file.write_text(sample_code, encoding="utf-8")

    extractor = RouteExtractor()
    endpoints = extractor.scan_repository(tmp_path)

    assert len(endpoints) == 2
    paths = {ep.path for ep in endpoints}
    assert "/api/v1/users/{user_id}" in paths
    assert "/api/v1/raw-query" in paths

    # Verify auth guard detection on first endpoint
    ep_auth = next(ep for ep in endpoints if ep.path == "/api/v1/users/{user_id}")
    assert ep_auth.has_auth_guard is True
    assert ep_auth.method == "GET"

    # Verify sensitive sink detection on second endpoint (raw_sql)
    ep_sql = next(ep for ep in endpoints if ep.path == "/api/v1/raw-query")
    assert ep_sql.has_auth_guard is False
    assert "raw_sql" in ep_sql.sensitive_operations
    assert ep_sql.method == "POST"


def test_vuln_classification():
    """Test classification of remote exploitable vs static code findings."""
    f_sqli = VulnerabilityFinding(
        id="STRIX-001",
        scanner=ScannerType.STRIX,
        title="SQL Injection in user search",
        description="Raw string formatting in SQL query allows full authentication bypass",
        severity=Severity.CRITICAL,
        file_path="api/search.py",
        cwe=["CWE-89"],
    )
    assert classify_vulnerability(f_sqli) == VulnCategory.EXPLOITABLE_REMOTE

    f_sri = VulnerabilityFinding(
        id="semgrep-sri",
        scanner=ScannerType.SEMGREP,
        title="Semgrep: missing-integrity",
        description="Missing Subresource Integrity hash on script tag",
        severity=Severity.MEDIUM,
        file_path="index.html",
        cwe=["CWE-353"],
    )
    assert classify_vulnerability(f_sri) == VulnCategory.CODE_QUALITY


def test_dast_url_normalization():
    """Test DAST URL normalization."""
    dast = DASTScanner()
    assert dast._normalize_url("example.com") == "https://example.com"
    assert dast._normalize_url("http://localhost:8000") == "http://localhost:8000"
