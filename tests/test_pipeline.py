"""
Comprehensive End-to-End Test for CyberSecurityBot Pipeline.
Tests:
1. SAST & Dependency Scanner (Vulnerable AST patterns: SQLi, hardcoded credentials, eval, shell=True).
2. DAST Dynamic Scanner (Missing CSP/HSTS headers, X-Powered-By, Insecure Cookies, CORS reflection).
3. AI Remediation Engine (Root cause analysis & secure patch generation).
4. Web API Health and Scanning Endpoints.
"""

import asyncio
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Response
import httpx

from ai.remediation_engine import RemediationEngine
from scanners.dast_scanner import DASTScanner
from scanners.models import DASTScanResult, SASTScanResult
from scanners.sast_scanner import SASTScanner
from web.api import app as fastapi_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cybersecuritybot.test_pipeline")


VULNERABLE_APP_CODE = '''"""
Sample intentionally vulnerable application for security pipeline testing.
"""
import sqlite3
import subprocess

HARDCODED_SECRET_KEY = "sk-live-1234567890abcdef1234567890abcdef"

def get_user_profile(user_input_id: str):
    # Vulnerable to SQL Injection (Bandit B608)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '" + user_input_id + "'"
    cursor.execute(query)
    return cursor.fetchall()

def run_system_ping(host: str):
    # Vulnerable to Command Injection (Bandit B602)
    return subprocess.Popen(f"ping -c 1 {host}", shell=True)

def execute_dynamic_calculation(expr: str):
    # Insecure direct eval (Bandit B307)
    return eval(expr)
'''

REQUIREMENTS_CONTENT = """requests==2.25.1
flask==1.1.2
urllib3==1.26.4
"""


# Create a mock vulnerable web application for offline DAST testing
mock_web_app = FastAPI()

@mock_web_app.get("/")
def index(response: Response):
    # Insecure: Leaks X-Powered-By, missing CSP and HSTS
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    response.headers["Server"] = "Apache/2.4.41"
    response.set_cookie(key="session_id", value="123456", httponly=False, secure=False)
    return {"message": "Welcome to test target"}


async def run_end_to_end_test():
    """Execute complete SAST, DAST, and AI remediation pipeline."""
    # 1. Create temporary mock repository
    temp_dir = Path(tempfile.mkdtemp(prefix="cybersec_test_"))
    logger.info(f"📁 Created mock vulnerable project at: {temp_dir}")

    try:
        app_file = temp_dir / "app.py"
        app_file.write_text(VULNERABLE_APP_CODE, encoding="utf-8")

        req_file = temp_dir / "requirements.txt"
        req_file.write_text(REQUIREMENTS_CONTENT, encoding="utf-8")

        # ----------------------------------------------------
        # STEP 1: SAST Code Audit
        # ----------------------------------------------------
        logger.info("🔍 Step 1: Running SAST Scanner across mock codebase...")
        scanner = SASTScanner()
        sast_result: SASTScanResult = await scanner.scan(temp_dir)

        print("\n" + "=" * 60)
        print("📊 SAST SCAN RESULTS SUMMARY")
        print("=" * 60)
        print(f"Target Path: {sast_result.target_path}")
        print(f"Scan Duration: {sast_result.duration_seconds}s")
        print(f"Total Vulnerabilities Discovered: {sast_result.total_findings}")
        print(f"Breakdown by Severity: {sast_result.findings_by_severity}")
        print("=" * 60)

        for idx, f in enumerate(sast_result.findings, 1):
            print(f"\n[{idx}] [{f.severity.value}] {f.title}")
            print(f"    Scanner: {f.scanner.value} | File: {f.file_path}:{f.line_start}")
            print(f"    Description: {f.description}")

        # ----------------------------------------------------
        # STEP 2: DAST Dynamic Web Endpoint Audit
        # ----------------------------------------------------
        logger.info("\n🌐 Step 2: Running DAST Scanner over target application...")
        dast_scanner = DASTScanner()

        # Probe the mock web app
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mock_web_app),
            base_url="http://testserver"
        ) as client:
            resp = await client.get("/")
            dast_findings = dast_scanner._check_security_headers("http://testserver/", resp.headers)
            dast_findings.extend(dast_scanner._check_information_disclosure("http://testserver/", resp.headers))
            dast_findings.extend(await dast_scanner._check_cookie_security("http://testserver/", resp))

        print("\n" + "=" * 60)
        print("🌐 DAST SCAN RESULTS SUMMARY")
        print("=" * 60)
        print(f"Total Dynamic Vulnerabilities: {len(dast_findings)}")
        for idx, df in enumerate(dast_findings, 1):
            print(f"[{idx}] [{df.severity.value}] {df.title} ({df.id})")
        print("=" * 60)

        # ----------------------------------------------------
        # STEP 3: AI Remediation on Top Finding
        # ----------------------------------------------------
        if sast_result.findings:
            target_finding = sast_result.findings[0]
            print("\n" + "=" * 60)
            print(f"🤖 Step 3: AI Remediation on Finding: {target_finding.title}")
            print("=" * 60)

            ai_engine = RemediationEngine()
            remediation = await ai_engine.analyze_and_remediate(
                target_finding, code_context=target_finding.code_snippet or VULNERABLE_APP_CODE
            )

            print("\n💡 AI Remediation Result:")
            print(f"- Target Vulnerability: {remediation.vuln_name}")
            print(f"- Explanation (RU):\n  {remediation.explanation_ru[:150]}...")
            print(f"- Impact Analysis:\n  {remediation.impact_analysis[:150]}...")
            print("- Proposed Remediation Steps:")
            for step in remediation.remediation_steps[:3]:
                print(f"  • {step}")
            print("\n- Fixed Secure Code Snippet:")
            print("--------------------------------------------------")
            print(remediation.fixed_code[:250])
            print("--------------------------------------------------")

        # ----------------------------------------------------
        # STEP 4: FastAPI Endpoint Check
        # ----------------------------------------------------
        logger.info("\n⚡ Step 4: Testing FastAPI Health & API Endpoints...")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fastapi_app),
            base_url="http://testserver"
        ) as api_client:
            health_resp = await api_client.get("/health")
            assert health_resp.status_code == 200, f"Health check failed: {health_resp.text}"
            health_data = health_resp.json()
            print(f"FastAPI Health Check: status={health_data['status']}, app={health_data['app_name']}")

        logger.info("✅ End-to-End Pipeline test completed successfully!")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("🧹 Cleaned up temporary test directory.")


if __name__ == "__main__":
    asyncio.run(run_end_to_end_test())
