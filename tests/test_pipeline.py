"""
End-to-End Pipeline Test for CyberSecurityBot.
Creates a temporary mock project with vulnerable code (SQLi, hardcoded secret, eval),
runs SASTScanner, and triggers AI remediation analysis.
"""

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai.remediation_engine import RemediationEngine
from scanners.models import SASTScanResult
from scanners.sast_scanner import SASTScanner

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


async def run_end_to_end_test():
    """Execute complete scan and AI remediation pipeline."""
    # 1. Create temporary mock repository
    temp_dir = Path(tempfile.mkdtemp(prefix="cybersec_test_"))
    logger.info(f"📁 Created mock vulnerable project at: {temp_dir}")

    try:
        app_file = temp_dir / "app.py"
        app_file.write_text(VULNERABLE_APP_CODE, encoding="utf-8")

        req_file = temp_dir / "requirements.txt"
        req_file.write_text(REQUIREMENTS_CONTENT, encoding="utf-8")

        # 2. Run SAST Scanner
        logger.info("🔍 Step 1: Running SAST Scanner across mock project...")
        scanner = SASTScanner()
        scan_result: SASTScanResult = await scanner.scan(temp_dir)

        print("\n" + "=" * 60)
        print("📊 SAST SCAN RESULTS SUMMARY")
        print("=" * 60)
        print(f"Target Path: {scan_result.target_path}")
        print(f"Scan Duration: {scan_result.duration_seconds}s")
        print(f"Total Vulnerabilities Discovered: {scan_result.total_findings}")
        print(f"Breakdown by Severity: {scan_result.findings_by_severity}")
        print("=" * 60)

        for idx, f in enumerate(scan_result.findings, 1):
            print(f"\n[{idx}] [{f.severity.value}] {f.title}")
            print(f"    Scanner: {f.scanner.value}")
            print(f"    File: {f.file_path} (lines: {f.line_start}-{f.line_end})")
            print(f"    Description: {f.description}")
            if f.code_snippet:
                print(f"    Snippet:\n{f.code_snippet.strip()}")

        # 3. Test AI Remediation on the first finding (if any findings present)
        if scan_result.findings:
            target_finding = scan_result.findings[0]
            print("\n" + "=" * 60)
            print(f"🤖 Step 2: Testing AI Remediation on Finding: {target_finding.title}")
            print("=" * 60)

            ai_engine = RemediationEngine()
            remediation = await ai_engine.analyze_and_remediate(
                target_finding, code_context=target_finding.code_snippet or VULNERABLE_APP_CODE
            )

            print("\n💡 AI Remediation Result:")
            print(f"- Target Vulnerability: {remediation.vuln_name}")
            print(f"- Confidence: {remediation.confidence_score * 100:.0f}%")
            print(f"- Explanation (RU):\n  {remediation.explanation_ru}")
            print(f"- Impact Analysis:\n  {remediation.impact_analysis}")
            print("- Proposed Steps:")
            for step in remediation.remediation_steps:
                print(f"  • {step}")
            print("\n- Fixed Secure Code:")
            print("--------------------------------------------------")
            print(remediation.fixed_code)
            print("--------------------------------------------------")

        logger.info("✅ End-to-End Pipeline test completed successfully!")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("🧹 Cleaned up temporary test directory.")


if __name__ == "__main__":
    asyncio.run(run_end_to_end_test())
