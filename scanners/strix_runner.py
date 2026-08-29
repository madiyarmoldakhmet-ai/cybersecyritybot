"""
Strix Engine Runner for CyberSecurityBot.
Deep AI Agentic Pentest & Multi-Agent Code Security Analysis.
Licensed under Apache-2.0 (Powered by Strix Engine).
Configured for local Ollama LLM (qwen2.5-coder:14b / 7b).
"""

import asyncio
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from openai import AsyncOpenAI

from core.config import settings
from scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("cybersecuritybot.strix_runner")

# Target extensions for deep agentic reasoning
AUDIT_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".dart", ".env", ".json", ".yaml",
    ".yml", ".rules", ".html", ".sh", ".sql"
}

# Directories to skip during code collection
SKIP_DIRS: Set[str] = {
    ".git", "node_modules", ".venv", "venv",
    "__pycache__", "build", "dist", ".dart_tool",
    ".idea", ".vscode", "site-packages"
}

STRIX_AGENT_SYSTEM_PROMPT = """
You are Strix Engine — an advanced autonomous AI penetration testing and security analysis agent (Apache-2.0).
Your mission is to perform deep static and dynamic logic-flaw analysis on the provided source code repository.
Look for:
1. Authentication & Authorization bypass (IDOR, broken object level auth, JWT flaws, session leaks)
2. Injection vulnerabilities (SQLi, NoSQLi, Command Injection, Template Injection, AST eval)
3. Cryptographic and Secret Exposure (Hardcoded API keys, private keys, insecure SSL/TLS configurations)
4. Business Logic Flaws & State Machine bypasses
5. Mobile & Cloud Misconfigurations (Firebase Firestore open rules, insecure intent filters, CORS reflection)

CRITICAL: Return output strictly as a JSON array of vulnerability finding objects.
Format:
[
  {
    "id": "STRIX-VULN-001",
    "title": "Clear concise vulnerability title",
    "description": "Comprehensive explanation of the vulnerability and attack vector",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
    "file_path": "path/to/file.ext",
    "line_start": 10,
    "line_end": 25,
    "code_snippet": "vulnerable code block",
    "cwe": ["CWE-89"],
    "cve": [],
    "recommendation": "Concrete remediation advice and how to fix it securely"
  }
]
Return ONLY raw JSON, with no markdown fences, no conversational text.
"""


class StrixEngine:
    """
    Asynchronous Strix Pentest & Agentic Security Engine.
    Executes deep multi-agent vulnerability discovery on target repositories using local Ollama.
    """

    def __init__(
        self,
        ollama_base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_seconds: int = 180,
    ) -> None:
        # LLM Endpoint configured for local Ollama
        self.ollama_base_url = (
            ollama_base_url
            or getattr(settings, "strix_ollama_base_url", "http://localhost:11434/v1")
        )
        self.model_name = (
            model_name
            or getattr(settings, "strix_model", "qwen2.5-coder:14b")
            or settings.ollama_model
        )
        self.timeout_seconds = timeout_seconds

        self.client = AsyncOpenAI(
            base_url=self.ollama_base_url,
            api_key="ollama",
            timeout=float(self.timeout_seconds),
            max_retries=2,
        )

    def _collect_repository_code(
        self, repo_dir: Path, max_files: int = 30, max_total_bytes: int = 120_000
    ) -> List[Dict[str, str]]:
        """Collect source code files from repository for deep agent analysis."""
        collected: List[Dict[str, str]] = []
        total_bytes = 0

        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

            for file in sorted(files):
                if file.startswith("."):
                    continue

                file_path = Path(root) / file
                ext = file_path.suffix.lower()

                if ext in AUDIT_EXTENSIONS or file in {".env", "Dockerfile", "firebase.json"}:
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="replace")
                        rel_path = file_path.relative_to(repo_dir).as_posix()

                        # Skip minified/huge files
                        if len(content) > 30_000:
                            content = content[:30_000] + "\n# ... [Truncated by Strix Engine]"

                        collected.append({"file_path": rel_path, "content": content})
                        total_bytes += len(content)

                        if len(collected) >= max_files or total_bytes >= max_total_bytes:
                            break
                    except Exception as e:
                        logger.debug(f"Failed to read {file_path}: {e}")

            if len(collected) >= max_files or total_bytes >= max_total_bytes:
                break

        return collected

    async def _run_cli_if_available(self, repo_dir: Path) -> Optional[List[VulnerabilityFinding]]:
        """Attempt to run official strix CLI binary if installed in environment."""
        strix_bin = shutil.which("strix")
        if not strix_bin:
            return None

        logger.info(f"Found strix CLI at {strix_bin}. Executing deep scan on {repo_dir}...")
        env = os.environ.copy()
        env["OPENAI_API_BASE"] = self.ollama_base_url
        env["OPENAI_BASE_URL"] = self.ollama_base_url
        env["OPENAI_API_KEY"] = "ollama"
        env["STRIX_LLM"] = f"ollama/{self.model_name}"
        env["LLM_MODEL"] = self.model_name

        try:
            cmd = [
                strix_bin,
                "-t", str(repo_dir),
                "-n",
                "--scan-mode", "deep",
                "--scope-mode", "full",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=float(self.timeout_seconds)
            )

            out_text = stdout.decode("utf-8", errors="replace")
            findings = self._parse_strix_output(out_text, repo_dir)
            if findings:
                return findings
        except Exception as ex:
            logger.warning(f"Strix CLI execution returned or failed: {ex}. Falling back to internal agentic runner.")

        return None

    def _parse_strix_output(self, raw_output: str, repo_dir: Path) -> List[VulnerabilityFinding]:
        """Parse JSON or text findings from Strix Agent output."""
        findings: List[VulnerabilityFinding] = []
        cleaned = raw_output.strip()

        # Handle markdown fences
        if "```json" in cleaned:
            parts = cleaned.split("```json")
            if len(parts) > 1:
                cleaned = parts[1].split("```")[0].strip()
        elif "```" in cleaned:
            parts = cleaned.split("```")
            if len(parts) > 1:
                cleaned = parts[1].split("```")[0].strip()

        try:
            # Look for JSON array in text
            start_idx = cleaned.find("[")
            end_idx = cleaned.rfind("]")
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                json_str = cleaned[start_idx : end_idx + 1]
                data = json.loads(json_str)

                if isinstance(data, list):
                    for idx, item in enumerate(data):
                        if not isinstance(item, dict):
                            continue

                        sev_str = str(item.get("severity", "HIGH")).upper()
                        try:
                            sev = Severity(sev_str)
                        except ValueError:
                            sev = Severity.HIGH

                        findings.append(
                            VulnerabilityFinding(
                                id=str(item.get("id") or f"STRIX-{idx+1:03d}"),
                                scanner=ScannerType.STRIX,
                                title=str(item.get("title") or "Strix Agent Identified Vulnerability"),
                                description=str(item.get("description") or "Discovered by deep agentic analysis."),
                                severity=sev,
                                file_path=str(item.get("file_path") or "repository"),
                                line_start=item.get("line_start") or 1,
                                line_end=item.get("line_end") or item.get("line_start") or 1,
                                code_snippet=item.get("code_snippet") or "",
                                cwe=item.get("cwe") if isinstance(item.get("cwe"), list) else ([str(item.get("cwe"))] if item.get("cwe") else ["CWE-699"]),
                                cve=item.get("cve") if isinstance(item.get("cve"), list) else [],
                                recommendation=str(item.get("recommendation") or "Implement defensive input validation and least privilege principles."),
                                raw_metadata={"engine": "strix", "license": "Apache-2.0", "item": item},
                            )
                        )
        except Exception as parse_err:
            logger.debug(f"Failed to parse JSON findings from Strix: {parse_err}")

        return findings

    async def _run_agentic_scan(self, repo_dir: Path) -> List[VulnerabilityFinding]:
        """Execute deep multi-agent analysis directly through local Ollama."""
        code_files = self._collect_repository_code(repo_dir)
        if not code_files:
            logger.info("No supported code files found in repository for Strix deep scan.")
            return []

        # Prepare codebase bundle prompt
        code_summary = []
        for file_info in code_files:
            code_summary.append(
                f"### File: `{file_info['file_path']}`\n"
                f"```\n{file_info['content']}\n```\n"
            )

        user_prompt = (
            f"Target Repository Directory: {repo_dir.name}\n"
            f"Total Files Analyzed: {len(code_files)}\n\n"
            "Below is the source code of the application. Perform an exhaustive penetration testing and code security review.\n"
            "Identify real exploitable flaws, logic bugs, insecure configurations, or dangerous sink calls.\n\n"
            + "\n".join(code_summary)
            + "\n\nReturn the identified findings strictly in the requested JSON format."
        )

        try:
            logger.info(f"Calling Ollama model {self.model_name} at {self.ollama_base_url} for Strix Deep Pentest...")
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": STRIX_AGENT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                max_tokens=2500,
            )
            raw_text = response.choices[0].message.content or ""
            return self._parse_strix_output(raw_text, repo_dir)
        except Exception as e:
            logger.error(f"Strix Agentic LLM execution failed: {e}")
            return []

    async def scan(self, repo_dir: Path) -> SASTScanResult:
        """
        Execute full Strix Deep Pentest on target directory.
        Returns standardized SASTScanResult with ScannerType.STRIX.
        """
        start_time = time.time()
        findings: List[VulnerabilityFinding] = []
        errors: List[str] = []

        target_path = Path(repo_dir).resolve()
        if not target_path.exists():
            return SASTScanResult(
                target_path=str(target_path),
                total_findings=0,
                findings_by_severity={},
                findings=[],
                duration_seconds=0.0,
                scanners_run=[ScannerType.STRIX],
                errors=[f"Target path does not exist: {target_path}"],
            )

        # 1. Try CLI first if present
        try:
            cli_findings = await self._run_cli_if_available(target_path)
            if cli_findings is not None:
                findings = cli_findings
        except Exception as ex:
            logger.debug(f"CLI check error: {ex}")

        # 2. Fall back to internal Agentic LLM pipeline
        if not findings:
            try:
                agent_findings = await self._run_agentic_scan(target_path)
                findings.extend(agent_findings)
            except Exception as e:
                err_msg = f"Strix deep scan error: {str(e)}"
                logger.exception(err_msg)
                errors.append(err_msg)

        duration = round(time.time() - start_time, 2)

        # Compute severity breakdown
        severity_counts: Dict[Severity, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return SASTScanResult(
            target_path=str(target_path),
            total_findings=len(findings),
            findings_by_severity=severity_counts,
            findings=findings,
            duration_seconds=duration,
            scanners_run=[ScannerType.STRIX],
            errors=errors,
        )
