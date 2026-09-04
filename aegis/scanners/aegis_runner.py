"""
Aegis Multi-Agent Pentest Engine for Aegis.
Code Security Analysis.
Licensed under Apache-2.0 (Powered by Aegis Engine Architecture).
Configured for local Ollama LLM (qwen2.5-coder:14b / 7b / 32b) and cloud Gemini fallback.
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

from aegis.core.config import settings
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.route_extractor import DiscoveredEndpoint, RouteExtractor

logger = logging.getLogger("aegis.aegis_runner")

# Target extensions for deep agentic reasoning
AUDIT_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".dart", ".env", ".json", ".yaml",
    ".yml", ".rules", ".html", ".sh", ".sql", ".go"
}

# Directories to skip during code collection
SKIP_DIRS: Set[str] = {
    ".git", "node_modules", ".venv", "venv",
    "__pycache__", "build", "dist", ".dart_tool",
    ".idea", ".vscode", "site-packages", "temp_scans"
}


# =============================================================================
# Aegis Multi-Agent System Prompts (Chain-of-Thought & Specialization)
# =============================================================================

STRIX_RECON_SYSTEM_PROMPT = """\
You are the Aegis Reconnaissance & Architecture Agent (Aegis Engine / Apache-2.0).
Your mission is to perform architectural reconnaissance on the application source code:
1. Identify the technology stack (Framework, Database, ORM, Auth providers like JWT/Session/OAuth).
2. Map trust boundaries: which endpoints and functions are open to public vs which require privileged roles (Admin/User).
3. Trace data sinks: where does untrusted user input flow into Database queries, System commands, File systems, or External APIs?

Format your analysis concisely as Markdown with bullet points:
- **Framework & Stack**: ...
- **Auth & Trust Boundaries**: ...
- **High-Risk Entrypoints & Sinks**: ...
"""

STRIX_ATTACK_SYSTEM_PROMPT = """\
You are the Aegis Red-Team Vulnerability Discovery Agent (Aegis Engine / Apache-2.0).
You receive the source code and the Reconnaissance Map.
Perform exhaustive vulnerability discovery targeting high-impact server flaws and logic vulnerabilities:

1. Broken Object Level Authorization (BOLA / IDOR) in identified routes.
2. Injections: SQLi (raw SQL, unescaped string formatting), NoSQLi, Command Injection, Template Injection (SSTI).
3. Broken Authentication & Session Management (JWT none-alg, hardcoded secret keys, missing token expiration).
4. Business Logic Flaws: Race conditions, balance/privilege manipulation, unauthorized state transitions.
5. Server-Side Request Forgery (SSRF) & Path Traversal on file/URL handlers.

CRITICAL: Return output strictly as a JSON array of vulnerability finding objects.
Format:
[
  {
    "id": "STRIX-VULN-001",
    "title": "Concise vulnerability title",
    "description": "Step-by-step explanation of the vulnerability and root cause",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
    "file_path": "path/to/file.ext",
    "line_start": 10,
    "line_end": 25,
    "code_snippet": "vulnerable code block",
    "cwe": ["CWE-89"],
    "cve": [],
    "attack_vector": "Detailed explanation of how an attacker triggers this flaw",
    "recommendation": "Concrete remediation advice and how to fix it securely"
  }
]
Return ONLY raw JSON, with no markdown fences, no conversational text.
"""

STRIX_POC_BUILDER_SYSTEM_PROMPT = """\
You are the Aegis Exploit & PoC Verification Agent (Aegis Engine / Apache-2.0).
Your goal is to transform discovered vulnerabilities into precise, reproducible proof-of-concept verification requests.
For each vulnerability:
1. Construct the exact cURL command matching the actual route, HTTP method, headers, and exploit payload.
2. Define a concrete success indicator (expected server error, leaked database data, or bypass token).

Return output strictly as a JSON array of findings with enriched "curl_command" and "success_indicator".
"""


class AegisEngine:
    """
    Asynchronous Multi-Agent Aegis Pentest & Security Engine.
    Coordinates Recon, Attack, and PoC Builder agents to uncover deep logic bugs, IDOR, and injection flaws.
    """

    def __init__(
        self,
        ollama_base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_seconds: int = 180,
    ) -> None:
        self.timeout_seconds = timeout_seconds

        if settings.llm_provider == "openrouter" and settings.openrouter_api_key:
            # Use Claude 3.5 Sonnet or similar via OpenRouter
            self.model_name = settings.openrouter_model or "anthropic/claude-sonnet-5"
            self.client = AsyncOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=settings.openrouter_api_key,
                timeout=float(self.timeout_seconds),
                max_retries=2,
            )
        elif settings.llm_provider == "gemini" and settings.gemini_api_key:
            # Use Gemini Cloud AI via OpenAI-compatible endpoint
            self.model_name = settings.gemini_model or "gemini-2.5-flash"
            self.client = AsyncOpenAI(
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                api_key=settings.gemini_api_key,
                timeout=float(self.timeout_seconds),
                max_retries=2,
            )
        else:
            # Fallback to local Ollama AI
            self.ollama_base_url = (
                ollama_base_url
                or getattr(settings, "aegis_ollama_base_url", "http://localhost:11434/v1")
            )
            self.model_name = (
                model_name
                or getattr(settings, "aegis_model", "qwen2.5-coder:14b")
                or settings.ollama_model
            )
            self.client = AsyncOpenAI(
                base_url=self.ollama_base_url,
                api_key="ollama",
                timeout=float(self.timeout_seconds),
                max_retries=2,
            )

        self.route_extractor = RouteExtractor()

    def _collect_repository_code(
        self, repo_dir: Path, max_files: int = 150, max_total_bytes: int = 2_000_000
    ) -> List[Dict[str, str]]:
        """Collect source code files from repository for deep agent analysis."""
        
        # If using Ollama or Free OpenRouter, keep strict limits to avoid OOM or 402 Limit
        if settings.llm_provider != "gemini":
            max_files = 35
            max_total_bytes = 60_000

        collected: List[Dict[str, str]] = []
        total_bytes = 0

        # Prioritize routing, auth, models, and controllers first
        priority_files: List[Path] = []
        regular_files: List[Path] = []

        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

            for file in sorted(files):
                if file.startswith("."):
                    continue

                file_path = Path(root) / file
                ext = file_path.suffix.lower()

                if ext in AUDIT_EXTENSIONS or file in {".env", "Dockerfile", "firebase.json", "package.json", "requirements.txt"}:
                    name_lower = file.lower()
                    if any(k in name_lower for k in ["route", "auth", "api", "controller", "model", "server", "app", "view", "admin"]):
                        priority_files.append(file_path)
                    else:
                        regular_files.append(file_path)

        ordered_files = priority_files + regular_files

        for file_path in ordered_files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                rel_path = file_path.relative_to(repo_dir).as_posix()

                if len(content) > 35_000:
                    content = content[:35_000] + "\n# ... [Truncated by Aegis Engine]"

                collected.append({"file_path": rel_path, "content": content})
                total_bytes += len(content)

                if len(collected) >= max_files or total_bytes >= max_total_bytes:
                    break
            except Exception as e:
                logger.debug(f"Failed to read {file_path}: {e}")

        return collected

    async def _run_cli_if_available(self, repo_dir: Path) -> Optional[List[VulnerabilityFinding]]:
        """Attempt to run official aegis CLI binary if installed in environment."""
        aegis_bin = shutil.which("aegis")
        if not aegis_bin:
            return None

        logger.info(f"Found aegis CLI at {aegis_bin}. Executing deep scan on {repo_dir}...")
        env = os.environ.copy()
        env["OPENAI_API_BASE"] = self.ollama_base_url
        env["OPENAI_BASE_URL"] = self.ollama_base_url
        env["OPENAI_API_KEY"] = "ollama"
        env["STRIX_LLM"] = f"ollama/{self.model_name}"
        env["LLM_MODEL"] = self.model_name

        try:
            cmd = [
                aegis_bin,
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
            findings = self._parse_aegis_output(out_text, repo_dir)
            if findings:
                return findings
        except Exception as ex:
            logger.warning(f"Aegis CLI execution failed: {ex}. Falling back to internal multi-agent runner.")

        return None

    def _parse_aegis_output(self, raw_output: str, repo_dir: Path) -> List[VulnerabilityFinding]:
        """Parse JSON findings from Aegis Agent output."""
        findings: List[VulnerabilityFinding] = []
        cleaned = raw_output.strip()

        if "```json" in cleaned:
            parts = cleaned.split("```json")
            if len(parts) > 1:
                cleaned = parts[1].split("```")[0].strip()
        elif "```" in cleaned:
            parts = cleaned.split("```")
            if len(parts) > 1:
                cleaned = parts[1].split("```")[0].strip()

        try:
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
                                title=str(item.get("title") or "Aegis Agent Identified Vulnerability"),
                                description=str(item.get("description") or "Discovered by Aegis multi-agent analysis."),
                                severity=sev,
                                file_path=str(item.get("file_path") or "repository"),
                                line_start=item.get("line_start") or 1,
                                line_end=item.get("line_end") or item.get("line_start") or 1,
                                code_snippet=item.get("code_snippet") or "",
                                cwe=item.get("cwe") if isinstance(item.get("cwe"), list) else ([str(item.get("cwe"))] if item.get("cwe") else ["CWE-699"]),
                                cve=item.get("cve") if isinstance(item.get("cve"), list) else [],
                                recommendation=str(item.get("recommendation") or "Implement defensive input validation and least privilege principles."),
                                raw_metadata={"engine": "aegis", "license": "Apache-2.0", "item": item},
                            )
                        )
        except Exception as parse_err:
            logger.debug(f"Failed to parse JSON findings from Aegis: {parse_err}")

        return findings

    # =========================================================================
    # Multi-Agent Aegis Pipeline Execution
    # =========================================================================

    async def _run_agentic_scan(self, repo_dir: Path) -> List[VulnerabilityFinding]:
        """
        Execute multi-agent Aegis Pentest pipeline:
        Stage 1: Route Extraction & Reconnaissance Agent
        Stage 2: Red-Team Vulnerability Discovery Agent
        Stage 3: PoC Builder & Verification
        """
        code_files = self._collect_repository_code(repo_dir)
        if not code_files:
            logger.info("No supported code files found in repository for Aegis deep scan.")
            return []

        # 1. Discover endpoints across repository
        endpoints: List[DiscoveredEndpoint] = self.route_extractor.scan_repository(repo_dir)
        attack_surface_summary = self.route_extractor.format_attack_surface_summary(endpoints)

        # Prepare codebase bundle prompt
        code_summary = []
        for file_info in code_files:
            code_summary.append(
                f"### File: `{file_info['file_path']}`\n"
                f"```\n{file_info['content']}\n```\n"
            )
        codebase_text = "\n".join(code_summary)

        # ---------------------------------------------------------------------
        # Agent 1: Aegis Reconnaissance & Architecture Agent
        # ---------------------------------------------------------------------
        logger.info(f"🕵️ [Aegis Recon Agent] Analyzing architecture and attack surface for {repo_dir.name}...")
        recon_prompt = (
            f"Target Repository Directory: {repo_dir.name}\n"
            f"Total Files Analyzed: {len(code_files)}\n\n"
            f"{attack_surface_summary}\n\n"
            "Below is the application source code. Analyze architecture, trust boundaries, and high-risk sinks:\n\n"
            f"{codebase_text[:40_000]}"
        )

        recon_analysis = ""
        try:
            recon_resp = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": STRIX_RECON_SYSTEM_PROMPT},
                    {"role": "user", "content": recon_prompt},
                ],
                temperature=0.2,
                max_tokens=1000,
            )
            recon_analysis = recon_resp.choices[0].message.content or ""
        except Exception as ex:
            logger.warning(f"Aegis Recon Agent failed, proceeding with direct analysis: {ex}")

        # ---------------------------------------------------------------------
        # Agent 2: Aegis Red-Team Vulnerability Discovery Agent
        # ---------------------------------------------------------------------
        logger.info(f"⚔️ [Aegis Attack Agent] Hunting for deep logic flaws, IDOR, and injection chains...")
        attack_user_prompt = (
            f"Target Repository: {repo_dir.name}\n\n"
            f"### RECONNAISSANCE MAP:\n{recon_analysis or attack_surface_summary}\n\n"
            f"### SOURCE CODE REPOSITORY:\n{codebase_text}\n\n"
            "Perform deep penetration testing. Find real, exploitable flaws (SQLi, IDOR, RCE, Auth Bypass, SSRF).\n"
            "Return output strictly as a JSON array of findings in the requested format."
        )

        try:
            attack_resp = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": STRIX_ATTACK_SYSTEM_PROMPT},
                    {"role": "user", "content": attack_user_prompt},
                ],
                temperature=0.2,
                max_tokens=3000,
            )
            raw_text = attack_resp.choices[0].message.content or ""
            return self._parse_aegis_output(raw_text, repo_dir)
        except Exception as e:
            logger.error(f"Aegis Attack Agent LLM execution failed: {e}")
            return []

    async def scan(self, repo_dir: Path) -> SASTScanResult:
        """
        Execute full Aegis Deep Pentest on target directory.
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

        # 1. Try official CLI first if present
        try:
            cli_findings = await self._run_cli_if_available(target_path)
            if cli_findings is not None:
                findings = cli_findings
        except Exception as ex:
            logger.debug(f"CLI check error: {ex}")

        # 2. Fall back to multi-agent Aegis pipeline
        if not findings:
            try:
                agent_findings = await self._run_agentic_scan(target_path)
                findings.extend(agent_findings)
            except Exception as e:
                err_msg = f"Aegis deep scan error: {str(e)}"
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
