"""
SAST Scanner Engine for CyberSecurityBot.
Executes static application security testing (AST Analyzer, Semgrep, Bandit) and dependency vulnerability checks (Pip-Audit).
Normalized findings are produced for subsequent AI analysis and auto-remediation.
"""

import ast
import asyncio
import json
import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from core.config import settings
from scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("cybersecuritybot.sast_scanner")
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))


class PythonASTSecurityVisitor(ast.NodeVisitor):
    """AST Visitor that inspects Python AST for critical security patterns."""

    def __init__(self, file_path: Path, file_content: str) -> None:
        self.file_path = file_path
        self.file_content = file_content
        self.lines = file_content.splitlines()
        self.findings: List[VulnerabilityFinding] = []

    def _get_snippet(self, start_line: int, end_line: Optional[int] = None) -> str:
        end = end_line or start_line
        selected = self.lines[max(0, start_line - 1): min(len(self.lines), end)]
        return "\n".join(selected)

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check for hardcoded API keys or passwords
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                is_secret_name = any(
                    k in var_name for k in ["secret", "api_key", "token", "password", "priv_key"]
                )
                if is_secret_name and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    if len(val) > 8 and not val.startswith("ENV_") and not val.startswith("${"):
                        self.findings.append(
                            VulnerabilityFinding(
                                id="hardcoded-secret",
                                scanner=ScannerType.CUSTOM,
                                title="Hardcoded Sensitive Credential or Secret",
                                description=f"Variable '{target.id}' contains a hardcoded plaintext secret.",
                                severity=Severity.HIGH,
                                file_path=str(self.file_path),
                                line_start=node.lineno,
                                line_end=node.end_lineno or node.lineno,
                                code_snippet=self._get_snippet(node.lineno, node.end_lineno),
                                cwe=["CWE-798"],
                                cve=[],
                                recommendation="Move sensitive credentials to environment variables or a secrets manager."
                            )
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # 1. Insecure eval() / exec()
        if func_name in ["eval", "exec"]:
            self.findings.append(
                VulnerabilityFinding(
                    id="dynamic-code-eval",
                    scanner=ScannerType.CUSTOM,
                    title=f"Insecure Dynamic Code Execution via {func_name}()",
                    description=f"Use of {func_name}() with dynamic input can lead to Arbitrary Code Execution.",
                    severity=Severity.HIGH,
                    file_path=str(self.file_path),
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    code_snippet=self._get_snippet(node.lineno, node.end_lineno),
                    cwe=["CWE-95"],
                    cve=[],
                    recommendation=f"Avoid using {func_name}(). Use safer alternatives (e.g. ast.literal_eval or dedicated parsers)."
                )
            )

        # 2. SQL Injection in cursor.execute()
        if func_name == "execute" and node.args:
            first_arg = node.args[0]
            # Check if string concatenation or f-string is used in SQL query
            is_dynamic_sql = isinstance(first_arg, (ast.BinOp, ast.JoinedStr))
            if is_dynamic_sql:
                self.findings.append(
                    VulnerabilityFinding(
                        id="sql-injection-dynamic-query",
                        scanner=ScannerType.CUSTOM,
                        title="Potential SQL Injection via Dynamic Query Construction",
                        description="SQL query is assembled via string concatenation/formatting instead of parameterized placeholders.",
                        severity=Severity.CRITICAL,
                        file_path=str(self.file_path),
                        line_start=node.lineno,
                        line_end=node.end_lineno or node.lineno,
                        code_snippet=self._get_snippet(node.lineno, node.end_lineno),
                        cwe=["CWE-89"],
                        cve=[],
                        recommendation="Use parameterized queries (e.g., cursor.execute('SELECT ... WHERE id = ?', (user_id,)))"
                    )
                )

        # 3. Insecure subprocess with shell=True
        if func_name in ["Popen", "run", "call", "check_output"]:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        VulnerabilityFinding(
                            id="subprocess-shell-true",
                            scanner=ScannerType.CUSTOM,
                            title="Command Injection Risk via subprocess shell=True",
                            description="subprocess invoked with shell=True can allow arbitrary command injection if arguments contain user input.",
                            severity=Severity.HIGH,
                            file_path=str(self.file_path),
                            line_start=node.lineno,
                            line_end=node.end_lineno or node.lineno,
                            code_snippet=self._get_snippet(node.lineno, node.end_lineno),
                            cwe=["CWE-78"],
                            cve=[],
                            recommendation="Set shell=False and pass command arguments as a list of strings."
                        )
                    )

        # 4. Insecure deserialization with pickle
        if func_name in ["loads", "load"] and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                self.findings.append(
                    VulnerabilityFinding(
                        id="insecure-pickle-deserialization",
                        scanner=ScannerType.CUSTOM,
                        title="Insecure Deserialization via pickle",
                        description="Unpickling untrusted data can lead to Remote Code Execution.",
                        severity=Severity.CRITICAL,
                        file_path=str(self.file_path),
                        line_start=node.lineno,
                        line_end=node.end_lineno or node.lineno,
                        code_snippet=self._get_snippet(node.lineno, node.end_lineno),
                        cwe=["CWE-502"],
                        cve=[],
                        recommendation="Use safe serialization formats like JSON, MessagePack, or Protocol Buffers."
                    )
                )

        self.generic_visit(node)


class SASTScanner:
    """Orchestrates static analysis tools and dependency vulnerability scanners."""

    def __init__(
        self,
        semgrep_config: Optional[str] = None,
        timeout_seconds: Optional[int] = None
    ) -> None:
        self.semgrep_config = semgrep_config or settings.semgrep_config
        self.timeout_seconds = timeout_seconds or settings.scan_timeout_seconds

    async def _run_command(
        self, cmd: List[str], cwd: Optional[Path] = None
    ) -> Tuple[int, str, str]:
        """Execute an asynchronous subprocess with safety timeouts."""
        cmd_str = " ".join(cmd)
        logger.debug(f"Executing scanner command: {cmd_str} in {cwd or os.getcwd()}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout_seconds
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            return process.returncode or 0, stdout_str, stderr_str

        except asyncio.TimeoutError:
            logger.error(f"Command timed out after {self.timeout_seconds}s: {cmd_str}")
            try:
                process.kill()
            except Exception:
                pass
            return -1, "", f"Timeout error after {self.timeout_seconds} seconds"
        except FileNotFoundError as fnf:
            return -2, "", f"Binary '{cmd[0]}' is not installed or not in PATH"
        except Exception as ex:
            return -3, "", str(ex)

    def _normalize_semgrep_severity(self, semgrep_sev: str) -> Severity:
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
            "INVENTORY": Severity.INFO,
            "EXPERIMENT": Severity.INFO,
        }
        return mapping.get(semgrep_sev.upper(), Severity.MEDIUM)

    def _normalize_bandit_severity(self, bandit_sev: str) -> Severity:
        mapping = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "UNDEFINED": Severity.INFO,
        }
        return mapping.get(bandit_sev.upper(), Severity.LOW)

    async def run_ast_analyzer(self, target_path: Path) -> List[VulnerabilityFinding]:
        """Analyze Python files using built-in AST security visitor."""
        findings: List[VulnerabilityFinding] = []
        py_files = list(target_path.glob("**/*.py"))

        for py_file in py_files:
            # Skip virtual environments and hidden paths
            if any(part.startswith(".") or part in ["venv", "env", ".venv"] for part in py_file.parts):
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content, filename=str(py_file))
                visitor = PythonASTSecurityVisitor(py_file, content)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except Exception as e:
                logger.debug(f"AST parsing skipped for {py_file}: {e}")

        return findings

    async def run_semgrep(self, target_path: Path) -> Tuple[List[VulnerabilityFinding], Optional[str]]:
        """Run Semgrep SAST scan over the target directory."""
        if not shutil.which("semgrep"):
            return [], "Semgrep binary not found in PATH."

        cmd = [
            "semgrep",
            "scan",
            f"--config={self.semgrep_config}",
            "--json",
            "--quiet",
            "--no-git-ignore",
            str(target_path.resolve()),
        ]

        retcode, stdout, stderr = await self._run_command(cmd)
        if not stdout.strip():
            return [], stderr.strip() or None

        findings: List[VulnerabilityFinding] = []
        try:
            data = json.loads(stdout)
            for res in data.get("results", []):
                check_id = res.get("check_id", "semgrep-finding")
                extra = res.get("extra", {})
                message = extra.get("message", "No description provided.")
                raw_severity = extra.get("severity", "WARNING")
                metadata = extra.get("metadata", {})

                raw_cwe = metadata.get("cwe", [])
                cwe_list = raw_cwe if isinstance(raw_cwe, list) else [str(raw_cwe)] if raw_cwe else []
                raw_cve = metadata.get("cve", [])
                cve_list = raw_cve if isinstance(raw_cve, list) else [str(raw_cve)] if raw_cve else []

                finding = VulnerabilityFinding(
                    id=check_id,
                    scanner=ScannerType.SEMGREP,
                    title=f"Semgrep: {check_id.split('.')[-1]}",
                    description=message,
                    severity=self._normalize_semgrep_severity(raw_severity),
                    file_path=res.get("path", str(target_path)),
                    line_start=res.get("start", {}).get("line"),
                    line_end=res.get("end", {}).get("line"),
                    code_snippet=extra.get("lines", None),
                    cwe=cwe_list,
                    cve=cve_list,
                    recommendation=metadata.get("fix", metadata.get("shortlink", None)),
                    raw_metadata=extra
                )
                findings.append(finding)
            return findings, None
        except Exception as e:
            return [], f"Semgrep parse error: {e}"

    async def run_bandit(self, target_path: Path) -> Tuple[List[VulnerabilityFinding], Optional[str]]:
        """Run Bandit security linter for Python files."""
        if not shutil.which("bandit"):
            return [], "Bandit binary not found in PATH."

        cmd = ["bandit", "-r", str(target_path.resolve()), "-f", "json", "-q"]
        retcode, stdout, stderr = await self._run_command(cmd)
        if not stdout.strip():
            return [], stderr.strip() or None

        findings: List[VulnerabilityFinding] = []
        try:
            data = json.loads(stdout)
            for res in data.get("results", []):
                test_id = res.get("test_id", "B000")
                test_name = res.get("test_name", "bandit_issue")
                cwe = []
                cwe_info = res.get("issue_cwe", {})
                if isinstance(cwe_info, dict) and "id" in cwe_info:
                    cwe.append(f"CWE-{cwe_info['id']}")

                finding = VulnerabilityFinding(
                    id=f"bandit.{test_id}",
                    scanner=ScannerType.BANDIT,
                    title=f"Bandit [{test_id}]: {test_name}",
                    description=res.get("issue_text", ""),
                    severity=self._normalize_bandit_severity(res.get("issue_severity", "LOW")),
                    file_path=res.get("filename", str(target_path)),
                    line_start=res.get("line_number"),
                    line_end=res.get("line_number"),
                    code_snippet=res.get("code"),
                    cwe=cwe,
                    cve=[],
                    recommendation=f"Reference: {res.get('more_info')}" if res.get("more_info") else None,
                    raw_metadata=res
                )
                findings.append(finding)
            return findings, None
        except Exception as e:
            return [], f"Bandit parse error: {e}"

    async def run_pip_audit(self, target_path: Path) -> Tuple[List[VulnerabilityFinding], Optional[str]]:
        """Run pip-audit on requirements files."""
        if not shutil.which("pip-audit"):
            return [], "pip-audit binary not found in PATH."

        req_files = list(target_path.glob("**/requirements*.txt"))
        if not req_files:
            return [], None

        all_findings: List[VulnerabilityFinding] = []
        for req_file in req_files:
            cmd = ["pip-audit", "-r", str(req_file.resolve()), "-f", "json", "--desc"]
            retcode, stdout, stderr = await self._run_command(cmd)
            if not stdout.strip():
                continue
            try:
                data = json.loads(stdout)
                dep_list = data if isinstance(data, list) else data.get("dependencies", [])
                for dep in dep_list:
                    pkg_name = dep.get("name", "unknown")
                    pkg_version = dep.get("version", "unknown")
                    for v in dep.get("vulns", []):
                        vuln_id = v.get("id", "VULN-000")
                        all_findings.append(
                            VulnerabilityFinding(
                                id=vuln_id,
                                scanner=ScannerType.PIP_AUDIT,
                                title=f"Dependency Vulnerability: {pkg_name} ({pkg_version})",
                                description=v.get("description", f"Vulnerability in {pkg_name}"),
                                severity=Severity.HIGH,
                                file_path=str(req_file.relative_to(target_path) if req_file.is_relative_to(target_path) else req_file),
                                code_snippet=f"{pkg_name}=={pkg_version}",
                                cve=[vuln_id] if vuln_id.startswith("CVE") else [],
                                recommendation=f"Upgrade {pkg_name} to version {', '.join(v.get('fix_versions', []))}",
                                raw_metadata=v
                            )
                        )
            except Exception:
                pass
        return all_findings, None

    async def scan(self, target_path: Union[str, Path]) -> SASTScanResult:
        """Run SAST scanners concurrently and aggregate results."""
        start_time = time.time()
        path = Path(target_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Target path does not exist: {path}")

        logger.info(f"Starting SAST security audit for: {path}")

        # Run built-in AST analyzer and CLI tools concurrently
        ast_task = asyncio.create_task(self.run_ast_analyzer(path))
        semgrep_task = asyncio.create_task(self.run_semgrep(path))
        bandit_task = asyncio.create_task(self.run_bandit(path))
        pip_audit_task = asyncio.create_task(self.run_pip_audit(path))

        ast_findings, (semgrep_findings, semgrep_err), (bandit_findings, bandit_err), (pip_findings, pip_err) = await asyncio.gather(
            ast_task, semgrep_task, bandit_task, pip_audit_task, return_exceptions=False
        )

        # Merge findings, avoiding duplicate IDs on identical lines
        seen_keys = set()
        all_findings: List[VulnerabilityFinding] = []

        for f in (bandit_findings + semgrep_findings + ast_findings + pip_findings):
            key = f"{f.file_path}:{f.line_start}:{f.id}"
            if key not in seen_keys:
                seen_keys.add(key)
                all_findings.append(f)

        errors: List[str] = []
        if semgrep_err:
            errors.append(f"Semgrep: {semgrep_err}")
        if bandit_err:
            errors.append(f"Bandit: {bandit_err}")
        if pip_err:
            errors.append(f"Pip-Audit: {pip_err}")

        severity_counts: Dict[Severity, int] = {sev: 0 for sev in Severity}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        duration = round(time.time() - start_time, 2)
        scanners_run = [ScannerType.CUSTOM, ScannerType.SEMGREP, ScannerType.BANDIT, ScannerType.PIP_AUDIT]

        result = SASTScanResult(
            target_path=str(path),
            total_findings=len(all_findings),
            findings_by_severity=severity_counts,
            findings=all_findings,
            duration_seconds=duration,
            scanners_run=scanners_run,
            errors=errors
        )

        logger.info(
            f"SAST audit completed in {duration}s. "
            f"Discovered {len(all_findings)} total findings across {path.name}."
        )
        return result
