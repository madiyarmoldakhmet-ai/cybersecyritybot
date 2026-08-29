"""
SAST Scanner Engine for CyberSecurityBot.
Executes static application security testing (Semgrep, Bandit) and dependency vulnerability checks (Pip-Audit).
Normalized findings are produced for subsequent AI analysis and auto-remediation.
"""

import asyncio
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from core.config import settings
from scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("cybersecuritybot.sast_scanner")
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))


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
            logger.warning(f"Scanner binary not found: {cmd[0]}: {fnf}")
            return -2, "", f"Binary '{cmd[0]}' is not installed or not in PATH"
        except Exception as ex:
            logger.exception(f"Unexpected error running command '{cmd_str}': {ex}")
            return -3, "", str(ex)

    def _normalize_semgrep_severity(self, semgrep_sev: str) -> Severity:
        """Map Semgrep severity to unified Severity enum."""
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
            "INVENTORY": Severity.INFO,
            "EXPERIMENT": Severity.INFO,
        }
        return mapping.get(semgrep_sev.upper(), Severity.MEDIUM)

    def _normalize_bandit_severity(self, bandit_sev: str) -> Severity:
        """Map Bandit severity to unified Severity enum."""
        mapping = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "UNDEFINED": Severity.INFO,
        }
        return mapping.get(bandit_sev.upper(), Severity.LOW)

    async def run_semgrep(self, target_path: Path) -> Tuple[List[VulnerabilityFinding], Optional[str]]:
        """Run Semgrep SAST scan over the target directory."""
        if not shutil.which("semgrep"):
            return [], "Semgrep executable not found. Please install via 'pip install semgrep'."

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

        findings: List[VulnerabilityFinding] = []
        if not stdout.strip():
            err_msg = stderr.strip() if stderr.strip() else None
            return [], err_msg

        try:
            data = json.loads(stdout)
            results = data.get("results", [])
            for res in results:
                check_id = res.get("check_id", "semgrep-finding")
                extra = res.get("extra", {})
                message = extra.get("message", "No description provided.")
                raw_severity = extra.get("severity", "WARNING")
                metadata = extra.get("metadata", {})

                # Extract CWEs
                raw_cwe = metadata.get("cwe", [])
                cwe_list = raw_cwe if isinstance(raw_cwe, list) else [str(raw_cwe)] if raw_cwe else []

                # Extract CVEs
                raw_cve = metadata.get("cve", [])
                cve_list = raw_cve if isinstance(raw_cve, list) else [str(raw_cve)] if raw_cve else []

                code_snippet = extra.get("lines", None)
                start_line = res.get("start", {}).get("line")
                end_line = res.get("end", {}).get("line")

                finding = VulnerabilityFinding(
                    id=check_id,
                    scanner=ScannerType.SEMGREP,
                    title=f"Semgrep: {check_id.split('.')[-1]}",
                    description=message,
                    severity=self._normalize_semgrep_severity(raw_severity),
                    file_path=res.get("path", str(target_path)),
                    line_start=start_line,
                    line_end=end_line,
                    code_snippet=code_snippet,
                    cwe=cwe_list,
                    cve=cve_list,
                    recommendation=metadata.get("fix", metadata.get("shortlink", None)),
                    raw_metadata=extra
                )
                findings.append(finding)

            return findings, None

        except json.JSONDecodeError as jde:
            logger.error(f"Failed to parse Semgrep JSON output: {jde}. Stdout: {stdout[:300]}")
            return [], f"JSON parse error from Semgrep: {jde}"

    async def run_bandit(self, target_path: Path) -> Tuple[List[VulnerabilityFinding], Optional[str]]:
        """Run Bandit security linter for Python files."""
        if not shutil.which("bandit"):
            return [], "Bandit executable not found. Please install via 'pip install bandit'."

        cmd = [
            "bandit",
            "-r",
            str(target_path.resolve()),
            "-f",
            "json",
            "-q"
        ]

        retcode, stdout, stderr = await self._run_command(cmd)

        findings: List[VulnerabilityFinding] = []
        if not stdout.strip():
            return [], (stderr.strip() if stderr.strip() else None)

        try:
            data = json.loads(stdout)
            results = data.get("results", [])
            for res in results:
                test_id = res.get("test_id", "B000")
                test_name = res.get("test_name", "bandit_issue")
                issue_text = res.get("issue_text", "")
                issue_severity = res.get("issue_severity", "LOW")
                filename = res.get("filename", str(target_path))
                line_num = res.get("line_number")
                code_snippet = res.get("code")
                more_info = res.get("more_info")

                cwe = []
                cwe_info = res.get("issue_cwe", {})
                if isinstance(cwe_info, dict) and "id" in cwe_info:
                    cwe.append(f"CWE-{cwe_info['id']}")

                finding = VulnerabilityFinding(
                    id=f"bandit.{test_id}",
                    scanner=ScannerType.BANDIT,
                    title=f"Bandit [{test_id}]: {test_name}",
                    description=issue_text,
                    severity=self._normalize_bandit_severity(issue_severity),
                    file_path=filename,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=code_snippet,
                    cwe=cwe,
                    cve=[],
                    recommendation=f"Reference: {more_info}" if more_info else None,
                    raw_metadata=res
                )
                findings.append(finding)

            return findings, None

        except json.JSONDecodeError as jde:
            logger.error(f"Failed to parse Bandit JSON output: {jde}. Stdout: {stdout[:300]}")
            return [], f"JSON parse error from Bandit: {jde}"

    async def run_pip_audit(self, target_path: Path) -> Tuple[List[VulnerabilityFinding], Optional[str]]:
        """Run pip-audit on requirement files found within the target path."""
        if not shutil.which("pip-audit"):
            return [], "pip-audit executable not found. Please install via 'pip install pip-audit'."

        req_files = list(target_path.glob("**/requirements*.txt"))
        if not req_files:
            return [], None  # No dependency files to audit

        all_findings: List[VulnerabilityFinding] = []
        errors: List[str] = []

        for req_file in req_files:
            cmd = [
                "pip-audit",
                "-r",
                str(req_file.resolve()),
                "-f",
                "json",
                "--desc"
            ]

            retcode, stdout, stderr = await self._run_command(cmd)

            if not stdout.strip():
                if stderr.strip():
                    errors.append(f"pip-audit error on {req_file.name}: {stderr.strip()}")
                continue

            try:
                data = json.loads(stdout)
                # pip-audit JSON structure: list of dependency items or dict with dependencies key
                dep_list = data if isinstance(data, list) else data.get("dependencies", [])
                for dep in dep_list:
                    pkg_name = dep.get("name", "unknown")
                    pkg_version = dep.get("version", "unknown")
                    vulns = dep.get("vulns", [])

                    for v in vulns:
                        vuln_id = v.get("id", "VULN-000")
                        description = v.get("description", f"Vulnerability in {pkg_name} {pkg_version}")
                        fix_versions = v.get("fix_versions", [])
                        recommendation = (
                            f"Upgrade {pkg_name} to version {', '.join(fix_versions)}"
                            if fix_versions
                            else f"Update or replace {pkg_name}"
                        )

                        finding = VulnerabilityFinding(
                            id=vuln_id,
                            scanner=ScannerType.PIP_AUDIT,
                            title=f"Dependency Vulnerability: {pkg_name} ({pkg_version})",
                            description=description,
                            severity=Severity.HIGH if vuln_id.startswith("CVE") or vuln_id.startswith("GHSA") else Severity.MEDIUM,
                            file_path=str(req_file.relative_to(target_path) if req_file.is_relative_to(target_path) else req_file),
                            line_start=None,
                            line_end=None,
                            code_snippet=f"{pkg_name}=={pkg_version}",
                            cwe=[],
                            cve=[vuln_id] if vuln_id.startswith("CVE") else [],
                            recommendation=recommendation,
                            raw_metadata=v
                        )
                        all_findings.append(finding)

            except json.JSONDecodeError as jde:
                errors.append(f"Failed to parse pip-audit JSON for {req_file.name}: {jde}")

        return all_findings, ("; ".join(errors) if errors else None)

    async def scan(self, target_path: Union[str, Path]) -> SASTScanResult:
        """Run all available SAST scanners concurrently and aggregate results."""
        start_time = time.time()
        path = Path(target_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Target path does not exist: {path}")

        logger.info(f"Starting SAST security audit for: {path}")

        # Run scanners concurrently for maximum DevSecOps speed
        semgrep_task = asyncio.create_task(self.run_semgrep(path))
        bandit_task = asyncio.create_task(self.run_bandit(path))
        pip_audit_task = asyncio.create_task(self.run_pip_audit(path))

        (semgrep_findings, semgrep_err), (bandit_findings, bandit_err), (pip_findings, pip_err) = await asyncio.gather(
            semgrep_task, bandit_task, pip_audit_task, return_exceptions=False
        )

        all_findings: List[VulnerabilityFinding] = []
        all_findings.extend(semgrep_findings)
        all_findings.extend(bandit_findings)
        all_findings.extend(pip_findings)

        errors: List[str] = []
        if semgrep_err:
            errors.append(f"Semgrep: {semgrep_err}")
        if bandit_err:
            errors.append(f"Bandit: {bandit_err}")
        if pip_err:
            errors.append(f"Pip-Audit: {pip_err}")

        # Calculate severity breakdown
        severity_counts: Dict[Severity, int] = {sev: 0 for sev in Severity}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        duration = round(time.time() - start_time, 2)
        scanners_run = [ScannerType.SEMGREP, ScannerType.BANDIT, ScannerType.PIP_AUDIT]

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


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = SASTScanner()
    scan_result = asyncio.run(scanner.scan(target))
    print(scan_result.model_dump_json(indent=2))
