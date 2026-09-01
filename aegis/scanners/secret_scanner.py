import logging
import re
from pathlib import Path
from typing import List
import uuid

from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("aegis.secret_scanner")

class SecretScanner:
    """
    Secret Scanner to find hardcoded tokens, API keys, and passwords using regular expressions.
    """
    
    PATTERNS = {
        "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "Stripe API Key": re.compile(r"[sk|rk]_(?:test|live)_[0-9a-zA-Z]{24}"),
        "GitHub Token": re.compile(r"gh[p|o|u|s|r]_[A-Za-z0-9_]{36}"),
        "RSA Private Key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        "Generic Password": re.compile(r"(?i)(?:password|passwd|pwd|secret)\s*=\s*['\"]([^'\"]+)['\"]"),
        "Generic API Key": re.compile(r"(?i)(?:api_key|apikey|token)\s*=\s*['\"]([^'\"]+)['\"]")
    }

    IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
    IGNORE_EXTENSIONS = {
        ".jpg", ".png", ".gif", ".pdf", ".zip", ".tar", ".gz", ".mp3", ".mp4", ".pyc", ".o", ".so", ".dll", ".exe"
    }

    def __init__(self, event_bus=None):
        self.event_bus = event_bus

    async def _emit(self, event) -> None:
        if self.event_bus:
            try:
                await self.event_bus.emit(event)
            except Exception as e:
                logger.debug(f"Failed to emit event {event.event_type}: {e}")

    async def scan(self, target_dir: Path) -> List[VulnerabilityFinding]:
        findings = []
        target_path = Path(target_dir).resolve()

        if not target_path.exists():
            return findings
            
        from aegis.core.event_bus import FileScanning, CodeAnalyzing, VulnerabilityFound

        for filepath in target_path.rglob("*"):
            if not filepath.is_file():
                continue
            
            if any(part in self.IGNORE_DIRS for part in filepath.parts):
                continue
                
            if filepath.suffix.lower() in self.IGNORE_EXTENSIONS:
                continue

            rel_path = filepath.relative_to(target_path).as_posix()
            await self._emit(FileScanning(file_path=rel_path))

            try:
                content = filepath.read_text(encoding="utf-8")
                await self._emit(CodeAnalyzing(file_path=rel_path, snippet="Scanning for hardcoded secrets..."))
                
                for line_idx, line in enumerate(content.splitlines(), start=1):
                    for secret_type, pattern in self.PATTERNS.items():
                        match = pattern.search(line)
                        if match:
                            snippet = line.strip()
                            if len(snippet) > 200:
                                snippet = snippet[:200] + "..."
                                
                            findings.append(
                                VulnerabilityFinding(
                                    id=f"secret-{uuid.uuid4().hex[:8]}",
                                    scanner=ScannerType.SECRET,
                                    title=f"Hardcoded {secret_type}",
                                    description=f"A hardcoded {secret_type} was found in the source code. "
                                                f"Hardcoded secrets can lead to unauthorized access and data breaches.",
                                    severity=Severity.CRITICAL,
                                    file_path=rel_path,
                                    line_start=line_idx,
                                    line_end=line_idx,
                                    code_snippet=snippet,
                                    cwe=["CWE-798"],
                                    cve=[],
                                    recommendation="Remove the hardcoded secret. Use environment variables or a secure secrets management system (e.g., AWS Secrets Manager, HashiCorp Vault)."
                                )
                            )
                            await self._emit(VulnerabilityFound(
                                severity=Severity.CRITICAL.value,
                                title=f"Hardcoded {secret_type}",
                                file_path=rel_path,
                                line=line_idx,
                                explanation=f"Found hardcoded {secret_type}."
                            ))
            except UnicodeDecodeError:
                pass
            except Exception as e:
                logger.error(f"Error scanning file {filepath}: {e}")

        return findings
