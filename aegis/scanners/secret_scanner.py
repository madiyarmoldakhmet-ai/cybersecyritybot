import logging
import os
import re
from pathlib import Path
from typing import List, Tuple
import uuid

from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.sanitizer import FalsePositiveSanitizer

logger = logging.getLogger("aegis.secret_scanner")

#: Vendor-specific patterns are precise; "Generic" ones are additionally entropy-checked by consumers.
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Stripe API Key": re.compile(r"\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}\b"),
    "GitHub Token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "Telegram Bot Token": re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Slack Token": re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    "OpenAI API Key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    "Private Key": re.compile("-----BEGIN " + r"(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "Generic Password": re.compile(r"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]([^'\"]{6,})['\"]"),
    "Generic API Key": re.compile(r"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
}


def detect_secrets(line: str) -> List[Tuple[str, str]]:
    """Return ``(secret_type, secret_value)`` pairs found in a single line of text."""
    found: List[Tuple[str, str]] = []
    seen_spans: List[Tuple[int, int]] = []
    for secret_type, pattern in SECRET_PATTERNS.items():  # vendor patterns first, generic last
        for match in pattern.finditer(line):
            group = 1 if match.groups() else 0
            start, end = match.span(group)
            if any(start < e and s < end for s, e in seen_spans):
                continue  # already reported by a more specific pattern
            seen_spans.append((start, end))
            found.append((secret_type, match.group(group)))
    return found


_VALIDATOR = FalsePositiveSanitizer()


def is_plausible_secret(secret_type: str, value: str) -> bool:
    """Vendor formats are trusted; generic credential assignments must look random."""
    if _VALIDATOR.is_placeholder_text(value):
        return False
    if secret_type.startswith("Generic"):
        return _VALIDATOR.is_valid_secret_entropy(value)
    return True


def mask_secret(value: str) -> str:
    """Mask a secret for reports/logs: keep a short prefix and suffix only."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(12, len(value) - 6)}{value[-2:]}"


class SecretScanner:
    """
    Secret Scanner to find hardcoded tokens, API keys, and passwords using regular expressions.
    """
    
    PATTERNS = SECRET_PATTERNS

    IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "out", ".next", ".pytest_cache", "temp_scans"}
    IGNORE_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg", ".ico",
        ".pdf", ".zip", ".tar", ".gz", ".mp3", ".mp4", ".webm", ".mov", ".ogg", ".wav",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".wasm", ".bin", ".tgs",
        ".pyc", ".o", ".so", ".dll", ".exe", ".map", ".lock",
    }
    MAX_FILE_BYTES = 1_048_576  # 1 MB cap per text file
    MAX_PROGRESS_EVENTS = 60

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

        emitted_progress = 0
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]

            for fname in files:
                filepath = Path(root) / fname
                if filepath.suffix.lower() in self.IGNORE_EXTENSIONS:
                    continue
                try:
                    if filepath.stat().st_size > self.MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue

                rel_path = filepath.relative_to(target_path).as_posix()
                if emitted_progress < self.MAX_PROGRESS_EVENTS:
                    await self._emit(FileScanning(file_path=rel_path))

                try:
                    content = filepath.read_text(encoding="utf-8")
                    if emitted_progress < self.MAX_PROGRESS_EVENTS:
                        await self._emit(CodeAnalyzing(file_path=rel_path, snippet="Scanning for hardcoded secrets..."))
                        emitted_progress += 1

                    for line_idx, line in enumerate(content.splitlines(), start=1):
                        for secret_type, value in detect_secrets(line):
                            if not is_plausible_secret(secret_type, value):
                                continue
                            # Never copy the raw secret into reports, Telegram alerts or PR comments
                            snippet = line.strip().replace(value, mask_secret(value))
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
