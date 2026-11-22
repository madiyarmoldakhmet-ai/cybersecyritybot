"""
Backdoor, Reverse-Shell, Obfuscated Payload, Supply-Chain & Trojan Source Scanner.

Detects covert malicious implants and backdoors across Python, JS/TS, Shell, Go, PHP,
package.json lifecycle hooks, and setup.py installers:
  1. Reverse shells & C2 socket implants (/dev/tcp, bash -i, nc -e, pty.spawn, dup2+socket, Node net.Socket -> sh)
  2. Hidden authentication backdoors (magic master password/token/header bypasses, secret admin elevation)
  3. Obfuscated code execution & payload droppers (eval/exec on base64/zlib/hex/atob/Buffer, curl|sh, IEX)
  4. Malicious package.json preinstall/postinstall & setup.py exfiltration hooks
  5. Sensitive credential / SSH / AWS / .env exfiltration over HTTP/Discord/Telegram webhooks
  6. Trojan Source invisible Bidirectional Unicode attacks (CVE-2021-42574)
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import List, Set, Tuple

from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("aegis.backdoor_scanner")

_IGNORED_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", "out", "dist", "build",
    "coverage", ".turbo", ".cache", ".venv", "venv", "__pycache__", "vendor",
}
_CODE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".php", ".rb", ".go", ".java", ".dart",
}

# Bidirectional Unicode override characters used in Trojan Source (CVE-2021-42574)
_BIDI_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069", "\u200e", "\u200f",
}

# High-precision backdoor & implant rules: (id, title, severity, cwe, regex, recommendation)
_BACKDOOR_RULES: Tuple[Tuple[str, str, Severity, List[str], re.Pattern, str], ...] = (
    (
        "backdoor-reverse-shell",
        "Backdoor: Reverse Shell / Remote Interactive Shell Implant",
        Severity.CRITICAL,
        ["CWE-506", "CWE-78"],
        re.compile(
            r"(?:/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+|"
            r"bash\s+-i\s+>&\s*/dev/tcp/|"
            r"\b(?:nc|ncat|netcat)\s+[^;\n]*(?:-e|-c)\s+(?:/bin/)?(?:ba)?sh\b|"
            r"\bmkfifo\s+/tmp/[^;\n]+\|\s*(?:/bin/)?(?:ba)?sh\b|"
            r"\bpty\.spawn\s*\(\s*['\"](?:/bin/)?(?:ba)?sh['\"]|"
            r"\bos\.dup2\s*\(\s*\w+\.fileno\(\)\s*,\s*[012]\s*\)|"
            r"new\s+net\.Socket\s*\(\s*\).*?\.connect\s*\([^)]+\).*?spawn\s*\(\s*['\"](?:/bin/)?(?:ba)?sh['\"])",
            re.IGNORECASE | re.DOTALL,
        ),
        "Immediately remove the reverse-shell implant, audit git commit history to identify who introduced it, and rotate all host/CI credentials.",
    ),
    (
        "backdoor-obfuscated-exec",
        "Backdoor: Obfuscated Payload Execution (base64/zlib/hex -> eval/exec)",
        Severity.CRITICAL,
        ["CWE-506", "CWE-95"],
        re.compile(
            r"(?:\b(?:eval|exec)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex)\s*\(|"
            r"\b(?:eval|Function)\s*\(\s*(?:atob\s*\(|Buffer\.from\s*\([^)]*['\"](?:base64|hex)['\"]\s*\)\.toString)|"
            r"\bgetattr\s*\(\s*__builtins__\s*,\s*['\"](?:eval|exec|__import__)['\"]\s*\)|"
            r"\b__import__\s*\(\s*['\"]os['\"]\s*\)\.(?:system|popen)\s*\()",
            re.IGNORECASE,
        ),
        "Deobfuscate and inspect the hidden payload immediately. Remove dynamic obfuscated execution and treat the codebase as potentially compromised.",
    ),
    (
        "backdoor-remote-dropper",
        "Backdoor: Remote Script Dropper (curl/wget piped directly to shell)",
        Severity.CRITICAL,
        ["CWE-506", "CWE-494"],
        re.compile(
            r"(?:\b(?:curl|wget)\s+[^\n|]{4,180}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|"
            r"\bpowershell(?:\.exe)?\s+[^\n]*(?:-enc|-encodedcommand|iex\s*\(\s*new-object\s+net\.webclient))",
            re.IGNORECASE,
        ),
        "Never pipe remote scripts directly into a shell or PowerShell IEX. Pin verified artifacts with SHA-256 checksums.",
    ),
    (
        "backdoor-auth-bypass-magic",
        "Backdoor: Hardcoded Master Password / Secret Auth Bypass Branch",
        Severity.CRITICAL,
        ["CWE-912", "CWE-798"],
        re.compile(
            r"(?:\bif\s*\(?\s*(?:password|passwd|pwd|secret|token|pin|code)\s*===?\s*['\"][^'\"]{4,64}['\"]\s*\)?\s*(?::|\{)?\s*(?:return\s+(?:true|True|admin|user)|grant|is_?admin\s*=\s*(?:true|True))|"
            r"req(?:uest)?\.headers\[['\"]x-(?:backdoor|debug-admin|master-key|override-auth|god-mode)['\"]\]|"
            r"\b(?:x-backdoor|god_?mode|master_?bypass|backdoor_?token)\b\s*(?:===?|in\s+))",
            re.IGNORECASE,
        ),
        "Remove hardcoded authentication bypasses, magic headers, and master passwords immediately; enforce standard IdP/JWT verification for all users.",
    ),
    (
        "backdoor-env-ssh-exfil",
        "Backdoor: Sensitive Secret / SSH / AWS Credential Exfiltration",
        Severity.CRITICAL,
        ["CWE-506", "CWE-200"],
        re.compile(
            r"(?:(?:id_rsa|id_ed25519|/etc/shadow|\.aws/credentials|JSON\.stringify\s*\(\s*process\.env\s*\)|dict\s*\(\s*os\.environ\s*\))[\s\S]{0,280}"
            r"(?:fetch\s*\(|axios\.post|requests\.post|httpx\.post|urllib\.request\.urlopen|discord\.com/api/webhooks|api\.telegram\.org/bot)|"
            r"(?:fetch\s*\(|axios\.post|requests\.post|httpx\.post|urllib\.request\.urlopen|discord\.com/api/webhooks|api\.telegram\.org/bot)[\s\S]{0,280}"
            r"(?:id_rsa|id_ed25519|/etc/shadow|\.aws/credentials|JSON\.stringify\s*\(\s*process\.env\s*\)|dict\s*\(\s*os\.environ\s*\)))",
            re.IGNORECASE,
        ),
        "Remove the credential-stealing code immediately, inspect outbound endpoints, and rotate all exposed SSH keys, cloud credentials, and environment secrets.",
    ),
)

_SUSPICIOUS_NPM_HOOK_RE = re.compile(
    r"(?:\b(?:curl|wget)\b|\bnode\s+-e\b|\bpython3?\s+-c\b|\bbash\s+-c\b|/dev/tcp|"
    r"process\.env|\.ssh|\.aws|base64\s+-d|eval\s*\(|discord\.com/api/webhooks)",
    re.IGNORECASE,
)


def _is_scanner_self_or_test(rel_path: str) -> bool:
    low = rel_path.lower()
    return (
        low.endswith("backdoor_scanner.py")
        or "/tests/" in low
        or low.startswith("tests/")
        or "__tests__/" in low
        or ".test." in low
        or ".spec." in low
    )


def _snippet(lines: List[str], line_idx: int, pad: int = 3) -> str:
    lo = max(0, line_idx - 1 - pad)
    hi = min(len(lines), line_idx + pad)
    return "\n".join(lines[lo:hi])


class BackdoorScanner:
    """Detects backdoors, reverse shells, obfuscated droppers, malicious npm hooks, and Trojan Source."""

    async def scan(self, target_dir: Path) -> List[VulnerabilityFinding]:
        target_path = Path(target_dir).resolve()
        if not target_path.exists():
            return []

        findings: List[VulnerabilityFinding] = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in _IGNORED_DIRS and not d.startswith(".")]
            for file in sorted(files):
                fp = Path(root) / file
                rel = fp.relative_to(target_path).as_posix()
                if _is_scanner_self_or_test(rel):
                    continue

                if file == "package.json":
                    findings.extend(self._scan_package_json_hooks(fp, rel))
                    continue

                if fp.suffix.lower() not in _CODE_EXTS:
                    continue
                try:
                    if fp.stat().st_size > 512 * 1024:
                        continue
                    content = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                findings.extend(self._scan_source(rel, content))
        return findings

    def _scan_source(self, rel_path: str, content: str) -> List[VulnerabilityFinding]:
        out: List[VulnerabilityFinding] = []
        lines = content.splitlines()
        seen_ids: Set[str] = set()

        # 1. Trojan Source hidden Bidirectional Unicode characters (CVE-2021-42574)
        for idx, line in enumerate(lines, start=1):
            if any(ch in _BIDI_CHARS for ch in line):
                out.append(
                    VulnerabilityFinding(
                        id="backdoor-trojan-source-bidi",
                        scanner=ScannerType.BACKDOOR,
                        title="Backdoor: Hidden Bidirectional Unicode (Trojan Source CVE-2021-42574)",
                        description=(
                            f"Invisible Unicode bidi override character detected in `{rel_path}:{idx}`. "
                            "Attackers use Trojan Source characters to visually disguise malicious backdoor logic as harmless comments."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=_snippet(lines, idx, pad=2),
                        cwe=["CWE-506"],
                        cve=["CVE-2021-42574"],
                        recommendation="Strip all bidirectional Unicode control characters and inspect the true execution order of surrounding code.",
                    )
                )
                break

        # 2. Regex backdoor & malware patterns
        for rule_id, title, severity, cwe, pattern, rec in _BACKDOOR_RULES:
            if rule_id in seen_ids:
                continue
            m = pattern.search(content)
            if not m:
                continue
            line_no = content[: m.start()].count("\n") + 1
            seen_ids.add(rule_id)
            out.append(
                VulnerabilityFinding(
                    id=rule_id,
                    scanner=ScannerType.BACKDOOR,
                    title=title,
                    description=(
                        f"Potential malicious backdoor or covert implant detected in `{rel_path}:{line_no}`.\n"
                        f"Matched signature: `{m.group(0).strip()[:140]}`"
                    ),
                    severity=severity,
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=_snippet(lines, line_no, pad=3),
                    cwe=list(cwe),
                    recommendation=rec,
                    raw_metadata={"detector": "backdoor-scanner"},
                )
            )
        return out

    def _scan_package_json_hooks(self, file_path: Path, rel_path: str) -> List[VulnerabilityFinding]:
        out: List[VulnerabilityFinding] = []
        try:
            raw = file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except Exception:
            return out

        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            return out

        lines = raw.splitlines()
        for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            if _SUSPICIOUS_NPM_HOOK_RE.search(cmd):
                line_no = next(
                    (i for i, l in enumerate(lines, 1) if f'"{hook}"' in l),
                    1,
                )
                out.append(
                    VulnerabilityFinding(
                        id=f"backdoor-npm-{hook}",
                        scanner=ScannerType.BACKDOOR,
                        title=f"Supply-Chain Backdoor: Suspicious npm `{hook}` lifecycle script",
                        description=(
                            f"`{rel_path}` defines a `{hook}` script (`{cmd[:140]}`) that executes automatically on `npm install` "
                            "and references shell droppers, environment secrets, or external exfiltration."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=_snippet(lines, line_no, pad=2),
                        cwe=["CWE-506"],
                        recommendation=f"Audit and remove the malicious `{hook}` script before running `npm install`, and run installs with `--ignore-scripts`.",
                    )
                )
        return out
