"""
Aegis Flutter/Dart Security Rules Engine
=========================================
The world's first dedicated security scanner for Flutter & Dart projects.

These rules detect vulnerabilities specific to mobile Flutter apps that
NO existing scanner (Semgrep, Bandit, ESLint, SonarQube) covers.

Each rule is a class with a `scan()` method that parses file content
and returns a list of VulnerabilityFinding objects.
"""

import re
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Set, Optional

from aegis.scanners.models import VulnerabilityFinding, Severity, ScannerType

logger = logging.getLogger("aegis.flutter_rules")


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class FlutterSecurityRule(ABC):
    """Base class for all Flutter/Dart security rules."""

    id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    cwe: List[str] = []
    file_extensions: Set[str] = set()

    def _snippet(self, lines: List[str], line_idx: int, context: int = 5) -> str:
        start = max(0, line_idx - context)
        end = min(len(lines), line_idx + context + 1)
        return "\n".join(lines[start:end])

    def _make_finding(
        self,
        file_path: str,
        line_start: int,
        code_snippet: str,
        recommendation: str,
        line_end: Optional[int] = None,
    ) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            id=self.id,
            scanner=ScannerType.FLUTTER,
            title=self.title,
            description=self.description,
            severity=self.severity,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end or line_start,
            code_snippet=code_snippet,
            cwe=list(self.cwe),
            recommendation=recommendation,
        )

    @abstractmethod
    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        ...


# ---------------------------------------------------------------------------
# Rule 1: SharedPreferences Insecure Storage
# ---------------------------------------------------------------------------

class SharedPrefsInsecureStorage(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-001"
    title = "SharedPreferences Insecure Storage"
    description = (
        "Sensitive data (tokens, passwords, secrets) is stored in SharedPreferences "
        "which is plain-text XML on Android and plist on iOS. Any rooted/jailbroken "
        "device or a backup extraction can read this data."
    )
    severity = Severity.HIGH
    cwe = ["CWE-922"]
    file_extensions = {".dart"}

    _SENSITIVE_KEYS = re.compile(
        r"""(?:setString|setInt|setBool)\s*\(\s*['"]([^'"]*(?:token|password|secret|key|session|auth|credential|jwt|api_key|apikey|pin|otp)[^'"]*)['"]""",
        re.IGNORECASE,
    )

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        lines = content.splitlines()
        if "SharedPreferences" not in content:
            return findings

        for idx, line in enumerate(lines):
            m = self._SENSITIVE_KEYS.search(line)
            if m:
                findings.append(self._make_finding(
                    file_path=file_path,
                    line_start=idx + 1,
                    code_snippet=self._snippet(lines, idx),
                    recommendation=(
                        "Use flutter_secure_storage instead of SharedPreferences for "
                        "sensitive data. flutter_secure_storage encrypts values using "
                        "Keychain (iOS) and EncryptedSharedPreferences (Android).\n"
                        "Используй flutter_secure_storage вместо SharedPreferences "
                        "для хранения чувствительных данных."
                    ),
                ))
        return findings


# ---------------------------------------------------------------------------
# Rule 2: Disabled SSL Certificate Validation
# ---------------------------------------------------------------------------

class DisabledSSLValidation(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-002"
    title = "Disabled SSL Certificate Validation"
    description = (
        "badCertificateCallback is set to always return true, completely disabling "
        "TLS certificate validation. This allows Man-in-the-Middle (MitM) attacks."
    )
    severity = Severity.CRITICAL
    cwe = ["CWE-295"]
    file_extensions = {".dart"}

    _PATTERN = re.compile(
        r"badCertificateCallback\s*[=:]\s*\(.*?\)\s*(?:=>|{?\s*return)\s*true",
        re.DOTALL,
    )

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            if "badCertificateCallback" in line and "true" in line:
                findings.append(self._make_finding(
                    file_path=file_path,
                    line_start=idx + 1,
                    code_snippet=self._snippet(lines, idx),
                    recommendation=(
                        "Implement proper certificate pinning using the "
                        "http_certificate_pinning or dio_certificate_pinning package. "
                        "Never return true from badCertificateCallback in production.\n"
                        "Никогда не возвращай true из badCertificateCallback в продакшене. "
                        "Используй certificate pinning."
                    ),
                ))
        return findings


# ---------------------------------------------------------------------------
# Rule 3: Insecure Random Number Generator
# ---------------------------------------------------------------------------

class InsecureRandom(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-003"
    title = "Insecure Random Number Generator"
    description = (
        "dart:math Random() is a pseudorandom generator (PRNG) that is predictable. "
        "For security-sensitive operations (OTP, tokens, nonces), use Random.secure()."
    )
    severity = Severity.MEDIUM
    cwe = ["CWE-330"]
    file_extensions = {".dart"}

    _IMPORT_PATTERN = re.compile(r"import\s+['\"]dart:math['\"]")
    _INSECURE = re.compile(r"\bRandom\(\)")

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        if not self._IMPORT_PATTERN.search(content):
            return findings

        lines = content.splitlines()
        for idx, line in enumerate(lines):
            if self._INSECURE.search(line) and "Random.secure()" not in line:
                findings.append(self._make_finding(
                    file_path=file_path,
                    line_start=idx + 1,
                    code_snippet=self._snippet(lines, idx),
                    recommendation=(
                        "Replace Random() with Random.secure() for any security-related "
                        "operation (tokens, OTP codes, cryptographic nonces).\n"
                        "Замени Random() на Random.secure() для любых операций, "
                        "связанных с безопасностью."
                    ),
                ))
        return findings


# ---------------------------------------------------------------------------
# Rule 4: WebView JavaScript Injection Risk
# ---------------------------------------------------------------------------

class WebViewJSInjection(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-004"
    title = "WebView JavaScript Injection Risk"
    description = (
        "WebView has unrestricted JavaScript enabled without a navigationDelegate. "
        "This can lead to XSS if the WebView loads untrusted content."
    )
    severity = Severity.HIGH
    cwe = ["CWE-79"]
    file_extensions = {".dart"}

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        if "JavascriptMode.unrestricted" not in content and "javaScriptMode: JavaScriptMode.unrestricted" not in content:
            return findings

        has_nav_delegate = "navigationDelegate" in content
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            if "unrestricted" in line and not has_nav_delegate:
                findings.append(self._make_finding(
                    file_path=file_path,
                    line_start=idx + 1,
                    code_snippet=self._snippet(lines, idx, context=8),
                    recommendation=(
                        "Add a navigationDelegate to whitelist allowed domains. "
                        "Restrict JavaScript execution to trusted origins only.\n"
                        "Добавь navigationDelegate для ограничения разрешённых доменов."
                    ),
                ))
        return findings


# ---------------------------------------------------------------------------
# Rule 5: Hardcoded API Endpoints
# ---------------------------------------------------------------------------

class HardcodedAPIEndpoint(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-005"
    title = "Hardcoded API Endpoint"
    description = (
        "Production or staging API URLs are hardcoded in Dart source files. "
        "These should be injected via build-time environment variables "
        "(--dart-define) to prevent accidental exposure."
    )
    severity = Severity.MEDIUM
    cwe = ["CWE-798"]
    file_extensions = {".dart"}

    _PATTERN = re.compile(
        r"""['"](https?://(?:api\.|prod\.|staging\.|backend\.)[^\s'"]+)['"]""",
        re.IGNORECASE,
    )

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            m = self._PATTERN.search(line)
            if m:
                # Skip test files
                if "/test/" in file_path or "_test.dart" in file_path:
                    continue
                findings.append(self._make_finding(
                    file_path=file_path,
                    line_start=idx + 1,
                    code_snippet=self._snippet(lines, idx),
                    recommendation=(
                        "Use --dart-define=API_URL=... at build time and access via "
                        "String.fromEnvironment('API_URL'). Never hardcode production "
                        "endpoints in source code.\n"
                        "Используй --dart-define для передачи URL. Не хардкодь "
                        "продакшен-эндпоинты."
                    ),
                ))
        return findings


# ---------------------------------------------------------------------------
# Rule 6: Debug Mode in Release
# ---------------------------------------------------------------------------

class DebugModeInRelease(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-006"
    title = "Debug Mode Check in Release Code"
    description = (
        "kDebugMode or assert() with side effects found in non-test code. "
        "This may leak debug information or behave differently in release builds."
    )
    severity = Severity.LOW
    cwe = ["CWE-489"]
    file_extensions = {".dart"}

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        if "/test/" in file_path or "_test.dart" in file_path:
            return findings

        lines = content.splitlines()
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if "kDebugMode" in stripped and ("if" in stripped or "==" in stripped):
                findings.append(self._make_finding(
                    file_path=file_path,
                    line_start=idx + 1,
                    code_snippet=self._snippet(lines, idx),
                    recommendation=(
                        "Use kReleaseMode for production checks. Remove debug-only "
                        "code paths or gate them properly with tree-shaking.\n"
                        "Используй kReleaseMode для продакшен-проверок."
                    ),
                ))
        return findings


# ---------------------------------------------------------------------------
# Rule 7: Missing Root/Jailbreak Detection
# ---------------------------------------------------------------------------

class MissingRootDetection(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-007"
    title = "Missing Root/Jailbreak Detection"
    description = (
        "No root/jailbreak detection package found in pubspec.yaml. "
        "Fintech and banking apps MUST detect compromised devices to prevent "
        "credential theft and tampering."
    )
    severity = Severity.MEDIUM
    cwe = ["CWE-919"]
    file_extensions = {".yaml"}

    _DETECTION_PACKAGES = {
        "flutter_jailbreak_detection",
        "root_checker",
        "safe_device",
        "freerasp",
        "device_security",
    }

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        if not file_path.endswith("pubspec.yaml"):
            return findings

        has_detection = any(pkg in content for pkg in self._DETECTION_PACKAGES)
        if not has_detection:
            findings.append(self._make_finding(
                file_path=file_path,
                line_start=1,
                code_snippet="# No root/jailbreak detection package found in dependencies",
                recommendation=(
                    "Add a root/jailbreak detection package to pubspec.yaml:\n"
                    "  dependencies:\n"
                    "    freerasp: ^6.0.0\n\n"
                    "freeRASP is the most comprehensive option (root, emulator, "
                    "debug, hooks, tamper detection).\n"
                    "Добавь пакет freerasp для обнаружения root/jailbreak."
                ),
            ))
        return findings


# ---------------------------------------------------------------------------
# Rule 8: Unencrypted SQLite Database
# ---------------------------------------------------------------------------

class UnencryptedSQLite(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-008"
    title = "Unencrypted SQLite Database"
    description = (
        "sqflite is used without encryption. SQLite databases on mobile devices "
        "can be extracted from backups or rooted devices, exposing all stored data."
    )
    severity = Severity.HIGH
    cwe = ["CWE-311"]
    file_extensions = {".dart"}

    _ENCRYPTED_IMPORTS = {"sqflite_sqlcipher", "encrypted_moor", "drift_sqcipher", "sqlcipher_flutter_libs"}

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        if "package:sqflite" not in content:
            return findings

        has_encryption = any(pkg in content for pkg in self._ENCRYPTED_IMPORTS)
        if has_encryption:
            return findings

        lines = content.splitlines()
        for idx, line in enumerate(lines):
            if "package:sqflite" in line:
                findings.append(self._make_finding(
                    file_path=file_path,
                    line_start=idx + 1,
                    code_snippet=self._snippet(lines, idx),
                    recommendation=(
                        "Replace sqflite with sqflite_sqlcipher for transparent "
                        "AES-256 encryption of the database file. Add "
                        "sqlcipher_flutter_libs to your dependencies.\n"
                        "Замени sqflite на sqflite_sqlcipher для шифрования базы данных."
                    ),
                ))
                break  # One finding per file is enough
        return findings


# ---------------------------------------------------------------------------
# Rule 9: iOS ATS Bypass
# ---------------------------------------------------------------------------

class IOSATSBypass(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-009"
    title = "iOS App Transport Security Bypass"
    description = (
        "NSAllowsArbitraryLoads is set to true in Info.plist, disabling "
        "Apple's App Transport Security. This allows insecure HTTP connections "
        "and will likely cause App Store rejection."
    )
    severity = Severity.HIGH
    cwe = ["CWE-319"]
    file_extensions = {".plist"}

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        if "NSAllowsArbitraryLoads" not in content:
            return findings

        lines = content.splitlines()
        for idx, line in enumerate(lines):
            if "NSAllowsArbitraryLoads" in line:
                # Check if next non-empty line contains <true/>
                for check_idx in range(idx + 1, min(idx + 3, len(lines))):
                    if "<true/>" in lines[check_idx]:
                        findings.append(self._make_finding(
                            file_path=file_path,
                            line_start=idx + 1,
                            line_end=check_idx + 1,
                            code_snippet=self._snippet(lines, idx, context=4),
                            recommendation=(
                                "Remove NSAllowsArbitraryLoads or set it to false. "
                                "If specific domains need HTTP, use "
                                "NSExceptionDomains instead of disabling ATS globally.\n"
                                "Удали NSAllowsArbitraryLoads или выстави false. "
                                "Для конкретных доменов используй NSExceptionDomains."
                            ),
                        ))
                        break
        return findings


# ---------------------------------------------------------------------------
# Rule 10: Exported Android Components Without Permission
# ---------------------------------------------------------------------------

class ExportedAndroidComponents(FlutterSecurityRule):
    id = "AEGIS-FLUTTER-010"
    title = "Exported Android Component Without Permission"
    description = (
        "An Android component (Activity, Service, Receiver) is exported "
        "without a required permission. Any app on the device can invoke it, "
        "potentially triggering unauthorized actions."
    )
    severity = Severity.MEDIUM
    cwe = ["CWE-926"]
    file_extensions = {".xml"}

    _EXPORTED = re.compile(r'android:exported\s*=\s*"true"')
    _PERMISSION = re.compile(r'android:permission\s*=')

    def scan(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        findings = []
        if "AndroidManifest.xml" not in file_path:
            return findings

        lines = content.splitlines()
        for idx, line in enumerate(lines):
            if self._EXPORTED.search(line) and not self._PERMISSION.search(line):
                # Check surrounding lines (component tag might span multiple lines)
                context_block = "\n".join(lines[max(0, idx - 2):min(len(lines), idx + 5)])
                if not self._PERMISSION.search(context_block):
                    findings.append(self._make_finding(
                        file_path=file_path,
                        line_start=idx + 1,
                        code_snippet=self._snippet(lines, idx, context=4),
                        recommendation=(
                            "Add android:permission to restrict access, or set "
                            "android:exported=\"false\" if external access is not needed.\n"
                            "Добавь android:permission или выстави exported=false."
                        ),
                    ))
        return findings


# ---------------------------------------------------------------------------
# Rule Registry & Scanner
# ---------------------------------------------------------------------------

ALL_FLUTTER_RULES: List[FlutterSecurityRule] = [
    SharedPrefsInsecureStorage(),
    DisabledSSLValidation(),
    InsecureRandom(),
    WebViewJSInjection(),
    HardcodedAPIEndpoint(),
    DebugModeInRelease(),
    MissingRootDetection(),
    UnencryptedSQLite(),
    IOSATSBypass(),
    ExportedAndroidComponents(),
]


class FlutterSecurityScanner:
    """
    Aegis Flutter Security Scanner — the world's first dedicated
    security scanner for Flutter/Dart mobile projects.

    Recursively scans .dart, .yaml, .plist, and .xml files and
    applies all registered Flutter security rules.
    """

    def __init__(self, rules: Optional[List[FlutterSecurityRule]] = None, event_bus: Optional[Any] = None):
        self.rules = rules or ALL_FLUTTER_RULES
        self.event_bus = event_bus

    async def _emit(self, event) -> None:
        if self.event_bus:
            try:
                await self.event_bus.emit(event)
            except Exception as e:
                logger.debug(f"Failed to emit event {event.event_type}: {e}")

    async def scan(self, target_dir: Path) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        target = Path(target_dir)

        if not target.exists():
            logger.error(f"Target directory does not exist: {target}")
            return findings

        # Collect all scannable extensions from rules
        all_extensions: Set[str] = set()
        for rule in self.rules:
            all_extensions.update(rule.file_extensions)

        # Walk the project tree
        skip_dirs = {".git", ".dart_tool", "build", ".flutter-plugins", "node_modules", ".venv"}
        
        from aegis.core.event_bus import FileScanning, CodeAnalyzing, VulnerabilityFound
        
        for ext in all_extensions:
            pattern = f"*{ext}"
            for file_path in target.rglob(pattern):
                # Skip build artifacts and hidden dirs
                parts = set(file_path.parts)
                if parts & skip_dirs:
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception as e:
                    logger.debug(f"Could not read {file_path}: {e}")
                    continue

                rel_path = str(file_path.relative_to(target))
                await self._emit(FileScanning(file_path=rel_path))

                for rule in self.rules:
                    if ext in rule.file_extensions:
                        try:
                            await self._emit(CodeAnalyzing(file_path=rel_path, snippet=f"Applying Flutter rule: {rule.title}"))
                            rule_findings = rule.scan(rel_path, content)
                            if rule_findings:
                                for f in rule_findings:
                                    await self._emit(VulnerabilityFound(
                                        severity=f.severity.value,
                                        title=f.title,
                                        file_path=f.file_path,
                                        line=f.line_start,
                                        explanation=f.description
                                    ))
                            findings.extend(rule_findings)
                        except Exception as e:
                            logger.debug(f"Rule {rule.id} failed on {rel_path}: {e}")

        logger.info(
            f"Flutter Security Scanner completed: {len(findings)} findings "
            f"from {len(self.rules)} rules"
        )
        return findings
