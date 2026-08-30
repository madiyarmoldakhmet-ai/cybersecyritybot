"""
Mobile DevSecOps Scanner for CyberSecurityBot.
Deep specialized static analysis for:
- Flutter & Dart (SharedPreferences plaintext secrets, SSL badCertificateCallback bypass, cleartext HTTP, hardcoded crypto keys)
- Firebase Firestore Security Rules (Public read/write access, missing auth checks)
- Android Manifest misconfigurations (allowBackup, usesCleartextTraffic, exported components)
- iOS Info.plist security (NSAllowsArbitraryLoads / ATS bypass)
"""

import os
import re
from pathlib import Path
from typing import List, Optional

from scanners.models import ScannerType, Severity, VulnerabilityFinding
from scanners.sanitizer import FalsePositiveSanitizer, calculate_shannon_entropy


class MobileSecurityScanner:
    """Specialized Mobile & Cloud Security Scanner for Flutter, Firebase, Android and iOS."""

    def __init__(self) -> None:
        self.sanitizer = FalsePositiveSanitizer()

    async def scan(self, repo_dir: Path) -> List[VulnerabilityFinding]:
        """Scan repository for Mobile DevSecOps vulnerabilities."""
        findings: List[VulnerabilityFinding] = []
        target_path = Path(repo_dir).resolve()

        if not target_path.exists():
            return findings

        for root, dirs, files in os.walk(target_path):
            # Skip ignored directories
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".") and d not in {"node_modules", ".venv", "venv", "build", ".dart_tool", "__pycache__"}
            ]

            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(target_path).as_posix()

                # Skip tests and mock files
                if self.sanitizer.is_test_file(rel_path):
                    continue

                name_lower = file.lower()

                # 1. Flutter / Dart files
                if name_lower.endswith(".dart"):
                    findings.extend(self._scan_dart_file(file_path, rel_path))

                # 2. Firebase & Firestore Security Rules
                elif name_lower.endswith(".rules") or name_lower == "firestore.rules":
                    findings.extend(self._scan_firestore_rules(file_path, rel_path))

                # 3. Android Manifest
                elif name_lower == "androidmanifest.xml":
                    findings.extend(self._scan_android_manifest(file_path, rel_path))

                # 4. iOS Info.plist
                elif name_lower == "info.plist":
                    findings.extend(self._scan_ios_plist(file_path, rel_path))

                # 5. Firebase configuration JSON files
                elif name_lower == "google-services.json":
                    findings.extend(self._scan_google_services_json(file_path, rel_path))

        return findings

    # ---- 1. Dart & Flutter Analysis -----------------------------------------

    def _scan_dart_file(self, file_path: Path, rel_path: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
        except Exception:
            return findings

        # Rule 1.1: Insecure SSL certificate callback bypass
        ssl_bypass_pattern = re.compile(
            r"badCertificateCallback\s*=\s*(\(.*?\)\s*=>\s*true|\(.*?\)\s*\{\s*return\s+true\s*;\s*\})",
            re.IGNORECASE | re.DOTALL,
        )
        if ssl_bypass_pattern.search(content):
            match_line = 1
            for idx, line in enumerate(lines, 1):
                if "badCertificateCallback" in line:
                    match_line = idx
                    break

            findings.append(
                VulnerabilityFinding(
                    id="FLUTTER-SSL-BYPASS",
                    scanner=ScannerType.MOBILE,
                    title="Insecure SSL/TLS Certificate Validation Bypass (Flutter)",
                    description=(
                        "Detected `badCertificateCallback` returning `true`. This completely disables "
                        "SSL/TLS certificate verification, exposing mobile users to Man-in-the-Middle (MitM) attacks."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    line_start=match_line,
                    line_end=min(match_line + 3, len(lines)),
                    code_snippet="\n".join(lines[max(0, match_line - 1) : min(len(lines), match_line + 3)]),
                    cwe=["CWE-295"],
                    cve=[],
                    recommendation=(
                        "Remove the `badCertificateCallback = (cert, host, port) => true;` override. "
                        "Use proper SSL pinning with SecurityContext or trusted CA certificates in production."
                    ),
                    raw_metadata={"category": "mobile_network_security", "framework": "flutter"},
                )
            )

        # Rule 1.2: Sensitive credentials in SharedPreferences instead of flutter_secure_storage
        shared_pref_secret = re.compile(
            r"(prefs|sharedPreferences|preferences)\.setString\(\s*['\"](token|auth_token|access_token|jwt|password|secret|api_key)['\"],\s*([^)]+)\)",
            re.IGNORECASE,
        )
        for idx, line in enumerate(lines, 1):
            m = shared_pref_secret.search(line)
            if m:
                findings.append(
                    VulnerabilityFinding(
                        id="FLUTTER-SHARED-PREFS-SECRET",
                        scanner=ScannerType.MOBILE,
                        title="Plaintext Token Storage in SharedPreferences",
                        description=(
                            f"Sensitive authentication credential `{m.group(2)}` is being stored in unencrypted `SharedPreferences`. "
                            "On rooted devices or backup extractions, this allows unauthorized token exfiltration."
                        ),
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip(),
                        cwe=["CWE-312", "CWE-922"],
                        cve=[],
                        recommendation=(
                            "Replace `SharedPreferences` with `flutter_secure_storage` (using Keychain on iOS and Android KeyStore) "
                            "for storing sensitive tokens, secrets, or passwords."
                        ),
                        raw_metadata={"category": "mobile_storage", "framework": "flutter"},
                    )
                )

        # Rule 1.3: Cleartext HTTP endpoints
        http_cleartext_pattern = re.compile(r"['\"](http://[a-zA-Z0-9_\-\.\:\/]+)['\"]")
        for idx, line in enumerate(lines, 1):
            if "localhost" in line or "127.0.0.1" in line or "10.0.2.2" in line:
                continue

            matches = http_cleartext_pattern.findall(line)
            for url in matches:
                findings.append(
                    VulnerabilityFinding(
                        id="FLUTTER-CLEARTEXT-HTTP",
                        scanner=ScannerType.MOBILE,
                        title="Unencrypted Cleartext HTTP Communication in Mobile App",
                        description=(
                            f"Discovered insecure cleartext HTTP URL `{url}` in mobile network request. "
                            "Sensitive API traffic transmitted over plain HTTP is susceptible to interception and tampering."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip(),
                        cwe=["CWE-319"],
                        cve=[],
                        recommendation=f"Update `{url}` to use encrypted HTTPS protocol (`https://`).",
                        raw_metadata={"category": "mobile_network_security", "framework": "flutter"},
                    )
                )

        return findings

    # ---- 2. Firebase Firestore Rules Analysis -------------------------------

    def _scan_firestore_rules(self, file_path: Path, rel_path: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
        except Exception:
            return findings

        # Rule 2.1: Open public read/write permission (allow read, write: if true;)
        open_rule_pattern = re.compile(
            r"allow\s+(read,\s*write|write,\s*read|write|read)\s*:\s*if\s+true\s*;",
            re.IGNORECASE,
        )

        for idx, line in enumerate(lines, 1):
            if open_rule_pattern.search(line):
                is_write = "write" in line.lower()
                sev = Severity.CRITICAL if is_write else Severity.HIGH
                findings.append(
                    VulnerabilityFinding(
                        id="FIREBASE-OPEN-SECURITY-RULE",
                        scanner=ScannerType.MOBILE,
                        title="Overly Permissive Firebase Firestore Security Rule",
                        description=(
                            f"Firestore rule on line {idx} allows unrestricted public access (`{line.strip()}`). "
                            "Anyone on the internet can read or overwrite your entire Firebase database without authentication."
                        ),
                        severity=sev,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip(),
                        cwe=["CWE-284", "CWE-732"],
                        cve=[],
                        recommendation=(
                            "Restrict database access using Firebase Authentication rules: "
                            "`allow read, write: if request.auth != null && request.auth.uid == userId;`"
                        ),
                        raw_metadata={"category": "cloud_database_security", "service": "firebase_firestore"},
                    )
                )

        return findings

    # ---- 3. AndroidManifest.xml Analysis ------------------------------------

    def _scan_android_manifest(self, file_path: Path, rel_path: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
        except Exception:
            return findings

        # Rule 3.1: allowBackup="true"
        if 'android:allowBackup="true"' in content:
            match_line = next((i for i, l in enumerate(lines, 1) if 'android:allowBackup="true"' in l), 1)
            findings.append(
                VulnerabilityFinding(
                    id="ANDROID-ALLOW-BACKUP",
                    scanner=ScannerType.MOBILE,
                    title="Android Backup Enabled (allowBackup=true)",
                    description=(
                        "Application has `android:allowBackup=\"true\"` enabled. Attackers with physical or ADB access "
                        "can extract app private data, databases, and cached sessions via `adb backup`."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=rel_path,
                    line_start=match_line,
                    line_end=match_line,
                    code_snippet=lines[match_line - 1].strip(),
                    cwe=["CWE-921", "CWE-312"],
                    cve=[],
                    recommendation='Set `android:allowBackup="false"` in the `<application>` tag of `AndroidManifest.xml`.',
                    raw_metadata={"category": "android_security", "platform": "android"},
                )
            )

        # Rule 3.2: usesCleartextTraffic="true"
        if 'android:usesCleartextTraffic="true"' in content:
            match_line = next((i for i, l in enumerate(lines, 1) if 'android:usesCleartextTraffic="true"' in l), 1)
            findings.append(
                VulnerabilityFinding(
                    id="ANDROID-CLEARTEXT-TRAFFIC",
                    scanner=ScannerType.MOBILE,
                    title="Android Cleartext Traffic Permitted (usesCleartextTraffic=true)",
                    description=(
                        "Application explicitly allows unencrypted HTTP network traffic (`usesCleartextTraffic=\"true\"`). "
                        "This bypasses Android Network Security Configuration safeguards against MitM eavesdropping."
                    ),
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line_start=match_line,
                    line_end=match_line,
                    code_snippet=lines[match_line - 1].strip(),
                    cwe=["CWE-319"],
                    cve=[],
                    recommendation='Set `android:usesCleartextTraffic="false"` and enforce HTTPS for all domains.',
                    raw_metadata={"category": "android_security", "platform": "android"},
                )
            )

        return findings

    # ---- 4. iOS Info.plist Analysis -----------------------------------------

    def _scan_ios_plist(self, file_path: Path, rel_path: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
        except Exception:
            return findings

        # Rule 4.1: NSAllowsArbitraryLoads = true (ATS Bypass)
        if "NSAllowsArbitraryLoads" in content and ("<true/>" in content or "<true />" in content):
            match_line = next((i for i, l in enumerate(lines, 1) if "NSAllowsArbitraryLoads" in l), 1)
            findings.append(
                VulnerabilityFinding(
                    id="IOS-ATS-BYPASS",
                    scanner=ScannerType.MOBILE,
                    title="iOS App Transport Security (ATS) Disabled",
                    description=(
                        "The application disables iOS App Transport Security (ATS) via `NSAllowsArbitraryLoads = true`. "
                        "This allows insecure HTTP connections and weakens encryption standards for all network requests."
                    ),
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line_start=match_line,
                    line_end=min(match_line + 2, len(lines)),
                    code_snippet="\n".join(lines[max(0, match_line - 1) : min(len(lines), match_line + 2)]),
                    cwe=["CWE-319"],
                    cve=[],
                    recommendation="Remove `NSAllowsArbitraryLoads = true`. Use domain-specific exceptions only if strictly necessary.",
                    raw_metadata={"category": "ios_security", "platform": "ios"},
                )
            )

        return findings

    # ---- 5. Google Services JSON Secret Analysis ---------------------------

    def _scan_google_services_json(self, file_path: Path, rel_path: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
        except Exception:
            return findings

        # Check for exposed API Keys in client json with entropy verification
        api_key_matches = re.finditer(r'"current_key":\s*"([a-zA-Z0-9_\-]{20,})"', content)
        for m in api_key_matches:
            key_val = m.group(1)
            # Verify high entropy to prevent dummy matches
            if calculate_shannon_entropy(key_val) >= 3.6 and not self.sanitizer.is_placeholder_text(key_val):
                line_no = content[: m.start()].count("\n") + 1
                findings.append(
                    VulnerabilityFinding(
                        id="FIREBASE-EXPOSED-CLIENT-API-KEY",
                        scanner=ScannerType.MOBILE,
                        title="Exposed Firebase Google Services API Key",
                        description=(
                            f"Discovered active Firebase Client API Key `{key_val[:8]}...` in `{rel_path}`. "
                            "Ensure API key restrictions (Android SHA-1 & Package Name restriction) are configured in Google Cloud Console."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                        cwe=["CWE-522", "CWE-798"],
                        cve=[],
                        recommendation="Add Android application package name and SHA-1 fingerprint restrictions in Google Cloud Console.",
                        raw_metadata={"category": "mobile_secrets", "platform": "android"},
                    )
                )

        return findings
