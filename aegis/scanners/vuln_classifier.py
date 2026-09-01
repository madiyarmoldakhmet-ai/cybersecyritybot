"""
Vulnerability Classifier for Aegis.
Determines whether a vulnerability can be verified via HTTP request (remote exploit)
or requires static/local code verification only.
"""

from enum import Enum
from typing import Set

from aegis.scanners.models import ScannerType, VulnerabilityFinding


class VulnCategory(str, Enum):
    """Classification of vulnerability verification method."""
    EXPLOITABLE_REMOTE = "exploitable_remote"   # Can be verified via HTTP request (SQLi, XSS, IDOR, RCE, SSRF)
    CODE_QUALITY = "code_quality"               # Static/config issue, no HTTP exploit possible


# CWE IDs that are exploitable via network requests
_REMOTE_CWES: Set[str] = {
    # Injection
    "CWE-89",   # SQL Injection
    "CWE-79",   # Cross-site Scripting (XSS)
    "CWE-78",   # OS Command Injection
    "CWE-77",   # Command Injection
    "CWE-94",   # Code Injection
    "CWE-917",  # Expression Language Injection
    "CWE-1336", # Template Injection (SSTI)
    "CWE-943",  # NoSQL Injection
    "CWE-90",   # LDAP Injection
    "CWE-611",  # XML External Entity (XXE)
    "CWE-91",   # XML Injection

    # Auth & Access
    "CWE-639",  # IDOR
    "CWE-284",  # Improper Access Control
    "CWE-285",  # Improper Authorization
    "CWE-862",  # Missing Authorization
    "CWE-863",  # Incorrect Authorization
    "CWE-306",  # Missing Authentication
    "CWE-287",  # Improper Authentication
    "CWE-352",  # CSRF

    # SSRF & Redirects
    "CWE-918",  # Server-Side Request Forgery
    "CWE-601",  # Open Redirect

    # File & Path
    "CWE-22",   # Path Traversal
    "CWE-434",  # Unrestricted File Upload
    "CWE-98",   # Remote File Inclusion

    # Deserialization
    "CWE-502",  # Deserialization of Untrusted Data

    # CORS / Headers
    "CWE-942",  # Permissive CORS
    "CWE-346",  # Origin Validation Error
}

# CWE IDs that are static/config issues — cannot be exploited via HTTP
_STATIC_CWES: Set[str] = {
    "CWE-353",  # Missing Integrity Check (SRI)
    "CWE-327",  # Broken Crypto Algorithm
    "CWE-328",  # Weak Hash
    "CWE-330",  # Insufficient Randomness
    "CWE-326",  # Inadequate Encryption Strength
    "CWE-798",  # Hardcoded Credentials
    "CWE-259",  # Hardcoded Password
    "CWE-321",  # Hardcoded Cryptographic Key
    "CWE-312",  # Cleartext Storage of Sensitive Info
    "CWE-532",  # Insertion of Sensitive Info into Log
    "CWE-209",  # Error Info Exposure (typically static)
    "CWE-215",  # Insertion of Sensitive Info Into Debug Code
    "CWE-676",  # Use of Potentially Dangerous Function
    "CWE-242",  # Use of Inherently Dangerous Function
    "CWE-377",  # Insecure Temporary File
    "CWE-250",  # Unnecessary Privileges
    "CWE-732",  # Incorrect Permission Assignment
    "CWE-311",  # Missing Encryption
    "CWE-295",  # Improper Certificate Validation
    "CWE-297",  # Improper Validation of Host Cert
    "CWE-338",  # Weak PRNG
    "CWE-699",  # Generic Software Flaw (usually static)
    "CWE-710",  # Improper Coding Standards
    "CWE-1004", # Sensitive Cookie Without HttpOnly
    "CWE-614",  # Sensitive Cookie Not Over HTTPS
    "CWE-16",   # Configuration
}

# Keywords in title/description that signal remote exploitability
_REMOTE_KEYWORDS = {
    "injection", "sqli", "xss", "cross-site", "csrf", "ssrf",
    "idor", "traversal", "path traversal", "rce", "remote code",
    "command injection", "open redirect", "redirect",
    "deserialization", "file upload", "xxe",
    "unauthorized access", "authentication bypass", "auth bypass",
    "broken access", "cors misconfiguration", "cors reflection",
    "api key exposed in endpoint", "broken authentication",
    "nosql injection", "template injection", "ssti",
    "privilege escalation", "insecure direct object",
}

# Keywords that signal static / code-quality issues
_STATIC_KEYWORDS = {
    "missing-integrity", "integrity", "subresource",
    "hardcoded", "hard-coded", "secret", "api key", "api_key",
    "private key", "token in source", "credentials in",
    "entropy", "weak hash", "insecure random",
    "eval(", "exec(", "pickle", "shell=true",
    "ssl", "tls", "certificate", "verify=false",
    "cleartext", "plaintext", "log sensitive",
    "debug mode", "debug=true", "missing csp",
    "missing x-frame", "missing x-content-type",
    "httponly", "secure flag", "samesite",
    "insecure deserialization in code",
    "no integrity", "sri",
}


def classify_vulnerability(finding: VulnerabilityFinding) -> VulnCategory:
    """
    Classify a vulnerability finding as remotely exploitable or static code quality issue.

    Priority:
    1. DAST scanner findings are always remote
    2. CWE-based classification
    3. Keyword-based classification from title + description
    4. Default: CODE_QUALITY (safe fallback — don't promise exploits we can't deliver)
    """
    # DAST findings are always network-exploitable
    if finding.scanner == ScannerType.DAST:
        return VulnCategory.EXPLOITABLE_REMOTE

    # Check CWE codes
    finding_cwes = set(finding.cwe) if finding.cwe else set()
    if finding_cwes & _REMOTE_CWES:
        return VulnCategory.EXPLOITABLE_REMOTE
    if finding_cwes & _STATIC_CWES:
        return VulnCategory.CODE_QUALITY

    # Keyword analysis on title + description (lowercased)
    text = f"{finding.title} {finding.description}".lower()

    remote_score = sum(1 for kw in _REMOTE_KEYWORDS if kw in text)
    static_score = sum(1 for kw in _STATIC_KEYWORDS if kw in text)

    if remote_score > static_score:
        return VulnCategory.EXPLOITABLE_REMOTE
    if static_score > 0:
        return VulnCategory.CODE_QUALITY

    # File extension heuristic: .html/.css/.env files are usually static issues
    ext = finding.file_path.rsplit(".", 1)[-1].lower() if "." in finding.file_path else ""
    if ext in {"html", "htm", "css", "env", "md", "txt", "cfg", "ini", "toml"}:
        return VulnCategory.CODE_QUALITY

    # Default: CODE_QUALITY — safer than promising an exploit that will fail
    return VulnCategory.CODE_QUALITY
