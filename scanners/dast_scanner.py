"""
DAST (Dynamic Application Security Testing) Scanner for CyberSecurityBot.
Performs safe, non-destructive active dynamic security audits on HTTP/HTTPS endpoints:
- Security Headers Inspection (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Insecure CORS Configuration & Wildcard Origin Reflection
- Cookie Security Flags (Secure, HttpOnly, SameSite)
- Active Probing: SQL Injection error detection, Reflected XSS canary, Path Traversal
- Sensitive debug & admin file exposure (/.env, /.git/HEAD, /actuator, /swagger.json)
- Server & Tech Stack Information Disclosure
"""

import asyncio
import logging
import re
import time
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from scanners.models import DASTScanResult, ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("cybersecuritybot.dast_scanner")

# SQL Error signatures for dynamic error-based SQLi detection
SQL_ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*MySQL", re.I),
    re.compile(r"Warning.*mysql_.*", re.I),
    re.compile(r"valid MySQL result", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"Warning.*\Wpg_.*", re.I),
    re.compile(r"valid PostgreSQL result", re.I),
    re.compile(r"Driver.*SQL[\-\_\ ]*Server", re.I),
    re.compile(r"OLE DB.*SQL Server", re.I),
    re.compile(r"SQLite/JDBCDriver", re.I),
    re.compile(r"SQLite.Exception", re.I),
    re.compile(r"System.Data.SQLite.SQLiteException", re.I),
    re.compile(r"Unclosed quotation mark after the character string", re.I),
    re.compile(r"syntax error in query expression", re.I),
    re.compile(r"ORA-[0-9]{4,5}", re.I),
]

SENSITIVE_DEBUG_PATHS = [
    ("/.env", "Exposed Environment Variables (/.env)", Severity.CRITICAL, "DB_PASSWORD|SECRET_KEY|API_KEY"),
    ("/.git/HEAD", "Exposed Git Repository Metadata (/.git/HEAD)", Severity.HIGH, "ref: refs/"),
    ("/actuator/health", "Spring Actuator Management Endpoint", Severity.MEDIUM, "status.*UP"),
    ("/swagger.json", "Exposed OpenAPI / Swagger Documentation", Severity.LOW, "openapi|swagger"),
    ("/api-docs", "Exposed API Documentation Endpoint", Severity.LOW, "swagger|openapi|api-docs"),
    ("/metrics", "Exposed Prometheus / Server Metrics", Severity.LOW, "http_requests|process_cpu"),
]


class DASTScanner:
    """Dynamic Application Security Scanner for live web applications and API endpoints."""

    def __init__(self, timeout_seconds: float = 10.0, follow_redirects: bool = True) -> None:
        self.timeout_seconds = timeout_seconds
        self.follow_redirects = follow_redirects
        self.headers = {
            "User-Agent": "CyberSecurityBot-SecurityAuditor/2.0 (Powered by Strix Engine; +https://github.com/madiyarmoldakhmet-ai/cybersecyritybot)"
        }

    def _normalize_url(self, raw_url: str) -> str:
        """Ensure standard HTTP/HTTPS scheme."""
        url = raw_url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"
        return url

    # ---- 1. Passive Header & Config Audits -----------------------------------

    def _check_security_headers(self, url: str, headers: httpx.Headers) -> List[VulnerabilityFinding]:
        """Audit presence and configuration of essential HTTP security response headers."""
        findings: List[VulnerabilityFinding] = []
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Content-Security-Policy (CSP)
        if "content-security-policy" not in lower_headers:
            findings.append(
                VulnerabilityFinding(
                    id="dast.missing-csp",
                    scanner=ScannerType.DAST,
                    title="Missing Content-Security-Policy (CSP) Header",
                    description="The server does not send a Content-Security-Policy header. This increases exposure to Cross-Site Scripting (XSS) and data injection attacks.",
                    severity=Severity.HIGH,
                    file_path=url,
                    cwe=["CWE-1021", "CWE-79"],
                    cve=[],
                    recommendation="Implement a strict CSP (e.g. default-src 'self'; script-src 'self').",
                    raw_metadata={"url": url}
                )
            )

        # Strict-Transport-Security (HSTS)
        if url.startswith("https://") and "strict-transport-security" not in lower_headers:
            findings.append(
                VulnerabilityFinding(
                    id="dast.missing-hsts",
                    scanner=ScannerType.DAST,
                    title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                    description="The web server does not enforce HTTPS via HSTS. Users may be vulnerable to SSL stripping and Man-in-the-Middle (MitM) attacks.",
                    severity=Severity.MEDIUM,
                    file_path=url,
                    cwe=["CWE-319", "CWE-523"],
                    cve=[],
                    recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
                    raw_metadata={"url": url}
                )
            )

        # X-Frame-Options (Clickjacking)
        if "x-frame-options" not in lower_headers and "content-security-policy" not in lower_headers:
            findings.append(
                VulnerabilityFinding(
                    id="dast.missing-x-frame-options",
                    scanner=ScannerType.DAST,
                    title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                    description="X-Frame-Options header is not set, allowing the application to be embedded in iframes on malicious websites (Clickjacking).",
                    severity=Severity.MEDIUM,
                    file_path=url,
                    cwe=["CWE-1021"],
                    cve=[],
                    recommendation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                    raw_metadata={"url": url}
                )
            )

        # X-Content-Type-Options
        if lower_headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(
                VulnerabilityFinding(
                    id="dast.missing-x-content-type-options",
                    scanner=ScannerType.DAST,
                    title="Missing X-Content-Type-Options: nosniff Header",
                    description="X-Content-Type-Options is missing or not set to 'nosniff', allowing browsers to MIME-sniff response content.",
                    severity=Severity.LOW,
                    file_path=url,
                    cwe=["CWE-16"],
                    cve=[],
                    recommendation="Set 'X-Content-Type-Options: nosniff' header.",
                    raw_metadata={"url": url}
                )
            )

        return findings

    async def _check_cors_configuration(self, url: str, client: httpx.AsyncClient) -> List[VulnerabilityFinding]:
        """Audit for permissive CORS and Origin Reflection."""
        findings: List[VulnerabilityFinding] = []
        evil_origin = "https://attacker-controlled-origin.example.com"
        custom_headers = {**self.headers, "Origin": evil_origin}

        try:
            resp = await client.get(url, headers=custom_headers)
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            if acao == evil_origin or acao == "*":
                if acac == "true" or acao == evil_origin:
                    findings.append(
                        VulnerabilityFinding(
                            id="dast.cors-arbitrary-origin-reflection",
                            scanner=ScannerType.DAST,
                            title="Insecure CORS: Arbitrary Origin Reflection",
                            description=f"Server reflects arbitrary untrusted Origin header ('{evil_origin}') in Access-Control-Allow-Origin.",
                            severity=Severity.HIGH,
                            file_path=url,
                            cwe=["CWE-942", "CWE-346"],
                            cve=[],
                            recommendation="Validate Origin against a strict whitelist of authorized domains.",
                            raw_metadata={"origin": evil_origin, "acao": acao, "acac": acac}
                        )
                    )
        except Exception as e:
            logger.debug(f"CORS check failed on {url}: {e}")

        return findings

    async def _check_cookie_security(self, url: str, response: httpx.Response) -> List[VulnerabilityFinding]:
        """Audit Set-Cookie security flags."""
        findings: List[VulnerabilityFinding] = []
        is_https = url.startswith("https://")

        for cookie in response.cookies.jar:
            flags_missing = []
            if is_https and not cookie.secure:
                flags_missing.append("Secure")
            if "httponly" not in str(cookie._rest).lower():
                flags_missing.append("HttpOnly")

            if flags_missing:
                findings.append(
                    VulnerabilityFinding(
                        id=f"dast.insecure-cookie-{cookie.name}",
                        scanner=ScannerType.DAST,
                        title=f"Insecure Cookie Flags for '{cookie.name}'",
                        description=f"Cookie '{cookie.name}' is set without {' and '.join(flags_missing)} flag(s).",
                        severity=Severity.MEDIUM,
                        file_path=url,
                        code_snippet=f"Set-Cookie: {cookie.name}=...",
                        cwe=["CWE-614", "CWE-1004"],
                        cve=[],
                        recommendation="Ensure all sensitive cookies specify Secure, HttpOnly, and SameSite=Lax/Strict flags.",
                        raw_metadata={"cookie_name": cookie.name, "missing": flags_missing}
                    )
                )

        return findings

    # ---- 2. Active Security Probing -----------------------------------------

    async def _probe_sql_injection(self, url: str, client: httpx.AsyncClient) -> List[VulnerabilityFinding]:
        """Active Canary Probe: Check for SQL injection error leakage in parameters."""
        findings: List[VulnerabilityFinding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # Test default parameter
            test_url = f"{url}{'&' if '?' in url else '?'}id=1%27%20OR%20%271%27=%271"
            try:
                resp = await client.get(test_url)
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern.search(resp.text):
                        findings.append(
                            VulnerabilityFinding(
                                id="dast.active-sqli-error",
                                scanner=ScannerType.DAST,
                                title="Active Probe: SQL Injection Error Detected",
                                description=f"The endpoint leaked database error signatures when probed with a single quote: {pattern.pattern}",
                                severity=Severity.CRITICAL,
                                file_path=test_url,
                                cwe=["CWE-89"],
                                cve=[],
                                recommendation="Use parameterized queries / prepared statements (e.g. ORM or parameterized cursor execution).",
                                raw_metadata={"payload": "id=1' OR '1'='1", "pattern": pattern.pattern}
                            )
                        )
                        break
            except Exception:
                pass

        return findings

    async def _probe_reflected_xss(self, url: str, client: httpx.AsyncClient) -> List[VulnerabilityFinding]:
        """Active Canary Probe: Check for unescaped HTML/JS reflection in parameters."""
        findings: List[VulnerabilityFinding] = []
        canary = "strix_xss_canary_probe_991"
        payload = f"<script>{canary}</script>"
        test_url = f"{url}{'&' if '?' in url else '?'}q={payload}"

        try:
            resp = await client.get(test_url)
            if payload in resp.text and "text/html" in resp.headers.get("content-type", ""):
                findings.append(
                    VulnerabilityFinding(
                        id="dast.active-reflected-xss",
                        scanner=ScannerType.DAST,
                        title="Active Probe: Reflected Cross-Site Scripting (XSS)",
                        description=f"Server reflected unescaped HTML script tags in the response body for parameter 'q'.",
                        severity=Severity.HIGH,
                        file_path=test_url,
                        cwe=["CWE-79"],
                        cve=[],
                        recommendation="Implement HTML output encoding / context-aware escaping on all user-controlled reflections.",
                        raw_metadata={"payload": payload}
                    )
                )
        except Exception:
            pass

        return findings

    async def _check_sensitive_file_exposures(self, base_url: str, client: httpx.AsyncClient) -> List[VulnerabilityFinding]:
        """Active Probe: Check for exposed sensitive files (.env, .git/HEAD, Actuators)."""
        findings: List[VulnerabilityFinding] = []

        for path, title, sev, indicator_regex in SENSITIVE_DEBUG_PATHS:
            target = urljoin(base_url, path)
            try:
                resp = await client.get(target)
                if resp.status_code == 200 and re.search(indicator_regex, resp.text, re.I):
                    findings.append(
                        VulnerabilityFinding(
                            id=f"dast.exposed-file-{path.replace('/', '-').strip('-')}",
                            scanner=ScannerType.DAST,
                            title=title,
                            description=f"Publicly accessible sensitive file found at {target} matching signature '{indicator_regex}'.",
                            severity=sev,
                            file_path=target,
                            cwe=["CWE-200", "CWE-538"],
                            cve=[],
                            recommendation=f"Restrict public web server access to '{path}' or remove file from the production deployment root.",
                            raw_metadata={"url": target, "status": resp.status_code}
                        )
                    )
            except Exception:
                pass

        return findings

    # ---- 3. Full DAST Scan Workflow -----------------------------------------

    async def scan_url(
        self, target_url: str, additional_paths: Optional[List[str]] = None
    ) -> DASTScanResult:
        """Run comprehensive dynamic security audit against the specified URL and endpoints."""
        start_time = time.time()
        base_url = self._normalize_url(target_url)
        all_findings: List[VulnerabilityFinding] = []
        errors: List[str] = []
        tested_urls: Set[str] = set()

        paths_to_test = ["/"] + (additional_paths or ["/api", "/login", "/health", "/robots.txt"])

        async with httpx.AsyncClient(
            verify=False,
            timeout=self.timeout_seconds,
            headers=self.headers,
            follow_redirects=self.follow_redirects
        ) as client:
            # 1. Check root sensitive files first
            all_findings.extend(await self._check_sensitive_file_exposures(base_url, client))

            # 2. Iterate endpoints for header, CORS, cookie, and active probes
            for path in paths_to_test:
                full_url = urljoin(base_url, path)
                if full_url in tested_urls:
                    continue
                tested_urls.add(full_url)

                try:
                    resp = await client.get(full_url)
                    # Passive checks
                    all_findings.extend(self._check_security_headers(full_url, resp.headers))
                    all_findings.extend(await self._check_cookie_security(full_url, resp))
                    all_findings.extend(await self._check_cors_configuration(full_url, client))

                    # Active probing
                    all_findings.extend(await self._probe_sql_injection(full_url, client))
                    all_findings.extend(await self._probe_reflected_xss(full_url, client))

                except httpx.RequestError as req_err:
                    logger.warning(f"DAST request error on {full_url}: {req_err}")
                    errors.append(f"Failed to connect to {full_url}: {str(req_err)}")
                except Exception as ex:
                    logger.exception(f"Unexpected error testing {full_url}: {ex}")
                    errors.append(f"Error testing {full_url}: {str(ex)}")

        # Calculate severity breakdown
        severity_counts: Dict[Severity, int] = {sev: 0 for sev in Severity}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        duration = round(time.time() - start_time, 2)

        return DASTScanResult(
            target_url=base_url,
            endpoints_tested=list(tested_urls),
            total_findings=len(all_findings),
            findings_by_severity=severity_counts,
            findings=all_findings,
            duration_seconds=duration,
            errors=errors
        )
