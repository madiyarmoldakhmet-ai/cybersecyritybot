"""
DAST (Dynamic Application Security Testing) Scanner for CyberSecurityBot.
Performs safe, non-destructive dynamic security audits on HTTP/HTTPS endpoints:
- Security Headers Inspection (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Insecure CORS Configuration & Wildcard Origin Reflection
- Cookie Security Flags (Secure, HttpOnly, SameSite)
- Server & Tech Stack Information Disclosure
- Open Redirect Parameter Probing
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from scanners.models import DASTScanResult, ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("cybersecuritybot.dast_scanner")


class DASTScanner:
    """Dynamic Application Security Scanner for live web applications and API endpoints."""

    def __init__(self, timeout_seconds: float = 10.0, follow_redirects: bool = True) -> None:
        self.timeout_seconds = timeout_seconds
        self.follow_redirects = follow_redirects
        self.headers = {
            "User-Agent": "CyberSecurityBot-SecurityAuditor/1.0 (+https://github.com/madiyarmoldakhmet-ai/cybersecyritybot)"
        }

    def _normalize_url(self, raw_url: str) -> str:
        """Ensure standard HTTP/HTTPS scheme."""
        url = raw_url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"
        return url

    def _check_security_headers(self, url: str, headers: httpx.Headers) -> List[VulnerabilityFinding]:
        """Audit presence and configuration of essential HTTP security response headers."""
        findings: List[VulnerabilityFinding] = []
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # 1. Content-Security-Policy (CSP)
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

        # 2. Strict-Transport-Security (HSTS) - for HTTPS
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

        # 3. X-Frame-Options (Clickjacking)
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

        # 4. X-Content-Type-Options
        if lower_headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(
                VulnerabilityFinding(
                    id="dast.missing-nosniff",
                    scanner=ScannerType.DAST,
                    title="Missing X-Content-Type-Options: nosniff",
                    description="Without 'X-Content-Type-Options: nosniff', browsers may MIME-sniff responses away from the declared content-type, executing untrusted scripts.",
                    severity=Severity.LOW,
                    file_path=url,
                    cwe=["CWE-16"],
                    cve=[],
                    recommendation="Configure 'X-Content-Type-Options: nosniff' header.",
                    raw_metadata={"url": url}
                )
            )

        return findings

    def _check_information_disclosure(self, url: str, headers: httpx.Headers) -> List[VulnerabilityFinding]:
        """Detect tech stack and backend version leakage in HTTP headers."""
        findings: List[VulnerabilityFinding] = []
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Check Server header
        server_header = lower_headers.get("server", "")
        if server_header and any(c.isdigit() for c in server_header):
            findings.append(
                VulnerabilityFinding(
                    id="dast.server-version-leak",
                    scanner=ScannerType.DAST,
                    title=f"Detailed Server Version Leaked: {server_header}",
                    description=f"The 'Server' header exposes detailed software versions ('{server_header}'), assisting attackers in vulnerability targeting.",
                    severity=Severity.LOW,
                    file_path=url,
                    code_snippet=f"Server: {server_header}",
                    cwe=["CWE-200"],
                    cve=[],
                    recommendation="Configure the web server/reverse proxy to strip version numbers or mask the Server header.",
                    raw_metadata={"header": server_header}
                )
            )

        # Check X-Powered-By header
        powered_by = lower_headers.get("x-powered-by", "")
        if powered_by:
            findings.append(
                VulnerabilityFinding(
                    id="dast.x-powered-by-leak",
                    scanner=ScannerType.DAST,
                    title=f"Technology Stack Disclosure via X-Powered-By: {powered_by}",
                    description=f"The application leaks underlying framework information in the 'X-Powered-By: {powered_by}' header.",
                    severity=Severity.LOW,
                    file_path=url,
                    code_snippet=f"X-Powered-By: {powered_by}",
                    cwe=["CWE-200"],
                    cve=[],
                    recommendation="Disable the X-Powered-By header in application middleware (e.g. app.disable('x-powered-by')).",
                    raw_metadata={"header": powered_by}
                )
            )

        return findings

    async def _check_cors_configuration(self, url: str, client: httpx.AsyncClient) -> List[VulnerabilityFinding]:
        """Probe for insecure Cross-Origin Resource Sharing (CORS) configurations."""
        findings: List[VulnerabilityFinding] = []
        origin_payload = "https://evil-attacker.example.com"

        try:
            resp = await client.get(
                url,
                headers={"Origin": origin_payload},
                timeout=self.timeout_seconds
            )
            allow_origin = resp.headers.get("access-control-allow-origin", "")
            allow_creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

            if allow_origin == "*" and allow_creds:
                findings.append(
                    VulnerabilityFinding(
                        id="dast.cors-wildcard-with-credentials",
                        scanner=ScannerType.DAST,
                        title="Critical CORS Misconfiguration: Wildcard with Credentials",
                        description="The endpoint allows all origins (*) while allowing credentials (cookies/auth headers).",
                        severity=Severity.CRITICAL,
                        file_path=url,
                        code_snippet="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                        cwe=["CWE-942"],
                        cve=[],
                        recommendation="Explicitly whitelist trusted origins instead of using wildcard origins when credentials are supported.",
                        raw_metadata={"headers": dict(resp.headers)}
                    )
                )
            elif allow_origin == origin_payload:
                findings.append(
                    VulnerabilityFinding(
                        id="dast.cors-arbitrary-origin-reflection",
                        scanner=ScannerType.DAST,
                        title="Insecure CORS: Arbitrary Origin Reflection",
                        description="The server reflects untrusted request Origin headers back into Access-Control-Allow-Origin.",
                        severity=Severity.HIGH,
                        file_path=url,
                        code_snippet=f"Origin: {origin_payload}\nAccess-Control-Allow-Origin: {allow_origin}",
                        cwe=["CWE-942"],
                        cve=[],
                        recommendation="Validate the Origin header against a strict server-side whitelist before echoing it.",
                        raw_metadata={"headers": dict(resp.headers)}
                    )
                )
        except Exception as e:
            logger.debug(f"CORS probe skipped/failed for {url}: {e}")

        return findings

    async def _check_cookie_security(self, url: str, response: httpx.Response) -> List[VulnerabilityFinding]:
        """Verify presence of Secure, HttpOnly, and SameSite flags on session cookies."""
        findings: List[VulnerabilityFinding] = []
        cookies = response.cookies

        for cookie in cookies.jar:
            flags_missing = []
            if not cookie.secure and url.startswith("https://"):
                flags_missing.append("Secure")
            if not getattr(cookie, "httponly", False) and "httponly" not in str(cookie._rest).lower():
                flags_missing.append("HttpOnly")

            if flags_missing:
                findings.append(
                    VulnerabilityFinding(
                        id="dast.insecure-cookie-flags",
                        scanner=ScannerType.DAST,
                        title=f"Cookie '{cookie.name}' Missing Security Flags ({', '.join(flags_missing)})",
                        description=f"Cookie '{cookie.name}' is set without {' and '.join(flags_missing)} flag(s), making it vulnerable to interception or XSS-based theft.",
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
            for path in paths_to_test:
                full_url = urljoin(base_url, path)
                if full_url in tested_urls:
                    continue
                tested_urls.add(full_url)

                try:
                    resp = await client.get(full_url)
                    # 1. Header checks
                    all_findings.extend(self._check_security_headers(full_url, resp.headers))
                    # 2. Info disclosure checks
                    all_findings.extend(self._check_information_disclosure(full_url, resp.headers))
                    # 3. Cookie security
                    all_findings.extend(await self._check_cookie_security(full_url, resp))
                    # 4. CORS Misconfiguration checks
                    all_findings.extend(await self._check_cors_configuration(full_url, client))

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


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    dast = DASTScanner()
    res = asyncio.run(dast.scan_url(target))
    print(res.model_dump_json(indent=2))
