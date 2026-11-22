"""
System Architecture Analyst & Defensive Adversarial Threat Modeler (14th Scanner).

Combines a Senior Systems Analyst view with an adversarial defensive threat-modeling mindset
on verified repositories (zero exploit generation; 100% static code & architecture review):

1. Tech Stack, Data-Store & Infrastructure Mapping
2. Attack Surface & Trust Boundary Analysis (endpoints, auth coverage %, unprotected mutations)
3. Systemic Architectural Misconfiguration Detection:
   - CORS wildcard + credentials (CWE-942)
   - Insecure session cookie flags (CWE-614 / CWE-1004)
   - Missing global rate limiting on auth/mutating APIs (CWE-770)
   - Missing HTTP security headers / CSP / Helmet (CWE-693)
   - Container running as root in Dockerfile (CWE-250)
   - Production debug mode / stack trace leakage (CWE-209)
   - Systemic weak auth coverage across sensitive endpoints (CWE-862)
4. Post-Scan STRIDE Classification & Conceptual Multi-Step Risk Chaining (Blast Radius)
   showing how verified findings across files compound into architectural business risks,
   paired with a prioritized engineering remediation roadmap.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.route_extractor import DiscoveredEndpoint, RouteExtractor

logger = logging.getLogger("aegis.system_analyst")

_IGNORED_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", "out", "dist", "build",
    "coverage", ".turbo", ".cache", ".venv", "venv", "__pycache__", "vendor",
    ".pytest_cache", ".mypy_cache", "temp_scans",
}
_SOURCE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".dart", ".java", ".rb", ".php", ".yml", ".yaml", ".json", ".toml",
}
_PUBLIC_ROUTE_RE = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|signup|sign-up|register|logout|health|healthz|ready|ping|"
    r"status|metrics|docs|openapi|public|verify|reset-password|forgot-password|oauth|callback|"
    r"demo|chat|contact|subscribe|newsletter|search|catalog|products)(?:/|$)",
    re.IGNORECASE,
)

# Tech-stack detectors (pattern -> label)
_FRAMEWORK_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bfrom\s+fastapi\b|\bFastAPI\s*\("), "FastAPI"),
    (re.compile(r"\bfrom\s+flask\b|\bFlask\s*\("), "Flask"),
    (re.compile(r"\bdjango\.|DJANGO_SETTINGS_MODULE"), "Django"),
    (re.compile(r'"next"\s*:|next\.config\.'), "Next.js"),
    (re.compile(r"\bexpress\s*\(\s*\)|from\s+['\"]express['\"]"), "Express"),
    (re.compile(r"@nestjs/core|@Controller\("), "NestJS"),
    (re.compile(r'"react"\s*:'), "React"),
    (re.compile(r"package:flutter/|flutter:"), "Flutter/Dart"),
    (re.compile(r"\bgithub\.com/gin-gonic/gin\b|\bgin\.Default\("), "Go/Gin"),
)
_DATASTORE_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bprisma\b|@prisma/client", re.IGNORECASE), "Prisma ORM"),
    (re.compile(r"\bsqlalchemy\b", re.IGNORECASE), "SQLAlchemy"),
    (re.compile(r"\bsupabase\b", re.IGNORECASE), "Supabase"),
    (re.compile(r"\bfirestore\b|\bfirebase\b", re.IGNORECASE), "Firebase/Firestore"),
    (re.compile(r"\bmongoose\b|\bmongodb\b|\bpymongo\b", re.IGNORECASE), "MongoDB"),
    (re.compile(r"\bpsycopg2?\b|\basyncpg\b|\bpostgres(?:ql)?\b", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"\bsqlite3?\b", re.IGNORECASE), "SQLite"),
    (re.compile(r"\bredis\b|\bioredis\b|\bupstash\b", re.IGNORECASE), "Redis"),
)

# Defensive posture signals across the codebase
_RATE_LIMIT_RE = re.compile(
    r"\b(?:slowapi|Limiter\(|express-rate-limit|rateLimit\(|@upstash/ratelimit|"
    r"django_ratelimit|ThrottlerModule|ratelimit|rate_limit|limit_req)\b",
    re.IGNORECASE,
)
_SECURITY_HEADERS_RE = re.compile(
    r"(?:\bhelmet\s*\(|Content-Security-Policy|Strict-Transport-Security|"
    r"X-Frame-Options|X-Content-Type-Options|SecurityMiddleware|secure_headers)",
    re.IGNORECASE,
)
_CORS_WILDCARD_CREDS_RE = re.compile(
    r"(?:allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\][\s\S]{0,180}allow_credentials\s*=\s*True|"
    r"allow_credentials\s*=\s*True[\s\S]{0,180}allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|"
    r"origin\s*:\s*(?:true|['\"]\*['\"])[\s\S]{0,140}credentials\s*:\s*true|"
    r"credentials\s*:\s*true[\s\S]{0,140}origin\s*:\s*(?:true|['\"]\*['\"]))",
    re.IGNORECASE,
)
_INSECURE_COOKIE_RE = re.compile(
    r"(?:set_cookie\s*\([^)]*(?:httponly\s*=\s*False|secure\s*=\s*False)|"
    r"(?:res\.cookie|cookies\(\)\.set)\s*\([^)]*(?:httpOnly\s*:\s*false|secure\s*:\s*false))",
    re.IGNORECASE | re.DOTALL,
)
_DEBUG_LEAK_RE = re.compile(
    r"(?:\bapp\.run\s*\([^)]*debug\s*=\s*True|"
    r"^\s*DEBUG\s*=\s*True\s*$|"
    r"return\s+[^\n]*(?:traceback\.format_exc\(\)|err\.stack|error\.stack))",
    re.IGNORECASE | re.MULTILINE,
)


def _is_test_or_scanner_file(rel_path: str) -> bool:
    low = rel_path.lower()
    return (
        low.endswith("system_analyst.py")
        or "/tests/" in low
        or low.startswith("tests/")
        or "__tests__/" in low
        or ".test." in low
        or ".spec." in low
    )


def _line_of(content: str, offset: int) -> int:
    return content[:offset].count("\n") + 1


def _snippet(content: str, line_no: int, pad: int = 3) -> str:
    lines = content.splitlines()
    lo = max(0, line_no - 1 - pad)
    hi = min(len(lines), line_no + pad)
    return "\n".join(lines[lo:hi])


class SystemAnalystScanner:
    """
    Performs holistic architectural mapping, trust-boundary auditing, STRIDE classification,
    and conceptual multi-step risk chaining across the target repository.
    """

    def __init__(self) -> None:
        self.route_extractor = RouteExtractor()

    async def scan(self, target_dir: Path) -> Tuple[List[VulnerabilityFinding], Dict[str, Any]]:
        """
        Scan repository architecture and return `(systemic_findings, preliminary_system_analysis)`.
        Call `enrich_with_findings(system_analysis, all_clean_findings)` once all scanners finish
        to compute full STRIDE breakdown and cross-file conceptual risk chains.
        """
        target_path = Path(target_dir).resolve()
        if not target_path.exists():
            return [], self._empty_analysis()

        # Single-file scan mode: skip repo-wide architecture heuristics
        if target_path.is_file():
            return [], self._empty_analysis()

        endpoints = [
            ep
            for ep in self.route_extractor.scan_repository(target_path)
            if ep.framework != "openapi" and not _is_test_or_scanner_file(ep.file_path)
        ]

        frameworks: Set[str] = set()
        languages: Set[str] = set()
        datastores: Set[str] = set()
        infra: Set[str] = set()
        has_rate_limit = False
        has_security_headers = False
        first_server_entry: Optional[Tuple[str, int, str]] = None
        findings: List[VulnerabilityFinding] = []
        seen_rules: Set[str] = set()
        total_code_files = 0

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in _IGNORED_DIRS and not d.startswith(".")]
            for fname in sorted(files):
                fp = Path(root) / fname
                rel = fp.relative_to(target_path).as_posix()

                # Infrastructure inventory
                low_name = fname.lower()
                if low_name == "dockerfile" or low_name.startswith("dockerfile."):
                    infra.add("Docker")
                    self._check_dockerfile(fp, rel, findings, seen_rules)
                    continue
                if low_name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                    infra.add("Docker Compose")
                elif ".github/workflows/" in rel:
                    infra.add("GitHub Actions CI/CD")
                elif low_name == "render.yaml":
                    infra.add("Render")
                elif low_name.endswith(".tf"):
                    infra.add("Terraform")
                elif low_name == "vercel.json":
                    infra.add("Vercel")

                if fp.suffix.lower() not in _SOURCE_EXTS:
                    continue
                if _is_test_or_scanner_file(rel):
                    continue
                try:
                    if fp.stat().st_size > 512 * 1024:
                        continue
                    content = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                total_code_files += 1
                ext_low = fp.suffix.lower()
                if ext_low == ".py":
                    languages.add("Python")
                elif ext_low in {".ts", ".tsx"}:
                    languages.add("TypeScript")
                elif ext_low in {".js", ".jsx", ".mjs", ".cjs"}:
                    languages.add("JavaScript")
                elif ext_low == ".dart":
                    languages.add("Dart/Flutter")
                elif ext_low == ".go":
                    languages.add("Go")
                elif ext_low == ".php":
                    languages.add("PHP")
                elif ext_low == ".java":
                    languages.add("Java")

                for pat, label in _FRAMEWORK_PATTERNS:
                    if pat.search(content):
                        frameworks.add(label)
                        if first_server_entry is None and label in ("FastAPI", "Flask", "Django", "Next.js", "Express", "NestJS", "Go/Gin"):
                            first_server_entry = (rel, 1, _snippet(content, 1, pad=4))

                for pat, label in _DATASTORE_PATTERNS:
                    if pat.search(content):
                        datastores.add(label)

                if not has_rate_limit and _RATE_LIMIT_RE.search(content):
                    has_rate_limit = True
                if not has_security_headers and _SECURITY_HEADERS_RE.search(content):
                    has_security_headers = True

                # Systemic Check 1: CORS wildcard + credentials
                if "sys-cors-wildcard-credentials" not in seen_rules and fp.suffix.lower() in {".py", ".js", ".ts", ".mjs", ".cjs"}:
                    m_cors = _CORS_WILDCARD_CREDS_RE.search(content)
                    if m_cors:
                        seen_rules.add("sys-cors-wildcard-credentials")
                        ln = _line_of(content, m_cors.start())
                        findings.append(
                            VulnerabilityFinding(
                                id="sys-cors-wildcard-credentials",
                                scanner=ScannerType.SYSTEM_ANALYST,
                                title="Architecture: Wildcard CORS Combined with Credentials Enabled",
                                description=(
                                    f"Server CORS policy in `{rel}:{ln}` allows wildcard/reflected origins alongside "
                                    "`credentials=True`, permitting untrusted origins to make authenticated cross-site requests."
                                ),
                                severity=Severity.CRITICAL,
                                file_path=rel,
                                line_start=ln,
                                line_end=ln,
                                code_snippet=_snippet(content, ln),
                                cwe=["CWE-942", "CWE-346"],
                                recommendation="Replace wildcard/reflected CORS origins with an explicit allowlist of trusted frontend origins.",
                                raw_metadata={"stride": "Spoofing"},
                            )
                        )

                # Systemic Check 2: Insecure session cookie flags
                if "sys-insecure-cookie-flags" not in seen_rules and fp.suffix.lower() in {".py", ".js", ".ts", ".tsx"}:
                    m_cookie = _INSECURE_COOKIE_RE.search(content)
                    if m_cookie:
                        seen_rules.add("sys-insecure-cookie-flags")
                        ln = _line_of(content, m_cookie.start())
                        findings.append(
                            VulnerabilityFinding(
                                id="sys-insecure-cookie-flags",
                                scanner=ScannerType.SYSTEM_ANALYST,
                                title="Architecture: Insecure Cookie Flags (httpOnly=false or secure=false)",
                                description=(
                                    f"Cookie set in `{rel}:{ln}` disables `HttpOnly` or `Secure`, exposing session tokens "
                                    "to client-side XSS exfiltration or cleartext network interception."
                                ),
                                severity=Severity.HIGH,
                                file_path=rel,
                                line_start=ln,
                                line_end=ln,
                                code_snippet=_snippet(content, ln),
                                cwe=["CWE-614", "CWE-1004"],
                                recommendation="Enforce `HttpOnly=True`, `Secure=True`, and `SameSite=Lax` (or `Strict`) on all session/auth cookies.",
                                raw_metadata={"stride": "Information Disclosure"},
                            )
                        )

                # Systemic Check 3: Debug mode / stack-trace leak in API response
                if "sys-debug-stacktrace-prod" not in seen_rules and fp.suffix.lower() in {".py", ".js", ".ts"}:
                    m_dbg = _DEBUG_LEAK_RE.search(content)
                    if m_dbg:
                        seen_rules.add("sys-debug-stacktrace-prod")
                        ln = _line_of(content, m_dbg.start())
                        findings.append(
                            VulnerabilityFinding(
                                id="sys-debug-stacktrace-prod",
                                scanner=ScannerType.SYSTEM_ANALYST,
                                title="Architecture: Debug Mode or Internal Stack Trace Exposed to Clients",
                                description=(
                                    f"`{rel}:{ln}` enables debug mode or returns raw stack traces to clients, leaking internal "
                                    "file paths, dependencies, and framework internals useful for mapping further flaws."
                                ),
                                severity=Severity.HIGH,
                                file_path=rel,
                                line_start=ln,
                                line_end=ln,
                                code_snippet=_snippet(content, ln),
                                cwe=["CWE-209", "CWE-489"],
                                recommendation="Disable debug mode in production via environment variables and return opaque error IDs while logging stack traces server-side.",
                                raw_metadata={"stride": "Information Disclosure"},
                            )
                        )

        # Attack Surface & Auth Coverage Matrix
        non_public = [ep for ep in endpoints if not _PUBLIC_ROUTE_RE.search(ep.path)]
        protected_non_public = [ep for ep in non_public if ep.has_auth_guard]
        unprotected_mutations = [
            ep
            for ep in non_public
            if not ep.has_auth_guard and ep.method.upper() in {"POST", "PUT", "PATCH", "DELETE", "ACTION"}
        ]
        auth_coverage_pct = (
            round((len(protected_non_public) / len(non_public)) * 100)
            if non_public
            else (100 if endpoints else None)
        )

        # Systemic Check 4: Weak Trust Boundary (low auth coverage across >= 3 mutating routes)
        if len(unprotected_mutations) >= 3 and (auth_coverage_pct is not None and auth_coverage_pct < 50):
            sample_routes = ", ".join(f"{ep.method} {ep.path}" for ep in unprotected_mutations[:5])
            first_ep = unprotected_mutations[0]
            findings.append(
                VulnerabilityFinding(
                    id="sys-trust-boundary-unauth-surface",
                    scanner=ScannerType.SYSTEM_ANALYST,
                    title=f"Architecture: Weak Trust Boundary ({len(unprotected_mutations)} Unprotected Mutating Endpoints)",
                    description=(
                        f"Only {auth_coverage_pct}% of non-public API endpoints enforce an authentication guard. "
                        f"State-changing routes exposed without visible auth middleware include: {sample_routes}."
                    ),
                    severity=Severity.HIGH,
                    file_path=first_ep.file_path,
                    line_start=first_ep.line_number,
                    line_end=first_ep.line_number,
                    code_snippet=first_ep.code_snippet,
                    cwe=["CWE-862", "CWE-306"],
                    recommendation="Enforce a default-deny authentication middleware/dependency at the router layer and explicitly allowlist only public routes.",
                    raw_metadata={"stride": "Elevation of Privilege"},
                )
            )

        # Systemic Check 5: Missing rate limiting on multi-endpoint APIs
        anchor_file, anchor_line, anchor_snip = self._pick_anchor(endpoints, first_server_entry)
        if len(endpoints) >= 3 and not has_rate_limit and anchor_file:
            findings.append(
                VulnerabilityFinding(
                    id="sys-missing-rate-limit",
                    scanner=ScannerType.SYSTEM_ANALYST,
                    title="Architecture: No API Rate Limiting Detected Across Endpoints",
                    description=(
                        f"Discovered {len(endpoints)} API endpoints with no rate-limiting middleware detected "
                        "(e.g. `slowapi`, `express-rate-limit`, `@upstash/ratelimit`). Auth, search, and billing routes are exposed to brute-force and resource exhaustion."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=anchor_file,
                    line_start=anchor_line,
                    line_end=anchor_line,
                    code_snippet=anchor_snip,
                    cwe=["CWE-770", "CWE-307"],
                    recommendation="Add sliding-window rate limiting on login, verification, upload, and state-mutating API routes.",
                    raw_metadata={"stride": "Denial of Service"},
                )
            )

        # Systemic Check 6: Missing HTTP security headers on web/API servers
        web_frameworks = frameworks & {"FastAPI", "Flask", "Django", "Next.js", "Express", "NestJS", "Go/Gin"}
        if web_frameworks and len(endpoints) >= 2 and not has_security_headers and anchor_file:
            findings.append(
                VulnerabilityFinding(
                    id="sys-missing-security-headers",
                    scanner=ScannerType.SYSTEM_ANALYST,
                    title="Architecture: Missing HTTP Security Headers (CSP / HSTS / X-Frame-Options)",
                    description=(
                        f"Web service ({', '.join(sorted(web_frameworks))}) does not configure defensive HTTP headers "
                        "(`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`), "
                        "increasing clickjacking and XSS blast radius."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=anchor_file,
                    line_start=anchor_line,
                    line_end=anchor_line,
                    code_snippet=anchor_snip,
                    cwe=["CWE-693", "CWE-1021"],
                    recommendation="Add security-header middleware (e.g. `helmet`, Next.js `headers()`, or FastAPI middleware setting CSP, HSTS, X-Frame-Options: DENY, and nosniff).",
                    raw_metadata={"stride": "Tampering"},
                )
            )

        # Build architectural summary payload
        sensitive_sinks = sorted({op for ep in endpoints for op in ep.sensitive_operations})
        trust_boundaries = self._build_trust_boundaries(frameworks, datastores, infra, endpoints, unprotected_mutations)

        analysis: Dict[str, Any] = {
            "tech_stack": sorted(frameworks) or sorted(languages) or ["Generic / Multi-language"],
            "datastores": sorted(datastores),
            "infrastructure": sorted(infra),
            "files_analyzed": total_code_files,
            "endpoints_total": len(endpoints),
            "non_public_endpoints": len(non_public),
            "protected_endpoints": len(protected_non_public),
            "auth_coverage_pct": auth_coverage_pct,
            "unprotected_mutations": [
                {"method": ep.method, "path": ep.path, "location": f"{ep.file_path}:{ep.line_number}"}
                for ep in unprotected_mutations[:10]
            ],
            "sensitive_sinks": sensitive_sinks,
            "defense_controls": {
                "rate_limiting": has_rate_limit,
                "security_headers": has_security_headers,
            },
            "trust_boundaries": trust_boundaries,
            "stride_breakdown": {},
            "risk_chains": [],
            "remediation_roadmap": [],
        }

        return findings, analysis

    def enrich_with_findings(
        self,
        analysis: Dict[str, Any],
        findings: List[VulnerabilityFinding],
    ) -> Dict[str, Any]:
        """
        Synthesize STRIDE threat counts, conceptual multi-step risk chains (blast radius),
        and an architectural remediation roadmap from all validated scanner findings.
        """
        stride: Dict[str, int] = {
            "Spoofing": 0,
            "Tampering": 0,
            "Repudiation": 0,
            "Information Disclosure": 0,
            "Denial of Service": 0,
            "Elevation of Privilege": 0,
        }

        buckets: Dict[str, List[VulnerabilityFinding]] = {
            "backdoor": [],
            "secret": [],
            "auth_idor": [],
            "injection_rce": [],
            "pii": [],
            "infra_priv": [],
            "supply_chain": [],
            "race_payment": [],
        }

        for f in findings:
            cat = self._classify_stride(f)
            stride[cat] = stride.get(cat, 0) + 1

            blob = f"{f.id} {f.title} {f.description} {' '.join(f.cwe)}".lower()
            id_title = f"{f.id} {f.title} {' '.join(f.cwe)}".lower()
            if f.scanner == ScannerType.BACKDOOR or "backdoor" in id_title or "cwe-506" in id_title or "cwe-912" in id_title:
                buckets["backdoor"].append(f)
            if f.scanner in (ScannerType.SECRET, ScannerType.GIT_HISTORY) or "cwe-798" in id_title or "secret" in id_title or "api key" in id_title or "token" in id_title:
                buckets["secret"].append(f)
            if any(k in id_title for k in ("idor", "cwe-639", "cwe-862", "cwe-285", "cwe-284", "cwe-942", "unauth", "broken_auth", "missing auth", "trust boundary", "jwt", "cors", "rbac")):
                buckets["auth_idor"].append(f)
            if f.severity in (Severity.CRITICAL, Severity.HIGH) and "b404" not in id_title and any(k in id_title for k in ("sql", "cwe-89", "command", "cwe-78", "shell", "eval", "rce", "ssrf", "cwe-918", "deserial", "path traversal", "cwe-22", "xss", "cwe-79", "mass assignment", "cwe-915")):
                buckets["injection_rce"].append(f)
            if any(k in blob for k in ("иин", "iin", "pii", "персонал", "cwe-200", "password hash", "stack trace")):
                buckets["pii"].append(f)
            if any(k in blob for k in ("docker", "root", "cwe-250", "firestore", "cwe-732")):
                buckets["infra_priv"].append(f)
            if f.scanner in (ScannerType.SCA, ScannerType.PIP_AUDIT) or "npm-" in blob or "cve-" in blob:
                buckets["supply_chain"].append(f)
            if any(k in blob for k in ("race", "cwe-362", "webhook", "cwe-345", "balance", "payment")):
                buckets["race_payment"].append(f)

        chains: List[Dict[str, Any]] = []

        # Chain 1: Covert Backdoor / Supply-Chain Implant
        if buckets["backdoor"]:
            refs = self._format_refs(buckets["backdoor"])
            chains.append({
                "severity": "CRITICAL",
                "title": "Covert Backdoor / Implant Compromise Chain",
                "steps": [
                    f"Обнаружен скрытый бэкдор или вредоносная закладка ({refs})",
                    "Обход штатной аутентификации или несанкционированное выполнение кода / слив окружения",
                    "Полный неконтролируемый доступ к продакшен-среде и секретам",
                ],
                "defense": "Немедленно удалить закладку, проверить git blame/историю коммитов и ротировать все ключи и токены среды.",
            })

        # Chain 2: Injection / RCE + Privileged Container / Exposed Secrets
        if buckets["injection_rce"] and (buckets["infra_priv"] or buckets["secret"]):
            entry_refs = self._format_refs(buckets["injection_rce"])
            amp_refs = self._format_refs(buckets["infra_priv"] or buckets["secret"])
            chains.append({
                "severity": "CRITICAL",
                "title": "Input Injection → Host/Cloud Lateral Movement Chain",
                "steps": [
                    f"Точка входа через инъекцию / опасный sink ({entry_refs})",
                    f"Усиление радиуса поражения за счёт привилегий контейнера или доступных секретов ({amp_refs})",
                    "Риск компрометации базы данных, облачных API и смежных сервисов",
                ],
                "defense": "Закрыть инъекции параметризацией/валидацией, перевести контейнер на непривилегированного USER и изолировать секреты в KMS/Vault.",
            })

        # Chain 3: Broken Auth / IDOR + Database / Payment Logic
        if buckets["auth_idor"] and (buckets["race_payment"] or analysis.get("unprotected_mutations")):
            auth_refs = self._format_refs(buckets["auth_idor"])
            second = self._format_refs(buckets["race_payment"]) if buckets["race_payment"] else f"{len(analysis.get('unprotected_mutations') or [])} незащищённых мутирующих роутов"
            chains.append({
                "severity": "CRITICAL",
                "title": "Trust Boundary Bypass → Account & Business-Logic Abuse",
                "steps": [
                    f"Слабая граница доверия / отсутствие проверки прав ({auth_refs})",
                    f"Доступ к операциям изменения данных, балансов или вебхуков ({second})",
                    "Риск несанкционированного изменения чужих данных, подмены ролей или финансовых потерь",
                ],
                "defense": "Внедрить default-deny auth middleware, проверять owner_id/tenant_id на уровне ORM-запросов и обернуть балансовые операции в транзакции с блокировкой.",
            })

        # Chain 4: Hardcoded / Ghost Secrets + External Services
        if buckets["secret"]:
            sec_refs = self._format_refs(buckets["secret"])
            chains.append({
                "severity": "CRITICAL",
                "title": "Credential Leakage → Direct Cloud / API Takeover",
                "steps": [
                    f"Обнаружены открытые или удалённые из HEAD, но живые в Git-истории секреты ({sec_refs})",
                    "Прямой доступ к внешним API, базам данных или репозиторию в обход приложения",
                    "Риск утечки данных клиентов, несанкционированного биллинга или подмены релизов",
                ],
                "defense": "Отозвать и перевыпустить скомпрометированные ключи, вычистить историю Git (git filter-repo) и включить pre-commit secret scanning.",
            })

        # Chain 5: PII / Data Disclosure + Compliance Impact
        if buckets["pii"] or (buckets["auth_idor"] and analysis.get("datastores")):
            pii_refs = self._format_refs(buckets["pii"] or buckets["auth_idor"])
            chains.append({
                "severity": "HIGH",
                "title": "Sensitive Data / PII Exposure → Regulatory & Reputational Risk",
                "steps": [
                    f"Точка утечки чувствительных данных или ПДн/ИИН ({pii_refs})",
                    "Отсутствие маскирования / изоляции на границе ответа или логов",
                    "Нарушение требований защиты ПДн (ст. 79 КоАП РК / Закон РК № 94-V)",
                ],
                "defense": "Внедрить централизованное маскирование ИИН/ПДн в логах, DTO-фильтрацию ответов API и строгий RBAC.",
            })

        # Chain 6: Vulnerable Supply-Chain Dependencies
        if buckets["supply_chain"] and len(chains) < 4:
            sca_refs = self._format_refs(buckets["supply_chain"])
            chains.append({
                "severity": "HIGH",
                "title": "Transitive Supply-Chain Dependency Exposure",
                "steps": [
                    f"Уязвимые пакеты с известными CVE в зависимостях ({sca_refs})",
                    "Наследование известных уязвимостей (auth bypass / RCE / prototype pollution) в рантайме",
                ],
                "defense": "Обновить уязвимые зависимости до пропатченных версий, зафиксировать lockfile и включить автоматический SCA-контроль в CI.",
            })

        roadmap = self._build_roadmap(buckets, analysis)

        enriched = dict(analysis)
        enriched["stride_breakdown"] = stride
        enriched["risk_chains"] = chains[:5]
        enriched["remediation_roadmap"] = roadmap
        return enriched

    def _check_dockerfile(
        self,
        fp: Path,
        rel: str,
        findings: List[VulnerabilityFinding],
        seen_rules: Set[str],
    ) -> None:
        if "sys-docker-root-user" in seen_rules:
            return
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        if not re.search(r"^\s*FROM\s+", content, re.IGNORECASE | re.MULTILINE):
            return
        # Check if any non-root USER instruction exists in the final stage
        stages = re.split(r"(?im)^\s*FROM\s+", content)
        final_stage = stages[-1] if stages else content
        user_lines = re.findall(r"(?im)^\s*USER\s+(\S+)", final_stage)
        has_non_root = any(u.lower() not in ("root", "0", "0:0") for u in user_lines)
        if not has_non_root:
            seen_rules.add("sys-docker-root-user")
            cmd_match = re.search(r"(?im)^\s*(?:CMD|ENTRYPOINT)\s+", final_stage)
            line_no = _line_of(content, content.rfind(cmd_match.group(0))) if cmd_match else 1
            findings.append(
                VulnerabilityFinding(
                    id="sys-docker-root-user",
                    scanner=ScannerType.SYSTEM_ANALYST,
                    title="Architecture: Docker Container Runs as Root User",
                    description=(
                        f"`{rel}` does not switch to a non-root `USER` in the final image stage. "
                        "If an application vulnerability is exploited, the attacker gains root privileges inside the container."
                    ),
                    severity=Severity.HIGH,
                    file_path=rel,
                    line_start=max(1, line_no),
                    line_end=max(1, line_no),
                    code_snippet=_snippet(content, max(1, line_no)),
                    cwe=["CWE-250"],
                    recommendation="Create a dedicated unprivileged user (`useradd -m appuser`) and add `USER appuser` before `CMD`/`ENTRYPOINT`.",
                    raw_metadata={"stride": "Elevation of Privilege"},
                )
            )

    @staticmethod
    def _pick_anchor(
        endpoints: List[DiscoveredEndpoint],
        first_server_entry: Optional[Tuple[str, int, str]],
    ) -> Tuple[Optional[str], int, Optional[str]]:
        if first_server_entry:
            return first_server_entry
        if endpoints:
            ep = endpoints[0]
            return ep.file_path, ep.line_number, ep.code_snippet
        return None, 1, None

    @staticmethod
    def _build_trust_boundaries(
        frameworks: Set[str],
        datastores: Set[str],
        infra: Set[str],
        endpoints: List[DiscoveredEndpoint],
        unprotected_mutations: List[DiscoveredEndpoint],
    ) -> List[str]:
        boundaries: List[str] = []
        if endpoints:
            boundaries.append(
                f"Client → API Perimeter ({len(endpoints)} маршрутов; незащищённых мутаций: {len(unprotected_mutations)})"
            )
        if datastores:
            boundaries.append(f"Application → Data Layer ({', '.join(sorted(datastores))})")
        if any("outbound_http_ssrf" in ep.sensitive_operations for ep in endpoints):
            boundaries.append("Application → External HTTP / Webhooks (контроль SSRF и подписей)")
        if infra:
            boundaries.append(f"Runtime & CI/CD Boundary ({', '.join(sorted(infra))})")
        if not boundaries and frameworks:
            boundaries.append(f"Application Layer ({', '.join(sorted(frameworks))})")
        return boundaries

    @staticmethod
    def _classify_stride(f: VulnerabilityFinding) -> str:
        meta_stride = (f.raw_metadata or {}).get("stride")
        if isinstance(meta_stride, str) and meta_stride:
            return meta_stride
        blob = f"{f.id} {f.title} {f.description} {' '.join(f.cwe)}".lower()
        if any(k in blob for k in ("cwe-639", "idor", "cwe-862", "cwe-285", "cwe-250", "cwe-732", "privilege", "root", "rbac", "unauth")):
            return "Elevation of Privilege"
        if any(k in blob for k in ("cwe-798", "secret", "token", "key", "jwt", "spoof", "cors", "cwe-942", "cwe-295", "ssl", "tls")):
            return "Spoofing"
        if any(k in blob for k in ("sql", "cwe-89", "cwe-78", "shell", "eval", "exec", "backdoor", "cwe-506", "mass assignment", "cwe-915", "xss", "cwe-79", "ssrf", "cwe-918", "prototype", "webhook", "cwe-345")):
            return "Tampering"
        if any(k in blob for k in ("cwe-770", "rate limit", "cwe-362", "race", "redos", "dos")):
            return "Denial of Service"
        if any(k in blob for k in ("cwe-200", "cwe-209", "cwe-312", "cwe-319", "иин", "iin", "pii", "cookie", "cwe-614", "cwe-22", "path traversal", "disclosure", "leak")):
            return "Information Disclosure"
        return "Tampering"

    @staticmethod
    def _format_refs(items: List[VulnerabilityFinding], limit: int = 2) -> str:
        parts = []
        seen = set()
        for f in items:
            ref = f"`{f.file_path}:{f.line_start or 1}`"
            if ref not in seen:
                seen.add(ref)
                parts.append(f"{f.title[:48]} ({ref})")
            if len(parts) >= limit:
                break
        return "; ".join(parts)

    @staticmethod
    def _build_roadmap(buckets: Dict[str, List[VulnerabilityFinding]], analysis: Dict[str, Any]) -> List[str]:
        steps: List[str] = []
        if buckets["backdoor"] or buckets["secret"]:
            steps.append("P0 (Срочно): Удалить закладки/бэкдоры, отозвать утекшие секреты и вычистить Git-историю.")
        if buckets["injection_rce"] or buckets["auth_idor"]:
            steps.append("P1 (Периметр и права): Закрыть инъекции (SQLi/Cmd/SSRF), внедрить default-deny auth middleware и проверку owner_id (IDOR).")
        if buckets["race_payment"] or buckets["pii"]:
            steps.append("P2 (Бизнес-логика и ПДн): Обернуть финансовые операции в DB-транзакции с блокировкой, проверить HMAC вебхуков и замаскировать ИИН/ПДн.")
        controls = analysis.get("defense_controls") or {}
        if not controls.get("rate_limiting") or not controls.get("security_headers") or buckets["infra_priv"]:
            steps.append("P3 (Системный харденинг): Добавить rate limiting, заголовки CSP/HSTS/X-Frame-Options и непривилегированного USER в Dockerfile.")
        if not steps:
            steps.append("Архитектурный периметр чист: поддерживай CI/CD-проверку на каждый коммит и авто-ротацию секретов.")
        return steps

    @staticmethod
    def _empty_analysis() -> Dict[str, Any]:
        return {
            "tech_stack": [],
            "datastores": [],
            "infrastructure": [],
            "files_analyzed": 0,
            "endpoints_total": 0,
            "non_public_endpoints": 0,
            "protected_endpoints": 0,
            "auth_coverage_pct": None,
            "unprotected_mutations": [],
            "sensitive_sinks": [],
            "defense_controls": {"rate_limiting": False, "security_headers": False},
            "trust_boundaries": [],
            "stride_breakdown": {},
            "risk_chains": [],
            "remediation_roadmap": [],
        }
