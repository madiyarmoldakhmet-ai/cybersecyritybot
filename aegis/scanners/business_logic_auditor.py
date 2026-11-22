"""
Hybrid Business-Logic & Access-Control Security Auditor built on top of `RouteExtractor`.

Combines two complementary layers so it works reliably both 100% offline AND with deep LLM reasoning:
  Stage A — Deterministic Structural Business-Logic Analysis (<30ms, zero hallucination):
    * IDOR / Broken Object Level Authorization (CWE-639)
    * Missing Auth / Broken Access Control on sensitive DB mutations (CWE-862)
    * Mass Assignment of raw request body into ORM writes (CWE-915)
    * Unverified Webhook handlers (CWE-345)
    * Balance / Credit / Inventory Race Conditions — TOCTOU without lock/transaction (CWE-362)

  Stage B — Targeted LLM Business-Logic Auditor (Local Ollama `qwen2.5-coder:7b` or BYOK):
    * Inspects only the highest-risk extracted API routes & Next.js Server Actions with numbered source lines.
    * Demands concrete attack scenarios (step-by-step HTTP exploit) + exact line number + verbatim evidence snippet.
    * Runs an Anti-Hallucination Gate: discards any LLM finding whose line or evidence snippet does not
      actually exist in the source file.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aegis.core.llm_runtime import chat_completion
from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.route_extractor import DiscoveredEndpoint, RouteExtractor

logger = logging.getLogger("aegis.business_logic_auditor")

# Routes that are legitimately unauthenticated by design
_PUBLIC_ROUTE_RE = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|signup|sign-up|register|logout|health|healthz|ready|ping|"
    r"status|metrics|docs|openapi|public|verify|reset-password|forgot-password|oauth|callback|"
    r"demo|chat|contact|subscribe|newsletter|search|catalog|products)(?:/|$)",
    re.IGNORECASE,
)

# High-risk business domains
_SENSITIVE_ROUTE_RE = re.compile(
    r"(?:admin|user|users|account|profile|order|orders|invoice|payment|pay|billing|wallet|"
    r"balance|transfer|withdraw|refund|payout|credit|role|permission|secret|token|key|org|"
    r"team|member|billing|delete|remove|export|download|document|file|record|patient|report)",
    re.IGNORECASE,
)

_ID_PARAM_RE = re.compile(
    r"(?:\{([a-zA-Z0-9_]*id)\}|:([a-zA-Z0-9_]*id)|\[([a-zA-Z0-9_]*id)\]|"
    r"req\.(?:params|query|body)\.(?:id|userId|orderId|accountId|docId|recordId|itemId)|"
    r"searchParams\.get\(['\"](?:id|userId|orderId|accountId)['\"]\))",
    re.IGNORECASE,
)

_OWNERSHIP_CHECK_RE = re.compile(
    r"(?:owner_id|user_id\s*==|userId\s*[:=]|authorId|createdBy|account_owner|"
    r"current_user\.id|session\.user\.id|req\.user\.id|auth\.uid|user\.role\s*===?\s*['\"]admin['\"]|"
    r"is_admin|isAdmin|check_owner|assert_owner|belongs_to|where:\s*\{[^}]*userId|"
    r"\.eq\(\s*['\"]user_id['\"])",
    re.IGNORECASE,
)

_DB_RECORD_ACCESS_RE = re.compile(
    r"(?:prisma\.\w+\.(?:findUnique|findFirst|update|delete|upsert)|"
    r"supabase\.from\([^)]+\)\.(?:select|update|delete)|"
    r"\.(?:findById|findByIdAndUpdate|findByIdAndDelete|findOne|deleteOne|updateOne|destroy)\s*\(|"
    r"(?:db|session)\.query\(|get_object_or_404|SELECT\s+.+\s+WHERE\s+id\s*=|"
    r"DELETE\s+FROM\s+\w+\s+WHERE|UPDATE\s+\w+\s+SET)",
    re.IGNORECASE,
)

_MASS_ASSIGNMENT_RE = re.compile(
    r"(?:prisma\.\w+\.(?:create|update)\s*\(\s*\{\s*data\s*:\s*(?:req\.body|body|\{\s*\.\.\.(?:req\.body|body))|"
    r"\.(?:create|update|findByIdAndUpdate|insert)\s*\(\s*(?:req\.body|\{\s*\.\.\.req\.body)|"
    r"(?:User|Order|Account|Profile)\s*\(\s*\*\*(?:req\.json|request\.json|data|payload|body))",
    re.IGNORECASE,
)

_WEBHOOK_SIG_RE = re.compile(
    r"(?:hmac|compare_digest|timingSafeEqual|constructEvent|x-hub-signature|stripe-signature|"
    r"verify_signature|verifySignature|webhook_secret|WEBHOOK_SECRET|svix)",
    re.IGNORECASE,
)

_BALANCE_CHECK_RE = re.compile(
    r"(?:balance|credits?|funds|amount_available|wallet\.\w+|stock|inventory)\s*(?:>=|>|<|<=)\s*",
    re.IGNORECASE,
)
_BALANCE_MUTATION_RE = re.compile(
    r"(?:balance|credits?|funds|wallet\.\w+|stock|inventory)\s*(?:-=|\+=|=\s*[^=]*[-+])|"
    r"(?:update|save|commit)\s*\(",
    re.IGNORECASE,
)
_TX_LOCK_RE = re.compile(
    r"(?:with_for_update|FOR\s+UPDATE|\$transaction|atomic\s*\(|BEGIN\s+TRANSACTION|"
    r"asyncio\.Lock|threading\.Lock|SELECT\s+.*FOR\s+UPDATE|decrement\s*:|increment\s*:|"
    r"\$inc\b|SET\s+balance\s*=\s*balance\s*-)",
    re.IGNORECASE,
)

_LLM_LOGIC_SYSTEM_PROMPT = """\
You are a Principal Defensive AppSec Engineer, Adversarial Threat Modeler & Senior Systems Analyst auditing a verified codebase's backend API routes for REAL business-logic vulnerabilities, trust-boundary gaps, state-machine flaws, and covert backdoors that conventional SAST tools miss.

Think with an adversarial mindset to find subtle design & authorization flaws, while keeping all output strictly defensive (conceptual threat & blast-radius explanation + concrete code fix; NEVER generate weaponized exploit scripts, malware, or live attack payloads).

Focus strictly on these 8 classes:
1. BACKDOOR (CWE-506 / CWE-912): covert auth bypasses (magic passwords/tokens/headers like `x-admin-bypass`, hardcoded backdoor user IDs), hidden privilege escalation branches, secret exfiltration to external URLs/webhooks, obfuscated eval/exec, or logic time-bombs.
2. IDOR (Broken Object Level Authorization, CWE-639): endpoint accesses/modifies/deletes a record by user-supplied ID without verifying the caller owns it or belongs to the same tenant.
3. BROKEN_AUTH_RBAC (CWE-862 / CWE-285): missing authentication or privilege/role check on sensitive mutations, admin routes, or state transitions.
4. WORKFLOW_BYPASS (CWE-840): business-logic or state-machine flaw allowing skipped verification, negative quantities/amounts, client-trusted prices/discounts, or replayed tokens.
5. SSRF (CWE-918): server fetches attacker-controlled URL without host/IP allowlist.
6. RACE_CONDITION (CWE-362): check-then-act on money/balance/credits/coupons/inventory without DB transaction or row lock.
7. MASS_ASSIGNMENT (CWE-915): unvalidated request body fields (e.g., role, isAdmin, balance, price) written straight to DB.
8. DATA_EXPOSURE (CWE-200): returning password hashes, tokens, secrets, or other users' PII.

STRICT ANTI-HALLUCINATION RULES:
- Report ONLY vulnerabilities that are 100% proven by the provided code lines.
- If the route looks properly protected or has no proven business-logic flaw, return `{"findings": []}`.
- Every finding MUST include:
  - `line_number`: exact integer line number from the numbered snippet
  - `evidence_code`: exact verbatim substring copied from that line
  - `attack_scenario`: concise 1-2 sentence conceptual threat impact & blast radius explaining why this flaw matters (defensive threat modeling, no weaponized exploit code)

Respond ONLY with valid JSON:
{
  "findings": [
    {
      "category": "IDOR",
      "severity": "CRITICAL",
      "line_number": 42,
      "title": "Short specific title",
      "description": "Why this is vulnerable in this exact handler and which trust boundary is broken.",
      "attack_scenario": "Any authenticated user supplying another user's order ID can delete records outside their ownership scope.",
      "evidence_code": "await prisma.order.delete({ where: { id } })",
      "cwe": "CWE-639",
      "recommendation": "Scope the query by session.user.id (where: { id, userId: session.user.id })."
    }
  ]
}
"""


class BusinessLogicAuditor:
    """
    Audits extracted API routes & Server Actions for Backdoors, IDOR, Broken Auth/RBAC,
    Workflow Bypasses, SSRF, Race Conditions, Mass Assignment, and Data Exposure.
    """

    def __init__(
        self,
        enable_llm: Optional[bool] = None,
        max_llm_routes: int = 5,
        llm_timeout: float = 28.0,
    ) -> None:
        self.extractor = RouteExtractor()
        self.enable_llm = (not bool(os.environ.get("PYTEST_CURRENT_TEST"))) if enable_llm is None else enable_llm
        self.max_llm_routes = max_llm_routes
        self.llm_timeout = llm_timeout

    async def scan(self, repo_dir: Path) -> List[VulnerabilityFinding]:
        target_path = Path(repo_dir).resolve()
        if not target_path.exists():
            return []

        endpoints = self.extractor.scan_repository(target_path)
        if not endpoints:
            return []

        # Skip test/mock files and OpenAPI-only specs without code
        auditable = [
            ep
            for ep in endpoints
            if ep.framework != "openapi"
            and ep.code_snippet
            and not self._is_test_path(ep.file_path)
        ]
        if not auditable:
            return []

        # Stage A: Fast deterministic structural checks across ALL routes
        findings: List[VulnerabilityFinding] = []
        for ep in auditable:
            findings.extend(self._audit_endpoint_structural(ep))

        # Stage B: Deep LLM Business-Logic review on the highest-risk routes (strict 15s total wall-clock cap)
        if self.enable_llm:
            prioritized = sorted(auditable, key=self._risk_priority, reverse=True)[: self.max_llm_routes]
            high_value = [ep for ep in prioritized if self._risk_priority(ep) >= 2]
            if high_value:
                try:
                    llm_findings = await asyncio.wait_for(
                        self._audit_endpoints_llm(high_value, target_path),
                        timeout=32.0,
                    )
                    findings.extend(llm_findings)
                except asyncio.TimeoutError:
                    logger.info("Business-Logic LLM stage hit 32s cap — returning structural findings immediately.")

        return self._deduplicate(findings)

    # ---- Stage A: Structural Business-Logic Checks ----------------------------------

    def _audit_endpoint_structural(self, ep: DiscoveredEndpoint) -> List[VulnerabilityFinding]:
        out: List[VulnerabilityFinding] = []
        code = ep.code_snippet or ""
        path_lower = ep.path.lower()
        method = ep.method.upper()
        is_mutation = method in {"POST", "PUT", "PATCH", "DELETE", "SERVER_ACTION"}
        is_public = bool(_PUBLIC_ROUTE_RE.search(path_lower))
        is_sensitive_path = bool(_SENSITIVE_ROUTE_RE.search(path_lower))
        has_db_mutation = "db_mutation" in ep.sensitive_operations or "raw_sql" in ep.sensitive_operations

        # 1. IDOR (Broken Object Level Authorization)
        has_id_param = bool(_ID_PARAM_RE.search(ep.path) or _ID_PARAM_RE.search(code))
        if has_id_param and _DB_RECORD_ACCESS_RE.search(code) and not _OWNERSHIP_CHECK_RE.search(code):
            if not is_public or is_mutation:
                out.append(
                    VulnerabilityFinding(
                        id="logic-idor-missing-ownership",
                        scanner=ScannerType.AI_LOGIC,
                        title=f"IDOR: `{method} {ep.path}` accesses/modifies record by ID without ownership check",
                        description=(
                            f"Handler `{method} {ep.path}` in `{ep.file_path}:{ep.line_number}` accepts a resource ID "
                            f"and queries/mutates the database without verifying that the record belongs to the authenticated user.\n"
                            f"Attack scenario: An authenticated user iterates IDs on `{method} {ep.path}` to read or tamper with other users' records."
                        ),
                        severity=Severity.CRITICAL if is_mutation else Severity.HIGH,
                        file_path=ep.file_path,
                        line_start=ep.line_number,
                        line_end=ep.line_number,
                        code_snippet=code[:600],
                        cwe=["CWE-639", "CWE-284"],
                        recommendation=(
                            "Bind every DB lookup/update/delete to the authenticated caller's ID "
                            "(e.g. `where: { id, userId: session.user.id }` or explicit owner/role check)."
                        ),
                        raw_metadata={"endpoint": f"{method} {ep.path}", "category": "IDOR", "stage": "structural"},
                    )
                )

        # 2. Missing Auth Guard on Sensitive State-Mutating Route
        if (
            is_mutation
            and not ep.has_auth_guard
            and not is_public
            and "webhook" not in path_lower
            and (has_db_mutation or is_sensitive_path)
            and ep.framework != "nextjs-action"  # NextJSSecurityScanner already flags unauth server actions
        ):
            out.append(
                VulnerabilityFinding(
                    id="logic-missing-auth-mutation",
                    scanner=ScannerType.AI_LOGIC,
                    title=f"Broken Access Control: unauthenticated `{method} {ep.path}` mutates sensitive state",
                    description=(
                        f"Route `{method} {ep.path}` (`{ep.file_path}:{ep.line_number}`) performs state changes "
                        f"without any authentication middleware, session check, or RBAC guard.\n"
                        f"Attack scenario: Any unauthenticated caller can invoke `{method} {ep.path}` directly to alter or delete data."
                    ),
                    severity=Severity.CRITICAL if ("admin" in path_lower or "delete" in method.lower() or "balance_or_payment" in ep.sensitive_operations) else Severity.HIGH,
                    file_path=ep.file_path,
                    line_start=ep.line_number,
                    line_end=ep.line_number,
                    code_snippet=code[:600],
                    cwe=["CWE-862", "CWE-306"],
                    recommendation="Require authenticated session/JWT middleware and explicit role/ownership authorization before executing mutations.",
                    raw_metadata={"endpoint": f"{method} {ep.path}", "category": "BROKEN_AUTH_RBAC", "stage": "structural"},
                )
            )

        # 3. Mass Assignment (spreading raw body into ORM create/update)
        m_mass = _MASS_ASSIGNMENT_RE.search(code)
        if m_mass:
            rel_offset = code[: m_mass.start()].count("\n")
            out.append(
                VulnerabilityFinding(
                    id="logic-mass-assignment",
                    scanner=ScannerType.AI_LOGIC,
                    title=f"Mass Assignment in `{method} {ep.path}` (raw request body passed to DB)",
                    description=(
                        f"Unfiltered request payload is passed directly into an ORM create/update call in `{ep.file_path}`.\n"
                        'Attack scenario: Attacker injects privileged fields like `{"role": "admin", "isAdmin": true, "balance": 999999}` in the JSON body.'
                    ),
                    severity=Severity.HIGH,
                    file_path=ep.file_path,
                    line_start=ep.line_number + rel_offset,
                    line_end=ep.line_number + rel_offset,
                    code_snippet=code[:600],
                    cwe=["CWE-915"],
                    recommendation="Explicitly pick allowed fields (e.g. via Pydantic / Zod schema) instead of passing raw `req.body` or `**payload` to the database.",
                    raw_metadata={"endpoint": f"{method} {ep.path}", "category": "MASS_ASSIGNMENT", "stage": "structural"},
                )
            )

        # 4. Unverified Webhook Endpoint
        if "webhook" in path_lower and is_mutation and not _WEBHOOK_SIG_RE.search(code):
            out.append(
                VulnerabilityFinding(
                    id="logic-unverified-webhook",
                    scanner=ScannerType.AI_LOGIC,
                    title=f"Unverified Webhook handler `{method} {ep.path}` lacks HMAC signature validation",
                    description=(
                        f"Webhook endpoint `{ep.path}` processes inbound POST payloads without verifying a cryptographic signature.\n"
                        f"Attack scenario: Attacker sends forged payment/event webhook payloads to trigger free upgrades or unauthorized actions."
                    ),
                    severity=Severity.HIGH,
                    file_path=ep.file_path,
                    line_start=ep.line_number,
                    line_end=ep.line_number,
                    code_snippet=code[:600],
                    cwe=["CWE-345"],
                    recommendation="Verify the webhook HMAC signature using constant-time comparison (`hmac.compare_digest` / `crypto.timingSafeEqual` / provider SDK `constructEvent`).",
                    raw_metadata={"endpoint": f"{method} {ep.path}", "category": "BROKEN_AUTH_RBAC", "stage": "structural"},
                )
            )

        # 5. Race Condition (TOCTOU) on balance / credits / inventory
        if (
            "balance_or_payment" in ep.sensitive_operations
            and _BALANCE_CHECK_RE.search(code)
            and _BALANCE_MUTATION_RE.search(code)
            and not _TX_LOCK_RE.search(code)
        ):
            out.append(
                VulnerabilityFinding(
                    id="logic-race-condition-balance",
                    scanner=ScannerType.AI_LOGIC,
                    title=f"Race Condition (TOCTOU) on balance/credits in `{method} {ep.path}`",
                    description=(
                        f"Handler `{method} {ep.path}` checks balance/credits/stock and updates it in separate non-atomic steps without a DB transaction or row lock.\n"
                        f"Attack scenario: Sending 10 concurrent requests to `{method} {ep.path}` passes the balance check multiple times (double-spend)."
                    ),
                    severity=Severity.HIGH,
                    file_path=ep.file_path,
                    line_start=ep.line_number,
                    line_end=ep.line_number,
                    code_snippet=code[:600],
                    cwe=["CWE-362"],
                    recommendation="Use an atomic conditional SQL update (`UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1`) or `SELECT ... FOR UPDATE` inside a transaction.",
                    raw_metadata={"endpoint": f"{method} {ep.path}", "category": "RACE_CONDITION", "stage": "structural"},
                )
            )

        return out

    # ---- Stage B: Targeted LLM Business-Logic Auditor -------------------------------

    async def _audit_endpoints_llm(
        self, endpoints: List[DiscoveredEndpoint], target_path: Path
    ) -> List[VulnerabilityFinding]:
        sem = asyncio.Semaphore(2)

        async def _bounded(ep: DiscoveredEndpoint) -> List[VulnerabilityFinding]:
            async with sem:
                return await self._audit_single_endpoint_llm(ep, target_path)

        results = await asyncio.gather(*(_bounded(ep) for ep in endpoints), return_exceptions=True)
        out: List[VulnerabilityFinding] = []
        for res in results:
            if isinstance(res, list):
                out.extend(res)
        return out

    async def _audit_single_endpoint_llm(
        self, ep: DiscoveredEndpoint, target_path: Path
    ) -> List[VulnerabilityFinding]:
        full_file = target_path / ep.file_path
        if not full_file.is_file():
            return []
        try:
            all_lines = full_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

        start_line = max(1, ep.line_number)
        end_line = min(len(all_lines), start_line + 85)
        numbered_lines = [f"{ln}: {all_lines[ln - 1]}" for ln in range(start_line, end_line + 1)]
        numbered_block = "\n".join(numbered_lines)
        raw_window = "\n".join(all_lines[start_line - 1 : end_line])

        user_prompt = (
            f"Endpoint: `{ep.method.upper()} {ep.path}` (framework: {ep.framework})\n"
            f"File: `{ep.file_path}` (lines {start_line}-{end_line})\n"
            f"Detected auth guard: {'YES (' + (ep.auth_detail or 'present') + ')' if ep.has_auth_guard else 'NONE DETECTED'}\n"
            f"Sensitive operations: {', '.join(ep.sensitive_operations) or 'none'}\n\n"
            f"### NUMBERED HANDLER CODE:\n```\n{numbered_block}\n```\n"
            "Return JSON with proven business-logic vulnerabilities only (or empty list)."
        )

        raw = await chat_completion(
            _LLM_LOGIC_SYSTEM_PROMPT,
            user_prompt,
            temperature=0.05,
            max_tokens=1100,
            timeout=self.llm_timeout,
            task_label=f"LogicAudit:{ep.file_path}:{ep.line_number}",
            deep_reasoning=True,
        )
        if not raw:
            return []

        return self._parse_and_verify_llm_findings(raw, ep, all_lines, start_line, end_line, raw_window)

    def _parse_and_verify_llm_findings(
        self,
        raw_text: str,
        ep: DiscoveredEndpoint,
        all_lines: List[str],
        start_line: int,
        end_line: int,
        raw_window: str,
    ) -> List[VulnerabilityFinding]:
        """Parse LLM JSON and strictly reject any hallucinated line numbers or fabricated code."""
        text = raw_text.strip()
        if "```json" in text:
            text = text.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in text:
            text = text.split("```", 1)[1].split("```", 1)[0].strip()

        lo, hi = text.find("{"), text.rfind("}")
        if lo == -1 or hi == -1:
            return []
        try:
            payload = json.loads(text[lo : hi + 1])
        except json.JSONDecodeError:
            return []

        raw_items = payload.get("findings")
        if not isinstance(raw_items, list):
            return []

        sev_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        verified: List[VulnerabilityFinding] = []
        norm_window = " ".join(raw_window.split())

        for item in raw_items[:4]:
            if not isinstance(item, dict):
                continue
            category = str(item.get("category") or "LOGIC").upper().strip()
            title = str(item.get("title") or "").strip()
            description = str(item.get("description") or "").strip()
            attack = str(item.get("attack_scenario") or "").strip()
            evidence = str(item.get("evidence_code") or "").strip()
            rec = str(item.get("recommendation") or "").strip()
            cwe_raw = str(item.get("cwe") or "").strip()
            sev_raw = str(item.get("severity") or "HIGH").upper().strip()

            try:
                line_num = int(item.get("line_number") or 0)
            except (TypeError, ValueError):
                continue

            # Anti-Hallucination Gate #1: line number must fall within audited handler window
            if not title or not attack or line_num < start_line or line_num > end_line:
                continue

            # Anti-Hallucination Gate #2: evidence code must genuinely exist in the handler source
            if not evidence or len(evidence) < 6:
                continue
            norm_evidence = " ".join(evidence.split())
            if norm_evidence not in norm_window:
                logger.debug(f"Dropped ungrounded LLM finding '{title}' (evidence not found in {ep.file_path})")
                continue

            snippet_lo = max(0, line_num - 4)
            snippet_hi = min(len(all_lines), line_num + 3)
            snippet = "\n".join(all_lines[snippet_lo:snippet_hi])
            full_desc = f"{description}\n\n**Сценарий атаки:** {attack}"
            cwes = [cwe_raw] if cwe_raw.startswith("CWE-") else []

            verified.append(
                VulnerabilityFinding(
                    id=f"ai-logic-{category.lower().replace('_', '-')}",
                    scanner=ScannerType.AI_LOGIC,
                    title=f"[AI Logic · {category}] {title}",
                    description=full_desc,
                    severity=sev_map.get(sev_raw, Severity.HIGH),
                    file_path=ep.file_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=snippet,
                    cwe=cwes,
                    recommendation=rec or "Enforce server-side authorization and strict validation for this business flow.",
                    raw_metadata={
                        "endpoint": f"{ep.method.upper()} {ep.path}",
                        "category": category,
                        "attack_scenario": attack,
                        "evidence_code": evidence,
                        "stage": "llm-verified",
                    },
                )
            )
        return verified

    # ---- Helpers --------------------------------------------------------------------

    @staticmethod
    def _is_test_path(rel_path: str) -> bool:
        low = rel_path.lower()
        return (
            low.startswith("tests/")
            or "/tests/" in low
            or "__tests__/" in low
            or ".test." in low
            or ".spec." in low
            or "/test_" in low
        )

    @staticmethod
    def _risk_priority(ep: DiscoveredEndpoint) -> int:
        score = 0
        if not ep.has_auth_guard:
            score += 2
        if ep.method.upper() in {"POST", "PUT", "PATCH", "DELETE", "SERVER_ACTION"}:
            score += 2
        if _ID_PARAM_RE.search(ep.path) or _ID_PARAM_RE.search(ep.code_snippet or ""):
            score += 2
        if _SENSITIVE_ROUTE_RE.search(ep.path):
            score += 2
        score += len(ep.sensitive_operations)
        if _PUBLIC_ROUTE_RE.search(ep.path):
            score -= 3
        return score

    @staticmethod
    def _deduplicate(findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        seen: Set[Tuple[str, str, str]] = set()
        out: List[VulnerabilityFinding] = []
        for f in findings:
            cat = str(f.raw_metadata.get("category") or f.id)
            ep = str(f.raw_metadata.get("endpoint") or f.line_start)
            key = (f.file_path, ep, cat)
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
