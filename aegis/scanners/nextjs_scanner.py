"""
Deep JS / TypeScript / Next.js Security Analyzer & Variable-Level Taint Engine.

Catches modern JavaScript, TypeScript, React, Node.js, and Next.js vulnerabilities that
generic regex scanners miss:
  1. `NEXT_PUBLIC_` secret leakage (.env*, next.config.*, TS/JS sources)
  2. Next.js Server Actions ('use server') performing DB mutations without auth/session checks
  3. Prototype Pollution (CWE-1321): unsafe deep merge / Object.assign / untrusted dynamic key write
  4. Variable-level JS/TS Taint Analysis (sources -> assignments/destructuring/templates -> sinks):
     - SQL Injection (CWE-89): prisma.$queryRawUnsafe, db.query, pool.query, knex.raw
     - SSRF (CWE-918): fetch, axios, got, http/https.get with user-controlled URL
     - OS Command Injection (CWE-78): child_process exec/execSync/spawn
     - Path Traversal (CWE-22): fs.readFile/writeFile/unlink, res.sendFile
     - Open Redirect (CWE-601): NextResponse.redirect, res.redirect, redirect()
     - XSS (CWE-79): dangerouslySetInnerHTML, .innerHTML =
     - Code Injection (CWE-95): eval, new Function
  5. Insecure JWT verification (jwt.decode / algorithms: ['none']), weak auth cookies, and
     client-side privileged service_role / firebase-admin leakage.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("aegis.nextjs_scanner")

_IGNORED_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", "out", "dist", "build",
    "coverage", ".turbo", ".cache", ".venv", "venv", "__pycache__", "vendor",
}
_JS_TS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# ---- 1. Next.js / Modern JS Structural Rules -----------------------------------------

_NEXT_PUBLIC_SECRET_RE = re.compile(
    r"\bNEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|DATABASE_URL|DB_PASS|PASSWORD|JWT_SECRET|ADMIN_KEY|STRIPE_SK|API_SECRET|ACCESS_TOKEN)[A-Z0-9_]*\b"
)
_SERVER_ACTION_DIRECTIVE_RE = re.compile(r"""^\s*['"]use server['"]\s*;?""", re.MULTILINE)
_CLIENT_DIRECTIVE_RE = re.compile(r"""^\s*['"]use client['"]\s*;?""", re.MULTILINE)
_EXPORT_ASYNC_FN_RE = re.compile(
    r"export\s+(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
)
_AUTH_CHECK_RE = re.compile(
    r"\b(?:auth\s*\(|getServerSession|getSession|currentUser|getAuth|requireAuth|requireUser|"
    r"verifyToken|jwt\.verify|supabase\.auth\.getUser|cookies\(\)\.get\([^)]*(?:token|session|auth)|"
    r"headers\(\)\.get\([^)]*authorization|assertAuthorized|checkPermission|hasRole|isAdmin)\b",
    re.IGNORECASE,
)
_DB_MUTATION_RE = re.compile(
    r"(?:\bprisma\.[A-Za-z0-9_]+\.(?:create|update|delete|upsert|updateMany|deleteMany)\s*\(|"
    r"\bsupabase\.from\([^)]+\)\.(?:insert|update|delete|upsert)\s*\(|"
    r"\bdb\.(?:insert|update|delete|execute|query)\s*\(|"
    r"\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b)",
    re.IGNORECASE,
)
_PROTO_POLLUTION_MERGE_RE = re.compile(
    r"\b(?:_\.merge|_\.defaultsDeep|lodash\.merge|deepMerge|mergeDeep|extend\s*\(\s*true\s*,)\s*\([^)]*(?:req\.body|req\.query|body|payload|input|params)",
    re.IGNORECASE,
)
_PROTO_DYNAMIC_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*="
)
_PROTO_GUARD_RE = re.compile(r"__proto__|constructor|prototype|Object\.hasOwn|hasOwnProperty")
_JWT_DECODE_AUTH_RE = re.compile(r"\bjwt\.decode\s*\(")
_JWT_NONE_ALG_RE = re.compile(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]", re.IGNORECASE)
_INSECURE_COOKIE_RE = re.compile(
    r"(?:setCookie|cookies\(\)\.set|res\.cookie)\s*\([^;]{0,220}?(?:httpOnly\s*:\s*false|secure\s*:\s*false)",
    re.IGNORECASE | re.DOTALL,
)
_CLIENT_PRIVILEGED_RE = re.compile(
    r"(?:SUPABASE_SERVICE_ROLE|service_role|firebase-admin|process\.env\.(?:DATABASE_URL|JWT_SECRET|STRIPE_SECRET_KEY))"
)

# ---- 2. JS/TS Variable-Level Taint Patterns ------------------------------------------

# Attacker-controlled input sources in Express / Fastify / Next.js App & Pages Router / Browser
_JS_SOURCE_EXPR_RE = re.compile(
    r"(?:"
    r"\breq(?:uest)?\.(?:query|body|params|headers|cookies)\b|"
    r"\breq(?:uest)?\.nextUrl\.searchParams\b|"
    r"\bsearchParams\.get(?:All)?\s*\(|"
    r"\b(?:await\s+)?req(?:uest)?\.(?:json|text|formData)\s*\(|"
    r"\bformData\.get\s*\(|"
    r"\bnew\s+URLSearchParams\s*\(\s*window\.location\.search\s*\)|"
    r"\bwindow\.location\.(?:search|hash|href)\b"
    r")"
)

# Sanitizers that neutralize tainted expressions
_JS_SANITIZER_RE = re.compile(
    r"\b(?:Number|parseInt|parseFloat|Boolean|encodeURIComponent|encodeURI|"
    r"DOMPurify\.sanitize|sanitizeHtml|validator\.escape|escapeHtml|"
    r"path\.basename|isSafeUrl|validateUrl|allowlist|whitelist|ALLOWED_HOSTS)\b"
)

# Variable declarations / assignments
_JS_SIMPLE_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=]+)?=\s*(.+)"
)
_JS_DESTRUCTURE_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*(?::[^=]+)?=\s*(.+)"
)
_JS_REASSIGN_RE = re.compile(r"^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+)")

# High-confidence sinks: (rule_id, kind, severity, cwe, regex, recommendation)
_JS_TAINT_SINKS: Tuple[Tuple[str, str, Severity, List[str], re.Pattern, str], ...] = (
    (
        "js-taint-sqli",
        "SQL Injection (JS/TS Taint)",
        Severity.CRITICAL,
        ["CWE-89"],
        re.compile(
            r"\b(?:prisma\.\$(?:query|execute)RawUnsafe|(?:db|pool|client|conn|connection|sequelize|mysql|pg)\.query|knex\.raw)\s*\(([^;\n]+)"
        ),
        "Use parameterized queries (`$1`, `?`, or Prisma tagged template `prisma.$queryRaw` with placeholders) instead of interpolating untrusted input.",
    ),
    (
        "js-taint-cmdi",
        "OS Command Injection (JS/TS Taint)",
        Severity.CRITICAL,
        ["CWE-78"],
        re.compile(r"\b(?:child_process\.)?(?:exec|execSync|execFile|spawn|spawnSync)\s*\(([^;\n]+)"),
        "Pass an argument array to `execFile`/`spawn` with `shell: false` and strictly allowlist user parameters.",
    ),
    (
        "js-taint-ssrf",
        "Server-Side Request Forgery / SSRF (JS/TS Taint)",
        Severity.HIGH,
        ["CWE-918"],
        re.compile(r"\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|got(?:\.(?:get|post))?|https?\.get)\s*\(([^;\n]+)"),
        "Validate the target URL against a strict hostname/scheme allowlist and block private/metadata IP ranges (127.0.0.0/8, 169.254.169.254, 10.0.0.0/8).",
    ),
    (
        "js-taint-path-traversal",
        "Path Traversal / Arbitrary File Access (JS/TS Taint)",
        Severity.HIGH,
        ["CWE-22"],
        re.compile(
            r"\b(?:fs\.(?:promises\.)?(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync|createReadStream)|res\.(?:sendFile|download))\s*\(([^;\n]+)"
        ),
        "Normalize with `path.resolve(BASE_DIR, path.basename(userInput))` and verify `resolved.startsWith(BASE_DIR + path.sep)`.",
    ),
    (
        "js-taint-open-redirect",
        "Open Redirect (JS/TS Taint)",
        Severity.MEDIUM,
        ["CWE-601"],
        re.compile(r"\b(?:NextResponse\.redirect|res\.redirect|(?<!\.)redirect)\s*\(([^;\n]+)"),
        "Only allow relative paths starting with `/` (and not `//`) or validate against an explicit allowlist of trusted origins.",
    ),
    (
        "js-taint-xss",
        "Cross-Site Scripting / XSS (JS/TS Taint)",
        Severity.HIGH,
        ["CWE-79"],
        re.compile(r"(?:dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}\n]+)|\.innerHTML\s*=\s*([^;\n]+))"),
        "Avoid `innerHTML` / `dangerouslySetInnerHTML` with untrusted input; use React text rendering or sanitize with `DOMPurify.sanitize()`.",
    ),
    (
        "js-taint-code-injection",
        "Dynamic Code Execution (JS/TS Taint)",
        Severity.CRITICAL,
        ["CWE-95"],
        re.compile(r"\b(?:eval|new\s+Function|vm\.runInNewContext)\s*\(([^;\n]+)"),
        "Remove `eval()` / `new Function()` on user-controlled values and replace with safe JSON parsing or an explicit lookup table.",
    ),
)


def _extract_snippet(lines: List[str], line_idx: int, pad: int = 3) -> str:
    lo = max(0, line_idx - 1 - pad)
    hi = min(len(lines), line_idx + pad)
    return "\n".join(lines[lo:hi])


def _is_test_or_mock_path(rel_path: str) -> bool:
    low = rel_path.lower()
    return (
        "__tests__/" in low
        or ".test." in low
        or ".spec." in low
        or "/fixtures/" in low
        or "/mocks/" in low
    )


class JSTaintAnalyzer:
    """Lightweight intra-file variable-level taint tracker for JS / TS / Next.js."""

    def analyze_file(self, rel_path: str, content: str) -> List[VulnerabilityFinding]:
        if _is_test_or_mock_path(rel_path):
            return []

        lines = content.splitlines()
        tainted: Dict[str, Tuple[str, int]] = {}  # var_name -> (source_origin, def_line)
        findings: List[VulnerabilityFinding] = []
        seen_keys: Set[Tuple[str, int]] = set()

        # Seed Next.js Server Action parameters (`export async function foo(formData, userId)`)
        is_server_action_file = bool(_SERVER_ACTION_DIRECTIVE_RE.search(content))

        for idx, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("*"):
                continue

            if is_server_action_file:
                fn_m = _EXPORT_ASYNC_FN_RE.search(raw_line)
                if fn_m:
                    for raw_param in fn_m.group(2).split(","):
                        p_name = raw_param.split(":")[0].split("=")[0].strip().lstrip(".")
                        if re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", p_name) and p_name not in {"_", "prevState"}:
                            tainted[p_name] = (f"serverAction({fn_m.group(1)}).{p_name}", idx)

            # 1. Track taint propagation through destructuring assignments:
            #    const { url, id: userId } = req.query
            destr = _JS_DESTRUCTURE_ASSIGN_RE.search(raw_line)
            if destr:
                lhs_vars, rhs = destr.group(1), destr.group(2)
                rhs_origin = self._expr_taint_origin(rhs, tainted)
                if rhs_origin:
                    for item in lhs_vars.split(","):
                        part = item.strip().lstrip(".")
                        if not part:
                            continue
                        alias = part.split(":")[-1].split("=")[0].strip()
                        if re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", alias):
                            tainted[alias] = (f"{rhs_origin} -> {alias}", idx)
                continue

            # 2. Track simple declarations & reassignments:
            #    const target = `https://${host}/api`
            assign = _JS_SIMPLE_ASSIGN_RE.search(raw_line) or _JS_REASSIGN_RE.search(raw_line)
            if assign and not raw_line.strip().startswith(("return ", "if ", "while ", "for ")):
                var_name, rhs = assign.group(1), assign.group(2)
                if _JS_SANITIZER_RE.search(rhs):
                    tainted.pop(var_name, None)
                else:
                    rhs_origin = self._expr_taint_origin(rhs, tainted)
                    if rhs_origin:
                        tainted[var_name] = (f"{rhs_origin} -> {var_name}", idx)

            # 3. Check dangerous sinks on this line
            for rule_id, kind, severity, cwe, sink_re, rec in _JS_TAINT_SINKS:
                m = sink_re.search(raw_line)
                if not m:
                    continue
                arg_expr = next((g for g in m.groups() if g), "")
                if not arg_expr:
                    continue

                # Skip sanitized calls or parameterized SQL (second arg is array/object and first arg is static literal)
                if _JS_SANITIZER_RE.search(arg_expr):
                    continue
                if rule_id == "js-taint-sqli":
                    # If first argument is a plain quoted string with no ${...} or +, it's parameterized!
                    first_arg = arg_expr.split(",", 1)[0].strip()
                    if (
                        (first_arg.startswith("'") and first_arg.endswith("'") and "+" not in first_arg)
                        or (first_arg.startswith('"') and first_arg.endswith('"') and "+" not in first_arg)
                        or (first_arg.startswith("`") and first_arg.endswith("`") and "${" not in first_arg)
                    ):
                        continue
                if rule_id == "js-taint-ssrf":
                    # Relative internal API calls like fetch(`/api/users/${id}`) are NOT SSRF!
                    first_arg = arg_expr.split(",", 1)[0].strip()
                    if re.match(r"""^[`'"]/""", first_arg):
                        continue
                    # Skip fetch calls with explicit host allowlist check in nearby 6 lines
                    nearby = "\n".join(lines[max(0, idx - 7) : idx])
                    if re.search(r"ALLOWED_HOSTS|isSafeUrl|allowlist|new\s+URL\(", nearby, re.IGNORECASE) and (
                        "hostname" in nearby or "origin" in nearby
                    ):
                        continue
                if rule_id == "js-taint-open-redirect":
                    nearby = "\n".join(lines[max(0, idx - 6) : idx])
                    if re.search(r"startsWith\s*\(\s*['\"]/['\"]", nearby):
                        continue

                origin = self._expr_taint_origin(arg_expr, tainted)
                if not origin:
                    continue

                key = (rule_id, idx)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                findings.append(
                    VulnerabilityFinding(
                        id=rule_id,
                        scanner=ScannerType.NEXTJS,
                        title=f"{kind} in `{Path(rel_path).name}`",
                        description=(
                            f"Untrusted input flows into dangerous sink without sanitization.\n"
                            f"Taint path: `{origin}` → line {idx}."
                        ),
                        severity=severity,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=_extract_snippet(lines, idx, pad=3),
                        cwe=list(cwe),
                        recommendation=rec,
                        raw_metadata={"taint_origin": origin, "analyzer": "js-taint-engine"},
                    )
                )

        return findings

    @staticmethod
    def _expr_taint_origin(expr: str, tainted: Dict[str, Tuple[str, int]]) -> Optional[str]:
        if _JS_SANITIZER_RE.search(expr):
            return None
        direct = _JS_SOURCE_EXPR_RE.search(expr)
        if direct:
            return direct.group(0).strip()
        for var_name, (origin, _) in tainted.items():
            if re.search(rf"\b{re.escape(var_name)}\b", expr):
                return origin
        return None


class NextJSSecurityScanner:
    """Scans JS/TS/React/Next.js projects for framework flaws + variable-level JS/TS taint."""

    def __init__(self) -> None:
        self.taint = JSTaintAnalyzer()

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
                ext = fp.suffix.lower()

                is_env = file.startswith(".env") and not file.endswith((".example", ".sample", ".template"))
                if not is_env and ext not in _JS_TS_EXTS:
                    continue
                try:
                    if fp.stat().st_size > 512 * 1024:
                        continue
                    content = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                if is_env:
                    findings.extend(self._scan_env_next_public(rel, content))
                    continue

                findings.extend(self._scan_nextjs_patterns(rel, content))
                findings.extend(self.taint.analyze_file(rel, content))

        return findings

    def _scan_env_next_public(self, rel_path: str, content: str) -> List[VulnerabilityFinding]:
        out: List[VulnerabilityFinding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if line.strip().startswith("#"):
                continue
            m = _NEXT_PUBLIC_SECRET_RE.search(line)
            if m:
                out.append(
                    VulnerabilityFinding(
                        id="nextjs-public-env-secret",
                        scanner=ScannerType.NEXTJS,
                        title=f"Secret exposed to browser bundle via `{m.group(0)}`",
                        description=(
                            f"Next.js inlines every `NEXT_PUBLIC_*` variable into client-side JavaScript bundles. "
                            f"`{m.group(0)}` looks like a privileged credential and will be publicly readable by any visitor."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=_extract_snippet(lines, idx, pad=1),
                        cwe=["CWE-200", "CWE-798"],
                        recommendation="Remove the `NEXT_PUBLIC_` prefix so the secret stays server-only, and rotate the exposed value.",
                    )
                )
        return out

    def _scan_nextjs_patterns(self, rel_path: str, content: str) -> List[VulnerabilityFinding]:
        if _is_test_or_mock_path(rel_path):
            return []

        out: List[VulnerabilityFinding] = []
        lines = content.splitlines()

        # 1. NEXT_PUBLIC_ secret reference in code
        for idx, line in enumerate(lines, start=1):
            m = _NEXT_PUBLIC_SECRET_RE.search(line)
            if m:
                out.append(
                    VulnerabilityFinding(
                        id="nextjs-public-env-secret",
                        scanner=ScannerType.NEXTJS,
                        title=f"Client-exposed secret variable `{m.group(0)}`",
                        description=(
                            f"Using `{m.group(0)}` exposes sensitive credentials in the compiled browser JS bundle."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=_extract_snippet(lines, idx, pad=2),
                        cwe=["CWE-200", "CWE-798"],
                        recommendation="Move this secret to a server-only environment variable without `NEXT_PUBLIC_` and call it from a Server Component or API route.",
                    )
                )
                break

        # 2. Next.js Server Actions ('use server') without authentication before DB mutation
        if _SERVER_ACTION_DIRECTIVE_RE.search(content):
            has_file_auth = bool(_AUTH_CHECK_RE.search(content))
            for fn_m in _EXPORT_ASYNC_FN_RE.finditer(content):
                fn_name = fn_m.group(1)
                fn_line = content[: fn_m.start()].count("\n") + 1
                body_window = content[fn_m.start() : fn_m.start() + 1800]
                # Skip explicit auth actions (login/signup/register)
                if re.search(r"login|signin|signup|register|verify|logout", fn_name, re.IGNORECASE):
                    continue
                if _DB_MUTATION_RE.search(body_window) and not _AUTH_CHECK_RE.search(body_window) and not has_file_auth:
                    out.append(
                        VulnerabilityFinding(
                            id="nextjs-unauth-server-action",
                            scanner=ScannerType.NEXTJS,
                            title=f"Unauthenticated Next.js Server Action `{fn_name}` performs DB mutation",
                            description=(
                                f"Server Action `{fn_name}` in `{rel_path}` is publicly callable as a POST endpoint "
                                f"and mutates database state without verifying user session or authorization."
                            ),
                            severity=Severity.CRITICAL,
                            file_path=rel_path,
                            line_start=fn_line,
                            line_end=fn_line,
                            code_snippet=_extract_snippet(lines, fn_line, pad=5),
                            cwe=["CWE-862", "CWE-306"],
                            recommendation="Call `const session = await auth()` (or `getServerSession`) at the top of every Server Action and verify ownership/role before mutating data.",
                        )
                    )

        # 3. Client component referencing privileged server-only keys/SDKs
        if _CLIENT_DIRECTIVE_RE.search(content):
            for idx, line in enumerate(lines, start=1):
                if _CLIENT_PRIVILEGED_RE.search(line):
                    out.append(
                        VulnerabilityFinding(
                            id="nextjs-client-privileged-key",
                            scanner=ScannerType.NEXTJS,
                            title="Privileged server credential/SDK referenced inside `'use client'` module",
                            description=(
                                f"`{rel_path}` is marked `'use client'` and references a privileged backend key or admin SDK."
                            ),
                            severity=Severity.CRITICAL,
                            file_path=rel_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=_extract_snippet(lines, idx, pad=2),
                            cwe=["CWE-798", "CWE-200"],
                            recommendation="Use privileged keys only in Server Components, Server Actions, or API routes.",
                        )
                    )
                    break

        # 4. Prototype Pollution (unsafe deep merge or double-bracket dynamic write without guard)
        for m in _PROTO_POLLUTION_MERGE_RE.finditer(content):
            line_no = content[: m.start()].count("\n") + 1
            out.append(
                VulnerabilityFinding(
                    id="js-prototype-pollution",
                    scanner=ScannerType.NEXTJS,
                    title="Prototype Pollution via unsafe deep merge of user input",
                    description=(
                        "Merging untrusted request payload recursively without filtering `__proto__`, `constructor`, "
                        "and `prototype` allows attackers to pollute `Object.prototype` across the Node.js process."
                    ),
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=_extract_snippet(lines, line_no, pad=3),
                    cwe=["CWE-1321"],
                    recommendation="Validate payload with a strict schema (Zod/Valibot) or strip `__proto__`, `constructor`, and `prototype` keys before merging.",
                )
            )
            break

        if not _PROTO_GUARD_RE.search(content) and _JS_SOURCE_EXPR_RE.search(content):
            for m in _PROTO_DYNAMIC_ASSIGN_RE.finditer(content):
                line_no = content[: m.start()].count("\n") + 1
                out.append(
                    VulnerabilityFinding(
                        id="js-prototype-pollution-bracket",
                        scanner=ScannerType.NEXTJS,
                        title="Potential Prototype Pollution via unguarded nested bracket assignment",
                        description=(
                            f"Nested property write `{m.group(0).strip()}` in a request-handling file has no "
                            f"`__proto__`/`constructor`/`prototype` key guard."
                        ),
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=_extract_snippet(lines, line_no, pad=3),
                        cwe=["CWE-1321"],
                        recommendation="Reject forbidden keys (`__proto__`, `constructor`, `prototype`) or use `new Map()` instead of plain objects.",
                    )
                )
                break

        # 5. Insecure JWT (jwt.decode without jwt.verify OR algorithms: ['none'])
        if _JWT_DECODE_AUTH_RE.search(content) and "jwt.verify" not in content:
            m = _JWT_DECODE_AUTH_RE.search(content)
            if m:
                line_no = content[: m.start()].count("\n") + 1
                out.append(
                    VulnerabilityFinding(
                        id="js-insecure-jwt-decode",
                        scanner=ScannerType.NEXTJS,
                        title="JWT decoded without cryptographic signature verification (`jwt.decode`)",
                        description=(
                            "`jwt.decode()` only Base64-decodes the token payload without verifying the signature. "
                            "An attacker can forge arbitrary `userId` or `role: 'admin'` claims."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=_extract_snippet(lines, line_no, pad=3),
                        cwe=["CWE-347"],
                        recommendation="Replace `jwt.decode(token)` with `jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] })`.",
                    )
                )

        m_none = _JWT_NONE_ALG_RE.search(content)
        if m_none:
            line_no = content[: m_none.start()].count("\n") + 1
            out.append(
                VulnerabilityFinding(
                    id="js-jwt-none-alg",
                    scanner=ScannerType.NEXTJS,
                    title="JWT accepts unsigned `'none'` algorithm",
                    description="Allowing `algorithms: ['none']` lets attackers bypass JWT signature validation completely.",
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=_extract_snippet(lines, line_no, pad=2),
                    cwe=["CWE-347"],
                    recommendation="Remove `'none'` and restrict `algorithms` to strong algorithms like `['HS256']` or `['RS256']`.",
                )
            )

        # 6. Weak auth cookie flags (httpOnly: false / secure: false)
        m_cookie = _INSECURE_COOKIE_RE.search(content)
        if m_cookie and re.search(r"session|token|auth|jwt|refresh", m_cookie.group(0), re.IGNORECASE):
            line_no = content[: m_cookie.start()].count("\n") + 1
            out.append(
                VulnerabilityFinding(
                    id="js-insecure-auth-cookie",
                    scanner=ScannerType.NEXTJS,
                    title="Authentication cookie missing `httpOnly: true` or `secure: true`",
                    description=(
                        "Setting `httpOnly: false` or `secure: false` on a session/auth cookie exposes tokens to XSS "
                        "theft (`document.cookie`) or plaintext network interception."
                    ),
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=_extract_snippet(lines, line_no, pad=3),
                    cwe=["CWE-614", "CWE-1004"],
                    recommendation="Set `{ httpOnly: true, secure: true, sameSite: 'lax' }` on all authentication cookies.",
                )
            )

        return out
