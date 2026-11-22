"""
SAST Scanner Engine for Aegis.
Executes multi-language static application security testing:
- Flutter / Dart / JS / TS / Python / JSON / YAML / HTML / Env security rules
- Python AST security visitor (SQLi, eval, pickle, subprocess shell=True)
- Universal heuristic patterns (Firebase/Google API keys, Telegram bot tokens, Private keys, Insecure SSL callbacks, Open Firestore rules, DOM XSS)
- CLI scanners: Semgrep, Bandit, Pip-Audit
"""

import ast
import asyncio
import json
import esprima
import logging
import os
import re
import shutil
import time
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Pattern, Tuple, Union, Set

from aegis.core.config import settings
from aegis.core.event_bus import ScanEventBus, ScanStarted, FileScanning, CodeAnalyzing, VulnerabilityFound
from aegis.core.project_config import ProjectConfig, load_config
from aegis.scanners.ai_filter import AIFalsePositiveFilter
from aegis.scanners.mobile_scanner import MobileSecurityScanner
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.sanitizer import FalsePositiveSanitizer, calculate_shannon_entropy

logger = logging.getLogger("aegis.sast_scanner")

# List of directories to ignore during all code traversals and static analysis
IGNORED_DIRS = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "env",
    "build",
    "dist",
    "out",
    ".next",
    ".dart_tool",
    ".idea",
    "__pycache__",
    "temp_scans",
    ".pytest_cache",
    ".tox",
    ".mypy_cache",
    "site-packages",
}

# Target file extensions for multi-language security inspection
TARGET_EXTENSIONS = {
    ".dart",
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".rules",
    ".env",
    ".env.example",
    ".html",
}


def extract_code_context(
    file_path: Union[str, Path], line_number: Optional[int] = None, padding: int = 15
) -> Optional[str]:
    """
    Extract a clean 30-line window (15 lines before, 15 lines after) around the finding line.
    Prevents overflowing LLM context window with entire large files.
    """
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return None

    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            return None

        target_line = line_number or 1
        first_line = max(1, target_line - padding)
        last_line = min(len(lines), target_line + padding)
        return "\n".join(lines[first_line - 1 : last_line])
    except Exception as e:
        logger.debug(f"Failed to extract code context from {p}: {e}")
        return None


class MultiLanguagePatternScanner:
    """Universal regex and heuristic security pattern scanner across multi-language source files."""

    RULES: List[Dict[str, Any]] = [
        # 1. Google / Firebase API Keys
        {
            "id": "exposed-google-firebase-key",
            "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{30,45}\b"),
            "title": "Exposed Google / Firebase API Key",
            "description": "Hardcoded Google/Firebase API key detected in source code.",
            "severity": Severity.HIGH,
            "cwe": ["CWE-798"],
            "cve": [],
            "recommendation": "Store API keys in environment variables or restrict key permissions in Google Cloud Console.",
        },
        # 2. Telegram Bot Tokens
        {
            "id": "exposed-telegram-bot-token",
            "regex": re.compile(r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b"),
            "title": "Exposed Telegram Bot Token",
            "description": "Telegram Bot API token is hardcoded in source code, risking unauthorized bot control.",
            "severity": Severity.CRITICAL,
            "cwe": ["CWE-798"],
            "cve": [],
            "recommendation": "Revoke this token via @BotFather and pass token via environment variables.",
        },
        # 3. Private Cryptographic Keys
        {
            "id": "hardcoded-private-key",
            "regex": re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
            "title": "Hardcoded Private Cryptographic Key",
            "description": "Plaintext private cryptographic key embedded in repository.",
            "severity": Severity.CRITICAL,
            "cwe": ["CWE-798", "CWE-312"],
            "cve": [],
            "recommendation": "Remove private keys from source code immediately and rotate credentials.",
        },
        # 4. Service Secrets (OpenAI, GitHub, Slack)
        {
            "id": "hardcoded-service-secret",
            "regex": re.compile(r"\b(?:sk-live-[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|xox[baprs]-[0-9a-zA-Z]{10,})\b"),
            "title": "Hardcoded Service API Secret (OpenAI / GitHub / Slack)",
            "description": "Hardcoded live API secret detected.",
            "severity": Severity.CRITICAL,
            "cwe": ["CWE-798"],
            "cve": [],
            "recommendation": "Revoke the secret immediately and load secrets securely from environment variables.",
        },
        # 5. Flutter / Dart Disabled SSL/TLS Validation
        {
            "id": "dart-disabled-ssl-validation",
            "regex": re.compile(r"badCertificateCallback\s*=\s*.*=>\s*true|badCertificateCallback.*\{\s*return\s+true;\s*\}|allowInsecureConnection\s*:\s*true"),
            "title": "Flutter/Dart: Disabled SSL/TLS Certificate Validation",
            "description": "SSL certificate verification is bypassed via badCertificateCallback returning true, leaving app vulnerable to MitM attacks.",
            "severity": Severity.CRITICAL,
            "cwe": ["CWE-295"],
            "cve": [],
            "recommendation": "Enforce strict TLS validation and certificate pinning in production.",
            "exts": {".dart", ".js", ".ts"},
        },
        # 6. Insecure Cleartext HTTP URLs
        {
            "id": "insecure-cleartext-http-url",
            "regex": re.compile(r"""["']http://(?!localhost|127\.0\.0\.1|10\.\d|192\.168|schema\.org|www\.w3\.org)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^"']*["']"""),
            "title": "Insecure Cleartext HTTP Communication URL",
            "description": "Cleartext HTTP endpoint detected. Network traffic is unencrypted and vulnerable to eavesdropping.",
            "severity": Severity.MEDIUM,
            "cwe": ["CWE-319"],
            "cve": [],
            "recommendation": "Replace 'http://' with 'https://' to ensure encrypted data transit.",
            "exts": {".dart", ".js", ".ts", ".jsx", ".tsx", ".py"},
        },
        # 7. Open Firestore / Database Rules
        {
            "id": "insecure-firestore-open-rules",
            "regex": re.compile(r"allow\s+read,\s*write\s*:\s*if\s+true\s*;|allow\s+write\s*:\s*if\s+true\s*;"),
            "title": "Insecure Database / Firestore Public Write Rules",
            "description": "Database rules allow public unauthenticated read/write access ('if true'), exposing all database records.",
            "severity": Severity.CRITICAL,
            "cwe": ["CWE-284", "CWE-732"],
            "cve": [],
            "recommendation": "Restrict access rules to authenticated users (e.g. 'if request.auth != null').",
            "exts": {".json", ".yaml", ".yml", ".rules", ".txt", ".dart"},
        },

    ]

    @classmethod
    def scan_file(cls, file_path: Path, content: str) -> List[VulnerabilityFinding]:
        """Scan file content line-by-line against universal security pattern rules."""
        findings: List[VulnerabilityFinding] = []
        ext = file_path.suffix.lower()
        # Handle files without standard extension like .env
        if not ext and file_path.name.startswith(".env"):
            ext = ".env"

        lines = content.splitlines()

        for rule in cls.RULES:
            # Check extension filtering if rule specifies target extensions
            allowed_exts = rule.get("exts")
            if allowed_exts and ext not in allowed_exts:
                continue

            pattern: Pattern = rule["regex"]

            for line_idx, line in enumerate(lines, 1):
                # Skip comments where applicable to reduce false positives
                line_stripped = line.strip()
                if line_stripped.startswith("//") or line_stripped.startswith("#") or line_stripped.startswith("/*"):
                    # Only skip comment lines if not checking for hardcoded secrets
                    if "key" not in rule["id"] and "secret" not in rule["id"] and "token" not in rule["id"]:
                        continue

                match = pattern.search(line)
                if match:
                    # Extract 30-line code window context
                    first_line = max(1, line_idx - 15)
                    last_line = min(len(lines), line_idx + 15)
                    snippet = "\n".join(lines[first_line - 1 : last_line])

                    findings.append(
                        VulnerabilityFinding(
                            id=rule["id"],
                            scanner=ScannerType.CUSTOM,
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            file_path=str(file_path),
                            line_start=line_idx,
                            line_end=line_idx,
                            code_snippet=snippet,
                            cwe=rule["cwe"],
                            cve=rule["cve"],
                            recommendation=rule["recommendation"],
                            raw_metadata={"matched_text": match.group(0)[:60]}
                        )
                    )

        return findings


class PythonASTSecurityVisitor(ast.NodeVisitor):
    """AST Visitor that inspects Python AST for critical Python-specific security patterns."""

    def __init__(self, file_path: Path, file_content: str) -> None:
        self.file_path = file_path
        self.file_content = file_content
        self.lines = file_content.splitlines()
        self.findings: List[VulnerabilityFinding] = []
        self.dynamic_string_vars: Set[str] = set()

    def _visit_fn_scope(self, node: ast.AST) -> None:
        prev_vars = self.dynamic_string_vars
        self.dynamic_string_vars = set()
        self.generic_visit(node)
        self.dynamic_string_vars = prev_vars

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_fn_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_fn_scope(node)

    def _is_dynamic_expr(self, expr: ast.AST) -> bool:
        if isinstance(expr, (ast.BinOp, ast.JoinedStr)):
            return True
        if isinstance(expr, ast.Name) and expr.id in self.dynamic_string_vars:
            return True
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            return True
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._is_dynamic_expr(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.dynamic_string_vars.add(target.id)
        else:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.dynamic_string_vars.discard(target.id)
        self.generic_visit(node)

    def _get_snippet(self, start_line: int, end_line: Optional[int] = None, padding: int = 15) -> str:
        """Extract a 30-line code window (15 lines before, 15 lines after) around the finding."""
        end = end_line or start_line
        first_line = max(1, start_line - padding)
        last_line = min(len(self.lines), end + padding)
        selected = self.lines[first_line - 1 : last_line]
        return "\n".join(selected)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # 1. Insecure eval() / exec()
        if func_name in ["eval", "exec"]:
            self.findings.append(
                VulnerabilityFinding(
                    id="dynamic-code-eval",
                    scanner=ScannerType.CUSTOM,
                    title=f"Insecure Dynamic Code Execution via {func_name}()",
                    description=f"Use of {func_name}() with dynamic input can lead to Arbitrary Code Execution.",
                    severity=Severity.HIGH,
                    file_path=str(self.file_path),
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    code_snippet=self._get_snippet(node.lineno, node.end_lineno),
                    cwe=["CWE-95"],
                    cve=[],
                    recommendation=f"Avoid using {func_name}(). Use safer alternatives (e.g. ast.literal_eval or dedicated parsers)."
                )
            )

        # 2. SQL Injection in cursor.execute()
        if func_name == "execute" and node.args:
            first_arg = node.args[0]
            if self._is_dynamic_expr(first_arg):
                self.findings.append(
                    VulnerabilityFinding(
                        id="sql-injection-dynamic-query",
                        scanner=ScannerType.CUSTOM,
                        title="Potential SQL Injection via Dynamic Query Construction",
                        description="SQL query is assembled via string concatenation/formatting instead of parameterized placeholders.",
                        severity=Severity.CRITICAL,
                        file_path=str(self.file_path),
                        line_start=node.lineno,
                        line_end=node.end_lineno or node.lineno,
                        code_snippet=self._get_snippet(node.lineno, node.end_lineno),
                        cwe=["CWE-89"],
                        cve=[],
                        recommendation="Use parameterized queries (e.g., cursor.execute('SELECT ... WHERE id = ?', (user_id,)))"
                    )
                )

        # 3. Insecure subprocess with shell=True
        if func_name in ["Popen", "run", "call", "check_output"]:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        VulnerabilityFinding(
                            id="subprocess-shell-true",
                            scanner=ScannerType.CUSTOM,
                            title="Command Injection Risk via subprocess shell=True",
                            description="subprocess invoked with shell=True can allow arbitrary command injection if arguments contain user input.",
                            severity=Severity.HIGH,
                            file_path=str(self.file_path),
                            line_start=node.lineno,
                            line_end=node.end_lineno or node.lineno,
                            code_snippet=self._get_snippet(node.lineno, node.end_lineno),
                            cwe=["CWE-78"],
                            cve=[],
                            recommendation="Set shell=False and pass command arguments as a list of strings."
                        )
                    )

        # 4. Insecure deserialization with pickle
        if func_name in ["loads", "load"] and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                self.findings.append(
                    VulnerabilityFinding(
                        id="insecure-pickle-deserialization",
                        scanner=ScannerType.CUSTOM,
                        title="Insecure Deserialization via pickle",
                        description="Unpickling untrusted data can lead to Remote Code Execution.",
                        severity=Severity.CRITICAL,
                        file_path=str(self.file_path),
                        line_start=node.lineno,
                        line_end=node.end_lineno or node.lineno,
                        code_snippet=self._get_snippet(node.lineno, node.end_lineno),
                        cwe=["CWE-502"],
                        cve=[],
                        recommendation="Use safe serialization formats like JSON, MessagePack, or Protocol Buffers."
                    )
                )

        self.generic_visit(node)


class JSASTSecurityVisitor:
    """AST Visitor that inspects JavaScript/TypeScript AST for DOM XSS and vulnerabilities using esprima."""

    def __init__(self, file_path: Path, file_content: str) -> None:
        self.file_path = file_path
        self.file_content = file_content
        self.lines = file_content.splitlines()
        self.findings: List[VulnerabilityFinding] = []
        self.safe_vars: Set[str] = set()

    def _get_snippet(self, start_line: int, end_line: Optional[int] = None, padding: int = 15) -> str:
        """Extract a 30-line code window (15 lines before, 15 lines after) around the finding."""
        end = end_line or start_line
        first_line = max(1, start_line - padding)
        last_line = min(len(self.lines), end + padding)
        selected = self.lines[first_line - 1 : last_line]
        return "\n".join(selected)

    def _is_safe_data_flow(self, right_node: Any) -> bool:
        """Check if the right side of the assignment is safe (static or sanitized)."""
        if not right_node or not isinstance(right_node, dict):
            return False
            
        node_type = right_node.get("type")
        
        # 1. Static strings / literals are safe
        if node_type == "Literal":
            return True
            
        # 1.5. Identifiers checking local data flow
        if node_type == "Identifier":
            return right_node.get("name") in self.safe_vars
            
        # 2. Sanitized function calls
        if node_type == "CallExpression":
            callee = right_node.get("callee", {})
            func_name = ""
            if callee.get("type") == "Identifier":
                func_name = callee.get("name", "")
            elif callee.get("type") == "MemberExpression":
                prop = callee.get("property", {})
                if prop.get("type") == "Identifier":
                    func_name = prop.get("name", "")
            
            # If function name contains known sanitization keywords, consider it safe
            safe_keywords = [
                "escape", "sanitize", "purify", "encode", "xss", 
                "tolocalestring", "tolocaletimestring", "toisostring", "tostring"
            ]
            func_lower = func_name.lower()
            if any(kw in func_lower for kw in safe_keywords):
                return True
                
        # 3. Template Literals (check internal expressions)
        if node_type == "TemplateLiteral":
            expressions = right_node.get("expressions", [])
            if not expressions:
                return True
            # For template literals, if all expressions inside are safe, it's safe
            for expr in expressions:
                if not self._is_safe_data_flow(expr):
                    return False
            return True
            
        # 4. Conditional Expressions (ternary operators)
        if node_type == "ConditionalExpression":
            return self._is_safe_data_flow(right_node.get("consequent")) and self._is_safe_data_flow(right_node.get("alternate"))
            
        # 5. Logical Expressions (e.g., a || b)
        if node_type == "LogicalExpression":
            return self._is_safe_data_flow(right_node.get("left")) and self._is_safe_data_flow(right_node.get("right"))

        return False

    def visit(self, node: Any) -> None:
        """Recursively traverse the AST dict to find vulnerable patterns."""
        if not node:
            return
            
        if isinstance(node, dict):
            node_type = node.get("type")
            loc = node.get("loc", {})
            start_line = loc.get("start", {}).get("line", 1) if loc else 1
            end_line = loc.get("end", {}).get("line", start_line) if loc else start_line

            # A. Check for Assignment to innerHTML or outerHTML
            if node_type == "AssignmentExpression":
                left = node.get("left", {})
                right = node.get("right", {})
                if left.get("type") == "MemberExpression":
                    prop = left.get("property", {})
                    if prop.get("type") == "Identifier" and prop.get("name") in ["innerHTML", "outerHTML"]:
                        if not self._is_safe_data_flow(right):
                            self.findings.append(
                                VulnerabilityFinding(
                                    id="js-dom-xss-ast",
                                    scanner=ScannerType.CUSTOM,
                                    title=f"Potential DOM XSS via Unsafe {prop.get('name')}",
                                    description=f"Direct assignment of unsanitized data to {prop.get('name')} can lead to DOM XSS.",
                                    severity=Severity.HIGH,
                                    file_path=str(self.file_path),
                                    line_start=start_line,
                                    line_end=end_line,
                                    code_snippet=self._get_snippet(start_line, end_line),
                                    cwe=["CWE-79"],
                                    cve=[],
                                    recommendation="Use textContent or sanitize HTML with DOMPurify/escapeHtml before rendering."
                                )
                            )

            # B. Check for JSX dangerouslySetInnerHTML
            elif node_type == "JSXAttribute":
                name_node = node.get("name", {})
                if name_node.get("type") == "JSXIdentifier" and name_node.get("name") == "dangerouslySetInnerHTML":
                    # For dangerouslySetInnerHTML, the value is a JSXExpressionContainer
                    val_node = node.get("value", {})
                    if val_node.get("type") == "JSXExpressionContainer":
                        inner_expr = val_node.get("expression", {})
                        if inner_expr.get("type") == "ObjectExpression":
                            for obj_prop in inner_expr.get("properties", []):
                                key = obj_prop.get("key", {})
                                if key.get("type") == "Identifier" and key.get("name") == "__html":
                                    html_val = obj_prop.get("value")
                                    if not self._is_safe_data_flow(html_val):
                                        self.findings.append(
                                            VulnerabilityFinding(
                                                id="js-jsx-dangerously-set",
                                                scanner=ScannerType.CUSTOM,
                                                title="Potential DOM XSS via dangerouslySetInnerHTML",
                                                description="Usage of dangerouslySetInnerHTML with unsanitized data.",
                                                severity=Severity.HIGH,
                                                file_path=str(self.file_path),
                                                line_start=start_line,
                                                line_end=end_line,
                                                code_snippet=self._get_snippet(start_line, end_line),
                                                cwe=["CWE-79"],
                                                cve=[],
                                                recommendation="Ensure data is heavily sanitized using DOMPurify before dangerously setting HTML."
                                            )
                                        )

            # B.5 Check for local variable declarations (Data flow tracking)
            elif node_type == "VariableDeclarator":
                id_node = node.get("id", {})
                init_node = node.get("init")
                if id_node.get("type") == "Identifier" and init_node:
                    if self._is_safe_data_flow(init_node):
                        self.safe_vars.add(id_node.get("name"))

            # C. Check for document.write()
            elif node_type == "CallExpression":
                callee = node.get("callee", {})
                if callee.get("type") == "MemberExpression":
                    obj = callee.get("object", {})
                    prop = callee.get("property", {})
                    if obj.get("type") == "Identifier" and obj.get("name") == "document":
                        if prop.get("type") == "Identifier" and prop.get("name") == "write":
                            args = node.get("arguments", [])
                            # If it's just writing static string, it's low risk, but generally write() is bad
                            is_safe = all(self._is_safe_data_flow(arg) for arg in args) if args else False
                            if not is_safe:
                                self.findings.append(
                                    VulnerabilityFinding(
                                        id="js-document-write-xss",
                                        scanner=ScannerType.CUSTOM,
                                        title="Insecure document.write() Invocation",
                                        description="Use of document.write() with dynamic content can introduce DOM XSS vulnerabilities.",
                                        severity=Severity.HIGH,
                                        file_path=str(self.file_path),
                                        line_start=start_line,
                                        line_end=end_line,
                                        code_snippet=self._get_snippet(start_line, end_line),
                                        cwe=["CWE-79"],
                                        cve=[],
                                        recommendation="Avoid document.write(). Use standard DOM manipulation APIs (createElement / appendChild)."
                                    )
                                )

            # Recursively check children
            for key, val in node.items():
                if isinstance(val, (dict, list)):
                    self.visit(val)

        elif isinstance(node, list):
            for item in node:
                self.visit(item)


class SASTScanner:
    """Orchestrates multi-language static analysis tools, mobile DevSecOps rules, and dependency vulnerability scanners."""

    def __init__(
        self,
        semgrep_config: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        min_secret_entropy: float = 3.6,
        event_bus: Optional['ScanEventBus'] = None,
        enable_ai_logic_llm: Optional[bool] = None,
    ) -> None:
        self.semgrep_config = semgrep_config or settings.semgrep_config
        self.timeout_seconds = timeout_seconds or settings.scan_timeout_seconds
        self.mobile_scanner = MobileSecurityScanner()
        self.sanitizer = FalsePositiveSanitizer(min_secret_entropy=min_secret_entropy)
        self.event_bus = event_bus
        self.enable_ai_logic_llm = enable_ai_logic_llm

    async def _run_command(
        self, cmd: List[str], cwd: Optional[Path] = None
    ) -> Tuple[int, str, str]:
        """Execute an asynchronous subprocess with safety timeouts."""
        cmd_str = " ".join(cmd)
        logger.debug(f"Executing scanner command: {cmd_str} in {cwd or os.getcwd()}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout_seconds
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            return process.returncode or 0, stdout_str, stderr_str

        except asyncio.TimeoutError:
            logger.error(f"Command timed out after {self.timeout_seconds}s: {cmd_str}")
            try:
                process.kill()
            except Exception as kill_err:
                logger.debug(f"Process kill ignored after timeout: {kill_err}")
            return -1, "", f"Timeout error after {self.timeout_seconds} seconds"
        except FileNotFoundError as fnf:
            return -2, "", f"Binary '{cmd[0]}' is not installed or not in PATH"
        except Exception as ex:
            return -3, "", str(ex)

    async def _emit(self, event) -> None:
        if self.event_bus:
            try:
                await self.event_bus.emit(event)
            except Exception as e:
                logger.debug(f"Failed to emit event {event.event_type}: {e}")

    def _normalize_semgrep_severity(self, semgrep_sev: str) -> Severity:
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
            "INVENTORY": Severity.INFO,
            "EXPERIMENT": Severity.INFO,
        }
        return mapping.get(semgrep_sev.upper(), Severity.MEDIUM)

    def _normalize_bandit_severity(self, bandit_sev: str) -> Severity:
        mapping = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "UNDEFINED": Severity.INFO,
        }
        return mapping.get(bandit_sev.upper(), Severity.LOW)

    async def run_multi_language_analyzer(self, target_path: Path) -> List[VulnerabilityFinding]:
        """Analyze multi-language source files (Dart, JS, TS, Python, JSON, YAML) with directory pruning."""
        findings: List[VulnerabilityFinding] = []
        emitted_progress = 0
        max_progress_events = 80
        max_file_bytes = 512_000

        for root, dirs, files in os.walk(target_path):
            # Prune ignored directories in-place to prevent os.walk from descending into them
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]

            for file in files:
                file_path = Path(root) / file
                ext = file_path.suffix.lower()
                is_env = file.startswith(".env")

                if ext in TARGET_EXTENSIONS or is_env:
                    try:
                        if file_path.stat().st_size > max_file_bytes:
                            continue
                    except OSError:
                        continue
                    rel_display = str(file_path.relative_to(target_path) if file_path.is_relative_to(target_path) else file_path)
                    if emitted_progress < max_progress_events:
                        await self._emit(FileScanning(file_path=rel_display))
                        emitted_progress += 1
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="replace")

                        # 1. Universal multi-language pattern checks (Dart, JS, TS, Python, Secrets, Rules)
                        pattern_findings = MultiLanguagePatternScanner.scan_file(file_path, content)
                        findings.extend(pattern_findings)
                        for f in pattern_findings:
                            await self._emit(VulnerabilityFound(
                                severity=f.severity.value,
                                title=f.title,
                                file_path=f.file_path,
                                line=f.line_start,
                                explanation=f.description
                            ))

                        # 2. Python-specific AST security visitor
                        if ext == ".py":
                            try:
                                if emitted_progress < max_progress_events:
                                    await self._emit(CodeAnalyzing(file_path=rel_display, snippet="ast.parse() - Analyzing Python syntax tree..."))
                                tree = ast.parse(content, filename=str(file_path))
                                ast_visitor = PythonASTSecurityVisitor(file_path, content)
                                ast_visitor.visit(tree)
                                findings.extend(ast_visitor.findings)
                                for f in ast_visitor.findings:
                                    await self._emit(VulnerabilityFound(
                                        severity=f.severity.value,
                                        title=f.title,
                                        file_path=f.file_path,
                                        line=f.line_start,
                                        explanation=f.description
                                    ))
                            except Exception as ast_err:
                                logger.debug(f"AST parsing skipped for {file_path}: {ast_err}")

                        # 3. JavaScript AST security visitor (esprima only supports JS/JSX, not TS)
                        if ext in (".js", ".jsx") and len(content) <= 250_000:
                            try:
                                if emitted_progress < max_progress_events:
                                    await self._emit(CodeAnalyzing(file_path=rel_display, snippet="esprima.parseScript() - Analyzing JS AST..."))
                                js_tree = esprima.parseScript(content, {"loc": True, "jsx": True}).toDict()
                                js_ast_visitor = JSASTSecurityVisitor(file_path, content)
                                js_ast_visitor.visit(js_tree)
                                findings.extend(js_ast_visitor.findings)
                                for f in js_ast_visitor.findings:
                                    await self._emit(VulnerabilityFound(
                                        severity=f.severity.value,
                                        title=f.title,
                                        file_path=f.file_path,
                                        line=f.line_start,
                                        explanation=f.description
                                    ))
                            except Exception as js_ast_err:
                                logger.debug(f"JS AST parsing skipped for {file_path}: {js_ast_err}")

                    except Exception as e:
                        logger.debug(f"Multi-language scanner skipped {file_path}: {e}")

        return findings

    async def run_semgrep(self, target_path: Path) -> Tuple[List[VulnerabilityFinding], Optional[str]]:
        """Run Semgrep SAST scan over the target directory with excluded paths."""
        if not shutil.which("semgrep"):
            return [], "Semgrep binary not found in PATH."

        semgrep_excludes = sorted(
            IGNORED_DIRS | {"public", "assets", "docs", "scripts", "vendor", "third_party", "coverage", "*.min.js", "*.map"}
        )
        exclude_args = [f"--exclude={d}" for d in semgrep_excludes]

        cmd = [
            "semgrep",
            "scan",
            f"--config={self.semgrep_config}",
            "--json",
            "--quiet",
            *exclude_args,
            str(target_path.resolve()),
        ]

        retcode, stdout, stderr = await self._run_command(cmd)
        if not stdout.strip():
            return [], stderr.strip() or None

        findings: List[VulnerabilityFinding] = []
        try:
            data = json.loads(stdout)
            for res in data.get("results", []):
                check_id = res.get("check_id", "semgrep-finding")
                extra = res.get("extra", {})
                message = extra.get("message", "No description provided.")
                raw_severity = extra.get("severity", "WARNING")
                metadata = extra.get("metadata", {})

                raw_cwe = metadata.get("cwe", [])
                cwe_list = raw_cwe if isinstance(raw_cwe, list) else [str(raw_cwe)] if raw_cwe else []
                raw_cve = metadata.get("cve", [])
                cve_list = raw_cve if isinstance(raw_cve, list) else [str(raw_cve)] if raw_cve else []

                start_line = res.get("start", {}).get("line")
                end_line = res.get("end", {}).get("line")
                file_p = res.get("path", str(target_path))

                # Extract 30-line code window context if file exists
                snippet = extra.get("lines", None)
                if not snippet or len(snippet.splitlines()) < 5:
                    window_ctx = extract_code_context(file_p, start_line, padding=15)
                    if window_ctx:
                        snippet = window_ctx

                finding = VulnerabilityFinding(
                    id=check_id,
                    scanner=ScannerType.SEMGREP,
                    title=f"Semgrep: {check_id.split('.')[-1]}",
                    description=message,
                    severity=self._normalize_semgrep_severity(raw_severity),
                    file_path=file_p,
                    line_start=start_line,
                    line_end=end_line,
                    code_snippet=snippet,
                    cwe=cwe_list,
                    cve=cve_list,
                    recommendation=metadata.get("fix", metadata.get("shortlink", None)),
                    raw_metadata=extra
                )
                findings.append(finding)
            return findings, None
        except Exception as e:
            return [], f"Semgrep parse error: {e}"

    async def run_bandit(self, target_path: Path) -> Tuple[List[VulnerabilityFinding], Optional[str]]:
        """Run Bandit security linter with excluded directories."""
        if not shutil.which("bandit"):
            return [], "Bandit binary not found in PATH."

        exclude_str = ",".join(IGNORED_DIRS)
        cmd = [
            "bandit",
            "-r",
            str(target_path.resolve()),
            "-x",
            exclude_str,
            "-f",
            "json",
            "-q",
        ]

        retcode, stdout, stderr = await self._run_command(cmd)
        if not stdout.strip():
            return [], stderr.strip() or None

        findings: List[VulnerabilityFinding] = []
        try:
            data = json.loads(stdout)
            for res in data.get("results", []):
                test_id = res.get("test_id", "B000")
                test_name = res.get("test_name", "bandit_issue")
                cwe = []
                cwe_info = res.get("issue_cwe", {})
                if isinstance(cwe_info, dict) and "id" in cwe_info:
                    cwe.append(f"CWE-{cwe_info['id']}")

                filename = res.get("filename", str(target_path))
                line_num = res.get("line_number")

                snippet = res.get("code")
                window_ctx = extract_code_context(filename, line_num, padding=15)
                if window_ctx:
                    snippet = window_ctx

                finding = VulnerabilityFinding(
                    id=f"bandit.{test_id}",
                    scanner=ScannerType.BANDIT,
                    title=f"Bandit [{test_id}]: {test_name}",
                    description=res.get("issue_text", ""),
                    severity=self._normalize_bandit_severity(res.get("issue_severity", "LOW")),
                    file_path=filename,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=snippet,
                    cwe=cwe,
                    cve=[],
                    recommendation=f"Reference: {res.get('more_info')}" if res.get("more_info") else None,
                    raw_metadata=res
                )
                findings.append(finding)
            return findings, None
        except Exception as e:
            return [], f"Bandit parse error: {e}"

    async def run_pip_audit(self, target_path: Path) -> Tuple[List[VulnerabilityFinding], Optional[str]]:
        """Run pip-audit on requirements files found outside ignored directories."""
        if not shutil.which("pip-audit"):
            return [], "pip-audit binary not found in PATH."

        req_files: List[Path] = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
            for file in files:
                if file.startswith("requirements") and file.endswith(".txt"):
                    req_files.append(Path(root) / file)

        if not req_files:
            return [], None

        all_findings: List[VulnerabilityFinding] = []
        for req_file in req_files:
            cmd = ["pip-audit", "-r", str(req_file.resolve()), "-f", "json", "--desc"]
            retcode, stdout, stderr = await self._run_command(cmd)
            if not stdout.strip():
                continue
            try:
                data = json.loads(stdout)
                dep_list = data if isinstance(data, list) else data.get("dependencies", [])
                for dep in dep_list:
                    pkg_name = dep.get("name", "unknown")
                    pkg_version = dep.get("version", "unknown")
                    for v in dep.get("vulns", []):
                        vuln_id = v.get("id", "VULN-000")
                        all_findings.append(
                            VulnerabilityFinding(
                                id=vuln_id,
                                scanner=ScannerType.PIP_AUDIT,
                                title=f"Dependency Vulnerability: {pkg_name} ({pkg_version})",
                                description=v.get("description", f"Vulnerability in {pkg_name}"),
                                severity=Severity.HIGH,
                                file_path=str(req_file.relative_to(target_path) if req_file.is_relative_to(target_path) else req_file),
                                code_snippet=f"{pkg_name}=={pkg_version}",
                                cve=[vuln_id] if vuln_id.startswith("CVE") else [],
                                recommendation=f"Upgrade {pkg_name} to version {', '.join(v.get('fix_versions', []))}",
                                raw_metadata=v
                            )
                        )
            except Exception as pa_err:
                logger.debug(f"Failed to parse pip-audit JSON output: {pa_err}")
        return all_findings, None

    async def run_taint_analysis(self, target_path: Path) -> List[VulnerabilityFinding]:
        """Run cross-file Python AST taint analysis and normalize findings."""
        from aegis.scanners.taint_engine import TaintEngine

        def _run() -> List[VulnerabilityFinding]:
            taint_findings = TaintEngine(str(target_path)).analyze()
            converted: List[VulnerabilityFinding] = []
            for idx, tf in enumerate(taint_findings, 1):
                sink_p = Path(tf.sink_file)
                rel_sink = sink_p.relative_to(target_path).as_posix() if sink_p.is_relative_to(target_path) else str(sink_p)
                src_p = Path(tf.source_file)
                rel_src = src_p.relative_to(target_path).as_posix() if src_p.is_relative_to(target_path) else str(src_p)
                sev = Severity.CRITICAL if tf.severity == "CRITICAL" else Severity.HIGH
                flow_str = " ".join(tf.taint_path)
                converted.append(
                    VulnerabilityFinding(
                        id=f"taint-flow-{idx}",
                        scanner=ScannerType.CUSTOM,
                        title=f"{tf.sink_kind or tf.vulnerability_type}: {flow_str}",
                        description=(
                            f"Untrusted input `{tf.source_name or 'user input'}` from `{rel_src}:{tf.source_line}` "
                            f"reaches `{tf.sink_name or 'sink'}` at `{rel_sink}:{tf.sink_line}` via `{flow_str}` "
                            "without sanitization (variable-level inter-procedural data flow)."
                        ),
                        severity=sev,
                        file_path=rel_sink,
                        line_start=tf.sink_line,
                        line_end=tf.sink_line,
                        code_snippet="\n".join(tf.code_snippets),
                        cwe=tf.cwe or ["CWE-20"],
                        cve=[],
                        recommendation="Validate and sanitize untrusted input at the entry point and use parameterized sinks.",
                        raw_metadata={
                            "taint_path": tf.taint_path,
                            "source": {"file": rel_src, "line": tf.source_line, "name": tf.source_name},
                            "sink": {"file": rel_sink, "line": tf.sink_line, "name": tf.sink_name},
                            "sink_kind": tf.sink_kind,
                        },
                    )
                )
            return converted

        return await asyncio.to_thread(_run)

    async def run_git_history(self, target_path: Path) -> List[VulnerabilityFinding]:
        """Git Time Machine: secrets deleted from HEAD but still recoverable from history."""
        from aegis.core.config import settings
        from aegis.scanners.git_history import GitHistoryScanner

        if not settings.git_history_scan_enabled or not GitHistoryScanner.is_git_repo(target_path):
            return []
        scanner = GitHistoryScanner(max_commits=settings.git_history_max_commits)
        try:
            history = await asyncio.to_thread(scanner.scan_history, target_path)
        except Exception as e:
            logger.warning(f"Git history scan skipped: {e}")
            return []
        return GitHistoryScanner.to_findings(history)

    def _apply_project_config(
        self, findings: List[VulnerabilityFinding], project_cfg: ProjectConfig
    ) -> List[VulnerabilityFinding]:
        """Filter findings by .aegis.yml ignore_paths, ignore_rules, and severity_threshold."""
        sev_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        threshold_sev = Severity[project_cfg.severity_threshold.upper()] if project_cfg.severity_threshold.upper() in Severity.__members__ else Severity.LOW
        max_rank = sev_rank[threshold_sev]
        ignored_rules = set(project_cfg.ignore_rules or [])

        filtered: List[VulnerabilityFinding] = []
        for f in findings:
            if f.id in ignored_rules:
                continue
            if sev_rank.get(f.severity, 4) > max_rank:
                continue
            rel = f.file_path.replace("\\", "/").lstrip("./")
            if self._matches_ignore_pattern(rel, project_cfg.ignore_paths):
                continue
            filtered.append(f)
        return filtered

    @staticmethod
    def _matches_ignore_pattern(rel_path: str, patterns: List[str]) -> bool:
        if not patterns:
            return False
        posix = PurePosixPath(rel_path)
        for pat in patterns:
            norm_pat = pat.replace("\\", "/").lstrip("./")
            if not norm_pat:
                continue
            if posix.match(norm_pat):
                return True
            if norm_pat.endswith("/**") and (rel_path.startswith(norm_pat[:-2]) or rel_path == norm_pat[:-3]):
                return True
        return False

    def _run_custom_rules(self, target_path: Path, project_cfg: ProjectConfig) -> List[VulnerabilityFinding]:
        """Evaluate repository-level .aegis.yml regex rules cleanly without duplicating file traversal."""
        if not project_cfg.custom_rules:
            return []

        compiled_rules = []
        for rule in project_cfg.custom_rules:
            try:
                sev = Severity[rule.severity.upper()] if rule.severity.upper() in Severity.__members__ else Severity.MEDIUM
                compiled_rules.append((rule, re.compile(rule.pattern), sev))
            except re.error as exc:
                logger.warning(f"Skipping invalid custom rule '{rule.id}': {exc}")

        if not compiled_rules:
            return []

        findings: List[VulnerabilityFinding] = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() not in TARGET_EXTENSIONS and not file.startswith(".env"):
                    continue
                rel = file_path.relative_to(target_path).as_posix()
                if self._matches_ignore_pattern(rel, project_cfg.ignore_paths):
                    continue
                try:
                    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                except Exception as read_err:
                    logger.debug(f"Skipping unreadable file {file_path}: {read_err}")
                    continue
                for line_idx, line in enumerate(lines, 1):
                    for rule, pattern, sev in compiled_rules:
                        if pattern.search(line):
                            first_line = max(1, line_idx - 5)
                            last_line = min(len(lines), line_idx + 5)
                            findings.append(
                                VulnerabilityFinding(
                                    id=rule.id,
                                    scanner=ScannerType.CUSTOM,
                                    title=rule.title,
                                    description=f"Matched project policy rule '{rule.id}' from .aegis.yml.",
                                    severity=sev,
                                    file_path=rel,
                                    line_start=line_idx,
                                    line_end=line_idx,
                                    code_snippet="\n".join(lines[first_line - 1 : last_line]),
                                    cwe=list(rule.cwe),
                                    recommendation="Remediate according to repository security policy (.aegis.yml).",
                                )
                            )
        return findings

    async def scan(self, target_path: Union[str, Path]) -> SASTScanResult:
        """Run multi-language SAST, Mobile DevSecOps rules, Taint Engine, and dependency vulnerability scanners concurrently with zero-noise sanitization."""
        start_time = time.time()
        path = Path(target_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Target path does not exist: {path}")

        project_cfg = load_config(str(path))
        logger.info(f"Starting multi-language SAST & Mobile security audit for: {path}")

        # Emit ScanStarted
        total_files = 0
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
            total_files += len(files)
        await self._emit(ScanStarted(repo_url=str(path), total_files=total_files))

        from aegis.scanners.secret_scanner import SecretScanner
        from aegis.scanners.flutter_rules import FlutterSecurityScanner
        from aegis.scanners.sca_scanner import SCAScanner
        from aegis.scanners.nextjs_scanner import NextJSSecurityScanner
        from aegis.scanners.business_logic_auditor import BusinessLogicAuditor
        from aegis.scanners.backdoor_scanner import BackdoorScanner

        secret_scanner = SecretScanner()
        flutter_scanner = FlutterSecurityScanner()
        sca_scanner = SCAScanner()
        nextjs_scanner = NextJSSecurityScanner()
        logic_auditor = BusinessLogicAuditor(enable_llm=self.enable_ai_logic_llm)
        backdoor_scanner = BackdoorScanner()

        # Pass event_bus to other scanners if they support it
        if hasattr(secret_scanner, 'event_bus'):
            secret_scanner.event_bus = self.event_bus
        if hasattr(flutter_scanner, 'event_bus'):
            flutter_scanner.event_bus = self.event_bus

        # Run built-in multi-language analyzer, mobile scanner, taint engine, Next.js/JS taint,
        # backdoor detector, business-logic auditor, SCA, and CLI tools concurrently
        ml_task = asyncio.create_task(self.run_multi_language_analyzer(path))
        mobile_task = asyncio.create_task(self.mobile_scanner.scan(path))
        taint_task = asyncio.create_task(self.run_taint_analysis(path))
        nextjs_task = asyncio.create_task(nextjs_scanner.scan(path))
        backdoor_task = asyncio.create_task(backdoor_scanner.scan(path))
        logic_task = asyncio.create_task(logic_auditor.scan(path))
        sca_task = asyncio.create_task(sca_scanner.scan(path))
        semgrep_task = asyncio.create_task(self.run_semgrep(path))
        bandit_task = asyncio.create_task(self.run_bandit(path))
        pip_audit_task = asyncio.create_task(self.run_pip_audit(path))
        secret_task = asyncio.create_task(secret_scanner.scan(path))

        (
            ml_findings,
            mobile_findings,
            taint_findings,
            nextjs_findings,
            backdoor_findings,
            logic_findings,
            sca_findings,
            (semgrep_findings, semgrep_err),
            (bandit_findings, bandit_err),
            (pip_findings, pip_err),
            secret_findings,
        ) = await asyncio.gather(
            ml_task,
            mobile_task,
            taint_task,
            nextjs_task,
            backdoor_task,
            logic_task,
            sca_task,
            semgrep_task,
            bandit_task,
            pip_audit_task,
            secret_task,
            return_exceptions=False,
        )

        # Emit real-time stream alerts for Next.js / JS Taint, Backdoor & Business-Logic Auditor findings
        for f in backdoor_findings + nextjs_findings + logic_findings:
            await self._emit(
                VulnerabilityFound(
                    severity=f.severity.value,
                    title=f.title,
                    file_path=f.file_path,
                    line=f.line_start,
                    explanation=f.description,
                )
            )

        # Flutter scan runs asynchronously now
        flutter_findings = await flutter_scanner.scan(path)
        custom_findings = self._run_custom_rules(path, project_cfg)
        history_findings = await self.run_git_history(path)

        raw_findings: List[VulnerabilityFinding] = (
            backdoor_findings
            + mobile_findings
            + bandit_findings
            + semgrep_findings
            + ml_findings
            + taint_findings
            + nextjs_findings
            + logic_findings
            + sca_findings
            + (pip_findings or [])
            + secret_findings
            + flutter_findings
            + custom_findings
            + history_findings
        )

        # Normalize paths relative to target_path for consistent deduplication and reports
        for f in raw_findings:
            fp = Path(f.file_path)
            if fp.is_absolute() and fp.is_relative_to(path):
                f.file_path = fp.relative_to(path).as_posix()

        # Apply Zero-Noise False-Positive Sanitizer (Shannon Entropy & Test Filter)
        clean_findings = self.sanitizer.sanitize_findings(raw_findings)
        clean_findings = self._apply_project_config(clean_findings, project_cfg)

        # Apply AI-Assisted Smart Filter to drop semantic false positives when enabled by policy
        ai_filter = AIFalsePositiveFilter()
        if project_cfg.ai_filter and ai_filter.enabled:
            logger.info("Running AI-Assisted Smart Filter on findings...")
            clean_findings = await ai_filter.filter_findings(clean_findings)

        errors: List[str] = []
        if semgrep_err:
            errors.append(f"Semgrep: {semgrep_err}")
        if bandit_err:
            errors.append(f"Bandit: {bandit_err}")
        if pip_err:
            errors.append(f"Pip-Audit: {pip_err}")

        severity_counts: Dict[Severity, int] = {sev: 0 for sev in Severity}
        for f in clean_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        duration = round(time.time() - start_time, 2)
        scanners_run = [
            ScannerType.BACKDOOR,
            ScannerType.MOBILE,
            ScannerType.CUSTOM,
            ScannerType.NEXTJS,
            ScannerType.AI_LOGIC,
            ScannerType.SCA,
            ScannerType.SEMGREP,
            ScannerType.BANDIT,
            ScannerType.PIP_AUDIT,
            ScannerType.SECRET,
            ScannerType.FLUTTER,
            ScannerType.GIT_HISTORY,
        ]

        result = SASTScanResult(
            target_path=str(path),
            total_findings=len(clean_findings),
            findings_by_severity=severity_counts,
            findings=clean_findings,
            duration_seconds=duration,
            scanners_run=scanners_run,
            errors=errors
        )

        logger.info(
            f"SAST & Mobile DevSecOps audit completed in {duration}s. "
            f"Discovered {len(clean_findings)} validated findings (sanitized from {len(raw_findings)} raw candidates)."
        )
        
        # Complete the event bus
        if self.event_bus:
            await self.event_bus.complete(total_findings=len(clean_findings), duration_seconds=duration)
            
        return result


if __name__ == "__main__":
    import sys

    from aegis.core.logging_config import setup_logging

    # Logs go through the logging config; stdout carries only the JSON result for piping
    setup_logging()
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = SASTScanner()
    scan_result = asyncio.run(scanner.scan(target))
    sys.stdout.write(scan_result.model_dump_json(indent=2) + "\n")
