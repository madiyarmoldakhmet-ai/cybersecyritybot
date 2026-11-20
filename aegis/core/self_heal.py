"""
Self-Healing with proof: fix → re-scan → keep only patches that verifiably remove findings.

The healer never trusts a patch blindly (not even an LLM one):

1. The repository is copied to a sandbox directory.
2. Deterministic, AST-based fixers rewrite only files that have findings:
   * SQL built by concatenation / f-strings  →  parameterised query
   * ``eval(x)``                             →  ``ast.literal_eval(x)``
   * ``subprocess.*(f"...", shell=True)``    →  argument list without a shell
   * IIN / PII in log f-strings              →  masked (``********1234``)
   * hard-coded secrets                      →  ``os.environ["NAME"]``
   * Dart ``badCertificateCallback => true``  →  removed (default TLS validation)
3. Every patched Python file must still parse; otherwise it is reverted.
4. The sandbox is scanned again with the full SAST pipeline. A file whose patch introduced a
   new finding is reverted and the sandbox re-scanned.
5. Optionally the project's own test-suite runs on the healed copy (CLI only — it executes code).

The result says exactly which findings disappeared, the before/after Security Score and ₸ risk,
a unified diff per file, and what still needs a human (e.g. rotating a key that lives in history).
"""

import ast
import asyncio
import difflib
import logging
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from aegis.core.project_config import load_config
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.risk_model import assess_risk
from aegis.scanners.secret_scanner import detect_secrets, is_plausible_secret
from aegis.scanners.security_score import calculate_score, get_grade

logger = logging.getLogger("aegis.self_heal")


# --------------------------------------------------------------------------------------
# Result models
# --------------------------------------------------------------------------------------


class FileFix(BaseModel):
    file_path: str
    fixers: List[str] = Field(default_factory=list)
    diff: str
    fixed_findings: List[str] = Field(default_factory=list)
    verified: bool = False


class ManualAction(BaseModel):
    title: str
    location: str
    severity: str
    action: str


class HealingReport(BaseModel):
    before_score: int
    before_grade: str
    after_score: int
    after_grade: str
    before_findings: int
    after_findings: int
    before_risk_kzt: int = 0
    after_risk_kzt: int = 0
    fixes: List[FileFix] = Field(default_factory=list)
    reverted_files: List[str] = Field(default_factory=list)
    manual_actions: List[ManualAction] = Field(default_factory=list)
    tests_passed: Optional[bool] = None
    tests_output: str = ""

    @property
    def fixed_count(self) -> int:
        return sum(len(f.fixed_findings) for f in self.fixes)


# --------------------------------------------------------------------------------------
# Source editing helpers
# --------------------------------------------------------------------------------------


def _replace_stmt(lines: List[str], stmt: ast.stmt, new_stmt: ast.stmt) -> None:
    """Replace the source lines of ``stmt`` with ``ast.unparse(new_stmt)`` keeping indentation."""
    start, end = stmt.lineno - 1, stmt.end_lineno
    indent = re.match(r"\s*", lines[start]).group(0)
    rendered = ast.unparse(new_stmt).splitlines()
    lines[start:end] = [indent + rendered[0]] + [indent + ln for ln in rendered[1:]]


def _ensure_import(text: str, module: str) -> str:
    tree = ast.parse(text)
    for node in tree.body:
        if isinstance(node, ast.Import) and any(a.name == module for a in node.names):
            return text
    lines = text.splitlines(keepends=True)
    insert_at = 0
    for node in tree.body:
        is_docstring = isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        is_future = isinstance(node, ast.ImportFrom) and node.module == "__future__"
        if is_docstring or is_future:
            insert_at = node.end_lineno
            continue
        break
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)) and not (isinstance(node, ast.ImportFrom) and node.module == "__future__"):
            insert_at = node.lineno - 1
            break
    lines.insert(insert_at, f"import {module}\n")
    return "".join(lines)


def _statements(tree: ast.AST):
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            for stmt in getattr(node, field, []) or []:
                if isinstance(stmt, ast.stmt):
                    yield node, stmt


def _last_assignment(tree: ast.AST, name: str, before_line: int) -> Optional[ast.Assign]:
    best = None
    for _, stmt in _statements(tree):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and stmt.targets[0].id == name
            and stmt.lineno < before_line
            and (best is None or stmt.lineno > best.lineno)
        ):
            best = stmt
    return best


def _flatten_string_expr(node: ast.AST) -> Optional[List[object]]:
    """``"a" + x + "b"`` / ``f"a{x}b"`` → ``["a", <x>, "b"]`` (None if not a string build)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        parts: List[object] = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue) and v.format_spec is None and v.conversion == -1:
                parts.append(v.value)
            else:
                return None
        return parts
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _flatten_string_expr(node.left), _flatten_string_expr(node.right)
        if left is None and right is None:
            return None
        return (left if left is not None else [node.left]) + (right if right is not None else [node.right])
    return None


def _stmt_containing(tree: ast.AST, node: ast.AST) -> Optional[ast.stmt]:
    best = None
    for _, stmt in _statements(tree):
        if stmt.lineno <= node.lineno and stmt.end_lineno >= node.end_lineno:
            if best is None or (stmt.end_lineno - stmt.lineno) <= (best.end_lineno - best.lineno):
                best = stmt
    return best


# --------------------------------------------------------------------------------------
# Python fixers: (source_text, findings_in_file) -> new_text (unchanged if not applicable)
# --------------------------------------------------------------------------------------


def fix_sql_injection(text: str, findings: List[VulnerabilityFinding]) -> str:
    tree = ast.parse(text)
    paramstyle = "%s" if re.search(r"\b(psycopg2?|pymysql|MySQLdb|mysql\.connector|asyncpg)\b", text) else "?"
    edits: List[Tuple[ast.stmt, ast.stmt]] = []

    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"execute", "executemany"}
            and len(node.args) == 1
            and not node.keywords
        ):
            continue
        arg = node.args[0]
        assign = _last_assignment(tree, arg.id, node.lineno) if isinstance(arg, ast.Name) else None
        expr = assign.value if assign is not None else arg
        parts = _flatten_string_expr(expr)
        if not parts or all(isinstance(p, str) for p in parts):
            continue

        sql, params = "", []
        for i, part in enumerate(parts):
            if isinstance(part, str):
                sql += part
                continue
            prev_quoted = sql[-1:] in {"'", '"'}
            nxt = parts[i + 1] if i + 1 < len(parts) and isinstance(parts[i + 1], str) else ""
            if prev_quoted and nxt[:1] == sql[-1]:
                sql = sql[:-1]
                parts[i + 1] = nxt[1:]
            sql += paramstyle
            params.append(part)
        param_tuple = ast.Tuple(elts=params, ctx=ast.Load())

        call_stmt = _stmt_containing(tree, node)
        if call_stmt is None:
            continue
        new_call = ast.Call(func=node.func, args=[], keywords=[])
        if assign is not None:
            edits.append((assign, ast.Assign(targets=assign.targets, value=ast.Constant(sql), lineno=0)))
            new_call.args = [arg, param_tuple]
        else:
            new_call.args = [ast.Constant(sql), param_tuple]
        new_stmt = _swap_node(call_stmt, node, new_call)
        edits.append((call_stmt, new_stmt))

    return _apply_edits(text, edits)


def fix_eval(text: str, findings: List[VulnerabilityFinding]) -> str:
    tree = ast.parse(text)
    edits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval" and len(node.args) == 1:
            stmt = _stmt_containing(tree, node)
            if stmt is None:
                continue
            safe = ast.Call(func=ast.Attribute(value=ast.Name("ast", ast.Load()), attr="literal_eval", ctx=ast.Load()), args=node.args, keywords=[])
            edits.append((stmt, _swap_node(stmt, node, safe)))
    new = _apply_edits(text, edits)
    return _ensure_import(new, "ast") if new != text else text


def _fstring_to_argv(parts: List[object]) -> Optional[ast.List]:
    """``["tar -czf /tmp/", <name>, ".tgz /data"]`` → ``["tar", "-czf", f"/tmp/{name}.tgz", "/data"]``."""
    words: List[List[object]] = [[]]
    for part in parts:
        if isinstance(part, str):
            if re.search(r"[;&|`$<>(){}*?]", part):
                return None  # real shell syntax: needs a human
            chunks = re.split(r"(\s+)", part)
            for chunk in chunks:
                if not chunk:
                    continue
                if chunk.isspace():
                    if words[-1]:
                        words.append([])
                else:
                    words[-1].append(chunk)
        else:
            words[-1].append(part)
    elts = []
    for word in words:
        if not word:
            continue
        if all(isinstance(w, str) for w in word):
            elts.append(ast.Constant("".join(word)))
        elif len(word) == 1:
            elts.append(ast.Call(func=ast.Name("str", ast.Load()), args=[word[0]], keywords=[]))
        else:
            values = [ast.Constant(w) if isinstance(w, str) else ast.FormattedValue(value=w, conversion=-1, format_spec=None) for w in word]
            elts.append(ast.JoinedStr(values=values))
    return ast.List(elts=elts, ctx=ast.Load()) if elts else None


def fix_shell_injection(text: str, findings: List[VulnerabilityFinding]) -> str:
    tree = ast.parse(text)
    edits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and node.args):
            continue
        name = ast.unparse(node.func)
        shell_kw = next((kw for kw in node.keywords if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True), None)
        if not (name.startswith("subprocess.") and shell_kw):
            continue
        arg = node.args[0]
        assign = _last_assignment(tree, arg.id, node.lineno) if isinstance(arg, ast.Name) else None
        parts = _flatten_string_expr(assign.value if assign is not None else arg)
        if not parts:
            continue
        argv = _fstring_to_argv(parts)
        if argv is None:
            continue
        stmt = _stmt_containing(tree, node)
        if stmt is None:
            continue
        new_call = ast.Call(func=node.func, args=list(node.args), keywords=[kw for kw in node.keywords if kw is not shell_kw])
        if assign is not None:
            edits.append((assign, ast.Assign(targets=assign.targets, value=argv, lineno=0)))
        else:
            new_call.args[0] = argv
        edits.append((stmt, _swap_node(stmt, node, new_call)))
    return _apply_edits(text, edits)


_PII_NAME = re.compile(r"(?i)(^|_)(iin|bin|inn|passport|phone|card(_?number)?|pan)($|_)")
_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical"}


def fix_pii_logging(text: str, findings: List[VulnerabilityFinding]) -> str:
    tree = ast.parse(text)
    edits = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _LOG_METHODS
            and node.args
            and isinstance(node.args[0], ast.JoinedStr)
        ):
            continue
        changed = False
        values = []
        for v in node.args[0].values:
            if isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name) and _PII_NAME.search(v.value.id):
                masked = ast.Subscript(
                    value=ast.Call(func=ast.Name("str", ast.Load()), args=[v.value], keywords=[]),
                    slice=ast.Slice(lower=ast.UnaryOp(op=ast.USub(), operand=ast.Constant(4))),
                    ctx=ast.Load(),
                )
                values.append(ast.FormattedValue(value=masked, conversion=-1, format_spec=ast.JoinedStr([ast.Constant("*>12")])))
                changed = True
            elif isinstance(v, ast.Constant):
                values.append(ast.Constant(re.sub(r"(?i)\b(iin|иин)\b", lambda m: m.group(0) + "_masked", v.value)))
            else:
                values.append(v)
        if not changed:
            continue
        stmt = _stmt_containing(tree, node)
        new_call = ast.Call(func=node.func, args=[ast.JoinedStr(values)] + node.args[1:], keywords=node.keywords)
        edits.append((stmt, _swap_node(stmt, node, new_call)))
    return _apply_edits(text, edits)


def fix_hardcoded_secrets(text: str, findings: List[VulnerabilityFinding]) -> str:
    if not any(f.scanner == ScannerType.SECRET or "CWE-798" in f.cwe for f in findings):
        return text
    tree = ast.parse(text)
    src_lines = text.splitlines()
    edits = []
    for node in tree.body:
        line = src_lines[node.lineno - 1] if node.lineno <= len(src_lines) else ""
        # match by content, not line number: earlier fixers may have inserted imports
        has_secret = any(is_plausible_secret(t, v) for t, v in detect_secrets(line))
        if (
            isinstance(node, ast.Assign)
            and has_secret
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            env_name = node.targets[0].id.upper()
            env_lookup = ast.Subscript(
                value=ast.Attribute(value=ast.Name("os", ast.Load()), attr="environ", ctx=ast.Load()),
                slice=ast.Constant(env_name),
                ctx=ast.Load(),
            )
            edits.append((node, ast.Assign(targets=node.targets, value=env_lookup, lineno=0)))
    new = _apply_edits(text, edits)
    return _ensure_import(new, "os") if new != text else text


def fix_dart_tls(text: str, findings: List[VulnerabilityFinding]) -> str:
    pattern = re.compile(r"^[ \t]*\w+\.badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true\s*;[ \t]*\n?", re.MULTILINE)
    return pattern.sub("", text)


def _swap_node(stmt: ast.stmt, old: ast.AST, new: ast.AST) -> ast.stmt:
    """Deep-copy ``stmt`` with ``old`` (matched by position) replaced by ``new``."""
    import copy

    clone = copy.deepcopy(stmt)

    class Swapper(ast.NodeTransformer):
        def generic_visit(self, node):
            if (
                type(node) is type(old)
                and getattr(node, "lineno", None) == old.lineno
                and getattr(node, "col_offset", None) == old.col_offset
                and getattr(node, "end_col_offset", None) == old.end_col_offset
            ):
                return new
            return super().generic_visit(node)

    return ast.fix_missing_locations(Swapper().visit(clone))


def _apply_edits(text: str, edits: List[Tuple[ast.stmt, ast.stmt]]) -> str:
    if not edits:
        return text
    lines = text.splitlines()
    seen = set()
    for stmt, new_stmt in sorted(edits, key=lambda e: e[0].lineno, reverse=True):
        if stmt.lineno in seen:
            continue
        seen.add(stmt.lineno)
        _replace_stmt(lines, stmt, new_stmt)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


PYTHON_FIXERS: List[Tuple[str, Callable[[str, List[VulnerabilityFinding]], str]]] = [
    ("Параметризованный SQL-запрос", fix_sql_injection),
    ("eval() → ast.literal_eval()", fix_eval),
    ("Команда списком аргументов без shell", fix_shell_injection),
    ("Маскирование ИИН/ПДн в логах", fix_pii_logging),
    ("Секрет → переменная окружения", fix_hardcoded_secrets),
]
DART_FIXERS = [("Включена проверка TLS-сертификата", fix_dart_tls)]


# --------------------------------------------------------------------------------------
# Verification loop
# --------------------------------------------------------------------------------------


def _finding_key(f: VulnerabilityFinding) -> Tuple[str, str, str]:
    norm_id = re.sub(r"-(?:[0-9a-f]{8,}|\d+)$", "", f.id)
    return (f.file_path, f.scanner.value, norm_id)


_PENALTY = {Severity.CRITICAL: 25, Severity.HIGH: 10, Severity.MEDIUM: 3, Severity.LOW: 1, Severity.INFO: 0}


def _file_penalty(findings: List[VulnerabilityFinding], rel: str) -> int:
    return sum(_PENALTY[f.severity] for f in findings if f.file_path == rel)


def _regressed_files(before: SASTScanResult, after: SASTScanResult, candidates) -> List[str]:
    """A patch is kept only if it strictly lowers the file's risk and adds no new HIGH/CRITICAL issue."""
    before_keys = Counter(_finding_key(f) for f in before.findings)
    new_keys = Counter(_finding_key(f) for f in after.findings) - before_keys
    bad = []
    for rel in candidates:
        new_severe = any(
            k[0] == rel and f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in after.findings if (k := _finding_key(f)) in new_keys
        )
        if new_severe or _file_penalty(after.findings, rel) >= _file_penalty(before.findings, rel):
            bad.append(rel)
    return bad


def _manual_action(f: VulnerabilityFinding) -> str:
    if f.scanner == ScannerType.GIT_HISTORY:
        return "Отозвать/перевыпустить ключ у провайдера и очистить историю (git filter-repo). Патч кода это не исправит."
    return f.recommendation or "Требуется ручной разбор."


class SelfHealer:
    def __init__(self, scan_fn: Optional[Callable] = None, run_tests: bool = False, test_timeout: float = 180.0):
        self._scan_fn = scan_fn
        self.run_tests = run_tests
        self.test_timeout = test_timeout

    async def _scan(self, path: Path) -> SASTScanResult:
        if self._scan_fn is not None:
            return await self._scan_fn(path)
        from aegis.scanners.sast_scanner import SASTScanner

        return await SASTScanner().scan(path)

    @staticmethod
    def _heal_file(path: Path, findings: List[VulnerabilityFinding]) -> Tuple[Optional[str], List[str]]:
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None, []
        fixers = PYTHON_FIXERS if path.suffix == ".py" else DART_FIXERS if path.suffix == ".dart" else []
        text, applied = original, []
        for label, fixer in fixers:
            try:
                new = fixer(text, findings)
            except (SyntaxError, ValueError, RecursionError) as e:
                logger.debug(f"{label} skipped for {path.name}: {e}")
                continue
            if new != text:
                if path.suffix == ".py":
                    try:
                        ast.parse(new)
                    except SyntaxError:
                        continue  # never keep a patch that breaks the file
                text = new
                applied.append(label)
        return (text if text != original else None), applied

    def _run_tests(self, root: Path) -> Tuple[Optional[bool], str]:
        has_tests = any(root.rglob("test_*.py")) or any(root.rglob("*_test.py"))
        if not self.run_tests or not has_tests:
            return None, ""
        try:
            proc = subprocess.run(  # nosec B603
                [sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider"],
                cwd=root, capture_output=True, text=True, timeout=self.test_timeout,
            )
        except subprocess.TimeoutExpired:
            return False, "Тесты превысили лимит времени."
        return proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]

    async def heal(self, repo_path, before: Optional[SASTScanResult] = None, apply_to: Optional[Path] = None) -> HealingReport:
        """Heal a sandbox copy of ``repo_path``. With ``apply_to`` the verified files are written there."""
        src = Path(repo_path).resolve()
        before = before or await self._scan(src)
        risk_cfg = load_config(str(src)).risk

        sandbox_root = Path(tempfile.mkdtemp(prefix="aegis_heal_"))
        sandbox = sandbox_root / src.name
        try:
            shutil.copytree(src, sandbox, symlinks=True, ignore=shutil.ignore_patterns("node_modules", ".venv", "venv", "__pycache__"))

            by_file: Dict[str, List[VulnerabilityFinding]] = {}
            for f in before.findings:
                by_file.setdefault(f.file_path, []).append(f)

            originals: Dict[str, str] = {}
            applied: Dict[str, List[str]] = {}
            for rel, file_findings in by_file.items():
                target = sandbox / rel
                if not target.is_file() or not target.resolve().is_relative_to(sandbox.resolve()):
                    continue
                new_text, labels = await asyncio.to_thread(self._heal_file, target, file_findings)
                if new_text is None:
                    continue
                originals[rel] = target.read_text(encoding="utf-8")
                target.write_text(new_text, encoding="utf-8")
                applied[rel] = labels

            after = await self._scan(sandbox) if applied else before
            before_keys = Counter(_finding_key(f) for f in before.findings)

            reverted: List[str] = []
            for _ in range(3):
                bad = _regressed_files(before, after, list(applied))
                if not bad:
                    break
                for rel in bad:
                    (sandbox / rel).write_text(originals.pop(rel), encoding="utf-8")
                    applied.pop(rel)
                    reverted.append(rel)
                after = await self._scan(sandbox)

            after_keys = Counter(_finding_key(f) for f in after.findings)
            fixes: List[FileFix] = []
            gone = before_keys - after_keys  # findings that disappeared after patching
            for rel, labels in applied.items():
                fixed = []
                for f in by_file[rel]:
                    key = _finding_key(f)
                    if gone[key] > 0:
                        gone[key] -= 1
                        fixed.append(f.title)
                new_text = (sandbox / rel).read_text(encoding="utf-8")
                diff = "".join(difflib.unified_diff(
                    originals[rel].splitlines(keepends=True), new_text.splitlines(keepends=True),
                    fromfile=f"a/{rel}", tofile=f"b/{rel}",
                ))
                fixes.append(FileFix(file_path=rel, fixers=labels, diff=diff, fixed_findings=fixed, verified=bool(fixed)))

            tests_passed, tests_output = await asyncio.to_thread(self._run_tests, sandbox) if applied else (None, "")

            if apply_to is not None and tests_passed is not False:
                for fix in fixes:
                    if fix.verified:
                        (Path(apply_to) / fix.file_path).write_text((sandbox / fix.file_path).read_text(encoding="utf-8"), encoding="utf-8")

            manual = [
                ManualAction(title=f.title, location=f"{f.file_path}:{f.line_start or 1}", severity=f.severity.value, action=_manual_action(f))
                for f in after.findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]
            b_score, a_score = calculate_score(before.findings), calculate_score(after.findings)
            return HealingReport(
                before_score=b_score,
                before_grade=get_grade(b_score)[0],
                after_score=a_score,
                after_grade=get_grade(a_score)[0],
                before_findings=before.total_findings,
                after_findings=after.total_findings,
                before_risk_kzt=assess_risk(before.findings, risk_cfg).total_kzt,
                after_risk_kzt=assess_risk(after.findings, risk_cfg).total_kzt,
                fixes=sorted(fixes, key=lambda x: x.file_path),
                reverted_files=reverted,
                manual_actions=manual,
                tests_passed=tests_passed,
                tests_output=tests_output,
            )
        finally:
            shutil.rmtree(sandbox_root, ignore_errors=True)
