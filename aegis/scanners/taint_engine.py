"""
Inter-procedural, variable-level taint analysis for Python projects.

How it works
------------
1. Every ``def`` / ``async def`` in the project (plus module-level code) is parsed with ``ast``.
2. Each function is interpreted abstractly: every variable carries a set of *origins* —
   either an untrusted **source** (``request.args.get(...)``, ``input()``, a FastAPI/Flask
   route parameter, ...) or one of the function's own **parameters**.
3. Taint propagates through assignments, f-strings, concatenation, containers, method calls on
   tainted objects and calls into other project functions. Sanitizers (``int()``,
   ``shlex.quote()``, ``html.escape()``, ...) remove taint **only from the value they wrap**,
   so ``uid = int(uid)`` cleans ``uid`` but a sanitizer elsewhere in the function does not.
4. For each function a *summary* is computed: which parameters reach the return value and which
   parameters reach which sinks (with the call chain). Summaries are iterated to a fixpoint, so
   flows across any number of functions and files are found.
5. Sinks look only at the dangerous argument: ``cursor.execute(sql, params)`` checks ``sql`` —
   a parameterised query with tainted ``params`` is *not* reported.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from pydantic import BaseModel, Field


class TaintFinding(BaseModel):
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int
    taint_path: List[str]
    vulnerability_type: str
    severity: str
    code_snippets: List[str]
    source_name: str = ""
    sink_name: str = ""
    sink_kind: str = ""
    cwe: List[str] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Sources, sanitizers and sinks
# --------------------------------------------------------------------------------------

#: Attribute chains whose value is attacker-controlled (prefix match on the dotted name).
SOURCE_PREFIXES = (
    "request.args",
    "request.form",
    "request.json",
    "request.get_json",
    "request.values",
    "request.data",
    "request.files",
    "request.cookies",
    "request.headers",
    "request.query_params",
    "request.path_params",
    "request.body",
    "request.GET",
    "request.POST",
    "request.FILES",
    "request.COOKIES",
    "request.META",
    "sys.argv",
)
SOURCE_CALLS = {"input", "raw_input"}

#: Calls whose result is safe regardless of input.
SANITIZERS = {
    "int", "float", "bool", "len", "abs", "round", "isinstance", "hash",
    "escape", "html.escape", "markupsafe.escape", "bleach.clean",
    "shlex.quote", "pipes.quote", "re.escape",
    "os.path.basename", "secure_filename", "werkzeug.utils.secure_filename",
    "uuid.UUID", "validate", "sanitize", "quote", "urllib.parse.quote",
}

#: Route decorators: their function parameters are user input.
ROUTE_DECORATOR_SUFFIXES = (".get", ".post", ".put", ".patch", ".delete", ".route", ".api_route", ".websocket")
NON_INPUT_PARAMS = {"self", "cls", "request", "db", "session", "cursor", "conn", "background_tasks", "response", "current_user"}


@dataclass(frozen=True)
class SinkSpec:
    kind: str
    cwe: Tuple[str, ...]
    severity: str
    arg_index: Optional[int] = 0  # positional arg that must be tainted; None = any argument
    keyword: Optional[str] = None  # keyword alternative for the dangerous argument


SQL_SINK = SinkSpec("SQL Injection", ("CWE-89",), "CRITICAL", 0, "sql")
CMD_SINK = SinkSpec("OS Command Injection", ("CWE-78",), "CRITICAL", 0, "args")
CMD_SINK_NOSHELL = SinkSpec("Argument Injection", ("CWE-88",), "HIGH", 0, "args")
CODE_SINK = SinkSpec("Code Injection", ("CWE-95",), "CRITICAL", 0, None)
PATH_SINK = SinkSpec("Path Traversal", ("CWE-22",), "HIGH", 0, "file")
DESER_SINK = SinkSpec("Insecure Deserialization", ("CWE-502",), "CRITICAL", 0, None)
SSRF_SINK = SinkSpec("Server-Side Request Forgery", ("CWE-918",), "HIGH", 0, "url")
SSTI_SINK = SinkSpec("Server-Side Template Injection", ("CWE-1336",), "CRITICAL", 0, "source")
REDIRECT_SINK = SinkSpec("Open Redirect", ("CWE-601",), "MEDIUM", 0, "location")

_EXACT_SINKS = {
    "os.system": CMD_SINK,
    "os.popen": CMD_SINK,
    "eval": CODE_SINK,
    "exec": CODE_SINK,
    "compile": CODE_SINK,
    "open": PATH_SINK,
    "send_file": PATH_SINK,
    "flask.send_file": PATH_SINK,
    "pickle.loads": DESER_SINK,
    "pickle.load": DESER_SINK,
    "marshal.loads": DESER_SINK,
    "yaml.load": DESER_SINK,
    "yaml.unsafe_load": DESER_SINK,
    "requests.get": SSRF_SINK,
    "requests.post": SSRF_SINK,
    "requests.request": SinkSpec("Server-Side Request Forgery", ("CWE-918",), "HIGH", 1, "url"),
    "httpx.get": SSRF_SINK,
    "httpx.post": SSRF_SINK,
    "urllib.request.urlopen": SSRF_SINK,
    "urlopen": SSRF_SINK,
    "render_template_string": SSTI_SINK,
    "flask.render_template_string": SSTI_SINK,
    "jinja2.Template": SSTI_SINK,
    "Template": SSTI_SINK,
    "redirect": REDIRECT_SINK,
    "RedirectResponse": SinkSpec("Open Redirect", ("CWE-601",), "MEDIUM", 0, "url"),
}
_SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"}
_SQL_METHODS = {"execute", "executemany", "executescript", "raw", "extra"}


def _sink_for_call(call_name: str, node: ast.Call) -> Optional[SinkSpec]:
    if call_name in _EXACT_SINKS:
        spec = _EXACT_SINKS[call_name]
        if call_name == "yaml.load" and any(
            kw.arg == "Loader" and "Safe" in (_dotted(kw.value) or "") for kw in node.keywords
        ):
            return None
        return spec
    parts = call_name.split(".")
    if parts[0] == "subprocess" and parts[-1] in _SUBPROCESS_FUNCS:
        if parts[-1] in {"getoutput", "getstatusoutput"}:
            return CMD_SINK
        shell = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        return CMD_SINK if shell else CMD_SINK_NOSHELL
    if len(parts) >= 2 and parts[-1] in _SQL_METHODS:
        return SQL_SINK
    return None


def _dotted(node: ast.AST) -> Optional[str]:
    """``a.b.c`` for Name/Attribute chains (call results are walked through: ``a().b`` -> ``a.b``)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    return None


def _is_source_name(dotted: Optional[str]) -> bool:
    if not dotted:
        return False
    return any(dotted == p or dotted.startswith(p + ".") or dotted.startswith(p + "[") for p in SOURCE_PREFIXES)


# --------------------------------------------------------------------------------------
# Abstract values
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    file: str
    line: int
    name: str
    func: str  # label of the function where the input entered


@dataclass(frozen=True)
class Param:
    index: int


Origin = object  # Source | Param
Taint = FrozenSet[Origin]
EMPTY: Taint = frozenset()


@dataclass(frozen=True)
class ParamSink:
    """Parameter ``index`` of a function reaches ``sink`` through ``chain`` of functions."""

    index: int
    sink_name: str
    sink_file: str
    sink_line: int
    spec: SinkSpec
    chain: Tuple[str, ...]


@dataclass
class Summary:
    returns: Taint = EMPTY
    param_sinks: FrozenSet[ParamSink] = frozenset()

    def key(self):
        return (self.returns, self.param_sinks)


@dataclass
class FunctionInfo:
    qname: str
    name: str
    file: str
    node: ast.AST
    params: List[str]
    is_method: bool
    route_params: Set[str]
    calls: Set[str]


# --------------------------------------------------------------------------------------
# Function analysis
# --------------------------------------------------------------------------------------


class _FunctionAnalyzer:
    def __init__(self, engine: "TaintEngine", fn: FunctionInfo, collect: bool):
        self.engine = engine
        self.fn = fn
        self.collect = collect
        self.env: Dict[str, Taint] = {}
        self.returns: Set[Origin] = set()
        self.param_sinks: Set[ParamSink] = set()
        self.branch_depth = 0

        for idx, p in enumerate(fn.params):
            if p in fn.route_params:
                self.env[p] = frozenset({Source(fn.file, fn.node.lineno, f"route parameter `{p}`", fn.name)})
            else:
                self.env[p] = frozenset({Param(idx)})

    # ---------------- statements ----------------
    def run(self) -> Summary:
        body = self.fn.node.body if hasattr(self.fn.node, "body") else []
        self._block(body)
        return Summary(frozenset(self.returns), frozenset(self.param_sinks))

    def _block(self, stmts):
        for stmt in stmts:
            self._stmt(stmt)

    def _assign_target(self, target: ast.AST, taint: Taint):
        if isinstance(target, ast.Name):
            if self.branch_depth:
                self.env[target.id] = self.env.get(target.id, EMPTY) | taint
            else:
                self.env[target.id] = taint
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign_target(elt.value if isinstance(elt, ast.Starred) else elt, taint)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            # container[x] = tainted / obj.attr = tainted -> container/obj becomes tainted (weak update)
            base = _dotted(target)
            root = base.split(".")[0] if base else None
            if root:
                self.env[root] = self.env.get(root, EMPTY) | taint
            if isinstance(target, ast.Attribute) and base:
                self.env[base] = self.env.get(base, EMPTY) | taint

    def _stmt(self, stmt: ast.stmt):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(stmt, ast.Assign):
            taint = self._expr(stmt.value)
            for t in stmt.targets:
                self._assign_target(t, taint)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._assign_target(stmt.target, self._expr(stmt.value))
        elif isinstance(stmt, ast.AugAssign):
            taint = self._expr(stmt.value) | self._expr(stmt.target)
            self._assign_target(stmt.target, taint)
        elif isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self.returns |= self._expr(stmt.value)
        elif isinstance(stmt, ast.Expr):
            self._expr(stmt.value)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_taint = self._expr(stmt.iter)
            self.branch_depth += 1
            for _ in range(2):  # second pass lets loop-carried taint settle
                self._assign_target(stmt.target, iter_taint)
                self._block(stmt.body)
            self._block(stmt.orelse)
            self.branch_depth -= 1
        elif isinstance(stmt, ast.While):
            self._expr(stmt.test)
            self.branch_depth += 1
            for _ in range(2):
                self._block(stmt.body)
            self._block(stmt.orelse)
            self.branch_depth -= 1
        elif isinstance(stmt, ast.If):
            self._expr(stmt.test)
            self.branch_depth += 1
            self._block(stmt.body)
            self._block(stmt.orelse)
            self.branch_depth -= 1
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                taint = self._expr(item.context_expr)
                if item.optional_vars is not None:
                    self._assign_target(item.optional_vars, taint)
            self._block(stmt.body)
        elif isinstance(stmt, ast.Try) or (hasattr(ast, "TryStar") and isinstance(stmt, getattr(ast, "TryStar"))):
            self.branch_depth += 1
            self._block(stmt.body)
            for h in stmt.handlers:
                self._block(h.body)
            self._block(stmt.orelse)
            self.branch_depth -= 1
            self._block(stmt.finalbody)
        elif hasattr(ast, "Match") and isinstance(stmt, getattr(ast, "Match")):
            self._expr(stmt.subject)
            self.branch_depth += 1
            for case in stmt.cases:
                self._block(case.body)
            self.branch_depth -= 1
        else:
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self._expr(child)

    # ---------------- expressions ----------------
    def _expr(self, node: Optional[ast.AST]) -> Taint:
        if node is None:
            return EMPTY
        if isinstance(node, ast.Name):
            return self.env.get(node.id, EMPTY)
        if isinstance(node, ast.Constant):
            return EMPTY
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            dotted = _dotted(node)
            if _is_source_name(dotted):
                return frozenset({Source(self.fn.file, node.lineno, dotted, self.fn.name)})
            taint = self.env.get(dotted, EMPTY) if dotted else EMPTY
            taint |= self._expr(node.value)
            if isinstance(node, ast.Subscript):
                self._expr(node.slice)
            return taint
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, ast.JoinedStr):
            return self._union(node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr(node.left) | self._expr(node.right)
        if isinstance(node, ast.BoolOp):
            return self._union(node.values)
        if isinstance(node, ast.UnaryOp):
            self._expr(node.operand)
            return EMPTY if isinstance(node.op, ast.Not) else self._expr(node.operand)
        if isinstance(node, ast.Compare):
            self._expr(node.left)
            self._union(node.comparators)
            return EMPTY  # booleans do not carry attacker-controlled strings
        if isinstance(node, ast.IfExp):
            self._expr(node.test)
            return self._expr(node.body) | self._expr(node.orelse)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._union(node.elts)
        if isinstance(node, ast.Starred):
            return self._expr(node.value)
        if isinstance(node, ast.Dict):
            return self._union([k for k in node.keys if k is not None]) | self._union(node.values)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            for gen in node.generators:
                self._assign_target(gen.target, self._expr(gen.iter))
            return self._expr(node.elt)
        if isinstance(node, ast.DictComp):
            for gen in node.generators:
                self._assign_target(gen.target, self._expr(gen.iter))
            return self._expr(node.key) | self._expr(node.value)
        if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)):
            return self._expr(node.value)
        if isinstance(node, ast.NamedExpr):
            taint = self._expr(node.value)
            self._assign_target(node.target, taint)
            return taint
        if isinstance(node, ast.Lambda):
            return EMPTY
        taint = EMPTY
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                taint |= self._expr(child)
        return taint

    def _union(self, nodes) -> Taint:
        taint = EMPTY
        for n in nodes:
            taint |= self._expr(n)
        return taint

    def _call(self, node: ast.Call) -> Taint:
        call_name = _dotted(node.func) or ""
        short = call_name.split(".")[-1]
        arg_taints = [self._expr(a) for a in node.args]
        kw_taints = {kw.arg: self._expr(kw.value) for kw in node.keywords}
        receiver = self._expr(node.func.value) if isinstance(node.func, ast.Attribute) else EMPTY

        # 1) Sinks
        spec = _sink_for_call(call_name, node)
        if spec is not None:
            if spec.arg_index is None:
                dangerous = self._union_list(arg_taints) | self._union_list(kw_taints.values())
            else:
                dangerous = arg_taints[spec.arg_index] if len(arg_taints) > spec.arg_index else EMPTY
                if spec.keyword and spec.keyword in kw_taints:
                    dangerous |= kw_taints[spec.keyword]
            if dangerous:
                self._hit_sink(dangerous, call_name, node.lineno, spec, (self.fn.name,))

        # 2) Sources
        if call_name in SOURCE_CALLS or _is_source_name(call_name):
            return frozenset({Source(self.fn.file, node.lineno, call_name, self.fn.name)})

        # 3) Sanitizers
        if call_name in SANITIZERS or short in SANITIZERS or short.startswith(("validate_", "sanitize_", "clean_")):
            return EMPTY

        # 4) Calls into project functions -> apply summaries
        callees = self.engine.resolve_callees(self.fn.file, call_name)
        if callees:
            result = EMPTY
            for callee_q in callees:
                callee = self.engine.functions[callee_q]
                summary = self.engine.summaries.get(callee_q, Summary())
                bound = self._bind_args(callee, node, arg_taints, kw_taints, receiver)
                for origin in summary.returns:
                    if isinstance(origin, Param):
                        result |= bound.get(origin.index, EMPTY)
                    else:
                        result |= {origin}
                for ps in summary.param_sinks:
                    taint = bound.get(ps.index, EMPTY)
                    if taint:
                        self._hit_sink(taint, ps.sink_name, ps.sink_line, ps.spec, (self.fn.name,) + ps.chain, ps.sink_file)
            return result

        # 5) Unknown/library call: result derives from receiver and arguments
        if short in {"fetchone", "fetchall", "fetchmany", "cursor", "connect", "commit", "close"}:
            return EMPTY
        return receiver | self._union_list(arg_taints) | self._union_list(kw_taints.values())

    @staticmethod
    def _union_list(taints) -> Taint:
        out = EMPTY
        for t in taints:
            out |= t
        return out

    @staticmethod
    def _bind_args(callee: FunctionInfo, node: ast.Call, arg_taints, kw_taints, receiver) -> Dict[int, Taint]:
        bound: Dict[int, Taint] = {}
        offset = 0
        if callee.is_method and isinstance(node.func, ast.Attribute):
            bound[0] = receiver
            offset = 1
        for i, t in enumerate(arg_taints):
            idx = i + offset
            if idx < len(callee.params):
                bound[idx] = bound.get(idx, EMPTY) | t
            elif callee.params:  # *args collapse onto the last parameter
                last = len(callee.params) - 1
                bound[last] = bound.get(last, EMPTY) | t
        for name, t in kw_taints.items():
            if name in callee.params:
                idx = callee.params.index(name)
                bound[idx] = bound.get(idx, EMPTY) | t
        return bound

    def _hit_sink(self, taint: Taint, sink_name, sink_line, spec: SinkSpec, chain: Tuple[str, ...], sink_file=None):
        sink_file = sink_file or self.fn.file
        for origin in taint:
            if isinstance(origin, Param):
                self.param_sinks.add(ParamSink(origin.index, sink_name, sink_file, sink_line, spec, chain))
            elif self.collect:
                self.engine.record_finding(origin, sink_name, sink_file, sink_line, spec, chain)


# --------------------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------------------


class TaintEngine:
    SKIP_PARTS = {"venv", ".venv", "node_modules", "__pycache__", ".git", "site-packages", "tests", "test"}
    MAX_ROUNDS = 12

    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir)
        self.functions: Dict[str, FunctionInfo] = {}
        self.summaries: Dict[str, Summary] = {}
        self.call_graph: Dict[str, dict] = {}  # kept for introspection / debugging
        self._name_index: Dict[str, List[str]] = {}
        self._findings: Dict[tuple, TaintFinding] = {}
        self._lines: Dict[str, List[str]] = {}

    # ---------------- graph construction ----------------
    def build_graph(self):
        self.functions, self.summaries, self.call_graph, self._name_index = {}, {}, {}, {}
        for py_file in sorted(self.target_dir.rglob("*.py")):
            rel_parts = py_file.relative_to(self.target_dir).parts
            if any(part in self.SKIP_PARTS for part in rel_parts):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(py_file))
            except (SyntaxError, ValueError, OSError):
                continue
            self._lines[str(py_file)] = source.splitlines()
            self._register_module(str(py_file), tree)

        for qname, fn in self.functions.items():
            self.call_graph[qname] = {"name": fn.name, "file": fn.file, "calls": fn.calls}

    def _register_module(self, filepath: str, tree: ast.Module):
        module_body = [s for s in tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        if module_body:
            mod = ast.Module(body=module_body, type_ignores=[])
            mod.lineno = 1
            self._add_function(filepath, "<module>", mod, [], False, set())

        def walk(node, in_class: bool):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    walk(child, True)
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = child.args
                    params = [a.arg for a in args.posonlyargs + args.args]
                    if args.vararg:
                        params.append(args.vararg.arg)
                    params += [a.arg for a in args.kwonlyargs]
                    is_method = in_class and bool(params) and params[0] in {"self", "cls"}
                    self._add_function(filepath, child.name, child, params, is_method, self._route_params(child, params))
                    walk(child, False)
                else:
                    walk(child, in_class)

        walk(tree, False)

    @staticmethod
    def _route_params(node, params: List[str]) -> Set[str]:
        is_route = False
        for dec in node.decorator_list:
            name = _dotted(dec) or ""
            if name.endswith(ROUTE_DECORATOR_SUFFIXES):
                is_route = True
        if not is_route:
            return set()
        args = node.args
        all_args = args.posonlyargs + args.args
        defaults = [None] * (len(all_args) - len(args.defaults)) + list(args.defaults)
        result = set()
        for a, d in zip(all_args, defaults):
            if a.arg in NON_INPUT_PARAMS:
                continue
            if d is not None and "Depends" in (_dotted(d) or ""):
                continue
            result.add(a.arg)
        return result

    def _add_function(self, filepath, name, node, params, is_method, route_params):
        qname = f"{filepath}::{name}:{getattr(node, 'lineno', 0)}"
        calls = {(_dotted(n.func) or "") for n in ast.walk(node) if isinstance(n, ast.Call)}
        self.functions[qname] = FunctionInfo(qname, name, filepath, node, params, is_method, route_params, calls)
        if name != "<module>":
            self._name_index.setdefault(name, []).append(qname)

    def resolve_callees(self, caller_file: str, call_name: str) -> List[str]:
        if not call_name:
            return []
        short_name = call_name.split(".")[-1]
        candidates = self._name_index.get(short_name) or []
        if not candidates:
            return []
        same_file = [c for c in candidates if self.functions[c].file == caller_file]
        return same_file if same_file else candidates

    # ---------------- findings ----------------
    def _line(self, file: str, line: int) -> str:
        lines = self._lines.get(file, [])
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    def record_finding(self, source: Source, sink_name, sink_file, sink_line, spec: SinkSpec, chain: Tuple[str, ...]):
        key = (source.file, source.line, sink_file, sink_line)
        if key in self._findings:
            return
        labels: List[str] = []
        for label in (source.func,) + chain:
            if not labels or labels[-1] != label:
                labels.append(label)
        path = [f"{labels[0]}()"] + [f"-> {lbl}()" for lbl in labels[1:]]
        self._findings[key] = TaintFinding(
            source_file=source.file,
            source_line=source.line,
            sink_file=sink_file,
            sink_line=sink_line,
            taint_path=path,
            vulnerability_type="Tainted Data Flow",
            severity=spec.severity,
            code_snippets=[
                f"Source: {source.name} at line {source.line}: {self._line(source.file, source.line)}",
                f"Sink: {sink_name} at line {sink_line}: {self._line(sink_file, sink_line)}",
            ],
            source_name=source.name,
            sink_name=sink_name,
            sink_kind=spec.kind,
            cwe=list(spec.cwe),
        )

    # ---------------- driver ----------------
    def analyze(self) -> List[TaintFinding]:
        self.build_graph()
        self._findings = {}

        for _ in range(self.MAX_ROUNDS):
            changed = False
            for qname, fn in self.functions.items():
                new = _FunctionAnalyzer(self, fn, collect=False).run()
                old = self.summaries.get(qname)
                if old is None or old.key() != new.key():
                    self.summaries[qname] = new
                    changed = True
            if not changed:
                break

        for fn in self.functions.values():
            _FunctionAnalyzer(self, fn, collect=True).run()

        return sorted(self._findings.values(), key=lambda f: (f.sink_file, f.sink_line, f.source_line))
