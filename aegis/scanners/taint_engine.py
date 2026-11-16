import ast
import os
from pathlib import Path
from typing import List, Dict, Set, Optional
from pydantic import BaseModel
from collections import deque

class TaintFinding(BaseModel):
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int
    taint_path: List[str]
    vulnerability_type: str
    severity: str
    code_snippets: List[str]

SOURCES = {
    "request.args",
    "request.form",
    "request.json",
    "request.query_params",
    "request.body",
    "input",
    "sys.argv",
    "os.environ",
}
SINKS = {"cursor.execute", "os.system", "subprocess.run", "subprocess.Popen", "eval", "exec", "open", "pickle.loads", "yaml.load"}
SANITIZERS = {"escape", "bleach.clean", "int", "validate", "html.escape"}


class ASTNodeVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.functions = {}  # qualified_key -> {name, node, calls, sources, sinks, sanitizers, file}
        self.current_func: Optional[str] = None

    def _visit_fn(self, node):
        prev_func = self.current_func
        qname = f"{self.filepath}::{node.name}"
        self.current_func = qname
        self.functions[qname] = {
            "name": node.name,
            "node": node,
            "calls": set(),
            "sources": [],
            "sinks": [],
            "sanitizers": set(),
            "file": self.filepath,
        }
        self.generic_visit(node)
        self.current_func = prev_func

    def visit_FunctionDef(self, node):
        self._visit_fn(node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_fn(node)

    def _get_call_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_call_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return None

    def visit_Call(self, node):
        call_name = self._get_call_name(node.func)
        if call_name and self.current_func:
            self.functions[self.current_func]["calls"].add(call_name)

            if call_name in SOURCES or any(call_name.startswith(s) for s in SOURCES):
                self.functions[self.current_func]["sources"].append((call_name, node.lineno))
            elif call_name in SINKS:
                self.functions[self.current_func]["sinks"].append((call_name, node.lineno))
            elif call_name in SANITIZERS:
                self.functions[self.current_func]["sanitizers"].add(call_name)

        self.generic_visit(node)


class TaintEngine:
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir)
        self.call_graph = {}  # qualified_key -> {name, file, calls, sources, sinks, sanitizers}
        self._name_index: Dict[str, List[str]] = {}

    def build_graph(self):
        self.call_graph = {}
        self._name_index = {}
        skip_parts = {"venv", ".venv", "node_modules", "__pycache__", ".git", "site-packages"}
        for py_file in self.target_dir.rglob("*.py"):
            if any(part in skip_parts for part in py_file.parts):
                continue

            try:
                with open(py_file, "r", encoding="utf-8", errors="replace") as f:
                    tree = ast.parse(f.read(), filename=str(py_file))
                visitor = ASTNodeVisitor(str(py_file))
                visitor.visit(tree)
                for qname, meta in visitor.functions.items():
                    self.call_graph[qname] = meta
                    self._name_index.setdefault(meta["name"], []).append(qname)
            except Exception:
                continue

    def _resolve_callees(self, caller_file: str, call_name: str) -> List[str]:
        short_name = call_name.split(".")[-1]
        candidates = self._name_index.get(call_name) or self._name_index.get(short_name) or []
        if not candidates:
            return []
        same_file = [c for c in candidates if self.call_graph[c]["file"] == caller_file]
        return same_file if same_file else candidates

    def analyze(self) -> List[TaintFinding]:
        self.build_graph()
        findings = []

        # Start BFS from any function containing a Source
        for func_key, data in self.call_graph.items():
            func_label = data["name"]
            for source_name, src_line in data["sources"]:
                if data["sanitizers"]:
                    continue

                queue = deque([(func_key, [f"{func_label}()"], {func_key})])

                while queue:
                    curr_key, path, visited = queue.popleft()
                    curr_data = self.call_graph.get(curr_key)
                    if not curr_data:
                        continue

                    for sink_name, snk_line in curr_data["sinks"]:
                        findings.append(TaintFinding(
                            source_file=data["file"],
                            source_line=src_line,
                            sink_file=curr_data["file"],
                            sink_line=snk_line,
                            taint_path=path,
                            vulnerability_type="Tainted Data Flow",
                            severity="CRITICAL" if "execute" in sink_name or "system" in sink_name or "exec" in sink_name else "HIGH",
                            code_snippets=[f"Source: {source_name} at line {src_line}", f"Sink: {sink_name} at line {snk_line}"],
                        ))

                    for call in curr_data["calls"]:
                        for target_key in self._resolve_callees(curr_data["file"], call):
                            if target_key not in visited:
                                call_data = self.call_graph[target_key]
                                if not call_data["sanitizers"]:
                                    target_label = call_data["name"]
                                    queue.append((target_key, path + [f"-> {target_label}()"], visited | {target_key}))

        return findings
