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

SOURCES = {"request.args", "request.form", "request.json", "input", "sys.argv", "os.environ"}
SINKS = {"cursor.execute", "os.system", "subprocess.run", "eval", "exec", "open", "pickle.loads", "yaml.load"}
SANITIZERS = {"escape", "bleach.clean", "int", "validate"}

class ASTNodeVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.functions = {} # name -> {ast_node, calls, sources, sinks, sanitizers}
        self.current_func = None
        
    def visit_FunctionDef(self, node):
        prev_func = self.current_func
        self.current_func = node.name
        self.functions[node.name] = {
            "node": node,
            "calls": set(),
            "sources": [],
            "sinks": [],
            "sanitizers": set(),
            "file": self.filepath
        }
        self.generic_visit(node)
        self.current_func = prev_func

    def _get_call_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
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
        self.call_graph = {} # func_name -> {file, calls, sources, sinks, sanitizers}
        
    def build_graph(self):
        for py_file in self.target_dir.rglob("*.py"):
            if "venv" in str(py_file) or "node_modules" in str(py_file):
                continue
                
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=str(py_file))
                visitor = ASTNodeVisitor(str(py_file))
                visitor.visit(tree)
                self.call_graph.update(visitor.functions)
            except Exception:
                continue

    def analyze(self) -> List[TaintFinding]:
        self.build_graph()
        findings = []
        
        # Start BFS from any function containing a Source
        for func_name, data in self.call_graph.items():
            for source_name, src_line in data["sources"]:
                # If there is a sanitizer in the same function, we naively assume it's sanitized
                if data["sanitizers"]:
                    continue
                    
                # Queue for BFS: (current_func, path_so_far, visited)
                queue = deque([(func_name, [f"{func_name}()"], {func_name})])
                
                while queue:
                    curr_func, path, visited = queue.popleft()
                    curr_data = self.call_graph.get(curr_func)
                    if not curr_data: continue
                    
                    # Check if current function has a Sink
                    for sink_name, snk_line in curr_data["sinks"]:
                        findings.append(TaintFinding(
                            source_file=data["file"],
                            source_line=src_line,
                            sink_file=curr_data["file"],
                            sink_line=snk_line,
                            taint_path=path,
                            vulnerability_type="Tainted Data Flow",
                            severity="CRITICAL" if "execute" in sink_name or "system" in sink_name or "exec" in sink_name else "HIGH",
                            code_snippets=[f"Source: {source_name} at line {src_line}", f"Sink: {sink_name} at line {snk_line}"]
                        ))
                    
                    # Continue BFS via calls
                    for call in curr_data["calls"]:
                        if call in self.call_graph and call not in visited:
                            call_data = self.call_graph[call]
                            if not call_data["sanitizers"]:
                                queue.append((call, path + [f"-> {call}()"], visited | {call}))
                                
        return findings
