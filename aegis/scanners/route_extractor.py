"""
Route and Attack Surface Extractor for Aegis.
Statically discovers API endpoints, methods, parameters, and authentication decorators
across Python (FastAPI, Flask, Django), JavaScript/TypeScript (Express, NestJS, Next.js), and Go.
"""

import ast
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("aegis.route_extractor")

# Files and directories to ignore during route discovery
IGNORE_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__",
    "build", "dist", ".dart_tool", ".idea", ".vscode", "temp_scans"
}


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered HTTP endpoint in the target repository."""
    path: str
    method: str  # GET, POST, PUT, DELETE, PATCH, etc.
    file_path: str
    line_number: int
    framework: str  # fastapi, flask, django, express, nestjs, nextjs, unknown
    parameters: List[str] = field(default_factory=list)
    has_auth_guard: bool = False
    auth_detail: Optional[str] = None
    sensitive_operations: List[str] = field(default_factory=list)  # e.g., ["raw_sql", "shell_exec", "file_io"]
    code_snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method.upper(),
            "file_path": self.file_path,
            "line_number": self.line_number,
            "framework": self.framework,
            "parameters": self.parameters,
            "has_auth_guard": self.has_auth_guard,
            "auth_detail": self.auth_detail,
            "sensitive_operations": self.sensitive_operations,
        }


class RouteExtractor:
    """Scans codebases to construct an Attack Surface & Endpoint Map."""

    # Common authentication keywords in decorators, middlewares, or parameter dependencies
    AUTH_KEYWORDS = {
        "auth", "login_required", "authenticate", "jwt", "bearer", "token",
        "permission", "authorize", "get_current_user", "require_user",
        "is_authenticated", "has_role", "admin_required", "guard", "useguards"
    }

    # Dangerous patterns within handler functions
    DANGEROUS_OPERATIONS = [
        (re.compile(r"(cursor\.execute|execute_query|\.raw\(|session\.execute)\s*\("), "raw_sql"),
        (re.compile(r"(subprocess\.(Popen|run|call|check_output)|os\.system|os\.popen|exec\(|eval\()\s*"), "shell_exec"),
        (re.compile(r"(open\(|fs\.read|fs\.write|res\.sendFile|send_file|send_from_directory)\s*\("), "file_io"),
        (re.compile(r"(requests\.(get|post|put)|httpx\.(get|post)|fetch\(|axios\.(get|post))\s*\("), "outbound_http_ssrf"),
        (re.compile(r"(pickle\.loads?|yaml\.load\(|unserialize)\s*\("), "deserialization"),
    ]

    def scan_repository(self, repo_dir: Path) -> List[DiscoveredEndpoint]:
        """Discover all exposed routes and endpoints across the repository."""
        endpoints: List[DiscoveredEndpoint] = []
        target_path = Path(repo_dir).resolve()

        if not target_path.exists():
            return endpoints

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]

            for file in sorted(files):
                file_path = Path(root) / file
                rel_path = file_path.relative_to(target_path).as_posix()
                ext = file_path.suffix.lower()

                try:
                    if ext == ".py":
                        endpoints.extend(self._scan_python_file(file_path, rel_path))
                    elif ext in {".js", ".ts", ".jsx", ".tsx"}:
                        endpoints.extend(self._scan_javascript_file(file_path, rel_path))
                    elif file.endswith(("swagger.json", "openapi.yaml", "openapi.json")):
                        endpoints.extend(self._scan_openapi_file(file_path, rel_path))
                except Exception as ex:
                    logger.debug(f"Failed to extract routes from {rel_path}: {ex}")

        logger.info(f"Discovered {len(endpoints)} API endpoints in {repo_dir.name}")
        return endpoints

    # ---- Python Route Extraction --------------------------------------------

    def _scan_python_file(self, file_path: Path, rel_path: str) -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=rel_path)
        except Exception:
            return self._regex_fallback_python(file_path, rel_path)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Inspect decorators for Flask / FastAPI / Django
                for decorator in node.decorator_list:
                    dec_info = self._parse_python_decorator(decorator)
                    if dec_info:
                        path, method, framework, has_auth, auth_detail = dec_info

                        # Extract function parameters
                        params = [arg.arg for arg in node.args.args if arg.arg not in {"self", "cls", "request"}]

                        # Check for auth inside function arguments (e.g. Depends(get_current_user))
                        if not has_auth:
                            for default in node.args.defaults:
                                default_str = ast.unparse(default).lower() if hasattr(ast, "unparse") else ""
                                if any(ak in default_str for ak in self.AUTH_KEYWORDS):
                                    has_auth = True
                                    auth_detail = default_str[:50]
                                    break

                        # Extract sensitive operations within function body
                        func_code = ast.get_source_segment(content, node) if hasattr(ast, "get_source_segment") else ""
                        sensitive_ops = self._detect_sensitive_ops(func_code or content)

                        endpoints.append(
                            DiscoveredEndpoint(
                                path=path,
                                method=method,
                                file_path=rel_path,
                                line_number=node.lineno,
                                framework=framework,
                                parameters=params,
                                has_auth_guard=has_auth,
                                auth_detail=auth_detail,
                                sensitive_operations=sensitive_ops,
                                code_snippet=(func_code or "")[:400]
                            )
                        )

        # Fallback to regex if AST missed unconventional routers
        if not endpoints:
            endpoints.extend(self._regex_fallback_python(file_path, rel_path))

        return endpoints

    def _parse_python_decorator(self, decorator: ast.AST) -> Optional[tuple]:
        """Parse decorator node to determine path, method, framework and auth guard."""
        # Case: @app.get("/users"), @router.post("/items"), @app.route("/login", methods=["POST"])
        if isinstance(decorator, ast.Call):
            func = decorator.func
            if isinstance(func, ast.Attribute):
                attr_name = func.attr.lower()  # 'get', 'post', 'route', 'api_route', etc.
                
                # Extract path (first positional argument or keyword 'rule'/'path')
                path = "/"
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    path = str(decorator.args[0].value)

                # Framework and method detection
                framework = "fastapi"
                method = "GET"

                if attr_name in {"get", "post", "put", "delete", "patch", "options", "head"}:
                    method = attr_name.upper()
                    framework = "fastapi"
                elif attr_name == "route":
                    framework = "flask"
                    method = "GET"
                    # Check methods keyword argument: methods=['POST', 'GET']
                    for kw in decorator.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            methods_found = [
                                elt.value for elt in kw.value.elts if isinstance(elt, ast.Constant)
                            ]
                            if methods_found:
                                method = methods_found[0].upper()

                # Check for auth decorators or keywords
                has_auth = False
                auth_detail = None
                for kw in decorator.keywords:
                    if any(ak in str(kw.arg).lower() for ak in self.AUTH_KEYWORDS):
                        has_auth = True
                        auth_detail = f"param:{kw.arg}"

                return (path, method, framework, has_auth, auth_detail)

        return None

    def _regex_fallback_python(self, file_path: Path, rel_path: str) -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return endpoints

        # FastAPI / Flask regex
        route_pattern = re.compile(
            r'@(?:app|router|bp|api)\.(get|post|put|delete|patch|route)\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        for match in route_pattern.finditer(content):
            method = match.group(1).upper()
            if method == "ROUTE":
                method = "GET"
            path = match.group(2)
            line_no = content[:match.start()].count("\n") + 1
            has_auth = any(ak in content[max(0, match.start() - 200):match.end() + 200].lower() for ak in self.AUTH_KEYWORDS)
            sensitive_ops = self._detect_sensitive_ops(content[match.start():match.start() + 500])

            endpoints.append(
                DiscoveredEndpoint(
                    path=path,
                    method=method,
                    file_path=rel_path,
                    line_number=line_no,
                    framework="python",
                    has_auth_guard=has_auth,
                    sensitive_operations=sensitive_ops
                )
            )

        return endpoints

    # ---- JavaScript / TypeScript Route Extraction ---------------------------

    def _scan_javascript_file(self, file_path: Path, rel_path: str) -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return endpoints

        # 1. Express / Fastify style: app.get('/users', ...), router.post('/login', ...)
        express_pattern = re.compile(
            r'\b(?:app|router|api|server)\.(get|post|put|delete|patch)\s*\(\s*["\'`]([^"\'`]+)["\'`]',
            re.IGNORECASE
        )
        for match in express_pattern.finditer(content):
            method = match.group(1).upper()
            path = match.group(2)
            line_no = content[:match.start()].count("\n") + 1
            surrounding = content[max(0, match.start() - 100):min(len(content), match.end() + 400)]
            has_auth = any(ak in surrounding.lower() for ak in self.AUTH_KEYWORDS)
            sensitive_ops = self._detect_sensitive_ops(surrounding)

            endpoints.append(
                DiscoveredEndpoint(
                    path=path,
                    method=method,
                    file_path=rel_path,
                    line_number=line_no,
                    framework="express",
                    has_auth_guard=has_auth,
                    sensitive_operations=sensitive_ops
                )
            )

        # 2. Next.js App Router API Routes: export async function GET(req), etc.
        if "api/" in rel_path or "route." in rel_path:
            nextjs_methods = re.findall(r'export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(', content)
            for m in nextjs_methods:
                # Derive path from file path (e.g. app/api/auth/route.ts -> /api/auth)
                inferred_path = "/" + rel_path.replace("app/", "").replace("pages/", "").replace("/route.ts", "").replace("/route.js", "")
                has_auth = any(ak in content.lower() for ak in self.AUTH_KEYWORDS)
                sensitive_ops = self._detect_sensitive_ops(content)

                endpoints.append(
                    DiscoveredEndpoint(
                        path=inferred_path,
                        method=m.upper(),
                        file_path=rel_path,
                        line_number=1,
                        framework="nextjs",
                        has_auth_guard=has_auth,
                        sensitive_operations=sensitive_ops
                    )
                )

        return endpoints

    # ---- OpenAPI / Swagger Extraction ---------------------------------------

    def _scan_openapi_file(self, file_path: Path, rel_path: str) -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            # Parse YAML or JSON (fallback to basic JSON if PyYAML not present, but we try json first)
            import json
            import yaml
            
            data = None
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                data = yaml.safe_load(content)

            if not isinstance(data, dict):
                return endpoints

            paths = data.get("paths", {})
            for path, path_obj in paths.items():
                if not isinstance(path_obj, dict):
                    continue
                for method, op_obj in path_obj.items():
                    if method.lower() not in {"get", "post", "put", "delete", "patch"}:
                        continue
                        
                    has_auth = "security" in op_obj or "security" in data
                    
                    endpoints.append(
                        DiscoveredEndpoint(
                            path=path,
                            method=method.upper(),
                            file_path=rel_path,
                            line_number=1,
                            framework="openapi",
                            has_auth_guard=has_auth,
                            sensitive_operations=["openapi_schema_extracted"]
                        )
                    )

        except Exception as e:
            logger.debug(f"Failed to parse OpenAPI file {rel_path}: {e}")

        return endpoints

    # ---- Helpers ------------------------------------------------------------

    def _detect_sensitive_ops(self, code_block: str) -> List[str]:
        """Detect dangerous internal operations like raw SQL, subprocess, or file access."""
        ops: Set[str] = set()
        for pattern, op_name in self.DANGEROUS_OPERATIONS:
            if pattern.search(code_block):
                ops.add(op_name)
        return sorted(list(ops))

    def format_attack_surface_summary(self, endpoints: List[DiscoveredEndpoint]) -> str:
        """Render a concise markdown table and summary of the attack surface for Aegis Agents."""
        if not endpoints:
            return "No public HTTP endpoints detected in repository."

        lines = [
            f"### Attack Surface Map ({len(endpoints)} endpoints discovered)",
            "| Method | Path | Auth Guard | Sensitive Sinks | File Location |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ]

        for ep in endpoints[:30]:  # Limit top 30 endpoints for prompt context
            auth_str = "🛡️ Protected" if ep.has_auth_guard else "⚠️ Public / Open"
            sinks_str = ", ".join(ep.sensitive_operations) if ep.sensitive_operations else "-"
            lines.append(f"| `{ep.method}` | `{ep.path}` | {auth_str} | `{sinks_str}` | `{ep.file_path}:{ep.line_number}` |")

        if len(endpoints) > 30:
            lines.append(f"\n*...и еще {len(endpoints) - 30} эндпоинтов.*")

        return "\n".join(lines)
