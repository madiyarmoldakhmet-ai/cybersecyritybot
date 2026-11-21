import logging
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import uuid
import httpx

from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("aegis.sca_scanner")

_REQ_SPEC_RE = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s,;]+)?")


class SCAScanner:
    """
    Software Composition Analysis (SCA) Scanner.
    Parses package.json and requirements.txt to find vulnerable dependencies using OSV API.
    """

    OSV_API_URL = "https://api.osv.dev/v1/querybatch"

    async def scan(self, target_dir: Path) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        target_path = Path(target_dir).resolve()

        if not target_path.exists():
            return findings

        package_json_path = target_path / "package.json"
        if package_json_path.exists():
            findings.extend(await self._scan_npm(package_json_path, target_path))

        req_txt_path = target_path / "requirements.txt"
        if req_txt_path.exists():
            findings.extend(await self._scan_pypi(req_txt_path, target_path))

        return findings

    async def _scan_npm(self, file_path: Path, target_dir: Path) -> List[VulnerabilityFinding]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
            deps = data.get("dependencies") if isinstance(data.get("dependencies"), dict) else {}
            dev_deps = data.get("devDependencies") if isinstance(data.get("devDependencies"), dict) else {}
            all_deps = {**dev_deps, **deps}
            if not all_deps:
                return findings

            # Resolve real line numbers inside package.json instead of hardcoding line 1
            pkg_lines: Dict[str, int] = {}
            for idx, raw_line in enumerate(content.splitlines(), start=1):
                m = re.search(r'"([^"]+)"\s*:', raw_line)
                if m and m.group(1) in all_deps and m.group(1) not in pkg_lines:
                    pkg_lines[m.group(1)] = idx

            clean_deps: Dict[str, Tuple[str, int]] = {}
            for name, version in all_deps.items():
                clean_v = str(version).lstrip("^~><=")
                if clean_v and "*" not in clean_v and clean_v[0].isdigit():
                    clean_deps[name] = (clean_v, pkg_lines.get(name, 1))

            dev_only = {name for name in dev_deps if name not in deps}
            findings = await self._query_osv_batch(
                clean_deps,
                "npm",
                file_path.relative_to(target_dir).as_posix(),
                dev_only_packages=dev_only,
            )
        except Exception as e:
            logger.error(f"Failed to scan package.json: {e}")
        return findings

    async def _scan_pypi(self, file_path: Path, target_dir: Path) -> List[VulnerabilityFinding]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            deps: Dict[str, Tuple[str, int]] = {}
            for line_num, raw_line in enumerate(content.splitlines(), start=1):
                line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                match = _REQ_SPEC_RE.match(line)
                if not match:
                    continue
                pkg_name, op, raw_ver = match.group(1), match.group(2), match.group(3)
                if op in ("==", ">=", "~=") and raw_ver:
                    version = raw_ver.split(",", 1)[0].strip()
                    if version and version[0].isdigit():
                        deps[pkg_name] = (version, line_num)

            if deps:
                findings = await self._query_osv_batch(
                    deps, "PyPI", file_path.relative_to(target_dir).as_posix()
                )
        except Exception as e:
            logger.error(f"Failed to scan requirements.txt: {e}")
        return findings

    async def _query_osv_batch(
        self,
        packages: Dict[str, Tuple[str, int]],
        ecosystem: str,
        file_rel_path: str,
        dev_only_packages: Optional[set] = None,
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        dev_set = dev_only_packages or set()
        queries = []
        line_map: List[int] = []
        for name, (version, line_num) in packages.items():
            queries.append({"package": {"name": name, "ecosystem": ecosystem}, "version": version})
            line_map.append(line_num)

        if not queries:
            return findings

        batch_size = 1000
        for i in range(0, len(queries), batch_size):
            batch = queries[i : i + batch_size]
            batch_lines = line_map[i : i + batch_size]
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(self.OSV_API_URL, json={"queries": batch})
                    if resp.status_code == 200:
                        results = resp.json().get("results", [])
                        for idx, result in enumerate(results):
                            if "vulns" in result:
                                pkg = batch[idx]["package"]["name"]
                                ver = batch[idx]["version"]
                                line_num = batch_lines[idx]
                                is_dev = pkg in dev_set
                                for vuln in result["vulns"]:
                                    finding = self._parse_osv_vuln(
                                        vuln, pkg, ver, file_rel_path, line_num, is_dev_only=is_dev
                                    )
                                    if finding:
                                        findings.append(finding)
                    else:
                        logger.error(f"OSV API error: {resp.status_code} - {resp.text}")
            except Exception as e:
                logger.error(f"Failed to query OSV API: {e}")

        unique_findings = {f.id: f for f in findings}
        return list(unique_findings.values())

    def _parse_osv_vuln(
        self,
        vuln: Dict,
        pkg_name: str,
        pkg_version: str,
        file_path: str,
        line_start: int = 1,
        is_dev_only: bool = False,
    ) -> Optional[VulnerabilityFinding]:
        vuln_id = vuln.get("id", str(uuid.uuid4()))
        summary = vuln.get("summary", f"Vulnerability in {pkg_name}")
        details = vuln.get("details", "No details provided by OSV.")
        aliases = vuln.get("aliases", [])
        cves = [a for a in aliases if a.startswith("CVE-")]
        severity = Severity.INFO if is_dev_only else (Severity.HIGH if cves else Severity.MEDIUM)
        title = f"[devDependency] {summary}" if is_dev_only else summary
        scope_note = (
            f"Dev-only build/test package `{pkg_name}` (v{pkg_version}) in `devDependencies` "
            f"(not shipped in production client bundle).\n\n{details}"
            if is_dev_only
            else f"Package `{pkg_name}` (v{pkg_version}) is vulnerable.\n\n{details}"
        )
        code_snippet = f'"{pkg_name}": "{pkg_version}"'

        return VulnerabilityFinding(
            id=f"sca-{vuln_id.lower()}",
            scanner=ScannerType.SCA,
            title=title,
            description=scope_note,
            severity=severity,
            file_path=file_path,
            line_start=line_start,
            code_snippet=code_snippet,
            cve=cves,
            recommendation="Update the package to a non-vulnerable version.",
            raw_metadata={
                "osv_id": vuln_id,
                "dependency_scope": "devDependencies" if is_dev_only else "dependencies",
            },
        )
