import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
import httpx

from strix.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
import uuid

logger = logging.getLogger("cybersecuritybot.sca_scanner")

class SCAScanner:
    """
    Software Composition Analysis (SCA) Scanner.
    Parses package.json and requirements.txt to find vulnerable dependencies using OSV API.
    """

    OSV_API_URL = "https://api.osv.dev/v1/querybatch"

    def __init__(self):
        pass

    async def scan(self, target_dir: Path) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        target_path = Path(target_dir).resolve()
        
        if not target_path.exists():
            return findings

        package_json_path = target_path / "package.json"
        if package_json_path.exists():
            npm_findings = await self._scan_npm(package_json_path, target_path)
            findings.extend(npm_findings)

        req_txt_path = target_path / "requirements.txt"
        if req_txt_path.exists():
            pypi_findings = await self._scan_pypi(req_txt_path, target_path)
            findings.extend(pypi_findings)

        return findings

    async def _scan_npm(self, file_path: Path, target_dir: Path) -> List[VulnerabilityFinding]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            
            all_deps = {**deps, **dev_deps}
            
            if not all_deps:
                return findings
            
            clean_deps = {}
            for name, version in all_deps.items():
                clean_v = version.lstrip('^~><=')
                if clean_v and '*' not in clean_v:
                    clean_deps[name] = clean_v

            findings = await self._query_osv_batch(clean_deps, "npm", file_path.relative_to(target_dir).as_posix())
            
        except Exception as e:
            logger.error(f"Failed to scan package.json: {e}")
            
        return findings

    async def _scan_pypi(self, file_path: Path, target_dir: Path) -> List[VulnerabilityFinding]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            deps = {}
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '==' in line:
                    parts = line.split('==')
                    deps[parts[0].strip()] = parts[1].strip()
                elif '>=' in line:
                    parts = line.split('>=')
                    deps[parts[0].strip()] = parts[1].strip()
                    
            if deps:
                findings = await self._query_osv_batch(deps, "PyPI", file_path.relative_to(target_dir).as_posix())
                
        except Exception as e:
            logger.error(f"Failed to scan requirements.txt: {e}")
            
        return findings

    async def _query_osv_batch(self, packages: Dict[str, str], ecosystem: str, file_rel_path: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        
        queries = []
        for name, version in packages.items():
            queries.append({
                "package": {"name": name, "ecosystem": ecosystem},
                "version": version
            })
            
        if not queries:
            return findings

        batch_size = 1000
        for i in range(0, len(queries), batch_size):
            batch = queries[i:i+batch_size]
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(
                        self.OSV_API_URL, 
                        json={"queries": batch}
                    )
                    
                    if resp.status_code == 200:
                        results = resp.json().get("results", [])
                        for idx, result in enumerate(results):
                            if "vulns" in result:
                                pkg = batch[idx]["package"]["name"]
                                ver = batch[idx]["version"]
                                for vuln in result["vulns"]:
                                    finding = self._parse_osv_vuln(vuln, pkg, ver, file_rel_path)
                                    if finding:
                                        findings.append(finding)
                    else:
                        logger.error(f"OSV API error: {resp.status_code} - {resp.text}")
            except Exception as e:
                logger.error(f"Failed to query OSV API: {e}")
                
        unique_findings = {f.id: f for f in findings}
        return list(unique_findings.values())

    def _parse_osv_vuln(self, vuln: Dict, pkg_name: str, pkg_version: str, file_path: str) -> Optional[VulnerabilityFinding]:
        vuln_id = vuln.get("id", str(uuid.uuid4()))
        summary = vuln.get("summary", f"Vulnerability in {pkg_name}")
        details = vuln.get("details", "No details provided by OSV.")
        
        aliases = vuln.get("aliases", [])
        cves = [a for a in aliases if a.startswith("CVE-")]
        
        severity = Severity.HIGH if cves else Severity.MEDIUM
            
        code_snippet = f'"{pkg_name}": "{pkg_version}"'

        return VulnerabilityFinding(
            id=f"sca-{vuln_id.lower()}",
            scanner=ScannerType.SCA,
            title=summary,
            description=f"Package `{pkg_name}` (v{pkg_version}) is vulnerable.\n\n{details}",
            severity=severity,
            file_path=file_path,
            line_start=1,
            code_snippet=code_snippet,
            cve=cves,
            recommendation="Update the package to a non-vulnerable version.",
            raw_metadata={"osv_id": vuln_id}
        )
