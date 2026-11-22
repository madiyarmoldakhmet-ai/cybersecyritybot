"""
Software Composition Analysis (SCA) Scanner.

Discovers manifests across root and monorepo subprojects (`package.json`,
`package-lock.json`, `requirements.txt`, `pyproject.toml`), queries OSV.dev in batch,
falls back to a curated offline high-impact CVE advisory table (for air-gapped /
unreachable OSV environments), and optionally runs `npm audit --json` when a lockfile
is present.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import httpx

from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding

logger = logging.getLogger("aegis.sca_scanner")

_REQ_SPEC_RE = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s,;]+)?")
_IGNORED_SCA_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", ".venv", "venv", "__pycache__",
    "dist", "build", "out", ".turbo", ".cache", "coverage", "vendor",
}

# Offline fallback advisories for critical real-world JS/TS/Next.js/Python packages
# Format: (package_name, ecosystem, max_vulnerable_tuple_exclusive, cve, severity, title, recommendation)
_OFFLINE_ADVISORIES: Tuple[Tuple[str, str, Tuple[int, int, int], str, Severity, str, str], ...] = (
    (
        "next",
        "npm",
        (14, 2, 25),
        "CVE-2025-29927",
        Severity.CRITICAL,
        "Next.js Middleware Authorization Bypass (x-middleware-subrequest)",
        "Upgrade `next` to >=14.2.25 (or >=15.2.3 on Next 15) and never rely solely on middleware for auth.",
    ),
    (
        "next",
        "npm",
        (14, 1, 1),
        "CVE-2024-34351",
        Severity.HIGH,
        "Next.js Server Actions SSRF via Host Header",
        "Upgrade `next` to >=14.1.1.",
    ),
    (
        "lodash",
        "npm",
        (4, 17, 21),
        "CVE-2021-23337",
        Severity.HIGH,
        "Lodash Command Injection / Prototype Pollution",
        "Upgrade `lodash` to >=4.17.21.",
    ),
    (
        "jsonwebtoken",
        "npm",
        (9, 0, 0),
        "CVE-2022-23529",
        Severity.HIGH,
        "jsonwebtoken Insecure Secret Key Verification",
        "Upgrade `jsonwebtoken` to >=9.0.0.",
    ),
    (
        "axios",
        "npm",
        (1, 7, 4),
        "CVE-2024-39338",
        Severity.HIGH,
        "Axios Server-Side Request Forgery (SSRF) on Unexpected URL Protocols",
        "Upgrade `axios` to >=1.7.4.",
    ),
    (
        "express",
        "npm",
        (4, 19, 2),
        "CVE-2024-29041",
        Severity.MEDIUM,
        "Express Open Redirect via Malformed URL",
        "Upgrade `express` to >=4.19.2.",
    ),
    (
        "minimist",
        "npm",
        (1, 2, 6),
        "CVE-2021-44906",
        Severity.CRITICAL,
        "Minimist Prototype Pollution",
        "Upgrade `minimist` to >=1.2.6.",
    ),
    (
        "serialize-javascript",
        "npm",
        (6, 0, 2),
        "CVE-2020-7660",
        Severity.HIGH,
        "serialize-javascript Arbitrary Code Execution / XSS",
        "Upgrade `serialize-javascript` to >=6.0.2.",
    ),
    (
        "ws",
        "npm",
        (8, 17, 1),
        "CVE-2024-37890",
        Severity.HIGH,
        "ws Denial of Service via Excess HTTP Headers",
        "Upgrade `ws` to >=8.17.1.",
    ),
    (
        "pyyaml",
        "PyPI",
        (5, 4, 0),
        "CVE-2020-14343",
        Severity.CRITICAL,
        "PyYAML Arbitrary Code Execution via yaml.load",
        "Upgrade `PyYAML` to >=6.0.1 and use `yaml.safe_load`.",
    ),
    (
        "django",
        "PyPI",
        (4, 2, 16),
        "CVE-2024-45231",
        Severity.HIGH,
        "Outdated Django with Known Security Advisories",
        "Upgrade `django` to the latest supported LTS patch release.",
    ),
    (
        "cryptography",
        "PyPI",
        (42, 0, 4),
        "CVE-2024-26130",
        Severity.HIGH,
        "cryptography NULL Pointer Dereference / PKCS12 Vulnerability",
        "Upgrade `cryptography` to >=42.0.4.",
    ),
)


def _parse_semver(version: str) -> Optional[Tuple[int, int, int]]:
    """Extract numeric (major, minor, patch) from a version string like '^14.1.0'."""
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


class SCAScanner:
    """
    Software Composition Analysis (SCA) Scanner.
    Parses package.json, package-lock.json, requirements.txt, and pyproject.toml across
    monorepo subprojects using OSV Batch API, offline critical CVE advisories, and npm audit.
    """

    OSV_API_URL = "https://api.osv.dev/v1/querybatch"

    def _discover_manifests(self, target_path: Path, max_depth: int = 3) -> Dict[str, List[Path]]:
        found: Dict[str, List[Path]] = {
            "package.json": [],
            "package-lock.json": [],
            "requirements.txt": [],
            "pyproject.toml": [],
        }
        base_depth = len(target_path.parts)
        for root, dirs, files in os.walk(target_path):
            cur = Path(root)
            depth = len(cur.parts) - base_depth
            if depth >= max_depth:
                dirs[:] = []
            else:
                dirs[:] = [d for d in dirs if d not in _IGNORED_SCA_DIRS and not d.startswith(".")]
            for name in files:
                if name in found:
                    found[name].append(cur / name)
        return found

    async def scan(self, target_dir: Path) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        target_path = Path(target_dir).resolve()

        if not target_path.exists():
            return findings

        manifests = self._discover_manifests(target_path)

        tasks = []
        for pkg_json in manifests["package.json"][:6]:
            tasks.append(self._scan_npm(pkg_json, target_path))
        for lock_file in manifests["package-lock.json"][:3]:
            tasks.append(self._scan_npm_lockfile(lock_file, target_path))
        for req_txt in manifests["requirements.txt"][:6]:
            tasks.append(self._scan_pypi(req_txt, target_path))
        for pyproject in manifests["pyproject.toml"][:4]:
            tasks.append(self._scan_pyproject(pyproject, target_path))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    findings.extend(res)

        # Deduplicate by (id, file_path) so root + subproject findings stay distinct
        unique: Dict[Tuple[str, str], VulnerabilityFinding] = {}
        for f in findings:
            key = (f.id, f.file_path)
            if key not in unique:
                unique[key] = f
        return list(unique.values())

    async def _scan_npm(self, file_path: Path, target_dir: Path) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
            deps = data.get("dependencies") if isinstance(data.get("dependencies"), dict) else {}
            dev_deps = data.get("devDependencies") if isinstance(data.get("devDependencies"), dict) else {}
            all_deps = {**dev_deps, **deps}
            if not all_deps:
                return findings

            pkg_lines: Dict[str, int] = {}
            for idx, raw_line in enumerate(content.splitlines(), start=1):
                m = re.search(r'"([^"]+)"\s*:', raw_line)
                if m and m.group(1) in all_deps and m.group(1) not in pkg_lines:
                    pkg_lines[m.group(1)] = idx

            clean_deps: Dict[str, Tuple[str, int]] = {}
            for name, version in all_deps.items():
                clean_v = str(version).lstrip("^~><= ")
                if clean_v and "*" not in clean_v and clean_v[0].isdigit():
                    clean_deps[name] = (clean_v, pkg_lines.get(name, 1))

            dev_only = {name for name in dev_deps if name not in deps}
            rel_path = file_path.relative_to(target_dir).as_posix()

            # 1. Always evaluate offline high-impact advisories first (works air-gapped!)
            findings.extend(self._check_offline_advisories(clean_deps, "npm", rel_path, dev_only_packages=dev_only))

            # 2. Query OSV.dev batch API for full CVE coverage
            osv_findings = await self._query_osv_batch(
                clean_deps,
                "npm",
                rel_path,
                dev_only_packages=dev_only,
            )
            findings.extend(osv_findings)
        except Exception as e:
            logger.error(f"Failed to scan {file_path.name}: {e}")
        return findings

    async def _scan_npm_lockfile(self, lock_path: Path, target_dir: Path) -> List[VulnerabilityFinding]:
        """Parse package-lock.json resolved transitive versions & optionally invoke `npm audit --json`."""
        findings: List[VulnerabilityFinding] = []
        rel_path = lock_path.relative_to(target_dir).as_posix()
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8", errors="replace"))
            resolved: Dict[str, Tuple[str, int]] = {}
            dev_only: Set[str] = set()

            # npm lockfile v2/v3 `packages` map
            packages_map = data.get("packages")
            if isinstance(packages_map, dict):
                for pkg_key, meta in packages_map.items():
                    if not pkg_key or not isinstance(meta, dict):
                        continue
                    name = pkg_key.rsplit("node_modules/", 1)[-1]
                    ver = str(meta.get("version") or "").strip()
                    if name and ver and ver[0].isdigit() and name not in resolved:
                        resolved[name] = (ver, 1)
                        if meta.get("dev"):
                            dev_only.add(name)

            # npm lockfile v1 `dependencies` map
            deps_map = data.get("dependencies")
            if not resolved and isinstance(deps_map, dict):
                for name, meta in deps_map.items():
                    if not isinstance(meta, dict):
                        continue
                    ver = str(meta.get("version") or "").strip()
                    if ver and ver[0].isdigit():
                        resolved[name] = (ver, 1)
                        if meta.get("dev"):
                            dev_only.add(name)

            # Cap transitive OSV query to first 250 packages for speed
            capped = dict(list(resolved.items())[:250])
            if capped:
                findings.extend(self._check_offline_advisories(capped, "npm", rel_path, dev_only_packages=dev_only))
                findings.extend(await self._query_osv_batch(capped, "npm", rel_path, dev_only_packages=dev_only))

            # Optional native `npm audit --json --package-lock-only` when npm is installed
            npm_bin = shutil.which("npm")
            if npm_bin and (lock_path.parent / "package.json").exists():
                findings.extend(await self._run_npm_audit(npm_bin, lock_path.parent, rel_path))
        except Exception as exc:
            logger.debug(f"Lockfile scan skipped for {rel_path}: {exc}")
        return findings

    async def _run_npm_audit(self, npm_bin: str, cwd: Path, rel_lock_path: str) -> List[VulnerabilityFinding]:
        """Run `npm audit --json --package-lock-only` with a tight 8s timeout (non-fatal on offline hosts)."""
        findings: List[VulnerabilityFinding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                npm_bin,
                "audit",
                "--json",
                "--package-lock-only",
                cwd=str(cwd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8.0)
            if not stdout:
                return findings
            payload = json.loads(stdout.decode("utf-8", errors="replace"))
            vulns = payload.get("vulnerabilities")
            if not isinstance(vulns, dict):
                return findings
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "moderate": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            for pkg_name, entry in list(vulns.items())[:25]:
                if not isinstance(entry, dict):
                    continue
                sev_raw = str(entry.get("severity") or "medium").lower()
                severity = sev_map.get(sev_raw, Severity.MEDIUM)
                if severity in (Severity.LOW, Severity.INFO):
                    continue
                via = entry.get("via") or []
                advisories = [v for v in via if isinstance(v, dict)]
                if not advisories:
                    continue
                first = advisories[0]
                title = str(first.get("title") or f"Vulnerable npm package: {pkg_name}")
                url = str(first.get("url") or "")
                ghsa_match = re.search(r"(GHSA-[a-z0-9-]+|CVE-\d{4}-\d+)", url, re.IGNORECASE)
                adv_id = ghsa_match.group(1) if ghsa_match else f"npm-{pkg_name}"
                cves = [adv_id] if adv_id.upper().startswith("CVE-") else []
                fix_avail = entry.get("fixAvailable")
                rec = (
                    f"Run `npm audit fix` or upgrade `{pkg_name}`."
                    if fix_avail
                    else f"Upgrade or replace `{pkg_name}` to remediate {adv_id}."
                )
                findings.append(
                    VulnerabilityFinding(
                        id=f"sca-npm-{adv_id.lower()}",
                        scanner=ScannerType.SCA,
                        title=f"npm audit: {pkg_name} — {title}",
                        description=f"Detected via `npm audit` in `{rel_lock_path}` for `{pkg_name}` ({entry.get('range', '*')}). {url}",
                        severity=severity,
                        file_path=rel_lock_path,
                        line_start=1,
                        code_snippet=f'"{pkg_name}": "{entry.get("range", "*")}"',
                        cve=cves,
                        cwe=[str(c) for c in (first.get("cwe") or []) if isinstance(c, str)],
                        recommendation=rec,
                        raw_metadata={"source": "npm-audit", "advisory_url": url},
                    )
                )
        except Exception as exc:
            logger.debug(f"npm audit skipped in {cwd}: {exc}")
        return findings

    async def _scan_pypi(self, file_path: Path, target_dir: Path) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
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
                rel_path = file_path.relative_to(target_dir).as_posix()
                findings.extend(self._check_offline_advisories(deps, "PyPI", rel_path))
                findings.extend(await self._query_osv_batch(deps, "PyPI", rel_path))
        except Exception as e:
            logger.error(f"Failed to scan {file_path.name}: {e}")
        return findings

    async def _scan_pyproject(self, file_path: Path, target_dir: Path) -> List[VulnerabilityFinding]:
        """Extract pinned/bounded dependencies from pyproject.toml."""
        findings: List[VulnerabilityFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            deps: Dict[str, Tuple[str, int]] = {}
            for line_num, raw_line in enumerate(content.splitlines(), start=1):
                m = re.search(r'["\']([A-Za-z0-9._-]+)\s*(==|>=|~=)\s*([0-9][0-9A-Za-z._-]*)["\']', raw_line)
                if m:
                    deps[m.group(1)] = (m.group(3), line_num)
            if deps:
                rel_path = file_path.relative_to(target_dir).as_posix()
                findings.extend(self._check_offline_advisories(deps, "PyPI", rel_path))
                findings.extend(await self._query_osv_batch(deps, "PyPI", rel_path))
        except Exception as e:
            logger.debug(f"pyproject.toml scan skipped for {file_path}: {e}")
        return findings

    def _check_offline_advisories(
        self,
        packages: Dict[str, Tuple[str, int]],
        ecosystem: str,
        file_rel_path: str,
        dev_only_packages: Optional[set] = None,
    ) -> List[VulnerabilityFinding]:
        """Fast local advisory check for critical CVEs (works 100% offline / air-gapped)."""
        dev_set = dev_only_packages or set()
        out: List[VulnerabilityFinding] = []
        pkg_lookup = {k.lower(): (k, v[0], v[1]) for k, v in packages.items()}
        for adv_pkg, adv_eco, max_excl, cve, sev, title, rec in _OFFLINE_ADVISORIES:
            if adv_eco.lower() != ecosystem.lower():
                continue
            hit = pkg_lookup.get(adv_pkg.lower())
            if not hit:
                continue
            orig_name, ver_str, line_num = hit
            parsed = _parse_semver(ver_str)
            if not parsed or parsed >= max_excl:
                continue
            # Special Next.js 15.x check for CVE-2025-29927 (fixed in 15.2.3)
            if adv_pkg == "next" and cve == "CVE-2025-29927" and parsed[0] == 15 and parsed >= (15, 2, 3):
                continue
            is_dev = orig_name in dev_set
            eff_sev = Severity.INFO if is_dev else sev
            out.append(
                VulnerabilityFinding(
                    id=f"sca-{cve.lower()}",
                    scanner=ScannerType.SCA,
                    title=f"[devDependency] {title}" if is_dev else f"{title} ({orig_name} {ver_str})",
                    description=(
                        f"Known vulnerable version `{orig_name}@{ver_str}` detected in `{file_rel_path}` ({cve}). "
                        f"Fixed in >={max_excl[0]}.{max_excl[1]}.{max_excl[2]}."
                    ),
                    severity=eff_sev,
                    file_path=file_rel_path,
                    line_start=line_num,
                    code_snippet=f'"{orig_name}": "{ver_str}"',
                    cve=[cve],
                    recommendation=rec,
                    raw_metadata={"source": "offline-advisory", "cve": cve},
                )
            )
        return out

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
                        logger.debug(f"OSV API non-200: {resp.status_code}")
            except Exception as e:
                logger.debug(f"OSV batch query skipped (offline/timeout): {e}")

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
