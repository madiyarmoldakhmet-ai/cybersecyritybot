"""
Resilient GitHub repository cloning and commit metadata extraction for Commit Guardian.

Handles both small/medium repos (bounded multi-commit clone for Git Time Machine) and
large/asset-heavy repos or slow networks (metadata-only partial clone + prioritized
sparse checkout of security-relevant source files + shallow fallback), plus GitHub API
commit-log hydration when shallow depth=1 clones only contain HEAD locally.
"""

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional

import httpx

from aegis.core.config import settings
from aegis.core.verifier import OwnershipVerifier

logger = logging.getLogger("aegis.git_clone")

LARGE_REPO_THRESHOLD_KB = 15_000  # 15 MB: switch directly to code-only sparse clone
DEFAULT_SPARSE_MAX_FILES = 250
RETRY_SPARSE_MAX_FILES = 100

SKIP_DIR_NAMES = {
    "node_modules", ".git", ".venv", "venv", "env", "build", "dist", "out",
    ".next", ".nuxt", ".dart_tool", ".idea", "__pycache__", "temp_scans",
    ".pytest_cache", ".tox", ".mypy_cache", "site-packages",
    "public", "assets", "static", "media", "fonts", "images", "img", "icons",
    "docs", "doc", "vendor", "third_party", "testdata", "fixtures",
    "__fixtures__", "screenshots", "storybook-static", "coverage",
}

SECURITY_CODE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".dart", ".java", ".kt", ".go",
    ".rb", ".php", ".yml", ".yaml", ".rules", ".sql", ".sh", ".toml",
    ".cfg", ".ini", ".xml", ".gradle", ".plist", ".swift", ".rs", ".cs",
    ".c", ".cpp", ".h", ".html", ".json",
}

HIGH_PRIORITY_FILENAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "dockerfile",
    "docker-compose.yml", "docker-compose.yaml", ".aegis.yml", ".env",
    ".env.example", ".env.local", ".env.production", "pubspec.yaml",
    "go.mod", "pom.xml", "cargo.toml", "firestore.rules",
    "androidmanifest.xml", "info.plist", "google-services.json",
}

SECURITY_PATH_KEYWORDS = (
    "auth", "login", "oauth", "jwt", "token", "secret", "cred", "key",
    "crypto", "cipher", "pass", "session", "cookie", "security", "guard",
    "perm", "role", "admin", "payment", "billing", "checkout", "wallet",
    "bank", "iin", "pii", "sql", "query", "db", "database", "prisma",
    "api", "server", "backend", "route", "controller", "middleware",
    "webhook", "upload", "exec", "shell", "config", "settings", "env",
)


@dataclass
class CloneOutcome:
    success: bool
    mode: str = "full"
    error: str = ""
    repo_size_kb: Optional[int] = None
    files_checked_out: Optional[int] = None


StatusCallback = Callable[[str], Awaitable[None]]


def _git_env() -> Dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _sanitize_error(text: str, token: str) -> str:
    cleaned = (text or "").strip().replace("\r", " ")
    if token:
        cleaned = cleaned.replace(token, "***")
    return cleaned[:240]


async def _run_git(
    args: List[str],
    timeout: float,
    cwd: Optional[Path] = None,
) -> tuple[int, str, str]:
    """Execute git with strict timeout and guaranteed subprocess cleanup."""
    process = await asyncio.create_subprocess_exec(
        "git",
        *args,
        cwd=str(cwd) if cwd else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_git_env(),
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return (
            process.returncode if process.returncode is not None else -1,
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except Exception as wait_err:
            logger.debug(f"git process wait skipped after kill: {wait_err}")
        raise


async def fetch_github_repo_size_kb(repo_name: str, token: str = "") -> Optional[int]:
    """Quickly query GitHub repo size (KB) so huge asset-heavy repos skip bloated full clones."""
    headers = {
        "User-Agent": "CommitGuardian-Cloner/2.0",
        "Accept": "application/vnd.github.v3+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            resp = await client.get(f"https://api.github.com/repos/{repo_name}", headers=headers)
            if resp.status_code == 200:
                size = resp.json().get("size")
                if isinstance(size, int) and size >= 0:
                    return size
    except Exception as exc:
        logger.debug(f"Could not query GitHub size for {repo_name}: {type(exc).__name__}: {exc}")
    return None


def select_security_sparse_paths(all_paths: List[str], max_files: int = DEFAULT_SPARSE_MAX_FILES) -> List[str]:
    """Filter and prioritize security-relevant source and config paths for sparse checkout."""
    scored: List[tuple[int, str]] = []
    for raw_path in all_paths:
        path = raw_path.strip().lstrip("/")
        if not path:
            continue
        parts = path.split("/")
        low_parts = [p.lower() for p in parts]
        if any(part in SKIP_DIR_NAMES or (part.startswith(".") and part != ".github") for part in low_parts[:-1]):
            continue

        fname = low_parts[-1]
        if fname.endswith((".min.js", ".min.css", ".map", ".d.ts", ".lock", ".svg", ".snap")):
            continue
        if fname in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock"}:
            continue

        ext = os.path.splitext(fname)[1]
        is_priority_cfg = fname in HIGH_PRIORITY_FILENAMES or fname.startswith(".env")
        if not is_priority_cfg and ext not in SECURITY_CODE_EXTS:
            continue

        # Lower score = higher priority
        score = 50
        if is_priority_cfg:
            score = 0
        elif any(kw in path.lower() for kw in SECURITY_PATH_KEYWORDS):
            score = 10
        elif ext in {".py", ".ts", ".tsx", ".js", ".jsx", ".dart", ".go", ".java", ".kt", ".rb", ".php"}:
            score = 25
        elif ext in {".yml", ".yaml", ".rules", ".sql", ".sh", ".xml", ".plist", ".gradle"}:
            score = 30
        elif ext == ".json":
            score = 65  # Deprioritize bulk locale/data JSONs below real source code

        if any(seg in {"test", "tests", "__tests__", "spec", "e2e", "mocks"} for seg in low_parts[:-1]):
            score += 40

        scored.append((score, path))

    scored.sort(key=lambda item: (item[0], len(item[1]), item[1]))
    return [path for _, path in scored[:max_files]]


async def _try_sparse_code_clone(
    repo_name: str,
    safe_url: str,
    dest_dir: Path,
    clean_token: str,
    max_files: int,
    on_status: Optional[StatusCallback] = None,
) -> CloneOutcome:
    """Fast partial metadata clone + sparse checkout of prioritized security-relevant source files."""
    shutil.rmtree(dest_dir, ignore_errors=True)
    if on_status:
        await on_status(
            f"Умный sparse-клон {repo_name} (пропускаю медиа/ассеты, забираю до {max_files} ключевых файлов кода)..."
        )
    try:
        rc, _, stderr = await _run_git(
            [
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--no-tags",
                "--filter=blob:none",
                "--no-checkout",
                "--",
                safe_url,
                str(dest_dir),
            ],
            timeout=45.0,
        )
        if rc != 0:
            err = _sanitize_error(stderr, clean_token)
            logger.warning(f"Sparse metadata clone failed for {repo_name}: {err}")
            return CloneOutcome(success=False, mode="sparse", error=err or "Ошибка metadata-клона")

        rc_ls, stdout_ls, stderr_ls = await _run_git(
            ["ls-tree", "-r", "--name-only", "HEAD"], timeout=10.0, cwd=dest_dir
        )
        if rc_ls != 0:
            return CloneOutcome(success=False, mode="sparse", error=_sanitize_error(stderr_ls, clean_token))

        selected = select_security_sparse_paths(stdout_ls.splitlines(), max_files=max_files)
        if not selected:
            # Repo has only non-standard files; check out HEAD cleanly
            rc_co, _, stderr_co = await _run_git(["checkout", "HEAD"], timeout=60.0, cwd=dest_dir)
            if rc_co != 0:
                return CloneOutcome(success=False, mode="sparse", error=_sanitize_error(stderr_co, clean_token))
            return CloneOutcome(success=True, mode="sparse", files_checked_out=0)

        rc_sp, _, stderr_sp = await _run_git(
            ["sparse-checkout", "init", "--no-cone"], timeout=10.0, cwd=dest_dir
        )
        if rc_sp != 0:
            return CloneOutcome(success=False, mode="sparse", error=_sanitize_error(stderr_sp, clean_token))

        sparse_file = dest_dir / ".git" / "info" / "sparse-checkout"
        sparse_file.write_text("\n".join(f"/{p}" for p in selected) + "\n", encoding="utf-8")

        rc_co, _, stderr_co = await _run_git(["checkout", "HEAD"], timeout=75.0, cwd=dest_dir)
        if rc_co != 0:
            err = _sanitize_error(stderr_co, clean_token)
            logger.warning(f"Sparse checkout ({len(selected)} files) failed for {repo_name}: {err}")
            return CloneOutcome(success=False, mode="sparse", error=err)

        logger.info(f"Sparse-cloned {repo_name}: {len(selected)} prioritized code/config files.")
        return CloneOutcome(success=True, mode="sparse", files_checked_out=len(selected))
    except asyncio.TimeoutError:
        logger.warning(f"Sparse clone timed out for {repo_name} (max_files={max_files})")
        return CloneOutcome(success=False, mode="sparse", error="Таймаут загрузки исходных файлов с GitHub")
    except Exception as exc:
        logger.warning(f"Sparse clone error for {repo_name}: {type(exc).__name__}: {exc}")
        return CloneOutcome(success=False, mode="sparse", error=f"{type(exc).__name__}: {exc}")


async def clone_repo_resilient(
    repo_url: str,
    dest_dir: Path,
    token: Optional[str] = None,
    on_status: Optional[StatusCallback] = None,
) -> CloneOutcome:
    """
    Clone a validated GitHub repository reliably across normal repos, huge monorepos, and slow networks.

    Tier 1 (size <= 15 MB): bounded multi-commit clone (depth <= 25) for full Git Time Machine.
    Tier 2 (size > 15 MB or Tier 1 timeout): partial metadata clone + prioritized code-only sparse checkout.
    Tier 3 (fallback): retry sparse with 100 critical files, then plain shallow --depth 1 clone.
    """
    repo_name = OwnershipVerifier.parse_github_repo(repo_url)
    if not repo_name:
        logger.warning(f"Rejected invalid or non-GitHub clone URL: {repo_url}")
        return CloneOutcome(success=False, error="Неверный формат GitHub URL или owner/repo.")

    clean_token = (token or "").strip()
    safe_url = (
        f"https://x-access-token:{clean_token}@github.com/{repo_name}.git"
        if clean_token
        else f"https://github.com/{repo_name}.git"
    )

    repo_size_kb = await fetch_github_repo_size_kb(repo_name, token=clean_token)
    is_large_repo = repo_size_kb is not None and repo_size_kb > LARGE_REPO_THRESHOLD_KB

    # Tier 1: Bounded multi-commit clone for small/medium repositories
    if not is_large_repo:
        clone_depth = str(max(1, min(settings.webhook_clone_depth, 25)))
        logger.info(f"Cloning {repo_name} (depth={clone_depth}, size_kb={repo_size_kb}) into {dest_dir}...")
        try:
            rc, _, stderr = await _run_git(
                [
                    "clone",
                    "--depth",
                    clone_depth,
                    "--single-branch",
                    "--no-tags",
                    "--",
                    safe_url,
                    str(dest_dir),
                ],
                timeout=45.0,
            )
            if rc == 0:
                return CloneOutcome(success=True, mode="full", repo_size_kb=repo_size_kb)

            err_msg = _sanitize_error(stderr, clean_token)
            logger.error(f"Failed to clone repository {repo_name}: {err_msg}")
            lower_err = err_msg.lower()
            if "not found" in lower_err or "authentication failed" in lower_err or "could not read username" in lower_err:
                return CloneOutcome(
                    success=False,
                    mode="full",
                    repo_size_kb=repo_size_kb,
                    error=f"Репозиторий {repo_name} недоступен или приватный (укажите GitHub Token).",
                )
        except asyncio.TimeoutError:
            logger.warning(
                f"Full clone timed out after 45s for {repo_name}; switching to code-only sparse clone..."
            )
            if on_status:
                await on_status(
                    f"Клон {repo_name} занял >45с — переключаюсь на быстрый sparse-клон исходного кода..."
                )
        except Exception as exc:
            logger.error(f"Error during git clone for {repo_name}: {type(exc).__name__}: {exc}")
    else:
        size_mb = (repo_size_kb or 0) / 1024.0
        logger.info(f"Large repository detected ({repo_name}: {size_mb:.1f} MB) — using code-only sparse clone.")
        if on_status:
            await on_status(
                f"Репозиторий крупный ({size_mb:.1f} МБ) — включаю быстрый sparse-клон только исходного кода..."
            )

    # Tier 2: Smart sparse code-only clone (250 files, then retry 100 critical files on slow links)
    for max_files in (DEFAULT_SPARSE_MAX_FILES, RETRY_SPARSE_MAX_FILES):
        sparse_res = await _try_sparse_code_clone(
            repo_name, safe_url, dest_dir, clean_token, max_files=max_files, on_status=on_status
        )
        sparse_res.repo_size_kb = repo_size_kb
        if sparse_res.success:
            return sparse_res

    # Tier 3: Plain shallow --depth 1 fallback (in case remote rejects partial clones)
    shutil.rmtree(dest_dir, ignore_errors=True)
    if on_status:
        await on_status(f"Пробую облегчённый shallow-клон (--depth 1) для {repo_name}...")
    try:
        rc, _, stderr = await _run_git(
            [
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--no-tags",
                "--",
                safe_url,
                str(dest_dir),
            ],
            timeout=90.0,
        )
        if rc == 0:
            return CloneOutcome(success=True, mode="shallow", repo_size_kb=repo_size_kb)
        err_msg = _sanitize_error(stderr, clean_token)
        logger.error(f"Shallow clone failed for {repo_name}: {err_msg}")
        return CloneOutcome(
            success=False,
            mode="shallow",
            repo_size_kb=repo_size_kb,
            error=f"Не удалось клонировать {repo_name}: {err_msg or 'ошибка git clone'}",
        )
    except asyncio.TimeoutError:
        logger.error(f"All clone strategies timed out for {repo_name}")
        return CloneOutcome(
            success=False,
            mode="shallow",
            repo_size_kb=repo_size_kb,
            error=f"Таймаут загрузки {repo_name} с GitHub (медленный канал или слишком большой репозиторий). Попробуйте ZIP-архив или повторите позже.",
        )
    except Exception as exc:
        logger.error(f"Unexpected clone failure for {repo_name}: {type(exc).__name__}: {exc}")
        return CloneOutcome(
            success=False,
            mode="shallow",
            repo_size_kb=repo_size_kb,
            error=f"Ошибка клонирования {repo_name} ({type(exc).__name__}).",
        )


async def fetch_github_commits(
    repo_name: str,
    token: Optional[str] = None,
    limit: int = 10,
) -> List[Dict[str, str]]:
    """Fetch recent commits from GitHub REST API to hydrate shallow/sparse clones."""
    headers = {
        "User-Agent": "CommitGuardian-Commits/2.0",
        "Accept": "application/vnd.github.v3+json",
    }
    clean_token = (token or "").strip()
    if clean_token:
        headers["Authorization"] = f"Bearer {clean_token}"
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(
                f"https://api.github.com/repos/{repo_name}/commits",
                params={"per_page": limit},
                headers=headers,
            )
            if resp.status_code != 200:
                return []
            items = resp.json()
            if not isinstance(items, list):
                return []
            commits: List[Dict[str, str]] = []
            for item in items[:limit]:
                sha = str(item.get("sha") or "").strip()
                commit_obj = item.get("commit") or {}
                author_obj = commit_obj.get("author") or {}
                msg = str(commit_obj.get("message") or "").splitlines()
                subject = msg[0].strip() if msg else ""
                if sha:
                    commits.append({
                        "sha": sha,
                        "short": sha[:8],
                        "author": str(author_obj.get("name") or (item.get("author") or {}).get("login") or "unknown").strip(),
                        "date": str(author_obj.get("date") or "").strip(),
                        "subject": subject,
                    })
            return commits
    except Exception as exc:
        logger.debug(f"Could not hydrate commits from GitHub API for {repo_name}: {type(exc).__name__}: {exc}")
        return []


async def extract_git_metadata(
    repo_dir: Path,
    fallback_sha: str,
    fallback_branch: str = "main",
    fallback_author: str = "unknown",
    repo_name: Optional[str] = None,
    token: Optional[str] = None,
) -> tuple[str, str, str, List[Dict[str, str]]]:
    """Read real branch, HEAD commit SHA/author, and recent commit log (with GitHub API hydration on shallow clones)."""
    branch = fallback_branch
    commits: List[Dict[str, str]] = []

    if (repo_dir / ".git").exists():
        try:
            rc_br, out_br, _ = await _run_git(["rev-parse", "--abbrev-ref", "HEAD"], timeout=5.0, cwd=repo_dir)
            if rc_br == 0:
                parsed_br = out_br.strip()
                if parsed_br and parsed_br != "HEAD":
                    branch = parsed_br
        except Exception as exc:
            logger.debug(f"Could not read git branch for {repo_dir}: {exc}")

        try:
            rc_log, out_log, _ = await _run_git(
                ["log", "-n", "10", "--format=%H%x1f%an%x1f%aI%x1f%s"],
                timeout=5.0,
                cwd=repo_dir,
            )
            if rc_log == 0:
                for line in out_log.splitlines():
                    parts = line.split("\x1f")
                    if len(parts) >= 4:
                        sha = parts[0].strip()
                        commits.append({
                            "sha": sha,
                            "short": sha[:8],
                            "author": parts[1].strip(),
                            "date": parts[2].strip(),
                            "subject": parts[3].strip(),
                        })
        except Exception as exc:
            logger.debug(f"Could not read git log for {repo_dir}: {exc}")

    # On shallow (--depth 1) or sparse clones, hydrate the recent 10 commits from GitHub API
    if repo_name and len(commits) <= 1:
        api_commits = await fetch_github_commits(repo_name, token=token, limit=10)
        if len(api_commits) > len(commits):
            commits = api_commits

    if commits:
        return commits[0]["sha"], branch, commits[0]["author"] or fallback_author, commits
    return fallback_sha, branch, fallback_author, []
