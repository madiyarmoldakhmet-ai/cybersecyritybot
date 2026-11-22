"""
Proof of Ownership & Access Verification Module.
Ensures security audits and remediations can verify repository or domain authorship.
Supports strict GitHub token permissions, zero-token commit / verify.txt challenges,
DNS TXT domain verification (with DNS-over-HTTPS fallback), and signed proof tokens.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import time
import uuid
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlparse

import httpx
from github import Auth, Github, GithubException

logger = logging.getLogger("aegis.verifier")

_PROOF_SECRET = os.environ.get("AEGIS_PROOF_SECRET", "").encode("utf-8") or secrets.token_bytes(32)
_CHALLENGE_TTL_SECONDS = 1800
_CHALLENGES: Dict[str, Tuple[str, float]] = {}
_GITHUB_ETAG_CACHE: Dict[str, Tuple[str, Any]] = {}


class OwnershipVerifier:
    """Verifies user ownership/authorship of GitHub repositories and web domains."""

    @staticmethod
    def parse_github_repo(repo_input: str) -> Optional[str]:
        """
        Extract 'owner/repo' string from full GitHub URL or shorthand.
        Preserves dotted repository names such as 'vercel/next.js'.
        """
        input_clean = repo_input.strip()
        if not input_clean:
            return None

        https_pattern = r"(?:https?://)?(?:www\.)?github\.com/([^/\s]+)/([^/\s?#]+)"
        ssh_pattern = r"git@github\.com:([^/\s]+)/([^/\s?#]+)"

        match = re.search(https_pattern, input_clean, re.IGNORECASE) or re.search(
            ssh_pattern, input_clean, re.IGNORECASE
        )

        if match:
            owner = match.group(1)
            repo = match.group(2)
            if repo.lower().endswith(".git"):
                repo = repo[:-4]
            if owner and repo:
                return f"{owner}/{repo}"
            return None

        parts = [p for p in input_clean.split("/") if p]
        if len(parts) == 2 and not input_clean.startswith(("http://", "https://")):
            repo = parts[1][:-4] if parts[1].lower().endswith(".git") else parts[1]
            return f"{parts[0]}/{repo}"

        return None

    @staticmethod
    def normalize_domain(domain_input: str) -> Optional[str]:
        """Extract clean hostname from a domain name or HTTP/HTTPS URL."""
        raw = (domain_input or "").strip()
        if not raw:
            return None
        candidate = raw if "://" in raw else f"https://{raw}"
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").strip().lower()
        if not host or "." not in host and host != "localhost":
            return None
        return host

    @staticmethod
    def generate_commit_challenge() -> str:
        """Generate a unique random verification token for commit-based proof of ownership."""
        unique_id = uuid.uuid4().hex[:10]
        return f"cybersec-verify-{unique_id}"

    @staticmethod
    def build_github_verify_url(
        repo_full_name: str,
        challenge_code: str,
        branch: str = "main",
        filename: str = "verify.txt",
    ) -> str:
        """Build a 1-click GitHub New File URL with filename, challenge code, and commit message pre-filled."""
        safe_branch = quote((branch or "main").strip(), safe="/")
        safe_filename = quote((filename or "verify.txt").strip())
        safe_value = quote(challenge_code.strip())
        safe_msg = quote(f"Verify Commit Guardian ownership: {challenge_code.strip()}")
        return (
            f"https://github.com/{repo_full_name}/new/{safe_branch}"
            f"?filename={safe_filename}&value={safe_value}&message={safe_msg}"
        )

    @classmethod
    def issue_challenge(
        cls,
        target: str,
        target_type: str = "auto",
        branch: str = "main",
        filename: str = "verify.txt",
    ) -> Dict[str, Any]:
        """Create and cache a time-bound authorship challenge for a GitHub repo or domain."""
        now = time.time()
        expired = [k for k, (_, exp) in _CHALLENGES.items() if exp < now]
        for key in expired:
            _CHALLENGES.pop(key, None)

        resolved_type = target_type
        normalized: Optional[str] = None
        display_repo: Optional[str] = None
        if target_type in ("auto", "github"):
            repo_name = cls.parse_github_repo(target)
            if repo_name:
                display_repo = repo_name
                normalized = repo_name.lower()
                resolved_type = "github"

        if normalized is None and target_type in ("auto", "domain"):
            host = cls.normalize_domain(target)
            if host:
                normalized = host
                resolved_type = "domain"

        if normalized is None:
            raise ValueError(f"Неверный формат цели проверки авторства: '{target}'")

        existing = _CHALLENGES.get(normalized)
        if existing and existing[1] > now + 60:
            code = existing[0]
        else:
            code = cls.generate_commit_challenge()
            _CHALLENGES[normalized] = (code, now + _CHALLENGE_TTL_SECONDS)

        verify_url: Optional[str] = None
        if resolved_type == "github":
            repo_for_url = display_repo or normalized
            verify_url = cls.build_github_verify_url(repo_for_url, code, branch=branch, filename=filename)
            instructions = [
                f"1 клик в браузере (без терминала): откройте ссылку и нажмите «Commit changes» — `{filename}` заполнен автоматически",
                f"Или вставьте код `{code}` в описание репозитория (GitHub → About → Description)",
            ]
        else:
            instructions = [
                f"Добавьте DNS TXT-запись для `_cybersec-verify.{normalized}` (или корневого домена `{normalized}`) со значением `{code}`",
            ]

        return {
            "target": normalized,
            "target_type": resolved_type,
            "challenge_code": code,
            "verify_url": verify_url,
            "default_branch": branch if resolved_type == "github" else None,
            "verify_filename": filename if resolved_type == "github" else None,
            "expires_in_seconds": _CHALLENGE_TTL_SECONDS,
            "instructions": instructions,
        }

    @classmethod
    async def issue_challenge_async(
        cls,
        target: str,
        target_type: str = "auto",
        token: str = "",
    ) -> Dict[str, Any]:
        """Async variant of issue_challenge that detects the repo's real default branch and avoids filename collision."""
        base = cls.issue_challenge(target, target_type=target_type)
        if base.get("target_type") != "github":
            return base

        repo_name = cls.parse_github_repo(target) or base["target"]
        code = base["challenge_code"]
        branch = "main"
        filename = "verify.txt"

        headers = {
            "User-Agent": "CommitGuardian-Verifier/2.1",
            "Accept": "application/vnd.github.v3+json",
        }
        gh_token = (token or os.environ.get("GITHUB_TOKEN", "")).strip()
        if gh_token and not gh_token.startswith("your_"):
            headers["Authorization"] = f"Bearer {gh_token}"

        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                repo_resp = await client.get(f"https://api.github.com/repos/{repo_name}", headers=headers)
                if repo_resp.status_code == 200:
                    meta = repo_resp.json()
                    branch = (meta.get("default_branch") or "main").strip() or "main"
                    # Avoid GitHub "A file with the same name already exists" if verify.txt already exists
                    exists_resp = await client.get(
                        f"https://api.github.com/repos/{repo_name}/contents/verify.txt",
                        headers=headers,
                    )
                    if exists_resp.status_code == 200:
                        suffix = code.rsplit("-", 1)[-1][:8]
                        filename = f"verify-{suffix}.txt"
        except Exception as exc:
            logger.debug(f"GitHub metadata lookup skipped for {repo_name}: {exc}")

        return cls.issue_challenge(target, target_type="github", branch=branch, filename=filename)

    @classmethod
    def has_active_challenge(cls, target: str, code: str) -> bool:
        """Check whether a challenge code matches an issued active challenge (optional strict binding)."""
        clean_code = code.strip()
        if not clean_code:
            return False
        repo = cls.parse_github_repo(target)
        host = cls.normalize_domain(target)
        keys = [k for k in (repo.lower() if repo else None, host) if k]
        now = time.time()
        for k in keys:
            entry = _CHALLENGES.get(k)
            if entry and entry[1] >= now and hmac.compare_digest(entry[0], clean_code):
                return True
        return False

    @classmethod
    def create_proof_token(cls, target: str, method: str, actor: str, ttl_seconds: int = 3600) -> str:
        """Sign a short-lived HMAC proof token certifying verified authorship."""
        repo = cls.parse_github_repo(target)
        normalized = repo.lower() if repo else (cls.normalize_domain(target) or target.strip().lower())
        payload = {
            "t": normalized,
            "m": method,
            "a": actor or "verified-author",
            "exp": int(time.time()) + ttl_seconds,
        }
        raw = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode("utf-8")).decode("ascii")
        sig = hmac.new(_PROOF_SECRET, raw.encode("ascii"), hashlib.sha256).hexdigest()[:32]
        return f"{raw}.{sig}"

    @classmethod
    def verify_proof_token(cls, proof_token: Optional[str], target: str) -> Optional[Dict[str, str]]:
        """Validate a signed proof token against the target repository or domain."""
        if not proof_token or "." not in proof_token:
            return None
        try:
            raw, sig = proof_token.strip().rsplit(".", 1)
            expected_sig = hmac.new(_PROOF_SECRET, raw.encode("ascii"), hashlib.sha256).hexdigest()[:32]
            if not hmac.compare_digest(sig, expected_sig):
                return None
            padded = raw + "=" * (-len(raw) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
            if int(payload.get("exp", 0)) < int(time.time()):
                return None
            repo = cls.parse_github_repo(target)
            normalized = repo.lower() if repo else (cls.normalize_domain(target) or target.strip().lower())
            if payload.get("t") != normalized:
                return None
            return {
                "target": normalized,
                "method": str(payload.get("m", "verified")),
                "actor": str(payload.get("a", "verified-author")),
            }
        except Exception as exc:
            logger.debug(f"Proof token validation failed: {exc}")
            return None

    @staticmethod
    async def verify_commit_challenge(
        repo_identifier: str, challenge_code: str
    ) -> Tuple[bool, str]:
        """
        Verify repository ownership via zero-terminal GitHub signals (with ETag caching
        so automatic browser polling uses 0 quota on 304 Not Modified):
        1. Last 10 commit messages (covers 1-click GitHub New File commit & git commit --allow-empty).
        2. GitHub repository About / Description field.
        3. Instant GitHub Contents API for verify.txt / verify-<suffix>.txt / .well-known/aegis-verify.txt.
        4. raw.githubusercontent.com fallback if GitHub API rate limit is reached.
        """
        clean_code = challenge_code.strip()
        repo_full_name = OwnershipVerifier.parse_github_repo(repo_identifier)
        if not repo_full_name:
            return False, f"Неверный формат репозитория: '{repo_identifier}'."
        if not clean_code:
            return False, "Код подтверждения пустой."

        base_headers: Dict[str, str] = {
            "User-Agent": "CommitGuardian-Verifier/2.1",
            "Accept": "application/vnd.github.v3+json",
            "Cache-Control": "no-cache",
        }
        gh_token = os.environ.get("GITHUB_TOKEN", "").strip()
        if gh_token and not gh_token.startswith("your_"):
            base_headers["Authorization"] = f"Bearer {gh_token}"

        suffix = clean_code.rsplit("-", 1)[-1][:8] if "-" in clean_code else clean_code[:8]
        candidate_files = [f"verify-{suffix}.txt", "verify.txt", ".well-known/aegis-verify.txt"]

        async def _get_with_etag(client: httpx.AsyncClient, url: str) -> Tuple[int, Any, bool]:
            """Returns (status_code, json_payload, was_304)."""
            req_headers = dict(base_headers)
            cached = _GITHUB_ETAG_CACHE.get(url)
            if cached:
                req_headers["If-None-Match"] = cached[0]
            resp = await client.get(url, headers=req_headers)
            if resp.status_code == 304 and cached:
                return 200, cached[1], True
            if resp.status_code == 200:
                payload = resp.json()
                etag = (getattr(resp, "headers", None) or {}).get("etag") or (
                    getattr(resp, "headers", None) or {}
                ).get("ETag")
                if etag:
                    if len(_GITHUB_ETAG_CACHE) > 256:
                        _GITHUB_ETAG_CACHE.clear()
                    _GITHUB_ETAG_CACHE[url] = (etag, payload)
                return 200, payload, False
            return resp.status_code, None, False

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                # 1. Check recent commits (ETag-cached -> 304 consumes 0 GitHub API quota)
                commits_url = f"https://api.github.com/repos/{repo_full_name}/commits?per_page=10"
                commits_status, commits_data, commits_304 = await _get_with_etag(client, commits_url)
                if commits_status == 200 and isinstance(commits_data, list):
                    for commit in commits_data:
                        commit_msg = commit.get("commit", {}).get("message", "")
                        if clean_code in commit_msg:
                            author = commit.get("commit", {}).get("author", {}).get("name", "Author")
                            sha = commit.get("sha", "")[:7]
                            return (
                                True,
                                f"Код подтверждения найден в коммите `{sha}` от {author}. Авторство {repo_full_name} подтверждено.",
                            )

                # 2. Check repository About / Description + capture default_branch (ETag-cached)
                default_branch = "main"
                repo_url = f"https://api.github.com/repos/{repo_full_name}"
                repo_status, repo_data, _ = await _get_with_etag(client, repo_url)
                if repo_status == 200 and isinstance(repo_data, dict):
                    default_branch = (repo_data.get("default_branch") or "main").strip() or "main"
                    desc = str(repo_data.get("description") or "")
                    if clean_code in desc:
                        return (
                            True,
                            f"Код подтверждения найден в описании репозитория (About). Авторство {repo_full_name} подтверждено.",
                        )
                elif repo_status == 404 or commits_status == 404:
                    return (
                        False,
                        f"Репозиторий '{repo_full_name}' не найден или он приватный (для приватных репо вставьте GitHub Token).",
                    )

                # 3. Instant GitHub Contents API check (only when commits changed or first check — avoids rate limit burn)
                if commits_status == 200 and not commits_304:
                    for rel_path in candidate_files:
                        content_url = f"https://api.github.com/repos/{repo_full_name}/contents/{rel_path}"
                        try:
                            c_resp = await client.get(content_url, headers=base_headers)
                            if c_resp.status_code == 200:
                                c_json = c_resp.json()
                                raw_b64 = c_json.get("content") or ""
                                if raw_b64:
                                    decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
                                    if clean_code in decoded:
                                        return (
                                            True,
                                            f"Код подтверждения найден в `{rel_path}`. Авторство {repo_full_name} подтверждено.",
                                        )
                        except Exception as content_err:
                            logger.debug(f"Could not fetch contents {content_url}: {content_err}")

                # 4. raw.githubusercontent.com fallback (no 60/hr API rate limit)
                branches = list(dict.fromkeys([default_branch, "main", "master"]))
                cache_bust = int(time.time())
                for branch in branches:
                    for rel_path in (f"verify-{suffix}.txt", "verify.txt"):
                        raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/{rel_path}?t={cache_bust}"
                        try:
                            raw_resp = await client.get(raw_url)
                            if raw_resp.status_code == 200 and clean_code in raw_resp.text:
                                return (
                                    True,
                                    f"Код подтверждения найден в `{rel_path}` (ветка `{branch}`). Авторство {repo_full_name} подтверждено.",
                                )
                        except Exception as raw_ex:
                            logger.debug(f"Could not fetch {raw_url}: {raw_ex}")

                if commits_status == 403 and repo_status == 403:
                    return False, "Превышен лимит запросов GitHub API. Вставьте GitHub Token для мгновенной проверки."
                if commits_status not in (200, 403) and repo_status not in (200, 403):
                    return False, f"GitHub API вернул статус {commits_status} при проверке репозитория."

                return (
                    False,
                    f"Ожидаю подтверждение `{clean_code}` в `{repo_full_name}` — нажмите «Commit changes» на GitHub или добавьте код в описание репо.",
                )
        except Exception as e:
            logger.warning(f"Error checking commit challenge for {repo_full_name}: {e}")
            return False, f"Сетевая ошибка при проверке репозитория: {str(e)}"

    @staticmethod
    async def verify_repo_ownership_strict(
        token: str, repo_identifier: str
    ) -> Dict[str, Any]:
        """
        Strictly verify repository authorship/write permissions using GitHub Token.
        Never bypasses token verification even for public repositories.
        """
        clean_token = token.strip() if token else ""
        repo_full_name = OwnershipVerifier.parse_github_repo(repo_identifier)
        if not repo_full_name:
            return {
                "verified": False,
                "username": "",
                "repo_owner": "",
                "role": "None",
                "message": f"Неверный формат репозитория: '{repo_identifier}'.",
                "can_create_pr": False,
                "is_public": False,
            }

        def _sync_check() -> Dict[str, Any]:
            try:
                if not clean_token:
                    is_public = False
                    repo_owner = ""
                    try:
                        gh_public = Github(timeout=10)
                        pub_repo = gh_public.get_repo(repo_full_name)
                        is_public = not pub_repo.private
                        repo_owner = pub_repo.owner.login
                    except Exception as pub_err:
                        logger.debug(f"Public metadata lookup skipped for {repo_full_name}: {pub_err}")

                    return {
                        "verified": False,
                        "username": "",
                        "repo_owner": repo_owner,
                        "role": "PublicReadOnly" if is_public else "None",
                        "message": (
                            f"Репозиторий `{repo_full_name}` открыт для чтения, но авторство не подтверждено — укажите GitHub Token или пройдите Commit Challenge."
                            if is_public
                            else "GitHub Token не передан, а без него нельзя подтвердить права на приватный репозиторий."
                        ),
                        "can_create_pr": False,
                        "is_public": is_public,
                    }

                auth = Auth.Token(clean_token)
                gh = Github(auth=auth, timeout=15)

                try:
                    current_user = gh.get_user().login
                except GithubException as auth_err:
                    if auth_err.status == 401:
                        return {
                            "verified": False,
                            "username": "",
                            "repo_owner": "",
                            "role": "None",
                            "message": "Токен недействителен или отозван GitHub (401 Unauthorized).",
                            "can_create_pr": False,
                            "is_public": False,
                        }
                    raise auth_err

                try:
                    repo = gh.get_repo(repo_full_name)
                    repo_owner = repo.owner.login
                    perms = repo.permissions
                    is_public = not repo.private
                except GithubException as ghe:
                    if ghe.status == 404:
                        return {
                            "verified": False,
                            "username": current_user,
                            "repo_owner": "",
                            "role": "None",
                            "message": f"Репозиторий '{repo_full_name}' не найден или у @{current_user} нет к нему доступа.",
                            "can_create_pr": False,
                            "is_public": False,
                        }
                    err_msg = ghe.data.get("message", str(ghe)) if isinstance(ghe.data, dict) else str(ghe)
                    return {
                        "verified": False,
                        "username": current_user,
                        "repo_owner": "",
                        "role": "None",
                        "message": f"Ошибка GitHub API ({ghe.status}): {err_msg}",
                        "can_create_pr": False,
                        "is_public": False,
                    }

                is_owner = current_user.lower() == repo_owner.lower()
                has_admin = bool(perms and perms.admin)
                has_push = bool(perms and perms.push)

                if is_owner:
                    role = "Owner"
                elif has_admin:
                    role = "Admin"
                elif has_push:
                    role = "Contributor"
                else:
                    role = "ReadOnly"

                if is_owner or has_admin or has_push:
                    return {
                        "verified": True,
                        "username": current_user,
                        "repo_owner": repo_owner,
                        "role": role,
                        "message": f"Авторство подтверждено для @{current_user} в {repo.full_name} (роль: {role}).",
                        "can_create_pr": True,
                        "is_public": is_public,
                    }
                return {
                    "verified": False,
                    "username": current_user,
                    "repo_owner": repo_owner,
                    "role": "ReadOnly",
                    "message": f"Пользователь @{current_user} имеет только права чтения в {repo_full_name} (нужны права Owner/Admin/Write).",
                    "can_create_pr": False,
                    "is_public": is_public,
                }
            except Exception as ex:
                logger.error(f"Unexpected error in strict ownership check: {ex}")
                return {
                    "verified": False,
                    "username": "",
                    "repo_owner": "",
                    "role": "Error",
                    "message": f"Ошибка при проверке прав репозитория: {str(ex)}",
                    "can_create_pr": False,
                    "is_public": False,
                }

        return await asyncio.to_thread(_sync_check)

    @staticmethod
    async def verify_github_access(
        token: Optional[str], repo_identifier: str
    ) -> Tuple[bool, str, bool]:
        """Verify access for scanning: strict token check if token supplied, else allow public read-only."""
        clean_token = token.strip() if token else ""
        if clean_token:
            res = await OwnershipVerifier.verify_repo_ownership_strict(clean_token, repo_identifier)
            return res["verified"], res["message"], res["can_create_pr"]

        repo_full_name = OwnershipVerifier.parse_github_repo(repo_identifier)
        if not repo_full_name:
            return False, f"Неверный формат репозитория: '{repo_identifier}'.", False

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://api.github.com/repos/{repo_full_name}",
                    headers={"User-Agent": "CommitGuardian-Verifier/2.0"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if not data.get("private", False):
                        return (
                            True,
                            f"Публичный репозиторий `{repo_full_name}` доступен в режиме чтения (авторство не проверялось).",
                            False,
                        )
                    return (
                        False,
                        f"Репозиторий `{repo_full_name}` приватный. Подтвердите авторство через GitHub Token.",
                        False,
                    )
                if resp.status_code == 404:
                    return False, f"Репозиторий `{repo_full_name}` не найден на GitHub или является приватным.", False
                return True, f"Репозиторий `{repo_full_name}` (запуск проверки).", False
        except Exception:
            return True, f"Репозиторий `{repo_full_name}` (запуск проверки).", False

    @staticmethod
    async def verify_domain_txt_record(
        domain: str, expected_token: str
    ) -> Tuple[bool, str]:
        """
        Verify domain ownership via DNS TXT record ('_cybersec-verify.<domain>' or root domain).
        Uses native 'dig' when available and falls back to DNS-over-HTTPS for Docker/Colab containers.
        """
        clean_domain = OwnershipVerifier.normalize_domain(domain)
        clean_token = (expected_token or "").strip()
        if not clean_domain:
            return False, f"Неверный формат домена: '{domain}'."
        if not clean_token:
            return False, "Код подтверждения TXT пустой."

        record_names = [f"_cybersec-verify.{clean_domain}", clean_domain]
        has_dig = shutil.which("dig") is not None

        for host in record_names:
            if has_dig:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "dig",
                        "+short",
                        "TXT",
                        host,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8.0)
                    if clean_token in stdout.decode("utf-8", errors="replace"):
                        return True, f"Владение доменом {clean_domain} подтверждено через DNS TXT ({host})."
                except Exception as e:
                    logger.debug(f"dig TXT lookup failed for {host}: {e}")

            for doh_url in (
                f"https://cloudflare-dns.com/dns-query?name={host}&type=TXT",
                f"https://dns.google/resolve?name={host}&type=TXT",
            ):
                try:
                    async with httpx.AsyncClient(timeout=8.0) as client:
                        resp = await client.get(doh_url, headers={"Accept": "application/dns-json"})
                        if resp.status_code == 200:
                            answers = resp.json().get("Answer", [])
                            if any(clean_token in str(ans.get("data", "")) for ans in answers):
                                return True, f"Владение доменом {clean_domain} подтверждено через DoH TXT ({host})."
                except Exception as doh_err:
                    logger.debug(f"DoH TXT lookup error for {host}: {doh_err}")

        return False, f"TXT-запись '{clean_token}' не найдена в DNS для {clean_domain}."
