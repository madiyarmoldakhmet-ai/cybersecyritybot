"""
Proof of Ownership & Access Verification Module.
Ensures security audits and remediations are only performed on authorized repositories and assets.
Supports strict token-based ownership checks and zero-token commit challenge verification.
"""

import asyncio
import logging
import re
import uuid
from typing import Any, Dict, Optional, Tuple
import httpx
from github import Github, GithubException, Auth

logger = logging.getLogger("aegis.verifier")


class OwnershipVerifier:
    """Verifies user ownership of GitHub repositories and domains."""

    @staticmethod
    def parse_github_repo(repo_input: str) -> Optional[str]:
        """
        Extract 'owner/repo' string from full GitHub URL or shorthand.
        Examples:
            - 'https://github.com/madiyarmoldakhmet-ai/aegis' -> 'madiyarmoldakhmet-ai/aegis'
            - 'git@github.com:owner/repo.git' -> 'owner/repo'
            - 'owner/repo' -> 'owner/repo'
        """
        input_clean = repo_input.strip()
        if not input_clean:
            return None

        https_pattern = r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/\s.]+)(?:\.git)?"
        ssh_pattern = r"git@github\.com:([^/]+)/([^/\s.]+)(?:\.git)?"

        match = re.search(https_pattern, input_clean, re.IGNORECASE) or re.search(
            ssh_pattern, input_clean, re.IGNORECASE
        )

        if match:
            return f"{match.group(1)}/{match.group(2)}"

        parts = [p for p in input_clean.split("/") if p]
        if len(parts) == 2 and not input_clean.startswith("http"):
            return f"{parts[0]}/{parts[1]}"

        return None

    @staticmethod
    def generate_commit_challenge() -> str:
        """Generate a unique random verification token for commit-based proof of ownership."""
        unique_id = uuid.uuid4().hex[:10]
        return f"cybersec-verify-{unique_id}"

    @staticmethod
    async def verify_commit_challenge(
        repo_identifier: str, challenge_code: str
    ) -> Tuple[bool, str]:
        """
        Verify repository ownership by checking:
        1. Presence of challenge_code in 'verify.txt' at repository root.
        2. Presence of challenge_code in any of the last 10 commit messages.
        """
        clean_code = challenge_code.strip()
        repo_full_name = OwnershipVerifier.parse_github_repo(repo_identifier)
        if not repo_full_name:
            return False, f"Неверный формат репозитория: '{repo_identifier}'."

        headers = {
            "User-Agent": "Aegis-Verifier/1.0",
            "Accept": "application/vnd.github.v3+json",
        }

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                # 1. Check verify.txt in main / master branches
                for branch in ["main", "master"]:
                    raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/verify.txt"
                    try:
                        raw_resp = await client.get(raw_url)
                        if raw_resp.status_code == 200 and clean_code in raw_resp.text:
                            return (
                                True,
                                f"Код подтверждения найден в файле `verify.txt` (ветка `{branch}`)! Авторство репозитория {repo_full_name} успешно подтверждено.",
                            )
                    except Exception as raw_ex:
                        logger.debug(f"Could not fetch {raw_url}: {raw_ex}")

                # 2. Check the last 10 commits
                commits_url = f"https://api.github.com/repos/{repo_full_name}/commits?per_page=10"
                resp = await client.get(commits_url, headers=headers)
                if resp.status_code == 200:
                    commits = resp.json()
                    for commit in commits:
                        commit_msg = commit.get("commit", {}).get("message", "")
                        if clean_code in commit_msg:
                            author = commit.get("commit", {}).get("author", {}).get("name", "Unknown")
                            sha = commit.get("sha", "")[:7]
                            return (
                                True,
                                f"Код подтверждения найден в коммите `{sha}` от {author}! Авторство репозитория {repo_full_name} успешно подтверждено.",
                            )
                    return (
                        False,
                        f"Код '{clean_code}' не найден в файле `verify.txt` или в последних 10 коммитах репозитория {repo_full_name}. Убедитесь, что вы выполнили `git push`.",
                    )
                elif resp.status_code == 404:
                    return False, f"Репозиторий '{repo_full_name}' не найден на GitHub."
                elif resp.status_code == 403:
                    return False, "Превышен лимит запросов GitHub API. Попробуйте подтверждение через токен."
                else:
                    return False, f"GitHub API вернул статус {resp.status_code} при проверке коммитов."
        except Exception as e:
            logger.warning(f"Error checking commit challenge for {repo_full_name}: {e}")
            return False, f"Сетевая ошибка при проверке коммитов: {str(e)}"

    @staticmethod
    async def verify_repo_ownership_strict(
        token: str, repo_identifier: str
    ) -> Dict[str, Any]:
        """
        Strictly verify repository ownership and author permissions using GitHub Token.
        Returns:
            {
                "verified": bool,
                "username": str,
                "repo_owner": str,
                "role": str, # "Owner" | "Admin" | "Contributor" | "None"
                "message": str,
                "can_create_pr": bool
            }
        """
        clean_token = token.strip() if token else ""
        repo_full_name = OwnershipVerifier.parse_github_repo(repo_identifier)

        def _sync_check() -> Dict[str, Any]:
            try:
                # 1. Check if repo is public first (bypass authorship for open source)
                try:
                    gh_public = Github(timeout=10)
                    repo = gh_public.get_repo(repo_full_name)
                    if not repo.private:
                        return {
                            "verified": True,
                            "username": "Guest",
                            "repo_owner": repo.owner.login,
                            "role": "Public",
                            "message": f"Репозиторий {repo.full_name} является открытым (Open Source). Проверка авторства пропущена (допускается локальное сканирование).",
                            "can_create_pr": False,
                        }
                except Exception:
                    pass # Fallback to strict token check if not found or API limit

                if not clean_token:
                    return {
                        "verified": False,
                        "username": "",
                        "repo_owner": "",
                        "role": "None",
                        "message": "GitHub Personal Access Token не предоставлен для проверки авторства (а репозиторий не является открытым).",
                        "can_create_pr": False,
                    }

                auth = Auth.Token(clean_token)
                gh = Github(auth=auth, timeout=15)

                # 2. Get authenticated user
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
                        }
                    raise auth_err

                # 2. Get repository details and permissions
                try:
                    repo = gh.get_repo(repo_full_name)
                    repo_owner = repo.owner.login
                    perms = repo.permissions
                except GithubException as ghe:
                    if ghe.status == 404:
                        return {
                            "verified": False,
                            "username": current_user,
                            "repo_owner": "",
                            "role": "None",
                            "message": f"Репозиторий '{repo_full_name}' не найден или у вас нет к нему доступа.",
                            "can_create_pr": False,
                        }
                    err_msg = ghe.data.get("message", str(ghe)) if isinstance(ghe.data, dict) else str(ghe)
                    return {
                        "verified": False,
                        "username": current_user,
                        "repo_owner": "",
                        "role": "None",
                        "message": f"Ошибка GitHub API ({ghe.status}): {err_msg}",
                        "can_create_pr": False,
                    }

                # 3. Ownership / Push / Admin check
                is_owner = current_user.lower() == repo_owner.lower()
                has_admin = perms and perms.admin
                has_push = perms and perms.push

                if is_owner:
                    role = "Owner"
                elif has_admin:
                    role = "Admin"
                elif has_push:
                    role = "Contributor"
                else:
                    role = "None"

                if is_owner or has_admin or has_push:
                    return {
                        "verified": True,
                        "username": current_user,
                        "repo_owner": repo_owner,
                        "role": role,
                        "message": f"Вы авторизованы как @{current_user}. Проверяем ваши права на репозиторий {repo.full_name}... Авторизация подтверждена! (Роль: {role})",
                        "can_create_pr": True,
                    }
                else:
                    return {
                        "verified": False,
                        "username": current_user,
                        "repo_owner": repo_owner,
                        "role": "ReadOnly",
                        "message": f"⛔ Доступ запрещен! Вы (@{current_user}) не являетесь владельцем или контрибьютором репозитория {repo_full_name}.",
                        "can_create_pr": False,
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
                }

        return await asyncio.to_thread(_sync_check)

    @staticmethod
    async def verify_github_access(
        token: Optional[str], repo_identifier: str
    ) -> Tuple[bool, str, bool]:
        """Legacy helper delegating to strict verification or public repo check."""
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
                    headers={"User-Agent": "Aegis-Verifier/1.0"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if not data.get("private", False):
                        return (
                            True,
                            f"Публичный репозиторий `{repo_full_name}` доступен в режиме чтения.",
                            False,
                        )
                    else:
                        return (
                            False,
                            f"Репозиторий `{repo_full_name}` приватный. Для доступа требуется подтверждение авторства.",
                            False,
                        )
                elif resp.status_code == 404:
                    return False, f"Репозиторий `{repo_full_name}` не найден на GitHub.", False
                else:
                    return True, f"Репозиторий `{repo_full_name}` (запуск проверки).", False
        except Exception:
            return True, f"Репозиторий `{repo_full_name}` (запуск проверки).", False

    @staticmethod
    async def verify_domain_txt_record(
        domain: str, expected_token: str
    ) -> Tuple[bool, str]:
        """
        Verify domain ownership via DNS TXT record (e.g. for DAST / web audits).
        Checks '_cybersec-verify.<domain>' or root domain.
        """
        clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip()
        record_names = [f"_cybersec-verify.{clean_domain}", clean_domain]

        for host in record_names:
            cmd = ["dig", "+short", "TXT", host]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                output = stdout.decode("utf-8")

                if expected_token in output:
                    return True, f"Владение доменом {clean_domain} подтверждено через TXT-запись ({host})."
            except Exception as e:
                logger.warning(f"DNS query error for {host}: {e}")

        return False, f"TXT-запись со значением '{expected_token}' не найдена в DNS для {clean_domain}."
