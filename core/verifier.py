"""
Proof of Ownership & Access Verification Module.
Ensures security audits and remediations are only performed on authorized repositories and assets.
"""

import asyncio
import logging
import re
from typing import Optional, Tuple
import httpx
from github import Github, GithubException, Auth

logger = logging.getLogger("cybersecuritybot.verifier")


class OwnershipVerifier:
    """Verifies user ownership of GitHub repositories and domains."""

    @staticmethod
    def parse_github_repo(repo_input: str) -> Optional[str]:
        """
        Extract 'owner/repo' string from full GitHub URL or shorthand.
        Examples:
            - 'https://github.com/madiyarmoldakhmet-ai/cybersecyritybot' -> 'madiyarmoldakhmet-ai/cybersecyritybot'
            - 'git@github.com:owner/repo.git' -> 'owner/repo'
            - 'owner/repo' -> 'owner/repo'
        """
        input_clean = repo_input.strip()
        if not input_clean:
            return None

        # Regex for HTTPS and SSH GitHub links
        https_pattern = r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/\s.]+)(?:\.git)?"
        ssh_pattern = r"git@github\.com:([^/]+)/([^/\s.]+)(?:\.git)?"

        match = re.search(https_pattern, input_clean, re.IGNORECASE) or re.search(
            ssh_pattern, input_clean, re.IGNORECASE
        )

        if match:
            return f"{match.group(1)}/{match.group(2)}"

        # If already formatted as 'owner/repo'
        parts = [p for p in input_clean.split("/") if p]
        if len(parts) == 2 and not input_clean.startswith("http"):
            return f"{parts[0]}/{parts[1]}"

        return None

    @staticmethod
    async def verify_github_access(
        token: Optional[str], repo_identifier: str
    ) -> Tuple[bool, str, bool]:
        """
        Verify access to the target repository.
        Returns: (is_accessible: bool, status_message: str, can_create_pr: bool)
        """
        clean_token = token.strip() if token else ""
        repo_full_name = OwnershipVerifier.parse_github_repo(repo_identifier)
        if not repo_full_name:
            return (
                False,
                f"Неверный формат репозитория: '{repo_identifier}'. Ожидается 'owner/repo' или URL.",
                False,
            )

        # Case 1: Token is not provided - check if repository is public
        if not clean_token:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(
                        f"https://api.github.com/repos/{repo_full_name}",
                        headers={"User-Agent": "CyberSecurityBot-Verifier/1.0"}
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if not data.get("private", False):
                            return (
                                True,
                                f"Публичный репозиторий `{repo_full_name}` доступен в режиме чтения (без прав на создание PR).",
                                False,
                            )
                        else:
                            return (
                                False,
                                f"Репозиторий `{repo_full_name}` приватный. Для доступа требуется GitHub Token.",
                                False,
                            )
                    elif resp.status_code == 404:
                        return (
                            False,
                            f"Репозиторий `{repo_full_name}` не найден или является приватным. Для доступа требуется GitHub Token.",
                            False,
                        )
                    elif resp.status_code == 403:
                        # API rate limit reached for anonymous, but git clone might still succeed for public repos
                        return (
                            True,
                            f"Публичный репозиторий `{repo_full_name}` (лимит API GitHub исчерпан, запуск клонирования).",
                            False,
                        )
                    else:
                        return (
                            False,
                            f"Ошибка GitHub API при проверке публичного репозитория ({resp.status_code}).",
                            False,
                        )
            except Exception as ex:
                logger.warning(f"Error checking public repo {repo_full_name}: {ex}")
                # Fallback: assume accessible for clone
                return (
                    True,
                    f"Режим без токена: запуск проверки доступности `{repo_full_name}`.",
                    False,
                )

        # Case 2: Token is provided - authenticate via PyGithub 2.x
        def _sync_check() -> Tuple[bool, str, bool]:
            try:
                auth = Auth.Token(clean_token)
                gh = Github(auth=auth, timeout=15)

                # 1. Verify token validity and authenticate user
                try:
                    user = gh.get_user()
                    username = user.login
                except GithubException as auth_err:
                    if auth_err.status == 401:
                        return (
                            False,
                            "Токен недействителен или отозван GitHub (401 Unauthorized).",
                            False,
                        )
                    raise auth_err

                # 2. Check repository permissions
                try:
                    repo = gh.get_repo(repo_full_name)
                    perms = repo.permissions

                    # Check if user has push (write) or admin access
                    if perms and (perms.push or perms.admin):
                        perm_type = "Admin" if perms.admin else "Push/Write"
                        return (
                            True,
                            f"Успешная верификация! Пользователь @{username} имеет права {perm_type} на {repo.full_name}.",
                            True,
                        )
                    else:
                        return (
                            True,
                            f"Пользователь @{username} имеет доступ к {repo.full_name} в режиме чтения (нет прав записи для создания PR).",
                            False,
                        )
                except GithubException as ghe:
                    if ghe.status == 404:
                        return (
                            False,
                            f"Репозиторий '{repo_full_name}' не найден или токен не имеет к нему доступа (404 Not Found).",
                            False,
                        )
                    err_msg = ghe.data.get("message", str(ghe)) if isinstance(ghe.data, dict) else str(ghe)
                    return False, f"Ошибка GitHub API ({ghe.status}): {err_msg}", False

            except Exception as e:
                return False, f"Не удалось выполнить проверку GitHub: {str(e)}", False

        return await asyncio.to_thread(_sync_check)

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
