"""
Proof of Ownership & Access Verification Module.
Ensures security audits and remediations are only performed on authorized repositories and assets.
"""

import asyncio
import logging
import re
from typing import Optional, Tuple
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
        token: str, repo_identifier: str
    ) -> Tuple[bool, str]:
        """
        Verify that the provided token has push or admin permissions on the target repository.
        Returns: (is_authorized, status_message)
        """
        repo_full_name = OwnershipVerifier.parse_github_repo(repo_identifier)
        if not repo_full_name:
            return False, f"Неверный формат репозитория: '{repo_identifier}'. Ожидается 'owner/repo' или URL."

        def _sync_check() -> Tuple[bool, str]:
            try:
                auth = Auth.Token(token.strip())
                gh = Github(auth=auth, timeout=15)
                user = gh.get_user()
                username = user.login

                repo = gh.get_repo(repo_full_name)
                perms = repo.permissions

                # Check if user has push (write) or admin access
                if perms and (perms.push or perms.admin):
                    perm_type = "Admin" if perms.admin else "Push/Write"
                    return (
                        True,
                        f"Успешная верификация! Пользователь @{username} имеет права {perm_type} на {repo.full_name}."
                    )
                else:
                    return (
                        False,
                        f"Отказано в доступе: пользователь @{username} не имеет прав записи (push/admin) в {repo.full_name}."
                    )

            except GithubException as ghe:
                if ghe.status == 404:
                    return (
                        False,
                        f"Репозиторий '{repo_full_name}' не найден или токен не имеет к нему доступа (404 Not Found)."
                    )
                if ghe.status == 401:
                    return False, "Неверный или просроченный GitHub Token (401 Unauthorized)."
                return False, f"Ошибка GitHub API ({ghe.status}): {ghe.data.get('message', str(ghe))}"
            except Exception as e:
                return False, f"Не удалось выполнить проверку GitHub: {str(e)}"

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
