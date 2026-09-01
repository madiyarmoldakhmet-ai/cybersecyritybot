"""
Automated Pull Request Generator for Aegis.
Applies AI-generated security remediations and opens GitHub Pull Requests.
"""

import asyncio
import datetime
import logging
import re
from typing import Optional, Tuple
from github import Auth, Github, GithubException

from aegis.ai.remediation_engine import RemediationResult
from aegis.core.verifier import OwnershipVerifier
from aegis.scanners.models import VulnerabilityFinding

logger = logging.getLogger("aegis.pr_creator")


class PullRequestCreator:
    """Handles automated branch creation, patch application, and Pull Request publishing."""

    @staticmethod
    def _sanitize_branch_name(name: str) -> str:
        """Convert arbitrary string into a valid Git branch name segment."""
        clean = re.sub(r"[^a-zA-Z0-9_\-]+", "-", name.lower()).strip("-")
        return clean[:30]

    @staticmethod
    def _build_pr_body(
        finding: VulnerabilityFinding, remediation: RemediationResult
    ) -> str:
        """Format detailed Markdown body for the Pull Request."""
        cwe_str = ", ".join(finding.cwe) if finding.cwe else "N/A"
        cve_str = ", ".join(finding.cve) if finding.cve else "N/A"
        steps_md = "\n".join(f"- {step}" for step in remediation.remediation_steps)

        return f"""## 🛡️ Aegis — Automated Security Fix

### 📌 Обзор уязвимости
- **Тип / ID:** `{finding.id}`
- **Уровень критичности:** **`{finding.severity.value}`**
- **Затронутый файл:** `{finding.file_path}` (строки: {finding.line_start or 1}-{finding.line_end or 1})
- **CWE / CVE:** CWE: `{cwe_str}` | CVE: `{cve_str}`

---

### 🔍 Описание и первопричина
{remediation.explanation_ru}

### ⚠️ Анализ рисков и Impact
{remediation.impact_analysis}

### 🛠️ Что было изменено:
{steps_md if steps_md else "- Применен безопасный патч для устранения уязвимости."}

{f"```diff\n{remediation.diff_patch}\n```" if remediation.diff_patch else ""}

---
> 🤖 **Aegis DevSecOps Engine**  
> *Сгенерировано автоматически с использованием локального AI-ассистента ({remediation.confidence_score * 100:.0f}% confidence).*  
> Пожалуйста, проверьте изменения перед слиянием (merge) в основную ветку.
"""

    @staticmethod
    async def create_remediation_pr(
        token: str,
        repo_identifier: str,
        file_path: str,
        fixed_content: str,
        finding: VulnerabilityFinding,
        remediation: RemediationResult,
        base_branch: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Create a new branch with the remediated file content and open a Pull Request.
        Returns: (success: bool, message: str, pr_html_url: Optional[str])
        """
        clean_token = token.strip()
        if not clean_token:
            return False, "Предоставлен пустой GitHub Token.", None

        repo_full_name = OwnershipVerifier.parse_github_repo(repo_identifier)
        if not repo_full_name:
            return False, f"Неверный идентификатор репозитория: '{repo_identifier}'", None

        def _sync_create_pr() -> Tuple[bool, str, Optional[str]]:
            try:
                auth = Auth.Token(clean_token)
                gh = Github(auth=auth, timeout=30)
                repo = gh.get_repo(repo_full_name)

                # Determine base branch
                target_base = base_branch or repo.default_branch
                base_ref = repo.get_branch(target_base)
                base_sha = base_ref.commit.sha

                # Create unique branch name
                timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
                safe_vuln = PullRequestCreator._sanitize_branch_name(finding.id)
                branch_name = f"security-fix/{safe_vuln}-{timestamp}"

                # Create branch on GitHub
                repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)
                logger.info(f"Created branch '{branch_name}' on {repo.full_name}")

                # Clean relative file path
                clean_path = file_path.lstrip("/")

                # Get existing file SHA on base branch to update it
                try:
                    contents = repo.get_contents(clean_path, ref=branch_name)
                    file_sha = contents.sha if not isinstance(contents, list) else contents[0].sha
                    repo.update_file(
                        path=clean_path,
                        message=f"fix(security): resolve {finding.id} in {clean_path}",
                        content=fixed_content,
                        sha=file_sha,
                        branch=branch_name,
                    )
                except GithubException as ge:
                    if ge.status == 404:
                        # File did not exist on branch, create it
                        repo.create_file(
                            path=clean_path,
                            message=f"fix(security): add secure implementation for {finding.id}",
                            content=fixed_content,
                            branch=branch_name,
                        )
                    else:
                        raise ge

                # Create Pull Request
                pr_title = f"🛡️ [Security Fix] Resolve {finding.title} in `{clean_path}`"
                pr_body = PullRequestCreator._build_pr_body(finding, remediation)

                pull_request = repo.create_pull(
                    title=pr_title,
                    body=pr_body,
                    head=branch_name,
                    base=target_base,
                )

                logger.info(f"Pull Request created successfully: {pull_request.html_url}")
                return (
                    True,
                    f"Pull Request успешно создан: {pull_request.html_url}",
                    pull_request.html_url,
                )

            except GithubException as ghe:
                err_text = ghe.data.get("message", str(ghe)) if hasattr(ghe, "data") else str(ghe)
                logger.error(f"GitHub PR creation failed ({ghe.status}): {err_text}")
                return False, f"Ошибка создания PR в GitHub ({ghe.status}): {err_text}", None
            except Exception as e:
                logger.exception(f"Unexpected error creating PR: {e}")
                return False, f"Внутренняя ошибка создания PR: {str(e)}", None

        return await asyncio.to_thread(_sync_create_pr)
