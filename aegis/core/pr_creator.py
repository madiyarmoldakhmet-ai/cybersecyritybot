"""
Automated Pull Request Generator for Aegis.
Applies AI-generated security remediations and opens GitHub Pull Requests.
"""

import asyncio
import datetime
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from github import Auth, Github, GithubException, InputGitTreeElement

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

        ownership = await OwnershipVerifier.verify_repo_ownership_strict(clean_token, repo_full_name)
        if not ownership.get("verified") or not ownership.get("can_create_pr"):
            return False, ownership.get("message", "Недостаточно прав для создания PR в репозитории."), None

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

    @staticmethod
    async def commit_multi_file_fixes(
        token: str,
        repo_identifier: str,
        file_updates: List[Tuple[str, str]],
        summary_lines: List[str],
        before_score: int,
        after_score: int,
        before_grade: str,
        after_grade: str,
        fixed_count: int,
        direct_commit: bool = False,
        commit_message: Optional[str] = None,
        base_branch: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Atomically commit multiple verified Self-Heal file fixes into GitHub (Claude Code style).
        - When direct_commit=False (default): creates branch `aegis/autofix-<ts>`, pushes 1 atomic commit, opens PR.
        - When direct_commit=True: pushes 1 atomic commit directly to default branch (auto-falls back to branch + PR
          if GitHub Branch Protection blocks direct pushes).
        """
        clean_token = (token or "").strip()
        if not clean_token:
            return {"success": False, "committed": False, "message": "Нужен GitHub Token с правами repo для коммита."}
        if not file_updates:
            return {"success": False, "committed": False, "message": "Нет проверенных патчей для коммита."}

        repo_full_name = OwnershipVerifier.parse_github_repo(repo_identifier)
        if not repo_full_name:
            return {"success": False, "committed": False, "message": f"Неверный репозиторий: '{repo_identifier}'."}

        ownership = await OwnershipVerifier.verify_repo_ownership_strict(clean_token, repo_full_name)
        if not ownership.get("verified") or not ownership.get("can_create_pr"):
            return {
                "success": False,
                "committed": False,
                "message": ownership.get("message", "Недостаточно прав (нужны права Write/Owner и scope repo)."),
            }

        files_list = [p.lstrip("/") for p, _ in file_updates]
        default_msg = (
            f"fix(security): auto-heal {fixed_count} vulnerabilities "
            f"(Score {before_score} {before_grade} -> {after_score} {after_grade})\n\n"
            + "\n".join(f"- {line}" for line in summary_lines[:12])
            + "\n\nCo-Authored-By: Commit Guardian (Aegis Orca) <aegis@commit-guardian.local>"
        )
        final_commit_msg = (commit_message or "").strip() or default_msg

        def _sync_atomic_commit() -> Dict[str, Any]:
            try:
                auth = Auth.Token(clean_token)
                gh = Github(auth=auth, timeout=30)
                repo = gh.get_repo(repo_full_name)

                target_base = base_branch or repo.default_branch
                base_ref = repo.get_branch(target_base)
                base_sha = base_ref.commit.sha
                base_commit = repo.get_git_commit(base_sha)
                base_tree = base_commit.tree

                # Build 1 atomic multi-file Git tree via blobs
                tree_elements = []
                for rel_path, content in file_updates:
                    clean_path = rel_path.lstrip("/")
                    blob = repo.create_git_blob(content, "utf-8")
                    tree_elements.append(
                        InputGitTreeElement(path=clean_path, mode="100644", type="blob", sha=blob.sha)
                    )

                new_tree = repo.create_git_tree(tree_elements, base_tree)
                new_commit = repo.create_git_commit(
                    message=final_commit_msg,
                    tree=new_tree,
                    parents=[base_commit],
                )
                commit_sha = new_commit.sha
                commit_url = f"https://github.com/{repo.full_name}/commit/{commit_sha}"

                if direct_commit:
                    try:
                        ref = repo.get_git_ref(f"heads/{target_base}")
                        ref.edit(sha=commit_sha, force=False)
                        logger.info(f"Direct atomic commit {commit_sha[:7]} pushed to {repo.full_name}@{target_base}")
                        return {
                            "success": True,
                            "committed": True,
                            "direct_commit": True,
                            "branch_name": target_base,
                            "base_branch": target_base,
                            "commit_sha": commit_sha,
                            "commit_url": commit_url,
                            "pull_request_url": None,
                            "files_committed": files_list,
                            "message": (
                                f"Коммит `{commit_sha[:7]}` успешно запушен в ветку `{target_base}` "
                                f"({len(files_list)} файл(ов), Score {before_score} → {after_score})."
                            ),
                        }
                    except GithubException as prot_err:
                        if prot_err.status not in (403, 422):
                            raise prot_err
                        logger.info(
                            f"Branch '{target_base}' is protected ({prot_err.status}); falling back to autofix branch + PR"
                        )

                # Safe branch + Pull Request flow (default or Branch Protection fallback)
                ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
                branch_name = f"aegis/autofix-{ts}"
                repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=commit_sha)

                pr_title = (
                    f"🛡️ fix(security): auto-heal {fixed_count} issues "
                    f"(Score {before_score} {before_grade} → {after_score} {after_grade})"
                )
                bullets = "\n".join(f"- {line}" for line in summary_lines[:20]) or "- Применены проверенные AST/SAST-патчи."
                pr_body = (
                    f"## 🛡️ Commit Guardian — Verified Auto-Fix\n\n"
                    f"| Метрика | До | После |\n"
                    f"|---|---|---|\n"
                    f"| **Security Score** | `{before_score}/100 ({before_grade})` | **`{after_score}/100 ({after_grade})`** |\n"
                    f"| **Исправлено уязвимостей** | — | **`{fixed_count}`** |\n"
                    f"| **Изменено файлов** | — | **`{len(files_list)}`** |\n\n"
                    f"### Изменения (подтверждены пересканированием SAST)\n{bullets}\n\n"
                    f"> 🤖 Создано автоматически Commit Guardian (Aegis Orca) после локального пересканирования в песочнице."
                )
                pr = repo.create_pull(title=pr_title, body=pr_body, head=branch_name, base=target_base)
                fallback_note = (
                    f" (ветка `{target_base}` защищена Branch Protection, поэтому создан PR)"
                    if direct_commit
                    else ""
                )
                return {
                    "success": True,
                    "committed": True,
                    "direct_commit": False,
                    "branch_name": branch_name,
                    "base_branch": target_base,
                    "commit_sha": commit_sha,
                    "commit_url": commit_url,
                    "pull_request_url": pr.html_url,
                    "files_committed": files_list,
                    "message": (
                        f"Коммит `{commit_sha[:7]}` запушен в ветку `{branch_name}` и открыт Pull Request{fallback_note}."
                    ),
                }

            except GithubException as ghe:
                err_text = ghe.data.get("message", str(ghe)) if hasattr(ghe, "data") else str(ghe)
                logger.error(f"GitHub atomic auto-commit failed ({ghe.status}): {err_text}")
                return {
                    "success": False,
                    "committed": False,
                    "message": f"GitHub API ({ghe.status}): {err_text}",
                }
            except Exception as exc:
                logger.exception(f"Unexpected error in atomic auto-commit: {exc}")
                return {
                    "success": False,
                    "committed": False,
                    "message": f"Ошибка коммита: {exc}",
                }

        return await asyncio.to_thread(_sync_atomic_commit)
