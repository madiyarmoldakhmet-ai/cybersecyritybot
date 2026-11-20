"""
Git Time Machine — finds secrets that were "deleted" but still live in git history.

Removing a key from the code does not revoke it: anyone with read access to the repository
(or a leaked mirror/backup) can run ``git log -p`` and recover it. This scanner replays the
repository history commit by commit and, for every secret it sees, reports:

* the commit/author/date that introduced it,
* whether it is still in ``HEAD`` or was removed (and by which commit),
* the **exposure window** — how many days the credential has been recoverable.

Secrets that are no longer in ``HEAD`` ("ghost secrets") become CRITICAL findings, because the
working-tree secret scanner cannot see them and developers usually believe they are gone.
"""

import hashlib
import logging
import re
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.secret_scanner import detect_secrets, is_plausible_secret, mask_secret

logger = logging.getLogger("aegis.git_history")

_COMMIT_MARK = "\x00COMMIT\x00"
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_SKIP_SUFFIXES = {".lock", ".svg", ".min.js", ".map"}


@dataclass
class CommitRef:
    sha: str
    author: str
    date: datetime
    subject: str

    @property
    def short(self) -> str:
        return self.sha[:8]

    def to_dict(self) -> dict:
        return {"sha": self.sha, "short": self.short, "author": self.author, "date": self.date.isoformat(), "subject": self.subject}


@dataclass
class HistorySecret:
    fingerprint: str
    secret_type: str
    masked_value: str
    file_path: str
    line: int
    introduced: CommitRef
    removed: Optional[CommitRef] = None
    still_in_head: bool = False
    commits_seen: List[str] = field(default_factory=list)

    @property
    def is_ghost(self) -> bool:
        return not self.still_in_head

    def exposure_days(self, now: Optional[datetime] = None) -> int:
        """Days the secret has been readable by anyone with repository access (it never stops while history exists)."""
        now = now or datetime.now(timezone.utc)
        return max(0, (now - self.introduced.date).days)

    def to_dict(self, now: Optional[datetime] = None) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "secret_type": self.secret_type,
            "masked_value": self.masked_value,
            "file_path": self.file_path,
            "line": self.line,
            "introduced": self.introduced.to_dict(),
            "removed": self.removed.to_dict() if self.removed else None,
            "still_in_head": self.still_in_head,
            "status": "ACTIVE_IN_HEAD" if self.still_in_head else "GHOST_IN_HISTORY",
            "exposure_days": self.exposure_days(now),
        }


class GitHistoryScanner:
    """Replays ``git log -p`` and tracks every secret's lifecycle."""

    def __init__(self, max_commits: int = 500, timeout_seconds: float = 60.0) -> None:
        self.max_commits = max_commits
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def is_git_repo(path: Path) -> bool:
        return (Path(path) / ".git").exists()

    def _git(self, repo: Path, *args: str) -> subprocess.CompletedProcess:
        git_bin = shutil.which("git") or "git"
        return subprocess.run(  # nosec B603
            [git_bin, "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_seconds,
        )

    def _present_in_head(self, repo: Path, value: str) -> bool:
        proc = self._git(repo, "grep", "-q", "-F", "-e", value, "HEAD", "--")
        return proc.returncode == 0

    def scan_history(self, repo_path) -> List[HistorySecret]:
        repo = Path(repo_path).resolve()
        if not self.is_git_repo(repo):
            return []

        proc = self._git(
            repo,
            "log", "--all", "--reverse", "--no-color", "--no-renames", "--no-ext-diff",
            "-p", "--unified=0", f"--max-count={self.max_commits}",
            "--format=%x00COMMIT%x00%H%x00%an%x00%aI%x00%s",
        )
        if proc.returncode != 0:
            logger.warning("git log failed for %s: %s", repo, proc.stderr.strip()[:200])
            return []

        secrets: Dict[str, HistorySecret] = {}
        values: Dict[str, str] = {}  # fingerprint -> raw value (kept in memory only)
        commit: Optional[CommitRef] = None
        new_file: Optional[str] = None
        old_file: Optional[str] = None
        new_line = 0

        for raw in proc.stdout.splitlines():
            if raw.startswith(_COMMIT_MARK):
                parts = raw[len(_COMMIT_MARK):].split("\x00")
                if len(parts) >= 4:
                    try:
                        date = datetime.fromisoformat(parts[2])
                    except ValueError:
                        date = datetime.now(timezone.utc)
                    commit = CommitRef(parts[0], parts[1], date, parts[3])
                new_file = old_file = None
                continue
            if commit is None:
                continue
            if raw.startswith("--- "):
                old_file = raw[6:] if raw.startswith("--- a/") else None
                continue
            if raw.startswith("+++ "):
                new_file = raw[6:] if raw.startswith("+++ b/") else None
                continue
            hunk = _HUNK_RE.match(raw)
            if hunk:
                new_line = int(hunk.group(1))
                continue
            if raw.startswith("+"):
                path = new_file
                if path and not any(path.endswith(s) for s in _SKIP_SUFFIXES):
                    added_line = raw[1:]
                    for kind, value in detect_secrets(added_line):
                        if kind == "Private Key" and "re.compile(" in added_line:
                            continue
                        if not is_plausible_secret(kind, value):
                            continue
                        fp = hashlib.sha256(value.encode()).hexdigest()[:12]
                        if fp not in secrets:
                            secrets[fp] = HistorySecret(
                                fingerprint=fp,
                                secret_type=kind,
                                masked_value=mask_secret(value),
                                file_path=path,
                                line=new_line,
                                introduced=commit,
                            )
                            values[fp] = value
                        else:
                            secrets[fp].removed = None  # re-added after a removal
                        if commit.sha not in secrets[fp].commits_seen:
                            secrets[fp].commits_seen.append(commit.sha)
                new_line += 1
            elif raw.startswith("-") and old_file:
                line_text = raw[1:]
                for fp, value in values.items():
                    if value in line_text:
                        secrets[fp].removed = commit

        for fp, secret in secrets.items():
            secret.still_in_head = self._present_in_head(repo, values[fp])
            if secret.still_in_head:
                secret.removed = None
        values.clear()

        return sorted(secrets.values(), key=lambda s: s.introduced.date)

    @staticmethod
    def to_findings(history: List[HistorySecret], now: Optional[datetime] = None) -> List[VulnerabilityFinding]:
        """Ghost secrets (not visible in HEAD) as CRITICAL findings; HEAD secrets are reported by SecretScanner."""
        findings: List[VulnerabilityFinding] = []
        for s in history:
            if not s.is_ghost:
                continue
            days = s.exposure_days(now)
            removed_txt = (
                f"удалён в коммите `{s.removed.short}` ({s.removed.author}, {s.removed.date.date()})"
                if s.removed
                else "отсутствует в HEAD"
            )
            findings.append(
                VulnerabilityFinding(
                    id=f"git-history-ghost-secret-{s.fingerprint}",
                    scanner=ScannerType.GIT_HISTORY,
                    title=f"Ghost secret in git history: {s.secret_type}",
                    description=(
                        f"{s.secret_type} `{s.masked_value}` добавлен в коммите `{s.introduced.short}` "
                        f"({s.introduced.author}, {s.introduced.date.date()}) и {removed_txt}, "
                        f"но до сих пор восстанавливается командой `git log -p`. "
                        f"Окно утечки: {days} дн. Удаление из кода НЕ отзывает ключ."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=s.file_path,
                    line_start=s.line,
                    line_end=s.line,
                    code_snippet=f"{s.file_path}:{s.line} @ {s.introduced.short}: {s.masked_value}",
                    cwe=["CWE-798", "CWE-540"],
                    recommendation=(
                        "1) Немедленно отзовите/ротируйте ключ у провайдера. "
                        "2) Очистите историю: `git filter-repo --replace-text` (или BFG) и force-push. "
                        "3) Попросите всех участников заново клонировать репозиторий."
                    ),
                    raw_metadata={"git_history": s.to_dict(now)},
                )
            )
        return findings
