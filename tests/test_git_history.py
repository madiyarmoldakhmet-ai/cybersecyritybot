"""Git Time Machine: secrets deleted from HEAD but still recoverable from history."""

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegis.scanners.git_history import GitHistoryScanner
from aegis.scanners.models import ScannerType, Severity
from aegis.scanners.secret_scanner import detect_secrets, mask_secret

# Synthetic values, split so repository push-protection never sees a literal token
TG_TOKEN = "7312456789:" + "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1"
AWS_KEY = "AKIA" + "Z7QW3RTY5UIO9PLM"


def _git(repo: Path, *args, date: str = "2026-09-01T10:00:00+05:00"):
    env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date,
           "GIT_AUTHOR_NAME": "Dev", "GIT_AUTHOR_EMAIL": "dev@example.kz",
           "GIT_COMMITTER_NAME": "Dev", "GIT_COMMITTER_EMAIL": "dev@example.kz"}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


@pytest.fixture
def repo_with_ghost(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "bot.py").write_text(f'TELEGRAM_TOKEN = "{TG_TOKEN}"\nprint("hi")\n')
    (repo / "aws.py").write_text(f'KEY = "{AWS_KEY}"\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init bot", date="2026-09-01T10:00:00+05:00")
    (repo / "bot.py").write_text('import os\nTELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]\nprint("hi")\n')
    _git(repo, "commit", "-q", "-am", "move token to env", date="2026-10-01T10:00:00+05:00")
    return repo


def test_detects_ghost_secret_with_exposure_window(repo_with_ghost):
    history = GitHistoryScanner().scan_history(repo_with_ghost)
    by_type = {s.secret_type: s for s in history}

    ghost = by_type["Telegram Bot Token"]
    assert ghost.is_ghost
    assert ghost.removed is not None and ghost.removed.subject == "move token to env"
    assert ghost.introduced.subject == "init bot"
    assert ghost.file_path == "bot.py" and ghost.line == 1
    now = datetime(2026, 11, 18, tzinfo=timezone.utc)
    assert ghost.exposure_days(now) == 77

    active = by_type["AWS Access Key"]
    assert active.still_in_head and not active.is_ghost and active.removed is None


def test_only_ghost_secrets_become_findings_and_raw_value_never_leaks(repo_with_ghost):
    history = GitHistoryScanner().scan_history(repo_with_ghost)
    findings = GitHistoryScanner.to_findings(history)
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == ScannerType.GIT_HISTORY
    assert f.severity == Severity.CRITICAL
    assert "CWE-798" in f.cwe
    dumped = f.model_dump_json()
    assert TG_TOKEN not in dumped
    assert mask_secret(TG_TOKEN) in dumped
    assert f.raw_metadata["git_history"]["status"] == "GHOST_IN_HISTORY"


def test_non_git_directory_is_ignored(tmp_path):
    (tmp_path / "a.py").write_text(f'K = "{AWS_KEY}"\n')
    assert GitHistoryScanner().scan_history(tmp_path) == []


@pytest.mark.asyncio
async def test_sast_scanner_reports_ghost_secret(repo_with_ghost):
    from aegis.scanners.sast_scanner import SASTScanner

    result = await SASTScanner().scan(repo_with_ghost)
    ghosts = [f for f in result.findings if f.scanner == ScannerType.GIT_HISTORY]
    assert len(ghosts) == 1
    assert TG_TOKEN not in result.model_dump_json()


def test_secret_patterns_fixed_and_masked():
    assert detect_secrets("x = 'sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2" + "'")[0][0] == "Stripe API Key"
    # old buggy character classes matched '|' and other noise
    assert detect_secrets("gh|_" + "a" * 36) == []
    assert [t for t, _ in detect_secrets(f'TOKEN = "{TG_TOKEN}"')] == ["Telegram Bot Token"]
    assert mask_secret(TG_TOKEN).startswith("7312") and TG_TOKEN not in mask_secret(TG_TOKEN)
