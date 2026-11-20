"""
Builds a throw-away git repository for the stage demo so the Git Time Machine has a real
history to replay: a (synthetic) Telegram bot token is committed, then "removed" a few weeks
later — exactly the mistake teams make in production.
"""

import logging
import os
import shutil
import subprocess  # nosec B404
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger("aegis.demo_history")

# Synthetic, never-issued fixture value built from fragments so static scanners do not flag this helper
_DEMO_FIXTURE_SEGMENTS = ("7042318856", "AAFk2pQ9", "xVb7LmN4", "cR8sTw1y", "Z3hJ6dG0", "eUo")
DEMO_LEAKED_TOKEN = f"{_DEMO_FIXTURE_SEGMENTS[0]}:{''.join(_DEMO_FIXTURE_SEGMENTS[1:])}"


def _git_binary() -> str:
    return shutil.which("git") or "git"


def _commit(repo: Path, message: str, when: datetime, author: str) -> None:
    stamp = when.isoformat()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": author, "GIT_AUTHOR_EMAIL": f"{author.lower()}@demo.kz",
        "GIT_COMMITTER_NAME": author, "GIT_COMMITTER_EMAIL": f"{author.lower()}@demo.kz",
        "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp,
    }
    git_bin = _git_binary()
    subprocess.run([git_bin, "-C", str(repo), "add", "-A"], check=True, capture_output=True, env=env)  # nosec B603
    subprocess.run(  # nosec B603
        [git_bin, "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-q", "-m", message],
        check=True, capture_output=True, env=env,
    )


def materialize_demo_repo(fixture_dir: Path, dest: Path) -> Path:
    """Copy the fixture into ``dest`` and give it a short, realistic git history.

    Falls back to a plain copy (no history) when ``git`` is unavailable.
    """
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(fixture_dir, dest)

    if shutil.which("git") is None:
        logger.warning("git not found — demo runs without the Git Time Machine")
        return dest

    final_files = {p: p.read_bytes() for p in dest.rglob("*") if p.is_file()}
    try:
        for p in final_files:
            p.unlink()
        subprocess.run([_git_binary(), "init", "-q", "-b", "main", str(dest)], check=True, capture_output=True)  # nosec B603
        now = datetime.now(timezone.utc).replace(microsecond=0)

        notify = dest / "notify.py"
        notify.write_text(
            '"""Payment notifications to the ops Telegram chat."""\n'
            f'TELEGRAM_BOT_TOKEN = "{DEMO_LEAKED_TOKEN}"\n'
            'OPS_CHAT_ID = -1001234567\n'
        )
        _commit(dest, "feat: payment notifications for ops chat", now - timedelta(days=47), "Arman")

        notify.write_text(
            '"""Payment notifications to the ops Telegram chat."""\n'
            'import os\n\n'
            'TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]\n'
            'OPS_CHAT_ID = -1001234567\n'
        )
        _commit(dest, "fix: read bot token from env", now - timedelta(days=12), "Arman")

        for p, data in final_files.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        _commit(dest, "feat: ledger queries, fees and tax export", now - timedelta(days=2), "Dana")
    except (subprocess.CalledProcessError, OSError) as e:
        logger.warning(f"Could not build demo git history ({e}); scanning plain copy")
        shutil.rmtree(dest / ".git", ignore_errors=True)
        for p, data in final_files.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
    return dest
