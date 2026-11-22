"""
One-command deployer for Commit Guardian to Hugging Face Spaces (Docker, 16 GB RAM Free Tier).

Usage:
    python3 scripts/deploy_hf_space.py --space commit-guardian [--private]
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from huggingface_hub import HfApi

SPACE_README_TEMPLATE = """---
title: Commit Guardian
emoji: 🐋
colorFrom: slate
colorTo: red
sdk: docker
app_port: 7860
pinned: false
short_description: AI AppSec Auditor, Business-Logic Scanner & GitHub Auto-Fix
---

# Commit Guardian (Aegis Orca)

24/7 Cloud AI AppSec Auditor with 12 parallel security engines (Semgrep, Bandit, pip-audit, Python/JS/TS Taint, Next.js Server Actions, OSV SCA, AI Business-Logic Auditor for IDOR/Auth/SSRF/Race Conditions, Git Time Machine, Self-Healing Auto-Fix & Atomic GitHub PR).
"""

IGNORE_PATTERNS = [
    ".git",
    ".git/**",
    ".venv",
    ".venv/**",
    "venv/**",
    "__pycache__",
    "**/__pycache__/**",
    "*.pyc",
    "aegis_web/node_modules",
    "aegis_web/node_modules/**",
    "aegis_web/.next",
    "aegis_web/.next/**",
    "aegis_web/out",
    "aegis_web/out/**",
    "reports",
    "reports/**",
    "data",
    "data/**",
    "temp_scans",
    "temp_scans/**",
    "tests",
    "tests/**",
    ".env",
    ".env.*",
    "*.log",
    "*.zip",
    ".DS_Store",
    "README.md",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy Commit Guardian to Hugging Face Docker Space")
    parser.add_argument("--space", default="commit-guardian", help="Space slug (default: commit-guardian)")
    parser.add_argument("--private", action="store_true", help="Create a private Space")
    args = parser.parse_args()

    api = HfApi()
    try:
        user_info = api.whoami()
    except Exception as exc:
        print(f"ERROR: Not logged in to Hugging Face ({exc}). Run `hf auth login` first.", file=sys.stderr)
        return 1

    username = user_info.get("name") or user_info.get("fullname")
    repo_id = f"{username}/{args.space}" if "/" not in args.space else args.space
    repo_root = Path(__file__).resolve().parent.parent

    print(f"Creating/ensuring Docker Space: https://huggingface.co/spaces/{repo_id} ...")
    api.create_repo(
        repo_id=repo_id,
        repo_type="space",
        space_sdk="docker",
        private=args.private,
        exist_ok=True,
    )

    # Configure non-secret runtime env vars on the Space
    api.add_space_variable(repo_id=repo_id, key="ENVIRONMENT", value="production")
    api.add_space_variable(repo_id=repo_id, key="ALLOW_CLOUD_LLM", value="true")

    # Forward any cloud AI key present in local environment into Space Secrets (encrypted by HF)
    for provider, key_name, model_name, default_model in (
        ("gemini", "GEMINI_API_KEY", "GEMINI_MODEL", "gemini-2.5-flash"),
        ("openrouter", "OPENROUTER_API_KEY", "OPENROUTER_MODEL", "openai/gpt-4o-mini"),
    ):
        val = (os.environ.get(key_name) or "").strip()
        if val:
            api.add_space_secret(repo_id=repo_id, key=key_name, value=val)
            api.add_space_variable(repo_id=repo_id, key="LLM_PROVIDER", value=provider)
            api.add_space_variable(
                repo_id=repo_id,
                key=model_name,
                value=(os.environ.get(model_name) or default_model).strip(),
            )
            print(f"Configured encrypted Space Secret `{key_name}` (provider={provider}).")

    # Upload Space README.md with Docker YAML frontmatter
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(SPACE_README_TEMPLATE)
        readme_tmp = Path(tf.name)
    try:
        api.upload_file(
            path_or_fileobj=str(readme_tmp),
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="space",
            commit_message="Configure Hugging Face Docker Space (port 7860)",
        )
    finally:
        readme_tmp.unlink(missing_ok=True)

    print(f"Uploading repository to Space {repo_id} ...")
    api.upload_folder(
        folder_path=str(repo_root),
        repo_id=repo_id,
        repo_type="space",
        ignore_patterns=IGNORE_PATTERNS,
        commit_message="Deploy Commit Guardian (12 scanners + 3D Orca + Auto-Fix & GitHub PR)",
    )

    slug_host = repo_id.replace("/", "-").replace("_", "-").lower()
    print(f"\nDONE! Space URL: https://huggingface.co/spaces/{repo_id}")
    print(f"Direct App URL:  https://{slug_host}.hf.space")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
