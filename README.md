# AEGIS

Aegis is a CLI-first, open-source security scanner that combines SAST, SCA, and Secret Detection with false-positive filtering and automatic code remediation.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)

## Quick Start

```bash
# Install
git clone https://github.com/madiyarmoldakhmet-ai/aegis.git
cd aegis
pip install .

# Scan any project
aegis scan /path/to/your/project

# Scan + auto-fix vulnerabilities with AI
aegis scan . --autofix

# Export to SARIF (GitHub Security tab compatible)
aegis scan . --format sarif
```

## Features

- **SAST** — Static analysis via Bandit & Semgrep
- **SCA** — Dependency CVE scanning (pip-audit + OSV)
- **Secrets** — Regex-based detection of API keys, tokens, RSA keys
- **Taint Analysis** — Cross-file data flow tracking from source to sink
- **AI Filter** — LLM eliminates false positives by analyzing code context
- **Auto-Remediation** — AI writes secure code patches for every finding
- **Reporting** — SARIF Export, PDF Reports, Terminal UI

## CLI Reference

| Command | Description |
|---------|-------------|
| `aegis scan <path>` | Run full security scan (SAST + SCA + Secrets) |
| `aegis scan <path> --deep` | Deep AI-powered penetration test |
| `aegis scan <path> --autofix` | Scan + generate AI code fixes |
| `aegis scan <path> --export-pdf` | Export professional PDF report |
| `aegis scan <path> --format sarif` | Export SARIF for GitHub Security tab |
| `aegis scan <path> --format json` | Machine-readable JSON output |

## Configuration

### Environment Variables (`.env`)

```env
# LLM Provider: openrouter | gemini | ollama
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=anthropic/claude-sonnet-5

# Local AI
USE_LOCAL_LLM=false
OLLAMA_BASE_URL=http://localhost:11434
```

### Project Config (`.aegis.yml`)

Place this in the root of any project you scan:

```yaml
ignore_paths:
  - "tests/**"
  - "docs/**"
  - "migrations/**"

severity_threshold: MEDIUM

custom_rules:
  - id: no-prod-urls
    pattern: "https?://(?:prod|staging)\\."
    title: "Hardcoded production URL"
    severity: MEDIUM
    cwe: ["CWE-798"]

ai_filter: true
```

## License

MIT