<div align="center">

<br>

<img src="https://img.shields.io/badge/AEGIS-Security_Scanner-0d1117?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiM1OGE2ZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMTIgMjJzOC00IDgtMTBWNWwtOC0zLTggM3Y3YzAgNiA4IDEwIDggMTB6Ii8+PC9zdmc+" alt="Aegis" />

# 🛡️ AEGIS

### Autonomous AI-Powered DevSecOps Engine

*Find vulnerabilities. Fix them automatically. Ship secure code.*

<br>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)
[![CI](https://img.shields.io/badge/CI%2FCD-GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)](.github/workflows/security-scan.yml)

<br>

<img width="700" src="https://github.com/user-attachments/assets/placeholder-terminal-demo.gif" alt="Aegis CLI Demo" />

<br>
<br>

**Aegis** is a CLI-first, open-source security scanner that combines traditional SAST, SCA, and Secret Detection with AI-powered false-positive filtering and automatic code remediation.

It doesn't just *find* the vulnerability — it *writes the fix* for you.

<br>

[Quick Start](#-quick-start) •
[Features](#-features) •
[How It Works](#-how-it-works) •
[CLI Reference](#-cli-reference) •
[CI/CD Integration](#-cicd-integration) •
[Configuration](#-configuration)

<br>

---

</div>

<br>

## ⚡ Quick Start

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

<br>

## 🔥 Features

<table>
<tr>
<td width="50%">

### 🔍 Multi-Engine Scanning
- **SAST** — Static analysis via Bandit & Semgrep
- **SCA** — Dependency CVE scanning (pip-audit + OSV)
- **Secrets** — Regex-based detection of API keys, tokens, RSA keys
- **Taint Analysis** — Cross-file data flow tracking from source to sink

</td>
<td width="50%">

### 🧠 AI-Powered Intelligence
- **Smart Filter** — LLM eliminates false positives by analyzing code context
- **Auto-Remediation** — AI writes secure code patches for every finding
- **Multi-LLM** — Works with Claude, Gemini, or local Ollama models
- **Zero Data Leak** — Run 100% locally with Ollama

</td>
</tr>
<tr>
<td width="50%">

### 📊 Enterprise Reporting
- **Security Score** — A+ to F grade with color-coded terminal card
- **SARIF Export** — GitHub Security tab integration out-of-the-box
- **PDF Reports** — Professional audit documents via ReportLab
- **shields.io Badges** — Embeddable score badges for README

</td>
<td width="50%">

### 🚀 DevOps Native
- **GitHub Action** — Drop-in `action.yml` for CI/CD pipelines
- **Docker** — Single container deployment
- **CLI-First** — Beautiful terminal UI with Rich progress bars
- **`.aegis.yml`** — Per-project configuration (ignore paths, rules, thresholds)

</td>
</tr>
</table>

<br>

## 🏗️ How It Works

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│              │    │              │    │              │    │              │
│  Your Code   │───▶│   Scanners   │───▶│  AI Filter   │───▶│   Results    │
│              │    │              │    │              │    │              │
│  .py .js ... │    │ SAST + SCA + │    │ LLM removes  │    │ Score Card + │
│              │    │ Secrets +    │    │ false         │    │ Table + PDF  │
│              │    │ Taint Engine │    │ positives     │    │ + SARIF      │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
                                                                   │
                                                                   ▼
                                                           ┌──────────────┐
                                                           │  Auto-Fixer  │
                                                           │              │
                                                           │ AI writes    │
                                                           │ secure code  │
                                                           └──────────────┘
```

<br>

## 🖥️ CLI Reference

| Command | Description |
|---------|-------------|
| `aegis scan <path>` | Run full security scan (SAST + SCA + Secrets) |
| `aegis scan <path> --deep` | Deep AI-powered penetration test |
| `aegis scan <path> --autofix` | Scan + generate AI code fixes |
| `aegis scan <path> --export-pdf` | Export professional PDF report |
| `aegis scan <path> --format sarif` | Export SARIF for GitHub Security tab |
| `aegis scan <path> --format json` | Machine-readable JSON output |

<br>

## 🔁 CI/CD Integration

### GitHub Actions (Recommended)

Drop this into `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  aegis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: madiyarmoldakhmet-ai/aegis-action@v1
        with:
          fail_on_critical: true
```

Results automatically appear in your repository's **Security → Code scanning** tab.

### Docker

```bash
docker build -t aegis .
docker run -v $(pwd):/scan aegis scan /scan --format sarif
```

<br>

## ⚙️ Configuration

### Environment Variables (`.env`)

```env
# LLM Provider: openrouter | gemini | ollama
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=anthropic/claude-sonnet-5

# Local AI (zero data leak)
USE_LOCAL_LLM=false
OLLAMA_BASE_URL=http://localhost:11434

# Telegram Bot (optional)
TELEGRAM_BOT_TOKEN=your-bot-token
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

<br>

## 🗂️ Project Structure

```
aegis/
├── cli.py                  # Typer CLI with Rich UI
├── core/
│   ├── config.py           # Settings & environment loader
│   ├── project_config.py   # .aegis.yml parser
│   ├── pr_creator.py       # GitHub PR auto-creation
│   └── queue_manager.py    # Async task queue
├── scanners/
│   ├── sast_scanner.py     # Bandit + Semgrep integration
│   ├── sca_scanner.py      # Dependency CVE scanning
│   ├── secret_scanner.py   # Regex-based secret detection
│   ├── taint_engine.py     # Cross-file data flow analysis
│   ├── ai_filter.py        # LLM false-positive filter
│   ├── auto_fixer.py       # AI code remediation
│   ├── security_score.py   # A+ to F scoring engine
│   ├── pdf_generator.py    # Enterprise PDF reports
│   └── models.py           # Pydantic data models
└── ai/
    └── remediation_engine.py
```

<br>

## 🔐 Zero Data Leak Mode

Run Aegis entirely offline using [Ollama](https://ollama.ai):

```bash
# 1. Install & start Ollama
ollama run qwen2.5-coder:14b

# 2. Configure .env
echo "USE_LOCAL_LLM=true" >> .env
echo "OLLAMA_BASE_URL=http://localhost:11434" >> .env

# 3. Scan — nothing leaves your machine
aegis scan . --autofix
```

<br>

## 📄 License

MIT © [Madiyar Moldakhmet](https://github.com/madiyarmoldakhmet-ai)

---

<div align="center">
<br>

**If Aegis helped you ship secure code, give it a ⭐**

<br>
</div>