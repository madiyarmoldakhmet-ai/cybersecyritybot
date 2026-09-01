<div align="center">

# 🦉 Aegis Engine
**Autonomous AI-DevSecOps Scanner & Auto-Remediation Tool**

[![Build Status](https://img.shields.io/github/actions/workflow/status/your-repo/aegis-engine/aegis-scan.yml?branch=main&style=flat-square)](https://github.com/your-repo/aegis-engine/actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/your-dockerhub/aegis-engine?style=flat-square)](https://hub.docker.com/r/your-dockerhub/aegis-engine)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg?style=flat-square)](https://www.python.org/downloads/)

</div>

Aegis Engine is an open-source, CLI-first, AI-driven DevSecOps scanner. It combines the speed of traditional SAST/DAST/SCA scanners with the intelligence of LLMs to not only find vulnerabilities but also **automatically fix them**.

## ✨ Features
- **Zero-Data-Leak (Local AI):** Run entirely locally using Ollama. Your source code never leaves your machine.
- **Auto-Remediation:** Aegis doesn't just complain; it writes the secure code for you.
- **Hybrid Scanning:** SAST (Semgrep, Bandit), DAST (Playwright), SCA (OSV API), and Secret Scanning via RegEx.
- **AI False-Positive Filter:** Smart LLM filtering reduces noise and ignores mock tokens or test API keys.
- **Enterprise PDF Reports:** Export gorgeous, detailed PDF security audits.

## 🚀 Quick Start (60 Seconds)

### Using Docker (Recommended)
```bash
# Scan a local repository
docker run -v $(pwd):/app aegis-engine scan /app --deep --autofix
```

### Using Python (CLI)
```bash
git clone https://github.com/your-repo/aegis-engine.git
cd aegis-engine
pip install -r requirements.txt

# Run the scanner
python -m aegis.cli scan ./my-vulnerable-app
```

## 🛠️ Commands

- `python -m aegis.cli scan <path>`: Run the fast DevSecOps pipeline.
- `python -m aegis.cli scan <path> --deep`: Run the deep AI pentest (Aegis Agent).
- `python -m aegis.cli scan <path> --autofix`: Automatically generate fixes for findings.
- `python -m aegis.cli scan <path> --export-pdf`: Export results to an Enterprise PDF.

## 🔐 Zero-Data-Leak Configuration
To use Aegis locally with Ollama (e.g., `qwen2.5-coder:7b`):
1. Install [Ollama](https://ollama.ai/)
2. Run `ollama run qwen2.5-coder:14b`
3. Configure your `.env`:
```env
USE_LOCAL_LLM=true
OLLAMA_BASE_URL=http://localhost:11434
```

## 🤖 CI/CD Integration
Add Aegis to your GitHub Actions to scan every PR automatically:
Check out our `.github/workflows/aegis-scan.yml` example.

---
*Built with ❤️ for the Open Source Security Community.*