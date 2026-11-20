# Commit Guardian 🔒

**Air-gapped on-premise AI AppSec platform for KZ Fintech & GovTech — 0 bytes sent to external clouds.**

Commit Guardian audits every commit, Pull Request, or ZIP upload within seconds: signed GitHub webhooks trigger multi-engine SAST + variable-level cross-file Taint tracking + **Git Time Machine** (deleted secrets still alive in commit history), deterministic **Art. 79 CoAP RK financial risk in tenge (`₸`)**, **Self-Healing with proof** (`AST patch → ast.parse → sandbox re-scan → rollback if unsafe`), Human-in-the-Loop FP appeals, and Compliance PDF/Markdown reports. Source code never leaves your servers.

| Verified Metric | Result |
|---|---|
| External Cloud Egress (`ALLOW_CLOUD_LLM=false`) | **0 bytes** (cloud keys stripped at startup) |
| Self-Scan Hygiene (`SASTScanner` on own repo) | **0 findings** across all severities |
| Automated Test Suite (`pytest tests/`) | **100+ unit & adversarial stress tests** |
| Stage Demo Audit (`demo/kz-fintech-app`) | **~4–5 s** (Semgrep + Bandit + AST Taint + Secrets + Git History + KZ IIN) |
| Verified Self-Healing Proof (`POST /api/scan/demo/heal`) | **Score F (0) → B/C (70)** · **17 → 4 findings** · **83.65M → 8.65M ₸** |
| Deployment | **1 command:** `docker compose up --build` (configurable `PORT`, `/health` check) |

```mermaid
flowchart LR
    A[git push / PR / ZIP] -->|HMAC SHA-256| B[Strict Ownership &<br/>Webhook Gate]
    B --> C[SAST · Taint AST · Secrets<br/>Git Time Machine · KZ IIN]
    C --> D[Python Risk Math<br/>Art. 79 CoAP RK ₸]
    C --> E[Self-Healing Sandbox<br/>AST → ast.parse → Re-scan]
    D --> F[Compliance PDF / MD<br/>Telegram · PR · /dashboard]
    E --> F
```

---

## 🏛 Gov Tech Benefits

| | |
|---|---|
| **Air-gapped by default** | All AI inference runs on a local Ollama model. Cloud providers (OpenRouter, Gemini) are **disabled unless `ALLOW_CLOUD_LLM=true` is set explicitly** — even if an API key is present in the environment, it is ignored. The dashboard and reports load nothing from the internet, so the whole system works inside a closed network. |
| **Compliance reporting** | Every audited commit — including clean ones — produces a timestamped Markdown + PDF report: repository, branch, commit hash, author, severity breakdown, every triggered SAST rule (file, line, CWE) and the AI's risk assessment. A durable audit trail for internal security reviews and regulators. |
| **Data sovereignty** | Code is cloned into a temporary directory, scanned and deleted. Reports, metrics (SQLite) and the model all stay on your infrastructure; no third-party SaaS is involved. |
| **Tamper-proof triggers** | GitHub webhooks are verified with HMAC SHA-256 (`hmac.compare_digest`). In `ENVIRONMENT=production`, unsigned webhooks are rejected outright. |
| **No human bottleneck** | Every push and pull request is audited automatically, 24/7, within the same pipeline — no waiting for a manual code review to catch leaked secrets or injections. |
| **SIEM-ready operations** | Structured logging with optional JSON output (`LOG_FORMAT=json`) and automatic masking of tokens and passwords in every log line. |

---

## ✨ Features

- **Commit Guardian webhook** — `push` and `pull_request` events, HMAC-verified, processed in a background queue, with automated Pull Request security comments when `GITHUB_TOKEN` is set.
- **Multi-engine SAST, Taint AST & Policy engine** — Semgrep, Bandit, pip-audit, entropy-checked secret masking, variable-level inter-procedural `TaintEngine`, mobile/Flutter rules, and `.aegis.yml` rules (`ignore_paths`, `severity_threshold`, `custom_rules` for 12-digit KZ IIN leaks, and `risk:` incident assumptions).
- **Git Time Machine (`git-history`)** — replays commit history (`git log -p`) to catch *ghost secrets* removed from `HEAD` but still recoverable, showing author, commit, and leak window in days.
- **Deterministic Financial Risk & ROI (`₸`)** — transparent Python model translating CWE/severity into Art. 79 CoAP RK regulatory fines (30–2,000 MRP, up to `8 650 000 ₸`) + incident exposure (`records_at_risk × cost_per_record_kzt`), plus an interactive team-size ROI calculator (`POST /api/v1/risk/roi`).
- **Self-Healing with proof (`POST /api/scan/demo/heal` · `aegis heal`)** — patches code in an isolated sandbox via AST fixers, validates syntax with `ast.parse()`, **re-scans** the patched copy, keeps only verified risk-reducing diffs, and rolls back any unsafe patch automatically.
- **Human-in-the-Loop Appeals & `F5` Persistence** — dispute false positives (`POST /api/v1/findings/appeal`) with instant deterministic `Security Score` recalculation, persistent SQLite audit log on `/dashboard`, and `localStorage` session recovery across browser refreshes.
- **Local AI analysis & strict `ast.parse()` post-validation** — false-positive filtering, executive summary in Russian, and CWE-aware remediation patches via local Ollama; any syntactically broken Python LLM patch is rejected automatically and replaced with a verified deterministic template.
- **Compliance reports & downloads** — `reports/<owner>__<repo>/<timestamp>_<commit>.md` and `.pdf` (Cyrillic-ready), downloadable directly from `/dashboard` or `/api/v1/reports/...` and delivered via Telegram.
- **Interactive web console & context-aware AI chat** — `/` (`aegis_web` Next.js obsidian console) with 1-click vulnerable fintech demo audit (`POST /api/scan/demo`), live WebSocket terminal, `Security Score (0–100 / A+..F)`, `/ws/chat` + `POST /api/chat` AppSec copilot with deterministic CWE/patch engine when Ollama is in standby, AI Patch diff modal, Auto-PR creation, and ZIP upload.
- **Strict Authorship Verification (`Проверка авторства`)** — `/api/v1/verify/challenge` & `/api/v1/verify/ownership` verify real GitHub write access (`push`/`admin`/`maintain` PAT check), signed challenge commits or `.well-known/aegis-verify.txt`, and DNS TXT `_aegis-challenge.<domain>` before unlocking private scans, DAST probes, or automated PRs via signed HMAC `proof_token`.
- **Google Colab GPU + 5 TB Google Drive runner** — [`notebooks/commit_guardian_colab_gpu.ipynb`](notebooks/commit_guardian_colab_gpu.ipynb) launches `qwen2.5-coder:32b`/`14b` on Colab GPU with Drive weight caching and exposes the live console over HTTPS.
- **Observability dashboard** — `GET /dashboard`: total scans, critical vulnerabilities found, average AI processing time, recent audits with PDF/MD links; auto-refreshes every 10 s without external CDN assets.
- **Telegram bot** — scan public GitHub repos or ZIP archives directly in Telegram and receive Security Score + attached Compliance PDF report.
- **DAST & GitHub Action** — HTTP security headers, CORS, cookie flags, Playwright XSS PoC, and SARIF upload to the GitHub Security tab (`action.yml`).

---

## 💼 B2B Model & Deployment Tiers (KZ Fintech / GovTech)

| Plan | Price | Scope |
|---|---|---|
| **Pilot (14 days)** | `0 ₸` | Docker setup in 15 min, 1–2 repos, Telegram alerts & PDF reports |
| **Team On-Premise** | `190 000 ₸ / mo` | Up to 25 developers, local Ollama, `.aegis.yml` PII rules, PR comments & SIEM logs |
| **Enterprise Air-Gapped** | Custom (from `650 000 ₸ / mo`) | Air-gapped perimeter deployment, custom compliance rules, SLA |

---

## 🚀 Quick Start

**Requirements:** Python 3.12+, Git, [Ollama](https://ollama.com).

```bash
git clone https://github.com/madiyarmoldakhmet-ai/cybersecyritybot.git
cd cybersecyritybot
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # then fill in TELEGRAM_BOT_TOKEN, GITHUB_WEBHOOK_SECRET, ...
ollama pull qwen2.5-coder:14b
uvicorn aegis_server.main:app --port 8000
```

Open **http://localhost:8000/dashboard**.

### Connect a repository

In the GitHub repository: **Settings → Webhooks → Add webhook**

| Field | Value |
|---|---|
| Payload URL | `https://<your-host>/api/v1/webhook/github` |
| Content type | `application/json` |
| Secret | the value of `GITHUB_WEBHOOK_SECRET` |
| Events | *Pushes* and *Pull requests* |

### Docker (1-Command Monolith)

```bash
cp .env.example .env
docker compose up --build          # PORT=8080 docker compose up --build for custom port
# Optional bundled Ollama sidecar:
docker compose --profile ollama up --build
```

Helper shortcuts via `Makefile`: `make run`, `make test`, `make self-scan`, `make web-build`, `make seed`, `make docker`.

The image bundles the frontend, API, Telegram bot, `git` and a Cyrillic font for PDF reports. Mount `reports/` and `data/` to keep audit reports and metrics across container restarts. See [DEPLOY.md](DEPLOY.md) for Railway / Render.

---

## ⚙️ Configuration

All settings are environment variables (see [`.env.example`](.env.example)). The most important:

| Variable | Default | Purpose |
|---|---|---|
| `ENVIRONMENT` | `development` | `production` makes `GITHUB_WEBHOOK_SECRET` mandatory |
| `GITHUB_WEBHOOK_SECRET` | — | HMAC secret shared with GitHub |
| `TELEGRAM_BOT_TOKEN` / `DEFAULT_TELEGRAM_CHAT_ID` | — | Bot and chat for alerts |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | `http://localhost:11434` / `qwen2.5-coder:14b` | Local model |
| `ALLOW_CLOUD_LLM` | `false` | Opt-in for OpenRouter/Gemini; keep `false` for air-gapped deployments |
| `SCAN_OUTPUT_DIR` | `./reports` | Where compliance reports are written |
| `REPORT_PDF_ENABLED` | `true` | PDF copy next to every Markdown report |
| `METRICS_DB_PATH` | `./data/commit_guardian.db` | SQLite metrics behind `/dashboard` |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `text` | `json` for SIEM ingestion |
| `CORS_ALLOW_ORIGINS` | — | Extra browser origins (wildcards are never allowed) |

---

## 🔌 API

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/webhook/github` | GitHub webhook receiver (push, pull_request, ping) |
| `POST` | `/api/scan/demo` | 1-click stage demo audit (with real Git Time Machine history + CoAP risk) |
| `POST` | `/api/scan/demo/heal` | Self-Healing sandbox: AST patch → `ast.parse` → re-scan → verified diffs |
| `POST` | `/api/scan/upload` | ZIP archive local scan + Compliance PDF generation |
| `POST` / `GET` / `DELETE` | `/api/v1/findings/appeal` | Human-in-the-Loop FP appeals with live Security Score recalculation |
| `POST` | `/api/v1/risk/roi` | Deterministic KZ ROI calculator vs in-house AppSec FTE |
| `GET` | `/dashboard` | Observability dashboard |
| `GET` | `/api/v1/dashboard/metrics` | Dashboard metrics as JSON |
| `GET` | `/api/v1/reports/{repo_slug}/{filename}` | Download persisted PDF / Markdown compliance report |
| `GET` | `/api/v1/metrics` | Queue and Ollama concurrency metrics |
| `GET` | `/health` | Health, Ollama connectivity, air-gap status |
| `POST` | `/api/chat` | HTTP AppSec chat fallback (context-aware offline & LLM) |
| `POST` | `/api/v1/verify/challenge` · `/api/v1/verify/ownership` | Strict GitHub/domain authorship challenges & HMAC proof tokens |
| `POST` | `/api/v1/scan/sast` · `/api/v1/scan/dast` · `/api/v1/remediate` | On-demand scans & remediation patches |

Interactive docs: `/docs`.

---

## 🛡 Security Model

- **Local-only AI policy** is enforced in configuration: without `ALLOW_CLOUD_LLM=true`, the provider is forced to Ollama and cloud keys are dropped at startup (logged as a warning).
- **Webhook authenticity** via HMAC SHA-256 with constant-time comparison; required in production.
- **Secrets never reach logs** — configured tokens, GitHub/OpenAI-style keys and credentials in clone URLs are masked by a logging filter.
- **Untrusted input handling** — repository names from webhooks are sanitised before being used in file paths and HTML-escaped on the dashboard; the dashboard ships a strict Content-Security-Policy.
- **No error detail leakage** — unhandled errors return an opaque `error_id`; details stay in the server log.
- **Ephemeral checkouts** — cloned code is deleted after every audit; a failed clone is reported as a failure, never as a clean scan.

---

## 🧪 Testing

```bash
pip install pytest pytest-asyncio
pytest
```

The suite covers the webhook pipeline end-to-end (with mocked scanners), report generation, the dashboard, metrics persistence and the hardening rules above.

---

## 📁 Project Structure

```
aegis/
  ai/            local AI: audit summaries, remediation
  core/          config & local-LLM policy, logging, queue, metrics store
  reporting/     Markdown + PDF compliance reports
  scanners/      SAST, secrets, mobile, DAST, AI false-positive filter
aegis_server/    production FastAPI app (Docker entrypoint)
web/             webhook receiver, dashboard, REST API
bot/             Telegram bot
aegis_web/       Next.js frontend
tests/           pytest suite
```

## 📝 License

MIT — see [LICENSE](LICENSE).

---

Built by [Madiyar Moldakhmet](https://github.com/madiyarmoldakhmet-ai) · madiyarmoldakhmet@gmail.com
