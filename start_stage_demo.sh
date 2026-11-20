#!/usr/bin/env bash
# Commit Guardian — 1-Click Offline Stage Demo Launcher (IVL Cup 2026)
# Runs the self-contained monolith on http://localhost:8000 with zero cloud/Wi-Fi dependency.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8000}"
URL="http://localhost:${PORT}"
BACKUP_VIDEO="${ROOT_DIR}/../Commit_Guardian_Stage_Backup_Demo_45s.mp4"

cd "$ROOT_DIR"

echo "============================================================"
echo "  Commit Guardian · Stage Monolith Launcher (Air-Gapped)"
echo "============================================================"

# Seed demo metrics only if the local SQLite database is currently empty
python3 scripts/seed_demo_data.py || true

# Reuse already-healthy local server if port is active
if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
  echo "[OK] Local monolith already running on ${URL}"
  if command -v open >/dev/null 2>&1; then
    open "${URL}"
  fi
  echo "Dashboard:     ${URL}/dashboard"
  echo "Backup video:  ${BACKUP_VIDEO}"
  exit 0
fi

echo "[1/2] Starting air-gapped monolith on ${URL} (ALLOW_CLOUD_LLM=false)..."
ENVIRONMENT=production \
ALLOW_CLOUD_LLM=false \
WEB_APP_URL="${URL}" \
CORS_ALLOW_ORIGINS="${URL},http://127.0.0.1:${PORT}" \
python3 -m uvicorn aegis_server.main:app --host 127.0.0.1 --port "${PORT}" &
SERVER_PID=$!

trap 'echo ""; echo "Stopping Commit Guardian (PID ${SERVER_PID})..."; kill "${SERVER_PID}" 2>/dev/null || true' INT TERM EXIT

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    echo "[2/2] Server healthy! Opening ${URL} ..."
    echo "Dashboard:     ${URL}/dashboard"
    echo "Backup video:  ${BACKUP_VIDEO}"
    if command -v open >/dev/null 2>&1; then
      open "${URL}"
    fi
    break
  fi
  sleep 0.5
done

wait "${SERVER_PID}"
