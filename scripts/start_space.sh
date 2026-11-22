#!/usr/bin/env bash
set -euo pipefail

# Start self-hosted Ollama daemon inside the 16 GB RAM Docker container
if command -v ollama >/dev/null 2>&1; then
  export OLLAMA_HOST="127.0.0.1:11434"
  export OLLAMA_MODELS="${HOME:-/home/guardian}/.ollama/models"
  mkdir -p "${OLLAMA_MODELS}"
  ollama serve >/tmp/ollama.log 2>&1 &

  # Pull lightweight CPU-friendly coding model in background when no cloud LLM key is configured
  (
    sleep 3
    if [ -z "${GEMINI_API_KEY:-}" ] && [ -z "${OPENROUTER_API_KEY:-}" ]; then
      MODEL_TO_PULL="${OLLAMA_MODEL:-qwen2.5-coder:1.5b}"
      echo "[start_space] Pulling self-hosted model ${MODEL_TO_PULL} in background..."
      ollama pull "${MODEL_TO_PULL}" >/tmp/ollama-pull.log 2>&1 || true
      echo "[start_space] Model ${MODEL_TO_PULL} ready!"
    fi
  ) &
fi

exec uvicorn aegis_server.main:app --host 0.0.0.0 --port "${PORT:-7860}"
