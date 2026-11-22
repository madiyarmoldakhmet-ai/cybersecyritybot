FROM node:22-slim AS frontend-builder
WORKDIR /app/aegis_web
ENV NODE_OPTIONS="--max-old-space-size=1536"
COPY aegis_web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY aegis_web/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    HOME=/home/guardian \
    SEMGREP_SEND_METRICS=off \
    PORT=7860
# git: repo cloning · fonts-dejavu-core: Cyrillic PDF reports · curl/zstd: self-hosted Ollama binary
RUN apt-get update \
    && apt-get install -y --no-install-recommends git fonts-dejavu-core curl ca-certificates zstd \
    && curl -fsSL https://ollama.com/install.sh | sh \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements-prod.txt
COPY --from=frontend-builder /app/aegis_web/out ./aegis_web/out
COPY aegis/ ./aegis/
COPY bot/ ./bot/
COPY aegis_server/ ./aegis_server/
COPY web/ ./web/
COPY demo_targets/ ./demo_targets/
COPY scripts/ ./scripts/
COPY .aegis.yml ./
RUN chmod +x /app/scripts/start_space.sh \
    && useradd --create-home --uid 1000 guardian \
    && mkdir -p /app/reports /app/data /app/temp_scans /home/guardian/.cache /home/guardian/.ollama/models \
    && chown -R guardian:guardian /app/reports /app/data /app/temp_scans /home/guardian
USER guardian
EXPOSE 7860
CMD ["/app/scripts/start_space.sh"]
