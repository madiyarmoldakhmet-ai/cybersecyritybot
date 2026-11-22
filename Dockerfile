FROM node:22-slim AS frontend-builder
WORKDIR /app/aegis_web
ENV NODE_OPTIONS="--max-old-space-size=1536"
COPY aegis_web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY aegis_web/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
# git: repository cloning for audits · fonts-dejavu-core: Cyrillic text in PDF audit reports
RUN apt-get update \
    && apt-get install -y --no-install-recommends git fonts-dejavu-core \
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
# Run as an unprivileged user; it owns only the directories the app writes to
RUN useradd --create-home --uid 10001 guardian \
    && mkdir -p /app/reports /app/data /app/temp_scans \
    && chown -R guardian:guardian /app/reports /app/data /app/temp_scans
USER guardian
ENV PORT=8000
CMD uvicorn aegis_server.main:app --host 0.0.0.0 --port $PORT
