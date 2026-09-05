FROM node:18 AS frontend-builder
WORKDIR /app/aegis_web
COPY aegis_web/package*.json ./
RUN npm install
COPY aegis_web/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=frontend-builder /app/aegis_web/out ./aegis_web/out
COPY aegis/ ./aegis/
COPY bot/ ./bot/
COPY aegis_server/ ./aegis_server/
# Порт для Render/Railway
ENV PORT=8000 
CMD uvicorn aegis_server.main:app --host 0.0.0.0 --port $PORT
