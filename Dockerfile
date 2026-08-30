FROM python:3.11-slim

# Install system dependencies (git is required for clone, curl for healthchecks)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Environment variables will be injected via docker-compose or run arguments
ENV PYTHONUNBUFFERED=1

# Expose API port for Webhooks
EXPOSE 8000

# Start FastAPI server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
