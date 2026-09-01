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

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Aegis CLI is the default entrypoint
ENTRYPOINT ["python", "-m", "aegis.cli"]
CMD ["--help"]
