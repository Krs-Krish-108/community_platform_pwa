# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

WORKDIR /app

# System dependencies for cryptography / bcrypt
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user for security
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Fail fast on misconfiguration — settings validation runs at import time
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
