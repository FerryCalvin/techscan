# syntax=docker/dockerfile:1.6

# --- Base image: Python runtime (Debian Slim) ---
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies (build and runtime)
# - curl/ca-certificates for downloads
# - git for optional admin update_tech endpoint (git pull)
# - libpq5 for psycopg runtime
# - nodejs + npm for the persistent Node scanner
# - Chromium dependencies required by Puppeteer (downloaded during npm ci)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates curl git \
    libpq5 \
    nodejs npm \
    # Chromium/Puppeteer deps
    fonts-liberation \
    libasound2 libatk-bridge2.0-0 libatk1.0-0 \
    libc6 libcairo2 libcups2 libdbus-1-3 libexpat1 \
    libglib2.0-0 libgtk-3-0 libnspr4 libnss3 \
    libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 \
    libx11-6 libx11-xcb1 libxcb1 libxcomposite1 \
    libxcursor1 libxdamage1 libxext6 libxfixes3 \
    libxi6 libxrandr2 libxrender1 libxss1 libxtst6 \
    libgbm1 \
 && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -ms /bin/bash appuser
WORKDIR /opt/techscan

# Copy dependency manifests early for better layer caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Install Node dependencies for the persistent scanner (this will download a compatible Chromium)
RUN npm ci --prefix node_scanner

# Expose app port
EXPOSE 8000

# Minimal runtime env defaults (can be overridden)
ENV TECHSCAN_PERSIST_BROWSER=1 \
    TECHSCAN_UNIFIED=1 \
    TECHSCAN_FORCE_FULL=1 \
    TECHSCAN_DISABLE_PERSIST_AUTOSTART=0 \
    TECHSCAN_LOG_LEVEL=INFO

# Ensure proper permissions for non-root execution
RUN chown -R appuser:appuser /opt/techscan
USER appuser

# Healthcheck (basic): hit /identify
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8000/identify || exit 1

# Run with Gunicorn
# Note: create_app() is the Flask factory in app/__init__.py
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "90", "app:create_app()"]
