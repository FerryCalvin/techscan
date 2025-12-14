# Docker deployment

This repo includes a production-ready Dockerfile and a docker-compose example to run the app with Postgres and Redis.

## Build and run locally

1) Build image

    docker build -t techscan-web .

2) Start stack (app + Postgres + Redis)

    docker compose up -d

The app listens on http://localhost:8000.

## Environment variables

- TECHSCAN_DB_URL: Postgres connection string (compose sets this for you)
- TECHSCAN_REDIS_URL: Redis URL for the rate limiter (compose sets this)
- TECHSCAN_PERSIST_BROWSER: 1 to enable the persistent Puppeteer daemon (default in image)
- TECHSCAN_DISABLE_PERSIST_AUTOSTART: set to 1 to prevent starting the daemon at app boot
- TECHSCAN_LOG_LEVEL: INFO, DEBUG, etc.
- TECHSCAN_ADMIN_TOKEN: if set, admin endpoints require header X-Admin-Token

## Notes on the Node/Puppeteer scanner

The image includes Node.js and installs node_scanner dependencies at build time. On first install, Puppeteer downloads a compatible Chromium build. The Dockerfile also installs system libraries required by headless Chromium.

If you prefer to disable the persistent daemon, set:

- TECHSCAN_PERSIST_BROWSER=0
- TECHSCAN_DISABLE_PERSIST_AUTOSTART=1

## Nginx reverse proxy

A hardened Nginx config with secure headers is provided at docs/deployment/nginx-techscan.conf. Place it on your reverse-proxy host, update cert paths and server_name, and point upstream to the container’s exposed port (8000 by default).
