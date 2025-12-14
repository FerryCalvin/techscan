# TechScan — Complete Documentation

TechScan is a web application for scanning websites/domains, identifying technologies in use (name, version, categories, confidence), storing results, and visualizing insights via dashboards, search, and per-domain history. It combines a Python Flask backend with optional Node.js scanning helpers and a PostgreSQL database. This document provides a comprehensive guide for installation, configuration, database schema, APIs, UI, scanners, operations, and testing.

## Table of Contents
- Overview
- Architecture
- Installation
- Configuration
- Database Schema
- Scanning Pipeline
- REST API Reference
- Frontend UI
- Node Scanner
- Operations & Deployment
- Troubleshooting
- Testing & QA
- Diagnostics & Instrumentation
- Contributing

## Overview

- Purpose: Scan domains to detect web technologies, aggregate statistics, and provide interfaces for search and history.
- Core features:
  - Fast and full scans with heuristic + evidence + version audit phases
  - Aggregated statistics (totals, averages, timeseries, top technologies/categories)
  - Per-domain history and diff (added/removed/changed technologies)
  - Technology search with domain listings
  - Domain group management with CRUD APIs
  - Liquid-glass styled UI with tech stack icons

## Architecture

- Backend: Flask application with Blueprints; data access via `app/db.py`.
- Core modules: scanning engine, heuristics, evidence processing, version audit.
- Database: PostgreSQL storing `scans` and `domain_techs` (denormalized for aggregates).
- Frontend: Jinja2 templates under `app/templates` and static assets under `app/static`.
- Node.js: auxiliary scanner utilities (`node_scanner/`), and tech icons from `node_modules/tech-stack-icons`.

### Key Paths
- `app/__init__.py`: Application factory/registration of blueprints
- `app/routes/`: Flask Blueprints (`ui.py`, `scan.py`, `tech.py`, `search.py`, `system.py`, `admin.py`)
- `app/scan_utils.py`: Scanning orchestration, single-flight, deferred sets, stats mirror
- `app/evidence_utils.py`, `app/heuristic_fast.py`, `app/version_audit.py`: detection logic
- `app/domain_groups.py`: domain grouping and persistence to JSON
- `app/db.py`: DB utilities and fallback in-memory mirror
- `app/templates/`: UI pages (`dashboard.html`, `stats.html`, `websites.html`, `tech_search.html`, `history.html`, `_tech_modal.html`)
- `app/static/`: CSS/JS assets (`techscan.css`)
- `node_scanner/`: Node-based scanning helpers
- `data/`: domain groups and latest versions JSON
- `scripts/`: operational scripts and test runners
- `tests/`: pytest suites for API and integration

## Installation

### Prerequisites
- Python 3.x
- Node.js (for `node_scanner` and icons)
- PostgreSQL (recommended; app supports DB-disabled fallback for demos)

### Python Environment
1. Create and activate virtual environment.
2. Install dependencies.

```powershell
# From repo root
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Node Dependencies (optional but recommended)
```powershell
cd node_scanner
npm install
cd ..
```

### Database Setup
Provision a PostgreSQL instance and create a database/user. Ensure connectivity parameters are available as environment variables or configured in `app/db.py`.

Minimal schema aligned with queries (example DDL; adjust types/constraints as needed):

```sql
-- scans: latest 2 per domain used for diffs and history
CREATE TABLE IF NOT EXISTS scans (
  id               BIGSERIAL PRIMARY KEY,
  domain           TEXT NOT NULL,
  mode             TEXT NOT NULL,          -- 'fast' or 'full'
  started_at       TIMESTAMP WITH TIME ZONE,
  finished_at      TIMESTAMP WITH TIME ZONE,
  duration_ms      DOUBLE PRECISION,
  from_cache       BOOLEAN,
  retries          INTEGER,
  timeout_used     INTEGER,
  technologies_json JSONB,                 -- array of {name, version, categories, confidence}
  raw_json          JSONB,                 -- phases and raw evidence
  payload_bytes     BIGINT,
  error             TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_domain_finished ON scans(domain, finished_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_finished ON scans(finished_at);

-- domain_techs: denormalized for aggregates
CREATE TABLE IF NOT EXISTS domain_techs (
  domain     TEXT NOT NULL,
  tech_name  TEXT NOT NULL,
  version    TEXT,
  categories TEXT   -- comma-separated label string; can be empty/null
);

CREATE INDEX IF NOT EXISTS idx_domain_techs_tech ON domain_techs(tech_name);
CREATE INDEX IF NOT EXISTS idx_domain_techs_domain ON domain_techs(domain);
```

Populate initial data if needed using scripts in `scripts/` (e.g., `seed_db.py`, `backfill_counts.py`).

## Configuration

### Environment Variables
Common settings (actual variable names may be defined in `app/db.py` and app factory):
- `DATABASE_URL` or individual parameters (`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`)
- `APP_DEBUG` (optional) to enable debug logging
- `DB_DISABLED` (optional) to run in memory-only mode
- `TECHSCAN_PREFLIGHT` (default `1`) enables a TCP reachability probe before launching Node/Puppeteer scans so unreachable hosts fail fast instead of timing out for ~45s.
- `TECHSCAN_DNS_NEG_CACHE` (default `600`) caches negative DNS lookups for a few minutes so recurring unreachable domains are skipped quickly.

### App Settings
- The Flask app registers Blueprints in `app/__init__.py`. Ensure the desired routes are enabled.
- Icon path: `app/routes/ui.py` computes `_ICON_DIR` pointing to `node_modules/tech-stack-icons/icons`.
- Stats mirror: `app/scan_utils.py` exposes `STATS` and helpers used by `/api/stats` when DB is disabled.

### Running Locally

```powershell
# Start Flask app
python run.py
```

Optional: start Node scanner servers if your workflow uses them:

```powershell
cd node_scanner
node server.js
# or
node http_server.js
```

## Scanning Pipeline

- Phase 1 (Fast): quick detection using heuristic and evidence parsing; single-flight prevents duplicate inflight scans; stats updated.
- Enrichment & Merge: deduplication and confidence updates; bucket categories handled.
- Phase 2 (Full): deeper scans scheduled for targets requiring more analysis; can be deferred (background).
- Persist: write scans to `scans` table; denormalize to `domain_techs` for aggregates.

Key modules:
- `app/scan_utils.py`: orchestration, phases, deferred set, `_single_flight_map`, aggregate stats utilities.
- `app/evidence_utils.py`: evidence extraction and scoring.
- `app/heuristic_fast.py`: heuristic pattern detection.
- `app/version_audit.py`: version extraction from detected artifacts.

## REST API Reference

Unless noted, all endpoints are defined in `app/routes/ui.py`. Other Blueprints add scanning/admin/system/search endpoints.

- UI Pages:
  - `GET /` and `GET /dashboard` → Dashboard (`dashboard.html`)
  - `GET /websites` → Domain management (`websites.html`)
  - `GET /technology` → Tech search (`tech_search.html`)
  - `GET /history` → History page (`history.html`)
  - `GET /stats` → Stats page (`stats.html`)
  - `GET /index.html` → Redirect to dashboard

- Diagnostics:
  - `GET /_routes` → List all registered routes
  - `POST /_debug/report` → Log UI instrumentation payload to `tmp/debug_report.jsonl`

- Data & Aggregates:
  - `GET /api/stats` → Runtime + DB aggregates: totals, averages, top technologies/categories, payload size stats
  - `GET /api/performance_timeseries` → Hourly scans, avg confidence, success/timeout/error totals over last 24h
  - `GET /api/domains` → Distinct domains with latest scan meta (mode, tech_count, payload)
  - `GET /api/domain/<domain>/detail` → Latest two scans, diff (added/removed/changed), normalized technologies, phases metrics
  - `GET /api/domain/<domain>/history?limit=20&offset=0` → Paginated history for a domain (limit 1–200)
  - `GET /api/top_technologies` → Top technologies in last 30 days (name, categories, count, avg_conf)
  - `GET /api/tech/<tech_name>/domains` → Domains using a specific technology (limit 500)
  - `GET /api/category/<category_name>/technologies` → Technologies within a category; includes `uncategorized` bucket

- Domain Groups (in `app/routes/ui.py` and `app/domain_groups.py`):
  - `POST /admin/domain_groups/reload` → Reload groups from JSON
  - `GET /api/domain_groups` → Fetch groups & diagnostics
  - `POST /api/domain_groups` → Add new group (`{"group": "GroupName"}`)
  - `DELETE /api/domain_groups/<group>` → Delete group
  - `POST /api/domain_groups/<group>/assign` → Assign domain to group (`{"domain": "example.com"}`)
  - `POST /api/domain_groups/<group>/rename` → Rename group (`{"new": "NewName"}`)
  - `POST /api/domain_groups/<group>/remove` → Remove domain from group (`{"domain": "example.com"}`)
  - `GET /api/domain_groups/_diag` → Diagnostics info
  - `GET /api/domain_groups/_raw` → Raw JSON content of groups file

- Assets:
  - `GET /assets/tech-icons/<filename>` → Serve tech stack icons with robust filename normalization

Other blueprints provide additional routes (scan initiation, system health, tech catalog, search), see `app/routes/*.py`.

## Frontend UI

- Templates:
  - `dashboard.html`: Overview dashboard; distinct evidence modal styling
  - `stats.html`: Cards, charts, top lists; fetches `/api/stats` and `/api/performance_timeseries`
  - `websites.html`: Domain table, rescan actions, inflight tracking map; batch operations
  - `tech_search.html`: Tech search page; liquid-glass aesthetic; domain lists per technology
  - `history.html`: Per-domain history with pagination
  - `_tech_modal.html`: Tech information modal with icons and metadata
  - `admin_phases.html`, `index.html`
- Static:
  - `app/static/techscan.css` plus `app/static/css/` and `app/static/js/`
- Icons:
  - Served via `/assets/tech-icons/...` from `node_modules/tech-stack-icons/icons`

## Node Scanner

- Location: `node_scanner/`
- Files:
  - `scanner.js`, `server.js`, `http_server.js`: helpers for external scanning workflows
  - `domains.txt`: input targets
  - `tmp_inspect_output.json`: sample output for inspection
  - `package.json`, `package-lock.json`: dependencies
- Usage:
  - Optional servers to augment scanning with Node tooling
  - Integrate outputs with Python pipeline as needed

## Operations & Deployment

### Running
```powershell
# Flask app
python run.py

# Optional: Node servers
cd node_scanner; node server.js
```

### Docker (indicative)
- Use `Dockerfile` for building the app image.
- `docker-compose.yml` likely defines services (app + db). Inspect and set env vars accordingly.
- Persistent volumes for Postgres data recommended.

### Environment Management
- Configure DB connection via `DATABASE_URL` or discrete env vars.
- Use `DB_DISABLED=true` for demo mode without a DB.
- Ensure `node_modules/tech-stack-icons` installed to serve icons.

## Troubleshooting

- DB disabled: `/api/stats` and others return fallback aggregates; some features limited.
- Missing icons: check `_ICON_DIR` path in `app/routes/ui.py`; install `tech-stack-icons` package.
- Timeouts/errors: see `/api/performance_timeseries` and inspect `raw_json->phases`.
- Route discovery: `GET /_routes` for a JSON list of registered endpoints.
- UI debug: `POST /_debug/report` writes payloads to `tmp/debug_report.jsonl`.
- Slow scans + zero technologies: verify the host is reachable (`Test-NetConnection domain -Port 443`). With the default `TECHSCAN_PREFLIGHT=1` the API now returns an explicit error instead of a 40s "ok" row; disable the preflight only if your environment forbids raw TCP sockets.
- VS Code Pylance MCP: when adding the MCP server in VS Code, select **Auth type: None** (or start your MCP adapter with `--no-auth`). Otherwise the editor attempts to fetch `/.well-known/openid-configuration` and the handshake fails with the 401/404/"Multiple connections" errors shown in the logs.

## Testing & QA

- Python tests: `tests/` contains API/integration suites
```powershell
# Quick smoke
venv\Scripts\python.exe -m pytest -q
```

- Playwright smoke: `scripts/playwright_smoke.py`
- Additional scripts: `scripts/smoke_scan_test.py`, `scripts/test_*` utilities

## Diagnostics & Instrumentation

- Stats mirrors in `app/scan_utils.py` provide runtime metrics (uptime, cache, durations) used when DB is disabled.
- Domain diffs computed server-side in `/api/domain/<domain>/detail`.
- Logging configured via `app/logging_utils.py`; adjust levels as needed.

## Contributing

- Follow code style in existing modules; keep changes minimal and focused.
- Update documentation and tests where applicable.
- Use Blueprints for new routes; prefer SQL queries consistent with current schema.

---

For architecture diagrams, sample datasets, or a quickstart guide tailored to your environment, open an issue or request an extension to this documentation.
