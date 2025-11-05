# TechScan

Fast, production-ready web technology scanner. TechScan exposes a Flask API that detects technologies running on a domain (CMS, frameworks, JS libraries, servers), enriches results with heuristics, and optionally persists scans to Postgres. A Node.js Wappalyzer worker is used for deep/full scans; Redis can be used to back rate limits and caching.

## What’s inside

- Python 3.12, Flask 3 app factory (`app:create_app()`)
- Heuristic “fast” scanner + optional Node/Wappalyzer “full” scanner
- Optional Postgres persistence (psycopg 3) with light connection pooling
- Optional Redis backend for rate limiting/cache
- Test suite (pytest) and basic security linting (Bandit)

## Requirements

- Python 3.11+ (tested on 3.12)
- Node.js 18+ (required for the Wappalyzer worker in `node_scanner/`)
- Optional: PostgreSQL 13+ (for persistence and search endpoints)
- Optional: Redis 6+ (for rate limiting/cache)

## Quickstart (Windows PowerShell)

1) Create and activate a virtual environment, then install deps

```powershell
python -m venv venv
./venv/Scripts/Activate.ps1
pip install -r requirements.txt
```

2) Install Node.js deps for deep scans

```powershell
cd node_scanner
npm install
cd ..
```

3) Create a `.env` file (dev only; production must use real env/secret manager)

```dotenv
# Database (choose ONE of the two)
TECHSCAN_DB_URL=postgresql://user:password@host:5432/techscan
# or compose from parts
# TECHSCAN_DB_HOST=localhost
# TECHSCAN_DB_PORT=5432
# TECHSCAN_DB_NAME=techscan
# TECHSCAN_DB_USER=postgres
# TECHSCAN_DB_PASSWORD=your_password

# Admin token for /admin/* endpoints
TECHSCAN_ADMIN_TOKEN=change-me

# Optional Redis (for rate limiting/cache)
# TECHSCAN_REDIS_URL=redis://localhost:6379/0

# Where your node scanner lives (auto-detected by default)
# WAPPALYZER_PATH=./node_scanner
```

4) Run the API for local development

```powershell
python run.py
# App runs at http://127.0.0.1:5000
```

Try a quick scan:

```powershell
curl "http://127.0.0.1:5000/scan?domain=example.com&quick=1"
```

## Production run

Use Gunicorn with the app factory (set env vars via systemd/containers, not .env):

```bash
gunicorn "app:create_app()" --bind 0.0.0.0:8000 --workers 4 --threads 2 --timeout 120 --access-logfile - --error-logfile -
```

Tips
- Put Nginx in front for TLS and compression
- Provide `TECHSCAN_ADMIN_TOKEN` and DB vars via your secret manager
- For rate limiting at scale, set `TECHSCAN_REDIS_URL`

## Key environment variables

- Persistence (choose ONE)
	- `TECHSCAN_DB_URL` full URL (preferred)
	- or compose from: `TECHSCAN_DB_HOST`, `TECHSCAN_DB_PORT`, `TECHSCAN_DB_NAME`, `TECHSCAN_DB_USER`, `TECHSCAN_DB_PASSWORD`
- Admin
	- `TECHSCAN_ADMIN_TOKEN` required for `/admin/*`
- Rate limiting/cache
	- `TECHSCAN_REDIS_URL` optional Redis connection string
- Scanner
	- `WAPPALYZER_PATH` path to `node_scanner/` (auto-detected if not set)
- Safety switches
	- `TECHSCAN_DISABLE_DB=1` run without a DB (persistence/search disabled)

## Endpoints (high level)

- `GET /scan?domain=...&quick=1|0&deep=1|0` Run a scan
- `GET /tech?domain=...` Technology details and history (if DB enabled)
- `GET /ui/*` Lightweight UI pages (stats, results)
- `GET /metrics/prometheus` Basic Prometheus metrics
- Admin (token required in header `Authorization: Bearer <token>`)
	- `POST /admin/log_level` change log level
	- `POST /admin/cache/flush` flush cache
	- `GET /admin/db/stats` DB stats (if enabled)
	- `POST /admin/version/reload` refresh datasets

## Running tests

Use the provided VS Code Task, or run directly:

```powershell
# VS Code Task: "tests - run pytest quick smoke"
pytest -q
```

## Security checks (Bandit)

Bandit was run on the `app/` tree. Summary:

- High: 0
- Medium: 0
- Low: 101 (mostly try/except pass/continue patterns, subprocess usage, asserts in internal utilities, and non-crypto random for jitter)

Notes
- These Low findings are expected in several “best-effort” sections (background workers, cache, enrichment). We’ll progressively tighten or annotate with `# nosec` where appropriate.
- No secrets are hard-coded; DB credentials must come from environment variables only.

## Troubleshooting

- “DB password required”: ensure `TECHSCAN_DB_URL` or the composed parts are present before the app imports `app/db.py`.
- Node scanner not found: run `npm install` under `node_scanner/` and verify `WAPPALYZER_PATH`.
- Rate limiter using memory: set `TECHSCAN_REDIS_URL` to enable Redis backend.

## Development notes

- App factory: `app:create_app()` (used by Gunicorn/process managers)
- Local dev loads `.env` via `python-dotenv` in `run.py` only. Production must use real env.
- Database schema is auto-ensured on startup when DB is enabled.

## License

This project’s license wasn’t specified. Add a LICENSE file if you intend to distribute publicly.

