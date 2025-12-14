# TechScan

For complete setup, server configuration, deployment, and API details, see the full documentation: `docs/README_full.md`.

Documentation links:
- Full guide: `docs/README_full.md`
- API spec (OpenAPI): `docs/openapi.yaml`
- Documentation standards: `docs/CONTRIBUTING_DOCS.md`

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
	- `TECHSCAN_PREFLIGHT` fail-fast TCP reachability check (default `1`, disable only if your network blocks raw sockets)
	- `TECHSCAN_DNS_NEG_CACHE` seconds to cache unreachable DNS lookups (default `600`)
- Safety switches
	- `TECHSCAN_DISABLE_DB=1` run without a DB (persistence/search disabled)
- Background maintenance
	- `TECHSCAN_WEEKLY_RESCAN` enable weekly auto-rescans (default `1`)
	- `TECHSCAN_WEEKLY_RESCAN_MAX` cap domains per sweep (default `2000`)
	- `TECHSCAN_WEEKLY_RESCAN_LOOKBACK_DAYS` days since last scan to qualify domains (default `7`)
	- `TECHSCAN_WEEKLY_RESCAN_CRON` cron-style schedule (`m h * * dow`, default `0 3 * * 0` for Sunday 03:00 local time)
	- `TECHSCAN_WEEKLY_RESCAN_INTERVAL_S` fallback interval when cron spec invalid (default `604800` seconds)

## Rekomendasi Infrastruktur 1 Tahun

Paket di bawah ini sudah dipakai untuk perhitungan satu tahun ke depan (dengan asumsi ±400 domain yang discan ulang setiap bulan dan aktivitas harian ringan):

- **CPU**: 4 vCPU (sekitar 2 core fisik dengan hyper-threading). Cukup untuk Flask API, worker Node/Chromium, dan job bulanan. Jika antrean scan sering menumpuk, siapkan opsi upgrade ke 8 vCPU.
- **RAM**: 16 GB. Memberi ruang untuk Python app, Node worker (±4 GB), Postgres, serta cache OS. Naikkan ke 24–32 GB bila jumlah domain atau concurrency bertambah banyak.
- **Storage utama**: SSD 200 GB.
  - ±30 GB untuk OS + dependensi
  - `<1 GB` data scan + index selama 1 tahun
  - sisanya untuk log, backup, dan ruang tumbuh
- **Database (opsional terpisah)**: jika memakai managed Postgres atau volume khusus, siapkan SSD 100 GB—sudah sangat cukup untuk beberapa tahun.
- **Jaringan**: NIC 1 Gbps, siapkan IP publik statis atau load balancer dengan TLS. Perkiraan data keluar <25 GB/tahun.
- **Backup & pemeliharaan**: snapshot mingguan + incremental harian, uji restore tiap kuartal. Patch OS bulanan, pantau utilisasi CPU/RAM/DB.
- **Monitoring**: aktifkan Prometheus/Grafana (atau solusi setara), alert untuk antrean scan dan error Node worker. Evaluasi ulang setengah tahun jika domain atau traffic meningkat >2×.

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
- VS Code Pylance MCP: when registering the MCP server inside VS Code, choose **Auth type: None** (or start your MCP adapter with `--no-auth`). Otherwise VS Code will try to fetch `/.well-known/openid-configuration` from port 3048 and the connector will fail with the 401/404 errors shown above.

## Development notes

- App factory: `app:create_app()` (used by Gunicorn/process managers)
- Local dev loads `.env` via `python-dotenv` in `run.py` only. Production must use real env.
- Database schema is auto-ensured on startup when DB is enabled.

## License

This project’s license wasn’t specified. Add a LICENSE file if you intend to distribute publicly.

