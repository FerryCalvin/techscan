# TechScan Setup Guide

This guide covers the installation, configuration, and deployment of TechScan.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:
- **Python 3.10+** (Required for the backend)
- **Node.js 18+** (Required for the unified scanner and icon assets)
- **PostgreSQL 14+** (Recommended for production; optional for testing)

---

## 🛠️ Installation

### 1. Clone various Repositories
```bash
git clone https://github.com/yourusername/techscan.git
cd techscan
```

### 2. Python Environment Setup
Create a virtual environment to isolate dependencies.

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Node.js Dependencies
Install the required Node.js packages for the unified scanner and technology icons.

```bash
cd node_scanner
npm install
cd ..
```

---

## ⚙️ Configuration

Create a `.env` file in the root directory. You can copy the example file:
```bash
cp .env.example .env
```

### 1. Database Configuration
Control how TechScan connects to its persistence layer.

| Variable | Description | Default |
|----------|-------------|---------|
| `TECHSCAN_DISABLE_DB` | Set to `1` to run in "in-memory" mode without PostgreSQL. | `0` |
| `TECHSCAN_DB_URL` | Full PostgreSQL connection string (overrides individual components). | `None` |
| `TECHSCAN_DB_HOST` | Database hostname. | `127.0.0.1` |
| `TECHSCAN_DB_PORT` | Database port. | `5432` |
| `TECHSCAN_DB_NAME` | Database name. | `techscan` |
| `TECHSCAN_DB_USER` | Database username. | `postgres` |
| `TECHSCAN_DB_PASSWORD` | Database password. | `None` |
| `TECHSCAN_ALLOW_EMPTY_DB_PASSWORD` | Set to `1` to allow empty passwords (dev only). | `0` |
| `TECHSCAN_DB_POOL_SIZE` | Max connections in the pool. | `10` |

### 2. Logging
Configure application verbosity and output format.

| Variable | Description | Default |
|----------|-------------|---------|
| `TECHSCAN_LOG_LEVEL` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). | `INFO` |
| `TECHSCAN_LOG_FORMAT` | Log format: `text` (human-readable) or `json` (structured). | `text` |
| `TECHSCAN_LOG_FILE` | Path to log file (if file logging is desired). | `None` |
| `TECHSCAN_LOG_MAX_BYTES` | Max size of log file before rotation. | `5242880` (5MB) |
| `TECHSCAN_LOG_BACKUP_COUNT` | Number of backup log files to keep. | `5` |

### 3. Scanning Engine
Fine-tune the behavior of the unified scanner and Wappalyzer integration.

| Variable | Description | Default |
|----------|-------------|---------|
| `WAPPALYZER_PATH` | Custom path to Wappalyzer installation. | `./node_scanner/node_modules/wappalyzer` |
| `TECHSCAN_NODE_CONCURRENCY` | Number of concurrent Node.js processes for deep scans. | `3` |
| `TECHSCAN_PERSIST_BROWSER` | Set to `1` to keep browser instance open (faster scans). | `1` |
| `TECHSCAN_PERSIST_TIMEOUT` | Idle timeout for persistent browser (seconds). | `70` |
| `TECHSCAN_UNIFIED` | Enable the unified scanning pipeline (Heuristic + Deep). | `1` |
| `TECHSCAN_FORCE_FULL` | Force deep scan even if heuristic finds technologies. | `1` |
| `TECHSCAN_UNIFIED_MIN_TECH` | Minimum technology count to accept before falling back to deep scan. | `25` |
| `TECHSCAN_VERSION_AUDIT` | Enable checking versions against `latest_versions.json`. | `1` |
| `TECHSCAN_DEEP_FULL_TIMEOUT_S` | Max duration for a deep browser scan (seconds). | `15` |
| `TECHSCAN_FAST_FULL_TIMEOUT_MS` | Max duration for simple heuristic checks (ms). | `10000` |

### 4. Background Jobs (Weekly Rescan)
Configure the automated rescanning of tracked domains.

| Variable | Description | Default |
|----------|-------------|---------|
| `TECHSCAN_WEEKLY_RESCAN` | Enable weekly rescan job (`1` = yes). | `1` |
| `TECHSCAN_WEEKLY_RESCAN_CRON` | Cron schedule for the job. | `0 3 * * 0` (Sun 3AM) |
| `TECHSCAN_WEEKLY_RESCAN_MAX` | Max number of domains to rescan per run. | `2000` |
| `TECHSCAN_WEEKLY_RESCAN_CONCURRENCY`| Number of concurrent threads for rescan. | `3` |

### 5. Rate Limiting & Networking
Protect the application and manage network behavior.

| Variable | Description | Default |
|----------|-------------|---------|
| `TECHSCAN_RATE_LIMIT` | Global rate limit for API endpoints. | `60 per minute` |
| `TECHSCAN_REDIS_URL` | Redis URL for rate limit storage/caching. | `None` (Use Memory) |
| `TECHSCAN_CACHE_ENABLED` | Enable Redis caching of scan results. | `0` |
| `TECHSCAN_CACHE_TTL` | Cache duration in seconds. | `3600` (1 hour) |
| `TECHSCAN_PREFLIGHT` | TCP check on port 443/80 before full scan. | `1` |
| `TECHSCAN_DNS_NEG_CACHE` | Negative DNS cache TTL (seconds). | `600` |

### 6. Admin & Security
Access control and security headers.

| Variable | Description | Default |
|----------|-------------|---------|
| `TECHSCAN_ADMIN_TOKEN` | Secret token required for `/admin` API endpoints. | `None` |
| `TECHSCAN_ADMIN_OPEN` | Set to `1` to disable admin auth (Dev Only!). | `0` |
| `TECHSCAN_CSP` | Custom Content-Security-Policy header value. | `None` |

### 7. Maintenance
Data retention policies.

| Variable | Description | Default |
|----------|-------------|---------|
| `TECHSCAN_CLEANUP_ENABLED` | Enable auto-deletion of old records. | `0` |
| `TECHSCAN_CLEANUP_DAYS` | Age of records to delete (days). | `90` |
| `TECHSCAN_CLEANUP_INTERVAL_HOURS` | Frequency of cleanup check (hours). | `24` |

---

## 🗄️ Database Setup

If you are using PostgreSQL:

1. **Create the Database**:
   ```sql
   CREATE DATABASE techscan;
   CREATE USER techscan_user WITH PASSWORD 'secure_password';
   GRANT ALL PRIVILEGES ON DATABASE techscan TO techscan_user;
   ```

2. **Run Migrations (Optional)**:
   The application will automatically create tables on startup if they don't exist. You can also seed initial data using:
   ```bash
   python scripts/seed_db.py
   ```

---

## 🚀 Running the Application

### Start the Flask Backend
```bash
python run.py
```
The dashboard will be available at [http://localhost:5000](http://localhost:5000).

### Using the Node.js Scanner
The unified scanner automatically invokes Node.js scripts. However, for debugging or standalone usage, you can run:

```bash
cd node_scanner
node scanner.js --url https://example.com
```

---

## 🐳 Docker Deployment

For containerized deployment, use the provided `Dockerfile` and `docker-compose.yml`.

```bash
docker-compose up --build -d
```
This will start the application and a PostgreSQL database container.
