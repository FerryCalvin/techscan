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

### Key Configuration Options

| Variable | Description | Default / Example |
|----------|-------------|-------------------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@localhost:5432/techscan` |
| `TECHSCAN_DISABLE_DB` | Run without a database (in-memory mode) | `0` (Set to `1` to enable) |
| `TECHSCAN_ADMIN_TOKEN` | Token for admin API actions | `changeme_in_production` |
| `TECHSCAN_PREFLIGHT` | Check TCP reachability before scanning | `1` (Enabled) |

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
