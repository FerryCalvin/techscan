# TechScan - Modern Web Technology Scanner

TechScan is a comprehensive web technology scanner that combines **heuristic detection**, **local pattern matching** (Wappalyzer-python), and **browser-based deep analysis** (Puppeteer) into a **Unified Scanning Pipeline**.

It provides a rich dashboard for visualizing technology trends, monitoring server health, and managing bulk scan operations.

![Dashboard](docs/assets/dashboard_preview.png)

## 🚀 Key Features

- **Unified Scanner**: Combines 3 engines (Heuristic, Python, Node.js) for maximum detection accuracy.
- **Bulk Scanning**: Scan hundreds of domains via UI or API with CSV export support.
- **Deep Analysis**: Detects DOM-based technologies (JS variables, CSS) invisible to simple scrapers.
- **Analytics Dashboard**: Real-time stats, uptime monitoring, and technology distribution charts.
- **Technology Deduplication**: Smartly merges duplicate detections (e.g., "PWA" vs "Progressive Web App").
- **API-First**: Full REST API for integration with other tools.

## 📂 Documentation

Detailed documentation is available in the `docs/` directory:

- [**Full Documentation**](docs/README_full.md) - Comprehensive guide.
- [**Technical Deep Dive**](docs/technical_deep_dive.md) - Architecture and implementation details.
- [**DB Configuration**](docs/db_configuration.md) - Database schema and setup.
- [**API Spec**](docs/openapi.yaml) - OpenAPI/Swagger specification.

## 🛠️ Installation

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** (for browser-based scanning)
- **PostgreSQL** (recommended for production)

### Quick Start (Local)

1. **Clone & Setup Python Environment**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. **Install Node.js Dependencies** (Required for Unified Scan)
   ```powershell
   cd node_scanner
   npm install
   cd ..
   ```

3. **Configure Environment**
   Create a `.env` file (see `.env.example`):
   ```ini
   TECHSCAN_DB_URL=postgresql://user:pass@localhost/techscan
   # Optional: Run without DB for testing
   # TECHSCAN_DISABLE_DB=1
   ```

4. **Run the Application**
   ```powershell
   python run.py
   ```
   Access the dashboard at `http://localhost:5000`.

## ⚡ API Usage

**Single Scan:**
```bash
curl -X POST http://localhost:5000/scan -H "Content-Type: application/json" -d '{"domain": "example.com", "full": true}'
```

**Bulk Scan:**
```bash
curl -X POST http://localhost:5000/bulk -H "Content-Type: application/json" -d '{"domains": ["example.com", "google.com"]}'
```

## 🏗️ Architecture

TechScan uses a tiered approach:
1. **Tier 0 (Heuristic)**: Fast HTTP check for headers/HTML patterns.
2. **Tier 1 (Wappalyzer-Local)**: Python-based regex matching.
3. **Tier 2 (Node-Puppeteer)**: Full browser render to execute JS and analyze DOM.

Results are aggregated, deduplicated, and stored in PostgreSQL.

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
