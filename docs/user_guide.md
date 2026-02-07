# TechScan User Guide

TechScan is a powerful web technology scanner designed to identify, analyze, and monitor the technologies powering websites. This guide explains how to use the dashboard, extensive scanning capabilities, and API.

## 🌟 Key Features

- **Unified Scanning**: Combines fast heuristic checks with deep browser-based analysis (Puppeteer) to detect technologies invisible to standard scrapers.
- **Bulk Operations**: Scan hundreds of domains simultaneously and export results.
- **Technology Deduplication**: Smartly merges duplicate detections (e.g., "PWA" vs "Progressive Web App") for clean reporting.
- **Analytics Dashboard**: Real-time insights into technology trends, server uptime, and scan performance.
- **Historical Tracking**: Monitor how a website's technology stack changes over time.

---

## 🖥️ Dashboard Overview

The dashboard is your central command center.

### 1. **Scan Panel**
- **Single Scan**: Enter a URL (e.g., `example.com`) to scan immediately.
- **Scan Mode**:
    - **Fast**: Quick HTTP header and HTML source analysis (~2s).
    - **Unified (Deep)**: Full browser rendering to execute JavaScript and detect dynamic assets (~15s).

---

## 🔍 Scanning Domains

### Single Scan
1. Navigate to the **Dashboard**.
2. Enter a domain (e.g., `unair.ac.id`) in the input box.
3. Click **Scan Now**.
4. Results will appear below, showing:
    - **Detected Technologies**: With versions and categories (e.g., *Nginx 1.18 - Web Server*).
    - **Confidence Score**: How certain the scanner is about the detection.
    - **Evidence**: Click the "Info" icon to see exactly *why* a tech was detected (e.g., specific script tag or cookie).

### Bulk Scan
1. Go to the **Websites** page or use the Bulk Scan panel on the Dashboard.
2. **Upload CSV/TXT**: Upload a file with one domain per line.
3. **Pasting**: Paste a list of domains directly into the text area.
4. Click **Start Bulk Scan**. The system will process them sequentially.

---

## 📊 Analytics & Reports

### Stats Page
- **Top Technologies**: Standard bar charts showing the most popular tech across all scanned domains.
- **Category Breakdown**: Pie charts showing the distribution of CMS, Web Servers, JavaScript Frameworks, etc.
- **Performance**: Monitor scan throughput (domains/minute) and success rates.

### Domain Detail
Click on any domain in the **Websites** list to view:
- **Current Stack**: The latest technology profile.
- **History**: A timeline of scans.
- **Diff View**: See exactly what changed between the last two scans (e.g., *Removed jQuery 1.12, Added jQuery 3.6*).

---

## ⚡ API Usage for Users

Automate your workflow using the REST API.

### 1. Start a Single Scan
**Endpoint**: `POST /scan`
```bash
curl -X POST http://localhost:5000/scan \
     -H "Content-Type: application/json" \
     -d '{"domain": "example.com", "mode": "unified"}'
```

### 2. Start a Bulk Scan
**Endpoint**: `POST /bulk`
```bash
curl -X POST http://localhost:5000/bulk \
     -H "Content-Type: application/json" \
     -d '{"domains": ["example.com", "google.com"], "mode": "fast"}'
```

### 3. Get Domain Details
**Endpoint**: `GET /api/domain/example.com/detail`
Returns the latest scan results, calculated differences, and normalized technology lists.

### 4. Search Domains by Tech
**Endpoint**: `GET /api/tech/Nginx/sites`
Returns a list of all domains detected running Nginx.
