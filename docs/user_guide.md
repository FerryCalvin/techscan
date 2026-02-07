# TechScan User Guide

TechScan is a comprehensive web technology scanner designed to identify, analyze, and monitor the technologies powering websites. This guide explains how to use the dashboard, manage stored data, and leverage the reporting tools.

## 🌟 Key Features

- **Unified Scanning**: Combines fast heuristic checks with deep browser-based analysis (Puppeteer) to detect technologies invisible to standard scrapers.
- **Bulk Operations**: Scan hundreds of domains simultaneously and export results.
- **Technology Deduplication**: Smartly merges duplicate detections (e.g., "PWA" vs "Progressive Web App") for clean reporting.
- **Analytics Dashboard**: Real-time insights into technology trends, server uptime, and scan performance.
- **Historical Tracking**: Monitor how a website's technology stack changes over time.

---

## 🖥️ Feature Overview

TechScan is organized into several key modules accessible via the navigation bar:

### 1. Dashboard (Lookup)
The entry point for all operations.
- **Single Scan**: Enter a URL (e.g., `example.com`) to scan immediately.
- **Unified Pipeline**: The engine automatically runs an adaptive "Unified" scan (combining headers, HTML, and browser-based checks) to ensure maximum detection accuracy without manual configuration.

### 2. Websites (Storage & Management)
Navigate to `/websites` to view your entire database of scanned domains.
- **Search & Filter**: Find specific domains or filter by status.
- **Domain Details**: Click any domain to view its full profile:
    - **Tech Stack**: List of all detected technologies with versions.
    - **Evidence**: Click the "Info" icon next to any tech to see *proof* (e.g., specific script tag, cookie name, or global JS variable).
    - **Export**: Download the domain's data.

### 3. Technology Search
Navigate to `/technology` to perform "reverse lookups".
- **Concept**: Instead of asking "What tech does this site use?", ask "Which sites use this tech?".
- **Usage**: Search for "Nginx", "React", or "Shopify".
- **Result**: Get a list of all domains in your database matching that technology.

### 4. History
Navigate to `/history` to see the global timeline of scanning activity.
- **Timeline**: View all scan jobs (single and bulk) in chronological order.
- **Changes**: Track when new scans were performed and if they were successful.

### 5. Stats (Analytics)
Navigate to `/stats` for high-level data visualization.
- **Top Technologies**: Bar charts showing the most popular tech across your dataset.
- **Category Breakdown**: Pie charts showing the distribution of CMS, Web Servers, JavaScript Frameworks, etc.
- **Performance**: Monitor scan throughput (domains/minute) and success rates.

### 6. Reports
Navigate to `/report` for an interactive, drill-down executive report.
- **Hierarchical View**: Browse data by Category -> Technology -> Website.
- **Drill-Down**:
    1. Click a Category (e.g., "CMS") to see top CMSs.
    2. Click a Technology (e.g., "WordPress") to see detailed usage stats.
    3. Click "Websites" to see the actual list of domains using it.

---

## 🔍 Scanning Guide

### Single Scan
1. Navigate to the **Dashboard**.
2. Enter a domain (e.g., `unair.ac.id`) in the input box.
3. Click **Scan Now**. Results will appear shortly.

### Bulk Scan
1. Go to the **Websites** page or use the Bulk Scan panel on the Dashboard.
2. **Upload CSV/TXT**: Upload a text file with one domain per line.
3. **Pasting**: Paste a list of domains directly into the text area.
4. Click **Start Bulk Scan**. The system will process the queue sequentially.

---

## ⚡ API Usage for Users

Automate your workflow using the REST API.

### 1. Start a Single Scan
**Endpoint**: `POST /scan`
```bash
curl -X POST http://localhost:5000/scan \
     -H "Content-Type: application/json" \
     -d '{"domain": "example.com"}'
```

### 2. Start a Bulk Scan
**Endpoint**: `POST /bulk`
```bash
curl -X POST http://localhost:5000/bulk \
     -H "Content-Type: application/json" \
     -d '{"domains": ["example.com", "google.com"]}'
```

### 3. Get Domain Details
**Endpoint**: `GET /api/domain/example.com/detail`
Returns the latest scan results, calculated differences, and normalized technology lists.

### 4. Search Domains by Tech
**Endpoint**: `GET /api/tech/Nginx/sites`
Returns a list of all domains detected running Nginx.
