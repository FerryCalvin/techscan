# TechScan

A fast, production-ready web technology scanner. TechScan detects technologies
running on websites (CMS, frameworks, JS libraries, servers) using a combination
of heuristic analysis and Wappalyzer-powered deep scanning.

## Features

- **Dual Scanning Modes**: Fast heuristic scanner + deep Wappalyzer-based detection
- **Modern Web UI**: Dashboard, websites management, technology search, scan history, and statistics
- **Weekly Auto-Rescan**: Automatic periodic scanning of all domains
- **Domain Groups**: Organize domains into custom groups
- **PostgreSQL Persistence**: Store scan results and technology history
- **Redis Integration**: Rate limiting and caching
- **REST API**: Full API access for automation
- **CSV Export**: Export scan results in bulk

## Technology Stack

- **Backend**: Python 3.12, Flask 3
- **Scanner**: Node.js 18+, Wappalyzer
- **Database**: PostgreSQL 13+ (optional)
- **Cache/Rate Limit**: Redis 6+ (optional)
- **Frontend**: Vanilla HTML/CSS/JS with glassmorphism UI

## Quick Start

### 1. Clone and Setup Environment

```bash
git clone https://github.com/FerryCalvin/techscan.git
cd techscan

# Create virtual environment
python -m venv venv

# Windows
./venv/Scripts/Activate.ps1

# Linux/Mac
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Install Node.js Scanner

```bash
cd node_scanner
npm install
cd ..
```

### 3. Configure Environment

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Essential variables:

```dotenv
# Database (required for persistence)
TECHSCAN_DB_HOST=127.0.0.1
TECHSCAN_DB_PORT=5432
TECHSCAN_DB_NAME=techscan
TECHSCAN_DB_USER=postgres
TECHSCAN_DB_PASSWORD=your_password

# Wappalyzer path
WAPPALYZER_PATH=/path/to/wappalyzer

# Admin token for protected endpoints
TECHSCAN_ADMIN_TOKEN=your_secret_token
```

### 4. Run the Application

```bash
python run.py
# Access at http://127.0.0.1:5000
```

## UI Pages

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Main scan interface with single/bulk scanning |
| Websites | `/websites` | View and manage all scanned domains |
| Technology Search | `/technology` | Search domains by technology |
| History | `/history` | Scan history with filtering |
| Statistics | `/stats` | System dashboard with charts and metrics |

## API Endpoints

### Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/scan?domain=example.com` | Scan a single domain |
| POST | `/bulk_scan` | Scan multiple domains |
| GET | `/bulk_scan?batch_id=xxx` | Get bulk scan results |
| GET | `/export_csv` | Export results as CSV |

### Domain Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/domains` | List all domains |
| GET | `/api/domain/{domain}/detail` | Get domain details |
| DELETE | `/api/domain/{domain}` | Delete a domain |

### Domain Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/domain_groups` | List all groups |
| POST | `/api/domain_groups` | Create a group |
| DELETE | `/api/domain_groups/{group}` | Delete a group |
| POST | `/api/domain_groups/{group}/assign` | Add domain to group |
| POST | `/api/domain_groups/{group}/remove` | Remove domain from group |

### Statistics & Metrics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Get system statistics |
| GET | `/api/top_technologies` | Top detected technologies |
| GET | `/api/performance/timeseries` | Scan performance data |
| GET | `/metrics/prometheus` | Prometheus metrics |

### Admin (requires `TECHSCAN_ADMIN_TOKEN`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/admin/cache/flush` | Flush cache |
| POST | `/admin/weekly_rescan/run` | Trigger weekly rescan |
| POST | `/admin/log_level` | Change log level |
| GET | `/admin/db/stats` | Database statistics |

## Environment Variables

See `.env.example` for complete documentation. Key variables:

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `TECHSCAN_DB_URL` | - | Full PostgreSQL URL |
| `TECHSCAN_DB_HOST` | `127.0.0.1` | Database host |
| `TECHSCAN_DB_PORT` | `5432` | Database port |
| `TECHSCAN_DB_NAME` | `techscan` | Database name |
| `TECHSCAN_DB_USER` | `postgres` | Username |
| `TECHSCAN_DB_PASSWORD` | - | Password (required) |
| `TECHSCAN_DISABLE_DB` | `0` | Set `1` to disable DB |

### Scanner

| Variable | Default | Description |
|----------|---------|-------------|
| `WAPPALYZER_PATH` | - | Path to Wappalyzer |
| `TECHSCAN_PERSIST_BROWSER` | `1` | Enable persistent browser |
| `TECHSCAN_UNIFIED` | `1` | Unified scan mode |
| `TECHSCAN_NODE_CONCURRENCY` | `3` | Concurrent Node scanners |

### Weekly Rescan

| Variable | Default | Description |
|----------|---------|-------------|
| `TECHSCAN_WEEKLY_RESCAN` | `1` | Enable weekly rescan |
| `TECHSCAN_WEEKLY_RESCAN_CRON` | `0 3 * * 0` | Cron schedule (Sunday 3AM) |
| `TECHSCAN_WEEKLY_RESCAN_MAX` | `2000` | Max domains per run |
| `TECHSCAN_WEEKLY_RESCAN_CONCURRENCY` | `3` | Concurrent scans |

### UI Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `TECHSCAN_STATS_AUTO_REFRESH` | `0` | Enable stats auto-refresh |
| `TECHSCAN_STATS_AUTO_REFRESH_INTERVAL_MS` | `300000` | Refresh interval (5 min) |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `TECHSCAN_ADMIN_TOKEN` | - | Token for admin endpoints (**required in production**) |
| `TECHSCAN_ADMIN_OPEN` | `0` | Set `1` to allow admin without token (dev only) |
| `TECHSCAN_CSP` | (default) | Custom Content-Security-Policy header |
| `TECHSCAN_UNIFIED_MIN_TECH` | `25` | Node fallback threshold |

### Database Cleanup

| Variable | Default | Description |
|----------|---------|-------------|
| `TECHSCAN_CLEANUP_ENABLED` | `0` | Enable scheduled cleanup |
| `TECHSCAN_CLEANUP_DAYS` | `90` | Retention period in days |
| `TECHSCAN_CLEANUP_INTERVAL_HOURS` | `24` | Cleanup interval |

## Production Deployment

### Using Gunicorn

```bash
gunicorn "app:create_app()" \
  --bind 0.0.0.0:8000 \
  --workers 4 \
  --threads 2 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
```

### Docker

```bash
docker-compose up -d
```

### Infrastructure Recommendations (1 Year)

| Resource | Recommendation |
|----------|----------------|
| CPU | 4 vCPU (scale to 8 if needed) |
| RAM | 16 GB minimum |
| Storage | SSD 200 GB |
| Database | Managed PostgreSQL or 100 GB SSD |
| Network | 1 Gbps, static IP |

## Project Structure

```text
techscan/
├── app/                    # Flask application
│   ├── routes/             # API endpoints
│   ├── templates/          # HTML templates
│   ├── static/             # CSS, JS, assets
│   ├── db.py               # Database layer
│   ├── scan_utils.py       # Scan logic
│   └── periodic.py         # Weekly rescan
├── node_scanner/           # Node.js Wappalyzer scanner
├── scripts/                # Utility scripts
├── tests/                  # Test suite
├── docs/                   # Documentation
├── data/                   # Data files
├── .env.example            # Environment template
├── requirements.txt        # Python dependencies
└── run.py                  # Development server
```

## Running Tests

```bash
# Run all tests
pytest -q

# Run without heavy tests
pytest -q -k "not playwright"
```

## Documentation

- [Full Guide](docs/README_full.md)
- [API Specification](docs/openapi.yaml)
- [Database Configuration](docs/db_configuration.md)
- [Contributing Guide](CONTRIBUTING.md)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "DB password required" | Set `TECHSCAN_DB_PASSWORD` or use `TECHSCAN_DB_URL` |
| Node scanner not found | Run `npm install` in `node_scanner/` |
| Rate limiter using memory | Set `TECHSCAN_REDIS_URL` for Redis backend |
| Weekly scan not running | Check `TECHSCAN_WEEKLY_RESCAN=1` |

## Security

- **Authentication**: Admin endpoints require `TECHSCAN_ADMIN_TOKEN` (secure by default)
- **SSRF Protection**: Private IPs and internal hostnames blocked
- **Security Headers**: CSP, X-Frame-Options, X-XSS-Protection, Referrer-Policy
- **Input Validation**: Domain length limits, dangerous character rejection
- **Rate Limiting**: Per-IP rate limiting with Redis support
- **CI Security**: Bandit and Ruff scans block builds on issues
- **No Hardcoded Secrets**: All credentials via environment variables

## License

MIT License - See [LICENSE](LICENSE) for details.

---

Built for Internship Project at Universitas Airlangga

---

# 📑 Laporan Detail Proyek (Untuk Presentasi)

Berikut adalah detail teknis dan manajerial proyek untuk dokumentasi dan bahan presentasi.

## 1. Identitas Proyek
*   **Judul**: TechScan: Sistem Pemindai dan Analisis Teknologi Web Berbasis Hybrid Machine Learning
*   **Instansi**: Universitas Airlangga
*   **Pengembang**: Ferry Calvin

## 2. Latar Belakang Masalah
*   **Visibilitas Aset IT yang Rendah**: Universitas Airlangga memiliki ratusan hingga ribuan subdomain (fakultas, departemen, unit kegiatan) yang terdesentralisasi. Sulit bagi tim IT pusat untuk mengetahui secara *real-time* teknologi apa saja yang digunakan di setiap unit.
*   **Deteksi Teknologi Konvensional Kurang Akurat**: Scanner berbasis *Regular Expression* tradisional sering gagal mendeteksi teknologi modern seperti *Single Page Application* (React, Vue, Svelte) yang kontennya di-render oleh JavaScript.
*   **Isu Keamanan & Kepatuhan**: Banyak website universitas yang mungkin menggunakan CMS atau plugin versi lama yang rentan, namun tidak terdeteksi karena kurangnya alat monitoring terpusat yang *scalable*.

## 3. Tujuan Proyek
1.  **Meningkatkan Akurasi Deteksi**: Membangun sistem yang mampu mendeteksi teknologi web modern dengan akurasi >90%, meminimalkan *false positives* (salah deteksi) yang sering terjadi pada scanner biasa.
2.  **Pemindaian Hibrida Cerdas**: Menggabungkan kecepatan deteksi statis dengan kedalaman analisis *machine learning* untuk hasil yang optimal.
3.  **Efisiensi Monitoring**: Menyediakan dashboard terpusat yang memungkinkan admin memantau distribusi teknologi, versi CMS, dan kesehatan aset web universitas secara *real-time*.

## 4. Teknologi yang Digunakan
*   **Backend**: Python 3.12 (Flask Framework) - Dipilih karena ekosistem *Machine Learning* yang kuat dan kemudahan pengembangan API.
*   **Scanner Engine**: Node.js 18+ & Wappalyzer Core - Untuk analisis dinamis berbasis *headless browser*.
*   **Machine Learning**:
    *   **Scikit-Learn**: Algoritma *Random Forest Classifier* untuk klasifikasi multi-label.
    *   **NumPy**: Komputasi numerik vektor fitur.
*   **Database**:
    *   **PostgreSQL**: Penyimpanan data relasional jangka panjang (persisten).
    *   **Redis**: Manajemen antrian *job* (Queue), caching hasil scan, dan *rate limiting*.
*   **Frontend**: Modern HTML5/CSS3 dengan desain *Glassmorphism*, responsif tanpa framework berat.
*   **Infrastructure**: Docker Containerization untuk kemudahan deployment.

## 5. Metodologi: Hybrid Detection System
Sistem ini menggunakan pendekatan **Hibrida 3-Lapis** untuk memastikan akurasi maksimal:

1.  **Static Analysis (Tier 1)**:
    *   Pencocokan pola cepat (*Regex*) pada kode sumber HTML dan HTTP Response Headers.
    *   Mendeteksi CMS umum (WordPress, Joomla) dan server web (Nginx, Apache).
2.  **Dynamic Analyis (Tier 2)**:
    *   Menggunakan *Headless Browser* untuk mengeksekusi JavaScript pada halaman.
    *   Mendeteksi variabel global JS (`window.React`, `window.Vue`) dan cookies spesifik.
3.  **Machine Learning Classification (Tier 3)**:
    *   Analisis probabilistik untuk pola yang ambigu.
    *   Mempelajari korelasi fitur samar (misal: struktur DOM spesifik, kombinasi script) untuk memprediksi teknologi yang disembunyikan atau tidak memiliki "signature" jelas.

## 6. Implementasi & Fitur Unggulan
*   **Intelligent Feature Extraction**: Modul ekstraksi fitur otomatis yang mengubah dokumen HTML menjadi vektor numerik untuk input ML (menghitung densitas script, rasio tag, pola meta).
*   **Anti-Overfitting ML**: Penerapan *Cross-Validation* (5-fold) dan *Regularization* ketat pada model Random Forest. Model dilatih untuk "skor nol" pada teknologi backend (DB) yang tidak terlihat, menghilangkan halusinasi deteksi.
*   **Auto-Healing Scan**: Jika mode cepat gagal mendeteksi teknologi kritis, sistem otomatis beralih ke mode *Deep Scan* (browser-based).
*   **API-First Design**: Seluruh fungsi pemindaian dapat diakses programatik via REST API, siap diintegrasikan dengan SIEM atau dashboard keamanan lain.

## 7. Hasil Pengujian
Pengujian dilakukan pada dataset sintetis dan *real-world* (domain `unair.ac.id` dan `youtube.com`):

*   **Akurasi Model**: 95.4% pada *Test Set*.
*   **Peningkatan Presisi**: Berhasil **menghilangkan 100% false positives** pada deteksi database (MySQL, PostgreSQL, Redis) yang sebelumnya salah terdeteksi oleh iterasi awal model.
*   **Cakupan Teknologi Baru**: Berhasil menambahkan dukungan deteksi akurat untuk teknologi:
    *   **Framework**: Svelte, Polymer.
    *   **Libraries**: Moment.js, Hammer.js, Swiper, LottieFiles.
    *   **Security/Ads**: reCAPTCHA, HSTS, Google Ads.
    *   **WordPress Ecosystem**: Elementor, Yoast SEO, WooCommerce.

## 8. Kendala & Solusi
| Kendala | Solusi yang Diterapkan |
| :--- | :--- |
| **Data Latih Terbatas** | Menggunakan *Synthetic Data Generation* dengan variasi acak untuk memperkaya dataset latih tanpa perlu ribuan scraping manual. |
| **False Positives** | Menambahkan 100+ sampel "negatif" (halaman yang *mirip* tapi *bukan* teknologi target) ke dalam data training untuk mengajarkan model perbedaan halus. |
| **Pemblokiran WAF** | Implementasi *Rate Limiting* adaptif dan *User-Agent Rotation* untuk menghindari pemblokiran IP saat scanning massal. |

## 9. Kesimpulan
TechScan berhasil dikembangkan sebagai solusi pemindaian teknologi web yang cerdas dan adaptif. Integrasi *Machine Learning* terbukti efektif menutup celah kelemahan scanner tradisional, terutama dalam menangani *false positives* dan teknologi modern. Sistem ini siap diimplementasikan sebagai alat pendukung utama bagi tim IT Universitas Airlangga untuk manajemen aset dan audit teknologi web yang berkelanjutan.
