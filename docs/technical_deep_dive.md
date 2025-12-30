# TechScan Technical Deep Dive

Dokumen ini menjelaskan konsep-konsep teknis dalam TechScan untuk persiapan presentasi.

---

## 1. Mengapa Flask, bukan FastAPI atau Django?

### Perbandingan Framework

| Framework | Karakteristik | Kapan Digunakan |
|-----------|---------------|-----------------|
| **Flask** ✅ | Lightweight, flexible, minimal | API sederhana, prototipe cepat |
| **FastAPI** | Async native, auto OpenAPI docs | High-performance API, microservices |
| **Django** | Full-featured, ORM built-in | Web app kompleks, admin panel |

### Alasan Memilih Flask untuk TechScan:

1. **Lightweight** - Tidak butuh ORM bawaan (kita pakai raw SQL + psycopg)
2. **Flexible routing** - Blueprint untuk modular routes
3. **Template engine** - Jinja2 untuk render HTML dashboard
4. **Mature ecosystem** - Flask-Limiter, Flask-CORS tersedia
5. **Learning curve** - Lebih mudah dipelajari

### Lokasi File Terkait:
- `app/__init__.py` - App factory, Flask initialization
- `app/routes/*.py` - Blueprint routes

---

## 2. Concurrent Request, Connection Pooling, Single-Flight

### Apa itu Concurrent Request?
**Concurrent request** = beberapa request yang datang bersamaan dalam waktu yang hampir sama.

```
Waktu 0ms: User A request /scan?domain=unair.ac.id
Waktu 5ms: User B request /scan?domain=its.ac.id  
Waktu 8ms: User C request /scan?domain=unair.ac.id
```
Ketiga request ini **concurrent** (berjalan bersamaan).

### Apa itu Connection Pooling?

**Tanpa pooling:**
```
Request 1 → Buat koneksi DB → Query → Tutup koneksi
Request 2 → Buat koneksi DB → Query → Tutup koneksi  (lambat!)
Request 3 → Buat koneksi DB → Query → Tutup koneksi
```

**Dengan pooling:**
```
                  ┌─────────────────┐
Request 1 ──────►│  Connection     │──► Query ──► Return ke pool
Request 2 ──────►│     Pool        │──► Query ──► Return ke pool
Request 3 ──────►│  (10 koneksi)   │──► Query ──► Return ke pool
                  └─────────────────┘
```
Koneksi **di-reuse**, tidak perlu buat baru setiap request.

### Lokasi File:
- `app/db.py` (line ~167-173) - psycopg_pool initialization

```python
# app/db.py
_POOL = _PsycopgConnectionPool(conninfo=DB_URL, max_size=DB_POOL_SIZE)
```

### Apa itu Single-Flight Deduplication?

Kalau User A dan User C request domain yang sama (`unair.ac.id`) bersamaan:

**Tanpa single-flight:**
```
User A → Scan unair.ac.id (20 detik)
User C → Scan unair.ac.id (20 detik)  ← DUPLIKAT!
Total: 40 detik kerja
```

**Dengan single-flight:**
```
User A → Scan unair.ac.id (Leader)
User C → Tunggu hasil User A (Follower)
Total: 20 detik kerja, User C dapat hasil gratis
```

### Lokasi File:
- `app/scan_utils.py` (line ~101-150) - Single-flight guard

```python
# app/scan_utils.py
def _single_flight_enter(cache_key: str) -> bool:
    # Returns True if caller is leader, False if follower
```

---

## 3. Dual Scanner → Unified Engine

### Mengapa Ada Dua Scanner?

| Scanner | Kecepatan | Akurasi | Teknologi |
|---------|-----------|---------|-----------|
| **Heuristic** | ~500ms | 60-70% | Regex, HTTP headers |
| **Wappalyzer** | 5-30s | 90%+ | Puppeteer, 3000+ signatures |

### Bagaimana Digabung (Unified)?

```
Request: /scan?domain=unair.ac.id
           │
           ▼
┌─────────────────────────────────────┐
│  UNIFIED ENGINE (scan_unified)       │
├─────────────────────────────────────┤
│  1. Heuristic Quick Scan (500ms)    │ ← Cepat, basic detection
│  2. Synthetic Headers (200ms)       │ ← Server, CDN, HSTS
│  3. Wappalyzer Deep Scan (5-30s)    │ ← Full browser, JS execution
│  4. Merge & Dedupe Results          │ ← Gabungkan semua
│  5. Version Audit                   │ ← Cek versi outdated
└─────────────────────────────────────┘
           │
           ▼
     29 Technologies Detected
```

### Lokasi File:
- `app/scan_utils.py` → `scan_unified()` function (line ~960+)
- `app/heuristic_fast.py` → Heuristic scanner
- `node_scanner/scanner.js` → Wappalyzer wrapper

---

## 4. Try-Catch di Setiap Layer & Failure Stub

### Apa itu Try-Catch di Setiap Layer?

```python
# Layer 1: Route handler
@app.route('/scan')
def scan():
    try:
        result = scan_domain(domain)  # Layer 2
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Layer 2: Scan logic
def scan_domain(domain):
    try:
        data = call_wappalyzer(domain)  # Layer 3
    except TimeoutError:
        return fallback_heuristic(domain)

# Layer 3: External call
def call_wappalyzer(domain):
    try:
        result = subprocess.run(...)
    except Exception as e:
        raise RuntimeError(f'Wappalyzer failed: {e}')
```

Error di-handle di SETIAP level, tidak langsung crash.

### Apa itu Failure Stub Saved to DB?

Ketika scan gagal, kita tetap **simpan record ke database**:

```python
# app/scan_utils.py - _persist_failure_scan()
payload = {
    'domain': domain,
    'status': 'error',
    'error': 'Connection timeout',
    'technologies': [],  # Empty karena gagal
    'duration': 5.2
}
db.save_scan(payload)  # Tetap disimpan!
```

**Mengapa?**
- UI bisa tampilkan "scan failed" daripada kosong
- Tracking berapa kali domain gagal
- Debugging lebih mudah

### Lokasi File:
- `app/scan_utils.py` (line ~281-327) - `_persist_failure_scan()`
- `app/routes/scan.py` - Route-level try-catch

---

## 5. Unit Test dengan Pytest

### Apa itu Pytest?

**Pytest** = Framework testing Python yang populer. Lebih simpel dari `unittest` bawaan.

```python
# Contoh test dengan pytest
def test_validate_domain():
    assert validate_domain('unair.ac.id') == 'unair.ac.id'
    assert validate_domain('UNAIR.AC.ID') == 'unair.ac.id'  # lowercase
    
def test_invalid_domain():
    with pytest.raises(ValueError):
        validate_domain('not a domain!')
```

Jalankan: `pytest tests/`

### Apakah TechScan Punya Unit Test?

**Ya!** Lokasi: `tests/` folder

```
tests/
├── test_scan_utils.py    ← Test domain validation, normalize
├── test_heuristic.py     ← Test heuristic detection
├── test_db.py            ← Test database operations
└── conftest.py           ← Pytest fixtures
```

### CI Integration:
- File: `.github/workflows/ci.yml`
- Jalankan otomatis saat push ke GitHub

---

## 6. Apa itu Boilerplate?

### Definisi
**Boilerplate** = Kode standar yang berulang di setiap project, bukan logic unik.

### Contoh Boilerplate di TechScan:

```python
# 1. Import statements (boilerplate)
import os
import logging
from flask import Flask, jsonify

# 2. App initialization (boilerplate)
app = Flask(__name__)
app.config['SOME_SETTING'] = os.environ.get('SOME_SETTING', 'default')

# 3. Error handler (boilerplate)
@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# 4. Logging setup (boilerplate)
logging.basicConfig(level=logging.INFO)
```

### AI Membantu Generate Boilerplate
AI sangat efektif untuk:
- Setup project structure
- Config files (pyproject.toml, ci.yml)
- Error handling patterns
- Database connection setup

---

## 7. Peta Lengkap File TechScan

### REST API Endpoints

| Endpoint | File | Fungsi |
|----------|------|--------|
| `GET /scan` | `app/routes/scan.py` | Single domain scan |
| `POST /bulk_scan` | `app/routes/scan.py` | Batch scan |
| `GET /api/domains` | `app/routes/ui.py` | List all domains |
| `GET /api/stats` | `app/routes/stats.py` | Statistics |
| `GET /api/tech_search` | `app/routes/search.py` | Search by technology |
| `GET /admin/*` | `app/routes/admin.py` | Admin functions |

### Database Layer

| File | Fungsi |
|------|--------|
| `app/db.py` | PostgreSQL connection, CRUD operations |
| `app/db.py:get_conn()` | Get connection from pool |
| `app/db.py:save_scan()` | Persist scan results |
| `app/db.py:ensure_schema()` | Create tables if not exist |

### Redis Usage

| File | Fungsi |
|------|--------|
| `app/__init__.py` | Redis initialization untuk Flask-Limiter |
| `app/bulk_store.py` | Bulk scan result caching |

```python
# app/__init__.py (line ~50-60)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    storage_uri=os.environ.get('TECHSCAN_REDIS_URL', 'memory://')
)
```

### Scanner Engine

| File | Fungsi |
|------|--------|
| `app/scan_utils.py` | Unified scan engine, caching, stats |
| `app/heuristic_fast.py` | Fast regex-based detection |
| `app/wapp_local.py` | Python-side Wappalyzer rules |
| `node_scanner/scanner.js` | Node.js Wappalyzer wrapper |

### Frontend Templates

| File | Fungsi |
|------|--------|
| `app/templates/base.html` | Layout utama, navbar |
| `app/templates/dashboard.html` | Scan form + results |
| `app/templates/websites.html` | Domain list |
| `app/templates/tech_search.html` | Search by tech |
| `app/templates/stats.html` | Analytics dashboard |

### Configuration

| File | Fungsi |
|------|--------|
| `.env.example` | Template environment variables |
| `pyproject.toml` | Python tools config (ruff) |
| `.github/workflows/ci.yml` | CI/CD pipeline |
| `run.py` | Entry point |

---

## Quick Reference Diagram

```
techscan/
├── app/
│   ├── __init__.py          ← Flask app factory
│   ├── db.py                 ← PostgreSQL + pooling
│   ├── scan_utils.py         ← CORE: Unified scan engine
│   ├── heuristic_fast.py     ← Fast scanner
│   ├── routes/
│   │   ├── scan.py           ← /scan, /bulk_scan
│   │   ├── ui.py             ← /api/domains, /websites
│   │   ├── search.py         ← /api/tech_search
│   │   ├── stats.py          ← /api/stats
│   │   └── admin.py          ← Admin endpoints
│   └── templates/            ← Jinja2 HTML
├── node_scanner/
│   └── scanner.js            ← Wappalyzer wrapper
├── tests/                    ← Pytest unit tests
├── .github/workflows/ci.yml  ← GitHub Actions
└── run.py                    ← Entry point
```

---

Dokumen ini bisa dibuka saat presentasi untuk referensi cepat.
