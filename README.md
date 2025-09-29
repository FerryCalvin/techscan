# TechScan (Flask + Wappalyzer Wrapper)

Minimal service untuk mendeteksi techstack & versi dari satu atau banyak domain menggunakan repo Wappalyzer lokal.

## Fitur

- Endpoint POST /scan (single domain)
- Endpoint POST /bulk (banyak domain, concurrency thread)
- Normalisasi output: technologies + categories + raw
- Cache in-memory (TTL 5 menit) untuk menghindari scan ulang cepat
- Bulk concurrency default 4
- Terima domain murni atau full URL (otomatis ekstrak host)
- Heuristik timeout configurable via file JSON (`app/heuristics_timeout.json` atau ENV `TECHSCAN_HEURISTICS_FILE`)
- Rate limiting per IP (Flask-Limiter)
- Endpoint admin untuk flush cache & reload heuristik
- Endpoint admin statistik `/admin/stats` (hits, misses, uptime, durasi rata-rata)
- Endpoint health check `/health` dan info versi `/version`

## Prasyarat

- Python 3.10+
- Node.js (>=14)
- Clone repo wappalyzer: contoh ke `d:\wappalyzer\wappalyzer3\wappalyzer-master`

## Instalasi

```pwsh
cd d:\magang\techscan
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
# Pastikan Node & repo wappalyzer sudah ada
```

## Jalankan

```pwsh
$env:WAPPALYZER_PATH='d:\wappalyzer\wappalyzer3\wappalyzer-master'
python run.py
```

Server default di port 5000.

## Web UI

Buka di browser: `http://127.0.0.1:5000/`.

Fitur halaman:

- Form single lookup: masukkan domain lalu Scan.
- Bulk upload: unggah file `.txt` (satu domain per baris) → tabel status.
- Kartu teknologi: nama, versi (jika ada), kategori.
- Panel kategori: agregasi per kategori.
- Raw JSON: expandable (details tag) untuk inspeksi.
- Penanda `(cached)` bila hasil diambil dari cache TTL 5 menit.

## Contoh Request

Single:

```pwsh
curl -X POST http://127.0.0.1:5000/scan -H "Content-Type: application/json" -d '{"domain":"unair.ac.id"}'

# Atau full URL (akan dinormalisasi ke host):
curl -X POST http://127.0.0.1:5000/scan -H "Content-Type: application/json" -d '{"domain":"https://mahasiswa.unair.ac.id/akademik/index.html"}'
```

Bulk:

```pwsh
curl -X POST http://127.0.0.1:5000/bulk -H "Content-Type: application/json" -d '{"domains":["unair.ac.id","example.com"]}'
```

## Format Output (singkat)

```json
{
  "domain":"unair.ac.id",
  "timestamp":1690000000,
  "technologies":[{"name":"WordPress","version":"6.4.2","categories":["CMS","Blogs"],"confidence":95}],
  "categories":{"CMS":[{"name":"WordPress","version":"6.4.2"}]},
  "raw": {"technologies":[...]}
}
```

## Penyesuaian

- Ubah TTL cache: edit `CACHE_TTL` di `app/scan_utils.py`.
- Timeout subprocess: parameter `timeout` di `scan_domain`.
- Concurrency bulk: argumen `concurrency` di `scan_bulk`.
- Heuristik timeout: edit file `app/heuristics_timeout.json` lalu panggil endpoint reload (lihat bagian Admin)

## Heuristik Timeout

File default: `app/heuristics_timeout.json` (bisa override dengan ENV `TECHSCAN_HEURISTICS_FILE`). Format:

```json
[
  {"pattern": "mahasiswa\\.unair\\.ac\\.id$", "min_timeout": 70, "note": "Site lambat"}
]
```

Juga mendukung format JSONL (satu objek per baris). Field:

- pattern (regex, Python flavor)
- min_timeout (int detik)
- note (opsional, diabaikan oleh program)

Saat di-load ulang, log akan menampilkan jumlah pattern. Jika file tidak ada → heuristik kosong.

## Mode Scan (Fast vs Full)

Default: fast

- Fast: blok resource berat (image, media, font, stylesheet), depth=1, delay=50ms → lebih cepat tapi bisa miss editor/JS lambat.
- Full: tidak blok resource (kecuali Anda paksa), depth=2, delay=100ms, maxWait lebih besar (15s default), lebih akurat.

Cara pakai:

Endpoint single:
```pwsh
curl -X POST http://127.0.0.1:5000/scan -H "Content-Type: application/json" -d '{"domain":"mahasiswa.unair.ac.id","full":true}'
```

Bulk:
```pwsh
curl -X POST http://127.0.0.1:5000/bulk -H "Content-Type: application/json" -d '{"domains":["mahasiswa.unair.ac.id"],"full":true}'
```

Per-mode cache terpisah (key: mode:domain). Hasil fast tidak dipakai untuk full dan sebaliknya.

Override via environment global (paksa semua jadi full):
```pwsh
$env:TECHSCAN_FULL='1'
```

Matikan blocking resource di fast mode (atau paksa block off di semua mode):
```pwsh
$env:TECHSCAN_BLOCK_RESOURCES='0'
```

`scan_mode` akan muncul di response (`fast` / `full`).

## Synthetic GA4 Detection

Jika pola Measurement ID (G-XXXX) ditemukan di isi/atribut script tapi Wappalyzer belum menandai GA4 terpisah, sistem menambahkan entri teknologi bernama `GA4` (kategori Analytics, confidence 50). Ini menjaga kompatibilitas dengan tampilan extension yang biasanya membedakan GA4 dari Google Analytics klasik.

## Synthetic Detection Tambahan (jQuery, jQuery UI, TinyMCE)

Untuk beberapa situs lama, definisi Wappalyzer kadang tidak memunculkan library tertentu jika resource diblok atau signature berubah. Maka ditambahkan heuristik ringan:

- jQuery: deteksi `window.jQuery.fn.jquery` atau `$().jquery` → versi diambil langsung.
- jQuery UI: deteksi `jQuery.ui.version`.
- TinyMCE: deteksi `tinymce.majorVersion/minorVersion` atau `tinyMCE.majorVersion`. Versi disusun `major.minor` (jika minor ada) atau hanya `major`.

Confidence diset moderat (50–60) karena ini synthetic (bukan pattern file). Jika suatu saat Wappalyzer mendeteksi juga, entri duplicate dicegah (tidak menambah kedua kalinya).

Catatan: Jika mode fast memblokir script/stylesheet terkait, gunakan full mode atau nonaktifkan blok resource agar detection muncul.

## Synthetic Tailwind CSS

Tailwind sering tidak terdeteksi bila hasil build sudah purge dan signature minimal. Heuristik tambahan:

- CDN/link/script mengandung "tailwind"
- Kepadatan kelas utilitas (tokens seperti `flex`, `mt-4`, `bg-blue-500`, prefix responsive `sm:` `md:` dll)
- Rasio hits >= 0.35 dengan >= 30 hits dan >= 8 prefix berbeda → dianggap Tailwind

Confidence 65 (CDN) atau 55 (heuristik). Env disable: `TECHSCAN_SYNTHETIC_TAILWIND=0`.

## Synthetic Floodlight (DoubleClick)

Deteksi script/img/iframe `fls.doubleclick.net/activity` → tambahkan teknologi `Floodlight` kategori Advertising (confidence 50). Env disable: `TECHSCAN_SYNTHETIC_FLOODLIGHT=0`.

## Lisensi

Wappalyzer adalah GPLv3. Integrasi ini harus mematuhi GPLv3 jika didistribusikan. Pastikan menyertakan atribusi & lisensi Wappalyzer jika dipublikasikan lebih luas.

## Roadmap (opsional lanjutan)

- Persistent storage (DB) untuk histori
- Scheduler re-scan domain
- Export CSV/JSONL
- Penilaian out-of-date (mapping versi terbaru)
- Rate limiting & auth
 
## Integrasi Node Scanner Lokal

Proyek ini menyertakan folder `node_scanner/` sebagai pembungkus ringan Wappalyzer + Puppeteer.

Instalasi dependencies scanner:

```pwsh
cd node_scanner
npm install
```

Server Flask otomatis memprioritaskan `node_scanner/scanner.js` bila ada. Jika tidak ditemukan, akan fallback ke path WAPPALYZER_PATH eksternal.

Variabel output `engine` menunjukkan sumber:

- `wappalyzer-local` → memakai `node_scanner/`
- `wappalyzer-external` → memakai repo/path eksternal

Jika error modul puppeteer hilang: jalankan `npm install` di dalam `node_scanner/`.

### Mengatasi Gagal Download Chrome (Puppeteer)

Kadang `npm install` gagal karena Puppeteer tidak bisa mengunduh Chrome (misal folder cache korup atau koneksi diblok). Opsi:

1. Hapus cache puppeteer korup lalu ulang:

  ```pwsh
  Remove-Item -Recurse -Force "$env:USERPROFILE\.cache\puppeteer" -ErrorAction SilentlyContinue
  cd node_scanner
  npm install
  ```

1. (Direkomendasikan) Lewati download dan gunakan Chrome/Edge yang sudah terpasang di sistem. Script `scanner.js` akan otomatis mencari executable tersebut di Program Files.

  ```pwsh
  cd node_scanner
  $env:PUPPETEER_SKIP_DOWNLOAD='1'
  npm install
  ```

  Jika ingin paksa path manual:

  ```pwsh
  $env:PUPPETEER_EXECUTABLE_PATH='C:\Program Files\Google\Chrome\Application\chrome.exe'
  node scanner.js example.com
  ```

1. Aktifkan debug untuk melihat path yang terdeteksi:

  ```pwsh
  $env:TECHSCAN_DEBUG='1'
  node scanner.js example.com
  ```

Jika semua gagal, coba update Node.js ke versi terbaru LTS dan ulangi.

## Bulk CLI (JSONL)

Selain endpoint HTTP & UI, tersedia script CLI: `scripts/bulk_scan.py`.

### Contoh File Input

`domains.txt`:

```text
unair.ac.id
example.com
# baris komentar akan di-skip
its.ac.id

https://mahasiswa.unair.ac.id/portal/login

```

### Jalankan Bulk CLI

```pwsh
python scripts/bulk_scan.py domains.txt -c 6 --timeout 50 > hasil.jsonl
```

Opsi:

- `-c / --concurrency`  jumlah thread (default 4)
- `-t / --timeout`      timeout per domain (detik)
- `--fresh`             abaikan cache (force rescan)
- `--pretty`            output 1 file JSON prettified (bukan JSONL)
- `--engine-path`       override WAPPALYZER_PATH jika tidak mau pakai environment variable
- `--retries`          jumlah retry jika scan gagal (timeout/error)
- `--ttl 600`         TTL custom (detik) untuk cache result (default 300)

### Format Output JSONL

Baris pertama meta:

```json
{"type":"meta","count":3,"seconds":4.12}
```

Diikuti 1 baris per domain (status ok / error):

```json
{"status":"ok","domain":"unair.ac.id", ...}
{"status":"error","domain":"abc","error":"invalid domain"}
```

### Tips

- Untuk dataset sangat besar, pisah menjadi beberapa batch untuk menghindari throttling situs.
- Gunakan `--fresh` hanya bila butuh memaksa hasil terbaru (beban lebih tinggi).
- Bisa dikombinasi dengan PowerShell piping:

  ```pwsh
  Get-Content domains.txt | Where-Object {$_ -notmatch '^#'} | Set-Content clean.txt
  python scripts/bulk_scan.py clean.txt > out.jsonl
  ```

## Timeout, Retry & HTTP Fallback

### API Parameters

Endpoint `/scan` dan `/bulk` sekarang menerima field opsional:

- `timeout` (int, detik) default 45
- `retries` (int) jumlah percobaan ulang jika gagal (timeout / error) default 0
- `fresh` (bool) paksa abaikan cache
- `concurrency` (bulk saja) default 4
- `ttl` (int) override TTL cache untuk hasil baru (detik, default 300)

Contoh:

```pwsh
curl -X POST http://127.0.0.1:5000/scan -H "Content-Type: application/json" -d '{"domain":"example.com","timeout":60,"retries":1}'
```

### Mekanisme Fallback

1. Jika percobaan pertama (mode external) HTTPS gagal sebelum habis semua attempt, sistem otomatis mencoba ulang dengan HTTP (port 80) pada attempt berikutnya.
2. Retries men-trigger percobaan penuh ulang (termasuk fallback logic) hingga batas `retries + 1` total attempt.
3. Jika berhasil setelah retry, response menyertakan field `retries` (jumlah retry yang dipakai).
4. Timeout menghasilkan pesan `timeout after Xs (attempt A/B)`.

### CLI Flags yang Relevan

`scripts/bulk_scan.py` sudah mendukung:

- `--timeout 60`
- `--fresh`
- `--concurrency 6`
- `--engine-path <path>`
- `--retries 1` (contoh)
- `--ttl 900` (contoh, 15 menit TTL)

### Best Practice


## Format Input Domain / URL

Input yang diterima (akan dinormalisasi ke host saja):

- example.com
- sub.example.com:8443
- <https://sub.example.com/path/page?query=1#frag>
- <http://user:pass@legacy.example.org/app>

Langkah normalisasi:

1. Hapus scheme (http://, https://, dll)
2. Buang credential (user:pass@)
3. Hilangkan port (:8080)
4. Ambil komponen host sebelum path/query/fragment
5. Validasi sederhana karakter host (alfanumerik, dash, dot)

Jika hasil kosong / tidak valid → error "invalid domain".

Catatan: Path tidak dipakai dalam fingerprint Wappalyzer pada implementasi saat ini.

## Bulk Output Langsung CSV

Selain `GET /export/csv` (hanya cache), endpoint POST `/bulk` dapat langsung mengembalikan CSV hasil scan baru:

```pwsh
curl -X POST http://127.0.0.1:5000/bulk?format=csv -H "Content-Type: application/json" -d '{"domains":["example.com","unair.ac.id"],"timeout":50,"retries":1,"ttl":600}' > bulk.csv
```

Atau letakkan `"format":"csv"` dalam JSON body. Field yang error akan memiliki baris dengan kolom status=error dan kolom lain kosong (kecuali domain & error).

## Export CSV

Endpoint baru: `GET /export/csv`

Query parameters:

- `domains=example.com,unair.ac.id` (opsional filter; jika tidak diberikan semua yang masih valid di cache)
- `include_raw=1` untuk menambahkan kolom raw JSON (stringified) – bisa memperbesar ukuran file.

Kolom output:

`domain,timestamp,tech_count,technologies,categories,cached,duration,retries,engine[,raw]`

Contoh unduh semua (PowerShell):

```pwsh
Invoke-WebRequest -Uri 'http://127.0.0.1:5000/export/csv' -OutFile export.csv
```

Contoh filter domain tertentu dan sertakan raw:

```pwsh
Invoke-WebRequest -Uri 'http://127.0.0.1:5000/export/csv?domains=unair.ac.id,example.com&include_raw=1' -OutFile subset.csv
```

## Rate Limiting

Menggunakan Flask-Limiter. Env vars:

- `TECHSCAN_RATE_LIMIT` (default `60 per minute`) limit global default
- `TECHSCAN_SINGLE_RATE_LIMIT` (default `120 per minute`) khusus endpoint /scan
- `TECHSCAN_BULK_RATE_LIMIT` (default `20 per minute`) khusus endpoint /bulk

Format limit mengikuti sintaks Flask-Limiter: contoh `100 per hour`, `10/second`, dll.

Jika ingin menonaktifkan, bisa set rate sangat tinggi atau modifikasi kode untuk menghapus limiter.

## Endpoint Admin

Semua prefiks `/admin`. Untuk keamanan produksi, set ENV `TECHSCAN_ADMIN_TOKEN` dan kirim header `X-Admin-Token`.

1. POST `/admin/cache/flush`

Body opsional:

```json
{"domains": ["example.com", "unair.ac.id"]}
```

Jika tanpa body/daftar domain → flush semua cache. Response:

```json
{"status":"ok","removed":10,"remaining":0,"total_before":10}
```

1. POST `/admin/heuristics/reload`

Reload file heuristik (berguna setelah edit file JSON tanpa restart service):

```pwsh
curl -X POST http://127.0.0.1:5000/admin/heuristics/reload
```

2. GET `/admin/stats`

Menampilkan metrik runtime (JSON):

```json
{
  "status": "ok",
  "stats": {
    "uptime_seconds": 123.4,
    "hits": 10,
    "misses": 5,
    "mode_hits": {"fast": 8, "full": 2},
    "mode_misses": {"fast": 3, "full": 2},
    "scans": 5,
    "cache_entries": 12,
    "average_duration_ms": {"fast": 320.55, "full": 1480.11},
    "synthetic": {"headers": 2}
  }
}
```

3. (Sebelumnya) `/admin/cache/flush` tetap ada.

## Health & Version Endpoint

- `GET /health` → `{"status":"ok","uptime_seconds":12.34}` (ringan untuk liveness/readiness probe)
- `GET /version` → `{"version":"0.3.0","git_commit":"a1b2c3d","uptime_seconds":12.34,"features":{"synthetic_headers":true}}`

Override versi manual: set ENV `TECHSCAN_VERSION`. Commit diambil best-effort dari `.git/HEAD`.

## Variabel Environment Ringkas

| Variable | Fungsi | Default |
|----------|--------|---------|
| WAPPALYZER_PATH | Path repo wappalyzer | (lihat contoh) |
| TECHSCAN_LOG_LEVEL | Level log | INFO |
| TECHSCAN_HEURISTICS_FILE | Path heuristik timeout | app/heuristics_timeout.json |
| TECHSCAN_ADMIN_TOKEN | Token admin untuk endpoint /admin | (kosong = bebas) |
| TECHSCAN_RATE_LIMIT | Default rate limit global | 60 per minute |
| TECHSCAN_SINGLE_RATE_LIMIT | Limit endpoint /scan | 120 per minute |
| TECHSCAN_BULK_RATE_LIMIT | Limit endpoint /bulk | 20 per minute |
| TECHSCAN_NAV_TIMEOUT | Override max wait puppeteer (detik) | (opsional) |
| TECHSCAN_VERSION | Override nilai versi yang dilaporkan `/version` | 0.3.0 |

## Contoh Konfigurasi Rate & Heuristik (PowerShell)

```pwsh
$env:TECHSCAN_RATE_LIMIT='100 per minute'
$env:TECHSCAN_BULK_RATE_LIMIT='15 per minute'
$env:TECHSCAN_HEURISTICS_FILE='D:\\magang\\techscan\\app\\heuristics_timeout.json'
$env:TECHSCAN_ADMIN_TOKEN='secret123'
python run.py
```



