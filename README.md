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

## Requirements

- Python 3.10+
- Node.js (>=14)
- Clone repo wappalyzer: contoh ke `d:\wappalyzer\wappalyzer3\wappalyzer-master`

## How To Install

```pwsh
your directory
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

## Integrasi Database (PostgreSQL)

Secara default aplikasi dapat menyimpan histori scan dan indeks teknologi ke PostgreSQL agar Anda bisa:

- Melihat histori scan per domain (`/history?domain=example.com`)
- Mencari semua domain yang memakai teknologi tertentu (`/search?tech=Laravel`)
- Mencari berdasarkan kategori (`/search?category=CMS`) atau kombinasi versi

### Konfigurasi Cepat

1. Siapkan database Postgres lokal, contoh:

```sql
CREATE DATABASE techscan;
```

2. Set environment variable koneksi (format psycopg):

```pwsh
$env:TECHSCAN_DB_URL='postgresql://postgres:postgres@localhost:5432/techscan'
```

3. Jalankan aplikasi. Schema otomatis dibuat (tabel `scans` dan `domain_techs`).

Jika ingin menonaktifkan DB (misal benchmark tanpa overhead):
```pwsh
$env:TECHSCAN_DISABLE_DB='1'
```

### Struktur Tabel Inti (Ringkas)

- `scans`: setiap eksekusi /scan (termasuk hit cache) → domain, mode/engine, durasi, timestamps, error, snapshot technologies + kolom terhitung:
  - `tech_count` (jumlah teknologi pada hasil itu)
  - `versions_count` (berapa yang punya field `version`)
- `domain_techs`: baris per (domain, tech[, version]) dengan `first_seen` & `last_seen` untuk tracking persistensi.

Kolom `tech_count` dan `versions_count` otomatis terisi untuk scan baru; jika Anda menambahkan kolom ini setelah ada data lama, jalankan skrip backfill:

```pwsh
python scripts/backfill_counts.py
```

Tambahkan `--force` bila ingin menghitung ulang semua baris; default hanya yang masih NULL.

### Endpoint Pencarian

Contoh:
```pwsh
curl "http://127.0.0.1:5000/search?tech=Laravel&limit=50"
curl "http://127.0.0.1:5000/search?category=CMS"
curl "http://127.0.0.1:5000/search?tech=React&version=18.2.0"
```
Response:
```json
{
  "count": 2,
  "results": [
    {"domain":"example.com","tech_name":"Laravel","version":null,"categories":["Frameworks"],"first_seen":1690001000,"last_seen":1690004000}
  ]
}
```

### Endpoint Histori

```pwsh
curl "http://127.0.0.1:5000/history?domain=example.com&limit=10"
```
Response contoh:
### Endpoint Statistik Database

Endpoint admin baru menyajikan agregasi data untuk dashboard cepat:

```pwsh
curl http://127.0.0.1:5000/admin/db_stats
```

Contoh response:

```json
{
  "status": "ok",
  "db_stats": {
    "scans_total": 1240,
    "domains_tracked": 310,
    "domain_tech_rows": 2280,
    "top_tech": [
      {"tech": "WordPress", "count": 140},
      {"tech": "jQuery", "count": 130}
    ],
    "avg_duration_24h": [
      {"mode": "fast_full", "avg_ms": 1875.4, "samples": 92},
      {"mode": "fast", "avg_ms": 540.2, "samples": 400}
    ],
    "version_presence_pct": 42.35
  }
}
```

Bidang:

- `scans_total` total baris di tabel `scans`.
- `domains_tracked` jumlah domain unik di `domain_techs`.
- `domain_tech_rows` total baris teknologi aktif.
- `top_tech` 15 teknologi teratas berdasarkan jumlah domain.
- `avg_duration_24h` rata-rata durasi per mode 24 jam terakhir.
- `version_presence_pct` persentase baris `domain_techs` yang memiliki `version` (indikasi kedalaman versi).

Gunakan untuk memantau coverage versi dan identifikasi teknologi populer.
```json
{
  "domain": "example.com",
  "count": 3,
  "history": [
    {"mode":"fast_full","started_at":1690003900,"finished_at":1690003902,"duration_ms":1890,"from_cache":false},
    {"mode":"fast","started_at":1690002000,"finished_at":1690002001,"duration_ms":740,"from_cache":true}
  ]
}
```

### Tips DBeaver

Koneksi: gunakan URL, atau host/port/db/user/password manual. Setelah itu Anda bisa:
Query populer:

```sql
SELECT tech_name, COUNT(*)
FROM domain_techs
GROUP BY tech_name
ORDER BY COUNT(*) DESC
LIMIT 20;
```

Analisis versi:

```sql
SELECT tech_name, version, COUNT(*)
FROM domain_techs
WHERE version IS NOT NULL
GROUP BY tech_name, version
ORDER BY COUNT(*) DESC;
```

### Env Variabel Terkait DB

| Variable | Fungsi | Default |
|----------|--------|---------|
| TECHSCAN_DB_URL | Koneksi Postgres | `postgresql://postgres:postgres@localhost:5432/techscan` |
| TECHSCAN_DISABLE_DB | Matikan persistence | 0 |

Ke depan: rencana tambah diff perubahan teknologi & export historis.

### Catatan Bulk Persistence

Sebelum patch terbaru hanya endpoint `/scan` yang mem-persist. Sekarang `/bulk` juga otomatis menambahkan setiap hasil (termasuk error) ke tabel `scans` dan memperbarui `domain_techs`. Jika Anda melakukan pengisian awal gunakan skrip seed:

```pwsh
python scripts/seed_db.py --bulk --url http://127.0.0.1:5000
```

Atau single sequential (lebih lambat, cocok debug):

```pwsh
python scripts/seed_db.py --url http://127.0.0.1:5000
```

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

## Quick vs Deep vs Full (Mode Baru)

Selain fast (heuristic + optional full) dan full klasik, kini tersedia dua lapisan tambahan yang mengoptimalkan rasio kecepatan vs kelengkapan:

| Mode | Jalur Utama | Komponen | Target Latency | Kapan Dipakai |
|------|-------------|----------|----------------|---------------|
| Quick | Heuristic tier0 + HTML sniff + (opsional micro fallback) | Tanpa Wappalyzer penuh kecuali micro fallback | ~0.2–0.9s typical | Explorasi massal sangat cepat, CMS utama, plugin populer, front-end framework cepat |
| Fast-Full | Single bounded full engine (no adaptive retry) | Wappalyzer full 1 attempt (strict ms budget) + enrichment | ~1.0–3.5s typical (default 5s cap) | Saat butuh cakupan mirip full lebih cepat dari full klasik |
| Deep | Heuristic (budget khusus) + constrained full (timeout rendah) + enrichment | Partial full (timeout < full) + merging | ~1.2–4s typical | Saat butuh versi lebih lengkap tanpa biaya full penuh |
| Full | Wappalyzer penuh (depth/await standar) | Engine penuh | 3–12s (variatif) | Audit akhir, completeness maksimal |

Perbedaan kunci:
- Deep melakukan dua fase internal: fase cepat heuristic diperluas (budget `TECHSCAN_DEEP_QUICK_BUDGET_MS`) lalu satu tembakan full singkat (`TECHSCAN_DEEP_FULL_TIMEOUT_S`). Jika full mini timeout → hasil heuristic tetap dipakai (tidak kosong).
- Deep menambahkan blok `phases` dalam response untuk diagnosa (durasi masing-masing fase, apakah partial, merged, truncated).
- Quick didesain supaya tidak pernah “benar-benar kosong” berkat HTML sniff + micro fallback (jika diaktifkan env).

### Aktivasi

Single request (body JSON):

```pwsh
curl -X POST http://127.0.0.1:5000/scan -H 'Content-Type: application/json' -d '{"domain":"example.com","quick":1}'
curl -X POST http://127.0.0.1:5000/scan -H 'Content-Type: application/json' -d '{"domain":"example.com","deep":1}'
curl -X POST http://127.0.0.1:5000/scan -H 'Content-Type: application/json' -d '{"domain":"example.com","full":1}'
```

Jika tidak ada flag → default mengikuti heuristic/fast biasa (atau quick jika di-force env). Prioritas parsing (pertama ditemukan): `full` > `deep` > `quick`.

### Environment Flags Terkait

| Variable | Fungsi | Default |
|----------|--------|---------|
| TECHSCAN_QUICK_SINGLE | Paksa semua /scan ke quick | 0 |
| TECHSCAN_QUICK_BUDGET_MS | Budget ms heuristic quick | 700 |
| TECHSCAN_QUICK_DEFER_FULL | Jalankan full di background setelah quick | 0 |
| TECHSCAN_DEEP_QUICK_BUDGET_MS | Budget ms fase heuristic dalam deep | 1200 |
| TECHSCAN_DEEP_FULL_TIMEOUT_S | Timeout detik mini full dalam deep | 6 |
| TECHSCAN_FAST_FULL_TIMEOUT_MS | Bounded fast-full hard cap (ms) | 5000 |
| TECHSCAN_FAST_FULL_DISABLE_CACHE | Jangan cache hasil fast-full | 0 |
| TECHSCAN_FAST_FULL_CACHE_TTL | TTL cache fast-full custom | (inherit default) |
| TECHSCAN_DEEP_DISABLE_CACHE | Jangan tulis hasil deep ke cache | 0 |
| TECHSCAN_DEEP_CACHE_TTL | TTL khusus cache hasil deep | (inherit) |
| TECHSCAN_VERSION_ENRICH | Aktifkan targeted version enrichment | 1 |
| TECHSCAN_ULTRA_QUICK | Heuristic-only ekstrem (tanpa full) | 0 |
| TECHSCAN_ULTRA_FALLBACK_MICRO | Aktifkan micro fallback saat ultra kosong | 0 |

### Contoh Potongan Response Deep

```json
{
  "engine": "deep-combined",
  "phases": {
    "quick_ms": 934,
    "full_ms": 1480,
    "merged": true,
    "full_timeout": false,
    "enriched": true
  },
  "technologies": [ {"name":"WordPress","version":"6.5.3"}, {"name":"WooCommerce","version":"8.2.1"} ]
}
```

## Targeted Version Enrichment (CMS Fokus)

Untuk meningkatkan keberadaan field `version` tanpa menjalankan full scan panjang, sistem melakukan fetch ringan setelah quick/deep selesai (hanya bila teknologi target terdeteksi dan belum punya versi):

| Teknologi | Endpoint Dicek | Metode Ekstraksi |
|-----------|----------------|------------------|
| WordPress | `/wp-json` | Ambil `generator` atau pola `wordpress` di JSON, regex semver ringan |
| Drupal | `/CHANGELOG.txt` | Regex `Drupal x.y.z` (first match) |
| Joomla | `/language/en-GB/en-GB.xml` | Parsing tag `<version>` sederhana |

Karakteristik:
- Timeout per target ±2–3s (non-blocking terhadap hasil dasar: jika gagal tidak fatal).
- Hanya dijalankan jika `TECHSCAN_VERSION_ENRICH=1` (default on).
- Jika versi ditemukan, `technologies[i].version` di-update dan kategori direbuild sehingga integritas panel kategori terjaga.
- Ditandai dengan flag di block phases / tiered: `enriched=true`.

Disarankan mematikan enrichment (`TECHSCAN_VERSION_ENRICH=0`) untuk workload ultra-bulk yang hanya butuh nama teknologi (latency mikro lebih ketat).

## Bulk Two-Phase (Quick lalu Deep Selektif)

Selain mode `TECHSCAN_BULK_TWO_PHASE` klasik (heuristic + full tertunda), kini ada pipeline dua fase yang menambah lapisan deep terarah.

Alur:
1. Fase 1 (quick semua domain) – sangat homogen cepat, memungkinkan progress bar lebih cepat terisi.
2. Seleksi domain untuk deep berdasarkan kriteria eskalasi:
   - `tech_count < TECHSCAN_BULK_DEEP_MIN_TECH` (default 2), ATAU
   - Semua teknologi hasil quick tidak punya `version`, ATAU
   - Hasil quick kosong.
3. Terapkan batas opsional:
   - `TECHSCAN_BULK_DEEP_MAX` (absolute count) ATAU
   - `TECHSCAN_BULK_DEEP_MAX_PCT` (persentase 0–100). Jika keduanya diset → gunakan yang lebih ketat.
4. Jalankan deep paralel terbatas (mengikuti concurrency bulk). Domain lain tetap final dengan hasil quick (plus enrichment bila aktif).

Aktivasi cepat (env):
```pwsh
$env:TECHSCAN_BULK_TWO_PHASE='1'   # jika belum aktif tiered lama
# (opsional) set parameter seleksi
$env:TECHSCAN_BULK_DEEP_MIN_TECH='2'
$env:TECHSCAN_BULK_DEEP_MAX='50'
# atau persentase
$env:TECHSCAN_BULK_DEEP_MAX_PCT='25'
```

Permintaan bulk juga bisa memaksa gaya ini dengan menambahkan `"two_phase":1` di body JSON (jika route mendukung; fallback ke env bila tidak ada field).

Blok metadata tambahan di output (per domain):

```json
"bulk_phase": {
  "phase": 1,
  "escalated": true,
  "reason": "low_tech_count"
}
```

Atau untuk domain yang tidak diekskalasi:

```json
"bulk_phase": {"phase": 1, "escalated": false}
```

Setelah deep selesai, entri domain dieksekusi ulang dengan `phase=2` dan `engine=deep-combined`.

## Strategi Re-Scan Massal (Praktik Rekomendasi)

Tujuan umum: Minimalkan total waktu wall-clock untuk ratusan/ribuan domain sambil tetap mendapatkan versi pada domain penting.

1. Jalankan quick semua domain dan simpan JSONL:
```pwsh
python scripts/bulk_scan.py domains.txt -c 8 --timeout 40 --fresh > quick_pass.jsonl
```
2. Ekstrak daftar domain yang:
   - tech_count < 2 ATAU
   - semua technologies tanpa `version`.
   (Gunakan jq atau skrip Python kecil.)
3. Jalankan deep hanya pada subset tersebut:
```pwsh
Get-Content quick_pass.jsonl | python scripts/filter_need_deep.py > need_deep.txt
python scripts/bulk_scan.py need_deep.txt -c 4 --timeout 70 --fresh --deep > deep_pass.jsonl
```
4. Merge hasil (prioritaskan deep):
```pwsh
python scripts/merge_deep_prefer.py quick_pass.jsonl deep_pass.jsonl > merged.jsonl
```
Skrip util merger dapat ditambahkan (lihat Next Steps bila belum tersedia).

Optimasi tambahan:
- Matikan audit versi di quick pass jika CPU bottleneck: `TECHSCAN_VERSION_AUDIT=0`.
- Pastikan enrichment aktif di quick (menambah versi tanpa deep) kecuali total throughput menjadi kritis.
- Gunakan persistent browser (`TECHSCAN_PERSIST_BROWSER=1`) untuk fase deep agar cold start berkurang.

## Ringkasan Flag Baru (Tambahan di Atas Tabel Utama)

Tambahan (jika belum tercantum di tabel Variabel Environment Ringkas):

| Variable | Fungsi Singkat |
|----------|----------------|
| TECHSCAN_DEEP_QUICK_BUDGET_MS | Budget heuristic internal deep |
| TECHSCAN_DEEP_FULL_TIMEOUT_S | Timeout mini full pada deep |
| TECHSCAN_DEEP_DISABLE_CACHE | Jangan simpan hasil deep |
| TECHSCAN_DEEP_CACHE_TTL | TTL khusus hasil deep |
| TECHSCAN_VERSION_ENRICH | Targeted CMS version enrichment |
| TECHSCAN_BULK_DEEP_MIN_TECH | Ambang eskalasi deep bulk |
| TECHSCAN_BULK_DEEP_MAX | Batas absolut domain deep |
| TECHSCAN_BULK_DEEP_MAX_PCT | Batas persentase domain deep |
| TECHSCAN_ULTRA_FALLBACK_MICRO | Micro fallback jika ultra kosong |

Pastikan tidak ada duplikasi definisi; jika tabel environment utama nanti digabung, hapus baris ganda.

## Runtime Stats (Admin) – Fast-Full Metrics

Endpoint `/admin/stats` sekarang termasuk metrik baru untuk fast_full:

```json
{
  "average_duration_ms": {"fast": 210.4, "full": 6820.9, "fast_full": 1895.2},
  "recent_latency_ms": {
    "fast_full": {"samples": 37, "p50": 1822.0, "p95": 2955.0}
  },
  "mode_hits": {"fast": 1234, "full": 210, "fast_full": 37},
  "mode_misses": {"fast": 12, "full": 4, "fast_full": 1}
}
```

Penjelasan ringkas:

- `average_duration_ms.fast_full` = total durasi eksekusi fast_full dibagi jumlah.
- `recent_latency_ms.fast_full` = ringkasan window (max 200 sample) dengan p50 & p95.
- `mode_hits/misses.fast_full` = hit/miss cache untuk key fast_full (jika cache diaktifkan).

Gunakan ini untuk tuning `TECHSCAN_FAST_FULL_TIMEOUT_MS` (misal ingin p95 < 3000ms). Jika p95 mendekati cap berarti banyak partial fallback atau saturasi.

## Benchmark Script: perf_fast_full_scan

Skrip baru `scripts/perf_fast_full_scan.py` membantu menguji beberapa nilai budget fast_full dan menganalisa trade-off latency vs coverage.

Contoh pemakaian (service Flask sudah berjalan):

```pwsh
python scripts/perf_fast_full_scan.py domains.txt --budgets 4000,5000,6000 --repeat 2 --concurrency 6 > bench.json
```

Output (JSON list) contoh:

```json
[
  {
    "budget_ms": 4000,
    "samples": 25,
    "avg_full_ms": 1780.44,
    "p50_full_ms": 1712.0,
    "p95_full_ms": 3110.0,
    "avg_tech_count": 6.2,
    "avg_with_version": 2.7,
    "partial_rate": 0.04,
    "errors": 0
  },
  {
    "budget_ms": 5000,
    "samples": 25,
    "avg_full_ms": 1912.10,
    "p50_full_ms": 1805.0,
    "p95_full_ms": 3290.0,
    "avg_tech_count": 6.6,
    "avg_with_version": 3.1,
    "partial_rate": 0.02,
    "errors": 0
  }
]
```

Switch ke CSV:

```pwsh
python scripts/perf_fast_full_scan.py domains.txt --budgets 3500,4500 --csv
```

Kolom penting:

- `avg_full_ms` / `p50_full_ms` / `p95_full_ms` → latency outcome.
- `avg_tech_count` → rata-rata jumlah teknologi terdeteksi.
- `avg_with_version` → rata-rata jumlah teknologi yang memiliki versi (indikator depth).
- `partial_rate` → proporsi scan yang jatuh ke fallback partial (timeout / error short-circuit).
- `errors` → error transport / HTTP (non-partial logic) yang terjadi.

Strategi tuning umum:

1. Start dengan 5000 ms, ukur p95. Jika p95 jauh < cap dan partial_rate rendah (<0.05) coba turunkan ke 4500 ms.
2. Bandingkan penurunan `avg_with_version` setelah pengurangan budget. Jika drop <5% bisa diterima.
3. Batas bawah realistis biasanya saat p95 mulai memotong banyak scan → partial_rate naik tajam.

Tips concurrency:

- Gunakan `--concurrency` mendekati jumlah CPU core / 1.5x jika IO heavy.
- Tambah `--delay 0.05` bila ingin mencegah burst terlalu agresif ke target eksternal.


## Diagnostik Quick & Micro

Endpoint `/admin/quick_diag?domain=example.com` menampilkan:
- Hasil heuristic mentah (token, pattern match, version evidence)
- Jika `micro=1`, hasil micro fallback (apakah menambah tech atau timeout) beserta timing.

Gunakan UI tombol “Micro Diag” untuk mempercepat analisa mengapa suatu domain butuh escalasi deep.

---

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

### Ikon Teknologi

UI menampilkan ikon untuk sebagian teknologi umum (WordPress, React, Laravel, Vue.js, Angular, Tailwind, PHP, MySQL, Redis, dll). Ikon disediakan sebagai SVG sederhana di `app/static/icons/` dan diinspirasi gaya Simple Icons. Merek dagang dan logo adalah milik pemiliknya masing‑masing. Jika Anda mendistribusikan ulang secara publik pastikan mematuhi kebijakan merek masing‑masing vendor.

Menambah ikon baru:
1. Tambahkan file SVG ke `app/static/icons/<nama>.svg` (ukuran viewBox 0 0 256 256 disarankan atau akan diskalakan otomatis).
2. Tambahkan mapping nama teknologi (lowercase) ke path SVG di objek `ICON_MAP` dalam `index.html`.
3. Refresh browser (aktifkan `TECHSCAN_TEMPLATE_AUTO_RELOAD=1` untuk auto reload saat development).

Fallback: Jika ikon tidak tersedia, UI akan menampilkan huruf pertama dengan warna background pseudo-random deterministik.

#### Sumber Ikon via CDN

Secara default UI mencoba memuat ikon dari paket publik `tech-stack-icons` melalui CDN (unpkg):

`https://unpkg.com/tech-stack-icons@latest/icons/<nama>.svg`

Jika ikon CDN gagal dimuat (404 / jaringan), otomatis fallback ke ikon lokal (jika tersedia) atau huruf berwarna.

Keuntungan:
- Tidak perlu menambah banyak file SVG lokal.
- Ikon konsisten & mudah diperbarui (update versi paket).

Risiko / Catatan:
- Ketergantungan koneksi internet untuk ikon baru.
- Sebaiknya pin versi tertentu untuk stabilitas produksi, misal ganti `@latest` menjadi `@1.4.0` (contoh):
  - Ubah konstanta `ICON_REMOTE_BASE` di `index.html`.

Offline / Air‑gapped:
- Salin ikon yang diperlukan ke `app/static/icons/` dan hapus entri di `REMOTE_ICON_MAP` atau set `ICON_REMOTE_BASE` ke folder lokal.

Lisensi & Merek:
- Ikon mengikuti gaya Simple Icons / sumber komunitas. Merek tetap milik pemilik masing‑masing.

### Menggunakan Paket `tech-stack-icons` Secara Lokal (Offline / Tanpa CDN)

Jika ingin menghindari ketergantungan CDN dan bekerja sepenuhnya offline:

1. Install paket (sekali):

   ```pwsh
   npm install tech-stack-icons
   ```
2. Ekstrak subset ikon yang dibutuhkan (varian default `dark`):

   ```pwsh
   node scripts/extract_stack_icons.mjs dark
   ```
3. Multi-variant: jalankan lagi untuk varian lain (misal `light`, `grayscale`). Struktur output sekarang:

   ```text
   app/static/icons/stack/
     dark/*.svg
     light/*.svg
     grayscale/*.svg (opsional)
   ```
4. Di UI klik tombol `Use Local Pack` untuk beralih sumber ikon ke folder lokal (menggunakan subfolder sesuai dropdown Variant). Klik lagi untuk kembali ke CDN.
5. Dropdown `Variant` akan memilih subfolder (`dark` / `light` / `grayscale`). Preferensi disimpan otomatis.
6. Tombol `Reset Icon Cache` membersihkan cache kegagalan (localStorage) dan mem-preload ulang ikon penting.

Menambah ikon baru / plugin populer:

1. Edit array `ICONS` di `scripts/extract_stack_icons.mjs` (atau tambahkan placeholder SVG manual di `app/static/icons/stack/<variant>/`).
2. Jalankan skrip untuk tiap varian yang ingin Anda hasilkan.
3. Jika ikon bukan bagian bawaan remote pack, tambahkan slug ke objek `LOCAL_EXTRA_ICONS` (di `app/templates/index.html`).
4. Refresh UI.

Placeholder tambahan yang saat ini disertakan (dark & light):

| Teknologi / Plugin | Slug File |
|--------------------|-----------|
| Yoast SEO          | yoastseo  |
| WPML               | wpml      |
| LiteSpeed          | litespeed |
| Google Analytics   | ga        |
| jQuery UI          | jqueryui  |
| jQuery Migrate     | jquerymigrate |

Semua berada di `app/static/icons/stack/<variant>/<slug>.svg`.

Persistensi preferensi otomatis (localStorage keys):

| Key | Nilai | Deskripsi |
|-----|-------|-----------|
| `techscan_remote_icons` | '1' / '0' | Aktif / nonaktif penggunaan CDN remote |
| `techscan_use_local_pack` | '1' / '0' | Prioritaskan ikon lokal multi-variant |
| `techscan_icon_variant` | dark / light / grayscale | Varian ikon lokal yang dipilih |
| `techscan_failed_remote_icons` | JSON array | Daftar slug ikon remote yang gagal dimuat (cache kegagalan) |

Fungsi `techIconHTML` kini otomatis memilih path `app/static/icons/stack/<variant>/<slug>.svg` saat mode lokal aktif dan memanfaatkan mapping tambahan `LOCAL_EXTRA_ICONS` untuk plugin populer yang belum ada di remote pack.

CI/CD: Jalankan skrip ekstraksi di pipeline build sehingga folder `app/static/icons/stack` selalu konsisten dengan versi paket yang ter-pin di `package.json`.

Catatan: Jika struktur internal paket berubah dan skrip tidak menemukan data ikon, Anda akan melihat peringatan. Perbarui heuristik skrip sesuai versi baru.


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

### Bulk Fallback Quick (Mitigasi Timeout Massal)

Untuk bulk scanning, Anda dapat menambahkan parameter `"fallback_quick": 1` (atau query `?fallback_quick=1`) agar setiap domain yang berakhir `status=error` dengan pesan mengandung kata kunci timeout (“timeout”, “timed out”, “time out”) segera di-rescan memakai jalur quick heuristic singkat.

Karakteristik:

- Hanya memproses entri yang gagal dengan timeout-like error; error lain (DNS, SSL, dll.) dibiarkan apa adanya.
- Jika quick scan berhasil, entri akhir diubah menjadi `status="ok"` dan field tambahan:
  - `fallback: "quick"`
  - `original_error: "...pesan error awal..."`
- Jika quick scan juga gagal, entri tetap `status=error` dan ditambah:
  - `fallback_attempt: "quick"`
  - `fallback_error: "...error quick..."`
- Persistensi ke DB tetap dilakukan (hasil ok maupun error) seperti biasa.
- CSV langsung (`POST /bulk?format=csv`) TIDAK memiliki kolom khusus `fallback` atau `original_error`; hanya kolom `error`. Artinya ketika fallback berhasil, kolom `error` akan kosong (karena status sudah ok) dan Anda hanya bisa melihat jejak fallback di response JSON (bukan di CSV). Jika butuh audit fallback, simpan output JSON sebelum konversi/unduh CSV.

Contoh request JSON:

```pwsh
curl -X POST http://127.0.0.1:5000/bulk -H "Content-Type: application/json" -d '{"domains":["timeout-domain.test","example.com"],"timeout":45,"retries":1,"fallback_quick":1}'
```

Contoh langsung CSV:

```pwsh
curl -X POST 'http://127.0.0.1:5000/bulk?format=csv&fallback_quick=1' -H 'Content-Type: application/json' -d '{"domains":["timeout-domain.test","example.com"],"timeout":45}' > bulk.csv
```

Kapan dipakai:

- Dataset besar dengan sebagian domain lambat / sering timeout dan Anda ingin tetap memiliki minimal deteksi teknologi dasar tanpa menunggu retry panjang.
- Fase eksplorasi awal untuk memetakan cakupan teknologi umum sebelum menjalankan deep/full terarah pada subset bermasalah.

Kapan TIDAK disarankan:

- Saat Anda perlu memastikan timeout yang terjadi dianalisis akar penyebabnya (misal isu jaringan atau pemblokiran) — fallback dapat “menutupi” jumlah real timeout.
- Ketika quick mode diperkirakan tidak memberi sinyal berarti (misal situs heavily client‑side rendering yang butuh eksekusi penuh).

Catatan performa: fallback menambah overhead hanya untuk domain bermasalah. Jika timeout rate rendah, dampak total kecil. Jika timeout rate tinggi, pertimbangkan meningkatkan `timeout` dasar atau mengaktifkan persistent browser sebelum mengandalkan fallback.

UI Web: centang opsi "Fallback Quick" di panel Bulk sebelum menekan tombol "Scan Bulk" untuk mengaktifkan perilaku ini. Tombol "Download CSV" memakai parameter yang sama dengan konfigurasi terakhir.

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

Jika version audit aktif akan ditambahkan kolom: `outdated_count,outdated_list`.

Pada mode fallback_quick (jika diaktifkan) baris hasil fallback yang sukses tidak menampilkan indikasi khusus di CSV (karena kolom fallback tidak ada). Gunakan output JSON untuk forensik jika diperlukan.

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

1. GET `/admin/stats`

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

1. (Sebelumnya) `/admin/cache/flush` tetap ada.

1. GET `/admin/benchmark/quick` atau POST `/admin/benchmark/quick`

   Jalankan benchmark internal heuristic cepat (quick scan) tanpa perlu script eksternal. Parameter (query atau JSON):
   - `domains` (comma / array) default: wordpress.org, reactjs.org, example.com
   - `budgets` (comma / array) default: 700,900,1200
   - `repeat` (int, max 5) pengulangan per budget
   - `defer_full` (0/1) default 0 (0 = jangan jadwalkan full background agar timing murni)

  Contoh:

  ```pwsh
   Invoke-WebRequest -Uri 'http://127.0.0.1:5000/admin/benchmark/quick?budgets=700,900&domains=wordpress.org,reactjs.org&repeat=2' | Select-Object -Expand Content
   ```

  Contoh POST:

  ```pwsh
   curl -X POST http://127.0.0.1:5000/admin/benchmark/quick -H 'Content-Type: application/json' -d '{"domains":["wordpress.org","example.com"],"budgets":[700,1200],"repeat":2}'
   ```

  Output ringkas per budget:

  ```json
   {
     "budget_ms":700,
     "samples":6,
     "avg_ms":182.11,
     "p50_ms":176.4,
     "p95_ms":null,
     "avg_tech_count":26.0,
     "min_tech_count":7,
     "max_tech_count":39,
     "errors":0
   }
   ```

### Extended Stats (Latency Percentile)

Endpoint `/admin/stats` sekarang menambahkan blok `recent_latency_ms`:

```json
"recent_latency_ms": {
  "fast": {"samples": 120, "p50": 165.2, "p95": 310.4},
  "full": {"samples": 34,  "p50": 1490.7, "p95": 2450.9}
}
```

Catatan:

- Sampel disimpan dalam ring buffer (maks 200 entri per mode) sehingga p50/p95 mencerminkan performa terbaru.
- `p95` akan bernilai 0 jika belum ada sampel; atau `null` pada benchmark quick jika jumlah sampel <20.
- Gunakan `average_duration_ms` untuk tren jangka panjang, dan `recent_latency_ms` untuk health real-time.

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
| TECHSCAN_TIERED | Aktifkan tiered heuristic pre-scan (stage 0) | 0 |
| TECHSCAN_TIERED_BUDGET_MS | Batas waktu (ms) heuristic cepat | 1800 |
| TECHSCAN_HEURISTIC_HTML_CAP_BYTES | Batas maksimum byte HTML yang dibaca heuristic (truncate) | 250000 |
| TECHSCAN_TIERED_ALLOW_EMPTY | Izinkan early-return meski kosong (edge case) | 0 |
| TECHSCAN_DEFER_FULL | Kembalikan hasil heuristic dulu, full scan di background | 0 |
| TECHSCAN_AUTO_FULL_MIN_TECH | Auto-trigger full (background) jika tech < N | 0 (off) |
| TECHSCAN_TIMEOUT_FALLBACK | Jika full scan timeout → fallback ke heuristic | 0 |
| TECHSCAN_MAX_ATTEMPTS | Paksa max attempts scan_domain (override retries) | (unset) |
| TECHSCAN_DISABLE_ADAPTIVE | Matikan adaptive timeout bump implicit | 0 |
| TECHSCAN_BULK_FAST_FIRST | Bulk: gunakan heuristic dulu (fast-first) | 0 |
| TECHSCAN_PERSIST_BROWSER | Mode server.js (browser persistent) | 0 |
| TECHSCAN_HARD_TIMEOUT_S | Hard wall-clock limit per domain (detik) | (unset) |
| TECHSCAN_BLOCK_RESOURCES | Blok static resources di fast mode | 1 |
| TECHSCAN_SYNTHETIC_HEADERS | Aktifkan tambahan header-based tech | 1 |
| TECHSCAN_TIMEOUT_FALLBACK | Fallback heuristic saat timeout fast | 0 |
| TECHSCAN_TIERED_BUDGET_MS | Budget ms untuk heuristic tier-0 | 1800 |
| TECHSCAN_VERSION_AUDIT | Aktifkan anotasi outdated vs latest | 1 |
| TECHSCAN_QUARANTINE_FAILS | Jumlah kegagalan sebelum domain di-quarantine | (unset=off) |
| TECHSCAN_QUARANTINE_MINUTES | Durasi quarantine menit | (unset) |
| TECHSCAN_PREFLIGHT | Aktifkan preflight TCP/DNS cepat (1=on) | 0 |
| TECHSCAN_DNS_NEG_CACHE | Detik cache DNS negative (resolve gagal) | 0 |
| TECHSCAN_SKIP_FULL_STRONG | Skip full scan jika strong CMS terdeteksi | 0 |
| TECHSCAN_BULK_TWO_PHASE | Bulk dua fase: heuristic semua dulu, full susulan | 0 |
| TECHSCAN_ULTRA_QUICK | Paksa semua fast scan hanya heuristic (tanpa Wappalyzer) | 0 |
| TECHSCAN_ULTRA_FALLBACK_MICRO | Aktifkan micro Wappalyzer fallback jika heuristic kosong | 0 |
| TECHSCAN_MICRO_TIMEOUT_S | Timeout detik untuk micro fallback | 2 |
| TECHSCAN_SKIP_VERSION_AUDIT | Lewati version audit (optimasi kecepatan) | 0 |
| TECHSCAN_DISABLE_SYNTHETIC | Nonaktifkan synthetic detection (headers/GA4/Tailwind/Floodlight) | 0 |
| TECHSCAN_HTML_SNIFF_TIMEOUT | Timeout detik HTML sniff ringan | 1.5 |
| TECHSCAN_HTML_SNIFF_BYTES | Maksimum byte dibaca HTML sniff | 20000 |
| TECHSCAN_HTML_SNIFF_CACHE_TTL | TTL cache hasil HTML sniff | 300 |
| TECHSCAN_DISABLE_IMPLICIT_RETRY | Matikan implicit timeout retry internal | 0 |

> Catatan: beberapa flag (seperti DEFER_FULL + TIERED) saling melengkapi: request cepat menerima jawaban heuristik dalam <2s, sementara Wappalyzer penuh berjalan di background dan cache diupdate otomatis.

## Tiered Heuristic Pre-Scan (Stage 0)

Heuristik cepat ("tier0") melakukan GET ringan (maks ±250KB HTML) dan mengekstrak sinyal prioritas:

Prioritas deteksi:

1. CMS / Framework (WordPress, Joomla, Drupal, Laravel, CodeIgniter, Next.js, Nuxt, React, Vue, Angular, Alpine.js)
2. WordPress Plugins (Elementor, WooCommerce, Contact Form 7, Yoast, WPForms, Wordfence, WP Rocket, Revolution Slider, dll.)
3. JS Libraries (jQuery, React, Vue.js, AngularJS, Alpine.js)
4. Web Server / Proxy (Nginx, Apache, Cloudflare, LiteSpeed, OpenResty, Caddy) + Security (HSTS)
5. Backend via `X-Powered-By` (PHP, Express, ASP.NET)
6. DB Panel Exposure (phpMyAdmin, Adminer) – low confidence
7. Version augmentation (meta generator, ?ver=, filename -x.y.z, banner comments, Angular ng-version, Next.js buildId)

Aturan Early Return (skip full scan):

- Ada CMS utama (WordPress/Joomla/Drupal) ATAU
- WordPress + plugin WP ditemukan ATAU
- ≥2 teknologi berbeda (kategori prioritas) ditemukan ATAU
- (Opsional) kosong tapi diizinkan (`TECHSCAN_TIERED_ALLOW_EMPTY=1`).

Jika tidak early-return dan `TECHSCAN_DEFER_FULL=1`: respons cepat dikirim dengan `engine="heuristic-tier0+deferred"` dan full scan jalan di background → hasil akhir menggantikan cache ketika selesai.

## Deferred & Auto-Trigger Full Scan

Mode:

- `TECHSCAN_DEFER_FULL=1`: selalu kembalikan hasil heuristic dulu.
- `TECHSCAN_AUTO_FULL_MIN_TECH=N`: jika jumlah tech hasil heuristic < N, sistem mengembalikan heuristic lalu menjadwalkan full scan background (tanpa flag deferred_full, memakai `auto_trigger_full`).

Field `tiered` untuk memonitor:

```json
{
  "tiered": {
    "stage": "heuristic",
    "early_return": true,
    "reason": "cms|multi|wordpress+plugins|empty|minimal",
    "deferred_full": true,
    "auto_trigger_full": true,
    "heuristic_duration": 0.842,
    "version_evidence": {"jQuery":[{"source":"library-pattern","value":"3.7.1"}]}
  }
}
```

## Timeout Handling & Fallback

Adaptive retry (timeout bump) aktif default (implicit attempt) kecuali dimatikan dengan `TECHSCAN_DISABLE_ADAPTIVE=1`.

Fallback Path:

1. Jika full scan timeout dan `TECHSCAN_TIMEOUT_FALLBACK=1` → jalankan heuristic baru (fresh) dan kembalikan itu (`engine=heuristic-tier0-timeout`).
2. Jika full scan error tetapi heuristic sudah ada (tiered enabled) → fallback ke hasil heuristic dengan flag `fallback=true`.
3. Hard cap (`TECHSCAN_HARD_TIMEOUT_S`) menghentikan loop scan keseluruhan meskipun adaptive ingin menambah attempt.

## Persistent Browser Mode

`TECHSCAN_PERSIST_BROWSER=1` mengaktifkan `node_scanner/server.js` (pool single browser). Dampak:

- Cold start lebih lambat sekali di awal.
- Subsequent scan jauh lebih cepat (tanpa open/close Chromium).
- Cocok untuk bulk volume tinggi.

## Bulk Fast-First Strategy

`TECHSCAN_BULK_FAST_FIRST=1` membuat setiap domain bulk memakai heuristic+deferred sehingga TTFB agregat turun drastis; full scan melengkapi data belakangan. Field `engine` menandai status awal.

## Version Augmentation & Evidence

Setiap sumber versi dicatat di `tiered.version_evidence` agar dapat audit asal versi. Sumber yang mungkin:

- `library-pattern` (regex filename seperti `jquery-3.7.1.js`)
- `meta-generator` (misal: `<meta name="generator" content="WordPress 6.5.2" />`)
- `asset-url` / `asset-presence` (?ver=, -x.y.z pada nama file)
- Banner comment (contoh: `/* bootstrap v5.3.3 */`)
- `ng-version-attr` (`ng-version="17.3.2"`)
- `next-data-buildId` (Next.js build marker)
- `x-powered-by` (PHP/8.2.x, Express/4.x)

Jika lebih dari satu nilai berbeda muncul, entri teknologi mendapat `alt_versions` sebagai daftar unik tersortir.

## Backend & Panel Detection (Heuristic)

Backend (X-Powered-By): PHP, Express, ASP.NET (confidence sedang). Versi diambil bila tersedia.

Panel DB (low confidence – bisa false positive):

- phpMyAdmin: pencarian substring yang mengandung "phpmyadmin" + kata terkait DB.
- Adminer: pencarian label "Adminer" opsional diikuti angka versi.

Disarankan tidak menganggap deteksi panel sebagai bukti eksposur tanpa verifikasi manual (misal lakukan HEAD/GET langsung ke jalur default /phpmyadmin/). Bisa ditingkatkan di masa depan.

## Ekstensi Server Detection Tambahan

Sudah didukung di header `Server`:

- Apache / httpd
- Nginx
- Cloudflare
- LiteSpeed / OpenLiteSpeed
- OpenResty
- Caddy

Rencana tambahan (bisa ditambah cepat): Gunicorn, uWSGI, Fastly, Varnish.

## Contoh Output Heuristic Early Return

```json
{
  "domain": "example.org",
  "engine": "heuristic-tier0",
  "scan_mode": "fast",
  "technologies": [
    {"name":"WordPress","version":"6.5.2","categories":["Content management systems","CMS"],"confidence":45},
    {"name":"jQuery","version":"3.7.1","categories":["JavaScript libraries"],"confidence":35}
  ],
  "tiered": {
    "stage": "heuristic",
    "early_return": true,
    "reason": "cms",
    "budget_ms": 1800,
    "version_evidence": {
      "jQuery": [{"source":"library-pattern","value":"3.7.1"}],
      "WordPress": [{"source":"meta-generator","value":"6.5.2"}]
    }
  }
}
```

## Benchmark Cepat (Heuristic vs Full)

Script bantuan: `scripts/test_inprocess.py`

Contoh jalankan heuristic-only + deferred full:

```pwsh
$env:TECHSCAN_TIERED='1'
$env:TECHSCAN_DEFER_FULL='1'
$env:TECHSCAN_TIMEOUT_FALLBACK='1'
python scripts/test_inprocess.py --domains wordpress.org vercel.com getbootstrap.com --fast --skip-baseline
```

## Unit Tests Heuristic Parsing

Tersedia unit test untuk fungsi helper parsing server & X-Powered-By serta pola panel DB.

Jalankan semua test:

```pwsh
python -m unittest discover -s tests -p 'test_*.py' -v
```

Contoh hasil:

```text
test_db_panel_patterns ... ok
test_extract_x_powered_by ... ok
test_parse_server_header_basic ... ok
test_parse_server_header_unmatched ... ok

Ran 4 tests in 0.01s
OK
```

## Heuristic Performance Quick Check

Script `scripts/test_inprocess.py` juga menampilkan ringkasan dua fase:

- `tiered_only` (tanpa persistent browser)
- `tiered_persist` (setelah enable persist → near-zero warm hits)

Gunakan untuk sanity sebelum deploy.

## Version Audit (Outdated Detection)

Fitur ini menambahkan anotasi apakah versi teknologi yang terdeteksi sudah mencapai versi terbaru berdasarkan file dataset `data/latest_versions.json`.

Aktif secara default (env `TECHSCAN_VERSION_AUDIT=1`). Set `TECHSCAN_VERSION_AUDIT=0` untuk menonaktifkan. Dapat di-toggle tanpa restart via endpoint admin runtime (`/admin/runtime/update`).

Struktur output tambahan:

```json
{
  "technologies": [
    {
      "name": "React",
      "version": "18.2.0",
      "audit": {"status": "outdated", "latest": "18.3.1"}
    },
    {
      "name": "Vue.js",
      "version": "3.5.8",
      "audit": {"status": "latest", "latest": "3.5.8"}
    }
  ],
  "audit": {
    "outdated_count": 2,
    "outdated_major": 1,
    "outdated_minor": 1,
    "outdated_patch": 0,
    "outdated": [
      {"name": "React", "version": "18.2.0", "latest": "18.3.1", "difference": "minor"},
      {"name": "jQuery", "version": "2.2.4", "latest": "3.7.1", "difference": "major"}
    ],
    "version_dataset": "latest_versions.json"
  }
}
```

Catatan:

- Hanya teknologi dengan field `version` yang dianotasi.
- Jika versi tidak match pola semver (misal build hash), dianggap tidak outdated (aman konservatif).
- Dataset bisa dioverride: `TECHSCAN_LATEST_VERSIONS_FILE=/path/custom_versions.json`.
- Field `alt_versions` (dari heuristic) tetap tidak mempengaruhi audit; hanya main `version` dipakai.
- Klasifikasi selisih (difference): `major`, `minor`, `patch` ditentukan dengan membandingkan komponen semver.
- Root meta menambahkan agregasi: `outdated_major`, `outdated_minor`, `outdated_patch`.

### Admin Dataset Versi

Endpoint baru untuk mengelola dataset versi terbaru:

1. `POST /admin/version_dataset/reload`
   - Body opsional: `{ "path": "custom.json" }` untuk set file baru sebelum reload.
   - Membersihkan cache internal (lru_cache) dan memuat ulang file.

2. `POST /admin/version_dataset/update`
   - Body contoh:

```json
{
  "mode": "merge",
  "data": {"React": "18.3.2", "Vue.js": "3.5.9"}
}
```

- Param `mode`: `merge` (default) menimpa key yang ada; `overwrite` mengganti seluruh isi file.
- Opsional `path` untuk menulis ke file lain; environment `TECHSCAN_LATEST_VERSIONS_FILE` akan di-set.

### Toggle Runtime Feature Flags

Runtime state: `GET /admin/runtime/state` sekarang mengembalikan juga `version_audit`.

Update tanpa restart:

```pwsh
curl -X POST http://127.0.0.1:5000/admin/runtime/update -H "X-Admin-Token: <token>" -H "Content-Type: application/json" -d '{"version_audit": false}'
```

Mengaktifkan kembali:

```pwsh
curl -X POST http://127.0.0.1:5000/admin/runtime/update -H "X-Admin-Token: <token>" -d '{"version_audit": true}'
```

### CSV Export Enhancement

`GET /export/csv` mendukung parameter tambahan:

- `outdated_only=1` hanya menampilkan domain dengan versi outdated.

Kolom baru:

- `outdated_count`, `outdated_list` (format: `Name (found -> latest)` pipe-separated)

`POST /bulk?format=csv` sekarang juga memasukkan kolom `outdated_count` dan `outdated_list`.

Output ringkas menampilkan rata-rata durasi per fase dan engine yang digunakan.

### Quarantine & Failure Tracking

Fitur opsional untuk mencegah pemborosan waktu pada domain yang terus-menerus gagal.

ENV contoh:

```pwsh
$env:TECHSCAN_QUARANTINE_FAILS='3'
$env:TECHSCAN_QUARANTINE_MINUTES='15'
```

Perilaku:

1. Setiap timeout / error menambah counter domain.
2. Saat mencapai ambang `TECHSCAN_QUARANTINE_FAILS`, domain masuk karantina selama `TECHSCAN_QUARANTINE_MINUTES`.
3. Selama karantina:

- Jika tiered aktif → dikembalikan heuristic cepat dengan flag `quarantined`.
- Jika tidak → error cepat tanpa membuka browser.

### Preflight DNS/TCP & Negative Cache

Aktifkan dengan:

```pwsh
$env:TECHSCAN_PREFLIGHT='1'
$env:TECHSCAN_DNS_NEG_CACHE='300'   # cache 5 menit untuk DNS gagal
```

Alur:

1. Resolve DNS + TCP connect port 443 (dan fallback 80) cepat.
2. Jika gagal → heuristic fallback (jika tiered) atau error `preflight unreachable`.
3. DNS gagal di-cache agar percobaan berulang tidak membuang waktu.

### Skip Full Scan Strong CMS

```pwsh
$env:TECHSCAN_SKIP_FULL_STRONG='1'
```

Jika heuristic mendeteksi WordPress + ≥1 plugin populer atau Joomla/Drupal, hasil dianggap final (`strong_cms_skip_full=true`) tanpa full scan.

### Two-Phase Bulk Pipeline

```pwsh
$env:TECHSCAN_BULK_TWO_PHASE='1'
```

Fase:

1. Heuristic semua domain (fase cepat homogen).
2. Full scan hanya domain yang masih perlu (bukan strong CMS, dan tidak already deferred/auto trigger).

Memberikan waktu respon awal bulk jauh lebih rendah sambil tetap melengkapi data penting di background.

### Granular Timing Metrics

Setiap hasil scan sekarang memiliki blok:

```json
"timing": {
  "overall_seconds": 18.734,
  "engine_seconds": 15.221,
  "overhead_seconds": 3.513
}
```

Makna:

- overall_seconds: total durasi fungsi.
- engine_seconds: waktu menjalankan proses Wappalyzer / persistent client.
- overhead_seconds: sisa (merge, synthetic, audit, parsing).

Gunakan untuk mengidentifikasi bottleneck (misal engine terlalu tinggi → aktifkan persist browser, overhead tinggi → evaluasi heuristic / audit / synthetic).

### Error Classification Metrics

`/admin/stats` sekarang menyertakan blok `errors` dengan kategori:

```json
{"errors": {"timeout":12,"dns":5,"ssl":2,"conn":9,"quarantine":3,"preflight":17,"other":4}}
```

Kategori:

- timeout: proses Wappalyzer melebihi batas waktu
- dns: resolusi gagal / NXDOMAIN
- ssl: kegagalan negosiasi / sertifikat
- conn: koneksi TCP/HTTP ditolak / unreachable
- quarantine: domain sedang di-quarantine (skip full)
- preflight: gagal pada preflight TCP/DNS awal
- other: sisanya

Gunakan untuk tuning: jika `preflight` tinggi → mungkin daftar domain banyak yang mati; `timeout` tinggi → pertimbangkan persist browser / turunkan blocking / enable tiered.

### Adaptive Bulk Concurrency (Eksperimental)

Aktifkan:

```pwsh
$env:TECHSCAN_BULK_ADAPT='1'
```

Logika: bulk worker menyesuaikan jumlah thread berdasarkan rolling average durasi dan error rate.

Env pendukung:

- `TECHSCAN_BULK_MIN_THREADS` (default 2)
- `TECHSCAN_BULK_MAX_THREADS` (default 2x nilai awal `concurrency`)

Heuristik default:

- avg < 1s dan error rate < 10% → naikkan concurrency +1
- avg > 3s atau error rate > 30% → turunkan concurrency -1

Catatan: Bekerja untuk path non-two-phase. Jika dua fase aktif, adaptasi saat ini tidak diterapkan (bisa ditambah nanti).

### Scheduling Jitter

Kurangi thundering herd saat banyak background scan dijadwalkan bersamaan.

```pwsh
$env:TECHSCAN_SCHEDULE_JITTER_MS='250'
```

Menambahkan delay acak 0–250ms pada eksekusi worker/bulk adaptive & heuristic background.

### Persistent Browser Watchdog

`TECHSCAN_PERSIST_WATCHDOG=1` mengaktifkan pemantauan kegagalan beruntun pada mode persistent. Jika jumlah kegagalan dalam jendela waktu tertentu melampaui ambang, proses browser otomatis di-restart.

Env terkait:

- `TECHSCAN_PERSIST_FAIL_THRESHOLD` (default 5)
- `TECHSCAN_PERSIST_RESTART_WINDOW` (detik, default 180)

Tampilan log contoh:

```text
watchdog restarting persistent browser (failures=5 in 180s)
```

Mencegah stuck state (browser hang atau memory leak).

### Quick Single Scan Mode (Sub-Second Heuristic)

Jika Anda hanya butuh jawaban cepat (CMS / framework / plugin utama) dan bisa menunggu detail lengkap belakangan, aktifkan quick mode.

Cara pakai (sekali request):

```pwsh
curl -X POST http://127.0.0.1:5000/scan -H "Content-Type: application/json" -d '{"domain":"example.com","quick":1}'
```

Atau global via ENV:

```pwsh
$env:TECHSCAN_QUICK_SINGLE='1'
python run.py
```

Opsional: jalankan full scan di background setelah heuristic cepat:

```pwsh
$env:TECHSCAN_QUICK_SINGLE='1'
$env:TECHSCAN_QUICK_DEFER_FULL='1'
python run.py
```

Parameter tambahan:

- `TECHSCAN_QUICK_BUDGET_MS` (default 700) batas waktu heuristic (hasil tuning internal; 700ms memberi latency rata-rata lebih rendah tanpa kehilangan deteksi dibanding 900–1200ms pada sampel pengujian).
  Catatan: Jika pada lingkungan Anda 700ms tidak konsisten (misal fluktuasi jaringan membuat justru lebih lambat), jalankan ulang `scripts/perf_quick_scan.py` dan set nilai terbaik lokal via ENV sebelum start service.

Output flag tambahan di response:

```json
"tiered": { "quick": true, "deferred_full_quick": true }
```

Ketika full scan background selesai, cache akan diperbarui otomatis sehingga permintaan berikutnya untuk domain yang sama mengembalikan data lengkap.

### Ultra Quick Heuristic & Micro Fallback (Eksperimental)

Aktifkan ultra quick untuk memaksa jalur heuristic-only (tanpa Wappalyzer) pada fast scan:

```pwsh
$env:TECHSCAN_ULTRA_QUICK='1'
```

Kelebihan: latensi sangat rendah (< ~0.7s). Kekurangan: teknologi bisa kosong jika hanya muncul setelah eksekusi JS/DOM penuh.
Micro fallback (sekali pemanggilan Wappalyzer timeout kecil) akan mencoba menambah teknologi ketika hasil heuristic kosong:

```pwsh
$env:TECHSCAN_ULTRA_FALLBACK_MICRO='1'
$env:TECHSCAN_MICRO_TIMEOUT_S='3'  # default 2 jika tidak diset
```

Field `tiered` tambahan:

| Field | Deskripsi |
|-------|-----------|
| micro_planned | Heuristic kosong & fallback diaktifkan |
| micro_started | Eksekusi micro dimulai |
| micro_timeout_s | Timeout detik dipakai micro |
| micro_fallback | True jika micro menambah teknologi |
| micro_added | Jumlah teknologi baru dari micro |
| micro_engine_seconds | Durasi engine micro (jika ada) |
| micro_attempted | Percobaan dilakukan tapi tidak menambah |
| micro_error | Pesan error/timeout micro |

Contoh:

```json
"tiered": {
  "quick": true,
  "micro_planned": true,
  "micro_started": true,
  "micro_timeout_s": 3,
  "micro_attempted": true,
  "micro_error": "timeout after 4s (attempt 2/2)"
}
```

Optimasi tambahan (opsional) untuk memangkas overhead:

```pwsh
$env:TECHSCAN_SKIP_VERSION_AUDIT='1'
$env:TECHSCAN_DISABLE_SYNTHETIC='1'
```

Strategi tuning:

- Banyak hasil kosong → matikan ULTRA dan gunakan quick biasa (`TECHSCAN_QUICK_BUDGET_MS=700..900`).
- Micro sering timeout → naikkan `TECHSCAN_MICRO_TIMEOUT_S` (4–5).
- Ingin micro one-shot tanpa adaptive retry → `TECHSCAN_DISABLE_ADAPTIVE=1`.

Catatan: fitur eksperimen; validasi akurasi sebelum produksi.

### HTML Sniff Caching (Lightweight CMS/Framework Hint)

Untuk mengurangi hasil kosong pada ultra/quick mode tanpa biaya besar, sistem melakukan "HTML sniff" ringan (single GET ke `/`) saat hasil heuristic awal kosong.

Karakteristik:

- Timeout kecil (`TECHSCAN_HTML_SNIFF_TIMEOUT`, default 1.5s)
- Batas byte (`TECHSCAN_HTML_SNIFF_BYTES`, default 20000)
- Mencoba `https://` lebih dulu lalu fallback `http://`
- Deteksi cepat berbasis substring (tanpa DOM parse penuh):
  - WordPress (`wp-content/`, `wp-includes/`, meta generator)
  - Joomla (`joomla!`)
  - Drupal (meta generator / content)
  - Laravel (kata `laravel` + indikator `csrf-token` / meta)
  - CodeIgniter (string `codeigniter` + `ci_session` / core file)
  - Next.js (`next-data`, `_next`)
  - Nuxt.js (`nuxt=` atau `nuxt.config`)

Teknologi hasil sniff diberi suffix `(sniff)` (contoh: `WordPress (sniff)`) agar tidak rancu dengan deteksi penuh.

Caching:

- TTL dikontrol `TECHSCAN_HTML_SNIFF_CACHE_TTL` (default 300 detik)
- Hit cache kedua → tidak network call, flag: `tiered.html_sniff_cached=true` + `tiered.html_sniff_cache_age=<detik>`
- Jika menambah teknologi: `tiered.html_sniff=true` dan `tiered.html_sniff_added=<n>`
- Jika cached tapi nihil deteksi tetap menandai `html_sniff_cached` (membantu analisa kenapa micro fallback dijalankan)

Rencana lanjutan (belum ada): reuse HTML heuristic utama agar tidak perlu GET kedua (env kandidat `TECHSCAN_SNIFF_REUSE_HEURISTIC`).

### Single Attempt Micro (Disable Implicit Retry)

Default `scan_domain` punya implicit timeout retry (attempt 2/2) jika `retries=0`. Micro fallback sekarang secara temporer memaksa:

- `TECHSCAN_DISABLE_ADAPTIVE=1` (kecuali user sudah set 1)
- `TECHSCAN_DISABLE_IMPLICIT_RETRY=1` (baru) supaya benar-benar single attempt.

Jika ingin menguji perilaku adaptif micro, jalankan service dengan `TECHSCAN_DISABLE_IMPLICIT_RETRY=0` atau kosongkan variable.

### HTML Cap Heuristic

Untuk menstabilkan latency pada halaman dengan HTML sangat besar, Anda bisa membatasi jumlah byte yang dibaca oleh heuristic:

```pwsh
$env:TECHSCAN_HEURISTIC_HTML_CAP_BYTES='120000'
```

Jika batas tercapai, response menyertakan `tiered.html_truncated=true`. Rekomendasi batas praktis 100k–180k; terlalu rendah (<60k) berisiko melewatkan plugin WordPress yang dimuat di bagian akhir.

### HTML Sniff Cache Endpoint & Flag

Untuk memonitor dan mengelola cache hasil HTML sniff ringan:

Endpoint baru:

1. `GET /admin/sniff_cache` → snapshot ringkas:

   ```json
   {
     "status": "ok",
     "entries": 12,
     "hits": 34,
     "misses": 18,
     "items": [
       {"domain": "example.com", "age_s": 42.15, "detected": 1, "bytes": 8741},
       {"domain": "wordpress.org", "age_s": 5.02, "detected": 2, "bytes": 14320}
     ]
   }
   ```
   Kolom:
   - `entries`: jumlah entry aktif dalam cache (respect TTL `TECHSCAN_HTML_SNIFF_CACHE_TTL`).
   - `hits` / `misses`: counter kumulatif selama proses hidup.
   - `items`: maksimal 200 entry terbaru (age terendah dahulu) dengan jumlah teknologi sniff (`detected`).

2. `POST /admin/sniff_cache` atau `DELETE /admin/sniff_cache` dengan body opsional:

```json
{"domains": ["example.com","unair.ac.id"]}
```

 - Jika tanpa `domains` → flush semua cache sniff.
 - Response: `{ "status":"ok", "flushed": true, "domains": [...] }`.

Flag tambahan yang mengendalikan sniff:

| Variable | Deskripsi | Default |
|----------|-----------|---------|
| TECHSCAN_HTML_SNIFF | Master enable/disable sniff ringan (1=aktif, 0=matikan) | 1 |

Catatan: Jika `TECHSCAN_HTML_SNIFF=0`, jalur sniff dilewati dan tiered flag `html_sniff_*` tidak muncul.

Integrasi dengan `/admin/stats`:

Blok `sniff_cache` akan muncul bila tersedia:

```json
{
  "status": "ok",
  "stats": {
    "sniff_cache": {"entries": 5, "hits": 22, "misses": 9},
    "hits": 120,
    "misses": 45
  }
}
```

Gunakan ini untuk memvalidasi efektivitas sniff (misal melihat rasio hit/miss; jika miss tinggi dan latency meningkat, pertimbangkan menaikkan TTL atau menyesuaikan pattern deteksi).


## Contoh Konfigurasi Rate & Heuristik (PowerShell)

```pwsh
$env:TECHSCAN_RATE_LIMIT='100 per minute'
$env:TECHSCAN_BULK_RATE_LIMIT='15 per minute'
$env:TECHSCAN_HEURISTICS_FILE='D:\\magang\\techscan\\app\\heuristics_timeout.json'
$env:TECHSCAN_ADMIN_TOKEN='secret123'
python run.py
```



