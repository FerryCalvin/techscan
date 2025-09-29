#!/usr/bin/env python
"""Bulk domain scanner CLI.
Reads a text file with one domain per line, scans using internal logic and prints JSONL.
Usage:
  python scripts/bulk_scan.py domains.txt --concurrency 6 --timeout 50 --fresh > results.jsonl
Options:
    --concurrency / -c   Number of parallel threads (default 4)
    --timeout / -t       Per-domain timeout seconds (default 45)
    --retries            Retry attempts if scan fails (timeout/error) (default 0)
    --ttl                Custom cache TTL seconds for new results (default 300)
  --fresh              Ignore cache for all domains
  --pretty             Pretty print (multi-line) instead of JSONL (slower, not recommended for > few hundred)
  --engine-path        Override WAPPALYZER_PATH (else env or config)
"""
from __future__ import annotations
import os, sys, json, argparse, time
from typing import List

# Allow running without installation
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.scan_utils import scan_bulk  # type: ignore


def read_domains(path: str) -> List[str]:
    out: List[str] = []
    if path == '-':  # stdin
        source = sys.stdin
    else:
        # Resolve search paths if not absolute and file missing
        candidate_paths = []
        if os.path.isabs(path):
            candidate_paths.append(path)
        else:
            candidate_paths.append(path)  # as provided (cwd)
            base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            candidate_paths.append(os.path.join(base, path))  # project root relative
            candidate_paths.append(os.path.join(base, 'node_scanner', path))  # node_scanner folder
        existing = next((p for p in candidate_paths if os.path.isfile(p)), None)
        if not existing:
            raise FileNotFoundError(f'File domains tidak ditemukan. Dicoba: {candidate_paths}')
        source = open(existing, 'r', encoding='utf-8')
    try:
        for line in source:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            out.append(line.lower())
    finally:
        if path != '-' and not source.closed:
            source.close()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file', help='File berisi daftar domain (satu per baris)')
    ap.add_argument('-c', '--concurrency', type=int, default=4)
    ap.add_argument('-t', '--timeout', type=int, default=45)
    ap.add_argument('--fresh', action='store_true', help='Abaikan cache (force rescan)')
    ap.add_argument('--retries', type=int, default=0, help='Jumlah retry jika scan gagal (timeout/error)')
    ap.add_argument('--ttl', type=int, help='Override TTL cache per hasil baru (detik, default 300)')
    ap.add_argument('--pretty', action='store_true', help='Output pretty JSON (bukan JSONL)')
    ap.add_argument('--engine-path', help='Override WAPPALYZER_PATH (jika tidak ingin pakai env)')
    args = ap.parse_args()

    wappalyzer_path = args.engine_path or os.environ.get('WAPPALYZER_PATH')
    if not wappalyzer_path:
        print('Error: WAPPALYZER_PATH belum diset dan --engine-path tidak diberikan', file=sys.stderr)
        sys.exit(2)
    if not os.path.isdir(wappalyzer_path):
        print('Error: path WAPPALYZER_PATH tidak valid', file=sys.stderr)
        sys.exit(2)

    try:
        domains = read_domains(args.file)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        print('Gunakan path absolut atau pindah ke root project, atau pakai "-" dan pipe dari stdin.', file=sys.stderr)
        sys.exit(2)
    if not domains:
        print('Tidak ada domain valid di file input', file=sys.stderr)
        sys.exit(1)

    start = time.time()
    results = scan_bulk(domains, wappalyzer_path, concurrency=args.concurrency, timeout=args.timeout, fresh=args.fresh, retries=args.retries, ttl=args.ttl)
    duration = time.time() - start

    if args.pretty:
        # Pretty print single JSON array
        print(json.dumps({'meta': {'count': len(results), 'seconds': round(duration, 2), 'retries': args.retries, 'ttl': args.ttl}, 'results': results}, ensure_ascii=False, indent=2))
    else:
        # JSONL header line (meta)
        meta = {'type': 'meta', 'count': len(results), 'seconds': round(duration, 2), 'retries': args.retries, 'ttl': args.ttl}
        print(json.dumps(meta, ensure_ascii=False))
        for r in results:
            print(json.dumps(r, ensure_ascii=False))

if __name__ == '__main__':
    main()
