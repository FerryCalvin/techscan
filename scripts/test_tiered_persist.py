"""Automated smoke test for tiered heuristic + persistent browser.

Usage (PowerShell example):
  $env:PYTHONPATH = 'd:/magang/techscan'; python scripts/test_tiered_persist.py \
      --domains wordpress.org reactjs.org example.com \
      --base-url http://localhost:5000

The Flask app and (optionally) persistent Node server must already be running.
This script will:
 1. Ensure flags OFF (baseline fast scan) and run scans.
 2. Enable tiered only, rerun scans.
 3. Enable tiered + persist, warm-up + rerun scans.
 4. Summarize durations, engines, early_return occurrences.
Outputs a compact table + JSON summary.
"""
from __future__ import annotations
import time, json, argparse, sys
import requests
from typing import List, Dict, Any

ADMIN_TOKEN = None  # set via --admin-token or env if needed

def _admin(url: str, path: str, method: str='GET', json_body: dict | None=None):
    headers = {}
    if ADMIN_TOKEN:
        headers['X-Admin-Token'] = ADMIN_TOKEN
    r = requests.request(method, f"{url}{path}", json=json_body, timeout=30, headers=headers)
    r.raise_for_status()
    return r.json()

def _scan(url: str, domain: str) -> Dict[str, Any]:
    r = requests.post(f"{url}/scan", json={'domain': domain}, timeout=120)
    try:
        data = r.json()
    except Exception:
        data = {'status': 'error', 'http_status': r.status_code, 'text': r.text[:200]}
    if r.status_code != 200:
        data['http_status'] = r.status_code
    return data

def run_phase(label: str, base_url: str, domains: List[str]):
    rows = []
    for d in domains:
        t0 = time.time()
        res = _scan(base_url, d)
        t1 = time.time()
        duration = res.get('duration') or round(t1-t0,2)
        rows.append({
            'domain': d,
            'engine': res.get('engine'),
            'early': (res.get('tiered') or {}).get('early_return'),
            'reason': (res.get('tiered') or {}).get('reason') or (res.get('tiered') or {}).get('heuristic_reason'),
            'techs': len(res.get('technologies') or []),
            'duration': duration,
            'cached': res.get('cached', False),
            'error': res.get('error')
        })
    return rows

def summarize(phases: Dict[str, List[Dict[str, Any]]]):
    # compute average per phase
    out = []
    for label, rows in phases.items():
        valid = [r for r in rows if not r.get('error')]
        avg = sum(r['duration'] for r in valid)/len(valid) if valid else 0
        out.append({'phase': label, 'avg_duration': round(avg,2), 'domains': len(rows)})
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base-url', default='http://localhost:5000')
    ap.add_argument('--domains', nargs='+', default=['wordpress.org','reactjs.org','example.com'])
    ap.add_argument('--admin-token')
    args = ap.parse_args()
    global ADMIN_TOKEN
    ADMIN_TOKEN = args.admin_token

    phases: Dict[str, List[Dict[str, Any]]] = {}
    base = args.base_url.rstrip('/')

    print('[1] Baseline (flags off)')
    _admin(base, '/admin/runtime/update', method='POST', json_body={'tiered': False, 'persist_browser': False})
    phases['baseline'] = run_phase('baseline', base, args.domains)

    print('[2] Tiered only')
    _admin(base, '/admin/runtime/update', method='POST', json_body={'tiered': True, 'persist_browser': False})
    phases['tiered_only'] = run_phase('tiered_only', base, args.domains)

    print('[3] Tiered + Persist (warm-up)')
    _admin(base, '/admin/runtime/update', method='POST', json_body={'tiered': True, 'persist_browser': True})
    # warm-up single trivial domain to launch browser
    _ = _scan(base, args.domains[0])
    phases['tiered_persist'] = run_phase('tiered_persist', base, args.domains)

    summary = summarize(phases)

    print('\nSummary:')
    for row in summary:
        print(f"  {row['phase']:<15} avg={row['avg_duration']}s domains={row['domains']}")
    print('\nDetails:')
    for ph, rows in phases.items():
        print(f"Phase: {ph}")
        for r in rows:
            print(f"  {r['domain']:<18} dur={r['duration']:<6} eng={r['engine']:<20} early={r['early']} reason={r['reason']} techs={r['techs']} cached={r['cached']} err={r['error']}")
    print('\nJSON Summary:')
    print(json.dumps({'summary': summary, 'phases': phases}, indent=2))

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted', file=sys.stderr)
        sys.exit(130)
