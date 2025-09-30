"""In-process end-to-end test of scan pipeline (tiered + persist) without starting external HTTP server.

Runs three phases:
  1. baseline (tiered off, persist off)
  2. tiered_only (tiered on, persist off)
  3. tiered_persist (tiered on, persist on)

It invokes the Flask app with test_client so routes are exercised:
  - /admin/runtime/update for toggles
  - /scan for each domain provided

Output: JSON summary with per-phase stats.

Usage (PowerShell):
  $env:PYTHONPATH='D:/magang/techscan'; D:/magang/techscan/venv/Scripts/python.exe scripts/test_inprocess.py \
      --domains wordpress.org reactjs.org example.com --show-details

Note: Persistent browser mode still launches the Node daemon via persistent_client when enabled.
Set TECHSCAN_DISABLE_DB=1 if Postgres not available.
"""
from __future__ import annotations
import os, time, json, argparse, statistics

# Ensure DB can be disabled for test speed if user wants
os.environ.setdefault('TECHSCAN_DISABLE_DB', '1')

from app import create_app


def phase_scan(client, label: str, domains: list[str], timeout_s: int):
    rows = []
    for d in domains:
        t0 = time.time()
        resp = client.post('/scan', json={'domain': d, 'timeout': timeout_s})
        dt_wall = time.time() - t0
        try:
            data = resp.get_json() or {}
        except Exception:
            data = {'error': 'invalid json', 'status_code': resp.status_code}
        rows.append({
            'domain': d,
            'status_code': resp.status_code,
            'error': data.get('error'),
            'engine': data.get('engine'),
            'early': (data.get('tiered') or {}).get('early_return'),
            'reason': (data.get('tiered') or {}).get('reason') or (data.get('tiered') or {}).get('heuristic_reason'),
            'duration_reported': data.get('duration'),
            'wall': round(dt_wall, 3),
            'tech_count': len(data.get('technologies') or [])
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--domains', nargs='+', default=['wordpress.org','reactjs.org','example.com'])
    ap.add_argument('--show-details', action='store_true')
    ap.add_argument('--warm', type=int, default=0, help='Warm-up scans (extra baseline repetitions)')
    ap.add_argument('--timeout', type=int, default=45, help='Timeout to send to /scan (seconds).')
    ap.add_argument('--baseline-timeout', type=int, default=None, help='Optional different timeout for baseline phase.')
    ap.add_argument('--fast', action='store_true', help='Fast mode: reduce timeouts (baseline=20,tiered=20,persist=20 unless overridden).')
    ap.add_argument('--skip-baseline', action='store_true', help='Skip baseline phase (start directly with tiered).')
    args = ap.parse_args()

    app = create_app()
    client = app.test_client()

    def toggle(tiered: bool, persist: bool):
        r = client.post('/admin/runtime/update', json={'tiered': tiered, 'persist_browser': persist})
        if r.status_code != 200:
            raise RuntimeError(f'Failed toggling flags {tiered=},{persist=} status={r.status_code} body={r.data[:200]}')

    phases: dict[str, list[dict]] = {}

    # optional warm baseline
    for i in range(args.warm):
        toggle(False, False)
        phase_scan(client, f'warm_{i}', args.domains)

    # Determine timeouts per phase
    base_timeout = args.baseline_timeout or args.timeout
    tiered_timeout = args.timeout
    persist_timeout = args.timeout
    if args.fast:
        base_timeout = 20 if args.baseline_timeout is None else args.baseline_timeout
        tiered_timeout = min(tiered_timeout, 20)
        persist_timeout = min(persist_timeout, 20)

    if not args.skip_baseline:
        toggle(False, False)
        phases['baseline'] = phase_scan(client, 'baseline', args.domains, base_timeout)

    # tiered only
    toggle(True, False)
    phases['tiered_only'] = phase_scan(client, 'tiered_only', args.domains, tiered_timeout)

    # tiered + persist
    toggle(True, True)
    # warm first domain to spawn browser
    phase_scan(client, 'warm_persist', [args.domains[0]], persist_timeout)
    phases['tiered_persist'] = phase_scan(client, 'tiered_persist', args.domains, persist_timeout)

    # summarize
    summary = []
    baseline_avg = None
    for label, rows in phases.items():
        successes = [r for r in rows if not r.get('error')]
        wall_times = [r['wall'] for r in successes]
        avg = round(statistics.mean(wall_times), 3) if wall_times else None
        if label == 'baseline':
            baseline_avg = avg
        early = sum(1 for r in successes if r.get('early'))
        timeouts = sum(1 for r in rows if r.get('error'))
        engines = sorted(set((r.get('engine') or 'unknown') for r in rows))
        entry = {
                'phase': label,
                'avg_wall_s': avg,
                'domains': len(rows),
                'success': len(successes),
                'timeouts_or_errors': timeouts,
                'early_count': early,
                'engines': engines
        }
        if baseline_avg and avg and label != 'baseline':
            try:
                entry['speedup_vs_baseline'] = round((baseline_avg / avg), 2)
            except Exception:
                pass
        summary.append(entry)

    output = {'summary': summary, 'phases': phases}
    print(json.dumps(output if args.show_details else {'summary': summary}, indent=2))

if __name__ == '__main__':
    main()
