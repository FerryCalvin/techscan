import os, time, json, argparse, statistics, sys, pathlib
import requests

# Simple performance harness for quick scan mode.
# Usage:
#   python scripts/perf_quick_scan.py --domains domains.txt --budgets 1200 900 700 500 --repeat 2
# Ensure server running with TECHSCAN_QUICK_SINGLE=1 (and optionally TECHSCAN_QUICK_DEFER_FULL=0) for clean heuristic timing.

DEFAULT_BUDGETS = [1200, 900, 700, 500]

def load_domains(path):
    doms = []
    for line in open(path, 'r', encoding='utf-8'):
        line = line.strip()
        if not line or line.startswith('#'): continue
        doms.append(line)
    return doms

def run_scan(session, base_url, domain, budget):
    payload = {"domain": domain, "quick": 1}
    t0 = time.time()
    r = session.post(f"{base_url}/scan", json=payload, timeout=60)
    elapsed = time.time() - t0
    data = None
    try:
        data = r.json()
    except Exception:
        data = {"error": r.text[:120]}
    tech_count = len(data.get('technologies', [])) if isinstance(data, dict) else 0
    return {
        'domain': domain,
        'status': 'ok' if r.status_code == 200 else 'error',
        'elapsed': elapsed,
        'tech_count': tech_count,
        'reason': (data.get('tiered') or {}).get('reason') if isinstance(data, dict) else None,
        'error': data.get('error') if isinstance(data, dict) else None
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--domains', required=True, help='Path to domains list (one per line)')
    ap.add_argument('--budgets', nargs='*', type=int, default=DEFAULT_BUDGETS, help='List of heuristic budgets ms to test')
    ap.add_argument('--repeat', type=int, default=1, help='Repeat each budget pass N times')
    ap.add_argument('--server', default='http://127.0.0.1:5000', help='Base server URL')
    ap.add_argument('--warm', type=int, default=1, help='Warm-up passes (ignored in stats)')
    args = ap.parse_args()

    domains = load_domains(args.domains)
    if not domains:
        print('No domains loaded', file=sys.stderr)
        return 1

    session = requests.Session()

    results_summary = []

    for warm_i in range(args.warm):
        for b in args.budgets:
            os.environ['TECHSCAN_QUICK_BUDGET_MS'] = str(b)
            for d in domains:
                try:
                    run_scan(session, args.server, d, b)
                except Exception:
                    pass

    for b in args.budgets:
        times = []
        tech_counts = []
        errors = 0
        for rep in range(args.repeat):
            os.environ['TECHSCAN_QUICK_BUDGET_MS'] = str(b)
            for d in domains:
                res = run_scan(session, args.server, d, b)
                if res['status'] != 'ok':
                    errors += 1
                else:
                    times.append(res['elapsed'])
                    tech_counts.append(res['tech_count'])
        if times:
            summary = {
                'budget_ms': b,
                'samples': len(times),
                'avg_ms': round(statistics.mean(times)*1000,2),
                'p50_ms': round(statistics.median(times)*1000,2),
                'p95_ms': round(sorted(times)[int(len(times)*0.95)-1]*1000,2) if len(times) >= 20 else None,
                'avg_tech_count': round(statistics.mean(tech_counts),2) if tech_counts else 0,
                'min_tech_count': min(tech_counts) if tech_counts else 0,
                'max_tech_count': max(tech_counts) if tech_counts else 0,
                'errors': errors
            }
        else:
            summary = {'budget_ms': b, 'samples': 0, 'errors': errors}
        results_summary.append(summary)
        print(json.dumps(summary))
    # Write aggregate file
    out_path = pathlib.Path('perf_quick_summary.json')
    out_path.write_text(json.dumps(results_summary, indent=2))
    print('Saved summary to', out_path)

if __name__ == '__main__':
    raise SystemExit(main())
