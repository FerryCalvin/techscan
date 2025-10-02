#!/usr/bin/env python
"""Benchmark Fast-Full scan mode across timeout budgets.

Usage:
  python scripts/perf_fast_full_scan.py domains.txt --budgets 4000,5000,6000 --repeat 2 --url http://127.0.0.1:5000 --concurrency 4

If domains file omitted, uses a small default list.
Outputs JSON summary to stdout (one object per budget) unless --csv specified.
"""
from __future__ import annotations
import argparse, json, time, statistics, threading, queue, os, sys, pathlib
import urllib.request

DEFAULT_DOMAINS = [
    'wordpress.org','example.com','reactjs.org','joomla.org','drupal.org'
]

def post_json(base_url: str, domain: str):
    data = json.dumps({'domain': domain, 'fast_full': 1}).encode('utf-8')
    req = urllib.request.Request(f'{base_url}/scan', data=data, headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode('utf-8','ignore')
    return json.loads(raw)

def percentile(vals, p):
    if not vals:
        return 0
    if len(vals) == 1:
        return vals[0]
    k = int(round((p/100.0)*(len(vals)-1)))
    k = max(0,min(len(vals)-1,k))
    return sorted(vals)[k]

def run_budget(base_url: str, domains: list[str], budget_ms: int, repeat: int, concurrency: int, delay: float):
    os.environ['TECHSCAN_FAST_FULL_TIMEOUT_MS'] = str(budget_ms)
    results = []
    q = queue.Queue()
    for _ in range(repeat):
        for d in domains:
            q.put(d)
    lock = threading.Lock()
    latency = []
    partial = 0
    errors = 0
    tech_counts = []
    versions_counts = []

    def worker():
        nonlocal partial, errors
        while True:
            try:
                d = q.get_nowait()
            except queue.Empty:
                break
            t0 = time.time()
            try:
                res = post_json(base_url, d)
                took = (time.time()-t0)*1000
                phases = res.get('phases') or {}
                techs = res.get('technologies') or []
                v_with_version = sum(1 for t in techs if t.get('version'))
                with lock:
                    latency.append(phases.get('full_ms') or int(took))
                    tech_counts.append(len(techs))
                    versions_counts.append(v_with_version)
                    if phases.get('partial'): partial += 1
            except Exception:
                with lock:
                    errors += 1
            finally:
                if delay>0:
                    time.sleep(delay)
                q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(concurrency, q.qsize()))]
    for t in threads: t.start()
    for t in threads: t.join()

    summary = {
        'budget_ms': budget_ms,
        'samples': len(latency),
        'avg_full_ms': round(statistics.mean(latency),2) if latency else 0,
        'p50_full_ms': round(percentile(latency,50),2),
        'p95_full_ms': round(percentile(latency,95),2),
        'avg_tech_count': round(statistics.mean(tech_counts),2) if tech_counts else 0,
        'avg_with_version': round(statistics.mean(versions_counts),2) if versions_counts else 0,
        'partial_rate': round(partial/len(latency),3) if latency else 0,
        'errors': errors
    }
    return summary

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('domains_file', nargs='?', help='Text file of domains (one per line)')
    ap.add_argument('--budgets', default='5000', help='Comma separated timeout budgets ms (e.g. 4000,5000,6000)')
    ap.add_argument('--repeat', type=int, default=1, help='Repeat passes for statistical smoothing')
    ap.add_argument('--url', default='http://127.0.0.1:5000', help='Base service URL')
    ap.add_argument('-c','--concurrency', type=int, default=4)
    ap.add_argument('--delay', type=float, default=0.0, help='Inter-request delay seconds (throttle)')
    ap.add_argument('--csv', action='store_true', help='Output CSV instead of JSON list')
    args = ap.parse_args()

    if args.domains_file:
        path = pathlib.Path(args.domains_file)
        if not path.exists():
            print(f'File not found: {path}', file=sys.stderr)
            sys.exit(1)
        domains = []
        for line in path.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            domains.append(line)
        if not domains:
            domains = DEFAULT_DOMAINS
    else:
        domains = DEFAULT_DOMAINS

    budgets = []
    for b in args.budgets.split(','):
        try:
            iv = int(b.strip())
            if iv>0: budgets.append(iv)
        except ValueError:
            continue
    if not budgets:
        budgets = [5000]

    all_summaries = []
    for b in budgets:
        summary = run_budget(args.url.rstrip('/'), domains, b, args.repeat, args.concurrency, args.delay)
        all_summaries.append(summary)

    if args.csv:
        import csv, io
        out = io.StringIO()
        fieldnames = list(all_summaries[0].keys()) if all_summaries else ['budget_ms']
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_summaries:
            writer.writerow(row)
        print(out.getvalue().rstrip())
    else:
        print(json.dumps(all_summaries, indent=2))

if __name__ == '__main__':
    main()
