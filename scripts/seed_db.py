#!/usr/bin/env python
"""Seed database with a sample set of domains via /scan or /bulk.
Usage:
  python scripts/seed_db.py --domains domains.txt --url http://127.0.0.1:5000 --bulk --concurrency 4
If --domains not supplied, uses a small default list.
"""

from __future__ import annotations
import argparse, pathlib, json, urllib.request, urllib.error, time


def post_json(url: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", help="File with one domain per line")
    ap.add_argument("--url", default="http://127.0.0.1:5000", help="Base service URL")
    ap.add_argument("--bulk", action="store_true", help="Use /bulk endpoint instead of multiple /scan calls")
    ap.add_argument("-c", "--concurrency", type=int, default=4, help="Bulk concurrency if using --bulk")
    args = ap.parse_args()

    if args.domains:
        p = pathlib.Path(args.domains)
        raw = p.read_text(encoding="utf-8").splitlines()
        domains = [l.strip() for l in raw if l.strip() and not l.startswith("#")]
    else:
        domains = ["example.com", "wordpress.org", "drupal.org", "joomla.org", "reactjs.org"]
    base = args.url.rstrip("/")

    start = time.time()
    if args.bulk:
        print(f"Seeding via /bulk count={len(domains)} ...")
        out = post_json(f"{base}/bulk", {"domains": domains, "concurrency": args.concurrency})
        print(f"Bulk done status_keys={list(out.keys())} duration={time.time() - start:.2f}s")
    else:
        print(f"Seeding via /scan sequential count={len(domains)}")
        for d in domains:
            try:
                r = post_json(f"{base}/scan", {"domain": d})
                print("OK", d, "techs=", len(r.get("technologies") or []))
            except urllib.error.HTTPError as he:
                print("ERR", d, he)
            except Exception as e:
                print("ERR", d, e)
    print("Seed complete. Check database tables.")


if __name__ == "__main__":
    main()
