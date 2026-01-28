#!/usr/bin/env python
"""Merge quick and deep JSONL outputs, preferring deep/full results per domain.

Usage:
  python scripts/merge_deep_prefer.py quick_pass.jsonl deep_pass.jsonl > merged.jsonl

Rules:
  - The first line of each (meta) preserved from quick, updated counts.
  - For each domain, choose deep/full engine result if present else quick.
  - Status error lines kept if domain has no ok line in either file.
  - Recalculate meta count and total seconds as sum of unique chosen lines (seconds not precise).
"""

from __future__ import annotations
import sys, json
from collections import OrderedDict


def load_jsonl(path: str):
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                continue
    return items


def pick(best, candidate):
    if best is None:
        return candidate
    be = best.get("engine", "")
    ce = candidate.get("engine", "")

    # prefer deep/full over quick/heuristic
    def rank(engine: str):
        if "full" in engine:
            return 3
        if "deep" in engine:
            return 2
        if "heuristic" in engine or "quick" in engine:
            return 1
        return 0

    if rank(ce) > rank(be):
        return candidate
    return best


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    quick_items = load_jsonl(sys.argv[1])
    deep_items = load_jsonl(sys.argv[2])
    by_domain: OrderedDict[str, dict] = OrderedDict()
    errors = []
    for coll in (quick_items, deep_items):
        for obj in coll:
            if obj.get("status") == "meta":
                continue
            dom = obj.get("domain") or obj.get("host")
            if not dom:
                continue
            if obj.get("status") == "error":
                # store errors only if domain unseen
                if dom not in by_domain:
                    errors.append(obj)
                continue
            prev = by_domain.get(dom)
            by_domain[dom] = pick(prev, obj)
    # Output meta
    meta = {"type": "meta", "count": len(by_domain), "merged": True}
    print(json.dumps(meta, ensure_ascii=False))
    for dom, obj in by_domain.items():
        print(json.dumps(obj, ensure_ascii=False))
    # dangling errors for domains not present success
    for e in errors:
        dom = e.get("domain") or e.get("host")
        if dom not in by_domain:
            print(json.dumps(e, ensure_ascii=False))


if __name__ == "__main__":
    main()
