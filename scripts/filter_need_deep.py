#!/usr/bin/env python
"""Filter domains from a quick JSONL pass that merit deep escalation.

Input: JSONL from stdout or file (arg1). Lines with {"status":"ok"...}.
Criteria (default):
  - technologies length < 2 OR (no technology has a non-empty 'version')
  - AND not already deep/full engine
Usage:
  python scripts/filter_need_deep.py quick_pass.jsonl > need_deep.txt
Options:
  --min-tech N        (default 2)
  --require-version   Only escalate when zero versions present (ignore tech_count)
  --max N             Cap number of domains emitted (first N matching)

If no file given, reads stdin.
"""
from __future__ import annotations
import sys, json, argparse

def iter_lines(handle):
    for line in handle:
        line=line.strip()
        if not line: continue
        if line.startswith('{'):
            yield line

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file', nargs='?')
    ap.add_argument('--min-tech', type=int, default=2)
    ap.add_argument('--require-version', action='store_true')
    ap.add_argument('--max', type=int, default=0)
    args = ap.parse_args()

    src = open(args.file,'r',encoding='utf-8') if args.file else sys.stdin
    out_count=0
    seen=set()
    for raw in iter_lines(src):
        try:
            obj=json.loads(raw)
        except Exception:
            continue
        if obj.get('status')=='meta':
            continue
        if obj.get('status')=='error':
            continue
        dom = obj.get('domain') or obj.get('host')
        if not dom or dom in seen:
            continue
        seen.add(dom)
        engine = obj.get('engine','')
        if 'deep' in engine or 'full' in engine:
            continue  # already escalated
        techs = obj.get('technologies') or []
        tech_count=len(techs)
        any_version=any(t.get('version') for t in techs)
        escalate=False
        if args.require_version:
            if not any_version:
                escalate=True
        else:
            if tech_count < args.min_tech or not any_version:
                escalate=True
        if escalate:
            print(dom)
            out_count+=1
            if args.max and out_count>=args.max:
                break
    if src is not sys.stdin:
        src.close()

if __name__=='__main__':
    main()
