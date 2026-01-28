"""Run heuristic fast scan directly (without Flask or Wappalyzer) to validate tier0 logic.

Usage:
  $env:PYTHONPATH='d:/magang/techscan'; python scripts/test_heuristic_only.py --domains wordpress.org reactjs.org example.com

Outputs JSON lines with detected technologies and early_return flag.
"""

from __future__ import annotations
import argparse, json, time
from app.heuristic_fast import run_heuristic


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", nargs="+", required=True)
    ap.add_argument("--budget-ms", type=int, default=1800)
    args = ap.parse_args()
    out = []
    for d in args.domains:
        t0 = time.time()
        res = run_heuristic(d, budget_ms=args.budget_ms)
        res["wall"] = round(time.time() - t0, 3)
        # prune raw html (not stored) keep summary
        print(
            json.dumps(
                {
                    "domain": res["domain"],
                    "engine": res["engine"],
                    "early_return": res["tiered"]["early_return"],
                    "reason": res["tiered"]["reason"],
                    "techs": [{"name": t["name"], "version": t.get("version")} for t in res["technologies"]],
                    "duration": res["duration"],
                    "wall": res["wall"],
                },
                ensure_ascii=False,
            )
        )
        out.append(res)


if __name__ == "__main__":
    main()
