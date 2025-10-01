# Contributing Guide

Thanks for your interest in improving TechScan! This guide explains how to set up the project, create high‑quality contributions, and keep performance goals intact.

## Table of Contents

1. Philosophy & Goals
2. Architecture Overview
3. Getting Started
4. Environment Flags
5. Running Scans (CLI & HTTP)
6. Testing & Quality Gates
7. Performance Expectations
8. Commit & Branch Conventions
9. Pull Request Checklist
10. Adding / Modifying Heuristics
11. Adding New Scan Modes
12. Optional: History Cleanup (Large Artifacts)
13. Release & Tagging

---

## 1. Philosophy & Goals

- Fast first result: Quick mode should finish in sub‑second to a few seconds.
- Layered depth: Quick → Deep (hybrid) → Full (optional) → Future: Fast-Full bounded.
- Version richness: Provide versions when discoverable with minimal overhead.
- Deterministic & cache‑friendly: Avoid unnecessary repeated heavy scans.
- Bulk efficiency: Only escalate a minority of targets.

## 2. Architecture Overview

Core module: `app/scan_utils.py`

- `quick_single_scan()` – heuristic + HTML sniff + micro fallback.
- `deep_scan()` – extends heuristic with bounded partial full scan.
- `bulk_quick_then_deep()` – two-phase escalation logic.
- `_targeted_version_enrichment()` – CMS version fetchers.
- Future `fast_full_scan()` (planned) – bounded full tech enumeration.

Routes: `app/routes/scan.py` exposes HTTP endpoints.
Heuristics: `app/heuristic_fast.py` (pattern & meta extraction).
Version audit: `app/version_audit.py` assists version logic.
Helper scripts: `scripts/` (filter, merge, perf, smoke).

## 3. Getting Started

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
# Optional: Node-based scanner (if using full / deep partial)
npm install --prefix node_scanner
```

Run server:

```bash
python run.py
```

Open: <http://localhost:5000>

## 4. Environment Flags (Key)

- `TECHSCAN_VERSION_ENRICH=1` – enable CMS enrichment.
- `TECHSCAN_DEEP_QUICK_BUDGET_MS` – ms budget for first heuristic stage of deep.
- `TECHSCAN_DEEP_FULL_TIMEOUT_S` – seconds cap for partial full phase.
- Bulk escalation:
  - `TECHSCAN_BULK_DEEP_MIN_TECH`
  - `TECHSCAN_BULK_DEEP_MAX_TECH`
  - `TECHSCAN_BULK_DEEP_MAX_PCT`
- Sniff & fallback:
  - `TECHSCAN_HTML_SNIFF=1`
  - `TECHSCAN_ULTRA_FALLBACK_MICRO=1`
- (Planned) `TECHSCAN_FAST_FULL_TIMEOUT_MS` – cap for upcoming fast-full.

## 5. Running Scans

Programmatic:

```python
from app.scan_utils import quick_single_scan, deep_scan
print(quick_single_scan("https://example.com"))
```

CLI / scripts:

```bash
python scripts/perf_quick_scan.py domains.txt
```

Bulk two-phase workflow:

1. Quick pass -> JSONL
2. Filter for deep: `python scripts/filter_need_deep.py quick.jsonl > need_deep.txt`
3. Deep scan subset
4. Merge: `python scripts/merge_deep_prefer.py quick.jsonl deep.jsonl > merged.jsonl`

## 6. Testing & Quality Gates

Run all tests:

```bash
pytest -q
```

Smoke test:

```bash
python scripts/smoke_scan_test.py https://example.com
```

Before submitting a PR ensure:

- Tests pass (no regressions)
- New code has basic coverage (happy path + 1 failure/timeout case)
- No obvious performance regressions (quick scan still fast on a cached domain)

## 7. Performance Expectations

- Quick: < ~1500 ms typical (network dependent). Avoid blocking operations beyond HTML fetch + heuristic parse.
- Deep: Bounded by configured budgets; should not exceed a few extra seconds beyond quick for average sites.
- Avoid synchronous full DOM automation in quick mode.

## 8. Commit & Branch Conventions

Branch naming:

- `feat/<short-desc>` – new feature
- `fix/<issue-or-bug>` – bugfix
- `perf/<area>` – performance improvement
- `chore/<task>` – non-functional (infra, deps, cleanup)
- `docs/<scope>` – documentation only

Commit message format:

```
<type>: <summary>

Optional body with rationale & perf notes.
```

Allowed types: feat, fix, perf, chore, docs, refactor, test, ci

## 9. Pull Request Checklist

- [ ] Title uses conventional prefix
- [ ] Linked issue (if applicable)
- [ ] CHANGELOG updated (Add an entry under "Unreleased")
- [ ] Docs / README updated for user-visible changes
- [ ] Tests added or adjusted
- [ ] No secrets or large blobs committed

## 10. Adding / Modifying Heuristics

- Keep regex lists minimal & ordered by frequency.
- Cache repeated expensive patterns.
- Add unit tests verifying detection & non-detection (negative cases).
- Document new heuristic in code comments.

## 11. Adding New Scan Modes

1. Define performance target & budget env var(s).
2. Implement in `scan_utils` (keep pure + side-effect light).
3. Add route / UI toggle if user-triggered.
4. Add tests for timeout adherence & output shape.
5. Update README + CHANGELOG.

## 12. Optional History Cleanup (Large Artifacts)

If the `venv` or big JSONL files were ever pushed and you want to purge them:

```bash
pip install git-filter-repo  # if not already available
# Dry run suggestion: clone a FRESH mirror first
git filter-repo --force --invert-paths --path venv/ --path *.jsonl

git push --force --tags origin main
```

After rewriting:

- Ask collaborators to reclone (history is rewritten).
- Consider creating a fresh tag (e.g., v0.4.0-recut) if necessary.

## 13. Release & Tagging

1. Update CHANGELOG: move items from Unreleased to new version section.
2. Commit with `docs: update changelog for vX.Y.Z`.
3. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. (Optional) Create GitHub Release page with highlights & perf notes.

---

Questions? Open an issue or start a discussion.

Happy scanning!
