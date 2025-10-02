# Changelog

All notable changes to this project will be documented in this file.

The format loosely follows Keep a Changelog and Semantic Versioning (when practical).

## [Unreleased]

### Added (Unreleased)

- Fast-Full bounded mode: single-attempt full engine with strict wall-clock budget (`TECHSCAN_FAST_FULL_TIMEOUT_MS`, default 5000ms) returning heuristic fallback on timeout/error.
- UI option and `/scan` flag `fast_full` plus tests (`tests/test_fast_full.py`).
- Fast-Full runtime metrics: per-mode duration aggregation & recent latency window (p50/p95) exposed via `/admin/stats`.
- Benchmark harness `scripts/perf_fast_full_scan.py` comparing multiple timeout budgets with latency & coverage metrics.
- Database: added `tech_count` and `versions_count` columns to `scans` with automatic migration & population for new scans.
- Admin endpoint `/admin/db_stats` exposing aggregate database metrics (total scans, domains tracked, top technologies, avg durations last 24h, version presence percentage).
- Backfill utility `scripts/backfill_counts.py` to populate new count columns for legacy rows.

### Changed (Unreleased)

- README updated with Fast-Full row in mode comparison and new environment variables table entries.
- README augmented with Fast-Full stats documentation and benchmark script usage examples.

### Notes (Unreleased)

- Fast-Full complements Quick and Deep: use when Deep misses some late-loading tech but classic Full is too slow.


## [v0.4.0] - 2025-10-01

### Added

- Quick scan pipeline: heuristic HTML sniff + micro fallback for near-instant detection.
- Deep (hybrid) scan mode: Extended heuristic phase + bounded partial full scan with phased timing metadata.
- Two-phase bulk strategy: Run quick on all targets, escalate selectively based on tech count, missing versions, or empties.
- Targeted version enrichment for common CMS (WordPress `/wp-json`, Drupal `CHANGELOG.txt`, Joomla language XML) behind `TECHSCAN_VERSION_ENRICH`.
- Helper scripts: `scripts/filter_need_deep.py`, `scripts/merge_deep_prefer.py`, performance and smoke test utilities.
- Admin/diagnostic routes & UI toggles for modes and cache/sniff controls.
- `version_audit` module for structured version evaluation.

### Changed

- Unified scan orchestration in `app/scan_utils.py` with enrichment integrated into quick & deep flows.
- Updated README with detailed mode comparison (Quick vs Deep vs Full) and environment variables.

### Removed / Cleaned

- Removed committed virtual environment and transient JSONL scan outputs from repository tracking.
- Added comprehensive `.gitignore` to prevent future inclusion of build artifacts, venv, `node_modules`, and large scan result files.

### Performance

- Typical quick scan duration: a few hundred milliseconds to low single-digit seconds (depending on network & HTML size).
- Deep scan maintains bounded latency via staged time budgets (`TECHSCAN_DEEP_QUICK_BUDGET_MS`, `TECHSCAN_DEEP_FULL_TIMEOUT_S`).

### Internal

- Added unit tests for heuristic parsing, error classification, quarantine handling, version audit, and helper scripts.
- Smoke test script validates quick and deep flows end-to-end.

### Notes

- Consider upcoming "fast-full" bounded mode to bridge gap between deep hybrid and unrestricted full scan.
- If the repository history previously contained large artifacts (e.g., `venv`), you may optionally rewrite history (see forthcoming CONTRIBUTING guidance).

[v0.4.0]: https://github.com/FerryCalvin/techscan/releases/tag/v0.4.0
