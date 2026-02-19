import threading, time, os, logging, datetime, concurrent.futures
from . import db as _db
from .scan_utils import get_cached_or_scan, scan_unified

_LOG = logging.getLogger("techscan.periodic")

# Dedicated file logger for weekly rescan — always writes to disk so we can trace execution
_FILE_LOG = None

def _get_file_log():
    global _FILE_LOG
    if _FILE_LOG is None:
        _FILE_LOG = logging.getLogger("techscan.weekly_rescan_file")
        _FILE_LOG.setLevel(logging.DEBUG)
        try:
            log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "weekly_rescan.log")
            fh = logging.FileHandler(log_path, encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            _FILE_LOG.addHandler(fh)
        except Exception:
            pass  # fall back to root logger if file handler fails
    return _FILE_LOG

_WEEKLY_THREAD = None
_WEEKLY_LOCK = threading.Lock()
_WEEKLY_SWEEP_LOCK = threading.Lock()
_LAST_SCHEDULED_TS: float | None = None


def _weekly_budget_ms() -> int:
    try:
        return max(3000, int(os.environ.get("TECHSCAN_WEEKLY_RESCAN_BUDGET_MS", "30000")))
    except Exception:
        return 30000


def _persist_stub_scan(domain: str, start_ts: float, *, mode: str, error: str | None = None):
    finished = time.time()
    payload = {
        "domain": domain,
        "scan_mode": mode,
        "engine": f"weekly-rescan-{mode}",
        "technologies": [],
        "categories": {},
        "duration": round(max(0.0, finished - start_ts), 3),
        "started_at": start_ts,
        "finished_at": finished,
        "raw": {"weekly_rescan_stub": True},
        "error": error or "weekly rescan failure",
    }
    try:
        _db.save_scan(payload, from_cache=False, timeout_used=0)
    except Exception:
        _LOG.debug("weekly_rescan: failed persisting stub domain=%s", domain, exc_info=True)


def _run_weekly_scan(domain: str, wapp_path: str, *, reason: str, use_unified: bool) -> tuple[bool, str | None]:
    flog = _get_file_log()
    start_ts = time.time()
    flog.info("START domain=%s reason=%s unified=%s", domain, reason, use_unified)
    try:
        if use_unified:
            budget_ms = _weekly_budget_ms()
            result = scan_unified(domain, wapp_path, budget_ms=budget_ms)
            result["scan_mode"] = "unified"
            result.setdefault("engine", "unified")
            result.setdefault("started_at", start_ts)
            result.setdefault("finished_at", time.time())
            tech_count = len(result.get("technologies") or [])
            flog.info("SCAN_OK domain=%s techs=%d duration=%.1fs", domain, tech_count, time.time() - start_ts)
            try:
                _db.save_scan(result, from_cache=False, timeout_used=max(1, int(budget_ms / 1000)))
                flog.info("SAVE_OK domain=%s techs=%d", domain, tech_count)
            except Exception as save_err:
                _LOG.warning("weekly_rescan[%s]: save_scan FAILED domain=%s err=%s", reason, domain, save_err, exc_info=True)
                flog.error("SAVE_FAIL domain=%s err=%s", domain, save_err)
        else:
            try:
                get_cached_or_scan(domain, wapp_path, fresh=True, full=True)
            except TypeError:
                get_cached_or_scan(domain, wapp_path, fresh=True)
            flog.info("SCAN_OK domain=%s (legacy mode) duration=%.1fs", domain, time.time() - start_ts)
        return True, None
    except Exception as err:
        _LOG.exception("weekly_rescan[%s]: scan failed for %s", reason, domain)
        flog.error("SCAN_FAIL domain=%s err=%s duration=%.1fs", domain, err, time.time() - start_ts)
        _persist_stub_scan(domain, start_ts, mode="unified" if use_unified else "full", error=str(err))
        return False, str(err)


def _cron_to_weekday(value: str) -> int | None:
    """Translate cron-style day-of-week token to Python weekday (Mon=0)."""
    token = value.strip().upper()
    if token == "*":
        return None
    day_map = {
        "MON": 0,
        "TUE": 1,
        "WED": 2,
        "THU": 3,
        "FRI": 4,
        "SAT": 5,
        "SUN": 6,
    }
    if token in day_map:
        return day_map[token]
    try:
        num = int(token)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"invalid day token {value!r}") from exc
    if num in (0, 7):
        return 6
    if 1 <= num <= 6:
        return num - 1
    raise ValueError(f"unsupported day token {value!r}")


def _parse_weekly_cron(spec: str) -> tuple[int, int, int | None]:
    """Parse minimal cron syntax ``m h * * dow`` and return (minute, hour, weekday)."""
    parts = spec.split()
    if len(parts) != 5:
        raise ValueError("cron spec must have 5 fields (m h dom mon dow)")
    minute_s, hour_s, dom_s, month_s, dow_s = parts
    if dom_s != "*" or month_s != "*":
        raise ValueError("cron spec only supports * for day-of-month and month")
    try:
        minute = int(minute_s)
        hour = int(hour_s)
    except ValueError as exc:
        raise ValueError("minute and hour must be integers") from exc
    if not (0 <= minute <= 59 and 0 <= hour <= 23):
        raise ValueError("minute must be 0-59 and hour 0-23")
    weekday = _cron_to_weekday(dow_s)
    return minute, hour, weekday


def _compute_next_run(minute: int, hour: int, weekday: int | None, now: float | None = None) -> float:
    """Calculate next run epoch for the cron tuple using local time."""
    now = now or time.time()
    now_dt = datetime.datetime.fromtimestamp(now)
    target = now_dt.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if weekday is None:
        if target <= now_dt:
            target += datetime.timedelta(days=1)
        return target.timestamp()
    days_ahead = (weekday - now_dt.weekday()) % 7
    if days_ahead == 0 and target <= now_dt:
        days_ahead = 7
    target += datetime.timedelta(days=days_ahead)
    return target.timestamp()


def _resolve_next_run(now: float | None = None, *, allow_past: bool = False) -> float:
    cron_default = "0 3 * * 0"
    cron_spec = (os.environ.get("TECHSCAN_WEEKLY_RESCAN_CRON") or cron_default).strip()
    now = now or time.time()
    try:
        minute, hour, weekday = _parse_weekly_cron(cron_spec)
        now_dt = datetime.datetime.fromtimestamp(now)
        target = now_dt.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if weekday is None:
            if target <= now_dt and not allow_past:
                target += datetime.timedelta(days=1)
        else:
            days_ahead = (weekday - now_dt.weekday()) % 7
            if days_ahead == 0 and target <= now_dt:
                if allow_past:
                    # allow immediate catch-up when the scheduled slot was missed while server was down
                    pass
                else:
                    days_ahead = 7
            target += datetime.timedelta(days=days_ahead)
        nxt = target.timestamp()
        if allow_past and nxt < now:
            # return the missed slot so the caller can execute immediately
            pass
        elif nxt <= now:
            # ensure we always schedule a future run when catch-up not requested
            nxt = now + 1
        global _LAST_SCHEDULED_TS
        if _LAST_SCHEDULED_TS is None or abs(_LAST_SCHEDULED_TS - nxt) > 1:
            _LOG.info(
                "weekly_rescan: next run scheduled via cron=%s at %s", cron_spec, datetime.datetime.fromtimestamp(nxt)
            )
            _LAST_SCHEDULED_TS = nxt
        return nxt
    except Exception as err:
        fallback = int(os.environ.get("TECHSCAN_WEEKLY_RESCAN_INTERVAL_S", str(7 * 24 * 3600)))
        wait_seconds = max(60, fallback)
        _LOG.warning(
            "weekly_rescan: invalid cron spec %r (%s); falling back to interval %ss", cron_spec, err, wait_seconds
        )
        return now + wait_seconds


def _select_rescan_candidates(cutoff_ts: float, max_per_run: int) -> list[str]:
    """Select domains for weekly rescan - now selects ALL unique domains, not just stale ones."""
    domains: list[str] = []
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                # Changed: Select ALL unique domains, not just those with old scans
                cur.execute("SELECT DISTINCT domain FROM scans ORDER BY domain LIMIT %s", (int(max_per_run),))
                rows = cur.fetchall()
                domains = [r[0] for r in rows]
                _LOG.info("weekly_rescan: selected %d domains from scans table", len(domains))
    except Exception as query_err:
        _LOG.debug("weekly_rescan: primary query failed, trying domain_techs fallback (%s)", query_err)
        try:
            with _db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT DISTINCT domain FROM domain_techs ORDER BY domain LIMIT %s", (int(max_per_run),)
                    )
                    rows = cur.fetchall()
                    domains = [r[0] for r in rows]
                    _LOG.info("weekly_rescan: selected %d domains from domain_techs fallback", len(domains))
        except Exception:
            _LOG.exception("weekly_rescan: fallback domain_techs query failed")
            domains = []
    return domains


def _execute_weekly_rescan(
    wapp_path: str, max_per_run: int, lookback_days: int, *, reason: str = "scheduled", dry_run: bool = False
) -> dict:
    flog = _get_file_log()
    start = time.time()
    cutoff = start - (lookback_days * 24 * 3600)
    use_unified = os.environ.get("TECHSCAN_UNIFIED", "1") == "1"
    summary: dict[str, object] = {
        "reason": reason,
        "lookback_days": lookback_days,
        "max_per_run": max_per_run,
        "cutoff_ts": cutoff,
        "dry_run": dry_run,
        "use_unified": use_unified,
    }
    flog.info("=== SWEEP START reason=%s max=%d lookback=%d dry=%s ===", reason, max_per_run, lookback_days, dry_run)
    _LOG.info("weekly_rescan[%s]: sweep starting (max=%d lookback=%d)", reason, max_per_run, lookback_days)
    with _WEEKLY_SWEEP_LOCK:
        try:
            domains = _select_rescan_candidates(cutoff, max_per_run)
            summary["candidate_domains"] = len(domains)
            summary["sample_domains"] = domains[:15]
            summary["attempted"] = len(domains)
            flog.info("CANDIDATES count=%d sample=%s", len(domains), domains[:5])
            if not domains:
                _LOG.info("weekly_rescan[%s]: no domains qualified for rescan", reason)
                flog.info("NO CANDIDATES - sweep ending")
                summary["scanned"] = 0
                return summary
            _LOG.info(
                "weekly_rescan[%s]: rescanning %d domains (limit=%s lookback=%s)",
                reason,
                len(domains),
                max_per_run,
                lookback_days,
            )
            scanned = 0
            failures: list[dict[str, str]] = []
            if not dry_run:
                use_unified = bool(summary["use_unified"])
                try:
                    concurrency = int(os.environ.get("TECHSCAN_WEEKLY_RESCAN_CONCURRENCY", "1"))
                except Exception:
                    concurrency = 1
                concurrency = max(1, concurrency)
                futures: dict[concurrent.futures.Future, str] = {}
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(concurrency, max(1, len(domains)))
                ) as executor:
                    for domain in domains:
                        fut = executor.submit(
                            _run_weekly_scan, domain, wapp_path, reason=reason, use_unified=use_unified
                        )
                        futures[fut] = domain
                    total = len(futures)
                    completed = 0
                    for future in concurrent.futures.as_completed(futures):
                        domain = futures[future]
                        completed += 1
                        try:
                            ok, err = future.result()
                        except Exception as exc:
                            _LOG.exception("weekly_rescan[%s]: worker crashed for %s", reason, domain)
                            flog.error("WORKER_CRASH domain=%s err=%s", domain, exc)
                            failures.append({"domain": domain, "error": str(exc)})
                            continue
                        if ok:
                            scanned += 1
                        else:
                            failures.append({"domain": domain, "error": err or "unknown"})
                        # Log progress every 10 domains or on failure
                        if completed % 10 == 0 or not ok:
                            elapsed = time.time() - start
                            _LOG.info(
                                "weekly_rescan[%s]: progress %d/%d scanned=%d failed=%d elapsed=%.0fs",
                                reason, completed, total, scanned, len(failures), elapsed
                            )
                            flog.info(
                                "PROGRESS %d/%d scanned=%d failed=%d elapsed=%.0fs",
                                completed, total, scanned, len(failures), elapsed
                            )
            summary["scanned"] = scanned if not dry_run else 0
            if failures:
                summary["failed"] = len(failures)
                summary["failed_samples"] = failures[:15]
            flog.info("=== SWEEP DONE scanned=%d failed=%d duration=%.1fs ===", scanned, len(failures), time.time() - start)
            _LOG.info("weekly_rescan[%s]: sweep complete scanned=%d failed=%d duration=%.1fs", reason, scanned, len(failures), time.time() - start)
            return summary
        except Exception:
            _LOG.exception("weekly_rescan[%s]: unexpected error during sweep", reason)
            flog.error("SWEEP_EXCEPTION err=%s", reason, exc_info=True)
            summary["error"] = "sweep_failed"
            return summary
        finally:
            summary["duration_s"] = round(time.time() - start, 3)


def _run_weekly_loop(wapp_path: str, max_per_run: int = 2000, lookback_days: int = 7):
    """Worker loop scanning domains on a weekly cadence (cron-style or interval fallback)."""
    # Check if we missed a scheduled run recently (grace period catch-up)
    # allow_past=True returns the scheduled time even if it's in the past.
    next_run = _resolve_next_run(allow_past=True)
    now = time.time()
    
    # If the scheduled time was missed by more than 15 minutes (900s), skip it.
    # If it was missed by < 15 mins (e.g. server restart), we'll run it immediately.
    # If next_run is in the future, allow_past=True returns the future time anyway.
    grace_period = 900  # 15 minutes
    if next_run < (now - grace_period):
        _LOG.info("weekly_rescan: missed schedule at %s (too old), skipping to next", datetime.datetime.fromtimestamp(next_run))
        next_run = _resolve_next_run(allow_past=False)
    elif next_run < now:
        _LOG.info("weekly_rescan: catching up missed schedule at %s (within grace period)", datetime.datetime.fromtimestamp(next_run))

    flog = _get_file_log()
    flog.info("LOOP_START wapp_path=%s max_per_run=%d lookback=%d next_run=%s", wapp_path, max_per_run, lookback_days, datetime.datetime.fromtimestamp(next_run))
    while True:
        try:
            if os.environ.get("TECHSCAN_DISABLE_DB", "0") == "1":
                _LOG.info("weekly_rescan: DB disabled, skipping upcoming run")
                time.sleep(300)
                next_run = _resolve_next_run(allow_past=False)
                continue
            if os.environ.get("TECHSCAN_WEEKLY_RESCAN", "1") != "1":
                _LOG.info("weekly_rescan: disabled via environment; sleeping 10 minutes")
                time.sleep(600)
                next_run = _resolve_next_run(allow_past=False)
                continue
            now = time.time()
            if now < next_run:
                time.sleep(min(300, next_run - now))
                continue
            flog.info("CRON_TRIGGER now=%s next_run=%s", datetime.datetime.fromtimestamp(now), datetime.datetime.fromtimestamp(next_run))
            _LOG.info("weekly_rescan: cron trigger firing now=%s", datetime.datetime.fromtimestamp(now))
            _execute_weekly_rescan(wapp_path, max_per_run, lookback_days)
            flog.info("CRON_TRIGGER_DONE")
        except Exception:
            _LOG.exception("weekly_rescan: unexpected error in loop")
            flog.error("LOOP_EXCEPTION", exc_info=True)
        finally:
            lookback_env = os.environ.get("TECHSCAN_WEEKLY_RESCAN_LOOKBACK_DAYS")
            if lookback_env:
                try:
                    lookback_days = max(1, int(lookback_env))
                except Exception:
                    _LOG.debug("weekly_rescan: invalid lookback env=%s", lookback_env)
            max_env = os.environ.get("TECHSCAN_WEEKLY_RESCAN_MAX")
            if max_env:
                try:
                    max_per_run = max(1, int(max_env))
                except Exception:
                    _LOG.debug("weekly_rescan: invalid max env=%s", max_env)
            next_run = _resolve_next_run()


def start_weekly_rescan(app):
    global _WEEKLY_THREAD
    enabled = os.environ.get("TECHSCAN_WEEKLY_RESCAN", "1")
    if enabled != "1":
        _LOG.info("weekly rescan disabled (set TECHSCAN_WEEKLY_RESCAN=1 to enable)")
        return
    if os.environ.get("TECHSCAN_DISABLE_DB", "0") == "1":
        _LOG.info("weekly rescan skipped because TECHSCAN_DISABLE_DB=1")
        return
    try:
        wapp_path = app.config.get("WAPPALYZER_PATH")
        if not wapp_path:
            _LOG.warning("weekly rescan disabled: WAPPALYZER_PATH not configured")
            return
        if not os.path.exists(wapp_path):
            _LOG.warning("weekly rescan disabled: WAPPALYZER_PATH not found at %s", wapp_path)
            return
        max_per_run = int(os.environ.get("TECHSCAN_WEEKLY_RESCAN_MAX", "2000"))
        lookback_days = int(os.environ.get("TECHSCAN_WEEKLY_RESCAN_LOOKBACK_DAYS", "7"))
        with _WEEKLY_LOCK:
            if _WEEKLY_THREAD and _WEEKLY_THREAD.is_alive():
                _LOG.info("weekly rescan thread already running")
                return
            thread = threading.Thread(
                target=_run_weekly_loop, args=(wapp_path, max_per_run, lookback_days), daemon=True, name="weekly-rescan"
            )
            _WEEKLY_THREAD = thread
            thread.start()
        _LOG.info("weekly rescan thread started (max_per_run=%s lookback_days=%s)", max_per_run, lookback_days)
    except Exception:
        _LOG.exception("failed starting weekly rescan thread")


def run_weekly_rescan_once(
    app, *, max_domains: int | None = None, lookback_days: int | None = None, dry_run: bool = False
) -> dict:
    """Execute one-off weekly rescan sweep triggered manually (admin diagnostics)."""
    wapp_path = app.config.get("WAPPALYZER_PATH")
    if not wapp_path:
        raise ValueError("WAPPALYZER_PATH not configured; cannot run rescan")
    if not os.path.exists(wapp_path):
        raise FileNotFoundError(f"WAPPALYZER_PATH not found at {wapp_path}")
    max_env = os.environ.get("TECHSCAN_WEEKLY_RESCAN_MAX", "2000")
    lookback_env = os.environ.get("TECHSCAN_WEEKLY_RESCAN_LOOKBACK_DAYS", "7")
    max_per_run = int(max_domains if max_domains is not None else max_env)
    lookback = int(lookback_days if lookback_days is not None else lookback_env)
    return _execute_weekly_rescan(wapp_path, max_per_run, lookback, reason="manual", dry_run=dry_run)
