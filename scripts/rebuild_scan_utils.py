import pathlib

path = pathlib.Path(r"d:\magang\techscan\app\scan_utils.py")
content = path.read_text(encoding="utf-8")

# Find the end of deep_scan (return result) before fast_full_scan
# We look for "def fast_full_scan"
if "def fast_full_scan" in content:
    # Split and take the first part unique
    pre_content = content.split("def fast_full_scan")[0]

    # Verify it ends cleanly (it should end with return result or cache logic)
    # We should add a few newlines
    pre_content = pre_content.rstrip() + "\n\n"

    # Define clean fast_full_scan
    clean_func = '''# --------------------------- FAST-FULL (Bounded Single-Phase) SCAN ---------------------------
def fast_full_scan(domain: str, wappalyzer_path: str) -> Dict[str, Any]:
    """Run a *single* bounded full Wappalyzer scan with a strict wall-clock budget.

    Goals:
      - Faster than classic full (skip adaptive retry & multi-attempt logic)
      - More complete than quick (directly runs full engine, not just heuristic)
      - Deterministic upper bound (timeout budget in ms) returning partial heuristic fallback if exceeded.

    Environment:
      TECHSCAN_FAST_FULL_TIMEOUT_MS   (default 5000)   - hard cap (ms) for the full engine attempt.
      TECHSCAN_FAST_FULL_DISABLE_CACHE (='1')          - if set, do not cache result.
      TECHSCAN_FAST_FULL_CACHE_TTL     (int seconds)   - override cache TTL (default CACHE_TTL).

    Behaviour:
      - Disables adaptive bump & implicit retry (single shot)
      - Sets TECHSCAN_HARD_TIMEOUT_S to budget (seconds) so internal loop respects wall clock
      - If scan succeeds before timeout -> engine='fast-full'
      - If any exception (timeout/error) -> fallback to heuristic quick scan and mark partial

    Response extras:
      phases = { 'full_ms', 'timeout_ms', 'partial': bool, 'error'? }
      engine  = 'fast-full' | 'fast-full-partial'
      scan_mode = 'fast_full'
    """
    start_all = time.time()
    started_at = start_all
    # Resolve timeout budget
    try:
        budget_ms = int(os.environ.get('TECHSCAN_FAST_FULL_TIMEOUT_MS', '5000'))
    except ValueError:
        budget_ms = 5000
    if budget_ms < 1000:  # enforce minimal sane lower bound
        budget_ms = 1000
    timeout_s = max(1, int((budget_ms + 999) / 1000))  # round up to whole seconds for scan_domain

    # Preserve env toggles we will override
    old_ultra = os.environ.get('TECHSCAN_ULTRA_QUICK')
    old_adapt = os.environ.get('TECHSCAN_DISABLE_ADAPTIVE')
    old_impl = os.environ.get('TECHSCAN_DISABLE_IMPLICIT_RETRY')
    old_hard = os.environ.get('TECHSCAN_HARD_TIMEOUT_S')
    result: Dict[str, Any] | None = None
    error: str | None = None
    try:
        os.environ['TECHSCAN_ULTRA_QUICK'] = '0'
        os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = '1'
        os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY'] = '1'
        os.environ['TECHSCAN_HARD_TIMEOUT_S'] = str(timeout_s)
        full_start = time.time()
        # Single attempt full scan
        result = scan_domain(domain, wappalyzer_path, timeout=timeout_s, retries=0, full=True)
        full_done = time.time()
        full_elapsed = int((full_done - full_start) * 1000)
        result['engine'] = 'fast-full'
        result['scan_mode'] = 'fast_full'
        # Phases: full_attempt_ms (engine+processing), fallback_ms (0 if none)
        result['phases'] = {
            'full_ms': full_elapsed,              # legacy kept for compatibility
            'full_attempt_ms': full_elapsed,
            'fallback_ms': 0,
            'timeout_ms': budget_ms,
            'partial': False
        }
        result['started_at'] = started_at
        result['finished_at'] = full_done
        result['duration'] = round(full_done - started_at, 3)
    except Exception as fe:  # Timeout or other error -> fallback heuristic
        error = str(fe)
        logging.getLogger('techscan.fast_full').warning('fast_full primary scan failed domain=%s err=%s (fallback heuristic)', domain, fe)
        # Tandai waktu akhir attempt full sebelum fallback heuristic dimulai
        fail_end = time.time()
        # Fallback heuristic quick scan (best effort, never raise)
        try:
            quick_res = quick_single_scan(domain, wappalyzer_path, defer_full=False)
        except Exception as qe:
            # If heuristic also fails, synthesize minimal structure
            logging.getLogger('techscan.fast_full').error('heuristic fallback failed domain=%s err=%s', domain, qe)
            quick_res = {
                'domain': domain,
                'technologies': [],
                'categories': {},
                'tiered': {'heuristic_error': str(qe)}
            }
        quick_res['engine'] = 'fast-full-partial'
        quick_res['scan_mode'] = 'fast_full'
        fallback_done = time.time()
        # Heuristic result may include phases.heuristic_ms; treat that as fallback_ms
        heuristic_ms = 0
        try:
            heuristic_ms = int(quick_res.get('phases', {}).get('heuristic_ms') or 0)
        except Exception:
            heuristic_ms = 0
        # full_attempt_ms = waktu attempt full sampai error (fail_end - start_all)
        full_attempt_ms = int((fail_end - start_all) * 1000)
        # fallback_ms = heuristic_ms (durasi heuristic aktual)
        quick_res['phases'] = {
            'full_ms': full_attempt_ms,   # legacy alias
            'full_attempt_ms': full_attempt_ms,
            'fallback_ms': heuristic_ms,
            'timeout_ms': budget_ms,
            'partial': True,
            'error': error
        }
        quick_res['started_at'] = started_at
        quick_res['finished_at'] = fallback_done
        quick_res['duration'] = round(fallback_done - started_at, 3)
        result = quick_res
    finally:
        # Restore env
        if old_ultra is not None:
            os.environ['TECHSCAN_ULTRA_QUICK'] = old_ultra
        else:
            os.environ.pop('TECHSCAN_ULTRA_QUICK', None)
        if old_adapt is not None:
            os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = old_adapt
        else:
            os.environ.pop('TECHSCAN_DISABLE_ADAPTIVE', None)
        if old_impl is not None:
            os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY'] = old_impl
        else:
            os.environ.pop('TECHSCAN_DISABLE_IMPLICIT_RETRY', None)
        if old_hard is not None:
            os.environ['TECHSCAN_HARD_TIMEOUT_S'] = old_hard
        else:
            os.environ.pop('TECHSCAN_HARD_TIMEOUT_S', None)

    # Record stats for fast_full (treat as its own mode)
    try:
        elapsed = time.time() - start_all
        # Guarantee a minimal positive elapsed to avoid zero averages in tests when mocked scan returns instantly
        if elapsed <= 0:
            elapsed = 0.0005  # 0.5 ms minimal
        with _stats_lock:
            # increment scans separately from scan_domain internal counter (still counts underlying full engine)
            STATS['durations']['fast_full']['count'] += 1
            STATS['durations']['fast_full']['total'] += elapsed
            STATS['recent_samples']['fast_full'].append(elapsed)
    except Exception:
        pass

    # Targeted enrichment (only if still missing versions)
    if os.environ.get('TECHSCAN_VERSION_ENRICH','1') == '1' and result:
        try:
            if any(t.get('version') in (None, '') for t in result.get('technologies') or []):
                _targeted_version_enrichment(result, timeout=2.5)
        except Exception as ee:
            logging.getLogger('techscan.enrich').debug('fast_full enrich fail domain=%s err=%s', domain, ee)

    # Cache (unless disabled)
    if result and os.environ.get('TECHSCAN_FAST_FULL_DISABLE_CACHE','0') != '1':
        try:
            cache_ttl = CACHE_TTL
            try:
                c_override = int(os.environ.get('TECHSCAN_FAST_FULL_CACHE_TTL','0'))
                if c_override > 0:
                    cache_ttl = c_override
            except ValueError:
                pass
            cache_key = f"full:{result.get('domain')}"
            with _lock:
                _cache[cache_key] = {'ts': time.time(), 'data': result, 'ttl': cache_ttl}
                with _stats_lock:
                    STATS['cache_entries'] = len(_cache)
        except Exception:
            pass
    return result
'''
    path.write_text(pre_content + clean_func, encoding="utf-8")
    print("Rebuilt file successfully.")
else:
    print("Could not find fast_full_scan start.")
