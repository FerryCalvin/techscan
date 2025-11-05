
from flask import Blueprint, request, jsonify, current_app
import os, logging, json, time
from ..scan_utils import flush_cache, load_heuristic_patterns, get_stats
from .. import heuristic_fast
import pathlib, shlex
from .. import safe_subprocess as sproc
from .. import version_audit
from .. import scan_utils
from .. import db as dbmod
from statistics import mean, median
import random

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def _check_auth():
    token_required = os.environ.get('TECHSCAN_ADMIN_TOKEN')
    if not token_required:  # open if not set
        return True
    provided = request.headers.get('X-Admin-Token')
    return provided == token_required

@admin_bp.before_request
def admin_auth():
    if not _check_auth():
        return jsonify({'error': 'unauthorized'}), 401

@admin_bp.route('/cache/flush', methods=['POST'])
def cache_flush():
    data = request.get_json(silent=True) or {}
    domains = data.get('domains') if isinstance(data.get('domains'), list) else None
    res = flush_cache(domains)
    logging.getLogger('techscan.admin').info('cache flush domains=%s removed=%s remaining=%s',
                                            'subset' if domains else 'all', res['removed'], res['remaining'])
    return jsonify({'status': 'ok', **res})

@admin_bp.route('/log_level', methods=['GET','POST'])
def log_level():
    """Get or update active root/application log level at runtime.

    GET  /admin/log_level -> { level: CURRENT }
    POST /admin/log_level {"level": "DEBUG"} (accepts DEBUG, INFO, WARNING, ERROR, CRITICAL)
    Optional header: X-Admin-Token if TECHSCAN_ADMIN_TOKEN set.
    Also updates env var TECHSCAN_LOG_LEVEL for downstream spawned processes.
    """
    current = logging.getLogger().getEffectiveLevel()
    if request.method == 'GET':
        return jsonify({'status':'ok','level': logging.getLevelName(current)})
    data = request.get_json(silent=True) or {}
    lvl = str(data.get('level') or '').upper().strip()
    mapping = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'WARN': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    if lvl not in mapping:
        return jsonify({'error': 'level must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL'}), 400
    logging.getLogger().setLevel(mapping[lvl])
    # Also ensure our namespace loggers inherit / update
    for name in ['techscan','techscan.scan','techscan.fast_full','techscan.scan_domain','techscan.admin']:
        logging.getLogger(name).setLevel(mapping[lvl])
    os.environ['TECHSCAN_LOG_LEVEL'] = lvl
    logging.getLogger('techscan.admin').info('log level changed runtime level=%s', lvl)
    return jsonify({'status':'ok','level': lvl})

@admin_bp.route('/heuristics/reload', methods=['POST'])
def heuristics_reload():
    load_heuristic_patterns()  # will read default path or env
    return jsonify({'status': 'ok', 'message': 'heuristics reloaded'})

@admin_bp.route('/stats', methods=['GET'])
def stats_view():
    stats = get_stats()
    # augment with sniff cache counts if available
    try:
        snap = scan_utils._sniff_cache_snapshot()  # type: ignore[attr-defined]
        stats['sniff_cache'] = {
            'entries': snap['entries'],
            'hits': snap['hits'],
            'misses': snap['misses']
        }
    except Exception as e:
        logging.getLogger('techscan.admin').debug('stats sniff_cache augmentation failed: %s', e)
    return jsonify({'status': 'ok', 'stats': stats})

@admin_bp.route('/phases', methods=['GET'])
def phases_view():
    """Return recent per-phase timings to help diagnose where time is spent.
    Query: limit (default 50)
    Response includes recent items and average per-phase summary.
    """
    try:
        limit = int(request.args.get('limit') or 50)
    except ValueError:
        limit = 50
    try:
        data = scan_utils.phases_recent(limit=limit)
        return jsonify({'status': 'ok', **data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/db_stats', methods=['GET'])
def db_stats_view():
    """Return aggregate database statistics (scans total, domains tracked, top tech, etc.).
    Lightweight wrapper over db.db_stats().
    """
    try:
        res = dbmod.db_stats()
        return jsonify({'status': 'ok', 'db_stats': res})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/db_pool', methods=['GET'])
def db_pool_view():
    """Return lightweight DB pool stats for monitoring.

    This endpoint surfaces pool metrics useful for Grafana probes or
    manual checks (max_size, num_connections, available, in_use, timestamp).
    Requires same admin auth as other admin endpoints.
    """
    try:
        stats = dbmod.pool_stats()
        return jsonify({'status': 'ok', 'pool': stats})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/sniff_cache', methods=['GET','POST','DELETE'])
def sniff_cache_view():
    """Inspect or flush HTML sniff cache.
    GET: returns snapshot (top 200 entries) with age & detected counts
    DELETE/POST with body {"flush": true, "domains": [..]} to clear all or selected domains.
    """
    if request.method in ('POST','DELETE'):
        body = request.get_json(silent=True) or {}
        domains = body.get('domains') if isinstance(body.get('domains'), list) else None
        from .. import scan_utils as su
        with su._html_sniff_lock:  # type: ignore[attr-defined]
            if domains:
                for d in list(su._html_sniff_cache.keys()):  # type: ignore[attr-defined]
                    if d in domains:
                        su._html_sniff_cache.pop(d, None)  # type: ignore[attr-defined]
            else:
                su._html_sniff_cache.clear()  # type: ignore[attr-defined]
        return jsonify({'status':'ok','flushed': True, 'domains': domains or 'all'})
    try:
        snap = scan_utils._sniff_cache_snapshot()  # type: ignore[attr-defined]
        return jsonify({'status':'ok', **snap})
    except Exception as e:
        logging.getLogger('techscan.admin').debug('sniff_cache snapshot failed: %s', e)
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/update_tech', methods=['POST'])
def update_tech():
    """Update technology definition data (Wappalyzer) without restarting.
    Strategy:
      1. If WAPPALYZER_PATH is a git repo -> git pull --ff-only
      2. Else if contains package.json -> npm update wappalyzer (or install if missing)
      3. Clear cached categories loader so new definitions picked up on next scan.
    Body (optional): {"force": true, "npm_cmd": "pnpm"}
    Returns JSON status + method + stdout/stderr snippet.
    """
    wpath = current_app.config.get('WAPPALYZER_PATH')
    if not wpath:
        return jsonify({'error': 'WAPPALYZER_PATH not configured'}), 400
    p = pathlib.Path(wpath)
    if not p.exists():
        return jsonify({'error': f'path not found: {wpath}'}), 400
    data = request.get_json(silent=True) or {}
    force = bool(data.get('force'))
    npm_cmd = data.get('npm_cmd') or os.environ.get('TECHSCAN_NPM_CMD') or 'npm'
    method = None
    stdout = ''
    stderr = ''
    try:
        if (p/'.git').exists():
            # Git repository update
            method = 'git-pull'
            cmd = ['git', '-C', str(p), 'pull', '--ff-only']
            proc = sproc.safe_run(cmd, capture_output=True, text=True, timeout=120)
            stdout, stderr = proc.stdout, proc.stderr
            if proc.returncode != 0:
                return jsonify({'error': 'git pull failed', 'method': method, 'stderr': stderr[-400:]}), 500
        else:
            pkg_json = p / 'package.json'
            if not pkg_json.exists():
                return jsonify({'error': 'No .git or package.json at WAPPALYZER_PATH; cannot auto-update.'}), 400
            # NPM update/install
            method = 'npm-update'
            # Force can trigger install of latest explicitly
            if force:
                cmd = [npm_cmd, 'install', 'wappalyzer@latest']
            else:
                cmd = [npm_cmd, 'update', 'wappalyzer']
            proc = sproc.safe_run(cmd, cwd=str(p), capture_output=True, text=True, timeout=240)
            stdout, stderr = proc.stdout, proc.stderr
            if proc.returncode != 0:
                return jsonify({'error': 'npm update failed', 'method': method, 'stderr': stderr[-400:]}), 500
        # Clear cached categories so new definitions used next scan
        try:
            from ..scan_utils import load_categories
            load_categories.cache_clear()  # type: ignore[attr-defined]
        except Exception as ce:
            logging.getLogger('techscan.admin').warning('failed clearing categories cache err=%s', ce)
        snippet_out = (stdout or '')[-400:]
        snippet_err = (stderr or '')[-400:]
        logging.getLogger('techscan.admin').info('update_tech success method=%s wpath=%s', method, wpath)
        return jsonify({'status': 'ok', 'method': method, 'stdout': snippet_out, 'stderr': snippet_err})
    except sproc.TimeoutExpired:
        return jsonify({'error': f'{method or "update"} command timeout'}), 504
    except FileNotFoundError as nf:
        return jsonify({'error': f'command not found: {nf}'}), 500
    except Exception as e:
        logging.getLogger('techscan.admin').error('update_tech error method=%s err=%s', method, e)
        return jsonify({'error': str(e), 'method': method}), 500

@admin_bp.route('/runtime/state', methods=['GET'])
def runtime_state():
    """Return current runtime feature flags that can be toggled without restart.
    Flags surfaced:
      persist_browser: whether persistent Puppeteer daemon usage is enabled (TECHSCAN_PERSIST_BROWSER)
      tiered: whether tiered heuristic pre-scan stage is enabled (TECHSCAN_TIERED)
    """
    persist = os.environ.get('TECHSCAN_PERSIST_BROWSER','0') == '1'
    tiered = os.environ.get('TECHSCAN_TIERED','0') == '1'
    version_audit_flag = os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1'
    return jsonify({'status': 'ok', 'flags': {
        'persist_browser': persist,
        'tiered': tiered,
        'version_audit': version_audit_flag
    }})

@admin_bp.route('/quick_diag', methods=['GET'])
def quick_diag():
    """Diagnostic heuristic + (optional) micro scan without using cache.
    Query params:
      domain=example.com (required)
      micro=1 (optional) force micro fallback attempt even if technologies found empty
    Returns heuristic result plus timing and (if micro) micro_* tiered flags similar to quick_single_scan.
    Does NOT persist or cache.
    """
    dom = request.args.get('domain','').strip()
    if not dom:
        return jsonify({'error':'domain required'}), 400
    try:
        norm = scan_utils.validate_domain(scan_utils.extract_host(dom))
    except Exception:
        return jsonify({'error':'invalid domain'}), 400
    budget = int(os.environ.get('TECHSCAN_QUICK_BUDGET_MS', '700'))
    allow_empty = os.environ.get('TECHSCAN_TIERED_ALLOW_EMPTY','0') == '1'
    t0 = time.time()
    try:
        hres = heuristic_fast.run_heuristic(norm, budget_ms=budget, allow_empty_early=allow_empty)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    hres.setdefault('tiered', {})['diag'] = True
    hres['duration'] = round(time.time()-t0,3)
    force_micro = request.args.get('micro') == '1'
    if (force_micro or not hres.get('technologies')) and os.environ.get('TECHSCAN_ULTRA_FALLBACK_MICRO','0') == '1':
        # replicate micro fallback logic minimally
        tier_meta = hres.setdefault('tiered', {})
        tier_meta['micro_planned'] = True
        try:
            micro_timeout = int(os.environ.get('TECHSCAN_MICRO_TIMEOUT_S','2'))
        except ValueError:
            micro_timeout = 2
        tier_meta['micro_timeout_s'] = micro_timeout
        tier_meta['micro_started'] = True
        _old_ultra = os.environ.get('TECHSCAN_ULTRA_QUICK')
        _old_adapt = os.environ.get('TECHSCAN_DISABLE_ADAPTIVE')
        try:
            if _old_ultra == '1':
                os.environ['TECHSCAN_ULTRA_QUICK'] = '0'
            if os.environ.get('TECHSCAN_DISABLE_ADAPTIVE','0') != '1':
                os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = '1'
            micro = scan_utils.scan_domain(norm, current_app.config.get('WAPPALYZER_PATH'), timeout=micro_timeout, retries=0, full=False)
        except Exception as me:
            tier_meta['micro_attempted'] = True
            tier_meta['micro_error'] = str(me)
        else:
            micro_techs = micro.get('technologies') or []
            if micro_techs:
                exist = {t['name'] for t in hres.get('technologies', [])}
                added = 0
                for t in micro_techs:
                    if t['name'] not in exist:
                        hres['technologies'].append(t)
                        exist.add(t['name'])
                        added += 1
                tier_meta['micro_fallback'] = True
                tier_meta['micro_added'] = added
                tier_meta['micro_engine_seconds'] = micro.get('timing', {}).get('engine_seconds') if isinstance(micro.get('timing'), dict) else None
            else:
                tier_meta['micro_attempted'] = True
                tier_meta.setdefault('micro_added', 0)
        finally:
            if _old_ultra == '1':
                os.environ['TECHSCAN_ULTRA_QUICK'] = '1'
            if _old_adapt is not None:
                os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = _old_adapt
            else:
                if os.environ.get('TECHSCAN_DISABLE_ADAPTIVE') == '1':
                    os.environ.pop('TECHSCAN_DISABLE_ADAPTIVE', None)
    return jsonify({'status':'ok', **hres})

@admin_bp.route('/runtime/update', methods=['POST'])
def runtime_update():
    """Update runtime feature flags (no process restart required).
    Body JSON (all optional – only provided keys are applied):
      {
        "persist_browser": true|false,
        "tiered": true|false
      }
    Returns previous and new effective values.
    """
    data = request.get_json(silent=True) or {}
    applied = {}
    previous = {
        'persist_browser': os.environ.get('TECHSCAN_PERSIST_BROWSER','0') == '1',
        'tiered': os.environ.get('TECHSCAN_TIERED','0') == '1',
        'version_audit': os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1'
    }
    # persist_browser toggle
    if 'persist_browser' in data:
        val = bool(data['persist_browser'])
        os.environ['TECHSCAN_PERSIST_BROWSER'] = '1' if val else '0'
        applied['persist_browser'] = val
    # tiered toggle (future heuristic stage)
    if 'tiered' in data:
        val = bool(data['tiered'])
        os.environ['TECHSCAN_TIERED'] = '1' if val else '0'
        applied['tiered'] = val
    if 'version_audit' in data:
        val = bool(data['version_audit'])
        os.environ['TECHSCAN_VERSION_AUDIT'] = '1' if val else '0'
        applied['version_audit'] = val
    new_state = {
        'persist_browser': os.environ.get('TECHSCAN_PERSIST_BROWSER','0') == '1',
        'tiered': os.environ.get('TECHSCAN_TIERED','0') == '1',
        'version_audit': os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1'
    }
    logging.getLogger('techscan.admin').info('runtime flags update previous=%s new=%s applied_keys=%s', previous, new_state, list(applied.keys()))
    return jsonify({'status': 'ok', 'previous': previous, 'new': new_state, 'changed': applied})

@admin_bp.route('/version_dataset/reload', methods=['POST'])
def version_dataset_reload():
    """Clear cached latest versions mapping so next audit uses updated file.
    If body provides 'path', temporarily set TECHSCAN_LATEST_VERSIONS_FILE before clearing cache.
    """
    data = request.get_json(silent=True) or {}
    path = data.get('path') if isinstance(data.get('path'), str) else None
    if path:
        os.environ['TECHSCAN_LATEST_VERSIONS_FILE'] = path
    try:
        version_audit.load_latest_versions.cache_clear()  # type: ignore[attr-defined]
        # Touch load to validate
        m = version_audit.load_latest_versions()
        return jsonify({'status':'ok','count': len(m)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/version_dataset/update', methods=['POST'])
def version_dataset_update():
    """Replace or patch the latest versions dataset.
    Body JSON:
      {"data": {"React": "18.3.2", ...}, "mode": "overwrite|merge", "path": "optional custom path"}
    - overwrite: replace entire file with provided data
    - merge (default): read existing file, update keys with provided mapping
    After write, cache cleared so new data active.
    """
    body = request.get_json(silent=True) or {}
    incoming = body.get('data') or {}
    mode = (body.get('mode') or 'merge').lower()
    if not isinstance(incoming, dict) or not incoming:
        return jsonify({'error': 'data mapping required'}), 400
    path = body.get('path') or os.environ.get('TECHSCAN_LATEST_VERSIONS_FILE') or str(pathlib.Path(__file__).resolve().parent.parent.parent / 'data' / 'latest_versions.json')
    p = pathlib.Path(path)
    try:
        if mode not in ('merge','overwrite'):
            return jsonify({'error': 'mode must be merge or overwrite'}), 400
        if mode == 'merge' and p.exists():
            try:
                current = json.loads(p.read_text(encoding='utf-8'))
                if not isinstance(current, dict):
                    current = {}
            except Exception:
                current = {}
            current.update({str(k): str(v) for k,v in incoming.items()})
            data_write = current
        else:
            data_write = {str(k): str(v) for k,v in incoming.items()}
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data_write, indent=2, ensure_ascii=False), encoding='utf-8')
        os.environ['TECHSCAN_LATEST_VERSIONS_FILE'] = str(p)
        version_audit.load_latest_versions.cache_clear()  # type: ignore[attr-defined]
        loaded = version_audit.load_latest_versions()
        return jsonify({'status': 'ok', 'path': str(p), 'count': len(loaded), 'mode': mode})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@admin_bp.route('/redis_health', methods=['GET'])
def redis_health():
    """Ping configured Redis instance used by Flask-Limiter (TECHSCAN_REDIS_URL).
    Returns {ok: true, ping: 'PONG'} or error with 500 if unavailable.
    """
    url = os.environ.get('TECHSCAN_REDIS_URL')
    if not url:
        return jsonify({'ok': False, 'error': 'TECHSCAN_REDIS_URL not set'}), 400
    try:
        # Import here to avoid hard-dependency when not used
        from redis import from_url
        r = from_url(url)
        pong = r.ping()
        return jsonify({'ok': True, 'ping': pong})
    except Exception as e:
        logging.getLogger('techscan.admin').warning('redis_health failed url=%s err=%s', url, e)
        return jsonify({'ok': False, 'error': str(e)}), 500

@admin_bp.route('/quarantine/state', methods=['GET'])
def quarantine_state():
    """List active quarantined domains (best-effort, internal state)."""
    # Access internal map via protected attributes; safe read-only snapshot
    res = []
    now = time.time()
    try:
        qm = scan_utils._fail_map  # type: ignore[attr-defined]
        for dom, meta in list(qm.items()):
            qt = meta.get('quarantine_until', 0.0)
            if qt and qt > now:
                res.append({'domain': dom, 'quarantine_until': qt, 'seconds_remaining': round(qt-now, 2)})
        res.sort(key=lambda x: x['seconds_remaining'], reverse=True)
    except Exception as e:
        logging.getLogger('techscan.admin').debug('quarantine state snapshot failed: %s', e)
        return jsonify({'error': str(e)}), 500
    return jsonify({'status':'ok','count': len(res),'items': res})

@admin_bp.route('/benchmark/quick', methods=['POST','GET'])
def benchmark_quick():
    """Run an internal quick heuristic benchmark for selected domains.
    Query/body params:
      domains: comma-separated list (query) or JSON {"domains": [...]} (fallback: uses 3 sample popular domains if absent)
      budgets: comma-separated ms list (e.g. 700,900,1200) or JSON {"budgets": [..]}
      repeat: repetitions per domain per budget (default 1)
      defer_full: 0/1 force disable deferred full (default 0) to keep pure heuristic timing
    Returns summary per budget: avg_ms, p50_ms, p95_ms, tech_count_avg, errors.
    Note: This issues HTTP calls through internal Flask test client to reuse existing route logic.
    """
    # Collect inputs
    data = request.get_json(silent=True) or {}
    domains_q = request.args.get('domains')
    budgets_q = request.args.get('budgets')
    repeat_q = request.args.get('repeat')
    domains = []
    if isinstance(data.get('domains'), list):
        domains = [d for d in data['domains'] if isinstance(d,str)]
    elif domains_q:
        domains = [d.strip() for d in domains_q.split(',') if d.strip()]
    if not domains:
        domains = ['wordpress.org','reactjs.org','example.com']
    budgets = []
    if isinstance(data.get('budgets'), list):
        budgets = [int(b) for b in data['budgets'] if isinstance(b,(int,str)) and str(b).isdigit()]
    elif budgets_q:
        for part in budgets_q.split(','):
            part = part.strip()
            if part.isdigit():
                budgets.append(int(part))
    if not budgets:
        budgets = [700,900,1200]
    try:
        repeat = int(data.get('repeat') or (repeat_q or 1))
    except ValueError:
        repeat = 1
    repeat = max(1, min(5, repeat))
    # Optionally force disable deferred full to isolate heuristic timing
    defer_full_flag = str(data.get('defer_full') or request.args.get('defer_full') or '0')
    disable_defer = defer_full_flag == '0'
    # We'll call the quick_single_scan directly to avoid network overhead
    wpath = current_app.config.get('WAPPALYZER_PATH') or os.environ.get('WAPPALYZER_PATH','')
    results = []
    errors = []
    for budget in budgets:
        times = []
        tech_counts = []
        err_count = 0
        for _ in range(repeat):
            for dom in domains:
                try:
                    t0 = time.time()
                    res = scan_utils.quick_single_scan(dom, wappalyzer_path=wpath, budget_ms=budget, defer_full=not disable_defer)
                    elapsed = (time.time()-t0)*1000.0
                    times.append(elapsed)
                    tech_counts.append(len(res.get('technologies',[])))
                except Exception as e:
                    err_count += 1
                    errors.append({'domain': dom, 'budget': budget, 'error': str(e)})
        if times:
            stimes = sorted(times)
            def pct(p):
                k = int(round((p/100.0)*(len(stimes)-1)))
                k = max(0, min(len(stimes)-1, k))
                return stimes[k]
            summary = {
                'budget_ms': budget,
                'samples': len(times),
                'avg_ms': round(mean(times),2),
                'p50_ms': round(pct(50),2),
                'p95_ms': round(pct(95),2) if len(times) >= 20 else None,
                'avg_tech_count': round(mean(tech_counts),2) if tech_counts else 0,
                'min_tech_count': min(tech_counts) if tech_counts else 0,
                'max_tech_count': max(tech_counts) if tech_counts else 0,
                'errors': err_count
            }
        else:
            summary = {'budget_ms': budget, 'samples': 0, 'errors': err_count}
        results.append(summary)
    return jsonify({'status':'ok','domains': domains,'repeat': repeat,'budgets': budgets,'summaries': results,'errors_detail': errors[:10]})

@admin_bp.route('/db_check', methods=['GET'])
def db_check():
    """Lightweight DB diagnostics: connectivity, counts, last scan info.
    Returns JSON with ok flag, error (if any), latency, counts, last_scan.
    """
    try:
        diag = dbmod.get_db_diagnostics()
        # Optional write-test (?write_test=1) performs an insert+rollback to validate write permissions separately from basic connectivity.
        write_test_flag = request.args.get('write_test') == '1'
        if write_test_flag and not diag.get('disabled'):
            from .. import db as _db
            try:
                with _db.get_conn() as conn:  # type: ignore
                    with conn.cursor() as cur:
                        # Use a SAVEPOINT so we can rollback just this test without affecting other outer work
                        cur.execute('SAVEPOINT techscan_diag')
                        try:
                            cur.execute("""INSERT INTO scans(domain, mode, started_at, finished_at, duration_ms, from_cache, adaptive_timeout, retries, timeout_used, tech_count, versions_count, technologies_json, categories_json, raw_json, error)
                                         VALUES ('__diag_write_test__','diag', NOW(), NOW(), 0, FALSE, FALSE, 0, 0, 0, 0, '[]'::jsonb, '{}'::jsonb, NULL, NULL)""")
                            # Rollback only the savepoint so no real row persists
                            cur.execute('ROLLBACK TO SAVEPOINT techscan_diag')
                            diag['write_test'] = {'ok': True}
                        except Exception as wte:
                            # Attempt to rollback savepoint; if that fails, full rollback best-effort
                            try:
                                cur.execute('ROLLBACK TO SAVEPOINT techscan_diag')
                            except Exception:
                                conn.rollback()
                            diag['write_test'] = {'ok': False, 'error': str(wte)}
            except Exception as outer_wte:
                diag['write_test'] = {'ok': False, 'error': str(outer_wte)}
        status = 200 if diag.get('ok') else 500 if not diag.get('disabled') else 200
        return jsonify({'status': 'ok' if diag.get('ok') else 'fail', 'diagnostics': diag}), status
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/health', methods=['GET'])
def health_summary():
    """Aggregate health snapshot for admin dashboard.
    Returns:
      - node_scanner_alive, heap_used_mb (if ping ok)
      - db_connected and brief stats
      - cache_items and uptime
    """
    # Uptime from system blueprint state if available
    try:
        import time
        uptime = time.time() - scan_utils._START_TIME  # type: ignore[attr-defined]
    except Exception:
        uptime = None
    # Node persistent daemon
    node = {'available': False}
    try:
        from .. import persistent_client as pc
        resp = pc.ping()
        node = {
            'available': True,
            'heap_used_mb': resp.get('heapUsedMB'),
            'pid': resp.get('pid'),
            'uptime_s': resp.get('uptimeSec') or resp.get('uptime')
        }
    except Exception as e:
        node = {'available': False, 'error': str(e)}
    # DB diagnostics (light)
    try:
        diag = dbmod.get_db_diagnostics()
        db_info = {
            'connected': bool(diag.get('ok')),
            'disabled': bool(diag.get('disabled')),
            'latency_ms': diag.get('latency_ms'),
            'scans_count': diag.get('scans_count'),
            'domain_techs_count': diag.get('domain_techs_count')
        }
    except Exception as e:
        db_info = {'connected': False, 'error': str(e)}
    # Cache items
    try:
        with scan_utils._lock:  # type: ignore[attr-defined]
            cache_items = len(scan_utils._cache)  # type: ignore[attr-defined]
    except Exception:
        cache_items = None
    out = {
        'status': 'ok' if node.get('available') or db_info.get('connected') else 'degraded',
        'node_scanner': node,
        'database': db_info,
        'cache_items': cache_items,
        'uptime_seconds': round(uptime,2) if uptime else None
    }
    return jsonify(out)
