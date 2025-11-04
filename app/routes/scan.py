from flask import Blueprint, request, jsonify, current_app, Response
import logging, time, os
from ..scan_utils import get_cached_or_scan, scan_bulk, DOMAIN_RE, extract_host, snapshot_cache, validate_domain, quick_single_scan, deep_scan, scan_unified, bulk_quick_then_deep, fast_full_scan
from .. import db as _db
from .. import bulk_store  # added for native batch caching
from flask_limiter import Limiter

bp = Blueprint('scan', __name__)

# Alias at module level to avoid accidental shadowing inside functions
deep_scan_fn = deep_scan

# Alias at module scope to avoid accidental function-local shadowing which can
# trigger UnboundLocalError when Python marks the name as local in a function.
deep_scan_fn = deep_scan

# Custom limits (can be overridden via env)
BULK_LIMIT = os.environ.get('TECHSCAN_BULK_RATE_LIMIT', '20 per minute')
SINGLE_LIMIT = os.environ.get('TECHSCAN_SINGLE_RATE_LIMIT', '120 per minute')

def limit_decorator():
    limiter: Limiter = current_app.extensions.get('limiter')  # type: ignore
    return limiter

@bp.route('/scan', methods=['POST','GET'])
def _scan_rate_wrapper():
    limiter = current_app.extensions.get('limiter')
    if limiter:
        # apply limit manually (since blueprint-level decorator sometimes loads before limiter)
        @limiter.limit(SINGLE_LIMIT)
        def inner():
            return scan_single_impl()
        return inner()
    return scan_single_impl()

def scan_single_impl():
    # Support both JSON POST and simple GET query form
    if request.method == 'GET':
        data = {
            'domain': request.args.get('domain') or request.args.get('d'),
            'timeout': request.args.get('timeout'),
            'retries': request.args.get('retries'),
            'ttl': request.args.get('ttl'),
            'full': request.args.get('full'),
            'deep': request.args.get('deep'),
            'fast_full': request.args.get('fast_full'),
            'fresh': request.args.get('fresh'),
            'quick': request.args.get('quick'),
        }
    else:
        data = request.get_json(silent=True) or {}
    start = time.time()
    # Optional per-request debug escalation (?debug=1) without restarting service
    debug_escalated = False
    if request.args.get('debug') == '1' or str((data or {}).get('debug')).lower() in ('1','true','yes'):
        root_logger = logging.getLogger()
        if root_logger.level > logging.DEBUG:
            root_logger.setLevel(logging.DEBUG)
            logging.getLogger('techscan.scan').debug('per-request debug escalation active')
            debug_escalated = True
    if data is None or not isinstance(data, dict):
        return jsonify({'error': 'invalid JSON body'}), 400
    raw_input = (data.get('domain') or '').strip()
    domain = extract_host(raw_input)
    timeout = int(data.get('timeout') or 45)
    retries = int(data.get('retries') or 0)
    ttl = data.get('ttl')
    full = bool(data.get('full') or False)
    deep = bool(data.get('deep') or False)
    fast_full = bool(data.get('fast_full') or False)
    try:
        ttl_int = int(ttl) if ttl is not None else None
    except ValueError:
        ttl_int = None
    fresh = bool(data.get('fresh') or False)
    logging.getLogger('techscan.scan').info('/scan request input=%s domain=%s timeout=%s retries=%s fresh=%s ttl=%s full=%s deep=%s fast_full=%s', raw_input, domain, timeout, retries, fresh, ttl_int, full, deep, fast_full)
    if not raw_input:
        return jsonify({'error': 'missing domain field'}), 400
    try:
        domain = validate_domain(domain)
    except ValueError:
        logging.getLogger('techscan.scan').warning('/scan invalid domain input=%r parsed=%r bytes=%s', raw_input, domain, '-'.join(str(ord(c)) for c in domain))
        return jsonify({'error': 'invalid domain format'}), 400
    wpath = current_app.config['WAPPALYZER_PATH']
    # Local alias to avoid accidental name-shadowing causing UnboundLocalError
    deep_scan_fn = deep_scan
    quick_flag = False
    # quick mode precedence: body.quick, query quick=1, or env TECHSCAN_QUICK_SINGLE=1
    if str(data.get('quick')).lower() in ('1','true','yes') or request.args.get('quick') == '1' or os.environ.get('TECHSCAN_QUICK_SINGLE','0') == '1':
        quick_flag = True
    defer_quick = os.environ.get('TECHSCAN_QUICK_DEFER_FULL','0') == '1'
    try:
        # If the request explicitly asks for a specific mode, respect it.
        # Otherwise prefer the more-complete deep/full path when unified mode is enabled
        # or when TECHSCAN_FORCE_FULL is set. This makes the scanner return the most
        # comprehensive detection by default after restarts.
        force_full_env = os.environ.get('TECHSCAN_FORCE_FULL','0') == '1'
        if fast_full:
            result = fast_full_scan(domain, wpath)
        elif deep or force_full_env:
            # If unified pipeline is enabled, prefer it even for explicit "deep" requests
            # This restores the multi-stage adaptive pipeline (heuristic -> py-local -> micro -> short full)
            if os.environ.get('TECHSCAN_UNIFIED', '1') == '1':
                try:
                    # Use provided timeout (seconds) as a minimum budget, convert to ms
                    budget_ms = max(6000, int(timeout) * 1000)
                except Exception:
                    budget_ms = 12000
                logging.getLogger('techscan.scan').info('deep request: using unified pipeline budget_ms=%s', budget_ms)
                try:
                    result = scan_unified(domain, wpath, budget_ms=budget_ms)
                except Exception as ue:
                    logging.getLogger('techscan.scan').warning('unified pipeline failed for deep request, falling back to deep_scan domain=%s err=%s', domain, ue)
                    result = deep_scan_fn(domain, wpath)
            else:
                result = deep_scan_fn(domain, wpath)
        elif quick_flag and not force_full_env:
            result = quick_single_scan(domain, wpath, defer_full=defer_quick, timeout_full=timeout, retries_full=retries)
        else:
            # Prefer unified/deep by default for completeness when unified mode enabled
            if os.environ.get('TECHSCAN_UNIFIED','1') == '1' or force_full_env:
                # Prefer the unified pipeline for more complete detection by default when
                # TECHSCAN_UNIFIED is enabled. Use the request timeout (seconds) as
                # budget_ms for the unified engine (converted to milliseconds).
                try:
                    budget_ms = max(3000, int(timeout) * 1000)
                except Exception:
                    budget_ms = 6000
                logging.getLogger('techscan.scan').info('defaulting to unified scan for more complete detection budget_ms=%s', budget_ms)
                result = scan_unified(domain, wpath, budget_ms=budget_ms)
            else:
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.getLogger('techscan.scan').debug('quick_flag_evaluation quick_flag=%s body.quick=%r env.TECHSCAN_QUICK_SINGLE=%s args.quick=%s', quick_flag, data.get('quick'), os.environ.get('TECHSCAN_QUICK_SINGLE','0'), request.args.get('quick'))
                result = get_cached_or_scan(domain, wpath, timeout=timeout, retries=retries, fresh=fresh, ttl=ttl_int, full=full)
        # Backward compat: ensure started_at/finished_at appear (cache hit may lack them)
        if 'started_at' not in result:
            result['started_at'] = result.get('timestamp')
        if 'finished_at' not in result:
            result['finished_at'] = int(time.time())
        # Observability: warn if scan returned very few technologies
        try:
            techs_check = result.get('technologies') or []
            if isinstance(techs_check, list) and len(techs_check) <= 3:
                logging.getLogger('techscan.scan').warning('Low tech count (%d) for domain=%s engine=%s phases=%s', len(techs_check), domain, result.get('engine'), result.get('phases'))
        except Exception:
            pass
        # Performance summary log (optional)
        if os.environ.get('TECHSCAN_PERF_LOG','0') == '1':
            try:
                techs = result.get('technologies') or []
                tech_count = len(techs)
                with_version = sum(1 for t in techs if t.get('version'))
                phases = result.get('phases') or {}
                tiered = result.get('tiered') or {}
                logger = logging.getLogger('techscan.perf')
                # Keep it compact key=value pairs on one line
                parts = [
                    f"domain={domain}",
                    f"engine={result.get('engine')}",
                    f"mode={result.get('scan_mode')}",
                    f"tech={tech_count}",
                    f"with_ver={with_version}",
                    f"duration_s={result.get('duration')}",
                    f"cached={result.get('cached', False)}",
                ]
                for k in ('heuristic_ms','synthetic_ms','micro_ms','node_full_ms','engine_ms','version_audit_ms'):
                    if k in phases:
                        parts.append(f"{k}={phases.get(k)}")
                if 'micro_used' in tiered:
                    parts.append(f"micro_used={bool(tiered.get('micro_used'))}")
                if 'node_full_used' in tiered:
                    parts.append(f"node_full_used={bool(tiered.get('node_full_used'))}")
                if 'retries' in result:
                    parts.append(f"retries={result.get('retries')}")
                if result.get('adaptive_timeout'):
                    parts.append("adaptive=1")
                logger.info('[perf] ' + ' '.join(parts))
            except Exception:
                pass
        logging.getLogger('techscan.scan').info('/scan success domain=%s quick=%s deep=%s fast_full=%s duration=%.2fs retries_used=%s', domain, quick_flag, deep, fast_full, time.time()-start, result.get('retries',0))
        if debug_escalated:
            # Revert to original level (INFO by default)
            try:
                base_level_name = os.environ.get('TECHSCAN_LOG_LEVEL', 'INFO').upper()
                base_level = getattr(logging, base_level_name, logging.INFO)
                logging.getLogger().setLevel(base_level)
            except Exception:
                pass
        # Persist scan (best-effort) if DB enabled
        try:
            duration = (result.get('finished_at', time.time()) - result.get('started_at', result.get('timestamp', time.time())))
            meta_for_db = {
                'domain': domain,
                'scan_mode': result.get('engine') or ('fast_full' if fast_full else 'deep' if deep else 'quick' if quick_flag else ('full' if full else 'fast')),
                'started_at': result.get('started_at'),
                'finished_at': result.get('finished_at'),
                'duration': duration,
                'technologies': result.get('technologies'),
                'categories': result.get('categories'),
                'raw': result.get('raw'),
                'retries': result.get('retries',0),
                'adaptive_timeout': result.get('phases',{}).get('adaptive'),
                'error': result.get('error')
            }
            timeout_used = 0
            # Derive timeout used if present in phases metadata
            phases = result.get('phases') or {}
            for k in ('full_budget_ms','timeout_ms','budget_ms'):
                if k in phases:
                    try:
                        timeout_used = int(phases[k])
                        break
                    except Exception:
                        pass
            _db.save_scan(meta_for_db, result.get('cached', False), timeout_used)
        except Exception as persist_ex:
            logging.getLogger('techscan.scan').warning('persist_failed domain=%s err=%s', domain, persist_ex)
        return jsonify(result)
    except Exception as e:
        # Log full traceback to help diagnose UnboundLocalError or other issues
        import traceback as _tb
        tb = _tb.format_exc()
        logging.getLogger('techscan.scan').exception('/scan error domain=%s err=%s\n%s', domain, e, tb)
        # Return traceback in response for easier local debugging (remove in production)
        try:
            return jsonify({'domain': domain, 'error': str(e), 'traceback': tb}), 500
        except Exception:
            return jsonify({'domain': domain, 'error': str(e)}), 500
        # Attempt to log failed attempt as scan row too (with error)
        try:
            _db.save_scan({
                'domain': domain,
                'scan_mode': 'error',
                'started_at': start,
                'finished_at': time.time(),
                'duration': time.time()-start,
                'technologies': [],
                'categories': {},
                'raw': None,
                'retries': 0,
                'error': str(e)
            }, from_cache=False, timeout_used=0)
        except Exception:
            pass
        return jsonify({'domain': domain, 'error': str(e)}), 500

@bp.route('/bulk', methods=['POST'])
def bulk_rate_wrapper():
    limiter = current_app.extensions.get('limiter')
    if limiter:
        @limiter.limit(BULK_LIMIT)
        def inner():
            return scan_bulk_route_impl()
        return inner()
    return scan_bulk_route_impl()

# BULK_NATIVE_ENHANCED
def scan_bulk_route_impl():
    """Native enhanced bulk route (batch_id retrieval, CSV export, cached_only, error_summary).
    Query / body parameters:
      domains: list[str]
      batch_id: retrieve previously stored batch (no new scan)
      format: json|csv
      cached_only: 1 -> CSV from cache (no scan)
      include_raw: 1 -> include raw JSON column in CSV
    """
    data = request.get_json(silent=True) or {}
    start = time.time()
    debug_escalated = False
    if request.args.get('debug') == '1' or (isinstance(data, dict) and str(data.get('debug')).lower() in ('1','true','yes')):
        root_logger = logging.getLogger()
        if root_logger.level > logging.DEBUG:
            root_logger.setLevel(logging.DEBUG)
            logging.getLogger('techscan.bulk').debug('per-request debug escalation active')
            debug_escalated = True
    batch_id_req = request.args.get('batch_id') or data.get('batch_id')
    out_format = (request.args.get('format') or data.get('format') or 'json').lower()
    include_raw = (request.args.get('include_raw') == '1') or bool(data.get('include_raw'))
    cached_only = (request.args.get('cached_only') == '1') or bool(data.get('cached_only'))

    # Retrieval path (no new scan)
    if batch_id_req:
        meta = bulk_store.get_batch(batch_id_req)
        if not meta:
            return jsonify({'error': 'batch_id not found', 'batch_id': batch_id_req}), 404
        results = meta['results']
        ok = sum(1 for r in results if r and r.get('status') == 'ok')
        buckets = {'timeout':0,'dns':0,'ssl':0,'connection':0,'other':0}
        for r in results:
            if not r or r.get('status') == 'ok':
                continue
            err = (r.get('error') or '').lower()
            if 'timeout' in err or 'timed out' in err:
                buckets['timeout'] += 1
            elif 'dns' in err or 'nodename' in err:
                buckets['dns'] += 1
            elif 'ssl' in err or 'cert' in err:
                buckets['ssl'] += 1
            elif 'connection' in err or 'refused' in err or 'unreachable' in err:
                buckets['connection'] += 1
            else:
                buckets['other'] += 1
        if out_format == 'csv':
            import csv, io, json as _json
            output = io.StringIO()
            fieldnames = ['status','domain','timestamp','tech_count','technologies','categories','cached','duration','retries','engine','error','outdated_count','outdated_list']
            if include_raw:
                fieldnames.append('raw')
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                if not r:
                    continue
                if r.get('status') != 'ok':
                    row_err = {k: r.get(k) for k in ['status','domain','error']}
                    writer.writerow(row_err)
                    continue
                techs = r.get('technologies') or []
                tech_list = [f"{t.get('name')}" + (f" ({t.get('version')})" if t.get('version') else '') for t in techs]
                categories = sorted((r.get('categories') or {}).keys())
                audit_meta = r.get('audit') or {}
                outdated_items = audit_meta.get('outdated') or []
                outdated_list_str = ' | '.join(f"{o.get('name')} ({o.get('version')} -> {o.get('latest')})" for o in outdated_items)
                row = {
                    'status': r.get('status'),
                    'domain': r.get('domain'),
                    'timestamp': r.get('timestamp'),
                    'tech_count': len(techs),
                    'technologies': ' | '.join(tech_list),
                    'categories': ' | '.join(categories),
                    'cached': r.get('cached'),
                    'duration': r.get('duration'),
                    'retries': r.get('retries',0),
                    'engine': r.get('engine'),
                    'error': r.get('error'),
                    'outdated_count': audit_meta.get('outdated_count'),
                    'outdated_list': outdated_list_str
                }
                if include_raw:
                    row['raw'] = _json.dumps(r.get('raw'), ensure_ascii=False)
                writer.writerow(row)
            csv_data = output.getvalue()
            return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename=bulk_batch_{batch_id_req}.csv'})
        return jsonify({'count': len(results), 'ok': ok, 'batch_id': batch_id_req, 'error_summary': buckets, 'results': results, 'retrieved': True})

    # cached_only CSV path (no re-scan)
    if out_format == 'csv' and cached_only:
        domains = data.get('domains') or []
        if not isinstance(domains, list):
            return jsonify({'error': 'domains field must be a list'}), 400
        from ..scan_utils import snapshot_cache as _snapshot_cache
        cache_rows = _snapshot_cache(domains)
        best = {}
        for r in cache_rows:
            dom = r.get('domain')
            if not dom:
                continue
            prev = best.get(dom)
            if not prev or (r.get('scan_mode')=='full' and prev.get('scan_mode')!='full'):
                best[dom] = r
        import csv, io, json as _json
        output = io.StringIO()
        fieldnames = ['status','domain','timestamp','tech_count','technologies','categories','cached','duration','retries','engine','error','outdated_count','outdated_list']
        if include_raw:
            fieldnames.append('raw')
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        now_ts = int(time.time())
        for d in domains:
            dom_l = (d or '').strip().lower()
            r = best.get(dom_l)
            if not r:
                writer.writerow({'status':'missing','domain': dom_l})
                continue
            techs = r.get('technologies') or []
            tech_list = [f"{t.get('name')}" + (f" ({t.get('version')})" if t.get('version') else '') for t in techs]
            categories = sorted((r.get('categories') or {}).keys())
            audit_meta = r.get('audit') or {}
            outdated_items = audit_meta.get('outdated') or []
            outdated_list_str = ' | '.join(f"{o.get('name')} ({o.get('version')} -> {o.get('latest')})" for o in outdated_items)
            row = {
                'status':'ok','domain':dom_l,'timestamp':r.get('timestamp') or now_ts,'tech_count':len(techs),
                'technologies':' | '.join(tech_list),'categories':' | '.join(categories),'cached':True,
                'duration': r.get('duration'),'retries': r.get('retries',0),'engine': r.get('engine'),
                'error': r.get('error'),'outdated_count': audit_meta.get('outdated_count'),'outdated_list': outdated_list_str
            }
            if include_raw:
                row['raw'] = _json.dumps(r.get('raw'), ensure_ascii=False)
            writer.writerow(row)
        csv_data = output.getvalue()
        return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=bulk_cached.csv'})

    # New scan path
    data = request.get_json(silent=True) or {}
    domains = data.get('domains') or []
    if not isinstance(domains, list):
        return jsonify({'error': 'domains field must be a list'}), 400
    if not domains:
        return jsonify({'error': 'domains list empty'}), 400

    timeout = int(data.get('timeout') or 30)
    retries = int(data.get('retries') or 2)
    ttl = data.get('ttl')
    try:
        ttl_int = int(ttl) if ttl is not None else None
    except ValueError:
        ttl_int = None
    full = bool(data.get('full') or False)
    two_phase = bool(data.get('two_phase') or (request.args.get('two_phase')=='1'))
    fallback_quick = bool(data.get('fallback_quick') or (request.args.get('fallback_quick')=='1'))
    if not fallback_quick and os.environ.get('TECHSCAN_BULK_FALLBACK_QUICK_DEFAULT','0') == '1':
        fallback_quick = True
    fresh = bool(data.get('fresh') or False)
    concurrency = int(data.get('concurrency') or 4)
    wpath = current_app.config['WAPPALYZER_PATH']
    logging.getLogger('techscan.bulk').info('/bulk scan start domains=%d two_phase=%s full=%s fallback_quick=%s', len(domains), two_phase, full, fallback_quick)

    if two_phase:
        results = bulk_quick_then_deep(domains, wpath, concurrency=concurrency)
    else:
        results = scan_bulk(domains, wpath, concurrency=concurrency, timeout=timeout, retries=retries, fresh=fresh, ttl=ttl_int, full=full)

    if fallback_quick:
        fixed = []
        for r in results:
            if not r or r.get('status')=='ok':
                fixed.append(r); continue
            err = (r.get('error') or '').lower()
            if 'timeout' in err or 'timed out' in err or 'time out' in err:
                dom = r.get('domain')
                try:
                    quick_res = quick_single_scan(dom, wpath, defer_full=False)
                    quick_res['status']='ok'; quick_res['fallback']='quick'; quick_res['original_error']=r.get('error')
                    fixed.append(quick_res); continue
                except Exception as qe:
                    r['fallback_attempt']='quick'; r['fallback_error']=str(qe)
            fixed.append(r)
        results = fixed

    # Save batch
    try:
        batch_id = bulk_store.save_batch(results, domains)
    except Exception:
        batch_id = None

    # Error buckets
    buckets = {'timeout':0,'dns':0,'ssl':0,'connection':0,'other':0}
    for r in results:
        if not r or r.get('status')=='ok':
            continue
        err = (r.get('error') or '').lower()
        if 'timeout' in err or 'timed out' in err:
            buckets['timeout'] += 1
        elif 'dns' in err or 'nodename' in err:
            buckets['dns'] += 1
        elif 'ssl' in err or 'cert' in err:
            buckets['ssl'] += 1
        elif 'connection' in err or 'refused' in err or 'unreachable' in err:
            buckets['connection'] += 1
        else:
            buckets['other'] += 1

    ok = sum(1 for r in results if r and r.get('status')=='ok')
    logging.getLogger('techscan.bulk').info('/bulk done total=%d ok=%d duration=%.2fs batch_id=%s', len(results), ok, time.time()-start, batch_id)
    if debug_escalated:
        try:
            base_level_name = os.environ.get('TECHSCAN_LOG_LEVEL', 'INFO').upper()
            base_level = getattr(logging, base_level_name, logging.INFO)
            logging.getLogger().setLevel(base_level)
        except Exception:
            pass

    if out_format == 'csv':
        import csv, io, json as _json
        output = io.StringIO()
        fieldnames = ['status','domain','timestamp','tech_count','technologies','categories','cached','duration','retries','engine','error','outdated_count','outdated_list']
        if include_raw:
            fieldnames.append('raw')
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            if not r:
                continue
            if r.get('status')!='ok':
                row_err = {k: r.get(k) for k in ['status','domain','error']}
                if include_raw:
                    row_err.setdefault('raw','')
                writer.writerow(row_err)
                continue
            techs = r.get('technologies') or []
            tech_list = [f"{t.get('name')}" + (f" ({t.get('version')})" if t.get('version') else '') for t in techs]
            categories = sorted((r.get('categories') or {}).keys())
            audit_meta = r.get('audit') or {}
            outdated_items = audit_meta.get('outdated') or []
            outdated_list_str = ' | '.join(f"{o.get('name')} ({o.get('version')} -> {o.get('latest')})" for o in outdated_items)
            row = {
                'status': r.get('status'),
                'domain': r.get('domain'),
                'timestamp': r.get('timestamp'),
                'tech_count': len(techs),
                'technologies': ' | '.join(tech_list),
                'categories': ' | '.join(categories),
                'cached': r.get('cached'),
                'duration': r.get('duration'),
                'retries': r.get('retries',0),
                'engine': r.get('engine'),
                'error': r.get('error'),
                'outdated_count': audit_meta.get('outdated_count'),
                'outdated_list': outdated_list_str
            }
            if include_raw:
                row['raw'] = _json.dumps(r.get('raw'), ensure_ascii=False)
            writer.writerow(row)
        csv_data = output.getvalue()
        return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=bulk_scan.csv'})

    # Persist best-effort
    try:
        for r in results:
            if not r:
                continue
            if 'started_at' not in r:
                r['started_at'] = r.get('timestamp')
            if 'finished_at' not in r:
                r['finished_at'] = int(time.time())
            mode = r.get('engine') or ('full' if (r.get('engine')=='wappalyzer-external') else 'fast')
            meta_for_db = {
                'domain': r.get('domain'),
                'scan_mode': mode,
                'started_at': r.get('started_at'),
                'finished_at': r.get('finished_at'),
                'duration': r.get('duration') or 0,
                'technologies': r.get('technologies') or [],
                'categories': r.get('categories') or {},
                'raw': r.get('raw'),
                'retries': r.get('retries',0),
                'adaptive_timeout': (r.get('phases') or {}).get('adaptive'),
                'error': r.get('error') if r.get('status') != 'ok' else None
            }
            timeout_used = 0
            phases = r.get('phases') or {}
            for k in ('full_budget_ms','timeout_ms','budget_ms'):
                if k in phases:
                    try:
                        timeout_used = int(phases[k]); break
                    except Exception:
                        pass
            _db.save_scan(meta_for_db, r.get('cached', False), timeout_used)
    except Exception as bulk_persist_ex:
        logging.getLogger('techscan.bulk').warning('bulk_persist_failed err=%s', bulk_persist_ex)

    return jsonify({'count': len(results), 'ok': ok, 'batch_id': batch_id, 'error_summary': buckets, 'results': results})

@bp.route('/export/csv', methods=['GET'])
def export_csv():
    """Export cached (non-expired) scan results as CSV.
    Query params:
      domains=comma,separated,list (optional filter)
      include_raw=1 (include raw JSON in a column) (optional)
    Columns: domain,timestamp,tech_count,technologies,categories,cached,duration,retries,engine[,raw]
    - technologies: pipe-separated 'Name (version)' entries
    - categories: pipe-separated category names
    """
    domains_param = request.args.get('domains')
    doms = [d.strip().lower() for d in domains_param.split(',')] if domains_param else None
    include_raw = request.args.get('include_raw') == '1'
    outdated_only = request.args.get('outdated_only') == '1'
    rows = snapshot_cache(doms)
    if outdated_only:
        # Filter rows having audit.outdated_count > 0
        filtered = []
        for r in rows:
            audit_meta = r.get('audit') or {}
            if audit_meta.get('outdated_count'):
                filtered.append(r)
        rows = filtered
    import csv, io
    output = io.StringIO()
    fieldnames = ['domain','timestamp','tech_count','technologies','categories','cached','duration','retries','engine','outdated_count','outdated_list']
    if include_raw:
        fieldnames.append('raw')
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        techs = r.get('technologies') or []
        tech_list = [f"{t.get('name')}" + (f" ({t.get('version')})" if t.get('version') else '') for t in techs]
        categories = sorted((r.get('categories') or {}).keys())
        audit_meta = r.get('audit') or {}
        outdated_items = audit_meta.get('outdated') or []
        outdated_list_str = ' | '.join(f"{o.get('name')} ({o.get('version')} -> {o.get('latest')})" for o in outdated_items)
        row = {
            'domain': r.get('domain'),
            'timestamp': r.get('timestamp'),
            'tech_count': len(techs),
            'technologies': ' | '.join(tech_list),
            'categories': ' | '.join(categories),
            'cached': r.get('cached', False),
            'duration': r.get('duration'),
            'retries': r.get('retries', 0),
            'engine': r.get('engine'),
            'outdated_count': audit_meta.get('outdated_count'),
            'outdated_list': outdated_list_str
        }
        if include_raw:
            import json as _json
            row['raw'] = _json.dumps(r.get('raw'), ensure_ascii=False)
        writer.writerow(row)
    csv_data = output.getvalue()
    return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=techscan_export.csv'})
