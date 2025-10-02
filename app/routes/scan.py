from flask import Blueprint, request, jsonify, current_app
import logging, time
from ..scan_utils import get_cached_or_scan, scan_bulk, DOMAIN_RE, extract_host, snapshot_cache, validate_domain, quick_single_scan, deep_scan, bulk_quick_then_deep, fast_full_scan
from .. import db as _db
from flask import Response
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter

bp = Blueprint('scan', __name__)

# Custom limits (can be overridden via env)
import os
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
    quick_flag = False
    # quick mode precedence: body.quick, query quick=1, or env TECHSCAN_QUICK_SINGLE=1
    if str(data.get('quick')).lower() in ('1','true','yes') or request.args.get('quick') == '1' or os.environ.get('TECHSCAN_QUICK_SINGLE','0') == '1':
        quick_flag = True
    defer_quick = os.environ.get('TECHSCAN_QUICK_DEFER_FULL','0') == '1'
    try:
        if fast_full:
            result = fast_full_scan(domain, wpath)
        elif deep:
            result = deep_scan(domain, wpath)
        elif quick_flag:
            result = quick_single_scan(domain, wpath, defer_full=defer_quick, timeout_full=timeout, retries_full=retries)
        else:
            # Debug instrumentation: log why quick not triggered
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.getLogger('techscan.scan').debug('quick_flag_evaluation quick_flag=%s body.quick=%r env.TECHSCAN_QUICK_SINGLE=%s args.quick=%s', quick_flag, data.get('quick'), os.environ.get('TECHSCAN_QUICK_SINGLE','0'), request.args.get('quick'))
            result = get_cached_or_scan(domain, wpath, timeout=timeout, retries=retries, fresh=fresh, ttl=ttl_int, full=full)
        # Backward compat: ensure started_at/finished_at appear (cache hit may lack them)
        if 'started_at' not in result:
            result['started_at'] = result.get('timestamp')
        if 'finished_at' not in result:
            result['finished_at'] = int(time.time())
        logging.getLogger('techscan.scan').info('/scan success domain=%s quick=%s deep=%s fast_full=%s duration=%.2fs retries_used=%s', domain, quick_flag, deep, fast_full, time.time()-start, result.get('retries',0))
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
        logging.getLogger('techscan.scan').error('/scan error domain=%s err=%s', domain, e)
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

def scan_bulk_route_impl():
    data = request.get_json(silent=True) or {}
    start = time.time()
    domains = data.get('domains') or []
    timeout = int(data.get('timeout') or 30)
    retries = int(data.get('retries') or 2)
    ttl = data.get('ttl')
    full = bool(data.get('full') or False)
    two_phase = bool(data.get('two_phase') or (request.args.get('two_phase')=='1'))
    fallback_quick = bool(data.get('fallback_quick') or (request.args.get('fallback_quick')=='1'))
    try:
        ttl_int = int(ttl) if ttl is not None else None
    except ValueError:
        ttl_int = None
    out_format = (data.get('format') or request.args.get('format') or 'json').lower()
    include_raw = bool(data.get('include_raw')) or (request.args.get('include_raw') == '1')
    fresh = bool(data.get('fresh') or False)
    concurrency = int(data.get('concurrency') or 4)
    logging.getLogger('techscan.bulk').info('/bulk request count=%s timeout=%s retries=%s fresh=%s concurrency=%s ttl=%s format=%s full=%s two_phase=%s fallback_quick=%s', len(domains), timeout, retries, fresh, concurrency, ttl_int, out_format, full, two_phase, fallback_quick)
    if not isinstance(domains, list):
        return jsonify({'error': 'domains field must be a list'}), 400
    if not domains:
        return jsonify({'error': 'domains list empty'}), 400
    wpath = current_app.config['WAPPALYZER_PATH']
    if two_phase:
        results = bulk_quick_then_deep(domains, wpath, concurrency=concurrency)
    else:
        results = scan_bulk(domains, wpath, concurrency=concurrency, timeout=timeout, retries=retries, fresh=fresh, ttl=ttl_int, full=full)

    # Optional fallback quick scan for timeouts/errors
    if fallback_quick:
        fixed = []
        for r in results:
            if not r or r.get('status') == 'ok':
                fixed.append(r)
                continue
            err = (r.get('error') or '').lower()
            # Consider timeouts / unreachable keywords
            if 'timeout' in err or 'timed out' in err or 'time out' in err:
                dom = r.get('domain')
                try:
                    quick_res = quick_single_scan(dom, wpath, defer_full=False)
                    quick_res['status'] = 'ok'
                    quick_res['fallback'] = 'quick'
                    quick_res['original_error'] = r.get('error')
                    fixed.append(quick_res)
                    continue
                except Exception as qe:
                    r['fallback_attempt'] = 'quick'
                    r['fallback_error'] = str(qe)
            fixed.append(r)
        results = fixed
    invalid_count = 0
    for d in domains:
        try:
            validate_domain(extract_host((d or '').strip()))
        except ValueError:
            invalid_count += 1
    if invalid_count:
        logging.getLogger('techscan.bulk').warning('/bulk filtered_invalid=%s', invalid_count)
    ok = sum(1 for r in results if r and r.get('status')=='ok')
    logging.getLogger('techscan.bulk').info('/bulk done total=%s ok=%s duration=%.2fs', len(results), ok, time.time()-start)
    if out_format == 'csv':
        # Build CSV from just scanned results (ignores cache snapshot; use export for cached only)
        import csv, io
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
                row_err = {k: r.get(k) for k in fieldnames if k in ['status','domain','error']}
                if include_raw:
                    row_err.setdefault('raw', '')
                writer.writerow(row_err)
                continue
            techs = r.get('technologies') or []
            tech_list = [f"{t.get('name')}" + (f" ({t.get('version')})" if t.get('version') else '') for t in techs]
            categories = sorted((r.get('categories') or {}).keys())
            # Backward compat: ensure started_at/finished_at appear (cache hit may lack them)
            if 'started_at' not in r:
                r['started_at'] = r.get('timestamp')
            if 'finished_at' not in r:
                r['finished_at'] = int(time.time())
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
                'retries': r.get('retries', 0),
                'engine': r.get('engine'),
                'error': r.get('error'),
                'outdated_count': audit_meta.get('outdated_count'),
                'outdated_list': outdated_list_str
            }
            if include_raw:
                import json as _json
                row['raw'] = _json.dumps(r.get('raw'), ensure_ascii=False)
            writer.writerow(row)
        csv_data = output.getvalue()
        return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=bulk_scan.csv'})
    # Persist each successful scan result (and errors) for history
    try:
        for r in results:
            if not r:
                continue
            # Normalize timestamps for DB
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
                        timeout_used = int(phases[k])
                        break
                    except Exception:
                        pass
            _db.save_scan(meta_for_db, r.get('cached', False), timeout_used)
    except Exception as bulk_persist_ex:
        logging.getLogger('techscan.bulk').warning('bulk_persist_failed err=%s', bulk_persist_ex)
    return jsonify({'count': len(results), 'results': results})

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
