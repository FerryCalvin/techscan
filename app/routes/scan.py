from flask import Blueprint, request, jsonify, current_app
import logging, time
from ..scan_utils import get_cached_or_scan, scan_bulk, DOMAIN_RE, extract_host, snapshot_cache, validate_domain
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

@bp.route('/scan', methods=['POST'])
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
    # original implementation moved to scan_single_impl
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
    try:
        ttl_int = int(ttl) if ttl is not None else None
    except ValueError:
        ttl_int = None
    fresh = bool(data.get('fresh') or False)
    logging.getLogger('techscan.scan').info('/scan request input=%s domain=%s timeout=%s retries=%s fresh=%s ttl=%s full=%s', raw_input, domain, timeout, retries, fresh, ttl_int, full)
    if not raw_input:
        return jsonify({'error': 'missing domain field'}), 400
    try:
        domain = validate_domain(domain)
    except ValueError:
        logging.getLogger('techscan.scan').warning('/scan invalid domain input=%r parsed=%r bytes=%s', raw_input, domain, '-'.join(str(ord(c)) for c in domain))
        return jsonify({'error': 'invalid domain format'}), 400
    wpath = current_app.config['WAPPALYZER_PATH']
    try:
        result = get_cached_or_scan(domain, wpath, timeout=timeout, retries=retries, fresh=fresh, ttl=ttl_int, full=full)
        # Backward compat: ensure started_at/finished_at appear (cache hit may lack them)
        if 'started_at' not in result:
            result['started_at'] = result.get('timestamp')
        if 'finished_at' not in result:
            result['finished_at'] = int(time.time())
        logging.getLogger('techscan.scan').info('/scan success domain=%s duration=%.2fs retries_used=%s', domain, time.time()-start, result.get('retries',0))
        return jsonify(result)
    except Exception as e:
        logging.getLogger('techscan.scan').error('/scan error domain=%s err=%s', domain, e)
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
    try:
        ttl_int = int(ttl) if ttl is not None else None
    except ValueError:
        ttl_int = None
    out_format = (data.get('format') or request.args.get('format') or 'json').lower()
    include_raw = bool(data.get('include_raw')) or (request.args.get('include_raw') == '1')
    fresh = bool(data.get('fresh') or False)
    concurrency = int(data.get('concurrency') or 4)
    logging.getLogger('techscan.bulk').info('/bulk request count=%s timeout=%s retries=%s fresh=%s concurrency=%s ttl=%s format=%s full=%s', len(domains), timeout, retries, fresh, concurrency, ttl_int, out_format, full)
    if not isinstance(domains, list):
        return jsonify({'error': 'domains field must be a list'}), 400
    if not domains:
        return jsonify({'error': 'domains list empty'}), 400
    wpath = current_app.config['WAPPALYZER_PATH']
    results = scan_bulk(domains, wpath, concurrency=concurrency, timeout=timeout, retries=retries, fresh=fresh, ttl=ttl_int, full=full)
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
        fieldnames = ['status','domain','timestamp','tech_count','technologies','categories','cached','duration','retries','engine','error']
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
                'error': r.get('error')
            }
            if include_raw:
                import json as _json
                row['raw'] = _json.dumps(r.get('raw'), ensure_ascii=False)
            writer.writerow(row)
        csv_data = output.getvalue()
        return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=bulk_scan.csv'})
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
    rows = snapshot_cache(doms)
    import csv, io
    output = io.StringIO()
    fieldnames = ['domain','timestamp','tech_count','technologies','categories','cached','duration','retries','engine']
    if include_raw:
        fieldnames.append('raw')
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        techs = r.get('technologies') or []
        tech_list = [f"{t.get('name')}" + (f" ({t.get('version')})" if t.get('version') else '') for t in techs]
        categories = sorted((r.get('categories') or {}).keys())
        row = {
            'domain': r.get('domain'),
            'timestamp': r.get('timestamp'),
            'tech_count': len(techs),
            'technologies': ' | '.join(tech_list),
            'categories': ' | '.join(categories),
            'cached': r.get('cached', False),
            'duration': r.get('duration'),
            'retries': r.get('retries', 0),
            'engine': r.get('engine')
        }
        if include_raw:
            import json as _json
            row['raw'] = _json.dumps(r.get('raw'), ensure_ascii=False)
        writer.writerow(row)
    csv_data = output.getvalue()
    return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=techscan_export.csv'})
