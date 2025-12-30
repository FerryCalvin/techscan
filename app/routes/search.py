from flask import Blueprint, request, jsonify
import logging
from ..scan_utils import validate_domain
from ..scan_utils import extract_host
from .. import db as _db

search_bp = Blueprint('search', __name__)

@search_bp.route('/search', methods=['GET'])
def search_tech():
    tech = request.args.get('tech')
    category = request.args.get('category')
    version = request.args.get('version')
    limit = int(request.args.get('limit', 200))
    offset = int(request.args.get('offset', 0))
    new24 = request.args.get('new24') in ('1','true','yes','on')
    sort_key = request.args.get('sort')
    sort_dir = request.args.get('dir','desc')
    try:
        rows = _db.search_tech(tech=tech, category=category, version=version, limit=limit, offset=offset, new24=new24, sort_key=sort_key, sort_dir=sort_dir)
        total = _db.count_search_tech(tech=tech, category=category, version=version, new24=new24)
        return jsonify({'count': len(rows), 'results': rows, 'offset': offset, 'limit': limit, 'total': total, 'new24': new24, 'sort': sort_key, 'dir': sort_dir})
    except Exception as e:
        logging.getLogger('techscan.search').error('search error tech=%s category=%s version=%s err=%s', tech, category, version, e)
        return jsonify({'error': 'search failed', 'details': str(e)}), 500

@search_bp.route('/tech_suggest', methods=['GET'])
def tech_suggest():
    """Return distinct technology names containing the given fragment.
    Params: prefix (required, min length 2), limit (default 10, max 50)
    Response: {suggestions: ["WordPress", "WooCommerce", ...]}
    """
    prefix = (request.args.get('prefix') or '').strip()
    if not prefix:
        return jsonify({'suggestions': []})
    if len(prefix) > 64:
        prefix = prefix[:64]
    prefix = prefix.replace('%', '').replace('_', '')
    min_length = 2
    if len(prefix) < min_length:
        return jsonify({'suggestions': []})
    try:
        limit = int(request.args.get('limit', 10))
    except ValueError:
        limit = 10
    limit = max(1, min(limit, 50))
    if getattr(_db, '_DB_DISABLED', False):
        return jsonify({'suggestions': []})
    like_any = f'%{prefix}%'
    like_prefix = f'{prefix}%'
    try:
        with _db.get_conn() as conn:  # type: ignore[attr-defined]
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT tech_name FROM (
                        SELECT DISTINCT tech_name
                        FROM domain_techs
                        WHERE tech_name ILIKE %s
                    ) AS uniq
                    ORDER BY
                        CASE WHEN tech_name ILIKE %s THEN 0 ELSE 1 END,
                        tech_name ASC
                    LIMIT %s
                    """,
                    (like_any, like_prefix, limit)
                )
                rows = cur.fetchall()
        suggestions = [r[0] for r in rows if r and r[0]]
        return jsonify({'suggestions': suggestions, 'count': len(suggestions), 'prefix': prefix})
    except Exception as e:
        logging.getLogger('techscan.search').warning('tech_suggest failed prefix=%s err=%s', prefix, e)
        return jsonify({'suggestions': [], 'error': 'suggest failed'}), 500

@search_bp.route('/category_suggest', methods=['GET'])
def category_suggest():
    """Return distinct category names starting with a given prefix.
    Categories are stored as comma-separated values in domain_techs.categories.
    We unnest by splitting then DISTINCT filter. This is a lightweight helper
    for the tech search UI. Params: prefix, limit (default 10, max 50).
    """
    prefix = (request.args.get('prefix') or '').strip()
    if not prefix:
        return jsonify({'suggestions': []})
    if len(prefix) > 64:
        prefix = prefix[:64]
    try:
        limit = int(request.args.get('limit', 10))
    except ValueError:
        limit = 10
    limit = max(1, min(limit, 50))
    if getattr(_db, '_DB_DISABLED', False):
        return jsonify({'suggestions': []})
    try:
        with _db.get_conn() as conn:  # type: ignore[attr-defined]
            with conn.cursor() as cur:
                # Split categories string by comma, trim blanks, filter by prefix
                cur.execute(
                    """
                    WITH cats AS (
                        SELECT DISTINCT UNNEST(STRING_TO_ARRAY(categories, ',')) AS cat
                        FROM domain_techs
                        WHERE categories IS NOT NULL
                    )
                    SELECT cat FROM cats
                    WHERE cat IS NOT NULL AND cat <> '' AND LOWER(cat) LIKE LOWER(%s)
                    ORDER BY cat ASC LIMIT %s
                    """,
                    (prefix + '%', limit)
                )
                rows = cur.fetchall()
        suggestions = [r[0] for r in rows if r and r[0]]
        return jsonify({'suggestions': suggestions, 'count': len(suggestions), 'prefix': prefix})
    except Exception as e:
        logging.getLogger('techscan.search').warning('category_suggest failed prefix=%s err=%s', prefix, e)
        return jsonify({'suggestions': [], 'error': 'suggest failed'}), 500

@search_bp.route('/domain', methods=['GET'])
def domain_lookup():
    """Return current technologies (from latest scan) for a single domain.
    Params: domain=example.com
    Response: {domain, count, technologies:[{name, version, categories}], categories:{}}
    """
    raw = (request.args.get('domain') or '').strip().lower()
    if not raw:
        return jsonify({'error':'missing domain param'}), 400
    try:
        dom = validate_domain(extract_host(raw))
    except ValueError:
        return jsonify({'error':'invalid domain'}), 400
    
    # Get technologies from latest scan (not historical domain_techs)
    duration_ms = None
    payload_bytes = None
    scan_time = None
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    SELECT technologies_json, finished_at, duration_ms, payload_bytes, started_at
                    FROM scans 
                    WHERE domain = %s 
                    ORDER BY finished_at DESC 
                    LIMIT 1
                ''', (dom,))
                row = cur.fetchone()
        
        if row and row[0]:
            techs_raw = row[0] if isinstance(row[0], list) else []
            # Normalize technologies
            techs = []
            seen = set()  # dedupe by (name, version)
            for t in techs_raw:
                if not isinstance(t, dict) or not t.get('name'):
                    continue
                key = (t.get('name', ''), t.get('version', '') or '')
                if key in seen:
                    continue
                seen.add(key)
                techs.append({
                    'name': t.get('name'),
                    'version': t.get('version'),
                    'categories': t.get('categories') if isinstance(t.get('categories'), list) else [],
                    'confidence': t.get('confidence'),
                })
            scan_time = row[1].timestamp() if row[1] else None
            duration_ms = row[2]
            payload_bytes = row[3]
            # Calculate duration from timestamps if not stored
            if duration_ms is None and row[4] and row[1]:
                try:
                    duration_ms = int((row[1] - row[4]).total_seconds() * 1000)
                except:
                    pass
        else:
            # Fallback to domain_techs if no scan found
            rows = _db.get_domain_techs(dom)
            techs = [
                {
                    'name': r['tech_name'],
                    'version': r['version'],
                    'categories': r['categories'],
                }
                for r in rows
            ]
    except Exception as e:
        logging.getLogger('techscan.search').error('domain_lookup error: %s', e)
        return jsonify({'error': 'lookup failed'}), 500
    
    # Aggregate categories panel style
    cats = {}
    for t in techs:
        for c in t.get('categories') or []:
            if isinstance(c, str):
                cats.setdefault(c, []).append({'name': t['name'], 'version': t.get('version')})
    
    return jsonify({
        'domain': dom, 
        'count': len(techs), 
        'technologies': techs, 
        'categories': cats,
        'scan_time': scan_time,
        'duration_ms': duration_ms,
        'duration': round(duration_ms / 1000, 2) if duration_ms else None,
        'payload_bytes': payload_bytes
    })

@search_bp.route('/history', methods=['GET'])
def history():
    domain = request.args.get('domain','').strip()
    if not domain:
        return jsonify({'error': 'missing domain'}), 400
    try:
        domain_norm = validate_domain(domain)
    except Exception:
        return jsonify({'error': 'invalid domain'}), 400
    limit = int(request.args.get('limit', 20))
    offset = int(request.args.get('offset', 0))
    try:
        rows = _db.history(domain_norm, limit=limit, offset=offset)
        total = _db.count_history(domain_norm)
        return jsonify({'domain': domain_norm, 'count': len(rows), 'history': rows, 'offset': offset, 'limit': limit, 'total': total})
    except Exception as e:
        logging.getLogger('techscan.search').error('history error domain=%s err=%s', domain_norm, e)
        return jsonify({'error': 'history failed'}), 500

@search_bp.route('/diff', methods=['GET'])
def diff_domain():
    """Return technology diff between the last two scans for a domain.
    Response fields:
      - domain
      - latest_scan (timestamp finished_at)
      - previous_scan (timestamp finished_at)
      - added: [tech objects newly present]
      - removed: [tech objects that disappeared]
      - unchanged_count
    If fewer than 2 scans exist -> 400.
    """
    domain = request.args.get('domain','').strip()
    if not domain:
        return jsonify({'error':'missing domain'}), 400
    try:
        domain_norm = validate_domain(domain)
    except Exception:
        return jsonify({'error':'invalid domain'}), 400
    try:
        # Fetch last two scan snapshots with technologies_json
        from psycopg import sql as _sql  # local import avoid global if db disabled
        with _db.get_conn() as conn:  # type: ignore[attr-defined]
            with conn.cursor() as cur:
                cur.execute('''SELECT finished_at, technologies_json FROM scans
                               WHERE domain=%s ORDER BY finished_at DESC LIMIT 2''', (domain_norm,))
                rows = cur.fetchall()
        if len(rows) < 2:
            return jsonify({'error':'not enough scans for diff','domain': domain_norm, 'available': len(rows)}), 400
        latest_ts, latest_techs = rows[0]
        prev_ts, prev_techs = rows[1]
        latest_list = latest_techs if isinstance(latest_techs, list) else []
        prev_list = prev_techs if isinstance(prev_techs, list) else []
        # Build maps by name -> versions and full entries for changed detection
        from collections import defaultdict
        latest_by_name = defaultdict(list)
        prev_by_name = defaultdict(list)
        for t in latest_list:
            if isinstance(t, dict) and t.get('name'):
                latest_by_name[t['name']].append(t)
        for t in prev_list:
            if isinstance(t, dict) and t.get('name'):
                prev_by_name[t['name']].append(t)
        # Normalize versions (None -> '') for comparison
        def vers(v):
            return v or ''
        # Determine changed: names present in both where version sets differ
        changed = []
        for name in set(latest_by_name.keys()) & set(prev_by_name.keys()):
            latest_versions = {vers(t.get('version')) for t in latest_by_name[name]}
            prev_versions = {vers(t.get('version')) for t in prev_by_name[name]}
            if latest_versions != prev_versions:
                removed_versions = sorted([v for v in (prev_versions - latest_versions) if v])
                added_versions = sorted([v for v in (latest_versions - prev_versions) if v])
                upgrade_path = None
                # Single version swap (one removed, one added) classify direction if semantic
                if len(removed_versions) == 1 and len(added_versions) == 1:
                    from_v = removed_versions[0]
                    to_v = added_versions[0]
                    def parse_num(v):
                        import re
                        parts = re.split(r'[^0-9]+', v)
                        nums = [int(p) for p in parts if p.isdigit()]
                        return nums or [0]
                    try:
                        from_nums = parse_num(from_v)
                        to_nums = parse_num(to_v)
                        direction = 'upgrade' if to_nums > from_nums else ('downgrade' if to_nums < from_nums else 'change')
                    except Exception:
                        direction = 'change'
                    upgrade_path = {'from': from_v, 'to': to_v, 'direction': direction}
                changed.append({
                    'name': name,
                    'previous_versions': sorted([v for v in prev_versions if v]),
                    'current_versions': sorted([v for v in latest_versions if v]),
                    'removed_versions': removed_versions,
                    'added_versions': added_versions,
                    'upgrade_path': upgrade_path
                })
        # For added/removed we consider (name, version) pairs excluding those that are part of a changed name
        changed_names = {c['name'] for c in changed}
        def pair_key(t):
            if not isinstance(t, dict) or not t.get('name'):
                return None
            return (t.get('name'), vers(t.get('version')))
        latest_pairs = {pair_key(t): t for t in latest_list if pair_key(t) and t.get('name') not in changed_names}
        prev_pairs = {pair_key(t): t for t in prev_list if pair_key(t) and t.get('name') not in changed_names}
        added = [latest_pairs[k] for k in latest_pairs.keys() - prev_pairs.keys()]
        removed = [prev_pairs[k] for k in prev_pairs.keys() - latest_pairs.keys()]
        unchanged = latest_pairs.keys() & prev_pairs.keys()
        return jsonify({
            'domain': domain_norm,
            'latest_scan': latest_ts.timestamp(),
            'previous_scan': prev_ts.timestamp(),
            'added': added,
            'removed': removed,
            'changed': changed,
            'changed_count': len(changed),
            'unchanged_count': len(unchanged)
        })
    except Exception as e:
        logging.getLogger('techscan.search').error('diff error domain=%s err=%s', domain_norm, e)
        return jsonify({'error':'diff failed'}), 500

@search_bp.route('/scan_history', methods=['GET'])
def scan_history():
    """Return scan history rows (global or per-domain) with sorting & pagination.
    Params:
      domain (optional) - if provided, filter to that domain; else global recent scans
      limit (default 20, max 200)
      offset (default 0)
    sort (finished_at|started_at|duration_ms|domain|payload_bytes) default finished_at
      dir (asc|desc) default desc
    Response: {count, results:[{domain,mode,started_at,finished_at,duration_ms,from_cache,adaptive_timeout,retries,timeout_used}], offset, limit, total}
    """
    if getattr(_db, '_DB_DISABLED', False):
        return jsonify({'count':0,'results':[],'offset':0,'limit':20,'total':0})
    domain = (request.args.get('domain') or '').strip().lower()
    try:
        limit = int(request.args.get('limit','20'))
        offset = int(request.args.get('offset','0'))
    except ValueError:
        return jsonify({'error':'bad_params'}), 400
    if limit < 1: limit = 20
    if limit > 200: limit = 200
    if offset < 0: offset = 0
    sort_key = (request.args.get('sort') or 'finished_at').lower()
    sort_dir = (request.args.get('dir') or 'desc').lower()
    valid_cols = {
        'finished_at': 'finished_at',
        'started_at': 'started_at',
        'duration_ms': 'duration_ms',
        'domain': 'domain',
        'payload_bytes': 'payload_bytes'
    }
    col = valid_cols.get(sort_key, 'finished_at')
    dir_sql = 'ASC' if sort_dir == 'asc' else 'DESC'
    base = 'FROM scans'
    params = []
    where = ''
    if domain:
        where = ' WHERE domain=%s'
        params.append(domain)
    count_sql = 'SELECT COUNT(*) ' + base + where
    sql = f'''SELECT domain, mode, started_at, finished_at, duration_ms, from_cache, adaptive_timeout, retries, timeout_used, payload_bytes
              {base}{where} ORDER BY {col} {dir_sql} LIMIT %s OFFSET %s'''
    params.extend([limit, offset])
    try:
        with _db.get_conn() as conn:  # type: ignore[attr-defined]
            with conn.cursor() as cur:
                cur.execute(count_sql, params[:-2])
                total = cur.fetchone()[0]
                cur.execute(sql, params)
                rows = cur.fetchall()
        out = []
        for r in rows:
            started_dt = r[2]
            finished_dt = r[3]
            duration_ms = r[4]
            needs_recalc = duration_ms is None
            if not needs_recalc:
                try:
                    needs_recalc = float(duration_ms) <= 0
                except Exception:
                    needs_recalc = True
            if needs_recalc and started_dt and finished_dt:
                try:
                    duration_ms = max(0, int((finished_dt - started_dt).total_seconds() * 1000))
                except Exception:
                    duration_ms = None
            out.append({
                'domain': r[0],
                'mode': r[1],
                'started_at': started_dt.timestamp() if started_dt else None,
                'finished_at': finished_dt.timestamp() if finished_dt else None,
                'duration_ms': duration_ms,
                'from_cache': r[5],
                'adaptive_timeout': r[6],
                'retries': r[7],
                'timeout_used': r[8],
                'payload_bytes': r[9]
            })
        return jsonify({'count': len(out), 'results': out, 'offset': offset, 'limit': limit, 'total': total, 'sort': col, 'dir': dir_sql.lower(), 'domain': domain or None})
    except Exception as e:
        logging.getLogger('techscan.search').error('scan_history_failed domain=%s err=%s', domain, e)
        return jsonify({'error':'history_failed'}), 500

@search_bp.route('/domain_suggest', methods=['GET'])
def domain_suggest():
    """Suggest distinct domains starting with prefix (case-insensitive).
    Params: prefix (min 1), limit (default 10, max 50)
    Source: scans table distinct domain values ordered ASC.
    """
    if getattr(_db, '_DB_DISABLED', False):
        return jsonify({'suggestions': []})
    prefix = (request.args.get('prefix') or '').strip().lower()
    if not prefix:
        return jsonify({'suggestions': []})
    if len(prefix) > 128:
        prefix = prefix[:128]
    try:
        limit = int(request.args.get('limit','10'))
    except ValueError:
        limit = 10
    limit = max(1, min(limit, 50))
    try:
        with _db.get_conn() as conn:  # type: ignore[attr-defined]
            with conn.cursor() as cur:
                cur.execute('''SELECT DISTINCT domain FROM scans WHERE LOWER(domain) LIKE %s ORDER BY domain ASC LIMIT %s''', (prefix+'%', limit))
                rows = cur.fetchall()
        suggestions = [r[0] for r in rows if r and r[0]]
        return jsonify({'suggestions': suggestions, 'count': len(suggestions), 'prefix': prefix})
    except Exception as e:
        logging.getLogger('techscan.search').warning('domain_suggest_failed prefix=%s err=%s', prefix, e)
        return jsonify({'suggestions': [], 'error': 'suggest failed'}), 500
