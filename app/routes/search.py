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

@search_bp.route('/domain', methods=['GET'])
def domain_lookup():
    """Return current technologies (merged view) for a single domain.
    Params: domain=example.com
    Response: {domain, count, technologies:[{name, version, categories, first_seen, last_seen}]}
    """
    raw = (request.args.get('domain') or '').strip().lower()
    if not raw:
        return jsonify({'error':'missing domain param'}), 400
    try:
        dom = validate_domain(extract_host(raw))
    except ValueError:
        return jsonify({'error':'invalid domain'}), 400
    rows = _db.get_domain_techs(dom)
    # Normalize shape to match other endpoints: name/version/categories
    techs = [
        {
            'name': r['tech_name'],
            'version': r['version'],
            'categories': r['categories'],
            'first_seen': r['first_seen'],
            'last_seen': r['last_seen']
        } for r in rows
    ]
    # Aggregate categories panel style
    cats = {}
    for t in techs:
        for c in t.get('categories') or []:
            cats.setdefault(c, []).append({'name': t['name'], 'version': t.get('version')})
    return jsonify({'domain': dom, 'count': len(techs), 'technologies': techs, 'categories': cats})

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
