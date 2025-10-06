from flask import Blueprint, render_template, jsonify, request, redirect, url_for

from .. import db as _db
from .. import domain_groups as _dg

ui_bp = Blueprint('ui', __name__)

# --- Diff helper ---

def _compute_diff(latest: dict | None, previous: dict | None):
    if not latest and not previous:
        return {'added': [], 'removed': [], 'changed': []}
    latest_techs = latest.get('technologies') if latest else []
    prev_techs = previous.get('technologies') if previous else []
    # Build maps by name
    lmap = {}
    for t in latest_techs or []:
        n = t.get('name')
        if not n: continue
        lmap[n] = t
    pmap = {}
    for t in prev_techs or []:
        n = t.get('name')
        if not n: continue
        pmap[n] = t
    added = []
    removed = []
    changed = []
    for name, lt in lmap.items():
        pt = pmap.get(name)
        if not pt:
            added.append({'name': name, 'version': lt.get('version')})
        else:
            lv = lt.get('version')
            pv = pt.get('version')
            if lv and pv and lv != pv:
                changed.append({'name': name, 'from': pv, 'to': lv})
            elif (lv and not pv) or (pv and not lv):
                # treat gaining or losing version as change
                if lv != pv:
                    changed.append({'name': name, 'from': pv, 'to': lv})
    for name, pt in pmap.items():
        if name not in lmap:
            removed.append({'name': name, 'version': pt.get('version')})
    return {'added': added, 'removed': removed, 'changed': changed}

@ui_bp.route('/')
@ui_bp.route('/dashboard')
def home():
    return render_template('dashboard.html')

@ui_bp.route('/index.html')
def legacy_index_redirect():
    """Redirect old single-page UI path to new dashboard so cached bookmarks still work."""
    resp = redirect(url_for('ui.home'), 301)
    try:
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
    except Exception:
        pass
    return resp

@ui_bp.route('/websites')
def websites_page():
    return render_template('websites.html')

@ui_bp.route('/technology')
def technology_page():
    return render_template('tech_search.html')

@ui_bp.route('/history')
def history_page():
    return render_template('history.html')

@ui_bp.route('/api/domains')
def api_domains():
    # Collect domain meta from scans/domain_techs.
    # Strategy: get distinct domains from domain_techs mirror and DB stats if available.
    domain_meta = []
    diff_extras: dict[str, dict] = {}
    try:
        if not getattr(_db, '_DB_DISABLED', False):
            from ..db import get_conn
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT d.domain,
                               MAX(s.finished_at) AS last_scan,
                               (ARRAY_AGG(s.mode ORDER BY s.finished_at DESC))[1] AS last_mode,
                               COUNT(distinct d.tech_name) AS tech_count
                        FROM domain_techs d
                        LEFT JOIN scans s ON s.domain = d.domain
                        GROUP BY d.domain
                    """)
                    rows = cur.fetchall()
                    for r in rows:
                        domain = r[0]
                        last_scan_ts = r[1].timestamp() if r[1] else None
                        last_mode = r[2]
                        tech_count = r[3]
                        domain_meta.append((domain, last_scan_ts, last_mode, tech_count))
                # Compute diff counts for each domain (best-effort) by looking at last two scans
                try:
                    with conn.cursor() as cur2:
                        cur2.execute("""
                            SELECT domain, finished_at, technologies_json
                            FROM (
                                SELECT domain, finished_at, technologies_json,
                                       row_number() OVER (PARTITION BY domain ORDER BY finished_at DESC) AS rn
                                FROM scans
                            ) t WHERE rn <= 2
                        """)
                        tmp: dict[str, list[tuple]] = {}
                        for d, finished_at, techs in cur2.fetchall():
                            tmp.setdefault(d, []).append((finished_at, techs if isinstance(techs, list) else []))
                        for d, arr in tmp.items():
                            if len(arr) >= 1:
                                arr.sort(key=lambda x: x[0], reverse=True)
                                latest = arr[0][1]
                                prev = arr[1][1] if len(arr) > 1 else []
                                try:
                                    # build maps
                                    lmap = {t.get('name'): t for t in latest if isinstance(t, dict) and t.get('name')}
                                    pmap = {t.get('name'): t for t in prev if isinstance(t, dict) and t.get('name')}
                                    added = sum(1 for k in lmap.keys() if k not in pmap)
                                    removed = sum(1 for k in pmap.keys() if k not in lmap)
                                    changed = 0
                                    for k,v in lmap.items():
                                        pv = pmap.get(k)
                                        if pv:
                                            lv = v.get('version')
                                            pv_v = pv.get('version')
                                            if lv != pv_v and (lv or pv_v):
                                                changed += 1
                                    if added or removed or changed:
                                        diff_extras[d] = {'diff_added': added, 'diff_removed': removed, 'diff_changed': changed}
                                except Exception:
                                    continue
                except Exception:
                    pass
        else:
            mem = getattr(_db, '_MEM_DOMAIN_TECHS', {})
            by_domain = {}
            for (domain, name, version), rec in mem.items():
                dm = by_domain.setdefault(domain, {'techs': set(), 'last_seen': None})
                dm['techs'].add(name)
                ls = rec.get('last_seen')
                if ls and (dm['last_seen'] is None or ls > dm['last_seen']):
                    dm['last_seen'] = ls
            for domain, info in by_domain.items():
                domain_meta.append((domain, info['last_seen'], None, len(info['techs'])))
    except Exception as e:
        return jsonify({'error': 'failed_collect_domains', 'detail': str(e)}), 500
    payload = _dg.group_domains(domain_meta, extras=diff_extras)
    return jsonify(payload)

@ui_bp.route('/api/domain/<domain>/detail')
def api_domain_detail(domain: str):
    # Retrieve latest two scans
    if getattr(_db, '_DB_DISABLED', False):
        return jsonify({'error': 'db_disabled'}), 503
    from ..db import get_conn
    # Import scan_utils to introspect inflight/deferred status (best-effort)
    try:
        from .. import scan_utils as _su
    except Exception:
        _su = None
    latest = None
    previous = None
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, mode, started_at, finished_at, duration_ms, from_cache, retries, timeout_used, technologies_json, raw_json
                    FROM scans WHERE domain=%s ORDER BY finished_at DESC LIMIT 2
                """, (domain,))
                rows = cur.fetchall()
                if not rows:
                    return jsonify({'error': 'not_found'}), 404
                def row_to_scan(r):
                    techs = r[8] if isinstance(r[8], list) else []
                    return {
                        'scan_id': r[0],
                        'mode': r[1],
                        'started_at': r[2].timestamp(),
                        'finished_at': r[3].timestamp(),
                        'duration_ms': r[4],
                        'from_cache': r[5],
                        'retries': r[6],
                        'timeout_used': r[7],
                        'technologies': techs,
                        'raw': r[9]
                    }
                if len(rows) >= 1:
                    latest = row_to_scan(rows[0])
                if len(rows) == 2:
                    previous = row_to_scan(rows[1])
    except Exception as e:
        return jsonify({'error': 'db_query_failed', 'detail': str(e)}), 500
    diff = _compute_diff(latest, previous)
    # Metrics: extract phases if present in raw
    metrics = {}
    try:
        phases = (latest.get('raw') or {}).get('phases') if latest else None
        if isinstance(phases, dict):
            for k in ['engine_ms','synthetic_ms','heuristic_total_ms','heuristic_core_ms','sniff_ms','micro_ms','full_attempt_ms','fallback_ms','version_audit_ms']:
                if k in phases:
                    metrics[k] = phases[k]
    except Exception:
        pass
    technologies = latest.get('technologies') if latest else []
    # Ensure simplified tech objects (name, version, categories, confidence) if raw format contains them
    norm_tech = []
    for t in technologies:
        if not isinstance(t, dict):
            continue
        norm_tech.append({
            'name': t.get('name'),
            'version': t.get('version'),
            'categories': t.get('categories') or [],
            'confidence': t.get('confidence')
        })
    response = {
        'domain': domain,
        'latest': {k: latest[k] for k in ['scan_id','mode','started_at','finished_at','duration_ms','from_cache','retries','timeout_used']},
        'previous': ({k: previous[k] for k in ['scan_id','mode','finished_at']} if previous else None),
        'diff': diff,
        'technologies': norm_tech,
        'metrics': metrics
    }
    # In-progress detection heuristics: if single-flight map or deferred background set contains domain key
    try:
        in_progress = False
        eta_s = None
        if _su:
            # Check deferred background full set
            if domain in getattr(_su, '_deferred_inflight', set()):
                in_progress = True
            # Check single-flight: look for either fast:domain or full:domain entries
            sf_map = getattr(_su, '_single_flight_map', {})
            if f"fast:{domain}" in sf_map or f"full:{domain}" in sf_map:
                in_progress = True
            # crude ETA guess: use average fast duration from stats if available
            stats = getattr(_su, 'STATS', {})
            if in_progress and stats:
                try:
                    avg_ms = stats.get('average_duration_ms', {}).get('fast') or 0
                    if avg_ms:
                        eta_s = round((avg_ms/1000.0),2)
                except Exception:
                    pass
        if in_progress:
            response['status'] = 'in-progress'
            if eta_s:
                response['eta_seconds'] = eta_s
    except Exception:
        pass
    return jsonify(response)

@ui_bp.route('/api/domain/<domain>/history')
def api_domain_history(domain: str):
    try:
        limit = int(request.args.get('limit','20'))
        offset = int(request.args.get('offset','0'))
    except ValueError:
        return jsonify({'error':'bad_params'}), 400
    if limit < 1 or limit > 200:
        limit = 20
    if offset < 0:
        offset = 0
    try:
        total = _db.count_history(domain)
        rows = _db.history(domain, limit=limit, offset=offset)
    except Exception as e:
        return jsonify({'error':'db_error','detail':str(e)}), 500
    return jsonify({
        'domain': domain,
        'limit': limit,
        'offset': offset,
        'total': total,
        'scans': rows
    })

@ui_bp.route('/admin/domain_groups/reload', methods=['POST'])
def admin_domain_groups_reload():
    obj = _dg.reload()
    return jsonify({'status': 'reloaded', 'groups_version': obj.version, 'updated_at': obj.updated_at})
