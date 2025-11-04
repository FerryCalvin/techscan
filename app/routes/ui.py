from flask import Blueprint, render_template, jsonify, request, redirect, url_for
import logging, os

from .. import db as _db
from .. import domain_groups as _dg

ui_bp = Blueprint('ui', __name__)
_log = logging.getLogger('techscan.ui')

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
    # Serve the statistics dashboard as the site homepage (dashboard view)
    # The `stats.html` template contains the consolidated dashboard widgets
    # (summary cards, charts, top technologies). Keep `/dashboard` route
    # for compatibility while making the homepage the stats dashboard.
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

@ui_bp.route('/stats')
def stats_page():
    """Render statistics dashboard page (front-end loads data from /api/stats)."""
    return render_template('stats.html')

@ui_bp.route('/_routes')
def list_routes():
    """Diagnostic: list all registered routes (methods + rule + endpoint)."""
    try:
        from flask import current_app
        output = []
        for rule in current_app.url_map.iter_rules():
            methods = sorted(m for m in rule.methods if m not in ('HEAD','OPTIONS'))
            output.append({'rule': str(rule), 'endpoint': rule.endpoint, 'methods': methods})
        output.sort(key=lambda x: x['rule'])
        return jsonify({'status':'ok','count': len(output),'routes': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ui_bp.route('/api/stats')
def api_stats():
    """Aggregated stats for dashboards: scans, averages, top tech and categories.
    When DB is disabled, falls back to in-memory metrics and mirrors.
    """
    out = {}
    # Base runtime stats
    try:
        from .. import scan_utils as _su
        s = _su.get_stats()
        # overall average duration (weighted across modes if possible)
        try:
            with _su._stats_lock:  # type: ignore[attr-defined]
                d = _su.STATS.get('durations', {})  # type: ignore[attr-defined]
                total = 0.0; count = 0
                for k in ('fast','fast_full','full'):
                    b = d.get(k) or {}
                    total += float(b.get('total') or 0.0)
                    count += int(b.get('count') or 0)
                out['avg_duration_ms'] = round((total / count) * 1000, 2) if count else 0.0
                # avg version audit ms if tracked
                ph = _su.STATS.get('phases', {})  # type: ignore[attr-defined]
                vam = float(ph.get('version_audit_ms') or 0)
                vac = int(ph.get('version_audit_count') or 0)
                out['avg_version_audit_ms'] = round(vam / vac, 2) if vac else 0.0
        except Exception:
            out['avg_duration_ms'] = s.get('average_duration_ms', {}).get('fast')
            out['avg_version_audit_ms'] = 0.0
        out['uptime_seconds'] = s.get('uptime_seconds')
        out['cache_entries'] = s.get('cache_entries')
    except Exception:
        pass
    # DB-backed aggregates when available
    if not getattr(_db, '_DB_DISABLED', False):
        try:
            from ..db import get_conn
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # scans total and last scan
                    cur.execute('SELECT COUNT(*), MAX(finished_at) FROM scans')
                    r = cur.fetchone()
                    out['scans_total'] = r[0] or 0
                    out['last_scan'] = {'finished_at': r[1].timestamp()} if r and r[1] else None
                    
                    # unique domains count
                    cur.execute('SELECT COUNT(DISTINCT domain) FROM domain_techs')
                    unique_count = cur.fetchone()
                    out['unique_domains'] = unique_count[0] if unique_count else 0
                    
                    # avg tech count and duration over last 24h
                    cur.execute("""
                        SELECT AVG(tech_count), AVG(duration_ms)
                        FROM scans WHERE finished_at >= NOW() - INTERVAL '24 hours'
                    """)
                    r2 = cur.fetchone()
                    if r2:
                        out['avg_tech_count'] = float(r2[0]) if r2[0] is not None else None
                        out['avg_duration_ms_24h'] = float(r2[1]) if r2[1] is not None else None
                    # avg evidence/version audit from raw_json->phases (best-effort)
                    try:
                        cur.execute("""
                            SELECT AVG( (raw_json->'phases'->>'evidence_ms')::INT ),
                                   AVG( (raw_json->'phases'->>'version_audit_ms')::INT )
                            FROM scans WHERE raw_json IS NOT NULL AND finished_at >= NOW() - INTERVAL '24 hours'
                        """)
                        r3 = cur.fetchone()
                        out['avg_evidence_ms_24h'] = float(r3[0]) if r3 and r3[0] is not None else None
                        out['avg_version_audit_ms_24h'] = float(r3[1]) if r3 and r3[1] is not None else None
                    except Exception:
                        out['avg_evidence_ms_24h'] = None
                        out['avg_version_audit_ms_24h'] = out.get('avg_version_audit_ms')

                    # top technologies
                    cur.execute(
                        """
                        SELECT tech_name, categories, COUNT(*) AS c
                        FROM domain_techs GROUP BY tech_name, categories ORDER BY c DESC LIMIT 15
                        """
                    )
                    out['top_technologies'] = [{'tech': r[0], 'categories': r[1], 'count': r[2]} for r in cur.fetchall()]

                    # top categories (split comma-separated categories)
                    # Include explicit 'uncategorized' bucket for rows where categories is NULL/empty
                    cur.execute(
                        """
                        SELECT category, c FROM (
                          SELECT LOWER(trim(x)) AS category, COUNT(*) AS c
                          FROM (
                            SELECT unnest(string_to_array(categories, ',')) AS x
                            FROM domain_techs
                            WHERE categories IS NOT NULL
                          ) t
                          WHERE trim(x) <> ''
                          GROUP BY LOWER(trim(x))
                          UNION ALL
                          SELECT 'uncategorized' AS category, COUNT(*) FROM domain_techs WHERE categories IS NULL OR trim(categories) = ''
                        ) q
                        ORDER BY c DESC
                        LIMIT 15
                        """
                    )
                    out['top_categories'] = [{'category': r[0], 'count': r[1]} for r in cur.fetchall()]
        except Exception as e:
            return jsonify({'error': 'db_query_failed', 'detail': str(e)}), 500
    else:
        # Fallback to in-memory mirror when DB disabled
        try:
            mem = getattr(_db, '_MEM_DOMAIN_TECHS', {})
            scans_total = 0  # unknown without DB
            last_seen = 0
            tech_counts = {}
            cat_counts = {}
            unique_domains_set = set()
            for (domain, name, _ver), rec in mem.items():
                unique_domains_set.add(domain)
                tech_counts[name] = tech_counts.get(name, 0) + 1
                if rec.get('categories'):
                    for cat in rec['categories'].split(','):
                        k = cat.strip().lower()
                        if not k:
                            continue
                        cat_counts[k] = cat_counts.get(k, 0) + 1
                if rec.get('last_seen') and rec['last_seen'] > last_seen:
                    last_seen = rec['last_seen']
            out['scans_total'] = scans_total
            out['unique_domains'] = len(unique_domains_set)
            out['last_scan'] = {'finished_at': last_seen} if last_seen else None
            out['top_technologies'] = sorted(
                [{'tech': k, 'count': v} for k,v in tech_counts.items()], key=lambda x: x['count'], reverse=True
            )[:15]
            out['top_categories'] = sorted(
                [{'category': k, 'count': v} for k,v in cat_counts.items()], key=lambda x: x['count'], reverse=True
            )[:15]
        except Exception:
            out.setdefault('top_technologies', [])
            out.setdefault('top_categories', [])
    return jsonify(out)

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
                # Use latest scan row per domain to derive tech_count so the domains listing
                # reflects the most recent scan's technologies array length (consistent with /api/domain/<domain>/detail)
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT s.domain,
                               s.finished_at AS last_scan,
                               s.mode AS last_mode,
                               COALESCE(jsonb_array_length(s.technologies_json), 0) AS tech_count
                        FROM (
                            SELECT DISTINCT ON (domain) domain, finished_at, mode, technologies_json
                            FROM scans
                            ORDER BY domain, finished_at DESC
                        ) s
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
            for k in ['engine_ms','synthetic_ms','heuristic_total_ms','heuristic_core_ms','sniff_ms','micro_ms','node_full_ms','full_attempt_ms','fallback_ms','version_audit_ms']:
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

# --- Domain group CRUD API ---
@ui_bp.route('/api/domain_groups', methods=['GET'])
def api_domain_groups_get():
    try:
        obj = _dg.load()
        _log.debug('domain_groups_get version=%s keys=%s', obj.version, list(obj.groups.keys()))
        return jsonify({'version': obj.version, 'updated_at': obj.updated_at, 'groups': obj.groups})
    except Exception as e:
        _log.exception('domain_groups_get_failed err=%s', e)
        return jsonify({'error': 'internal', 'detail': str(e)}), 500

@ui_bp.route('/api/domain_groups', methods=['POST'])
def api_domain_groups_add():
    try:
        data = request.get_json(force=True, silent=True) or {}
        group = data.get('group')
        _log.info('domain_group_add request group=%s', group)
        obj = _dg.add_group(group)
        _log.info('domain_group_add_success group=%s version=%s', group, obj.version)
        from .. import domain_groups as _dg_mod
        diag = _dg_mod.diagnostics()
        return jsonify({'status': 'ok', 'groups': obj.groups, 'version': obj.version, 'added': group, 'diag': diag})
    except ValueError as e:
        _log.warning('domain_group_add_value_error group=%s err=%s', request.json, e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': str(e), 'diag': diag}), 400
    except Exception as e:
        _log.exception('domain_group_add_failed err=%s', e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': 'internal', 'detail': str(e), 'diag': diag}), 500

@ui_bp.route('/api/domain_groups/<group>', methods=['DELETE'])
def api_domain_groups_delete(group):
    try:
        _log.info('domain_group_delete request group=%s', group)
        obj = _dg.delete_group(group)
        _log.info('domain_group_delete_success group=%s version=%s', group, obj.version)
        from .. import domain_groups as _dg_mod
        diag = _dg_mod.diagnostics()
        return jsonify({'status': 'ok', 'groups': obj.groups, 'version': obj.version, 'deleted': group, 'diag': diag})
    except ValueError as e:
        _log.warning('domain_group_delete_value_error group=%s err=%s', group, e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': str(e), 'diag': diag}), 400
    except Exception as e:
        _log.exception('domain_group_delete_failed group=%s err=%s', group, e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': 'internal', 'detail': str(e), 'diag': diag}), 500

@ui_bp.route('/api/domain_groups/<group>/assign', methods=['POST'])
def api_domain_groups_assign(group):
    try:
        data = request.get_json(force=True, silent=True) or {}
        domain = data.get('domain')
        _log.info('domain_group_assign request group=%s domain=%s', group, domain)
        obj = _dg.assign_domain(group, domain)
        _log.info('domain_group_assign_success group=%s domain=%s', group, domain)
        from .. import domain_groups as _dg_mod
        diag = _dg_mod.diagnostics()
        return jsonify({'status': 'ok', 'groups': obj.groups, 'version': obj.version, 'assigned': {'group': group, 'domain': domain}, 'diag': diag})
    except ValueError as e:
        _log.warning('domain_group_assign_value_error group=%s domain=%s err=%s', group, data.get('domain'), e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': str(e), 'diag': diag}), 400
    except Exception as e:
        _log.exception('domain_group_assign_failed group=%s domain=%s err=%s', group, data.get('domain'), e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': 'internal', 'detail': str(e), 'diag': diag}), 500

@ui_bp.route('/api/domain_groups/<group>/rename', methods=['POST'])
def api_domain_groups_rename(group):
    try:
        data = request.get_json(force=True, silent=True) or {}
        new_name = data.get('new')
        _log.info('domain_group_rename request old=%s new=%s', group, new_name)
        obj = _dg.rename_group(group, new_name)
        _log.info('domain_group_rename_success old=%s new=%s version=%s', group, new_name, obj.version)
        from .. import domain_groups as _dg_mod
        diag = _dg_mod.diagnostics()
        return jsonify({'status': 'ok', 'renamed': {'old': group, 'new': new_name}, 'groups': obj.groups, 'version': obj.version, 'diag': diag})
    except ValueError as e:
        _log.warning('domain_group_rename_value_error old=%s new=%s err=%s', group, data.get('new'), e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': str(e), 'diag': diag}), 400
    except Exception as e:
        _log.exception('domain_group_rename_failed old=%s new=%s err=%s', group, data.get('new'), e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': 'internal', 'detail': str(e), 'diag': diag}), 500

@ui_bp.route('/api/domain_groups/<group>/remove', methods=['POST'])
def api_domain_groups_remove(group):
    try:
        data = request.get_json(force=True, silent=True) or {}
        domain = data.get('domain')
        _log.info('domain_group_remove request group=%s domain=%s', group, domain)
        obj = _dg.remove_domain(group, domain)
        _log.info('domain_group_remove_success group=%s domain=%s', group, domain)
        from .. import domain_groups as _dg_mod
        diag = _dg_mod.diagnostics()
        return jsonify({'status': 'ok', 'groups': obj.groups, 'version': obj.version, 'removed': {'group': group, 'domain': domain}, 'diag': diag})
    except ValueError as e:
        _log.warning('domain_group_remove_value_error group=%s domain=%s err=%s', group, data.get('domain'), e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': str(e), 'diag': diag}), 400
    except Exception as e:
        _log.exception('domain_group_remove_failed group=%s domain=%s err=%s', group, data.get('domain'), e)
        try:
            from .. import domain_groups as _dg_mod
            diag = _dg_mod.diagnostics()
        except Exception:
            diag = None
        return jsonify({'error': 'internal', 'detail': str(e), 'diag': diag}), 500

@ui_bp.route('/api/domain_groups/_diag', methods=['GET'])
def api_domain_groups_diag():
    try:
        from .. import domain_groups as _dg_mod
        info = _dg_mod.diagnostics()
        _log.debug('domain_group_diag info=%s', info)
        return jsonify({'status': 'ok', 'info': info})
    except Exception as e:
        _log.exception('domain_group_diag_failed err=%s', e)
        return jsonify({'error': 'internal', 'detail': str(e)}), 500

@ui_bp.route('/api/domain_groups/_raw', methods=['GET'])
def api_domain_groups_raw():
    """Return raw JSON file content (best-effort) for deep debugging."""
    try:
        from .. import domain_groups as _dg_mod
        diag = _dg_mod.diagnostics()
        path = diag.get('path')
        raw_content = None
        read_err = None
        if path and os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    raw_content = f.read()
            except Exception as re:
                read_err = str(re)
        return jsonify({'status': 'ok', 'diag': diag, 'raw': raw_content, 'read_error': read_err})
    except Exception as e:
        _log.exception('domain_group_raw_failed err=%s', e)
        return jsonify({'error': 'internal', 'detail': str(e)}), 500


# Temporary debug endpoint used by the UI instrumentation when diagnosing
# Playwright click/visibility issues. Accepts a JSON payload and records it
# to both the application logger and a file at tmp/debug_report.jsonl so the
# test runner can inspect the payload after a failing run.
@ui_bp.route('/_debug/report', methods=['POST'])
def debug_report():
    try:
        data = request.get_json(force=True, silent=True) or {}
        try:
            _log.info('DEBUG REPORT: %s', data)
        except Exception:
            pass
        # also persist to a file for easier inspection in test runs
        try:
            # Persist debug reports into the repository tmp/ directory so test runs
            # can consistently locate them regardless of the process cwd.
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
            ddir = os.path.join(repo_root, 'tmp')
            os.makedirs(ddir, exist_ok=True)
            path = os.path.join(ddir, 'debug_report.jsonl')
            import json
            with open(path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(data, default=str) + '\n')
        except Exception:
            _log.exception('write_debug_file_failed')
        return jsonify({'status': 'ok'})
    except Exception as e:
        _log.exception('debug_report_failed')
        return jsonify({'error': str(e)}), 500

# Redundant guard: ensure /stats route exists even if earlier insertion is removed by merge.
try:
    stats_page
except NameError:
    @ui_bp.route('/stats')
    def stats_page():
        return render_template('stats.html')

# Independent API

@ui_bp.route("/api/performance_timeseries")
def api_performance_timeseries():
    from app.db import get_db
    import datetime

    db = get_db()
    rows = db.execute("""
        SELECT date_trunc('hour', finished_at) AS hour,
               COUNT(*) AS scans,
               AVG(confidence) AS avg_conf,
               SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) AS success,
               SUM(CASE WHEN status='timeout' THEN 1 ELSE 0 END) AS timeout,
               SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS error
        FROM scans
        WHERE finished_at > NOW() - INTERVAL '24 hours'
        GROUP BY hour
        ORDER BY hour
    """).fetchall()

    if not rows:
        # fallback
        return {
            "timestamps": [f"{i}h" for i in range(1,13)],
            "scans": [10,20,30,15,25,35,30,20,25,40,50,45],
            "avg_conf": [80,78,75,83,85,90,88,79,84,86,89,92],
            "success": 120, "timeout": 10, "error": 5,
        }

    timestamps = [r["hour"].strftime("%H:%M") for r in rows]
    return {
        "timestamps": timestamps,
        "scans": [r["scans"] for r in rows],
        "avg_conf": [r["avg_conf"] for r in rows],
        "success": sum(r["success"] for r in rows),
        "timeout": sum(r["timeout"] for r in rows),
        "error": sum(r["error"] for r in rows),
    }
    
@ui_bp.route("/api/top_technologies")
def api_top_technologies():
    from app.db import get_db
    db = get_db()
    rows = db.execute("""
        SELECT t.name, t.category, COUNT(*) as count, AVG(t.confidence) as avg_conf
        FROM technologies t
        JOIN scans s ON s.id = t.scan_id
        WHERE s.finished_at > NOW() - INTERVAL '30 days'
        GROUP BY t.name, t.category
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    if not rows:
        return [{"name":"Apache","category":"Web Server","count":50,"avg_conf":90},
                {"name":"jQuery","category":"JS Lib","count":40,"avg_conf":95}]

    return [dict(r) for r in rows]

@ui_bp.route('/api/tech/<tech_name>/domains')
def api_tech_domains(tech_name: str):
    """Get list of domains that use a specific technology."""
    try:
        if getattr(_db, '_DB_DISABLED', False):
            # Fallback to in-memory mirror
            mem = getattr(_db, '_MEM_DOMAIN_TECHS', {})
            domains = set()
            for (domain, name, _ver), rec in mem.items():
                if name.lower() == tech_name.lower():
                    domains.add(domain)
            return jsonify({'tech': tech_name, 'domains': sorted(list(domains))})
        
        from ..db import get_conn
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT domain 
                    FROM domain_techs 
                    WHERE LOWER(tech_name) = LOWER(%s)
                    ORDER BY domain
                    LIMIT 500
                """, (tech_name,))
                domains = [r[0] for r in cur.fetchall()]
                return jsonify({'tech': tech_name, 'domains': domains, 'count': len(domains)})
    except Exception as e:
        _log.exception('tech_domains_failed tech=%s err=%s', tech_name, e)
        return jsonify({'error': 'internal', 'detail': str(e)}), 500

@ui_bp.route('/api/category/<category_name>/technologies')
def api_category_technologies(category_name: str):
    """Get list of technologies in a specific category, ordered by usage count."""
    try:
        if getattr(_db, '_DB_DISABLED', False):
            # Fallback to in-memory mirror
            mem = getattr(_db, '_MEM_DOMAIN_TECHS', {})
            tech_counts = {}
            for (domain, name, version), rec in mem.items():
                cats = rec.get('categories', '')
                if cats and category_name.lower() in cats.lower():
                    tech_counts[name] = tech_counts.get(name, 0) + 1
            
            techs = sorted(
                [{'tech': k, 'count': v, 'category': category_name} for k,v in tech_counts.items()],
                key=lambda x: x['count'],
                reverse=True
            )
            return jsonify({'category': category_name, 'technologies': techs[:20]})
        
        from ..db import get_conn
        with get_conn() as conn:
            with conn.cursor() as cur:
                # Search for category in comma-separated categories field
                cur.execute("""
                    SELECT tech_name, COUNT(*) as count
                    FROM domain_techs
                    WHERE LOWER(categories) LIKE LOWER(%s)
                    GROUP BY tech_name
                    ORDER BY count DESC
                    LIMIT 20
                """, (f'%{category_name}%',))
                techs = [{'tech': r[0], 'count': r[1], 'category': category_name} for r in cur.fetchall()]
                return jsonify({'category': category_name, 'technologies': techs})
    except Exception as e:
        _log.exception('category_technologies_failed category=%s err=%s', category_name, e)
        return jsonify({'error': 'internal', 'detail': str(e)}), 500

