from flask import Blueprint, render_template, jsonify, request, redirect, url_for, send_from_directory, abort
import logging, os, datetime
from werkzeug.utils import safe_join

from .. import db as _db
from .. import domain_groups as _dg

ui_bp = Blueprint('ui', __name__)
_log = logging.getLogger('techscan.ui')

_ICON_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'node_modules', 'tech-stack-icons', 'icons'))
if not os.path.isdir(_ICON_DIR):
    _log.warning('tech-stack-icons icon directory missing path=%s', _ICON_DIR)

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
        _log.debug('failed to set no-cache headers on legacy redirect', exc_info=True)
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


@ui_bp.route('/report')
def report_page():
    """Render report page for executive presentations with hierarchical drill-down."""
    return render_template('report.html')

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
            _log.debug('failed to compute aggregated avg durations from STATS; falling back', exc_info=True)
            out['avg_duration_ms'] = s.get('average_duration_ms', {}).get('fast')
            out['avg_version_audit_ms'] = 0.0
        out['uptime_seconds'] = s.get('uptime_seconds')
        out['cache_entries'] = s.get('cache_entries')
    except Exception:
        _log.debug('failed to load runtime STATS mirror', exc_info=True)
    # DB-backed aggregates when available
    if not getattr(_db, '_DB_DISABLED', False):
        try:
            from ..db import get_conn
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # scans total, last scan, and total payload footprint
                    cur.execute('SELECT COUNT(*), MAX(finished_at), SUM(payload_bytes) FROM scans')
                    r = cur.fetchone()
                    out['scans_total'] = r[0] or 0
                    out['last_scan'] = {'finished_at': r[1].timestamp()} if r and r[1] else None
                    total_payload_raw = r[2] if r else None
                    try:
                        out['total_payload_bytes'] = int(total_payload_raw) if total_payload_raw is not None else 0
                    except Exception:
                        out['total_payload_bytes'] = float(total_payload_raw) if total_payload_raw is not None else 0.0
                    
                    # unique domains count from domain_techs mirror (legacy)
                    cur.execute('SELECT COUNT(DISTINCT domain) FROM domain_techs')
                    unique_count = cur.fetchone()
                    out['unique_domains'] = unique_count[0] if unique_count else 0

                    # total domains aligned with /api/domains (distinct domains from scans table)
                    try:
                        cur.execute('SELECT COUNT(DISTINCT domain) FROM scans')
                        domain_row = cur.fetchone()
                        domains_total = domain_row[0] if domain_row else out['unique_domains']
                        out['domains_total'] = domains_total
                        out['total_domains'] = domains_total
                    except Exception:
                        out['domains_total'] = out.get('unique_domains', 0)
                        out['total_domains'] = out['domains_total']
                    
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
                            SELECT
                                AVG(
                                    CASE
                                        WHEN (raw_json->'phases'->>'evidence_ms') ~ '^-?[0-9]+(\\.[0-9]+)?$'
                                            THEN (raw_json->'phases'->>'evidence_ms')::DOUBLE PRECISION
                                        ELSE NULL
                                    END
                                ) AS evidence_avg,
                                AVG(
                                    CASE
                                        WHEN (raw_json->'phases'->>'version_audit_ms') ~ '^-?[0-9]+(\\.[0-9]+)?$'
                                            THEN (raw_json->'phases'->>'version_audit_ms')::DOUBLE PRECISION
                                        ELSE NULL
                                    END
                                ) AS version_audit_avg
                            FROM scans
                            WHERE raw_json IS NOT NULL AND finished_at >= NOW() - INTERVAL '24 hours'
                        """)
                        r3 = cur.fetchone()
                        out['avg_evidence_ms_24h'] = float(r3[0]) if r3 and r3[0] is not None else None
                        out['avg_version_audit_ms_24h'] = float(r3[1]) if r3 and r3[1] is not None else None
                    except Exception:
                        _log.debug('failed to compute evidence/version audit rolling averages', exc_info=True)
                        out['avg_evidence_ms_24h'] = None
                        out['avg_version_audit_ms_24h'] = out.get('avg_version_audit_ms')

                    # top technologies (larger window, default uncategorized bucket)
                    cur.execute(
                        """
                           SELECT tech_name,
                               COALESCE(NULLIF(categories, ''), 'Uncategorized') AS cat_label,
                               COUNT(DISTINCT domain) AS c
                        FROM domain_techs
                           GROUP BY tech_name, COALESCE(NULLIF(categories, ''), 'Uncategorized')
                        ORDER BY c DESC
                        LIMIT 60
                        """
                    )
                    out['top_technologies'] = [{'tech': r[0], 'categories': r[1], 'count': r[2]} for r in cur.fetchall()]

                    # top categories (split comma-separated categories)
                    # Include explicit 'uncategorized' bucket for rows where categories is NULL/empty
                    cur.execute(
                                """
                                    SELECT category, c FROM (
                                    SELECT LOWER(trim(x)) AS category, COUNT(DISTINCT domain) AS c
                                        FROM (
                                        SELECT domain, unnest(string_to_array(categories, ',')) AS x
                                        FROM domain_techs
                                        WHERE categories IS NOT NULL
                                            ) t
                                            WHERE trim(x) <> ''
                                            GROUP BY LOWER(trim(x))
                                            UNION ALL
                                            SELECT 'uncategorized' AS category, COUNT(DISTINCT domain) FROM domain_techs WHERE categories IS NULL OR trim(categories) = ''
                                            ) q
                                            ORDER BY c DESC
                                            LIMIT 60
                                        """
                                        )
                    out['top_categories'] = [{'category': r[0], 'count': r[1]} for r in cur.fetchall()]

                    # payload size aggregates (last 30 days)
                    try:
                        cur.execute(
                            """
                            SELECT
                                AVG(payload_bytes) FILTER (WHERE finished_at >= NOW() - INTERVAL '1 day') AS avg_day,
                                AVG(payload_bytes) FILTER (WHERE finished_at >= NOW() - INTERVAL '7 day') AS avg_week,
                                AVG(payload_bytes) FILTER (WHERE finished_at >= NOW() - INTERVAL '30 day') AS avg_month
                            FROM scans
                            WHERE finished_at >= NOW() - INTERVAL '30 day' AND payload_bytes IS NOT NULL
                            """
                        )
                        payload_row = cur.fetchone()
                        out['payload_size_stats'] = {
                            'avg_daily_bytes': float(payload_row[0]) if payload_row and payload_row[0] is not None else None,
                            'avg_weekly_bytes': float(payload_row[1]) if payload_row and payload_row[1] is not None else None,
                            'avg_monthly_bytes': float(payload_row[2]) if payload_row and payload_row[2] is not None else None
                        }
                    except Exception:
                        _log.debug('failed to compute payload size aggregates', exc_info=True)
                        out['payload_size_stats'] = {
                            'avg_daily_bytes': None,
                            'avg_weekly_bytes': None,
                            'avg_monthly_bytes': None
                        }
        except Exception as e:
            _log.exception('api_stats db aggregation failed err=%s', e)
            out['db_error'] = str(e)
            out.setdefault('top_technologies', [])
            out.setdefault('top_categories', [])
            out.setdefault('payload_size_stats', {
                'avg_daily_bytes': None,
                'avg_weekly_bytes': None,
                'avg_monthly_bytes': None
            })
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
                [{'tech': k, 'count': v} for k, v in tech_counts.items()], key=lambda x: x['count'], reverse=True
            )[:30]
            out['top_categories'] = sorted(
                [{'category': k, 'count': v} for k, v in cat_counts.items()], key=lambda x: x['count'], reverse=True
            )[:25]
            out['payload_size_stats'] = {
                'avg_daily_bytes': None,
                'avg_weekly_bytes': None,
                'avg_monthly_bytes': None
            }
            out['total_payload_bytes'] = None
        except Exception:
            out.setdefault('top_technologies', [])
            out.setdefault('top_categories', [])
            out.setdefault('payload_size_stats', {
                'avg_daily_bytes': None,
                'avg_weekly_bytes': None,
                'avg_monthly_bytes': None
            })
            out.setdefault('total_payload_bytes', None)
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
                               COALESCE(jsonb_array_length(s.technologies_json), 0) AS tech_count,
                               s.payload_bytes
                        FROM (
                            SELECT DISTINCT ON (domain) domain, finished_at, mode, technologies_json, payload_bytes
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
                        payload_bytes = r[4]
                        domain_meta.append((domain, last_scan_ts, last_mode, tech_count, payload_bytes))
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
                    _log.debug('failed computing per-domain diff extras', exc_info=True)
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
                domain_meta.append((domain, info['last_seen'], None, len(info['techs']), None))
    except Exception as e:
        return jsonify({'error': 'failed_collect_domains', 'detail': str(e)}), 500
    payload = _dg.group_domains(domain_meta, extras=diff_extras)
    return jsonify(payload)

@ui_bp.route('/api/domain/<domain>', methods=['DELETE'])
def api_domain_delete(domain: str):
    raw_domain = (domain or '').strip()
    if not raw_domain:
        return jsonify({'error': 'bad_domain'}), 400
    normalized = raw_domain.lower()
    scans_deleted = 0
    tech_rows_deleted = 0
    db_disabled = bool(getattr(_db, '_DB_DISABLED', False))
    runtime_disabled = False
    try:
        runtime_disabled = bool(getattr(_db, '_is_disabled_runtime', lambda: False)())
    except Exception:
        runtime_disabled = False
    db_disabled = db_disabled or runtime_disabled
    if not db_disabled:
        try:
            get_conn = getattr(_db, 'get_conn')
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute('DELETE FROM scans WHERE domain=%s', (normalized,))
                    scans_deleted = cur.rowcount or 0
                    cur.execute('DELETE FROM domain_techs WHERE domain=%s', (normalized,))
                    tech_rows_deleted = cur.rowcount or 0
                conn.commit()  # IMPORTANT: Commit the transaction to persist changes
        except Exception as e:
            _log.exception('api_domain_delete_failed domain=%s', normalized)
            return jsonify({'error': 'delete_failed', 'detail': str(e)}), 500
    else:
        # Mirror removal handled below via in-memory store purge
        pass
    mem_entries_cleared = 0
    try:
        mem = getattr(_db, '_MEM_DOMAIN_TECHS', {})
        if mem:
            to_remove = [k for k in list(mem.keys()) if k and k[0] == normalized]
            for key in to_remove:
                mem.pop(key, None)
            mem_entries_cleared = len(to_remove)
    except Exception:
        _log.debug('api_domain_delete_mem_cleanup_failed domain=%s', normalized, exc_info=True)
    # When DB is disabled, mem mirror is the source of truth for tech rows
    if db_disabled:
        tech_rows_deleted = mem_entries_cleared
    # Remove from any assigned groups
    groups_removed = 0
    try:
        membership = _dg.load().membership(normalized)
        groups_removed = len(membership)
        if groups_removed:
            _dg.remove_domain_everywhere(normalized)
    except Exception:
        _log.debug('api_domain_delete_group_cleanup_failed domain=%s', normalized, exc_info=True)
    # Flush sniff cache entries for this domain (best-effort)
    sniff_purged = False
    try:
        from .. import scan_utils as _su
        flushed = 0
        for key in {raw_domain, normalized}:
            if not key:
                continue
            try:
                if getattr(_su, '_html_sniff_cache', None) and key in _su._html_sniff_cache:  # type: ignore[attr-defined]
                    _su._html_sniff_cache.pop(key, None)  # type: ignore[attr-defined]
                    flushed += 1
            except Exception:
                continue
        sniff_purged = flushed > 0
    except Exception:
        _log.debug('api_domain_delete_sniff_cleanup_failed domain=%s', normalized, exc_info=True)
    # Clear cached aggregate counts
    try:
        cache = getattr(_db, '_count_cache', None)
        if cache:
            cache.clear()
    except Exception:
        pass
    _log.info('api_domain_delete_ok domain=%s scans=%s tech_rows=%s groups=%s mem_cleared=%s', normalized, scans_deleted, tech_rows_deleted, groups_removed, mem_entries_cleared)
    return jsonify({
        'status': 'deleted',
        'domain': normalized,
        'scans_deleted': scans_deleted,
        'tech_rows_deleted': tech_rows_deleted,
        'groups_removed': groups_removed,
        'mem_entries_cleared': mem_entries_cleared,
        'sniff_cache_cleared': sniff_purged
    })

@ui_bp.route('/api/domain/<domain>/detail')
def api_domain_detail(domain: str):
    # Retrieve latest two scans
    db_disabled = bool(getattr(_db, '_DB_DISABLED', False))
    try:
        if getattr(_db, '_is_disabled_runtime', None):
            db_disabled = db_disabled or bool(_db._is_disabled_runtime())  # type: ignore[attr-defined]
    except Exception:
        pass
    if db_disabled:
        return jsonify({'error': 'db_disabled'}), 503
    snapshot_param = (request.args.get('snapshot') or '').strip().lower()
    prefer_best_snapshot = snapshot_param in ('best', 'max', 'top')
    # Import scan_utils to introspect inflight/deferred status (best-effort)
    try:
        from .. import scan_utils as _su
    except Exception:
        _su = None
    latest = None
    previous = None
    best_scan = None
    try:
        get_conn = getattr(_db, 'get_conn')
        with get_conn() as conn:
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
                    'tech_count': len(techs),
                    'raw': r[9],
                    'payload_bytes': (r[10] if len(r) > 10 else None)
                }
            with conn.cursor() as cur:
                cur.execute(
                    """
                        SELECT id, mode, started_at, finished_at, duration_ms, from_cache, retries, timeout_used,
                               technologies_json, raw_json, payload_bytes
                        FROM scans
                        WHERE domain=%s
                        ORDER BY finished_at DESC
                        LIMIT 2
                    """,
                    (domain,)
                )
                rows = cur.fetchall()
                if not rows:
                    return jsonify({'error': 'not_found'}), 404
                if len(rows) >= 1:
                    latest = row_to_scan(rows[0])
                if len(rows) >= 2:
                    previous = row_to_scan(rows[1])
            with conn.cursor() as cur_best:
                cur_best.execute(
                    """
                        SELECT id, mode, started_at, finished_at, duration_ms, from_cache, retries, timeout_used,
                               technologies_json, raw_json, payload_bytes
                        FROM scans
                        WHERE domain=%s
                        ORDER BY COALESCE(tech_count, 0) DESC, finished_at DESC
                        LIMIT 1
                    """,
                    (domain,)
                )
                brow = cur_best.fetchone()
                if isinstance(brow, (list, tuple)) and len(brow) >= 10:
                    best_scan = row_to_scan(brow)
    except Exception as e:
        return jsonify({'error': 'db_query_failed', 'detail': str(e)}), 500
    active_snapshot = 'latest'
    # Only use best snapshot if explicitly requested via query parameter
    # Removed auto-preference to best snapshot to keep metrics consistent with table listing
    if prefer_best_snapshot and best_scan:
        active_snapshot = 'best'
    active_scan = best_scan if active_snapshot == 'best' else latest
    if not active_scan:
        # fallback: use latest even if best missing or preference failed
        active_snapshot = 'latest'
        active_scan = latest
    compare_scan = None
    if active_snapshot == 'latest':
        compare_scan = previous
    else:
        # when viewing best snapshot, compare against actual latest if different, else previous
        if latest and best_scan and latest.get('scan_id') != best_scan.get('scan_id'):
            compare_scan = latest
        else:
            compare_scan = previous
    diff = _compute_diff(active_scan, compare_scan)
    # Metrics: extract phases if present in raw
    metrics = {}
    try:
        phases = (active_scan.get('raw') or {}).get('phases') if active_scan else None
        if isinstance(phases, dict):
            for k in ['engine_ms','synthetic_ms','heuristic_total_ms','heuristic_core_ms','sniff_ms','micro_ms','node_full_ms','full_attempt_ms','fallback_ms','version_audit_ms']:
                if k in phases:
                    metrics[k] = phases[k]
    except Exception:
        _log.debug('failed to extract phases metrics from latest raw', exc_info=True)
    technologies = active_scan.get('technologies') if active_scan else []
    # Ensure simplified tech objects (name, version, categories, confidence) if raw format contains them
    norm_tech = []
    for t in technologies:
        if not isinstance(t, dict):
            continue
        # Get detection_raw for fallback evidence extraction
        detection_raw = t.get('detection_raw') or {}
        tech_entry = {
            'name': t.get('name'),
            'version': t.get('version'),
            'categories': t.get('categories') or [],
            'confidence': t.get('confidence'),
            # Basic info
            'website': t.get('website'),
            'description': t.get('description'),
            'icon': t.get('icon'),
            'cpe': t.get('cpe'),
            # Wappalyzer evidence/detection fields (check detection_raw as fallback)
            'headers': t.get('headers') or detection_raw.get('headers'),
            'scripts': t.get('scripts') or detection_raw.get('scripts'),
            'scriptSrc': t.get('scriptSrc') or detection_raw.get('scriptSrc'),
            'meta': t.get('meta') or detection_raw.get('meta'),
            'html': t.get('html') or detection_raw.get('html'),
            'url': t.get('url') or detection_raw.get('url'),
            'cookies': t.get('cookies') or detection_raw.get('cookies'),
            'dom': t.get('dom') or detection_raw.get('dom'),
            'xpath': t.get('xpath') or detection_raw.get('xpath'),
            'js': t.get('js') or detection_raw.get('js'),
            'css': t.get('css') or detection_raw.get('css'),
            'robots': t.get('robots') or detection_raw.get('robots'),
            'text': t.get('text') or detection_raw.get('text'),
            'certIssuer': t.get('certIssuer') or detection_raw.get('certIssuer'),
            # Pattern/match data
            'pattern': t.get('pattern') or detection_raw.get('pattern'),
            'match': t.get('match') or detection_raw.get('match'),
            'regex': t.get('regex') or detection_raw.get('regex'),
            # Relationships
            'implies': t.get('implies') or detection_raw.get('implies'),
            'requires': t.get('requires') or detection_raw.get('requires'),
            'excludes': t.get('excludes') or detection_raw.get('excludes'),
            # Evidence array (normalized evidence from scan_utils)
            'evidence': t.get('evidence') or [],
        }
        # Clean up None values
        tech_entry = {k: v for k, v in tech_entry.items() if v is not None}
        norm_tech.append(tech_entry)
    tiered_hint_meta = None
    raw_blob = active_scan.get('raw') if active_scan else None
    if isinstance(raw_blob, dict):
        tiered_hint_meta = raw_blob.get('_tiered_hint_meta')
    def summarize_full(scan: dict | None):
        if not scan:
            return None
        return {k: scan.get(k) for k in ['scan_id','mode','started_at','finished_at','duration_ms','from_cache','retries','timeout_used','payload_bytes','tech_count']}

    def summarize_brief(scan: dict | None):
        if not scan:
            return None
        return {k: scan.get(k) for k in ['scan_id','mode','finished_at','payload_bytes','tech_count']}

    response = {
        'domain': domain,
        'latest': summarize_full(latest),
        'previous': summarize_brief(previous),
        'best_snapshot': summarize_full(best_scan),
        'compare_snapshot': summarize_brief(compare_scan),
        'selected_snapshot': active_snapshot,
        'selected_scan': summarize_full(active_scan),
        'diff': diff,
        'technologies': norm_tech,
        'metrics': metrics
    }
    if tiered_hint_meta:
        response['tiered_hint_meta'] = tiered_hint_meta
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
                    _log.debug('failed to compute ETA from STATS', exc_info=True)
        if in_progress:
            response['status'] = 'in-progress'
            if eta_s:
                response['eta_seconds'] = eta_s
    except Exception:
        _log.debug('failed in in-progress detection heuristics', exc_info=True)
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

    @ui_bp.route('/assets/tech-icons/<path:filename>')
    def serve_tech_icon(filename: str):
        # Defensive: try multiple candidate filename normalizations before giving up.
        if not filename:
            abort(404)
        # Ensure svg extension
        if not filename.lower().endswith('.svg'):
            filename = filename + '.svg'

        def _candidates(name: str):
            name = name or ''
            base = os.path.basename(name)
            yield base
            # lowercase
            yield base.lower()
            # remove spaces, ampersands, parentheses variations
            no_paren = base.split('(')[0]
            yield no_paren
            # content inside parentheses
            if '(' in base and ')' in base:
                inside = base.split('(',1)[1].split(')',1)[0]
                yield inside + '.svg'
                yield inside.lower() + '.svg'
            # replace & with 'and' and non-alnum to hyphens
            s = base
            s = s.replace('&', 'and')
            import re
            s = re.sub(r"\s*\(.*?\)\s*", ' ', s)
            s = re.sub(r'[^a-zA-Z0-9]+', '-', s).strip('-')
            if s:
                if not s.lower().endswith('.svg'):
                    yield s.lower() + '.svg'
                else:
                    yield s.lower()

        # Try candidate paths
        tried = []
        for cand in _candidates(filename):
            try_path = safe_join(_ICON_DIR, cand)
            tried.append(cand)
            if not try_path:
                continue
            # Ensure path under icon dir
            if not str(try_path).startswith(_ICON_DIR):
                continue
            if os.path.isfile(try_path):
                rel_path = os.path.relpath(try_path, _ICON_DIR)
                try:
                    return send_from_directory(_ICON_DIR, rel_path, cache_timeout=60 * 60 * 24 * 7)
                except FileNotFoundError:
                    continue
        _log.debug('serve_tech_icon_missing requested=%s tried=%s dir=%s', filename, tried, _ICON_DIR)
        abort(404)

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
            _log.debug('failed to log debug report', exc_info=True)
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

def _timeseries_fallback_payload():
    labels = []
    now = datetime.datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    for i in range(11, -1, -1):
        slot = now - datetime.timedelta(hours=i)
        labels.append(slot.strftime('%H:%M'))
    scans = [18, 22, 27, 31, 36, 42, 45, 40, 34, 30, 26, 22]
    avg_conf = [83.2, 83.9, 84.6, 85.1, 85.8, 86.3, 86.6, 86.2, 85.7, 85.1, 84.6, 84.0]
    return {
        'timestamps': labels,
        'scans': scans[:len(labels)],
        'avg_conf': avg_conf[:len(labels)],
        'success': 820,
        'timeout': 145,
        'error': 35
    }


@ui_bp.route("/api/performance_timeseries")
def api_performance_timeseries():
    fallback = _timeseries_fallback_payload()
    if getattr(_db, '_DB_DISABLED', False):
        return jsonify(fallback)
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    WITH recent AS (
                        SELECT
                            date_trunc('hour', s.finished_at) AS hour,
                            NULLIF(s.error, '') AS error,
                            conf.avg_conf
                        FROM scans s
                        LEFT JOIN LATERAL (
                            SELECT AVG((tech->>'confidence')::DOUBLE PRECISION) AS avg_conf
                            FROM jsonb_array_elements(COALESCE(s.technologies_json, '[]'::jsonb)) AS tech
                            WHERE (tech->>'confidence') ~ '^-?[0-9]+(\\.[0-9]+)?$'
                        ) AS conf ON TRUE
                        WHERE s.finished_at > NOW() - INTERVAL '24 hours'
                    )
                    SELECT
                        hour,
                        COUNT(*) AS scans,
                        AVG(avg_conf) AS avg_conf,
                        SUM(CASE WHEN error IS NULL THEN 1 ELSE 0 END) AS success,
                        SUM(CASE WHEN error IS NOT NULL AND (
                            error ILIKE '%timeout%' OR
                            error ILIKE '%timed out%' OR
                            error ILIKE '%time out%' OR
                            error ILIKE '%deadline%'
                        ) THEN 1 ELSE 0 END) AS timeout,
                        SUM(CASE WHEN error IS NOT NULL AND NOT (
                            error ILIKE '%timeout%' OR
                            error ILIKE '%timed out%' OR
                            error ILIKE '%time out%' OR
                            error ILIKE '%deadline%'
                        ) THEN 1 ELSE 0 END) AS error
                    FROM recent
                    GROUP BY hour
                    ORDER BY hour
                """)
                rows = cur.fetchall()
    except Exception as exc:
        _log.warning('performance_timeseries query failed; using fallback', exc_info=True)
        return jsonify(fallback)

    if not rows:
        return jsonify(fallback)

    timestamps: list[str] = []
    scans: list[int] = []
    avg_conf: list[float] = []
    success_total = timeout_total = error_total = 0
    for hour, count, avg, success, timeout, error in rows:
        try:
            label = hour.strftime('%H:%M') if hasattr(hour, 'strftime') else str(hour)
        except Exception:
            label = str(hour)
        timestamps.append(label)
        scans.append(int(count or 0))
        avg_conf.append(float(avg) if avg is not None else 0.0)
        success_total += int(success or 0)
        timeout_total += int(timeout or 0)
        error_total += int(error or 0)

    payload = {
        'timestamps': timestamps,
        'scans': scans,
        'avg_conf': avg_conf,
        'success': success_total,
        'timeout': timeout_total,
        'error': error_total
    }
    return jsonify(payload)
    
@ui_bp.route("/api/top_technologies")
def api_top_technologies():
    if getattr(_db, '_DB_DISABLED', False):
        return jsonify([
            {"name": "Apache", "category": "Web Server", "count": 50, "avg_conf": 90},
            {"name": "jQuery", "category": "JS Library", "count": 40, "avg_conf": 95}
        ])
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    WITH expanded AS (
                        SELECT
                            tech->>'name' AS name,
                            (
                                SELECT array_to_string(ARRAY_AGG(DISTINCT trim(cat_name)) FILTER (WHERE trim(cat_name) <> ''), ', ')
                                FROM (
                                    SELECT cat->>'name' AS cat_name
                                    FROM jsonb_array_elements(tech->'categories') AS cat
                                ) AS cat_names
                            ) AS category_labels,
                            CASE
                                WHEN (tech->>'confidence') ~ '^-?[0-9]+(\\.[0-9]+)?$'
                                    THEN (tech->>'confidence')::DOUBLE PRECISION
                                ELSE NULL
                            END AS confidence
                        FROM scans s
                        CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.technologies_json, '[]'::jsonb)) AS tech
                        WHERE s.finished_at > NOW() - INTERVAL '30 days'
                    )
                    SELECT
                        name,
                        COALESCE(category_labels, '') AS categories,
                        COUNT(*) AS count,
                        AVG(confidence) AS avg_conf
                    FROM expanded
                    WHERE name IS NOT NULL AND trim(name) <> ''
                    GROUP BY name, category_labels
                    ORDER BY count DESC
                    LIMIT 10
                """)
                rows = cur.fetchall()
    except Exception:
        _log.warning('top_technologies query failed; returning fallback', exc_info=True)
        rows = []

    if not rows:
        return jsonify([
            {"name": "Apache", "category": "Web Server", "count": 50, "avg_conf": 90},
            {"name": "jQuery", "category": "JavaScript Library", "count": 40, "avg_conf": 95}
        ])

    normalized = []
    for name, category, count, avg_conf in rows:
        categories = []
        if category:
            categories = [seg.strip() for seg in str(category).split(',') if seg.strip()]
        normalized.append({
            'name': name,
            'category': category,
            'categories': categories,
            'count': int(count or 0),
            'avg_conf': float(avg_conf) if avg_conf is not None else None
        })
    return jsonify(normalized)

@ui_bp.route('/api/tech/<tech_name>/domains')
def api_tech_domains(tech_name: str):
    """Get list of domains that use a specific technology."""
    try:
        include_hints = request.args.get('include_hints') == '1'
        if getattr(_db, '_DB_DISABLED', False):
            # Fallback to in-memory mirror
            mem = getattr(_db, '_MEM_DOMAIN_TECHS', {})
            domains = set()
            for (domain, name, _ver), rec in mem.items():
                if name.lower() == tech_name.lower():
                    domains.add(domain)
            payload = {'tech': tech_name, 'domains': sorted(list(domains)), 'count': len(domains)}
            return jsonify(payload)
        
        from ..db import get_conn
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT domain 
                    FROM domain_techs 
                    WHERE LOWER(tech_name) = LOWER(%s)
                    ORDER BY domain
                    LIMIT 2000
                """, (tech_name,))
                domains = [r[0] for r in cur.fetchall()]
        hint_meta = {}
        if include_hints and domains:
            try:
                hint_meta = _db.get_hint_meta_for_domains(domains)
            except Exception:
                logging.getLogger('techscan.ui').debug('failed fetching hint meta for tech=%s', tech_name, exc_info=True)
        payload = {'tech': tech_name, 'domains': domains, 'count': len(domains)}
        if include_hints and hint_meta:
            payload['hint_meta'] = hint_meta
        return jsonify(payload)
    except Exception as e:
        _log.exception('tech_domains_failed tech=%s err=%s', tech_name, e)
        return jsonify({'error': 'internal', 'detail': str(e)}), 500

@ui_bp.route('/api/category/<category_name>/technologies')
def api_category_technologies(category_name: str):
    """Get list of technologies in a specific category, ordered by usage count.

    Handles both explicit category labels (split from comma-separated field) and the
    synthetic "uncategorized" bucket (rows where categories is NULL/empty).
    """
    # Map of technologies to their CORRECT categories (used to filter wrong-category results)
    TECH_CATEGORY_OVERRIDE = {
        # JavaScript Libraries - NOT CDN
        'jquery': 'javascript libraries',
        'jquery ui': 'javascript libraries',
        'jquery migrate': 'javascript libraries',
        'jquery cdn': 'javascript libraries',
        'react': 'javascript libraries',
        'vue.js': 'javascript libraries',
        'moment.js': 'javascript libraries',
        'lodash': 'javascript libraries',
        'axios': 'javascript libraries',
        
        # JavaScript Frameworks - NOT Web Servers, NOT Programming Languages
        'angular': 'javascript frameworks',
        'angularjs': 'javascript frameworks',
        'next.js': 'javascript frameworks',
        'nuxt.js': 'javascript frameworks',
        'nuxt': 'javascript frameworks',
        'gatsby': 'javascript frameworks',
        'express': 'javascript frameworks',
        'express.js': 'javascript frameworks',
        'nest.js': 'javascript frameworks',
        'nestjs': 'javascript frameworks',
        'meteor': 'javascript frameworks',
        'ember.js': 'javascript frameworks',
        
        # JavaScript Runtimes - NOT Programming Languages
        'node.js': 'javascript runtimes',
        'deno': 'javascript runtimes',
        'bun': 'javascript runtimes',
        
        # Build Tools - NOT Programming Languages
        'typescript': 'javascript libraries',
        'babel': 'javascript libraries',
        'webpack': 'javascript libraries',
        'vite': 'javascript libraries',
        
        # UI/CSS Frameworks
        'bootstrap': 'ui frameworks',
        'tailwind css': 'css frameworks',
        'foundation': 'ui frameworks',
        'bulma': 'css frameworks',
        
        # Font Scripts - NOT CDN
        'font awesome': 'font scripts',
        'google font api': 'font scripts',
        'google hosted libraries': 'cdn',
        
        # CDN only
        'cloudflare': 'cdn',
        'jsdelivr': 'cdn',
        'cdnjs': 'cdn',
        
        # Programming Languages (actual languages only)
        'php': 'programming languages',
        'python': 'programming languages',
        'ruby': 'programming languages',
        'java': 'programming languages',
        'go': 'programming languages',
        
        # Web Servers only
        'nginx': 'web servers',
        'apache': 'web servers',
        'apache http server': 'web servers',
        'litespeed': 'web servers',
        'caddy': 'web servers',
        'iis': 'web servers',
        'tengine': 'web servers',
        
        # WordPress Plugins
        'wpml': 'wordpress plugins',
        'wordpress multilingual plugin (wpml)': 'wordpress plugins',
        'slider revolution': 'wordpress plugins',
        'elementor': 'wordpress plugins',
        'yoast seo': 'wordpress plugins',
        'contact form 7': 'wordpress plugins',
        'woocommerce': 'e-commerce',
        
        # JavaScript Libraries (from uncategorized)
        'datatables': 'javascript libraries',
        'datatables.net': 'javascript libraries',
        'gsap': 'javascript libraries',
        'three.js': 'javascript libraries',
        'chart.js': 'javascript libraries',
        'd3.js': 'javascript libraries',
        'highcharts': 'javascript libraries',
        
        # Security
        'sucuri': 'security',
        'bitninja': 'security',
        'imunify360': 'security',
        'imunify360-webshield': 'security',
        
        # Analytics
        'tableau': 'analytics',
        'hotjar': 'analytics',
    }

    normalized = (category_name or '').strip().lower()
    if not normalized:
        return jsonify({'category': category_name, 'technologies': []})

    try:
        if getattr(_db, '_DB_DISABLED', False):
            # Fallback to in-memory mirror
            mem = getattr(_db, '_MEM_DOMAIN_TECHS', {})
            tech_counts = {}
            for (_domain, name, _version), rec in mem.items():
                cats = rec.get('categories')
                tokens = []
                if isinstance(cats, str) and cats.strip():
                    tokens = [c.strip().lower() for c in cats.split(',') if c.strip()]
                if normalized == 'uncategorized':
                    if tokens:
                        continue
                elif not tokens or normalized not in tokens:
                    continue
                tech_counts[name] = tech_counts.get(name, 0) + 1

            techs = sorted(
                [{'tech': k, 'count': v, 'category': category_name} for k, v in tech_counts.items()],
                key=lambda x: x['count'],
                reverse=True
            )
            return jsonify({'category': category_name, 'technologies': techs})

        from ..db import get_conn
        with get_conn() as conn:
            with conn.cursor() as cur:
                if normalized == 'uncategorized':
                    cur.execute(
                        """
                        SELECT tech_name, COUNT(DISTINCT domain) AS count
                        FROM domain_techs
                        WHERE categories IS NULL
                           OR trim(categories) = ''
                           OR LOWER(categories) = 'uncategorized'
                        GROUP BY tech_name
                        ORDER BY count DESC
                        """
                    )
                else:
                    cur.execute(
                        """
                        SELECT tech_name, COUNT(DISTINCT domain) AS count
                        FROM (
                            SELECT domain, tech_name,
                                   LOWER(trim(cat_val)) AS category_value
                            FROM domain_techs
                            CROSS JOIN LATERAL unnest(string_to_array(categories, ',')) AS cat(cat_val)
                            WHERE categories IS NOT NULL AND trim(categories) <> ''
                        ) t
                        WHERE category_value = %s
                        GROUP BY tech_name
                        ORDER BY count DESC
                        """,
                        (normalized,)
                    )
                techs = [{'tech': r[0], 'count': r[1], 'category': category_name} for r in cur.fetchall()]
                
                # Filter out technologies that belong to a different category per override
                def should_include(tech_item):
                    tech_lower = tech_item['tech'].lower()
                    correct_cat = TECH_CATEGORY_OVERRIDE.get(tech_lower)
                    if correct_cat is None:
                        # No override - keep if not uncategorized category
                        return normalized != 'uncategorized' or tech_lower not in TECH_CATEGORY_OVERRIDE
                    # Has override - only include if correct category matches requested
                    return correct_cat == normalized
                
                techs = [t for t in techs if should_include(t)]
                return jsonify({'category': category_name, 'technologies': techs})
    except Exception as e:
        _log.exception('category_technologies_failed category=%s err=%s', category_name, e)
        return jsonify({'error': 'internal', 'detail': str(e)}), 500

