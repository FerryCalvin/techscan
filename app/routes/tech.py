from flask import Blueprint, request, jsonify, current_app, Response
import time, os, logging, csv, io, json
from .. import db as _db
from ..tech_cache import get as cache_get, set as cache_set, invalidate as cache_invalidate

bp = Blueprint('tech', __name__, url_prefix='/api')


@bp.route('/tech/<tech_key>', methods=['GET'])
def tech_meta(tech_key: str):
    # aggregate meta for a technology
    key = f'tech:{tech_key}:meta'
    cached = cache_get(key)
    if cached:
        return jsonify(cached)
    # Build aggregated response from db helpers
    try:
        total = _db.count_search_tech(tech_key)
        last_30 = _db.count_search_tech(tech_key, new24=False)  # placeholder (we can refine)
        top_versions = _db.top_versions_for_tech(tech_key, limit=10)
        trend = _db.tech_trend(tech_key, days=30)
        sample = _db.search_tech(tech_key, limit=5)
        # pick a representative detected_version if present
        detected_version = top_versions[0]['version'] if top_versions else None
        out = {
            'tech_key': tech_key,
            'name': tech_key,
            'slug': tech_key,
            'categories': [],
            'detected_version': detected_version,
            'version_confidence': 0.0,
            'confidence': 0.0,
            'counts': {
                'total_sites': total,
                'last_30_days': sum(d['count'] for d in trend[-30:]) if trend else 0,
                'last_7_days': sum(d['count'] for d in trend[-7:]) if trend else 0
            },
            'top_versions': top_versions,
            'top_countries': [],
            'outdated': {'is_outdated': False},
            'confidence_breakdown': [],
            'sample_sites': [
                {
                    'domain': s['domain'],
                    'last_scan': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(s.get('last_seen') or time.time())),
                    'tech_count': 0,
                    'confidence': 0.0
                } for s in sample
            ],
            'last_updated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
        cache_set(key, out, ttl=120)
        return jsonify(out)
    except Exception as e:
        logging.getLogger('tech.api').exception('tech_meta error tech=%s err=%s', tech_key, e)
        return jsonify({'error': str(e)}), 500


@bp.route('/tech/<tech_key>/sites', methods=['GET'])
def tech_sites(tech_key: str):
    # Pagination params
    try:
        limit = int(request.args.get('limit') or 20)
    except Exception:
        limit = 20
    try:
        offset = int(request.args.get('offset') or 0)
    except Exception:
        offset = 0
    sort = request.args.get('sort') or 'recent'
    # caching first page
    cache_key = f'tech:{tech_key}:sites:limit={limit}:offset={offset}:sort={sort}'
    if offset == 0:
        cached = cache_get(cache_key)
        if cached:
            return jsonify(cached)
    try:
        rows = _db.search_tech(tech_key, limit=limit, offset=offset, sort_key='last_seen', sort_dir='desc')
        total = _db.count_search_tech(tech_key)
        sites = []
        for r in rows:
            sites.append({
                'domain': r['domain'],
                'last_scan': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(r.get('last_seen') or time.time())),
                'tech_count': 0,
                'confidence': 0.0,
                'summary': [],
                'detected_version': r.get('version'),
                'evidence_sample': {}
            })
        out = {
            'tech_key': tech_key,
            'limit': limit,
            'offset': offset,
            'total': total,
            'sites': sites
        }
        if offset == 0:
            cache_set(cache_key, out, ttl=30)
        return jsonify(out)
    except Exception as e:
        logging.getLogger('tech.api').exception('tech_sites error tech=%s err=%s', tech_key, e)
        return jsonify({'error': str(e)}), 500


@bp.route('/tech/<tech_key>/sites.csv', methods=['GET'])
def tech_sites_csv(tech_key: str):
    # Export limited CSV
    try:
        limit = min(2000, int(request.args.get('limit') or 500))
    except Exception:
        limit = 500
    rows = _db.search_tech(tech_key, limit=limit, offset=0, sort_key='last_seen', sort_dir='desc')
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['domain','last_scan','version','categories'])
    for r in rows:
        writer.writerow([r['domain'], time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(r.get('last_seen') or time.time())), r.get('version') or '', '|'.join(r.get('categories') or [])])
    csv_data = output.getvalue()
    return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename=tech_{tech_key}_sites.csv'})


@bp.route('/domain/<domain>/evidence_for_tech', methods=['GET'])
def domain_evidence_for_tech(domain: str):
    tech = request.args.get('tech')
    if not tech:
        return jsonify({'error':'missing tech param'}), 400
    try:
        # For now, try latest raw and filter evidence heuristically from _db.get_latest_scan_raw
        raw = _db.get_latest_scan_raw(domain)
        if not raw or not raw.get('raw'):
            return jsonify({'domain': domain, 'tech': tech, 'evidence': []})
        evidence = []
        # Attempt to extract some evidence fields if present
        r = raw.get('raw')
        if isinstance(r, dict):
            # headers
            headers = r.get('headers') or {}
            for k, v in headers.items():
                if tech.lower() in str(v).lower():
                    evidence.append({'type':'header','value': f"{k}: {v}", 'location':'headers'})
            # scripts
            scripts = (r.get('extras') or {}).get('scripts') or []
            for s in scripts:
                if tech.lower() in str(s).lower():
                    evidence.append({'type':'script','value': s, 'location':'scripts'})
        return jsonify({'domain': domain, 'tech': tech, 'evidence': evidence})
    except Exception as e:
        logging.getLogger('tech.api').exception('domain_evidence error domain=%s tech=%s err=%s', domain, tech, e)
        return jsonify({'error': str(e)}), 500


@bp.route('/tech/<tech_key>/invalidate_cache', methods=['POST'])
def tech_invalidate(tech_key: str):
    # Simple admin operation
    if os.environ.get('TECHSCAN_ADMIN_MODE','0') != '1':
        return jsonify({'error':'forbidden'}), 403
    cache_invalidate(f'tech:{tech_key}')
    return jsonify({'ok': True})
from flask import Blueprint, request, jsonify, current_app, Response
import json, logging, time, re
from .. import db as _db
from .. import tech_cache
from ..evidence_utils import (
    infer_snippet as _infer_snippet,
    normalize_evidence_entry as _normalize_evidence_entry,
    pattern_to_evidence as _pattern_to_evidence,
    extras_fallback_evidence as _extras_fallback_evidence,
    extract_header_maps,
    collect_header_evidence,
    dedupe_evidence_entries,
)

bp = Blueprint('tech', __name__, url_prefix='/api')

LOGGER = logging.getLogger('techscan.tech')


def _tokenise_terms(names):
    tokens: set[str] = set()
    for name in names:
        if not name or not isinstance(name, str):
            continue
        lowered = name.lower()
        tokens.add(lowered)
        tokens.add(re.sub(r'[^a-z0-9]+', '', lowered))
        tokens.add(lowered.replace(' ', ''))
    return {t for t in tokens if t}


def _iter_text_sources(raw_blob):
    if not isinstance(raw_blob, dict):
        return []
    sources: list[tuple[str, str]] = []
    for key in ('html', 'body', 'text', 'content'):  # primary payloads
        val = raw_blob.get(key)
        if isinstance(val, str) and val.strip():
            sources.append((key, val))
    extras = raw_blob.get('extras')
    if isinstance(extras, dict):
        for key in ('errors', 'warnings', 'logs', 'messages', 'details'):
            val = extras.get(key)
            if isinstance(val, str) and val.strip():
                sources.append((f'extras.{key}', val))
            elif isinstance(val, list):
                for idx, item in enumerate(val):
                    if isinstance(item, str) and item.strip():
                        sources.append((f'extras.{key}[{idx}]', item))
    responses = raw_blob.get('responses') or raw_blob.get('httpResponses')
    if isinstance(responses, list):
        for idx, resp in enumerate(responses):
            if not isinstance(resp, dict):
                continue
            body = resp.get('body') or resp.get('text') or resp.get('content')
            if isinstance(body, str) and body.strip():
                sources.append((f'responses[{idx}].body', body))
    return sources


def _textual_evidence_from_blob(tech_name: str | None, aliases: list[str] | None, raw_blob: dict, limit: int = 4):
    tokens = _tokenise_terms([tech_name, *(aliases or [])])
    if not tokens:
        return []
    entries: list[dict] = []
    for source, text in _iter_text_sources(raw_blob):
        lowered = text.lower()
        for token in tokens:
            idx = lowered.find(token)
            if idx == -1:
                continue
            start = max(0, idx - 60)
            end = min(len(text), idx + 90)
            snippet = text[start:end].strip().replace('\n', ' ')
            entries.append({
                'kind': 'text',
                'source': source,
                'pattern': token,
                'match': snippet
            })
            if len(entries) >= limit:
                return entries
    return entries


def _ts_to_iso(ts):
    try:
        import datetime
        # Use timezone-aware UTC timestamp to avoid deprecated utcfromtimestamp
        return datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).isoformat()
    except Exception:
        return None


def _coerce_object(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {}
    return {}


def _coerce_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            data = json.loads(value)
            return data if isinstance(data, list) else []
        except Exception:
            return []
    if isinstance(value, dict):
        return [value]
    return []



_EVIDENCE_KEYS = {'url','urls','snippet','value','match','pattern','headers','matches','note','key'}


def _entry_has_meaningful_details(entry) -> bool:
    if not isinstance(entry, dict):
        return False
    for key in _EVIDENCE_KEYS:
        if key not in entry:
            continue
        val = entry.get(key)
        if val is None:
            continue
        if isinstance(val, (list, dict)):
            if val:
                return True
        else:
            text = str(val)
            if text.strip():
                return True
    return False


def _filter_meaningful_evidence(entries):
    if not entries:
        return []
    filtered = []
    for entry in entries:
        if _entry_has_meaningful_details(entry):
            filtered.append(entry)
    return filtered



@bp.route('/tech/<tech_key>', methods=['GET'])
def tech_meta(tech_key):
    cache_key = f'tech:{tech_key}:meta'
    cached = tech_cache.get(cache_key)
    if cached:
        try:
            return jsonify(json.loads(cached))
        except Exception:
            LOGGER.debug('failed to decode cached tech_meta payload for key=%s', cache_key, exc_info=True)
    # Build aggregated response
    total = _db.count_search_tech(tech=tech_key)
    top_versions = _db.top_versions_for_tech(tech_key, limit=10)
    trend = _db.tech_trend(tech_key, days=30)
    sample = _db.search_tech(tech=tech_key, limit=5, offset=0)
    # derive simple confidence heuristics from sample (if present)
    confidence = None
    version_confidence = None
    if sample:
        # average per-domain confidence if present in sample 'confidence' field
        vals = [s.get('confidence') for s in sample if s.get('confidence') is not None]
        if vals:
            confidence = sum(vals) / len(vals)
    out = {
        'tech_key': tech_key,
        'name': tech_key,
        'slug': tech_key,
        'categories': [],
        'detected_version': top_versions[0]['version'] if top_versions else None,
        'version_confidence': version_confidence,
        'confidence': confidence,
        'counts': {
            'total_sites': total,
            'last_30_days': sum(d.get('count',0) for d in trend[-30:]) if trend else 0,
            'last_7_days': sum(d.get('count',0) for d in trend[-7:]) if trend else 0
        },
        'top_versions': top_versions,
        'top_countries': [],
        'outdated': {'is_outdated': False},
        'confidence_breakdown': [],
        'sample_sites': sample,
        'trend': trend,
        'last_updated': _ts_to_iso(time.time())
    }
    try:
        tech_cache.set(cache_key, json.dumps(out), ttl=120)
    except Exception:
        LOGGER.debug('failed to set cache for key=%s', cache_key, exc_info=True)
    return jsonify(out)


@bp.route('/techs/<tech_key>', methods=['GET'])
def tech_detail_short(tech_key):
    """Compatibility / drilldown endpoint used by the UI.
    Returns a compact payload with domains list, basic meta and a simple history.
    """
    cache_key = f'tech:{tech_key}:detail'
    cached = tech_cache.get(cache_key)
    if cached:
        try:
            return jsonify(json.loads(cached))
        except Exception:
            LOGGER.debug('failed to decode cached detail for key=%s', cache_key, exc_info=True)

    # Aggregate basic info
    total = _db.count_search_tech(tech=tech_key)
    trend = _db.tech_trend(tech_key, days=90) or []
    # fetch a reasonable sample of sites (for drilldown list)
    sites = _db.search_tech(tech=tech_key, limit=500, offset=0, sort_key='last_seen', sort_dir='desc') or []
    domains = [s.get('domain') for s in sites if s.get('domain')]

    # derive first/last seen (best-effort using site last_seen)
    ts = [s.get('last_seen') for s in sites if s.get('last_seen')]
    first_seen = min(ts) if ts else None
    last_seen = max(ts) if ts else None

    # Normalise trend into {t: label, v: value} entries for the frontend
    history = []
    for item in trend:
        if isinstance(item, dict):
            t = item.get('t') or item.get('label') or item.get('time')
            v = item.get('count') or item.get('v') or item.get('value') or 0
            history.append({'t': t, 'v': v})
        else:
            # fallback if trend is a tuple/list
            try:
                history.append({'t': item[0], 'v': item[1]})
            except Exception:
                continue

    out = {
        'tech': tech_key,
        'category': None,
        'version': None,
        'count': total,
        'first_seen': first_seen,
        'last_seen': last_seen,
        'domains': domains,
        'history': history,
    }

    try:
        tech_cache.set(cache_key, json.dumps(out), ttl=60)
    except Exception:
        LOGGER.debug('failed to set cache for key=%s', cache_key, exc_info=True)
    return jsonify(out)


@bp.route('/category/<category>/top', methods=['GET'])
def category_top(category: str):
    """Return top technologies for a given category (name match, case-insensitive).
    This is used by the frontend category carousel to fetch per-category top techs when
    the aggregated /api/stats payload doesn't include detailed mappings.
    """
    try:
        try:
            limit = int(request.args.get('limit') or 15)
        except Exception:
            limit = 15
        # If DB disabled, aggregate from the lightweight search_tech mirror
        if getattr(_db, '_DB_DISABLED', False):
            rows = _db.search_tech(category=category, limit=2000) or []
            counts = {}
            for r in rows:
                name = r.get('tech_name')
                if not name:
                    continue
                counts[name] = counts.get(name, 0) + 1
            items = sorted([{'tech': k, 'count': v} for k, v in counts.items()], key=lambda x: x['count'], reverse=True)[:limit]
            return jsonify(items)

        # Use SQL aggregation for efficiency
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('''SELECT tech_name, COUNT(*) AS c FROM domain_techs
                               WHERE (','||LOWER(categories)||',') LIKE %s
                               GROUP BY tech_name ORDER BY c DESC LIMIT %s''', (f'%,{category.lower()},%', limit))
                rows = cur.fetchall()
                out = [{'tech': r[0], 'count': r[1]} for r in rows]
        return jsonify(out)
    except Exception as e:
        logging.getLogger('tech.api').exception('category_top error category=%s err=%s', category, e)
        return jsonify({'error': str(e)}), 500


@bp.route('/tech/<tech_key>/sites', methods=['GET'])
def tech_sites(tech_key):
    try:
        limit = int(request.args.get('limit') or 20)
    except ValueError:
        limit = 20
    try:
        offset = int(request.args.get('offset') or 0)
    except ValueError:
        offset = 0
    sort = request.args.get('sort') or 'recent'
    cache_key = f'tech:{tech_key}:sites:limit={limit}:offset={offset}:sort={sort}'
    cached = tech_cache.get(cache_key)
    if cached:
        try:
            return jsonify(json.loads(cached))
        except Exception:
            pass
    sites = _db.search_tech(tech=tech_key, limit=limit, offset=offset, sort_key='last_seen', sort_dir='desc')
    total = _db.count_search_tech(tech=tech_key)
    out = {
        'tech_key': tech_key,
        'limit': limit,
        'offset': offset,
        'total': total,
        'sites': []
    }
    for s in sites:
        out['sites'].append({
            'domain': s.get('domain'),
            'last_scan': _ts_to_iso(s.get('last_seen')),
            'tech_count': s.get('tech_count') if s.get('tech_count') is not None else None,
            'confidence': s.get('confidence') if s.get('confidence') is not None else None,
            'summary': s.get('summary') or [],
            'detected_version': s.get('version')
        })
    try:
        tech_cache.set(cache_key, json.dumps(out), ttl=30)
    except Exception:
        pass
    return jsonify(out)


@bp.route('/tech/<tech_key>/sites.csv', methods=['GET'])
def tech_sites_csv(tech_key):
    try:
        limit = min(2000, int(request.args.get('limit') or 500))
    except ValueError:
        limit = 500
    sites = _db.search_tech(tech=tech_key, limit=limit, offset=0, sort_key='last_seen', sort_dir='desc')
    import io, csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['domain','last_scan','detected_version','categories'])
    for s in sites:
        writer.writerow([s.get('domain'), _ts_to_iso(s.get('last_seen')), s.get('version'), ';'.join(s.get('categories') or [])])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename=tech_{tech_key}_sites.csv'})


@bp.route('/tech/<tech_key>/invalidate_cache', methods=['POST'])
def invalidate_cache(tech_key):
    # Admin-only in production; here we perform best-effort invalidation
    prefix = f'tech:{tech_key}'
    tech_cache.invalidate(prefix)
    return jsonify({'ok': True, 'invalidated': prefix})


@bp.route('/domain/<domain>/evidence_for_tech', methods=['GET'])
def domain_evidence_for_tech(domain):
    tech = request.args.get('tech')
    if not tech:
        return jsonify({'error': 'missing tech param'}), 400
    raw = _db.get_latest_scan_raw(domain)
    if not raw:
        return jsonify({'domain': domain, 'tech': tech, 'evidence': []})
    tech_entries = _coerce_list(raw.get('technologies'))
    target = None
    for entry in tech_entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get('name')
        if name and name.lower() == tech.lower():
            target = entry
            break
    if not target:
        return jsonify({'domain': domain, 'tech': tech, 'evidence': []})

    evidence_payload: list[dict] = []
    for ev in _coerce_list(target.get('evidence')):
        normalized = _normalize_evidence_entry(ev)
        if normalized:
            evidence_payload.append(normalized)
    evidence_payload = _filter_meaningful_evidence(evidence_payload)

    raw_blob = _coerce_object(raw.get('raw'))
    hint_meta = raw_blob.get('_tiered_hint_meta') if isinstance(raw_blob, dict) else None
    patterns_map = _coerce_object(raw_blob.get('patterns')) if raw_blob else {}
    if patterns_map:
        candidates = []
        if target.get('name'):
            candidates.append(target['name'])
        if tech:
            candidates.append(tech)
        if isinstance(target.get('aliases'), list):
            candidates.extend([alias for alias in target['aliases'] if isinstance(alias, str)])
        seen_keys = {c.lower() for c in candidates if isinstance(c, str)}
        if seen_keys:
            for key, entries in patterns_map.items():
                if key.lower() not in seen_keys:
                    continue
                for item in _coerce_list(entries):
                    normalized = _pattern_to_evidence(item if isinstance(item, dict) else {})
                    if not normalized:
                        continue
                    normalized = _normalize_evidence_entry(normalized)
                    if normalized:
                        evidence_payload.append(normalized)
                # avoid scanning other keys once matched
                break
    evidence_payload = _filter_meaningful_evidence(evidence_payload)

    if raw_blob:
        header_maps = extract_header_maps(raw_blob)
        if header_maps:
            aliases = target.get('aliases') if isinstance(target.get('aliases'), list) else []
            header_entries = collect_header_evidence(target.get('name') or tech, header_maps, aliases)
            for entry in header_entries:
                normalized = _normalize_evidence_entry(entry)
                if normalized:
                    evidence_payload.append(normalized)
    evidence_payload = _filter_meaningful_evidence(evidence_payload)

    if raw_blob and not evidence_payload:
        extras = raw_blob.get('extras') if isinstance(raw_blob, dict) else {}
        fallback = _extras_fallback_evidence(tech, extras)
        for entry in fallback:
            normalized = _normalize_evidence_entry(entry)
            if normalized:
                evidence_payload.append(normalized)
        evidence_payload = _filter_meaningful_evidence(evidence_payload)

    if raw_blob and not evidence_payload:
        alias_values = target.get('aliases') if isinstance(target.get('aliases'), list) else []
        text_matches = _textual_evidence_from_blob(target.get('name') or tech, alias_values, raw_blob)
        for entry in text_matches:
            normalized = _normalize_evidence_entry(entry)
            if normalized:
                evidence_payload.append(normalized)
        evidence_payload = _filter_meaningful_evidence(evidence_payload)

    evidence_payload = dedupe_evidence_entries(evidence_payload)

    finished_at = raw.get('finished_at')
    try:
        finished_at = float(finished_at) if finished_at is not None else None
    except Exception:
        finished_at = None

    response = {
        'domain': domain,
        'tech': target.get('name') or tech,
        'evidence': evidence_payload,
        'version': target.get('version'),
        'confidence': target.get('confidence')
    }
    if finished_at is not None:
        response['finished_at'] = finished_at
    if hint_meta:
        response['hint_meta'] = hint_meta
    return jsonify(response)
