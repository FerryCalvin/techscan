import os
import time
import json
import logging
import threading
from urllib.parse import quote as _urlquote
from contextlib import contextmanager
import psycopg
try:
    # psycopg_pool provides a robust connection pool for psycopg (psycopg3)
    from psycopg_pool import ConnectionPool as _PsycopgConnectionPool
except Exception as pool_import_err:
    logging.getLogger('techscan.db').debug('psycopg_pool import failed err=%s', pool_import_err, exc_info=True)
    _PsycopgConnectionPool = None

_LOG = logging.getLogger('techscan.db')

# In-memory mirror storage for domain techs is always available (even when DB enabled)
_MEM_DOMAIN_TECHS: dict = {}

_DB_DISABLED_ENV = os.environ.get('TECHSCAN_DISABLE_DB', '0') == '1'

def _is_disabled_runtime() -> bool:
    """Runtime check so tests can flip TECHSCAN_DISABLE_DB after import.
    This complements the import-time flag and avoids opening connections when
    a test sets the env var with monkeypatch.
    """
    try:
        return os.environ.get('TECHSCAN_DISABLE_DB', '0') == '1'
    except Exception:
        return False

_explicit_url = os.environ.get('TECHSCAN_DB_URL')
if _explicit_url:
    DB_URL = _explicit_url
elif not _DB_DISABLED_ENV:
    # Build from individual pieces when DB enabled; all secrets must come from env
    db_host = os.environ.get('TECHSCAN_DB_HOST', '127.0.0.1')
    db_port = os.environ.get('TECHSCAN_DB_PORT', '5432')
    db_name = os.environ.get('TECHSCAN_DB_NAME', 'techscan')
    db_user = os.environ.get('TECHSCAN_DB_USER', 'postgres')
    db_pass = os.environ.get('TECHSCAN_DB_PASSWORD')
    if not db_pass:
        if os.environ.get('TECHSCAN_ALLOW_EMPTY_DB_PASSWORD', '0') == '1':
            _LOG.warning(
                'TECHSCAN_DB_PASSWORD is empty (allowed by '
                'TECHSCAN_ALLOW_EMPTY_DB_PASSWORD=1). Use only for local development.')
            db_pass = ''  # nosec B105: explicit empty password permitted only for local development override
        else:
            raise RuntimeError(
                'TECHSCAN_DB_PASSWORD is not set. '
                'Define TECHSCAN_DB_URL or set TECHSCAN_DB_PASSWORD via environment.')
    # URL-encode password to safely handle special characters (@, #, :)
    enc_pass = _urlquote(db_pass, safe='')
    DB_URL = f'postgresql://{db_user}:{enc_pass}@{db_host}:{db_port}/{db_name}'
else:
    DB_URL = ''

# Allow disabling DB usage completely for test/perf runs without a live Postgres
if _DB_DISABLED_ENV:
    _LOG.warning('TECHSCAN_DISABLE_DB=1 -> database persistence DISABLED (using stubs)')
    # Ensure in-memory mirror storage is defined before stubs use it
    _MEM_DOMAIN_TECHS = {}
    def ensure_schema():  # type: ignore
        return
    def save_scan(result: dict, from_cache: bool, timeout_used: int):  # type: ignore
        # In-memory minimal persistence to satisfy tests relying on domain lookup when DB disabled
        _mem_domain = result.get('domain')
        techs = result.get('technologies') or []
        now = result.get('finished_at') or result.get('timestamp') or time.time()
        for t in techs:
            name = t.get('name')
            if not name:
                continue
            key = (_mem_domain, name, t.get('version'))
            entry = _MEM_DOMAIN_TECHS.get(key)
            cats = ','.join(sorted(t.get('categories') or [])) if t.get('categories') else None
            if entry:
                entry['last_seen'] = now
                # merge categories if new present
                if cats and not entry.get('categories'):
                    entry['categories'] = cats
            else:
                _MEM_DOMAIN_TECHS[key] = {
                    'domain': _mem_domain,
                    'tech_name': name,
                    'version': t.get('version'),
                    'categories': cats,
                    'first_seen': now,
                    'last_seen': now
                }
    def search_tech(tech: str | None = None, category: str | None = None, version: str | None = None, limit: int = 200):  # type: ignore
        return []
    def history(domain: str, limit: int = 20):  # type: ignore
        return []
    def get_domain_techs(domain: str):  # type: ignore
        out = []
        for (d, name, version), rec in list(_MEM_DOMAIN_TECHS.items()):
            if d != domain:
                continue
            cats = rec.get('categories')
            out.append({
                'tech_name': name,
                'version': version,
                'categories': cats.split(',') if cats else [],
                'first_seen': rec['first_seen'],
                'last_seen': rec['last_seen']
            })
        # order by last_seen desc like real impl
        out.sort(key=lambda r: r['last_seen'], reverse=True)
        return out
    # Short-circuit further real definitions
    _DB_DISABLED = True
    # simple in-memory storage for domain techs (already defined at module top)
else:
    _DB_DISABLED = False

SCHEMA_STATEMENTS = [
    # scans table stores each scan invocation (cache hits recorded too for history visibility)
    '''CREATE TABLE IF NOT EXISTS scans (
        id BIGSERIAL PRIMARY KEY,
        domain TEXT NOT NULL,
        mode TEXT NOT NULL,
        started_at TIMESTAMPTZ NOT NULL,
        finished_at TIMESTAMPTZ NOT NULL,
        duration_ms INTEGER NOT NULL,
        from_cache BOOLEAN NOT NULL DEFAULT FALSE,
        adaptive_timeout BOOLEAN NOT NULL DEFAULT FALSE,
        retries INTEGER NOT NULL DEFAULT 0,
        timeout_used INTEGER NOT NULL DEFAULT 0,
        tech_count INTEGER,
        versions_count INTEGER,
        technologies_json JSONB NOT NULL,
        categories_json JSONB NOT NULL,
        raw_json JSONB,
        payload_bytes BIGINT,
        error TEXT
    );''',
    'CREATE INDEX IF NOT EXISTS idx_scans_domain_time ON scans(domain, finished_at DESC);',
    # domain_techs maintains current observed technology/version per domain
    '''CREATE TABLE IF NOT EXISTS domain_techs (
        id BIGSERIAL PRIMARY KEY,
        domain TEXT NOT NULL,
        tech_name TEXT NOT NULL,
        version TEXT,
        categories TEXT,
        first_seen TIMESTAMPTZ NOT NULL,
        last_seen TIMESTAMPTZ NOT NULL
    );''',
    'CREATE INDEX IF NOT EXISTS idx_domain_techs_tech ON domain_techs(tech_name);',
    'CREATE INDEX IF NOT EXISTS idx_domain_techs_last_seen ON domain_techs(last_seen DESC);',
    # Additional indices for new features / filters
    'CREATE INDEX IF NOT EXISTS idx_domain_techs_first_seen ON domain_techs(first_seen);',
    # Lowercase index to accelerate exact tech name lookups with LOWER(tech_name)=LOWER($1)
    'CREATE INDEX IF NOT EXISTS idx_domain_techs_lower_name ON domain_techs(LOWER(tech_name));',
    # Legacy functional unique index (kept if already exists).
    # New approach uses update-then-insert so we only need a normal index.
    'CREATE INDEX IF NOT EXISTS idx_domain_techs_dtv ON domain_techs(domain, tech_name, version);',
    # scan_jobs table for background job queue tracking
    '''CREATE TABLE IF NOT EXISTS scan_jobs (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        domains JSONB NOT NULL,
        options JSONB,
        progress INTEGER DEFAULT 0,
        total INTEGER DEFAULT 1,
        completed INTEGER DEFAULT 0,
        result JSONB,
        results JSONB,
        error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        finished_at TIMESTAMPTZ
    );''',
    'CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);',
    'CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at DESC);',
    # API Keys table for rate limiting
    '''CREATE TABLE IF NOT EXISTS api_keys (
        id SERIAL PRIMARY KEY,
        key_hash TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        rate_limit TEXT DEFAULT '1000 per hour',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_used_at TIMESTAMPTZ,
        request_count BIGINT DEFAULT 0
    );''',
    'CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);',
]

_pool: dict = {}
_count_cache: dict = {}
_COUNT_CACHE_TTL = 60  # seconds
_COUNT_CACHE_MAX = 500

# Connection pool (initialized when DB enabled)
DB_POOL_SIZE = int(os.environ.get('TECHSCAN_DB_POOL_SIZE', '10'))
_POOL = None

if os.environ.get('TECHSCAN_DISABLE_DB','0') != '1':
    # Try to create a psycopg_pool-backed pool if available
    if _PsycopgConnectionPool is not None:
        try:
            _POOL = _PsycopgConnectionPool(conninfo=DB_URL, max_size=DB_POOL_SIZE)
            logging.getLogger('techscan.db').info('Initialized psycopg connection pool size=%s', DB_POOL_SIZE)
        except Exception as e:
            logging.getLogger('techscan.db').warning(
                'Failed to initialize psycopg_pool: %s; '
                'will fall back to single-connection-per-use', e)
            _POOL = None
    else:
        logging.getLogger('techscan.db').info(
            'psycopg_pool not available; falling back to creating short-lived connections '
            '(set TECHSCAN_DB_POOL_SIZE and install psycopg_pool for pooling)')


def pool_stats():
    """Return lightweight pool statistics for monitoring.

    If a psycopg_pool ConnectionPool instance is initialized this
    returns a dict with basic counts (max_size, num_connections,
    available, in_use, timestamp). If no pool is present returns
    {'pool': None}.
    """
    try:
        if _POOL is not None:
            # psycopg_pool exposes .max_size and some runtime internals
            stats = {
                'max_size': getattr(_POOL, 'max_size', None),
                # num_connections: how many connections the pool has allocated
                'num_connections': getattr(_POOL, 'num_connections', None),
                # available: how many are currently available for checkout
                'available': getattr(_POOL, 'available', None),
                'in_use': None,
                'timestamp': time.time()
            }
            try:
                if stats['max_size'] is not None and stats['available'] is not None:
                    stats['in_use'] = max(0, int(stats['max_size']) - int(stats['available']))
            except Exception:
                stats['in_use'] = None
            return stats
    except Exception:
        # Defensive: never raise from telemetry helper
        logging.getLogger('techscan.db').exception('pool_stats helper failed')
    return {'pool': None}


def _pool_monitor_check():
    """Internal check used by optional background monitor.

    Returns tuple (ok: bool, stats: dict). Logs a warning when pool appears
    saturated.
    """
    st = pool_stats()
    ok = True
    try:
        if st and st.get('max_size') and st.get('in_use') is not None:
            if st['in_use'] >= st['max_size']:
                logging.getLogger('techscan.db').warning(
                    'DB pool at full capacity (%d/%d)', st['in_use'], st['max_size'])
                ok = False
    except Exception:
        pass
    return ok, st


# Background monitor thread controls (optional). When enabled via env var
# TECHSCAN_DB_POOL_MONITOR=1 the monitor thread will periodically log pool
# utilization and warn when saturated. Use start_pool_monitor()/stop_pool_monitor()
# to control lifecycle from application startup code.
_POOL_MONITOR_THREAD = None
_POOL_MONITOR_STOP = threading.Event()


def _pool_monitor_loop(interval_s: float = 10.0):
    log = logging.getLogger('techscan.db')
    while not _POOL_MONITOR_STOP.wait(interval_s):
        try:
            ok, stats = _pool_monitor_check()
            # Log at DEBUG normally, WARNING already emitted by _pool_monitor_check
            log.debug('db_pool monitor stats=%s ok=%s', stats, ok)
        except Exception:
            log.exception('unexpected error in db_pool monitor loop')


def start_pool_monitor(interval_s: float = 10.0):
    """Start the background pool monitor thread (idempotent).

    Call from application startup when you want lightweight telemetry/logging
    of the psycopg_pool usage. The thread is daemonic so it won't block shutdown.
    """
    global _POOL_MONITOR_THREAD, _POOL_MONITOR_STOP
    if _POOL_MONITOR_THREAD and _POOL_MONITOR_THREAD.is_alive():
        return
    _POOL_MONITOR_STOP.clear()
    interval = float(os.environ.get('TECHSCAN_DB_POOL_MONITOR_INTERVAL', '10'))
    t = threading.Thread(
        target=_pool_monitor_loop, args=(interval,), daemon=True, name='db-pool-monitor')
    _POOL_MONITOR_THREAD = t
    t.start()


def stop_pool_monitor():
    """Stop the background pool monitor thread if running."""
    global _POOL_MONITOR_THREAD, _POOL_MONITOR_STOP
    _POOL_MONITOR_STOP.set()
    if _POOL_MONITOR_THREAD:
        try:
            _POOL_MONITOR_THREAD.join(timeout=2.0)
        except Exception:
            pass
    _POOL_MONITOR_THREAD = None


@contextmanager
def get_conn():
    # Prefer using an established connection pool if available. Otherwise
    # create a short-lived connection per use (safer when clients may leak).
    if _POOL is not None:
        # psycopg_pool ConnectionPool yields a connection context
        with _POOL.connection() as conn:
            yield conn
    else:
        # Fallback: create a new connection and close it when done
        conn = psycopg.connect(DB_URL, autocommit=False)
        try:
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass


@contextmanager
def get_db():
    """Backwards-compatible alias returning a managed connection context."""
    with get_conn() as conn:
        yield conn

def ensure_schema():
    if _DB_DISABLED or _is_disabled_runtime():
        return
    with get_conn() as conn:
        with conn.cursor() as cur:
            for stmt in SCHEMA_STATEMENTS:
                cur.execute(stmt)
            # Add columns tech_count / versions_count if upgrading existing table
            cur.execute("""SELECT column_name FROM information_schema.columns WHERE table_name='scans'""")
            existing = {r[0] for r in cur.fetchall()}
            alter_needed = []
            if 'tech_count' not in existing:
                alter_needed.append('ADD COLUMN tech_count INTEGER')
            if 'versions_count' not in existing:
                alter_needed.append('ADD COLUMN versions_count INTEGER')
            if 'payload_bytes' not in existing:
                alter_needed.append('ADD COLUMN payload_bytes BIGINT')
            if alter_needed:
                cur.execute('ALTER TABLE scans ' + ', '.join(alter_needed))
        conn.commit()
    logging.getLogger('techscan.db').info('schema ensured')

def save_scan(result: dict, from_cache: bool, timeout_used: int):
    """Persist single scan result.

    result expects keys: domain, scan_mode, duration, technologies, categories,
    timestamp, (optional) adaptive_timeout, retries, raw
    """
    # If disabled at import-time or runtime, only mirror to in-memory store
    if _DB_DISABLED or _is_disabled_runtime():
        technologies = result.get('technologies') or []
        finished_at = result.get('finished_at') or result.get('timestamp') or time.time()
        for tech in technologies:
            name = tech.get('name')
            if not name:
                continue
            version = tech.get('version')
            cats = ','.join(sorted(tech.get('categories') or [])) if tech.get('categories') else None
            key = (result.get('domain'), name, version)
            existing = _MEM_DOMAIN_TECHS.get(key)
            if existing:
                existing['last_seen'] = finished_at
                if cats and not existing.get('categories'):
                    existing['categories'] = cats
            else:
                _MEM_DOMAIN_TECHS[key] = {
                    'domain': result.get('domain'),
                    'tech_name': name,
                    'version': version,
                    'categories': cats,
                    'first_seen': finished_at,
                    'last_seen': finished_at
                }
        return
    def _coerce_epoch(value, fallback):
        try:
            if value is None:
                return float(fallback)
            num = float(value)
            if num <= 0 and fallback is not None:
                return float(fallback)
            return num
        except Exception:
            return float(fallback if fallback is not None else time.time())

    base_now = time.time()
    started_at = _coerce_epoch(result.get('started_at') or result.get('_started_at') or result.get('timestamp'), base_now)
    finished_at = _coerce_epoch(result.get('finished_at') or result.get('_finished_at') or result.get('completed_at') or result.get('timestamp'), base_now)
    if finished_at < started_at:
        # Guard against inverted timestamps from upstream rounding issues.
        finished_at = started_at
    if not started_at:
        # Fallback: derive started_at from finished_at - duration if possible, else use finished_at
        try:
            started_at = float(finished_at) - (float(result.get('duration') or 0))
        except Exception:
            started_at = finished_at
    # epoch -> timestamptz via to_timestamp in parameterization OR convert in python via psycopg adaptation
    technologies = result.get('technologies') or []
    categories = result.get('categories') or {}
    raw = result.get('raw')
    hint_meta = None
    try:
        tiered_block = result.get('tiered') if isinstance(result, dict) else None
        if isinstance(tiered_block, dict):
            hint_meta = tiered_block.get('hint_meta') if isinstance(tiered_block.get('hint_meta'), dict) else None
    except Exception:
        hint_meta = None
    if hint_meta:
        if isinstance(raw, dict):
            raw = {**raw, '_tiered_hint_meta': hint_meta}
        else:
            payload = {'_tiered_hint_meta': hint_meta}
            if raw is not None:
                payload['_raw_payload'] = raw
            raw = payload
    adaptive = bool(result.get('adaptive_timeout'))
    retries = int(result.get('retries') or 0)
    duration_seconds_raw = result.get('duration')
    try:
        duration_seconds = float(duration_seconds_raw)
    except Exception:
        duration_seconds = None

    def _derive_duration_seconds() -> float | None:
        if started_at is None or finished_at is None:
            return None
        try:
            delta = float(finished_at) - float(started_at)
            if delta <= 0:
                return None
            return delta
        except Exception:
            return None

    if duration_seconds is None or duration_seconds <= 0:
        derived = _derive_duration_seconds()
        if derived is not None:
            duration_seconds = derived

    if duration_seconds is None or duration_seconds < 0:
        duration_seconds = 0.0

    duration_ms = int(round(duration_seconds * 1000))
    if duration_seconds > 0 and duration_ms <= 0:
        duration_ms = 1
    duration_ms = max(duration_ms, 0)
    # derive counts
    tech_count = len(technologies)
    versions_count = sum(1 for t in technologies if t.get('version'))
    payload_bytes = result.get('payload_bytes')
    if payload_bytes is None:
        try:
            payload_bytes = len(json.dumps(result, ensure_ascii=False).encode('utf-8'))
        except Exception:
            logging.getLogger('techscan.db').debug('failed estimating payload size for domain=%s', result.get('domain'), exc_info=True)
            payload_bytes = None
    try:
        if payload_bytes is not None:
            payload_bytes = int(payload_bytes)
            if payload_bytes < 0:
                payload_bytes = None
    except Exception:
        logging.getLogger('techscan.db').debug('invalid payload size for domain=%s payload=%s', result.get('domain'), payload_bytes, exc_info=True)
        payload_bytes = None
    log = logging.getLogger('techscan.db')
    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                '''INSERT INTO scans(domain, mode, started_at, finished_at, duration_ms, from_cache, adaptive_timeout, retries, timeout_used, tech_count, versions_count, technologies_json, categories_json, raw_json, payload_bytes, error)
                   VALUES (%s, %s, to_timestamp(%s), to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s)''',
                (
                    result['domain'],
                    result.get('scan_mode','fast'),
                    started_at,
                    finished_at,
                    duration_ms,
                    from_cache,
                    adaptive,
                    retries,
                    timeout_used,
                    tech_count,
                    versions_count,
                    json.dumps(technologies, ensure_ascii=False),
                    json.dumps(categories, ensure_ascii=False),
                    json.dumps(raw, ensure_ascii=False) if raw is not None else None,
                    payload_bytes,
                    result.get('error')
                )
                )
            except Exception as ins_ex:
                log.warning('insert_scans_failed domain=%s mode=%s err=%s', result.get('domain'), result.get('scan_mode'), ins_ex)
                raise
            # Update-then-insert pattern (avoids reliance on unique constraint) with explicit NULL branch to prevent unknown type errors.
            now_epoch = finished_at
            def _prep_categories(raw):
                if not raw:
                    return None
                filtered = []
                for cat in raw:
                    text = str(cat).strip()
                    if text:
                        filtered.append(text)
                if not filtered:
                    return None
                # Sort for deterministic storage and join with commas
                return ','.join(sorted(dict.fromkeys(filtered)))

            for tech in technologies:
                name = tech.get('name')
                if not name:
                    continue
                version = tech.get('version')  # may be None
                cats = _prep_categories(tech.get('categories'))
                try:
                    if version is None:
                        # NULL version branch
                        cur.execute(
                            'UPDATE domain_techs SET last_seen=to_timestamp(%s), categories=COALESCE(%s, categories)\n'
                            ' WHERE domain=%s AND tech_name=%s AND version IS NULL',
                            (now_epoch, cats, result['domain'], name)
                        )
                        if cur.rowcount == 0:
                            cur.execute(
                                'INSERT INTO domain_techs(domain, tech_name, version, categories, first_seen, last_seen)\n'
                                ' VALUES (%s,%s,NULL,%s,to_timestamp(%s),to_timestamp(%s))',
                                (result['domain'], name, cats, now_epoch, now_epoch)
                            )
                    else:
                        cur.execute(
                            'UPDATE domain_techs SET last_seen=to_timestamp(%s), categories=COALESCE(%s, categories)\n'
                            ' WHERE domain=%s AND tech_name=%s AND version=%s',
                            (now_epoch, cats, result['domain'], name, version)
                        )
                        if cur.rowcount == 0:
                            cur.execute(
                                'INSERT INTO domain_techs(domain, tech_name, version, categories, first_seen, last_seen)\n'
                                ' VALUES (%s,%s,%s,%s,to_timestamp(%s),to_timestamp(%s))',
                                (result['domain'], name, version, cats, now_epoch, now_epoch)
                            )
                except Exception as up_ex:
                    # Roll back the failed statement to keep transaction usable for remaining techs.
                    try:
                        conn.rollback()
                        # Re-begin a new transaction scope for subsequent operations
                        # (psycopg3 starts implicit transaction on next statement)
                    except Exception:
                        pass
                    log.warning('upsert_domain_tech_failed domain=%s tech=%s version=%s err=%s', result['domain'], name, version, up_ex)
        conn.commit()
    log.debug('save_scan_ok domain=%s mode=%s tech_count=%s versions_with=%s cache=%s timeout_used=%s', result.get('domain'), result.get('scan_mode'), tech_count, versions_count, from_cache, timeout_used)
    # Invalidate count cache because domain_techs may have changed
    if _count_cache:
        _count_cache.clear()
    # Mirror into in-memory map for test code paths that call _db.get_domain_techs after save_scan without performing query
    now_epoch = finished_at
    for tech in technologies:
        name = tech.get('name')
        if not name:
            continue
        version = tech.get('version')
        cats = _prep_categories(tech.get('categories'))
        key = (result['domain'], name, version)
        existing = _MEM_DOMAIN_TECHS.get(key)
        if existing:
            existing['last_seen'] = now_epoch
            if cats and not existing.get('categories'):
                existing['categories'] = cats
        else:
            _MEM_DOMAIN_TECHS[key] = {
                'domain': result['domain'],
                'tech_name': name,
                'version': version,
                'categories': cats,
                'first_seen': now_epoch,
                'last_seen': now_epoch
            }

def _prepare_tech_filter(raw: str | None):
    if not isinstance(raw, str):
        return None, None, False
    term = raw.strip()
    if not term:
        return None, None, False
    use_like = len(term) >= 3
    return term, (f'%{term}%') if use_like else term, use_like


def search_tech(tech: str | None = None, category: str | None = None, version: str | None = None, limit: int = 200, offset: int = 0, new24: bool = False, sort_key: str | None = None, sort_dir: str = 'desc'):
    """Return aggregated domain/technology rows with version history list."""
    def _normalize_categories(raw: str | None) -> list[str]:
        if not raw:
            return []
        return [c for c in (raw.split(',') if isinstance(raw, str) else []) if c]

    def _finalize_rows(rows: list[dict]):
        for entry in rows:
            versions = entry.get('versions') or []
            if not entry.get('version') and versions:
                entry['version'] = versions[0]
        return rows

    tech_term, tech_param, tech_use_like = _prepare_tech_filter(tech)

    if _DB_DISABLED or _is_disabled_runtime():
        # Aggregate from in-memory mirror when DB is disabled
        mem = _MEM_DOMAIN_TECHS
        if not mem:
            return []
        tech_lower = tech_term.lower() if tech_term else None
        category_lower = category.lower() if isinstance(category, str) else None
        cutoff = time.time() - 24 * 3600 if new24 else None
        data: dict[tuple[str | None, str | None], dict] = {}

        def _match_tech(name: str | None) -> bool:
            if tech_lower is None:
                return True
            candidate = (name or '').lower()
            if tech_use_like:
                return tech_lower in candidate
            return candidate == tech_lower

        for (domain, name, ver), rec in list(mem.items()):
            if not _match_tech(name):
                continue
            if category_lower:
                cats_raw = (rec.get('categories') or '')
                if category_lower not in str(cats_raw).lower():
                    continue
            if version and ver != version:
                continue
            if cutoff is not None:
                try:
                    first_seen_val = rec.get('first_seen', 0) or 0
                    if first_seen_val < cutoff:
                        continue
                except Exception:
                    continue
            key = (domain, name)
            entry = data.get(key)
            cats_list = _normalize_categories(rec.get('categories'))
            if entry is None:
                entry = {
                    'domain': domain,
                    'tech_name': name,
                    'version': ver,
                    'versions': [],
                    'categories': cats_list,
                    'first_seen': rec.get('first_seen'),
                    'last_seen': rec.get('last_seen'),
                }
                data[key] = entry
            rec_first = rec.get('first_seen')
            rec_last = rec.get('last_seen')
            if rec_first is not None and (entry.get('first_seen') is None or rec_first < entry['first_seen']):
                entry['first_seen'] = rec_first
            if rec_last is not None and (entry.get('last_seen') is None or rec_last > entry['last_seen']):
                entry['last_seen'] = rec_last
            if ver and ver not in entry['versions']:
                entry['versions'].append(ver)
            if cats_list and not entry.get('categories'):
                entry['categories'] = cats_list
            if ver and not entry.get('version'):
                entry['version'] = ver
        results = list(data.values())
        if not results:
            return []
        sort_key_norm = (sort_key or 'last_seen').lower()
        reverse = (sort_dir or '').lower() != 'asc'
        key_map = {
            'domain': lambda r: r['domain'],
            'tech_name': lambda r: r['tech_name'],
            'version': lambda r: r.get('version') or '',
            'first_seen': lambda r: r.get('first_seen') or 0,
            'last_seen': lambda r: r.get('last_seen') or 0
        }
        keyfn = key_map.get(sort_key_norm, key_map['last_seen'])
        try:
            results.sort(key=keyfn, reverse=reverse)
        except Exception:
            # Fallback to last_seen ordering if custom sort fails
            results.sort(key=key_map['last_seen'], reverse=True)
        end = offset + max(0, limit)
        return _finalize_rows(results[offset:end])

    clauses = []
    params: list = []
    if tech_term:
        if tech_use_like:
            clauses.append('LOWER(tech_name) LIKE LOWER(%s)')
        else:
            clauses.append('LOWER(tech_name)=LOWER(%s)')
        params.append(tech_param)
    if category:
        clauses.append("(','||LOWER(categories)||',') LIKE %s")
        params.append(f'%,{category.lower()},%')
    if version:
        clauses.append('version = %s')
        params.append(version)
    if new24:
        clauses.append('first_seen >= NOW() - INTERVAL \'24 hours\'')
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    valid_cols = {
        'domain': 's.domain',
        'tech_name': 's.tech_name',
        'version': 'l.latest_version',
        'first_seen': 's.first_seen',
        'last_seen': 's.last_seen'
    }
    sort_col = valid_cols.get((sort_key or '').lower(), 's.last_seen')
    dir_sql = 'ASC' if (sort_dir or '').lower() == 'asc' else 'DESC'
    sql = f'''
        WITH filtered AS (
            SELECT domain, tech_name, version, categories, first_seen, last_seen
            FROM domain_techs
            {where}
        ),
        summary AS (
            SELECT domain, tech_name,
                   MIN(first_seen) AS first_seen,
                   MAX(last_seen) AS last_seen
            FROM filtered
            GROUP BY domain, tech_name
        ),
        latest AS (
            SELECT DISTINCT ON (domain, tech_name)
                   domain,
                   tech_name,
                   version AS latest_version,
                   categories AS latest_categories
            FROM filtered
            ORDER BY domain, tech_name, last_seen DESC
        )
        SELECT s.domain,
               s.tech_name,
               l.latest_categories,
               s.first_seen,
               s.last_seen,
               l.latest_version,
               COALESCE(
                 (
                   SELECT jsonb_agg(jsonb_build_object('version', vs.version, 'last_seen', vs.last_seen)
                                    ORDER BY vs.last_seen DESC)
                   FROM (
                     SELECT version, MAX(last_seen) AS last_seen
                     FROM filtered
                     WHERE filtered.domain = s.domain
                       AND filtered.tech_name = s.tech_name
                       AND version IS NOT NULL AND version <> ''
                     GROUP BY version
                   ) vs
                 ), '[]'::jsonb
               ) AS versions_json
        FROM summary s
        JOIN latest l ON l.domain = s.domain AND l.tech_name = s.tech_name
        ORDER BY {sort_col} {dir_sql}
        LIMIT %s OFFSET %s
    '''
    params.extend([limit, offset])
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            out = []
            for row in rows:
                first_seen = row[3]
                last_seen = row[4]
                versions_payload = row[6] or []
                versions = []
                try:
                    for entry in versions_payload:
                        if isinstance(entry, dict):
                            ver = entry.get('version')
                        else:
                            ver = entry[0] if isinstance(entry, (list, tuple)) else None
                        if ver and ver not in versions:
                            versions.append(ver)
                except Exception:
                    pass
                out.append({
                    'domain': row[0],
                    'tech_name': row[1],
                    'categories': _normalize_categories(row[2]),
                    'first_seen': first_seen.timestamp() if first_seen else None,
                    'last_seen': last_seen.timestamp() if last_seen else None,
                    'version': row[5],
                    'versions': versions,
                })
            return _finalize_rows(out)

def count_search_tech(tech: str | None = None, category: str | None = None, version: str | None = None, new24: bool = False):
    tech_term, tech_param, tech_use_like = _prepare_tech_filter(tech)
    if _DB_DISABLED or _is_disabled_runtime():
        seen = set()
        cutoff = time.time() - 24 * 3600
        for (d, name, ver), rec in list(globals().get('_MEM_DOMAIN_TECHS', {}).items()):
            if tech_term:
                candidate = (name or '').lower()
                target = tech_term.lower()
                if tech_use_like:
                    if target not in candidate:
                        continue
                else:
                    if candidate != target:
                        continue
            if category:
                cats = (rec.get('categories') or '').lower()
                if category.lower() not in cats:
                    continue
            if version and ver != version:
                continue
            if new24:
                try:
                    if rec.get('first_seen', 0) < cutoff:
                        continue
                except Exception:
                    continue
            seen.add((d, name))
        return len(seen)
    # Cache key
    k = (tech_term.lower() if tech_term else None, category.lower() if category else None, version, new24, tech_use_like)
    now = time.time()
    # Purge stale entries occasionally
    if _count_cache and len(_count_cache) > _COUNT_CACHE_MAX:
        # simple size trim: remove oldest by timestamp
        for _ in range(len(_count_cache) - _COUNT_CACHE_MAX//2):
            oldest = min(_count_cache.items(), key=lambda x: x[1][1])[0]
            _count_cache.pop(oldest, None)
    if k in _count_cache:
        val, ts = _count_cache[k]
        if now - ts < _COUNT_CACHE_TTL:
            return val
    clauses = []
    params = []
    base = 'SELECT COUNT(DISTINCT (domain, tech_name)) FROM domain_techs'
    if tech_term:
        if tech_use_like:
            clauses.append('LOWER(tech_name) LIKE LOWER(%s)')
        else:
            clauses.append('LOWER(tech_name)=LOWER(%s)')
        params.append(tech_param)
    if category:
        clauses.append("(','||LOWER(categories)||',') LIKE %s")
        params.append(f'%,{category.lower()},%')
    if version:
        clauses.append('version = %s')
        params.append(version)
    if new24:
            clauses.append('first_seen >= NOW() - INTERVAL \'24 hours\'')
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    sql = base + where
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            val = cur.fetchone()[0]
            _count_cache[k] = (val, now)
            return val

def history(domain: str, limit: int = 20, offset: int = 0):
    if _DB_DISABLED or _is_disabled_runtime():
        return []
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT mode, started_at, finished_at, duration_ms, from_cache, adaptive_timeout, retries, timeout_used, payload_bytes
                           FROM scans WHERE domain=%s ORDER BY finished_at DESC LIMIT %s OFFSET %s''', (domain, limit, offset))
            rows = cur.fetchall()
            out = []
            for r in rows:
                started_dt = r[1]
                finished_dt = r[2]
                duration_ms = r[3]
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
                    'mode': r[0],
                    'started_at': started_dt.timestamp() if started_dt else None,
                    'finished_at': finished_dt.timestamp() if finished_dt else None,
                    'duration_ms': duration_ms,
                    'from_cache': r[4],
                    'adaptive_timeout': r[5],
                    'retries': r[6],
                    'timeout_used': r[7],
                    'payload_bytes': r[8]
                })
            return out

def get_domain_techs(domain: str):
    """Return current technologies for a domain from domain_techs ordered by last_seen desc.
    Output: list of {tech_name, version, categories, first_seen, last_seen}
    """
    # If DB disabled, synthesize from in-memory mirror (may be empty)
    if _DB_DISABLED or _is_disabled_runtime():
        out = []
        for (d, name, version), rec in getattr(globals(), '_MEM_DOMAIN_TECHS', {}).items():
            if d != domain:
                continue
            cats = rec.get('categories')
            out.append({
                'tech_name': name,
                'version': version,
                'categories': cats.split(',') if cats else [],
                'first_seen': rec['first_seen'],
                'last_seen': rec['last_seen']
            })
        out.sort(key=lambda r: r['last_seen'], reverse=True)
        return out
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT tech_name, version, categories, first_seen, last_seen
                           FROM domain_techs WHERE domain=%s ORDER BY last_seen DESC''', (domain,))
            rows = cur.fetchall()
            out = []
            for r in rows:
                out.append({
                    'tech_name': r[0],
                    'version': r[1],
                    'categories': r[2].split(',') if r[2] else [],
                    'first_seen': r[3].timestamp(),
                    'last_seen': r[4].timestamp()
                })
            if out:
                return out
    # Fallback: return from in-memory mirror if SQL produced no rows (e.g., tests without real DB writes)
    mirror = []
    for (d, name, version), rec in getattr(globals(), '_MEM_DOMAIN_TECHS', {}).items():
        if d != domain:
            continue
        cats = rec.get('categories')
        mirror.append({
            'tech_name': name,
            'version': version,
            'categories': cats.split(',') if cats else [],
            'first_seen': rec['first_seen'],
            'last_seen': rec['last_seen']
        })
    mirror.sort(key=lambda r: r['last_seen'], reverse=True)
    return mirror

def count_history(domain: str):
    if _DB_DISABLED or _is_disabled_runtime():
        return 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) FROM scans WHERE domain=%s', (domain,))
            return cur.fetchone()[0]


def get_latest_scan_raw(domain: str):
    """Return raw JSON of the latest scan for a domain, or None."""
    if _DB_DISABLED or _is_disabled_runtime():
        # try to synthesize from in-memory mirror by returning a fabricated raw
        # For tests, domain_techs mirror contains minimal info; return None
        return None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT raw_json, technologies_json, finished_at FROM scans WHERE domain=%s ORDER BY finished_at DESC LIMIT 1''', (domain,))
            row = cur.fetchone()
            if not row:
                return None
            raw_json = row[0]
            techs_json = row[1]
            finished_at = row[2]
            return {'raw': raw_json, 'technologies': techs_json, 'finished_at': finished_at.timestamp() if finished_at else None}


def get_hint_meta_for_domains(domains: list[str]) -> dict[str, dict]:
    """Return mapping of domain -> stored tiered hint metadata."""
    if not domains:
        return {}
    if _DB_DISABLED or _is_disabled_runtime():
        return {}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                '''
                SELECT domain, raw_json
                FROM (
                    SELECT domain, raw_json,
                           ROW_NUMBER() OVER (PARTITION BY domain ORDER BY finished_at DESC) AS rn
                    FROM scans
                    WHERE domain = ANY(%s)
                ) ranked
                WHERE rn = 1
                ''',
                (domains,)
            )
            rows = cur.fetchall()
    hint_map: dict[str, dict] = {}
    for domain, raw_json in rows:
        meta = raw_json.get('_tiered_hint_meta') if isinstance(raw_json, dict) else None
        if meta:
            hint_map[domain] = meta
    return hint_map


def top_versions_for_tech(tech: str, limit: int = 10):
    """Return list of (version, count) for top versions for a tech."""
    if _DB_DISABLED or _is_disabled_runtime():
        counts = {}
        for (d, name, ver), rec in list(globals().get('_MEM_DOMAIN_TECHS', {}).items()):
            if name.lower() != tech.lower():
                continue
            if ver is None:
                continue
            counts[ver] = counts.get(ver, 0) + 1
        items = sorted([{'version': v, 'count': c} for v, c in counts.items()], key=lambda x: x['count'], reverse=True)
        return items[:limit]
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT version, COUNT(*) AS cnt FROM domain_techs WHERE LOWER(tech_name)=LOWER(%s) AND version IS NOT NULL GROUP BY version ORDER BY cnt DESC LIMIT %s''', (tech, limit))
            return [{'version': r[0], 'count': r[1]} for r in cur.fetchall()]


def tech_trend(tech: str, days: int = 30):
    """Return timeseries counts per day for the past `days` days for a tech."""
    if _DB_DISABLED or _is_disabled_runtime():
        # approximate trend from in-memory mirror using last_seen timestamps
        from collections import defaultdict
        buckets = defaultdict(int)
        cutoff = time.time() - days*24*3600
        for (d, name, ver), rec in list(globals().get('_MEM_DOMAIN_TECHS', {}).items()):
            if name.lower() != tech.lower():
                continue
            ls = rec.get('last_seen')
            if not ls or ls < cutoff:
                continue
            day = time.strftime('%Y-%m-%d', time.gmtime(ls))
            buckets[day] += 1
        days_list = []
        for i in range(days):
            ts = time.time() - (days - i - 1)*24*3600
            day = time.strftime('%Y-%m-%d', time.gmtime(ts))
            days_list.append({'day': day, 'count': buckets.get(day, 0)})
        return days_list
    with get_conn() as conn:
        with conn.cursor() as cur:
            # Use domain_techs.last_seen (timestamptz) to compute daily counts
            cur.execute('''
                SELECT DATE(dt.last_seen) AS day, COUNT(DISTINCT dt.domain)
                FROM domain_techs dt
                WHERE LOWER(dt.tech_name)=LOWER(%s) AND dt.last_seen >= NOW() - (%s)::interval
                GROUP BY day ORDER BY day
            ''', (tech, f"{days} days"))
            return [{'day': r[0].isoformat(), 'count': r[1]} for r in cur.fetchall()]

def db_stats():
    """Return aggregate DB statistics for quick dashboard use."""
    if _DB_DISABLED or _is_disabled_runtime():
        return {'disabled': True}
    with get_conn() as conn:
        with conn.cursor() as cur:
            out = {}
            cur.execute('SELECT COUNT(*) FROM scans')
            out['scans_total'] = cur.fetchone()[0]
            cur.execute('SELECT COUNT(DISTINCT domain) FROM domain_techs')
            out['domains_tracked'] = cur.fetchone()[0]
            cur.execute('SELECT COUNT(*) FROM domain_techs')
            out['domain_tech_rows'] = cur.fetchone()[0]
            # Top technologies
            cur.execute('''SELECT tech_name, COUNT(*) AS c FROM domain_techs GROUP BY tech_name ORDER BY c DESC LIMIT 15''')
            out['top_tech'] = [{'tech': r[0], 'count': r[1]} for r in cur.fetchall()]
            # Average durations (last 24h if possible)
            cur.execute("""
                SELECT mode, AVG(duration_ms) AS avg_ms, COUNT(*)
                FROM scans
                WHERE finished_at >= NOW() - INTERVAL '24 hours'
                GROUP BY mode
                ORDER BY avg_ms
            """)
            out['avg_duration_24h'] = [{'mode': r[0], 'avg_ms': float(r[1]), 'samples': r[2]} for r in cur.fetchall()]
            # Version presence rate (rough)
            cur.execute('SELECT SUM(CASE WHEN version IS NOT NULL AND version<>'' THEN 1 ELSE 0 END), COUNT(*) FROM domain_techs')
            ver_with, ver_total = cur.fetchone()
            out['version_presence_pct'] = round((ver_with / ver_total)*100,2) if ver_total else 0.0
            return out

def get_db_diagnostics():
    """Collect lightweight diagnostics for /admin/db_check endpoint."""
    if _DB_DISABLED or _is_disabled_runtime():
        return {'disabled': True, 'ok': False}
    info = {
        'ok': False,
        'error': None,
        'latency_ms': None,
        'scans_count': None,
        'domain_techs_count': None,
        'distinct_domains': None,
        'last_scan': None,
        'db_url_masked': None,
        'db_disabled': _DB_DISABLED,
    }
    # mask DB URL (show driver + host:port/db)
    try:
        from urllib.parse import urlparse
        u = urlparse(DB_URL)
        masked = f"{u.scheme}://{u.hostname}:{u.port or ''}{u.path}"
        info['db_url_masked'] = masked.rstrip(':')
    except Exception:
        info['db_url_masked'] = 'unparseable'
    started = time.time()
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT 1')
                cur.fetchone()
                info['latency_ms'] = round((time.time()-started)*1000,2)
                cur.execute('SELECT COUNT(*) FROM scans')
                info['scans_count'] = cur.fetchone()[0]
                cur.execute('SELECT COUNT(*) FROM domain_techs')
                info['domain_techs_count'] = cur.fetchone()[0]
                cur.execute('SELECT COUNT(DISTINCT domain) FROM domain_techs')
                info['distinct_domains'] = cur.fetchone()[0]
                cur.execute("""SELECT domain, finished_at FROM scans ORDER BY finished_at DESC LIMIT 1""")
                row = cur.fetchone()
                if row:
                    info['last_scan'] = {
                        'domain': row[0],
                        'finished_at': row[1].timestamp()
                    }
        info['ok'] = True
    except Exception as e:
        info['error'] = str(e)
    return info


# ============ Scan Job Queue Helpers ============

def save_scan_job(job: dict):
    """Save a new scan job to database."""
    if _DB_DISABLED:
        return
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    INSERT INTO scan_jobs (id, type, status, domains, options, progress, total, completed, result, results, error, created_at, updated_at, finished_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, to_timestamp(%s), to_timestamp(%s), %s)
                    ON CONFLICT (id) DO UPDATE SET
                        status = EXCLUDED.status,
                        progress = EXCLUDED.progress,
                        completed = EXCLUDED.completed,
                        result = EXCLUDED.result,
                        results = EXCLUDED.results,
                        error = EXCLUDED.error,
                        updated_at = EXCLUDED.updated_at,
                        finished_at = EXCLUDED.finished_at
                ''', (
                    job.get('id'),
                    job.get('type', 'single'),
                    job.get('status', 'pending'),
                    job.get('domains', '[]'),
                    job.get('options', '{}'),
                    job.get('progress', 0),
                    job.get('total', 1),
                    job.get('completed', 0),
                    job.get('result'),
                    job.get('results'),
                    job.get('error'),
                    job.get('created_at'),
                    job.get('updated_at'),
                    None if not job.get('finished_at') else f"to_timestamp({job.get('finished_at')})"
                ))
    except Exception as e:
        logging.getLogger('techscan.db').debug(f"save_scan_job error: {e}")


def get_scan_job(job_id: str) -> dict | None:
    """Get scan job by ID."""
    if _DB_DISABLED:
        return None
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    SELECT id, type, status, domains, options, progress, total, completed, result, results, error, created_at, updated_at, finished_at
                    FROM scan_jobs WHERE id = %s
                ''', (job_id,))
                row = cur.fetchone()
                if row:
                    return {
                        'id': row[0],
                        'type': row[1],
                        'status': row[2],
                        'domains': row[3] if isinstance(row[3], str) else json.dumps(row[3]) if row[3] else '[]',
                        'options': row[4] if isinstance(row[4], str) else json.dumps(row[4]) if row[4] else '{}',
                        'progress': row[5],
                        'total': row[6],
                        'completed': row[7],
                        'result': row[8] if isinstance(row[8], str) else json.dumps(row[8]) if row[8] else None,
                        'results': row[9] if isinstance(row[9], str) else json.dumps(row[9]) if row[9] else None,
                        'error': row[10],
                        'created_at': row[11].timestamp() if row[11] else None,
                        'updated_at': row[12].timestamp() if row[12] else None,
                        'finished_at': row[13].timestamp() if row[13] else None,
                    }
    except Exception as e:
        logging.getLogger('techscan.db').debug(f"get_scan_job error: {e}")
    return None


def update_scan_job(job_id: str, updates: dict):
    """Update scan job fields."""
    if _DB_DISABLED:
        return
    if not updates:
        return
    try:
        # Build dynamic update
        set_parts = []
        values = []
        for key, val in updates.items():
            if key in ('id', 'created_at'):
                continue
            if key == 'finished_at' and val:
                set_parts.append(f"{key} = to_timestamp(%s)")
                values.append(val)
            elif key == 'updated_at' and val:
                set_parts.append(f"{key} = to_timestamp(%s)")
                values.append(val)
            else:
                set_parts.append(f"{key} = %s")
                values.append(val)
        if not set_parts:
            return
        values.append(job_id)
        sql = f"UPDATE scan_jobs SET {', '.join(set_parts)} WHERE id = %s"
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, tuple(values))
    except Exception as e:
        logging.getLogger('techscan.db').debug(f"update_scan_job error: {e}")


def get_recent_scan_jobs(limit: int = 20) -> list:
    """Get recent scan jobs for status display."""
    if _DB_DISABLED:
        return []
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    SELECT id, type, status, domains, progress, total, completed, error, created_at, updated_at, finished_at
                    FROM scan_jobs ORDER BY created_at DESC LIMIT %s
                ''', (limit,))
                rows = cur.fetchall()
                return [{
                    'id': r[0],
                    'type': r[1],
                    'status': r[2],
                    'domains': r[3] if isinstance(r[3], str) else json.dumps(r[3]) if r[3] else '[]',
                    'progress': r[4],
                    'total': r[5],
                    'completed': r[6],
                    'error': r[7],
                    'created_at': r[8].timestamp() if r[8] else None,
                    'updated_at': r[9].timestamp() if r[9] else None,
                    'finished_at': r[10].timestamp() if r[10] else None,
                } for r in rows]
    except Exception as e:
        logging.getLogger('techscan.db').debug(f"get_recent_scan_jobs error: {e}")
    return []


def get_recent_scans(limit: int = 500) -> list:
    """Get recent scan results for ML training.
    
    Returns scan results with domain, technologies, and raw_html.
    """
    if _DB_DISABLED:
        return []
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    SELECT domain, technologies_json, raw_json, mode, finished_at
                    FROM scans 
                    WHERE technologies_json IS NOT NULL 
                    ORDER BY finished_at DESC 
                    LIMIT %s
                ''', (limit,))
                rows = cur.fetchall()
                results = []
                for r in rows:
                    domain = r[0]
                    techs = r[1]
                    raw_json = r[2]
                    # Handle JSON stored as string
                    if isinstance(techs, str):
                        try:
                            techs = json.loads(techs)
                        except:
                            techs = []
                    # Extract HTML from raw_json if available
                    raw_html = None
                    if isinstance(raw_json, dict):
                        raw_html = raw_json.get('html') or raw_json.get('raw_html')
                    elif isinstance(raw_json, str):
                        try:
                            raw_data = json.loads(raw_json)
                            raw_html = raw_data.get('html') or raw_data.get('raw_html')
                        except:
                            pass
                    results.append({
                        'domain': domain,
                        'technologies': techs or [],
                        'raw_html': raw_html,
                        'scan_mode': r[3],
                        'timestamp': r[4].timestamp() if r[4] else None,
                    })
                return results
    except Exception as e:
        logging.getLogger('techscan.db').debug(f"get_recent_scans error: {e}")
    return []



# ============ Scheduled Cleanup ============

# Cleanup old scan records to prevent unbounded database growth.
# Disabled by default (TECHSCAN_CLEANUP_ENABLED=0).
# Enable via environment: TECHSCAN_CLEANUP_ENABLED=1

_CLEANUP_THREAD = None
_CLEANUP_STOP = threading.Event()


def cleanup_old_scans(retention_days: int = 90, dry_run: bool = False) -> dict:
    """Delete old scan records beyond retention period.
    
    Args:
        retention_days: Records older than this will be deleted. Default 90 days.
        dry_run: If True, only count records without deleting.
    
    Returns:
        dict with: deleted_scans, deleted_domain_techs, deleted_jobs, dry_run flag
    """
    if _DB_DISABLED or _is_disabled_runtime():
        return {'disabled': True, 'message': 'DB is disabled'}
    
    log = logging.getLogger('techscan.db')
    result = {
        'deleted_scans': 0,
        'deleted_domain_techs': 0,
        'deleted_jobs': 0,
        'retention_days': retention_days,
        'dry_run': dry_run
    }
    
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # Count old scans
                cur.execute('''
                    SELECT COUNT(*) FROM scans 
                    WHERE finished_at < NOW() - INTERVAL '%s days'
                ''', (retention_days,))
                scans_count = cur.fetchone()[0]
                
                # Count old domain_techs (not seen in retention period)
                cur.execute('''
                    SELECT COUNT(*) FROM domain_techs 
                    WHERE last_seen < NOW() - INTERVAL '%s days'
                ''', (retention_days,))
                techs_count = cur.fetchone()[0]
                
                # Count old jobs
                cur.execute('''
                    SELECT COUNT(*) FROM scan_jobs 
                    WHERE created_at < NOW() - INTERVAL '%s days'
                ''', (retention_days,))
                jobs_count = cur.fetchone()[0]
                
                if dry_run:
                    result['would_delete_scans'] = scans_count
                    result['would_delete_domain_techs'] = techs_count
                    result['would_delete_jobs'] = jobs_count
                    log.info('cleanup_old_scans DRY RUN: scans=%d techs=%d jobs=%d (retention=%d days)',
                             scans_count, techs_count, jobs_count, retention_days)
                else:
                    # Delete old scans
                    cur.execute('''
                        DELETE FROM scans 
                        WHERE finished_at < NOW() - INTERVAL '%s days'
                    ''', (retention_days,))
                    result['deleted_scans'] = cur.rowcount
                    
                    # Delete old domain_techs
                    cur.execute('''
                        DELETE FROM domain_techs 
                        WHERE last_seen < NOW() - INTERVAL '%s days'
                    ''', (retention_days,))
                    result['deleted_domain_techs'] = cur.rowcount
                    
                    # Delete old jobs
                    cur.execute('''
                        DELETE FROM scan_jobs 
                        WHERE created_at < NOW() - INTERVAL '%s days'
                    ''', (retention_days,))
                    result['deleted_jobs'] = cur.rowcount
                    
                    conn.commit()
                    log.info('cleanup_old_scans: deleted scans=%d techs=%d jobs=%d (retention=%d days)',
                             result['deleted_scans'], result['deleted_domain_techs'], 
                             result['deleted_jobs'], retention_days)
                    
    except Exception as e:
        log.error('cleanup_old_scans error: %s', e)
        result['error'] = str(e)
    
    return result


def _cleanup_loop(interval_hours: float, retention_days: int):
    """Background cleanup loop."""
    log = logging.getLogger('techscan.db')
    interval_seconds = interval_hours * 3600
    log.info('Cleanup scheduler started: interval=%s hours, retention=%s days', 
             interval_hours, retention_days)
    
    while not _CLEANUP_STOP.wait(interval_seconds):
        try:
            result = cleanup_old_scans(retention_days=retention_days)
            log.debug('Scheduled cleanup completed: %s', result)
        except Exception as e:
            log.error('Scheduled cleanup failed: %s', e)


def start_cleanup_scheduler():
    """Start background cleanup scheduler if enabled via environment.
    
    Environment variables:
        TECHSCAN_CLEANUP_ENABLED: '1' to enable (default '0' = disabled)
        TECHSCAN_CLEANUP_DAYS: Retention period in days (default 90)
        TECHSCAN_CLEANUP_INTERVAL_HOURS: How often to run cleanup (default 24)
    """
    global _CLEANUP_THREAD, _CLEANUP_STOP
    
    if os.environ.get('TECHSCAN_CLEANUP_ENABLED', '0') != '1':
        logging.getLogger('techscan.db').debug(
            'Cleanup scheduler disabled (set TECHSCAN_CLEANUP_ENABLED=1 to enable)')
        return False
    
    if _CLEANUP_THREAD and _CLEANUP_THREAD.is_alive():
        return True  # Already running
    
    try:
        retention_days = int(os.environ.get('TECHSCAN_CLEANUP_DAYS', '90'))
    except ValueError:
        retention_days = 90
    
    try:
        interval_hours = float(os.environ.get('TECHSCAN_CLEANUP_INTERVAL_HOURS', '24'))
    except ValueError:
        interval_hours = 24.0
    
    _CLEANUP_STOP.clear()
    t = threading.Thread(
        target=_cleanup_loop, 
        args=(interval_hours, retention_days), 
        daemon=True, 
        name='db-cleanup-scheduler'
    )
    _CLEANUP_THREAD = t
    t.start()
    return True


def stop_cleanup_scheduler():
    """Stop the cleanup scheduler if running."""
    global _CLEANUP_THREAD, _CLEANUP_STOP
    _CLEANUP_STOP.set()
    if _CLEANUP_THREAD:
        try:
            _CLEANUP_THREAD.join(timeout=2.0)
        except Exception:
            pass
    _CLEANUP_THREAD = None
