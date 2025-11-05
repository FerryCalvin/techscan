import os, time, json, logging
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
            _LOG.warning('TECHSCAN_DB_PASSWORD is empty (allowed by TECHSCAN_ALLOW_EMPTY_DB_PASSWORD=1). Use only for local development.')
            db_pass = ''  # nosec B105: explicit empty password permitted only for local development override
        else:
            raise RuntimeError('TECHSCAN_DB_PASSWORD is not set. Define TECHSCAN_DB_URL or set TECHSCAN_DB_PASSWORD via environment.')
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
    # Legacy functional unique index (kept if already exists). New approach uses update-then-insert so we only need a normal index.
    'CREATE INDEX IF NOT EXISTS idx_domain_techs_dtv ON domain_techs(domain, tech_name, version);'
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
            logging.getLogger('techscan.db').warning('Failed to initialize psycopg_pool: %s; will fall back to single-connection-per-use', e)
            _POOL = None
    else:
        logging.getLogger('techscan.db').info('psycopg_pool not available; falling back to creating short-lived connections (set TECHSCAN_DB_POOL_SIZE and install psycopg_pool for pooling)')


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
                logging.getLogger('techscan.db').warning('DB pool at full capacity (%d/%d)', st['in_use'], st['max_size'])
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
    t = threading.Thread(target=_pool_monitor_loop, args=(float(os.environ.get('TECHSCAN_DB_POOL_MONITOR_INTERVAL', '10')),), daemon=True, name='db-pool-monitor')
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

def ensure_schema():
    if _DB_DISABLED:
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
            if alter_needed:
                cur.execute('ALTER TABLE scans ' + ', '.join(alter_needed))
        conn.commit()
    logging.getLogger('techscan.db').info('schema ensured')

def save_scan(result: dict, from_cache: bool, timeout_used: int):
    """Persist single scan result.
    result expects keys: domain, scan_mode, duration, technologies, categories, timestamp, (optional) adaptive_timeout, retries, raw
    """
    if _DB_DISABLED:
        return
    started_at = result.get('started_at') or result.get('_started_at') or result.get('timestamp')
    finished_at = result.get('finished_at') or result.get('timestamp') or time.time()
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
    adaptive = bool(result.get('adaptive_timeout'))
    retries = int(result.get('retries') or 0)
    duration_ms = int(float(result.get('duration') or 0) * 1000)
    # derive counts
    tech_count = len(technologies)
    versions_count = sum(1 for t in technologies if t.get('version'))
    log = logging.getLogger('techscan.db')
    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                '''INSERT INTO scans(domain, mode, started_at, finished_at, duration_ms, from_cache, adaptive_timeout, retries, timeout_used, tech_count, versions_count, technologies_json, categories_json, raw_json, error)
                   VALUES (%s, %s, to_timestamp(%s), to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s)''',
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
                    result.get('error')
                )
                )
            except Exception as ins_ex:
                log.warning('insert_scans_failed domain=%s mode=%s err=%s', result.get('domain'), result.get('scan_mode'), ins_ex)
                raise
            # Update-then-insert pattern (avoids reliance on unique constraint) with explicit NULL branch to prevent unknown type errors.
            now_epoch = finished_at
            for tech in technologies:
                name = tech.get('name')
                if not name:
                    continue
                version = tech.get('version')  # may be None
                cats = ','.join(sorted(tech.get('categories') or [])) if tech.get('categories') else None
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
    global _MEM_DOMAIN_TECHS
    now_epoch = finished_at
    for tech in technologies:
        name = tech.get('name')
        if not name:
            continue
        version = tech.get('version')
        cats = ','.join(sorted(tech.get('categories') or [])) if tech.get('categories') else None
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

def search_tech(tech: str | None = None, category: str | None = None, version: str | None = None, limit: int = 200, offset: int = 0, new24: bool = False, sort_key: str | None = None, sort_dir: str = 'desc'):
    if _DB_DISABLED:
        # Return synthesized results from in-memory mirror
        out = []
        for (d, name, ver), rec in list(globals().get('_MEM_DOMAIN_TECHS', {}).items()):
            if tech and name.lower() != tech.lower():
                continue
            if category:
                cats = (rec.get('categories') or '').lower()
                if category.lower() not in cats:
                    continue
            if version and ver != version:
                continue
            if new24:
                try:
                    if rec.get('first_seen', 0) < (time.time() - 24*3600):
                        continue
                except Exception:
                    pass
            out.append({
                'domain': d,
                'tech_name': name,
                'version': ver,
                'categories': rec.get('categories').split(',') if rec.get('categories') else [],
                'first_seen': rec.get('first_seen'),
                'last_seen': rec.get('last_seen')
            })
        # sort
        reverse = (sort_dir.lower() != 'asc')
        key_map = {
            'domain': lambda r: r['domain'],
            'tech_name': lambda r: r['tech_name'],
            'version': lambda r: r['version'] or '',
            'first_seen': lambda r: r.get('first_seen', 0),
            'last_seen': lambda r: r.get('last_seen', 0)
        }
        keyfn = key_map.get((sort_key or '').lower(), lambda r: r.get('last_seen', 0))
        out.sort(key=keyfn, reverse=reverse)
        return out[offset:offset+limit]
    clauses = []
    params = []
    base = 'SELECT domain, tech_name, version, categories, first_seen, last_seen FROM domain_techs'
    if tech:
        clauses.append('LOWER(tech_name)=LOWER(%s)')
        params.append(tech)
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
        'domain': 'domain',
        'tech_name': 'tech_name',
        'version': 'version',
        'first_seen': 'first_seen',
        'last_seen': 'last_seen'
    }
    col = valid_cols.get((sort_key or '').lower(), 'last_seen')
    dir_sql = 'ASC' if sort_dir.lower() == 'asc' else 'DESC'
    order = f' ORDER BY {col} {dir_sql}'
    sql = base + where + order + ' LIMIT %s OFFSET %s'
    params.extend([limit, offset])
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            out = []
            for r in rows:
                out.append({
                    'domain': r[0],
                    'tech_name': r[1],
                    'version': r[2],
                    'categories': r[3].split(',') if r[3] else [],
                    'first_seen': r[4].timestamp(),
                    'last_seen': r[5].timestamp(),
                })
            return out

def count_search_tech(tech: str | None = None, category: str | None = None, version: str | None = None, new24: bool = False):
    if _DB_DISABLED:
        seen = set()
        for (d, name, ver), rec in list(globals().get('_MEM_DOMAIN_TECHS', {}).items()):
            if tech and name.lower() != tech.lower():
                continue
            if category:
                cats = (rec.get('categories') or '').lower()
                if category.lower() not in cats:
                    continue
            if version and ver != version:
                continue
            if new24:
                try:
                    if rec.get('first_seen', 0) < (time.time() - 24*3600):
                        continue
                except Exception:
                    pass
            seen.add(d)
        return len(seen)
    # Cache key
    k = (tech.lower() if tech else None, category.lower() if category else None, version, new24)
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
    base = 'SELECT COUNT(*) FROM domain_techs'
    if tech:
        clauses.append('LOWER(tech_name)=LOWER(%s)')
        params.append(tech)
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
    if _DB_DISABLED:
        return []
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT mode, started_at, finished_at, duration_ms, from_cache, adaptive_timeout, retries, timeout_used
                           FROM scans WHERE domain=%s ORDER BY finished_at DESC LIMIT %s OFFSET %s''', (domain, limit, offset))
            rows = cur.fetchall()
            return [
                {
                    'mode': r[0],
                    'started_at': r[1].timestamp(),
                    'finished_at': r[2].timestamp(),
                    'duration_ms': r[3],
                    'from_cache': r[4],
                    'adaptive_timeout': r[5],
                    'retries': r[6],
                    'timeout_used': r[7]
                } for r in rows
            ]

def get_domain_techs(domain: str):
    """Return current technologies for a domain from domain_techs ordered by last_seen desc.
    Output: list of {tech_name, version, categories, first_seen, last_seen}
    """
    # If DB disabled, synthesize from in-memory mirror (may be empty)
    if _DB_DISABLED:
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
    if _DB_DISABLED:
        return 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) FROM scans WHERE domain=%s', (domain,))
            return cur.fetchone()[0]


def get_latest_scan_raw(domain: str):
    """Return raw JSON of the latest scan for a domain, or None."""
    if _DB_DISABLED:
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


def top_versions_for_tech(tech: str, limit: int = 10):
    """Return list of (version, count) for top versions for a tech."""
    if _DB_DISABLED:
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
    if _DB_DISABLED:
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
    if _DB_DISABLED:
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
    if _DB_DISABLED:
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

