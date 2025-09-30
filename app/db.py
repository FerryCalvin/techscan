import os, time, json, logging
from contextlib import contextmanager
import psycopg

DB_URL = os.environ.get('TECHSCAN_DB_URL', 'postgresql://postgres:postgres@localhost:5432/techscan')

# Allow disabling DB usage completely for test/perf runs without a live Postgres
if os.environ.get('TECHSCAN_DISABLE_DB','0') == '1':
    logging.getLogger('techscan.db').warning('TECHSCAN_DISABLE_DB=1 -> database persistence DISABLED (using stubs)')
    def ensure_schema():  # type: ignore
        return
    def save_scan(result: dict, from_cache: bool, timeout_used: int):  # type: ignore
        return
    def search_tech(tech: str | None = None, category: str | None = None, version: str | None = None, limit: int = 200):  # type: ignore
        return []
    def history(domain: str, limit: int = 20):  # type: ignore
        return []
    # Short-circuit further real definitions
    _DB_DISABLED = True
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
        last_seen TIMESTAMPTZ NOT NULL,
        UNIQUE(domain, tech_name, COALESCE(version, ''))
    );''',
    'CREATE INDEX IF NOT EXISTS idx_domain_techs_tech ON domain_techs(tech_name);',
    'CREATE INDEX IF NOT EXISTS idx_domain_techs_last_seen ON domain_techs(last_seen DESC);'
]

_pool: dict = {}

@contextmanager
def get_conn():
    # simple pool keyed by thread id to reuse connection
    import threading
    tid = threading.get_ident()
    conn = _pool.get(tid)
    if conn is None or conn.closed:
        conn = psycopg.connect(DB_URL, autocommit=False)
        _pool[tid] = conn
    try:
        yield conn
    finally:
        # do not close for pooling; rely on process exit
        pass

def ensure_schema():
    if _DB_DISABLED:
        return
    with get_conn() as conn:
        with conn.cursor() as cur:
            for stmt in SCHEMA_STATEMENTS:
                cur.execute(stmt)
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
    # epoch -> timestamptz via to_timestamp in parameterization OR convert in python via psycopg adaptation
    technologies = result.get('technologies') or []
    categories = result.get('categories') or {}
    raw = result.get('raw')
    adaptive = bool(result.get('adaptive_timeout'))
    retries = int(result.get('retries') or 0)
    duration_ms = int(float(result.get('duration') or 0) * 1000)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                '''INSERT INTO scans(domain, mode, started_at, finished_at, duration_ms, from_cache, adaptive_timeout, retries, timeout_used, technologies_json, categories_json, raw_json, error)
                   VALUES (%s, %s, to_timestamp(%s), to_timestamp(%s), %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s)''',
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
                    json.dumps(technologies, ensure_ascii=False),
                    json.dumps(categories, ensure_ascii=False),
                    json.dumps(raw, ensure_ascii=False) if raw is not None else None,
                    result.get('error')
                )
            )
            # Upsert domain_techs
            now_epoch = finished_at
            for tech in technologies:
                name = tech.get('name')
                if not name:
                    continue
                version = tech.get('version')
                cats = ','.join(sorted(tech.get('categories') or [])) if tech.get('categories') else None
                cur.execute(
                    '''INSERT INTO domain_techs(domain, tech_name, version, categories, first_seen, last_seen)
                       VALUES (%s,%s,%s,%s,to_timestamp(%s),to_timestamp(%s))
                       ON CONFLICT (domain, tech_name, COALESCE(version, ''))
                       DO UPDATE SET last_seen = excluded.last_seen, categories = COALESCE(excluded.categories, domain_techs.categories)''',
                    (result['domain'], name, version, cats, now_epoch, now_epoch)
                )
        conn.commit()

def search_tech(tech: str | None = None, category: str | None = None, version: str | None = None, limit: int = 200):
    if _DB_DISABLED:
        return []
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
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    order = ' ORDER BY last_seen DESC'
    sql = base + where + order + ' LIMIT %s'
    params.append(limit)
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

def history(domain: str, limit: int = 20):
    if _DB_DISABLED:
        return []
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT mode, started_at, finished_at, duration_ms, from_cache, adaptive_timeout, retries, timeout_used
                           FROM scans WHERE domain=%s ORDER BY finished_at DESC LIMIT %s''', (domain, limit))
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

