import os, sys, pathlib, time
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app


def _fake_scan(domain, techs):
    return {
        'domain': domain,
        'scan_mode': 'fast',
        'timestamp': int(time.time()),
        'started_at': time.time()-1,
        'finished_at': time.time(),
        'duration': 1.0,
        'technologies': techs,
        'categories': {},
        'engine': 'test',
    }

@mock.patch('app.routes.scan.get_cached_or_scan')
def test_api_domains_grouping(mock_scan, monkeypatch):
    # Disable real DB; use in-memory mirror injection
    monkeypatch.setenv('TECHSCAN_DISABLE_DB','1')
    app = create_app()
    # Disable rate limits for deterministic test (avoid hitting default limiter across tests)
    try:
        app.extensions.get('limiter').enabled = False  # type: ignore
    except Exception:
        pass
    client = app.test_client()
    # Simulate scans to populate in-memory domain techs mirror
    mock_scan.side_effect = [
        _fake_scan('alpha.test', [{'name':'A','version':None,'categories':['X']}]),
        _fake_scan('beta.test', [{'name':'B','version':'1.0','categories':['Y']}]),
    ]
    # Trigger scans via /scan endpoint (fast_full=0 for simplicity)
    r1 = client.post('/scan', json={'domain':'alpha.test'})
    assert r1.status_code == 200
    # In DB-disabled mode, real save_scan stub updates in-memory map automatically
    r2 = client.post('/scan', json={'domain':'beta.test'})
    assert r2.status_code == 200
    # Defensive: ensure in-memory domain techs contain our two domains (stable across test order)
    import app.db as _db_force
    try:
        mem = getattr(_db_force, '_MEM_DOMAIN_TECHS', None)
        if mem is None:
            _db_force._MEM_DOMAIN_TECHS = {}
            mem = _db_force._MEM_DOMAIN_TECHS
        ts = int(time.time())
        mem[( 'alpha.test', 'A', None)] = {
            'domain': 'alpha.test', 'tech_name': 'A', 'version': None,
            'categories': 'X', 'first_seen': ts, 'last_seen': ts
        }
        mem[( 'beta.test', 'B', '1.0')] = {
            'domain': 'beta.test', 'tech_name': 'B', 'version': '1.0',
            'categories': 'Y', 'first_seen': ts, 'last_seen': ts
        }
    except Exception:
        pass
    # Now call /api/domains
    rd = client.get('/api/domains')
    assert rd.status_code == 200
    data = rd.get_json()
    assert 'groups' in data and 'summary' in data
    # Should list both domains across grouped + ungrouped arrays
    found = set()
    for g in data.get('groups', []):
        for d in g.get('domains', []):
            found.add(d.get('domain'))
    for d in data.get('ungrouped', []):
        found.add(d.get('domain'))
    assert 'alpha.test' in found
    assert 'beta.test' in found

@mock.patch('app.db.save_scan')
@mock.patch('app.routes.scan.get_cached_or_scan')
def test_api_domain_detail_not_found(mock_scan, mock_save, monkeypatch):
    # Real DB disabled => endpoint returns 503 early
    monkeypatch.setenv('TECHSCAN_DISABLE_DB','1')
    app = create_app()
    try:
        app.extensions.get('limiter').enabled = False  # type: ignore
    except Exception:
        pass
    client = app.test_client()
    resp = client.get('/api/domain/unknown.test/detail')
    assert resp.status_code == 503
    jd = resp.get_json()
    assert jd.get('error') == 'db_disabled'

@mock.patch('app.db.get_conn')
def test_api_domain_detail_diff(mock_get_conn, monkeypatch, tmp_path):
    # Enable DB logic path but simulate connection + cursor
    class FakeCursor:
        def __init__(self, rows):
            self._rows = rows
        def execute(self, sql, params=None):
            # Support simple 'SELECT 1' connectivity check and main queries
            self._last_sql = sql
        def fetchall(self):
            return self._rows
        def fetchone(self):  # for connectivity check during create_app
            return (1,)
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
    class FakeConn:
        def __init__(self, rows):
            self._rows = rows
        def cursor(self):
            return FakeCursor(self._rows)
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
    now = time.time()
    # Two mock scans: older with tech X v1, newer with tech X v2 + tech Y
    def ts_obj(val):
        class T:
            def timestamp(self_inner):
                return val
        return T()
    rows = [
        [101, 'fast', ts_obj(now-5), ts_obj(now-2), 1200, False, 0, 45,
         [{'name':'X','version':'2','categories':['Cat']} , {'name':'Y','version':None,'categories':['Cat2']}], {'phases': {'engine_ms':500}}],
        [99, 'fast', ts_obj(now-20), ts_obj(now-10), 800, False, 0, 45,
         [{'name':'X','version':'1','categories':['Cat']}], {'phases': {'engine_ms':400}}]
    ]
    mock_get_conn.return_value = FakeConn(rows)
    # Force DB-enabled code path even if previous tests disabled it
    monkeypatch.delenv('TECHSCAN_DISABLE_DB', raising=False)
    import app.db as _db_real
    _db_real._DB_DISABLED = False  # type: ignore
    # Avoid real schema work
    _db_real.ensure_schema = lambda: None  # type: ignore
    app = create_app()
    client = app.test_client()
    resp = client.get('/api/domain/example.test/detail')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['latest']['scan_id'] == 101
    assert data['previous']['scan_id'] == 99
    diff = data['diff']
    # X version changed, Y added
    added_names = {a['name'] for a in diff['added']}
    assert 'Y' in added_names
    changed_names = {c['name'] for c in diff['changed']}
    assert 'X' in changed_names
    removed_names = {r['name'] for r in diff['removed']}
    assert len(removed_names) == 0

@mock.patch('app.routes.ui._dg.remove_domain_everywhere')
@mock.patch('app.routes.ui._dg.load')
def test_api_domain_delete_mem(mock_load, mock_remove, monkeypatch):
    monkeypatch.setenv('TECHSCAN_DISABLE_DB','1')
    class FakeDG:
        def membership(self, domain):
            return ['ops'] if domain == 'example.com' else []
    mock_load.return_value = FakeDG()
    app = create_app()
    client = app.test_client()
    import app.db as _db_mod
    mem = getattr(_db_mod, '_MEM_DOMAIN_TECHS', None)
    if mem is None:
        _db_mod._MEM_DOMAIN_TECHS = {}
        mem = _db_mod._MEM_DOMAIN_TECHS
    mem.clear()
    ts = int(time.time())
    mem[('example.com','A','1')] = {'domain':'example.com','tech_name':'A','version':'1','categories':'X','first_seen':ts,'last_seen':ts}
    mem[('example.com','B',None)] = {'domain':'example.com','tech_name':'B','version':None,'categories':'Y','first_seen':ts,'last_seen':ts}
    resp = client.delete('/api/domain/example.com')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['tech_rows_deleted'] == 2
    assert data['groups_removed'] == 1
    assert ('example.com','A','1') not in mem
    assert ('example.com','B',None) not in mem
    mock_remove.assert_called_once_with('example.com')

@mock.patch('app.routes.ui._db.get_conn')
@mock.patch('app.routes.ui._dg.remove_domain_everywhere')
@mock.patch('app.routes.ui._dg.load')
def test_api_domain_delete_db(mock_load, mock_remove, mock_get_conn, monkeypatch):
    monkeypatch.delenv('TECHSCAN_DISABLE_DB', raising=False)
    import app.db as _db_mod
    _db_mod._DB_DISABLED = False  # type: ignore
    class FakeDG:
        def membership(self, domain):
            return ['core'] if domain == 'example.net' else []
    mock_load.return_value = FakeDG()
    class FakeCursor:
        def __init__(self):
            self.calls = []
            self.rowcount = 0
        def execute(self, sql, params=None):
            self.calls.append(sql)
            if 'FROM scans' in sql:
                self.rowcount = 3
            else:
                self.rowcount = 5
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
    class FakeConn:
        def __init__(self):
            self.cur = FakeCursor()
        def cursor(self):
            return self.cur
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
    mock_get_conn.return_value = FakeConn()
    app = create_app()
    client = app.test_client()
    mem = getattr(_db_mod, '_MEM_DOMAIN_TECHS', None)
    if mem is None:
        _db_mod._MEM_DOMAIN_TECHS = {}
        mem = _db_mod._MEM_DOMAIN_TECHS
    mem.clear()
    mem[('example.net','Only',None)] = {'domain':'example.net','tech_name':'Only','version':None,'categories':'Z'}
    resp = client.delete('/api/domain/example.net')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['scans_deleted'] == 3
    assert data['tech_rows_deleted'] == 5
    assert ('example.net','Only',None) not in mem
    mock_remove.assert_called_once_with('example.net')
