import json, time, os, sys, pathlib
# Ensure project root on path and disable DB before importing app so in-memory stub is used
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ['TECHSCAN_DISABLE_DB'] = '1'
from app import create_app
from app import db as _db

def test_domain_lookup_endpoint(monkeypatch):
    app = create_app()
    client = app.test_client()
    # Prepare synthetic rows returned by get_domain_techs (matching DB layer shape)
    fake_rows = [
        {'tech_name':'WordPress','version':'6.5.2','categories':['CMS','Blogs'],'first_seen':time.time()-2,'last_seen':time.time()-1},
        {'tech_name':'jQuery','version':'3.7.1','categories':['JavaScript libraries'],'first_seen':time.time()-2,'last_seen':time.time()-1},
    ]
    monkeypatch.setattr(_db, 'get_domain_techs', lambda domain: fake_rows if domain=='example.com' else [])
    r = client.get('/domain?domain=example.com')
    assert r.status_code == 200
    data = r.get_json()
    assert data['domain'] == 'example.com'
    names = {t['name'] for t in data['technologies']}
    assert 'WordPress' in names and 'jQuery' in names
    assert data['count'] >= 2
