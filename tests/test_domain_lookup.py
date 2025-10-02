import json, time
from app import create_app
from app import db as _db

def test_domain_lookup_endpoint(monkeypatch):
    app = create_app()
    client = app.test_client()
    # Insert a fake scan record directly using save_scan to populate domain_techs
    sample = {
        'domain': 'example.com',
        'scan_mode': 'fast',
        'started_at': time.time()-2,
        'finished_at': time.time()-1,
        'duration': 1.0,
        'technologies': [
            {'name':'WordPress','version':'6.5.2','categories':['CMS','Blogs']},
            {'name':'jQuery','version':'3.7.1','categories':['JavaScript libraries']}
        ],
        'categories': {},
        'raw': {'meta':'x'},
        'retries':0
    }
    _db.save_scan(sample, from_cache=False, timeout_used=0)
    r = client.get('/domain?domain=example.com')
    assert r.status_code == 200
    data = r.get_json()
    assert data['domain'] == 'example.com'
    names = {t['name'] for t in data['technologies']}
    assert 'WordPress' in names and 'jQuery' in names
    assert data['count'] >= 2
