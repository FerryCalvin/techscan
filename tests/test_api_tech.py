import os, pathlib, sys, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from app import db as _db


def test_api_tech_endpoints(monkeypatch):
    monkeypatch.setenv('TECHSCAN_DISABLE_DB', '1')
    app = create_app()
    try:
        app.extensions.get('limiter').enabled = False  # type: ignore
    except Exception:
        pass
    client = app.test_client()

    # Create a fake scan result and persist into in-memory mirror
    fake = {
        'domain': 'example.com',
        'timestamp': int(time.time()),
        'finished_at': int(time.time()),
        'duration': 1.2,
        'technologies': [
            {'name': 'Elementor', 'version': '5.44.0', 'categories': ['WordPress plugins']}
        ],
        'categories': {'WordPress plugins': [{'name':'Elementor','version':'5.44.0'}]}
    }
    _db.save_scan(fake, from_cache=False, timeout_used=0)

    # Meta endpoint
    resp = client.get('/api/tech/Elementor')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['tech_key'].lower() == 'elementor'

    # Sites endpoint
    resp2 = client.get('/api/tech/Elementor/sites')
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2['total'] >= 1
    assert any(s['domain'] == 'example.com' for s in data2['sites'])
