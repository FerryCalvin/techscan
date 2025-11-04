import os, logging, json
from app import create_app

def _make_app():
    app = create_app()
    app.config['TESTING'] = True
    return app

def test_admin_log_level_get_and_set_no_token():
    # Ensure no token set
    os.environ.pop('TECHSCAN_ADMIN_TOKEN', None)
    app = _make_app()
    client = app.test_client()
    r = client.get('/admin/log_level')
    assert r.status_code == 200
    data = r.get_json()
    assert data['status'] == 'ok'
    # Change level
    r2 = client.post('/admin/log_level', json={'level':'DEBUG'})
    assert r2.status_code == 200
    data2 = r2.get_json()
    assert data2['level'] == 'DEBUG'
    # Effective level applied
    assert logging.getLogger().getEffectiveLevel() == logging.DEBUG

def test_admin_log_level_with_token_and_invalid_level():
    os.environ['TECHSCAN_ADMIN_TOKEN'] = 'secret123'
    app = _make_app()
    client = app.test_client()
    # Missing token header
    r = client.post('/admin/log_level', json={'level':'INFO'})
    assert r.status_code == 401
    # Invalid level
    r2 = client.post('/admin/log_level', headers={'X-Admin-Token':'secret123'}, json={'level':'SILLY'})
    assert r2.status_code == 400
    # Valid change
    r3 = client.post('/admin/log_level', headers={'X-Admin-Token':'secret123'}, json={'level':'ERROR'})
    assert r3.status_code == 200
    assert logging.getLogger().getEffectiveLevel() == logging.ERROR
    # Cleanup
    os.environ.pop('TECHSCAN_ADMIN_TOKEN', None)
