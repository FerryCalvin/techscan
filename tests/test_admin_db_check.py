import os, sys, pathlib

# Ensure project root on sys.path when running tests directly
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app


def test_db_check_disabled(monkeypatch):
    monkeypatch.setenv('TECHSCAN_DISABLE_DB', '1')
    app = create_app()
    client = app.test_client()
    r = client.get('/admin/db_check')
    assert r.status_code == 200
    data = r.get_json()
    assert 'diagnostics' in data
    diag = data['diagnostics']
    assert diag.get('disabled') is True
    assert diag.get('ok') is False  # disabled means not an active OK connection


def test_db_check_structure(monkeypatch):
    # Force disable to avoid needing real Postgres; still want structural keys
    monkeypatch.setenv('TECHSCAN_DISABLE_DB', '1')
    app = create_app()
    client = app.test_client()
    resp = client.get('/admin/db_check')
    d = resp.get_json()['diagnostics']
    # Must always include these keys even if disabled
    # When disabled, we expect at least these keys
    assert 'ok' in d
    # Implementation returns 'disabled' instead of 'db_disabled' in this mode
    assert d.get('disabled') is True
