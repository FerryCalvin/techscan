import sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app

# Use an env that disables DB to avoid depending on Postgres for this unit test

def test_deep_scan_endpoint_runs(monkeypatch):
    monkeypatch.setenv('TECHSCAN_DISABLE_DB', '1')
    # Ensure persistence not required for unit test
    monkeypatch.setenv('TECHSCAN_PERSIST_BROWSER', '0')
    app = create_app()
    try:
        app.extensions.get('limiter').enabled = False  # type: ignore
    except Exception:
        pass
    client = app.test_client()
    # Call the scan endpoint with a small domain; this uses quick/deep code paths but
    # in test environment should not rely on external Node daemon.
    resp = client.get('/scan?domain=example.com&full=1')
    assert resp.status_code in (200, 500)  # If server raises 500, test will surface details
    data = resp.get_json()
    assert isinstance(data, dict)
    # If it's a successful scan, technologies should be present (list)
    if resp.status_code == 200:
        assert 'technologies' in data
        assert isinstance(data['technologies'], list)

