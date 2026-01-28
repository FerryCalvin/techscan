from app import create_app


def make_client(monkeypatch):
    # Ensure DB disabled to run tests without Postgres
    monkeypatch.setenv("TECHSCAN_DISABLE_DB", "1")
    app = create_app()
    app.testing = True
    return app.test_client()


def test_admin_db_pool_endpoint(monkeypatch):
    client = make_client(monkeypatch)
    r = client.get("/admin/db_pool")
    assert r.status_code == 200
    data = r.get_json()
    assert "pool" in data


def test_prometheus_metrics_endpoint(monkeypatch):
    client = make_client(monkeypatch)
    r = client.get("/metrics/prometheus")
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert "db_pool_in_use" in text
    assert "db_pool_available" in text
    assert "db_pool_max_size" in text
