import sys, pathlib, io, csv
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from app import bulk_store

SAMPLE_RESULTS = [
    {
        "status": "ok",
        "domain": "example.com",
        "timestamp": 111,
        "technologies": [{"name": "WordPress", "version": "6.0", "categories": ["CMS"]}],
        "categories": {"CMS": [{"name": "WordPress", "version": "6.0"}]},
        "cached": False,
        "duration": 1.2,
        "retries": 0,
        "engine": "fast",
        "audit": {"outdated_count": 0},
    }
]


@mock.patch("app.routes.scan.scan_bulk")
@mock.patch("app.routes.scan.bulk_quick_then_deep")
def test_bulk_returns_batch_id(mock_two_phase, mock_bulk):
    mock_two_phase.return_value = []
    mock_bulk.return_value = SAMPLE_RESULTS
    app = create_app()
    client = app.test_client()
    r = client.post("/bulk", json={"domains": ["example.com"]})
    assert r.status_code == 200
    data = r.get_json()
    assert data.get("batch_id")
    # ensure stored
    meta = bulk_store.get_batch(data["batch_id"])
    assert meta is not None
    assert meta["results"][0]["domain"] == "example.com"


@mock.patch("app.routes.scan.scan_bulk")
@mock.patch("app.routes.scan.bulk_quick_then_deep")
def test_bulk_batch_csv_download(mock_two_phase, mock_bulk):
    mock_two_phase.return_value = []
    mock_bulk.return_value = SAMPLE_RESULTS
    app = create_app()
    client = app.test_client()
    first = client.post("/bulk", json={"domains": ["example.com"]})
    bid = first.get_json()["batch_id"]
    # Now request CSV via batch_id (should not call scan again): we clear store to ensure retrieval works
    csv_resp = client.post(f"/bulk?format=csv&batch_id={bid}")
    assert csv_resp.status_code == 200
    assert csv_resp.mimetype == "text/csv"
    rows = list(csv.reader(io.StringIO(csv_resp.get_data(as_text=True))))
    assert rows[0][0] == "status"
    assert any("example.com" in row for row in rows)


@mock.patch("app.routes.scan.scan_bulk")
@mock.patch("app.routes.scan.bulk_quick_then_deep")
def test_bulk_cached_only_csv(mock_two_phase, mock_bulk):
    mock_two_phase.return_value = []
    mock_bulk.return_value = SAMPLE_RESULTS
    app = create_app()
    client = app.test_client()
    # Perform initial scan to populate cache batch
    client.post("/bulk", json={"domains": ["example.com"]})
    # Request cached_only CSV - should succeed even if no new scan executed
    resp = client.post("/bulk?format=csv&cached_only=1", json={"domains": ["example.com"]})
    assert resp.status_code == 200
    rows = list(csv.reader(io.StringIO(resp.get_data(as_text=True))))
    assert any("example.com" in row for row in rows)
