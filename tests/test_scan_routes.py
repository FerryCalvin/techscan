import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app


def test_unified_used_for_deep(monkeypatch):
    # Keep DB out of the loop for tests
    monkeypatch.setenv("TECHSCAN_DISABLE_DB", "1")
    # Ensure unified mode is enabled for the route decision
    monkeypatch.setenv("TECHSCAN_UNIFIED", "1")

    app = create_app()
    try:
        app.extensions.get("limiter").enabled = False  # type: ignore
    except Exception:
        pass
    client = app.test_client()

    # Provide a deterministic fake result for the unified pipeline so the test
    # checks that the route invoked scan_unified rather than falling back
    # to other code paths.
    import time as _time

    fake_result = {
        "domain": "example.com",
        "technologies": [],
        "engine": "unified",
        "timestamp": int(_time.time()),
        "started_at": int(_time.time()),
        "finished_at": int(_time.time()),
    }

    # Patch the symbol imported in the route module so the handler uses our fake
    monkeypatch.setattr("app.routes.scan.scan_unified", lambda domain, wpath, budget_ms=6000: fake_result)

    resp = client.get("/scan?domain=example.com&deep=1")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)
    assert data.get("engine") == "unified"
