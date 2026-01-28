import os
import time
import uuid
import pytest


requires_db = pytest.mark.skipif(
    os.environ.get("TECHSCAN_DISABLE_DB", "0") == "1" or not os.environ.get("TECHSCAN_DB_URL"),
    reason="TECHSCAN_DB_URL must be set and DB enabled for integration tests",
)


@requires_db
def test_schema_and_basic_persistence():
    # Import late so env is already loaded
    from app import db as _db

    # Ensure schema exists
    _db.ensure_schema()

    # Unique domain key for isolation
    dom = f"it-{uuid.uuid4().hex[:12]}.example"
    started = time.time() - 0.5
    finished = time.time()

    result = {
        "domain": dom,
        "scan_mode": "fast",
        "started_at": started,
        "finished_at": finished,
        "duration": finished - started,
        "technologies": [
            {"name": "Flask", "version": "3.0.3", "categories": ["Web frameworks"]},
            {"name": "Python", "version": None, "categories": ["Programming languages"]},
        ],
        "categories": {"Web frameworks": 1, "Programming languages": 1},
    }

    # Persist and then query back
    _db.save_scan(result, from_cache=False, timeout_used=0)

    # History must contain the insert
    hist = _db.history(dom, limit=5)
    assert isinstance(hist, list) and len(hist) >= 1

    # Domain techs should have at least Flask entry
    techs = _db.get_domain_techs(dom)
    names = {t["tech_name"] for t in techs}
    assert "Flask" in names

    # Search API should find the domain by tech name
    rows = _db.search_tech(tech="Flask", limit=50)
    assert any(r["domain"] == dom for r in rows)

    # Cleanup: remove rows for this domain to keep DB tidy (best-effort)
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scans WHERE domain=%s", (dom,))
                cur.execute("DELETE FROM domain_techs WHERE domain=%s", (dom,))
            conn.commit()
    except Exception:
        # Best-effort cleanup only
        pass
