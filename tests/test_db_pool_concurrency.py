import os
import time
import uuid
import threading
import pytest


requires_db = pytest.mark.skipif(
    os.environ.get('TECHSCAN_DISABLE_DB','0') == '1' or not os.environ.get('TECHSCAN_DB_URL'),
    reason='TECHSCAN_DB_URL must be set and DB enabled for pool concurrency test'
)


@requires_db
def test_concurrent_save_scan_pool_basic():
    from app import db as _db

    _db.ensure_schema()
    dom = f"pool-{uuid.uuid4().hex[:10]}.example"

    errors: list[str] = []
    def worker(i: int):
        try:
            t0 = time.time()
            res = {
                'domain': dom,
                'scan_mode': 'fast',
                'started_at': t0,
                'finished_at': t0 + 0.01,
                'duration': 0.01,
                'technologies': [
                    {'name': 'Flask', 'version': None, 'categories': ['Web frameworks']},
                ],
                'categories': {'Web frameworks': 1},
            }
            _db.save_scan(res, from_cache=False, timeout_used=0)
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"errors during concurrent save: {errors}"

    # Verify rows exist (at least one scan and a domain_tech entry)
    techs = _db.get_domain_techs(dom)
    assert any(t['tech_name'] == 'Flask' for t in techs)

    # Cleanup best-effort
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scans WHERE domain=%s", (dom,))
                cur.execute("DELETE FROM domain_techs WHERE domain=%s", (dom,))
            conn.commit()
    except Exception:
        pass
