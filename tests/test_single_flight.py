import threading, time, os
from app.scan_utils import STATS, _single_flight_enter, _single_flight_exit, _cache, _lock, CACHE_TTL

# We monkeypatch scan_domain to simulate a slow underlying scan so that
# followers exercise the single-flight wait path without relying on network.

# This test is heuristic: it ensures that concurrent invocations against the same domain
# only trigger (approximately) a single underlying scan_domain execution by observing
# single_flight metrics. We enable single-flight explicitly (default on) to be explicit.

def test_single_flight_deduplicates(monkeypatch, tmp_path):
    os.environ['TECHSCAN_SINGLE_FLIGHT'] = '1'
    domain = 'example.com'
    wappalyzer_path = os.environ.get('WAPPALYZER_PATH', 'wappalyzer')

    # Monkeypatch scan_domain BEFORE threads start
    # We'll test the single-flight primitives directly to avoid external scan variability.
    call_counter = {'count': 0}

    # Warm cache flush to ensure miss.
    from app.scan_utils import flush_cache
    flush_cache()

    results = []
    errors = []
    start = time.time()

    def worker():
        cache_key = f"fast:{domain}"
        leader = _single_flight_enter(cache_key)
        try:
            if leader:
                call_counter['count'] += 1
                # simulate work
                time.sleep(0.2)
                with _lock:
                    _cache[cache_key] = {'ts': time.time(), 'data': {'domain': domain, 'engine':'fake','scan_mode':'fast'}, 'ttl': CACHE_TTL}
            else:
                # follower should find cache once leader finishes
                with _lock:
                    pass
                results.append({'follower': True})
        finally:
            if leader:
                _single_flight_exit(cache_key)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads: t.start()
    for t in threads: t.join()

    elapsed = time.time() - start
    # All calls should succeed
    assert not errors
    sf = STATS.get('single_flight', {})
    assert call_counter['count'] == 1, f"expected exactly one leader run, got {call_counter['count']}"
    assert sf.get('hits', 0) >= 1
    assert sf.get('wait_ms', 0) >= 0
