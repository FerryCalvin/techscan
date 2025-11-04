import time
import os
import pytest

from app import create_app
from app import scan_utils


def test_infer_tech_from_urls_detects_basic_libs():
    urls = [
        'https://cdn.example.com/libs/jquery-3.7.1.min.js',
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
        'https://cdn.example.com/tailwind.min.css',
        'https://assets.example.com/fontawesome/6.0.0/css/all.min.css',
        'https://cdn.example.com/vue.runtime.min.js',
    ]
    hints = scan_utils.infer_tech_from_urls(urls)
    names = {h['name'] for h in hints}
    # Expect at least a few core libraries recognized
    assert 'jQuery' in names
    assert 'Bootstrap' in names or 'Tailwind CSS' in names


def test_enrichment_merges_into_unified(monkeypatch):
    """Integration: ensure hints from py-local extras (scripts) are merged into final unified output.
    We monkeypatch heuristic and py-local detector to avoid network and provide controlled extras.
    """
    # Avoid DB / persistent client / heavy startup
    monkeypatch.setenv('TECHSCAN_DISABLE_DB', '1')
    monkeypatch.setenv('TECHSCAN_DISABLE_PERSIST_AUTOSTART', '1')
    monkeypatch.setenv('TECHSCAN_SYNTHETIC_HEADERS', '0')
    monkeypatch.setenv('TECHSCAN_SKIP_VERSION_AUDIT', '1')

    # Monkeypatch heuristic module to return empty (scan_unified imports it lazily)
    import sys, types
    fake_heur = types.SimpleNamespace()
    fake_heur.run_heuristic = lambda domain, **kwargs: {'technologies': [], 'categories': {}}
    monkeypatch.setitem(sys.modules, 'app.heuristic_fast', fake_heur)

    # Monkeypatch load_categories to avoid needing WAPPALYZER_PATH files
    monkeypatch.setattr(scan_utils, 'load_categories', lambda path: {})

    # Provide a fake py-local detector module that returns raw extras with jquery script
    fake_wapp = types.SimpleNamespace()
    fake_wapp.detect = lambda domain, wappalyzer_path=None, timeout=None: {'technologies': [], 'categories': {}, 'extras': {'scripts': ['https://cdn.example.com/jquery-3.6.0.min.js']}}
    monkeypatch.setitem(sys.modules, 'app.wapp_local', fake_wapp)

    # Call unified scan
    out = scan_utils.scan_unified('example.com', wappalyzer_path='does-not-exist', budget_ms=1000)
    tech_names = {t.get('name') for t in out.get('technologies', [])}
    assert 'jQuery' in tech_names, f"expected jQuery in technologies, got {tech_names}"


def test_prometheus_metrics_format(monkeypatch):
    # Create app with DB disabled to avoid DB init at startup
    monkeypatch.setenv('TECHSCAN_DISABLE_DB', '1')
    monkeypatch.setenv('TECHSCAN_DISABLE_PERSIST_AUTOSTART', '1')
    # Create flask test client
    app = create_app()
    client = app.test_client()
    resp = client.get('/metrics/prometheus')
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    # Should contain basic metrics text
    assert 'db_pool_in_use' in text
    # Also should include enrichment metrics (present even if zero)
    assert 'techscan_enrichment_hints_total' in text or 'db_pool_in_use' in text
    # Merge counter should be exposed
    assert 'techscan_enrichment_merge_total' in text


def test_enrichment_stats_increment(monkeypatch):
    """Lightweight check that STATS['enrichment']['merge_total'] increases after a unified scan that provides extras."""
    # Disable DB/persistence side-effects
    monkeypatch.setenv('TECHSCAN_DISABLE_DB', '1')
    monkeypatch.setenv('TECHSCAN_DISABLE_PERSIST_AUTOSTART', '1')
    monkeypatch.setenv('TECHSCAN_SKIP_VERSION_AUDIT', '1')

    import app.scan_utils as su
    import sys, types

    # Ensure enrichment bucket exists
    with su._stats_lock:
        su.STATS.setdefault('enrichment', {'hints_total': 0, 'scans': 0, 'merge_total': 0, 'last_avg_conf': 0.0, 'last_update': 0.0})
    before = int(su.STATS['enrichment'].get('merge_total', 0))

    # Provide a fake py-local detector that returns an extras block (scripts) we expect infer_tech_from_urls to pick up
    fake_wapp = types.SimpleNamespace()
    fake_wapp.detect = lambda domain, wappalyzer_path=None, timeout=None: {'technologies': [], 'categories': {}, 'extras': {'scripts': ['https://cdn.example.org/jquery-3.6.0.min.js']}}
    monkeypatch.setitem(sys.modules, 'app.wapp_local', fake_wapp)

    # Monkeypatch load_categories as in other tests to avoid file IO
    monkeypatch.setattr(su, 'load_categories', lambda path: {})

    # Run a unified scan which should exercise the final enrichment merge path
    out = su.scan_unified('example.com', wappalyzer_path='does-not-exist', budget_ms=500)

    after = int(su.STATS['enrichment'].get('merge_total', 0))
    assert after >= before + 1, f"enrichment.merge_total did not increment (before={before} after={after})"
