import sys
import types
import pytest

from app import scan_utils


def test_infer_tech_from_urls_detects_basic_libs():
    urls = [
        "https://cdn.com/jquery.min.js",
        "https://cdn.com/bootstrap.min.css",
        "https://cdn.com/gtag.js",
    ]
    hints = scan_utils.infer_tech_from_urls(urls)
    names = {h["name"] for h in hints}
    assert {"jQuery", "Bootstrap", "Google Tag Manager"} & names


def test_enrichment_merges_into_unified(monkeypatch):
    assert hasattr(scan_utils, 'scan_unified')
    assert not hasattr(scan_utils, 'run_py_local')

    dummy_raw = {"extras": {"network": ["https://cdn.com/jquery.min.js"]}}

    fake = types.SimpleNamespace()
    # Return raw extras at top-level so scan_unified normalize + preservation picks them up
    fake.detect = lambda domain, wappalyzer_path=None, timeout=None: {"technologies": [], "extras": {"network": ["https://cdn.com/jquery.min.js"]}}
    monkeypatch.setitem(sys.modules, 'app.wapp_local', fake)

    monkeypatch.setattr(scan_utils, 'load_categories', lambda path: {})

    res = scan_utils.scan_unified('example.com', wappalyzer_path='wappalyzer', budget_ms=1000)
    tech_names = {t.get('name') for t in res.get('technologies', [])}
    assert 'jQuery' in tech_names
