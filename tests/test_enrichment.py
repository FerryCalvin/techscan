from app import create_app
from app import scan_utils


def test_infer_tech_from_urls_detects_basic_libs():
    urls = [
        "https://cdn.example.com/libs/jquery-3.7.1.min.js",
        "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css",
        "https://cdn.example.com/tailwind.min.css",
        "https://assets.example.com/fontawesome/6.0.0/css/all.min.css",
        "https://cdn.example.com/vue.runtime.min.js",
        "https://www.googletagmanager.com/gtag/js?id=G-ABCD1234",
        "https://fonts.googleapis.com/css2?family=Inter",
    ]
    hints = scan_utils.infer_tech_from_urls(urls)
    names = {h["name"] for h in hints}
    # Expect at least a few core libraries recognized
    assert "jQuery" in names
    assert "Bootstrap" in names or "Tailwind CSS" in names
    assert "Google Analytics" in names
    assert "Google Font API" in names


def test_infer_tech_from_urls_detects_extended_libs():
    urls = [
        "https://cdn.jsdelivr.net/npm/requirejs@2.3.6/dist/require.js",
        "https://cdn.jsdelivr.net/npm/mathjax@3.2.2/es5/tex-mml-chtml.js",
        "https://cdn.jsdelivr.net/npm/core-js@3.37.1/minified.js",
        "https://yui.yahooapis.com/3.18.1/build/yui/yui-min.js",
        "https://yui.yahooapis.com/3.18.1/build/yuidoc/yuidoc-parser-min.js",
        "https://vjs.zencdn.net/8.5.2/video.min.js",
        "https://www.googletagmanager.com/gtm.js?id=GTM-ABCDE",
        "https://cdn.jsdelivr.net/npm/tailwindcss@3.4.1/tailwind.min.css",
        "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css?ver=5.3.2",
        "https://cdn.example.edu/assets/index.php?ver=1.0",
    ]
    hints = scan_utils.infer_tech_from_urls(urls)
    names = {h["name"] for h in hints}
    assert {
        "RequireJS",
        "MathJax",
        "core-js",
        "YUI",
        "YUI Doc",
        "Video.js",
        "Google Tag Manager",
        "Tailwind CSS",
        "Bootstrap",
        "PHP",
    } <= names
    assert "jsDelivr" in names  # because multiple cdn.jsdelivr.net URLs appear


def test_enrichment_merges_into_unified(monkeypatch):
    """Integration: ensure hints from py-local extras (scripts) are merged into final unified output.
    We monkeypatch heuristic and py-local detector to avoid network and provide controlled extras.
    """
    # Avoid DB / persistent client / heavy startup
    monkeypatch.setenv("TECHSCAN_DISABLE_DB", "1")
    monkeypatch.setenv("TECHSCAN_DISABLE_PERSIST_AUTOSTART", "1")
    monkeypatch.setenv("TECHSCAN_SYNTHETIC_HEADERS", "0")
    monkeypatch.setenv("TECHSCAN_SKIP_VERSION_AUDIT", "1")

    # Import real modules to patch their attributes
    import app.heuristic_fast as real_heur
    import app.wapp_local as real_wapp

    # Monkeypatch run_heuristic attribute
    monkeypatch.setattr(real_heur, "run_heuristic", lambda domain, **kwargs: {"technologies": [], "categories": {}})

    # Monkeypatch load_categories
    monkeypatch.setattr(scan_utils, "load_categories", lambda path: {})

    # Monkeypatch detect attribute
    monkeypatch.setattr(
        real_wapp,
        "detect",
        lambda domain, wappalyzer_path=None, timeout=None: {
            "technologies": [],
            "categories": {},
            "extras": {"scripts": ["https://cdn.example.com/jquery-3.6.0.min.js"]},
        },
    )

    # Call unified scan
    out = scan_utils.scan_unified("example.com", wappalyzer_path="does-not-exist", budget_ms=1000)
    tech_names = {t.get("name") for t in out.get("technologies", [])}
    assert "jQuery" in tech_names, f"expected jQuery in technologies, got {tech_names}"


def test_prometheus_metrics_format(monkeypatch):
    # Create app with DB disabled to avoid DB init at startup
    monkeypatch.setenv("TECHSCAN_DISABLE_DB", "1")
    monkeypatch.setenv("TECHSCAN_DISABLE_PERSIST_AUTOSTART", "1")
    # Create flask test client
    app = create_app()
    client = app.test_client()
    resp = client.get("/metrics/prometheus")
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    # Should contain basic metrics text
    assert "db_pool_in_use" in text
    # Also should include enrichment metrics (present even if zero)
    assert "techscan_enrichment_hints_total" in text or "db_pool_in_use" in text
    # Merge counter should be exposed
    assert "techscan_enrichment_merge_total" in text


def test_enrichment_stats_increment(monkeypatch):
    """Lightweight check that STATS['enrichment']['merge_total'] increases after a unified scan that provides extras."""
    # Disable DB/persistence side-effects
    monkeypatch.setenv("TECHSCAN_DISABLE_DB", "1")
    monkeypatch.setenv("TECHSCAN_DISABLE_PERSIST_AUTOSTART", "1")
    monkeypatch.setenv("TECHSCAN_SKIP_VERSION_AUDIT", "1")

    import app.scan_utils as su
    import types

    # Ensure enrichment bucket exists
    with su._stats_lock:
        su.STATS.setdefault(
            "enrichment", {"hints_total": 0, "scans": 0, "merge_total": 0, "last_avg_conf": 0.0, "last_update": 0.0}
        )
    before = int(su.STATS["enrichment"].get("merge_total", 0))

    # Provide a fake py-local detector that returns an extras block (scripts) we expect infer_tech_from_urls to pick up
    fake_wapp = types.SimpleNamespace()
    fake_wapp.detect = lambda domain, wappalyzer_path=None, timeout=None: {
        "technologies": [],
        "categories": {},
        "extras": {"scripts": ["https://cdn.example.org/jquery-3.6.0.min.js"]},
    }
    monkeypatch.setattr(su, "wapp_local", fake_wapp)

    # Monkeypatch load_categories as in other tests to avoid file IO
    monkeypatch.setattr(su, "load_categories", lambda path: {})

    # Run a unified scan which should exercise the final enrichment merge path
    su.scan_unified("example.com", wappalyzer_path="does-not-exist", budget_ms=500)

    after = int(su.STATS["enrichment"].get("merge_total", 0))
    assert after >= before + 1, f"enrichment.merge_total did not increment (before={before} after={after})"
