import types


def test_enrichment_merge_and_dedupe(monkeypatch):
    """Simulate nested extras and duplicate tech entries; ensure merge works and dedupes."""
    # Disable persistence and DB side-effects
    monkeypatch.setenv("TECHSCAN_DISABLE_DB", "1")
    monkeypatch.setenv("TECHSCAN_DISABLE_PERSIST_AUTOSTART", "1")
    monkeypatch.setenv("TECHSCAN_SKIP_VERSION_AUDIT", "1")

    import app.scan_utils as su

    # Ensure categories loader doesn't try to read files
    monkeypatch.setattr(su, "load_categories", lambda path: {})

    # Fake scan_domain to return an Apache tech (this will create a duplicate when py-local also returns Apache)
    def fake_scan_domain(domain, wappalyzer_path=None, timeout=None, retries=0, full=False):
        return {
            "domain": domain,
            "technologies": [{"name": "Apache", "version": "2.4.41", "categories": ["Web servers"], "confidence": 50}],
            "categories": {"Web servers": [{"name": "Apache", "version": "2.4.41"}]},
        }

    monkeypatch.setattr(su, "scan_domain", fake_scan_domain)

    # Fake py-local detector to include nested extras and duplicate Apache tech
    fake_wapp = types.SimpleNamespace()

    def fake_detect(domain, wappalyzer_path=None, timeout=None):
        return {
            "technologies": [{"name": "Apache", "version": "2.4.41", "categories": ["Web servers"], "confidence": 50}],
            # nested extras shapes: raw.extras and data.extras
            "raw": {"extras": {"network": ["https://cdn.com/jquery-3.6.0.min.js"]}},
            "data": {"extras": {"scripts": ["https://cdn.com/bootstrap-4.5.3.js"]}},
        }

    fake_wapp.detect = fake_detect
    import app.wapp_local as real_wapp

    monkeypatch.setattr(real_wapp, "detect", fake_detect)

    # Snapshot enrichment counter
    before = su.STATS.setdefault("enrichment", {}).get("merge_total", 0)

    out = su.scan_unified("example.com", wappalyzer_path="does-not-exist", budget_ms=2000)

    names = [t.get("name") for t in out.get("technologies", [])]
    # Check enrichment hints were merged
    assert "jQuery" in names, f"expected jQuery in {names}"
    assert "Bootstrap" in names, f"expected Bootstrap in {names}"
    # Apache should be present once (deduped)
    assert names.count("Apache HTTP Server") == 1, (
        f"expected single Apache HTTP Server entry, got {names.count('Apache HTTP Server')}"
    )

    after = su.STATS.get("enrichment", {}).get("merge_total", 0)
    assert after >= before + 1
