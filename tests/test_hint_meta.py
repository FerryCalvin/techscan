from app.scan_utils import _attach_raw_hint_meta, _apply_hint_meta_detections


def test_attach_raw_hint_meta_merges_into_existing_bucket():
    payload = {
        "raw": {
            "_techscan_hint_meta": {
                "runtime_hits": [{"name": "Next.js", "label": "next-data-inline"}],
                "import_map": True,
            }
        },
        "tiered": {"hint_meta": {"cookie_hits": [{"name": "WordPress", "label": "wordpress_cookie"}]}},
    }
    _attach_raw_hint_meta(payload)
    tiered = payload["tiered"]
    hint_meta = tiered["hint_meta"]
    assert hint_meta["import_map"] is True
    assert hint_meta["cookie_hits"] == [{"name": "WordPress", "label": "wordpress_cookie"}]
    assert hint_meta["runtime_hits"] == [{"name": "Next.js", "label": "next-data-inline"}]
    assert tiered["hint_meta_source"] == "node-runtime"


def test_attach_raw_hint_meta_initializes_when_empty():
    payload = {
        "raw": {
            "_techscan_hint_meta": {
                "cookie_hits": [{"name": "Laravel", "label": "laravel_session"}],
                "manifest_hits": ["https://example.com/manifest.json"],
            }
        }
    }
    _attach_raw_hint_meta(payload)
    hint_meta = payload["tiered"]["hint_meta"]
    assert hint_meta["cookie_hits"][0]["name"] == "Laravel"
    assert hint_meta["manifest_hits"] == ["https://example.com/manifest.json"]


def test_hint_meta_detection_adds_jquery_migrate():
    payload = {
        "technologies": [],
        "categories": {},
        "raw": {"extras": {"scripts": ["https://example.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.0"]}},
    }
    _apply_hint_meta_detections(payload)
    tech_names = {t["name"] for t in payload["technologies"]}
    assert "jQuery Migrate" in tech_names
    tech = next(t for t in payload["technologies"] if t["name"] == "jQuery Migrate")
    assert tech["version"] == "3.4.0"
    assert payload["categories"]["JavaScript libraries"][0]["name"] == "jQuery Migrate"


def test_hint_meta_detection_uses_body_class_for_hello_elementor():
    payload = {
        "technologies": [],
        "categories": {},
        "raw": {"extras": {"scripts": [], "links": [], "body_classes": ["site", "hello-elementor"]}},
    }
    _apply_hint_meta_detections(payload)
    tech_names = {t["name"] for t in payload["technologies"]}
    assert "Hello Elementor Theme" in tech_names


def test_hint_meta_detection_detects_wpml_and_multisite():
    payload = {
        "technologies": [],
        "categories": {},
        "raw": {
            "extras": {
                "scripts": [
                    "https://example.com/wp-content/plugins/sitepress-multilingual-cms/res/js/sitepress.js?ver=4.6.3"
                ],
                "links": ["https://example.com/wp-content/uploads/sites/5/hero.css"],
            }
        },
    }
    _apply_hint_meta_detections(payload)
    tech_names = {t["name"] for t in payload["technologies"]}
    assert "WordPress Multilingual Plugin (WPML)" in tech_names
    assert "WordPress Multisite" in tech_names


def test_hint_meta_detection_updates_existing_wpml_version():
    payload = {
        "technologies": [{"name": "WPML", "version": None, "categories": [], "confidence": 50, "evidence": []}],
        "categories": {},
        "raw": {
            "extras": {
                "scripts": [
                    "https://example.com/wp-content/plugins/sitepress-multilingual-cms/res/js/sitepress.js?ver=4.6.3"
                ]
            }
        },
    }
    _apply_hint_meta_detections(payload)
    matches = [t for t in payload["technologies"] if t["name"] == "WPML"]
    assert len(matches) == 1
    assert matches[0]["version"] == "4.6.3"
