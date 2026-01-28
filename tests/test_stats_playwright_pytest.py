

def test_stats_page_fallback_and_modal(page):
    """Using pytest-playwright's `page` fixture: simulate API failures and verify fallback/modal behavior (sync style)."""
    url = 'http://localhost:5000/stats'
    # Seed localStorage with a small snapshot so client-side fallback has data
    snapshot = {
        "scans_total": 42,
        "top_technologies": [
            {
                "tech": "PlaywrightTestLib",
                "category": "Library",
                "count": 3,
                "last_seen": 1700000000,
                "domains": ["example.com","example.org"],
                "history": [{"t":"w-1","v":1},{"t":"w0","v":3}]
            }
        ]
    }
    # add_init_script runs before any page scripts and can seed localStorage
    page.add_init_script("window.localStorage.setItem('techscan_lastStats', %s);" % (repr(str(snapshot).replace("'", '"'))))

    # Abort the main API endpoints to simulate outage
    page.route('**/api/stats', lambda route: route.abort())
    page.route('**/api/system_health', lambda route: route.abort())

    resp = page.goto(url, wait_until='domcontentloaded')
    assert resp.status == 200

    # give client some time to attempt fetches and hit fallback
    page.wait_for_timeout(1500)

    # If there's no snapshot, the UI should not crash; ensure key elements exist
    assert page.query_selector('#total-domains') is not None

    # Try to click first tech row if present and ensure modal becomes visible
    row = page.query_selector('#top-tech-body tr')
    if row:
        row.click()
        # wait a bit for modal animation/DOM changes
        page.wait_for_timeout(500)
        modal_display = page.evaluate("getComputedStyle(document.getElementById('techModal')).display")
        assert modal_display != 'none'
