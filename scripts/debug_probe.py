from playwright.sync_api import sync_playwright
import time

URL = 'http://localhost:5000/stats'

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

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()
    # seed localStorage before page load
    page.add_init_script("window.localStorage.setItem('techscan_lastStats', %s);" % (repr(str(snapshot).replace("'", '"'))))
    page.goto(URL, wait_until='domcontentloaded')
    time.sleep(1.5)
    row = page.query_selector('#top-tech-body tr')
    if not row:
        print('No row found')
    else:
        br = page.evaluate('''(el) => {
            var r = el.getBoundingClientRect();
            var cx = Math.round(r.left + r.width/2);
            var cy = Math.round(r.top + r.height/2);
            var comp = window.getComputedStyle(el);
            var pts = [];
            try{ var els = document.elementsFromPoint(cx, cy); els.slice(0,6).forEach(function(e){ pts.push({tag: e.tagName, id: e.id||null, cls: e.className||null, z: window.getComputedStyle(e).zIndex}); }); }catch(e){ pts.push({error: String(e)}); }
            return {rect:{left:r.left,top:r.top,width:r.width,height:r.height}, point:{x:cx,y:cy}, computed:{display:comp.display, visibility:comp.visibility, opacity:comp.opacity, zIndex:comp.zIndex}, topElements:pts, ua:navigator.userAgent};
        }''', row)
        import json
        print(json.dumps(br, indent=2))
    browser.close()
