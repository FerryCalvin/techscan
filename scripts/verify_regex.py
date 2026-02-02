
import re

patterns = [
    ("jQuery", re.compile(r"jquery(?:[.-](?:\d[\w.-]*|min|slim|ui))?\.js", re.I)),
    ("Popper", re.compile(r"popper(?:.*)?\.js", re.I)),
    ("Bootstrap", re.compile(r"bootstrap(?:.*)?\.(?:css|js)", re.I)),
    ("SweetAlert", re.compile(r"sweetalert(?:2)?(?:.*)?\.js", re.I)),
]

test_urls = [
    "https://example.com/js/jquery.min.js",
    "https://example.com/js/jquery-3.6.0.min.js",
    "https://example.com/js/jquery.js",
    "https://example.com/assets/popper.min.js",
    "https://example.com/dist/sweetalert2.all.min.js",
    "https://example.com/bootstrap.min.css",
]

print("Testing Regex Patterns:")
for url in test_urls:
    matched = []
    for name, pat in patterns:
        if pat.search(url):
            matched.append(name)
    print(f"URL: {url} -> Matched: {matched}")
