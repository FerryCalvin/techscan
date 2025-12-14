"""Lightweight heuristic pre-scan (Tier 0 / Stage 1)

Goal: Very quick (sub-second to ~2s) probing using HEAD + simple GET to extract
high-priority signals BEFORE launching full Wappalyzer (Chromium) scan.

Priorities:
 1. CMS / Framework (WordPress, Joomla, Drupal, Laravel, CodeIgniter, Next.js, Nuxt, React, Vue)
 2. WordPress Plugins (Elementor, WooCommerce, Contact Form 7, Yoast, WPForms, Wordfence, WP Rocket, RevSlider)
 3. Core JS Libraries (jQuery, React, Vue, Angular, Alpine.js)
 4. Web Server / Reverse proxy (Server header) + Security (HSTS)
 5. Version extraction opportunistic (meta generator, ?ver=, filenames -x.y.z)
 6. DB exposure hints (phpMyAdmin, adminer) (very low confidence)

Returns structure:
{
  'domain': 'example.com',
  'started_at': <epoch>,
  'finished_at': <epoch>,
  'duration': float,
  'scan_mode': 'fast',
  'engine': 'heuristic-tier0',
  'technologies': [ {name, version, categories, confidence}... ],
  'categories': {CategoryName: [ {name, version} ]},
  'tiered': {
      'stage': 'heuristic',
      'early_return': bool,
      'reason': 'enough_priority_techs' | 'timeout' | 'minimal' | 'error'
  }
}

Early return rule (so Wappalyzer full scan skipped):
 - If at least one CMS/framework OR (>=2 distinct priorities total) found.
 - Or if explicit WordPress indicator (plugin dir + generator) found.
 - Otherwise we just attach partial result under key 'pre_heuristic' and continue to full scan.

Implementation notes:
 - Uses stdlib only (urllib / http.client) to avoid new deps.
 - Simple regex scanning limited to first ~250KB of HTML.
 - Timeout budget split: head_timeout + get_timeout (default total <= 2s configurable by env TECHSCAN_TIERED_BUDGET_MS)
"""
from __future__ import annotations
import time, re, http.client, socket, ssl, gzip, zlib
from typing import Dict, Any, List, Tuple

try:
    import brotli  # optional
except ImportError:  # pragma: no cover - optional dependency
    brotli = None

CMS_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ('WordPress', re.compile(r'wp-content/|wp-includes/|<meta[^>]+name=["\']generator["\'][^>]+wordpress', re.I)),
    ('Joomla', re.compile(r'/media/system/js/|Joomla!|<meta[^>]+generator["\'][^>]+joomla', re.I)),
    ('Joomla', re.compile(r'/components/com_[a-z0-9_]+', re.I)),
    ('Drupal', re.compile(r'/sites/(?:default|all)/|drupal-settings-json|<meta[^>]+name=["\']Generator["\'][^>]+Drupal', re.I)),
    ('Laravel', re.compile(r'laravel_session|/vendor/laravel', re.I)),
    ('CodeIgniter', re.compile(r'CodeIgniter', re.I)),
    ('Next.js', re.compile(r'_next/static', re.I)),
    ('Nuxt.js', re.compile(r'_nuxt/', re.I)),
    ('React', re.compile(r'data-reactroot|react\.development\.js', re.I)),
    ('Vue.js', re.compile(r'Vue\.config|vue\.runtime', re.I)),
    ('Angular', re.compile(r'angular(?:\.min)?\.js', re.I)),
    ('Alpine.js', re.compile(r'alpine(?:\.min)?\.js', re.I)),
]

WP_PLUGIN_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # Populer umum
    ('Elementor', re.compile(r'wp-content/plugins/elementor', re.I)),
    ('WooCommerce', re.compile(r'wp-content/plugins/woocommerce', re.I)),
    ('Contact Form 7', re.compile(r'wp-content/plugins/contact-form-7', re.I)),
    ('Yoast SEO', re.compile(r'wp-content/plugins/(?:wordpress-seo|wp-seo)', re.I)),
    ('WPForms', re.compile(r'wp-content/plugins/wpforms', re.I)),
    ('Wordfence', re.compile(r'wp-content/plugins/wordfence', re.I)),
    ('WP Rocket', re.compile(r'wp-content/plugins/wp-rocket', re.I)),
    ('Revolution Slider', re.compile(r'wp-content/plugins/revslider', re.I)),
    # Tambahan
    ('Advanced Custom Fields', re.compile(r'wp-content/plugins/advanced-custom-fields', re.I)),
    ('Jetpack', re.compile(r'wp-content/plugins/jetpack', re.I)),
    ('WordPress Multilingual Plugin (WPML)', re.compile(r'wp-content/plugins/sitepress-multilingual-cms', re.I)),
    ('Polylang', re.compile(r'wp-content/plugins/polylang', re.I)),
    ('Rank Math SEO', re.compile(r'wp-content/plugins/seo-by-rank-math', re.I)),
    ('UpdraftPlus', re.compile(r'wp-content/plugins/updraftplus', re.I)),
    ('Slider Revolution', re.compile(r'wp-content/plugins/revslider', re.I)),
]

WP_THEME_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ('Hello Elementor Theme', re.compile(r'wp-content/themes/hello-elementor', re.I))
]

LIB_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ('jQuery', re.compile(r'jquery[-\.](\d[\w\.\-]*)\.js', re.I)),
    ('jQuery Migrate', re.compile(r'jquery-migrate(?:\.min)?-(\d[\w\.\-]*)\.js', re.I)),
    ('React', re.compile(r'react(?:\.production)?(?:\.min)?\.js', re.I)),
    ('Vue.js', re.compile(r'vue(?:\.runtime)?(?:\.min)?\.js', re.I)),
    ('AngularJS', re.compile(r'angular(?:\.min)?\.js', re.I)),
    ('Alpine.js', re.compile(r'alpine(?:\.min)?\.js', re.I)),
]

# Database management panels exposure (low confidence, simple patterns)
DB_PANEL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ('phpMyAdmin', re.compile(r'phpmyadmin.+?(?:mysql|database)', re.I)),
    ('Adminer', re.compile(r'Adminer\s+(?:[0-9]+\.[0-9.]+)?', re.I)),
]

VERSION_FROM_QUERY = re.compile(r'[?&](?:ver|v|version)=(\d[\w\.\-]*)', re.I)
VERSION_IN_FILENAME = re.compile(r'-([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.\w{1,6}\b')
COMMENT_BANNER = re.compile(r'/\*!?\s*(bootstrap|tailwind(?:css)?|datatables)[^\n]*?v?(\d+\.\d+(?:\.\d+){0,2})', re.I)
NG_VERSION_ATTR = re.compile(r'ng-version="(\d+\.\d+(?:\.\d+)*)"', re.I)
NEXT_DATA_BUILDID = re.compile(r'__NEXT_DATA__"?\s*:\s*\{[^}]*?"buildId"\s*:\s*"([a-zA-Z0-9-_]+)"')
META_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
SERVER_HEADER = re.compile(r'([a-zA-Z0-9_-]+)(?:/([0-9][\w\.-]*))?')  # captures name/version pairs like nginx/1.22.1

PRIORITY_CATEGORIES = {
    'CMS': ['Content management systems','CMS'],
    'Frameworks': ['Web frameworks','JavaScript frameworks'],
    'Libraries': ['JavaScript libraries'],
    'Ecommerce': ['Ecommerce'],
    'Security': ['Security'],
    'Web servers': ['Web servers','Reverse proxies']
}

# Map heuristics to categories
CATEGORY_MAP = {
    'WordPress': ['Content management systems','CMS'],
    'Joomla': ['Content management systems','CMS'],
    'Drupal': ['Content management systems','CMS'],
    'Laravel': ['Web frameworks'],
    'CodeIgniter': ['Web frameworks'],
    'Next.js': ['Web frameworks'],
    'Nuxt.js': ['Web frameworks'],
    'React': ['JavaScript libraries'],
    'Vue.js': ['JavaScript libraries'],
    'Angular': ['JavaScript frameworks'],
    'AngularJS': ['JavaScript frameworks'],
    'Alpine.js': ['JavaScript libraries'],
    'jQuery': ['JavaScript libraries'],
    'Elementor': ['WordPress plugins'],
    'WooCommerce': ['Ecommerce','WordPress plugins'],
    'Contact Form 7': ['WordPress plugins'],
    'Yoast SEO': ['SEO','WordPress plugins'],
    'WPForms': ['WordPress plugins','Forms'],
    'Wordfence': ['Security','WordPress plugins'],
    'WP Rocket': ['Caching','WordPress plugins'],
    'Revolution Slider': ['Media','WordPress plugins'],
    'HSTS': ['Security'],
    'HP Smart': ['Device management'],
    'Apache': ['Web servers'],
    'Nginx': ['Web servers','Reverse proxies'],
    'Cloudflare': ['Reverse proxies','CDN'],
    'LiteSpeed': ['Web servers'],
    'OpenResty': ['Web servers','Reverse proxies'],
    'Caddy': ['Web servers','Reverse proxies'],
    'PHP': ['Programming languages'],
    'Express': ['Web frameworks','JavaScript frameworks'],
    'ASP.NET': ['Web frameworks'],
    'phpMyAdmin': ['Database management'],
    'Adminer': ['Database management'],
    'Gunicorn': ['Web servers','Application servers'],
    'uWSGI': ['Application servers'],
    'Fastly': ['CDN','Reverse proxies'],
    'Varnish': ['Reverse proxies','Caching'],
    'BitNinja': ['Security'],
    'Google reCAPTCHA': ['Security'],
    'IBM WebSphere': ['Application servers','Web servers'],
    'Shopify': ['Ecommerce'],
    'Livewire': ['JavaScript frameworks'],
    'Inertia.js': ['JavaScript frameworks'],
    'Svelte': ['JavaScript frameworks'],
    'SvelteKit': ['JavaScript frameworks'],
    'Remix': ['JavaScript frameworks'],
    'JBOSS Web': ['Application servers','Web servers'],
    'Symfony': ['Web frameworks'],
    'Django': ['Web frameworks'],
    'Python': ['Programming languages'],
    'Octane': ['Application servers','Web servers'],
    'Oracle ILOM': ['Device management'],
    'Import Maps': ['JavaScript tooling'],
    'Progressive Web App': ['Progressive web apps'],
    'Service Worker': ['Progressive web apps']
}

# Additional fingerprint sources beyond vanilla Wappalyzer signals
JS_RUNTIME_HINTS = [
    {'name': 'Next.js', 'pattern': re.compile(r'__NEXT_DATA__', re.I), 'reason': 'next-data-inline', 'confidence': 50},
    {'name': 'Nuxt.js', 'pattern': re.compile(r'__NUXT__', re.I), 'reason': 'nuxt-inline', 'confidence': 50},
    {'name': 'Svelte', 'pattern': re.compile(r'__SVELTE_HMR__', re.I), 'reason': 'svelte-hmr', 'confidence': 45},
    {'name': 'SvelteKit', 'pattern': re.compile(r'SvelteKit', re.I), 'reason': 'sveltekit-inline', 'confidence': 40},
    {'name': 'Remix', 'pattern': re.compile(r'__remixManifest', re.I), 'reason': 'remix-manifest', 'confidence': 45},
    {'name': 'Livewire', 'pattern': re.compile(r'window\.Livewire', re.I), 'reason': 'livewire-runtime', 'confidence': 45},
    {'name': 'Inertia.js', 'pattern': re.compile(r'window\.Inertia', re.I), 'reason': 'inertia-runtime', 'confidence': 40},
    {'name': 'Alpine.js', 'pattern': re.compile(r'window\.Alpine', re.I), 'reason': 'alpine-runtime', 'confidence': 35},
    {'name': 'Laravel', 'pattern': re.compile(r'window\.Laravel', re.I), 'reason': 'laravel-runtime', 'confidence': 40},
    {'name': 'Shopify', 'pattern': re.compile(r'window\.Shopify', re.I), 'reason': 'shopify-runtime', 'confidence': 40},
    {'name': 'Drupal', 'pattern': re.compile(r'drupalSettings', re.I), 'reason': 'drupal-runtime', 'confidence': 35}
]

COOKIE_HINTS = [
    {'name': 'Laravel', 'pattern': re.compile(r'laravel_session=', re.I), 'confidence': 65, 'implies': ['PHP'], 'label': 'laravel_session'},
    {'name': 'Laravel', 'pattern': re.compile(r'XSRF-TOKEN=', re.I), 'confidence': 60, 'implies': ['PHP'], 'label': 'xsrf_token'},
    {'name': 'CodeIgniter', 'pattern': re.compile(r'ci_session=', re.I), 'confidence': 55, 'implies': ['PHP'], 'label': 'ci_session'},
    {'name': 'WordPress', 'pattern': re.compile(r'wordpress_(?:test_|logged_in|sec|settings)', re.I), 'confidence': 55, 'implies': ['PHP'], 'label': 'wordpress_cookie'},
    {'name': 'PHP', 'pattern': re.compile(r'PHPSESSID=', re.I), 'confidence': 40, 'implies': [], 'label': 'phpsessid'}
]

FORM_TOKEN_HINTS = [
    {'name': 'Laravel', 'pattern': re.compile(r'<input[^>]+name=["\']?_token["\']', re.I), 'confidence': 60, 'reason': 'laravel-csrf', 'label': 'csrf_token'},
    {'name': 'CodeIgniter', 'pattern': re.compile(r'<input[^>]+name=["\']?ci_csrf_token["\']', re.I), 'confidence': 55, 'reason': 'ci-csrf', 'label': 'ci_csrf_token'},
    {'name': 'Django', 'pattern': re.compile(r'name=["\']?csrfmiddlewaretoken["\']', re.I), 'confidence': 55, 'reason': 'django-csrf', 'label': 'django_csrf'}
]

CSP_HINTS = [
    {'name': 'Next.js', 'pattern': re.compile(r'next(?:js|-data)', re.I), 'confidence': 35, 'label': 'csp-next'},
    {'name': 'Nuxt.js', 'pattern': re.compile(r'nuxt', re.I), 'confidence': 35, 'label': 'csp-nuxt'},
    {'name': 'Laravel', 'pattern': re.compile(r'laravel', re.I), 'confidence': 30, 'label': 'csp-laravel'},
    {'name': 'Symfony', 'pattern': re.compile(r'_profiler', re.I), 'confidence': 35, 'label': 'csp-symfony'},
    {'name': 'Shopify', 'pattern': re.compile(r'cdn\.shopify\.com', re.I), 'confidence': 30, 'label': 'csp-shopify'}
]

IMPORTMAP_RE = re.compile(r'<script[^>]+type=["\']importmap["\']', re.I)
MANIFEST_RE = re.compile(r'<link[^>]+rel=["\']manifest["\'][^>]*href=["\']([^"\']+)["\']', re.I)
WEBMANIFEST_URL_RE = re.compile(r'\.webmanifest(?:\?|$)', re.I)
PHP_FORM_ACTION_RE = re.compile(r'<form[^>]+action=["\'][^"\']+\.php', re.I)
FONT_HINTS = [
    {'name': 'Bootstrap Icons', 'pattern': re.compile(r'bootstrap-icons(?:\.woff2|\.ttf)', re.I), 'confidence': 30},
    {'name': 'Material Icons', 'pattern': re.compile(r'MaterialIcons(?:-Regular)?\.woff2', re.I), 'confidence': 25},
    {'name': 'PrimeIcons', 'pattern': re.compile(r'primeicons\.woff2', re.I), 'confidence': 25}
]

MAX_HTML_BYTES = 250_000  # hard upper safety cap

def _resolve_html_cap() -> int:
    """Return dynamic HTML byte cap for heuristic fetch.
    Environment variable TECHSCAN_HEURISTIC_HTML_CAP_BYTES can lower the cap (never raise beyond hard MAX_HTML_BYTES).
    If invalid or <=0, falls back to MAX_HTML_BYTES.
    """
    import os
    try:
        v = int(os.environ.get('TECHSCAN_HEURISTIC_HTML_CAP_BYTES','0') or '0')
        if v > 0:
            return min(v, MAX_HTML_BYTES)
    except ValueError:
        pass
    return MAX_HTML_BYTES


def _decompress_body(data: bytes, encoding: str | None) -> bytes:
    if not data or not encoding:
        return data
    enc = encoding.strip().lower()
    try:
        if enc in ('gzip', 'x-gzip'):
            return gzip.decompress(data)
        if enc in ('deflate', 'zlib'):
            return zlib.decompress(data)
        if enc == 'br' and brotli is not None:
            return brotli.decompress(data)
    except Exception:
        return data
    return data

# Confidence constants (easier tuning)
CONF_SERVER_PRIMARY = 35
CONF_SERVER_SECONDARY = 30
CONF_CDN = 25
CONF_BACKEND_LANG = 35
CONF_BACKEND_FRAMEWORK = 30
CONF_DB_PANEL = 12  # lowered for lower false-positive weight

def parse_server_header(value: str) -> tuple[str | None, str | None]:
    """Parse a Server header into canonical (technology-name, version).
    We normalize variant naming (openlitespeed -> LiteSpeed, httpd -> Apache).
    Returns (name, version) or (None, None).
    """
    if not value:
        return None, None
    m = SERVER_HEADER.match(value)
    if not m:
        return None, None
    raw, ver = m.group(1), m.group(2)
    lname = raw.lower()
    if lname in ('apache','httpd'):
        return 'Apache', ver
    if lname == 'nginx':
        return 'Nginx', ver
    if lname in ('cloudflare',):
        return 'Cloudflare', ver
    if lname in ('litespeed','openlitespeed'):
        return 'LiteSpeed', ver
    if lname == 'openresty':
        return 'OpenResty', ver
    if lname == 'caddy':
        return 'Caddy', ver
    if lname == 'gunicorn':
        return 'Gunicorn', ver
    if lname == 'uwsgi':
        return 'uWSGI', ver
    if lname == 'fastly':
        return 'Fastly', ver
    if lname == 'varnish':
        return 'Varnish', ver
    # Future extension handled by caller if needed
    return raw, ver

def extract_x_powered_by(value: str) -> list[tuple[str, str | None]]:
    """Extract technology list from X-Powered-By header.
    Returns list of (name, version|None). Recognized: PHP, Express, ASP.NET.
    """
    out: list[tuple[str,str|None]] = []
    if not value:
        return out
    parts = [p.strip() for p in re.split(r'[;,]', value) if p.strip()]
    for p in parts:
        mphp = re.match(r'php(?:/([0-9][\w\.-]*))?$', p, re.I)
        if mphp:
            out.append(('PHP', mphp.group(1)))
            continue
        mexp = re.match(r'express(?:/([0-9][\w\.-]*))?$', p, re.I)
        if mexp:
            out.append(('Express', mexp.group(1)))
            continue
        if 'asp.net' in p.lower():
            mver = re.search(r'(\d+\.\d+(?:\.\d+)*)', p)
            out.append(('ASP.NET', mver.group(1) if mver else None))
            continue
    return out

def _http_fetch(domain: str, total_timeout: float) -> tuple[dict, bytes, bool]:
    deadline = time.time() + total_timeout
    def remaining():
        return max(0.2, deadline - time.time())
    headers_lower = {}
    body = b''
    truncated = False
    cap = _resolve_html_cap()
    tried = []
    req_headers = {
        'User-Agent': 'TechScan-Tier0/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br'
    }
    target_host = domain
    target_path = '/'
    redirects_left = 2
    while time.time() < deadline:
        made_request = False
        for scheme, conn_cls, port in [
            ('https', http.client.HTTPSConnection, 443),
            ('http', http.client.HTTPConnection, 80)
        ]:
            if time.time() >= deadline:
                break
            try:
                conn = conn_cls(target_host, timeout=remaining())
                conn.request('GET', target_path, headers=req_headers)
                resp = conn.getresponse()
                headers_lower = {k.lower(): v for k,v in resp.getheaders()}
                status = getattr(resp, 'status', 200)
                if 300 <= status < 400 and redirects_left > 0 and headers_lower.get('location'):
                    location = headers_lower.get('location') or ''
                    new_url = location if '://' in location else f'{scheme}://{target_host}{location}'
                    parsed = urlparse(new_url)
                    new_host = parsed.hostname or target_host
                    new_path = parsed.path or '/'
                    if parsed.query:
                        new_path = f'{new_path}?{parsed.query}'
                    target_host = new_host
                    target_path = new_path
                    redirects_left -= 1
                    conn.close()
                    made_request = True
                    break  # restart outer loop with updated host/path
                # Read limited body
                buff = []
                remaining_bytes = cap
                while remaining_bytes > 0:
                    chunk = resp.read(min(8192, remaining_bytes))
                    if not chunk:
                        break
                    buff.append(chunk)
                    remaining_bytes -= len(chunk)
                    if time.time() >= deadline:
                        break
                body = b''.join(buff)
                if remaining_bytes <= 0:
                    truncated = True
                body = _decompress_body(body, headers_lower.get('content-encoding'))
                conn.close()
                tried.append(scheme)
                made_request = True
                if body:
                    return headers_lower, body, truncated
            except Exception:
                continue
        if not made_request:
            break
    return headers_lower, body, truncated
    for scheme, conn_cls, port in [
        ('https', http.client.HTTPSConnection, 443),
        ('http', http.client.HTTPConnection, 80)
    ]:
        if time.time() >= deadline:
            break
        try:
            conn = conn_cls(domain, timeout=remaining())
            conn.request('GET', '/', headers=req_headers)
            resp = conn.getresponse()
            headers_lower = {k.lower(): v for k,v in resp.getheaders()}
            # Read limited body
            buff = []
            remaining_bytes = cap
            while remaining_bytes > 0:
                chunk = resp.read(min(8192, remaining_bytes))
                if not chunk:
                    break
                buff.append(chunk)
                remaining_bytes -= len(chunk)
                if time.time() >= deadline:
                    break
            body = b''.join(buff)
            if remaining_bytes <= 0:
                truncated = True
            body = _decompress_body(body, headers_lower.get('content-encoding'))
            conn.close()
            tried.append(scheme)
            if body:
                break
        except Exception:
            continue
    return headers_lower, body, truncated

def _add(categories: dict, techs: list, name: str, version: str | None, confidence: int):
    entry = {'name': name, 'version': version, 'categories': CATEGORY_MAP.get(name, []), 'confidence': confidence}
    techs.append(entry)
    for cat in entry['categories']:
        categories.setdefault(cat, []).append({'name': name, 'version': version})

def run_heuristic(domain: str, budget_ms: int = 1800, allow_empty_early: bool = False) -> dict:
    t0 = time.time()
    started = t0
    headers, body, truncated = _http_fetch(domain, total_timeout=budget_ms / 1000.0)
    techs: List[Dict[str, Any]] = []
    categories: Dict[str, List[Dict[str, Any]]] = {}
    lower_html = body.decode('utf-8', 'ignore') if body else ''
    version_evidence: dict[str, list[dict[str,str]]] = {}
    alt_versions: dict[str, set[str]] = {}
    tier_meta_extra: Dict[str, Any] = {}

    def ensure_tech(name: str, confidence: int, label: str | None = None) -> Dict[str, Any]:
        for entry in techs:
            if entry['name'] == name:
                if confidence > entry['confidence']:
                    entry['confidence'] = confidence
                if label:
                    labels = entry.setdefault('labels', [])
                    if label not in labels:
                        labels.append(label)
                return entry
        _add(categories, techs, name, None, confidence)
        entry = techs[-1]
        if label:
            entry['labels'] = [label]
        return entry

    # Server header parsing (refactored)
    name, ver = parse_server_header(headers.get('server'))
    if name:
        conf = CONF_SERVER_PRIMARY if name in ('Apache','Nginx') else (
            CONF_CDN if name == 'Cloudflare' else CONF_SERVER_SECONDARY)
        _add(categories, techs, name, ver, conf)
    # X-Powered-By parsing (refactored)
    for bname, bver in extract_x_powered_by(headers.get('x-powered-by')):
        conf = CONF_BACKEND_LANG if bname == 'PHP' else CONF_BACKEND_FRAMEWORK
        _add(categories, techs, bname, bver, conf)
        if bver:
            version_evidence.setdefault(bname, []).append({'source':'x-powered-by','value':bver})
    if 'strict-transport-security' in headers:
        _add(categories, techs, 'HSTS', None, 20)

    # Bot protection / captcha indicators
    lower_html = lower_html or ''
    if 'bitninja' in lower_html and not any(t['name'] == 'BitNinja' for t in techs):
        _add(categories, techs, 'BitNinja', None, 32)
    if ('g-recaptcha' in lower_html or 'recaptcha/api.js' in lower_html) and not any(t['name'] == 'Google reCAPTCHA' for t in techs):
        _add(categories, techs, 'Google reCAPTCHA', None, 28)

    # Runtime globals / inline JS hints
    runtime_hits = []
    for hint in JS_RUNTIME_HINTS:
        if hint['pattern'].search(lower_html):
            ensure_tech(hint['name'], hint.get('confidence', 30), hint.get('reason'))
            runtime_hits.append({'name': hint['name'], 'reason': hint.get('reason')})
    if runtime_hits:
        tier_meta_extra['runtime_hits'] = runtime_hits

    # Cookie heuristics
    cookie_header = headers.get('set-cookie-all') or headers.get('set-cookie')
    if isinstance(cookie_header, list):
        cookie_blob = '; '.join(cookie_header)
    else:
        cookie_blob = cookie_header or ''
    cookie_hits = []
    if cookie_blob:
        for hint in COOKIE_HINTS:
            if hint['pattern'].search(cookie_blob):
                ensure_tech(hint['name'], hint['confidence'], hint.get('label'))
                for implied in hint.get('implies', []):
                    ensure_tech(implied, CONF_BACKEND_LANG if implied == 'PHP' else 25, 'cookie-implied')
                cookie_hits.append({'name': hint['name'], 'label': hint.get('label')})
    if cookie_hits:
        tier_meta_extra['cookie_hits'] = cookie_hits

    # Form token heuristics
    form_hits = []
    for hint in FORM_TOKEN_HINTS:
        if hint['pattern'].search(lower_html):
            ensure_tech(hint['name'], hint['confidence'], hint.get('label') or hint.get('reason'))
            form_hits.append({'name': hint['name'], 'label': hint.get('label')})
    if PHP_FORM_ACTION_RE.search(lower_html):
        ensure_tech('PHP', CONF_BACKEND_LANG, 'php-form-action')
        form_hits.append({'name': 'PHP', 'label': 'php-form-action'})
    if form_hits:
        tier_meta_extra['form_hits'] = form_hits

    # Content-Security-Policy heuristics
    csp_val = headers.get('content-security-policy')
    csp_hits = []
    service_worker_sources: List[str] = []
    if csp_val:
        for hint in CSP_HINTS:
            if hint['pattern'].search(csp_val):
                ensure_tech(hint['name'], hint['confidence'], hint.get('label'))
                csp_hits.append({'name': hint['name'], 'label': hint.get('label')})
        if 'worker-src' in csp_val or 'service-worker' in csp_val:
            ensure_tech('Service Worker', 32, 'csp-worker-src')
            ensure_tech('Progressive Web App', 28, 'csp-worker-src')
            csp_hits.append({'name': 'Service Worker', 'label': 'csp-worker-src'})
            service_worker_sources.append('csp')
    if csp_hits:
        tier_meta_extra['csp_hits'] = csp_hits

    # Import map / manifest hints
    if IMPORTMAP_RE.search(lower_html):
        ensure_tech('Import Maps', 30, 'importmap-script')
        tier_meta_extra['import_map'] = True
    manifest_hits = []
    manifest_match = MANIFEST_RE.search(lower_html)
    if manifest_match:
        manifest_url = manifest_match.group(1)
        ensure_tech('Progressive Web App', 30, 'manifest-link')
        manifest_hits.append({'source': 'html', 'url': manifest_url})
    if re.search(r'navigator\.serviceWorker\.register', lower_html):
        ensure_tech('Service Worker', 35, 'inline-register')
        ensure_tech('Progressive Web App', 30, 'inline-register')
        service_worker_sources.append('inline-js')

    # CMS / Framework patterns
    for name, pat in CMS_PATTERNS:
        if pat.search(lower_html):
            _add(categories, techs, name, None, 45)
    # WP plugins
    for name, pat in WP_PLUGIN_PATTERNS:
        if pat.search(lower_html):
            _add(categories, techs, name, None, 40)
    # Libraries
    for name, pat in LIB_PATTERNS:
        m = pat.search(lower_html)
        if m:
            ver = None
            if m.groups():
                # try group 1 or extract from match
                ver = m.group(1) if m.group(1) and len(m.groups())>=1 else None
            # Fallback: look for ?ver= near match region (simple)
            if not ver:
                span = m.span()
                window = lower_html[max(0, span[0]-120): span[1]+120]
                q = VERSION_FROM_QUERY.search(window)
                if q:
                    ver = q.group(1)
            _add(categories, techs, name, ver, 35)
            if ver:
                version_evidence.setdefault(name, []).append({'source':'library-pattern','value':ver})

    # Meta generator version extraction
    gen = META_GENERATOR.search(lower_html)
    if gen:
        gen_val = gen.group(1)
        # e.g. "WordPress 6.5.1" or "Joomla! - Open Source Content Management" etc.
        for name in ['WordPress','Joomla','Drupal']:
            if name.lower() in gen_val.lower():
                # naive version capture
                mver = re.search(r'(\d+\.\d+(?:\.\d+)*)', gen_val)
                ver = mver.group(1) if mver else None
                # update existing entry version if present
                for t in techs:
                    if t['name'] == name and ver and not t.get('version'):
                        t['version'] = ver
                        # also update categories list entry
                        for cat in CATEGORY_MAP.get(name, []):
                            for citem in categories.get(cat, []):
                                if citem['name'] == name:
                                    citem['version'] = ver
                        version_evidence.setdefault(name, []).append({'source':'meta-generator','value':ver})
                break

    # Asset URL scanning for version augmentation (stage 1)
    # Extract candidate asset URLs from HTML quickly (script/src & link/href)
    asset_urls = []
    for m in re.finditer(r'(?:script|link)[^>]+?(?:src|href)=["\']([^"\'>]+)["\']', lower_html, re.I):
        url = m.group(1)
        if len(url) < 4 or len(url) > 300:
            continue
        asset_urls.append(url)
    font_hits = []

    KNOWN_MAP = [
        ('WordPress', re.compile(r'/wp-(?:includes|content)/', re.I)),
        ('WooCommerce', re.compile(r'wp-content/plugins/woocommerce', re.I)),
        ('Elementor', re.compile(r'wp-content/plugins/elementor', re.I)),
        ('Contact Form 7', re.compile(r'wp-content/plugins/contact-form-7', re.I)),
        ('Yoast SEO', re.compile(r'wp-content/plugins/(?:wordpress-seo|wp-seo)', re.I)),
        ('WPForms', re.compile(r'wp-content/plugins/wpforms', re.I)),
        ('Wordfence', re.compile(r'wp-content/plugins/wordfence', re.I)),
        ('WP Rocket', re.compile(r'wp-content/plugins/wp-rocket', re.I)),
        ('Revolution Slider', re.compile(r'wp-content/plugins/revslider', re.I)),
        ('jQuery', re.compile(r'jquery[-\.](\d[\w\.\-]*)\.js', re.I)),
        ('Bootstrap', re.compile(r'bootstrap(?:\.bundle)?[-\.](\d[\w\.\-]*)\.(?:min\.)?(?:js|css)', re.I)),
        ('Tailwind CSS', re.compile(r'tailwind(?:\.min)?\.css', re.I)),
        ('DataTables', re.compile(r'datatables(?:\.min)?\.js', re.I)),
    ]

    def _record_version(name: str, ver: str, source: str):
        if not ver:
            return
        # update existing technology entry if present, else add skeleton with low confidence
        for t in techs:
            if t['name'] == name:
                if (not t.get('version')) or (t.get('version') != ver):
                    if not t.get('version'):
                        t['version'] = ver
                        for cat in t['categories']:
                            for citem in categories.get(cat, []):
                                if citem['name'] == name:
                                    citem['version'] = ver
                break
        else:
            # not found, add with minimal categories guess
            _add(categories, techs, name, ver, 20)
        version_evidence.setdefault(name, []).append({'source':source,'value':ver})

    for url in asset_urls:
        for fh in FONT_HINTS:
            if fh['pattern'].search(url):
                ensure_tech(fh['name'], fh['confidence'], 'font-asset')
                font_hits.append({'name': fh['name'], 'url': url})
                break
        if WEBMANIFEST_URL_RE.search(url):
            ensure_tech('Progressive Web App', 28, 'webmanifest-asset')
            manifest_hits.append({'source': 'asset', 'url': url})
        if re.search(r'(?:^|/)sw(?:\.|-)?[a-z0-9_-]*\.js', url):
            ensure_tech('Service Worker', 30, 'sw-asset')
            ensure_tech('Progressive Web App', 28, 'sw-asset')
            service_worker_sources.append('asset')
        qver = VERSION_FROM_QUERY.search(url)
        simple_file_ver = VERSION_IN_FILENAME.search(url)
        for name, pat in KNOWN_MAP:
            if pat.search(url):
                ver_candidate = None
                if qver:
                    ver_candidate = qver.group(1)
                elif simple_file_ver:
                    ver_candidate = simple_file_ver.group(1)
                # Special case Tailwind / DataTables often need comment parse; handled later if needed
                _record_version(name, ver_candidate, 'asset-url' if qver or simple_file_ver else 'asset-presence')

    if font_hits:
        tier_meta_extra['font_hits'] = font_hits
    if manifest_hits:
        tier_meta_extra['manifest_hits'] = manifest_hits
    if service_worker_sources:
        tier_meta_extra['service_worker_sources'] = sorted(set(service_worker_sources))

    # Phase 2: banner comment extraction (Bootstrap / Tailwind / DataTables)
    for cb in COMMENT_BANNER.finditer(lower_html[:120000]):  # limit scan for performance
        raw_name = cb.group(1).lower()
        ver = cb.group(2)
        name_map = {
            'bootstrap': 'Bootstrap',
            'tailwind': 'Tailwind CSS',
            'tailwindcss': 'Tailwind CSS',
            'datatables': 'DataTables'
        }
        mapped = name_map.get(raw_name)
        if mapped:
            _record_version(mapped, ver, 'banner-comment')

    # Angular ng-version attribute
    for ngm in NG_VERSION_ATTR.finditer(lower_html):
        ver = ngm.group(1)
        _record_version('Angular', ver, 'ng-version-attr')
        break  # one is enough

    # Next.js buildId (store as evidence only; not a semantic version but build marker)
    nd = NEXT_DATA_BUILDID.search(lower_html)
    if nd:
        build_id = nd.group(1)
        version_evidence.setdefault('Next.js', []).append({'source':'next-data-buildId','value':build_id})
        # ensure Next.js listed if not already (without version)
        if not any(t['name']=='Next.js' for t in techs):
            _add(categories, techs, 'Next.js', None, 30)

    # Improve jQuery version if mismatch and asset has newer
    # Already handled by _record_version merging logic.

    # DB exposure panels (very low confidence; purely string presence)
    for name, pat in DB_PANEL_PATTERNS:
        if pat.search(lower_html):
            _add(categories, techs, name, None, CONF_DB_PANEL)

    # Determine early return
    names = {t['name'] for t in techs}
    # Infer WordPress if plugin(s) present but WordPress belum muncul
    if any(n in names for n,_ in WP_PLUGIN_PATTERNS) and 'WordPress' not in names:
        _add(categories, techs, 'WordPress', None, 25)
        names.add('WordPress')
    has_cms = any(n in names for n in ['WordPress','Joomla','Drupal'])
    distinct_priority = len(names)
    early = False
    reason = 'minimal'
    if has_cms:
        early = True; reason = 'cms'
    elif 'WordPress' in names and any(p in names for p,_ in WP_PLUGIN_PATTERNS):
        early = True; reason = 'wordpress+plugins'
    elif distinct_priority >= 2:
        early = True; reason = 'multi'
    elif allow_empty_early and distinct_priority == 0:
        early = True; reason = 'empty'

    finished = time.time()
    result = {
        'domain': domain,
        'started_at': started,
        'finished_at': finished,
        'duration': round(finished-started,3),
        'technologies': techs,
        'categories': categories,
        'scan_mode': 'fast',
        'engine': 'heuristic-tier0',
        'tiered': {
            'stage': 'heuristic',
            'early_return': early,
            'reason': reason,
            'budget_ms': budget_ms,
            'html_truncated': truncated
        }
    }
    if version_evidence:
        result['tiered']['version_evidence'] = version_evidence
    if tier_meta_extra:
        result['tiered']['hint_meta'] = tier_meta_extra
    # alt_versions: collect if any tech has multiple evidence differing from main version
    for t in techs:
        name = t['name']
        if name in version_evidence:
            collected = {e['value'] for e in version_evidence[name] if e.get('value')}
            if t.get('version'):
                collected.add(t['version'])
            if len(collected) > 1:
                t.setdefault('alt_versions', sorted(collected))
    return result
