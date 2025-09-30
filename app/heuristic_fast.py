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
import time, re, http.client, socket, ssl
from typing import Dict, Any, List, Tuple

CMS_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ('WordPress', re.compile(r'wp-content/|wp-includes/|<meta[^>]+name=["\']generator["\'][^>]+wordpress', re.I)),
    ('Joomla', re.compile(r'/media/system/js/|Joomla!|<meta[^>]+generator["\'][^>]+joomla', re.I)),
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
    ('WPML', re.compile(r'wp-content/plugins/sitepress-multilingual-cms', re.I)),
    ('Polylang', re.compile(r'wp-content/plugins/polylang', re.I)),
    ('Rank Math SEO', re.compile(r'wp-content/plugins/seo-by-rank-math', re.I)),
    ('UpdraftPlus', re.compile(r'wp-content/plugins/updraftplus', re.I)),
    ('Slider Revolution', re.compile(r'wp-content/plugins/revslider', re.I)),
]

LIB_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ('jQuery', re.compile(r'jquery[-\.](\d[\w\.\-]*)\.js', re.I)),
    ('React', re.compile(r'react(?:\.production)?(?:\.min)?\.js', re.I)),
    ('Vue.js', re.compile(r'vue(?:\.runtime)?(?:\.min)?\.js', re.I)),
    ('AngularJS', re.compile(r'angular(?:\.min)?\.js', re.I)),
    ('Alpine.js', re.compile(r'alpine(?:\.min)?\.js', re.I)),
]

VERSION_FROM_QUERY = re.compile(r'[?&](?:ver|v|version)=(\d[\w\.\-]*)', re.I)
VERSION_IN_FILENAME = re.compile(r'-([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.\w{1,6}\b')
COMMENT_BANNER = re.compile(r'/\*!?\s*(bootstrap|tailwind(?:css)?|datatables)[^\n]*?v?(\d+\.\d+(?:\.\d+){0,2})', re.I)
NG_VERSION_ATTR = re.compile(r'ng-version="(\d+\.\d+(?:\.\d+)*)"', re.I)
NEXT_DATA_BUILDID = re.compile(r'__NEXT_DATA__"?\s*:\s*\{[^}]*?"buildId"\s*:\s*"([a-zA-Z0-9-_]+)"')
META_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
SERVER_HEADER = re.compile(r'([a-zA-Z0-9_-]+)(?:/([0-9][\w\.-]*))?')

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
    'Apache': ['Web servers'],
    'Nginx': ['Web servers','Reverse proxies'],
    'Cloudflare': ['Reverse proxies','CDN'],
}

MAX_HTML_BYTES = 250_000

def _http_fetch(domain: str, total_timeout: float) -> tuple[dict, bytes]:
    deadline = time.time() + total_timeout
    def remaining():
        return max(0.2, deadline - time.time())
    headers_lower = {}
    body = b''
    tried = []
    for scheme, conn_cls, port in [
        ('https', http.client.HTTPSConnection, 443),
        ('http', http.client.HTTPConnection, 80)
    ]:
        if time.time() >= deadline:
            break
        try:
            conn = conn_cls(domain, timeout=remaining())
            conn.request('GET', '/', headers={'User-Agent': 'TechScan-Tier0/1.0'})
            resp = conn.getresponse()
            headers_lower = {k.lower(): v for k,v in resp.getheaders()}
            # Read limited body
            buff = []
            remaining_bytes = MAX_HTML_BYTES
            while remaining_bytes > 0:
                chunk = resp.read(min(8192, remaining_bytes))
                if not chunk:
                    break
                buff.append(chunk)
                remaining_bytes -= len(chunk)
                if time.time() >= deadline:
                    break
            body = b''.join(buff)
            conn.close()
            tried.append(scheme)
            if body:
                break
        except Exception:
            continue
    return headers_lower, body

def _add(categories: dict, techs: list, name: str, version: str | None, confidence: int):
    entry = {'name': name, 'version': version, 'categories': CATEGORY_MAP.get(name, []), 'confidence': confidence}
    techs.append(entry)
    for cat in entry['categories']:
        categories.setdefault(cat, []).append({'name': name, 'version': version})

def run_heuristic(domain: str, budget_ms: int = 1800, allow_empty_early: bool = False) -> dict:
    t0 = time.time()
    started = t0
    headers, body = _http_fetch(domain, total_timeout=budget_ms / 1000.0)
    techs: List[Dict[str, Any]] = []
    categories: Dict[str, List[Dict[str, Any]]] = {}
    lower_html = body.decode('utf-8', 'ignore') if body else ''
    version_evidence: dict[str, list[dict[str,str]]] = {}
    alt_versions: dict[str, set[str]] = {}

    # Server header
    server = headers.get('server')
    if server:
        m = SERVER_HEADER.match(server)
        if m:
            nm, ver = m.group(1), m.group(2)
            lname = nm.lower()
            if lname == 'nginx':
                _add(categories, techs, 'Nginx', ver, 35)
            elif lname in ('apache','httpd'):
                _add(categories, techs, 'Apache', ver, 35)
            elif lname == 'cloudflare':
                _add(categories, techs, 'Cloudflare', ver, 25)
    if 'strict-transport-security' in headers:
        _add(categories, techs, 'HSTS', None, 20)

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
            'budget_ms': budget_ms
        }
    }
    if version_evidence:
        result['tiered']['version_evidence'] = version_evidence
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
