import json, re, threading, time, os, pathlib, logging
import socket, ssl, random
from functools import lru_cache
from collections import deque
from typing import Dict, Any, List
from . import version_audit
from . import safe_subprocess as sproc
from .evidence_utils import (
    normalize_evidence_entry,
    pattern_to_evidence,
    extras_fallback_evidence,
    extract_header_maps,
    collect_header_evidence,
    dedupe_evidence_entries,
    infer_snippet,
)

DOMAIN_RE = re.compile(r'^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$')
IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')  # Pre-compiled for SSRF check
CACHE_TTL = 300  # default seconds
# Default heuristic budget for quick single scan mode (tuned via perf harness)
QUICK_DEFAULT_BUDGET_MS = 700
# Fast-path toggle ENV flags:
#   TECHSCAN_SKIP_VERSION_AUDIT=1  -> skip version audit stages
#   TECHSCAN_DISABLE_SYNTHETIC=1   -> skip synthetic header detection
#   TECHSCAN_ULTRA_QUICK=1         -> force heuristic-only path inside scan_domain
_lock = threading.Lock()
_cache: Dict[str, Dict[str, Any]] = {}
_stats_lock = threading.Lock()
STATS: Dict[str, Any] = {
    'start_time': time.time(),
    'hits': 0,
    'misses': 0,
    'mode_hits': {'fast': 0, 'full': 0, 'fast_full': 0},
    'mode_misses': {'fast': 0, 'full': 0, 'fast_full': 0},
    'scans': 0,
    'cache_entries': 0,
    'synthetic': {'headers': 0, 'tailwind': 0, 'floodlight': 0},
    'durations': {
        'fast': {'count': 0, 'total': 0.0},
        'full': {'count': 0, 'total': 0.0},
        'fast_full': {'count': 0, 'total': 0.0}
    },
    'errors': {'timeout':0,'dns':0,'ssl':0,'conn':0,'quarantine':0,'preflight':0,'other':0},
    'recent_samples': {
        'fast': deque(maxlen=200),
        'full': deque(maxlen=200),
        'fast_full': deque(maxlen=200)
    },
    'phases': {
        'sniff_ms': 0,
        'sniff_count': 0,
        'engine_ms': 0,
        'engine_count': 0,
        'synthetic_ms': 0,
        'synthetic_count': 0,
        'version_audit_ms': 0,
        'version_audit_count': 0
    },
    'totals': {
        'scan_count': 0,
        'total_overall_ms': 0
    },
    # Single-flight (duplicate in-flight suppression) metrics
    'single_flight': {
        'hits': 0,          # followers that avoided starting a duplicate scan
        'wait_ms': 0,       # cumulative wait time of followers
        'inflight': 0       # current number of active leader scans
    }
}

TECH_NAME_REWRITES = {
    'WPML': 'WordPress Multilingual Plugin (WPML)',
    'Hello Elementor': 'Hello Elementor Theme'
}

_ASSET_VERSION_QUERY_RE = re.compile(r'[?&](?:ver|v|version)=([0-9]+(?:\.[0-9]+){0,3})', re.I)
_JQUERY_FILENAME_RE = re.compile(r'jquery(?:\.min)?[-_.]?([0-9]+(?:\.[0-9]+){0,3})', re.I)
_JQUERY_MIGRATE_FILENAME_RE = re.compile(r'jquery-migrate(?:\.min)?-([0-9]+(?:\.[0-9]+){0,3})', re.I)
_BOOTSTRAP_FILENAME_RE = re.compile(r'bootstrap(?:\.bundle)?(?:\.min)?[-_.]?([0-9]+(?:\.[0-9]+){0,3})', re.I)
_CORE_JS_FILENAME_RE = re.compile(r'core-js(?:\.legacy)?(?:\.min)?[-_.]?([0-9]+(?:\.[0-9]+){0,3})', re.I)
_REQUIREJS_FILENAME_RE = re.compile(r'require(?:\.min)?(?:\.js)?[-_.]?([0-9]+(?:\.[0-9]+){0,3})', re.I)
_VIDEOJS_FILENAME_RE = re.compile(r'video(?:\.min)?(?:\.js)?[-_.]?([0-9]+(?:\.[0-9]+){0,3})', re.I)
_MATHJAX_FILENAME_RE = re.compile(r'mathjax(?:\.min)?[-_.]?([0-9]+(?:\.[0-9]+){0,3})', re.I)
_YUI_FILENAME_RE = re.compile(r'yui(?:doc)?(?:\.min)?[-_.]?([0-9]+(?:\.[0-9]+){0,3})', re.I)
_TAILWIND_FILENAME_RE = re.compile(r'tailwind(?:\.min)?[-_.]?([0-9]+(?:\.[0-9]+){0,3})', re.I)


def canonicalize_tech_name(name: str | None) -> str | None:
    if not name:
        return name
    return TECH_NAME_REWRITES.get(name, name)

# Failure tracking & quarantine (domain-level)
_fail_lock = threading.Lock()
_fail_map: Dict[str, dict] = {}

# DNS negative cache & preflight
_dns_neg_lock = threading.Lock()
_dns_neg: Dict[str, float] = {}

# --------------------------- SINGLE-FLIGHT GUARD ---------------------------
_single_flight_lock = threading.Lock()
_single_flight_map: Dict[str, dict] = {}

def _single_flight_enter(cache_key: str) -> bool:
    """Enter single-flight section for given cache_key.
    Returns True if caller is the leader responsible for performing the scan.
    If another leader is running, this call will wait until completion and return False.
    Disabled when TECHSCAN_SINGLE_FLIGHT=0.
    """
    if os.environ.get('TECHSCAN_SINGLE_FLIGHT', '1') == '0':
        return True
    start_wait: float | None = None
    with _single_flight_lock:
        entry = _single_flight_map.get(cache_key)
        if entry is None:
            # Become leader
            cond = threading.Condition(_single_flight_lock)
            _single_flight_map[cache_key] = {'cond': cond, 'running': True}
            with _stats_lock:
                STATS['single_flight']['inflight'] += 1
            return True
        # Follower path: wait until leader completes
        cond: threading.Condition = entry['cond']
        start_wait = time.time()
        while entry.get('running'):
            cond.wait()
        # Leader finished; record wait stats
        if start_wait is not None:
            waited = time.time() - start_wait
            with _stats_lock:
                STATS['single_flight']['hits'] += 1
                STATS['single_flight']['wait_ms'] += int(waited * 1000)
        return False

def _single_flight_exit(cache_key: str):
    if os.environ.get('TECHSCAN_SINGLE_FLIGHT', '1') == '0':
        return
    with _single_flight_lock:
        entry = _single_flight_map.get(cache_key)
        if not entry:
            return
        if entry.get('running'):
            entry['running'] = False
            cond: threading.Condition = entry['cond']
            cond.notify_all()
            _single_flight_map.pop(cache_key, None)
            with _stats_lock:
                STATS['single_flight']['inflight'] -= 1

def _dns_negative(domain: str) -> bool:
    # Return True if domain is in negative cache and still valid
    ttl = 0
    try:
        ttl = int(os.environ.get('TECHSCAN_DNS_NEG_CACHE','0'))
    except ValueError:
        ttl = 0
    if ttl <= 0:
        return False
    now = time.time()
    with _dns_neg_lock:
        exp = _dns_neg.get(domain)
        if not exp:
            return False
        if exp > now:
            return True
        _dns_neg.pop(domain, None)
        return False

def _dns_add_negative(domain: str):
    try:
        ttl = int(os.environ.get('TECHSCAN_DNS_NEG_CACHE','0'))
    except ValueError:
        ttl = 0
    if ttl <= 0:
        return
    with _dns_neg_lock:
        _dns_neg[domain] = time.time() + ttl

def _preflight(domain: str) -> bool:
    """Fast TCP connect preflight to 443 (or 80 fallback) to short-circuit obviously dead domains.
    Controlled by TECHSCAN_PREFLIGHT=1. Returns True if reachable, False if definitely unreachable.
    If DNS fails, adds to negative cache.
    """
    if os.environ.get('TECHSCAN_PREFLIGHT','0') != '1':
        return True
    if _dns_negative(domain):
        return False
    # Try resolve
    try:
        addrs = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except Exception:
        _dns_add_negative(domain)
        return False
    targets = []
    for af, st, proto, cname, sa in addrs:
        targets.append((sa[0], 443))
    # Add port 80 as fallback to a subset
    if not targets:
        return False
    ok = False
    for ip, port in targets[:2]:  # limit attempts
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            s.close()
            ok = True
            break
        except Exception:
            continue
    if not ok:
        # Try port 80 quickly
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((targets[0][0], 80))
            s.close()
            ok = True
        except Exception:
            pass
    if not ok:
        # Add to negative if all attempts failed
        _dns_add_negative(domain)
    return ok

def _record_failure(domain: str, now: float | None = None):
    now = now or time.time()
    with _fail_lock:
        ent = _fail_map.setdefault(domain, {'fails': 0, 'last': 0.0, 'quarantine_until': 0.0})
        ent['fails'] += 1
        ent['last'] = now
        # If exceeds threshold configure quarantine
        try:
            thresh = int(os.environ.get('TECHSCAN_QUARANTINE_FAILS', '0'))
            minutes = float(os.environ.get('TECHSCAN_QUARANTINE_MINUTES', '0'))
        except ValueError:
            thresh, minutes = 0, 0.0
        if thresh > 0 and minutes > 0 and ent['fails'] >= thresh:
            ent['quarantine_until'] = max(ent.get('quarantine_until', 0.0), now + minutes * 60)
            # Reset fails after quarantine set to avoid runaway growth
            ent['fails'] = 0

def _check_quarantine(domain: str, now: float | None = None) -> bool:
    now = now or time.time()
    with _fail_lock:
        ent = _fail_map.get(domain)
        if not ent:
            return False
        if ent.get('quarantine_until', 0.0) > now:
            return True
        # Expired quarantine: allow and clean up if old
        if ent.get('quarantine_until') and ent['quarantine_until'] <= now:
            ent['quarantine_until'] = 0.0
        return False

def _record_success(domain: str):
    with _fail_lock:
        if domain in _fail_map:
            # partial decay: keep last time for forensic but reset fails & quarantine
            _fail_map[domain]['fails'] = 0
            _fail_map[domain]['quarantine_until'] = 0.0

def _classify_error(err: Exception) -> str:
    msg = str(err).lower()
    if 'timeout' in msg:
        return 'timeout'
    if 'preflight unreachable' in msg:
        return 'preflight'
    if 'temporary quarantine' in msg:
        return 'quarantine'
    if isinstance(err, socket.gaierror) or 'nxdomain' in msg or 'name or service not known' in msg:
        return 'dns'
    if 'ssl' in msg or 'certificate' in msg:
        return 'ssl'
    if 'connection refused' in msg or 'connect etimedout' in msg or 'network is unreachable' in msg:
        return 'conn'
    return 'other'


def _persist_failure_scan(
    domain: str,
    *,
    mode: str,
    timeout_used: int,
    retries: int,
    error: Exception | str,
    started_at: float | None = None,
    finished_at: float | None = None,
    engine: str = 'scan-error',
    raw: dict | None = None
) -> bool:
    """Record failed scan attempts so UI can display them like successes."""
    if not domain:
        return False
    msg = str(error)
    err_class = _classify_error(error) if isinstance(error, Exception) else 'other'
    stop_ts = finished_at or time.time()
    start_ts = started_at or stop_ts
    if stop_ts < start_ts:
        stop_ts = start_ts
    payload = {
        'domain': domain,
        'scan_mode': mode,
        'engine': engine,
        'status': 'error',
        'started_at': start_ts,
        'finished_at': stop_ts,
        'timestamp': stop_ts,
        'duration': round(max(0.0, stop_ts - start_ts), 3),
        'technologies': [],
        'categories': {},
        'retries': retries,
        'error': msg,
        'raw': {
            'error': msg,
            'error_class': err_class,
            **(raw or {})
        }
    }
    try:
        from . import db as _db  # local import to avoid circulars
        _db.save_scan(payload, from_cache=False, timeout_used=timeout_used)
        return True
    except Exception as db_ex:
        logging.getLogger('techscan.db').debug('save_scan failure stub failed domain=%s err=%s', domain, db_ex)
        return False

def extract_host(value: str) -> str:
    """Normalize input that may be a full URL (with scheme/path) into just the hostname.
    - Strips protocol (http/https)
    - Removes credentials, port, path, query, fragment
    - Lowercases result
    """
    v = (value or '').strip()
    if not v:
        return v
    # Add scheme if starts with //
    if v.startswith('//'):
        v = 'http:' + v
    if '://' in v:
        # Split off scheme
        v2 = v.split('://', 1)[1]
    else:
        v2 = v
    # Remove path/query/fragment
    for sep in ['/', '?', '#']:
        if sep in v2:
            v2 = v2.split(sep, 1)[0]
    # Remove credentials
    if '@' in v2:
        v2 = v2.split('@', 1)[1]
    # Remove port
    if ':' in v2:
        host_part = v2.split(':', 1)[0]
    else:
        host_part = v2
    return host_part.lower()


def extract_url_with_path(value: str) -> str:
    """Normalize URL but KEEP the path for unique endpoint identification.
    - Strips protocol (http/https)
    - Removes credentials, port, query, fragment
    - Keeps path (for fkg.unair.ac.id/blog vs fkg.unair.ac.id/shop)
    - Lowercases result
    - Removes trailing slash
    """
    v = (value or '').strip()
    if not v:
        return v
    # Add scheme if starts with //
    if v.startswith('//'):
        v = 'http:' + v
    if '://' in v:
        # Split off scheme
        v2 = v.split('://', 1)[1]
    else:
        v2 = v
    # Remove query/fragment but KEEP path
    for sep in ['?', '#']:
        if sep in v2:
            v2 = v2.split(sep, 1)[0]
    # Remove credentials
    if '@' in v2:
        v2 = v2.split('@', 1)[1]
    # Handle port: extract host:port and path separately
    if '/' in v2:
        host_port, path = v2.split('/', 1)
        path = '/' + path
    else:
        host_port = v2
        path = ''
    # Remove port from host
    if ':' in host_port:
        host_part = host_port.split(':', 1)[0]
    else:
        host_part = host_port
    # Combine and normalize
    result = (host_part + path).lower().rstrip('/')
    return result

def validate_domain(raw: str) -> str:
    """Return a normalized domain or raise ValueError.
    
    Security validations:
    - Lowercase and strip whitespace
    - Strip trailing dot
    - IDNA (punycode) encode/decode round trip for validation
    - Reject if regex mismatch
    - Block private/internal hostnames (SSRF protection)
    - Enforce maximum length
    - Reject dangerous characters
    """
    d = (raw or '').strip().lower().rstrip('.')
    if not d:
        raise ValueError('empty domain')
    
    # Length check (prevent buffer overflow / DoS)
    if len(d) > 253:
        raise ValueError('domain too long (max 253 chars)')
    
    # Check for dangerous characters that could be used for injection
    dangerous_chars = ['<', '>', '"', "'", '\\', '\n', '\r', '\t', '\x00']
    for c in dangerous_chars:
        if c in d:
            raise ValueError('domain contains invalid characters')
    
    # Block internal/private hostnames (SSRF protection)
    blocked_patterns = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '::1',
        '10.',
        '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.',
        '192.168.',
        '169.254.',  # Link-local
        'fc00:',     # IPv6 private
        'fe80:',     # IPv6 link-local
        '.internal',
        '.local',
        '.localdomain',
        '.localhost',
    ]
    for pattern in blocked_patterns:
        if d.startswith(pattern) or d.endswith(pattern) or d == pattern.rstrip('.'):
            raise ValueError('domain appears to be internal/private (SSRF blocked)')
    
    # Block pure IP addresses (should use domain names)
    if IPV4_RE.match(d):
        raise ValueError('IP addresses not allowed, use domain names')
    
    # Basic fast path
    if DOMAIN_RE.match(d):
        return d
    # Try IDNA (unicode domains)
    try:
        ascii_d = d.encode('idna').decode('ascii')
    except Exception:
        raise ValueError('invalid domain')
    if not DOMAIN_RE.match(ascii_d):
        raise ValueError('invalid domain')
    return ascii_d

@lru_cache(maxsize=1)
def load_categories(wappalyzer_path: str) -> Dict[int, str]:
    base = pathlib.Path(wappalyzer_path)
    # Support both repo layout (src/categories.json) and npm package layout (categories.json at root)
    candidates = [base / 'src' / 'categories.json', base / 'categories.json']
    selected = None
    for p in candidates:
        if p.exists():
            selected = p
            break
    if not selected:
        raise FileNotFoundError(f'categories.json not found under {wappalyzer_path}')
    with open(selected, 'r', encoding='utf-8') as f:
        raw = json.load(f)
    # file structure is array or object (in repo it's object mapping id-> {name:..})
    out = {}
    for k, v in raw.items():
        try:
            out[int(k)] = v['name'] if isinstance(v, dict) and 'name' in v else v
        except ValueError:
            continue
    return out

def normalize_result(domain: str, raw: Dict[str, Any], categories_map: Dict[int,str]) -> Dict[str, Any]:
    raw_dict = raw if isinstance(raw, dict) else {}
    techs = raw_dict.get('technologies') or raw_dict.get('applications') or []
    norm_techs = []
    category_bucket: Dict[str, List[Dict[str, Any]]] = {}
    patterns_map = raw_dict.get('patterns') if isinstance(raw_dict.get('patterns'), dict) else {}
    header_maps = extract_header_maps(raw_dict)
    extras_map = raw_dict.get('extras') if isinstance(raw_dict.get('extras'), dict) else {}
    for t in techs:
        # categories might be list of objects, ids, or already names (strings)
        cats = t.get('categories') or []
        names = []
        for c in cats:
            if isinstance(c, dict) and 'id' in c:
                names.append(c.get('name') or categories_map.get(c['id']) or str(c['id']))
            elif isinstance(c, int):
                names.append(categories_map.get(c) or str(c))
            elif isinstance(c, str):
                names.append(c)
        cleaned_names: List[str] = []
        for n in names:
            text = str(n).strip()
            if text:
                cleaned_names.append(text)
        names = list(dict.fromkeys(cleaned_names))  # dedupe preserving order
        raw_evidence = t.get('evidence')
        if isinstance(raw_evidence, dict):
            raw_evidence = [raw_evidence]
        elif not isinstance(raw_evidence, list):
            raw_evidence = []
        normalized_evidence: List[dict] = []
        for ev in raw_evidence:
            normalized = normalize_evidence_entry(ev)
            if normalized:
                normalized_evidence.append(normalized)

        tech_patterns = t.get('patterns')
        if isinstance(tech_patterns, dict):
            tech_patterns = [tech_patterns]
        if isinstance(tech_patterns, list):
            for pattern_entry in tech_patterns:
                normalized = pattern_to_evidence(pattern_entry if isinstance(pattern_entry, dict) else {})
                if not normalized:
                    continue
                normalized = normalize_evidence_entry(normalized)
                if normalized:
                    normalized_evidence.append(normalized)

        raw_name = t.get('name')
        tech_name = canonicalize_tech_name(raw_name)
        tech_slug = t.get('slug')
        alias_values = []
        if isinstance(t.get('aliases'), list):
            alias_values = [alias for alias in t['aliases'] if isinstance(alias, str)]

        if patterns_map:
            candidate_keys = {k.lower() for k in [raw_name, tech_slug] if isinstance(k, str)}
            candidate_keys.update(alias.lower() for alias in alias_values)
            if candidate_keys:
                for key, entries in patterns_map.items():
                    if key.lower() not in candidate_keys:
                        continue
                    sequence = entries if isinstance(entries, list) else [entries]
                    for item in sequence:
                        normalized = pattern_to_evidence(item if isinstance(item, dict) else {})
                        if not normalized:
                            continue
                        normalized = normalize_evidence_entry(normalized)
                        if normalized:
                            normalized_evidence.append(normalized)
                    break

        if header_maps:
            header_entries = collect_header_evidence(tech_name or tech_slug or '', header_maps, alias_values)
            for entry in header_entries:
                normalized = normalize_evidence_entry(entry)
                if normalized:
                    normalized_evidence.append(normalized)

        if not normalized_evidence and extras_map:
            fallback_entries = extras_fallback_evidence(tech_name or tech_slug or '', extras_map)
            for entry in fallback_entries:
                normalized = normalize_evidence_entry(entry)
                if normalized:
                    normalized_evidence.append(normalized)

        script_sources: List[str] = []
        script_field = t.get('scriptSrc') or t.get('scripts')
        if isinstance(script_field, list):
            script_sources.extend([s for s in script_field if isinstance(s, str)])
        elif isinstance(script_field, str):
            script_sources.append(script_field)
        if script_sources:
            for src in script_sources:
                entry_evidence = {
                    'kind': 'asset',
                    'source': 'scriptSrc',
                    'url': src,
                    'snippet': infer_snippet(src)
                }
                normalized = normalize_evidence_entry(entry_evidence)
                if normalized:
                    normalized_evidence.append(normalized)

        normalized_evidence = dedupe_evidence_entries(normalized_evidence)

        entry_name = tech_name or raw_name or t.get('name')
        entry = {
            'name': entry_name,
            'version': t.get('version'),
            'categories': names,
            'confidence': t.get('confidence'),
            'evidence': normalized_evidence,
            'detection_raw': t
        }
        if tech_slug:
            entry['slug'] = tech_slug
        if alias_values:
            entry['aliases'] = alias_values
        norm_techs.append(entry)
        for n in names:
            category_bucket.setdefault(n, []).append({'name': entry['name'], 'version': entry['version']})
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.getLogger('techscan.normalize').debug('domain=%s tech_count=%d category_count=%d', domain, len(norm_techs), len(category_bucket))
    return {
        'domain': domain,
        'timestamp': int(time.time()),
        'technologies': norm_techs,
        'categories': category_bucket,
        'raw': raw
    }


def infer_tech_from_urls(urls: List[str]) -> List[Dict[str, Any]]:
    """Lightweight inference from asset URLs (js/css/fonts) to provide hints when full JS execution isn't available.
    Returns list of tech dicts compatible with normalized entries.
    """
    hints: List[Dict[str, Any]] = []
    if not urls:
        return hints

    def _has_hint(name: str) -> bool:
        return any(h.get('name') == name for h in hints)

    def _add_hint(name: str, categories: List[str], confidence: int, *, url: str | None = None, pattern: re.Pattern | None = None, version: str | None = None) -> None:
        if _has_hint(name):
            return
        resolved_version = version
        if url and resolved_version is None:
            resolved_version = _extract_asset_version(url, pattern)
        entry = {
            'name': name,
            'version': resolved_version,
            'categories': categories,
            'confidence': confidence
        }
        hints.append(entry)

    for raw_url in urls:
        if not isinstance(raw_url, str) or not raw_url:
            continue
        lowered = raw_url.lower()

        if 'jquery' in lowered:
            _add_hint('jQuery', ['JavaScript libraries'], 20, url=raw_url, pattern=_JQUERY_FILENAME_RE)
        if 'bootstrap' in lowered:
            _add_hint('Bootstrap', ['UI frameworks'], 18, url=raw_url, pattern=_BOOTSTRAP_FILENAME_RE)
        if 'tailwind' in lowered:
            _add_hint('Tailwind CSS', ['UI frameworks','CSS'], 16, url=raw_url, pattern=_TAILWIND_FILENAME_RE)
        if 'vue' in lowered or 'vue.runtime' in lowered:
            _add_hint('Vue.js', ['JavaScript frameworks'], 18, url=raw_url)
        if 'react' in lowered or 'react-dom' in lowered:
            _add_hint('React', ['JavaScript frameworks'], 18, url=raw_url)
        if 'require.js' in lowered or 'requirejs' in lowered:
            _add_hint('RequireJS', ['JavaScript frameworks'], 25, url=raw_url, pattern=_REQUIREJS_FILENAME_RE)
        if 'video.js' in lowered or 'video.min.js' in lowered or 'videojs' in lowered:
            _add_hint('Video.js', ['Video players'], 22, url=raw_url, pattern=_VIDEOJS_FILENAME_RE)
        if 'mathjax' in lowered:
            _add_hint('MathJax', ['JavaScript graphics'], 24, url=raw_url, pattern=_MATHJAX_FILENAME_RE)
        if 'core-js' in lowered:
            _add_hint('core-js', ['JavaScript libraries'], 20, url=raw_url, pattern=_CORE_JS_FILENAME_RE)
        if 'yuidoc' in lowered:
            _add_hint('YUI Doc', ['Documentation tools'], 18, url=raw_url, pattern=_YUI_FILENAME_RE)
        if 'yui' in lowered:
            _add_hint('YUI', ['JavaScript libraries'], 18, url=raw_url, pattern=_YUI_FILENAME_RE)
        if 'popper' in lowered:
            _add_hint('Popper', ['JavaScript libraries'], 12, url=raw_url)
        if 'fontawesome' in lowered or 'font-awesome' in lowered:
            _add_hint('Font Awesome', ['Font scripts'], 14, url=raw_url)
        if 'fonts.googleapis.com' in lowered:
            _add_hint('Google Font API', ['Font scripts'], 14, url=raw_url)
        if 'cdn.jsdelivr.net' in lowered:
            _add_hint('jsDelivr', ['CDN'], 30, url=raw_url)
        if 'gtag/js' in lowered:
            _add_hint('Google Analytics', ['Analytics'], 25, url=raw_url)
        if 'googletagmanager.com/gtm.js' in lowered or 'gtm.js' in lowered:
            _add_hint('Google Tag Manager', ['Tag managers','Analytics'], 28, url=raw_url)
        if 'analytics.js' in lowered or 'ga.js' in lowered:
            _add_hint('Google Analytics', ['Analytics'], 20, url=raw_url)
        if re.search(r'\.php(?:\b|\?)', lowered):
            _add_hint('PHP', ['Programming languages'], 18, url=raw_url)
    return hints

    def _has_hint(name: str) -> bool:
        return any(h.get('name') == name for h in hints)

    def _add_hint(name: str, categories: List[str], confidence: int, *, url: str | None = None, pattern: re.Pattern | None = None, version: str | None = None) -> None:
        if _has_hint(name):
            return
        resolved_version = version
        if url and resolved_version is None:
            resolved_version = _extract_asset_version(url, pattern)
        entry = {
            'name': name,
            'version': resolved_version,
            'categories': categories,
            'confidence': confidence
        }
        hints.append(entry)

    for raw_url in urls:
        if not isinstance(raw_url, str) or not raw_url:
            continue
        lowered = raw_url.lower()

        if 'jquery' in lowered:
            _add_hint('jQuery', ['JavaScript libraries'], 20, url=raw_url, pattern=_JQUERY_FILENAME_RE)
        if 'bootstrap' in lowered:
            _add_hint('Bootstrap', ['UI frameworks'], 18, url=raw_url, pattern=_BOOTSTRAP_FILENAME_RE)
        if 'tailwind' in lowered:
            _add_hint('Tailwind CSS', ['UI frameworks','CSS'], 16, url=raw_url, pattern=_TAILWIND_FILENAME_RE)
        if 'vue' in lowered or 'vue.runtime' in lowered:
            _add_hint('Vue.js', ['JavaScript frameworks'], 18, url=raw_url)
        if 'react' in lowered or 'react-dom' in lowered:
            _add_hint('React', ['JavaScript frameworks'], 18, url=raw_url)
        if 'require.js' in lowered or 'requirejs' in lowered:
            _add_hint('RequireJS', ['JavaScript frameworks'], 25, url=raw_url, pattern=_REQUIREJS_FILENAME_RE)
        if 'video.js' in lowered or 'videojs' in lowered:
            _add_hint('Video.js', ['Video players'], 22, url=raw_url, pattern=_VIDEOJS_FILENAME_RE)
        if 'mathjax' in lowered:
            _add_hint('MathJax', ['JavaScript graphics'], 24, url=raw_url, pattern=_MATHJAX_FILENAME_RE)
        if 'core-js' in lowered:
            _add_hint('core-js', ['JavaScript libraries'], 20, url=raw_url, pattern=_CORE_JS_FILENAME_RE)
        if 'yuidoc' in lowered:
            _add_hint('YUI Doc', ['Documentation tools'], 18, url=raw_url, pattern=_YUI_FILENAME_RE)
        if 'yui' in lowered:
            _add_hint('YUI', ['JavaScript libraries'], 18, url=raw_url, pattern=_YUI_FILENAME_RE)
        if 'popper' in lowered:
            _add_hint('Popper', ['JavaScript libraries'], 12, url=raw_url)
        if 'fontawesome' in lowered or 'font-awesome' in lowered:
            _add_hint('Font Awesome', ['Font scripts'], 14, url=raw_url)
        if 'fonts.googleapis.com' in lowered:
            _add_hint('Google Font API', ['Font scripts'], 14, url=raw_url)
        if 'cdn.jsdelivr.net' in lowered:
            _add_hint('jsDelivr', ['CDN'], 30, url=raw_url)
        if 'gtag/js' in lowered:
            _add_hint('Google Analytics', ['Analytics'], 25, url=raw_url)
        if 'googletagmanager.com/gtm.js' in lowered or 'gtm.js' in lowered:
            _add_hint('Google Tag Manager', ['Tag managers','Analytics'], 28, url=raw_url)
        if 'analytics.js' in lowered or 'ga.js' in lowered:
            _add_hint('Google Analytics', ['Analytics'], 20, url=raw_url)
        if re.search(r'\.php(?:|\?)', lowered):
            _add_hint('PHP', ['Programming languages'], 18, url=raw_url)
    return hints


def _merge_hint_meta(dest: Dict[str, Any], src: Dict[str, Any]) -> None:
    """Recursively merge heuristic hint metadata dictionaries."""
    for key, value in src.items():
        if key not in dest:
            dest[key] = value
            continue
        current = dest.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            _merge_hint_meta(current, value)
        elif isinstance(current, list) and isinstance(value, list):
            existing = current
            for item in value:
                if item not in existing:
                    existing.append(item)
        else:
            dest[key] = value


def _attach_raw_hint_meta(target: Dict[str, Any]) -> None:
    """Copy browser/runtime hint metadata from raw payload into tiered block."""
    if not isinstance(target, dict):
        return
    raw_block = target.get('raw')
    if not isinstance(raw_block, dict):
        return
    node_hint_meta = raw_block.get('_techscan_hint_meta') or raw_block.get('techscan_hint_meta')
    if not isinstance(node_hint_meta, dict) or not node_hint_meta:
        return
    tier_block = target.setdefault('tiered', {})
    dest_hint = tier_block.setdefault('hint_meta', {})
    if isinstance(dest_hint, dict):
        _merge_hint_meta(dest_hint, node_hint_meta)
    else:
        tier_block['hint_meta'] = node_hint_meta
    tier_block.setdefault('hint_meta_source', 'node-runtime')


def _extract_asset_version(url: str | None, pattern: re.Pattern | None = None) -> str | None:
    if not url or not isinstance(url, str):
        return None
    match = _ASSET_VERSION_QUERY_RE.search(url)
    if match:
        return match.group(1)
    if pattern:
        match = pattern.search(url)
        if match:
            return match.group(1)
    return None


def _apply_hint_meta_detections(payload: Dict[str, Any]) -> None:
    """Derive additional technologies from extras/hint metadata (runtime JS context)."""
    if not isinstance(payload, dict):
        return
    techs = payload.setdefault('technologies', [])
    if not isinstance(techs, list):
        return
    raw_block = payload.get('raw') if isinstance(payload.get('raw'), dict) else None
    if not raw_block:
        return
    extras = raw_block.get('extras') if isinstance(raw_block.get('extras'), dict) else None
    if not extras:
        return
    scripts = [s for s in extras.get('scripts') or [] if isinstance(s, str) and s]
    links = [l for l in extras.get('links') or [] if isinstance(l, str) and l]
    body_classes = [cls.lower() for cls in extras.get('body_classes') or [] if isinstance(cls, str)]
    if not scripts and not links and not body_classes:
        return
    categories_bucket = payload.setdefault('categories', {})

    def _find_entry(canon_name: str | None) -> dict | None:
        if not canon_name:
            return None
        for entry in techs:
            existing = canonicalize_tech_name(entry.get('name'))
            if existing == canon_name:
                return entry
        return None

    def _ensure_category_entry(name: str, version: str | None, cats: List[str]) -> None:
        for cat in cats:
            bucket = categories_bucket.setdefault(cat, [])
            if not any(item.get('name') == name and item.get('version') == version for item in bucket):
                bucket.append({'name': name, 'version': version})

    def _add_hint_entry(name: str, cats: List[str], confidence: int, *, version: str | None = None, url: str | None = None, note: str | None = None) -> None:
        canon = canonicalize_tech_name(name) or name
        existing_entry = _find_entry(canon)
        if existing_entry:
            if version and not existing_entry.get('version'):
                existing_entry['version'] = version
            return
        evidence: List[dict] = []
        if url:
            ev = {'kind': 'asset', 'source': 'hint-meta', 'url': url}
            snippet = infer_snippet(url)
            if snippet:
                ev['snippet'] = snippet
            if note:
                ev['note'] = note
            evidence.append(ev)
        elif note:
            evidence.append({'kind': 'hint', 'source': 'hint-meta', 'note': note})
        entry = {
            'name': name,
            'version': version,
            'categories': cats,
            'confidence': confidence,
            'evidence': evidence
        }
        techs.append(entry)
        _ensure_category_entry(name, version, cats)

    all_urls = scripts + links
    jq_migrate_url = next((url for url in scripts if 'jquery-migrate' in url.lower()), None)
    if jq_migrate_url:
        jq_version = _extract_asset_version(jq_migrate_url, _JQUERY_MIGRATE_FILENAME_RE)
        _add_hint_entry('jQuery Migrate', ['JavaScript libraries'], 45, version=jq_version, url=jq_migrate_url)

    hello_url = next((url for url in all_urls if 'hello-elementor' in url.lower()), None)
    hello_body = any('hello-elementor' in cls for cls in body_classes)
    if hello_url or hello_body:
        note = 'detected via body class' if hello_body and not hello_url else None
        _add_hint_entry('Hello Elementor Theme', ['WordPress themes'], 40, url=hello_url, note=note)

    wpml_url = None
    for candidate in all_urls:
        lowered = candidate.lower()
        if 'wp-content' not in lowered:
            continue
        if 'sitepress-multilingual-cms' in lowered or ('wpml' in lowered and 'plugins' in lowered):
            wpml_url = candidate
            break
    if wpml_url:
        wpml_version = _extract_asset_version(wpml_url)
        _add_hint_entry('WordPress Multilingual Plugin (WPML)', ['WordPress plugins','Localization'], 45, version=wpml_version, url=wpml_url)

    multisite_url = next((url for url in all_urls if '/wp-content/uploads/sites/' in url.lower()), None)
    if multisite_url:
        _add_hint_entry('WordPress Multisite', ['Content management systems'], 35, url=multisite_url)


def merge_heuristic_payload(target: Dict[str, Any], heuristic: Dict[str, Any], *, domain: str | None = None) -> None:
    """Merge heuristic technologies/categories + metadata into the final scan result."""
    if not heuristic:
        return
    try:
        if not isinstance(target.get('technologies'), list):
            target['technologies'] = []
        ttechs = target.setdefault('technologies', [])
        existing_names = {t.get('name') for t in ttechs if isinstance(t, dict) and t.get('name')}
        for htech in heuristic.get('technologies') or []:
            if not isinstance(htech, dict):
                continue
            name = canonicalize_tech_name(htech.get('name'))
            if not name or name in existing_names:
                continue
            htech['name'] = name
            ttechs.append(htech)
            existing_names.add(name)
        if not isinstance(target.get('categories'), dict):
            target['categories'] = {}
        rcats = target.setdefault('categories', {})
        for cat, arr in (heuristic.get('categories') or {}).items():
            if not isinstance(arr, list):
                continue
            bucket = rcats.setdefault(cat, [])
            existing_pairs = {(b.get('name'), b.get('version')) for b in bucket if isinstance(b, dict)}
            for item in arr:
                if not isinstance(item, dict):
                    continue
                key = (item.get('name'), item.get('version'))
                if key in existing_pairs:
                    continue
                bucket.append({'name': item.get('name'), 'version': item.get('version')})
                existing_pairs.add(key)
        tiered_src = heuristic.get('tiered') or {}
        tiered_dest = target.setdefault('tiered', {})
        if heuristic.get('duration') is not None:
            tiered_dest['heuristic_duration'] = heuristic.get('duration')
        if tiered_src.get('reason'):
            tiered_dest['heuristic_reason'] = tiered_src.get('reason')
        tiered_dest['used'] = True
        hint_meta = tiered_src.get('hint_meta') if isinstance(tiered_src.get('hint_meta'), dict) else None
        if hint_meta:
            dest_hint = tiered_dest.setdefault('hint_meta', {})
            _merge_hint_meta(dest_hint, hint_meta)
    except Exception as exc:
        logging.getLogger('techscan.tiered').debug('merge heuristic failed domain=%s err=%s', domain or target.get('domain'), exc)

_heuristics_lock = threading.Lock()
_heuristics_patterns: list[tuple[re.Pattern, int]] = []

# Cache for lightweight HTML sniff results: {domain: {'ts': float, 'techs': [...], 'meta': {...}}}
_html_sniff_cache: Dict[str, Dict[str, Any]] = {}
_html_sniff_lock = threading.Lock()
_html_sniff_hits = 0
_html_sniff_misses = 0

def _sniff_html(domain: str) -> Dict[str, Any]:
    """Lightweight single-request HTML sniff for CMS/framework hints.
    Returns {'techs': [...], 'meta': {...}}. Uses HTTPS first, falls back to HTTP if HTTPS fails early.
    Caching governed by TECHSCAN_HTML_SNIFF_CACHE_TTL (seconds, default 300). Max bytes & timeout configurable.
    """
    global _html_sniff_hits, _html_sniff_misses
    if os.environ.get('TECHSCAN_HTML_SNIFF','1') != '1':
        return {'techs': [], 'meta': {'disabled': True}}
    ttl = 300
    try:
        ttl = int(os.environ.get('TECHSCAN_HTML_SNIFF_CACHE_TTL','300'))
    except ValueError:
        ttl = 300
    now = time.time()
    if ttl > 0:
        with _html_sniff_lock:
            ent = _html_sniff_cache.get(domain)
            if ent and (now - ent['ts'] < ttl):
                # Return cached copy
                _html_sniff_hits += 1
                return {'techs': ent.get('techs',[]), 'meta': {**(ent.get('meta') or {}), 'cache_age': round(now-ent['ts'],2), 'cached': True}}
    _html_sniff_misses += 1
    # Perform fresh sniff
    import http.client
    sniff_timeout = 1.5
    try:
        sniff_timeout = float(os.environ.get('TECHSCAN_HTML_SNIFF_TIMEOUT','1.5'))
    except ValueError:
        pass
    max_bytes = 20000
    try:
        max_bytes = int(os.environ.get('TECHSCAN_HTML_SNIFF_BYTES','20000'))
    except ValueError:
        pass
    schemes = ['https','http']
    raw_html = b''
    used_scheme = None
    err: Exception | None = None
    for scheme in schemes:
        try:
            conn_cls = http.client.HTTPSConnection if scheme=='https' else http.client.HTTPConnection
            conn = conn_cls(domain, timeout=sniff_timeout)
            conn.request('GET','/', headers={'User-Agent':'TechScan/sniff'})
            resp = conn.getresponse()
            if resp.status >= 400:
                conn.close()
                continue
            while len(raw_html) < max_bytes:
                chunk = resp.read(min(4096, max_bytes-len(raw_html)))
                if not chunk:
                    break
                raw_html += chunk
            conn.close()
            used_scheme = scheme
            break
        except Exception as e:
            err = e
            continue
    techs: List[Dict[str, Any]] = []
    meta: Dict[str, Any] = {'bytes': len(raw_html), 'timeout': sniff_timeout, 'scheme': used_scheme, 'truncated': len(raw_html) >= max_bytes}
    if err and not used_scheme:
        meta['error'] = str(err)
    if raw_html:
        sample = raw_html.decode('utf-8', errors='ignore')
        low = sample.lower()
        def add(name, categories, confidence=20):
            techs.append({'name': name, 'version': None, 'categories': categories, 'confidence': confidence})
        # WordPress / Joomla / Drupal
        if ('wp-content/' in low) or ('wp-includes/' in low) or ('content="wordpress' in low):
            add('WordPress (sniff)', ['CMS','Blogs'], 25)
        if 'joomla!' in low:
            add('Joomla (sniff)', ['CMS'], 20)
        if 'name="generator" content="drupal' in low or 'content="drupal ' in low:
            add('Drupal (sniff)', ['CMS'], 20)
        # Laravel detection heuristics
        if ('laravel' in low and ('csrf-token' in low or 'routes/web.php' in low)) or 'x-powered-by" content="laravel' in low:
            add('Laravel (sniff)', ['Frameworks'], 18)
        # CodeIgniter (common strings, not very reliable)
        if 'codeigniter' in low and ('ci_session' in low or 'system/core/codeigniter.php' in low):
            add('CodeIgniter (sniff)', ['Frameworks'], 15)
        # Next.js / Nuxt
        if 'next-data' in low and '_next' in low:
            add('Next.js (sniff)', ['JavaScript frameworks'], 15)
        if 'nuxt=' in low or 'nuxt.config' in low:
            add('Nuxt.js (sniff)', ['JavaScript frameworks'], 15)
        meta['detected'] = len(techs)
    if ttl > 0:
        with _html_sniff_lock:
            _html_sniff_cache[domain] = {'ts': now, 'techs': techs, 'meta': meta}
    return {'techs': techs, 'meta': meta}

def _sniff_cache_snapshot():
    now = time.time()
    with _html_sniff_lock:
        items = []
        for dom, ent in _html_sniff_cache.items():
            age = round(now - ent.get('ts', now), 2)
            items.append({'domain': dom, 'age_s': age, 'detected': len(ent.get('techs') or []), 'bytes': ent.get('meta',{}).get('bytes')})
        items.sort(key=lambda x: x['age_s'])
        return {
            'entries': len(_html_sniff_cache),
            'items': items[:200],
            'hits': _html_sniff_hits,
            'misses': _html_sniff_misses
        }

# Track domains that currently have a deferred background scan in progress
_deferred_lock = threading.Lock()
_deferred_inflight: set[str] = set()

def load_heuristic_patterns(config_path: str | None = None) -> None:
    """Load heuristic timeout patterns from JSON file.
    File format: list of objects: {"pattern": "regex", "min_timeout": int}
    Comments (# ...) and blank lines are ignored if file is .jsonl style (one JSON per line) OR array JSON.
    Both array JSON and JSONL accepted.
    """
    path = config_path or os.environ.get('TECHSCAN_HEURISTICS_FILE') or str(pathlib.Path(__file__).resolve().parent / 'heuristics_timeout.json')
    p = pathlib.Path(path)
    patterns: list[tuple[re.Pattern, int]] = []
    if not p.exists():
        logging.getLogger('techscan.heuristics').info('heuristics file not found path=%s (using empty list)', path)
        with _heuristics_lock:
            _heuristics_patterns.clear()
        return
    try:
        text = p.read_text(encoding='utf-8')
        text_strip = text.strip()
        entries: list[dict[str, object]] = []
        if text_strip.startswith('['):  # JSON array
            data = json.loads(text_strip)
            if isinstance(data, list):
                entries = [e for e in data if isinstance(e, dict)]
        else:  # JSONL style
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    logging.getLogger('techscan.heuristics').warning('skip invalid JSONL line: %s', line[:80])
                    continue
                if isinstance(obj, dict):
                    entries.append(obj)
        for e in entries:
            pat_s = e.get('pattern') if isinstance(e.get('pattern'), str) else None
            mt = e.get('min_timeout') if isinstance(e.get('min_timeout'), int) else None
            if not pat_s or mt is None:
                continue
            try:
                pat = re.compile(pat_s)
                patterns.append((pat, mt))
            except re.error as er:
                logging.getLogger('techscan.heuristics').warning('invalid regex pattern=%s err=%s', pat_s, er)
        with _heuristics_lock:
            _heuristics_patterns.clear()
            _heuristics_patterns.extend(patterns)
        logging.getLogger('techscan.heuristics').info('loaded heuristics count=%d path=%s', len(patterns), path)
    except Exception as e:
        logging.getLogger('techscan.heuristics').error('failed loading heuristics path=%s err=%s', path, e)

def apply_min_timeout(domain: str, requested: int) -> int:
    with _heuristics_lock:
        patterns = list(_heuristics_patterns)
    for pat, min_to in patterns:
        if pat.search(domain):
            return max(requested, min_to)
    return requested

# Initial load at import
load_heuristic_patterns()

def scan_domain(domain: str, wappalyzer_path: str, timeout: int = 45, retries: int = 0, full: bool = False) -> Dict[str, Any]:
    original_input = domain
    domain = validate_domain(extract_host(domain))
    # Preflight connectivity check
    if not _preflight(domain):
        logging.getLogger('techscan.preflight').warning('preflight unreachable domain=%s', domain)
        # Optional heuristic fallback if tiered enabled
        if os.environ.get('TECHSCAN_TIERED','0') == '1':
            try:
                from . import heuristic_fast
                hres = heuristic_fast.run_heuristic(domain, budget_ms=int(os.environ.get('TECHSCAN_TIERED_BUDGET_MS','1200')), allow_empty_early=True)
                hres.setdefault('tiered', {})['preflight_unreachable'] = True
                hres['engine'] = 'heuristic-tier0-preflight'
                hres['scan_mode'] = 'fast'
                return hres
            except Exception:
                pass
        raise RuntimeError('preflight unreachable')
    # Quarantine short-circuit (skip expensive scan and optionally return heuristic fallback)
    if _check_quarantine(domain):
        logging.getLogger('techscan.quarantine').info('skip scan (quarantined) domain=%s', domain)
        # Attempt heuristic immediate if tiered enabled or forced
        if os.environ.get('TECHSCAN_TIERED','0') == '1':
            try:
                from . import heuristic_fast
                hres = heuristic_fast.run_heuristic(domain, budget_ms=int(os.environ.get('TECHSCAN_TIERED_BUDGET_MS','1600')), allow_empty_early=True)
                hres.setdefault('tiered', {})['quarantined'] = True
                hres['engine'] = 'heuristic-tier0-quarantine'
                hres['scan_mode'] = 'fast'
                return hres
            except Exception:
                pass
        raise RuntimeError('domain in temporary quarantine')
    # Ultra quick heuristic-only shortcut
    if os.environ.get('TECHSCAN_ULTRA_QUICK','0') == '1' and not full:
        try:
            from . import heuristic_fast
            uq_budget = int(os.environ.get('TECHSCAN_QUICK_BUDGET_MS', str(QUICK_DEFAULT_BUDGET_MS)))
            uq = heuristic_fast.run_heuristic(domain, budget_ms=uq_budget, allow_empty_early=True)
            uq['engine'] = 'heuristic-ultra'
            uq['scan_mode'] = 'fast'
            if os.environ.get('TECHSCAN_SKIP_VERSION_AUDIT','0') != '1' and os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
                try:
                    version_audit.audit_versions(uq)
                except Exception as ae:
                    logging.getLogger('techscan.audit').debug('ultra audit fail domain=%s err=%s', domain, ae)
            return uq
        except Exception as ue:
            logging.getLogger('techscan.ultra').warning('ultra quick path failed domain=%s err=%s (fall back)', domain, ue)
    persist = os.environ.get('TECHSCAN_PERSIST_BROWSER','0') == '1'
    # Python-local Wappalyzer-style detection (no browser) if enabled and not full mode
    use_py_wapp = (os.environ.get('TECHSCAN_PY_WAPP','0') == '1') and not persist
    local_scanner = pathlib.Path(__file__).resolve().parent.parent / 'node_scanner' / ('scanner.js' if not persist else 'server.js')
    if use_py_wapp and not full:
        # Fast local detector; skip Node/Chromium entirely
        logger = logging.getLogger('techscan.scan_domain')
        op_start = time.time()
        try:
            from . import wapp_local
            data = wapp_local.detect(domain, wappalyzer_path, timeout=min(timeout, 6))
            op_end = time.time()
            categories_map = load_categories(wappalyzer_path)
            result = normalize_result(domain, data, categories_map)
            _apply_hint_meta_detections(result)
            # Synthetic header detection remains useful to add server/CDN hints
            synthetic_allowed = (os.environ.get('TECHSCAN_SYNTHETIC_HEADERS', '1') == '1' and os.environ.get('TECHSCAN_DISABLE_SYNTHETIC','0') != '1')
            synth_start = time.time()
            if synthetic_allowed:
                try:
                    synth = synthetic_header_detection(domain, timeout=min(5, timeout))
                    if synth:
                        existing_names = {t['name'] for t in result['technologies']}
                        added = False
                        for tech in synth:
                            if tech['name'] not in existing_names:
                                result['technologies'].append(tech)
                                for cat in tech.get('categories', []):
                                    result['categories'].setdefault(cat, []).append({'name': tech['name'], 'version': tech.get('version')})
                                added = True
                        if added:
                            logging.getLogger('techscan.synthetic').debug('added synthetic headers domain=%s items=%d', domain, len(synth))
                            with _stats_lock:
                                STATS['synthetic']['headers'] += 1
                except Exception as se:
                    logging.getLogger('techscan.synthetic').debug('synthetic header detection failed domain=%s err=%s', domain, se)
            synth_end = time.time()
            result['scan_mode'] = 'fast'
            result['engine'] = 'wappalyzer-py-local'
            result['timing'] = {
                'overall_seconds': round((op_end - op_start), 3),
                'engine_seconds': round((op_end - op_start), 3),
                'overhead_seconds': 0.0
            }
            result['duration'] = round((op_end - op_start), 2)
            result['started_at'] = op_start
            result['finished_at'] = op_end
            result.setdefault('phases', {})['engine_ms'] = int((op_end - op_start) * 1000)
            result['phases']['synthetic_ms'] = int((synth_end - synth_start) * 1000) if synthetic_allowed else 0
            logger.info('scan success domain=%s engine=%s duration=%.2fs', domain, result['engine'], (op_end - op_start))
            _record_success(domain)
            # Version audit
            if os.environ.get('TECHSCAN_SKIP_VERSION_AUDIT','0') != '1' and os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
                va_start = time.time()
                try:
                    version_audit.audit_versions(result)
                except Exception as ae:
                    logging.getLogger('techscan.audit').debug('audit fail py-local domain=%s err=%s', domain, ae)
                finally:
                    va_end = time.time()
                    duration_ms = int((va_end - va_start)*1000)
                    result.setdefault('phases', {})['version_audit_ms'] = duration_ms
                    with _stats_lock:
                        STATS['phases']['version_audit_ms'] += duration_ms
                        STATS['phases']['version_audit_count'] += 1
            return result
        except Exception as e:
            # Fall back to existing engines if py-local fails
            logging.getLogger('techscan.scan_domain').warning('py-local detector failed domain=%s err=%s (fallback to existing path)', domain, e)

    if persist:
        # We'll route via persistent_client, but keep mode label
        mode = 'persist'
        cmd = ['node', str(local_scanner), domain]
    else:
        if local_scanner.exists():
            cli = local_scanner
            mode = 'local'
            cmd = ['node', str(cli), domain]
        else:
            cli = pathlib.Path(wappalyzer_path) / 'src' / 'drivers' / 'npm' / 'cli.js'
            if not cli.exists():
                raise FileNotFoundError('wappalyzer cli not found at expected path')
            mode = 'external'
            url = f'https://{domain}'
            cmd = ['node', str(cli), url]
    last_err: Exception | None = None
    # attempts include first try + retries
    # Add one implicit timeout retry if user did not specify retries (best-effort)
    implicit_timeout_retry = (retries == 0)
    # Allow explicit disabling of implicit timeout retry (e.g., micro fallback single-shot)
    if os.environ.get('TECHSCAN_DISABLE_IMPLICIT_RETRY','0') == '1':
        implicit_timeout_retry = False
    attempts = retries + 1
    # Max attempts override via env
    try:
        max_attempts_env = int(os.environ.get('TECHSCAN_MAX_ATTEMPTS','0'))
        if max_attempts_env > 0 and attempts > max_attempts_env:
            attempts = max_attempts_env
    except ValueError:
        pass
    logger = logging.getLogger('techscan.scan_domain')
    # Heuristic raise timeout for certain domains (effective timeout)
    eff_timeout = apply_min_timeout(domain, timeout)
    logger.debug('effective_timeout domain=%s requested=%s effective=%s attempts=%d implicit_retry=%s full=%s',
                 domain, timeout, eff_timeout, attempts, implicit_timeout_retry, full)
    # Base timeout used for adaptive bump calculations (store original effective after heuristics)
    base_timeout = eff_timeout
    adaptive_used = False
    t0 = time.time()
    started_at = t0
    hard_cap_env = os.environ.get('TECHSCAN_HARD_TIMEOUT_S')
    hard_cap: float | None = None
    try:
        if hard_cap_env:
            hard_cap = float(hard_cap_env)
    except ValueError:
        hard_cap = None
    attempt = 1
    # Use while so we can extend 'attempts' dynamically (adaptive implicit retry)
    while attempt <= attempts:
        # Hard cap enforcement: jika sudah melewati batas global, hentikan
        if hard_cap and (time.time() - t0) > hard_cap:
            logger.warning('hard cap reached domain=%s cap=%ss attempts=%d', domain, hard_cap, attempt)
            raise RuntimeError(f'hard cap {hard_cap}s reached before completion')
        logger.debug('scan start domain=%s attempt=%d/%d timeout=%s cmd=%s', domain, attempt, attempts, eff_timeout, ' '.join(cmd))
        try:
            # Prepare env for subprocess (do not mutate global os.environ directly)
            env = os.environ.copy()
            # Pass navigation timeout in ms (slightly lower than total Python timeout allowance)
            env['TECHSCAN_NAV_TIMEOUT'] = str(int(min(eff_timeout - 1, eff_timeout) * 1000)) if eff_timeout > 2 else str(int(eff_timeout * 1000))
            if full:
                env['TECHSCAN_FULL'] = '1'
            # Explicit toggle for resource blocking default (fast mode blocks). Full mode unsets blocking unless user forces.
            if full:
                env.setdefault('TECHSCAN_BLOCK_RESOURCES', '0')
            op_start = time.time()
            if persist:
                # Use persistent client
                from . import persistent_client as pc
                data = pc.scan(domain, full=full)
            else:
                proc = sproc.safe_run(cmd, capture_output=True, text=True, timeout=eff_timeout, env=env)
                if proc.returncode != 0:
                    stderr = proc.stderr.strip()
                    if 'Cannot find module' in stderr and 'puppeteer' in stderr:
                        raise RuntimeError(
                            'puppeteer module missing for Wappalyzer CLI. Perbaiki dengan: '
                            '1) cd ke repo wappalyzer lalu jalankan "yarn install" kemudian "yarn run link". '
                            'Atau 2) Install paket npm wappalyzer lokal: "npm init -y && npm install wappalyzer" lalu set WAPPALYZER_PATH ke folder paket.'
                        )
                    if mode == 'external' and attempt == 1 and 'https://' in cmd[-1]:
                        url_http = cmd[-1].replace('https://', 'http://', 1)
                        cmd[-1] = url_http
                        last_err = RuntimeError(stderr or 'scan failed')
                        continue
                    raise RuntimeError(stderr or 'scan failed')
                try:
                    data = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    raise RuntimeError('invalid json output')
            op_end = time.time()
            categories_map = load_categories(wappalyzer_path)
            result = normalize_result(domain, data, categories_map)
            _attach_raw_hint_meta(result)
            _apply_hint_meta_detections(result)
            # Synthetic header-based detection (optional + allow disable)
            synthetic_allowed = (os.environ.get('TECHSCAN_SYNTHETIC_HEADERS', '1') == '1' and os.environ.get('TECHSCAN_DISABLE_SYNTHETIC','0') != '1')
            synth_start = time.time()
            if synthetic_allowed:
                try:
                    synth = synthetic_header_detection(domain, timeout=min(5, timeout))
                    if synth:
                        # Merge synthetic techs if not already present
                        existing_names = {t['name'] for t in result['technologies']}
                        added = False
                        for tech in synth:
                            if tech['name'] not in existing_names:
                                result['technologies'].append(tech)
                                for cat in tech.get('categories', []):
                                    result['categories'].setdefault(cat, []).append({'name': tech['name'], 'version': tech.get('version')})
                                added = True
                        if added:
                            logging.getLogger('techscan.synthetic').debug('added synthetic headers domain=%s items=%d', domain, len(synth))
                            with _stats_lock:
                                STATS['synthetic']['headers'] += 1
                except Exception as se:
                    logging.getLogger('techscan.synthetic').debug('synthetic header detection failed domain=%s err=%s', domain, se)
            synth_end = time.time()
            result['scan_mode'] = 'full' if full else 'fast'
            result['engine'] = f'wappalyzer-{mode}'
            if attempt > 1:
                result['retries'] = attempt - 1
            if adaptive_used:
                result['adaptive_timeout'] = True
            finished_at = time.time()
            elapsed = finished_at - t0
            engine_elapsed = op_end - op_start
            if engine_elapsed < 0:
                engine_elapsed = 0
            result['timing'] = {
                'overall_seconds': round(elapsed, 3),
                'engine_seconds': round(engine_elapsed, 3),
                'overhead_seconds': round(elapsed - engine_elapsed, 3)
            }
            result['duration'] = round(elapsed, 2)
            result['started_at'] = started_at
            result['finished_at'] = finished_at
            # Add phases sub-structure (ms)
            result.setdefault('phases', {})['engine_ms'] = int(engine_elapsed * 1000)
            result['phases']['synthetic_ms'] = int((synth_end - synth_start) * 1000) if synthetic_allowed else 0
            logger.info('scan success domain=%s engine=%s duration=%.2fs attempts=%d', domain, result['engine'], elapsed, attempt)
            _record_success(domain)
            # stats: record duration
            with _stats_lock:
                mode_key = 'full' if full else 'fast'
                STATS['scans'] += 1
                bucket = STATS['durations'][mode_key]
                bucket['count'] += 1
                bucket['total'] += elapsed
                # aggregate phase timings
                STATS['phases']['engine_ms'] += int(engine_elapsed * 1000)
                STATS['phases']['engine_count'] += 1
                if synthetic_allowed:
                    STATS['phases']['synthetic_ms'] += result['phases']['synthetic_ms']
                    STATS['phases']['synthetic_count'] += 1
                STATS['totals']['scan_count'] += 1
                STATS['totals']['total_overall_ms'] += int(elapsed * 1000)
                try:
                    STATS['recent_samples'][mode_key].append(elapsed)
                except Exception:
                    pass
                # increment synthetic counters if present in technologies
                try:
                    tech_names = {t.get('name') for t in result.get('technologies', [])}
                    if 'Tailwind CSS' in tech_names:
                        STATS['synthetic']['tailwind'] += 1
                    if 'Floodlight' in tech_names or 'DoubleClick Floodlight' in tech_names:
                        STATS['synthetic']['floodlight'] += 1
                except Exception:
                    pass
            return result
        except (sproc.TimeoutExpired) as te:
            last_err = te
            _record_failure(domain)
            with _stats_lock:
                STATS['errors']['timeout'] += 1
            # If implicit retry allowed and we have not used it yet, extend attempts by one.
            if implicit_timeout_retry:
                implicit_timeout_retry = False
                attempts += 1  # extend total allowed attempts (unless disabled)
                disable_adaptive = os.environ.get('TECHSCAN_DISABLE_ADAPTIVE','0') == '1'
                if not disable_adaptive:
                    # Adaptive bump: increase timeout (cap 120s) and relax blocking in fast mode
                    new_timeout = min(int(base_timeout * 1.6), base_timeout + 60, 120)
                    if new_timeout > eff_timeout:
                        logger.warning('adaptive timeout bump domain=%s old=%ss new=%ss', domain, eff_timeout, new_timeout)
                        eff_timeout = new_timeout
                        adaptive_used = True
                else:
                    logger.debug('adaptive bump disabled domain=%s', domain)
                if not full and os.environ.get('TECHSCAN_BLOCK_RESOURCES', '1') != '0':
                    os.environ['TECHSCAN_BLOCK_RESOURCES'] = '0'
                    logger.info('disabled resource blocking for retry domain=%s', domain)
                logger.info('implicit timeout retry scheduled domain=%s new_attempts=%d', domain, attempts)
                attempt += 1
                continue
            if attempt == attempts:
                elapsed_all = time.time()-t0
                logger.warning('scan timeout domain=%s after %.2fs attempts=%d', domain, elapsed_all, attempt)
                # Timeout fallback: jika diaktifkan, kembalikan hasil heuristic cepat (fresh) agar tidak error total
                if os.environ.get('TECHSCAN_TIMEOUT_FALLBACK','0') == '1' and not full:
                    try:
                        from . import heuristic_fast
                        hres = heuristic_fast.run_heuristic(domain, budget_ms= int(os.environ.get('TECHSCAN_TIERED_BUDGET_MS','1800')), allow_empty_early=True)
                        hres.setdefault('tiered', {})['timeout_fallback'] = True
                        hres['engine'] = 'heuristic-tier0-timeout'
                        hres['scan_mode'] = 'fast'
                        hres['timeout_error'] = f'timeout after {eff_timeout}s (attempt {attempt}/{attempts})'
                        hres['duration'] = round(elapsed_all,2)
                        return hres
                    except Exception:
                        pass
                raise RuntimeError(f'timeout after {eff_timeout}s (attempt {attempt}/{attempts})')
            attempt += 1
            continue
        except Exception as e:  # other errors
            last_err = e
            _record_failure(domain)
            if attempt == attempts:
                logger.error('scan error domain=%s err=%s', domain, e)
                cls = _classify_error(e)
                with _stats_lock:
                    if cls in STATS['errors']:
                        STATS['errors'][cls] += 1
                    else:
                        STATS['errors']['other'] += 1
                raise
            attempt += 1
            continue
        # success path - break loop (return already executed)
        break
    # Should not reach here
    raise last_err or RuntimeError('unknown scan failure')
    

def get_cached_or_scan(domain: str, wappalyzer_path: str, timeout: int = 45, fresh: bool = False, retries: int = 0, ttl: int | None = None, full: bool = False) -> Dict[str, Any]:
    now = time.time()
    eff_ttl = ttl if (isinstance(ttl, int) and ttl > 0) else CACHE_TTL
    cache_key = f"{('full' if full else 'fast')}:{domain}"
    if not fresh:
        with _lock:
            item = _cache.get(cache_key)
            if item and now - item['ts'] < item.get('ttl', CACHE_TTL):
                with _stats_lock:
                    STATS['hits'] += 1
                    STATS['mode_hits']['full' if full else 'fast'] += 1
                cached_result = {**item['data'], 'cached': True}
                # Persist cache hit to DB for history
                try:
                    from . import db as _db
                    # Derive timeout used (not stored previously) best effort
                    _db.save_scan(cached_result, from_cache=True, timeout_used=timeout)
                except Exception as db_ex:
                    logging.getLogger('techscan.db').debug('save_scan cache hit failed domain=%s err=%s', domain, db_ex)
                return cached_result
    with _stats_lock:
        STATS['misses'] += 1
        STATS['mode_misses']['full' if full else 'fast'] += 1
    # Tiered heuristic pre-scan (only for fast mode, not full) if enabled
    tiered_enabled = (not full) and (os.environ.get('TECHSCAN_TIERED','0') == '1')
    heuristic_result: Dict[str, Any] | None = None

    if tiered_enabled:
        try:
            from . import heuristic_fast
            budget_ms = int(os.environ.get('TECHSCAN_TIERED_BUDGET_MS','1800'))
            allow_empty = os.environ.get('TECHSCAN_TIERED_ALLOW_EMPTY','0') == '1'
            hstart = time.time()
            heuristic_result = heuristic_fast.run_heuristic(domain, budget_ms=budget_ms, allow_empty_early=allow_empty)
            # Early return decision
            if heuristic_result.get('tiered', {}).get('early_return'):
                heuristic_result['tiered']['final'] = True  # type: ignore
                heuristic_result['engine'] = 'heuristic-tier0'
                # Optional: skip full permanently for strong CMS detection (WordPress + ≥1 plugin or Joomla/Drupal) when flag enabled
                if os.environ.get('TECHSCAN_SKIP_FULL_STRONG','0') == '1':
                    try:
                        technames = {t.get('name') for t in heuristic_result.get('technologies', [])}
                        strong = False
                        if 'WordPress' in technames:
                            # count WP plugins (rough heuristic: technologies containing spaces or plugin names common)
                            plugins = [n for n in technames if n in ('WooCommerce','Elementor','Yoast SEO','Wordfence','Contact Form 7','WPForms','WP Rocket','Slider Revolution')]
                            if plugins:
                                strong = True
                        if technames & {'Joomla','Drupal'}:
                            strong = True
                        if strong:
                            heuristic_result.setdefault('tiered', {})['strong_cms_skip_full'] = True
                    except Exception:
                        pass
                if os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
                    try:
                        version_audit.audit_versions(heuristic_result)
                    except Exception as ae:
                        logging.getLogger('techscan.audit').debug('audit fail early heur domain=%s err=%s', domain, ae)
                # Persist heuristic-only result (mark special engine)
                try:
                    from . import db as _db
                    _db.save_scan(heuristic_result, from_cache=False, timeout_used=timeout)
                except Exception as db_ex:
                    logging.getLogger('techscan.db').debug('save_scan heuristic early return failed domain=%s err=%s', domain, db_ex)
                with _lock:
                    _cache[cache_key] = {'ts': now, 'data': heuristic_result, 'ttl': eff_ttl}
                    with _stats_lock:
                        STATS['cache_entries'] = len(_cache)
                return heuristic_result
            else:
                heuristic_result['tiered']['final'] = False  # type: ignore
                heuristic_result['engine'] = 'heuristic-tier0+pending'
                # If strong CMS and skip flag active, convert to early-return final
                if os.environ.get('TECHSCAN_SKIP_FULL_STRONG','0') == '1':
                    try:
                        technames = {t.get('name') for t in heuristic_result.get('technologies', [])}
                        strong = False
                        if 'WordPress' in technames:
                            plugins = [n for n in technames if n in ('WooCommerce','Elementor','Yoast SEO','Wordfence','Contact Form 7','WPForms','WP Rocket','Slider Revolution')]
                            if plugins:
                                strong = True
                        if technames & {'Joomla','Drupal'}:
                            strong = True
                        if strong:
                            heuristic_result['tiered']['early_return'] = True
                            heuristic_result['tiered']['strong_cms_skip_full'] = True
                            heuristic_result['engine'] = 'heuristic-tier0'
                            heuristic_result['tiered']['final'] = True
                            if os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
                                try:
                                    version_audit.audit_versions(heuristic_result)
                                except Exception:
                                    pass
                            try:
                                from . import db as _db
                                _db.save_scan(heuristic_result, from_cache=False, timeout_used=timeout)
                            except Exception:
                                pass
                            with _lock:
                                _cache[cache_key] = {'ts': now, 'data': heuristic_result, 'ttl': eff_ttl}
                                with _stats_lock:
                                    STATS['cache_entries'] = len(_cache)
                            return heuristic_result
                    except Exception:
                        pass
                # Deferred full scan mode: immediately return heuristic and schedule background Wappalyzer
                if os.environ.get('TECHSCAN_DEFER_FULL','0') == '1' and not full:
                    quick = heuristic_result
                    quick.setdefault('tiered', {})['deferred_full'] = True
                    if os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
                        try:
                            version_audit.audit_versions(quick)
                        except Exception as ae:
                            logging.getLogger('techscan.audit').debug('audit fail deferred quick domain=%s err=%s', domain, ae)
                    quick['engine'] = 'heuristic-tier0+deferred'
                    quick['scan_mode'] = 'fast'
                    # Cache quick response
                    with _lock:
                        _cache[cache_key] = {'ts': now, 'data': quick, 'ttl': eff_ttl}
                        with _stats_lock:
                            STATS['cache_entries'] = len(_cache)
                    # Persist quick response
                    try:
                        from . import db as _db
                        _db.save_scan(quick, from_cache=False, timeout_used=timeout)
                    except Exception:
                        pass
                    # Schedule background scan if not already inflight
                    def _bg_full():
                        # We reuse the same timeout for initial attempt; adaptive logic inside scan_domain may extend
                        try:
                            result_full = scan_domain(domain, wappalyzer_path, timeout=timeout, retries=retries, full=full)
                            # Merge heuristic content similar to later merge logic
                            if heuristic_result:
                                merge_heuristic_payload(result_full, heuristic_result, domain=domain)
                                tier_info = result_full.setdefault('tiered', {})
                                tier_info['deferred_full'] = False
                                tier_info['final'] = True
                                tier_info['from_deferred'] = True
                            # Persist & update cache
                            try:
                                from . import db as _db
                                _db.save_scan(result_full, from_cache=False, timeout_used=timeout)
                            except Exception:
                                pass
                            with _lock:
                                _cache[cache_key] = {'ts': time.time(), 'data': result_full, 'ttl': eff_ttl}
                                with _stats_lock:
                                    STATS['cache_entries'] = len(_cache)
                            logging.getLogger('techscan.defer').info('deferred full scan complete domain=%s duration=%.2fs', domain, result_full.get('duration'))
                        except Exception as e:
                            logging.getLogger('techscan.defer').warning('deferred full scan failed domain=%s err=%s', domain, e)
                        finally:
                            with _deferred_lock:
                                _deferred_inflight.discard(domain)
                    with _deferred_lock:
                        already = domain in _deferred_inflight
                        if not already:
                            _deferred_inflight.add(domain)
                            threading.Thread(target=_bg_full, name=f'defer-full-{domain}', daemon=True).start()
                        else:
                            logging.getLogger('techscan.defer').debug('deferred scan already inflight domain=%s', domain)
                    return quick
                # Auto trigger full scan (background) if heuristic tech count terlalu sedikit (< threshold)
                try:
                    min_trigger = int(os.environ.get('TECHSCAN_AUTO_FULL_MIN_TECH','0'))
                except ValueError:
                    min_trigger = 0
                if not full and min_trigger > 0 and os.environ.get('TECHSCAN_DEFER_FULL','0') != '1':
                    tech_count = len(heuristic_result.get('technologies') or [])
                    if tech_count < min_trigger:
                        # Fast return + schedule full like deferred logic (without marking deferred_full so user tahu ini auto-trigger)
                        auto_quick = heuristic_result
                        auto_quick.setdefault('tiered', {})['auto_trigger_full'] = True
                        if os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
                            try:
                                version_audit.audit_versions(auto_quick)
                            except Exception as ae:
                                logging.getLogger('techscan.audit').debug('audit fail auto quick domain=%s err=%s', domain, ae)
                        auto_quick['engine'] = 'heuristic-tier0+auto'
                        with _lock:
                            _cache[cache_key] = {'ts': now, 'data': auto_quick, 'ttl': eff_ttl}
                            with _stats_lock:
                                STATS['cache_entries'] = len(_cache)
                        try:
                            from . import db as _db
                            _db.save_scan(auto_quick, from_cache=False, timeout_used=timeout)
                        except Exception:
                            pass
                        def _bg_full_auto():
                            try:
                                result_full = scan_domain(domain, wappalyzer_path, timeout=timeout, retries=retries, full=full)
                                if heuristic_result:
                                    merge_heuristic_payload(result_full, heuristic_result, domain=domain)
                                    tier_info = result_full.setdefault('tiered', {})
                                    tier_info['auto_trigger_full'] = True
                                    tier_info['final'] = True
                                    tier_info['from_auto_trigger'] = True
                                try:
                                    from . import db as _db
                                    _db.save_scan(result_full, from_cache=False, timeout_used=timeout)
                                except Exception:
                                    pass
                                with _lock:
                                    _cache[cache_key] = {'ts': time.time(), 'data': result_full, 'ttl': eff_ttl}
                                    with _stats_lock:
                                        STATS['cache_entries'] = len(_cache)
                                logging.getLogger('techscan.auto').info('auto-trigger full scan complete domain=%s duration=%.2fs (initial tech_count=%d)', domain, result_full.get('duration'), tech_count)
                            except Exception as e:
                                logging.getLogger('techscan.auto').warning('auto-trigger full scan failed domain=%s err=%s', domain, e)
                            finally:
                                with _deferred_lock:
                                    _deferred_inflight.discard(domain)
                        with _deferred_lock:
                            if domain not in _deferred_inflight:
                                _deferred_inflight.add(domain)
                                threading.Thread(target=_bg_full_auto, name=f'auto-full-{domain}', daemon=True).start()
                        return auto_quick
        except Exception as he:
            logging.getLogger('techscan.tiered').warning('heuristic pre-scan failed domain=%s err=%s', domain, he)
            heuristic_result = None

    # Single-flight guard: only one leader performs scan_domain. Followers will wait then re-check cache.
    is_leader = _single_flight_enter(cache_key)
    try:
        # Followers (not leader) arrive here after leader finished; return cached result if available
        if not is_leader:
            with _lock:
                item2 = _cache.get(cache_key)
                if item2 and (time.time() - item2['ts'] < item2.get('ttl', CACHE_TTL)):
                    return {**item2['data'], 'cached': True, 'single_flight_follower': True}
            # Edge case: leader failed and no cache populated; proceed to attempt scan (promote self logically)
            is_leader = True
            # Update inflight metric since we are effectively becoming a new leader
            with _stats_lock:
                STATS['single_flight']['inflight'] += 1
        scan_started_at = time.time()
        try:
            result = scan_domain(domain, wappalyzer_path, timeout=timeout, retries=retries, full=full)
        except Exception as e:
            # If timeout or scan error and we have heuristic partial, return heuristic instead of total failure
            if tiered_enabled and heuristic_result:
                heuristic_result.setdefault('tiered', {})['fallback'] = True
                if os.environ.get('TECHSCAN_SKIP_VERSION_AUDIT','0') != '1' and os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
                    try:
                        version_audit.audit_versions(heuristic_result)
                    except Exception as ae:
                        logging.getLogger('techscan.audit').debug('audit fail fallback domain=%s err=%s', domain, ae)
                heuristic_result.setdefault('error', str(e))
                heuristic_result.setdefault('error_class', _classify_error(e))
                logging.getLogger('techscan.tiered').warning('scan failed using heuristic fallback domain=%s err=%s', domain, e)
                with _lock:
                    _cache[cache_key] = {'ts': now, 'data': heuristic_result, 'ttl': eff_ttl}
                    with _stats_lock:
                        STATS['cache_entries'] = len(_cache)
                try:
                    from . import db as _db
                    _db.save_scan(heuristic_result, from_cache=False, timeout_used=timeout)
                except Exception:
                    pass
                return heuristic_result
            _persist_failure_scan(
                domain,
                mode='full' if full else 'fast',
                timeout_used=timeout,
                retries=retries,
                error=e,
                started_at=scan_started_at,
                finished_at=time.time(),
                engine='scan-error',
                raw={'source': 'get_cached_or_scan'}
            )
            raise
    finally:
        if is_leader:
            _single_flight_exit(cache_key)
    # Merge heuristic partial if exists and not early-return
    if heuristic_result and not heuristic_result.get('tiered',{}).get('early_return'):
        merge_heuristic_payload(result, heuristic_result, domain=domain)
    # Version audit on final full result (merged or pure)
    if os.environ.get('TECHSCAN_SKIP_VERSION_AUDIT','0') != '1' and os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
        va_start = time.time()
        try:
            version_audit.audit_versions(result)
        except Exception as ae:
            logging.getLogger('techscan.audit').debug('audit fail full domain=%s err=%s', domain, ae)
        finally:
            va_end = time.time()
            duration_ms = int((va_end - va_start)*1000)
            result.setdefault('phases', {})['version_audit_ms'] = duration_ms
            with _stats_lock:
                STATS['phases']['version_audit_ms'] += duration_ms
                STATS['phases']['version_audit_count'] += 1
    # Persist fresh scan
    try:
        from . import db as _db
        _db.save_scan(result, from_cache=False, timeout_used=timeout)
    except Exception as db_ex:
        logging.getLogger('techscan.db').debug('save_scan fresh failed domain=%s err=%s', domain, db_ex)
    with _lock:
        _cache[cache_key] = {'ts': now, 'data': result, 'ttl': eff_ttl}
        with _stats_lock:
            STATS['cache_entries'] = len(_cache)
    return result


def scan_unified(domain: str, wappalyzer_path: str, budget_ms: int = 6000) -> Dict[str, Any]:
    """Unified, adaptive engine:
    1) Heuristic tier-0 quick probe (HTML GET + headers) for fast CMS/libraries/server hints.
    2) Python-local Wappalyzer rules (no browser) on the same HTML/headers context for broader coverage.
    3) Synthetic header detection (HEAD) for server/CDN/HSTS.
    4) Targeted version enrichment (e.g., WP/Drupal/Joomla).
    5) If still sparse, attempt a single micro Node fallback (strict short timeout, no adaptive retries).
    6) If still below threshold and budget allows, attempt a short full Node fallback (no implicit retry; unblocks resources).

    Returns normalized result with engine='unified' and detailed phases timing.
    """
    logging.getLogger('techscan.unified').info('scan_unified called domain=%s budget_ms=%s', domain, budget_ms)
    t0 = time.time()
    domain = validate_domain(extract_host(domain))
    phases: Dict[str, int] = {}
    techs: List[Dict[str, Any]] = []
    cats: Dict[str, List[Dict[str, Any]]] = {}
    # 1) Heuristic quick
    heur_res: Dict[str, Any] | None = None
    try:
        from . import heuristic_fast
        hstart = time.time()
        heur_res = heuristic_fast.run_heuristic(domain, budget_ms=min(budget_ms, 1800), allow_empty_early=True)
        phases['heuristic_ms'] = int((time.time() - hstart)*1000)
        techs.extend(heur_res.get('technologies') or [])
        for cat, arr in (heur_res.get('categories') or {}).items():
            bucket = cats.setdefault(cat, [])
            for it in arr:
                if not any(b['name']==it['name'] and b.get('version')==it.get('version') for b in bucket):
                    bucket.append({'name': it['name'], 'version': it.get('version')})
    except Exception as e:
        logging.getLogger('techscan.unified').debug('heuristic failed domain=%s err=%s', domain, e)
    # 2) Python-local Wappalyzer detection
    py_local_ms = 0
    try:
        pstart = time.time()
        from . import wapp_local
        raw = wapp_local.detect(domain, wappalyzer_path, timeout=min(4.0, budget_ms/1000.0))
        categories_map = load_categories(wappalyzer_path)
        nres = normalize_result(domain, raw, categories_map)
        py_local_ms = int((time.time() - pstart)*1000)
        phases['py_local_ms'] = py_local_ms
        # preserve extras for downstream evidence
        if raw and isinstance(raw, dict):
            nres.setdefault('raw', {})
            try:
                # Collect possible extras from a few common shapes used by detectors:
                # - raw may expose extras at top level: raw['extras']
                # - some detectors return nested shapes like raw['raw']['extras'] or raw['data']['extras']
                extras_acc: dict = {}
                # top-level extras
                top = raw.get('extras')
                if isinstance(top, dict):
                    for k, v in top.items():
                        extras_acc.setdefault(k, []).extend(v if isinstance(v, list) else [v])
                # nested raw.extras
                nested_raw = raw.get('raw')
                if isinstance(nested_raw, dict):
                    nr = nested_raw.get('extras')
                    if isinstance(nr, dict):
                        for k, v in nr.items():
                            extras_acc.setdefault(k, []).extend(v if isinstance(v, list) else [v])
                # nested data.extras
                nested_data = raw.get('data')
                if isinstance(nested_data, dict):
                    nd = nested_data.get('extras')
                    if isinstance(nd, dict):
                        for k, v in nd.items():
                            extras_acc.setdefault(k, []).extend(v if isinstance(v, list) else [v])
                # If we found any extras, normalize to lists and store
                if extras_acc:
                    normalized = {}
                    for k, v in extras_acc.items():
                        # flatten None and non-list into a single-item list
                        if v is None:
                            normalized[k] = []
                        else:
                            # ensure strings are preserved as items
                            normalized[k] = [item for item in v if item is not None]
                    nres['raw']['extras'] = normalized
            except Exception:
                pass
        # merge techs and categories
        existing = {t['name'] for t in techs}
        for t in nres.get('technologies') or []:
            if t['name'] not in existing:
                techs.append(t); existing.add(t['name'])
        for cat, arr in (nres.get('categories') or {}).items():
            bucket = cats.setdefault(cat, [])
            for it in arr:
                if not any(b['name']==it['name'] and b.get('version')==it.get('version') for b in bucket):
                    bucket.append({'name': it['name'], 'version': it.get('version')})
    except Exception as e:
        logging.getLogger('techscan.unified').debug('py-local failed domain=%s err=%s', domain, e)
    # 3) Synthetic headers
    try:
        sstart = time.time()
        synth = synthetic_header_detection(domain, timeout=3)
        if synth:
            existing = {t['name'] for t in techs}
            for t in synth:
                if t['name'] not in existing:
                    techs.append(t); existing.add(t['name'])
                    for cat in t.get('categories') or []:
                        bucket = cats.setdefault(cat, [])
                        if not any(b['name']==t['name'] and b.get('version')==t.get('version') for b in bucket):
                            bucket.append({'name': t['name'], 'version': t.get('version')})
        phases['synthetic_ms'] = int((time.time() - sstart)*1000)
    except Exception as e:
        logging.getLogger('techscan.unified').debug('synthetic failed domain=%s err=%s', domain, e)
    # 4) Targeted version enrichment
    enriched = False
    try:
        fake_result = {'domain': domain, 'technologies': techs, 'categories': cats}
        enriched = _targeted_version_enrichment(fake_result, timeout=2.0)
        if enriched:
            # sync back possibly updated categories
            cats = fake_result.get('categories') or cats
    except Exception as e:
        logging.getLogger('techscan.unified').debug('enrich failed domain=%s err=%s', domain, e)
    # 5) Micro Node fallback only if sparse
    def count_signal(ts: List[Dict[str, Any]]) -> int:
        return sum(1 for t in ts if t.get('name'))
    # Threshold for triggering Node fallbacks
    try:
        unified_min_tech = int(os.environ.get('TECHSCAN_UNIFIED_MIN_TECH', '25'))
    except ValueError:
        unified_min_tech = 25
    # Allow minimum budget override before node fallbacks kick in (default 4000ms)
    try:
        fallback_min_budget_ms = int(os.environ.get('TECHSCAN_FALLBACK_MIN_BUDGET_MS', '4000') or '4000')
    except ValueError:
        fallback_min_budget_ms = 4000
    # Optional fast full timeout override in milliseconds (prefer this for short full fallback)
    try:
        fast_full_ms = int(os.environ.get('TECHSCAN_FAST_FULL_TIMEOUT_MS', '0') or '0')
    except ValueError:
        fast_full_ms = 0
    micro_used = False
    node_full_used = False
    current_count = count_signal(techs)
    logging.getLogger('techscan.unified').debug('fallback_check domain=%s tech_count=%s min_threshold=%s budget_ms=%s', domain, current_count, unified_min_tech, budget_ms)
    # Micro fallback is gated by TECHSCAN_ULTRA_FALLBACK_MICRO (default enabled)
    if current_count <= unified_min_tech and os.environ.get('TECHSCAN_ULTRA_FALLBACK_MICRO', '1') == '1' and fallback_min_budget_ms <= budget_ms:
        try:
            # One-shot micro: short cap, no adaptive retry, and resource blocking on
            micro_start = time.time()
            # Derive timeout: allow a bit longer if not using persistent browser
            try:
                micro_to_env = int(os.environ.get('TECHSCAN_MICRO_TIMEOUT_S','0') or '0')
            except ValueError:
                micro_to_env = 0
            persist = (os.environ.get('TECHSCAN_PERSIST_BROWSER','0') == '1')
            # default 5s when persist, 8s when not persist (cold launch overhead)
            micro_default = 5 if persist else 8
            micro_timeout_s = micro_to_env if micro_to_env > 0 else micro_default
            # Allow adaptive multiplier via env to shorten micro attempt without removing base default
            try:
                micro_scale = float(os.environ.get('TECHSCAN_MICRO_TIMEOUT_SCALE', '1.0') or '1.0')
            except ValueError:
                micro_scale = 1.0
            micro_timeout_s = max(3, int(micro_timeout_s * micro_scale))
            # Respect remaining budget
            rem_ms = max(0, budget_ms - int((time.time() - t0) * 1000))
            if rem_ms > 0:
                micro_timeout_s = min(micro_timeout_s, max(3, int(rem_ms/1000)))
            added_micro = 0
            old_ultra = os.environ.get('TECHSCAN_ULTRA_QUICK'); os.environ['TECHSCAN_ULTRA_QUICK']='0'
            old_adapt = os.environ.get('TECHSCAN_DISABLE_ADAPTIVE'); os.environ['TECHSCAN_DISABLE_ADAPTIVE']='1'
            old_impl = os.environ.get('TECHSCAN_DISABLE_IMPLICIT_RETRY'); os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY']='1'
            old_pyw = os.environ.get('TECHSCAN_PY_WAPP'); os.environ['TECHSCAN_PY_WAPP'] = '0'
            try:
                node = scan_domain(domain, wappalyzer_path, timeout=micro_timeout_s, retries=0, full=False)
                existing = {t['name'] for t in techs}
                for t in node.get('technologies') or []:
                    if t['name'] not in existing:
                        techs.append(t); existing.add(t['name']); added_micro += 1
                for cat, arr in (node.get('categories') or {}).items():
                    bucket = cats.setdefault(cat, [])
                    for it in arr:
                        if not any(b['name']==it['name'] and b.get('version')==it.get('version') for b in bucket):
                            bucket.append({'name': it['name'], 'version': it.get('version')})
            finally:
                micro_end = time.time()
                if old_ultra is not None: os.environ['TECHSCAN_ULTRA_QUICK']=old_ultra
                else: os.environ.pop('TECHSCAN_ULTRA_QUICK', None)
                if old_adapt is not None: os.environ['TECHSCAN_DISABLE_ADAPTIVE']=old_adapt
                else: os.environ.pop('TECHSCAN_DISABLE_ADAPTIVE', None)
                if old_impl is not None: os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY']=old_impl
                else: os.environ.pop('TECHSCAN_DISABLE_IMPLICIT_RETRY', None)
                if old_pyw is not None: os.environ['TECHSCAN_PY_WAPP']=old_pyw
                else: os.environ.pop('TECHSCAN_PY_WAPP', None)
            try:
                phases['micro_ms'] = int((micro_end - micro_start) * 1000)
            except Exception:
                pass
            if added_micro > 0:
                micro_used = True
        except Exception as e:
            logging.getLogger('techscan.unified').debug('micro fallback failed domain=%s err=%s', domain, e)
    # 6) Short full Node fallback if still below threshold and budget remains
    if count_signal(techs) < unified_min_tech and fallback_min_budget_ms <= budget_ms:
        try:
            remaining_ms = max(0, budget_ms - int((time.time() - t0) * 1000))
            # Require at least 3s remaining to attempt a short full
            if remaining_ms >= 3000:
                full_start = time.time()
                # Allow override via env; default max 9s
                try:
                    full_max_env = int(os.environ.get('TECHSCAN_SHORT_FULL_MAX_S','0') or '0')
                except ValueError:
                    full_max_env = 0
                # base cap in seconds (env overrides allowed)
                full_cap = full_max_env if full_max_env > 0 else 9
                # If user provided a fast full timeout in ms, prefer that as cap (convert to seconds)
                if fast_full_ms and fast_full_ms > 0:
                    ff_s = max(1, int(fast_full_ms / 1000))
                    full_cap = ff_s
                full_timeout_s = max(3, min(full_cap, int(remaining_ms/1000)))
                # Force Node full path: disable py-local and implicit retry
                old_ultra = os.environ.get('TECHSCAN_ULTRA_QUICK'); os.environ['TECHSCAN_ULTRA_QUICK']='0'
                old_impl = os.environ.get('TECHSCAN_DISABLE_IMPLICIT_RETRY'); os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY']='1'
                old_pyw = os.environ.get('TECHSCAN_PY_WAPP'); os.environ['TECHSCAN_PY_WAPP'] = '0'
                added_full = 0
                try:
                    node_full = scan_domain(domain, wappalyzer_path, timeout=full_timeout_s, retries=0, full=True)
                    existing = {t['name'] for t in techs}
                    for t in node_full.get('technologies') or []:
                        if t['name'] not in existing:
                            techs.append(t); existing.add(t['name']); added_full += 1
                    for cat, arr in (node_full.get('categories') or {}).items():
                        bucket = cats.setdefault(cat, [])
                        for it in arr:
                            if not any(b['name']==it['name'] and b.get('version')==it.get('version') for b in bucket):
                                bucket.append({'name': it['name'], 'version': it.get('version')})
                finally:
                    full_end = time.time()
                    if old_ultra is not None: os.environ['TECHSCAN_ULTRA_QUICK']=old_ultra
                    else: os.environ.pop('TECHSCAN_ULTRA_QUICK', None)
                    if old_impl is not None: os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY']=old_impl
                    else: os.environ.pop('TECHSCAN_DISABLE_IMPLICIT_RETRY', None)
                    if old_pyw is not None: os.environ['TECHSCAN_PY_WAPP']=old_pyw
                    else: os.environ.pop('TECHSCAN_PY_WAPP', None)
                try:
                    phases['node_full_ms'] = int((full_end - full_start) * 1000)
                except Exception:
                    pass
                if added_full > 0:
                    node_full_used = True
        except Exception as e:
            logging.getLogger('techscan.unified').debug('node full fallback failed domain=%s err=%s', domain, e)
    # Sanitize obviously wrong versions before finalizing (e.g., WordPress "1.0.0" or timestamp-like)
    try:
        def _looks_like_bad_wp(ver: str) -> bool:
            v = ver.strip()
            # Reject very short bogus like '1' or '1.0.0'
            if v in ('1', '1.0', '1.0.0'):
                return True
            # Reject long digit sequences (likely timestamps)
            if any(len(tok) >= 6 and tok.isdigit() for tok in re.split(r'[^0-9]', v)):
                return True
            # If purely digits and dots but major < 3, likely noise for modern sites
            m = re.match(r'^(\d+)(?:\.\d+){0,2}$', v)
            if m:
                try:
                    return int(m.group(1)) < 3
                except Exception:
                    return False
            return False
        for t in techs:
            if (t.get('name') or '').lower() == 'wordpress' and t.get('version'):
                if _looks_like_bad_wp(str(t.get('version'))):
                    t['version'] = None
    except Exception:
        pass
    # Post-fallback targeted enrichment (e.g., try /wp-json after Node added CMS)
    try:
        fake_final = {'domain': domain, 'technologies': techs, 'categories': cats}
        changed2 = _targeted_version_enrichment(fake_final, timeout=2.0)
        if changed2:
            cats = fake_final.get('categories') or cats
    except Exception as pe:
        logging.getLogger('techscan.unified').debug('post-enrich failed domain=%s err=%s', domain, pe)
    # Assemble unified result
    elapsed = time.time() - t0
    # Build categories from techs if empty
    if not cats:
        rec: Dict[str, List[Dict[str, Any]]] = {}
        for t in techs:
            for c in t.get('categories') or []:
                bucket = rec.setdefault(c, [])
                if not any(b['name']==t['name'] and b.get('version')==t.get('version') for b in bucket):
                    bucket.append({'name': t['name'], 'version': t.get('version')})
        cats = rec
    out = {
        'domain': domain,
        'timestamp': int(time.time()),
        'technologies': techs,
        'categories': cats,
        'engine': 'unified',
        'scan_mode': 'fast',
        'duration': round(elapsed, 2),
        'phases': phases
    }
    # --- Deduplicate / normalize similar technology entries ---
    try:
        def _normalize_name(n: str) -> str:
            if not n:
                return ''
            return re.sub(r'[^a-z0-9]+', ' ', n.lower()).strip()

        def _should_merge(name_a: str, name_b: str) -> bool:
            # Only merge truly duplicate entries, NOT related but distinct technologies
            # e.g., DON'T merge: jQuery vs jQuery UI vs jQuery Migrate (distinct libs)
            # e.g., DON'T merge: Elementor vs Essential Addons for Elementor (distinct plugins)
            if not name_a or not name_b:
                return False
            # Exact equality - definitely merge
            if name_a == name_b:
                return True
            # Stricter: only merge if one is exact prefix + version suffix or very minor variant
            # e.g., "wordpress" vs "wordpress 6.0" should merge
            # e.g., "jquery" vs "jquery ui" should NOT merge (ui is not a version)
            tokens_a = name_a.split()
            tokens_b = name_b.split()
            # If token counts differ by more than 1, likely different tech
            if abs(len(tokens_a) - len(tokens_b)) > 1:
                return False
            # If exactly same tokens (just different order/spacing), merge
            if set(tokens_a) == set(tokens_b):
                return True
            # If shorter is exact match of longer minus last token AND last token looks like version
            def looks_like_version(t: str) -> bool:
                return bool(re.match(r'^[\d\.]+$', t)) or t in ('sniff', 'latest', 'stable')
            if len(tokens_a) < len(tokens_b):
                shorter, longer = tokens_a, tokens_b
            else:
                shorter, longer = tokens_b, tokens_a
            # Check if shorter matches longer prefix and remaining is version-like
            if shorter == longer[:len(shorter)]:
                remaining = longer[len(shorter):]
                if len(remaining) == 1 and looks_like_version(remaining[0]):
                    return True
            # Otherwise, don't merge - they're distinct technologies
            return False

        def _parse_version_tuple(v: str | None) -> tuple:
            if not v:
                return ()
            nums = re.findall(r"\d+", str(v))
            try:
                return tuple(int(n) for n in nums)
            except Exception:
                return ()

        def _choose_version(current: str | None, candidate: str | None) -> str | None:
            """Prefer the higher semantic-ish version if both are present."""
            if not candidate:
                return current
            if not current:
                return candidate
            if candidate == current:
                return current
            c1 = _parse_version_tuple(current)
            c2 = _parse_version_tuple(candidate)
            if c2 and c1:
                return candidate if c2 > c1 else current
            # Fallback: keep current
            return current

        merged_list: List[Dict[str, Any]] = []
        for t in out.get('technologies', []) or []:
            name = (t.get('name') or '').strip()
            norm = _normalize_name(name)
            placed = False
            for u in merged_list:
                uname = (u.get('name') or '').strip()
                unorm = _normalize_name(uname)
                if _should_merge(norm, unorm):
                    # merge t into u
                    # prefer version (pick higher if both exist)
                    u['version'] = _choose_version(u.get('version'), t.get('version'))
                    # prefer the name that has a version or longer descriptive name
                    if (t.get('version') and not u.get('version')) or (len(name) > len(uname) and not u.get('version')):
                        u['name'] = t.get('name')
                    # confidence: take maximum
                    try:
                        u['confidence'] = max(int(u.get('confidence') or 0), int(t.get('confidence') or 0))
                    except Exception:
                        u['confidence'] = u.get('confidence') or t.get('confidence')
                    # categories: union without duplicates
                    u_cats = u.setdefault('categories', []) or []
                    for c in (t.get('categories') or []):
                        if c not in u_cats:
                            u_cats.append(c)
                    # evidence: union list of evidence dicts
                    u_evd = u.setdefault('evidence', []) or []
                    for ev in (t.get('evidence') or []):
                        if ev not in u_evd:
                            u_evd.append(ev)
                    placed = True
                    break
            if not placed:
                # copy to avoid mutating original structures
                # ensure evidence list exists
                newt = {**t}
                if 'evidence' not in newt:
                    newt['evidence'] = t.get('evidence') or []
                merged_list.append(newt)
        out['technologies'] = merged_list
    except Exception as _ded_err:
        logging.getLogger('techscan.unified').debug('dedupe pass failed domain=%s err=%s', domain, _ded_err)
    # --- Canonicalize common aliases (keep aliases list) ---
    try:
        # mapping of normalized token -> canonical display name
        canonical_map = {
            'apache http server': 'Apache HTTP Server',
            'apache': 'Apache HTTP Server',
            'nginx': 'Nginx',
            'cloudflare': 'Cloudflare',
            'jquery': 'jQuery',
            'bootstrap': 'Bootstrap',
            'google analytics': 'Google Analytics',
            'php': 'PHP'
        }
        canoned: List[Dict[str, Any]] = []
        for t in out.get('technologies', []) or []:
            name = (t.get('name') or '').strip()
            norm = _normalize_name(name)
            canon_name = None
            for key, val in canonical_map.items():
                if key in norm:
                    canon_name = val
                    break
            if not canon_name:
                # keep as-is
                canoned.append(t)
                continue
            # Find existing canoned entry
            found = None
            for e in canoned:
                if (e.get('name') or '') == canon_name:
                    found = e; break
            if found:
                # merge into found, keep aliases
                aliases = found.setdefault('aliases', [])
                if name not in aliases and name != found.get('name'):
                    aliases.append(name)
                # prefer version
                found['version'] = _choose_version(found.get('version'), t.get('version'))
                # max confidence
                try:
                    found['confidence'] = max(int(found.get('confidence') or 0), int(t.get('confidence') or 0))
                except Exception:
                    found['confidence'] = found.get('confidence') or t.get('confidence')
                # union categories
                fcats = found.setdefault('categories', []) or []
                for c in (t.get('categories') or []):
                    if c not in fcats:
                        fcats.append(c)
                    # union evidence
                    fevd = found.setdefault('evidence', []) or []
                    for ev in (t.get('evidence') or []):
                        if ev not in fevd:
                            fevd.append(ev)
            else:
                # keep original 'name' but annotate canonical_name and aliases
                new = {**t}
                new.setdefault('aliases', [])
                if canon_name and canon_name not in new['aliases'] and canon_name != name:
                    new['aliases'].append(canon_name)
                # record canonical_name for UI/consistency without changing primary 'name'
                new['canonical_name'] = canon_name
                # ensure evidence carried over
                if 'evidence' not in new:
                    new['evidence'] = t.get('evidence') or []
                canoned.append(new)
        out['technologies'] = canoned
    except Exception:
        pass
    # Attach raw extras if available from py-local for version evidence
    try:
        if 'raw' not in out and 'raw' in locals().get('nres', {}):
            out['raw'] = locals()['nres']['raw']
    except Exception:
        pass
    # Mark which fallbacks were used for observability
    if micro_used:
        out.setdefault('tiered', {})['micro_used'] = True
    if node_full_used:
        out.setdefault('tiered', {})['node_full_used'] = True
    # Apply static version evidences before final audit
    try:
        if os.environ.get('TECHSCAN_VERSION_EVIDENCE','1') == '1':
            version_audit.apply_version_evidence(out)
    except Exception:
        pass
    # --- Final safety-net enrichment merge ---
    try:
        all_urls: List[str] = []
        # Collect extras from possible sources (out itself, and last py-local nres if present)
        for candidate in (out, locals().get('nres', {})):
            if not candidate or not isinstance(candidate, dict):
                continue
            raw = candidate.get('raw') or {}
            if not isinstance(raw, dict):
                continue
            extras = raw.get('extras') or {}
            if not isinstance(extras, dict):
                continue
            for key in ('network', 'scripts', 'links', 'urls'):
                val = extras.get(key)
                if isinstance(val, list):
                    for u in val:
                        try:
                            if u:
                                all_urls.append(u)
                        except Exception:
                            continue
        if all_urls:
            hints = infer_tech_from_urls(all_urls)
            if hints:
                # merge hints defensively into out without overwriting existing higher-confidence techs
                existing_names = {t.get('name') for t in out.get('technologies', [])}
                added = 0
                for h in hints:
                    if h.get('name') not in existing_names:
                        out.setdefault('technologies', []).append(h)
                        # categories: pick first category if available, else 'Uncategorized'
                        for cat in (h.get('categories') or ['Uncategorized']):
                            bucket = out.setdefault('categories', {})
                            arr = bucket.setdefault(cat, [])
                            if not any(b.get('name') == h.get('name') and b.get('version') == h.get('version') for b in arr):
                                arr.append({'name': h.get('name'), 'version': h.get('version')})
                        added += 1
                logging.getLogger('techscan.unified').info('[enrich-merge] added %d tech hints (%s) urls=%d', added, ', '.join(h.get('name') for h in hints), len(all_urls))
                # update enrichment stats snapshot
                try:
                    with _stats_lock:
                        ent = STATS.setdefault('enrichment', {'hints_total': 0, 'scans': 0, 'merge_total': 0, 'last_avg_conf': 0.0, 'last_update': 0.0})
                        ent['hints_total'] = int(ent.get('hints_total', 0) + len(hints))
                        ent['merge_total'] = int(ent.get('merge_total', 0) + len(hints))
                        ent['scans'] = int(ent.get('scans', 0) + 1)
                        # compute avg confidence of last hints
                        try:
                            avg = float(sum((h.get('confidence') or 0) for h in hints) / max(1, len(hints)))
                        except Exception:
                            avg = 0.0
                        ent['last_avg_conf'] = float(avg)
                        ent['last_update'] = int(time.time())
                except Exception:
                    pass
    except Exception as e:
        logging.getLogger('techscan.unified').warning('[enrich-merge] failed domain=%s err=%s', domain, e)
    # Final audit
    if os.environ.get('TECHSCAN_SKIP_VERSION_AUDIT','0') != '1' and os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
        try:
            version_audit.audit_versions(out)
        except Exception:
            pass
    # --- Assign default categories to well-known technologies lacking them ---
    try:
        CATEGORY_FALLBACKS = {
            'jquery': ['JavaScript libraries'],
            'jquery ui': ['JavaScript libraries'],
            'jquery migrate': ['JavaScript libraries'],
            'font awesome': ['Font scripts'],
            'wpml': ['Translation', 'WordPress plugins'],
            'wordpress multilingual plugin': ['Translation', 'WordPress plugins'],
            'tailwind css': ['UI frameworks'],
            'tailwindcss': ['UI frameworks'],
            'doubleclick floodlight': ['Advertising'],
            'google adsense': ['Advertising'],
            'bootstrap': ['UI frameworks'],
            'react': ['JavaScript frameworks'],
            'vue.js': ['JavaScript frameworks'],
            'angular': ['JavaScript frameworks'],
            'lodash': ['JavaScript libraries'],
            'underscore.js': ['JavaScript libraries'],
            'modernizr': ['JavaScript libraries'],
            'axios': ['JavaScript libraries'],
            'wordpress': ['CMS', 'Blogs'],
            'nginx': ['Web servers', 'Reverse proxies'],
            'apache': ['Web servers'],
        }
        for t in out.get('technologies', []) or []:
            cats = t.get('categories') or []
            if not cats:
                name_lower = (t.get('name') or '').lower().strip()
                for key, fallback_cats in CATEGORY_FALLBACKS.items():
                    if key in name_lower or name_lower.startswith(key.split()[0]):
                        t['categories'] = fallback_cats
                        # Also update main categories dict
                        for c in fallback_cats:
                            bucket = out.setdefault('categories', {}).setdefault(c, [])
                            if not any(b.get('name') == t.get('name') for b in bucket):
                                bucket.append({'name': t.get('name'), 'version': t.get('version')})
                        break
    except Exception:
        pass
    return out

def scan_bulk(domains: List[str], wappalyzer_path: str, concurrency: int = 4, timeout: int = 45, fresh: bool = False, retries: int = 0, ttl: int | None = None, full: bool = False) -> List[Dict[str, Any]]:
    log = logging.getLogger('techscan.bulk')
    original_inputs = [(d or '').strip() for d in domains]
    filtered: List[str] = []  # hosts only (for validation/scanning)
    normalized_urls: List[str] = []  # full URLs with paths (for database storage)
    index_map: List[int] = []
    invalid_persisted: Dict[int, bool] = {}
    prefilled_errors: Dict[int, Dict[str, Any]] = {}
    for idx_raw, cleaned in enumerate(original_inputs):
        host = extract_host(cleaned)
        url_with_path = extract_url_with_path(cleaned)  # Keep path for unique endpoint
        if not host:
            prefilled_errors[idx_raw] = {
                'status': 'error',
                'domain': url_with_path or cleaned or (domains[idx_raw] or ''),
                'input_value': cleaned,
                'error': 'empty domain input',
                'timestamp': int(time.time())
            }
            log.warning('bulk scan skipped empty domain input index=%d raw=%r', idx_raw, domains[idx_raw])
            stub_domain = prefilled_errors[idx_raw]['domain']
            if stub_domain:
                if _persist_failure_scan(
                    stub_domain,
                    mode='bulk-precheck',
                    timeout_used=timeout,
                    retries=0,
                    error='empty domain input',
                    raw={'input_value': cleaned, 'source': 'bulk-precheck'}
                ):
                    prefilled_errors[idx_raw]['persisted_db'] = True
            continue
        if not DOMAIN_RE.match(host):
            prefilled_errors[idx_raw] = {
                'status': 'error',
                'domain': url_with_path or host,
                'input_value': cleaned,
                'error': 'invalid domain format',
                'timestamp': int(time.time())
            }
            log.warning('bulk scan invalid domain index=%d raw=%r normalized=%s', idx_raw, domains[idx_raw], host)
            if _persist_failure_scan(
                url_with_path or host,
                mode='bulk-precheck',
                timeout_used=timeout,
                retries=0,
                error='invalid domain format',
                raw={'input_value': cleaned, 'source': 'bulk-precheck'}
            ):
                prefilled_errors[idx_raw]['persisted_db'] = True
            continue
        filtered.append(host.lower())  # host only for scanning
        normalized_urls.append(url_with_path)  # full URL with path for storage
        index_map.append(idx_raw)

    results_filtered: List[Dict[str, Any]] = [None] * len(filtered)  # type: ignore

    def assemble(filtered_payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        final: List[Dict[str, Any]] = [None] * len(domains)  # type: ignore
        for orig_idx, err_payload in prefilled_errors.items():
            final[orig_idx] = dict(err_payload)
        for filtered_idx, orig_idx in enumerate(index_map):
            payload = filtered_payloads[filtered_idx]
            if payload is None:
                payload = {
                    'status': 'error',
                    'domain': normalized_urls[filtered_idx],  # Use URL with path
                    'input_value': original_inputs[orig_idx],
                    'error': 'scan result missing',
                    'timestamp': int(time.time())
                }
            else:
                payload.setdefault('status', 'ok')
                payload.setdefault('timestamp', int(time.time()))
                payload.setdefault('domain', normalized_urls[filtered_idx])  # Use URL with path
                payload.setdefault('input_value', original_inputs[orig_idx])
            final[orig_idx] = payload
        for i in range(len(final)):
            if final[i] is None:
                raw_input = original_inputs[i]
                final[i] = {
                    'status': 'error',
                    'domain': extract_url_with_path(raw_input) or raw_input or '',  # Use URL with path
                    'input_value': raw_input,
                    'error': 'scan result missing',
                    'timestamp': int(time.time())
                }
        return final  # type: ignore

    def finalize_results(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not items:
            return items
        for entry in items:
            if not entry or entry.get('status') == 'ok' or entry.get('persisted_db'):
                continue
            dom = entry.get('domain')
            if not dom:
                continue
            raw_meta = {
                'source': 'bulk-result',
                'error_payload': entry.get('error'),
                'input_value': entry.get('input_value')
            }
            if _persist_failure_scan(
                dom,
                mode='bulk',
                timeout_used=timeout,
                retries=int(entry.get('retries') or 0),
                error=entry.get('error') or 'bulk scan error',
                raw=raw_meta
            ):
                entry['persisted_db'] = True
        return items

    if not filtered:
        return finalize_results(assemble(results_filtered))

    idx = 0
    lock_i = threading.Lock()
    fast_first = (os.environ.get('TECHSCAN_BULK_FAST_FIRST','0') == '1') and not full
    two_phase = (os.environ.get('TECHSCAN_BULK_TWO_PHASE','0') == '1') and not full and os.environ.get('TECHSCAN_TIERED','0') == '1'
    adaptive = (os.environ.get('TECHSCAN_BULK_ADAPT','0') == '1') and not full
    try:
        jitter_ms = int(os.environ.get('TECHSCAN_SCHEDULE_JITTER_MS','0') or '0')
    except ValueError:
        jitter_ms = 0

    if two_phase:
        # Phase 1: run heuristic for all domains quickly (deferred or skip scheduling full here)
        phase1: List[Dict[str, Any]] = [None] * len(filtered)  # type: ignore
        def worker_phase1():
            nonlocal idx
            while True:
                with lock_i:
                    if idx >= len(filtered):
                        break
                    i = idx; idx += 1
                dom = filtered[i]
                try:
                    # Force heuristic only: call get_cached_or_scan with current tiered config but ensure not full and disable defer scheduling by temporary env tweak if needed
                    # Use existing logic; if deferred enabled it will schedule background full automatically (fine)
                    res = get_cached_or_scan(dom, wappalyzer_path, timeout=timeout, fresh=fresh, retries=0, ttl=ttl, full=False)
                    phase1[i] = {'status':'ok', **res}
                except Exception as e:
                    log.warning('bulk scan phase1 error domain=%s err=%s', dom, e)
                    phase1[i] = {'status':'error','domain':dom,'error':str(e)}
        threads = [threading.Thread(target=worker_phase1) for _ in range(min(concurrency, len(filtered)))]
        for t in threads: t.start()
        for t in threads: t.join()
        # Phase 2: schedule full scans for those not strong_cms_skip_full and not deferred background already if DEFER_FULL off
        phase2_threads = []
        def phase2_full(i: int, dom: str):
            # Only run if not already cached full
            try:
                full_res = get_cached_or_scan(dom, wappalyzer_path, timeout=timeout, fresh=fresh, retries=retries, ttl=ttl, full=True)
                results_filtered[i] = {'status':'ok', **full_res}
            except Exception as e:
                log.warning('bulk scan phase2 error domain=%s err=%s', dom, e)
                # fallback to phase1 result if exists
                if phase1[i] and phase1[i].get('status')=='ok':
                    r = dict(phase1[i])
                    r.setdefault('tiered',{})['full_error']=str(e)
                    results_filtered[i] = r
                else:
                    results_filtered[i] = {'status':'error','domain':dom,'error':str(e)}
        for i, r in enumerate(phase1):
            if not r or r.get('status')!='ok':
                results_filtered[i] = r
                continue
            tiered_meta = r.get('tiered') or {}
            if tiered_meta.get('strong_cms_skip_full'):
                results_filtered[i] = r  # Accept heuristic as final
                continue
            # If deferred already scheduled we accept phase1 result (will fill cache later)
            if tiered_meta.get('deferred_full') or tiered_meta.get('auto_trigger_full'):
                results_filtered[i] = r
                continue
            # Schedule explicit full scan thread
            th = threading.Thread(target=phase2_full, args=(i, r.get('domain')), daemon=True)
            phase2_threads.append(th)
            th.start()
            # Proportional throttle: avoid launching too many at once
            time.sleep(0.02)
        for th in phase2_threads:
            th.join()
        # Fill any still None with phase1 result
        for i, r in enumerate(results_filtered):
            if r is None:
                results_filtered[i] = phase1[i]
        return finalize_results(assemble(results_filtered))

    # Adaptive path (if enabled and not two_phase) else legacy
    if not two_phase and adaptive:
        target = min(concurrency, max(1, len(filtered)))
        min_c = max(1, int(os.environ.get('TECHSCAN_BULK_MIN_THREADS','2')))
        max_c = max(target, int(os.environ.get('TECHSCAN_BULK_MAX_THREADS', str(target*2))))
        durations: list[float] = []
        errs: list[int] = []
        adjust_lock = threading.Lock()
        threads: list[threading.Thread] = []

        def maybe_jitter():
            if jitter_ms > 0:
                # non-cryptographic jitter to avoid herd effects in concurrent calls
                time.sleep(random.uniform(0, jitter_ms)/1000.0)  # nosec B311

        def adjust():
            nonlocal target
            if len(durations) < 5:
                return
            avg = sum(durations[-20:]) / min(len(durations),20)
            erate = sum(errs[-20:]) / min(len(errs),20)
            new_t = target
            if avg < 1.0 and erate < 0.1:
                new_t += 1
            elif avg > 3.0 or erate > 0.3:
                new_t -= 1
            new_t = max(min_c, min(max_c, new_t))
            target = new_t

        def worker_adapt():
            nonlocal idx
            while True:
                with lock_i:
                    if idx >= len(filtered):
                        break
                    i = idx; idx += 1
                dom = filtered[i]
                st = time.time()
                flag_err = 0
                try:
                    maybe_jitter()
                    if fast_first:
                        res = get_cached_or_scan(dom, wappalyzer_path, timeout=timeout, fresh=fresh, retries=0, ttl=ttl, full=False)
                    else:
                        res = get_cached_or_scan(dom, wappalyzer_path, timeout=timeout, fresh=fresh, retries=retries, ttl=ttl, full=full)
                    results_filtered[i] = {'status':'ok', **res}
                except Exception as e:
                    log.warning('bulk scan adaptive error domain=%s err=%s', dom, e)
                    results_filtered[i] = {'status':'error','domain':dom,'error':str(e)}
                    flag_err = 1
                finally:
                    et = time.time()
                    with adjust_lock:
                        durations.append(et-st)
                        errs.append(flag_err)
                        adjust()

        def ensure_threads():
            alive = [t for t in threads if t.is_alive()]
            threads[:] = alive
            need = target - len(alive)
            for _ in range(need):
                t = threading.Thread(target=worker_adapt, daemon=True)
                threads.append(t)
                t.start()

        ensure_threads()
        while True:
            with lock_i:
                done = idx >= len(filtered)
            if done:
                for t in threads:
                    t.join()
                break
            ensure_threads()
            time.sleep(0.05)
        return finalize_results(assemble(results_filtered))

    # Legacy non-adaptive bulk worker path (fast_first or normal)
    def worker():
        nonlocal idx
        while True:
            with lock_i:
                if idx >= len(filtered):
                    break
                i = idx; idx += 1
            dom = filtered[i]
            try:
                if fast_first:
                    res = get_cached_or_scan(dom, wappalyzer_path, timeout=timeout, fresh=fresh, retries=0, ttl=ttl, full=False)
                else:
                    res = get_cached_or_scan(dom, wappalyzer_path, timeout=timeout, fresh=fresh, retries=retries, ttl=ttl, full=full)
                results_filtered[i] = {'status': 'ok', **res}
            except Exception as e:
                log.warning('bulk scan error domain=%s err=%s', dom, e)
                results_filtered[i] = {'status': 'error', 'domain': dom, 'error': str(e)}
    threads = [threading.Thread(target=worker) for _ in range(min(concurrency, len(filtered)))]
    for t in threads: t.start()
    for t in threads: t.join()
    return finalize_results(assemble(results_filtered))

# --------------------------- BULK QUICK -> DEEP PIPELINE ---------------------------
def bulk_quick_then_deep(domains: List[str], wappalyzer_path: str, concurrency: int = 6) -> List[Dict[str, Any]]:
    """Two-phase bulk pipeline:
        Phase 1: quick_single_scan for all domains (heuristic + sniff + micro fallback)
        Phase 2: deep_scan only for domains that meet escalation criteria.

        Escalation criteria (OR logic):
          - tech_count < TECHSCAN_BULK_DEEP_MIN_TECH (default 2)
          - All detected technologies have no version AND at least one technology exists
        Limits:
          - Optional cap: TECHSCAN_BULK_DEEP_MAX (absolute number) OR TECHSCAN_BULK_DEEP_MAX_PCT (percentage 0-100)

        Returns list aligned to input order with merged results. Each item includes 'bulk_phases'.
    """
    original_inputs = [(d or '').strip() for d in domains]
    try:
        bulk_timeout = int(os.environ.get('TECHSCAN_BULK_TIMEOUT','45'))
    except ValueError:
        bulk_timeout = 45
    try:
        min_tech = int(os.environ.get('TECHSCAN_BULK_DEEP_MIN_TECH','2'))
    except ValueError:
        min_tech = 2
    try:
        max_abs = int(os.environ.get('TECHSCAN_BULK_DEEP_MAX','0'))
    except ValueError:
        max_abs = 0
    try:
        max_pct = float(os.environ.get('TECHSCAN_BULK_DEEP_MAX_PCT','0'))
    except ValueError:
        max_pct = 0.0
    filtered: List[str] = []  # host-only for validation/scanning
    normalized_urls_two: List[str] = []  # full URLs with paths for storage
    index_map: List[int] = []
    for i, raw_value in enumerate(original_inputs):
        d2 = extract_host(raw_value)  # host-only for validation
        url_with_path = extract_url_with_path(raw_value)  # full URL with path for storage
        if DOMAIN_RE.match(d2):
            filtered.append(d2.lower())
            normalized_urls_two.append(url_with_path)
            index_map.append(i)
        else:
            stripped_url = url_with_path or d2 or raw_value
            if stripped_url:
                if _persist_failure_scan(
                    stripped_url,
                    mode='bulk-precheck',
                    timeout_used=bulk_timeout,
                    retries=0,
                    error='invalid domain',
                    raw={'source': 'bulk-two-phase', 'input_value': raw_value}
                ):
                    invalid_persisted[i] = True
    results: List[Dict[str, Any]] = [None] * len(domains)  # type: ignore
    phase1: List[Dict[str, Any]] = [None] * len(filtered)  # type: ignore
    # Phase 1 quick scans
    lock_i = threading.Lock()
    idx = 0
    def worker_q():
        nonlocal idx
        while True:
            with lock_i:
                if idx >= len(filtered):
                    break
                i = idx; idx += 1
            dom = filtered[i]
            t0 = time.time()
            try:
                qres = quick_single_scan(dom, wappalyzer_path, defer_full=False)
                qres.setdefault('bulk_phases', {})['phase1_ms'] = int((time.time()-t0)*1000)
                phase1[i] = {'status':'ok', **qres}
            except Exception as e:
                phase1[i] = {'status':'error','domain':dom,'error':str(e)}
    threads = [threading.Thread(target=worker_q, daemon=True) for _ in range(min(concurrency, len(filtered)))]
    for t in threads: t.start()
    for t in threads: t.join()
    # Decide escalation list
    escalate_indices: List[int] = []
    for i, r in enumerate(phase1):
        if not r or r.get('status')!='ok':
            continue
        techs = r.get('technologies') or []
        tech_count = len(techs)
        if tech_count == 0:
            # escalate empty always
            escalate = True
        else:
            all_no_version = all(not t.get('version') for t in techs)
            escalate = (tech_count < min_tech) or all_no_version
        if escalate:
            escalate_indices.append(i)
    # Apply caps
    if escalate_indices:
        if max_abs > 0 and len(escalate_indices) > max_abs:
            escalate_indices = escalate_indices[:max_abs]
        if max_pct > 0:
            cap = int(len(filtered) * (max_pct/100.0)) or 1
            if len(escalate_indices) > cap:
                escalate_indices = escalate_indices[:cap]
    escalate_set = set(escalate_indices)
    # Phase 2 deep scans
    if escalate_indices:
        lock_j = threading.Lock()
        jdx = 0
        # Map integer position in escalate_indices
        def worker_d():
            nonlocal jdx
            while True:
                with lock_j:
                    if jdx >= len(escalate_indices):
                        break
                    pos = escalate_indices[jdx]; jdx += 1
                dom = filtered[pos]
                t1 = time.time()
                try:
                    dres = deep_scan(dom, wappalyzer_path)
                    dres.setdefault('bulk_phases', {})['phase2_ms'] = int((time.time()-t1)*1000)
                    dres['bulk_phases']['escalated'] = True
                    phase1[pos] = {'status':'ok', **dres}
                except Exception as e:
                    # retain phase1 but annotate error
                    if phase1[pos] and phase1[pos].get('status')=='ok':
                        phase1[pos].setdefault('bulk_phases', {})['phase2_error'] = str(e)
                    else:
                        phase1[pos] = {'status':'error','domain':dom,'error':str(e)}
        threads2 = [threading.Thread(target=worker_d, daemon=True) for _ in range(min(concurrency, len(escalate_indices)))]
        for t in threads2: t.start()
        for t in threads2: t.join()
    def finalize_bulk_results(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not entries:
            return entries
        for entry in entries:
            if not entry or entry.get('status') == 'ok' or entry.get('persisted_db'):
                continue
            dom_key = entry.get('domain') or extract_url_with_path(entry.get('input_value') or '')
            if not dom_key:
                continue
            raw_meta = {
                'source': 'bulk-two-phase',
                'input_value': entry.get('input_value'),
                'error_payload': entry.get('error')
            }
            if _persist_failure_scan(
                dom_key,
                mode='bulk-two-phase',
                timeout_used=bulk_timeout,
                retries=int(entry.get('retries') or 0),
                error=entry.get('error') or 'bulk two-phase error',
                raw=raw_meta
            ):
                entry['persisted_db'] = True
        return entries

    # Final assembly mapping back to original order
    for local_i, orig_i in enumerate(index_map):
        r = phase1[local_i]
        if r and r.get('status')=='ok':
            # ensure bulk_phases present
            bp = r.setdefault('bulk_phases', {})
            bp.setdefault('escalated', local_i in escalate_set)
            r.setdefault('input_value', original_inputs[orig_i])
            results[orig_i] = r
        else:
            fallback = r or {'status':'error','domain': normalized_urls_two[local_i] if local_i < len(normalized_urls_two) else None,'error':'unknown'}
            fallback.setdefault('input_value', original_inputs[orig_i])
            results[orig_i] = fallback
    # Fill None for invalid domains
    for i, _ in enumerate(domains):
        if results[i] is None:
            raw_value = original_inputs[i]
            dom_key = extract_url_with_path(raw_value) or raw_value
            results[i] = {'status':'error','domain': dom_key or raw_value, 'error':'invalid domain', 'input_value': raw_value}
            if dom_key and _persist_failure_scan(
                dom_key,
                mode='bulk-precheck',
                timeout_used=bulk_timeout,
                retries=0,
                error='invalid domain',
                raw={'source': 'bulk-two-phase', 'input_value': raw_value}
            ):
                results[i]['persisted_db'] = True
            elif invalid_persisted.get(i):
                results[i]['persisted_db'] = True
        else:
            results[i].setdefault('input_value', original_inputs[i])
            if invalid_persisted.get(i):
                results[i]['persisted_db'] = True
    return finalize_bulk_results(results)

def _targeted_version_enrichment(result: Dict[str, Any], timeout: float = 2.5) -> bool:
    """Attempt fast, technology-specific version lookups for popular CMS/frameworks.
    Current strategies (low-impact, single short request each):
      - WordPress: /wp-json (parse greeting, version field) OR meta generator tag already present.
      - Drupal: /CHANGELOG.txt first line containing version.
      - Joomla: /language/en-GB/en-GB.xml (version tag) limited bytes.
    Returns True if any version field was added.
    Controlled by TECHSCAN_VERSION_ENRICH=1 (caller checks); this function self-guards against long delays.
    """
    techs = result.get('technologies') or []
    domain = result.get('domain')
    if not domain or not techs:
        return False
    # Map simple name variants to canonical enrichment handlers
    name_map = {}
    for t in techs:
        n = (t.get('name') or '').lower()
        if 'wordpress' in n:
            name_map['wordpress'] = t
        elif 'drupal' in n and 'sniff' not in n:
            name_map['drupal'] = t
        elif 'joomla' in n and 'sniff' not in n:
            name_map['joomla'] = t
    if not name_map:
        return False
    import http.client
    changed = False
    deadline = time.time() + timeout
    def remaining():
        return max(0.3, deadline - time.time())
    def fetch_path(path: str, max_bytes: int = 15000) -> bytes | None:
        if time.time() >= deadline:
            return None
        data = b''
        for scheme in ('https','http'):
            if time.time() >= deadline:
                break
            try:
                conn_cls = http.client.HTTPSConnection if scheme=='https' else http.client.HTTPConnection
                conn = conn_cls(domain, timeout=remaining())
                conn.request('GET', path, headers={'User-Agent':'TechScan/enrich'})
                resp = conn.getresponse()
                if resp.status >= 400:
                    conn.close(); continue
                while len(data) < max_bytes:
                    chunk = resp.read(min(4096, max_bytes-len(data)))
                    if not chunk: break
                    data += chunk
                conn.close()
                break
            except Exception:
                continue
        return data or None
    # WordPress enrichment
    if 'wordpress' in name_map and not name_map['wordpress'].get('version'):
        blob = fetch_path('/wp-json')
        if blob and blob.startswith(b'{'):
            try:
                js = json.loads(blob.decode('utf-8','ignore'))
                v = js.get('generated') or js.get('version') or (js.get('name') if isinstance(js.get('name'), str) and 'WordPress' in js.get('name') else None)
                # Some WP returns {"name":"Site Title","description":"","url":"...","home":"...","gmt_offset":...}
                # Real version sometimes under "routes"/"/wp/v2" meta; skip deep parse to stay fast.
                if isinstance(v, str) and any(ch.isdigit() for ch in v):
                    # sanitize keep digits and dots
                    mv = re.findall(r'(\d+\.[0-9][0-9\.\-a-zA-Z]*)', v)
                    if mv:
                        name_map['wordpress']['version'] = mv[0]
                        changed = True
            except Exception:
                pass
    # Drupal enrichment
    if 'drupal' in name_map and not name_map['drupal'].get('version'):
        blob = fetch_path('/CHANGELOG.txt', max_bytes=400)
        if blob:
            first = blob.decode('utf-8','ignore').splitlines()[0:3]
            for line in first:
                m = re.search(r'Drupal (?:core )?(\d+\.[0-9]+(?:\.[0-9]+)?)', line, re.I)
                if m:
                    name_map['drupal']['version'] = m.group(1)
                    changed = True
                    break
    # Joomla enrichment
    if 'joomla' in name_map and not name_map['joomla'].get('version'):
        blob = fetch_path('/language/en-GB/en-GB.xml', max_bytes=6000)
        if blob and b'<version>' in blob:
            try:
                txt = blob.decode('utf-8','ignore')
                m = re.search(r'<version>([^<]+)</version>', txt, re.I)
                if m:
                    ver = m.group(1).strip()
                    if any(ch.isdigit() for ch in ver):
                        name_map['joomla']['version'] = ver
                        changed = True
            except Exception:
                pass
    if changed:
        # Rebuild categories to ensure versioned entries reflected (UI may display versions inside badges)
        cats: Dict[str, List[Dict[str, Any]]] = {}
        for t in techs:
            for cat in t.get('categories') or []:
                bucket = cats.setdefault(cat, [])
                if not any(b['name']==t.get('name') and b.get('version')==t.get('version') for b in bucket):
                    bucket.append({'name': t.get('name'), 'version': t.get('version')})
        if cats:
            result['categories'] = cats
    return changed



def snapshot_cache(domains: List[str] | None = None) -> List[Dict[str, Any]]:
    """Return list of cached scan results (non-expired) optionally filtered by domains list.
    Each item mirrors original stored data plus 'cached': True flag.
    """
    now = time.time()
    out: List[Dict[str, Any]] = []
    dom_filter = set(d.lower() for d in domains) if domains else None
    with _lock:
        for key, item in _cache.items():
            ttl_val = item.get('ttl', CACHE_TTL)
            if now - item['ts'] >= ttl_val:
                continue
            # key format mode:domain
            parts = key.split(':',1)
            mode = 'fast'
            dom = key
            if len(parts)==2:
                mode, dom = parts
            if dom_filter and dom not in dom_filter:
                continue
            data = {**item['data'], 'cached': True, 'scan_mode': item['data'].get('scan_mode', mode)}
            out.append(data)
    # sort by domain for deterministic export
    out.sort(key=lambda x: (x.get('domain',''), x.get('scan_mode','')))
    return out

def flush_cache(domains: List[str] | None = None) -> dict:
    """Flush entire cache or only specified domains.
    Returns dict with counts: {'removed': n, 'remaining': m, 'total_before': tb}
    """
    with _lock:
        total_before = len(_cache)
        if not domains:
            removed = total_before
            _cache.clear()
            remaining = 0
        else:
            removed = 0
            lower = {d.lower() for d in domains}
            for k in list(_cache.keys()):
                # key format mode:domain
                parts = k.split(':', 1)
                dom = parts[1] if len(parts) == 2 else k
                if dom in lower:
                    _cache.pop(k, None)
                    removed += 1
            remaining = len(_cache)
    with _stats_lock:
        STATS['cache_entries'] = len(_cache)
    return {'removed': removed, 'remaining': remaining, 'total_before': total_before}

def get_stats() -> Dict[str, Any]:
    now = time.time()
    with _stats_lock:
        # compute averages
        def avg(bucket):
            return (bucket['total'] / bucket['count']) if bucket['count'] else 0.0
        fast_avg = avg(STATS['durations']['fast'])
        full_avg = avg(STATS['durations']['full'])
        fast_full_avg = avg(STATS['durations'].get('fast_full', {'count':0,'total':0}))

        def percentiles(data: deque, p: float) -> float:
            if not data:
                return 0.0
            arr = sorted(data)
            k = int(round((p/100.0)*(len(arr)-1)))
            k = max(0, min(len(arr)-1, k))
            return arr[k]

        fast_samples = STATS['recent_samples']['fast']
        full_samples = STATS['recent_samples']['full']
        fast_full_samples = STATS['recent_samples'].get('fast_full', deque())

        return {
            'uptime_seconds': round(now - STATS['start_time'], 2),
            'hits': STATS['hits'],
            'misses': STATS['misses'],
            'mode_hits': STATS['mode_hits'],
            'mode_misses': STATS['mode_misses'],
            'scans': STATS['scans'],
            'cache_entries': STATS['cache_entries'],
            'average_duration_ms': {
                'fast': round(fast_avg * 1000, 2),
                'fast_full': round(fast_full_avg * 1000, 2),
                'full': round(full_avg * 1000, 2)
            },
            'recent_latency_ms': {
                'fast': {
                    'samples': len(fast_samples),
                    'p50': round(percentiles(fast_samples,50)*1000,2),
                    'p95': round(percentiles(fast_samples,95)*1000,2)
                },
                'fast_full': {
                    'samples': len(fast_full_samples),
                    'p50': round(percentiles(fast_full_samples,50)*1000,2),
                    'p95': round(percentiles(fast_full_samples,95)*1000,2)
                },
                'full': {
                    'samples': len(full_samples),
                    'p50': round(percentiles(full_samples,50)*1000,2),
                    'p95': round(percentiles(full_samples,95)*1000,2)
                }
            },
            'synthetic': STATS['synthetic'],
            'errors': STATS.get('errors', {}),
            'single_flight': STATS.get('single_flight', {})
        }

def synthetic_header_detection(domain: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Very lightweight HEAD request over TLS then (optionally) plain HTTP to extract server and security headers.
    Returns list of technology dicts similar to normalized entries.
    """
    import http.client
    out: List[Dict[str, Any]] = []
    deadlines = time.time() + timeout
    def remaining():
        return max(0.5, deadlines - time.time())
    tried = []
    for scheme in ['https', 'http']:
        if time.time() >= deadlines:
            break
        try:
            conn_cls = http.client.HTTPSConnection if scheme == 'https' else http.client.HTTPConnection
            conn = conn_cls(domain, timeout=remaining())
            conn.request('HEAD', '/', headers={'User-Agent': 'TechScan/1.0'})
            resp = conn.getresponse()
            headers = {k.lower(): v for k,v in resp.getheaders()}
            server = headers.get('server')
            if server:
                # Attempt simple parse like 'nginx/1.22.1' or 'nginx'
                m = re.match(r'([a-zA-Z0-9_-]+)(?:/(\d[\w\.-]*))?', server)
                if m:
                    name = m.group(1)
                    ver = m.group(2)
                    lname = name.lower()
                    if lname == 'nginx':
                        out.append({'name': 'Nginx', 'version': ver, 'categories': ['Web servers','Reverse proxies'], 'confidence': 40, 'evidence':[{'type':'header','name':'server','value':server}]})
                    elif lname in ('apache','httpd'):
                        out.append({'name': 'Apache', 'version': ver, 'categories': ['Web servers'], 'confidence': 40, 'evidence':[{'type':'header','name':'server','value':server}]})
                    elif lname == 'cloudflare':
                        out.append({'name': 'Cloudflare', 'version': ver, 'categories': ['Reverse proxies','CDN'], 'confidence': 30, 'evidence':[{'type':'header','name':'server','value':server}]})
            if 'strict-transport-security' in headers:
                out.append({'name': 'HSTS', 'version': None, 'categories': ['Security'], 'confidence': 30, 'evidence':[{'type':'header','name':'strict-transport-security','value':headers.get('strict-transport-security')}]})
            # X-Powered-By header often indicates PHP
            xpb = headers.get('x-powered-by')
            if xpb:
                try:
                    xb = xpb.lower()
                    if 'php' in xb and not any(o['name']=='PHP' for o in out):
                        out.append({'name': 'PHP', 'version': None, 'categories': ['Programming languages'], 'confidence': 40, 'evidence':[{'type':'header','name':'x-powered-by','value':xpb}]})
                except Exception:
                    pass
            conn.close()
            tried.append(scheme)
        except Exception:
            continue
        # Stop after first success
        if out:
            break
    return out

# --------------------------- QUICK SINGLE SCAN (heuristic only) ---------------------------
def quick_single_scan(domain: str, wappalyzer_path: str, budget_ms: int | None = None, defer_full: bool = False, timeout_full: int = 45, retries_full: int = 0) -> Dict[str, Any]:
    """Perform a very fast heuristic-only scan and optionally schedule a background full scan.

        Params:
            domain: raw or normalized domain/URL (will normalize)
            budget_ms: override heuristic budget (default from ENV TECHSCAN_QUICK_BUDGET_MS or fallback 700)
            defer_full: if True schedule background full scan (ENV TECHSCAN_QUICK_DEFER_FULL=1)
            timeout_full / retries_full: parameters for background full scan

    Returns heuristic result with engine='heuristic-quick'. If background full scheduled, adds tiered.deferred_full_quick=true.
    Caches result under fast cache key so later full scan may merge (same behavior as tiered deferred logic).
    """
    from . import heuristic_fast
    raw_input = domain
    domain = validate_domain(extract_host(domain))
    try:
        if budget_ms is None:
            budget_ms = int(os.environ.get('TECHSCAN_QUICK_BUDGET_MS', str(QUICK_DEFAULT_BUDGET_MS)))
    except ValueError:
        budget_ms = QUICK_DEFAULT_BUDGET_MS
    allow_empty = os.environ.get('TECHSCAN_TIERED_ALLOW_EMPTY','0') == '1'
    q_start = time.time()
    hres = heuristic_fast.run_heuristic(domain, budget_ms=budget_ms, allow_empty_early=allow_empty)
    core_done = time.time()
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.getLogger('techscan.quick').debug('quick start domain=%s heuristic_tech=%d categories=%d budget_ms=%s', domain, len(hres.get('technologies') or []), len(hres.get('categories') or {}), budget_ms)
    hres.setdefault('tiered', {})['quick'] = True
    # Rekam durasi heuristic keseluruhan (ms) agar fallback fast_full bisa pakai sebagai fallback_ms
    phases_ref = hres.setdefault('phases', {})
    try:
        phases_ref['heuristic_core_ms'] = int((core_done - q_start) * 1000)
    except Exception:
        phases_ref['heuristic_core_ms'] = phases_ref.get('heuristic_core_ms', 0)
    hres['engine'] = 'heuristic-quick'
    hres['scan_mode'] = 'fast'
    # Version audit if enabled
    if os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
        try:
            version_audit.audit_versions(hres)
        except Exception:
            pass
    # Defer caching until after sniff/micro fallback adjustments so cache has enriched data
    cache_key = f"fast:{domain}"
    now = time.time()
    # Lightweight HTML sniff: if no technologies OR categories empty (to enrich)
    sniff_start = None
    sniff_end = None
    if (not hres.get('technologies')) or not hres.get('categories'):
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.getLogger('techscan.quick').debug('sniff decision domain=%s trigger_sniff technologies=%d categories_empty=%s', domain, len(hres.get('technologies') or []), not bool(hres.get('categories')))
        try:
            sniff_start = time.time()
            sniff = _sniff_html(domain)
            techs_found = sniff.get('techs', [])
            if techs_found:
                existing_names = {t['name'] for t in hres.get('technologies', [])}
                added = 0
                for ft in techs_found:
                    if ft['name'] not in existing_names:
                        hres['technologies'].append(ft)
                        existing_names.add(ft['name'])
                        added += 1
                # Ensure categories dict reflects sniff additions
                if added:
                    cats = hres.setdefault('categories', {})
                    for ft in techs_found:
                        for cat in ft.get('categories', []) or []:
                            bucket = cats.setdefault(cat, [])
                            # avoid duplicate entries
                            if not any(b['name'] == ft['name'] and b.get('version') == ft.get('version') for b in bucket):
                                bucket.append({'name': ft['name'], 'version': ft.get('version')})
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.getLogger('techscan.quick').debug('sniff added domain=%s added=%d total_tech=%d', domain, added, len(hres.get('technologies') or []))
                tier = hres.setdefault('tiered', {})
                tier['html_sniff'] = True
                tier['html_sniff_added'] = added
                if sniff.get('meta', {}).get('cached'):
                    tier['html_sniff_cached'] = True
                    tier['html_sniff_cache_age'] = sniff['meta'].get('cache_age')
            else:
                # still record cached/no detection metadata
                if sniff.get('meta', {}).get('cached'):
                    tier = hres.setdefault('tiered', {})
                    tier['html_sniff_cached'] = True
                    tier['html_sniff_cache_age'] = sniff['meta'].get('cache_age')
            sniff_end = time.time()
        except Exception as _sn_err:
            logging.getLogger('techscan.sniff').debug('sniff error domain=%s err=%s', domain, _sn_err)
            sniff_end = time.time()
    micro_start = None
    micro_end = None
    if not hres.get('technologies') and os.environ.get('TECHSCAN_ULTRA_FALLBACK_MICRO','0') == '1':
        tier_meta = hres.setdefault('tiered', {})
        tier_meta['micro_planned'] = True
        try:
            micro_start = time.time()
            micro_timeout_env = os.environ.get('TECHSCAN_MICRO_TIMEOUT_S','2')
            try:
                micro_timeout = int(micro_timeout_env)
            except ValueError:
                micro_timeout = 2
            tier_meta['micro_timeout_s'] = micro_timeout
            tier_meta['micro_started'] = True
            logging.getLogger('techscan.micro').info('micro fallback start domain=%s timeout=%ss', domain, micro_timeout)
            # Temporarily disable ULTRA_QUICK so scan_domain actually invokes wappalyzer
            _old_ultra = os.environ.get('TECHSCAN_ULTRA_QUICK')
            _old_adapt = os.environ.get('TECHSCAN_DISABLE_ADAPTIVE')
            _old_implicit = os.environ.get('TECHSCAN_DISABLE_IMPLICIT_RETRY')
            try:
                if _old_ultra == '1':
                    os.environ['TECHSCAN_ULTRA_QUICK'] = '0'
                # Force disable adaptive for true micro single-shot (unless user explicitly set 1 already)
                if os.environ.get('TECHSCAN_DISABLE_ADAPTIVE','0') != '1':
                    os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = '1'
                # Also disable implicit retry so we truly perform only one Wappalyzer attempt
                os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY'] = '1'
                micro = scan_domain(domain, wappalyzer_path, timeout=micro_timeout, retries=0, full=False)
            finally:
                if _old_ultra == '1':
                    os.environ['TECHSCAN_ULTRA_QUICK'] = '1'
                if _old_adapt is not None:
                    os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = _old_adapt
                else:
                    # restore default (remove var) if we set it
                    if os.environ.get('TECHSCAN_DISABLE_ADAPTIVE') == '1':
                        os.environ.pop('TECHSCAN_DISABLE_ADAPTIVE', None)
                if _old_implicit is not None:
                    os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY'] = _old_implicit
                else:
                    if os.environ.get('TECHSCAN_DISABLE_IMPLICIT_RETRY') == '1':
                        os.environ.pop('TECHSCAN_DISABLE_IMPLICIT_RETRY', None)
            micro_techs = micro.get('technologies') or []
            if micro_techs:
                existing = {t['name'] for t in hres.get('technologies', [])}
                added = 0
                for t in micro_techs:
                    if t['name'] not in existing:
                        hres['technologies'].append(t)
                        existing.add(t['name'])
                        added += 1
                # merge categories
                hcats = hres.setdefault('categories', {})
                for cat, arr in (micro.get('categories') or {}).items():
                    bucket = hcats.setdefault(cat, [])
                    exist_pairs = {(b['name'], b.get('version')) for b in bucket}
                    for it in arr:
                        key = (it['name'], it.get('version'))
                        if key not in exist_pairs:
                            bucket.append(it)
                tier_meta['micro_fallback'] = True
                tier_meta['micro_added'] = added
                tier_meta['micro_engine_seconds'] = micro.get('timing', {}).get('engine_seconds') if isinstance(micro.get('timing'), dict) else None
                logging.getLogger('techscan.micro').info('micro fallback success domain=%s added=%d engine_seconds=%s', domain, added, tier_meta.get('micro_engine_seconds'))
            else:
                tier_meta['micro_attempted'] = True
                tier_meta['micro_added'] = 0
                logging.getLogger('techscan.micro').info('micro fallback empty domain=%s', domain)
            micro_end = time.time()
        except Exception as mf_err:
            tier_meta['micro_attempted'] = True
            tier_meta['micro_error'] = str(mf_err)
            logging.getLogger('techscan.micro').warning('micro fallback failed domain=%s err=%s', domain, mf_err)
            micro_end = time.time()
    # Finalize timing breakdown
    try:
        if sniff_start and sniff_end:
            phases_ref['sniff_ms'] = int((sniff_end - sniff_start) * 1000)
        if micro_start and micro_end:
            phases_ref['micro_ms'] = int((micro_end - micro_start) * 1000)
        total = phases_ref.get('heuristic_core_ms', 0) + phases_ref.get('sniff_ms', 0) + phases_ref.get('micro_ms', 0)
        phases_ref['heuristic_total_ms'] = total
        # backward compatible alias
        phases_ref['heuristic_ms'] = phases_ref.get('heuristic_total_ms')
    except Exception:
        pass
    # If we have technologies but categories still empty (e.g., added only via sniff), synthesize categories now
    if hres.get('technologies'):
        cats_current = hres.get('categories') or {}
        # Rebuild if empty or missing expected categories from technologies
        if not cats_current or all(len(v)==0 for v in cats_current.values()):
            cats: Dict[str, List[Dict[str, Any]]] = {}
            for t in hres.get('technologies', []):
                for cat in t.get('categories', []) or []:
                    bucket = cats.setdefault(cat, [])
                    if not any(b['name']==t['name'] and b.get('version')==t.get('version') for b in bucket):
                        bucket.append({'name': t['name'], 'version': t.get('version')})
            if cats:
                hres['categories'] = cats
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.getLogger('techscan.quick').debug('category rebuild domain=%s cat_count=%d', domain, len(cats))
        else:
            # Force a final reconstruction pass to ensure no category drift (e.g., sniff added after initial categories built elsewhere)
            forced: Dict[str, List[Dict[str, Any]]] = {}
            for t in hres.get('technologies', []):
                for cat in t.get('categories', []) or []:
                    bucket = forced.setdefault(cat, [])
                    if not any(b['name']==t['name'] and b.get('version')==t.get('version') for b in bucket):
                        bucket.append({'name': t['name'], 'version': t.get('version')})
            # Only overwrite if forced has strictly more non-empty categories than current (avoid shrinking)
            if forced:
                cur_non_empty = sum(1 for v in cats_current.values() if v)
                forced_non_empty = sum(1 for v in forced.values() if v)
                if forced_non_empty >= cur_non_empty and forced != cats_current:
                    hres['categories'] = forced
                    if logging.getLogger().isEnabledFor(logging.DEBUG):
                        logging.getLogger('techscan.quick').debug('category force rebuild domain=%s old=%d new=%d', domain, cur_non_empty, forced_non_empty)
    # Write cache now that fast enrichment (sniff/micro/category synthesis) is done
    with _lock:
        _cache[cache_key] = {'ts': time.time(), 'data': hres, 'ttl': CACHE_TTL}
        with _stats_lock:
            STATS['cache_entries'] = len(_cache)
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.getLogger('techscan.quick').debug('quick final domain=%s tech=%d categories=%d sniff_cached=%s', domain, len(hres.get('technologies') or []), len(hres.get('categories') or {}), hres.get('tiered',{}).get('html_sniff_cached'))
    # Background full scheduling (optional)
    if defer_full:
        hres['tiered']['deferred_full_quick'] = True
        def _bg_full():
            try:
                full_res = scan_domain(domain, wappalyzer_path, timeout=timeout_full, retries=retries_full, full=False)
                # Merge heuristic if not already included
                if full_res:
                    try:
                        existing = {t['name'] for t in full_res.get('technologies', [])}
                        for t in hres.get('technologies', []):
                            if t['name'] not in existing:
                                full_res['technologies'].append(t)
                        rcats = full_res.setdefault('categories', {})
                        for cat, arr in (hres.get('categories') or {}).items():
                            bucket = rcats.setdefault(cat, [])
                            existing_pairs = {(b['name'], b.get('version')) for b in bucket}
                            for item in arr:
                                key = (item['name'], item.get('version'))
                                if key not in existing_pairs:
                                    bucket.append(item)
                        full_res.setdefault('tiered', {})['merged_quick'] = True
                        full_res['tiered']['final'] = True
                    except Exception:
                        pass
                    # Audit after merge
                    if os.environ.get('TECHSCAN_VERSION_AUDIT','1') == '1':
                        try:
                            version_audit.audit_versions(full_res)
                        except Exception:
                            pass
                    # Persist & cache
                    try:
                        from . import db as _db
                        _db.save_scan(full_res, from_cache=False, timeout_used=timeout_full)
                    except Exception:
                        pass
                    with _lock:
                        _cache[cache_key] = {'ts': time.time(), 'data': full_res, 'ttl': CACHE_TTL}
                        with _stats_lock:
                            STATS['cache_entries'] = len(_cache)
            except Exception:
                pass
        threading.Thread(target=_bg_full, name=f'quick-full-{domain}', daemon=True).start()
    # Persist heuristic quick
    try:
        from . import db as _db
        _db.save_scan(hres, from_cache=False, timeout_used=0)
    except Exception:
        pass
    # Targeted version enrichment (best-effort, after persistence; updates cache if versions added)
    if os.environ.get('TECHSCAN_VERSION_ENRICH','1') == '1':
        try:
            if any(t.get('version') in (None, '') for t in hres.get('technologies') or []):
                changed = _targeted_version_enrichment(hres, timeout=2.0)
                if changed:
                    with _lock:
                        _cache[cache_key] = {'ts': time.time(), 'data': hres, 'ttl': CACHE_TTL}
        except Exception as enr_err:
            logging.getLogger('techscan.enrich').debug('quick enrich fail domain=%s err=%s', domain, enr_err)
    return hres

# --------------------------- DEEP (Time-Budgeted) SCAN ---------------------------
def deep_scan(domain: str, wappalyzer_path: str) -> Dict[str, Any]:
    """Perform a time-budgeted 'deep' scan:

    Phases:
      1. Heuristic quick scan with (possibly higher) budget.
      2. Constrained full Wappalyzer scan (short timeout, single attempt, no adaptive bump).
      3. Merge results (prefer versions from full scan when both present).

    Environment variables:
      TECHSCAN_DEEP_QUICK_BUDGET_MS   (default 1200)  – heuristic budget for phase 1
      TECHSCAN_DEEP_FULL_TIMEOUT_S    (default 6)     – timeout seconds for constrained full scan
      TECHSCAN_DEEP_DISABLE_CACHE     (if '1' do not write cache)
      TECHSCAN_DEEP_CACHE_TTL         (override TTL for deep result; default uses fast or full TTL logic => full key)

    Returns consolidated result with:
      engine = 'deep-combined'
      scan_mode = 'deep'
      phases: {quick_ms, full_ms, total_ms, full_error?, partial?}
    """
    start_all = time.time()
    # Phase 1: heuristic (reuse quick_single_scan but without defer scheduling)
    try:
        deep_quick_budget = int(os.environ.get('TECHSCAN_DEEP_QUICK_BUDGET_MS','1200'))
    except ValueError:
        deep_quick_budget = 1200
    # Run quick with custom budget (temporarily override env variable consumed inside quick_single_scan)
    old_budget = os.environ.get('TECHSCAN_QUICK_BUDGET_MS')
    os.environ['TECHSCAN_QUICK_BUDGET_MS'] = str(deep_quick_budget)
    try:
        quick_res = quick_single_scan(domain, wappalyzer_path, budget_ms=deep_quick_budget, defer_full=False)
    finally:
        if old_budget is not None:
            os.environ['TECHSCAN_QUICK_BUDGET_MS'] = old_budget
        else:
            os.environ.pop('TECHSCAN_QUICK_BUDGET_MS', None)
    quick_elapsed = time.time() - start_all
    # Phase 2: constrained full scan
    try:
        # Increase default constrained full timeout to 12s to reduce premature partial fallbacks
        deep_full_timeout = float(os.environ.get('TECHSCAN_DEEP_FULL_TIMEOUT_S','12'))
    except ValueError:
        deep_full_timeout = 12.0
    # Prepare environment toggles to enforce single shot, no adaptive, no ultra shortcut
    old_ultra = os.environ.get('TECHSCAN_ULTRA_QUICK')
    old_adapt = os.environ.get('TECHSCAN_DISABLE_ADAPTIVE')
    old_impl = os.environ.get('TECHSCAN_DISABLE_IMPLICIT_RETRY')
    old_hard = os.environ.get('TECHSCAN_HARD_TIMEOUT_S')
    try:
        os.environ['TECHSCAN_ULTRA_QUICK'] = '0'
        os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = '1'
        os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY'] = '1'
        os.environ['TECHSCAN_HARD_TIMEOUT_S'] = str(deep_full_timeout)
        full_start = time.time()
        full_res = scan_domain(domain, wappalyzer_path, timeout=int(deep_full_timeout), retries=0, full=True)
        full_elapsed = time.time() - full_start
    except Exception as fe:
        full_res = None
        full_elapsed = 0.0
        full_error = str(fe)
    finally:
        # restore env
        if old_ultra is not None: os.environ['TECHSCAN_ULTRA_QUICK'] = old_ultra
        else: os.environ.pop('TECHSCAN_ULTRA_QUICK', None)
        if old_adapt is not None: os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = old_adapt
        else: os.environ.pop('TECHSCAN_DISABLE_ADAPTIVE', None)
        if old_impl is not None: os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY'] = old_impl
        else: os.environ.pop('TECHSCAN_DISABLE_IMPLICIT_RETRY', None)
        if old_hard is not None: os.environ['TECHSCAN_HARD_TIMEOUT_S'] = old_hard
        else: os.environ.pop('TECHSCAN_HARD_TIMEOUT_S', None)

    # Merge logic
    if full_res:
        merged = full_res
        merged.setdefault('tiered', {})['deep_quick_tech_count'] = len(quick_res.get('technologies') or [])
        # Add any heuristic-only tech not in full
        existing = {t['name'] for t in merged.get('technologies', [])}
        added = 0
        for t in quick_res.get('technologies', []):
            if t['name'] not in existing:
                merged['technologies'].append(t)
                existing.add(t['name'])
                # categories merge
                for cat, arr in (quick_res.get('categories') or {}).items():
                    bucket = merged.setdefault('categories', {}).setdefault(cat, [])
                    if not any(b['name']==t['name'] and b.get('version')==t.get('version') for b in bucket):
                        bucket.append({'name': t['name'], 'version': t.get('version')})
                added += 1
        merged['engine'] = 'deep-combined'
        merged['scan_mode'] = 'deep'
        phases = {
            'quick_ms': int(quick_elapsed*1000),
            'full_ms': int(full_elapsed*1000),
            'total_ms': int((time.time()-start_all)*1000),
            'heuristic_added': added,
            'quick_budget_ms': deep_quick_budget,
            'full_timeout_s': deep_full_timeout
        }
        merged['phases'] = phases
        result = merged
    else:
        # Return partial quick result annotated
        result = quick_res
        result.setdefault('tiered', {})['deep_full_error'] = full_error  # type: ignore
        result['engine'] = 'deep-partial'
        result['scan_mode'] = 'deep'
        phases = {
            'quick_ms': int(quick_elapsed*1000),
            'full_ms': 0,
            'total_ms': int((time.time()-start_all)*1000),
            'full_error': full_error,  # type: ignore
            'partial': True,
            'quick_budget_ms': deep_quick_budget,
            'full_timeout_s': deep_full_timeout
        }
        result['phases'] = phases

    # Targeted enrichment for deep result if versions still missing
    if os.environ.get('TECHSCAN_VERSION_ENRICH','1') == '1':
        try:
            if any(t.get('version') in (None, '') for t in result.get('technologies') or []):
                changed = _targeted_version_enrichment(result, timeout=3.0)
                if changed:
                    logging.getLogger('techscan.enrich').debug('deep enrich added_versions domain=%s', domain)
        except Exception as de:
            logging.getLogger('techscan.enrich').debug('deep enrich fail domain=%s err=%s', domain, de)

    # Cache deep result (under full cache key for richer reuse unless disabled)
    if os.environ.get('TECHSCAN_DEEP_DISABLE_CACHE','0') != '1':
        cache_ttl = None
        try:
            cache_ttl = int(os.environ.get('TECHSCAN_DEEP_CACHE_TTL','0'))
        except ValueError:
            cache_ttl = 0
        if not cache_ttl or cache_ttl < 0:
            cache_ttl = CACHE_TTL
        cache_key = f"full:{result.get('domain')}"
        with _lock:
            _cache[cache_key] = {'ts': time.time(), 'data': result, 'ttl': cache_ttl}
            with _stats_lock:
                STATS['cache_entries'] = len(_cache)
    return result

# --------------------------- FAST-FULL (Bounded Single-Phase) SCAN ---------------------------
def fast_full_scan(domain: str, wappalyzer_path: str) -> Dict[str, Any]:
    """Run a *single* bounded full Wappalyzer scan with a strict wall-clock budget.

    Goals:
      - Faster than classic full (skip adaptive retry & multi-attempt logic)
      - More complete than quick (directly runs full engine, not just heuristic)
      - Deterministic upper bound (timeout budget in ms) returning partial heuristic fallback if exceeded.

    Environment:
      TECHSCAN_FAST_FULL_TIMEOUT_MS   (default 5000)   – hard cap (ms) for the full engine attempt.
      TECHSCAN_FAST_FULL_DISABLE_CACHE (='1')          – if set, do not cache result.
      TECHSCAN_FAST_FULL_CACHE_TTL     (int seconds)   – override cache TTL (default CACHE_TTL).

    Behaviour:
      - Disables adaptive bump & implicit retry (single shot)
      - Sets TECHSCAN_HARD_TIMEOUT_S to budget (seconds) so internal loop respects wall clock
      - If scan succeeds before timeout -> engine='fast-full'
      - If any exception (timeout/error) -> fallback to heuristic quick scan and mark partial

    Response extras:
      phases = { 'full_ms', 'timeout_ms', 'partial': bool, 'error'? }
      engine  = 'fast-full' | 'fast-full-partial'
      scan_mode = 'fast_full'
    """
    start_all = time.time()
    started_at = start_all
    # Resolve timeout budget
    try:
        budget_ms = int(os.environ.get('TECHSCAN_FAST_FULL_TIMEOUT_MS', '5000'))
    except ValueError:
        budget_ms = 5000
    if budget_ms < 1000:  # enforce minimal sane lower bound
        budget_ms = 1000
    timeout_s = max(1, int((budget_ms + 999) / 1000))  # round up to whole seconds for scan_domain

    # Preserve env toggles we will override
    old_ultra = os.environ.get('TECHSCAN_ULTRA_QUICK')
    old_adapt = os.environ.get('TECHSCAN_DISABLE_ADAPTIVE')
    old_impl = os.environ.get('TECHSCAN_DISABLE_IMPLICIT_RETRY')
    old_hard = os.environ.get('TECHSCAN_HARD_TIMEOUT_S')
    result: Dict[str, Any] | None = None
    error: str | None = None
    try:
        os.environ['TECHSCAN_ULTRA_QUICK'] = '0'
        os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = '1'
        os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY'] = '1'
        os.environ['TECHSCAN_HARD_TIMEOUT_S'] = str(timeout_s)
        full_start = time.time()
        # Single attempt full scan
        result = scan_domain(domain, wappalyzer_path, timeout=timeout_s, retries=0, full=True)
        full_done = time.time()
        full_elapsed = int((full_done - full_start) * 1000)
        result['engine'] = 'fast-full'
        result['scan_mode'] = 'fast_full'
        # Phases: full_attempt_ms (engine+processing), fallback_ms (0 if none)
        result['phases'] = {
            'full_ms': full_elapsed,              # legacy kept for compatibility
            'full_attempt_ms': full_elapsed,
            'fallback_ms': 0,
            'timeout_ms': budget_ms,
            'partial': False
        }
        result['started_at'] = started_at
        result['finished_at'] = full_done
        result['duration'] = round(full_done - started_at, 3)
    except Exception as fe:  # Timeout or other error -> fallback heuristic
        error = str(fe)
        logging.getLogger('techscan.fast_full').warning('fast_full primary scan failed domain=%s err=%s (fallback heuristic)', domain, fe)
        # Tandai waktu akhir attempt full sebelum fallback heuristic dimulai
        fail_end = time.time()
        # Fallback heuristic quick scan (best effort, never raise)
        try:
            quick_res = quick_single_scan(domain, wappalyzer_path, defer_full=False)
        except Exception as qe:
            # If heuristic also fails, synthesize minimal structure
            logging.getLogger('techscan.fast_full').error('heuristic fallback failed domain=%s err=%s', domain, qe)
            quick_res = {
                'domain': domain,
                'technologies': [],
                'categories': {},
                'tiered': {'heuristic_error': str(qe)}
            }
        quick_res['engine'] = 'fast-full-partial'
        quick_res['scan_mode'] = 'fast_full'
        fallback_done = time.time()
        # Heuristic result may include phases.heuristic_ms; treat that as fallback_ms
        heuristic_ms = 0
        try:
            heuristic_ms = int(quick_res.get('phases', {}).get('heuristic_ms') or 0)
        except Exception:
            heuristic_ms = 0
        # full_attempt_ms = waktu attempt full sampai error (fail_end - start_all)
        full_attempt_ms = int((fail_end - start_all) * 1000)
        # fallback_ms = heuristic_ms (durasi heuristic aktual)
        quick_res['phases'] = {
            'full_ms': full_attempt_ms,   # legacy alias
            'full_attempt_ms': full_attempt_ms,
            'fallback_ms': heuristic_ms,
            'timeout_ms': budget_ms,
            'partial': True,
            'error': error
        }
        quick_res['started_at'] = started_at
        quick_res['finished_at'] = fallback_done
        quick_res['duration'] = round(fallback_done - started_at, 3)
        result = quick_res
    finally:
        # Restore env
        if old_ultra is not None: os.environ['TECHSCAN_ULTRA_QUICK'] = old_ultra
        else: os.environ.pop('TECHSCAN_ULTRA_QUICK', None)
        if old_adapt is not None: os.environ['TECHSCAN_DISABLE_ADAPTIVE'] = old_adapt
        else: os.environ.pop('TECHSCAN_DISABLE_ADAPTIVE', None)
        if old_impl is not None: os.environ['TECHSCAN_DISABLE_IMPLICIT_RETRY'] = old_impl
        else: os.environ.pop('TECHSCAN_DISABLE_IMPLICIT_RETRY', None)
        if old_hard is not None: os.environ['TECHSCAN_HARD_TIMEOUT_S'] = old_hard
        else: os.environ.pop('TECHSCAN_HARD_TIMEOUT_S', None)

    # Record stats for fast_full (treat as its own mode)
    try:
        elapsed = time.time() - start_all
        # Guarantee a minimal positive elapsed to avoid zero averages in tests when mocked scan returns instantly
        if elapsed <= 0:
            elapsed = 0.0005  # 0.5 ms minimal
        with _stats_lock:
            # increment scans separately from scan_domain internal counter (still counts underlying full engine)
            STATS['durations']['fast_full']['count'] += 1
            STATS['durations']['fast_full']['total'] += elapsed
            STATS['recent_samples']['fast_full'].append(elapsed)
    except Exception:
        pass

    # Targeted enrichment (only if still missing versions)
    if os.environ.get('TECHSCAN_VERSION_ENRICH','1') == '1' and result:
        try:
            if any(t.get('version') in (None, '') for t in result.get('technologies') or []):
                _targeted_version_enrichment(result, timeout=2.5)
        except Exception as ee:
            logging.getLogger('techscan.enrich').debug('fast_full enrich fail domain=%s err=%s', domain, ee)

    # Cache (unless disabled)
    if result and os.environ.get('TECHSCAN_FAST_FULL_DISABLE_CACHE','0') != '1':
        try:
            cache_ttl = CACHE_TTL
            try:
                c_override = int(os.environ.get('TECHSCAN_FAST_FULL_CACHE_TTL','0'))
                if c_override > 0:
                    cache_ttl = c_override
            except ValueError:
                pass
            cache_key = f"full:{result.get('domain')}"
            with _lock:
                _cache[cache_key] = {'ts': time.time(), 'data': result, 'ttl': cache_ttl}
                with _stats_lock:
                    STATS['cache_entries'] = len(_cache)
        except Exception:
            pass
    return result  # type: ignore
