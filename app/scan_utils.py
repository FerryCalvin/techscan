import json, re, subprocess, threading, time, os, pathlib, logging
import socket, ssl
from functools import lru_cache
from typing import Dict, Any, List

DOMAIN_RE = re.compile(r'^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$')
CACHE_TTL = 300  # default seconds
_lock = threading.Lock()
_cache: Dict[str, Dict[str, Any]] = {}
_stats_lock = threading.Lock()
STATS: Dict[str, Any] = {
    'start_time': time.time(),
    'hits': 0,
    'misses': 0,
    'mode_hits': {'fast': 0, 'full': 0},
    'mode_misses': {'fast': 0, 'full': 0},
    'scans': 0,  # total scan_domain invocations (including retries counted once)
    'cache_entries': 0,  # updated on write
    'synthetic': {'headers': 0, 'tailwind': 0, 'floodlight': 0},
    'durations': {
        'fast': {'count': 0, 'total': 0.0},
        'full': {'count': 0, 'total': 0.0}
    }
}

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

def validate_domain(raw: str) -> str:
    """Return a normalized domain or raise ValueError.
    - Lowercase
    - Strip trailing dot
    - IDNA (punycode) encode/decode round trip for validation
    - Reject if regex mismatch
    """
    d = (raw or '').strip().lower().rstrip('.')
    if not d:
        raise ValueError('empty domain')
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
    categories_file = pathlib.Path(wappalyzer_path) / 'src' / 'categories.json'
    with open(categories_file, 'r', encoding='utf-8') as f:
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
    techs = raw.get('technologies') or raw.get('applications') or []
    norm_techs = []
    category_bucket: Dict[str, List[Dict[str, Any]]] = {}
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
        names = list(dict.fromkeys(names))  # dedupe preserving order
        entry = {
            'name': t.get('name'),
            'version': t.get('version'),
            'categories': names,
            'confidence': t.get('confidence')
        }
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

_heuristics_lock = threading.Lock()
_heuristics_patterns: list[tuple[re.Pattern, int]] = []

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
    persist = os.environ.get('TECHSCAN_PERSIST_BROWSER','0') == '1'
    local_scanner = pathlib.Path(__file__).resolve().parent.parent / 'node_scanner' / ('scanner.js' if not persist else 'server.js')
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
            if persist:
                # Use persistent client
                from . import persistent_client as pc
                data = pc.scan(domain, full=full)
            else:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=eff_timeout, env=env)
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
            categories_map = load_categories(wappalyzer_path)
            result = normalize_result(domain, data, categories_map)
            # Synthetic header-based detection (optional)
            if os.environ.get('TECHSCAN_SYNTHETIC_HEADERS', '1') == '1':
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
            result['scan_mode'] = 'full' if full else 'fast'
            result['engine'] = f'wappalyzer-{mode}'
            if attempt > 1:
                result['retries'] = attempt - 1
            if adaptive_used:
                result['adaptive_timeout'] = True
            finished_at = time.time()
            elapsed = finished_at - t0
            result['duration'] = round(elapsed, 2)
            result['started_at'] = started_at
            result['finished_at'] = finished_at
            logger.info('scan success domain=%s engine=%s duration=%.2fs attempts=%d', domain, result['engine'], elapsed, attempt)
            # stats: record duration
            with _stats_lock:
                mode_key = 'full' if full else 'fast'
                STATS['scans'] += 1
                bucket = STATS['durations'][mode_key]
                bucket['count'] += 1
                bucket['total'] += elapsed
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
        except (subprocess.TimeoutExpired) as te:
            last_err = te
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
            if attempt == attempts:
                logger.error('scan error domain=%s err=%s', domain, e)
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
                # Deferred full scan mode: immediately return heuristic and schedule background Wappalyzer
                if os.environ.get('TECHSCAN_DEFER_FULL','0') == '1' and not full:
                    quick = heuristic_result
                    quick.setdefault('tiered', {})['deferred_full'] = True
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
                                try:
                                    existing = {t['name'] for t in result_full.get('technologies', [])}
                                    for t in heuristic_result.get('technologies', []):
                                        if t['name'] not in existing:
                                            result_full['technologies'].append(t)
                                    rcats = result_full.setdefault('categories', {})
                                    for cat, arr in (heuristic_result.get('categories') or {}).items():
                                        bucket = rcats.setdefault(cat, [])
                                        existing_pairs = {(b['name'], b.get('version')) for b in bucket}
                                        for item in arr:
                                            key = (item['name'], item.get('version'))
                                            if key not in existing_pairs:
                                                bucket.append(item)
                                    result_full.setdefault('tiered', {})['heuristic_duration'] = heuristic_result.get('duration')
                                    result_full['tiered']['heuristic_reason'] = heuristic_result.get('tiered',{}).get('reason')
                                    result_full['tiered']['used'] = True
                                    result_full['tiered']['deferred_full'] = False
                                    result_full['tiered']['final'] = True
                                    result_full['tiered']['from_deferred'] = True
                                except Exception as me:
                                    logging.getLogger('techscan.tiered').debug('deferred merge heuristic failed domain=%s err=%s', domain, me)
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
                                    try:
                                        existing = {t['name'] for t in result_full.get('technologies', [])}
                                        for t in heuristic_result.get('technologies', []):
                                            if t['name'] not in existing:
                                                result_full['technologies'].append(t)
                                        rcats = result_full.setdefault('categories', {})
                                        for cat, arr in (heuristic_result.get('categories') or {}).items():
                                            bucket = rcats.setdefault(cat, [])
                                            existing_pairs = {(b['name'], b.get('version')) for b in bucket}
                                            for item in arr:
                                                key = (item['name'], item.get('version'))
                                                if key not in existing_pairs:
                                                    bucket.append(item)
                                        result_full.setdefault('tiered', {})['heuristic_duration'] = heuristic_result.get('duration')
                                        result_full['tiered']['heuristic_reason'] = heuristic_result.get('tiered',{}).get('reason')
                                        result_full['tiered']['used'] = True
                                        result_full['tiered']['auto_trigger_full'] = True
                                        result_full['tiered']['final'] = True
                                        result_full['tiered']['from_auto_trigger'] = True
                                    except Exception as me:
                                        logging.getLogger('techscan.tiered').debug('auto-trigger merge heuristic failed domain=%s err=%s', domain, me)
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

    try:
        result = scan_domain(domain, wappalyzer_path, timeout=timeout, retries=retries, full=full)
    except Exception as e:
        # If timeout or scan error and we have heuristic partial, return heuristic instead of total failure
        if tiered_enabled and heuristic_result:
            heuristic_result.setdefault('tiered', {})['fallback'] = True
            heuristic_result.setdefault('error', str(e))
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
        raise
    # Merge heuristic partial if exists and not early-return
    if heuristic_result and not heuristic_result.get('tiered',{}).get('early_return'):
        try:
            # Avoid duplicating technologies by name
            existing = {t['name'] for t in result.get('technologies', [])}
            for t in heuristic_result.get('technologies', []):
                if t['name'] not in existing:
                    result['technologies'].append(t)
            # categories merge
            rcats = result.setdefault('categories', {})
            for cat, arr in (heuristic_result.get('categories') or {}).items():
                bucket = rcats.setdefault(cat, [])
                existing_pairs = {(b['name'], b.get('version')) for b in bucket}
                for item in arr:
                    key = (item['name'], item.get('version'))
                    if key not in existing_pairs:
                        bucket.append(item)
            result.setdefault('tiered', {})['heuristic_duration'] = heuristic_result.get('duration')
            result['tiered']['heuristic_reason'] = heuristic_result.get('tiered',{}).get('reason')
            result['tiered']['used'] = True
        except Exception as me:
            logging.getLogger('techscan.tiered').debug('merge heuristic failed domain=%s err=%s', domain, me)
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

def scan_bulk(domains: List[str], wappalyzer_path: str, concurrency: int = 4, timeout: int = 45, fresh: bool = False, retries: int = 0, ttl: int | None = None, full: bool = False) -> List[Dict[str, Any]]:
    filtered = []
    for d in domains:
        d2 = extract_host((d or '').strip())
        if DOMAIN_RE.match(d2):
            filtered.append(d2.lower())
    results: List[Dict[str, Any]] = [None] * len(filtered)  # type: ignore
    idx = 0
    lock_i = threading.Lock()
    fast_first = (os.environ.get('TECHSCAN_BULK_FAST_FIRST','0') == '1') and not full

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
                    # Force heuristic path: enable tiered + defer if not already
                    # Temporarily set env flags inside thread (local copy)
                    # We call get_cached_or_scan with fast mode; relying on existing deferred / auto-trigger
                    res = get_cached_or_scan(dom, wappalyzer_path, timeout=timeout, fresh=fresh, retries=0, ttl=ttl, full=False)
                else:
                    res = get_cached_or_scan(dom, wappalyzer_path, timeout=timeout, fresh=fresh, retries=retries, ttl=ttl, full=full)
                results[i] = {'status': 'ok', **res}
            except Exception as e:
                results[i] = {'status': 'error', 'domain': dom, 'error': str(e)}
    threads = [threading.Thread(target=worker) for _ in range(min(concurrency, len(filtered)))]
    for t in threads: t.start()
    for t in threads: t.join()
    return results

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
                'full': round(full_avg * 1000, 2)
            },
            'synthetic': STATS['synthetic']
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
                        out.append({'name': 'Nginx', 'version': ver, 'categories': ['Web servers','Reverse proxies'], 'confidence': 40})
                    elif lname in ('apache','httpd'):
                        out.append({'name': 'Apache', 'version': ver, 'categories': ['Web servers'], 'confidence': 40})
                    elif lname == 'cloudflare':
                        out.append({'name': 'Cloudflare', 'version': ver, 'categories': ['Reverse proxies','CDN'], 'confidence': 30})
            if 'strict-transport-security' in headers:
                out.append({'name': 'HSTS', 'version': None, 'categories': ['Security'], 'confidence': 30})
            conn.close()
            tried.append(scheme)
        except Exception:
            continue
        # Stop after first success
        if out:
            break
    return out
