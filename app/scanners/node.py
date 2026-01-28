import os
import time
import json
import logging
import pathlib
import socket
from typing import Dict, Any, List

import requests
from .. import safe_subprocess as sproc
from .. import version_audit
from ..utils.domain import validate_domain, extract_host, preflight
from ..scanners.state import STATS, _fail_lock, _fail_map, _stats_lock, _check_quarantine
from ..utils.tech_data import load_categories, normalize_result, attach_raw_hint_meta as _attach_raw_hint_meta, apply_hint_meta_detections as _apply_hint_meta_detections

def synthetic_header_detection(domain: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Detect technologies based on HTTP headers (synthetic)."""
    url = f"https://{domain}" if not domain.startswith('http') else domain
    techs = []
    try:
        # Request with minimal budget and no verify for speed
        resp = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
        headers = resp.headers
        
        # Simple header analysis
        server = headers.get('Server')
        if server:
            # e.g., Nginx, Apache/2.4
            name = server.split('/')[0].strip()
            if name:
                techs.append({'name': name, 'version': None, 'categories': ['Web Servers'], 'confidence': 100, 'header': True})
        
        powered = headers.get('X-Powered-By')
        if powered:
             # e.g. PHP/7.4, Express
            name = powered.split('/')[0].strip()
            if name:
                techs.append({'name': name, 'version': None, 'categories': ['Programming Languages', 'Web Frameworks'], 'confidence': 100, 'header': True})

        if 'cf-ray' in headers or 'cf-cache-status' in headers:
            techs.append({'name': 'Cloudflare', 'categories': ['CDN', 'Security'], 'confidence': 100, 'header': True})
            
    except Exception:
        # Fail silently for synthetic (optional enhancement)
        pass
    return techs

# Constants
QUICK_DEFAULT_BUDGET_MS = 2500

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

def _record_success(domain: str):
    with _fail_lock:
        if domain in _fail_map:
            # partial decay: keep last time for forensic but reset fails & quarantine
            _fail_map[domain]['fails'] = 0
            _fail_map[domain]['quarantine_until'] = 0.0

def apply_min_timeout(domain: str, requested: int) -> int:
    """Heuristic logic to raise timeout for known slower endpoints."""
    # Placeholder: currently passes through, but structure is here for improvement
    return max(requested, 5)

def scan_domain(domain: str, wappalyzer_path: str, timeout: int = 45, retries: int = 0, full: bool = False, url: str | None = None) -> Dict[str, Any]:
    # Domain is used for structural identity, preflight, cache keys.
    # URL (if provided) is used for the actual detection target (page fetch).
    raw_target = url if url else domain
    domain = validate_domain(extract_host(domain))
    # Preflight connectivity check (always against host)
    if not preflight(domain):
        logging.getLogger('techscan.preflight').warning('preflight unreachable domain=%s', domain)
        # Optional heuristic fallback if tiered enabled
        if os.environ.get('TECHSCAN_TIERED','0') == '1':
            try:
                from .. import heuristic_fast
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
                from .. import heuristic_fast
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
            from .. import heuristic_fast
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
    # Resolve scanner path relative to expected location (2 levels up from here since we are in app/scanners now? 
    # No, app/scanners is one level deeper than app. 
    # original: app/scan_utils.py -> parent.parent / node_scanner
    # new: app/scanners/node.py -> parent.parent.parent / node_scanner
    local_scanner = pathlib.Path(__file__).resolve().parent.parent.parent / 'node_scanner' / ('scanner.js' if not persist else 'server.js')
    
    if use_py_wapp and not full:
        # Fast local detector; skip Node/Chromium entirely
        logger = logging.getLogger('techscan.scan_domain')
        op_start = time.time()
        try:
            from .. import wapp_local
            # Pass full URL if available
            data = wapp_local.detect(raw_target, wappalyzer_path, timeout=min(timeout, 6))
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
        # CMD not used for safe_run in persist mode, but kept for logging/debug strings
        cmd = ['node', str(local_scanner), raw_target]
    else:
        if local_scanner.exists():
            cli = local_scanner
            mode = 'local'
            cmd = ['node', str(cli), raw_target]
        else:
            cli = pathlib.Path(wappalyzer_path) / 'src' / 'drivers' / 'npm' / 'cli.js'
            if not cli.exists():
                raise FileNotFoundError('wappalyzer cli not found at expected path')
            mode = 'external'
            # For external driver, ensure it has protocol if missing (raw_target usually has it if from url)
            # If raw_target is just domain, add https
            target_url = raw_target
            if not target_url.startswith(('http://', 'https://')):
                 target_url = f'https://{target_url}'
            cmd = ['node', str(cli), target_url]
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
                from .. import persistent_client as pc
                data = pc.scan(raw_target, full=full)
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
            try:
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
                        from .. import heuristic_fast
                        hres = heuristic_fast.run_heuristic(domain, budget_ms= int(os.environ.get('TECHSCAN_TIERED_BUDGET_MS','1800')), allow_empty_early=True)
                        hres.setdefault('tiered', {})['timeout_fallback'] = True
                        hres['engine'] = 'heuristic-fallback-timeout'
                        hres['scan_mode'] = 'fast'
                        return hres
                    except Exception:
                        pass
                raise TimeoutError(f'timeout after {elapsed_all:.1f}s')
        except Exception as e:
            last_err = e
            logger.warning('scan attempt %d failed domain=%s err=%s', attempt, domain, e)
            _record_failure(domain)
            attempt += 1
            if attempt > attempts:
                raise last_err
        time.sleep(1)

    if last_err:
        raise last_err
    raise RuntimeError('scan failed (unknown reason)')
