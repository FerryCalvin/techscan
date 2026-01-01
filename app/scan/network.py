"""Network utilities for scanning.

This module handles:
- DNS negative caching
- TCP preflight checks
- Domain quarantine/failure tracking
- Single-flight request deduplication
- Error classification
"""

import os
import socket
import time
import logging
import threading
from typing import Dict, Any, Optional, Union

# ============ Module-level State ============

# Failure tracking & quarantine (domain-level)
_fail_lock = threading.Lock()
_fail_map: Dict[str, dict] = {}

# DNS negative cache
_dns_neg_lock = threading.Lock()
_dns_neg: Dict[str, float] = {}

# Single-flight guard
_single_flight_lock = threading.Lock()
_single_flight_map: Dict[str, dict] = {}

# Stats reference (will be set by stats module)
STATS: Optional[Dict[str, Any]] = None
_stats_lock: Optional[threading.Lock] = None


def set_stats_reference(stats: Dict[str, Any], lock: threading.Lock):
    """Set reference to global stats dict for metrics tracking."""
    global STATS, _stats_lock
    STATS = stats
    _stats_lock = lock


# ============ Single-Flight Guard ============

def single_flight_enter(cache_key: str) -> bool:
    """Enter single-flight section for given cache_key.
    
    Returns True if caller is the leader responsible for performing the scan.
    If another leader is running, this call will wait until completion and return False.
    Disabled when TECHSCAN_SINGLE_FLIGHT=0.
    """
    if os.environ.get('TECHSCAN_SINGLE_FLIGHT', '1') == '0':
        return True
    
    start_wait: Optional[float] = None
    with _single_flight_lock:
        entry = _single_flight_map.get(cache_key)
        if entry is None:
            # Become leader
            cond = threading.Condition(_single_flight_lock)
            _single_flight_map[cache_key] = {'cond': cond, 'running': True}
            if STATS and _stats_lock:
                with _stats_lock:
                    STATS['single_flight']['inflight'] += 1
            return True
        # Follower path: wait until leader completes
        cond: threading.Condition = entry['cond']
        start_wait = time.time()
        while entry.get('running'):
            cond.wait()
        # Leader finished; record wait stats
        if start_wait is not None and STATS and _stats_lock:
            waited = time.time() - start_wait
            with _stats_lock:
                STATS['single_flight']['hits'] += 1
                STATS['single_flight']['wait_ms'] += int(waited * 1000)
        return False


def single_flight_exit(cache_key: str):
    """Exit single-flight section, notifying waiting followers."""
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
            if STATS and _stats_lock:
                with _stats_lock:
                    STATS['single_flight']['inflight'] -= 1


# ============ DNS Negative Cache ============

def dns_negative(domain: str) -> bool:
    """Check if domain is in negative cache and still valid."""
    ttl = 0
    try:
        ttl = int(os.environ.get('TECHSCAN_DNS_NEG_CACHE', '0'))
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


def dns_add_negative(domain: str):
    """Add domain to DNS negative cache."""
    try:
        ttl = int(os.environ.get('TECHSCAN_DNS_NEG_CACHE', '0'))
    except ValueError:
        ttl = 0
    if ttl <= 0:
        return
    with _dns_neg_lock:
        _dns_neg[domain] = time.time() + ttl


# ============ Preflight Check ============

def preflight(domain: str) -> bool:
    """Fast TCP connect preflight to check domain reachability.
    
    Attempts connection to port 443, falls back to 80.
    Controlled by TECHSCAN_PREFLIGHT=1.
    
    Returns:
        True if reachable, False if definitely unreachable
    """
    if os.environ.get('TECHSCAN_PREFLIGHT', '0') != '1':
        return True
    if dns_negative(domain):
        return False
    
    # Try resolve
    try:
        addrs = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except Exception:
        dns_add_negative(domain)
        return False
    
    targets = []
    for af, st, proto, cname, sa in addrs:
        targets.append((sa[0], 443))
    
    if not targets:
        return False
    
    ok = False
    # Try port 443
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
        dns_add_negative(domain)
    
    return ok


# ============ Failure Tracking & Quarantine ============

def record_failure(domain: str, now: Optional[float] = None):
    """Record a scan failure for a domain."""
    now = now or time.time()
    with _fail_lock:
        ent = _fail_map.setdefault(domain, {'fails': 0, 'last': 0.0, 'quarantine_until': 0.0})
        ent['fails'] += 1
        ent['last'] = now
        # If exceeds threshold, configure quarantine
        try:
            thresh = int(os.environ.get('TECHSCAN_QUARANTINE_FAILS', '0'))
            minutes = float(os.environ.get('TECHSCAN_QUARANTINE_MINUTES', '0'))
        except ValueError:
            thresh, minutes = 0, 0.0
        if thresh > 0 and minutes > 0 and ent['fails'] >= thresh:
            ent['quarantine_until'] = max(ent.get('quarantine_until', 0.0), now + minutes * 60)
            ent['fails'] = 0  # Reset to avoid runaway growth


def check_quarantine(domain: str, now: Optional[float] = None) -> bool:
    """Check if domain is currently quarantined."""
    now = now or time.time()
    with _fail_lock:
        ent = _fail_map.get(domain)
        if not ent:
            return False
        if ent.get('quarantine_until', 0.0) > now:
            return True
        # Expired quarantine: allow and clean up
        if ent.get('quarantine_until') and ent['quarantine_until'] <= now:
            ent['quarantine_until'] = 0.0
        return False


def record_success(domain: str):
    """Record a successful scan, clearing failure state."""
    with _fail_lock:
        if domain in _fail_map:
            _fail_map[domain]['fails'] = 0
            _fail_map[domain]['quarantine_until'] = 0.0


# ============ Error Classification ============

def classify_error(err: Union[Exception, str]) -> str:
    """Classify an error into a category for metrics.
    
    Returns:
        One of: timeout, preflight, quarantine, dns, ssl, conn, other
    """
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


# ============ Persist Failure Scan ============

def persist_failure_scan(
    domain: str,
    *,
    mode: str,
    timeout_used: int,
    retries: int,
    error: Union[Exception, str],
    started_at: Optional[float] = None,
    finished_at: Optional[float] = None,
    engine: str = 'scan-error',
    raw: Optional[dict] = None
) -> bool:
    """Record failed scan attempts to database for UI display."""
    if not domain:
        return False
    
    msg = str(error)
    err_class = classify_error(error) if isinstance(error, Exception) else 'other'
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
        from .. import db as _db  # local import to avoid circulars
        _db.save_scan(payload, from_cache=False, timeout_used=timeout_used)
        return True
    except Exception as db_ex:
        logging.getLogger('techscan.db').debug('save_scan failure stub failed domain=%s err=%s', domain, db_ex)
        return False


# ============ Exports ============

__all__ = [
    # Single-flight
    'single_flight_enter',
    'single_flight_exit',
    'set_stats_reference',
    # DNS
    'dns_negative',
    'dns_add_negative',
    # Preflight
    'preflight',
    # Quarantine
    'record_failure',
    'check_quarantine',
    'record_success',
    # Error handling
    'classify_error',
    'persist_failure_scan',
]
