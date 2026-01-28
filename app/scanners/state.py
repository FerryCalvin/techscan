import threading
import time
from typing import Dict, Any, List, Optional
from collections import deque

# Global Locks
_lock = threading.Lock()
_stats_lock = threading.Lock()
_fail_lock = threading.Lock()
_dns_neg_lock = threading.Lock()
_single_flight_lock = threading.Lock()

# Global State
_cache: Dict[str, Dict[str, Any]] = {}
_fail_map: Dict[str, dict] = {}
_dns_neg: Dict[str, float] = {}
_single_flight_map: Dict[str, dict] = {}

def _check_quarantine(domain: str) -> bool:
    """Check if domain is currently in failure quarantine."""
    with _fail_lock:
        ent = _fail_map.get(domain)
        if not ent:
            return False
        q_until = ent.get('quarantine_until', 0.0)
        if q_until > 0 and time.time() < q_until:
            return True
        return False


# Statistics
STATS: Dict[str, Any] = {
    'start_time': time.time(),
    'hits': 0,
    'misses': 0,
    'mode_hits': {'fast': 0, 'full': 0, 'fast_full': 0},
    'mode_misses': {'fast': 0, 'full': 0, 'fast_full': 0},
    'scans': 0,
    'cache_entries': 0,
    'errors': {
        'timeout': 0,
        'dns': 0,
        'connection': 0,
        'generic': 0
    },
    'durations': {
        'fast': {'count': 0, 'total': 0.0},
        'full': {'count': 0, 'total': 0.0},
        'fast_full': {'count': 0, 'total': 0.0}
    },
    'recent_samples': {
        'fast': deque(maxlen=50),
        'full': deque(maxlen=50),
        'fast_full': deque(maxlen=50)
    },
    'synthetic': {
        'headers': 0,
        'tailwind': 0,
        'floodlight': 0
    },
    'phases': {
        'heuristic_ms': 0,
        'heuristic_count': 0,
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
    'single_flight': {
        'active_keys': 0,
        'locked': 0,
        'inflight': 0
    }
}

def _dns_negative(domain: str) -> Optional[float]:
    """Check if domain is in DNS negative cache (recently failed resolution)."""
    with _dns_neg_lock:
        return _dns_neg.get(domain)

def _dns_add_negative(domain: str, duration: float = 600.0) -> None:
    """Add domain to DNS negative cache."""
    with _dns_neg_lock:
        _dns_neg[domain] = time.time() + duration

def _record_failure(domain: str, reason: str = 'generic', ttl: float = 300.0) -> None:
    """Record a failure for a domain to prevent rapid retries (quarantine)."""
    # Allow override by env var if using default logic (though caller can pass explicit ttl)
    if ttl == 300.0:
        import os
        try:
            minutes = float(os.environ.get('TECHSCAN_QUARANTINE_MINUTES', '5'))
            ttl = minutes * 60
        except ValueError:
            ttl = 300.0
            
    with _fail_lock:
        _fail_map[domain] = {
            'reason': reason,
            'quarantine_until': time.time() + ttl,
            'count': _fail_map.get(domain, {}).get('count', 0) + 1
        }

def _record_success(domain: str) -> None:
    """Clear any failure record for a domain upon success."""
    with _fail_lock:
        if domain in _fail_map:
            del _fail_map[domain]
