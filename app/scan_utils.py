from .scanners.state import (
    STATS,
    _stats_lock
)

# Cache configuration
import os
import time

CACHE_TTL = int(os.environ.get('TECHSCAN_CACHE_TTL', '3600'))

# Ensure STATS has necessary keys if not initialized by main
with _stats_lock:
    if 'hits' not in STATS:
        STATS['hits'] = 0
    if 'misses' not in STATS:
        STATS['misses'] = 0
    if 'scans' not in STATS:
        STATS['scans'] = 0
    if 'single_flight' not in STATS:
        STATS['single_flight'] = {'active_keys': 0, 'inflight': 0, 'locked': 0, 'hits': 0, 'wait_ms': 0}
    else:
        if 'hits' not in STATS['single_flight']:
            STATS['single_flight']['hits'] = 0
        if 'wait_ms' not in STATS['single_flight']:
            STATS['single_flight']['wait_ms'] = 0

def get_stats():
    # Re-implementation of get_stats accessing global STATS from state
    now = time.time()
    with _stats_lock:
        def avg(bucket):
            return (bucket['total'] / bucket['count']) if bucket['count'] else 0.0
        fast_avg = avg(STATS['durations']['fast'])
        full_avg = avg(STATS['durations']['full'])
        fast_full_avg = avg(STATS['durations'].get('fast_full', {'count':0,'total':0}))
        
        return {
            'uptime_seconds': round(now - STATS['start_time'], 2),
            'hits': STATS['hits'],
            'misses': STATS['misses'],
            'scans': STATS['scans'],
            'average_duration_ms': {
                'full': round(full_avg * 1000, 2),
                'fast_full': round(fast_full_avg * 1000, 2)
            },
            'recent_latency_ms': {
                'fast': {'average': round(fast_avg * 1000, 2), 'samples': STATS['durations']['fast']['count']},
                'full': {'average': round(full_avg * 1000, 2), 'samples': STATS['durations']['full']['count']},
                'fast_full': {'average': round(fast_full_avg * 1000, 2), 'samples': STATS['durations'].get('fast_full', {}).get('count', 0)}
            }
        }

def load_heuristic_patterns():
    # Stub for reloading heuristic patterns (not yet implemented or static)
    pass


# ---- RE-EXPORTS for scan.py compatibility ----
from .utils.domain import validate_domain, extract_host, extract_url_with_path, DOMAIN_RE
from .scanners.node import scan_domain

from app.utils.tech_data import (
    infer_tech_from_urls,
    load_categories
)
import app.wapp_local as wapp_local
import app.heuristic_fast as heuristic_fast
from app.heuristic_fast import synthetic_header_detection
import app.scanners.core as core_import
from .scanners.core import (
    quick_single_scan,
    deep_scan,
    fast_full_scan,
    get_cached_or_scan,
    scan_bulk,
    bulk_quick_then_deep,
    scan_unified,
    snapshot_cache,
    flush_cache
)

from .scanners.state import (
    _record_failure,
    _record_success,
    _check_quarantine,
    _dns_negative
)

__all__ = [
    "STATS",
    "get_stats",
    "load_heuristic_patterns",
    "validate_domain",
    "extract_host",
    "extract_url_with_path",
    "DOMAIN_RE",
    "scan_domain",
    "quick_single_scan",
    "deep_scan",
    "fast_full_scan",
    "get_cached_or_scan",
    "scan_bulk",
    "bulk_quick_then_deep",
    "scan_unified",
    "synthetic_header_detection",
    "snapshot_cache",
    "flush_cache",
    "infer_tech_from_urls",
    "load_categories",
    "wapp_local",
    "heuristic_fast",
    "_record_failure",
    "_record_success",
    "_check_quarantine",
    "_dns_negative",
]
