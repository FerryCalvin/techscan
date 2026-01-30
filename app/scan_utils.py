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
# These were previously defined here or imported here





