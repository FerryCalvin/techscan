"""Prometheus metrics for TechScan.

Provides application metrics in Prometheus format for monitoring and alerting.
Metrics are exposed at /metrics/prometheus endpoint.
"""

import time
from functools import wraps
from typing import Optional

# Try to import prometheus_client, provide stub if not available
try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    CONTENT_TYPE_LATEST = 'text/plain'
    
    def generate_latest(registry=None):
        return b'# prometheus_client not installed\n'

# ============ Metrics Definitions ============

if PROMETHEUS_AVAILABLE:
    # Scan counters
    SCAN_TOTAL = Counter(
        'techscan_scans_total',
        'Total number of scans performed',
        ['mode', 'status']  # mode: single/bulk, status: success/error
    )
    
    # Scan duration histogram
    SCAN_DURATION = Histogram(
        'techscan_scan_duration_seconds',
        'Time spent processing scans',
        ['mode'],
        buckets=[0.5, 1, 2, 5, 10, 20, 30, 60, 120]
    )
    
    # Technologies detected gauge
    TECH_COUNT = Gauge(
        'techscan_technologies_detected',
        'Number of technologies detected in last scan',
        ['domain']
    )
    
    # Active scans gauge
    ACTIVE_SCANS = Gauge(
        'techscan_active_scans',
        'Number of currently running scans'
    )
    
    # Error counter by type
    ERRORS_TOTAL = Counter(
        'techscan_errors_total',
        'Total number of errors',
        ['error_type']  # timeout, connection, validation, etc.
    )
    
    # Database metrics
    DB_CONNECTIONS = Gauge(
        'techscan_db_connections_active',
        'Number of active database connections'
    )
    
    # Cache metrics
    CACHE_HITS = Counter(
        'techscan_cache_hits_total',
        'Cache hit count'
    )
    CACHE_MISSES = Counter(
        'techscan_cache_misses_total',
        'Cache miss count'
    )

else:
    # Stub classes when prometheus_client not available
    class StubMetric:
        def labels(self, *args, **kwargs): return self
        def inc(self, v=1): pass
        def dec(self, v=1): pass
        def set(self, v): pass
        def observe(self, v): pass
    
    SCAN_TOTAL = StubMetric()
    SCAN_DURATION = StubMetric()
    TECH_COUNT = StubMetric()
    ACTIVE_SCANS = StubMetric()
    ERRORS_TOTAL = StubMetric()
    DB_CONNECTIONS = StubMetric()
    CACHE_HITS = StubMetric()
    CACHE_MISSES = StubMetric()


# ============ Helper Functions ============

def record_scan(mode: str, status: str, duration: float, tech_count: int = 0, domain: str = ''):
    """Record scan metrics.
    
    Args:
        mode: 'single' or 'bulk'
        status: 'success' or 'error'
        duration: Scan duration in seconds
        tech_count: Number of technologies detected
        domain: Domain that was scanned
    """
    SCAN_TOTAL.labels(mode=mode, status=status).inc()
    SCAN_DURATION.labels(mode=mode).observe(duration)
    if tech_count > 0 and domain:
        TECH_COUNT.labels(domain=domain).set(tech_count)


def record_error(error_type: str):
    """Record error by type.
    
    Args:
        error_type: Type of error (timeout, connection, validation, ssrf, etc.)
    """
    ERRORS_TOTAL.labels(error_type=error_type).inc()


def track_active_scan():
    """Context manager to track active scan count."""
    class ScanTracker:
        def __enter__(self):
            ACTIVE_SCANS.inc()
            self.start_time = time.time()
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            ACTIVE_SCANS.dec()
            return False
        
        @property
        def duration(self):
            return time.time() - self.start_time
    
    return ScanTracker()


def get_metrics():
    """Get current metrics in Prometheus format.
    
    Returns:
        bytes: Prometheus-formatted metrics
    """
    return generate_latest()


def get_content_type():
    """Get Prometheus content type header value."""
    return CONTENT_TYPE_LATEST
