"""Statistics and metrics for TechScan scanning.

This module provides:
- Global STATS dictionary for tracking scan metrics
- get_stats() function for current statistics
- synthetic_header_detection() for lightweight header analysis
"""

import re
import time
import http.client
import threading
from collections import deque
from typing import Dict, Any, List

# ============ Global Stats ============

_stats_lock = threading.Lock()

STATS: Dict[str, Any] = {
    "start_time": time.time(),
    "hits": 0,
    "misses": 0,
    "mode_hits": {"fast": 0, "full": 0, "fast_full": 0},
    "mode_misses": {"fast": 0, "full": 0, "fast_full": 0},
    "scans": 0,
    "cache_entries": 0,
    "synthetic": {"headers": 0, "tailwind": 0, "floodlight": 0},
    "durations": {
        "fast": {"count": 0, "total": 0.0},
        "full": {"count": 0, "total": 0.0},
        "fast_full": {"count": 0, "total": 0.0},
    },
    "errors": {"timeout": 0, "dns": 0, "ssl": 0, "conn": 0, "quarantine": 0, "preflight": 0, "other": 0},
    "recent_samples": {"fast": deque(maxlen=200), "full": deque(maxlen=200), "fast_full": deque(maxlen=200)},
    "phases": {
        "sniff_ms": 0,
        "sniff_count": 0,
        "engine_ms": 0,
        "engine_count": 0,
        "synthetic_ms": 0,
        "synthetic_count": 0,
        "version_audit_ms": 0,
        "version_audit_count": 0,
    },
    "totals": {"scan_count": 0, "total_overall_ms": 0},
    # Single-flight (duplicate in-flight suppression) metrics
    "single_flight": {
        "hits": 0,  # followers that avoided starting a duplicate scan
        "wait_ms": 0,  # cumulative wait time of followers
        "inflight": 0,  # current number of active leader scans
    },
    # Enrichment metrics
    "enrichment": {"hints_total": 0, "scans": 0, "last_avg_conf": 0.0, "merge_total": 0, "last_update": 0},
}


def get_stats_lock() -> threading.Lock:
    """Get the stats lock for external modules."""
    return _stats_lock


def get_stats() -> Dict[str, Any]:
    """Get current scan statistics.

    Returns:
        Dict with uptime, cache stats, duration averages, errors, etc.
    """
    now = time.time()
    with _stats_lock:
        # compute averages
        def avg(bucket):
            return (bucket["total"] / bucket["count"]) if bucket["count"] else 0.0

        fast_avg = avg(STATS["durations"]["fast"])
        full_avg = avg(STATS["durations"]["full"])
        fast_full_avg = avg(STATS["durations"].get("fast_full", {"count": 0, "total": 0}))

        def percentiles(data: deque, p: float) -> float:
            if not data:
                return 0.0
            arr = sorted(data)
            k = int(round((p / 100.0) * (len(arr) - 1)))
            k = max(0, min(len(arr) - 1, k))
            return arr[k]

        fast_samples = STATS["recent_samples"]["fast"]
        full_samples = STATS["recent_samples"]["full"]
        fast_full_samples = STATS["recent_samples"].get("fast_full", deque())

        return {
            "uptime_seconds": round(now - STATS["start_time"], 2),
            "hits": STATS["hits"],
            "misses": STATS["misses"],
            "mode_hits": STATS["mode_hits"],
            "mode_misses": STATS["mode_misses"],
            "scans": STATS["scans"],
            "cache_entries": STATS["cache_entries"],
            "average_duration_ms": {
                "fast": round(fast_avg * 1000, 2),
                "fast_full": round(fast_full_avg * 1000, 2),
                "full": round(full_avg * 1000, 2),
            },
            "recent_latency_ms": {
                "fast": {
                    "samples": len(fast_samples),
                    "p50": round(percentiles(fast_samples, 50) * 1000, 2),
                    "p95": round(percentiles(fast_samples, 95) * 1000, 2),
                },
                "fast_full": {
                    "samples": len(fast_full_samples),
                    "p50": round(percentiles(fast_full_samples, 50) * 1000, 2),
                    "p95": round(percentiles(fast_full_samples, 95) * 1000, 2),
                },
                "full": {
                    "samples": len(full_samples),
                    "p50": round(percentiles(full_samples, 50) * 1000, 2),
                    "p95": round(percentiles(full_samples, 95) * 1000, 2),
                },
            },
            "synthetic": STATS["synthetic"],
            "errors": STATS.get("errors", {}),
            "single_flight": STATS.get("single_flight", {}),
        }


# ============ Synthetic Header Detection ============


def synthetic_header_detection(domain: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Lightweight HEAD request to extract server and security headers.

    Attempts HTTPS first, falls back to HTTP.

    Args:
        domain: Domain to check
        timeout: Total timeout in seconds

    Returns:
        List of technology dicts with evidence
    """
    out: List[Dict[str, Any]] = []
    deadline = time.time() + timeout

    def remaining():
        return max(0.5, deadline - time.time())

    for scheme in ["https", "http"]:
        if time.time() >= deadline:
            break
        try:
            conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(domain, timeout=remaining())
            conn.request("HEAD", "/", headers={"User-Agent": "TechScan/1.0"})
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}

            # Parse Server header
            server = headers.get("server")
            if server:
                m = re.match(r"([a-zA-Z0-9_-]+)(?:/(\d[\w\.-]*))?", server)
                if m:
                    name = m.group(1)
                    ver = m.group(2)
                    lname = name.lower()
                    if lname == "nginx":
                        out.append(
                            {
                                "name": "Nginx",
                                "version": ver,
                                "categories": ["Web servers", "Reverse proxies"],
                                "confidence": 40,
                                "evidence": [{"type": "header", "name": "server", "value": server}],
                            }
                        )
                    elif lname in ("apache", "httpd"):
                        out.append(
                            {
                                "name": "Apache",
                                "version": ver,
                                "categories": ["Web servers"],
                                "confidence": 40,
                                "evidence": [{"type": "header", "name": "server", "value": server}],
                            }
                        )
                    elif lname == "cloudflare":
                        out.append(
                            {
                                "name": "Cloudflare",
                                "version": ver,
                                "categories": ["Reverse proxies", "CDN"],
                                "confidence": 30,
                                "evidence": [{"type": "header", "name": "server", "value": server}],
                            }
                        )

            # HSTS header
            if "strict-transport-security" in headers:
                out.append(
                    {
                        "name": "HSTS",
                        "version": None,
                        "categories": ["Security"],
                        "confidence": 30,
                        "evidence": [
                            {
                                "type": "header",
                                "name": "strict-transport-security",
                                "value": headers.get("strict-transport-security"),
                            }
                        ],
                    }
                )

            # X-Powered-By header
            xpb = headers.get("x-powered-by")
            if xpb:
                try:
                    xb = xpb.lower()
                    if "php" in xb and not any(o["name"] == "PHP" for o in out):
                        out.append(
                            {
                                "name": "PHP",
                                "version": None,
                                "categories": ["Programming languages"],
                                "confidence": 40,
                                "evidence": [{"type": "header", "name": "x-powered-by", "value": xpb}],
                            }
                        )
                except Exception:
                    pass

            conn.close()
        except Exception:
            continue

        # Stop after first success
        if out:
            break

    return out


# ============ Stats Update Helpers ============


def increment_stat(key: str, amount: int = 1):
    """Increment a top-level stat counter."""
    with _stats_lock:
        if key in STATS:
            STATS[key] += amount


def increment_nested_stat(key1: str, key2: str, amount: int = 1):
    """Increment a nested stat counter."""
    with _stats_lock:
        if key1 in STATS and key2 in STATS[key1]:
            STATS[key1][key2] += amount


def record_duration(mode: str, duration: float):
    """Record a scan duration for averaging."""
    with _stats_lock:
        if mode in STATS["durations"]:
            STATS["durations"][mode]["count"] += 1
            STATS["durations"][mode]["total"] += duration
        if mode in STATS["recent_samples"]:
            STATS["recent_samples"][mode].append(duration)


# ============ Exports ============

__all__ = [
    "STATS",
    "_stats_lock",
    "get_stats_lock",
    "get_stats",
    "synthetic_header_detection",
    "increment_stat",
    "increment_nested_stat",
    "record_duration",
]
