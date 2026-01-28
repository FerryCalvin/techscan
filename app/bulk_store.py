"""In-memory bulk scan batch store.
Stores recent bulk scan result lists so CSV export or follow-up fetch does not trigger re-scan.
Not intended for long-term persistence. Controlled by TECHSCAN_BULK_BATCH_MAX and TECHSCAN_BULK_BATCH_TTL.
"""

from __future__ import annotations
import threading
import time
import uuid
import os
from typing import Dict, Any, List, Optional

_lock = threading.Lock()
_batches: Dict[str, Dict[str, Any]] = {}


def _prune_locked(now: float):
    # TTL based prune
    try:
        ttl = int(os.environ.get("TECHSCAN_BULK_BATCH_TTL", "1800"))  # 30m default
    except ValueError:
        ttl = 1800
    if ttl > 0:
        to_del = [bid for bid, meta in _batches.items() if now - meta["ts"] > ttl]
        for bid in to_del:
            _batches.pop(bid, None)
    # Max count prune
    try:
        max_batches = int(os.environ.get("TECHSCAN_BULK_BATCH_MAX", "50"))
    except ValueError:
        max_batches = 50
    if max_batches > 0 and len(_batches) > max_batches:
        # remove oldest beyond limit
        ordered = sorted(_batches.items(), key=lambda x: x[1]["ts"])
        excess = len(_batches) - max_batches
        for bid, _ in ordered[:excess]:
            _batches.pop(bid, None)


def save_batch(results: List[Dict[str, Any]], domains: List[str]) -> str:
    now = time.time()
    batch_id = uuid.uuid4().hex[:16]
    with _lock:
        _prune_locked(now)
        _batches[batch_id] = {"ts": now, "results": results, "domains": list(domains)}
    return batch_id


def store_batch(batch_id: str, results: List[Dict[str, Any]], extra_meta: Dict[str, Any] = None) -> None:
    """Store a batch with a specific ID (e.g. from RQ job)."""
    now = time.time()
    with _lock:
        _prune_locked(now)
        _batches[batch_id] = {
            "ts": now,
            "results": results,
            "domains": [r["domain"] for r in results if r.get("domain")],
            **(extra_meta or {}),
        }


def get_batch(batch_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        meta = _batches.get(batch_id)
        if not meta:
            return None
        # Touch access time? (not required now)
        return meta


def clear_all():  # for tests
    with _lock:
        _batches.clear()
