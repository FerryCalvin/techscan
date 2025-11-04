import time
from typing import Any, Optional

# Simple process-local TTL cache. If REDIS_URL is configured we could
# wire Redis instead, but keep a lightweight default for tests and
# single-process deployments.
_CACHE: dict = {}


def get(key: str) -> Optional[Any]:
    ent = _CACHE.get(key)
    if not ent:
        return None
    val, expires = ent
    if expires and time.time() > expires:
        _CACHE.pop(key, None)
        return None
    return val


def set(key: str, value: Any, ttl: int = 60) -> None:
    expires = time.time() + ttl if ttl and ttl > 0 else None
    _CACHE[key] = (value, expires)


def invalidate(prefix: str) -> None:
    # invalidate all keys that start with prefix
    for k in list(_CACHE.keys()):
        if k.startswith(prefix):
            _CACHE.pop(k, None)

import time
from typing import Any, Dict, Optional

# Simple in-process TTL cache used for tech aggregates. If REDIS_URL provided,
# prefer Redis (not implemented here to keep dependency minimal); this helper
# provides a basic interface used by the tech endpoints.
_CACHE: Dict[str, Dict[str, Any]] = {}

def get(key: str) -> Optional[Any]:
    rec = _CACHE.get(key)
    if not rec:
        return None
    if rec['expires_at'] < time.time():
        _CACHE.pop(key, None)
        return None
    return rec['value']

def set(key: str, value: Any, ttl: int = 60) -> None:
    _CACHE[key] = {'value': value, 'expires_at': time.time() + ttl}

def invalidate(prefix: str) -> None:
    # remove keys starting with prefix
    for k in list(_CACHE.keys()):
        if k.startswith(prefix):
            _CACHE.pop(k, None)
import time
import os
try:
    import redis
except Exception:
    redis = None

_LOCAL_CACHE = {}
_LOCAL_TTL = int(os.environ.get('TECHSCAN_TECH_CACHE_TTL', '120'))

def _now():
    return int(time.time())

def get(key):
    # Try Redis if configured
    if redis and os.environ.get('TECHSCAN_REDIS_URL'):
        try:
            r = redis.from_url(os.environ.get('TECHSCAN_REDIS_URL'))
            val = r.get(key)
            if val is None:
                return None
            return val.decode('utf-8')
        except Exception:
            pass
    # Local in-memory
    ent = _LOCAL_CACHE.get(key)
    if not ent:
        return None
    val, ts, ttl = ent
    if _now() - ts > ttl:
        _LOCAL_CACHE.pop(key, None)
        return None
    return val

def set(key, value, ttl=None):
    if ttl is None:
        ttl = _LOCAL_TTL
    if redis and os.environ.get('TECHSCAN_REDIS_URL'):
        try:
            r = redis.from_url(os.environ.get('TECHSCAN_REDIS_URL'))
            r.setex(key, ttl, value)
            return
        except Exception:
            pass
    _LOCAL_CACHE[key] = (value, _now(), ttl)

def invalidate(prefix):
    # prefix-based invalidation for local cache
    keys = [k for k in list(_LOCAL_CACHE.keys()) if k.startswith(prefix)]
    for k in keys:
        _LOCAL_CACHE.pop(k, None)
    # Redis pattern invalidation (best-effort)
    if redis and os.environ.get('TECHSCAN_REDIS_URL'):
        try:
            r = redis.from_url(os.environ.get('TECHSCAN_REDIS_URL'))
            for k in r.scan_iter(match=prefix + '*'):
                r.delete(k)
        except Exception:
            pass
