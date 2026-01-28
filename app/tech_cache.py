import os
import time

try:
    import redis
except Exception:
    redis = None

_LOCAL_CACHE = {}
_LOCAL_TTL = int(os.environ.get("TECHSCAN_TECH_CACHE_TTL", "120"))


def _now():
    return int(time.time())


def get(key):
    # Try Redis if configured
    if redis and os.environ.get("TECHSCAN_REDIS_URL"):
        try:
            r = redis.from_url(os.environ.get("TECHSCAN_REDIS_URL"))
            val = r.get(key)
            if val is None:
                return None
            return val.decode("utf-8")
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
    if redis and os.environ.get("TECHSCAN_REDIS_URL"):
        try:
            r = redis.from_url(os.environ.get("TECHSCAN_REDIS_URL"))
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
    if redis and os.environ.get("TECHSCAN_REDIS_URL"):
        try:
            r = redis.from_url(os.environ.get("TECHSCAN_REDIS_URL"))
            for k in r.scan_iter(match=prefix + "*"):
                r.delete(k)
        except Exception:
            pass
