"""Redis caching layer for TechScan.

Provides caching for scan results to reduce redundant scanning.
Falls back gracefully when Redis is not available.
"""

import os
import json
import logging
import time
from typing import Optional, Dict, Any

# Try to import redis, provide stub if not available
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None  # type: ignore

# ============ Configuration ============

_REDIS_CLIENT: Optional[Any] = None
_CACHE_ENABLED = False

# Default TTL for scan results (1 hour)
DEFAULT_TTL = 3600


def init_cache() -> bool:
    """Initialize Redis cache connection.
    
    Returns:
        True if cache is available and enabled
    """
    global _REDIS_CLIENT, _CACHE_ENABLED
    
    if not REDIS_AVAILABLE:
        logging.getLogger('techscan.cache').debug('Redis not installed, cache disabled')
        return False
    
    if os.environ.get('TECHSCAN_CACHE_ENABLED', '0') != '1':
        logging.getLogger('techscan.cache').debug('Cache disabled (TECHSCAN_CACHE_ENABLED != 1)')
        return False
    
    redis_url = os.environ.get('TECHSCAN_REDIS_URL')
    if not redis_url:
        logging.getLogger('techscan.cache').debug('No TECHSCAN_REDIS_URL configured')
        return False
    
    try:
        _REDIS_CLIENT = redis.from_url(redis_url, decode_responses=True)
        # Test connection
        _REDIS_CLIENT.ping()
        _CACHE_ENABLED = True
        logging.getLogger('techscan.cache').info('Redis cache initialized')
        return True
    except Exception as e:
        logging.getLogger('techscan.cache').warning('Redis connection failed: %s', e)
        _CACHE_ENABLED = False
        return False


def is_enabled() -> bool:
    """Check if cache is enabled and connected."""
    return _CACHE_ENABLED and _REDIS_CLIENT is not None


# ============ Cache Keys ============

def _scan_key(domain: str, mode: str = 'default') -> str:
    """Generate cache key for scan result."""
    return f"techscan:scan:{mode}:{domain.lower()}"


def _tech_key(domain: str) -> str:
    """Generate cache key for technology list."""
    return f"techscan:tech:{domain.lower()}"


# ============ Scan Cache Operations ============

def get_cached_scan(domain: str, mode: str = 'default') -> Optional[Dict[str, Any]]:
    """Get cached scan result for domain.
    
    Args:
        domain: Domain that was scanned
        mode: Scan mode (quick, full, deep)
    
    Returns:
        Cached scan result dict or None
    """
    if not is_enabled():
        return None
    
    try:
        key = _scan_key(domain, mode)
        data = _REDIS_CLIENT.get(key)  # type: ignore
        if data:
            result = json.loads(data)
            result['cached'] = True
            result['cache_age'] = time.time() - result.get('cached_at', 0)
            
            # Update metrics
            try:
                from . import metrics
                metrics.CACHE_HITS.inc()
            except Exception:
                pass
            
            logging.getLogger('techscan.cache').debug('cache_hit domain=%s mode=%s', domain, mode)
            return result
    except Exception as e:
        logging.getLogger('techscan.cache').debug('get_cached_scan error: %s', e)
    
    # Update metrics for cache miss
    try:
        from . import metrics
        metrics.CACHE_MISSES.inc()
    except Exception:
        pass
    
    return None


def cache_scan(domain: str, result: Dict[str, Any], mode: str = 'default', ttl: Optional[int] = None) -> bool:
    """Cache scan result for domain.
    
    Args:
        domain: Domain that was scanned
        result: Scan result dict
        mode: Scan mode
        ttl: Cache TTL in seconds (default from env or 3600)
    
    Returns:
        True if cached successfully
    """
    if not is_enabled():
        return False
    
    if ttl is None:
        try:
            ttl = int(os.environ.get('TECHSCAN_CACHE_TTL', str(DEFAULT_TTL)))
        except ValueError:
            ttl = DEFAULT_TTL
    
    try:
        key = _scan_key(domain, mode)
        # Add timestamp for cache age calculation
        result_copy = dict(result)
        result_copy['cached_at'] = time.time()
        
        _REDIS_CLIENT.setex(key, ttl, json.dumps(result_copy, default=str))  # type: ignore
        logging.getLogger('techscan.cache').debug('cache_set domain=%s mode=%s ttl=%d', domain, mode, ttl)
        return True
    except Exception as e:
        logging.getLogger('techscan.cache').debug('cache_scan error: %s', e)
    
    return False


def invalidate_scan(domain: str, mode: Optional[str] = None) -> int:
    """Invalidate cached scan result.
    
    Args:
        domain: Domain to invalidate
        mode: Specific mode to invalidate, or None for all modes
    
    Returns:
        Number of keys deleted
    """
    if not is_enabled():
        return 0
    
    try:
        if mode:
            # Delete specific mode
            key = _scan_key(domain, mode)
            return _REDIS_CLIENT.delete(key)  # type: ignore
        else:
            # Delete all modes for domain
            pattern = f"techscan:scan:*:{domain.lower()}"
            keys = _REDIS_CLIENT.keys(pattern)  # type: ignore
            if keys:
                return _REDIS_CLIENT.delete(*keys)  # type: ignore
    except Exception as e:
        logging.getLogger('techscan.cache').debug('invalidate_scan error: %s', e)
    
    return 0


# ============ Technology Cache ============

def get_cached_technologies(domain: str) -> Optional[list]:
    """Get cached technology list for domain."""
    if not is_enabled():
        return None
    
    try:
        key = _tech_key(domain)
        data = _REDIS_CLIENT.get(key)  # type: ignore
        if data:
            return json.loads(data)
    except Exception as e:
        logging.getLogger('techscan.cache').debug('get_cached_technologies error: %s', e)
    
    return None


def cache_technologies(domain: str, technologies: list, ttl: Optional[int] = None) -> bool:
    """Cache technology list for domain."""
    if not is_enabled():
        return False
    
    if ttl is None:
        try:
            ttl = int(os.environ.get('TECHSCAN_CACHE_TTL', str(DEFAULT_TTL)))
        except ValueError:
            ttl = DEFAULT_TTL
    
    try:
        key = _tech_key(domain)
        _REDIS_CLIENT.setex(key, ttl, json.dumps(technologies, default=str))  # type: ignore
        return True
    except Exception as e:
        logging.getLogger('techscan.cache').debug('cache_technologies error: %s', e)
    
    return False


# ============ Cache Management ============

def flush_all() -> bool:
    """Flush all TechScan cache entries.
    
    Returns:
        True if successful
    """
    if not is_enabled():
        return False
    
    try:
        pattern = "techscan:*"
        keys = _REDIS_CLIENT.keys(pattern)  # type: ignore
        if keys:
            _REDIS_CLIENT.delete(*keys)  # type: ignore
            logging.getLogger('techscan.cache').info('Flushed %d cache entries', len(keys))
        return True
    except Exception as e:
        logging.getLogger('techscan.cache').error('flush_all error: %s', e)
    
    return False


def get_stats() -> Dict[str, Any]:
    """Get cache statistics.
    
    Returns:
        Dict with cache stats
    """
    stats = {
        'enabled': _CACHE_ENABLED,
        'redis_available': REDIS_AVAILABLE,
    }
    
    if is_enabled():
        try:
            info = _REDIS_CLIENT.info('memory')  # type: ignore
            stats['memory_used'] = info.get('used_memory_human', 'unknown')
            
            # Count TechScan keys
            pattern = "techscan:*"
            keys = _REDIS_CLIENT.keys(pattern)  # type: ignore
            stats['key_count'] = len(keys) if keys else 0
        except Exception as e:
            stats['error'] = str(e)
    
    return stats
