"""API Key management for rate limiting.

Provides functions for creating, validating, and managing API keys
with custom rate limits per key.
"""

import os
import secrets
import hashlib
import logging
from typing import Optional, Dict, Any
from flask import request

# ============ API Key Generation ============

def generate_api_key() -> str:
    """Generate a new API key.
    
    Returns:
        A 32-character hex string prefixed with 'ts_'
    """
    return f"ts_{secrets.token_hex(16)}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage.
    
    Args:
        api_key: The raw API key
    
    Returns:
        SHA256 hash of the key
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


# ============ Database Operations ============

def create_api_key(name: str, rate_limit: str = "1000 per hour") -> Optional[Dict[str, Any]]:
    """Create a new API key.
    
    Args:
        name: Descriptive name for the key
        rate_limit: Rate limit string (e.g., "100 per minute")
    
    Returns:
        Dict with key details including the raw key (only time it's visible)
    """
    from . import db as _db
    
    if _db._DB_DISABLED:
        return None
    
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    INSERT INTO api_keys (key_hash, name, rate_limit)
                    VALUES (%s, %s, %s)
                    RETURNING id, created_at
                ''', (key_hash, name, rate_limit))
                row = cur.fetchone()
                conn.commit()
                
                return {
                    'id': row[0],
                    'api_key': raw_key,  # Only time the raw key is returned!
                    'name': name,
                    'rate_limit': rate_limit,
                    'created_at': row[1].isoformat() if row[1] else None
                }
    except Exception as e:
        logging.getLogger('techscan.api_keys').error('create_api_key failed: %s', e)
        return None


def validate_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Validate an API key and return its details.
    
    Args:
        api_key: The raw API key to validate
    
    Returns:
        Dict with key details if valid, None otherwise
    """
    from . import db as _db
    
    if _db._DB_DISABLED or not api_key:
        return None
    
    key_hash = hash_api_key(api_key)
    
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    SELECT id, name, rate_limit, is_active, created_at, request_count
                    FROM api_keys WHERE key_hash = %s
                ''', (key_hash,))
                row = cur.fetchone()
                
                if row and row[3]:  # is_active
                    # Update last_used and request_count
                    cur.execute('''
                        UPDATE api_keys 
                        SET last_used_at = NOW(), request_count = request_count + 1
                        WHERE key_hash = %s
                    ''', (key_hash,))
                    conn.commit()
                    
                    return {
                        'id': row[0],
                        'name': row[1],
                        'rate_limit': row[2],
                        'is_active': row[3],
                        'created_at': row[4].isoformat() if row[4] else None,
                        'request_count': row[5]
                    }
    except Exception as e:
        logging.getLogger('techscan.api_keys').debug('validate_api_key error: %s', e)
    
    return None


def list_api_keys() -> list:
    """List all API keys (without the actual keys).
    
    Returns:
        List of API key records
    """
    from . import db as _db
    
    if _db._DB_DISABLED:
        return []
    
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    SELECT id, name, rate_limit, is_active, created_at, last_used_at, request_count
                    FROM api_keys ORDER BY created_at DESC
                ''')
                rows = cur.fetchall()
                return [{
                    'id': r[0],
                    'name': r[1],
                    'rate_limit': r[2],
                    'is_active': r[3],
                    'created_at': r[4].isoformat() if r[4] else None,
                    'last_used_at': r[5].isoformat() if r[5] else None,
                    'request_count': r[6]
                } for r in rows]
    except Exception as e:
        logging.getLogger('techscan.api_keys').error('list_api_keys failed: %s', e)
    
    return []


def revoke_api_key(key_id: int) -> bool:
    """Revoke an API key by ID.
    
    Args:
        key_id: The database ID of the key to revoke
    
    Returns:
        True if successful
    """
    from . import db as _db
    
    if _db._DB_DISABLED:
        return False
    
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE api_keys SET is_active = FALSE WHERE id = %s', (key_id,))
                conn.commit()
                return cur.rowcount > 0
    except Exception as e:
        logging.getLogger('techscan.api_keys').error('revoke_api_key failed: %s', e)
    
    return False


def delete_api_key(key_id: int) -> bool:
    """Permanently delete an API key.
    
    Args:
        key_id: The database ID of the key to delete
    
    Returns:
        True if successful
    """
    from . import db as _db
    
    if _db._DB_DISABLED:
        return False
    
    try:
        with _db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM api_keys WHERE id = %s', (key_id,))
                conn.commit()
                return cur.rowcount > 0
    except Exception as e:
        logging.getLogger('techscan.api_keys').error('delete_api_key failed: %s', e)
    
    return False


# ============ Rate Limiter Integration ============

# Cache for API key lookups to reduce DB hits
_KEY_CACHE: Dict[str, Dict[str, Any]] = {}
_KEY_CACHE_TTL = 60  # seconds

def get_rate_limit_key() -> str:
    """Custom key function for Flask-Limiter.
    
    Checks for API key in header or query param.
    Returns API key hash if valid, otherwise falls back to IP.
    
    Usage in limiter:
        limiter = Limiter(key_func=get_rate_limit_key)
    """
    # Check for API key in request
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    
    if api_key and os.environ.get('TECHSCAN_API_KEY_ENABLED', '0') == '1':
        # Validate and get rate limit
        key_info = validate_api_key(api_key)
        if key_info:
            # Store rate limit info for later use
            request.api_key_info = key_info  # type: ignore
            return f"apikey:{hash_api_key(api_key)[:16]}"
    
    # Fallback to IP-based limiting
    from flask_limiter.util import get_remote_address
    return get_remote_address()


def get_dynamic_rate_limit() -> str:
    """Get rate limit for current request based on API key.
    
    Returns the rate limit string for the current request,
    using API key's limit if available, otherwise default.
    """
    default_limit = os.environ.get('TECHSCAN_RATE_LIMIT', '60 per minute')
    
    # Check if request has API key info attached
    key_info = getattr(request, 'api_key_info', None)
    if key_info and key_info.get('rate_limit'):
        return key_info['rate_limit']
    
    return default_limit
