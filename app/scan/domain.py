"""Domain validation and extraction utilities.

This module provides functions for:
- Domain/URL parsing and normalization
- Domain validation with security checks (SSRF protection)
- Technology name canonicalization
"""

import re
from typing import Optional

# ============ Regex Patterns ============

# Domain validation pattern
DOMAIN_RE = re.compile(r"^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")

# IPv4 address pattern (for SSRF blocking)
IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# ============ Tech Name Normalization ============

TECH_NAME_REWRITES = {"WPML": "WordPress Multilingual Plugin (WPML)", "Hello Elementor": "Hello Elementor Theme"}


def canonicalize_tech_name(name: Optional[str]) -> Optional[str]:
    """Normalize technology name using rewrite rules.

    Args:
        name: Raw technology name

    Returns:
        Canonical name or original if no rewrite exists
    """
    if not name:
        return name
    return TECH_NAME_REWRITES.get(name, name)


# ============ URL/Host Extraction ============


def extract_host(value: str) -> str:
    """Normalize input that may be a full URL into just the hostname.

    - Strips protocol (http/https)
    - Removes credentials, port, path, query, fragment
    - Lowercases result

    Args:
        value: URL or domain string

    Returns:
        Normalized hostname (lowercase)
    """
    v = (value or "").strip()
    if not v:
        return v
    # Add scheme if starts with //
    if v.startswith("//"):
        v = "http:" + v
    if "://" in v:
        # Split off scheme
        v2 = v.split("://", 1)[1]
    else:
        v2 = v
    # Remove path/query/fragment
    for sep in ["/", "?", "#"]:
        if sep in v2:
            v2 = v2.split(sep, 1)[0]
    # Remove credentials
    if "@" in v2:
        v2 = v2.split("@", 1)[1]
    # Remove port
    if ":" in v2:
        host_part = v2.split(":", 1)[0]
    else:
        host_part = v2
    return host_part.lower()


def extract_url_with_path(value: str) -> str:
    """Normalize URL but KEEP the path for unique endpoint identification.

    - Strips protocol (http/https)
    - Removes credentials, port, query, fragment
    - Keeps path (for fkg.unair.ac.id/blog vs fkg.unair.ac.id/shop)
    - Lowercases result
    - Removes trailing slash

    Args:
        value: URL string

    Returns:
        Normalized URL with path (lowercase)
    """
    v = (value or "").strip()
    if not v:
        return v
    # Add scheme if starts with //
    if v.startswith("//"):
        v = "http:" + v
    if "://" in v:
        # Split off scheme
        v2 = v.split("://", 1)[1]
    else:
        v2 = v
    # Remove query/fragment but KEEP path
    for sep in ["?", "#"]:
        if sep in v2:
            v2 = v2.split(sep, 1)[0]
    # Remove credentials
    if "@" in v2:
        v2 = v2.split("@", 1)[1]
    # Handle port: extract host:port and path separately
    if "/" in v2:
        host_port, path = v2.split("/", 1)
        path = "/" + path
    else:
        host_port = v2
        path = ""
    # Remove port from host
    if ":" in host_port:
        host_part = host_port.split(":", 1)[0]
    else:
        host_part = host_port
    # Combine and normalize
    result = (host_part + path).lower().rstrip("/")
    return result


# ============ Domain Validation ============

# Blocked patterns for SSRF protection
BLOCKED_PATTERNS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "169.254.",  # Link-local
    "fc00:",  # IPv6 private
    "fe80:",  # IPv6 link-local
    ".internal",
    ".local",
    ".localdomain",
    ".localhost",
]


def validate_domain(raw: str) -> str:
    """Validate and normalize a domain name.

    Security validations:
    - Lowercase and strip whitespace
    - Strip trailing dot
    - IDNA (punycode) encode/decode round trip
    - Block private/internal hostnames (SSRF protection)
    - Enforce maximum length (253 chars)
    - Reject dangerous characters

    Args:
        raw: Raw domain input

    Returns:
        Normalized, validated domain

    Raises:
        ValueError: If domain is invalid or blocked
    """
    d = (raw or "").strip().lower().rstrip(".")
    if not d:
        raise ValueError("empty domain")

    # Length check (prevent buffer overflow / DoS)
    if len(d) > 253:
        raise ValueError("domain too long (max 253 chars)")

    # Check for dangerous characters that could be used for injection
    dangerous_chars = ["<", ">", '"', "'", "\\", "\n", "\r", "\t", "\x00"]
    for c in dangerous_chars:
        if c in d:
            raise ValueError("domain contains invalid characters")

    # Block internal/private hostnames (SSRF protection)
    for pattern in BLOCKED_PATTERNS:
        if d.startswith(pattern) or d.endswith(pattern) or d == pattern.rstrip("."):
            raise ValueError("domain appears to be internal/private (SSRF blocked)")

    # Block pure IP addresses (should use domain names)
    if IPV4_RE.match(d):
        raise ValueError("IP addresses not allowed, use domain names")

    # Basic fast path
    if DOMAIN_RE.match(d):
        return d

    # Try IDNA (unicode domains)
    try:
        ascii_d = d.encode("idna").decode("ascii")
    except Exception:
        raise ValueError("invalid domain")

    if not DOMAIN_RE.match(ascii_d):
        raise ValueError("invalid domain")

    return ascii_d


# ============ Exports ============

__all__ = [
    "DOMAIN_RE",
    "IPV4_RE",
    "TECH_NAME_REWRITES",
    "BLOCKED_PATTERNS",
    "canonicalize_tech_name",
    "extract_host",
    "extract_url_with_path",
    "validate_domain",
]
