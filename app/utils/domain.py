import re
import socket
import os
from ..scanners.state import _dns_negative, _dns_add_negative

# Precompiled regex for performance
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
# RegEx for IPv4 to block direct IP usage (enforced by policy)
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def extract_host(value: str) -> str:
    """Normalize input that may be a full URL (with scheme/path) into just the hostname.
    - Strips protocol (http/https)
    - Removes credentials, port, path, query, fragment
    - Lowercases result
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


def validate_domain(raw: str) -> str:
    """Return a normalized domain or raise ValueError.

    Security validations:
    - Lowercase and strip whitespace
    - Strip trailing dot
    - IDNA (punycode) encode/decode round trip for validation
    - Reject if regex mismatch
    - Block private/internal hostnames (SSRF protection)
    - Enforce maximum length
    - Reject dangerous characters
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
    blocked_patterns = [
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
    for pattern in blocked_patterns:
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


def preflight(domain: str) -> bool:
    """Fast TCP connect preflight to 443 (or 80 fallback) to short-circuit obviously dead domains.
    Controlled by TECHSCAN_PREFLIGHT=1. Returns True if reachable, False if definitely unreachable.
    If DNS fails, adds to negative cache.
    """
    if os.environ.get("TECHSCAN_PREFLIGHT", "0") != "1":
        return True
    if _dns_negative(domain):
        return False
    # Try resolve
    try:
        addrs = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except Exception:
        _dns_add_negative(domain)
        return False
    targets = []
    for af, st, proto, cname, sa in addrs:
        targets.append((sa[0], 443))
    # Add port 80 as fallback to a subset
    if not targets:
        return False
    ok = False
    for ip, port in targets[:2]:  # limit attempts
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            s.close()
            ok = True
            break
        except Exception:
            continue
    if not ok:
        # Try port 80 quickly
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((targets[0][0], 80))
            s.close()
            ok = True
        except Exception:
            pass
    if not ok:
        # Add to negative if all attempts failed
        _dns_add_negative(domain)
    return ok
