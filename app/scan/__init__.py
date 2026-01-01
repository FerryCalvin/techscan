"""TechScan Scanning Package.

This package contains modular components for web technology scanning.
The main scan_utils.py acts as a facade for backward compatibility.

Modules:
- domain: Domain validation and extraction utilities
- network: DNS, preflight, quarantine, single-flight guards
- normalize: Result normalization, tech canonicalization
- cache: In-memory scan result caching
- single: Single domain scanning (scan_domain, scan_unified)
- bulk: Bulk domain scanning
- modes: Quick/deep/fast-full scan modes
- stats: Statistics and metrics
"""

# Version info
__version__ = '1.0.0'

# Re-export domain utilities
from .domain import (
    DOMAIN_RE,
    IPV4_RE,
    TECH_NAME_REWRITES,
    BLOCKED_PATTERNS,
    canonicalize_tech_name,
    extract_host,
    extract_url_with_path,
    validate_domain,
)

__all__ = [
    # domain.py exports
    'DOMAIN_RE',
    'IPV4_RE',
    'TECH_NAME_REWRITES',
    'BLOCKED_PATTERNS',
    'canonicalize_tech_name',
    'extract_host',
    'extract_url_with_path',
    'validate_domain',
    # network.py exports
    'single_flight_enter',
    'single_flight_exit',
    'dns_negative',
    'dns_add_negative',
    'preflight',
    'record_failure',
    'check_quarantine',
    'record_success',
    'classify_error',
    'persist_failure_scan',
]

# Re-export network utilities
from .network import (
    single_flight_enter,
    single_flight_exit,
    dns_negative,
    dns_add_negative,
    preflight,
    record_failure,
    check_quarantine,
    record_success,
    classify_error,
    persist_failure_scan,
)


