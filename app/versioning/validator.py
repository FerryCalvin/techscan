"""Version validation utilities.

Validates extracted versions against expected formats.
"""

import re
from typing import Optional, Tuple


# Semver pattern: major.minor.patch (optional patch)
SEMVER_PATTERN = re.compile(r'^(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].*)?$')


def is_valid_semver(version: str) -> bool:
    """Check if version matches semantic versioning format."""
    return bool(SEMVER_PATTERN.match(version))


def parse_semver(version: str) -> Optional[Tuple[int, int, int]]:
    """Parse version string to (major, minor, patch) tuple.
    
    Returns None if invalid format.
    """
    match = SEMVER_PATTERN.match(version)
    if not match:
        return None
    
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0
    
    return (major, minor, patch)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.
    
    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    p1 = parse_semver(v1)
    p2 = parse_semver(v2)
    
    if p1 is None or p2 is None:
        # Fallback to string comparison
        return 0 if v1 == v2 else (1 if v1 > v2 else -1)
    
    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


def is_plausible_version(version: str, tech_name: str = '') -> bool:
    """Check if version is plausible (not obviously incorrect).
    
    Filters out:
    - Timestamp-like values (1768368369)
    - Obviously wrong versions (100.0.0)
    - Empty or null values
    
    This is a hook point for future ML verification.
    """
    if not version:
        return False
    
    # Filter timestamps (10+ digit numbers)
    if re.match(r'^\d{10,}$', version):
        return False
    
    # Parse version
    parsed = parse_semver(version)
    if not parsed:
        # Allow some non-semver formats like "GA4"
        return len(version) <= 10
    
    major, minor, patch = parsed
    
    # Major version sanity check (most libs are < 100)
    if major > 50:
        return False
    
    return True


def normalize_version(version: str) -> str:
    """Normalize version string format.
    
    Examples:
        "v1.2.3" -> "1.2.3"
        "1.2" -> "1.2.0"
    """
    if not version:
        return ''
    
    # Remove leading 'v'
    version = version.lstrip('vV')
    
    # Add missing patch version
    if re.match(r'^\d+\.\d+$', version):
        version = version + '.0'
    
    return version
