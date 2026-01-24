"""Version Detection Module.

Multi-signal version detection system that doesn't rely on Wappalyzer.
Designed with extensibility for future ML verification (Option 3).

Architecture:
- patterns.py: Version detection patterns database
- extractor.py: Main extraction logic
- validator.py: Version format validation
- signals.py: Individual signal detectors
"""

from .extractor import VersionExtractor, extract_versions
from .patterns import VERSION_PATTERNS

__all__ = ['VersionExtractor', 'extract_versions', 'VERSION_PATTERNS']
