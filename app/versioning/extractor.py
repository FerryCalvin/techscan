"""Multi-signal version extractor.

Extracts versions using multiple detection signals:
1. JS Runtime Variables (highest accuracy)
2. URL Pattern Matching
3. Meta Tag Detection
4. HTML Comment Detection

Designed with extensibility for future ML verification (Option 3).
"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from .patterns import VERSION_PATTERNS, get_pattern_for_tech, normalize_tech_key
from .validator import is_plausible_version, normalize_version

logger = logging.getLogger('techscan.versioning')


@dataclass
class VersionResult:
    """Result of version detection for a technology."""
    tech_name: str
    version: Optional[str]
    confidence: float  # 0.0 - 1.0
    source: str  # 'js_var', 'url', 'meta', 'comment', 'wappalyzer_fallback'
    evidence: str  # What matched
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'tech_name': self.tech_name,
            'version': self.version,
            'confidence': self.confidence,
            'source': self.source,
            'evidence': self.evidence,
        }


class VersionExtractor:
    """Multi-signal version extractor.
    
    Usage:
        extractor = VersionExtractor()
        results = extractor.extract_all(html, headers, js_vars, urls)
        
        # Apply to technology list
        updated_techs = extractor.apply_to_technologies(techs, results)
    """
    
    def __init__(self):
        self.patterns = VERSION_PATTERNS
        self._ml_verifier = None  # Hook for future ML verification
    
    def set_ml_verifier(self, verifier):
        """Set ML verifier for Option 3 integration (future).
        
        The verifier should implement:
            verifier.verify(tech_name, version, context) -> (is_valid, confidence)
        """
        self._ml_verifier = verifier
    
    def extract_from_js_vars(
        self, 
        js_vars: Dict[str, Any], 
        tech_key: str
    ) -> Optional[VersionResult]:
        """Extract version from JavaScript runtime variables.
        
        Args:
            js_vars: Dict of {variable_path: value} from browser/node
            tech_key: Technology pattern key
            
        Returns:
            VersionResult or None
        """
        config = self.patterns.get(tech_key)
        if not config:
            return None
        
        for signal in config.get('signals', []):
            if signal.get('type') != 'js_var':
                continue
            
            variable = signal.get('variable', '')
            if variable in js_vars:
                version = str(js_vars[variable])
                version = normalize_version(version)
                
                if is_plausible_version(version, config.get('name', '')):
                    return VersionResult(
                        tech_name=config.get('name', tech_key),
                        version=version,
                        confidence=signal.get('confidence', 1.0),
                        source='js_var',
                        evidence=f"{variable}={version}"
                    )
        
        return None
    
    def extract_from_urls(
        self, 
        urls: List[str], 
        tech_key: str
    ) -> Optional[VersionResult]:
        """Extract version from URL patterns.
        
        Args:
            urls: List of URLs (scripts, stylesheets, etc.)
            tech_key: Technology pattern key
            
        Returns:
            VersionResult or None
        """
        config = self.patterns.get(tech_key)
        if not config:
            return None
        
        for signal in config.get('signals', []):
            if signal.get('type') != 'url':
                continue
            
            pattern = signal.get('pattern', '')
            if not pattern:
                continue
            
            regex = re.compile(pattern, re.IGNORECASE)
            
            for url in urls:
                match = regex.search(url)
                if match and match.groups():
                    version = match.group(1)
                    version = normalize_version(version)
                    
                    if is_plausible_version(version, config.get('name', '')):
                        return VersionResult(
                            tech_name=config.get('name', tech_key),
                            version=version,
                            confidence=signal.get('confidence', 0.85),
                            source='url',
                            evidence=url
                        )
        
        return None
    
    def extract_from_meta(
        self, 
        html: str, 
        tech_key: str
    ) -> Optional[VersionResult]:
        """Extract version from meta tags.
        
        Args:
            html: Raw HTML content
            tech_key: Technology pattern key
            
        Returns:
            VersionResult or None
        """
        config = self.patterns.get(tech_key)
        if not config:
            return None
        
        for signal in config.get('signals', []):
            if signal.get('type') != 'meta':
                continue
            
            pattern = signal.get('pattern', '')
            if not pattern:
                continue
            
            regex = re.compile(pattern, re.IGNORECASE)
            match = regex.search(html)
            
            if match and match.groups():
                version = match.group(1)
                version = normalize_version(version)
                
                if is_plausible_version(version, config.get('name', '')):
                    return VersionResult(
                        tech_name=config.get('name', tech_key),
                        version=version,
                        confidence=signal.get('confidence', 0.9),
                        source='meta',
                        evidence=match.group(0)[:100]
                    )
        
        return None
    
    def extract_from_comments(
        self, 
        html: str, 
        tech_key: str
    ) -> Optional[VersionResult]:
        """Extract version from HTML comments.
        
        Args:
            html: Raw HTML content
            tech_key: Technology pattern key
            
        Returns:
            VersionResult or None
        """
        config = self.patterns.get(tech_key)
        if not config:
            return None
        
        for signal in config.get('signals', []):
            if signal.get('type') != 'comment':
                continue
            
            pattern = signal.get('pattern', '')
            if not pattern:
                continue
            
            # Search in HTML comments
            comment_pattern = r'<!--[^>]*' + pattern + r'[^>]*-->'
            regex = re.compile(comment_pattern, re.IGNORECASE)
            match = regex.search(html)
            
            if match:
                # Extract version from the inner pattern
                inner_regex = re.compile(pattern, re.IGNORECASE)
                inner_match = inner_regex.search(match.group(0))
                
                if inner_match and inner_match.groups():
                    version = inner_match.group(1)
                    version = normalize_version(version)
                    
                    if is_plausible_version(version, config.get('name', '')):
                        return VersionResult(
                            tech_name=config.get('name', tech_key),
                            version=version,
                            confidence=signal.get('confidence', 0.7),
                            source='comment',
                            evidence=match.group(0)[:100]
                        )
        
        return None
    
    def extract_version(
        self,
        tech_key: str,
        html: str = '',
        urls: List[str] = None,
        js_vars: Dict[str, Any] = None,
    ) -> Optional[VersionResult]:
        """Extract version for a technology using all available signals.
        
        Tries signals in priority order:
        1. JS variables (highest confidence)
        2. URL patterns
        3. Meta tags
        4. HTML comments
        
        Args:
            tech_key: Technology key (e.g., 'jquery_ui')
            html: Raw HTML content
            urls: List of resource URLs
            js_vars: JavaScript runtime variables
            
        Returns:
            Best VersionResult or None
        """
        urls = urls or []
        js_vars = js_vars or {}
        
        # Normalize key
        tech_key = normalize_tech_key(tech_key)
        
        # Try in priority order
        results = []
        
        # 1. JS variables (highest priority)
        if js_vars:
            result = self.extract_from_js_vars(js_vars, tech_key)
            if result:
                results.append(result)
        
        # 2. URL patterns
        if urls:
            result = self.extract_from_urls(urls, tech_key)
            if result:
                results.append(result)
        
        # 3. Meta tags
        if html:
            result = self.extract_from_meta(html, tech_key)
            if result:
                results.append(result)
        
        # 4. HTML comments
        if html:
            result = self.extract_from_comments(html, tech_key)
            if result:
                results.append(result)
        
        # Return highest confidence result
        if not results:
            return None
        
        best = max(results, key=lambda r: r.confidence)
        
        # Hook for ML verification (future Option 3)
        if self._ml_verifier:
            is_valid, ml_confidence = self._ml_verifier.verify(
                best.tech_name, 
                best.version,
                {'html': html[:1000], 'urls': urls[:10]}
            )
            if not is_valid:
                logger.debug(f"ML verifier rejected version: {best.tech_name}={best.version}")
                return None
            best.confidence = (best.confidence + ml_confidence) / 2
        
        return best
    
    def apply_to_technologies(
        self,
        technologies: List[Dict[str, Any]],
        html: str = '',
        urls: List[str] = None,
        js_vars: Dict[str, Any] = None,
    ) -> List[Dict[str, Any]]:
        """Apply version detection to a list of technologies.
        
        Updates version field if a better version is found.
        
        Args:
            technologies: List of technology dicts with 'name' field
            html: Raw HTML content
            urls: List of resource URLs
            js_vars: JavaScript runtime variables
            
        Returns:
            Updated technologies list
        """
        urls = urls or []
        js_vars = js_vars or {}
        
        for tech in technologies:
            name = tech.get('name', '')
            if not name:
                continue
            
            # Normalize name to key
            tech_key = normalize_tech_key(name)
            
            # Skip if no pattern defined
            if tech_key not in self.patterns:
                continue
            
            # Extract version
            result = self.extract_version(tech_key, html, urls, js_vars)
            
            if result:
                current_version = tech.get('version')
                
                # Only update if:
                # 1. No current version, OR
                # 2. New version has higher confidence source
                should_update = False
                
                if not current_version:
                    should_update = True
                elif not is_plausible_version(current_version, name):
                    should_update = True
                elif result.source == 'js_var':
                    # JS var always wins
                    should_update = True
                
                if should_update:
                    old_version = tech.get('version')
                    tech['version'] = result.version
                    tech['version_source'] = result.source
                    tech['version_confidence'] = result.confidence
                    
                    logger.debug(
                        f"Version updated: {name} {old_version} -> {result.version} "
                        f"(source={result.source}, confidence={result.confidence:.2f})"
                    )
        
        return technologies


def extract_versions(
    technologies: List[Dict[str, Any]],
    html: str = '',
    urls: List[str] = None,
    js_vars: Dict[str, Any] = None,
) -> List[Dict[str, Any]]:
    """Convenience function to extract versions for technologies.
    
    Args:
        technologies: List of technology dicts
        html: Raw HTML content
        urls: Resource URLs
        js_vars: JS runtime variables
        
    Returns:
        Updated technologies with corrected versions
    """
    extractor = VersionExtractor()
    return extractor.apply_to_technologies(technologies, html, urls, js_vars)
