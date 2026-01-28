"""Feature extraction from HTML and HTTP headers.

Extracts numerical and categorical features from web content
for machine learning classification.
"""

import re
from typing import Dict, Any, List


# ============ Feature Patterns ============

# Common technology indicators in HTML
FRAMEWORK_PATTERNS = {
    # Core frameworks
    'wordpress': [r'wp-content', r'wp-includes', r'wordpress', r'wp-json'],
    'react': [r'react', r'__NEXT_DATA__', r'_next/', r'reactroot'],
    'vue': [r'vue\.', r'v-cloak', r'v-if', r'nuxt', r'__NUXT__'],
    'angular': [r'ng-', r'angular', r'ng-app', r'ng-controller'],
    'svelte': [r'svelte', r'__svelte'],
    'polymer': [r'polymer', r'iron-', r'paper-', r'web-component'],
    
    # JS libraries
    'jquery': [r'jquery', r'\$\(document\)', r'\$\(function'],
    'momentjs': [r'moment\.js', r'moment\.min\.js', r'moment\('],
    'corejs': [r'core-js', r'core\.js'],
    'swiper': [r'swiper', r'swiper-slide', r'swiper-container'],
    'hammerjs': [r'hammer\.js', r'hammer\.min\.js', r'Hammer\.'],
    'lottie': [r'lottie', r'lottie-player', r'lottiefiles'],
    
    # CSS frameworks - more specific patterns
    'bootstrap': [r'bootstrap', r'btn-primary', r'container-fluid'],
    'tailwind': [r'tailwindcss', r'tailwind\.css', r'tailwind\.min\.css'],  # More specific
    
    # Backend frameworks
    'laravel': [r'laravel', r'csrf-token', r'_token'],
    'django': [r'csrfmiddlewaretoken', r'django'],
    'php': [r'\.php', r'phpsessid', r'php'],
    'asp': [r'\.aspx?', r'__viewstate', r'asp\.net'],
    'nodejs': [r'express', r'node', r'npm'],
    
    # WordPress plugins/themes - more specific patterns
    'elementor': [r'elementor', r'e-container', r'elementor-widget', r'elementor-element'],
    'yoast': [r'yoast', r'yoast-schema', r'wpseo'],
    'woocommerce': [r'woocommerce', r'wc-add-to-cart', r'wc-cart', r'wc-checkout'],  # More specific
    
    # Analytics/Marketing
    'ga': [r'google-analytics', r'gtag', r'ga\(', r'googletagmanager'],
    'gtm': [r'googletagmanager', r'gtm\.js', r'GTM-'],
    'onesignal': [r'onesignal', r'OneSignal'],
    
    # PWA/Service Worker
    'pwa': [r'manifest\.json', r'service-worker', r'serviceworker', r'web-app-manifest'],
    
    # Video/Media
    'youtube': [r'youtube\.com/embed', r'youtube-player', r'yt-player'],
    
    # Security
    'recaptcha': [r'recaptcha', r'grecaptcha', r'g-recaptcha'],
    'hsts': [r'strict-transport-security'],
    
    # Advertising
    'googleads': [r'googlesyndication', r'googleadservices', r'doubleclick'],
}


# Header-based indicators
SERVER_PATTERNS = {
    'nginx': r'nginx',
    'apache': r'apache|httpd',
    'iis': r'microsoft-iis',
    'cloudflare': r'cloudflare',
    'litespeed': r'litespeed',
}



class FeatureExtractor:
    """Extract ML features from HTML content and headers."""
    
    def __init__(self):
        self.framework_patterns = {
            name: [re.compile(p, re.I) for p in patterns]
            for name, patterns in FRAMEWORK_PATTERNS.items()
        }
        self.server_patterns = {
            name: re.compile(pattern, re.I)
            for name, pattern in SERVER_PATTERNS.items()
        }
    
    def extract_all(self, html: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract all features from HTML and headers.
        
        Args:
            html: HTML content of the page
            headers: HTTP response headers
            
        Returns:
            Dictionary of features for ML model
        """
        features = {}
        
        # HTML-based features
        features.update(self._extract_html_features(html))
        
        # Header-based features
        features.update(self._extract_header_features(headers))
        
        # Pattern-based features
        features.update(self._extract_pattern_features(html))
        
        # Meta features
        features.update(self._extract_meta_features(html))
        
        return features
    
    def _extract_html_features(self, html: str) -> Dict[str, Any]:
        """Extract basic HTML structural features."""
        html_lower = html.lower() if html else ''
        
        return {
            # Size features
            'html_length': len(html) if html else 0,
            'html_length_bucket': self._bucket_size(len(html) if html else 0),
            
            # Tag counts
            'script_count': html_lower.count('<script'),
            'link_count': html_lower.count('<link'),
            'meta_count': html_lower.count('<meta'),
            'div_count': html_lower.count('<div'),
            'img_count': html_lower.count('<img'),
            'form_count': html_lower.count('<form'),
            'iframe_count': html_lower.count('<iframe'),
            
            # Resource counts
            'js_file_count': len(re.findall(r'\.js["\'\?]', html_lower)),
            'css_file_count': len(re.findall(r'\.css["\'\?]', html_lower)),
            
            # Structural indicators
            'has_doctype': html_lower.startswith('<!doctype'),
            'has_html5_doctype': '<!doctype html>' in html_lower[:100],
            'has_viewport': 'viewport' in html_lower,
            'has_charset': 'charset' in html_lower,
        }
    
    def _extract_header_features(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract features from HTTP headers."""
        headers_lower = {k.lower(): v for k, v in (headers or {}).items()}
        
        features = {
            'header_count': len(headers) if headers else 0,
            'has_server': 'server' in headers_lower,
            'has_x_powered_by': 'x-powered-by' in headers_lower,
            'has_content_type': 'content-type' in headers_lower,
            'has_cache_control': 'cache-control' in headers_lower,
            'has_security_headers': (
                'strict-transport-security' in headers_lower or
                'content-security-policy' in headers_lower or
                'x-frame-options' in headers_lower
            ),
        }
        
        # Server detection
        server = headers_lower.get('server', '').lower()
        for name, pattern in self.server_patterns.items():
            features[f'server_{name}'] = bool(pattern.search(server))
        
        # X-Powered-By detection
        powered = headers_lower.get('x-powered-by', '').lower()
        features['powered_php'] = 'php' in powered
        features['powered_asp'] = 'asp' in powered
        features['powered_express'] = 'express' in powered
        
        return features
    
    def _extract_pattern_features(self, html: str) -> Dict[str, Any]:
        """Extract framework/library pattern-based features."""
        html_lower = html.lower() if html else ''
        features = {}
        
        for framework, patterns in self.framework_patterns.items():
            match_count = sum(
                len(pattern.findall(html_lower))
                for pattern in patterns
            )
            features[f'pattern_{framework}'] = match_count
            features[f'has_{framework}'] = match_count > 0
        
        return features
    
    def _extract_meta_features(self, html: str) -> Dict[str, Any]:
        """Extract features from meta tags."""
        features = {
            'has_generator': False,
            'has_og_tags': False,
            'has_twitter_cards': False,
            'has_schema_org': False,
        }
        
        if not html:
            return features
        
        html_lower = html.lower()
        
        # Generator meta tag
        if 'name="generator"' in html_lower or "name='generator'" in html_lower:
            features['has_generator'] = True
        
        # Open Graph
        if 'og:' in html_lower or 'property="og:' in html_lower:
            features['has_og_tags'] = True
        
        # Twitter Cards
        if 'twitter:' in html_lower:
            features['has_twitter_cards'] = True
        
        # Schema.org
        if 'schema.org' in html_lower or 'itemtype=' in html_lower:
            features['has_schema_org'] = True
        
        return features
    
    def _bucket_size(self, size: int) -> int:
        """Bucket size into categories."""
        if size < 1000:
            return 0  # tiny
        elif size < 10000:
            return 1  # small
        elif size < 50000:
            return 2  # medium
        elif size < 200000:
            return 3  # large
        else:
            return 4  # huge
    
    def to_vector(self, features: Dict[str, Any]) -> List[float]:
        """Convert feature dict to numerical vector for ML model.
        
        Args:
            features: Feature dictionary
            
        Returns:
            List of float values
        """
        # Define feature order for consistent vectorization
        feature_order = [
            # Numeric features
            'html_length_bucket', 'script_count', 'link_count', 'meta_count',
            'div_count', 'img_count', 'form_count', 'iframe_count',
            'js_file_count', 'css_file_count', 'header_count',
            # Boolean features (converted to 0/1)
            'has_doctype', 'has_html5_doctype', 'has_viewport', 'has_charset',
            'has_server', 'has_x_powered_by', 'has_security_headers',
            'server_nginx', 'server_apache', 'server_iis', 'server_cloudflare',
            'powered_php', 'powered_asp', 'powered_express',
            'has_generator', 'has_og_tags', 'has_twitter_cards', 'has_schema_org',
            # Pattern counts - core frameworks
            'pattern_wordpress', 'pattern_react', 'pattern_vue', 'pattern_angular', 
            'pattern_svelte', 'pattern_polymer',
            # Pattern counts - JS libraries
            'pattern_jquery', 'pattern_momentjs', 'pattern_corejs', 'pattern_swiper',
            'pattern_hammerjs', 'pattern_lottie',
            # Pattern counts - CSS frameworks
            'pattern_bootstrap', 'pattern_tailwind',
            # Pattern counts - backend
            'pattern_laravel', 'pattern_django', 'pattern_php', 'pattern_asp', 'pattern_nodejs',
            # Pattern counts - plugins/analytics
            'pattern_elementor', 'pattern_yoast', 'pattern_woocommerce',
            'pattern_ga', 'pattern_gtm', 'pattern_onesignal', 'pattern_pwa',
            # Pattern counts - media/security/ads
            'pattern_youtube', 'pattern_recaptcha', 'pattern_hsts', 'pattern_googleads',
            # Has patterns - core frameworks
            'has_wordpress', 'has_react', 'has_vue', 'has_angular', 
            'has_svelte', 'has_polymer',
            # Has patterns - JS libraries
            'has_jquery', 'has_momentjs', 'has_corejs', 'has_swiper',
            'has_hammerjs', 'has_lottie',
            # Has patterns - CSS frameworks
            'has_bootstrap', 'has_tailwind',
            # Has patterns - backend
            'has_laravel', 'has_django', 'has_php', 'has_asp', 'has_nodejs',
            # Has patterns - plugins/analytics
            'has_elementor', 'has_yoast', 'has_woocommerce',
            'has_ga', 'has_gtm', 'has_onesignal', 'has_pwa',
            # Has patterns - media/security/ads
            'has_youtube', 'has_recaptcha', 'has_hsts', 'has_googleads',
        ]

        
        vector = []
        for key in feature_order:
            value = features.get(key, 0)
            if isinstance(value, bool):
                vector.append(1.0 if value else 0.0)
            elif isinstance(value, (int, float)):
                vector.append(float(value))
            else:
                vector.append(0.0)
        
        return vector
    
    @staticmethod
    def get_feature_names() -> List[str]:
        """Get ordered list of feature names."""
        return [
            'html_length_bucket', 'script_count', 'link_count', 'meta_count',
            'div_count', 'img_count', 'form_count', 'iframe_count',
            'js_file_count', 'css_file_count', 'header_count',
            'has_doctype', 'has_html5_doctype', 'has_viewport', 'has_charset',
            'has_server', 'has_x_powered_by', 'has_security_headers',
            'server_nginx', 'server_apache', 'server_iis', 'server_cloudflare',
            'powered_php', 'powered_asp', 'powered_express',
            'has_generator', 'has_og_tags', 'has_twitter_cards', 'has_schema_org',
            'pattern_wordpress', 'pattern_react', 'pattern_vue', 'pattern_angular',
            'pattern_svelte', 'pattern_polymer',
            'pattern_jquery', 'pattern_momentjs', 'pattern_corejs', 'pattern_swiper',
            'pattern_hammerjs', 'pattern_lottie',
            'pattern_bootstrap', 'pattern_tailwind',
            'pattern_laravel', 'pattern_django', 'pattern_php', 'pattern_asp', 'pattern_nodejs',
            'pattern_elementor', 'pattern_yoast', 'pattern_woocommerce',
            'pattern_ga', 'pattern_gtm', 'pattern_onesignal', 'pattern_pwa',
            'pattern_youtube', 'pattern_recaptcha', 'pattern_hsts', 'pattern_googleads',
            'has_wordpress', 'has_react', 'has_vue', 'has_angular',
            'has_svelte', 'has_polymer',
            'has_jquery', 'has_momentjs', 'has_corejs', 'has_swiper',
            'has_hammerjs', 'has_lottie',
            'has_bootstrap', 'has_tailwind',
            'has_laravel', 'has_django', 'has_php', 'has_asp', 'has_nodejs',
            'has_elementor', 'has_yoast', 'has_woocommerce',
            'has_ga', 'has_gtm', 'has_onesignal', 'has_pwa',
            'has_youtube', 'has_recaptcha', 'has_hsts', 'has_googleads',
        ]




# Module-level instance for convenience
_extractor = None


def get_extractor() -> FeatureExtractor:
    """Get singleton FeatureExtractor instance."""
    global _extractor
    if _extractor is None:
        _extractor = FeatureExtractor()
    return _extractor


def extract_features(html: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """Convenience function to extract features."""
    return get_extractor().extract_all(html, headers)


def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """Convenience function to convert features to vector."""
    return get_extractor().to_vector(features)
