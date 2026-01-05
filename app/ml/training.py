"""Training utilities for the ML classifier.

Generates training data from existing scan results in the database.
"""

import logging
import requests
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime

from .features import extract_features, features_to_vector
from .classifier import TechClassifier, TARGET_TECHNOLOGIES

logger = logging.getLogger('techscan.ml.training')


class TrainingDataGenerator:
    """Generate training data from existing scans."""
    
    def __init__(self):
        self.samples: List[Tuple[List[float], List[str]]] = []
    
    def fetch_html(self, domain: str, timeout: int = 10) -> Tuple[str, Dict[str, str]]:
        """Fetch HTML and headers from a domain.
        
        Args:
            domain: Domain to fetch
            timeout: Request timeout
            
        Returns:
            Tuple of (html_content, headers_dict)
        """
        url = f"https://{domain}"
        try:
            resp = requests.get(url, timeout=timeout, headers={
                'User-Agent': 'TechScan ML Trainer/1.0'
            })
            return resp.text, dict(resp.headers)
        except Exception as e:
            logger.debug(f"Failed to fetch {domain}: {e}")
            # Try HTTP
            try:
                url = f"http://{domain}"
                resp = requests.get(url, timeout=timeout, headers={
                    'User-Agent': 'TechScan ML Trainer/1.0'
                })
                return resp.text, dict(resp.headers)
            except Exception:
                return '', {}
    
    def generate_from_database(self, limit: int = 500) -> int:
        """Generate training data from database scans.
        
        Args:
            limit: Maximum number of scans to process
            
        Returns:
            Number of samples generated
        """
        try:
            from .. import db as _db
        except ImportError:
            logger.error("Cannot import db module")
            return 0
        
        scans = _db.get_recent_scans(limit=limit)
        count = 0
        
        for scan in scans:
            domain = scan.get('domain')
            technologies = scan.get('technologies', [])
            
            if not domain or not technologies:
                continue
            
            # Get tech names that match our targets
            tech_names = []
            for tech in technologies:
                name = tech.get('name', '') if isinstance(tech, dict) else str(tech)
                # Check if this tech or similar exists in targets
                matching = self._match_technology(name)
                if matching:
                    tech_names.append(matching)
            
            if not tech_names:
                continue
            
            # Fetch current HTML for features
            html, headers = self.fetch_html(domain)
            if not html:
                continue
            
            # Extract features
            features = extract_features(html, headers)
            vector = features_to_vector(features)
            
            self.samples.append((vector, list(set(tech_names))))
            count += 1
            
            if count % 10 == 0:
                logger.info(f"Generated {count} training samples...")
        
        logger.info(f"Generated {count} training samples total")
        return count
    
    def _match_technology(self, name: str) -> Optional[str]:
        """Match a technology name to our target list."""
        name_lower = name.lower()
        
        for target in TARGET_TECHNOLOGIES:
            target_lower = target.lower()
            if target_lower in name_lower or name_lower in target_lower:
                return target
        
        # Special mappings
        mappings = {
            'wordpress': 'WordPress',
            'vue': 'Vue.js',
            'angular': 'Angular',
            'jquery': 'jQuery',
            'tailwind': 'Tailwind CSS',
            'nginx': 'Nginx',
            'apache': 'Apache',
            'cloudflare': 'Cloudflare',
            'mysql': 'MySQL',
            'postgresql': 'PostgreSQL',
            'mongodb': 'MongoDB',
            'elementor': 'Elementor',
            'woocommerce': 'WooCommerce',
            'font awesome': 'Font Awesome',
            'fontawesome': 'Font Awesome',
            'google analytics': 'Google Analytics',
            'google tag manager': 'Google Tag Manager',
            'gtm': 'Google Tag Manager',
            'google fonts': 'Google Fonts',
        }
        
        for key, value in mappings.items():
            if key in name_lower:
                return value
        
        return None
    
    def add_sample(self, html: str, headers: Dict[str, str], technologies: List[str]):
        """Add a manual training sample.
        
        Args:
            html: HTML content
            headers: HTTP headers
            technologies: List of technology names
        """
        features = extract_features(html, headers)
        vector = features_to_vector(features)
        
        valid_techs = [t for t in technologies if t in TARGET_TECHNOLOGIES]
        if valid_techs:
            self.samples.append((vector, valid_techs))
    
    def get_training_data(self) -> Tuple[List[List[float]], List[List[str]]]:
        """Get training data as X, y format.
        
        Returns:
            Tuple of (feature_vectors, label_lists)
        """
        if not self.samples:
            return [], []
        
        X = [s[0] for s in self.samples]
        y = [s[1] for s in self.samples]
        return X, y
    
    def clear(self):
        """Clear all samples."""
        self.samples = []


def train_from_database(limit: int = 500, save: bool = True) -> Dict[str, Any]:
    """Train classifier from database scans.
    
    Args:
        limit: Maximum scans to use
        save: Whether to save model after training
        
    Returns:
        Training metrics
    """
    generator = TrainingDataGenerator()
    count = generator.generate_from_database(limit=limit)
    
    if count < 10:
        return {
            'error': f'Not enough samples: {count}',
            'min_required': 10
        }
    
    X, y = generator.get_training_data()
    
    classifier = TechClassifier()
    metrics = classifier.train(X, y)
    
    if save:
        classifier.save()
    
    return metrics


def create_demo_training_data() -> Tuple[List[List[float]], List[List[str]]]:
    """Create comprehensive demo training data for testing.
    
    Improved version with:
    - More samples (300+)
    - Less randomness for consistent patterns
    - Better feature-label correlation
    """
    import random
    random.seed(42)  # Reproducible results
    
    samples_X = []
    samples_y = []
    
    def add_sample(base_features: Dict, labels: List[str], variations: int = 1):
        """Add sample with small variations."""
        for _ in range(variations):
            features = base_features.copy()
            # Add small noise to numeric features
            for key in features:
                if isinstance(features[key], int) and ('count' in key or 'pattern' in key):
                    noise = random.randint(-2, 2)
                    features[key] = max(0, features[key] + noise)
            samples_X.append(features_to_vector(features))
            samples_y.append(labels.copy())

    
    # ============ WordPress Sites (50 samples) ============
    # Pure WordPress
    add_sample({
        'html_length_bucket': 3, 'script_count': 12, 'link_count': 8,
        'pattern_wordpress': 35, 'pattern_php': 15, 'pattern_jquery': 8,
        'has_wordpress': True, 'has_php': True, 'has_jquery': True,
        'has_generator': True, 'has_og_tags': True,
    }, ['WordPress', 'PHP', 'jQuery'], variations=15)
    
    # WordPress + WooCommerce
    add_sample({
        'html_length_bucket': 4, 'script_count': 18, 'link_count': 12,
        'pattern_wordpress': 45, 'pattern_php': 20, 'pattern_jquery': 12,
        'has_wordpress': True, 'has_php': True, 'has_jquery': True,
        'has_generator': True, 'has_og_tags': True, 'has_schema_org': True,
    }, ['WordPress', 'PHP', 'jQuery', 'WooCommerce'], variations=10)
    
    # WordPress + Elementor
    add_sample({
        'html_length_bucket': 4, 'script_count': 20, 'link_count': 15,
        'pattern_wordpress': 50, 'pattern_php': 18, 'pattern_jquery': 15,
        'has_wordpress': True, 'has_php': True, 'has_jquery': True,
        'has_generator': True, 'div_count': 80,
    }, ['WordPress', 'PHP', 'jQuery', 'Elementor'], variations=10)
    
    # WordPress minimal
    add_sample({
        'html_length_bucket': 2, 'script_count': 6, 'link_count': 4,
        'pattern_wordpress': 20, 'pattern_php': 8,
        'has_wordpress': True, 'has_php': True,
        'has_generator': True,
    }, ['WordPress', 'PHP'], variations=15)
    
    # ============ React Sites (45 samples) ============
    # React SPA
    add_sample({
        'html_length_bucket': 1, 'script_count': 3, 'div_count': 5,
        'pattern_react': 25, 'has_react': True,
        'has_html5_doctype': True, 'has_viewport': True,
    }, ['React'], variations=15)
    
    # React + Node.js
    add_sample({
        'html_length_bucket': 2, 'script_count': 5, 'div_count': 10,
        'pattern_react': 30, 'pattern_nodejs': 8,
        'has_react': True, 'has_nodejs': True,
        'has_html5_doctype': True, 'has_viewport': True,
    }, ['React', 'Node.js'], variations=15)
    
    # Next.js (React-based)
    add_sample({
        'html_length_bucket': 2, 'script_count': 8, 'div_count': 15,
        'pattern_react': 40, 'pattern_nodejs': 12,
        'has_react': True, 'has_nodejs': True,
        'has_html5_doctype': True, 'has_viewport': True, 'has_og_tags': True,
    }, ['React', 'Node.js'], variations=15)
    
    # ============ Vue.js Sites (40 samples) ============
    # Vue SPA
    add_sample({
        'html_length_bucket': 1, 'script_count': 4, 'div_count': 8,
        'pattern_vue': 20, 'has_vue': True,
        'has_html5_doctype': True, 'has_viewport': True,
    }, ['Vue.js'], variations=15)
    
    # Vue + Tailwind
    add_sample({
        'html_length_bucket': 2, 'script_count': 6, 'div_count': 25,
        'pattern_vue': 28, 'pattern_tailwind': 15,
        'has_vue': True, 'has_tailwind': True,
        'has_html5_doctype': True, 'has_viewport': True,
    }, ['Vue.js', 'Tailwind CSS'], variations=15)
    
    # Nuxt.js (Vue-based)
    add_sample({
        'html_length_bucket': 2, 'script_count': 7, 'div_count': 20,
        'pattern_vue': 35, 'pattern_nodejs': 10,
        'has_vue': True, 'has_nodejs': True,
        'has_html5_doctype': True, 'has_og_tags': True,
    }, ['Vue.js', 'Node.js'], variations=10)
    
    # ============ Angular Sites (30 samples) ============
    add_sample({
        'html_length_bucket': 2, 'script_count': 5, 'div_count': 15,
        'pattern_angular': 25, 'has_angular': True,
        'has_html5_doctype': True, 'has_viewport': True,
    }, ['Angular'], variations=15)
    
    add_sample({
        'html_length_bucket': 3, 'script_count': 8, 'div_count': 25,
        'pattern_angular': 35, 'pattern_nodejs': 8,
        'has_angular': True, 'has_nodejs': True,
        'has_html5_doctype': True, 'has_viewport': True,
    }, ['Angular', 'Node.js'], variations=15)
    
    # ============ Laravel Sites (35 samples) ============
    add_sample({
        'html_length_bucket': 3, 'script_count': 8, 'link_count': 6,
        'pattern_laravel': 20, 'pattern_php': 15,
        'has_laravel': True, 'has_php': True,
        'has_viewport': True, 'has_charset': True,
    }, ['Laravel', 'PHP'], variations=15)
    
    add_sample({
        'html_length_bucket': 3, 'script_count': 12, 'link_count': 8,
        'pattern_laravel': 25, 'pattern_php': 18, 'pattern_bootstrap': 12,
        'has_laravel': True, 'has_php': True, 'has_bootstrap': True,
        'has_viewport': True,
    }, ['Laravel', 'PHP', 'Bootstrap'], variations=10)
    
    add_sample({
        'html_length_bucket': 3, 'script_count': 10, 'link_count': 7,
        'pattern_laravel': 22, 'pattern_php': 16, 'pattern_vue': 15,
        'has_laravel': True, 'has_php': True, 'has_vue': True,
        'has_viewport': True,
    }, ['Laravel', 'PHP', 'Vue.js'], variations=10)
    
    # ============ Django Sites (25 samples) ============
    add_sample({
        'html_length_bucket': 2, 'script_count': 5, 'link_count': 4,
        'pattern_django': 15, 'has_django': True,
        'has_viewport': True, 'has_charset': True,
    }, ['Django'], variations=15)
    
    add_sample({
        'html_length_bucket': 3, 'script_count': 8, 'link_count': 6,
        'pattern_django': 20, 'pattern_bootstrap': 10,
        'has_django': True, 'has_bootstrap': True,
        'has_viewport': True,
    }, ['Django', 'Bootstrap'], variations=10)
    
    # ============ Static/Bootstrap Sites (30 samples) ============
    add_sample({
        'html_length_bucket': 2, 'script_count': 4, 'link_count': 5,
        'pattern_bootstrap': 20, 'pattern_jquery': 8,
        'has_bootstrap': True, 'has_jquery': True,
        'has_html5_doctype': True,
    }, ['Bootstrap', 'jQuery'], variations=15)
    
    add_sample({
        'html_length_bucket': 2, 'script_count': 3, 'link_count': 4,
        'pattern_tailwind': 25, 'has_tailwind': True,
        'has_html5_doctype': True, 'has_viewport': True,
    }, ['Tailwind CSS'], variations=15)
    
    # ============ Server-side Detection (30 samples) ============
    # Nginx
    add_sample({
        'header_count': 12, 'has_server': True, 'server_nginx': True,
        'has_security_headers': True, 'html_length_bucket': 2,
    }, ['Nginx'], variations=15)
    
    # Apache
    add_sample({
        'header_count': 10, 'has_server': True, 'server_apache': True,
        'powered_php': True, 'html_length_bucket': 3,
    }, ['Apache', 'PHP'], variations=15)
    
    # ============ Analytics/Tracking (25 samples) ============
    add_sample({
        'html_length_bucket': 3, 'script_count': 10,
        'has_og_tags': True, 'has_twitter_cards': True,
        'pattern_jquery': 5,
    }, ['Google Analytics', 'jQuery'], variations=15)
    
    add_sample({
        'html_length_bucket': 3, 'script_count': 12,
        'has_og_tags': True, 'has_schema_org': True,
    }, ['Google Analytics', 'Google Tag Manager'], variations=10)
    
    # ============ Cloudflare (15 samples) ============
    add_sample({
        'header_count': 15, 'has_server': True, 'server_cloudflare': True,
        'has_security_headers': True, 'html_length_bucket': 2,
    }, ['Cloudflare'], variations=15)
    
    # ============ Google Fonts / Font Awesome (20 samples) ============
    add_sample({
        'html_length_bucket': 2, 'link_count': 8, 'css_file_count': 4,
        'has_viewport': True,
    }, ['Google Fonts'], variations=10)
    
    add_sample({
        'html_length_bucket': 3, 'link_count': 10, 'css_file_count': 5,
        'pattern_bootstrap': 8, 'has_bootstrap': True,
    }, ['Font Awesome', 'Bootstrap'], variations=10)
    
    # ============ NEGATIVE SAMPLES ============
    # These teach the model what patterns DON'T indicate certain technologies
    # Critical for reducing false positives
    
    # WordPress sites do NOT have ASP.NET, PostgreSQL, MongoDB, Redis
    add_sample({
        'html_length_bucket': 3, 'script_count': 12, 'link_count': 8,
        'pattern_wordpress': 35, 'pattern_php': 15, 'pattern_jquery': 8,
        'has_wordpress': True, 'has_php': True, 'has_jquery': True,
        'has_generator': True, 'server_nginx': True,
        # No ASP.NET patterns
        'has_asp': False, 'pattern_asp': 0,
        'powered_asp': False,
    }, ['WordPress', 'PHP', 'jQuery', 'Nginx'], variations=20)
    
    # React sites do NOT have WordPress, PHP, ASP.NET
    add_sample({
        'html_length_bucket': 2, 'script_count': 5, 'div_count': 15,
        'pattern_react': 35, 'pattern_nodejs': 10,
        'has_react': True, 'has_nodejs': True,
        'has_html5_doctype': True, 'has_viewport': True,
        # No PHP/WordPress/ASP.NET
        'has_wordpress': False, 'pattern_wordpress': 0,
        'has_php': False, 'pattern_php': 0,
        'has_asp': False, 'pattern_asp': 0,
    }, ['React', 'Node.js'], variations=20)
    
    # Vue sites - also negative for WordPress/PHP
    add_sample({
        'html_length_bucket': 2, 'script_count': 6, 'div_count': 20,
        'pattern_vue': 30, 'pattern_tailwind': 15,
        'has_vue': True, 'has_tailwind': True,
        'has_html5_doctype': True, 'has_viewport': True,
        # No WordPress/PHP
        'has_wordpress': False, 'pattern_wordpress': 0,
        'has_php': False, 'pattern_php': 0,
    }, ['Vue.js', 'Tailwind CSS'], variations=15)
    
    # Static HTML sites - minimal tech
    add_sample({
        'html_length_bucket': 1, 'script_count': 2, 'link_count': 3,
        'div_count': 10, 'has_html5_doctype': True, 'has_viewport': True,
        # No frameworks
        'has_wordpress': False, 'has_react': False, 'has_vue': False,
        'has_php': False, 'has_nodejs': False, 'has_angular': False,
        'pattern_wordpress': 0, 'pattern_react': 0, 'pattern_vue': 0,
    }, ['Bootstrap'], variations=15)
    
    # ASP.NET specific patterns (so model learns what ASP.NET looks like)
    add_sample({
        'html_length_bucket': 3, 'script_count': 8, 'form_count': 2,
        'has_asp': True, 'pattern_asp': 20, 'powered_asp': True,
        'has_html5_doctype': True,
        # Explicitly NOT PHP/WordPress
        'has_php': False, 'pattern_php': 0, 'has_wordpress': False,
    }, ['ASP.NET'], variations=15)
    
    # Pure PHP sites (not WordPress, not Laravel)
    add_sample({
        'html_length_bucket': 2, 'script_count': 5, 'link_count': 4,
        'has_php': True, 'pattern_php': 12, 'powered_php': True,
        # Not WordPress, not Laravel
        'has_wordpress': False, 'pattern_wordpress': 0,
        'has_laravel': False, 'pattern_laravel': 0,
    }, ['PHP'], variations=15)
    
    # ============ NEW TECHNOLOGIES ============
    
    # Svelte sites
    add_sample({
        'html_length_bucket': 2, 'script_count': 4, 'div_count': 12,
        'pattern_svelte': 20, 'has_svelte': True,
        'has_html5_doctype': True, 'has_viewport': True,
    }, ['Svelte'], variations=15)
    
    # Moment.js (JS date library)
    add_sample({
        'html_length_bucket': 3, 'script_count': 10,
        'pattern_momentjs': 8, 'has_momentjs': True,
        'pattern_jquery': 5, 'has_jquery': True,
    }, ['Moment.js', 'jQuery'], variations=15)
    
    # Swiper (carousel library)
    add_sample({
        'html_length_bucket': 3, 'script_count': 8,
        'pattern_swiper': 12, 'has_swiper': True,
        'div_count': 30,
    }, ['Swiper'], variations=15)
    
    # Elementor (WordPress page builder)
    add_sample({
        'html_length_bucket': 4, 'script_count': 18, 'link_count': 12,
        'pattern_elementor': 25, 'has_elementor': True,
        'pattern_wordpress': 35, 'has_wordpress': True,
        'has_php': True, 'pattern_php': 15,
    }, ['Elementor', 'WordPress', 'PHP'], variations=20)
    
    # Yoast SEO
    add_sample({
        'html_length_bucket': 3, 'script_count': 12,
        'pattern_yoast': 15, 'has_yoast': True,
        'pattern_wordpress': 30, 'has_wordpress': True,
        'has_og_tags': True, 'has_schema_org': True,
    }, ['Yoast SEO', 'WordPress'], variations=15)
    
    # PWA (Progressive Web App)
    add_sample({
        'html_length_bucket': 2, 'script_count': 6,
        'pattern_pwa': 8, 'has_pwa': True,
        'has_viewport': True, 'has_html5_doctype': True,
    }, ['PWA'], variations=15)
    
    # OneSignal (push notifications)
    add_sample({
        'html_length_bucket': 3, 'script_count': 10,
        'pattern_onesignal': 5, 'has_onesignal': True,
        'has_og_tags': True,
    }, ['OneSignal'], variations=10)
    
    # Combined: WordPress + Elementor + Yoast
    add_sample({
        'html_length_bucket': 4, 'script_count': 20, 'link_count': 15,
        'pattern_wordpress': 50, 'has_wordpress': True,
        'pattern_elementor': 30, 'has_elementor': True,
        'pattern_yoast': 12, 'has_yoast': True,
        'pattern_php': 18, 'has_php': True,
        'has_og_tags': True, 'has_schema_org': True,
    }, ['WordPress', 'Elementor', 'Yoast SEO', 'PHP'], variations=20)
    
    logger.info(f"Created {len(samples_X)} demo training samples")
    return samples_X, samples_y




def train_demo() -> Dict[str, Any]:
    """Train with demo data using balanced hyperparameters.
    
    Uses regularization to prevent overfitting while maintaining
    good generalization performance.
    """
    X, y = create_demo_training_data()
    
    # Create classifier
    classifier = TechClassifier()
    
    # Train with balanced hyperparameters
    # Regularization settings to prevent overfitting:
    # - max_depth=8: Prevents trees from memorizing training data
    # - min_samples_split=5: Requires minimum samples to split
    # - min_samples_leaf=2: Prevents tiny leaf nodes
    # - max_features='sqrt': Limits features per split
    # - test_size=0.25: Larger test set for honest evaluation
    metrics = classifier.train(
        X, y,
        test_size=0.25,  # 75/25 split for better evaluation
        use_cross_validation=True,  # 5-fold CV for robust estimation
        n_estimators=150,  # Balanced: not too many, not too few
        max_depth=8,  # Regularization: prevent deep memorization
        min_samples_split=5,  # Regularization: prevent tiny splits
        min_samples_leaf=2,  # Regularization: prevent tiny leaves
        max_features='sqrt',  # Regularization: feature sampling
    )


    
    classifier.save()
    return metrics
