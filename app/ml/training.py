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
    """Create demo training data for testing."""
    # This creates synthetic data for demonstration
    # In production, use real data from database
    
    import random
    
    samples_X = []
    samples_y = []
    
    # WordPress sample patterns
    for _ in range(20):
        features = {
            'html_length_bucket': 3,
            'script_count': random.randint(5, 15),
            'pattern_wordpress': random.randint(10, 50),
            'pattern_php': random.randint(5, 20),
            'has_wordpress': True,
            'has_php': True,
            'has_jquery': random.choice([True, False]),
            'pattern_jquery': random.randint(0, 10),
            'has_generator': True,
        }
        samples_X.append(features_to_vector(features))
        techs = ['WordPress', 'PHP']
        if features.get('has_jquery'):
            techs.append('jQuery')
        samples_y.append(techs)
    
    # React sample patterns
    for _ in range(20):
        features = {
            'html_length_bucket': 2,
            'script_count': random.randint(3, 10),
            'pattern_react': random.randint(5, 30),
            'pattern_nodejs': random.randint(0, 10),
            'has_react': True,
            'has_nodejs': random.choice([True, False]),
            'has_html5_doctype': True,
        }
        samples_X.append(features_to_vector(features))
        techs = ['React']
        if features.get('has_nodejs'):
            techs.append('Node.js')
        samples_y.append(techs)
    
    # Vue sample patterns
    for _ in range(15):
        features = {
            'html_length_bucket': 2,
            'script_count': random.randint(3, 8),
            'pattern_vue': random.randint(5, 25),
            'has_vue': True,
            'has_tailwind': random.choice([True, False]),
            'pattern_tailwind': random.randint(0, 15),
        }
        samples_X.append(features_to_vector(features))
        techs = ['Vue.js']
        if features.get('has_tailwind'):
            techs.append('Tailwind CSS')
        samples_y.append(techs)
    
    # Generic PHP/Laravel
    for _ in range(15):
        features = {
            'html_length_bucket': random.randint(2, 4),
            'script_count': random.randint(3, 12),
            'pattern_php': random.randint(5, 20),
            'pattern_laravel': random.randint(3, 15),
            'has_php': True,
            'has_laravel': True,
            'has_bootstrap': random.choice([True, False]),
            'pattern_bootstrap': random.randint(0, 10),
        }
        samples_X.append(features_to_vector(features))
        techs = ['PHP', 'Laravel']
        if features.get('has_bootstrap'):
            techs.append('Bootstrap')
        samples_y.append(techs)
    
    logger.info(f"Created {len(samples_X)} demo training samples")
    return samples_X, samples_y


def train_demo() -> Dict[str, Any]:
    """Train with demo data for testing."""
    X, y = create_demo_training_data()
    classifier = TechClassifier()
    metrics = classifier.train(X, y)
    classifier.save()
    return metrics
