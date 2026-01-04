"""ML Classifier for technology prediction.

Uses scikit-learn to train and predict technologies
based on extracted features from web content.
"""

import os
import json
import pickle
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import MultiLabelBinarizer
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from .features import extract_features, features_to_vector, get_extractor

logger = logging.getLogger('techscan.ml')


# ============ Target Technologies ============

# Technologies we want to predict (multi-label classification)
TARGET_TECHNOLOGIES = [
    'WordPress', 'React', 'Vue.js', 'Angular', 'jQuery',
    'Bootstrap', 'Tailwind CSS', 'Laravel', 'Django', 'PHP',
    'ASP.NET', 'Node.js', 'Nginx', 'Apache', 'Cloudflare',
    'MySQL', 'PostgreSQL', 'MongoDB', 'Redis',
    'Google Analytics', 'Google Tag Manager', 'Google Fonts',
    'Font Awesome', 'Elementor', 'WooCommerce',
]


class TechClassifier:
    """Multi-label classifier for technology prediction."""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize classifier.
        
        Args:
            model_path: Path to saved model file (optional)
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required. Install with: pip install scikit-learn")
        
        self.model: Optional[RandomForestClassifier] = None
        self.label_binarizer = MultiLabelBinarizer(classes=TARGET_TECHNOLOGIES)
        self.label_binarizer.fit([TARGET_TECHNOLOGIES])  # Fit with all possible labels
        self.feature_names = get_extractor().get_feature_names()
        self.is_trained = False
        self.model_path = model_path or self._default_model_path()
        self.metadata: Dict[str, Any] = {}
        
        # Try to load existing model
        if os.path.exists(self.model_path):
            self.load()
    
    def _default_model_path(self) -> str:
        """Get default model path."""
        base = Path(__file__).parent.parent.parent
        model_dir = base / 'models'
        model_dir.mkdir(exist_ok=True)
        return str(model_dir / 'tech_classifier.pkl')
    
    def train(
        self,
        X: List[List[float]],
        y: List[List[str]],
        test_size: float = 0.2,
        **kwargs
    ) -> Dict[str, Any]:
        """Train the classifier.
        
        Args:
            X: Feature vectors (list of feature lists)
            y: Labels (list of technology name lists)
            test_size: Fraction for test split
            **kwargs: Additional params for RandomForestClassifier
            
        Returns:
            Dictionary with training metrics
        """
        logger.info(f"Training classifier with {len(X)} samples...")
        
        # Convert labels to binary matrix
        y_binary = self.label_binarizer.transform(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_binary, test_size=test_size, random_state=42
        )
        
        # Create and train model
        self.model = RandomForestClassifier(
            n_estimators=kwargs.get('n_estimators', 100),
            max_depth=kwargs.get('max_depth', 10),
            min_samples_split=kwargs.get('min_samples_split', 5),
            n_jobs=-1,
            random_state=42
        )
        
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        
        # Calculate metrics
        metrics = {
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'accuracy': accuracy_score(y_test, y_pred),
            'feature_count': len(self.feature_names),
            'label_count': len(TARGET_TECHNOLOGIES),
            'trained_at': datetime.now().isoformat(),
        }
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            importances = list(zip(self.feature_names, self.model.feature_importances_))
            importances.sort(key=lambda x: x[1], reverse=True)
            metrics['top_features'] = importances[:10]
        
        self.metadata = metrics
        logger.info(f"Training complete. Accuracy: {metrics['accuracy']:.2%}")
        
        return metrics
    
    def predict(
        self,
        html: str,
        headers: Dict[str, str],
        threshold: float = 0.3
    ) -> List[Dict[str, Any]]:
        """Predict technologies for given content.
        
        Args:
            html: HTML content
            headers: HTTP headers
            threshold: Probability threshold for predictions
            
        Returns:
            List of predicted technologies with confidence scores
        """
        if not self.is_trained:
            logger.warning("Model not trained, returning empty predictions")
            return []
        
        # Extract features
        features = extract_features(html, headers)
        vector = features_to_vector(features)
        
        # Get predictions
        probas = self.model.predict_proba([vector])
        
        predictions = []
        for i, tech in enumerate(TARGET_TECHNOLOGIES):
            # RandomForest returns list of arrays for multi-output
            if len(probas) > i:
                proba = probas[i][0]
                if len(proba) > 1:
                    confidence = proba[1]  # Probability of positive class
                else:
                    confidence = proba[0]
            else:
                confidence = 0.0
            
            if confidence >= threshold:
                predictions.append({
                    'name': tech,
                    'confidence': round(confidence * 100, 1),
                    'source': 'ml-classifier'
                })
        
        # Sort by confidence
        predictions.sort(key=lambda x: x['confidence'], reverse=True)
        
        return predictions
    
    def predict_from_features(
        self,
        features: Dict[str, Any],
        threshold: float = 0.3
    ) -> List[Dict[str, Any]]:
        """Predict from pre-extracted features."""
        if not self.is_trained:
            return []
        
        vector = features_to_vector(features)
        probas = self.model.predict_proba([vector])
        
        predictions = []
        for i, tech in enumerate(TARGET_TECHNOLOGIES):
            if len(probas) > i:
                proba = probas[i][0]
                confidence = proba[1] if len(proba) > 1 else proba[0]
            else:
                confidence = 0.0
            
            if confidence >= threshold:
                predictions.append({
                    'name': tech,
                    'confidence': round(confidence * 100, 1),
                    'source': 'ml-classifier'
                })
        
        predictions.sort(key=lambda x: x['confidence'], reverse=True)
        return predictions
    
    def save(self, path: Optional[str] = None) -> str:
        """Save model to file.
        
        Args:
            path: Optional path, uses default if not provided
            
        Returns:
            Path where model was saved
        """
        path = path or self.model_path
        
        data = {
            'model': self.model,
            'label_binarizer': self.label_binarizer,
            'metadata': self.metadata,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
        }
        
        with open(path, 'wb') as f:
            pickle.dump(data, f)
        
        logger.info(f"Model saved to {path}")
        return path
    
    def load(self, path: Optional[str] = None) -> bool:
        """Load model from file.
        
        Args:
            path: Optional path, uses default if not provided
            
        Returns:
            True if loaded successfully
        """
        path = path or self.model_path
        
        if not os.path.exists(path):
            logger.warning(f"Model file not found: {path}")
            return False
        
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)
            
            self.model = data['model']
            self.label_binarizer = data['label_binarizer']
            self.metadata = data.get('metadata', {})
            self.is_trained = data.get('is_trained', True)
            
            logger.info(f"Model loaded from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get classifier status."""
        return {
            'is_trained': self.is_trained,
            'model_path': self.model_path,
            'model_exists': os.path.exists(self.model_path),
            'sklearn_available': SKLEARN_AVAILABLE,
            'target_technologies': TARGET_TECHNOLOGIES,
            'feature_count': len(self.feature_names),
            'metadata': self.metadata,
        }


# ============ Module-level convenience ============

_classifier: Optional[TechClassifier] = None


def get_classifier() -> TechClassifier:
    """Get singleton classifier instance."""
    global _classifier
    if _classifier is None:
        _classifier = TechClassifier()
    return _classifier


def predict_technologies(
    html: str,
    headers: Dict[str, str],
    threshold: float = 0.3
) -> List[Dict[str, Any]]:
    """Convenience function to predict technologies."""
    return get_classifier().predict(html, headers, threshold)


def is_model_trained() -> bool:
    """Check if model is trained."""
    return get_classifier().is_trained
