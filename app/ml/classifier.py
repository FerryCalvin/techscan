"""ML Classifier for technology prediction.

Uses scikit-learn to train and predict technologies
based on extracted features from web content.

Anti-overfitting measures:
- Cross-validation for robust accuracy estimation
- Regularization via max_depth and min_samples constraints
- Train/validation/test split for honest evaluation
"""

import os
import json
import pickle
import logging
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import MultiLabelBinarizer
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.metrics import classification_report, accuracy_score, hamming_loss
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
        use_cross_validation: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """Train the classifier with anti-overfitting measures.
        
        Args:
            X: Feature vectors (list of feature lists)
            y: Labels (list of technology name lists)
            test_size: Fraction for test split
            use_cross_validation: Whether to use k-fold CV for robust estimation
            **kwargs: Additional params for RandomForestClassifier
            
        Returns:
            Dictionary with training metrics including overfitting indicators
        """
        logger.info(f"Training classifier with {len(X)} samples...")
        
        # Convert to numpy array with explicit dtype
        X_array = np.array(X, dtype=np.float64)
        
        # Convert labels to binary matrix
        y_binary = self.label_binarizer.transform(y)
        
        # Split data: train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X_array, y_binary, test_size=test_size, random_state=42
        )
        
        # Model hyperparameters with regularization
        n_estimators = kwargs.get('n_estimators', 100)
        max_depth = kwargs.get('max_depth', 8)  # Reduced from 10 to prevent overfitting
        min_samples_split = kwargs.get('min_samples_split', 5)
        min_samples_leaf = kwargs.get('min_samples_leaf', 2)  # New: prevent tiny leaves
        max_features = kwargs.get('max_features', 'sqrt')  # New: limit features per split
        
        # Create model with regularization
        # Note: oob_score=False because it doesn't work well with multi-output
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            max_features=max_features,
            n_jobs=-1,
            random_state=42,
            oob_score=False,  # Disabled for multi-output classification
        )

        # Train model
        self.model.fit(X_train, y_train)

        self.is_trained = True
        
        # Evaluate on train and test sets
        y_train_pred = self.model.predict(X_train)
        y_test_pred = self.model.predict(X_test)
        
        train_accuracy = accuracy_score(y_train, y_train_pred)
        test_accuracy = accuracy_score(y_test, y_test_pred)
        
        # Calculate hamming loss (better for multi-label)
        train_hamming = hamming_loss(y_train, y_train_pred)
        test_hamming = hamming_loss(y_test, y_test_pred)
        
        # Cross-validation for robust estimation
        cv_scores = None
        cv_mean = None
        cv_std = None
        if use_cross_validation and len(X_train) >= 20:
            try:
                # Use first column of y for stratification (most common label)
                # For multi-label, we'll do simple 5-fold
                from sklearn.model_selection import KFold
                kf = KFold(n_splits=5, shuffle=True, random_state=42)
                cv_scores_list = []
                for train_idx, val_idx in kf.split(X_train):
                    X_cv_train, X_cv_val = X_train[train_idx], X_train[val_idx]
                    y_cv_train, y_cv_val = y_train[train_idx], y_train[val_idx]
                    
                    cv_model = RandomForestClassifier(
                        n_estimators=n_estimators,
                        max_depth=max_depth,
                        min_samples_split=min_samples_split,
                        min_samples_leaf=min_samples_leaf,
                        max_features=max_features,
                        n_jobs=-1,
                        random_state=42
                    )
                    cv_model.fit(X_cv_train, y_cv_train)
                    cv_pred = cv_model.predict(X_cv_val)
                    cv_scores_list.append(accuracy_score(y_cv_val, cv_pred))
                
                cv_scores = cv_scores_list
                cv_mean = np.mean(cv_scores_list)
                cv_std = np.std(cv_scores_list)
            except Exception as e:
                logger.warning(f"Cross-validation failed: {e}")
        
        # Overfitting detection
        overfit_gap = train_accuracy - test_accuracy
        overfit_warning = overfit_gap > 0.15  # >15% gap is concerning
        
        # Calculate metrics
        metrics = {
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'train_accuracy': round(train_accuracy, 4),
            'test_accuracy': round(test_accuracy, 4),
            'accuracy': round(test_accuracy, 4),  # Report test accuracy as main metric
            'train_hamming_loss': round(train_hamming, 4),
            'test_hamming_loss': round(test_hamming, 4),
            'overfit_gap': round(overfit_gap, 4),
            'overfit_warning': overfit_warning,
            'feature_count': len(self.feature_names),
            'label_count': len(TARGET_TECHNOLOGIES),
            'trained_at': datetime.now().isoformat(),
            'hyperparameters': {
                'n_estimators': n_estimators,
                'max_depth': max_depth,
                'min_samples_split': min_samples_split,
                'min_samples_leaf': min_samples_leaf,
                'max_features': max_features,
            }
        }
        
        # Add OOB score if available
        if hasattr(self.model, 'oob_score_'):
            metrics['oob_score'] = round(self.model.oob_score_, 4)
        
        # Add cross-validation results
        if cv_mean is not None:
            metrics['cv_mean'] = round(cv_mean, 4)
            metrics['cv_std'] = round(cv_std, 4)
            metrics['cv_scores'] = [round(s, 4) for s in cv_scores]
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            importances = list(zip(self.feature_names, self.model.feature_importances_))
            importances.sort(key=lambda x: x[1], reverse=True)
            metrics['top_features'] = importances[:10]
        
        self.metadata = metrics
        
        # Log results
        logger.info(f"Training complete.")
        logger.info(f"  Train accuracy: {train_accuracy:.2%}")
        logger.info(f"  Test accuracy: {test_accuracy:.2%}")
        logger.info(f"  Overfit gap: {overfit_gap:.2%}")
        if cv_mean:
            logger.info(f"  CV accuracy: {cv_mean:.2%} ± {cv_std:.2%}")
        if overfit_warning:
            logger.warning("  ⚠️ Overfitting detected! Consider more data or stronger regularization.")
        
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
