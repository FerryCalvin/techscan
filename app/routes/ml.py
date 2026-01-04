"""ML API routes for technology prediction and model management.

Endpoints:
- POST /ml/predict - Predict technologies from HTML/URL
- POST /ml/train - Train model from database
- POST /ml/train/demo - Train with demo data
- GET /ml/status - Get model status
"""

from flask import Blueprint, request, jsonify, current_app
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger('techscan.ml.api')

bp = Blueprint('ml', __name__, url_prefix='/ml')


def _get_classifier():
    """Lazy import to avoid circular imports."""
    from ..ml.classifier import get_classifier
    return get_classifier()


def _get_feature_extractor():
    """Lazy import feature extractor."""
    from ..ml.features import get_extractor
    return get_extractor()


@bp.route('/status', methods=['GET'])
def status():
    """Get ML classifier status."""
    try:
        classifier = _get_classifier()
        return jsonify(classifier.get_status())
    except ImportError as e:
        return jsonify({
            'error': 'scikit-learn not installed',
            'message': str(e),
            'install_command': 'pip install scikit-learn'
        }), 503
    except Exception as e:
        logger.error(f"ML status error: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/predict', methods=['POST'])
def predict():
    """Predict technologies from HTML or URL.
    
    Request body:
    {
        "url": "https://example.com",  // OR
        "html": "<html>...</html>",
        "headers": {"key": "value"},  // optional
        "threshold": 0.3  // optional, default 0.3
    }
    
    Response:
    {
        "predictions": [
            {"name": "WordPress", "confidence": 85.2, "source": "ml-classifier"},
            ...
        ],
        "features_extracted": 45,
        "model_trained": true
    }
    """
    try:
        classifier = _get_classifier()
    except ImportError as e:
        return jsonify({
            'error': 'scikit-learn not installed',
            'install_command': 'pip install scikit-learn'
        }), 503
    
    data = request.get_json() or {}
    
    html = data.get('html', '')
    headers = data.get('headers', {})
    threshold = float(data.get('threshold', 0.3))
    url = data.get('url', '')
    
    # Fetch HTML if URL provided
    if url and not html:
        try:
            resp = requests.get(url, timeout=10, headers={
                'User-Agent': 'TechScan ML/1.0'
            })
            html = resp.text
            headers = dict(resp.headers)
        except Exception as e:
            return jsonify({'error': f'Failed to fetch URL: {e}'}), 400
    
    if not html:
        return jsonify({'error': 'No HTML content provided'}), 400
    
    # Extract features
    extractor = _get_feature_extractor()
    features = extractor.extract_all(html, headers)
    
    # Make predictions
    predictions = classifier.predict(html, headers, threshold=threshold)
    
    return jsonify({
        'predictions': predictions,
        'features_extracted': len(features),
        'model_trained': classifier.is_trained,
        'threshold': threshold
    })


@bp.route('/features', methods=['POST'])
def extract_features():
    """Extract features from HTML without prediction.
    
    Useful for debugging and understanding what features are detected.
    """
    data = request.get_json() or {}
    
    html = data.get('html', '')
    headers = data.get('headers', {})
    url = data.get('url', '')
    
    if url and not html:
        try:
            resp = requests.get(url, timeout=10, headers={
                'User-Agent': 'TechScan ML/1.0'
            })
            html = resp.text
            headers = dict(resp.headers)
        except Exception as e:
            return jsonify({'error': f'Failed to fetch URL: {e}'}), 400
    
    if not html:
        return jsonify({'error': 'No HTML content provided'}), 400
    
    extractor = _get_feature_extractor()
    features = extractor.extract_all(html, headers)
    
    # Group features by category for readability
    grouped = {
        'html_structure': {k: v for k, v in features.items() if k.startswith(('html_', 'has_doctype', 'script_', 'link_', 'meta_', 'div_', 'img_', 'form_', 'iframe_', 'js_', 'css_'))},
        'headers': {k: v for k, v in features.items() if k.startswith(('header_', 'has_server', 'has_x_', 'has_content', 'has_cache', 'has_security', 'server_', 'powered_'))},
        'patterns': {k: v for k, v in features.items() if k.startswith('pattern_')},
        'detected': {k: v for k, v in features.items() if k.startswith('has_') and not k.startswith(('has_doctype', 'has_server', 'has_x_', 'has_content', 'has_cache', 'has_security'))},
        'meta': {k: v for k, v in features.items() if k.startswith('has_generator') or k.startswith('has_og') or k.startswith('has_twitter') or k.startswith('has_schema')},
    }
    
    return jsonify({
        'features': features,
        'grouped': grouped,
        'feature_count': len(features)
    })


@bp.route('/train', methods=['POST'])
def train():
    """Train model from database scans.
    
    Request body (optional):
    {
        "limit": 500,  // max scans to use
        "save": true   // save model after training
    }
    """
    try:
        from ..ml.training import train_from_database
    except ImportError as e:
        return jsonify({
            'error': 'ML modules not available',
            'message': str(e)
        }), 503
    
    data = request.get_json() or {}
    limit = int(data.get('limit', 500))
    save = data.get('save', True)
    
    try:
        metrics = train_from_database(limit=limit, save=save)
        return jsonify({
            'status': 'success',
            'metrics': metrics
        })
    except Exception as e:
        logger.error(f"Training error: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/train/demo', methods=['POST'])
def train_demo():
    """Train model with demo data (for testing).
    
    This creates synthetic training data and trains a model.
    Useful for testing the ML pipeline without real data.
    """
    try:
        from ..ml.training import train_demo as _train_demo
    except ImportError as e:
        return jsonify({
            'error': 'ML modules not available',
            'message': str(e)
        }), 503
    
    try:
        metrics = _train_demo()
        return jsonify({
            'status': 'success',
            'type': 'demo',
            'metrics': metrics
        })
    except Exception as e:
        logger.error(f"Demo training error: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/model/info', methods=['GET'])
def model_info():
    """Get detailed model information."""
    try:
        classifier = _get_classifier()
        status = classifier.get_status()
        
        # Add feature names
        from ..ml.features import FeatureExtractor
        status['feature_names'] = FeatureExtractor.get_feature_names()
        
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
