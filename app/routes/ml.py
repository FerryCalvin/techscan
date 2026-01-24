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


@bp.route('/train/combined', methods=['POST'])
def train_combined():
    """Train model with combined demo + database data.
    
    This approach uses synthetic demo data as a strong foundation
    and augments with real database scan data for better generalization.
    
    Request body (optional):
    {
        "db_limit": 300,      // max database scans to include
        "demo_weight": 0.7    // weight of demo data (0.0-1.0)
    }
    """
    try:
        from ..ml.training import train_combined as _train_combined
    except ImportError as e:
        return jsonify({
            'error': 'ML modules not available',
            'message': str(e)
        }), 503
    
    data = request.get_json() or {}
    db_limit = int(data.get('db_limit', 300))
    demo_weight = float(data.get('demo_weight', 0.7))
    
    try:
        metrics = _train_combined(db_limit=db_limit, demo_weight=demo_weight)
        return jsonify({
            'status': 'success',
            'type': 'combined',
            'metrics': metrics
        })
    except Exception as e:
        logger.error(f"Combined training error: {e}")
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


@bp.route('/hybrid_scan', methods=['POST'])
def hybrid_scan():
    """Hybrid scan: ML prediction + unified scan, merged and deduplicated.
    
    This endpoint:
    1. Runs ML prediction (instant)
    2. Runs unified scan (thorough)
    3. Merges results, keeps highest confidence per technology
    4. Returns combined, deduplicated results
    
    Request body:
    {
        "domain": "example.com",  // required
        "ml_threshold": 0.3,      // optional, default 0.3
        "include_raw": false      // optional, include raw results
    }
    
    Response:
    {
        "domain": "example.com",
        "technologies": [...],
        "sources": {"ml": 5, "unified": 20},
        "duration_ms": 1234
    }
    """
    import time
    start_time = time.time()
    
    data = request.get_json() or {}
    domain = data.get('domain', '').strip()
    ml_threshold = float(data.get('ml_threshold', 0.3))
    include_raw = data.get('include_raw', False)
    
    if not domain:
        return jsonify({'error': 'domain is required'}), 400
    
    # Normalize domain
    if not domain.startswith('http'):
        url = f'https://{domain}'
    else:
        url = domain
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    
    results = {
        'domain': domain,
        'technologies': [],
        'sources': {'ml': 0, 'unified': 0},
        'ml_predictions': [],
        'unified_results': [],
    }
    
    # Step 1: ML Prediction (fast)
    try:
        classifier = _get_classifier()
        extractor = _get_feature_extractor()
        
        # Fetch HTML
        resp = requests.get(url, timeout=15, headers={
            'User-Agent': 'TechScan Hybrid/1.0'
        })
        html = resp.text
        headers = dict(resp.headers)
        
        # ML predictions
        ml_predictions = classifier.predict(html, headers, threshold=ml_threshold)
        results['ml_predictions'] = ml_predictions
        results['sources']['ml'] = len(ml_predictions)
        
        logger.info(f"Hybrid scan {domain}: ML found {len(ml_predictions)} technologies")
        
    except Exception as e:
        logger.warning(f"ML prediction failed for {domain}: {e}")
        ml_predictions = []
    
    # Step 2: Unified Scan (thorough)
    try:
        from ..scan_utils import scan_unified
        
        unified_result = scan_unified(domain)
        unified_techs = unified_result.get('technologies', [])
        results['unified_results'] = unified_techs
        results['sources']['unified'] = len(unified_techs)
        
        logger.info(f"Hybrid scan {domain}: Unified found {len(unified_techs)} technologies")
        
    except Exception as e:
        logger.warning(f"Unified scan failed for {domain}: {e}")
        unified_techs = []
    
    # Step 3: Merge and deduplicate
    tech_map = {}  # name_lower -> best result
    
    # Add ML predictions
    for pred in ml_predictions:
        name = pred.get('name', '')
        name_lower = name.lower()
        confidence = pred.get('confidence', 0)
        
        if name_lower not in tech_map or confidence > tech_map[name_lower].get('confidence', 0):
            tech_map[name_lower] = {
                'name': name,
                'confidence': confidence,
                'source': 'ml',
                'version': None,
                'categories': []
            }
    
    # Add/update with unified results
    for tech in unified_techs:
        name = tech.get('name', '')
        name_lower = name.lower()
        confidence = tech.get('confidence', 0)
        
        existing = tech_map.get(name_lower)
        if not existing or confidence > existing.get('confidence', 0):
            tech_map[name_lower] = {
                'name': name,
                'confidence': confidence,
                'source': 'unified' if not existing else 'both',
                'version': tech.get('version'),
                'categories': tech.get('categories', [])
            }
        elif existing and existing.get('source') == 'ml':
            # Update source to 'both' if unified also found it
            existing['source'] = 'both'
            # Use unified's version/categories (more reliable)
            if tech.get('version'):
                existing['version'] = tech.get('version')
            if tech.get('categories'):
                existing['categories'] = tech.get('categories')
    
    # Convert to sorted list
    merged = sorted(tech_map.values(), key=lambda x: -x.get('confidence', 0))
    results['technologies'] = merged
    
    # Calculate duration
    duration_ms = int((time.time() - start_time) * 1000)
    results['duration_ms'] = duration_ms
    results['tech_count'] = len(merged)
    
    # Remove raw if not requested
    if not include_raw:
        del results['ml_predictions']
        del results['unified_results']
    
    return jsonify(results)

