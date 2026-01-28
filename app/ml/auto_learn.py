"""Auto-learning module for ML classifier.

Automatically triggers retraining based on:
- Number of new scans since last training
- Time since last training
- Manual trigger

Environment variables:
- TECHSCAN_ML_AUTO_LEARN: Enable/disable auto-learning (default: 1)
- TECHSCAN_ML_RETRAIN_THRESHOLD: Scans before retraining (default: 50)
- TECHSCAN_ML_RETRAIN_HOURS: Hours before periodic retrain (default: 24)
"""

import os
import logging
import threading
from datetime import datetime

logger = logging.getLogger('techscan.ml.auto_learn')

# Configuration
AUTO_LEARN_ENABLED = os.environ.get('TECHSCAN_ML_AUTO_LEARN', '1') == '1'
RETRAIN_THRESHOLD = int(os.environ.get('TECHSCAN_ML_RETRAIN_THRESHOLD', '50'))
RETRAIN_HOURS = int(os.environ.get('TECHSCAN_ML_RETRAIN_HOURS', '24'))

# State tracking
_state = {
    'scans_since_training': 0,
    'last_training_time': None,
    'last_training_accuracy': None,
    'is_training': False,
    'training_lock': threading.Lock(),
}


def get_state() -> dict:
    """Get current auto-learn state."""
    return {
        'enabled': AUTO_LEARN_ENABLED,
        'scans_since_training': _state['scans_since_training'],
        'last_training_time': _state['last_training_time'].isoformat() if _state['last_training_time'] else None,
        'last_training_accuracy': _state['last_training_accuracy'],
        'is_training': _state['is_training'],
        'retrain_threshold': RETRAIN_THRESHOLD,
        'retrain_hours': RETRAIN_HOURS,
    }


def should_retrain() -> tuple[bool, str]:
    """Check if retraining should be triggered.
    
    Returns:
        Tuple of (should_retrain, reason)
    """
    if not AUTO_LEARN_ENABLED:
        return False, 'auto-learn disabled'
    
    if _state['is_training']:
        return False, 'already training'
    
    # Check scan threshold
    if _state['scans_since_training'] >= RETRAIN_THRESHOLD:
        return True, f'scan threshold reached ({_state["scans_since_training"]} >= {RETRAIN_THRESHOLD})'
    
    # Check time threshold
    if _state['last_training_time']:
        hours_since = (datetime.now() - _state['last_training_time']).total_seconds() / 3600
        if hours_since >= RETRAIN_HOURS:
            return True, f'time threshold reached ({hours_since:.1f}h >= {RETRAIN_HOURS}h)'
    
    return False, 'thresholds not reached'


def record_scan():
    """Record that a new scan was completed.
    
    Call this after each successful scan to track for auto-retraining.
    """
    if not AUTO_LEARN_ENABLED:
        return
    
    with _state['training_lock']:
        _state['scans_since_training'] += 1
    
    # Check if we should trigger retraining
    should, reason = should_retrain()
    if should:
        logger.info(f"Auto-retrain triggered: {reason}")
        _trigger_async_retrain()


def _trigger_async_retrain():
    """Trigger retraining in background thread."""
    def _retrain():
        try:
            _state['is_training'] = True
            logger.info("Starting auto-retrain...")
            
            from .training import train_combined
            metrics = train_combined(db_limit=300, demo_weight=0.7, save=True)
            
            with _state['training_lock']:
                _state['scans_since_training'] = 0
                _state['last_training_time'] = datetime.now()
                _state['last_training_accuracy'] = metrics.get('test_accuracy')
            
            logger.info(f"Auto-retrain complete. Accuracy: {metrics.get('test_accuracy', 0):.1%}")
            
        except Exception as e:
            logger.error(f"Auto-retrain failed: {e}")
        finally:
            _state['is_training'] = False
    
    thread = threading.Thread(target=_retrain, daemon=True)
    thread.start()


def force_retrain() -> dict:
    """Force immediate retraining.
    
    Returns:
        Training metrics
    """
    if _state['is_training']:
        return {'error': 'training already in progress'}
    
    try:
        _state['is_training'] = True
        logger.info("Force retrain triggered...")
        
        from .training import train_combined
        metrics = train_combined(db_limit=500, demo_weight=0.7, save=True)
        
        with _state['training_lock']:
            _state['scans_since_training'] = 0
            _state['last_training_time'] = datetime.now()
            _state['last_training_accuracy'] = metrics.get('test_accuracy')
        
        return metrics
        
    except Exception as e:
        logger.error(f"Force retrain failed: {e}")
        return {'error': str(e)}
    finally:
        _state['is_training'] = False


def reset_counter():
    """Reset the scan counter (e.g., after manual training)."""
    with _state['training_lock']:
        _state['scans_since_training'] = 0
        _state['last_training_time'] = datetime.now()
