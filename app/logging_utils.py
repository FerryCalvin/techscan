import logging
import threading
import time
import os
from typing import Dict, Tuple, Optional
from datetime import datetime

# Try to import python-json-logger, fallback to custom implementation
try:
    try:
        from pythonjsonlogger import json as jsonlogger
    except ImportError:
        from pythonjsonlogger import jsonlogger
    HAS_JSON_LOGGER = True
except ImportError:
    HAS_JSON_LOGGER = False


class TechScanJsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging.
    
    Outputs log records as single-line JSON with consistent fields:
    - timestamp: ISO 8601 format
    - level: Log level name
    - logger: Logger name
    - message: Log message
    - Additional fields from record extras
    """
    
    def format(self, record: logging.LogRecord) -> str:
        import json
        
        log_obj = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        # Add exception info if present
        if record.exc_info:
            log_obj['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields commonly used in techscan
        for key in ('domain', 'duration', 'tech_count', 'status', 'error', 
                    'batch_id', 'scan_mode', 'retries', 'payload_bytes'):
            if hasattr(record, key):
                log_obj[key] = getattr(record, key)
        
        return json.dumps(log_obj, ensure_ascii=False)


def get_formatter(log_format: Optional[str] = None) -> logging.Formatter:
    """Get appropriate log formatter based on format setting.
    
    Args:
        log_format: 'json' for JSON output, anything else for text
    
    Returns:
        logging.Formatter instance
    """
    if log_format is None:
        log_format = os.environ.get('TECHSCAN_LOG_FORMAT', 'text')
    
    if log_format.lower() == 'json':
        if HAS_JSON_LOGGER:
            # Use python-json-logger if available
            return jsonlogger.JsonFormatter(
                '%(timestamp)s %(level)s %(name)s %(message)s',
                rename_fields={'levelname': 'level', 'name': 'logger'},
                timestamp=True
            )
        else:
            # Use custom formatter
            return TechScanJsonFormatter()
    else:
        # Default text formatter
        return logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')


_SuppressionKey = Tuple[str, str, int]
_SuppressionState = Dict[str, float | int]

_SUPPRESSION_LOCK = threading.Lock()
_SUPPRESSION_STATE: Dict[_SuppressionKey, _SuppressionState] = {}


def log_suppressed(
    logger: logging.Logger,
    exc: Exception,
    context: str,
    *,
    level: int = logging.DEBUG,
    sample: int = 5,
    cooldown: float = 120.0,
) -> int:
    """Emit a throttled log entry for repeated soft-failures.

    Parameters
    ----------
    logger: logging.Logger
        Target logger to write into.
    exc: Exception
        Exception instance that triggered the suppression log.
    context: str
        Human-readable identifier so we can aggregate per-failure site.
    level: int
        Logging level; defaults to ``DEBUG``.
    sample: int
        Emit the first ``sample`` occurrences before throttling kicks in.
    cooldown: float
        Minimum seconds between emissions once the initial sample budget is
        exhausted. Acts as a rate limit for noisy contexts.

    Returns
    -------
    int
        Total number of times this ``context`` has requested logging (including
        suppressed writes). Caller can use this to feed ancillary metrics.
    """
    now = time.time()
    key: _SuppressionKey = (logger.name, context, level)
    with _SUPPRESSION_LOCK:
        state = _SUPPRESSION_STATE.setdefault(key, {'count': 0, 'last_emit': 0.0})
        state['count'] = int(state['count']) + 1
        count = int(state['count'])
        last_emit = float(state.get('last_emit', 0.0))
        should_emit = count <= sample or (now - last_emit) >= cooldown
        if should_emit:
            state['last_emit'] = now
    if should_emit:
        logger.log(level, '%s err=%s (suppressed=%d)', context, exc, max(0, count - 1), exc_info=True)
    return count


def get_suppressed_snapshot() -> Dict[str, Dict[str, float | int]]:
    """Return a shallow copy of suppression counters for observability."""
    with _SUPPRESSION_LOCK:
        snapshot: Dict[str, Dict[str, float | int]] = {}
        for (logger_name, context, level), state in _SUPPRESSION_STATE.items():
            key = f'{logger_name}:{context}:{level}'
            snapshot[key] = {
                'count': int(state.get('count', 0)),
                'last_emit': float(state.get('last_emit', 0.0)),
            }
    return snapshot


def reset_suppressed_state() -> None:
    """Clear suppression counters. Useful for unit tests."""
    with _SUPPRESSION_LOCK:
        _SUPPRESSION_STATE.clear()
