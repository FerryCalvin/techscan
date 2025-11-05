import logging
import threading
import time
from typing import Dict, Tuple

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
