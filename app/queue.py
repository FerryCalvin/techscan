import os
import logging

_redis_conn = None
_queue = None
_rq_available = False

try:
    from redis import Redis
    from rq import Queue

    _rq_available = True
except ImportError as e:
    logging.getLogger("techscan").warning(f"rq/redis not installed - background queue disabled. Error: {e}")
    Redis = None
    Queue = None


def is_available():
    """Check if RQ is available and configured."""
    return _rq_available


def get_redis_connection():
    global _redis_conn
    if not _rq_available:
        raise RuntimeError("rq/redis not installed")
    if _redis_conn is None:
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        _redis_conn = Redis.from_url(redis_url)
    return _redis_conn


def get_queue(name="default"):
    global _queue
    if not _rq_available:
        raise RuntimeError("rq/redis not installed")
    if _queue is None:
        conn = get_redis_connection()
        _queue = Queue(name, connection=conn)
    return _queue
