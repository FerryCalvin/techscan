import os
import sys
from rq import Worker, Queue, Connection
from redis import Redis
import logging

# Ensure app is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app

listen = ['default']

def start_worker():
    redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
    conn = Redis.from_url(redis_url)

    # Preload app context so DB/logging is configured
    app = create_app()
    app.app_context().push()
    
    # Configure logging for worker
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('rq.worker')
    logger.info(f"RQ Worker starting, listening on {listen}")

    with Connection(conn):
        worker = Worker(map(Queue, listen))
        worker.work()

if __name__ == '__main__':
    start_worker()
