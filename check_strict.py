
try:
    from psycopg_pool import ConnectionPool
    print("psycopg_pool.ConnectionPool: OK")
except Exception as e:
    print(f"psycopg_pool.ConnectionPool: FAILED - {e}")

try:
    from redis import Redis
    from rq import Queue
    print("rq.Queue: OK")
except Exception as e:
    print(f"rq.Queue: FAILED - {e}")
