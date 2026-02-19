
import os
import sys

try:
    from redis import Redis
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    print(f"Testing Redis at {redis_url}")
    r = Redis.from_url(redis_url)
    r.ping()
    print("Redis PING success")
except Exception as e:
    print(f"Redis connection failed: {e}")
    sys.exit(1)
