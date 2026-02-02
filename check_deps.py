
import sys

def check(name, package=None):
    pkg = package or name
    try:
        __import__(pkg)
        print(f"{name}: INSTALLED")
    except ImportError:
        print(f"{name}: MISSING")

print("--- Dependency Check ---")
check("redis")
check("rq")
check("psycopg_pool")
