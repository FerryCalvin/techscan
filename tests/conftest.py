import sys
import os
import pathlib
import socket
import threading
import time
import warnings

# Filter noisy warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="pythonjsonlogger")
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

import pytest
from werkzeug.serving import make_server

# Ensure project root is on sys.path so 'import app' works when pytest runs from
# different working directories or when running individual tests.
_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Set test environment config BEFORE importing app to ensure it picks up
# static configuration (if any)
os.environ["TECHSCAN_ADMIN_OPEN"] = "1"
os.environ["TECHSCAN_DISABLE_RQ"] = "1"
os.environ["TECHSCAN_DISABLE_DB"] = "1"
if "TECHSCAN_ADMIN_TOKEN" in os.environ:
    del os.environ["TECHSCAN_ADMIN_TOKEN"]

from app import create_app


def _port_open(host: str, port: int, timeout: float = 0.2) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def _wait_for_server(host: str, port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(host, port):
            return True
        time.sleep(0.1)
    return _port_open(host, port)


@pytest.fixture(scope="session", autouse=True)
def _ensure_stats_server():
    """Start a lightweight Flask server for Playwright stats tests if none running."""
    host = os.environ.get("TECHSCAN_TEST_SERVER_HOST", "127.0.0.1")
    port = int(os.environ.get("TECHSCAN_TEST_SERVER_PORT", "5000"))
    if _port_open(host, port):
        # Something (maybe developer server) already listens; reuse it.
        yield
        return
    # Bypass admin token check for tests
    os.environ["TECHSCAN_ADMIN_OPEN"] = "1"
    os.environ["TECHSCAN_DISABLE_RQ"] = "1"
    app = create_app()
    app.testing = True
    server = make_server(host, port, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if not _wait_for_server(host, port):
        server.shutdown()
        thread.join(timeout=1)
        raise RuntimeError(f"Failed to start test server at http://{host}:{port}")
    try:
        yield
    finally:
        try:
            server.shutdown()
        except Exception:
            pass
        thread.join(timeout=2)


@pytest.fixture
def client():
    os.environ["TECHSCAN_ADMIN_OPEN"] = "1"
    os.environ["TECHSCAN_DISABLE_RQ"] = "1"
    app = create_app()
    app.testing = True
    return app.test_client()
