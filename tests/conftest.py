import sys
import pathlib

import pytest

# Ensure project root is on sys.path so 'import app' works when pytest runs from
# different working directories or when running individual tests.
_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.testing = True
    return app.test_client()
