import subprocess
import sys
import os
import shlex


def test_playwright_smoke_runs_and_detects_fallback():
    """Run the playwright smoke script and assert basic expectations.

    This test expects the dev server to be running at http://localhost:5000
    and that the smoke script will abort /api/stats to simulate failure.
    It asserts the page loads (HTTP 200) and that the client logged a stats fetch failure.
    """
    script = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'playwright_smoke.py')
    script = os.path.abspath(script)
    # Use the current python executable (should be venv python when running pytest from venv)
    cmd = [sys.executable, script]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    out = proc.stdout.decode('utf-8', errors='replace')
    # Debug output on failure
    if proc.returncode != 0:
        print('Playwright smoke exit code:', proc.returncode)
        print(out)
    # Basic assertions
    assert proc.returncode == 0, 'Playwright smoke script failed; see output above.'
    assert 'HTTP status: 200' in out, 'Expected stats page to load (HTTP 200). Output:\n' + out
    assert 'stats fetch failed' in out or 'Failed to fetch' in out, 'Expected client to log stats fetch failure when API aborted.'
