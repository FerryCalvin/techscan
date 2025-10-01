import unittest, pathlib, sys, time, os
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import scan_utils

class TestQuarantine(unittest.TestCase):
    def setUp(self):
        # Ensure environment for quick quarantine
        os.environ['TECHSCAN_QUARANTINE_FAILS'] = '1'
        os.environ['TECHSCAN_QUARANTINE_MINUTES'] = '0.001'  # ~0.06s
        # Disable preflight to not short-circuit
        os.environ['TECHSCAN_PREFLIGHT'] = '0'

    def test_quarantine_cycle(self):
        # Simulate failure recording then check quarantine triggers
        dom = 'example.com'
        scan_utils._record_failure(dom)
        self.assertTrue(scan_utils._check_quarantine(dom))
        # Wait for expiry
        time.sleep(0.2)
        self.assertFalse(scan_utils._check_quarantine(dom))
        # Success resets
        scan_utils._record_failure(dom)
        self.assertTrue(scan_utils._check_quarantine(dom))
        time.sleep(0.2)
        scan_utils._record_success(dom)
        self.assertFalse(scan_utils._check_quarantine(dom))

if __name__ == '__main__':
    unittest.main()
