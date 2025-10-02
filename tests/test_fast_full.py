import unittest, pathlib, sys, os, time
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import scan_utils

class TestFastFullScan(unittest.TestCase):
    def setUp(self):
        # Provide a dummy wappalyzer path; tests monkeypatch scan_domain
        self.fake_path = str(ROOT / 'node_scanner')

    def test_fast_full_success(self):
        # Monkeypatch scan_domain to simulate quick successful full scan
        with mock.patch('app.scan_utils.scan_domain') as mscan:
            mscan.return_value = {
                'domain': 'example.com',
                'technologies': [{'name':'TestTech','version':'1.0','categories':['Test'], 'confidence':50}],
                'categories': {'Test':[{'name':'TestTech','version':'1.0'}]},
                'raw': {}
            }
            res = scan_utils.fast_full_scan('example.com', self.fake_path)
            self.assertEqual(res.get('engine'), 'fast-full')
            self.assertFalse(res.get('phases',{}).get('partial'))
            self.assertIn('full_ms', res.get('phases', {}))
            mscan.assert_called_once()

    def test_fast_full_timeout_fallback(self):
        # Simulate scan_domain raising timeout, then heuristic fallback returns minimal
        with mock.patch('app.scan_utils.scan_domain', side_effect=RuntimeError('timeout after 5s')):
            with mock.patch('app.scan_utils.quick_single_scan') as mquick:
                mquick.return_value = {
                    'domain': 'example.com',
                    'technologies': [],
                    'categories': {},
                    'tiered': {}
                }
                res = scan_utils.fast_full_scan('example.com', self.fake_path)
                self.assertEqual(res.get('engine'), 'fast-full-partial')
                self.assertTrue(res.get('phases',{}).get('partial'))
                self.assertIn('error', res.get('phases', {}))
                mquick.assert_called_once()

    def test_fast_full_budget_floor(self):
        # Ensure extremely low env budget is coerced to minimum
        os.environ['TECHSCAN_FAST_FULL_TIMEOUT_MS'] = '300'  # lower than floor
        with mock.patch('app.scan_utils.scan_domain') as mscan:
            mscan.return_value = {
                'domain': 'example.com',
                'technologies': [],
                'categories': {},
                'raw': {}
            }
            res = scan_utils.fast_full_scan('example.com', self.fake_path)
            # Timeout rounded up to at least 1 second, so scan_domain called with timeout>=1
            args, kwargs = mscan.call_args
            self.assertGreaterEqual(kwargs.get('timeout') or args[2], 1)
        os.environ.pop('TECHSCAN_FAST_FULL_TIMEOUT_MS', None)

if __name__ == '__main__':
    unittest.main()
