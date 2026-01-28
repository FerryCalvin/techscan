import unittest, pathlib, sys
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import scan_utils

class TestFastFullStats(unittest.TestCase):
    def setUp(self):
        # Reset stats buckets between tests (lightweight approach)
        scan_utils.STATS['durations']['fast_full'] = {'count':0,'total':0.0}
        scan_utils.STATS['recent_samples']['fast_full'].clear()

    def test_stats_recorded_for_fast_full(self):
        fake_path = str(ROOT / 'node_scanner')
        with mock.patch('app.scanners.core.scan_domain') as mscan:
            mscan.return_value = {
                'domain': 'example.com',
                'technologies': [],
                'categories': {},
                'raw': {}
            }
            res = scan_utils.fast_full_scan('example.com', fake_path)
            self.assertEqual(res.get('engine'), 'fast-full')
        # After call, stats should have at least one fast_full sample
        stats = scan_utils.get_stats()
        self.assertIn('fast_full', stats['average_duration_ms'])
        self.assertGreater(stats['average_duration_ms']['fast_full'], 0)
        self.assertIn('fast_full', stats['recent_latency_ms'])
        self.assertGreater(stats['recent_latency_ms']['fast_full']['samples'], 0)

if __name__ == '__main__':
    unittest.main()
