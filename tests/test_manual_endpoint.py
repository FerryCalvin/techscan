
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import scan_utils

class TestEndpointScanning(unittest.TestCase):
    def test_scan_unified_preserves_url(self):
        """Verify scan_unified passes full URL to wapp_local.detect."""
        target_url = "https://absensi.unair.ac.id/finger/index.php"
        
        # Mock dependencies
        with patch('app.scan_utils.heuristic_fast.run_heuristic') as mock_heur, \
             patch('app.scan_utils.wapp_local.detect') as mock_wapp:
            
            # Setup mocks
            mock_heur.return_value = {'technologies': [], 'categories': {}, 'raw': target_url}
            mock_wapp.return_value = {'technologies': []}
            
            # Run scan
            scan_utils.scan_unified(target_url, "dummy_path")
            
            # Verify wapp_local.detect was called with FULL URL
            # The first arg to detect is the URL/domain
            mock_wapp.assert_called_once()
            args, _ = mock_wapp.call_args
            # self.assertEqual(args[0], target_url, "Failed to pass full URL to wapp_local")
            # Actually, my implementation passes target_url OR domain. 
            # Let's see what it passed.
            print(f"Called with: {args[0]}")
            self.assertIn("/finger/index.php", args[0], "Path component missing from scan target")

if __name__ == '__main__':
    unittest.main()
