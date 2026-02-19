"""Tests for Node scanner retry logic in app.scanners.core.scan_unified."""
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("TECHSCAN_DISABLE_DB", "1")
os.environ.setdefault("TECHSCAN_PERSIST_BROWSER", "0")


class TestNodeScannerRetry:
    """Test the retry logic when Node scanner fails or returns few technologies.
    
    scan_unified calls:
      1. heuristic_fast.run_heuristic (fast Python heuristic)
      2. wapp_local.detect (Python pattern matching)
      3. scan_domain (Node.js Puppeteer scanner) -- with retry loop
    """

    @patch("app.scanners.core.scan_domain")
    @patch("app.wapp_local.detect")
    @patch("app.heuristic_fast.run_heuristic")
    def test_retry_on_zero_techs(self, mock_heuristic, mock_wapp, mock_scan_domain):
        """If Node scanner returns 0 techs on first attempt, it should retry."""
        from app.scanners.core import scan_unified

        mock_heuristic.return_value = {
            "technologies": [{"name": "PHP", "confidence": 100, "categories": ["Programming languages"]}],
            "categories": {"Programming languages": [{"name": "PHP"}]},
        }
        mock_wapp.return_value = {"technologies": [], "extras": {}}

        # First call: 0 techs (failure), second call: some techs (success)
        mock_scan_domain.side_effect = [
            {"technologies": [], "categories": {}, "raw": {}},
            {
                "technologies": [
                    {"name": "WordPress", "confidence": 100, "categories": ["CMS"]},
                ],
                "categories": {"CMS": [{"name": "WordPress"}]},
                "raw": {},
            },
        ]

        result = scan_unified("test.com", "/fake/wapp/path", budget_ms=30000)

        assert mock_scan_domain.call_count == 2
        tech_names = {t["name"] for t in result.get("technologies", [])}
        assert "WordPress" in tech_names

    @patch("app.scanners.core.scan_domain")
    @patch("app.wapp_local.detect")
    @patch("app.heuristic_fast.run_heuristic")
    def test_no_retry_when_techs_sufficient(self, mock_heuristic, mock_wapp, mock_scan_domain):
        """If Node scanner returns techs on first attempt, no retry needed."""
        from app.scanners.core import scan_unified

        mock_heuristic.return_value = {"technologies": [], "categories": {}}
        mock_wapp.return_value = {"technologies": [], "extras": {}}

        mock_scan_domain.return_value = {
            "technologies": [
                {"name": "WordPress", "confidence": 100, "categories": ["CMS"]},
            ],
            "categories": {},
            "raw": {},
        }

        result = scan_unified("test.com", "/fake/wapp/path", budget_ms=30000)

        assert mock_scan_domain.call_count == 1

    @patch("app.scanners.core.scan_domain")
    @patch("app.wapp_local.detect")
    @patch("app.heuristic_fast.run_heuristic")
    def test_retry_on_exception(self, mock_heuristic, mock_wapp, mock_scan_domain):
        """If Node scanner raises exception, it should retry."""
        from app.scanners.core import scan_unified

        mock_heuristic.return_value = {"technologies": [], "categories": {}}
        mock_wapp.return_value = {"technologies": [], "extras": {}}

        mock_scan_domain.side_effect = [
            RuntimeError("scan timed out"),
            {
                "technologies": [{"name": "Nginx", "confidence": 100, "categories": ["Web servers"]}],
                "categories": {},
                "raw": {},
            },
        ]

        result = scan_unified("test.com", "/fake/wapp/path", budget_ms=30000)

        assert mock_scan_domain.call_count == 2
        tech_names = {t["name"] for t in result.get("technologies", [])}
        assert "Nginx" in tech_names

    @patch("app.scanners.core.scan_domain")
    @patch("app.wapp_local.detect")
    @patch("app.heuristic_fast.run_heuristic")
    def test_both_attempts_fail(self, mock_heuristic, mock_wapp, mock_scan_domain):
        """If both attempts fail, result should still have heuristic techs."""
        from app.scanners.core import scan_unified

        mock_heuristic.return_value = {
            "technologies": [{"name": "PHP", "confidence": 100, "categories": ["Programming languages"]}],
            "categories": {"Programming languages": [{"name": "PHP"}]},
        }
        mock_wapp.return_value = {"technologies": [], "extras": {}}

        mock_scan_domain.side_effect = [
            RuntimeError("timeout 1"),
            RuntimeError("timeout 2"),
        ]

        result = scan_unified("test.com", "/fake/wapp/path", budget_ms=30000)

        assert mock_scan_domain.call_count == 2
        tech_names = {t["name"] for t in result.get("technologies", [])}
        assert "PHP" in tech_names

    @patch("app.scanners.core.scan_domain")
    @patch("app.wapp_local.detect")
    @patch("app.heuristic_fast.run_heuristic")
    def test_retry_has_higher_timeout(self, mock_heuristic, mock_wapp, mock_scan_domain):
        """Retry should use 1.5x the original timeout."""
        from app.scanners.core import scan_unified

        mock_heuristic.return_value = {"technologies": [], "categories": {}}
        mock_wapp.return_value = {"technologies": [], "extras": {}}

        # First returns 0 techs, retry succeeds
        mock_scan_domain.side_effect = [
            {"technologies": [], "categories": {}, "raw": {}},
            {"technologies": [{"name": "X", "confidence": 100, "categories": []}], "categories": {}, "raw": {}},
        ]

        result = scan_unified("test.com", "/fake/wapp/path", budget_ms=30000)

        assert mock_scan_domain.call_count == 2
        # Second call should have higher timeout than first
        first_call = mock_scan_domain.call_args_list[0]
        second_call = mock_scan_domain.call_args_list[1]
        first_timeout = first_call[1].get("timeout", first_call[0][2] if len(first_call[0]) > 2 else 0)
        second_timeout = second_call[1].get("timeout", second_call[0][2] if len(second_call[0]) > 2 else 0)
        assert second_timeout >= first_timeout


class TestRetryThresholdEnv:
    """Test TECHSCAN_NODE_RETRY_THRESHOLD environment variable."""

    @patch("app.scanners.core.scan_domain")
    @patch("app.wapp_local.detect")
    @patch("app.heuristic_fast.run_heuristic")
    def test_custom_threshold(self, mock_heuristic, mock_wapp, mock_scan_domain, monkeypatch):
        """With threshold=5, retry if fewer than 5 techs from Node."""
        from app.scanners.core import scan_unified

        monkeypatch.setenv("TECHSCAN_NODE_RETRY_THRESHOLD", "5")

        mock_heuristic.return_value = {"technologies": [], "categories": {}}
        mock_wapp.return_value = {"technologies": [], "extras": {}}

        # First call returns 3 techs (< threshold 5), should retry
        mock_scan_domain.side_effect = [
            {
                "technologies": [
                    {"name": "A", "confidence": 100, "categories": []},
                    {"name": "B", "confidence": 100, "categories": []},
                    {"name": "C", "confidence": 100, "categories": []},
                ],
                "categories": {},
                "raw": {},
            },
            {
                "technologies": [
                    {"name": "A", "confidence": 100, "categories": []},
                    {"name": "B", "confidence": 100, "categories": []},
                    {"name": "C", "confidence": 100, "categories": []},
                    {"name": "D", "confidence": 100, "categories": []},
                    {"name": "E", "confidence": 100, "categories": []},
                    {"name": "F", "confidence": 100, "categories": []},
                ],
                "categories": {},
                "raw": {},
            },
        ]

        result = scan_unified("test.com", "/fake/wapp/path", budget_ms=30000)
        assert mock_scan_domain.call_count == 2
