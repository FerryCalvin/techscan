"""Tests for app.metrics — Prometheus metrics with stub fallback."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("TECHSCAN_DISABLE_DB", "1")
os.environ.setdefault("TECHSCAN_PERSIST_BROWSER", "0")


class TestStubMetrics:
    """Test that stub metrics work when prometheus_client is not available."""

    def test_record_scan_does_not_raise(self):
        from app.metrics import record_scan

        # Should not raise even without prometheus_client
        record_scan(mode="single", status="success", duration=1.5, tech_count=10, domain="test.com")

    def test_record_error_does_not_raise(self):
        from app.metrics import record_error

        record_error(error_type="timeout")

    def test_track_active_scan_context_manager(self):
        from app.metrics import track_active_scan

        tracker = track_active_scan()
        with tracker as t:
            assert hasattr(t, "start_time")
            assert t.duration >= 0

    def test_get_metrics_returns_bytes(self):
        from app.metrics import get_metrics

        result = get_metrics()
        assert isinstance(result, bytes)

    def test_get_content_type_returns_string(self):
        from app.metrics import get_content_type

        ct = get_content_type()
        assert isinstance(ct, str)


class TestMetricLabels:
    """Test metric label operations don't crash."""

    def test_scan_total_labels(self):
        from app.metrics import SCAN_TOTAL

        labeled = SCAN_TOTAL.labels(mode="single", status="success")
        # Should be callable
        labeled.inc()

    def test_errors_total_labels(self):
        from app.metrics import ERRORS_TOTAL

        labeled = ERRORS_TOTAL.labels(error_type="timeout")
        labeled.inc()

    def test_scan_duration_observe(self):
        from app.metrics import SCAN_DURATION

        labeled = SCAN_DURATION.labels(mode="single")
        labeled.observe(2.5)

    def test_active_scans_inc_dec(self):
        from app.metrics import ACTIVE_SCANS

        ACTIVE_SCANS.inc()
        ACTIVE_SCANS.dec()

    def test_cache_hits_inc(self):
        from app.metrics import CACHE_HITS, CACHE_MISSES

        CACHE_HITS.inc()
        CACHE_MISSES.inc()

    def test_enrichment_metrics(self):
        from app.metrics import ENRICHMENT_HINTS, ENRICHMENT_MERGE

        ENRICHMENT_HINTS.inc()
        ENRICHMENT_MERGE.inc()
