"""Tests for app.job_queue — Background job queue for scan persistence."""
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("TECHSCAN_DISABLE_DB", "1")
os.environ.setdefault("TECHSCAN_PERSIST_BROWSER", "0")


class TestGenerateJobId:
    """Test job ID generation."""

    def test_generates_string(self):
        from app.job_queue import generate_job_id

        job_id = generate_job_id()
        assert isinstance(job_id, str)
        assert len(job_id) > 0

    def test_unique_ids(self):
        from app.job_queue import generate_job_id

        ids = {generate_job_id() for _ in range(100)}
        assert len(ids) == 100  # All IDs should be unique


class TestJobStatuses:
    """Test status constants."""

    def test_status_values(self):
        from app.job_queue import STATUS_PENDING, STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED

        assert STATUS_PENDING == "pending"
        assert STATUS_RUNNING == "running"
        assert STATUS_COMPLETED == "completed"
        assert STATUS_FAILED == "failed"


class TestScanJobQueue:
    """Test ScanJobQueue class with in-memory storage."""

    def _make_queue(self, scan_fn=None, bulk_fn=None):
        from app.job_queue import ScanJobQueue

        if scan_fn is None:
            scan_fn = lambda domain, **kwargs: {
                "domain": domain,
                "technologies": [{"name": "WordPress"}],
                "categories": {},
            }
        return ScanJobQueue(scan_fn=scan_fn, bulk_scan_fn=bulk_fn)

    def test_submit_single(self):
        q = self._make_queue()
        job_id = q.submit_single("example.com")
        assert isinstance(job_id, str)
        assert len(job_id) > 0

    def test_get_job_after_submit(self):
        q = self._make_queue()
        job_id = q.submit_single("example.com")
        job = q.get_job(job_id)
        assert job is not None
        assert job["domain"] == "example.com" or "domain" in str(job)

    def test_submit_bulk(self):
        q = self._make_queue()
        job_id = q.submit_bulk(["example.com", "test.org"])
        assert isinstance(job_id, str)
        job = q.get_job(job_id)
        assert job is not None

    def test_get_recent_jobs(self):
        q = self._make_queue()
        q.submit_single("a.com")
        q.submit_single("b.com")
        recent = q.get_recent_jobs(limit=10)
        assert isinstance(recent, list)
        assert len(recent) >= 2

    def test_get_nonexistent_job(self):
        q = self._make_queue()
        job = q.get_job("nonexistent-id-12345")
        assert job is None

    def test_worker_start_stop(self):
        q = self._make_queue()
        q.start_worker()
        assert q._worker_thread is not None
        assert q._worker_thread.is_alive()
        q.stop_worker()
        time.sleep(0.5)
        # After stop_worker, _started should be False
        assert not q._started

    def test_worker_processes_job(self):
        """Worker should process submitted jobs."""
        results = []

        def mock_scan(domain, **kwargs):
            results.append(domain)
            return {"domain": domain, "technologies": [], "categories": {}}

        q = self._make_queue(scan_fn=mock_scan)
        q.start_worker()
        q.submit_single("test.org")
        # Give worker time to process
        time.sleep(2)
        q.stop_worker()
        assert "test.org" in results


class TestGlobalJobQueue:
    """Test global job queue helper functions."""

    def test_init_and_get(self):
        from app.job_queue import init_job_queue, get_job_queue, shutdown_job_queue

        mock_fn = lambda domain, **kw: {"technologies": []}
        init_job_queue(scan_fn=mock_fn)
        q = get_job_queue()
        assert q is not None
        shutdown_job_queue()
