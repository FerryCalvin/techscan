"""Background Job Queue for Scan Persistence.

Allows scans to continue running even when user navigates away from the page.
Jobs are stored in database and processed by background worker thread.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional

logger = logging.getLogger('techscan.job_queue')

# In-memory job store (fallback when DB disabled)
_memory_jobs: Dict[str, dict] = {}
_memory_lock = threading.Lock()

# Job statuses
STATUS_PENDING = 'pending'
STATUS_RUNNING = 'running'
STATUS_COMPLETED = 'completed'
STATUS_FAILED = 'failed'


def generate_job_id() -> str:
    """Generate unique job ID."""
    return f"job_{uuid.uuid4().hex[:12]}_{int(time.time())}"


class ScanJobQueue:
    """Background job queue for scan operations.
    
    Manages job submission, status tracking, and background processing.
    Works with both database storage and in-memory fallback.
    """
    
    def __init__(self, scan_fn: Callable = None, bulk_scan_fn: Callable = None):
        """Initialize job queue.
        
        Args:
            scan_fn: Function to call for single domain scan
            bulk_scan_fn: Function to call for bulk domain scan
        """
        self._scan_fn = scan_fn
        self._bulk_scan_fn = bulk_scan_fn
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._job_queue: List[str] = []
        self._queue_lock = threading.Lock()
        self._started = False
    
    def start_worker(self):
        """Start background worker thread."""
        if self._started:
            return
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        self._started = True
        logger.info("Job queue worker started")
    
    def stop_worker(self):
        """Stop background worker thread."""
        if not self._started:
            return
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)
        self._started = False
        logger.info("Job queue worker stopped")
    
    def submit_single(self, domain: str, options: dict = None) -> str:
        """Submit a single domain scan job.
        
        Returns job_id immediately. Scan runs in background.
        """
        job_id = generate_job_id()
        job = {
            'id': job_id,
            'type': 'single',
            'status': STATUS_PENDING,
            'domains': json.dumps([domain]),
            'domain': domain,  # convenience field
            'options': json.dumps(options or {}),
            'progress': 0,
            'total': 1,
            'completed': 0,
            'result': None,
            'error': None,
            'created_at': time.time(),
            'updated_at': time.time(),
            'finished_at': None,
        }
        self._save_job(job)
        self._enqueue(job_id)
        logger.info(f"Single scan job submitted: {job_id} for {domain}")
        return job_id
    
    def submit_bulk(self, domains: List[str], options: dict = None) -> str:
        """Submit a bulk domain scan job.
        
        Returns job_id immediately. Scans run in background.
        """
        job_id = generate_job_id()
        # Dedupe and clean domains
        clean_domains = list(dict.fromkeys([d.strip().lower() for d in domains if d.strip()]))
        job = {
            'id': job_id,
            'type': 'bulk',
            'status': STATUS_PENDING,
            'domains': json.dumps(clean_domains),
            'options': json.dumps(options or {}),
            'progress': 0,
            'total': len(clean_domains),
            'completed': 0,
            'result': None,
            'results': json.dumps([]),  # per-domain results
            'error': None,
            'created_at': time.time(),
            'updated_at': time.time(),
            'finished_at': None,
        }
        self._save_job(job)
        self._enqueue(job_id)
        logger.info(f"Bulk scan job submitted: {job_id} for {len(clean_domains)} domains")
        return job_id
    
    def get_job(self, job_id: str) -> Optional[dict]:
        """Get job status by ID."""
        return self._load_job(job_id)
    
    def get_recent_jobs(self, limit: int = 20) -> List[dict]:
        """Get recent jobs for status display."""
        # For simplicity, return from memory store
        with _memory_lock:
            jobs = list(_memory_jobs.values())
        jobs.sort(key=lambda j: j.get('created_at', 0), reverse=True)
        return jobs[:limit]
    
    def _enqueue(self, job_id: str):
        """Add job to processing queue."""
        with self._queue_lock:
            if job_id not in self._job_queue:
                self._job_queue.append(job_id)
    
    def _dequeue(self) -> Optional[str]:
        """Get next job from queue."""
        with self._queue_lock:
            if self._job_queue:
                return self._job_queue.pop(0)
            return None
    
    def _worker_loop(self):
        """Background worker loop."""
        logger.info("Worker loop started")
        while not self._stop_event.is_set():
            job_id = self._dequeue()
            if job_id:
                try:
                    self._process_job(job_id)
                except Exception as e:
                    logger.error(f"Error processing job {job_id}: {e}", exc_info=True)
                    self._update_job(job_id, {
                        'status': STATUS_FAILED,
                        'error': str(e),
                        'finished_at': time.time(),
                    })
            else:
                # No jobs, sleep briefly
                time.sleep(0.5)
        logger.info("Worker loop stopped")
    
    def _process_job(self, job_id: str):
        """Process a single job."""
        job = self._load_job(job_id)
        if not job:
            logger.warning(f"Job {job_id} not found")
            return
        
        job_type = job.get('type', 'single')
        
        # Update status to running
        self._update_job(job_id, {
            'status': STATUS_RUNNING,
            'updated_at': time.time(),
        })
        
        try:
            if job_type == 'single':
                self._process_single_job(job)
            elif job_type == 'bulk':
                self._process_bulk_job(job)
            else:
                raise ValueError(f"Unknown job type: {job_type}")
        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}", exc_info=True)
            self._update_job(job_id, {
                'status': STATUS_FAILED,
                'error': str(e),
                'finished_at': time.time(),
            })
    
    def _process_single_job(self, job: dict):
        """Process single domain scan job."""
        job_id = job['id']
        domains = json.loads(job.get('domains', '[]'))
        domain = domains[0] if domains else job.get('domain', '')
        options = json.loads(job.get('options', '{}'))
        
        if not domain:
            self._update_job(job_id, {
                'status': STATUS_FAILED,
                'error': 'No domain specified',
                'finished_at': time.time(),
            })
            return
        
        logger.info(f"Processing single scan job {job_id} for {domain}")
        
        # Call the scan function
        if self._scan_fn:
            try:
                result = self._scan_fn(domain, **options)
                
                # Save result to scans table so /domain endpoint can fetch it
                try:
                    from . import db
                    if result and hasattr(db, 'save_scan'):
                        tech_count = len(result.get('technologies', []))
                        logger.info(f"Saving scan result with {tech_count} technologies for {domain}")
                        db.save_scan(result, from_cache=False, timeout_used=45)
                        logger.debug(f"Saved scan result to DB for {domain}")
                except Exception as save_err:
                    logger.warning(f"Could not save scan to DB: {save_err}")
                
                self._update_job(job_id, {
                    'status': STATUS_COMPLETED,
                    'progress': 100,
                    'completed': 1,
                    'result': json.dumps(result) if result else None,
                    'finished_at': time.time(),
                })
                logger.info(f"Single scan job {job_id} completed")
            except Exception as e:
                logger.error(f"Single scan failed for {domain}: {e}")
                self._update_job(job_id, {
                    'status': STATUS_FAILED,
                    'error': str(e),
                    'finished_at': time.time(),
                })
        else:
            self._update_job(job_id, {
                'status': STATUS_FAILED,
                'error': 'Scan function not configured',
                'finished_at': time.time(),
            })
    
    def _process_bulk_job(self, job: dict):
        """Process bulk domain scan job."""
        job_id = job['id']
        domains = json.loads(job.get('domains', '[]'))
        options = json.loads(job.get('options', '{}'))
        total = len(domains)
        
        if not domains:
            self._update_job(job_id, {
                'status': STATUS_FAILED,
                'error': 'No domains specified',
                'finished_at': time.time(),
            })
            return
        
        logger.info(f"Processing bulk scan job {job_id} for {total} domains")
        
        results = []
        for i, domain in enumerate(domains):
            # Check if we should stop
            if self._stop_event.is_set():
                break
            
            # Update progress
            progress = int((i / total) * 100)
            self._update_job(job_id, {
                'progress': progress,
                'completed': i,
                'updated_at': time.time(),
            })
            
            # Scan domain
            try:
                if self._scan_fn:
                    result = self._scan_fn(domain, **options)
                    
                    # Save result to scans table
                    try:
                        from . import db
                        if result and hasattr(db, 'save_scan'):
                            db.save_scan(result, from_cache=False, timeout_used=45)
                    except Exception as save_err:
                        logger.debug(f"Could not save bulk scan result to DB: {save_err}")
                    
                    results.append({
                        'domain': domain,
                        'status': 'success',
                        'tech_count': len(result.get('technologies', [])) if result else 0,
                    })
                else:
                    results.append({
                        'domain': domain,
                        'status': 'error',
                        'error': 'Scan function not configured',
                    })
            except Exception as e:
                logger.error(f"Bulk scan error for {domain}: {e}")
                results.append({
                    'domain': domain,
                    'status': 'error',
                    'error': str(e),
                })
        
        # Mark completed
        self._update_job(job_id, {
            'status': STATUS_COMPLETED,
            'progress': 100,
            'completed': total,
            'results': json.dumps(results),
            'finished_at': time.time(),
        })
        logger.info(f"Bulk scan job {job_id} completed: {len(results)} domains processed")
    
    def _save_job(self, job: dict):
        """Save job to storage."""
        job_id = job['id']
        with _memory_lock:
            _memory_jobs[job_id] = job.copy()
        # Also try to save to database
        try:
            from . import db
            if hasattr(db, 'save_scan_job'):
                db.save_scan_job(job)
        except Exception as e:
            logger.debug(f"Could not save job to DB: {e}")
    
    def _load_job(self, job_id: str) -> Optional[dict]:
        """Load job from storage."""
        # Try database first
        try:
            from . import db
            if hasattr(db, 'get_scan_job'):
                job = db.get_scan_job(job_id)
                if job:
                    return job
        except Exception as e:
            logger.debug(f"Could not load job from DB: {e}")
        
        # Fallback to memory
        with _memory_lock:
            return _memory_jobs.get(job_id, {}).copy() if job_id in _memory_jobs else None
    
    def _update_job(self, job_id: str, updates: dict):
        """Update job in storage."""
        updates['updated_at'] = time.time()
        
        # Update in memory
        with _memory_lock:
            if job_id in _memory_jobs:
                _memory_jobs[job_id].update(updates)
        
        # Also try to update in database
        try:
            from . import db
            if hasattr(db, 'update_scan_job'):
                db.update_scan_job(job_id, updates)
        except Exception as e:
            logger.debug(f"Could not update job in DB: {e}")


# Global job queue instance
_job_queue: Optional[ScanJobQueue] = None


def get_job_queue() -> ScanJobQueue:
    """Get or create global job queue instance."""
    global _job_queue
    if _job_queue is None:
        _job_queue = ScanJobQueue()
    return _job_queue


def init_job_queue(scan_fn: Callable = None, bulk_scan_fn: Callable = None):
    """Initialize and start the job queue with scan functions."""
    global _job_queue
    _job_queue = ScanJobQueue(scan_fn=scan_fn, bulk_scan_fn=bulk_scan_fn)
    _job_queue.start_worker()
    return _job_queue


def shutdown_job_queue():
    """Stop the job queue worker."""
    global _job_queue
    if _job_queue:
        _job_queue.stop_worker()
        _job_queue = None
