
import os
import sys
import time
import logging

# Setup basic logging to see our warnings
logging.basicConfig(level=logging.INFO)

# Mock app context if needed? 
# job_queue.get_job_queue() needs app context? 
# app/__init__.py creates app. 

from app import create_app
from app.job_queue import get_job_queue

print("Initializing app...")
app = create_app()

with app.app_context():
    print("Getting job queue...")
    jq = get_job_queue()
    
    # Force start worker (should fallback to thread if RQ missing)
    print("Starting worker...")
    jq.start_worker()
    
    # Check if thread started
    if jq._worker_thread and jq._worker_thread.is_alive():
        print("Fallback: Internal worker thread STARTED.")
    else:
        # If RQ was available, thread wouldn't start. 
        # Identify via logs if RQ imported.
        print("Worker thread did NOT start (or RQ active).")

    # Define a dummy scan function
    def dummy_scan(domain, **kwargs):
        print(f"Dummy scan executing for {domain}")
        return {"technologies": [{"name": "DummyTech", "version": "1.0"}]}
        
    jq._scan_fn = dummy_scan
    
    # Submit job
    print("Submitting job...")
    job_id = jq.submit_single("example.com")
    print(f"Job ID: {job_id}")
    
    # Wait for completion
    for i in range(10):
        job = jq.get_job(job_id)
        status = job.get("status")
        print(f"Job status: {status}")
        if status == "completed":
            print("Job COMPLETED successfully.")
            break
        if status == "failed":
            print(f"Job FAILED: {job.get('error')}")
            break
        time.sleep(1)
        
    jq.stop_worker()
