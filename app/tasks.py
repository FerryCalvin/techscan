import logging
from app import db
from app.scanners.core import scan_bulk, bulk_quick_then_deep


def run_bulk_scan_task(job_id: str, domains: list[str], options: dict = None):
    """Background task to run a bulk scan."""
    options = options or {}
    logger = logging.getLogger("rq.worker")
    logger.info(f"Starting bulk scan task job_id={job_id} domains={len(domains)}")

    # Update job status to running
    _update_job_status(job_id, "running", progress=0)

    try:
        wappalyzer_path = options.get("wappalyzer_path", "wappalyzer")
        concurrency = options.get("concurrency", 4)
        two_phase = options.get("two_phase", False)
        timeout = options.get("timeout", 30)
        retries = options.get("retries", 2)
        full = options.get("full", False)
        fresh = options.get("fresh", False)
        ttl = options.get("ttl")

        if two_phase:
            results = bulk_quick_then_deep(domains, wappalyzer_path, concurrency=concurrency)
        else:
            results = scan_bulk(
                domains,
                wappalyzer_path,
                concurrency=concurrency,
                timeout=timeout,
                retries=retries,
                fresh=fresh,
                ttl=ttl,
                full=full,
            )

        # Update job with results
        _complete_job(job_id, results)
        logger.info(f"Finished bulk scan task job_id={job_id}")
        return results
    except Exception as e:
        logger.error(f"Failed bulk scan task job_id={job_id} err={e}", exc_info=True)
        _fail_job(job_id, str(e))
        raise


def _update_job_status(job_id, status, progress=None):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            if progress is not None:
                cur.execute(
                    "UPDATE scan_jobs SET status=%s, progress=%s, updated_at=NOW() WHERE id=%s",
                    (status, progress, job_id),
                )
            else:
                cur.execute("UPDATE scan_jobs SET status=%s, updated_at=NOW() WHERE id=%s", (status, job_id))
        conn.commit()


def _complete_job(job_id, results):
    import json

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_jobs 
                SET status='completed', 
                    progress=100, 
                    completed=100, 
                    results=%s::jsonb, 
                    finished_at=NOW(), 
                    updated_at=NOW() 
                WHERE id=%s
            """,
                (json.dumps(results, ensure_ascii=False), job_id),
            )
        conn.commit()


def _fail_job(job_id, error):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_jobs 
                SET status='failed', 
                error=%s, 
                finished_at=NOW(), 
                updated_at=NOW() 
                WHERE id=%s
            """,
                (error, job_id),
            )
        conn.commit()


def run_single_scan_task(job_id: str, domain: str, options: dict = None):
    """Background task to run a single scan."""
    options = options or {}
    logger = logging.getLogger("rq.worker")
    logger.info(f"Starting single scan task job_id={job_id} domain={domain}")

    # Update job status to running
    _update_job_status(job_id, "running", progress=0)

    try:
        wappalyzer_path = options.get("wappalyzer_path", "wappalyzer")
        # Use simple unified scan or whatever scan_unified wrapper provides
        from app.scanners.core import scan_unified
        
        # Determine budget based on options
        # Default budget 25s, deep 45s
        budget_ms = int(options.get("budget_ms", 25000))
        if options.get("deep"):
            budget_ms = 45000
        
        result = scan_unified(domain, wappalyzer_path, budget_ms=budget_ms)

        # Save result to scans table so /domain endpoint can fetch it
        try:
            if result and hasattr(db, "save_scan"):
               db.save_scan(result, from_cache=False, timeout_used=budget_ms//1000)
        except Exception as save_err:
             logger.warning(f"Could not save scan to DB: {save_err}")

        # Update job with result
        import json
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE scan_jobs SET status='completed', progress=100, completed=1, result=%s::jsonb, finished_at=NOW(), updated_at=NOW() WHERE id=%s",
                    (json.dumps(result, ensure_ascii=False), job_id)
                )
            conn.commit()
            
        logger.info(f"Finished single scan task job_id={job_id}")
        return result
    except Exception as e:
        logger.error(f"Failed single scan task job_id={job_id} err={e}", exc_info=True)
        _fail_job(job_id, str(e))
        raise
