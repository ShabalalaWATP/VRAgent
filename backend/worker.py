import signal
import sys
import time
from datetime import datetime, timedelta, timezone

import redis.exceptions
from rq import Connection, Worker
from rq.job import Job
from rq.registry import StartedJobRegistry, FailedJobRegistry

from backend.core.logging import get_logger
from backend.tasks.jobs import agentic_queue, exploit_queue, redis_conn, scan_queue, summary_queue

logger = get_logger(__name__)

# Timeout thresholds for orphan detection
ORPHAN_HEARTBEAT_THRESHOLD = 120  # seconds - job is orphaned if no heartbeat for this long
ORPHAN_STARTED_THRESHOLD = 1500   # seconds (25 min) - job is orphaned if started but not finished after this long


def handle_shutdown(signum, frame):
    """Handle graceful shutdown on SIGTERM/SIGINT."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    sys.exit(0)


def cleanup_orphaned_jobs():
    """
    Clean up orphaned jobs from all queues on startup.
    
    Orphaned jobs occur when a worker dies mid-job (e.g., container restart).
    These jobs get stuck in "started" state forever, blocking new jobs.
    """
    queues = [scan_queue, exploit_queue, summary_queue, agentic_queue]
    total_cleaned = 0
    now = datetime.now(timezone.utc)
    
    for queue in queues:
        try:
            registry = StartedJobRegistry(queue=queue)
            job_ids = registry.get_job_ids()
            
            for job_id in job_ids:
                try:
                    job = Job.fetch(job_id, connection=redis_conn)
                    
                    # Check if job is orphaned based on heartbeat or start time
                    is_orphaned = False
                    reason = ""
                    
                    # Check heartbeat - if too old, worker is likely dead
                    if job.last_heartbeat:
                        heartbeat_age = (now - job.last_heartbeat).total_seconds()
                        if heartbeat_age > ORPHAN_HEARTBEAT_THRESHOLD:
                            is_orphaned = True
                            reason = f"no heartbeat for {heartbeat_age:.0f}s"
                    
                    # Check start time - if running too long, likely stuck
                    if not is_orphaned and job.started_at:
                        started_age = (now - job.started_at).total_seconds()
                        # Only consider orphaned if started long ago AND no recent heartbeat
                        if started_age > ORPHAN_STARTED_THRESHOLD:
                            is_orphaned = True
                            reason = f"running for {started_age:.0f}s without completion"
                    
                    if is_orphaned:
                        logger.warning(
                            f"Found orphaned job {job_id} in {queue.name} ({reason}). "
                            f"Moving to failed queue."
                        )
                        # Remove from started registry
                        registry.remove(job)
                        # Mark as failed
                        job.set_status("failed")
                        job.exc_info = f"Job orphaned during worker restart: {reason}"
                        job.save()
                        # Add to failed registry for visibility
                        failed_registry = FailedJobRegistry(queue=queue)
                        failed_registry.add(job, ttl=-1)
                        total_cleaned += 1
                        
                except Exception as e:
                    logger.warning(f"Could not check job {job_id}: {e}")
                    # If we can't even fetch the job, remove it from registry
                    try:
                        registry.remove(job_id)
                        total_cleaned += 1
                    except Exception:
                        pass  # Cleanup failure is non-critical
                        
        except Exception as e:
            logger.warning(f"Error cleaning up queue {queue.name}: {e}")
    
    if total_cleaned > 0:
        logger.info(f"Cleaned up {total_cleaned} orphaned jobs on startup")
    else:
        logger.info("No orphaned jobs found")
    
    return total_cleaned


def run_worker():
    """Run the RQ worker with proper error handling and graceful shutdown."""
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    
    logger.info("Starting VRAgent background worker...")
    logger.info(f"Listening on queues: scans, exploitability, summaries, agentic")
    
    max_retries = 5
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            with Connection(redis_conn):
                # Clean up any orphaned jobs from previous worker crashes
                logger.info("Checking for orphaned jobs from previous sessions...")
                cleanup_orphaned_jobs()
                
                worker = Worker(
                    [scan_queue, exploit_queue, summary_queue, agentic_queue],
                    default_worker_ttl=420,  # Worker heartbeat timeout
                    job_monitoring_interval=5,  # Check for jobs every 5 seconds
                )
                worker.work(with_scheduler=False)
                break  # If we reach here, worker exited normally
        except redis.exceptions.ConnectionError as e:
            if attempt < max_retries - 1:
                logger.warning(f"Redis connection failed (attempt {attempt + 1}/{max_retries}): {e}")
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                logger.error(f"Failed to connect to Redis after {max_retries} attempts: {e}")
                logger.error("Make sure Redis is running and REDIS_URL is correct")
                sys.exit(1)
        except KeyboardInterrupt:
            logger.info("Worker interrupted by user")
            break
        except Exception as e:
            logger.exception(f"Worker crashed unexpectedly: {e}")
            sys.exit(1)


if __name__ == "__main__":
    run_worker()
