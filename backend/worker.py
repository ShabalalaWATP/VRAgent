import signal
import sys
import time

import redis.exceptions
from rq import Connection, Worker

from backend.core.logging import get_logger
from backend.tasks.jobs import exploit_queue, redis_conn, scan_queue, summary_queue

logger = get_logger(__name__)


def handle_shutdown(signum, frame):
    """Handle graceful shutdown on SIGTERM/SIGINT."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    sys.exit(0)


def run_worker():
    """Run the RQ worker with proper error handling and graceful shutdown."""
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    
    logger.info("Starting VRAgent background worker...")
    logger.info(f"Listening on queues: scans, exploitability, summaries")
    
    max_retries = 5
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            with Connection(redis_conn):
                worker = Worker(
                    [scan_queue, exploit_queue, summary_queue],
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
