from rq import Queue
from redis import Redis
from typing import Literal, Optional

from backend.core.config import settings
from backend.core.database import SessionLocal
from backend.core.exceptions import ProjectNotFoundError, ScanRunNotFoundError, ReportNotFoundError
from backend.core.logging import get_logger
from backend import models
from backend.services.scan_service import run_scan
from backend.services.exploit_service import generate_exploit_scenarios

logger = get_logger(__name__)

redis_conn: Redis = Redis.from_url(settings.redis_url)
scan_queue = Queue("scans", connection=redis_conn)
exploit_queue = Queue("exploitability", connection=redis_conn)


def enqueue_scan(project_id: int, scan_run_id: int):
    """Enqueue a scan job for background processing."""
    logger.info(f"Enqueueing scan for project {project_id}, scan_run {scan_run_id}")
    return scan_queue.enqueue(perform_scan, project_id, scan_run_id)


def enqueue_exploitability(report_id: int, mode: str = "auto"):
    """
    Enqueue an exploitability analysis job for background processing.
    
    Args:
        report_id: ID of the report to analyze
        mode: Analysis mode - "full", "summary", or "auto" (default)
              - full: Individual LLM analysis per finding (slow, detailed)
              - summary: Single executive summary + templates (fast, recommended for large codebases)
              - auto: Automatically selects based on finding count
    """
    logger.info(f"Enqueueing exploitability analysis for report {report_id} (mode: {mode})")
    return exploit_queue.enqueue(perform_exploitability, report_id, mode)


def perform_scan(project_id: int, scan_run_id: int) -> int:
    """
    Execute a vulnerability scan for a project.
    
    Args:
        project_id: ID of the project to scan
        scan_run_id: ID of the scan run record
        
    Returns:
        ID of the generated report
        
    Raises:
        ProjectNotFoundError: If project doesn't exist
        ScanRunNotFoundError: If scan run doesn't exist
    """
    logger.info(f"Starting scan for project {project_id}, scan_run {scan_run_id}")
    db = SessionLocal()
    
    try:
        project = db.get(models.Project, project_id)
        scan_run = db.get(models.ScanRun, scan_run_id)
        
        if not project:
            logger.error(f"Project {project_id} not found")
            raise ProjectNotFoundError(project_id)
        if not scan_run:
            logger.error(f"Scan run {scan_run_id} not found")
            raise ScanRunNotFoundError(scan_run_id)
        
        report = run_scan(db, project, scan_run)
        logger.info(f"Scan completed for project {project_id}, report {report.id}")
        return report.id
        
    except (ProjectNotFoundError, ScanRunNotFoundError):
        raise
    except Exception as e:
        logger.exception(f"Scan failed for project {project_id}: {e}")
        raise
    finally:
        db.close()


def perform_exploitability(report_id: int, mode: str = "auto") -> int:
    """
    Execute exploitability analysis for a report.
    
    Args:
        report_id: ID of the report to analyze
        mode: Analysis mode - "full", "summary", or "auto"
        
    Returns:
        ID of the analyzed report
        
    Raises:
        ReportNotFoundError: If report doesn't exist
    """
    logger.info(f"Starting exploitability analysis for report {report_id} (mode: {mode})")
    db = SessionLocal()
    
    try:
        report = db.get(models.Report, report_id)
        
        if not report:
            logger.error(f"Report {report_id} not found")
            raise ReportNotFoundError(report_id)
        
        # Use existing event loop or create new for async tasks
        db.expire_all()
        import asyncio
        asyncio.run(generate_exploit_scenarios(db, report, mode=mode))
        
        logger.info(f"Exploitability analysis completed for report {report_id}")
        return report_id
        
    except ReportNotFoundError:
        raise
    except Exception as e:
        logger.exception(f"Exploitability analysis failed for report {report_id}: {e}")
        raise
    finally:
        db.close()
