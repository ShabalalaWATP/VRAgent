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
summary_queue = Queue("summaries", connection=redis_conn)


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
        
        # Enqueue background AI summary generation so it's ready when user views the report
        try:
            enqueue_ai_summaries(report.id)
            logger.info(f"Enqueued AI summary generation for report {report.id}")
        except Exception as e:
            logger.warning(f"Failed to enqueue AI summary generation: {e}")
        
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


def enqueue_ai_summaries(report_id: int):
    """Enqueue AI summary generation job for background processing."""
    logger.info(f"Enqueueing AI summary generation for report {report_id}")
    return summary_queue.enqueue(perform_ai_summaries, report_id)


def perform_ai_summaries(report_id: int) -> int:
    """
    Generate AI summaries for a report in the background.
    
    This pre-generates the app and security summaries so they're ready
    when the user views the report, avoiding long wait times.
    
    Args:
        report_id: ID of the report to generate summaries for
        
    Returns:
        ID of the report
    """
    from collections import defaultdict
    from backend.core.config import settings
    
    logger.info(f"Starting AI summary generation for report {report_id}")
    db = SessionLocal()
    
    try:
        report = db.get(models.Report, report_id)
        if not report:
            logger.error(f"Report {report_id} not found")
            raise ReportNotFoundError(report_id)
        
        # Check if summaries already exist
        if report.data and report.data.get("ai_summaries"):
            logger.info(f"AI summaries already exist for report {report_id}, skipping")
            return report_id
        
        project_id = report.project_id
        project = db.get(models.Project, project_id)
        
        # Get all code chunks for context
        chunks = db.query(models.CodeChunk).filter(
            models.CodeChunk.project_id == project_id
        ).all()
        
        # Get findings for this report
        findings = db.query(models.Finding).filter(
            models.Finding.scan_run_id == report.scan_run_id
        ).all()
        
        # Build file metadata for statistics
        file_metadata = defaultdict(lambda: {"lines": 0, "language": None})
        for chunk in chunks:
            file_metadata[chunk.file_path]["language"] = chunk.language
            if chunk.end_line:
                file_metadata[chunk.file_path]["lines"] = max(
                    file_metadata[chunk.file_path]["lines"],
                    chunk.end_line
                )
        
        # Calculate statistics
        total_files = len(file_metadata)
        total_lines = sum(m["lines"] for m in file_metadata.values())
        languages = {}
        for m in file_metadata.values():
            lang = m["language"] or "Unknown"
            languages[lang] = languages.get(lang, 0) + 1
        
        # Get sample file paths for context
        sample_paths = list(file_metadata.keys())[:30]
        
        # Get sample code snippets
        sample_code = []
        for chunk in chunks[:5]:
            sample_code.append({
                "path": chunk.file_path,
                "language": chunk.language,
                "preview": chunk.code[:500] if chunk.code else ""
            })
        
        # Build severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        finding_types = {}
        for f in findings:
            sev = (f.severity or "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            ftype = f.type or "unknown"
            finding_types[ftype] = finding_types.get(ftype, 0) + 1
        
        # Generate AI summaries if API key is available
        app_summary = None
        security_summary = None
        
        if settings.gemini_api_key:
            try:
                from google import genai
                
                client = genai.Client(api_key=settings.gemini_api_key)
                
                # Build prompts
                app_prompt = f"""You are a senior software architect analyzing a codebase. Provide a comprehensive overview.

Project Name: {project.name if project else 'Unknown'}

FILES ANALYZED ({total_files} files, {total_lines:,} lines):
{chr(10).join(sample_paths[:20])}
{"..." if len(sample_paths) > 20 else ""}

LANGUAGE BREAKDOWN:
{chr(10).join(f"- {lang}: {count} files" for lang, count in sorted(languages.items(), key=lambda x: -x[1])[:5])}

SAMPLE CODE:
{chr(10).join(f"--- {s['path']} ({s['language']}) ---{chr(10)}{s['preview'][:300]}..." for s in sample_code[:3])}

Write a brief analysis in this format:
**Purpose & Functionality** - 2-3 sentences
**Technology Stack** - bullet list
**Key Components** - 3-5 components with brief descriptions"""

                # Generate app summary
                logger.info(f"Generating app summary for report {report_id}")
                response = client.models.generate_content(
                    model=settings.gemini_model_id,
                    contents=app_prompt
                )
                if response and response.text:
                    app_summary = response.text
                    logger.info(f"Generated app summary for report {report_id}")
                
                # Generate security summary only if there are findings
                if len(findings) > 0:
                    findings_details = []
                    for f in findings[:10]:
                        findings_details.append({
                            "severity": f.severity,
                            "type": f.type,
                            "file": f.file_path,
                            "summary": f.summary[:150] if f.summary else "",
                        })
                    
                    security_prompt = f"""You are a penetration tester. Analyze these vulnerabilities briefly.

Project: {project.name if project else 'Unknown'}
Findings: Critical={severity_counts['critical']}, High={severity_counts['high']}, Medium={severity_counts['medium']}, Low={severity_counts['low']}

SAMPLE FINDINGS:
{chr(10).join(f"- [{f['severity'].upper()}] {f['type']}: {f['summary']}" for f in findings_details)}

Write a brief analysis:
**Overall Risk Assessment** - CRITICAL/HIGH/MEDIUM/LOW with one sentence justification
**Primary Attack Vectors** - 3 bullet points
**Quick Wins** - 3 easiest exploits"""

                    logger.info(f"Generating security summary for report {report_id}")
                    response = client.models.generate_content(
                        model=settings.gemini_model_id,
                        contents=security_prompt
                    )
                    if response and response.text:
                        security_summary = response.text
                        logger.info(f"Generated security summary for report {report_id}")
                
                # Cache the summaries
                if app_summary or security_summary:
                    report_data = report.data or {}
                    report_data["ai_summaries"] = {
                        "app_summary": app_summary,
                        "security_summary": security_summary
                    }
                    report.data = report_data
                    db.commit()
                    logger.info(f"Cached AI summaries for report {report_id}")
                    
            except Exception as e:
                logger.error(f"Failed to generate AI summaries for report {report_id}: {e}")
        else:
            logger.info(f"No Gemini API key, skipping AI summary generation for report {report_id}")
        
        return report_id
        
    except Exception as e:
        logger.exception(f"AI summary generation failed for report {report_id}: {e}")
        raise
    finally:
        db.close()
