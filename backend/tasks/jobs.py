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
agentic_queue = Queue("agentic", connection=redis_conn)


def run_agentic_scan_inline(db, project: models.Project, scan_run: models.ScanRun) -> list:
    """
    Run agentic AI scan inline (synchronously) so findings are included in main report.
    
    This runs BEFORE the main scan's AI analysis phase so agentic findings
    can be included in attack chain detection and the final report.
    
    Args:
        db: Database session
        project: Project being scanned
        scan_run: Current scan run
        
    Returns:
        List of Finding models from the agentic scan
    """
    import asyncio
    from backend.services.agentic_scan_service import AgenticScanService
    from backend.services.websocket_service import progress_manager
    
    logger.info(f"Running inline agentic scan for project {project.id}")
    
    # Publish initial status
    progress_manager.publish_progress(
        scan_run.id, "agentic_scan", 5,
        "🤖 Starting Agentic AI deep code analysis..."
    )
    
    findings = []
    temp_dir = None
    
    try:
        # Determine code path - need to extract ZIP if uploaded
        from backend.services.codebase_service import unpack_zip_to_temp
        
        code_path = None
        if project.upload_path:
            # Extract ZIP to temp directory
            logger.info(f"Extracting {project.upload_path} for agentic scan")
            temp_dir = unpack_zip_to_temp(project.upload_path)
            code_path = str(temp_dir)
            logger.info(f"Extracted to {code_path}")
        elif project.git_url:
            code_path = project.git_url
        
        if not code_path:
            logger.warning(f"No code path for agentic scan on project {project.id}")
            return []
        
        service = AgenticScanService()
        
        def progress_callback(progress):
            """Update WebSocket with agentic scan progress"""
            phase_progress_map = {
                "initializing": 10,
                "chunking": 20,
                "entry_point_detection": 40,
                "flow_tracing": 60,
                "vulnerability_analysis": 80,
                "report_generation": 95,
                "complete": 100,
            }
            phase_name = progress.phase.value if hasattr(progress.phase, 'value') else str(progress.phase)
            pct = phase_progress_map.get(phase_name, 50)
            
            stats = []
            if progress.entry_points_found > 0:
                stats.append(f"🎯 {progress.entry_points_found} entry points")
            if progress.flows_traced > 0:
                stats.append(f"🔀 {progress.flows_traced} flows")
            if progress.vulnerabilities_found > 0:
                stats.append(f"⚠️ {progress.vulnerabilities_found} vulns")
            
            msg = f"🤖 {progress.message or phase_name}"
            if stats:
                msg += f" | {' | '.join(stats)}"
            
            progress_manager.publish_progress(scan_run.id, "agentic_scan", pct, msg)
        
        # Run the agentic scan
        async def run_scan():
            scan_id = await service.start_scan(
                project_id=project.id,
                project_path=code_path,
                progress_callback=progress_callback
            )
            return service.get_result(scan_id)
        
        result = asyncio.run(run_scan())
        
        if result and result.vulnerabilities:
            # Convert agentic vulnerabilities to Finding models
            for vuln in result.vulnerabilities:
                file_path = vuln.flow.entry_point.file_path if vuln.flow else "unknown"
                line_number = vuln.flow.entry_point.line_number if vuln.flow else 1
                
                finding = models.Finding(
                    project_id=project.id,
                    scan_run_id=scan_run.id,
                    type=f"agentic-{vuln.vulnerability_type}",
                    severity=vuln.severity,
                    file_path=file_path,
                    start_line=line_number,
                    summary=vuln.description[:500] if vuln.description else "Agentic AI detected vulnerability",
                    details={
                        "source": "agentic_ai",
                        "vulnerability_type": vuln.vulnerability_type,
                        "confidence": vuln.confidence,
                        "remediation": vuln.remediation,
                        "exploit_scenario": vuln.exploit_scenario,
                        "cwe_id": vuln.cwe_id,
                        "owasp_category": vuln.owasp_category,
                        "title": vuln.title,
                    }
                )
                findings.append(finding)
            
            logger.info(f"Agentic scan found {len(findings)} vulnerabilities for project {project.id}")
            progress_manager.publish_progress(
                scan_run.id, "agentic_scan", 100,
                f"🤖 Agentic AI complete: {len(findings)} vulnerabilities found"
            )
        else:
            progress_manager.publish_progress(
                scan_run.id, "agentic_scan", 100,
                "🤖 Agentic AI complete: No additional vulnerabilities found"
            )
        
        return findings
        
    except Exception as e:
        logger.error(f"Inline agentic scan failed for project {project.id}: {e}")
        progress_manager.publish_progress(
            scan_run.id, "agentic_scan", 100,
            f"🤖 Agentic AI scan skipped: {str(e)[:50]}"
        )
        return []
    finally:
        # Cleanup temp directory if created
        if temp_dir:
            import shutil
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.debug(f"Cleaned up agentic scan temp dir: {temp_dir}")
            except Exception:
                pass


def enqueue_scan(project_id: int, scan_run_id: int):
    """Enqueue a scan job for background processing."""
    logger.info(f"Enqueueing scan for project {project_id}, scan_run {scan_run_id}")
    # 30 minute timeout for large codebases
    return scan_queue.enqueue(perform_scan, project_id, scan_run_id, job_timeout=1800)


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
    # 20 minute timeout for exploitability analysis
    return exploit_queue.enqueue(perform_exploitability, report_id, mode, job_timeout=1200)


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
        
        # Run main scan (includes AI analysis and report generation)
        # Note: Agentic scan with CVE/SAST context is now handled INSIDE run_scan()
        # when scan_options.get("include_agentic") is True. This ensures AI has
        # full external intelligence (CVEs, EPSS, SAST findings) before analyzing code.
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
    # 15 minute timeout for AI summary generation
    return summary_queue.enqueue(perform_ai_summaries, report_id, job_timeout=900)


def perform_ai_summaries(report_id: int) -> int:
    """
    Generate AI summaries for a report in the background.
    
    Uses comprehensive context from:
    - Deep-analyzed files (Pass 3 of agentic scan)
    - Agentic scan synthesis results
    - All security findings with details
    - Attack chains detected
    - CVE and dependency data
    
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
        
        # Get all code chunks for context - prioritize security-relevant chunks
        chunks = db.query(models.CodeChunk).filter(
            models.CodeChunk.project_id == project_id
        ).all()
        
        # Get findings for this report - ALL findings for comprehensive analysis
        findings = db.query(models.Finding).filter(
            models.Finding.scan_run_id == report.scan_run_id
        ).order_by(
            # Prioritize: critical > high > medium > low
            models.Finding.severity.desc()
        ).all()
        
        # Get dependencies and vulnerabilities
        dependencies = db.query(models.Dependency).filter(
            models.Dependency.project_id == project_id
        ).all()
        
        vulnerabilities = db.query(models.Vulnerability).filter(
            models.Vulnerability.dependency_id.in_([d.id for d in dependencies])
        ).all() if dependencies else []
        
        # Build file metadata for statistics
        file_metadata = defaultdict(lambda: {"lines": 0, "language": None, "chunks": [], "findings": []})
        for chunk in chunks:
            file_metadata[chunk.file_path]["language"] = chunk.language
            file_metadata[chunk.file_path]["chunks"].append(chunk)
            if chunk.end_line:
                file_metadata[chunk.file_path]["lines"] = max(
                    file_metadata[chunk.file_path]["lines"],
                    chunk.end_line
                )
        
        # Map findings to files
        for f in findings:
            if f.file_path in file_metadata:
                file_metadata[f.file_path]["findings"].append(f)
        
        # Calculate statistics
        total_files = len(file_metadata)
        total_lines = sum(m["lines"] for m in file_metadata.values())
        languages = {}
        for m in file_metadata.values():
            lang = m["language"] or "Unknown"
            languages[lang] = languages.get(lang, 0) + 1
        
        # Get attack chains and AI summary from report data
        report_data = report.data or {}
        attack_chains = report_data.get("attack_chains", [])
        existing_ai_summary = report_data.get("ai_analysis_summary", {})
        scan_stats = report_data.get("scan_stats", {})
        
        # Extract synthesis results from agentic scan (if available)
        synthesis_data = scan_stats.get("synthesis", {})
        agentic_assessment = synthesis_data.get("assessment", "")
        agentic_recommendations = synthesis_data.get("recommendations", 0)
        multi_pass_data = scan_stats.get("multi_pass", {})
        
        # PRIORITIZE files with findings (these were deeply analyzed in the scan)
        files_with_findings = [(path, meta) for path, meta in file_metadata.items() if meta["findings"]]
        files_with_findings.sort(key=lambda x: len(x[1]["findings"]), reverse=True)
        
        # Get the TOP 20 most security-relevant files (by finding count)
        # These are the files that received deep analysis in Pass 2/3
        priority_files = files_with_findings[:20]
        
        # Build comprehensive code context from priority files
        priority_code_samples = []
        for path, meta in priority_files:
            # Get full code content for these files (up to 10000 chars each for security-critical files)
            full_code = ""
            for chunk in sorted(meta["chunks"], key=lambda c: c.start_line or 0):
                full_code += (chunk.code or "") + "\n"
            
            # Include findings for this file
            file_findings = [
                f"Line {f.start_line}: [{f.severity.upper()}] {f.type} - {f.summary[:100]}"
                for f in meta["findings"][:5]
            ]
            
            priority_code_samples.append({
                "path": path,
                "language": meta["language"],
                "code": full_code[:10000],  # More context for deep-analyzed files
                "lines": meta["lines"],
                "findings": file_findings
            })
        
        # Also get significant files WITHOUT findings for architecture context
        # These help understand what the app does beyond just security issues
        clean_files = [(path, meta) for path, meta in file_metadata.items() 
                       if not meta["findings"] and meta["lines"] > 50]
        clean_files.sort(key=lambda x: x[1]["lines"], reverse=True)
        
        # Get 10 significant clean files for comprehensive app understanding
        for path, meta in clean_files[:10]:
            full_code = ""
            for chunk in sorted(meta["chunks"], key=lambda c: c.start_line or 0):
                full_code += (chunk.code or "") + "\n"
            priority_code_samples.append({
                "path": path,
                "language": meta["language"],
                "code": full_code[:6000],  # Good context for clean files too
                "lines": meta["lines"],
                "findings": []
            })
        
        # Build severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        finding_types = defaultdict(int)
        agentic_findings = []
        sast_findings = []
        
        for f in findings:
            sev = (f.severity or "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            finding_types[f.type or "unknown"] += 1
            
            # Categorize findings
            if f.type and (f.type.startswith("agentic-") or (f.details and f.details.get("source") == "agentic_ai")):
                agentic_findings.append(f)
            else:
                sast_findings.append(f)
        
        # Generate AI summaries if API key is available
        app_summary = None
        security_summary = None
        
        if settings.gemini_api_key:
            try:
                from google import genai
                
                client = genai.Client(api_key=settings.gemini_api_key)
                
                # Build COMPREHENSIVE app prompt using ALL priority files (same context as security)
                code_sections = []
                for sample in priority_code_samples[:20]:  # ALL 20 deeply-analyzed + 10 clean files
                    findings_note = ""
                    if sample["findings"]:
                        findings_note = f"\n  ⚠️ SECURITY ISSUES IN THIS FILE:\n    " + "\n    ".join(sample["findings"][:3])
                    code_sections.append(
                        f"### {sample['path']} ({sample['language']}, {sample['lines']} lines){findings_note}\n"
                        f"```{sample['language']}\n{sample['code'][:5000]}\n```"
                    )
                
                # Dependency context
                dep_context = ""
                if dependencies:
                    dep_list = [f"- {d.name}@{d.version} ({d.ecosystem})" for d in dependencies[:20]]
                    vuln_deps = [v for v in vulnerabilities if v.severity in ("critical", "high")]
                    dep_context = f"""
DEPENDENCIES ({len(dependencies)} packages):
{chr(10).join(dep_list)}
{"..." if len(dependencies) > 20 else ""}

VULNERABLE DEPENDENCIES ({len(vuln_deps)} critical/high):
{chr(10).join(f"- {v.external_id}: affects dependency (CVSS: {v.cvss_score})" for v in vuln_deps[:10])}
"""
                
                # Include agentic scan synthesis if available
                synthesis_context = ""
                if agentic_assessment:
                    synthesis_context = f"""
## AI DEEP ANALYSIS SYNTHESIS:
{agentic_assessment[:1000]}
"""
                
                # Multi-pass scan stats context
                scan_context = ""
                if multi_pass_data:
                    scan_context = f"""
## SCAN ANALYSIS DEPTH:
- Files Triaged: {multi_pass_data.get('total_files_triaged', 0)}
- Pass 1 (Initial): {multi_pass_data.get('pass_1_files', 0)} files
- Pass 2 (Focused): {multi_pass_data.get('pass_2_files', 0)} files  
- Pass 3 (Deep): {multi_pass_data.get('pass_3_files', 0)} files
- High-Risk Files Identified: {multi_pass_data.get('high_risk_files', 0)}
"""
                
                app_prompt = f"""You are a senior software architect analyzing a codebase. Provide a COMPREHENSIVE overview.

Project Name: {project.name if project else 'Unknown'}
Total: {total_files} files, {total_lines:,} lines of code
Security Scan Results: {severity_counts['critical']} critical, {severity_counts['high']} high, {severity_counts['medium']} medium issues

LANGUAGE BREAKDOWN:
{chr(10).join(f"- {lang}: {count} files" for lang, count in sorted(languages.items(), key=lambda x: -x[1])[:8])}
{dep_context}
{scan_context}
{synthesis_context}

## DEEPLY ANALYZED SOURCE FILES ({len(priority_code_samples)} files with full context):
{chr(10).join(code_sections)}

Based on this comprehensive code review (the same files analyzed for security), write a detailed analysis:

**Purpose & Functionality**
- What does this application do? (3-4 sentences)
- What problem does it solve?
- Who is the target user?

**Technology Stack**
- Backend frameworks and languages
- Frontend technologies (if any)
- Databases and storage
- External services/APIs used
- Key libraries and their purposes

**Architecture Overview**
- Key architectural patterns identified (MVC, microservices, monolith, etc.)
- How components interact
- Entry points and data flow
- API structure (REST, GraphQL, etc.)

**Key Components** (8-10 components)
For each: name, purpose, and security relevance

**Notable Implementation Details**
- Authentication/authorization approach
- Data validation patterns
- Error handling approach
- Logging and monitoring
- Configuration management"""

                # Generate app summary
                logger.info(f"Generating comprehensive app summary for report {report_id}")
                response = client.models.generate_content(
                    model=settings.gemini_model_id,
                    contents=app_prompt,
                    generation_config={"max_output_tokens": 4000}
                )
                if response and response.text:
                    app_summary = response.text
                    logger.info(f"Generated app summary for report {report_id}")
                
                # Generate COMPREHENSIVE security summary
                if len(findings) > 0:
                    # Get detailed findings - up to 40 most important (same depth as app summary)
                    critical_high_findings = [f for f in findings if f.severity in ("critical", "high")][:25]
                    other_findings = [f for f in findings if f.severity not in ("critical", "high")][:15]
                    detailed_findings = critical_high_findings + other_findings
                    
                    findings_details = []
                    for f in detailed_findings:
                        ai_analysis = f.details.get("ai_analysis", {}) if f.details else {}
                        corroborated = "✓ AI-Confirmed" if ai_analysis.get("corroborated") else ""
                        fp_note = f" (FP likelihood: {ai_analysis.get('false_positive_score', 0):.0%})" if ai_analysis.get("false_positive_score") else ""
                        
                        findings_details.append({
                            "severity": f.severity,
                            "type": f.type,
                            "file": f.file_path,
                            "line": f.start_line,
                            "summary": f.summary[:250] if f.summary else "",  # More summary context
                            "corroborated": corroborated,
                            "fp_note": fp_note,
                            "details": str(f.details)[:400] if f.details else ""  # More detail context
                        })
                    
                    # Attack chains context
                    attack_chain_context = ""
                    if attack_chains:
                        attack_chain_context = f"""
## ATTACK CHAINS DETECTED ({len(attack_chains)}):
{chr(10).join(f"- {chain.get('title', 'Unknown')}: {chain.get('description', '')[:200]}" for chain in attack_chains[:8])}
"""
                    
                    # Finding type breakdown
                    type_breakdown = "\n".join(f"- {ftype}: {count}" for ftype, count in 
                                              sorted(finding_types.items(), key=lambda x: -x[1])[:15])
                    
                    # Include code context for security findings (same files as app summary)
                    security_code_sections = []
                    for sample in priority_code_samples[:15]:  # Top 15 files with findings
                        if sample["findings"]:
                            security_code_sections.append(
                                f"### {sample['path']} ({sample['language']})\n"
                                f"Issues: {chr(10).join(sample['findings'][:4])}\n"
                                f"```{sample['language']}\n{sample['code'][:3000]}\n```"
                            )
                    
                    security_prompt = f"""You are a senior penetration tester writing an executive security assessment.

Project: {project.name if project else 'Unknown'}
{scan_context}

## SECURITY SCAN SUMMARY:
- Total Findings: {len(findings)}
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Agentic AI Findings (deep analysis): {len(agentic_findings)}
- SAST Scanner Findings: {len(sast_findings)}

## FINDING TYPES:
{type_breakdown}
{attack_chain_context}
{synthesis_context if agentic_assessment else ""}

## VULNERABLE CODE FILES WITH CONTEXT:
{chr(10).join(security_code_sections[:10])}

## DETAILED FINDINGS (sorted by severity):
{chr(10).join(f"- [{f['severity'].upper()}] {f['type']} @ {f['file']}:{f['line']} {f['corroborated']}{f['fp_note']}" + chr(10) + f"  {f['summary']}" for f in findings_details)}

## VULNERABLE DEPENDENCIES:
{chr(10).join(f"- {v.external_id} (CVSS: {v.cvss_score}, Severity: {v.severity}): {v.description[:150] if v.description else 'N/A'}" for v in vulnerabilities[:15])}

Write a comprehensive security assessment:

**Executive Summary**
- 2-3 sentence overview of security posture
- Overall risk rating: CRITICAL/HIGH/MEDIUM/LOW with justification

**Critical & High Priority Issues**
- List the most dangerous findings with brief exploitation scenarios
- Focus on findings confirmed by AI analysis

**Attack Surface Analysis**
- Primary entry points identified
- Most likely attack vectors
- Data flow risks

**Top 5 Remediation Priorities**
For each: what to fix, why it matters, effort estimate (quick/medium/extensive)

**Positive Security Observations**
- Any good security practices observed
- Areas where the codebase is well-protected"""

                    logger.info(f"Generating comprehensive security summary for report {report_id}")
                    response = client.models.generate_content(
                        model=settings.gemini_model_id,
                        contents=security_prompt,
                        generation_config={"max_output_tokens": 4000}
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


def enqueue_agentic_scan(project_id: int, scan_run_id: int, report_id: int):
    """Enqueue an agentic AI scan job for background processing."""
    logger.info(f"Enqueueing agentic scan for project {project_id}")
    # 45 minute timeout for deep LLM analysis on large codebases
    return agentic_queue.enqueue(perform_agentic_scan, project_id, scan_run_id, report_id, job_timeout=2700)


def perform_agentic_scan(project_id: int, scan_run_id: int, report_id: int) -> dict:
    """
    Execute agentic AI vulnerability scan for a project.
    
    This performs deep code analysis using an LLM to trace data flows
    from entry points to potential sinks.
    
    Args:
        project_id: ID of the project to scan
        scan_run_id: ID of the scan run record
        report_id: ID of the report to attach findings to
        
    Returns:
        Dictionary with scan results summary
    """
    import asyncio
    from backend.services.agentic_scan_service import AgenticScanService, progress_to_dict
    from backend.services.websocket_service import progress_manager
    
    logger.info(f"Starting agentic scan for project {project_id}")
    db = SessionLocal()
    
    # Publish initial agentic scan status
    progress_manager.publish_progress(
        scan_run_id, "agentic_initializing", 0,
        "🤖 Starting Agentic AI deep analysis..."
    )
    
    temp_dir = None
    try:
        project = db.get(models.Project, project_id)
        if not project:
            logger.error(f"Project {project_id} not found")
            raise ProjectNotFoundError(project_id)
        
        # Determine code path - extract ZIP if uploaded
        from backend.services.codebase_service import unpack_zip_to_temp
        
        code_path = None
        if project.upload_path:
            # Extract ZIP to temp directory for scanning
            logger.info(f"Extracting {project.upload_path} for agentic scan")
            temp_dir = unpack_zip_to_temp(project.upload_path)
            code_path = str(temp_dir)
            logger.info(f"Extracted to {code_path}")
        elif project.git_url:
            code_path = project.git_url
        
        if not code_path:
            logger.error(f"No code path found for project {project_id}")
            return {"error": "No code available for scanning"}
        
        # Run the agentic scan with progress callback
        service = AgenticScanService()
        
        def progress_callback(progress):
            """Publish progress updates to WebSocket with detailed stats"""
            phase_map = {
                "initializing": ("agentic_initializing", 5),
                "chunking": ("agentic_chunking", 15),
                "entry_point_detection": ("agentic_entry_points", 35),
                "flow_tracing": ("agentic_flow_tracing", 60),
                "vulnerability_analysis": ("agentic_analyzing", 85),
                "report_generation": ("agentic_reporting", 95),
                "complete": ("agentic_complete", 100),
                "error": ("agentic_error", 0),
            }
            phase_name = progress.phase.value if hasattr(progress.phase, 'value') else progress.phase
            ws_phase, ws_progress = phase_map.get(phase_name, ("agentic_scanning", 50))
            
            # Build detailed message with stats
            stats_parts = []
            if progress.total_chunks > 0:
                stats_parts.append(f"📄 {progress.analyzed_chunks}/{progress.total_chunks} chunks")
            if progress.entry_points_found > 0:
                stats_parts.append(f"🎯 {progress.entry_points_found} entry points")
            if progress.flows_traced > 0:
                stats_parts.append(f"🔀 {progress.flows_traced} flows")
            if progress.vulnerabilities_found > 0:
                stats_parts.append(f"⚠️ {progress.vulnerabilities_found} vulns")
            
            stats_str = " | ".join(stats_parts) if stats_parts else ""
            base_message = progress.message or phase_name
            full_message = f"🤖 {base_message}"
            if stats_str:
                full_message += f"\n{stats_str}"
            
            progress_manager.publish_progress(
                scan_run_id, ws_phase, ws_progress,
                full_message
            )
        
        async def run_scan_with_retry(max_retries: int = 2):
            """Run scan with retry logic for transient failures"""
            last_error = None
            for attempt in range(max_retries + 1):
                try:
                    if attempt > 0:
                        logger.info(f"Agentic scan retry attempt {attempt}/{max_retries}")
                        progress_manager.publish_progress(
                            scan_run_id, "agentic_initializing", 5,
                            f"🤖 Retrying scan (attempt {attempt + 1}/{max_retries + 1})..."
                        )
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
                    scan_id = await service.start_scan(
                        project_id=project_id,
                        project_path=code_path,
                        progress_callback=progress_callback
                    )
                    return service.get_result(scan_id)
                except Exception as e:
                    last_error = e
                    logger.warning(f"Agentic scan attempt {attempt + 1} failed: {e}")
                    if "rate limit" in str(e).lower() or "timeout" in str(e).lower():
                        continue  # Retry on rate limits and timeouts
                    raise  # Don't retry other errors
            raise last_error
        
        result = asyncio.run(run_scan_with_retry())
        
        if result is None:
            logger.error(f"Agentic scan returned no result for project {project_id}")
            progress_manager.publish_progress(
                scan_run_id, "agentic_error", 0,
                "🤖 Agentic scan failed - no result returned"
            )
            return {"error": "Scan returned no result"}
        
        # Store agentic findings in the report
        report = db.get(models.Report, report_id)
        if report:
            report_data = report.data or {}
            report_data["agentic_scan"] = {
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "vulnerability_type": v.vulnerability_type,
                        "severity": v.severity,
                        "title": v.title,
                        "description": v.description,
                        "file_path": v.flow.entry_point.file_path if v.flow else None,
                        "line_number": v.flow.entry_point.line_number if v.flow else None,
                        "confidence": v.confidence,
                        "remediation": v.remediation,
                        "exploit_scenario": v.exploit_scenario,
                        "cwe_id": v.cwe_id,
                        "owasp_category": v.owasp_category,
                    }
                    for v in result.vulnerabilities
                ],
                "entry_points_count": len(result.entry_points),
                "files_analyzed": result.analyzed_chunks,
                "total_chunks": result.total_chunks,
                "duration_seconds": result.scan_duration_seconds,
                "status": "complete",
            }
            report.data = report_data
            db.commit()
            logger.info(f"Stored {len(result.vulnerabilities)} agentic findings for report {report_id}")
        
        # Also store as regular findings for unified view
        for vuln in result.vulnerabilities:
            file_path = vuln.flow.entry_point.file_path if vuln.flow else "unknown"
            line_number = vuln.flow.entry_point.line_number if vuln.flow else 1
            
            finding = models.Finding(
                project_id=project_id,
                scan_run_id=scan_run_id,
                type=f"agentic-{vuln.vulnerability_type}",
                severity=vuln.severity,
                file_path=file_path,
                start_line=line_number,
                summary=vuln.description[:500] if vuln.description else "Agentic AI detected vulnerability",
                details={
                    "source": "agentic_ai",
                    "vulnerability_type": vuln.vulnerability_type,
                    "confidence": vuln.confidence,
                    "remediation": vuln.remediation,
                    "exploit_scenario": vuln.exploit_scenario,
                    "cwe_id": vuln.cwe_id,
                }
            )
            db.add(finding)
        
        db.commit()
        
        # Publish completion
        progress_manager.publish_progress(
            scan_run_id, "agentic_complete", 100,
            f"🤖 Agentic AI scan complete! Found {len(result.vulnerabilities)} vulnerabilities"
        )
        
        logger.info(f"Agentic scan completed for project {project_id}")
        
        return {
            "vulnerabilities_found": len(result.vulnerabilities),
            "files_analyzed": result.analyzed_chunks,
            "duration_seconds": result.scan_duration_seconds,
        }
        
    except Exception as e:
        logger.exception(f"Agentic scan failed for project {project_id}: {e}")
        progress_manager.publish_progress(
            scan_run_id, "agentic_error", 0,
            f"🤖 Agentic scan failed: {str(e)[:100]}"
        )
        raise
    finally:
        # Clean up temp directory if created
        if temp_dir and temp_dir.exists():
            import shutil
            try:
                shutil.rmtree(temp_dir)
                logger.debug(f"Cleaned up temp dir: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temp dir {temp_dir}: {e}")
        db.close()