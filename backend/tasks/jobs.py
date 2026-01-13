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
        
        # Check if summaries already exist and are still valid
        # Summaries should be regenerated if findings have changed
        existing_summaries = report.data.get("ai_summaries") if report.data else None
        if existing_summaries:
            # Check if findings count matches what was used for the summary
            summary_findings_count = existing_summaries.get("findings_count", 0)
            current_findings_count = db.query(models.Finding).filter(
                models.Finding.scan_run_id == report.scan_run_id
            ).count()
            
            if summary_findings_count == current_findings_count:
                logger.info(f"AI summaries already exist for report {report_id} with same finding count ({current_findings_count}), skipping")
                return report_id
            else:
                logger.info(f"AI summaries need refresh: findings changed from {summary_findings_count} to {current_findings_count}")
        
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
                
                app_prompt = f"""You are an expert software architect and code analyst. Your task is to provide a COMPREHENSIVE analysis of what this application does based on DEEP code inspection.

## PROJECT INFORMATION
Project Name: {project.name if project else 'Unknown'}
Total Code: {total_files} files, {total_lines:,} lines of code
Languages: {', '.join(f'{lang}: {count} files' for lang, count in sorted(languages.items(), key=lambda x: -x[1])[:8])}
Security Scan Results: {severity_counts['critical']} critical, {severity_counts['high']} high, {severity_counts['medium']} medium issues
{dep_context}
{scan_context}
{synthesis_context}

## DEEPLY ANALYZED SOURCE FILES ({len(priority_code_samples)} files with full context):
{chr(10).join(code_sections)}

## YOUR TASK
Perform a THOROUGH analysis of the codebase by:
1. Reading ALL provided source code carefully
2. Tracing data flows and feature implementations
3. Identifying ALL major features and capabilities
4. Understanding how different components work together
5. Noting any hidden or non-obvious functionality

Generate a DETAILED, COMPREHENSIVE report. Use HTML formatting.

FORMAT YOUR RESPONSE AS CLEAN HTML (no markdown, no code blocks):
- Use <h3> for section headers
- Use <h4> for sub-sections
- Use <ul> and <li> for bullet points
- Use <strong> for emphasis
- Use <p> for paragraphs
- Use <code> for class/method names

REQUIRED SECTIONS (BE THOROUGH):

<h3>📱 Application Overview</h3>
<p>[2-3 sentences describing what this application is, its purpose, and target audience - base this on actual code analysis]</p>

<h3>🎯 Core Features & Functionality</h3>
<p>Based on deep code analysis, this application provides the following features:</p>

<h4>Main Features</h4>
<ul>
<li><strong>[Feature Name]:</strong> [Detailed description of what it does, HOW it works based on the code you see, which classes/modules implement it]</li>
[List ALL major features you can identify from the code]
</ul>

<h4>User Interface & Navigation</h4>
<ul>
<li>[Describe the app's UI patterns, components, pages/views, and navigation flow based on code analysis]</li>
</ul>

<h3>🔐 Authentication & User Management</h3>
<ul>
<li><strong>Authentication:</strong> [How authentication works - JWT? OAuth? Session-based? API keys?]</li>
<li><strong>Authorization:</strong> [Role-based? Permission system? Access control patterns?]</li>
<li><strong>Session Management:</strong> [How sessions/tokens are handled]</li>
<li><strong>User Data:</strong> [What user data is collected/stored]</li>
</ul>

<h3>📡 API & Network Communication</h3>
<h4>API Endpoints</h4>
<ul>
<li><strong>Endpoint Patterns:</strong> [REST? GraphQL? WebSocket?]</li>
<li><strong>Key Routes:</strong> [List important API endpoints found in code]</li>
<li><strong>Data Formats:</strong> [JSON? XML? How is data serialized?]</li>
</ul>

<h4>External Services</h4>
<ul>
<li>[Third-party APIs, cloud services, external dependencies]</li>
</ul>

<h3>💾 Data Storage & Persistence</h3>
<ul>
<li><strong>Database:</strong> [SQL? NoSQL? What ORM/driver? Schema patterns?]</li>
<li><strong>Caching:</strong> [Redis? Memcached? In-memory?]</li>
<li><strong>File Storage:</strong> [Local files? Cloud storage? How files are handled?]</li>
<li><strong>Data Models:</strong> [Key entities and relationships]</li>
</ul>

<h3>⚙️ Technology Stack</h3>
<ul>
<li><strong>Languages:</strong> [Programming languages with specific versions if apparent]</li>
<li><strong>Frameworks:</strong> [Web frameworks, libraries used]</li>
<li><strong>Build Tools:</strong> [Package managers, build systems]</li>
<li><strong>Runtime:</strong> [Node.js? Python? Docker?]</li>
</ul>

<h3>🏗️ Architecture & Design Patterns</h3>
<ul>
<li><strong>Architecture Style:</strong> [Monolith? Microservices? MVC? Clean Architecture?]</li>
<li><strong>Design Patterns:</strong> [Repository? Factory? Observer? etc.]</li>
<li><strong>Code Organization:</strong> [How is the codebase structured?]</li>
<li><strong>Module Boundaries:</strong> [How do components interact?]</li>
</ul>

<h3>🔌 Background Processing & Jobs</h3>
<ul>
<li>[Scheduled tasks? Message queues? Worker processes? Cron jobs?]</li>
</ul>

<h3>🔗 Integrations & External Dependencies</h3>
<ul>
<li>[Email services? Payment processors? Analytics? Logging?]</li>
</ul>

<h3>🔍 Notable Implementation Details</h3>
<ul>
<li>[Interesting technical patterns you noticed in the code]</li>
<li>[Unique approaches or clever solutions]</li>
<li>[Technical debt or areas that could be improved]</li>
</ul>

<h3>📊 Application Complexity Assessment</h3>
<p>[Simple utility / Medium complexity / Complex enterprise application - justify based on code analysis]</p>
<ul>
<li><strong>Lines of Code:</strong> {total_lines:,}</li>
<li><strong>File Count:</strong> {total_files}</li>
<li><strong>Technical Sophistication:</strong> [Basic / Intermediate / Advanced]</li>
</ul>

BE THOROUGH AND SPECIFIC. Reference actual classes, functions, and files you see in the code. Don't make assumptions - only report what you can verify from the code."""

                # Generate app summary
                logger.info(f"Generating comprehensive app summary for report {report_id}")
                from google.genai import types
                response = client.models.generate_content(
                    model=settings.gemini_model_id,
                    contents=app_prompt,
                    config=types.GenerateContentConfig(max_output_tokens=4000)
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
                    
                    security_prompt = f"""You are an elite RED TEAM OPERATOR performing offensive security assessment of this codebase. Your goal is to find EXPLOITABLE vulnerabilities and demonstrate HOW to attack this application.

Think like an ATTACKER, not a compliance auditor. Focus on:
- What can I ACTUALLY exploit?
- How do I chain vulnerabilities together?
- What's the realistic attack path to compromise the system?
- What would I do FIRST if I wanted to hack this app?

## CODEBASE CONTEXT
Project: {project.name if project else 'Unknown'}
{scan_context}

## SECURITY FINDINGS IDENTIFIED

### Severity Distribution
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Agentic AI Findings (deep analysis): {len(agentic_findings)}
- SAST Scanner Findings: {len(sast_findings)}
Total: {len(findings)} security weaknesses identified

### Findings by Category
{type_breakdown}
{attack_chain_context}
{synthesis_context if agentic_assessment else ""}

### Vulnerable Code Files
{chr(10).join(security_code_sections[:10])}

### Detailed Findings
{chr(10).join(f"- [{f['severity'].upper()}] {f['type']} @ {f['file']}:{f['line']} {f['corroborated']}{f['fp_note']}" + chr(10) + f"  {f['summary']}" for f in findings_details)}

### Vulnerable Dependencies
{chr(10).join(f"- {v.external_id} (CVSS: {v.cvss_score}, Severity: {v.severity}): {v.description[:150] if v.description else 'N/A'}" for v in vulnerabilities[:15])}

## YOUR MISSION
Perform an OFFENSIVE security assessment:
1. Identify the ATTACK SURFACE - where can an attacker get in?
2. Find EXPLOITABLE vulnerabilities with working attack scenarios
3. Build ATTACK CHAINS - how do multiple weaknesses combine?
4. Prioritize by REAL-WORLD EXPLOITABILITY, not theoretical risk
5. Provide PROOF-OF-CONCEPT ideas for each finding
6. Consider both REMOTE attacks (network) and LOCAL attacks (insider, supply chain)

Generate an ATTACKER-FOCUSED security report. Use HTML formatting.

FORMAT YOUR RESPONSE AS CLEAN HTML (no markdown):
- Use <h3> for section headers
- Use <h4> for sub-sections
- Use <ul> and <li> for bullet points
- Use <strong> for emphasis
- Use <code> ONLY for very short inline references like file paths
- ALWAYS use <pre><code>...</code></pre> for ANY code snippet, even single lines
- Severity badges: <span style="color: #dc2626; font-weight: bold;">CRITICAL</span>, <span style="color: #ea580c; font-weight: bold;">HIGH</span>, <span style="color: #ca8a04; font-weight: bold;">MEDIUM</span>, <span style="color: #16a34a; font-weight: bold;">LOW</span>

CRITICAL: ALL CODE MUST USE THIS EXACT FORMAT (not inside <li> tags):
<p><strong>Vulnerable Code:</strong></p>
<pre><code>$substitutions = array('&amp;' => '', ';' => '');
// This is vulnerable because...</code></pre>

<p><strong>PoC Exploit:</strong></p>
<pre><code>curl -X POST "https://target/api" -d "payload"</code></pre>

NEVER put code directly after a colon on the same line. ALWAYS use <pre><code> block on new line.

REQUIRED SECTIONS:

<h3>⚔️ Attack Summary</h3>
<p><strong>Hackability Score:</strong> [X/10] - How easy is this application to compromise?</p>
<p><strong>Most Dangerous Finding:</strong> [One-liner of the worst issue]</p>
<p><strong>Recommended Attack Path:</strong> [The attack chain I would use]</p>
<p><strong>Attacker Value:</strong> [What's worth stealing? User data? Credentials? Money? Business logic?]</p>

<h3>🎯 Attack Surface Analysis</h3>
<h4>Entry Points (How I Get In)</h4>
<ul>
<li><strong>API Endpoints:</strong> [Which endpoints are vulnerable? Authentication bypasses?]</li>
<li><strong>User Input:</strong> [Form fields, file uploads, query parameters at risk]</li>
<li><strong>Authentication:</strong> [Login weaknesses, session handling issues]</li>
<li><strong>File Operations:</strong> [Path traversal, file upload, file inclusion risks]</li>
<li><strong>Database Queries:</strong> [SQL injection, NoSQL injection points]</li>
<li><strong>External Dependencies:</strong> [Vulnerable libraries, supply chain risks]</li>
</ul>

<h4>Sensitive Assets (What I Want)</h4>
<ul>
<li>[User credentials, tokens, personal data, financial info, business data]</li>
<li>[Where is each asset stored? How is it protected?]</li>
</ul>

<h3>💀 Critical Exploits</h3>
<p>Vulnerabilities I can exploit RIGHT NOW:</p>

<h4>Exploit 1: [Catchy Attack Name]</h4>
<p><span style="color: #dc2626; font-weight: bold;">CRITICAL</span> (or appropriate severity)</p>
<ul>
<li><strong>What:</strong> [Technical description]</li>
<li><strong>Where:</strong> <code>[File:Line]</code></li>
</ul>
<p><strong>Vulnerable Code:</strong></p>
<pre><code>[The actual vulnerable code snippet - multiple lines]</code></pre>
<ul>
<li><strong>Attack Scenario:</strong> [Step-by-step how I would exploit this]</li>
</ul>
<p><strong>PoC:</strong></p>
<pre><code>[curl command / payload / exploit script]</code></pre>
<ul>
<li><strong>Impact:</strong> [What I gain - RCE? Data theft? Account takeover?]</li>
<li><strong>Difficulty:</strong> [Easy/Medium/Hard] - [Why]</li>
</ul>

[Repeat for top 3-5 most critical exploits]

<h3>🔗 Attack Chains</h3>
<p>How I combine multiple weaknesses for maximum impact:</p>

<h4>Chain 1: [Attack Chain Name]</h4>
<ol>
<li><strong>Step 1:</strong> [First exploit/technique - initial access]</li>
<li><strong>Step 2:</strong> [Second exploit/technique - escalation]</li>
<li><strong>Step 3:</strong> [Third technique - lateral movement or data access]</li>
<li><strong>Result:</strong> [What attacker achieves - full compromise, data exfil, etc.]</li>
</ol>

<h3>🔓 Authentication & Session Attacks</h3>
<ul>
<li><strong>Token Weakness:</strong> [Can I forge/steal/reuse tokens?]</li>
<li><strong>Session Hijacking:</strong> [How would I steal a session?]</li>
<li><strong>Credential Extraction:</strong> [Where are creds stored? Can I get them?]</li>
<li><strong>Privilege Escalation:</strong> [Can regular user become admin?]</li>
</ul>

<h3>💉 Injection Attack Vectors</h3>
<ul>
<li><strong>SQL Injection:</strong> [Where? PoC query?]</li>
<li><strong>Command Injection:</strong> [Any exec/system calls?]</li>
<li><strong>XSS (Cross-Site Scripting):</strong> [User input reflected unsanitized?]</li>
<li><strong>Path Traversal:</strong> [File operations I can abuse?]</li>
</ul>

<h3>🔑 Secrets & Sensitive Data Exposure</h3>
<ul>
<li><strong>[Secret Type]:</strong> <code>[Location]</code> - Risk: [What access does this give me?]</li>
</ul>

<h3>📦 Vulnerable Dependencies</h3>
<ul>
<li><strong>[Library Name]:</strong> [Known CVEs] - Exploitability: [Can I actually exploit this?]</li>
</ul>

<h3>🏴‍☠️ Exploit Scripts & PoCs</h3>
<p>Ready-to-use attack scripts and payloads:</p>
<pre><code># Example SQL Injection PoC
curl -X POST "https://target/api/endpoint" \\
  -H "Content-Type: application/json" \\
  -d '{{"id": "1' OR '1'='1"}}'
</code></pre>

<pre><code># Example Command Injection PoC
curl "https://target/api/ping?host=127.0.0.1;cat+/etc/passwd"
</code></pre>

<p>[Include actual PoC scripts based on the vulnerabilities found]</p>

<h3>📋 Attack Playbook</h3>
<p>If I had 1 hour to hack this application, I would:</p>
<ol>
<li><strong>[First 15 min]:</strong> [Initial reconnaissance and access technique]</li>
<li><strong>[Next 15 min]:</strong> [Privilege escalation / deeper access]</li>
<li><strong>[Next 15 min]:</strong> [Data exfiltration / persistence]</li>
<li><strong>[Final 15 min]:</strong> [Cover tracks / maximize impact]</li>
</ol>

<h3>🎯 Bug Bounty Priority List</h3>
<p>If this app had a bug bounty, I'd focus on:</p>
<ol>
<li>[Highest-impact vulnerability class] - [Why it's exploitable here]</li>
<li>[Second target] - [Specific weakness and approach]</li>
<li>[Third target] - [Attack vector]</li>
</ol>

<h3>⚠️ Quick Wins for Defenders</h3>
<p>Immediate fixes that would significantly reduce risk:</p>
<ol>
<li>[Critical fix #1 with specific code location]</li>
<li>[Critical fix #2 with implementation guidance]</li>
<li>[Critical fix #3 with detection/prevention tips]</li>
</ol>

## CRITICAL: REAL EXPLOITS ONLY
- Only report vulnerabilities you could ACTUALLY EXPLOIT based on the findings
- Provide SPECIFIC attack scenarios, not theoretical risks
- Include PROOF-OF-CONCEPT ideas (payloads, curl commands, scripts)
- Focus on REAL, EXPLOITABLE issues that would affect users

BE EXHAUSTIVE but ACCURATE. Reference specific code locations and files."""

                    logger.info(f"Generating comprehensive security summary for report {report_id}")
                    response = client.models.generate_content(
                        model=settings.gemini_model_id,
                        contents=security_prompt,
                        config=types.GenerateContentConfig(max_output_tokens=4000)
                    )
                    if response and response.text:
                        security_summary = response.text
                        logger.info(f"Generated security summary for report {report_id}")
                
                # Cache the summaries with metadata for cache validation
                if app_summary or security_summary:
                    report_data = report.data or {}
                    report_data["ai_summaries"] = {
                        "app_summary": app_summary,
                        "security_summary": security_summary,
                        "findings_count": len(findings),  # Track for cache invalidation
                        "generated_at": str(report.created_at),
                    }
                    report.data = report_data
                    db.commit()
                    logger.info(f"Cached AI summaries for report {report_id} (based on {len(findings)} findings)")
                    
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
        # Check for existing agentic findings to prevent duplicates (e.g., if inline scan already ran)
        existing_agentic = db.query(models.Finding).filter(
            models.Finding.scan_run_id == scan_run_id,
            models.Finding.type.like("agentic-%")
        ).all()
        
        # Build lookup set of existing findings by (file, line, type) to prevent duplicates
        existing_keys = set()
        for ef in existing_agentic:
            key = (ef.file_path, ef.start_line, ef.type)
            existing_keys.add(key)
        
        new_findings_count = 0
        for vuln in result.vulnerabilities:
            file_path = vuln.flow.entry_point.file_path if vuln.flow else "unknown"
            line_number = vuln.flow.entry_point.line_number if vuln.flow else 1
            finding_type = f"agentic-{vuln.vulnerability_type}"
            
            # Skip if this finding already exists (from inline scan)
            key = (file_path, line_number, finding_type)
            if key in existing_keys:
                logger.debug(f"Skipping duplicate agentic finding: {finding_type} at {file_path}:{line_number}")
                continue
            
            finding = models.Finding(
                project_id=project_id,
                scan_run_id=scan_run_id,
                type=finding_type,
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
            existing_keys.add(key)  # Track this finding to avoid self-duplicates
            new_findings_count += 1
        
        db.commit()
        logger.info(f"Added {new_findings_count} new agentic findings (skipped {len(result.vulnerabilities) - new_findings_count} duplicates)")
        
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