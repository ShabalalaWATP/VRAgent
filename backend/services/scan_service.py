import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Dict, Any, Callable
import hashlib

from sqlalchemy.orm import Session

from backend import models
from backend.core.config import settings
from backend.core.exceptions import ScanError
from backend.core.logging import get_logger
from backend.services import cve_service, dependency_service, report_service
from backend.services import secret_service, eslint_service, epss_service, semgrep_service
from backend.services import nvd_service, bandit_service, gosec_service
from backend.services import spotbugs_service, clangtidy_service
from backend.services import ai_analysis_service
from backend.services import deduplication_service, transitive_deps_service, reachability_service
from backend.services import docker_scan_service, iac_scan_service
from backend.services.codebase_service import (
    create_code_chunks,
    iter_source_files,
    split_into_chunks,
    unpack_zip_to_temp,
)
from backend.services.embedding_service import enrich_code_chunks
from backend.services.websocket_service import progress_manager
from backend.services.webhook_service import notify_scan_complete, get_webhooks

logger = get_logger(__name__)

# Maximum parallel scanners (don't overwhelm the system)
MAX_PARALLEL_SCANNERS = settings.max_parallel_scanners
# Maximum parallel phases for concurrent execution
MAX_PARALLEL_PHASES = 4
# Batch size for processing files in large codebases
FILE_PROCESSING_BATCH_SIZE = 100
# Maximum total chunks to process (prevents memory issues on huge repos)
MAX_TOTAL_CHUNKS = settings.max_total_chunks
# Memory-efficient chunk limit before flushing to DB
CHUNK_FLUSH_THRESHOLD = settings.chunk_flush_threshold


# Thread-safe progress tracking for parallel phases
class ParallelPhaseTracker:
    """Track progress of multiple parallel phases."""
    
    def __init__(self, scan_run_id: int, base_progress: int, progress_range: int):
        self.scan_run_id = scan_run_id
        self.base_progress = base_progress
        self.progress_range = progress_range
        self.phase_progress: Dict[str, int] = {}
        self._lock = __import__('threading').Lock()
    
    def update(self, phase: str, progress: int, message: str = ""):
        """Update progress for a specific phase."""
        with self._lock:
            self.phase_progress[phase] = progress
            # Calculate overall progress based on all phases
            if self.phase_progress:
                avg_progress = sum(self.phase_progress.values()) / len(self.phase_progress)
                overall = self.base_progress + int((avg_progress / 100) * self.progress_range)
                _broadcast_progress(self.scan_run_id, phase, overall, message)


def _broadcast_progress(scan_run_id: int, phase: str, progress: int, message: str = ""):
    """Helper to broadcast scan progress via Redis pub/sub to WebSocket clients."""
    try:
        # Use synchronous publish for worker process
        progress_manager.publish_progress(scan_run_id, phase, progress, message)
    except Exception as e:
        logger.debug(f"Could not broadcast progress: {e}")


def _detect_language(path: Path) -> str:
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescriptreact",
        ".java": "java",
        ".rb": "ruby",
        ".go": "go",
        ".php": "php",
        ".rs": "rust",
        ".kt": "kotlin",
        ".kts": "kotlin",
    }
    return mapping.get(path.suffix, "unknown")


def _compute_code_hash(code: str) -> str:
    """Compute a hash of code content for change detection."""
    return hashlib.sha256(code.encode()).hexdigest()[:32]


def _get_existing_embeddings(
    db: Session, 
    project_id: int
) -> dict:
    """
    Get existing code chunks with embeddings for a project.
    Returns a dict mapping (file_path, start_line, code_hash) -> embedding.
    This allows us to reuse embeddings when code hasn't changed.
    """
    existing_chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == project_id,
        models.CodeChunk.embedding.isnot(None)
    ).all()
    
    embeddings_map = {}
    for chunk in existing_chunks:
        # Only include chunks that have non-zero embeddings
        if chunk.embedding is not None:
            # Check if it's a zero vector (placeholder)
            embedding_list = list(chunk.embedding) if hasattr(chunk.embedding, '__iter__') else []
            if embedding_list and any(v != 0.0 for v in embedding_list[:10]):  # Check first 10 values
                code_hash = _compute_code_hash(chunk.code)
                key = (chunk.file_path, chunk.start_line, code_hash)
                embeddings_map[key] = embedding_list
    
    return embeddings_map


def _reuse_or_generate_embeddings(
    db: Session,
    project: models.Project,
    new_chunks: List[models.CodeChunk],
    existing_embeddings: dict
) -> tuple:
    """
    Check which chunks already have embeddings that can be reused.
    Returns (chunks_needing_embeddings, chunks_with_reused_embeddings, reuse_count).
    """
    chunks_to_embed = []
    reused_count = 0
    
    for chunk in new_chunks:
        code_hash = _compute_code_hash(chunk.code)
        key = (chunk.file_path, chunk.start_line, code_hash)
        
        if key in existing_embeddings:
            # Reuse existing embedding
            chunk.embedding = existing_embeddings[key]
            reused_count += 1
        else:
            chunks_to_embed.append(chunk)
    
    return chunks_to_embed, reused_count


def _run_scanners_parallel(source_root: Path, timeout_per_scanner: int = None) -> Dict[str, List[Any]]:
    """
    Run all SAST scanners in parallel using ThreadPoolExecutor.
    
    Each scanner runs in its own thread (they're subprocess-bound anyway).
    Returns a dict mapping scanner name to list of findings.
    
    Features for large codebases:
    - Per-scanner timeout to prevent hanging
    - Progressive result collection
    - Graceful degradation on scanner failures
    
    Args:
        source_root: Path to the source code directory
        timeout_per_scanner: Maximum seconds per scanner (uses config default if None)
        
    Returns:
        Dict mapping scanner name to list of findings
    """
    if timeout_per_scanner is None:
        timeout_per_scanner = settings.scanner_timeout
    results: Dict[str, List[Any]] = {
        "semgrep": [],
        "bandit": [],
        "gosec": [],
        "spotbugs": [],
        "clangtidy": [],
        "eslint": [],
        "secrets": [],
    }
    
    # Define scanner tasks: (name, check_available_func, run_func)
    scanner_tasks = []
    
    # Semgrep (all languages)
    if semgrep_service.is_semgrep_available():
        scanner_tasks.append(("semgrep", lambda: semgrep_service.run_security_audit(source_root)))
    
    # Bandit (Python)
    if bandit_service.is_bandit_available():
        scanner_tasks.append(("bandit", lambda: bandit_service.run_security_audit(source_root)))
    
    # gosec (Go)
    if gosec_service.is_gosec_available():
        scanner_tasks.append(("gosec", lambda: gosec_service.run_security_audit(source_root)))
    
    # SpotBugs (Java)
    if spotbugs_service.is_spotbugs_available():
        scanner_tasks.append(("spotbugs", lambda: spotbugs_service.run_security_audit(source_root)))
    
    # clang-tidy (C/C++)
    if clangtidy_service.is_clangtidy_available():
        scanner_tasks.append(("clangtidy", lambda: clangtidy_service.run_security_audit(source_root)))
    
    # ESLint (JS/TS) - always available (falls back gracefully)
    scanner_tasks.append(("eslint", lambda: eslint_service.run_eslint_security_scan(str(source_root))))
    
    # Secret scanner (Python-based, always available)
    scanner_tasks.append(("secrets", lambda: secret_service.scan_directory(str(source_root))))
    
    if not scanner_tasks:
        logger.warning("No scanners available")
        return results
    
    logger.info(f"Running {len(scanner_tasks)} scanners in parallel: {[t[0] for t in scanner_tasks]}")
    
    # Run scanners in parallel with individual timeouts
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_SCANNERS) as executor:
        # Submit all tasks
        future_to_name = {
            executor.submit(run_func): name 
            for name, run_func in scanner_tasks
        }
        
        # Collect results as they complete with timeout
        for future in as_completed(future_to_name, timeout=timeout_per_scanner * len(scanner_tasks)):
            name = future_to_name[future]
            try:
                scanner_results = future.result(timeout=timeout_per_scanner)
                results[name] = scanner_results if scanner_results else []
                logger.info(f"Scanner {name} completed: {len(results[name])} findings")
            except TimeoutError:
                logger.warning(f"Scanner {name} timed out after {timeout_per_scanner}s")
                results[name] = []
            except Exception as e:
                logger.error(f"Scanner {name} failed: {e}")
                results[name] = []
    
    total_findings = sum(len(v) for v in results.values())
    logger.info(f"All scanners complete. Total findings: {total_findings}")
    
    return results


def _run_parallel_scan_phases(
    source_root: Path,
    project: models.Project,
    tracker: ParallelPhaseTracker,
    timeout: int = None
) -> Dict[str, Any]:
    """
    Run multiple independent scan phases in parallel.
    
    This includes:
    - SAST scanners (Semgrep, Bandit, etc.)
    - Docker scanning (Dockerfile + image vulns)
    - IaC scanning (Terraform, K8s, CloudFormation)
    - Dependency parsing
    
    These phases don't depend on each other and can run concurrently.
    
    Args:
        source_root: Path to extracted source code
        project: Project being scanned
        tracker: Progress tracker for parallel updates
        timeout: Per-phase timeout
        
    Returns:
        Dict with results from each phase
    """
    if timeout is None:
        timeout = settings.scanner_timeout
    
    results = {
        "sast": {},
        "docker": None,
        "iac": None,
        "dependencies": [],
    }
    
    def run_sast():
        """Run all SAST scanners."""
        tracker.update("sast", 10, "Starting SAST scanners")
        sast_results = _run_scanners_parallel(source_root, timeout)
        tracker.update("sast", 100, f"SAST complete")
        return ("sast", sast_results)
    
    def run_docker():
        """Run Docker scanning."""
        tracker.update("docker", 10, "Scanning Docker resources")
        try:
            docker_result = docker_scan_service.scan_docker_resources(
                source_root,
                scan_images=docker_scan_service.is_trivy_available(),
                image_timeout=timeout
            )
            tracker.update("docker", 100, f"Docker scan complete: {len(docker_result.dockerfile_findings)} findings")
            return ("docker", docker_result)
        except Exception as e:
            logger.warning(f"Docker scanning failed: {e}")
            tracker.update("docker", 100, "Docker scan skipped")
            return ("docker", None)
    
    def run_iac():
        """Run IaC scanning."""
        tracker.update("iac", 10, "Scanning Infrastructure as Code")
        try:
            iac_result = iac_scan_service.scan_iac(
                source_root,
                use_checkov=iac_scan_service.is_checkov_available(),
                use_tfsec=iac_scan_service.is_tfsec_available(),
                timeout=timeout
            )
            tracker.update("iac", 100, f"IaC scan complete: {len(iac_result.findings)} findings")
            return ("iac", iac_result)
        except Exception as e:
            logger.warning(f"IaC scanning failed: {e}")
            tracker.update("iac", 100, "IaC scan skipped")
            return ("iac", None)
    
    def run_deps():
        """Parse dependencies."""
        tracker.update("dependencies", 10, "Parsing dependencies")
        try:
            deps = dependency_service.parse_dependencies(project, source_root)
            tracker.update("dependencies", 100, f"Found {len(deps)} dependencies")
            return ("dependencies", deps)
        except Exception as e:
            logger.warning(f"Dependency parsing failed: {e}")
            tracker.update("dependencies", 100, "Dependency parsing failed")
            return ("dependencies", [])
    
    # Run all phases in parallel
    phases = [run_sast, run_docker, run_iac, run_deps]
    logger.info(f"Running {len(phases)} scan phases in parallel")
    
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_PHASES) as executor:
        futures = {executor.submit(phase): phase.__name__ for phase in phases}
        
        for future in as_completed(futures, timeout=timeout * len(phases)):
            phase_name = futures[future]
            try:
                key, result = future.result(timeout=timeout)
                results[key] = result
                logger.debug(f"Phase {phase_name} completed")
            except TimeoutError:
                logger.warning(f"Phase {phase_name} timed out")
            except Exception as e:
                logger.error(f"Phase {phase_name} failed: {e}")
    
    return results


def _convert_scanner_results_to_findings(
    scanner_results: Dict[str, List[Any]], 
    source_root: Path
) -> List[models.Finding]:
    """Convert raw scanner results into Finding models."""
    findings: List[models.Finding] = []
    
    # Process Semgrep findings
    for sg_finding in scanner_results.get("semgrep", []):
        try:
            rel_path = str(Path(sg_finding.file_path).relative_to(source_root))
        except ValueError:
            rel_path = sg_finding.file_path
        
        findings.append(
            models.Finding(
                type="semgrep",
                severity=sg_finding.severity,
                file_path=rel_path,
                start_line=sg_finding.line_start,
                end_line=sg_finding.line_end,
                summary=f"[{sg_finding.rule_id}] {sg_finding.message}",
                details={
                    "rule_id": sg_finding.rule_id,
                    "category": sg_finding.category,
                    "cwe": sg_finding.cwe,
                    "owasp": sg_finding.owasp,
                    "code_snippet": sg_finding.code_snippet[:500] if sg_finding.code_snippet else None,
                    "fix": sg_finding.fix,
                },
            )
        )
    
    # Process Bandit findings
    for bandit_finding in scanner_results.get("bandit", []):
        try:
            rel_path = str(Path(bandit_finding.file_path).relative_to(source_root))
        except ValueError:
            rel_path = bandit_finding.file_path
        
        findings.append(
            models.Finding(
                type="bandit",
                severity=bandit_finding.severity,
                file_path=rel_path,
                start_line=bandit_finding.line_number,
                end_line=bandit_finding.line_range[1] if bandit_finding.line_range and len(bandit_finding.line_range) > 1 else bandit_finding.line_number,
                summary=f"[{bandit_finding.test_id}] {bandit_finding.message}",
                details={
                    "test_id": bandit_finding.test_id,
                    "test_name": bandit_finding.test_name,
                    "confidence": bandit_finding.confidence,
                    "cwe": bandit_finding.cwe,
                    "code_snippet": bandit_finding.code[:500] if bandit_finding.code else None,
                    "more_info": bandit_finding.more_info,
                },
            )
        )
    
    # Process gosec findings
    for gosec_finding in scanner_results.get("gosec", []):
        try:
            rel_path = str(Path(gosec_finding.file_path).relative_to(source_root))
        except ValueError:
            rel_path = gosec_finding.file_path
        
        findings.append(
            models.Finding(
                type="gosec",
                severity=gosec_finding.severity,
                file_path=rel_path,
                start_line=gosec_finding.line,
                end_line=gosec_finding.line,
                summary=f"[{gosec_finding.rule_id}] {gosec_finding.details}",
                details={
                    "rule_id": gosec_finding.rule_id,
                    "cwe": gosec_finding.cwe,
                    "confidence": gosec_finding.confidence,
                    "code_snippet": gosec_finding.code[:500] if gosec_finding.code else None,
                },
            )
        )
    
    # Process SpotBugs findings
    for sb_finding in scanner_results.get("spotbugs", []):
        findings.append(
            models.Finding(
                type="spotbugs",
                severity=sb_finding.severity,
                file_path=sb_finding.file_path,
                start_line=sb_finding.line,
                end_line=sb_finding.line,
                summary=f"[{sb_finding.bug_type}] {sb_finding.message}",
                details={
                    "bug_type": sb_finding.bug_type,
                    "category": sb_finding.category,
                    "priority": sb_finding.priority,
                    "class_name": sb_finding.class_name,
                    "method_name": sb_finding.method_name,
                    "cwe": sb_finding.cwe,
                },
            )
        )
    
    # Process clang-tidy findings
    for ct_finding in scanner_results.get("clangtidy", []):
        findings.append(
            models.Finding(
                type="clangtidy",
                severity=ct_finding.severity,
                file_path=ct_finding.file_path,
                start_line=ct_finding.line,
                end_line=ct_finding.line,
                summary=f"[{ct_finding.check_name}] {ct_finding.message}",
                details={
                    "check_name": ct_finding.check_name,
                    "column": ct_finding.column,
                    "cwe": ct_finding.cwe,
                    "code_snippet": ct_finding.code_snippet,
                },
            )
        )
    
    # Process ESLint findings
    for eslint_finding in scanner_results.get("eslint", []):
        findings.append(
            models.Finding(
                type="eslint_security",
                severity=eslint_finding.severity,
                file_path=eslint_finding.file_path,
                start_line=eslint_finding.line,
                end_line=eslint_finding.end_line,
                summary=f"[{eslint_finding.rule_id}] {eslint_finding.message}",
                details={
                    "rule_id": eslint_finding.rule_id,
                    "column": eslint_finding.column,
                },
            )
        )
    
    # Process secret findings
    for secret in scanner_results.get("secrets", []):
        findings.append(
            models.Finding(
                type="secret",
                severity=secret.severity,
                file_path=secret.file_path,
                start_line=secret.line_number,
                end_line=secret.line_number,
                summary=f"Potential {secret.secret_type} detected",
                details={
                    "secret_type": secret.secret_type,
                    "description": secret.description,
                    "masked_value": secret.masked_value,
                },
            )
        )
    
    return findings


def _static_checks(file_path: Path, contents: str) -> List[models.Finding]:
    findings: List[models.Finding] = []
    lower = contents.lower()
    patterns = [
        ("eval(", "medium", "Use of eval detected"),
        ("exec(", "medium", "Use of exec detected"),
        ("subprocess", "medium", "Subprocess usage found"),
        ("shell=true", "high", "Potential shell command injection via shell=True"),
        ("password=", "high", "Hard coded password-like string"),
        ("verify=false", "medium", "TLS verification disabled"),
        ("except Exception:", "low", "Overly broad exception handling"),
    ]
    for needle, severity, summary in patterns:
        if needle in lower:
            findings.append(
                models.Finding(
                    type="code_pattern",
                    severity=severity,
                    file_path=str(file_path),
                    start_line=1,
                    end_line=None,
                    summary=summary,
                    details={"pattern": needle},
                )
            )
    return findings


def run_scan(db: Session, project: models.Project, scan_run: Optional[models.ScanRun] = None) -> models.Report:
    """
    Execute a full vulnerability scan on a project.
    
    This includes:
    - Extracting and parsing source files
    - Running static pattern analysis
    - Generating code embeddings
    - Parsing dependencies
    - Looking up known CVEs
    - Creating findings and generating a report
    
    Progress updates are broadcast via WebSocket for real-time monitoring.
    
    Args:
        db: Database session
        project: Project model to scan
        scan_run: Optional existing ScanRun to update
        
    Returns:
        Generated Report model
        
    Raises:
        ScanError: If scan fails
    """
    logger.info(f"Starting scan for project '{project.name}' (ID: {project.id})")
    
    if scan_run is None:
        scan_run = models.ScanRun(
            project_id=project.id, status="running", started_at=datetime.utcnow(), error_message=None
        )
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)
    else:
        scan_run.status = "running"
        scan_run.started_at = datetime.utcnow()
        scan_run.finished_at = None
        scan_run.error_message = None
        db.add(scan_run)
        db.commit()

    # Broadcast scan started
    _broadcast_progress(scan_run.id, "initializing", 0, "Scan started")

    findings: List[models.Finding] = []
    try:
        if not project.upload_path:
            raise ScanError("Project has no uploaded archive to scan", project_id=project.id)
        
        # Phase 1: Extract archive (5%)
        _broadcast_progress(scan_run.id, "extracting", 5, "Extracting archive")
        logger.debug(f"Extracting archive: {project.upload_path}")
        source_root = unpack_zip_to_temp(project.upload_path)
        
        all_chunks: List[models.CodeChunk] = []
        file_count = 0
        
        # Phase 2: Parse source files with streaming for large codebases (10-30%)
        _broadcast_progress(scan_run.id, "parsing", 10, "Parsing source files")
        
        # Collect all source files first to show progress
        source_files = list(iter_source_files(source_root))
        total_files = len(source_files)
        logger.info(f"Found {total_files} source files to process")
        
        # Process files in batches for memory efficiency
        processed_files = 0
        total_chunks_created = 0
        chunks_buffer: List[models.CodeChunk] = []
        
        for file_path in source_files:
            try:
                # Check if we've hit the chunk limit
                if total_chunks_created >= MAX_TOTAL_CHUNKS:
                    logger.warning(f"Reached max chunk limit ({MAX_TOTAL_CHUNKS}), skipping remaining files")
                    _broadcast_progress(
                        scan_run.id, "parsing", 28, 
                        f"Chunk limit reached, processed {processed_files}/{total_files} files"
                    )
                    break
                
                contents = file_path.read_text(encoding="utf-8", errors="ignore")
                
                # Pass file path for language-specific chunking
                chunks = split_into_chunks(contents, str(file_path))
                
                # Limit chunks per file to prevent single file domination
                if len(chunks) > 50:
                    logger.debug(f"Limiting {len(chunks)} chunks to 50 for {file_path}")
                    chunks = chunks[:50]
                
                db_chunks = create_code_chunks(project, source_root, file_path, _detect_language(file_path), chunks)
                chunks_buffer.extend(db_chunks)
                total_chunks_created += len(db_chunks)
                
                # Static checks
                findings.extend(_static_checks(file_path, contents))
                processed_files += 1
                
                # Flush buffer periodically to prevent memory buildup
                if len(chunks_buffer) >= CHUNK_FLUSH_THRESHOLD:
                    all_chunks.extend(chunks_buffer)
                    db.add_all(chunks_buffer)
                    db.commit()
                    chunks_buffer = []
                    
                    # Update progress
                    progress_pct = 10 + int((processed_files / total_files) * 20)
                    _broadcast_progress(
                        scan_run.id, "parsing", progress_pct, 
                        f"Processed {processed_files}/{total_files} files ({total_chunks_created} chunks)"
                    )
                
            except Exception as e:
                logger.warning(f"Error processing file {file_path}: {e}")
                continue
        
        # Flush remaining chunks
        if chunks_buffer:
            all_chunks.extend(chunks_buffer)
            db.add_all(chunks_buffer)
            db.commit()
        
        file_count = processed_files
        logger.info(f"Processed {file_count} source files, {len(all_chunks)} code chunks")
        _broadcast_progress(scan_run.id, "parsing", 30, f"Parsed {file_count} files, {len(all_chunks)} chunks")

        # Phase 3: Generate embeddings (30-45%)
        # Check if we should skip embeddings entirely
        if settings.skip_embeddings:
            logger.info("Skipping embeddings (SKIP_EMBEDDINGS=true)")
            _broadcast_progress(scan_run.id, "embedding", 45, "Embeddings skipped (disabled)")
        else:
            _broadcast_progress(scan_run.id, "embedding", 35, "Generating code embeddings")
            logger.debug("Checking for reusable embeddings from previous scans")
            
            # Get existing embeddings from previous scans of this project
            existing_embeddings = _get_existing_embeddings(db, project.id)
            
            if existing_embeddings:
                logger.info(f"Found {len(existing_embeddings)} existing embeddings to potentially reuse")
                chunks_to_embed, reused_count = _reuse_or_generate_embeddings(
                    db, project, all_chunks, existing_embeddings
                )
                
                if reused_count > 0:
                    logger.info(f"Reused {reused_count} embeddings from previous scan, "
                               f"{len(chunks_to_embed)} chunks need new embeddings")
                    _broadcast_progress(
                        scan_run.id, "embedding", 38, 
                        f"Reusing {reused_count} embeddings, generating {len(chunks_to_embed)} new"
                    )
                
                # Only generate embeddings for chunks that need them
                if chunks_to_embed:
                    asyncio.run(enrich_code_chunks(chunks_to_embed))
            else:
                # No existing embeddings, generate all
                logger.debug("No existing embeddings found, generating all")
                asyncio.run(enrich_code_chunks(all_chunks))
            
            db.add_all(all_chunks)
            db.commit()
            _broadcast_progress(scan_run.id, "embedding", 45, "Embeddings complete")

        # Phase 4-7: Run parallel scan phases (45-72%)
        # SAST, Docker, IaC, and Dependencies all run concurrently
        _broadcast_progress(scan_run.id, "parallel_scanning", 45, "Running parallel scan phases")
        logger.info("Starting parallel scan phase execution")
        
        tracker = ParallelPhaseTracker(scan_run.id, 45, 25)  # Progress from 45-70%
        
        parallel_results = _run_parallel_scan_phases(
            source_root, project, tracker, settings.scanner_timeout
        )
        
        # Process SAST results
        scanner_results = parallel_results.get("sast", {})
        scanner_findings = _convert_scanner_results_to_findings(scanner_results, source_root)
        findings.extend(scanner_findings)
        logger.info(f"SAST scanners: {len(scanner_findings)} findings")
        
        # Process Docker results
        docker_result = parallel_results.get("docker")
        docker_findings_count = 0
        if docker_result:
            docker_finding_dicts = docker_scan_service.convert_to_findings(docker_result, source_root)
            for df in docker_finding_dicts:
                findings.append(models.Finding(
                    type=df["type"],
                    severity=df["severity"],
                    file_path=df.get("file_path"),
                    start_line=df.get("start_line"),
                    end_line=df.get("end_line"),
                    summary=df["summary"],
                    details=df.get("details", {}),
                ))
            docker_findings_count = len(docker_finding_dicts)
            logger.info(f"Docker scanning: {docker_findings_count} findings "
                       f"({docker_result.dockerfiles_scanned} Dockerfiles, "
                       f"{docker_result.images_scanned} images)")
        
        # Process IaC results
        iac_result = parallel_results.get("iac")
        iac_findings_count = 0
        if iac_result:
            iac_finding_dicts = iac_scan_service.convert_to_findings(iac_result, source_root)
            for iac_f in iac_finding_dicts:
                findings.append(models.Finding(
                    type=iac_f["type"],
                    severity=iac_f["severity"],
                    file_path=iac_f.get("file_path"),
                    start_line=iac_f.get("start_line"),
                    end_line=iac_f.get("end_line"),
                    summary=iac_f["summary"],
                    details=iac_f.get("details", {}),
                ))
            iac_findings_count = len(iac_finding_dicts)
            logger.info(f"IaC scanning: {iac_findings_count} findings "
                       f"({iac_result.files_scanned} files, "
                       f"frameworks: {', '.join(iac_result.frameworks_detected) or 'none'})")
        
        # Get dependencies from parallel results
        deps = parallel_results.get("dependencies", [])
        
        _broadcast_progress(
            scan_run.id, "scanning", 70, 
            f"Parallel phases complete: {len(scanner_findings)} SAST, "
            f"{docker_findings_count} Docker, {iac_findings_count} IaC"
        )
        
        # Phase 8: Deduplicate scanner findings (70-72%)
        _broadcast_progress(scan_run.id, "deduplication", 70, "Deduplicating scanner findings")
        logger.debug("Running cross-scanner deduplication")
        
        original_count = len(findings)
        deduplicated, dedup_stats = deduplication_service.deduplicate_findings(findings)
        findings = deduplicated
        
        if dedup_stats.get("duplicates_merged", 0) > 0:
            logger.info(
                f"Deduplication: {original_count} → {len(findings)} findings "
                f"({dedup_stats['duplicates_merged']} duplicates merged)"
            )
            _broadcast_progress(
                scan_run.id, "deduplication", 72, 
                f"Merged {dedup_stats['duplicates_merged']} duplicates"
            )
        else:
            _broadcast_progress(scan_run.id, "deduplication", 72, "No duplicates found")

        # Phase 9: Save dependencies from parallel phase (72-75%)
        _broadcast_progress(scan_run.id, "dependencies", 72, "Saving dependencies")
        if deps:
            db.add_all(deps)
            db.commit()
        logger.info(f"Saved {len(deps)} dependencies")
        
        # Phase 10: Transitive dependency analysis (75-77%)
        _broadcast_progress(scan_run.id, "transitive_deps", 75, "Analyzing dependency trees")
        logger.debug("Building transitive dependency trees")
        
        try:
            dependency_trees = transitive_deps_service.parse_dependency_tree(source_root)
            tree_stats = {
                "ecosystems_analyzed": len(dependency_trees),
                "total_packages": sum(len(t.all_packages) for t in dependency_trees.values()),
                "direct_deps": sum(len(t.direct_dependencies) for t in dependency_trees.values()),
            }
            logger.info(
                f"Dependency trees: {tree_stats['ecosystems_analyzed']} ecosystems, "
                f"{tree_stats['total_packages']} packages ({tree_stats['direct_deps']} direct)"
            )
            _broadcast_progress(
                scan_run.id, "transitive_deps", 77, 
                f"Analyzed {tree_stats['total_packages']} packages in dependency trees"
            )
        except Exception as e:
            logger.warning(f"Transitive dependency analysis failed (non-critical): {e}")
            dependency_trees = {}
            _broadcast_progress(scan_run.id, "transitive_deps", 77, "Skipped (no lock files)")
        
        _broadcast_progress(scan_run.id, "dependencies", 78, f"Found {len(deps)} dependencies")

        # Phase 11: CVE lookup (78-82%)
        _broadcast_progress(scan_run.id, "cve_lookup", 78, "Looking up known vulnerabilities")
        logger.debug("Looking up known vulnerabilities")
        vulns = asyncio.run(cve_service.lookup_dependencies(deps))
        db.add_all(vulns)
        db.commit()
        logger.info(f"Found {len(vulns)} known vulnerabilities")
        _broadcast_progress(scan_run.id, "cve_lookup", 82, f"Found {len(vulns)} CVEs")
        
        # Phase 11b: Enrich with transitive dependency info (82-84%)
        if dependency_trees and vulns:
            _broadcast_progress(scan_run.id, "transitive_analysis", 82, "Analyzing transitive vulnerabilities")
            logger.debug("Enriching vulnerabilities with dependency tree info")
            
            try:
                tree_analysis = transitive_deps_service.analyze_vulnerable_dependencies(
                    vulns, dependency_trees
                )
                transitive_count = sum(1 for t in tree_analysis.values() if t.is_transitive)
                logger.info(
                    f"Transitive analysis: {transitive_count}/{len(vulns)} vulnerabilities "
                    f"are in transitive dependencies"
                )
                _broadcast_progress(
                    scan_run.id, "transitive_analysis", 83, 
                    f"{transitive_count} transitive, {len(vulns)-transitive_count} direct"
                )
            except Exception as e:
                logger.warning(f"Transitive enrichment failed: {e}")
                tree_analysis = {}
        else:
            tree_analysis = {}
        
        # Phase 11c: Reachability analysis (84-86%)
        if vulns:
            _broadcast_progress(scan_run.id, "reachability", 84, "Analyzing vulnerability reachability")
            logger.debug("Running reachability analysis")
            
            try:
                reachability_results = reachability_service.analyze_reachability(
                    source_root, vulns, deps
                )
                reachability_map = {r.vulnerability_id: r for r in reachability_results}
                reachability_summary = reachability_service.get_reachability_summary(reachability_results)
                
                unreachable_count = reachability_summary.get("not_reachable", 0)
                if unreachable_count > 0:
                    logger.info(
                        f"Reachability: {unreachable_count}/{len(vulns)} vulnerabilities "
                        f"are in unreachable code paths"
                    )
                _broadcast_progress(
                    scan_run.id, "reachability", 86, 
                    f"{reachability_summary.get('reachable', len(vulns))} reachable, "
                    f"{unreachable_count} unreachable"
                )
            except Exception as e:
                logger.warning(f"Reachability analysis failed: {e}")
                reachability_map = {}
                reachability_summary = {}
        else:
            reachability_map = {}
            reachability_summary = {}

        # Phase 12: Parallel enrichment - EPSS + NVD + KEV (86-88%)
        # Run all enrichments in parallel for better performance
        _broadcast_progress(scan_run.id, "enrichment", 86, "Enriching vulnerabilities (NVD/EPSS/KEV)")
        logger.debug("Starting parallel vulnerability enrichment")
        
        vuln_dicts = [
            {"id": v.id, "external_id": v.external_id, "cvss_score": v.cvss_score}
            for v in vulns
        ]
        
        # Use the new parallel enrichment that handles NVD + KEV + EPSS together
        cve_vulns = [v for v in vuln_dicts if v.get("external_id", "").startswith("CVE-")]
        if cve_vulns:
            try:
                enriched_vulns = asyncio.run(nvd_service.enrich_all_parallel(vuln_dicts))
                _broadcast_progress(scan_run.id, "enrichment", 89, f"Enriched {len(cve_vulns)} CVEs")
            except Exception as e:
                logger.warning(f"Parallel enrichment failed, falling back to EPSS only: {e}")
                # Fallback to just EPSS enrichment
                enriched_vulns = asyncio.run(epss_service.enrich_vulnerabilities_with_epss(vuln_dicts))
        else:
            # No CVEs, just do EPSS enrichment for GHSA etc.
            enriched_vulns = asyncio.run(epss_service.enrich_vulnerabilities_with_epss(vuln_dicts))
        
        # Create a mapping for quick lookup
        epss_data = {v["id"]: v for v in enriched_vulns}

        dep_lookup = {d.id: d.name for d in deps}

        # Create findings for dependency vulnerabilities
        for vuln in vulns:
            # Get EPSS, NVD, and KEV data if available
            vuln_epss = epss_data.get(vuln.id, {})
            epss_score = vuln_epss.get("epss_score")
            epss_percentile = vuln_epss.get("epss_percentile")
            epss_priority = vuln_epss.get("epss_priority")
            nvd_enrichment = vuln_epss.get("nvd_enrichment", {})
            in_kev = vuln_epss.get("in_kev", False)
            combined_priority = vuln_epss.get("combined_priority")
            priority_label = vuln_epss.get("priority_label")
            
            # Use combined priority or EPSS priority to potentially escalate severity
            effective_severity = vuln.severity or "medium"
            
            # KEV vulnerabilities should always be high/critical
            if in_kev and effective_severity in ("low", "medium"):
                effective_severity = "high"
                logger.info(f"Escalating {vuln.external_id} to high (in CISA KEV)")
            elif epss_priority == "critical" and effective_severity in ("low", "medium"):
                effective_severity = "high"  # Escalate if highly likely to be exploited
            
            # Build details dict with all enrichment data
            details = {
                "external_id": vuln.external_id,
                "dependency": dep_lookup.get(vuln.dependency_id),
                "cvss_score": vuln.cvss_score,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "epss_priority": epss_priority,
                "in_kev": in_kev,  # Known Exploited Vulnerability flag
                "combined_priority": combined_priority,
                "priority_label": priority_label,
            }
            
            # Add NVD enrichment if available
            if nvd_enrichment:
                details["nvd_description"] = nvd_enrichment.get("description")
                details["cvss_vector"] = nvd_enrichment.get("cvss_v3", {}).get("vector_string") if nvd_enrichment.get("cvss_v3") else None
                details["cwe"] = nvd_enrichment.get("cwes", [])
                details["references"] = nvd_enrichment.get("references", [])[:5]  # Limit references
            
            # Add transitive dependency info if available
            dep = vuln.dependency
            if dep and tree_analysis:
                tree_info = tree_analysis.get(vuln.external_id)
                if tree_info:
                    details["is_transitive"] = tree_info.is_transitive
                    details["dependency_depth"] = tree_info.depth
                    details["dependency_chain"] = tree_info.dependency_chain[:5]  # Limit chain length
                    details["root_dependency"] = tree_info.root_dependency
            
            # Add reachability info if available
            reachability = reachability_map.get(vuln.external_id)
            if reachability:
                details["reachability"] = {
                    "is_reachable": reachability.is_reachable,
                    "confidence": reachability.confidence,
                    "reason": reachability.reason,
                    "recommendation": reachability.recommendation,
                    "import_count": len(reachability.import_locations),
                    "call_count": len(reachability.call_locations),
                }
                
                # Downgrade severity for unreachable vulnerabilities with high confidence
                if not reachability.is_reachable and reachability.confidence == "high":
                    if effective_severity in ("critical", "high"):
                        logger.debug(
                            f"Downgrading {vuln.external_id} from {effective_severity} to medium "
                            "(unreachable with high confidence)"
                        )
                        effective_severity = "medium"
                        details["severity_downgraded"] = True
                        details["original_severity"] = vuln.severity or "medium"
            
            findings.append(
                models.Finding(
                    project_id=project.id,
                    scan_run_id=scan_run.id,
                    type="dependency_vuln",
                    severity=effective_severity,
                    summary=vuln.title,
                    details=details,
                    linked_vulnerability=vuln,
                )
            )

        # Attach metadata for code findings
        for f in findings:
            f.project_id = project.id
            f.scan_run_id = scan_run.id
        db.add_all(findings)
        db.commit()

        logger.info(f"Total findings: {len(findings)}")
        
        # Phase 11: AI-Enhanced Analysis (90-94%)
        attack_chains_data = []
        ai_summary = None
        if findings:
            _broadcast_progress(scan_run.id, "ai_analysis", 90, "AI-enhanced vulnerability analysis")
            try:
                # Convert findings to dicts for AI analysis
                findings_dicts = []
                code_snippets = {}
                for f in findings:
                    finding_dict = {
                        "id": f.id,
                        "type": f.type,
                        "severity": f.severity,
                        "file_path": f.file_path,
                        "start_line": f.start_line,
                        "end_line": f.end_line,
                        "summary": f.summary,
                        "details": f.details or {},
                    }
                    findings_dicts.append(finding_dict)
                    # Get code snippet from details if available
                    if f.details and f.details.get("code_snippet"):
                        code_snippets[f.id] = f.details["code_snippet"]
                
                ai_result = asyncio.run(ai_analysis_service.analyze_findings(
                    findings_dicts,
                    code_snippets=code_snippets,
                    enable_llm=True,
                    max_llm_findings=20
                ))
                if ai_result:
                    from sqlalchemy.orm.attributes import flag_modified
                    
                    # Store AI summary for report
                    ai_summary = {
                        "findings_analyzed": ai_result.findings_analyzed,
                        "false_positives_detected": ai_result.false_positives_detected,
                        "severity_adjustments": ai_result.severity_adjustments,
                    }
                    
                    # Convert attack chains to dicts for storage
                    for chain in ai_result.attack_chains:
                        attack_chains_data.append({
                            "title": chain.title,
                            "severity": chain.severity,
                            "finding_ids": chain.finding_ids,
                            "description": chain.chain_description,
                            "impact": chain.impact,
                            "likelihood": chain.likelihood,
                        })
                    
                    # Apply results to findings
                    for f in findings:
                        if f.id in ai_result.analysis_results:
                            result = ai_result.analysis_results[f.id]
                            # Store AI analysis in details (must create new dict for SQLAlchemy)
                            new_details = dict(f.details) if f.details else {}
                            new_details["ai_analysis"] = {
                                "is_false_positive": result.false_positive_score >= 0.5,
                                "false_positive_reason": result.false_positive_reason,
                                "severity_adjusted": result.adjusted_severity is not None,
                                "original_severity": f.severity if result.adjusted_severity else None,
                                "severity_reason": result.severity_reason,
                                "data_flow_summary": result.data_flow,
                            }
                            f.details = new_details
                            flag_modified(f, "details")
                            # Update severity if adjusted
                            if result.adjusted_severity:
                                f.severity = result.adjusted_severity
                    
                    # Store attack chain info in findings
                    for chain in ai_result.attack_chains:
                        for finding_id in chain.finding_ids:
                            for f in findings:
                                if f.id == finding_id:
                                    new_details = dict(f.details) if f.details else {}
                                    if "ai_analysis" not in new_details:
                                        new_details["ai_analysis"] = {}
                                    new_details["ai_analysis"]["attack_chain"] = chain.title
                                    f.details = new_details
                                    flag_modified(f, "details")
                    
                    db.commit()
                    logger.info(f"AI analysis complete: {ai_result.false_positives_detected} likely false positives, "
                               f"{ai_result.severity_adjustments} severity adjustments, "
                               f"{len(ai_result.attack_chains)} attack chains")
            except Exception as e:
                logger.warning(f"AI analysis failed (non-critical): {e}")
        
        # Phase 13: Generate report (94-98%)
        _broadcast_progress(scan_run.id, "reporting", 94, "Generating report")
        # Include deduplication and analysis stats in report
        scan_stats = {
            "deduplication": dedup_stats if 'dedup_stats' in dir() else {},
            "transitive_analysis": tree_stats if 'tree_stats' in dir() else {},
            "reachability": reachability_summary if reachability_summary else {},
            "docker": {
                "dockerfiles_scanned": docker_result.dockerfiles_scanned if docker_result else 0,
                "images_scanned": docker_result.images_scanned if docker_result else 0,
                "dockerfile_findings": len(docker_result.dockerfile_findings) if docker_result else 0,
                "image_vulnerabilities": len(docker_result.image_vulnerabilities) if docker_result else 0,
                "base_images": docker_result.base_images_found[:10] if docker_result else [],
            } if docker_result else {},
            "iac": {
                "files_scanned": iac_result.files_scanned if iac_result else 0,
                "findings": len(iac_result.findings) if iac_result else 0,
                "frameworks": list(iac_result.frameworks_detected) if iac_result else [],
            } if iac_result else {},
        }
        
        report = report_service.create_report(
            db, project, scan_run, findings, 
            attack_chains=attack_chains_data,
            ai_summary=ai_summary,
            scan_stats=scan_stats
        )
        scan_run.status = "complete"
        scan_run.finished_at = datetime.utcnow()
        db.add(scan_run)
        db.commit()
        
        # Phase 14: Complete (100%)
        _broadcast_progress(scan_run.id, "complete", 100, f"Scan complete. {len(findings)} findings")
        
        logger.info(f"Scan completed successfully. Report ID: {report.id}")
        
        # Send webhook notifications
        webhooks = get_webhooks(project.id)
        if webhooks:
            logger.info(f"Sending {len(webhooks)} webhook notifications")
            try:
                # Calculate summary stats
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for f in findings:
                    if f.severity in severity_counts:
                        severity_counts[f.severity] += 1
                
                asyncio.run(notify_scan_complete(
                    project_id=project.id,
                    project_name=project.name,
                    scan_run_id=scan_run.id,
                    findings_count=len(findings),
                    severity_counts=severity_counts,
                    report_id=report.id
                ))
            except Exception as e:
                logger.warning(f"Failed to send webhook notifications: {e}")
        
        return report
        
    except Exception as exc:
        logger.exception(f"Scan failed for project {project.id}: {exc}")
        scan_run.status = "failed"
        scan_run.error_message = str(exc)
        scan_run.finished_at = datetime.utcnow()
        db.add(scan_run)
        db.commit()
        
        # Broadcast failure
        _broadcast_progress(scan_run.id, "failed", 0, str(exc))
        
        raise
