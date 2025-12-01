import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from sqlalchemy.orm import Session

from backend import models
from backend.core.exceptions import ScanError
from backend.core.logging import get_logger
from backend.services import cve_service, dependency_service, report_service
from backend.services import secret_service, eslint_service, epss_service, semgrep_service
from backend.services import nvd_service, bandit_service, gosec_service
from backend.services import spotbugs_service, clangtidy_service
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
        
        # Phase 2: Parse source files (10-30%)
        _broadcast_progress(scan_run.id, "parsing", 10, "Parsing source files")
        for file_path in iter_source_files(source_root):
            try:
                contents = file_path.read_text(encoding="utf-8", errors="ignore")
                chunks = split_into_chunks(contents)
                db_chunks = create_code_chunks(project, source_root, file_path, _detect_language(file_path), chunks)
                all_chunks.extend(db_chunks)
                findings.extend(_static_checks(file_path, contents))
                file_count += 1
            except Exception as e:
                logger.warning(f"Error processing file {file_path}: {e}")
                continue
        
        logger.info(f"Processed {file_count} source files, {len(all_chunks)} code chunks")
        _broadcast_progress(scan_run.id, "parsing", 30, f"Parsed {file_count} files")
        
        db.add_all(all_chunks)
        db.commit()

        # Phase 3: Generate embeddings (30-45%)
        _broadcast_progress(scan_run.id, "embedding", 35, "Generating code embeddings")
        logger.debug("Generating code embeddings")
        asyncio.run(enrich_code_chunks(all_chunks))
        db.add_all(all_chunks)
        db.commit()
        _broadcast_progress(scan_run.id, "embedding", 45, "Embeddings complete")

        # Phase 4: Secret detection (45-50%)
        _broadcast_progress(scan_run.id, "secrets", 48, "Scanning for hardcoded secrets")
        logger.debug("Scanning for hardcoded secrets")
        secret_findings = secret_service.scan_directory(str(source_root))
        for secret in secret_findings:
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
        logger.info(f"Found {len(secret_findings)} potential secrets")

        # Phase 5: ESLint security scan (50-55%)
        _broadcast_progress(scan_run.id, "eslint", 52, "Running ESLint security scan")
        logger.debug("Running ESLint security scan")
        eslint_findings = eslint_service.run_eslint_security_scan(str(source_root))
        for eslint_finding in eslint_findings:
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
        logger.info(f"Found {len(eslint_findings)} ESLint security issues")

        # Phase 6: Semgrep security scan (55-65%)
        _broadcast_progress(scan_run.id, "semgrep", 58, "Running Semgrep security scan")
        logger.debug("Running Semgrep security scan")
        if semgrep_service.is_semgrep_available():
            semgrep_findings = semgrep_service.run_security_audit(source_root)
            for sg_finding in semgrep_findings:
                # Make path relative to source root
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
            logger.info(f"Found {len(semgrep_findings)} Semgrep security issues")
        else:
            logger.info("Semgrep not installed, skipping deep static analysis")
        _broadcast_progress(scan_run.id, "semgrep", 65, "Static analysis complete")

        # Phase 6b: Bandit Python security scan (if Python files exist)
        _broadcast_progress(scan_run.id, "bandit", 66, "Running Bandit Python security scan")
        logger.debug("Running Bandit Python security scan")
        if bandit_service.is_bandit_available():
            bandit_findings = bandit_service.run_security_audit(source_root)
            for bandit_finding in bandit_findings:
                # Make path relative to source root
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
            logger.info(f"Found {len(bandit_findings)} Bandit Python security issues")
        else:
            logger.info("Bandit not installed, skipping Python security analysis")

        # Phase 6c: gosec Go security scan (if Go files exist)
        _broadcast_progress(scan_run.id, "gosec", 67, "Running gosec Go security scan")
        logger.debug("Running gosec Go security scan")
        if gosec_service.is_gosec_available():
            gosec_findings = gosec_service.run_security_audit(source_root)
            for gosec_finding in gosec_findings:
                # Make path relative to source root
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
            logger.info(f"Found {len(gosec_findings)} gosec Go security issues")
        else:
            logger.info("gosec not installed, skipping Go security analysis")

        # Phase 6d: SpotBugs Java security scan (if Java files exist)
        _broadcast_progress(scan_run.id, "spotbugs", 68, "Running SpotBugs Java security scan")
        logger.debug("Running SpotBugs Java security scan")
        if spotbugs_service.is_spotbugs_available():
            spotbugs_findings = spotbugs_service.run_security_audit(source_root)
            for sb_finding in spotbugs_findings:
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
            logger.info(f"Found {len(spotbugs_findings)} SpotBugs Java security issues")
        else:
            logger.info("SpotBugs not installed, skipping Java security analysis")

        # Phase 6e: clang-tidy C/C++ security scan
        _broadcast_progress(scan_run.id, "clangtidy", 69, "Running clang-tidy C/C++ security scan")
        logger.debug("Running clang-tidy C/C++ security scan")
        if clangtidy_service.is_clangtidy_available():
            clangtidy_findings = clangtidy_service.run_security_audit(source_root)
            for ct_finding in clangtidy_findings:
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
            logger.info(f"Found {len(clangtidy_findings)} clang-tidy C/C++ security issues")
        else:
            logger.info("clang-tidy not installed, skipping C/C++ security analysis")

        # Phase 7: Parse dependencies (65-75%)
        _broadcast_progress(scan_run.id, "dependencies", 68, "Parsing dependencies")
        logger.debug("Parsing dependencies")
        deps = dependency_service.parse_dependencies(project, source_root)
        db.add_all(deps)
        db.commit()
        logger.info(f"Found {len(deps)} dependencies")
        _broadcast_progress(scan_run.id, "dependencies", 75, f"Found {len(deps)} dependencies")

        # Phase 8: CVE lookup (75-85%)
        _broadcast_progress(scan_run.id, "cve_lookup", 78, "Looking up known vulnerabilities")
        logger.debug("Looking up known vulnerabilities")
        vulns = asyncio.run(cve_service.lookup_dependencies(deps))
        db.add_all(vulns)
        db.commit()
        logger.info(f"Found {len(vulns)} known vulnerabilities")
        _broadcast_progress(scan_run.id, "cve_lookup", 85, f"Found {len(vulns)} CVEs")

        # Phase 9: EPSS enrichment (85-90%)
        _broadcast_progress(scan_run.id, "epss", 88, "Fetching EPSS exploitation scores")
        logger.debug("Fetching EPSS exploitation probability scores")
        vuln_dicts = [
            {"id": v.id, "external_id": v.external_id, "cvss_score": v.cvss_score}
            for v in vulns
        ]
        enriched_vulns = asyncio.run(epss_service.enrich_vulnerabilities_with_epss(vuln_dicts))
        
        # Phase 9b: NVD enrichment (optional - enriches CVE details)
        # Only enrich if we have CVEs (not GHSA or other IDs)
        cve_vulns = [v for v in enriched_vulns if v.get("external_id", "").startswith("CVE-")]
        if cve_vulns:
            _broadcast_progress(scan_run.id, "nvd", 89, f"Enriching {len(cve_vulns)} CVEs from NVD")
            logger.debug(f"Enriching {len(cve_vulns)} CVEs from NVD")
            try:
                enriched_vulns = asyncio.run(nvd_service.enrich_vulnerabilities_with_nvd(enriched_vulns))
            except Exception as e:
                logger.warning(f"NVD enrichment failed (non-fatal): {e}")
        
        # Create a mapping for quick lookup
        epss_data = {v["id"]: v for v in enriched_vulns}

        dep_lookup = {d.id: d.name for d in deps}

        # Create findings for dependency vulnerabilities
        for vuln in vulns:
            # Get EPSS and NVD data if available
            vuln_epss = epss_data.get(vuln.id, {})
            epss_score = vuln_epss.get("epss_score")
            epss_percentile = vuln_epss.get("epss_percentile")
            epss_priority = vuln_epss.get("epss_priority")
            nvd_enrichment = vuln_epss.get("nvd_enrichment", {})
            
            # Use EPSS priority to potentially escalate severity
            effective_severity = vuln.severity or "medium"
            if epss_priority == "critical" and effective_severity in ("low", "medium"):
                effective_severity = "high"  # Escalate if highly likely to be exploited
            
            # Build details dict with all enrichment data
            details = {
                "external_id": vuln.external_id,
                "dependency": dep_lookup.get(vuln.dependency_id),
                "cvss_score": vuln.cvss_score,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "epss_priority": epss_priority,
            }
            
            # Add NVD enrichment if available
            if nvd_enrichment:
                details["nvd_description"] = nvd_enrichment.get("description")
                details["cvss_vector"] = nvd_enrichment.get("cvss_v3", {}).get("vector_string") if nvd_enrichment.get("cvss_v3") else None
                details["cwe"] = nvd_enrichment.get("cwes", [])
                details["references"] = nvd_enrichment.get("references", [])[:5]  # Limit references
            
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
        
        # Phase 10: Generate report (90-95%)
        _broadcast_progress(scan_run.id, "reporting", 92, "Generating report")
        report = report_service.create_report(db, project, scan_run, findings)
        scan_run.status = "complete"
        scan_run.finished_at = datetime.utcnow()
        db.add(scan_run)
        db.commit()
        
        # Phase 11: Complete (100%)
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
