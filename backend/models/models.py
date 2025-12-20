from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from pgvector.sqlalchemy import Vector

from backend.core.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")  # 'user' or 'admin'
    status = Column(String, nullable=False, default="pending")  # 'pending', 'approved', 'suspended'
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)

    projects = relationship("Project", back_populates="owner")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    git_url = Column(String, nullable=True)
    upload_path = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    owner = relationship("User", back_populates="projects")
    code_chunks = relationship("CodeChunk", back_populates="project")
    dependencies = relationship("Dependency", back_populates="project")
    vulnerabilities = relationship("Vulnerability", back_populates="project")
    scan_runs = relationship("ScanRun", back_populates="project")
    findings = relationship("Finding", back_populates="project")
    reports = relationship("Report", back_populates="project")
    network_analysis_reports = relationship("NetworkAnalysisReport", back_populates="project")
    fuzzing_sessions = relationship("FuzzingSession", back_populates="project")
    reverse_engineering_reports = relationship("ReverseEngineeringReport", back_populates="project")
    project_notes = relationship("ProjectNote", back_populates="project", cascade="all, delete-orphan")


class CodeChunk(Base):
    __tablename__ = "code_chunks"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    file_path = Column(String, nullable=False)
    language = Column(String, nullable=True)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    code = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    embedding = Column(Vector(768), nullable=True)  # text-embedding-004 produces 768-dim vectors

    project = relationship("Project", back_populates="code_chunks")


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    ecosystem = Column(String, nullable=True)
    manifest_path = Column(String, nullable=True)

    project = relationship("Project", back_populates="dependencies")
    vulnerabilities = relationship("Vulnerability", back_populates="dependency")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    dependency_id = Column(Integer, ForeignKey("dependencies.id"), nullable=True)
    source = Column(String, nullable=False)
    external_id = Column(String, nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)

    project = relationship("Project", back_populates="vulnerabilities")
    dependency = relationship("Dependency", back_populates="vulnerabilities")
    findings = relationship("Finding", back_populates="linked_vulnerability")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    status = Column(String, nullable=False, default="queued")
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    options = Column(JSON, nullable=True)  # Scan options like include_agentic

    project = relationship("Project", back_populates="scan_runs")
    findings = relationship("Finding", back_populates="scan_run")
    reports = relationship("Report", back_populates="scan_run")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("project_id", "scan_run_id", "id"),)

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), index=True)
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    file_path = Column(String, nullable=True)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    summary = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    linked_vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)

    project = relationship("Project", back_populates="findings")
    scan_run = relationship("ScanRun", back_populates="findings")
    linked_vulnerability = relationship("Vulnerability", back_populates="findings")
    exploit_scenarios = relationship("ExploitScenario", back_populates="finding")
    notes = relationship("FindingNote", back_populates="finding", cascade="all, delete-orphan")


class FindingNote(Base):
    """User notes on findings for tracking remediation, analysis, and comments."""
    __tablename__ = "finding_notes"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # Optional, for multi-user support
    
    content = Column(Text, nullable=False)
    note_type = Column(String, nullable=False, default="comment")  # comment, remediation, false_positive, accepted_risk, in_progress
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Optional extra data
    extra_data = Column(JSON, nullable=True)  # For additional structured data like tags, priority, etc.
    
    finding = relationship("Finding", back_populates="notes")
    user = relationship("User")


class ProjectNote(Base):
    """General project-level notes not tied to specific findings."""
    __tablename__ = "project_notes"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    title = Column(String, nullable=True)
    content = Column(Text, nullable=False)
    note_type = Column(String, nullable=False, default="general")  # general, todo, important, reference
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    extra_data = Column(JSON, nullable=True)
    
    project = relationship("Project", back_populates="project_notes")
    user = relationship("User")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    title = Column(String, nullable=False)
    summary = Column(Text, nullable=True)
    overall_risk_score = Column(Float, nullable=True)
    data = Column(JSON, nullable=True)

    project = relationship("Project", back_populates="reports")
    scan_run = relationship("ScanRun", back_populates="reports")
    exploit_scenarios = relationship("ExploitScenario", back_populates="report")


class ExploitScenario(Base):
    __tablename__ = "exploit_scenarios"

    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey("reports.id"), index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=True)  # Null for executive summaries
    severity = Column(String, nullable=True)
    title = Column(String, nullable=False)
    narrative = Column(Text, nullable=True)
    preconditions = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    poc_outline = Column(Text, nullable=True)
    poc_scripts = Column(JSON, nullable=True)  # Executable POC scripts by language
    attack_complexity = Column(String, nullable=True)  # Low, Medium, High
    exploit_maturity = Column(String, nullable=True)  # Proof of Concept, Functional, High
    mitigation_notes = Column(Text, nullable=True)

    report = relationship("Report", back_populates="exploit_scenarios")
    finding = relationship("Finding", back_populates="exploit_scenarios")


class NetworkAnalysisReport(Base):
    """Stores network analysis reports (PCAP, Nmap, DNS, etc.)."""
    __tablename__ = "network_analysis_reports"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)  # Optional project association
    analysis_type = Column(String, nullable=False)  # 'pcap', 'nmap', 'dns'
    report_type = Column(String, nullable=True)  # Alternative categorization (dns, pcap, nmap)
    title = Column(String, nullable=False)
    filename = Column(String, nullable=True)  # Original uploaded filename(s)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Risk assessment
    risk_level = Column(String, nullable=True)  # Critical, High, Medium, Low
    risk_score = Column(Integer, nullable=True)  # 0-100
    
    # Summary data
    summary_data = Column(JSON, nullable=True)  # Protocol stats, top talkers, etc.
    
    # Findings
    findings_data = Column(JSON, nullable=True)  # List of security findings
    
    # AI Analysis - structured report
    ai_report = Column(JSON, nullable=True)  # Full structured AI report
    
    # Generic report data (for DNS and other report types)
    report_data = Column(JSON, nullable=True)  # Flexible data storage
    
    # Export metadata
    last_exported_at = Column(DateTime(timezone=True), nullable=True)
    export_formats = Column(JSON, nullable=True)  # List of formats exported
    
    # Relationship
    project = relationship("Project", back_populates="network_analysis_reports")


class FuzzingSession(Base):
    """Stores fuzzing session data including config, results, and analysis."""
    __tablename__ = "fuzzing_sessions"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)  # Optional project association
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    target_url = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False, default="GET")
    status = Column(String, nullable=False, default="created", index=True)  # created, running, paused, completed, failed
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    
    # Configuration stored as JSON
    config = Column(JSON, nullable=True)
    
    # Statistics
    total_requests = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    interesting_count = Column(Integer, default=0)
    avg_response_time = Column(Float, nullable=True)
    
    # Results stored as JSON
    results = Column(JSON, nullable=True)
    
    # Findings from smart detection
    findings = Column(JSON, nullable=True)
    
    # Analysis results (WAF, rate limiting, etc.)
    analysis = Column(JSON, nullable=True)
    
    # Tags for organization
    tags = Column(JSON, nullable=True)
    
    # Relationship
    project = relationship("Project", back_populates="fuzzing_sessions")


class ReverseEngineeringReport(Base):
    """Stores reverse engineering analysis reports (Binary, APK, Docker)."""
    __tablename__ = "reverse_engineering_reports"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)
    
    # Report metadata
    analysis_type = Column(String, nullable=False, index=True)  # 'binary', 'apk', 'docker'
    title = Column(String, nullable=False)
    filename = Column(String, nullable=True)  # Original filename analyzed
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Risk assessment from AI
    risk_level = Column(String, nullable=True)  # Critical, High, Medium, Low, Clean
    risk_score = Column(Integer, nullable=True)  # 0-100
    
    # For binary analysis
    file_type = Column(String, nullable=True)
    architecture = Column(String, nullable=True)
    file_size = Column(Integer, nullable=True)
    is_packed = Column(String, nullable=True)
    packer_name = Column(String, nullable=True)
    
    # For APK analysis
    package_name = Column(String, nullable=True)
    version_name = Column(String, nullable=True)
    min_sdk = Column(Integer, nullable=True)
    target_sdk = Column(Integer, nullable=True)
    
    # For Docker analysis
    image_name = Column(String, nullable=True)
    image_id = Column(String, nullable=True)
    total_layers = Column(Integer, nullable=True)
    base_image = Column(String, nullable=True)
    
    # Analysis data (JSON)
    strings_count = Column(Integer, nullable=True)
    imports_count = Column(Integer, nullable=True)
    exports_count = Column(Integer, nullable=True)
    secrets_count = Column(Integer, nullable=True)
    suspicious_indicators = Column(JSON, nullable=True)  # List of suspicious findings
    permissions = Column(JSON, nullable=True)  # For APK
    security_issues = Column(JSON, nullable=True)  # Common findings
    
    # Full analysis data (for detailed view)
    full_analysis_data = Column(JSON, nullable=True)
    
    # AI Analysis - both raw and structured
    ai_analysis_raw = Column(Text, nullable=True)  # Original AI response
    ai_analysis_structured = Column(JSON, nullable=True)  # Parsed structured analysis
    
    # JADX Full Scan Data
    jadx_total_classes = Column(Integer, nullable=True)
    jadx_total_files = Column(Integer, nullable=True)
    jadx_data = Column(JSON, nullable=True)  # Contains classes sample, security issues, etc.
    
    # AI-Generated Reports (Deep Analysis)
    ai_functionality_report = Column(Text, nullable=True)
    ai_security_report = Column(Text, nullable=True)
    ai_privacy_report = Column(Text, nullable=True)
    ai_architecture_diagram = Column(Text, nullable=True)  # Mermaid diagram
    ai_threat_model = Column(JSON, nullable=True)
    ai_vuln_scan_result = Column(JSON, nullable=True)
    ai_chat_history = Column(JSON, nullable=True)
    ai_attack_surface_map = Column(Text, nullable=True)  # Mermaid attack tree diagram
    
    # Library CVE Analysis
    detected_libraries = Column(JSON, nullable=True)  # Libraries detected in APK
    library_cves = Column(JSON, nullable=True)  # CVEs found in libraries
    
    # Tags and notes
    tags = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    
    # Relationship
    project = relationship("Project", back_populates="reverse_engineering_reports")
