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
    email = Column(String, unique=True, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

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
    mitigation_notes = Column(Text, nullable=True)

    report = relationship("Report", back_populates="exploit_scenarios")
    finding = relationship("Finding", back_populates="exploit_scenarios")


class NetworkAnalysisReport(Base):
    """Stores network analysis reports (PCAP, Nmap, DNS, etc.)."""
    __tablename__ = "network_analysis_reports"

    id = Column(Integer, primary_key=True, index=True)
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
