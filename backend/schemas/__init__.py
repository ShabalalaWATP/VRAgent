from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None
    git_url: Optional[str] = None
    is_shared: bool = False


class ProjectCreate(ProjectBase):
    pass


class Project(ProjectBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    owner_id: Optional[int] = None
    owner_username: Optional[str] = None
    collaborator_count: int = 0
    user_role: Optional[str] = None  # 'owner', 'editor', 'viewer', 'admin'

    model_config = ConfigDict(from_attributes=True)


class ProjectCollaboratorBase(BaseModel):
    user_id: int
    role: str = "editor"  # 'viewer', 'editor', 'admin'


class ProjectCollaboratorCreate(ProjectCollaboratorBase):
    pass


class ProjectCollaborator(ProjectCollaboratorBase):
    id: int
    project_id: int
    added_at: datetime
    username: Optional[str] = None
    email: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ScanRun(BaseModel):
    id: int
    project_id: int
    status: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    error_message: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class Report(BaseModel):
    id: int
    project_id: int
    scan_run_id: int
    created_at: datetime
    title: str
    summary: Optional[str]
    overall_risk_score: Optional[float]
    data: Any

    model_config = ConfigDict(from_attributes=True)


class Finding(BaseModel):
    id: int
    project_id: int
    scan_run_id: int
    type: str
    severity: str
    file_path: Optional[str]
    start_line: Optional[int]
    end_line: Optional[int]
    summary: str
    details: Any = None
    linked_vulnerability_id: Optional[int]

    model_config = ConfigDict(from_attributes=True)


class ExploitScenario(BaseModel):
    id: int
    report_id: int
    finding_id: Optional[int]  # Null for executive summaries
    severity: Optional[str]
    title: str
    narrative: Optional[str]
    preconditions: Optional[str]
    impact: Optional[str]
    poc_outline: Optional[str]
    mitigation_notes: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class Dependency(BaseModel):
    id: int
    project_id: int
    name: str
    version: Optional[str]
    ecosystem: Optional[str]
    manifest_path: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class Vulnerability(BaseModel):
    id: int
    project_id: int
    dependency_id: Optional[int]
    source: str
    external_id: Optional[str]
    title: str
    description: Optional[str]
    severity: Optional[str]
    cvss_score: Optional[float]
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    model_config = ConfigDict(from_attributes=True)


class ReportSummary(BaseModel):
    report: Report
    findings: List[Finding] = []
    dependencies: List[Dependency] = []
    vulnerabilities: List[Vulnerability] = []
    exploit_scenarios: List[ExploitScenario] = []


class UploadResponse(BaseModel):
    message: str
    path: str
