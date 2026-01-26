"""
Combined Analysis Report Schemas

Pydantic models for the Combined Results Analysis feature that aggregates
data from Security Scans, Reverse Engineering reports, and Network Analysis.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


# ============================================================================
# Request Models
# ============================================================================

class SelectedScan(BaseModel):
    """A selected scan/report to include in the combined analysis."""
    scan_type: str = Field(
        ...,
        description="Type: 'security_scan', 'network_report', 'ssl_scan', 'dns_scan', "
                    "'traceroute_scan', 'nmap_scan', 'pcap_report', 'api_tester_report', "
                    "'dynamic_scan', 'mitm_analysis_report', 'fuzzing_session', "
                    "'agentic_fuzzer_report', 'binary_fuzzer_session', 're_report'"
    )
    scan_id: int = Field(..., description="The ID of the scan/report")
    title: Optional[str] = None  # For display purposes


class SupportingDocument(BaseModel):
    """A supporting document uploaded by the user."""
    filename: str
    content_type: str
    content_base64: str = Field(..., description="Base64 encoded file content")
    description: Optional[str] = None


class CombinedAnalysisRequest(BaseModel):
    """Request to generate a combined analysis report."""
    project_id: int
    title: str = Field(..., min_length=1, max_length=200)
    
    # Selected scans/reports to analyze
    selected_scans: List[SelectedScan] = Field(..., min_length=1)
    
    # Optional supporting documents
    supporting_documents: Optional[List[SupportingDocument]] = None

    # Optional references to existing document analysis reports
    document_analysis_report_ids: Optional[List[int]] = None
    
    # Project info dump from user
    project_info: Optional[str] = Field(None, max_length=10000, description="User-provided project context and information")
    
    # User's specific requirements for the report
    user_requirements: Optional[str] = Field(None, max_length=5000, description="What the user specifically wants from this report")
    
    # Report options
    include_exploit_recommendations: bool = Field(True, description="Include areas suitable for exploit development")
    include_attack_surface_map: bool = Field(True, description="Generate attack surface visualization")
    include_risk_prioritization: bool = Field(True, description="Prioritize findings by exploitability")
    

# ============================================================================
# Response Models
# ============================================================================

class AvailableScanItem(BaseModel):
    """An available scan/report that can be selected."""
    scan_type: str
    scan_id: int
    title: str
    created_at: datetime
    summary: Optional[str] = None
    risk_level: Optional[str] = None
    findings_count: Optional[int] = None
    
    class Config:
        from_attributes = True


class AvailableScansResponse(BaseModel):
    """Response listing all available scans for a project."""
    project_id: int
    project_name: str

    # Static Analysis
    security_scans: List[AvailableScanItem] = []

    # Dynamic Analysis - Network
    network_reports: List[AvailableScanItem] = []
    ssl_scans: List[AvailableScanItem] = []  # SSL/TLS security scans
    dns_scans: List[AvailableScanItem] = []  # DNS reconnaissance scans
    traceroute_scans: List[AvailableScanItem] = []  # Traceroute network path analysis
    nmap_scans: List[AvailableScanItem] = []  # Nmap port/service scans (live + uploaded)
    pcap_reports: List[AvailableScanItem] = []  # PCAP packet capture analysis
    api_tester_reports: List[AvailableScanItem] = []  # API endpoint security testing

    # Dynamic Analysis - Scanning
    dynamic_scans: List[AvailableScanItem] = []  # Dynamic Application Security Testing (DAST) scans
    mitm_analysis_reports: List[AvailableScanItem] = []  # MITM traffic analysis reports

    # Fuzzing
    fuzzing_sessions: List[AvailableScanItem] = []
    agentic_fuzzer_reports: List[AvailableScanItem] = []  # AI-driven agentic fuzzer reports
    binary_fuzzer_sessions: List[AvailableScanItem] = []  # Binary/AFL++ fuzzing sessions
    fuzzing_campaign_reports: List[AvailableScanItem] = []  # AI-generated campaign reports from Agentic Binary Fuzzer

    # Reverse Engineering
    re_reports: List[AvailableScanItem] = []

    total_available: int = 0


class ReportSection(BaseModel):
    """A section of the generated report."""
    title: str
    content: str
    section_type: str = "text"  # text, list, table, mermaid_diagram
    severity: Optional[str] = None  # For prioritized sections
    metadata: Optional[Dict[str, Any]] = None


class CrossAnalysisFinding(BaseModel):
    """A finding that spans multiple scan types."""
    title: str
    description: str
    severity: str
    sources: List[str] = []  # Which scan types contributed
    source_details: Optional[List[Dict[str, Any]]] = None
    exploitability_score: Optional[float] = None
    exploit_narrative: Optional[str] = None  # Detailed narrative of how the exploit works
    exploit_guidance: Optional[str] = None
    poc_available: Optional[bool] = None
    remediation: Optional[str] = None


class ExploitDevelopmentArea(BaseModel):
    """An area recommended for exploit development."""
    title: str
    description: str
    vulnerability_chain: List[str] = []
    attack_vector: str
    complexity: str  # Low, Medium, High
    impact: str
    prerequisites: Optional[List[str]] = None
    poc_guidance: Optional[str] = None
    full_poc_script: Optional[str] = None
    testing_notes: Optional[str] = None
    detection_evasion: Optional[str] = None


class BeginnerAttackStep(BaseModel):
    """A single step in a beginner attack guide."""
    step_number: int
    title: str
    explanation: str
    command_or_action: Optional[str] = None
    expected_output: Optional[str] = None
    troubleshooting: Optional[str] = None


class AttackTool(BaseModel):
    """Tool needed for an attack."""
    tool: str
    installation: Optional[str] = None
    purpose: Optional[str] = None


class BeginnerAttackGuide(BaseModel):
    """A beginner-friendly attack guide."""
    attack_name: str
    difficulty_level: str  # Beginner, Intermediate, Advanced
    estimated_time: Optional[str] = None
    prerequisites: List[str] = []
    tools_needed: List[AttackTool] = []
    step_by_step_guide: List[BeginnerAttackStep] = []
    success_indicators: List[str] = []
    what_you_can_do_after: Optional[str] = None


class PoCScript(BaseModel):
    """A proof-of-concept exploit script."""
    vulnerability_name: str
    language: str  # python, bash, javascript, curl, powershell
    description: str
    usage_instructions: Optional[str] = None
    script_code: str
    expected_output: Optional[str] = None
    customization_notes: Optional[str] = None


class AttackChainStep(BaseModel):
    """A step in an attack chain."""
    step: int
    action: str
    vulnerability_used: Optional[str] = None
    outcome: Optional[str] = None


class AttackChain(BaseModel):
    """A complete attack chain showing multi-step exploitation."""
    chain_name: str
    entry_point: str
    steps: List[AttackChainStep] = []
    final_impact: Optional[str] = None
    likelihood: Optional[str] = None
    diagram: Optional[str] = None


class SourceCodeFinding(BaseModel):
    """A vulnerability or issue found in source code during deep dive analysis."""
    file_path: str
    issue_type: str
    severity: str  # Critical, High, Medium, Low
    description: str
    vulnerable_code_snippet: Optional[str] = None
    code_snippet: Optional[str] = None  # Alias for backward compatibility
    line_numbers: Optional[str] = None
    exploitation_example: Optional[str] = None
    related_scan_findings: Optional[List[str]] = None
    secure_code_fix: Optional[str] = None
    remediation: Optional[str] = None


class CombinedAnalysisReportResponse(BaseModel):
    """The generated combined analysis report."""
    id: int
    project_id: int
    title: str
    created_at: datetime
    
    # Executive summary
    executive_summary: str
    
    # Overall risk assessment
    overall_risk_level: str
    overall_risk_score: int  # 0-100
    risk_justification: str
    
    # Aggregated statistics
    total_findings_analyzed: int
    scans_included: int
    scan_types_breakdown: Dict[str, int]
    
    # Report sections
    sections: List[ReportSection] = []
    
    # Cross-analysis results
    cross_analysis_findings: List[CrossAnalysisFinding] = []
    
    # Attack surface map (Mermaid diagram)
    attack_surface_diagram: Optional[str] = None
    
    # Attack chains showing multi-step exploitation
    attack_chains: Optional[List[AttackChain]] = None
    
    # Beginner-friendly attack guides
    beginner_attack_guide: Optional[List[BeginnerAttackGuide]] = None
    
    # Proof-of-concept scripts
    poc_scripts: Optional[List[PoCScript]] = None
    
    # Exploit development recommendations
    exploit_development_areas: List[ExploitDevelopmentArea] = []
    
    # Prioritized vulnerabilities
    prioritized_vulnerabilities: Optional[List[Dict[str, Any]]] = None
    
    # Source code findings from deep dive analysis
    source_code_findings: Optional[List[SourceCodeFinding]] = None
    
    # Documentation analysis if supporting docs were provided
    documentation_analysis: Optional[str] = None
    
    # Raw data references
    included_scans: List[SelectedScan] = []
    
    class Config:
        from_attributes = True


class CombinedAnalysisListItem(BaseModel):
    """Summary item for listing combined analysis reports."""
    id: int
    project_id: int
    title: str
    created_at: datetime
    overall_risk_level: str
    overall_risk_score: int
    total_findings_analyzed: int
    scans_included: int
    
    class Config:
        from_attributes = True


class CombinedAnalysisListResponse(BaseModel):
    """Response for listing combined analysis reports."""
    reports: List[CombinedAnalysisListItem] = []
    total: int = 0


# ============================================================================
# AI Chat Models
# ============================================================================

class ChatMessage(BaseModel):
    """A chat message in the conversation."""
    role: str = Field(..., description="'user' or 'assistant'")
    content: str


class CombinedAnalysisChatRequest(BaseModel):
    """Request to chat about a combined analysis report."""
    message: str = Field(..., min_length=1, max_length=2000)
    history: Optional[List[ChatMessage]] = Field(default=[], description="Previous messages for context")


class CombinedAnalysisChatResponse(BaseModel):
    """Response from the AI chat."""
    response: str
    suggestions: Optional[List[str]] = None
