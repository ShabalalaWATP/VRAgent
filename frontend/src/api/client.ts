const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(text || resp.statusText);
  }
  return (await resp.json()) as T;
}

export async function uploadZip(projectId: number, file: File) {
  const form = new FormData();
  form.append("file", file);
  const resp = await fetch(`${API_URL}/projects/${projectId}/upload`, {
    method: "POST",
    body: form
  });
  if (!resp.ok) {
    throw new Error(await resp.text());
  }
  return resp.json();
}

export async function cloneRepository(
  projectId: number, 
  repoUrl: string, 
  branch?: string
): Promise<CloneResponse> {
  const resp = await fetch(`${API_URL}/projects/${projectId}/clone`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repoUrl, branch })
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(text || resp.statusText);
  }
  return resp.json();
}

export const api = {
  getProjects: () => request<ProjectSummary[]>("/projects"),
  createProject: (payload: { name: string; description?: string; git_url?: string }) =>
    request<ProjectSummary>("/projects", { method: "POST", body: JSON.stringify(payload) }),
  getProject: (id: number) => request<ProjectSummary>(`/projects/${id}`),
  deleteProject: (id: number) => 
    request<{ status: string; project_id: number }>(`/projects/${id}`, { method: "DELETE" }),
  triggerScan: (projectId: number) =>
    request<ScanRun>(`/projects/${projectId}/scan`, { method: "POST" }),
  getReports: (projectId: number) => request<Report[]>(`/projects/${projectId}/reports`),
  getReport: (reportId: number) => request<Report>(`/reports/${reportId}`),
  getFindings: (reportId: number) => request<Finding[]>(`/reports/${reportId}/findings`),
  deleteReport: (reportId: number) => 
    request<{ status: string; report_id: number }>(`/reports/${reportId}`, { method: "DELETE" }),
  getCodeSnippet: (reportId: number, findingId: number) => 
    request<CodeSnippet>(`/reports/${reportId}/findings/${findingId}/snippet`),
  getCodebaseStructure: (reportId: number) =>
    request<CodebaseStructure>(`/reports/${reportId}/codebase`),
  getCodebaseSummary: (reportId: number) =>
    request<CodebaseSummary>(`/reports/${reportId}/codebase/summary`),
  getFileContent: (reportId: number, filePath: string) =>
    request<FileContent>(`/reports/${reportId}/codebase/file?file_path=${encodeURIComponent(filePath)}`),
  getDependencies: (reportId: number) =>
    request<DependencyGraph>(`/reports/${reportId}/dependencies`),
  getScanDiff: (reportId: number, compareReportId: number) =>
    request<ScanDiff>(`/reports/${reportId}/diff/${compareReportId}`),
  getFileTrends: (reportId: number, filePath: string) =>
    request<FileTrends>(`/reports/${reportId}/file-trends/${encodeURIComponent(filePath)}`),
  getTodos: (reportId: number) =>
    request<TodoScanResult>(`/reports/${reportId}/todos`),
  searchCode: (reportId: number, query: string) =>
    request<CodeSearchResult>(`/reports/${reportId}/search-code?q=${encodeURIComponent(query)}`),
  explainCode: (reportId: number, filePath: string, code: string, language?: string) =>
    request<CodeExplanation>(`/reports/${reportId}/explain-code`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_path: filePath, code, language }),
    }),
  getExploitability: (reportId: number) => request<ExploitScenario[]>(`/reports/${reportId}/exploitability`),
  startExploitability: (reportId: number, mode: "auto" | "summary" | "full" = "auto") =>
    request<{ status: string; mode: string }>(`/reports/${reportId}/exploitability?mode=${mode}`, { method: "POST" }),
  getAttackChains: (reportId: number) => request<AttackChain[]>(`/reports/${reportId}/attack-chains`),
  getAIInsights: (reportId: number) => request<AIInsights>(`/reports/${reportId}/ai-insights`),
  exportReport: (reportId: number, format: "markdown" | "pdf" | "docx") =>
    fetch(`${API_URL}/reports/${reportId}/export/${format}`),
  chatAboutReport: async (
    reportId: number,
    message: string,
    conversationHistory: ChatMessage[],
    contextTab: "findings" | "exploitability" = "findings"
  ): Promise<{ response: string; error?: string }> => {
    const resp = await fetch(`${API_URL}/reports/${reportId}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message,
        conversation_history: conversationHistory,
        context_tab: contextTab,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },
};

// Types mirrored from backend schemas (simplified)
export type ProjectSummary = {
  id: number;
  name: string;
  description?: string;
  git_url?: string;
  created_at: string;
  updated_at?: string;
};

export type ScanRun = {
  id: number;
  project_id: number;
  status: string;
  started_at?: string;
  finished_at?: string;
  error_message?: string;
};

export type Report = {
  id: number;
  project_id: number;
  scan_run_id: number;
  created_at: string;
  title: string;
  summary?: string;
  overall_risk_score?: number;
  data: {
    severity_counts?: Record<string, number>;
    affected_packages?: string[];
    code_issues?: { file?: string; summary: string; severity: string }[];
  };
};

export type Finding = {
  id: number;
  project_id: number;
  scan_run_id: number;
  type: string;
  severity: string;
  file_path?: string;
  line_number?: number;
  start_line?: number;
  end_line?: number;
  summary: string;
  details?: {
    secret_type?: string;
    description?: string;
    masked_value?: string;
    rule_id?: string;
    external_id?: string;
    dependency?: string;
    cvss_score?: number;
    cvss_vector?: string;
    epss_score?: number;
    epss_percentile?: number;
    epss_priority?: string;
    code_snippet?: string;
    message?: string;
    cwe?: string | string[];
    owasp?: string | string[];
    category?: string;
    fix?: string;
    nvd_description?: string;
    references?: Array<{ url: string; source?: string; tags?: string[] }>;
    // AI Analysis fields
    ai_analysis?: {
      is_false_positive?: boolean;
      false_positive_reason?: string;
      severity_adjusted?: boolean;
      original_severity?: string;
      severity_reason?: string;
      duplicate_group?: string;
      attack_chain?: string;
      data_flow_summary?: string;
    };
  };
};

export type ExploitScenario = {
  id: number;
  report_id: number;
  finding_id: number;
  severity?: string;
  title: string;
  narrative?: string;
  preconditions?: string;
  impact?: string;
  poc_outline?: string;
  mitigation_notes?: string;
};

export type CloneResponse = {
  message: string;
  repo_name: string;
  branch: string;
  path: string;
};

export type CodeSnippet = {
  finding_id: number;
  file_path: string | null;
  start_line: number | null;
  end_line: number | null;
  code_snippet: string | null;
  language?: string;
  source: "cached" | "code_chunk" | "none";
  details?: Record<string, unknown>;
};

export type FileFindings = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
};

export type CodebaseFile = {
  name: string;
  path: string;
  type: "file";
  language?: string;
  lines: number;
  chunks: number;
  findings: FileFindings;
};

export type CodebaseFolder = {
  name: string;
  path: string;
  type: "folder";
  children: CodebaseNode[];
  file_count: number;
  findings: FileFindings;
};

export type CodebaseNode = CodebaseFile | CodebaseFolder;

export type CodebaseStructure = {
  report_id: number;
  project_id: number;
  summary: {
    total_files: number;
    total_lines: number;
    languages: string[];
    total_findings: number;
  };
  tree: CodebaseNode[];
};

export type CodebaseSummary = {
  report_id: number;
  project_name: string;
  statistics: {
    total_files: number;
    total_lines: number;
    languages: Record<string, number>;
    findings_by_severity: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
    findings_by_type: Record<string, number>;
    total_findings: number;
  };
  app_summary: string | null;
  security_summary: string | null;
  has_app_summary: boolean;
  has_security_summary: boolean;
};

// File content for inline code preview
export type FileContent = {
  file_path: string;
  language: string | null;
  chunks: {
    start_line: number;
    end_line: number;
    code: string;
  }[];
  findings: {
    line: number;
    severity: string;
    type: string;
    summary: string;
  }[];
  total_lines: number;
  source?: "disk" | "chunks";  // "disk" = full file, "chunks" = assembled from indexed chunks
};

// Dependency graph types
export type ExternalDependency = {
  name: string;
  version: string | null;
  ecosystem: string;
  manifest_path: string | null;
  has_vulnerabilities: boolean;
};

export type InternalImport = {
  source: string;
  target: string;
  type: string;
};

export type DependencyGraph = {
  report_id: number;
  external_dependencies: ExternalDependency[];
  internal_imports: InternalImport[];
  files: string[];
  summary: {
    total_external: number;
    vulnerable_count: number;
    total_internal_edges: number;
    total_files: number;
    ecosystems: string[];
  };
};

// Scan diff types (Feature 5)
export type DiffFinding = {
  id: number;
  type: string;
  severity: string;
  summary: string;
  file_path: string | null;
  start_line: number | null;
};

export type ScanDiff = {
  report_id: number;
  compare_report_id: number;
  current_report_date: string | null;
  compare_report_date: string | null;
  new_findings: DiffFinding[];
  fixed_findings: DiffFinding[];
  summary: {
    total_new: number;
    total_fixed: number;
    files_with_new_findings: number;
    files_with_fixed_findings: number;
    severity_changes: {
      critical: { new: number; fixed: number };
      high: { new: number; fixed: number };
      medium: { new: number; fixed: number };
      low: { new: number; fixed: number };
      info: { new: number; fixed: number };
    };
    net_change: number;
  };
  changed_files: string[];
};

// File trends for sparkline (Feature: Finding Trends)
export type FileTrendPoint = {
  report_id: number;
  created_at: string | null;
  finding_count: number;
  severity_counts: Record<string, number>;
};

export type FileTrends = {
  file_path: string;
  trends: FileTrendPoint[];
  current_report_id: number;
};

// TODO/FIXME Scanner types
export type TodoItem = {
  type: "TODO" | "FIXME" | "HACK" | "XXX" | "BUG" | "NOTE";
  file_path: string;
  line: number;
  text: string;
  full_line: string;
};

export type TodoScanResult = {
  total: number;
  summary: Record<string, number>;
  by_file: Record<string, TodoItem[]>;
  items: TodoItem[];
};

// Code Search types
export type CodeSearchMatch = {
  file_path: string;
  line: number;
  content: string;
  context_before: string | null;
  context_after: string | null;
  language: string | null;
};

export type CodeSearchResult = {
  query: string;
  total: number;
  results: CodeSearchMatch[];
  truncated: boolean;
};

// Code Explanation types
export type CodeExplanation = {
  file_path: string;
  explanation: string | null;
  findings_count: number;
  error?: string;
};

export type AttackChain = {
  title: string;
  severity: string;
  finding_ids: number[];
  description: string;
  impact: string;
  likelihood: string;
};

export type FalsePositiveInfo = {
  finding_id: number;
  summary: string;
  reason: string | null;
  file_path: string | null;
};

export type AIInsights = {
  attack_chains: AttackChain[];
  false_positive_count: number;
  severity_adjustments: number;
  findings_analyzed: number;
  false_positives: FalsePositiveInfo[];
};

// PCAP Analysis Types
export type PcapFinding = {
  category: string;
  severity: string;
  title: string;
  description: string;
  source_ip?: string;
  dest_ip?: string;
  port?: number;
  protocol?: string;
  packet_number?: number;
  evidence?: string;
};

export type PcapSummary = {
  total_packets: number;
  duration_seconds: number;
  protocols: Record<string, number>;
  top_talkers: Array<{ ip: string; packets: number; bytes: number }>;
  dns_queries: string[];
  http_hosts: string[];
  potential_issues: number;
  // Network topology for visualization
  topology_nodes?: Array<{
    id: string;
    ip: string;
    type: "host" | "server" | "router" | "unknown";
    services?: string[];
    ports?: number[];
    packets?: number;
    bytes?: number;
    riskLevel?: "critical" | "high" | "medium" | "low" | "none";
  }>;
  topology_links?: Array<{
    source: string;
    target: string;
    protocol?: string;
    port?: number;
    packets?: number;
    bytes?: number;
    bidirectional?: boolean;
  }>;
};

export type PcapAnalysisResponse = {
  filename: string;
  summary: PcapSummary;
  findings: PcapFinding[];
  conversations: Array<{
    src: string;
    sport: number;
    dst: string;
    dport: number;
    protocol: string;
    service: string;
    packets: number;
    bytes: number;
  }>;
  ai_analysis?: string | AIAnalysisResult;
};

// AI Analysis result can be structured or raw
export type AIAnalysisResult = {
  structured_report?: AISecurityReport;
  raw_analysis?: string;
  parse_error?: string;
  error?: string;
};

// Structured AI Security Report
export type AISecurityReport = {
  risk_level: string;
  risk_score: number;
  executive_summary: string;
  
  // New detailed narrative section
  what_happened?: {
    narrative: string;
    timeline?: Array<{
      timestamp_range: string;
      description: string;
      hosts_involved: string[];
      significance: string;
    }>;
    communication_flow?: string;
  };
  
  key_findings: Array<{
    title: string;
    severity: string;
    description?: string;  // Legacy field
    what_we_found?: string;  // New detailed field
    evidence?: string;
    technical_evidence?: string;
    potential_impact?: string;
    recommendation?: string;
    recommended_action?: string;
  }>;
  
  traffic_analysis: {
    narrative_summary?: string;
    overall_assessment: string;
    protocol_breakdown_explained?: string;
    suspicious_patterns?: string[] | Array<{
      pattern_name: string;
      description: string;
      evidence: string;
      severity: string;
    }>;
    protocols_of_concern?: Array<{
      protocol: string;
      concern: string;
      affected_hosts: string[];
    }>;
    data_transfer_analysis?: string;
    data_flow_analysis?: string;
    encrypted_vs_cleartext?: string;
    encryption_assessment?: string;
  };
  
  // New hosts analysis section
  hosts_analysis?: Array<{
    ip_address: string;
    likely_role: string;
    hostname?: string;
    behavior_summary: string;
    services_identified?: string[];
    connections_made?: number;
    data_transferred?: string;
    risk_assessment: string;
    concerns?: string[];
  }>;
  
  dns_analysis: {
    narrative_summary?: string;
    overall_assessment: string;
    suspicious_domains: Array<{
      domain: string;
      reason?: string;
      why_suspicious?: string;
      threat_category: string;
      recommended_action?: string;
    }>;
    legitimate_activity?: string;
    dga_indicators?: string;
    dga_analysis?: string;
    tunneling_indicators?: string;
    tunneling_analysis?: string;
    notable_lookups?: string[];
  };
  
  credential_exposure: {
    severity: string;
    summary?: string;
    narrative_summary?: string;
    exposed_credentials: Array<{
      type?: string;
      credential_type?: string;
      service?: string;
      affected_service?: string;
      exposure_method?: string;
      source_ip?: string;
      source_host?: string;
      dest_ip?: string;
      destination?: string;
      risk?: string;
      risk_explanation?: string;
      immediate_action_required?: string;
    }>;
    affected_services?: string[];
    immediate_actions?: string[];
    secure_practices_observed?: string;
  };
  
  indicators_of_compromise: Array<{
    type?: string;
    ioc_type?: string;
    value?: string;
    ioc_value?: string;
    context?: string;
    context_explanation?: string;
    threat_level: string;
    threat_association?: string;
    recommended_action?: string;
    recommended_response?: string;
  }>;
  
  attack_indicators: {
    overall_assessment?: string;
    reconnaissance: {
      detected: boolean;
      evidence?: string;
      explanation?: string;
      techniques?: string[];
      attacker_interest?: string;
    };
    lateral_movement: {
      detected: boolean;
      evidence?: string;
      explanation?: string;
      affected_systems?: string[];
      movement_pattern?: string;
    };
    data_exfiltration: {
      detected: boolean;
      evidence?: string;
      explanation?: string;
      estimated_volume?: string;
      estimated_data_volume?: string;
      exfiltration_method?: string;
    };
    command_and_control: {
      detected: boolean;
      evidence?: string;
      explanation?: string;
      suspected_c2_endpoints?: string[];
      c2_infrastructure?: string[];
      communication_pattern?: string;
    };
  };
  
  recommendations: Array<{
    priority: string;
    title?: string;
    category?: string;
    action?: string;
    detailed_action?: string;
    rationale: string;
    expected_outcome?: string;
    effort?: string;
    effort_level?: string;
    responsible_team?: string;
  }>;
  
  timeline_analysis?: string;
  
  // Legacy affected_assets
  affected_assets?: Array<{
    ip: string;
    role: string;
    hostname?: string;
    risk_level: string;
    services_exposed?: string[];
    concerns: string;
  }>;
  
  // New conclusion field
  conclusion?: string;
};

export type MultiPcapAnalysisResponse = {
  total_files: number;
  total_packets: number;
  total_findings: number;
  analyses: PcapAnalysisResponse[];
  combined_ai_summary?: string;
  report_id?: number;  // ID of saved report in database
};

export type PcapStatusResponse = {
  available: boolean;
  message: string;
  max_file_size_mb: number;
  allowed_extensions: string[];
};

// PCAP Analysis Functions
export async function getPcapStatus(): Promise<PcapStatusResponse> {
  const resp = await fetch(`${API_URL}/pcap/status`);
  if (!resp.ok) {
    throw new Error(await resp.text());
  }
  return resp.json();
}

export async function analyzePcaps(
  files: File[],
  includeAi: boolean = true,
  maxPackets: number = 100000
): Promise<MultiPcapAnalysisResponse> {
  const form = new FormData();
  files.forEach((file) => form.append("files", file));

  const params = new URLSearchParams({
    include_ai: String(includeAi),
    max_packets: String(maxPackets),
  });

  const resp = await fetch(`${API_URL}/pcap/analyze?${params}`, {
    method: "POST",
    body: form,
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(text || resp.statusText);
  }
  return resp.json();
}

// PCAP Chat Types and Functions
export type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

export type PcapChatRequest = {
  message: string;
  conversation_history: ChatMessage[];
  pcap_context: {
    summary?: any;
    findings?: any[];
    ai_analysis?: any;
  };
};

export type PcapChatResponse = {
  response: string;
  error?: string;
};

export async function chatAboutPcap(request: PcapChatRequest): Promise<PcapChatResponse> {
  const resp = await fetch(`${API_URL}/pcap/chat`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(text || resp.statusText);
  }
  return resp.json();
}

// ============================================================================
// Saved PCAP Report Types and Functions
// ============================================================================

export type SavedReportSummary = {
  id: number;
  title: string;
  filename: string;
  analysis_type: string;
  risk_level: string;
  risk_score: number;
  total_findings: number;
  created_at: string;
};

export type SavedReportList = {
  reports: SavedReportSummary[];
  total: number;
};

export type SavedReportDetail = {
  id: number;
  title: string;
  filename: string;
  analysis_type: string;
  risk_level: string;
  risk_score: number;
  created_at: string;
  summary_data: {
    total_files: number;
    total_packets: number;
    total_findings: number;
    summaries: any[];
  };
  findings_data: Array<{
    category: string;
    severity: string;
    title: string;
    description: string;
    source_ip?: string;
    dest_ip?: string;
    port?: number;
    protocol?: string;
    packet_number?: number;
    evidence?: string;
    filename?: string;
  }>;
  ai_report?: {
    analyses: any[];
  };
};

export async function getPcapReports(skip: number = 0, limit: number = 20): Promise<SavedReportList> {
  const params = new URLSearchParams({
    skip: String(skip),
    limit: String(limit),
  });
  const resp = await fetch(`${API_URL}/pcap/reports?${params}`);
  if (!resp.ok) {
    throw new Error(await resp.text());
  }
  return resp.json();
}

export async function getPcapReport(reportId: number): Promise<SavedReportDetail> {
  const resp = await fetch(`${API_URL}/pcap/reports/${reportId}`);
  if (!resp.ok) {
    throw new Error(await resp.text());
  }
  return resp.json();
}

export async function deletePcapReport(reportId: number): Promise<{ message: string }> {
  const resp = await fetch(`${API_URL}/pcap/reports/${reportId}`, {
    method: "DELETE",
  });
  if (!resp.ok) {
    throw new Error(await resp.text());
  }
  return resp.json();
}

// ============================================================================
// Network Analysis Types (Unified)
// ============================================================================

export type NetworkFinding = {
  category: string;
  severity: string;
  title: string;
  description: string;
  host?: string;
  source_ip?: string;
  dest_ip?: string;
  port?: number;
  protocol?: string;
  service?: string;
  evidence?: string;
};

export type NetworkSummary = {
  total_findings: number;
  // PCAP-specific
  total_packets?: number;
  duration_seconds?: number;
  protocols?: Record<string, number>;
  top_talkers?: Array<{ ip: string; packets: number; bytes: number }>;
  dns_queries?: string[];
  http_hosts?: string[];
  // Nmap-specific
  total_hosts?: number;
  hosts_up?: number;
  open_ports?: number;
  services_detected?: Record<string, number>;
  scan_type?: string;
  command?: string;
};

export type NetworkAnalysis = {
  analysis_type: string;
  filename: string;
  summary: NetworkSummary;
  findings: NetworkFinding[];
  hosts?: any[];
  conversations?: any[];
  ai_analysis?: any;
};

export type NmapAnalysisResult = {
  analysis_type: string;
  total_files: number;
  total_findings: number;
  analyses: NetworkAnalysis[];
  report_id?: number;
};

export type SavedNetworkReport = {
  id: number;
  analysis_type: string;
  title: string;
  filename?: string;
  created_at: string;
  risk_level?: string;
  risk_score?: number;
  findings_count: number;
};

export type FullNetworkReport = {
  id: number;
  analysis_type: string;
  title: string;
  filename?: string;
  created_at: string;
  risk_level?: string;
  risk_score?: number;
  summary_data?: any;
  findings_data?: any[];
  ai_report?: any;
};

// Nmap scan types
export type NmapScanType = {
  id: string;
  name: string;
  description: string;
  timeout: number;
  requires_root: boolean;
  estimated_time: string;
  intensity: number;
};

// Nmap scan request
export type NmapScanRequest = {
  target: string;
  scan_type: string;
  ports?: string;
  title?: string;
};

// Packet capture profile
export type CaptureProfile = {
  id: string;
  name: string;
  description: string;
  default_filter: string;
  timeout: number;
  estimated_time: string;
  intensity: number;
};

// Network interface
export type NetworkInterface = {
  name: string;
  description: string;
};

// Packet capture request
export type PacketCaptureRequest = {
  interface: string;
  duration: number;
  packet_count?: number;
  capture_filter?: string;
  profile: string;
  title?: string;
};

// Network Analysis API Client
export const apiClient = {
  // Network Analysis endpoints
  getNetworkStatus: async (): Promise<{ 
    pcap_available: boolean; 
    nmap_available: boolean; 
    nmap_installed: boolean; 
    tshark_installed: boolean;
    message: string;
  }> => {
    const resp = await fetch(`${API_URL}/network/status`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get available Nmap scan types
  getNmapScanTypes: async (): Promise<NmapScanType[]> => {
    const resp = await fetch(`${API_URL}/network/nmap/scan-types`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get available packet capture profiles
  getCaptureProfiles: async (): Promise<CaptureProfile[]> => {
    const resp = await fetch(`${API_URL}/network/pcap/capture-profiles`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get available network interfaces
  getNetworkInterfaces: async (): Promise<NetworkInterface[]> => {
    const resp = await fetch(`${API_URL}/network/pcap/interfaces`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Validate a BPF capture filter
  validateCaptureFilter: async (filter: string): Promise<{ valid: boolean; filter: string; error?: string }> => {
    const resp = await fetch(`${API_URL}/network/pcap/validate-filter?filter_expr=${encodeURIComponent(filter)}`, {
      method: "POST",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Run live packet capture
  runPacketCapture: async (request: PacketCaptureRequest): Promise<MultiPcapAnalysisResponse> => {
    const resp = await fetch(`${API_URL}/network/pcap/capture`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Run a live Nmap scan
  runNmapScan: async (request: NmapScanRequest): Promise<NmapAnalysisResult> => {
    const resp = await fetch(`${API_URL}/network/nmap/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Validate a target before scanning
  validateNmapTarget: async (target: string): Promise<{ valid: boolean; target: string; error?: string }> => {
    const resp = await fetch(`${API_URL}/network/nmap/validate-target?target=${encodeURIComponent(target)}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  analyzeNmap: async (files: File[], includeAi: boolean = true, saveReport: boolean = true, title?: string): Promise<NmapAnalysisResult> => {
    const form = new FormData();
    files.forEach((file) => form.append("files", file));

    const params = new URLSearchParams({
      include_ai: String(includeAi),
      save_report: String(saveReport),
    });
    if (title) params.append("title", title);

    const resp = await fetch(`${API_URL}/network/nmap/analyze?${params}`, {
      method: "POST",
      body: form,
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  analyzePcapNetwork: async (files: File[], includeAi: boolean = true, saveReport: boolean = true, title?: string): Promise<NmapAnalysisResult> => {
    const form = new FormData();
    files.forEach((file) => form.append("files", file));

    const params = new URLSearchParams({
      include_ai: String(includeAi),
      save_report: String(saveReport),
    });
    if (title) params.append("title", title);

    const resp = await fetch(`${API_URL}/network/pcap/analyze?${params}`, {
      method: "POST",
      body: form,
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  getNetworkReports: async (analysisType?: string): Promise<SavedNetworkReport[]> => {
    const params = analysisType ? `?analysis_type=${analysisType}` : "";
    const resp = await fetch(`${API_URL}/network/reports${params}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  getNetworkReport: async (reportId: number): Promise<FullNetworkReport> => {
    const resp = await fetch(`${API_URL}/network/reports/${reportId}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  deleteNetworkReport: async (reportId: number): Promise<{ status: string; report_id: number }> => {
    const resp = await fetch(`${API_URL}/network/reports/${reportId}`, { method: "DELETE" });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  exportNetworkReport: async (reportId: number, format: "markdown" | "pdf" | "docx"): Promise<Blob> => {
    const resp = await fetch(`${API_URL}/network/reports/${reportId}/export/${format}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.blob();
  },

  // Chat about network analysis
  chatAboutNetworkAnalysis: async (
    message: string,
    conversationHistory: ChatMessage[],
    context: {
      summary?: any;
      findings?: any[];
      hosts?: any[];
      ai_analysis?: any;
    },
    analysisType: "nmap" | "pcap" = "nmap"
  ): Promise<{ response: string; error?: string }> => {
    const resp = await fetch(`${API_URL}/network/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message,
        conversation_history: conversationHistory,
        context,
        analysis_type: analysisType,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // SSL Scanner endpoints
  scanSSL: async (request: {
    targets: Array<{ host: string; port: number }>;
    timeout?: number;
    include_ai?: boolean;
    title?: string;
  }): Promise<any> => {
    const resp = await fetch(`${API_URL}/network/ssl/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  scanSSLSingle: async (host: string, port: number = 443, timeout: number = 10): Promise<any> => {
    const params = new URLSearchParams({
      host,
      port: String(port),
      timeout: String(timeout),
    });
    const resp = await fetch(`${API_URL}/network/ssl/scan-single?${params}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Protocol Decoder endpoints
  getDecoderStatus: async (): Promise<{
    available: boolean;
    message: string;
    supported_protocols: string[];
  }> => {
    const resp = await fetch(`${API_URL}/network/pcap/decoder-status`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  decodeProtocols: async (file: File, includeAi: boolean = true, maxPackets: number = 50000): Promise<any> => {
    const form = new FormData();
    form.append("file", file);

    const params = new URLSearchParams({
      include_ai: String(includeAi),
      max_packets: String(maxPackets),
    });

    const resp = await fetch(`${API_URL}/network/pcap/decode-protocols?${params}`, {
      method: "POST",
      body: form,
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ============================================================================
  // DNS Reconnaissance Endpoints
  // ============================================================================

  getDnsStatus: async (): Promise<{
    available: boolean;
    dnspython_installed: boolean;
    message: string;
    features: Record<string, boolean>;
  }> => {
    const resp = await fetch(`${API_URL}/dns/status`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  getDnsScanTypes: async (): Promise<DNSScanType[]> => {
    const resp = await fetch(`${API_URL}/dns/scan-types`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  validateDomain: async (domain: string): Promise<{ valid: boolean; domain?: string; error?: string }> => {
    const resp = await fetch(`${API_URL}/dns/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  runDnsScan: async (request: {
    domain: string;
    scan_type?: string;
    custom_subdomains?: string[];
    save_report?: boolean;
    report_title?: string;
    run_ai_analysis?: boolean;
  }): Promise<DNSReconResult> => {
    const resp = await fetch(`${API_URL}/dns/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  runDnsScanWithProgress: (
    request: {
      domain: string;
      scan_type?: string;
      custom_subdomains?: string[];
      save_report?: boolean;
      report_title?: string;
      run_ai_analysis?: boolean;
    },
    onProgress: (phase: string, progress: number, message: string) => void,
    onResult: (result: DNSReconResult) => void,
    onError: (error: string) => void
  ): AbortController => {
    const controller = new AbortController();
    
    (async () => {
      try {
        const resp = await fetch(`${API_URL}/dns/scan/stream`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
          signal: controller.signal,
        });
        
        if (!resp.ok) {
          onError(await resp.text());
          return;
        }
        
        const reader = resp.body?.getReader();
        if (!reader) {
          onError("No response body");
          return;
        }
        
        const decoder = new TextDecoder();
        let buffer = "";
        
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n\n");
          buffer = lines.pop() || "";
          
          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                const data = JSON.parse(line.slice(6));
                if (data.type === "progress") {
                  onProgress(data.phase, data.progress, data.message);
                } else if (data.type === "result") {
                  onResult(data.data);
                } else if (data.type === "error") {
                  onError(data.error);
                }
              } catch {
                // Ignore parse errors
              }
            }
          }
        }
      } catch (err: any) {
        if (err.name !== "AbortError") {
          onError(err.message || "Stream failed");
        }
      }
    })();
    
    return controller;
  },

  chatAboutDns: async (
    message: string,
    dnsContext: Record<string, any>,
    conversationHistory?: Array<{ role: string; content: string }>
  ): Promise<{ response: string; suggestions: string[] }> => {
    const resp = await fetch(`${API_URL}/dns/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message,
        dns_context: dnsContext,
        conversation_history: conversationHistory,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  getDnsReports: async (skip: number = 0, limit: number = 20): Promise<{ reports: SavedDNSReport[]; total: number }> => {
    const params = new URLSearchParams({ skip: String(skip), limit: String(limit) });
    const resp = await fetch(`${API_URL}/dns/reports?${params}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  getDnsReport: async (reportId: number): Promise<DNSReconResult> => {
    const resp = await fetch(`${API_URL}/dns/reports/${reportId}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  deleteDnsReport: async (reportId: number): Promise<void> => {
    const resp = await fetch(`${API_URL}/dns/reports/${reportId}`, { method: "DELETE" });
    if (!resp.ok) throw new Error(await resp.text());
  },

  // WHOIS Lookup Endpoints
  getWhoisStatus: async (): Promise<{ available: boolean; message: string }> => {
    const resp = await fetch(`${API_URL}/dns/whois/status`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  whoisDomain: async (domain: string): Promise<WhoisDomainResult> => {
    const resp = await fetch(`${API_URL}/dns/whois/domain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  whoisIP: async (ipAddress: string): Promise<WhoisIPResult> => {
    const resp = await fetch(`${API_URL}/dns/whois/ip`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip_address: ipAddress }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ============================================================================
  // Traceroute Visualization Endpoints
  // ============================================================================

  getTracerouteStatus: async (): Promise<TracerouteStatus> => {
    const resp = await fetch(`${API_URL}/traceroute/status`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  validateTracerouteTarget: async (target: string): Promise<{ valid: boolean; target?: string; resolved_ip?: string; error?: string }> => {
    const resp = await fetch(`${API_URL}/traceroute/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  runTraceroute: async (request: TracerouteRequest): Promise<TracerouteResponse> => {
    const resp = await fetch(`${API_URL}/traceroute/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  runTracerouteStream: (
    request: TracerouteRequest,
    onHop: (hopNumber: number, rawLine: string) => void,
    onComplete: (result: TracerouteResponse) => void,
    onError: (error: string) => void
  ): AbortController => {
    const controller = new AbortController();
    
    (async () => {
      try {
        const resp = await fetch(`${API_URL}/traceroute/run/stream`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
          signal: controller.signal,
        });
        
        if (!resp.ok) {
          onError(await resp.text());
          return;
        }
        
        const reader = resp.body?.getReader();
        if (!reader) {
          onError("No response body");
          return;
        }
        
        const decoder = new TextDecoder();
        let buffer = "";
        
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n\n");
          buffer = lines.pop() || "";
          
          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                const data = JSON.parse(line.slice(6));
                if (data.type === "hop") {
                  onHop(data.number, data.raw);
                } else if (data.type === "complete") {
                  onComplete(data);
                } else if (data.type === "error") {
                  onError(data.message);
                }
              } catch {
                // Ignore parse errors
              }
            }
          }
        }
      } catch (err: any) {
        if (err.name !== "AbortError") {
          onError(err.message || "Stream failed");
        }
      }
    })();
    
    return controller;
  },

  chatAboutTraceroute: async (
    message: string,
    tracerouteContext: Record<string, any>,
    conversationHistory?: Array<{ role: string; content: string }>
  ): Promise<{ response: string; error?: string }> => {
    const resp = await fetch(`${API_URL}/traceroute/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message,
        traceroute_context: tracerouteContext,
        chat_history: conversationHistory,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  getTracerouteReports: async (): Promise<TracerouteSavedReport[]> => {
    const resp = await fetch(`${API_URL}/traceroute/reports`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  getTracerouteReport: async (reportId: number): Promise<TracerouteReportDetail> => {
    const resp = await fetch(`${API_URL}/traceroute/reports/${reportId}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  deleteTracerouteReport: async (reportId: number): Promise<void> => {
    const resp = await fetch(`${API_URL}/traceroute/reports/${reportId}`, {
      method: "DELETE",
    });
    if (!resp.ok) throw new Error(await resp.text());
  },
};

// ============================================================================
// DNS Reconnaissance Types
// ============================================================================

export type DNSScanType = {
  id: string;
  name: string;
  description: string;
  record_types: string[];
  subdomain_count: number;
  check_security: boolean;
  zone_transfer: boolean;
  timeout: number;
  estimated_time: string;
};

export type DNSRecord = {
  record_type: string;
  name: string;
  value: string;
  ttl?: number;
  priority?: number;
};

export type SubdomainResult = {
  subdomain: string;
  full_domain: string;
  ip_addresses: string[];
  cname?: string;
  status: string;
};

export type DNSSecurityAnalysis = {
  has_spf: boolean;
  spf_record?: string;
  spf_issues: string[];
  has_dmarc: boolean;
  dmarc_record?: string;
  dmarc_issues: string[];
  has_dkim: boolean;
  dkim_selectors_found: string[];
  has_dnssec: boolean;
  dnssec_details?: string;
  has_caa: boolean;
  caa_records: string[];
  mail_security_score: number;
  overall_issues: string[];
  recommendations: string[];
};

export type DNSReconResult = {
  domain: string;
  scan_timestamp: string;
  scan_duration_seconds: number;
  records: DNSRecord[];
  nameservers: string[];
  mail_servers: Array<{ server: string; priority: number }>;
  subdomains: SubdomainResult[];
  zone_transfer_possible: boolean;
  zone_transfer_data: string[];
  security?: DNSSecurityAnalysis;
  reverse_dns: Record<string, string>;
  total_records: number;
  total_subdomains: number;
  unique_ips: string[];
  ai_analysis?: any;
  report_id?: number;
};

export type SavedDNSReport = {
  id: number;
  domain: string;
  scan_type: string;
  title?: string;
  total_records: number;
  total_subdomains: number;
  zone_transfer_possible: boolean;
  mail_security_score?: number;
  created_at: string;
};

// WHOIS Types
export type WhoisDomainResult = {
  domain: string;
  registrar?: string;
  registrar_url?: string;
  creation_date?: string;
  expiration_date?: string;
  updated_date?: string;
  name_servers: string[];
  status: string[];
  registrant_name?: string;
  registrant_organization?: string;
  registrant_country?: string;
  registrant_email?: string;
  admin_email?: string;
  tech_email?: string;
  dnssec?: string;
  raw_text: string;
  error?: string;
};

export type WhoisIPResult = {
  ip_address: string;
  network_name?: string;
  network_range?: string;
  cidr?: string;
  asn?: string;
  asn_name?: string;
  organization?: string;
  country?: string;
  registrar?: string;  // RIR (ARIN, RIPE, etc.)
  registration_date?: string;
  updated_date?: string;
  abuse_contact?: string;
  tech_contact?: string;
  description: string[];
  raw_text: string;
  error?: string;
};

// ============================================================================
// Traceroute Types
// ============================================================================

export type TracerouteStatus = {
  available: boolean;
  traceroute_installed: boolean;
  platform: string;
  message: string;
  features: {
    icmp_mode: boolean;
    udp_mode: boolean;
    custom_queries: boolean;
    hostname_resolution: boolean;
    mtr_available: boolean;
  };
};

export type TracerouteRequest = {
  target: string;
  max_hops?: number;
  timeout?: number;
  queries?: number;
  use_icmp?: boolean;
  resolve_hostnames?: boolean;
  save_report?: boolean;
  report_title?: string;
};

export type TracerouteHop = {
  hop_number: number;
  ip_address?: string;
  hostname?: string;
  rtt_ms: number[];
  avg_rtt_ms?: number;
  packet_loss: number;
  is_destination: boolean;
  is_timeout: boolean;
  asn?: string;
  location?: string;
};

export type TracerouteResult = {
  target: string;
  target_ip?: string;
  hops: TracerouteHop[];
  total_hops: number;
  completed: boolean;
  start_time: string;
  end_time: string;
  duration_ms: number;
  platform: string;
  command_used: string;
};

export type TracerouteAIAnalysis = {
  summary?: string;
  network_segments?: Array<{
    segment: string;
    hops: string;
    description: string;
  }>;
  performance_analysis?: {
    overall_latency: string;
    bottlenecks: string[];
    packet_loss_concerns: string[];
  };
  security_observations?: Array<{
    observation: string;
    severity: string;
    details: string;
  }>;
  recommendations?: string[];
  risk_score?: number;
  error?: string;
  raw_analysis?: string;
};

export type TracerouteResponse = {
  result: TracerouteResult;
  ai_analysis: TracerouteAIAnalysis;
  report_id?: number;
};

export type TracerouteSavedReport = {
  id: number;
  title: string;
  filename: string;
  risk_score: number;
  total_findings: number;
  created_at: string;
  summary?: string;
};

export type TracerouteReportDetail = {
  id: number;
  title: string;
  filename: string;
  analysis_type: string;
  risk_score: number;
  total_findings: number;
  summary?: string;
  report_data: {
    result: TracerouteResult;
    ai_analysis: TracerouteAIAnalysis;
  };
  ai_report: TracerouteAIAnalysis;
  created_at: string;
};

// ============================================================================
// API Endpoint Tester Types
// ============================================================================

export type APITestSeverity = "critical" | "high" | "medium" | "low" | "info";

export type APITestCategory = 
  | "authentication" 
  | "authorization" 
  | "input_validation" 
  | "rate_limiting" 
  | "cors" 
  | "headers" 
  | "information_disclosure" 
  | "http_methods" 
  | "graphql" 
  | "general";

export type APITestFinding = {
  title: string;
  description: string;
  severity: string;
  category: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  endpoint: string;
  owasp_api?: string;  // OWASP API Security Top 10 mapping
};

export type APIEndpointResult = {
  url: string;
  method: string;
  status_code?: number;
  response_time_ms: number;
  content_type?: string;
  response_size: number;
  headers: Record<string, string>;
  findings: APITestFinding[];
  error?: string;
};

export type APITestResult = {
  base_url: string;
  endpoints_tested: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  test_duration_seconds: number;
  endpoint_results: APIEndpointResult[];
  all_findings: APITestFinding[];
  security_score: number;
  summary: string;
  error?: string;
  owasp_api_breakdown?: Record<string, number>;  // OWASP API findings breakdown
};

export type APIEndpointConfig = {
  url: string;
  method: string;
  headers?: Record<string, string>;
  params?: Record<string, string>;
  body?: any;
};

export type APITestRequest = {
  base_url: string;
  endpoints: APIEndpointConfig[];
  auth_type?: "none" | "basic" | "bearer" | "api_key";
  auth_value?: string;
  test_auth?: boolean;
  test_cors?: boolean;
  test_rate_limit?: boolean;
  test_input_validation?: boolean;
  test_methods?: boolean;
  test_graphql?: boolean;
  proxy_url?: string;  // HTTP/HTTPS proxy URL
  timeout?: number;    // Request timeout in seconds
};

export type APIQuickScanRequest = {
  url: string;
  auth_header?: string;
  proxy_url?: string;  // HTTP/HTTPS proxy URL
};

// WebSocket Testing Types
export type WebSocketTestRequest = {
  url: string;
  auth_token?: string;
  test_messages?: string[];
  timeout?: number;
  proxy_url?: string;
};

export type WebSocketFinding = {
  title: string;
  description: string;
  severity: string;
  category: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  owasp_api?: string;
};

export type WebSocketTestResult = {
  url: string;
  connected: boolean;
  connection_time_ms: number;
  protocol?: string;
  subprotocol?: string;
  findings: WebSocketFinding[];
  messages_sent: number;
  messages_received: number;
  error?: string;
  test_duration_seconds: number;
  security_score: number;
  owasp_api_breakdown: Record<string, number>;
};

// OWASP API Security Top 10 Types
export type OWASPAPICategory = {
  name: string;
  description: string;
  url: string;
};

export type OWASPAPITop10 = {
  version: string;
  categories: Record<string, OWASPAPICategory>;
};

export type APITestAIAnalysis = {
  analysis: string;
  recommendations: string[];
  test_result_summary: {
    security_score: number;
    total_findings: number;
    critical_count: number;
    high_count: number;
  };
};

// Network Discovery Types
export type DiscoveredService = {
  ip: string;
  port: number;
  url: string;
  status_code: number;
  server?: string;
  title?: string;
  is_api: boolean;
  api_indicators: string[];
};

export type NetworkDiscoveryResult = {
  subnet: string;
  total_hosts_scanned: number;
  services_found: number;
  api_services_found: number;
  scan_duration_seconds: number;
  services: DiscoveredService[];
};

export type NetworkDiscoveryRequest = {
  subnet: string;
  ports?: number[];
  timeout?: number;
  max_concurrent?: number;
  max_hosts?: number;
  overall_timeout?: number;
};

// Target Preset Types
export type TargetPreset = {
  id: string;
  name: string;
  description: string;
  base_url: string;
  endpoints: { method: string; path: string }[];
  auth_type?: string;
  auth_value?: string;
  headers: Record<string, string>;
  tags: string[];
  is_default: boolean;
};

export type PresetCreateRequest = {
  name: string;
  description?: string;
  base_url: string;
  endpoints?: { method: string; path: string }[];
  auth_type?: string;
  auth_value?: string;
  headers?: Record<string, string>;
  tags?: string[];
};

// Batch Testing Types
export type BatchTestTarget = {
  url: string;
  name?: string;
  auth_type?: string;
  auth_value?: string;
};

export type BatchTestRequest = {
  targets: BatchTestTarget[];
  test_options?: Record<string, boolean>;
  proxy_url?: string;
  max_concurrent?: number;
};

export type BatchTargetResult = {
  target: string;
  name?: string;
  success: boolean;
  error?: string;
  security_score: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  findings: any[];
};

export type BatchTestResult = {
  total_targets: number;
  successful: number;
  failed: number;
  results: BatchTargetResult[];
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  scan_duration_seconds: number;
};

// OpenAPI Import Types
export type OpenAPIEndpoint = {
  path: string;
  method: string;
  summary: string;
  description: string;
  parameters: Array<{
    name: string;
    in: string;
    required: boolean;
    type: string;
  }>;
  request_body?: {
    content_type: string;
    required: boolean;
    schema: any;
  };
  security: string[];
  tags: string[];
};

export type OpenAPIParseResult = {
  title: string;
  version: string;
  base_url: string;
  endpoints: OpenAPIEndpoint[];
  security_schemes: Record<string, any>;
  total_endpoints: number;
  methods_breakdown: Record<string, number>;
  tags: string[];
  errors: string[];
};

export type OpenAPIImportRequest = {
  spec_content?: string;
  spec_url?: string;
};

// JWT Analyzer Types
export type JWTFinding = {
  title: string;
  description: string;
  severity: string;
  cwe?: string;
  evidence?: string;
  remediation?: string;
};

export type JWTAnalysisResult = {
  valid_structure: boolean;
  header: Record<string, any>;
  payload: Record<string, any>;
  signature: string;
  algorithm: string;
  findings: JWTFinding[];
  is_expired: boolean;
  expiry_time: string | null;
  issued_at: string | null;
  issuer: string | null;
  audience: string | null;
  subject: string | null;
  raw_parts: string[];
};

export type JWTAnalyzeRequest = {
  token: string;
  test_weak_secrets?: boolean;
};

// Export Report Types
export type ExportFormat = "json" | "markdown" | "pdf" | "docx";

export type ExportTestResultRequest = {
  test_result: APITestResult;
  format: ExportFormat;
  title?: string;
};

export type ExportBatchResultRequest = {
  batch_result: BatchTestResult;
  format: ExportFormat;
  title?: string;
};

export type ExportJWTResultRequest = {
  jwt_result: JWTAnalysisResult;
  format: ExportFormat;
};

export type ExportAutoTestResultRequest = {
  auto_test_result: AIAutoTestResult;
  format: ExportFormat;
  title?: string;
};

export type ExportWebSocketResultRequest = {
  websocket_result: WebSocketTestResult;
  format: ExportFormat;
  title?: string;
};

// Chat types for API Tester
export type APITesterChatMessage = {
  role: "user" | "assistant";
  content: string;
};

export type APITesterChatRequest = {
  message: string;
  conversation_history: APITesterChatMessage[];
  context: {
    test_result?: APITestResult;
    batch_result?: BatchTestResult;
    jwt_result?: JWTAnalysisResult;
    openapi_result?: OpenAPIParseResult;
  };
};

export type APITesterChatResponse = {
  response: string;
  error?: string;
};

// AI Auto-Test types
export type AIAutoTestRequest = {
  target: string;
  ports?: number[];
  probe_endpoints?: boolean;
  run_security_tests?: boolean;
  max_endpoints?: number;
  timeout?: number;
  network_timeout?: number;  // For CIDR/network scans - lower = faster
  max_concurrent?: number;   // Concurrent connections for network scans
  proxy_url?: string;
};

export type AIAutoTestResult = {
  target: string;
  target_type: string;
  discovered_services: Array<{
    port: number;
    scheme: string;
    url: string;
    status_code: number;
    content_type: string;
    server: string;
  }>;
  discovered_endpoints: Array<{
    path: string;
    url: string;
    method: string;
    status_code: number;
    content_type: string;
    is_json: boolean;
    is_html: boolean;
    requires_auth: boolean;
  }>;
  test_results: Array<{
    base_url: string;
    endpoints_tested: number;
    security_score: number;
    findings_count: number;
  }>;
  all_findings: APITestFinding[];
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  security_score: number;
  ai_summary: string;
  scan_duration_seconds: number;
  error?: string;
};

// Add to apiClient object
export const apiTester = {
  // Run comprehensive API security test
  testAPI: async (request: APITestRequest): Promise<APITestResult> => {
    const resp = await fetch(`${API_URL}/api-tester/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Quick scan a single endpoint
  quickScan: async (request: APIQuickScanRequest): Promise<APITestResult> => {
    const resp = await fetch(`${API_URL}/api-tester/quick-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get AI analysis of test results
  analyzeResults: async (testResult: APITestResult): Promise<APITestAIAnalysis> => {
    const resp = await fetch(`${API_URL}/api-tester/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test_result: testResult }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get common test payloads
  getPayloads: async (): Promise<Record<string, string[]>> => {
    const resp = await fetch(`${API_URL}/api-tester/payloads`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get security headers reference
  getSecurityHeadersInfo: async (): Promise<Record<string, { description: string; recommended: string }>> => {
    const resp = await fetch(`${API_URL}/api-tester/security-headers`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Test WebSocket endpoint for security vulnerabilities
  testWebSocket: async (request: WebSocketTestRequest): Promise<WebSocketTestResult> => {
    const resp = await fetch(`${API_URL}/api-tester/websocket-test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get OWASP API Security Top 10 reference
  getOWASPAPITop10: async (): Promise<OWASPAPITop10> => {
    const resp = await fetch(`${API_URL}/api-tester/owasp-api-top10`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get WebSocket test payloads
  getWebSocketPayloads: async (): Promise<Record<string, string[]>> => {
    const resp = await fetch(`${API_URL}/api-tester/websocket-payloads`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Discover HTTP/API services on a network
  discoverServices: async (request: NetworkDiscoveryRequest): Promise<NetworkDiscoveryResult> => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), (request.overall_timeout || 120) * 1000 + 10000); // Add 10s buffer
    
    try {
      const resp = await fetch(`${API_URL}/api-tester/discover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (!resp.ok) throw new Error(await resp.text());
      return resp.json();
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new Error(`Network discovery timed out after ${request.overall_timeout || 120}s`);
      }
      throw err;
    }
  },

  // Get all target presets
  getPresets: async (): Promise<TargetPreset[]> => {
    const resp = await fetch(`${API_URL}/api-tester/presets`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Create a new target preset
  createPreset: async (preset: PresetCreateRequest): Promise<TargetPreset> => {
    const resp = await fetch(`${API_URL}/api-tester/presets`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(preset),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Delete a target preset
  deletePreset: async (presetId: string): Promise<{ status: string; id: string }> => {
    const resp = await fetch(`${API_URL}/api-tester/presets/${presetId}`, {
      method: "DELETE",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Run batch test on multiple targets
  batchTest: async (request: BatchTestRequest): Promise<BatchTestResult> => {
    const resp = await fetch(`${API_URL}/api-tester/batch-test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Import OpenAPI/Swagger specification
  importOpenAPI: async (request: OpenAPIImportRequest): Promise<OpenAPIParseResult> => {
    const resp = await fetch(`${API_URL}/api-tester/import-openapi`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Analyze JWT token for security issues
  analyzeJWT: async (request: JWTAnalyzeRequest): Promise<JWTAnalysisResult> => {
    const resp = await fetch(`${API_URL}/api-tester/analyze-jwt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Export test result as JSON, Markdown, PDF, or Word
  exportTestResult: async (request: ExportTestResultRequest): Promise<Blob | string> => {
    const resp = await fetch(`${API_URL}/api-tester/export/test-result`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    // Return blob for binary formats, text for others
    if (request.format === "pdf" || request.format === "docx") {
      return resp.blob();
    }
    return resp.text();
  },

  // Export batch result as JSON, Markdown, PDF, or Word
  exportBatchResult: async (request: ExportBatchResultRequest): Promise<Blob | string> => {
    const resp = await fetch(`${API_URL}/api-tester/export/batch-result`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    if (request.format === "pdf" || request.format === "docx") {
      return resp.blob();
    }
    return resp.text();
  },

  // Export JWT analysis result as JSON, Markdown, PDF, or Word
  exportJWTResult: async (request: ExportJWTResultRequest): Promise<Blob | string> => {
    const resp = await fetch(`${API_URL}/api-tester/export/jwt-result`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    if (request.format === "pdf" || request.format === "docx") {
      return resp.blob();
    }
    return resp.text();
  },

  // Export AI Auto-Test result as JSON, Markdown, PDF, or Word
  exportAutoTestResult: async (request: ExportAutoTestResultRequest): Promise<Blob | string> => {
    const resp = await fetch(`${API_URL}/api-tester/export/auto-test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    if (request.format === "pdf" || request.format === "docx") {
      return resp.blob();
    }
    return resp.text();
  },

  // Export WebSocket test result as JSON, Markdown, PDF, or Word
  exportWebSocketResult: async (request: ExportWebSocketResultRequest): Promise<Blob | string> => {
    const resp = await fetch(`${API_URL}/api-tester/export/websocket`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    if (request.format === "pdf" || request.format === "docx") {
      return resp.blob();
    }
    return resp.text();
  },

  // Chat with AI about API security test results
  chatAboutTests: async (request: APITesterChatRequest): Promise<APITesterChatResponse> => {
    const resp = await fetch(`${API_URL}/api-tester/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // AI Auto-Test - Automated security testing for IPs, URLs, domains
  aiAutoTest: async (request: AIAutoTestRequest): Promise<AIAutoTestResult> => {
    const resp = await fetch(`${API_URL}/api-tester/auto-test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },
};
