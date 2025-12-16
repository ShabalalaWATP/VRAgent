const API_URL = import.meta.env.VITE_API_URL || "/api";
const ACCESS_TOKEN_KEY = "vragent_access_token";
const REFRESH_TOKEN_KEY = "vragent_refresh_token";

// Track if we're currently refreshing to prevent multiple refresh attempts
let isRefreshing = false;
let refreshPromise: Promise<boolean> | null = null;

// Get auth headers
function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem(ACCESS_TOKEN_KEY);
  const headers: HeadersInit = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

// Try to refresh the access token
async function tryRefreshToken(): Promise<boolean> {
  const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);
  if (!refreshToken) return false;

  try {
    const resp = await fetch(`${API_URL}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (resp.ok) {
      const tokens = await resp.json();
      localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access_token);
      localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh_token);
      console.log("[API] Token refreshed successfully");
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// Synchronized token refresh to prevent race conditions
async function refreshTokenIfNeeded(): Promise<boolean> {
  if (isRefreshing) {
    // Wait for the existing refresh to complete
    return refreshPromise || Promise.resolve(false);
  }

  isRefreshing = true;
  refreshPromise = tryRefreshToken().finally(() => {
    isRefreshing = false;
    refreshPromise = null;
  });

  return refreshPromise;
}

async function request<T>(path: string, options?: RequestInit, retryOnAuth = true): Promise<T> {
  const headers = new Headers(getAuthHeaders());
  
  // Merge any additional headers from options
  if (options?.headers) {
    const optHeaders = new Headers(options.headers);
    optHeaders.forEach((value, key) => {
      headers.set(key, value);
    });
  }

  const resp = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });
  
  // Handle 401 - try to refresh token first
  if (resp.status === 401 && retryOnAuth) {
    console.log("[API] Got 401, attempting token refresh...");
    const refreshed = await refreshTokenIfNeeded();
    
    if (refreshed) {
      // Retry the request with the new token
      return request<T>(path, options, false);
    }
    
    // Refresh failed - clear tokens and redirect
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    if (!window.location.pathname.includes("/login")) {
      window.location.href = "/login";
    }
    throw new Error("Unauthorized");
  }
  
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(text || resp.statusText);
  }
  return (await resp.json()) as T;
}

export async function uploadZip(projectId: number, file: File, retryOnAuth = true): Promise<any> {
  const form = new FormData();
  form.append("file", file);
  const token = localStorage.getItem(ACCESS_TOKEN_KEY);
  const headers: HeadersInit = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const resp = await fetch(`${API_URL}/projects/${projectId}/upload`, {
    method: "POST",
    headers,
    body: form
  });
  if (resp.status === 401 && retryOnAuth) {
    const refreshed = await refreshTokenIfNeeded();
    if (refreshed) {
      return uploadZip(projectId, file, false);
    }
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }
  if (!resp.ok) {
    throw new Error(await resp.text());
  }
  return resp.json();
}

export async function cloneRepository(
  projectId: number, 
  repoUrl: string, 
  branch?: string,
  retryOnAuth = true
): Promise<CloneResponse> {
  const token = localStorage.getItem(ACCESS_TOKEN_KEY);
  const headers: HeadersInit = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const resp = await fetch(`${API_URL}/projects/${projectId}/clone`, {
    method: "POST",
    headers,
    body: JSON.stringify({ repo_url: repoUrl, branch })
  });
  if (resp.status === 401 && retryOnAuth) {
    const refreshed = await refreshTokenIfNeeded();
    if (refreshed) {
      return cloneRepository(projectId, repoUrl, branch, false);
    }
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }
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
  triggerScan: (projectId: number, options?: { includeAgentic?: boolean }) =>
    request<ScanRun>(`/projects/${projectId}/scan`, { 
      method: "POST",
      body: JSON.stringify({ include_agentic: options?.includeAgentic ?? false })
    }),
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
  getCodebaseDiagram: (reportId: number) =>
    request<CodebaseDiagram>(`/reports/${reportId}/codebase/diagram`),
  getFileContent: (reportId: number, filePath: string) =>
    request<FileContent>(`/reports/${reportId}/codebase/file?file_path=${encodeURIComponent(filePath)}`),
  getDependencies: (reportId: number) =>
    request<DependencyGraph>(`/reports/${reportId}/dependencies`),
  getVulnerabilities: (reportId: number) =>
    request<VulnerabilitySummary>(`/reports/${reportId}/vulnerabilities`),
  getScanDiff: (reportId: number, compareReportId: number) =>
    request<ScanDiff>(`/reports/${reportId}/diff/${compareReportId}`),
  getFileTrends: (reportId: number, filePath: string) =>
    request<FileTrends>(`/reports/${reportId}/file-trends/${encodeURIComponent(filePath)}`),
  getTodos: (reportId: number) =>
    request<TodoScanResult>(`/reports/${reportId}/todos`),
  getSecrets: (reportId: number) =>
    request<SecretsScanResult>(`/reports/${reportId}/secrets`),
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
    scan_stats?: any;
    [key: string]: any;
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
    source?: string;  // Source of the finding (e.g., "agentic_ai")
    filtered_out?: boolean;  // Whether this finding was filtered by AI Analysis
    false_positive_score?: number;  // FP score from AI Analysis
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
  poc_scripts?: Record<string, string>;  // Language -> script content
  attack_complexity?: string;  // Low, Medium, High
  exploit_maturity?: string;  // Proof of Concept, Functional, High
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

// AI-generated Mermaid architecture diagram
export type CodebaseDiagram = {
  report_id: number;
  diagram: string;
  diagram_type: string;
  cached: boolean;
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

// CVE/CWE vulnerability summary types
export type CVEEntry = {
  cve_id: string;
  title: string;
  severity: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  affected_packages: string[];
  epss_score: number | null;
  cisa_kev: boolean;
  fix_available: boolean;
  published_date: string | null;
  description: string | null;
  references: string[];
};

export type CWEEntry = {
  cwe_id: string;
  name: string;
  count: number;
  severity_breakdown: Record<string, number>;
  findings?: Array<{
    id: number;
    file_path: string;
    line: number;
    severity: string;
    summary: string;
  }>;
  mitre_url: string;
};

export type VulnerabilitySummary = {
  report_id: number;
  cves: {
    items: CVEEntry[];
    total: number;
    by_severity: Record<string, number>;
    critical_count: number;
    high_count: number;
  };
  cwes: {
    items: CWEEntry[];
    total: number;
    unique_cwes: number;
    total_findings_with_cwe: number;
  };
  summary: {
    total_cves: number;
    total_cwes: number;
    total_findings: number;
    findings_by_severity: Record<string, number>;
    most_common_cwe: string | null;
    highest_cvss: number | null;
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

// Secrets/Sensitive Data Scanner types (credentials + PII)
export type SecretType = 
  // Credentials & API Keys
  | "email" | "api_key" | "password" | "token" | "aws_key" | "aws_secret" 
  | "private_key" | "github_token" | "jwt" | "url_with_creds" | "connection_string" 
  | "slack_webhook" | "stripe_key" | "google_api" | "openai_key" | "anthropic_key" 
  | "generic_secret" | "db_password" | "db_user"
  // PII - Personally Identifiable Information
  | "phone" | "phone_intl" | "ssn" | "credit_card" | "ip_address" 
  | "username" | "user_id" | "hardcoded_name" | "address";

export type SecretItem = {
  type: SecretType;
  file_path: string;
  line: number;
  value: string;        // Full unmasked value for security audit
  masked_value: string; // Same as value (no masking)
  full_line: string;
  severity: "critical" | "high" | "medium" | "low";
  // AI validation fields (when use_ai=true)
  ai_validated?: boolean;
  ai_is_real?: boolean;
  ai_confidence?: number;
  ai_reason?: string;
  ai_risk_level?: "critical" | "high" | "medium" | "low" | "none";
};

export type SecretsScanResult = {
  total: number;
  summary: Record<string, number>;
  by_file: Record<string, SecretItem[]>;
  by_type: Record<string, SecretItem[]>;
  items: SecretItem[];
  // AI validation metadata
  ai_validated?: boolean;
  ai_filtered_count?: number;
  ai_error?: string | null;
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
  // New agentic corroboration fields
  agentic_corroborated?: number;
  filtered_count?: number;
  filtered_findings?: Array<{
    finding_id: number;
    summary: string;
    type: string;
    severity: string;
    fp_score: number;
    reason?: string;
    file_path?: string;
  }>;
  agentic_findings_count?: number;
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
  maxPackets: number = 100000,
  saveReport: boolean = true,
  projectId?: number
): Promise<MultiPcapAnalysisResponse> {
  const form = new FormData();
  files.forEach((file) => form.append("files", file));

  const params = new URLSearchParams({
    include_ai: String(includeAi),
    max_packets: String(maxPackets),
    save_report: String(saveReport),
  });
  if (projectId !== undefined) params.append("project_id", String(projectId));

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

// ============================================================================
// Finding Notes Types
// ============================================================================

export type NoteType = "comment" | "remediation" | "false_positive" | "accepted_risk" | "in_progress";

export type FindingNote = {
  id: number;
  finding_id: number;
  user_id?: number;
  content: string;
  note_type: NoteType;
  created_at: string;
  updated_at: string;
  extra_data?: Record<string, any>;
};

export type FindingNoteCreate = {
  content: string;
  note_type?: NoteType;
  extra_data?: Record<string, any>;
};

export type FindingNoteUpdate = {
  content?: string;
  note_type?: NoteType;
  extra_data?: Record<string, any>;
};

export type FindingWithNotes = {
  id: number;
  project_id: number;
  type: string;
  severity: string;
  file_path?: string;
  start_line?: number;
  end_line?: number;
  summary: string;
  details?: Record<string, any>;
  notes_count: number;
  notes: FindingNote[];
};

export type ProjectNotesSummary = {
  total_notes: number;
  by_type: Record<string, number>;
  recent_notes: FindingNote[];
};

// ============================================================================
// Project Notes Types (general notes not tied to findings)
// ============================================================================

export type ProjectNoteType = "general" | "todo" | "important" | "reference";

export type ProjectNote = {
  id: number;
  project_id: number;
  user_id?: number;
  title?: string;
  content: string;
  note_type: ProjectNoteType;
  created_at: string;
  updated_at: string;
  extra_data?: Record<string, any>;
};

export type ProjectNoteCreate = {
  title?: string;
  content: string;
  note_type?: ProjectNoteType;
  extra_data?: Record<string, any>;
};

export type ProjectNoteUpdate = {
  title?: string;
  content?: string;
  note_type?: ProjectNoteType;
  extra_data?: Record<string, any>;
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
  project_id?: number;
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

  getNetworkReports: async (analysisType?: string, projectId?: number): Promise<SavedNetworkReport[]> => {
    const params = new URLSearchParams();
    if (analysisType) params.append("analysis_type", analysisType);
    if (projectId !== undefined) params.append("project_id", String(projectId));
    const queryString = params.toString() ? `?${params.toString()}` : "";
    const resp = await fetch(`${API_URL}/network/reports${queryString}`);
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

  // ============================================================================
  // Finding Notes Endpoints
  // ============================================================================

  getFindingNotes: async (findingId: number, noteType?: NoteType): Promise<FindingNote[]> => {
    const params = new URLSearchParams();
    if (noteType) params.append("note_type", noteType);
    const queryString = params.toString() ? `?${params.toString()}` : "";
    const resp = await fetch(`${API_URL}/findings/${findingId}/notes${queryString}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  createFindingNote: async (findingId: number, note: FindingNoteCreate): Promise<FindingNote> => {
    const resp = await fetch(`${API_URL}/findings/${findingId}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(note),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  updateFindingNote: async (noteId: number, note: FindingNoteUpdate): Promise<FindingNote> => {
    const resp = await fetch(`${API_URL}/findings/notes/${noteId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(note),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  deleteFindingNote: async (noteId: number): Promise<void> => {
    const resp = await fetch(`${API_URL}/findings/notes/${noteId}`, { method: "DELETE" });
    if (!resp.ok) throw new Error(await resp.text());
  },

  getProjectNotesSummary: async (projectId: number): Promise<ProjectNotesSummary> => {
    const resp = await fetch(`${API_URL}/findings/project/${projectId}/notes-summary`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  getProjectFindingsWithNotes: async (
    projectId: number,
    hasNotes?: boolean,
    noteType?: NoteType
  ): Promise<FindingWithNotes[]> => {
    const params = new URLSearchParams();
    if (hasNotes !== undefined) params.append("has_notes", String(hasNotes));
    if (noteType) params.append("note_type", noteType);
    const queryString = params.toString() ? `?${params.toString()}` : "";
    const resp = await fetch(`${API_URL}/findings/project/${projectId}/findings-with-notes${queryString}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ============================================================================
  // Project Notes API (general notes not tied to findings)
  // ============================================================================

  getProjectGeneralNotes: async (projectId: number, noteType?: ProjectNoteType): Promise<ProjectNote[]> => {
    const params = noteType ? `?note_type=${noteType}` : "";
    const resp = await fetch(`${API_URL}/findings/project/${projectId}/general-notes${params}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  createProjectNote: async (projectId: number, note: ProjectNoteCreate): Promise<ProjectNote> => {
    const resp = await fetch(`${API_URL}/findings/project/${projectId}/general-notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(note),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  updateProjectNote: async (noteId: number, note: ProjectNoteUpdate): Promise<ProjectNote> => {
    const resp = await fetch(`${API_URL}/findings/project-notes/${noteId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(note),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  deleteProjectNote: async (noteId: number): Promise<void> => {
    const resp = await fetch(`${API_URL}/findings/project-notes/${noteId}`, { method: "DELETE" });
    if (!resp.ok) throw new Error(await resp.text());
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
    project_id?: number;
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
      project_id?: number;
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

  // ============================================================================
  // VulnHuntr API Methods
  // ============================================================================
  
  vulnhuntrGetPatterns: async (): Promise<VulnHuntrPatterns> => {
    const resp = await fetch(`${API_URL}/vulnhuntr/patterns`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  vulnhuntrAnalyze: async (request: VulnHuntrRequest): Promise<VulnHuntrResponse> => {
    const resp = await fetch(`${API_URL}/vulnhuntr/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  vulnhuntrQuickScan: async (code: string, filename: string = "snippet.py", language: string = "python"): Promise<VulnHuntrQuickResponse> => {
    const resp = await fetch(`${API_URL}/vulnhuntr/quick-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, filename, language }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  vulnhuntrGetResults: async (scanId: string): Promise<VulnHuntrResult> => {
    const resp = await fetch(`${API_URL}/vulnhuntr/results/${scanId}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  vulnhuntrDownloadMarkdown: async (scanId: string): Promise<Blob> => {
    const resp = await fetch(`${API_URL}/vulnhuntr/results/${scanId}/markdown`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.blob();
  },
};

// ============================================================================
// VulnHuntr Types
// ============================================================================

export type VulnHuntrSourcePoint = {
  file_path: string;
  line_number: number;
  code_snippet: string;
  source_type: string;
  variable_name: string;
  confidence: number;
};

export type VulnHuntrSinkPoint = {
  file_path: string;
  line_number: number;
  code_snippet: string;
  sink_type: string;
  function_name: string;
  vulnerability_type: string;
  severity: string;
};

export type VulnHuntrCallChainNode = {
  file_path: string;
  line_number: number;
  function_name: string;
  code_snippet: string;
  data_variable: string;
  transformation: string;
};

export type VulnHuntrLlmAnalysis = {
  is_false_positive: boolean;
  confidence: number;
  description: string;
  exploit_scenario: string;
  remediation: string;
  sanitization_bypass?: string;
};

export type VulnHuntrVulnerabilityFlow = {
  id: string;
  source: VulnHuntrSourcePoint;
  sink: VulnHuntrSinkPoint;
  call_chain: VulnHuntrCallChainNode[];
  vulnerability_type: string;
  severity: string;
  confidence: number;
  description: string;
  remediation: string;
  cwe_id: string;
  owasp_category: string;
  llm_analysis?: VulnHuntrLlmAnalysis;
};

export type VulnHuntrRequest = {
  project_path: string;
  file_extensions?: string[];
  max_files?: number;
  deep_analysis?: boolean;
};

export type VulnHuntrResponse = {
  success: boolean;
  scan_id: string;
  total_files_scanned: number;
  sources_found: number;
  sinks_found: number;
  vulnerabilities_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scan_duration_seconds: number;
  vulnerabilities: VulnHuntrVulnerabilityFlow[];
  statistics: Record<string, unknown>;
};

export type VulnHuntrQuickResponse = {
  success: boolean;
  vulnerabilities_count: number;
  sources_found: number;
  sinks_found: number;
  vulnerabilities: VulnHuntrVulnerabilityFlow[];
};

export type VulnHuntrSinkInfo = {
  patterns_count: number;
  vulnerability_type: string;
  cwe: string;
  severity: string;
};

export type VulnHuntrPatterns = {
  sources: Record<string, number>;
  sinks: Record<string, VulnHuntrSinkInfo>;
  vulnerability_types: string[];
};

export type VulnHuntrResult = {
  scan_id: string;
  project_path: string;
  timestamp: string;
  total_files_scanned: number;
  sources_found: number;
  sinks_found: number;
  vulnerabilities: VulnHuntrVulnerabilityFlow[];
  statistics: Record<string, unknown>;
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
  project_id?: number;
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

// ===== Security Fuzzer API =====

export interface FuzzerConfig {
  target_url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  positions: string[];
  payloads: string[][];
  attack_mode: "sniper" | "batteringram" | "pitchfork" | "clusterbomb";
  threads: number;
  delay: number;
  timeout: number;
  follow_redirects: boolean;
  match_codes: number[];
  filter_codes: number[];
  match_regex: string;
  proxy_url?: string;
}

export interface FuzzerResponse {
  id: string;
  payload: string;
  status_code: number;
  response_length: number;
  response_time: number;
  content_type: string;
  headers: Record<string, string>;
  body: string;
  timestamp: string;
  error?: string;
  interesting: boolean;
  flags: string[];
}

export interface FuzzerFinding {
  type: string;
  severity: string;
  description: string;
  payload: string;
  evidence: string[];
  recommendation: string;
  response_id: string;
}

export interface FuzzerStats {
  total_requests: number;
  success_count: number;
  error_count: number;
  interesting_count: number;
  avg_response_time: number;
  start_time?: string;
  end_time?: string;
  requests_per_second: number;
}

export interface FuzzerResult {
  config: FuzzerConfig;
  responses: FuzzerResponse[];
  findings: FuzzerFinding[];
  stats: FuzzerStats;
}

export interface WordlistInfo {
  name: string;
  description: string;
  count: number;
}

export interface Wordlist {
  name: string;
  description: string;
  payloads: string[];
}

export const fuzzer = {
  // Run a complete fuzzing session
  run: async (config: FuzzerConfig): Promise<FuzzerResult> => {
    const resp = await fetch(`${API_URL}/fuzzer/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Stream fuzzing results via Server-Sent Events
  stream: (config: FuzzerConfig, onMessage: (event: any) => void, onError?: (err: any) => void): EventSource | null => {
    // We'll use fetch with streaming instead of EventSource since we need POST
    const controller = new AbortController();
    
    fetch(`${API_URL}/fuzzer/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(await response.text());
        }
        const reader = response.body?.getReader();
        if (!reader) {
          throw new Error("No response body");
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
                onMessage(data);
              } catch (e) {
                console.error("Failed to parse SSE data:", e);
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== "AbortError") {
          onError?.(err);
        }
      });
    
    // Return an object with abort method to cancel the stream
    return { close: () => controller.abort() } as any;
  },

  // Get available wordlists
  getWordlists: async (): Promise<Record<string, WordlistInfo>> => {
    const resp = await fetch(`${API_URL}/fuzzer/wordlists`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get a specific wordlist
  getWordlist: async (id: string): Promise<Wordlist> => {
    const resp = await fetch(`${API_URL}/fuzzer/wordlists/${id}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Export fuzzing results
  exportResults: async (result: FuzzerResult, format: "json" | "markdown"): Promise<{ content: string; filename: string; mime_type: string }> => {
    const resp = await fetch(`${API_URL}/fuzzer/export`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ result, format }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // WebSocket connection for real-time fuzzing
  connectWebSocket: (onMessage: (event: any) => void, onError?: (err: any) => void): WebSocket => {
    const wsUrl = API_URL.replace(/^http/, "ws") + "/fuzzer/ws";
    const ws = new WebSocket(wsUrl);
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };
    
    ws.onerror = (err) => {
      onError?.(err);
    };
    
    return ws;
  },

  // ===== Advanced Fuzzing Features =====

  // Encode payloads using various encoding schemes
  encode: async (
    payloads: string[],
    encodings: string[] = ["url"],
    chain: boolean = false
  ): Promise<{ encoded: Record<string, any>; available_encodings: string[] }> => {
    const resp = await fetch(`${API_URL}/fuzzer/encode`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payloads, encodings, chain }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Generate payloads using various generators
  generate: async (
    generatorType: string,
    params: Record<string, any>
  ): Promise<{ payloads: string[]; count: number; generator_type: string }> => {
    const resp = await fetch(`${API_URL}/fuzzer/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ generator_type: generatorType, params }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Mutate payloads for bypass attempts
  mutate: async (
    payloads: string[],
    mutationTypes: string[] = ["case", "encoding"]
  ): Promise<{ mutations: Record<string, string[]>; total_variants: number }> => {
    const resp = await fetch(`${API_URL}/fuzzer/mutate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payloads, mutation_types: mutationTypes }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Grep/search response content
  grep: async (
    content: string,
    rules: Array<{ name: string; pattern: string; is_regex?: boolean; case_sensitive?: boolean }> = [],
    useCommonRules: boolean = true
  ): Promise<{ matches: any[]; match_count: number; extracted: Record<string, string[]> }> => {
    const resp = await fetch(`${API_URL}/fuzzer/grep`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, rules, use_common_rules: useCommonRules }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Cluster similar responses
  cluster: async (
    responses: FuzzerResponse[],
    similarityThreshold: number = 0.85
  ): Promise<{ clusters: any[]; total_clusters: number; anomalous_responses: string[] }> => {
    const resp = await fetch(`${API_URL}/fuzzer/cluster`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ responses, similarity_threshold: similarityThreshold }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Comprehensive response analysis
  analyze: async (
    responses: FuzzerResponse[],
    options: {
      detectWaf?: boolean;
      detectRateLimit?: boolean;
      discoverParams?: boolean;
      clusterResponses?: boolean;
      extractData?: boolean;
    } = {}
  ): Promise<{
    waf_detection?: { detected: boolean; waf_type: string | null; confidence: number; indicators: string[]; bypass_suggestions: string[] };
    rate_limiting?: { detected: boolean; limit_type: string | null; threshold: number | null; indicators: string[] };
    discovered_parameters?: Array<{ name: string; source: string; param_type: string }>;
    discovered_endpoints?: string[];
    clustering?: { clusters: any[]; total_clusters: number; anomalous_responses: string[] };
    extracted_data?: Record<string, string[]>;
    statistics?: { unique_status_codes: number[]; avg_response_time: number; avg_response_length: number; error_count: number; interesting_count: number };
  }> => {
    const resp = await fetch(`${API_URL}/fuzzer/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        responses,
        detect_waf: options.detectWaf ?? true,
        detect_rate_limit: options.detectRateLimit ?? true,
        discover_params: options.discoverParams ?? true,
        cluster_responses: options.clusterResponses ?? true,
        extract_data: options.extractData ?? true,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get available encoding types
  getEncodings: async (): Promise<{ encodings: Array<{ value: string; name: string }> }> => {
    const resp = await fetch(`${API_URL}/fuzzer/encodings`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get available transformation types
  getTransformations: async (): Promise<{ transformations: Array<{ value: string; name: string }> }> => {
    const resp = await fetch(`${API_URL}/fuzzer/transformations`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get available payload generators
  getGenerators: async (): Promise<{ generators: Array<{ type: string; description: string; params: Record<string, string>; example: Record<string, any> }> }> => {
    const resp = await fetch(`${API_URL}/fuzzer/generators`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ==========================================================================
  // Session Management
  // ==========================================================================

  // Create a new fuzzing session
  createSession: async (data: {
    name: string;
    description?: string;
    target_url: string;
    method?: string;
    config?: Record<string, any>;
    tags?: string[];
    project_id?: number;
  }): Promise<{ id: number; name: string; target_url: string; status: string; created_at: string; message: string }> => {
    const resp = await fetch(`${API_URL}/fuzzer/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // List fuzzing sessions
  listSessions: async (params: {
    page?: number;
    page_size?: number;
    status?: string;
    search?: string;
    project_id?: number;
  } = {}): Promise<{
    sessions: Array<{
      id: number;
      name: string;
      description?: string;
      target_url: string;
      method: string;
      status: string;
      created_at: string;
      updated_at: string;
      started_at?: string;
      finished_at?: string;
      total_requests: number;
      success_count: number;
      error_count: number;
      interesting_count: number;
      avg_response_time?: number;
      tags: string[];
      findings_count: number;
      project_id?: number;
    }>;
    total: number;
    page: number;
    page_size: number;
  }> => {
    const queryParams = new URLSearchParams();
    if (params.page) queryParams.append("page", params.page.toString());
    if (params.page_size) queryParams.append("page_size", params.page_size.toString());
    if (params.status) queryParams.append("status", params.status);
    if (params.search) queryParams.append("search", params.search);
    if (params.project_id !== undefined) queryParams.append("project_id", params.project_id.toString());
    
    const resp = await fetch(`${API_URL}/fuzzer/sessions?${queryParams}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get a specific session
  getSession: async (sessionId: number): Promise<{
    id: number;
    name: string;
    description?: string;
    target_url: string;
    method: string;
    status: string;
    created_at: string;
    updated_at: string;
    started_at?: string;
    finished_at?: string;
    config: Record<string, any>;
    total_requests: number;
    success_count: number;
    error_count: number;
    interesting_count: number;
    avg_response_time?: number;
    results?: any[];
    findings?: any[];
    analysis?: any;
    tags: string[];
  }> => {
    const resp = await fetch(`${API_URL}/fuzzer/sessions/${sessionId}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Update a session
  updateSession: async (sessionId: number, data: {
    name?: string;
    description?: string;
    status?: string;
    results?: any[];
    findings?: any[];
    analysis?: any;
    tags?: string[];
    total_requests?: number;
    success_count?: number;
    error_count?: number;
    interesting_count?: number;
    avg_response_time?: number;
  }): Promise<{ id: number; name: string; status: string; message: string }> => {
    const resp = await fetch(`${API_URL}/fuzzer/sessions/${sessionId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Delete a session
  deleteSession: async (sessionId: number): Promise<{ message: string; id: number }> => {
    const resp = await fetch(`${API_URL}/fuzzer/sessions/${sessionId}`, {
      method: "DELETE",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Duplicate a session
  duplicateSession: async (sessionId: number): Promise<{ id: number; name: string; message: string }> => {
    const resp = await fetch(`${API_URL}/fuzzer/sessions/${sessionId}/duplicate`, {
      method: "POST",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Analyze a saved session
  analyzeSession: async (sessionId: number): Promise<{
    session_id: number;
    analysis: any;
    message: string;
  }> => {
    const resp = await fetch(`${API_URL}/fuzzer/sessions/${sessionId}/auto-analyze`, {
      method: "POST",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ==========================================================================
  // Smart Detection
  // ==========================================================================

  // Detect vulnerabilities in responses
  detectVulnerabilities: async (
    responses: FuzzerResponse[],
    baselineResponse?: FuzzerResponse
  ): Promise<{
    findings: Array<{
      id: string;
      vuln_type: string;
      severity: string;
      confidence: number;
      title: string;
      description: string;
      evidence: string[];
      payload: string;
      response_id: string;
      indicators: string[];
      recommendation: string;
      false_positive_likelihood: string;
    }>;
    total: number;
    by_severity: Record<string, number>;
    by_type: Record<string, number>;
  }> => {
    const resp = await fetch(`${API_URL}/fuzzer/smart-detect/vulnerabilities`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ responses, baseline_response: baselineResponse }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Detect anomalies in responses
  detectAnomalies: async (
    responses: FuzzerResponse[],
    sensitivity: number = 2.0
  ): Promise<{
    anomalies: Array<{
      response_id: string;
      anomaly_type: string;
      score: number;
      baseline_value: any;
      actual_value: any;
      deviation: number;
      description: string;
    }>;
    total: number;
    by_type: Record<string, number>;
    most_anomalous: string[];
  }> => {
    const resp = await fetch(`${API_URL}/fuzzer/smart-detect/anomalies`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ responses, sensitivity }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Perform differential analysis
  differentialAnalysis: async (
    baselineResponse: FuzzerResponse,
    testResponses: FuzzerResponse[]
  ): Promise<{
    results: Array<{
      response_id: string;
      payload: string;
      differences: Array<{ type: string; baseline: any; current: any; difference_percent?: number }>;
      similarity_score: number;
      potentially_interesting: boolean;
    }>;
    total: number;
    interesting_count: number;
    most_different: string[];
  }> => {
    const resp = await fetch(`${API_URL}/fuzzer/smart-detect/differential`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ baseline_response: baselineResponse, test_responses: testResponses }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Categorize responses
  categorizeResponses: async (responses: FuzzerResponse[]): Promise<{
    categories: Record<string, string[]>;
    summary: Record<string, number>;
  }> => {
    const resp = await fetch(`${API_URL}/fuzzer/smart-detect/categorize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ responses }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Comprehensive auto-analysis
  autoAnalyze: async (
    responses: FuzzerResponse[],
    options: {
      detect_vulnerabilities?: boolean;
      detect_anomalies?: boolean;
      categorize?: boolean;
      differential?: boolean;
      baseline_index?: number;
    } = {}
  ): Promise<{
    responses_analyzed: number;
    vulnerabilities?: {
      findings: any[];
      total: number;
      by_severity: Record<string, number>;
    };
    anomalies?: {
      items: any[];
      total: number;
      by_type: Record<string, number>;
    };
    categories?: {
      groups: Record<string, string[]>;
      summary: Record<string, number>;
    };
    differential?: {
      results: any[];
      interesting_count: number;
    };
    summary: {
      risk_score: number;
      risk_level: string;
      findings_count: number;
      anomalies_count: number;
      interesting_count: number;
    };
  }> => {
    const resp = await fetch(`${API_URL}/fuzzer/smart-detect/auto-analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        responses,
        detect_vulnerabilities: options.detect_vulnerabilities ?? true,
        detect_anomalies: options.detect_anomalies ?? true,
        categorize: options.categorize ?? true,
        differential: options.differential ?? false,
        baseline_index: options.baseline_index ?? 0,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },
};

// ============================================================================
// MITM Workbench Types and API
// ============================================================================

export interface MITMProxyConfig {
  proxy_id: string;
  listen_host: string;
  listen_port: number;
  target_host: string;
  target_port: number;
  mode: 'passthrough' | 'intercept' | 'auto_modify';
  tls_enabled: boolean;
}

export interface MITMProxyStats {
  requests: number;
  responses: number;
  bytes_sent: number;
  bytes_received: number;
  errors: number;
  rules_applied: number;
}

export interface MITMProxy {
  id: string;
  listen_host: string;
  listen_port: number;
  target_host: string;
  target_port: number;
  mode: 'passthrough' | 'intercept' | 'auto_modify';
  tls_enabled: boolean;
  running: boolean;
  stats: MITMProxyStats;
}

export interface MITMTrafficRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
}

export interface MITMTrafficResponse {
  status_code: number;
  status_text: string;
  headers: Record<string, string>;
  body: string;
}

export interface MITMTrafficEntry {
  id: string;
  timestamp: string;
  request: MITMTrafficRequest;
  response?: MITMTrafficResponse;
  duration_ms: number;
  modified: boolean;
  rules_applied: string[];
}

export interface MITMRule {
  id: string;
  name: string;
  enabled: boolean;
  match_direction: 'request' | 'response' | 'both';
  match_host?: string;
  match_path?: string;
  match_method?: string;
  match_content_type?: string;
  match_status_code?: number;
  action: 'modify' | 'drop' | 'delay';
  modify_headers?: Record<string, string>;
  remove_headers?: string[];
  body_find_replace?: Record<string, string>;
  delay_ms?: number;
}

export interface MITMPresetRule {
  id: string;
  name: string;
  description?: string;
}

export const mitmClient = {
  // Create a new MITM proxy instance
  createProxy: async (config: MITMProxyConfig): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // List all MITM proxy instances
  listProxies: async (): Promise<MITMProxy[]> => {
    const resp = await fetch(`${API_URL}/mitm/proxies`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get status and stats for a proxy
  getProxyStatus: async (proxyId: string): Promise<MITMProxy> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Start a proxy
  startProxy: async (proxyId: string): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/start`, {
      method: "POST",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Stop a proxy
  stopProxy: async (proxyId: string): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/stop`, {
      method: "POST",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Delete a proxy
  deleteProxy: async (proxyId: string): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}`, {
      method: "DELETE",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Set proxy interception mode
  setProxyMode: async (proxyId: string, mode: string): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/mode?mode=${mode}`, {
      method: "PUT",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get intercepted traffic for a proxy
  getTraffic: async (proxyId: string, limit: number = 100, offset: number = 0): Promise<{ entries: MITMTrafficEntry[] }> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/traffic?limit=${limit}&offset=${offset}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Clear traffic log for a proxy
  clearTraffic: async (proxyId: string): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/traffic`, {
      method: "DELETE",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Add an interception rule to a proxy
  addRule: async (proxyId: string, rule: Partial<MITMRule>): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/rules`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(rule),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get all rules for a proxy
  getRules: async (proxyId: string): Promise<MITMRule[]> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/rules`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Remove a rule from a proxy
  removeRule: async (proxyId: string, ruleId: string): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/rules/${ruleId}`, {
      method: "DELETE",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Enable/disable a rule
  toggleRule: async (proxyId: string, ruleId: string, enabled: boolean): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/rules/${ruleId}/toggle?enabled=${enabled}`, {
      method: "PUT",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get available preset rules
  getPresets: async (): Promise<MITMPresetRule[]> => {
    const resp = await fetch(`${API_URL}/mitm/presets`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Apply a preset rule to a proxy
  applyPreset: async (proxyId: string, presetId: string): Promise<any> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/presets/${presetId}`, {
      method: "POST",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // AI-powered traffic analysis
  analyzeTraffic: async (proxyId: string): Promise<MITMAnalysisResult> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/analyze`, {
      method: "POST",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Export analysis report
  exportReport: async (proxyId: string, format: 'markdown' | 'pdf' | 'docx'): Promise<Blob> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/export/${format}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.blob();
  },

  // Get guided setup information
  getGuidedSetup: async (): Promise<MITMGuidedSetup> => {
    const resp = await fetch(`${API_URL}/mitm/guided-setup`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },
};

// MITM Analysis Types
export interface MITMAnalysisFinding {
  severity: string;
  category: string;
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
}

export interface MITMAnalysisResult {
  summary: string;
  risk_score: number;
  risk_level: string;
  findings: MITMAnalysisFinding[];
  recommendations: string[];
  ai_analysis?: string;
  traffic_analyzed: number;
  rules_active: number;
}

export interface MITMGuidedStep {
  step: number;
  title: string;
  description: string;
  tips?: string[];
  icon?: string;
  fields?: Record<string, string>;
  modes?: Array<{ name: string; description: string; use_case: string }>;
  examples?: Array<{ type: string; instructions: string }>;
  presets?: Array<{ name: string; description: string }>;
  checks?: string[];
  formats?: Array<{ format: string; description: string }>;
}

export interface MITMGuidedSetup {
  title: string;
  description: string;
  difficulty: string;
  estimated_time: string;
  steps: MITMGuidedStep[];
  common_use_cases: Array<{
    title: string;
    description: string;
    steps: string[];
  }>;
  troubleshooting: Array<{
    issue: string;
    solutions: string[];
  }>;
}

// Test Scenarios for Beginners
export interface MITMTestScenario {
  id: string;
  name: string;
  description: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  category: string;
  icon: string;
  estimated_time: string;
  rules: Partial<MITMRule>[];
  what_to_look_for: string[];
  learning_points: string[];
}

export interface MITMScenarioResult {
  message: string;
  scenario: MITMTestScenario;
  rules_added: number;
  mode: string;
  next_steps: string[];
}

// Health Check Types
export interface MITMHealthCheck {
  name: string;
  status: 'pass' | 'fail' | 'info' | 'warning';
  message: string;
}

export interface MITMProxyHealth {
  proxy_id: string;
  status: 'healthy' | 'warning' | 'error';
  checks: MITMHealthCheck[];
  recommendations: string[];
}

// Add new methods to mitmClient
Object.assign(mitmClient, {
  // Get all test scenarios
  getTestScenarios: async (): Promise<MITMTestScenario[]> => {
    const resp = await fetch(`${API_URL}/mitm/test-scenarios`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get a specific test scenario
  getTestScenario: async (scenarioId: string): Promise<MITMTestScenario> => {
    const resp = await fetch(`${API_URL}/mitm/test-scenarios/${scenarioId}`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Run a test scenario on a proxy
  runTestScenario: async (proxyId: string, scenarioId: string): Promise<MITMScenarioResult> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/run-scenario/${scenarioId}`, {
      method: "POST",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Check proxy health
  checkProxyHealth: async (proxyId: string): Promise<MITMProxyHealth> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/health`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },
});

// ============================================================================
// Natural Language Rule Creation Types
// ============================================================================

export interface NaturalLanguageRuleRequest {
  description: string;
  proxy_id?: string;  // If provided, auto-apply to proxy
}

export interface NaturalLanguageRuleResponse {
  success: boolean;
  rule?: Partial<MITMRule>;
  interpretation: string;
  applied: boolean;
  error?: string;
}

// ============================================================================
// AI Suggestions Types
// ============================================================================

export interface AISuggestion {
  id: string;
  title: string;
  description: string;
  category: 'security' | 'performance' | 'debug' | 'learning';
  priority: 'high' | 'medium' | 'low';
  rule?: Partial<MITMRule>;
  natural_language: string;
}

export interface AISuggestionsResponse {
  proxy_id: string;
  suggestions: AISuggestion[];
  traffic_summary: {
    total_requests: number;
    unique_hosts: string[];
    unique_paths: string[];
    auth_detected: boolean;
    json_apis: boolean;
    has_cookies: boolean;
  };
  generated_at: string;
}

// Add Natural Language and AI Suggestions methods
Object.assign(mitmClient, {
  // Create a rule from natural language description
  createRuleFromNaturalLanguage: async (
    description: string,
    proxyId?: string
  ): Promise<NaturalLanguageRuleResponse> => {
    const resp = await fetch(`${API_URL}/mitm/ai/create-rule`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description, proxy_id: proxyId }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // Get AI-generated suggestions based on traffic patterns
  getAISuggestions: async (proxyId: string): Promise<AISuggestionsResponse> => {
    const resp = await fetch(`${API_URL}/mitm/proxies/${proxyId}/ai-suggestions`);
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },
});

// TypeScript interface extension for mitmClient
declare module './client' {
  interface MITMClientExtended {
    createRuleFromNaturalLanguage: (
      description: string,
      proxyId?: string
    ) => Promise<NaturalLanguageRuleResponse>;
    getAISuggestions: (proxyId: string) => Promise<AISuggestionsResponse>;
    getTestScenarios: () => Promise<MITMTestScenario[]>;
    getTestScenario: (scenarioId: string) => Promise<MITMTestScenario>;
    runTestScenario: (proxyId: string, scenarioId: string) => Promise<MITMScenarioResult>;
    checkProxyHealth: (proxyId: string) => Promise<MITMProxyHealth>;
  }
}

// ============================================================================
// Agentic AI Scan Types
// ============================================================================

export type AgenticScanPhase = 
  | "initializing"
  | "chunking"
  | "entry_point_detection"
  | "flow_tracing"
  | "vulnerability_analysis"
  | "report_generation"
  | "complete"
  | "error";

export interface AgenticScanRequest {
  project_id: number;
  project_path: string;
  file_extensions?: string[];
}

export interface AgenticScanStartResponse {
  scan_id: string;
  status: string;
  message: string;
}

export interface AgenticScanProgress {
  scan_id: string;
  project_id: number;
  phase: AgenticScanPhase;
  phase_progress: number;
  total_chunks: number;
  analyzed_chunks: number;
  entry_points_found: number;
  flows_traced: number;
  vulnerabilities_found: number;
  current_file?: string;
  message: string;
  started_at: string;
  estimated_completion?: string;
  completed_at?: string;
  status?: string;
}

export interface AgenticFlowStep {
  file_path: string;
  line_number: number;
  code_snippet: string;
  variable_name: string;
  transformation: string;
}

export interface AgenticEntryPoint {
  file_path: string;
  line_number: number;
  entry_type: string;
  variable_name: string;
  code_snippet: string;
}

export interface AgenticSink {
  file_path: string;
  line_number: number;
  sink_type: string;
  function_name: string;
  code_snippet: string;
}

export interface AgenticFlow {
  entry_point: AgenticEntryPoint;
  sink: AgenticSink;
  steps: AgenticFlowStep[];
}

export interface AgenticVulnerability {
  id: string;
  vulnerability_type: string;
  severity: string;
  cwe_id: string;
  owasp_category: string;
  title: string;
  description: string;
  llm_analysis: string;
  exploit_scenario: string;
  remediation: string;
  code_fix?: string;
  confidence: number;
  false_positive_likelihood: number;
  flow: AgenticFlow;
}

export interface AgenticScanStatistics {
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  by_type: Record<string, number>;
  by_file: Record<string, number>;
  entry_point_types: Record<string, number>;
  sink_types: Record<string, number>;
  avg_confidence: number;
}

export interface AgenticScanResult {
  scan_id: string;
  project_id: number;
  project_path: string;
  status: string;
  phase: AgenticScanPhase;
  total_chunks: number;
  analyzed_chunks: number;
  entry_points_count: number;
  sinks_count: number;
  flows_traced: number;
  vulnerabilities: AgenticVulnerability[];
  statistics: AgenticScanStatistics;
  started_at: string;
  completed_at?: string;
  scan_duration_seconds: number;
  error_message?: string;
}

export interface AgenticVulnerabilitySummary {
  id: string;
  type: string;
  severity: string;
  cwe_id: string;
  title: string;
  file: string;
  line: number;
  confidence: number;
}

export interface AgenticVulnerabilitiesResponse {
  scan_id: string;
  total: number;
  filtered: number;
  vulnerabilities: AgenticVulnerabilitySummary[];
}

// ============================================================================
// Agentic AI Scan Client
// ============================================================================

export const agenticScanClient = {
  /**
   * Start an agentic AI scan asynchronously.
   * Use getStatus to poll for progress or use the WebSocket for real-time updates.
   */
  startScan: async (request: AgenticScanRequest): Promise<AgenticScanStartResponse> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    const resp = await fetch(`${API_URL}/agentic-scan/start`, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Start an agentic AI scan and wait for completion.
   * Good for smaller projects or when immediate results are needed.
   */
  startScanSync: async (request: AgenticScanRequest): Promise<AgenticScanResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    const resp = await fetch(`${API_URL}/agentic-scan/start-sync`, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Get the current status/progress of a scan.
   */
  getStatus: async (scanId: string): Promise<AgenticScanProgress> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    const resp = await fetch(`${API_URL}/agentic-scan/status/${scanId}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Get the full result of a completed scan.
   */
  getResult: async (scanId: string): Promise<AgenticScanResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    const resp = await fetch(`${API_URL}/agentic-scan/result/${scanId}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Get just the vulnerabilities from a scan, optionally filtered by severity.
   */
  getVulnerabilities: async (scanId: string, severity?: string): Promise<AgenticVulnerabilitiesResponse> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    const params = severity ? `?severity=${severity}` : "";
    const resp = await fetch(`${API_URL}/agentic-scan/vulnerabilities/${scanId}${params}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Get statistics from a completed scan.
   */
  getStatistics: async (scanId: string): Promise<{
    scan_id: string;
    project_id: number;
    duration_seconds: number;
    total_chunks: number;
    entry_points: number;
    sinks: number;
    flows_traced: number;
    vulnerabilities: number;
    statistics: AgenticScanStatistics;
  }> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    const resp = await fetch(`${API_URL}/agentic-scan/statistics/${scanId}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * List all currently active scans.
   */
  listActiveScans: async (): Promise<{ active_scans: AgenticScanProgress[]; count: number }> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    const resp = await fetch(`${API_URL}/agentic-scan/active`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Cancel an active scan.
   */
  cancelScan: async (scanId: string): Promise<{ message: string; scan_id: string }> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    const resp = await fetch(`${API_URL}/agentic-scan/cancel/${scanId}`, {
      method: "DELETE",
      headers,
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Connect to WebSocket for real-time progress updates.
   * Returns a function to close the connection.
   */
  connectProgressWebSocket: (
    scanId: string,
    onProgress: (progress: AgenticScanProgress) => void,
    onError: (error: string) => void,
    onComplete: () => void
  ): (() => void) => {
    const wsUrl = `${API_URL.replace(/^http/, 'ws')}/agentic-scan/ws/${scanId}`;
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.phase === "complete" || data.phase === "error") {
          onComplete();
        }
        onProgress(data);
      } catch (e) {
        // Ignore parse errors for pong messages
        if (event.data !== "pong") {
          console.error("WebSocket parse error:", e);
        }
      }
    };

    ws.onerror = (event) => {
      onError("WebSocket connection error");
    };

    ws.onclose = () => {
      onComplete();
    };

    // Send periodic pings to keep connection alive
    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send("ping");
      }
    }, 30000);

    // Return cleanup function
    return () => {
      clearInterval(pingInterval);
      ws.close();
    };
  },

  /**
   * Poll for scan progress (alternative to WebSocket).
   * Returns a function to stop polling.
   */
  pollProgress: (
    scanId: string,
    onProgress: (progress: AgenticScanProgress) => void,
    onComplete: (result: AgenticScanResult) => void,
    onError: (error: string) => void,
    intervalMs: number = 2000
  ): (() => void) => {
    let active = true;
    
    const poll = async () => {
      while (active) {
        try {
          const progress = await agenticScanClient.getStatus(scanId);
          onProgress(progress);
          
          if (progress.phase === "complete" || progress.status === "complete") {
            const result = await agenticScanClient.getResult(scanId);
            onComplete(result);
            break;
          }
          
          if (progress.phase === "error") {
            onError(progress.message || "Scan failed");
            break;
          }
          
          await new Promise(resolve => setTimeout(resolve, intervalMs));
        } catch (e: any) {
          onError(e.message || "Polling error");
          break;
        }
      }
    };
    
    poll();
    
    return () => { active = false; };
  },
};


// ============================================================================
// REVERSE ENGINEERING TYPES AND FUNCTIONS
// ============================================================================

// Binary Analysis Types
export type BinaryStringResult = {
  value: string;
  offset: number;
  encoding: string;
  category?: string;
};

export type ImportedFunctionResult = {
  name: string;
  library: string;
  ordinal?: number;
  is_suspicious: boolean;
  reason?: string;
};

// PE Rich Header types
export type RichHeaderEntry = {
  product_id: number;
  build_id: number;
  count: number;
  product_name?: string;
  vs_version?: string;
};

export type RichHeader = {
  entries: RichHeaderEntry[];
  rich_hash: string;
  checksum: number;
  raw_data: string;
  clear_data: string;
};

// Hex Viewer types
export type HexViewRow = {
  offset: number;
  offset_hex: string;
  hex: string;
  ascii: string;
  bytes: number[];
};

export type HexViewResult = {
  offset: number;
  length: number;
  total_size: number;
  hex_data: string;
  ascii_preview: string;
  rows: HexViewRow[];
};

export type HexSearchResult = {
  offset: number;
  offset_hex: string;
  match_length: number;
  context_hex: string;
  context_ascii: string;
  match_offset_in_context: number;
};

export type HexSearchResponse = {
  query: string;
  search_type: string;
  pattern_hex: string;
  total_matches: number;
  results: HexSearchResult[];
};

export type BinaryMetadataResult = {
  file_type: string;
  architecture: string;
  file_size: number;
  entry_point?: number;
  is_packed: boolean;
  packer_name?: string;
  compile_time?: string;
  sections: Array<{
    name: string;
    virtual_address?: number;
    address?: number;
    virtual_size?: number;
    raw_size?: number;
    size?: number;
    entropy?: number;
    type?: string;
    flags?: string;
  }>;
  headers: Record<string, any>;
  // PE-specific fields
  rich_header?: RichHeader;
  imphash?: string;
  // ELF-specific fields
  interpreter?: string;
  linked_libraries?: string[];
  relro?: string;
  stack_canary?: boolean;
  nx_enabled?: boolean;
  pie_enabled?: boolean;
};

// ELF Symbol
export type ELFSymbolResult = {
  name: string;
  address: number;
  size: number;
  symbol_type: string;
  binding: string;
  section: string;
  is_imported: boolean;
  is_exported: boolean;
  is_suspicious: boolean;
  reason?: string;
};

// Disassembly Types
export type DisassemblyInstruction = {
  address: number;
  mnemonic: string;
  op_str: string;
  bytes_hex: string;
  size: number;
  is_call: boolean;
  is_jump: boolean;
  is_suspicious: boolean;
  comment?: string;
};

export type DisassemblyFunction = {
  name: string;
  address: number;
  size: number;
  instructions: DisassemblyInstruction[];
  calls: string[];
  suspicious_patterns: string[];
};

export type DisassemblyResult = {
  entry_point_disasm: DisassemblyInstruction[];
  functions: DisassemblyFunction[];
  suspicious_instructions: Array<{ function?: string; pattern?: string; note?: string }>;
  architecture: string;
  mode: string;
};

export type SecretResult = {
  type: string;
  value: string;
  masked_value: string;
  severity: string;
  context?: string;
  offset?: number;
};

export type SuspiciousIndicator = {
  category: string;
  severity: string;
  description: string;
  details?: any;
};

export type BinaryAnalysisResult = {
  filename: string;
  metadata: BinaryMetadataResult;
  strings_count: number;
  strings_sample: BinaryStringResult[];
  imports: ImportedFunctionResult[];
  exports: string[];
  secrets: SecretResult[];
  suspicious_indicators: SuspiciousIndicator[];
  // Enhanced ELF fields
  symbols?: ELFSymbolResult[];
  disassembly?: DisassemblyResult;
  dwarf_info?: {
    has_debug_info: boolean;
    compilation_units?: Array<{
      name: string;
      producer?: string;
      language?: number;
    }>;
    source_files?: string[];
    error?: string;
  };
  ai_analysis?: string;
  error?: string;
};

// APK Analysis Types
export type ApkPermissionResult = {
  name: string;
  is_dangerous: boolean;
  description?: string;
};

export type ApkComponentResult = {
  name: string;
  component_type: string;
  is_exported: boolean;
  intent_filters: string[];
};

export type ApkSecurityIssue = {
  category: string;
  severity: string;
  description: string;
  details?: any;
  recommendation?: string;
};

export type ApkCertificate = {
  subject: string;
  issuer: string;
  serial_number: string;
  fingerprint_sha256: string;
  fingerprint_sha1: string;
  fingerprint_md5: string;
  valid_from: string;
  valid_until: string;
  is_debug_cert: boolean;
  is_expired: boolean;
  is_self_signed: boolean;
  signature_version: string;
  public_key_algorithm?: string;
  public_key_bits?: number;
};

// DEX Analysis Types
export type DexSuspiciousMethod = {
  class: string;
  method: string;
  category: string;
  pattern: string;
};

export type DexTrackerInfo = {
  name: string;
  package: string;
  class: string;
};

export type DexClassInfo = {
  name: string;
  superclass?: string;
  interfaces: string[];
  methods_count: number;
};

export type DexAnalysis = {
  total_classes: number;
  total_methods: number;
  suspicious_classes: any[];
  suspicious_methods: DexSuspiciousMethod[];
  detected_trackers: DexTrackerInfo[];
  class_hierarchy: DexClassInfo[];
  reflection_usage: DexSuspiciousMethod[];
  crypto_usage: DexSuspiciousMethod[];
  native_calls: DexSuspiciousMethod[];
  dynamic_loading: DexSuspiciousMethod[];
  anti_analysis_detected: DexSuspiciousMethod[];
};

// Resource Analysis Types
export type ResourceSecret = {
  type: string;
  source: string;
  value_preview: string;
  severity: string;
};

export type ResourceAnalysis = {
  string_resources: Record<string, string>;
  string_count: number;
  asset_files: string[];
  raw_resources: string[];
  drawable_count: number;
  layout_count: number;
  potential_secrets: ResourceSecret[];
  interesting_assets: any[];
  database_files: string[];
  config_files: string[];
};

// Intent Filter Analysis Types
export type DeepLinkInfo = {
  url: string;
  component: string;
  type: string;
};

export type BrowsableActivity = {
  name: string;
  schemes: string[];
  hosts: string[];
};

export type ExportedComponent = {
  name: string;
  type: string;
  exported: boolean;
  has_intent_filter: boolean;
  actions: string[];
};

export type AttackSurfaceSummary = {
  total_deep_links: number;
  browsable_activities_count: number;
  custom_uri_schemes: string[];
  exported_activities: number;
  exported_services: number;
  exported_receivers: number;
  exported_providers: number;
};

export type IntentFilterAnalysis = {
  deep_links: DeepLinkInfo[];
  browsable_activities: BrowsableActivity[];
  exported_components: ExportedComponent[];
  uri_schemes: string[];
  data_handlers: any[];
  implicit_intents: any[];
  attack_surface_summary: AttackSurfaceSummary;
};

// Network Security Config Types
export type CertificatePin = {
  domains: string[];
  expiration?: string;
  pins: { digest: string; value: string }[];
};

export type DomainConfig = {
  domains: { name: string; include_subdomains: boolean }[];
  cleartext_permitted: boolean;
  has_pins: boolean;
};

export type NetworkSecurityConfig = {
  has_config: boolean;
  cleartext_permitted: boolean;
  cleartext_domains: string[];
  trust_anchors: { source: string; scope: string }[];
  certificate_pins: CertificatePin[];
  domain_configs: DomainConfig[];
  security_issues: string[];
  config_xml?: string;
};

// Smali/Bytecode Decompilation Types
export type SmaliMethodCode = {
  class_name: string;
  method_name: string;
  method_signature: string;
  access_flags: string;
  return_type: string;
  parameters: string[];
  registers_count: number;
  instructions: string[];
  instruction_count: number;
  has_try_catch: boolean;
  is_native: boolean;
  is_abstract: boolean;
};

export type SmaliInterestingMethod = {
  class: string;
  method: string;
  pattern: string;
  preview: string[];
};

export type SmaliSearchIndex = {
  class: string;
  method: string;
  signature: string;
  preview: string;
};

export type SmaliStatistics = {
  total_methods_analyzed: number;
  total_instructions: number;
  native_methods: number;
  abstract_methods: number;
  classes_analyzed: number;
};

export type SmaliAnalysis = {
  decompiled_methods: SmaliMethodCode[];
  class_smali: Record<string, string>;
  statistics: SmaliStatistics;
  interesting_methods: SmaliInterestingMethod[];
  search_index: SmaliSearchIndex[];
  error?: string;
};

// Dynamic Analysis / Frida Script Types
export type FridaScript = {
  name: string;
  category: string;
  description: string;
  script_code: string;
  target_classes: string[];
  target_methods: string[];
  is_dangerous: boolean;
  usage_instructions: string;
};

export type CryptoMethod = {
  pattern: string;
  description: string;
  context: string;
};

export type InterestingHook = {
  class: string;
  reason: string;
  methods: string[];
};

export type DynamicAnalysis = {
  package_name: string;
  frida_scripts: FridaScript[];
  ssl_pinning_detected: boolean;
  ssl_patterns_found: string[];
  root_detection_detected: boolean;
  root_patterns_found: string[];
  emulator_detection_detected: boolean;
  anti_tampering_detected: boolean;
  debugger_detection_detected: boolean;
  crypto_methods: CryptoMethod[];
  auth_patterns_found: string[];
  interesting_hooks: InterestingHook[];
  suggested_test_cases: string[];
  frida_spawn_command: string;
  frida_attach_command: string;
  total_scripts: number;
};

// Native Library Analysis Types
export type NativeFunction = {
  name: string;
  address: string;
  size: number;
  is_jni: boolean;
  is_exported: boolean;
  is_suspicious: boolean;
};

export type NativeLibraryInfo = {
  name: string;
  path: string;
  architecture: string;
  size: number;
  is_stripped: boolean;
  has_jni: boolean;
  has_anti_debug: boolean;
  has_crypto: boolean;
  functions: NativeFunction[];
  jni_functions: NativeFunction[];
  suspicious_functions: NativeFunction[];
  strings_found: string[];
  secrets_found: string[];
  urls_found: string[];
  anti_debug_indicators: string[];
  crypto_indicators: string[];
};

export type NativeAnalysisResult = {
  total_libraries: number;
  architectures: string[];
  libraries: NativeLibraryInfo[];
  total_jni_functions: number;
  total_suspicious_functions: number;
  has_native_anti_debug: boolean;
  has_native_crypto: boolean;
  native_secrets: string[];
  risk_level: "low" | "medium" | "high" | "critical";
  summary: string;
};

// Hardening Score Types
export type HardeningFinding = {
  issue: string;
  impact: string;
  severity: "low" | "medium" | "high" | "critical";
};

export type HardeningRecommendation = {
  action: string;
  priority: "low" | "medium" | "high";
  impact: string;
};

export type HardeningCategory = {
  name: string;
  score: number;
  max_score: number;
  percentage: number;
  weight: number;
  findings: HardeningFinding[];
  recommendations: HardeningRecommendation[];
};

export type HardeningScore = {
  overall_score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  risk_level: "low" | "medium" | "high" | "critical";
  categories: {
    code_protection: HardeningCategory;
    network_security: HardeningCategory;
    data_storage: HardeningCategory;
    authentication_crypto: HardeningCategory;
    platform_security: HardeningCategory;
  };
  attack_surface_summary: {
    exported_components: number;
    deep_links: number;
    dangerous_permissions: number;
    native_libraries: number;
    cleartext_traffic: boolean;
    debug_enabled: boolean;
    backup_enabled: boolean;
  };
  comparison: {
    industry_average: number;
    percentile: number;
  };
  top_risks: string[];
  quick_wins: string[];
};

// Data Flow / Taint Analysis Types
export type TaintSource = {
  source_type: string;
  class_name: string;
  method_name: string;
  description: string;
  sensitivity: "low" | "medium" | "high" | "critical";
  owasp_category: string;
};

export type TaintSink = {
  sink_type: string;
  class_name: string;
  method_name: string;
  description: string;
  risk_level: "low" | "medium" | "high" | "critical";
  owasp_category: string;
};

export type DataFlowPath = {
  source: TaintSource;
  sink: TaintSink;
  intermediate_methods: string[];
  affected_class: string;
  affected_method: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  recommendation: string;
  is_privacy_violation: boolean;
  gdpr_relevant: boolean;
  owasp_category: string;
};

export type DataFlowAnalysisResult = {
  total_sources: number;
  total_sinks: number;
  total_flows: number;
  critical_flows: number;
  high_risk_flows: number;
  sources_found: Array<{
    source_type: string;
    class_name: string;
    method_name: string;
    description: string;
    sensitivity: string;
    affected_method: string;
  }>;
  sinks_found: Array<{
    sink_type: string;
    class_name: string;
    method_name: string;
    description: string;
    risk_level: string;
    affected_method: string;
  }>;
  data_flow_paths: DataFlowPath[];
  privacy_violations: Array<{
    data_type: string;
    source: string;
    sink: string;
    description: string;
    affected_class: string;
    affected_method: string;
  }>;
  data_leak_risks: Array<{
    risk_type: string;
    source: string;
    sink: string;
    severity: string;
    description: string;
  }>;
  summary: string;
  recommendations: string[];
};

export type ApkAnalysisResult = {
  filename: string;
  package_name: string;
  version_name?: string;
  version_code?: number;
  min_sdk?: number;
  target_sdk?: number;
  permissions: ApkPermissionResult[];
  dangerous_permissions_count: number;
  components: ApkComponentResult[];
  strings_count: number;
  secrets: SecretResult[];
  urls: string[];
  native_libraries: string[];
  // Certificate info
  certificate?: ApkCertificate;
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  uses_features: string[];
  app_name?: string;
  debuggable: boolean;
  allow_backup: boolean;
  network_security_config?: string;
  // Analysis fields
  dex_analysis?: DexAnalysis;
  resource_analysis?: ResourceAnalysis;
  intent_filter_analysis?: IntentFilterAnalysis;
  network_config_analysis?: NetworkSecurityConfig;
  smali_analysis?: SmaliAnalysis;
  dynamic_analysis?: DynamicAnalysis;
  native_analysis?: NativeAnalysisResult;
  hardening_score?: HardeningScore;
  data_flow_analysis?: DataFlowAnalysisResult;
  // Security & AI
  security_issues: ApkSecurityIssue[];
  ai_analysis?: string;
  // New structured AI reports (HTML formatted)
  ai_report_functionality?: string;  // "What does this APK do" report
  ai_report_security?: string;        // "Security Findings" report
  // AI-generated Mermaid diagrams
  ai_architecture_diagram?: string;   // Architecture visualization
  ai_data_flow_diagram?: string;      // Data flow & privacy diagram
  error?: string;
};

// Docker Analysis Types
export type DockerLayerResult = {
  id: string;
  command: string;
  size: number;
};

export type DockerSecretResult = {
  layer_id: string;
  layer_command: string;
  secret_type: string;
  value: string;
  masked_value: string;
  context: string;
  severity: string;
};

export type DockerSecurityIssue = {
  category: string;
  severity: string;
  description: string;
  command?: string;
};

export type DockerAnalysisResult = {
  image_name: string;
  image_id: string;
  total_layers: number;
  total_size: number;
  total_size_human: string;
  base_image?: string;
  layers: DockerLayerResult[];
  secrets: DockerSecretResult[];
  deleted_files: Array<Record<string, any>>;
  security_issues: DockerSecurityIssue[];
  ai_analysis?: string;
  error?: string;
};

export type ReverseEngineeringStatus = {
  binary_analysis: boolean;
  apk_analysis: boolean;
  docker_analysis: boolean;
  jadx_available: boolean;
  docker_available: boolean;
  message: string;
};

export type DockerImageInfo = {
  name: string;
  id: string;
  size: string;
  created: string;
};

export type DockerImagesList = {
  images: DockerImageInfo[];
  total: number;
};

// ============================================================================
// AI-Powered APK Analysis Types
// ============================================================================

// Chat Types
export type ApkChatMessage = {
  role: "user" | "assistant";
  content: string;
  timestamp?: string;
};

export type ApkChatRequest = {
  message: string;
  conversation_history: ApkChatMessage[];
  analysis_context: Record<string, unknown>;
  beginner_mode?: boolean;
};

export type ApkChatResponse = {
  response: string;
  suggested_questions: string[];
  related_findings: string[];
  learning_tip?: string;
};

// Threat Model Types
export type ThreatActor = {
  name: string;
  motivation: string;
  capability: "Low" | "Medium" | "High";
  likelihood: "Low" | "Medium" | "High";
  description: string;
};

export type AttackScenario = {
  id: string;
  name: string;
  description: string;
  preconditions: string[];
  attack_steps: string[];
  impact: string;
  likelihood: "Low" | "Medium" | "High";
  severity: "Low" | "Medium" | "High" | "Critical";
  mitre_techniques: string[];
};

export type AttackTreeBranch = {
  method: string;
  sub_branches: string[];
  difficulty: "Easy" | "Medium" | "Hard";
};

export type AttackTree = {
  goal: string;
  branches: AttackTreeBranch[];
};

export type MitreMapping = {
  technique_id: string;
  technique_name: string;
  tactic: string;
  relevance: string;
  finding_reference: string;
};

export type RiskMatrix = {
  critical_risks: string[];
  high_risks: string[];
  medium_risks: string[];
  low_risks: string[];
  accepted_risks: string[];
};

export type PrioritizedThreat = {
  rank: number;
  threat: string;
  risk_score: number;
  rationale: string;
  recommendation: string;
};

export type ThreatModelRequest = {
  analysis_context: Record<string, unknown>;
  focus_areas?: string[];
  attacker_profile?: "script_kiddie" | "skilled" | "nation_state";
};

export type ThreatModelResponse = {
  threat_actors: ThreatActor[];
  attack_scenarios: AttackScenario[];
  attack_tree: AttackTree;
  mitre_attack_mappings: MitreMapping[];
  risk_matrix: RiskMatrix;
  prioritized_threats: PrioritizedThreat[];
  executive_summary: string;
};

// Exploit Suggestion Types
export type VulnerabilityInfo = {
  id: string;
  name: string;
  category: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  description: string;
  root_cause: string;
  affected_component: string;
};

export type ExploitStep = {
  step: number;
  action: string;
  command?: string;
  expected_result: string;
};

export type ExploitationPath = {
  vulnerability_id: string;
  name: string;
  prerequisites: string[];
  steps: ExploitStep[];
  success_indicators: string[];
  impact: string;
};

export type RequiredTool = {
  name: string;
  purpose: string;
  installation: string;
  usage_example: string;
};

export type PocScript = {
  vulnerability_id: string;
  name: string;
  language: string;
  description: string;
  code: string;
  usage: string;
};

export type MitigationBypass = {
  protection: string;
  bypass_method: string;
  tools: string[];
  difficulty: "Easy" | "Medium" | "Hard";
  detection_risk: string;
};

export type DifficultyAssessment = {
  overall_difficulty: "Easy" | "Medium" | "Hard" | "Expert";
  time_estimate: string;
  skill_requirements: string[];
  resource_requirements: string[];
  success_probability: "Low" | "Medium" | "High";
};

export type ExploitSuggestionRequest = {
  analysis_context: Record<string, unknown>;
  vulnerability_focus?: string;
  include_poc?: boolean;
  skill_level?: "beginner" | "intermediate" | "advanced";
};

export type ExploitSuggestionResponse = {
  vulnerabilities: VulnerabilityInfo[];
  exploitation_paths: ExploitationPath[];
  tools_required: RequiredTool[];
  poc_scripts: PocScript[];
  mitigation_bypasses: MitigationBypass[];
  difficulty_assessment: DifficultyAssessment;
};

// Walkthrough Types
export type WalkthroughStep = {
  step_number: number;
  phase: string;
  title: string;
  description: string;
  technical_detail: string;
  beginner_explanation: string;
  why_it_matters: string;
  findings_count: number;
  severity?: string;
  progress_percent: number;
};

export type LearningResource = {
  title: string;
  url: string;
  description: string;
};

export type AnalysisWalkthroughResponse = {
  total_steps: number;
  steps: WalkthroughStep[];
  glossary: Record<string, string>;
  learning_resources: LearningResource[];
  next_steps: string[];
};

// Chat Export Types
export type ChatExportRequest = {
  messages: ApkChatMessage[];
  analysis_context: Record<string, unknown>;
  format: "markdown" | "json" | "pdf";
};

// Code Explanation Types
export type SecurityConcern = {
  severity: "critical" | "high" | "medium" | "low";
  issue: string;
  location: string;
  recommendation: string;
};

export type CodeExplanationRequest = {
  source_code: string;
  class_name: string;
  language?: "java" | "smali" | "kotlin";
  focus_area?: "security" | "functionality" | "data_flow" | null;
  beginner_mode?: boolean;
};

export type CodeExplanationResponse = {
  summary: string;
  detailed_explanation: string;
  security_concerns: SecurityConcern[];
  interesting_findings: string[];
  data_flow_analysis?: string;
  suggested_focus_points: string[];
  code_quality_notes: string[];
};

// AI Code Search Types
export type CodeSearchAIRequest = {
  session_id: string;
  query: string;
  max_results?: number;
};

export type AICodeSearchMatch = {
  file_path: string;
  line_number: number;
  line_content: string;
  matched_pattern: string;
};

export type CodeSearchAIResponse = {
  query: string;
  interpreted_as: string;
  search_patterns: string[];
  results: AICodeSearchMatch[];
  suggestions: string[];
};

// Reverse Engineering API Client
export const reverseEngineeringClient = {
  /**
   * Get status of reverse engineering capabilities
   */
  getStatus: async (): Promise<ReverseEngineeringStatus> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/status`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Analyze a binary executable file (EXE, ELF, DLL)
   */
  analyzeBinary: async (
    file: File,
    includeAi: boolean = true
  ): Promise<BinaryAnalysisResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const form = new FormData();
    form.append("file", file);

    const params = new URLSearchParams({ include_ai: String(includeAi) });
    const resp = await fetch(`${API_URL}/reverse/analyze-binary?${params}`, {
      method: "POST",
      headers,
      body: form,
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || resp.statusText);
    }
    return resp.json();
  },

  /**
   * Analyze an Android APK file
   */
  analyzeApk: async (
    file: File,
    includeAi: boolean = true
  ): Promise<ApkAnalysisResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const form = new FormData();
    form.append("file", file);

    const params = new URLSearchParams({ include_ai: String(includeAi) });
    const resp = await fetch(`${API_URL}/reverse/analyze-apk?${params}`, {
      method: "POST",
      headers,
      body: form,
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || resp.statusText);
    }
    return resp.json();
  },

  /**
   * Analyze a Docker image's layers
   */
  analyzeDockerImage: async (
    imageName: string,
    includeAi: boolean = true
  ): Promise<DockerAnalysisResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const params = new URLSearchParams({ include_ai: String(includeAi) });
    const resp = await fetch(`${API_URL}/reverse/analyze-docker/${encodeURIComponent(imageName)}?${params}`, {
      headers,
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || resp.statusText);
    }
    return resp.json();
  },

  /**
   * List locally available Docker images
   */
  listDockerImages: async (): Promise<DockerImagesList> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/docker-images`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Save a reverse engineering report
   */
  saveReport: async (report: SaveREReportRequest): Promise<REReportSummary> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/reports`, {
      method: "POST",
      headers,
      body: JSON.stringify(report),
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || resp.statusText);
    }
    return resp.json();
  },

  /**
   * Export APK analysis report to Markdown, PDF, or Word format
   */
  exportApkReport: async (
    file: File,
    format: "markdown" | "pdf" | "docx",
    reportType: "functionality" | "security" | "both" = "both"
  ): Promise<Blob> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const form = new FormData();
    form.append("file", file);

    const params = new URLSearchParams({ format, report_type: reportType });
    const resp = await fetch(`${API_URL}/reverse/apk/export?${params}`, {
      method: "POST",
      headers,
      body: form,
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || resp.statusText);
    }
    return resp.blob();
  },

  /**
   * Export APK analysis report from existing result data
   */
  exportApkReportFromResult: async (
    resultData: ApkAnalysisResult,
    format: "markdown" | "pdf" | "docx",
    reportType: "functionality" | "security" | "both" = "both"
  ): Promise<Blob> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const params = new URLSearchParams({ format, report_type: reportType });
    const resp = await fetch(`${API_URL}/reverse/apk/export-from-result?${params}`, {
      method: "POST",
      headers,
      body: JSON.stringify(resultData),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || resp.statusText);
    }
    return resp.blob();
  },

  /**
   * List saved reports
   */
  listReports: async (params?: {
    analysis_type?: string;
    project_id?: number;
    risk_level?: string;
    limit?: number;
    offset?: number;
  }): Promise<REReportSummary[]> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const searchParams = new URLSearchParams();
    if (params?.analysis_type) searchParams.set("analysis_type", params.analysis_type);
    if (params?.project_id) searchParams.set("project_id", String(params.project_id));
    if (params?.risk_level) searchParams.set("risk_level", params.risk_level);
    if (params?.limit) searchParams.set("limit", String(params.limit));
    if (params?.offset) searchParams.set("offset", String(params.offset));
    
    const resp = await fetch(`${API_URL}/reverse/reports?${searchParams}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Get a specific report by ID
   */
  getReport: async (reportId: number): Promise<REReportDetail> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/reports/${reportId}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Delete a report
   */
  deleteReport: async (reportId: number): Promise<void> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/reports/${reportId}`, {
      method: "DELETE",
      headers,
    });
    if (!resp.ok) throw new Error(await resp.text());
  },

  /**
   * Export a saved report to Markdown, PDF, or Word format
   * Includes all analysis data: Quick Scan, JADX Full Scan, and AI Reports
   */
  exportSavedReport: async (
    reportId: number,
    format: "markdown" | "pdf" | "docx"
  ): Promise<Blob> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    
    const params = new URLSearchParams({ format });
    const resp = await fetch(`${API_URL}/reverse/reports/${reportId}/export?${params}`, {
      headers,
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || resp.statusText);
    }
    return resp.blob();
  },

  /**
   * Update a report (notes, tags, title)
   */
  updateReport: async (reportId: number, updates: {
    notes?: string;
    tags?: string[];
    title?: string;
  }): Promise<void> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const params = new URLSearchParams();
    if (updates.notes !== undefined) params.set("notes", updates.notes);
    if (updates.title !== undefined) params.set("title", updates.title);
    // Tags need special handling
    
    const resp = await fetch(`${API_URL}/reverse/reports/${reportId}?${params}`, {
      method: "PATCH",
      headers,
      body: updates.tags ? JSON.stringify({ tags: updates.tags }) : undefined,
    });
    if (!resp.ok) throw new Error(await resp.text());
  },

  // ================== AI-Powered APK Analysis API ==================

  /**
   * Chat about APK analysis results with AI
   */
  chatAboutApk: async (request: ApkChatRequest): Promise<ApkChatResponse> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/chat`, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Export chat conversation to file
   */
  exportApkChat: async (request: ChatExportRequest): Promise<Blob> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/chat/export`, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.blob();
  },

  /**
   * AI-powered code explanation for decompiled sources
   */
  explainCode: async (request: CodeExplanationRequest): Promise<CodeExplanationResponse> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/code/explain`, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * AI-powered semantic code search in decompiled sources
   */
  searchCodeAI: async (request: CodeSearchAIRequest): Promise<CodeSearchAIResponse> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/code/search-ai`, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Generate threat model for APK analysis
   */
  generateThreatModel: async (request: ThreatModelRequest): Promise<ThreatModelResponse> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/threat-model`, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Get AI-powered exploit suggestions for APK vulnerabilities
   */
  getExploitSuggestions: async (request: ExploitSuggestionRequest): Promise<ExploitSuggestionResponse> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/exploit-suggestions`, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Get educational walkthrough of APK analysis
   */
  getAnalysisWalkthrough: async (analysisContext: Record<string, unknown>): Promise<AnalysisWalkthroughResponse> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/walkthrough`, {
      method: "POST",
      headers,
      body: JSON.stringify({ analysis_context: analysisContext }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Hex Viewer API ==================

  /**
   * Upload a file for hex viewing
   */
  uploadForHexView: async (file: File): Promise<{ file_id: string; filename: string; file_size: number }> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const formData = new FormData();
    formData.append("file", file);
    
    const resp = await fetch(`${API_URL}/reverse/hex-upload`, {
      method: "POST",
      headers,
      body: formData,
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Get hex view of an uploaded file
   */
  getHexView: async (fileId: string, offset: number = 0, length: number = 512): Promise<HexViewResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const params = new URLSearchParams({
      offset: String(offset),
      length: String(length),
    });
    const resp = await fetch(`${API_URL}/reverse/hex/${fileId}?${params}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Search in hex file
   */
  searchHex: async (
    fileId: string,
    query: string,
    searchType: 'text' | 'hex' = 'text',
    maxResults: number = 50
  ): Promise<HexSearchResponse> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const params = new URLSearchParams({
      query,
      search_type: searchType,
      max_results: String(maxResults),
    });
    const resp = await fetch(`${API_URL}/reverse/hex/${fileId}/search?${params}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Delete an uploaded hex view file
   */
  deleteHexFile: async (fileId: string): Promise<void> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/hex/${fileId}`, {
      method: "DELETE",
      headers,
    });
    if (!resp.ok) throw new Error(await resp.text());
  },

  // ================== JADX Decompilation API ==================

  /**
   * Decompile APK to Java source code using JADX
   */
  decompileApk: async (file: File): Promise<JadxDecompilationResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const formData = new FormData();
    formData.append("file", file);

    // Use AbortController for 30 minute timeout (very large APKs like games can take a while)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1800000); // 30 minutes

    try {
      const resp = await fetch(`${API_URL}/reverse/apk/decompile`, {
        method: "POST",
        headers,
        body: formData,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (!resp.ok) throw new Error(await resp.text());
      return resp.json();
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('Decompilation timed out after 30 minutes. The APK may be extremely large or complex.');
      }
      throw error;
    }
  },

  /**
   * Get decompiled Java source code for a specific class
   */
  getDecompiledSource: async (sessionId: string, classPath: string): Promise<JadxSourceResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/${sessionId}/source/${encodeURIComponent(classPath)}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Search in decompiled Java sources
   */
  searchDecompiledSources: async (
    sessionId: string,
    query: string,
    maxResults: number = 50
  ): Promise<JadxSearchResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const params = new URLSearchParams({
      query,
      max_results: String(maxResults),
    });
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/${sessionId}/search?${params}`, { headers });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Clean up decompilation session
   */
  cleanupDecompilation: async (sessionId: string): Promise<void> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/${sessionId}`, {
      method: "DELETE",
      headers,
    });
    if (!resp.ok) throw new Error(await resp.text());
  },

  // ================== AI Code Analysis API ==================

  /**
   * Explain decompiled code with AI
   */
  explainCodeWithAI: async (
    sourceCode: string,
    className: string,
    explanationType: "general" | "security" | "method" = "general",
    methodName?: string
  ): Promise<AICodeExplanationResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/ai/explain`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        source_code: sourceCode,
        class_name: className,
        explanation_type: explanationType,
        method_name: methodName,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Analyze code vulnerabilities with AI
   */
  analyzeVulnerabilitiesWithAI: async (
    sourceCode: string,
    className: string
  ): Promise<AIVulnerabilityAnalysisResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/ai/vulnerabilities`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        source_code: sourceCode,
        class_name: className,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Analyze data flow in decompiled code
   */
  analyzeDataFlow: async (
    sourceCode: string,
    className: string
  ): Promise<ClassDataFlowResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/dataflow`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        source_code: sourceCode,
        class_name: className,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Build method call graph from decompiled code
   */
  buildCallGraph: async (
    sourceCode: string,
    className: string
  ): Promise<CallGraphResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/callgraph`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        source_code: sourceCode,
        class_name: className,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Smart search across decompiled sources
   */
  smartSearch: async (
    outputDirectory: string,
    query: string,
    searchType: "smart" | "vuln" | "regex" | "exact" = "smart",
    maxResults: number = 100
  ): Promise<SmartSearchResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/smart-search`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        output_directory: outputDirectory,
        query: query,
        search_type: searchType,
        max_results: maxResults,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * AI-powered vulnerability scan across multiple classes
   */
  aiVulnScan: async (
    outputDirectory: string,
    scanType: "quick" | "deep" | "focused" = "quick",
    focusAreas: string[] = []
  ): Promise<AIVulnScanResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/ai-vulnscan`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        output_directory: outputDirectory,
        scan_type: scanType,
        focus_areas: focusAreas,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Smali View API ==================

  /**
   * Get Smali bytecode view for a class
   */
  getSmaliView: async (
    outputDirectory: string,
    classPath: string
  ): Promise<SmaliViewResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/smali`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        output_directory: outputDirectory,
        class_path: classPath,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== String Extraction API ==================

  /**
   * Extract and categorize all strings from decompiled sources
   */
  extractStrings: async (
    outputDirectory: string,
    filters?: string[]
  ): Promise<StringExtractionResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/strings`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        output_directory: outputDirectory,
        filters: filters || null,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Cross-Reference (XREF) API ==================

  /**
   * Build cross-references for a class
   */
  getCrossReferences: async (
    outputDirectory: string,
    classPath: string
  ): Promise<CrossReferenceResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/xref`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        output_directory: outputDirectory,
        class_path: classPath,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Project ZIP API ==================

  /**
   * Get information about project ZIP
   */
  getProjectZipInfo: async (outputDirectory: string): Promise<ProjectZipInfo> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/zip-info`, {
      method: "POST",
      headers,
      body: JSON.stringify({ output_directory: outputDirectory }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  /**
   * Download project as ZIP file
   */
  downloadProjectZip: async (outputDirectory: string): Promise<Blob> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/download-zip`, {
      method: "POST",
      headers,
      body: JSON.stringify({ output_directory: outputDirectory }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.blob();
  },

  // ================== Permission Analysis API ==================

  /**
   * Analyze permissions from AndroidManifest.xml
   */
  analyzePermissions: async (outputDirectory: string): Promise<PermissionAnalysisResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/permissions`, {
      method: "POST",
      headers,
      body: JSON.stringify({ output_directory: outputDirectory }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Network Endpoint API ==================

  /**
   * Extract network endpoints from decompiled sources
   */
  extractNetworkEndpoints: async (outputDirectory: string): Promise<NetworkEndpointResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/network-endpoints`, {
      method: "POST",
      headers,
      body: JSON.stringify({ output_directory: outputDirectory }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Manifest Visualization API ==================

  /**
   * Generate manifest visualization for an APK
   */
  getManifestVisualization: async (file: File): Promise<ManifestVisualizationResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const formData = new FormData();
    formData.append("file", file);

    const resp = await fetch(`${API_URL}/reverse/apk/manifest-visualization`, {
      method: "POST",
      headers,
      body: formData,
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Attack Surface Map API ==================

  /**
   * Generate attack surface map for an APK
   */
  getAttackSurfaceMap: async (file: File): Promise<AttackSurfaceMapResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const formData = new FormData();
    formData.append("file", file);

    // Use AbortController for 15-minute timeout (large APK uploads can be slow)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 900000);

    try {
      const resp = await fetch(`${API_URL}/reverse/apk/attack-surface`, {
        method: "POST",
        headers,
        body: formData,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (!resp.ok) throw new Error(await resp.text());
      return resp.json();
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('Attack surface analysis timed out after 15 minutes. Please try a smaller APK.');
      }
      throw error;
    }
  },

  // ================== Obfuscation Analysis API ==================

  /**
   * Analyze APK for obfuscation techniques
   */
  analyzeObfuscation: async (file: File): Promise<ObfuscationAnalysisResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const formData = new FormData();
    formData.append("file", file);

    // Use AbortController for 15-minute timeout (large APK uploads can be slow)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 900000);

    try {
      const resp = await fetch(`${API_URL}/reverse/apk/obfuscation-analysis`, {
        method: "POST",
        headers,
        body: formData,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (!resp.ok) throw new Error(await resp.text());
      return resp.json();
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('Obfuscation analysis timed out after 15 minutes. Please try a smaller APK.');
      }
      throw error;
    }
  },

  // ================== Binary Entropy Analysis API ==================

  /**
   * Analyze binary entropy distribution
   */
  analyzeBinaryEntropy: async (
    file: File, 
    windowSize: number = 256, 
    stepSize: number = 128
  ): Promise<EntropyAnalysisResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const formData = new FormData();
    formData.append("file", file);

    const resp = await fetch(
      `${API_URL}/reverse/binary/entropy?window_size=${windowSize}&step_size=${stepSize}`, 
      {
        method: "POST",
        headers,
        body: formData,
      }
    );
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Crypto Audit API ==================

  /**
   * Perform comprehensive cryptographic audit on decompiled APK sources
   */
  cryptoAudit: async (outputDirectory: string): Promise<CryptoAuditResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/crypto-audit`, {
      method: "POST",
      headers,
      body: JSON.stringify({ output_directory: outputDirectory }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Component Map API ==================

  /**
   * Generate visual component map showing activities, services, receivers, providers
   */
  getComponentMap: async (outputDirectory: string): Promise<ComponentMapResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/component-map`, {
      method: "POST",
      headers,
      body: JSON.stringify({ output_directory: outputDirectory }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Class Dependency Graph API ==================

  /**
   * Generate a class dependency graph showing how classes are interconnected
   */
  getDependencyGraph: async (outputDirectory: string, maxClasses?: number): Promise<DependencyGraphResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/dependency-graph`, {
      method: "POST",
      headers,
      body: JSON.stringify({ 
        output_directory: outputDirectory,
        max_classes: maxClasses || 100
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },

  // ================== Symbol Lookup API (Jump to Definition) ==================

  /**
   * Look up a symbol (class, method, or field) and return its definition location
   */
  lookupSymbol: async (
    outputDirectory: string, 
    symbol: string, 
    symbolType?: "class" | "method" | "field"
  ): Promise<SymbolLookupResult> => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const resp = await fetch(`${API_URL}/reverse/apk/decompile/symbol-lookup`, {
      method: "POST",
      headers,
      body: JSON.stringify({ 
        output_directory: outputDirectory,
        symbol,
        symbol_type: symbolType || null
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  },
};

// Report types
export interface SaveREReportRequest {
  analysis_type: 'binary' | 'apk' | 'docker';
  title: string;
  filename?: string;
  project_id?: number;
  risk_level?: string;
  risk_score?: number;
  
  // Binary fields
  file_type?: string;
  architecture?: string;
  file_size?: number;
  is_packed?: boolean;
  packer_name?: string;
  
  // APK fields
  package_name?: string;
  version_name?: string;
  min_sdk?: number;
  target_sdk?: number;
  
  // Docker fields
  image_name?: string;
  image_id?: string;
  total_layers?: number;
  base_image?: string;
  
  // Counts
  strings_count?: number;
  imports_count?: number;
  exports_count?: number;
  secrets_count?: number;
  
  // JSON data
  suspicious_indicators?: Array<Record<string, unknown>>;
  permissions?: Array<Record<string, unknown>>;
  security_issues?: Array<Record<string, unknown>>;
  full_analysis_data?: Record<string, unknown>;
  
  // AI Quick Analysis
  ai_analysis_raw?: string;
  
  // JADX Full Scan Data (Deep Analysis)
  jadx_total_classes?: number;
  jadx_total_files?: number;
  jadx_output_directory?: string;
  jadx_classes_sample?: Array<Record<string, unknown>>;
  jadx_security_issues?: Array<Record<string, unknown>>;
  
  // AI-Generated Reports (Deep Analysis)
  ai_functionality_report?: string;
  ai_security_report?: string;
  ai_privacy_report?: string;
  ai_threat_model?: Record<string, unknown>;
  ai_vuln_scan_result?: Record<string, unknown>;
  ai_chat_history?: Array<Record<string, unknown>>;
  
  // Metadata
  tags?: string[];
  notes?: string;
}

export interface REReportSummary {
  id: number;
  analysis_type: string;
  title: string;
  filename?: string;
  risk_level?: string;
  risk_score?: number;
  created_at: string;
  tags?: string[];
}

export interface REReportDetail extends REReportSummary {
  updated_at: string;
  project_id?: number;
  
  file_type?: string;
  architecture?: string;
  file_size?: number;
  is_packed?: string;
  packer_name?: string;
  
  package_name?: string;
  version_name?: string;
  min_sdk?: number;
  target_sdk?: number;
  
  image_name?: string;
  image_id?: string;
  total_layers?: number;
  base_image?: string;
  
  strings_count?: number;
  imports_count?: number;
  exports_count?: number;
  secrets_count?: number;
  
  suspicious_indicators?: Array<Record<string, unknown>>;
  permissions?: Array<Record<string, unknown>>;
  security_issues?: Array<Record<string, unknown>>;
  full_analysis_data?: Record<string, unknown>;
  
  ai_analysis_raw?: string;
  ai_analysis_structured?: Record<string, unknown>;
  
  // JADX Full Scan Data
  jadx_total_classes?: number;
  jadx_total_files?: number;
  jadx_data?: {
    output_directory?: string;
    classes_sample?: Array<Record<string, unknown>>;
    security_issues?: Array<Record<string, unknown>>;
  };
  
  // AI-Generated Reports (Deep Analysis)
  ai_functionality_report?: string;
  ai_security_report?: string;
  ai_privacy_report?: string;
  ai_threat_model?: Record<string, unknown>;
  ai_vuln_scan_result?: Record<string, unknown>;
  ai_chat_history?: Array<Record<string, unknown>>;
  
  notes?: string;
}

// ============================================================================
// JADX Decompilation Types
// ============================================================================

export type JadxDecompiledClass = {
  class_name: string;
  package_name: string;
  file_path: string;
  line_count: number;
  is_activity: boolean;
  is_service: boolean;
  is_receiver: boolean;
  is_provider: boolean;
  extends?: string;
  security_issues_count: number;
};

export type JadxDecompilationResult = {
  package_name: string;
  total_classes: number;
  total_files: number;
  output_directory: string;  // This is actually the session_id
  decompilation_time: number;
  classes: JadxDecompiledClass[];
  source_tree: Record<string, unknown>;
  security_issues: Array<{
    type: string;
    severity: string;
    description: string;
    class: string;
    line: number;
    code_snippet: string;
  }>;
  errors: string[];
  warnings: string[];
};

export type JadxSourceResult = {
  class_name: string;
  package_name: string;
  file_path: string;
  source_code: string;
  line_count: number;
  is_activity: boolean;
  is_service: boolean;
  is_receiver: boolean;
  is_provider: boolean;
  extends?: string;
  implements: string[];
  methods: string[];
  security_issues: Array<{
    type: string;
    severity: string;
    description: string;
    class: string;
    line: number;
    code_snippet: string;
  }>;
};

export type JadxSearchResult = {
  query: string;
  total_results: number;
  results: Array<{
    file: string;
    line: number;
    content: string;
    class_name: string;
  }>;
};

// ============================================================================
// AI Code Analysis Types
// ============================================================================

export type AICodeExplanationResult = {
  class_name: string;
  explanation_type: "general" | "security" | "method";
  explanation: string;
  key_points: string[];
  security_concerns: Array<{
    concern: string;
    severity: string;
    line_hint?: string;
    recommendation?: string;
  }>;
  method_name?: string;
};

export type AIVulnerabilityAnalysisResult = {
  class_name: string;
  risk_level: "critical" | "high" | "medium" | "low" | "info" | "unknown" | "error";
  vulnerabilities: Array<{
    id: string;
    title: string;
    severity: string;
    category: string;
    description: string;
    affected_code?: string;
    impact?: string;
    cvss_estimate?: string;
  }>;
  recommendations: string[];
  exploitation_scenarios: string[];
  summary: string;
};

// ============================================================================
// Data Flow Analysis Types
// ============================================================================

export type DataFlowSourceEntry = {
  type: string;
  pattern?: string;
  line: number;
  code: string;
  variable?: string;
};

export type DataFlowSinkEntry = {
  type: string;
  pattern?: string;
  line: number;
  code: string;
};

export type DataFlowEntry = {
  source: {
    type: string;
    variable?: string;
    line: number;
  };
  sink: {
    type: string;
    line: number;
    code: string;
  };
  risk: "critical" | "high" | "medium" | "low";
};

export type DataFlowSummaryInfo = {
  total_sources: number;
  total_sinks: number;
  potential_leaks: number;
  risk_level: "critical" | "high" | "medium" | "low";
};

export type ClassDataFlowResult = {
  class_name: string;
  sources: DataFlowSourceEntry[];
  sinks: DataFlowSinkEntry[];
  flows: DataFlowEntry[];
  risk_flows: DataFlowEntry[];
  summary: DataFlowSummaryInfo;
};

// ============================================================================
// Method Call Graph Types
// ============================================================================

export type MethodParameter = {
  type: string;
  name: string;
};

export type MethodCall = {
  method: string;
  class?: string;
  line: number;
  type: "constructor" | "static" | "instance" | "super";
};

export type MethodInfo = {
  name: string;
  return_type: string;
  parameters: MethodParameter[];
  line_start: number;
  line_end: number;
  is_entry_point: boolean;
  calls: MethodCall[];
  called_by: string[];
  modifiers: string[];
};

export type CallInfo = {
  caller: string;
  caller_line: number;
  callee: string;
  callee_class: string;
  line: number;
  is_internal: boolean;
};

export type GraphNode = {
  id: string;
  label: string;
  type: "internal" | "external";
  is_entry_point: boolean;
  line?: number;
  class?: string;
};

export type GraphEdge = {
  from: string;
  to: string;
  label: string;
};

export type CallGraphStatistics = {
  total_methods: number;
  total_internal_calls: number;
  total_external_calls: number;
  max_depth: number;
  cyclomatic_complexity: number;
};

export type CallGraphResult = {
  class_name: string;
  methods: MethodInfo[];
  calls: CallInfo[];
  entry_points: Array<{
    name: string;
    line: number;
    type: string;
  }>;
  external_calls: CallInfo[];
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  statistics: CallGraphStatistics;
};

// ============================================================================
// Smart Search Types
// ============================================================================

export type SmartSearchMatch = {
  file: string;
  line: number;
  code: string;
  match: string;
  context?: string;
  vuln_type?: string;
  description?: string;
  severity?: string;
};

export type VulnSummaryItem = {
  count: number;
  severity: string;
  description: string;
};

export type SmartSearchResult = {
  query: string;
  search_type: string;
  total_matches: number;
  files_searched: number;
  matches: SmartSearchMatch[];
  vulnerability_summary: Record<string, VulnSummaryItem>;
  expanded_terms: string[];
  suggestions: string[];
  error?: string;
};

// ============================================================================
// AI Vulnerability Scan Types
// ============================================================================

export type AIVulnScanVulnerability = {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  affected_class: string;
  affected_method: string;
  description: string;
  code_snippet: string;
  impact: string;
  remediation: string;
  cwe_id: string;
};

export type AIVulnScanAttackChain = {
  name: string;
  steps: string[];
  impact: string;
  likelihood: "high" | "medium" | "low";
};

export type AIVulnScanRiskSummary = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export type AIVulnScanResult = {
  scan_type: string;
  focus_areas: string[];
  classes_scanned: number;
  vulnerabilities: AIVulnScanVulnerability[];
  risk_summary: AIVulnScanRiskSummary;
  attack_chains: AIVulnScanAttackChain[];
  recommendations: string[];
  summary: string;
  overall_risk: "critical" | "high" | "medium" | "low";
  error?: string;
};

// ============================================================================
// Smali View Types
// ============================================================================

export type SmaliInstruction = {
  method: string;
  instruction: string;
  category: string;
};

export type SmaliBytecodStats = {
  invocations?: Record<string, number>;
  field_ops?: Record<string, number>;
  control_flow?: Record<string, number>;
  suspicious_ops?: Record<string, number>;
};

export type SmaliViewResult = {
  class_path: string;
  smali_code: string;
  bytecode_stats: SmaliBytecodStats;
  registers_used: number;
  method_count: number;
  field_count: number;
  instructions: SmaliInstruction[];
  is_pseudo: boolean;
  error?: string;
};

// ============================================================================
// String Extraction Types
// ============================================================================

export type ExtractedString = {
  value: string;
  file: string;
  line: number;
  categories: string[];
  severity: "critical" | "high" | "medium" | "low";
  length: number;
  is_resource?: boolean;
};

export type StringExtractionResult = {
  total_strings: number;
  files_scanned: number;
  strings: ExtractedString[];
  stats: Record<string, number>;
  severity_counts: Record<string, number>;
  top_categories: Array<[string, number]>;
  error?: string;
};

// ============================================================================
// Cross-Reference (XREF) Types
// ============================================================================

export type XrefCaller = {
  class: string;
  file: string;
  method: string;
  line: number;
};

export type XrefCallee = {
  method: string;
  object: string;
  line: number;
};

export type XrefMethod = {
  name: string;
  return_type: string;
  params: string;
  signature: string;
  line: number;
  callers: XrefCaller[];
  callees: XrefCallee[];
  caller_count: number;
  callee_count: number;
};

export type XrefField = {
  name: string;
  type: string;
  line: number;
  readers: Array<{ class: string; file: string; line: number }>;
  writers: Array<{ class: string; file: string; line: number }>;
  read_count: number;
  write_count: number;
};

export type XrefStatistics = {
  method_count: number;
  field_count: number;
  total_incoming_refs: number;
  total_outgoing_refs: number;
  is_heavily_used: boolean;
  is_hub_class: boolean;
};

export type CrossReferenceResult = {
  class_name: string;
  package: string;
  file_path: string;
  methods: XrefMethod[];
  fields: XrefField[];
  statistics: XrefStatistics;
  summary: string;
  error?: string;
};

// ============================================================================
// Project ZIP Types
// ============================================================================

export type ProjectZipInfo = {
  total_files: number;
  total_size_bytes: number;
  total_size_mb: number;
  file_types: Record<string, number>;
  estimated_zip_size_mb: number;
  error?: string;
};

// ============================================================================
// Permission Analysis Types
// ============================================================================

export type PermissionInfo = {
  name: string;
  short_name: string;
  level: "dangerous" | "normal" | "signature" | "deprecated" | "unknown";
  description: string;
  category: string;
};

export type DangerousCombination = {
  permissions: string[];
  risk: "critical" | "high" | "medium";
  description: string;
};

export type PermissionAnalysisResult = {
  total_permissions: number;
  permissions: PermissionInfo[];
  by_level: Record<string, PermissionInfo[]>;
  by_category: Record<string, PermissionInfo[]>;
  dangerous_combinations: DangerousCombination[];
  risk_score: number;
  overall_risk: "critical" | "high" | "medium" | "low";
  summary: string;
  error?: string;
};

// ============================================================================
// Network Endpoint Types
// ============================================================================

export type NetworkEndpoint = {
  value: string;
  type: string;
  category: string;
  risk: "high" | "medium" | "low";
  file: string;
  line: number;
};

export type NetworkEndpointResult = {
  total_endpoints: number;
  endpoints: NetworkEndpoint[];
  by_category: Record<string, NetworkEndpoint[]>;
  by_risk: Record<string, NetworkEndpoint[]>;
  unique_domains: string[];
  domain_count: number;
  summary: string;
  error?: string;
};

// ============================================================================
// Manifest Visualization Types
// ============================================================================

export type ManifestNode = {
  id: string;
  name: string;
  node_type: "application" | "activity" | "service" | "receiver" | "provider" | "permission";
  label: string;
  is_exported: boolean;
  is_main: boolean;
  is_dangerous: boolean;
  attributes: Record<string, unknown>;
};

export type ManifestEdge = {
  source: string;
  target: string;
  edge_type: string;
  label: string;
};

export type ManifestVisualizationResult = {
  package_name: string;
  app_name?: string;
  version_name?: string;
  nodes: ManifestNode[];
  edges: ManifestEdge[];
  component_counts: {
    activities: number;
    services: number;
    receivers: number;
    providers: number;
    permissions: number;
  };
  permission_summary: {
    dangerous: number;
    normal: number;
    signature: number;
    total: number;
  };
  exported_count: number;
  main_activity?: string;
  deep_link_schemes: string[];
  mermaid_diagram: string;
};

// ============================================================================
// Attack Surface Map Types
// ============================================================================

export type AttackVector = {
  id: string;
  name: string;
  vector_type: "exported_activity" | "exported_service" | "exported_receiver" | "exported_provider" | "deep_link";
  component: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  exploitation_steps: string[];
  required_permissions: string[];
  adb_command?: string;
  intent_example?: string;
  mitigation?: string;
};

export type DeepLinkEntry = {
  scheme: string;
  host: string;
  path: string;
  full_url: string;
  handling_activity: string;
  parameters: string[];
  is_verified: boolean;
  security_notes: string[];
};

export type ExposedDataPath = {
  provider_name: string;
  uri_pattern: string;
  permissions_required: string[];
  operations: string[];
  is_exported: boolean;
  potential_data: string;
  risk_level: string;
};

export type AttackSurfaceMapResult = {
  package_name: string;
  total_attack_vectors: number;
  attack_vectors: AttackVector[];
  exposed_data_paths: ExposedDataPath[];
  deep_links: DeepLinkEntry[];
  overall_exposure_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  risk_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  priority_targets: string[];
  automated_tests: Array<{
    name: string;
    command: string;
    description: string;
  }>;
  mermaid_attack_tree: string;
};

// ============================================================================
// Obfuscation Analysis Types
// ============================================================================

export type ObfuscationIndicator = {
  indicator_type: string;
  confidence: "high" | "medium" | "low";
  description: string;
  evidence: string[];
  location?: string;
  deobfuscation_hint?: string;
};

export type StringEncryptionPattern = {
  pattern_name: string;
  class_name: string;
  method_name: string;
  encrypted_strings_count: number;
  decryption_method_signature?: string;
  sample_encrypted_values: string[];
  suggested_frida_hook?: string;
};

export type ClassNamingAnalysis = {
  total_classes: number;
  single_letter_classes: number;
  short_name_classes: number;
  meaningful_name_classes: number;
  obfuscation_ratio: number;
  sample_obfuscated_names: string[];
  sample_original_names: string[];
};

export type ControlFlowObfuscation = {
  pattern_type: string;
  affected_methods: number;
  sample_classes: string[];
  complexity_score: number;
};

export type NativeProtection = {
  has_native_libs: boolean;
  native_lib_names: string[];
  protection_indicators: string[];
  jni_functions: string[];
};

export type ObfuscationAnalysisResult = {
  package_name: string;
  overall_obfuscation_level: "none" | "light" | "moderate" | "heavy" | "extreme";
  obfuscation_score: number;
  detected_tools: string[];
  
  indicators: ObfuscationIndicator[];
  class_naming: ClassNamingAnalysis;
  string_encryption: StringEncryptionPattern[];
  control_flow: ControlFlowObfuscation[];
  native_protection: NativeProtection;
  
  deobfuscation_strategies: string[];
  recommended_tools: string[];
  frida_hooks: string[];
  
  analysis_time: number;
  warnings: string[];
};

// ============================================================================
// Binary Entropy Analysis Types
// ============================================================================

export type EntropyDataPoint = {
  offset: number;
  entropy: number;
  size: number;
};

export type EntropyRegion = {
  start_offset: number;
  end_offset: number;
  avg_entropy: number;
  max_entropy: number;
  min_entropy: number;
  classification: "packed" | "encrypted" | "code" | "data" | "sparse" | "empty" | "packed_code" | "resources";
  section_name?: string;
  description: string;
};

export type SectionEntropy = {
  name: string;
  entropy: number;
  virtual_address?: number;
  raw_size?: number;
  virtual_size?: number;
  address?: number;
  size?: number;
  characteristics?: string;
  type?: string;
};

export type EntropyAnalysisResult = {
  filename: string;
  file_size: number;
  overall_entropy: number;
  entropy_data: EntropyDataPoint[];
  regions: EntropyRegion[];
  is_likely_packed: boolean;
  packing_confidence: number;
  detected_packers: string[];
  section_entropy: SectionEntropy[];
  analysis_notes: string[];
  window_size: number;
  step_size: number;
};

// ============================================================================
// Crypto Audit Types
// ============================================================================

export type CryptoFinding = {
  type: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  recommendation: string;
  file: string;
  line: number;
  match: string;
  context?: string;
};

export type CryptoGoodPractice = {
  type: string;
  file: string;
  line: number;
  match: string;
};

export type CryptoAuditMethod = {
  type: string;
  algorithm: string;
  file: string;
  line: number;
};

export type CryptoAuditResult = {
  total_findings: number;
  findings: CryptoFinding[];
  by_severity: Record<string, CryptoFinding[]>;
  by_category: Record<string, CryptoFinding[]>;
  good_practices: CryptoGoodPractice[];
  crypto_methods: CryptoAuditMethod[];
  files_scanned: number;
  risk_score: number;
  grade: string;
  overall_risk: string;
  top_recommendations: string[];
  summary: string;
  error?: string;
};

// ============================================================================
// Component Map Types
// ============================================================================

export type ActivityComponentInfo = {
  name: string;
  full_name: string;
  exported: boolean;
  risk: string;
  launcher: boolean;
  actions: string[];
  categories: string[];
  data_schemes: string[];
  theme?: string;
  launch_mode: string;
};

export type ServiceComponentInfo = {
  name: string;
  full_name: string;
  exported: boolean;
  risk: string;
  actions: string[];
  permission?: string;
  foreground: boolean;
};

export type ReceiverComponentInfo = {
  name: string;
  full_name: string;
  exported: boolean;
  risk: string;
  actions: string[];
  permission?: string;
  system_broadcast: boolean;
};

export type ProviderComponentInfo = {
  name: string;
  full_name: string;
  exported: boolean;
  risk: string;
  authorities?: string;
  read_permission?: string;
  write_permission?: string;
  grant_uri_permissions: boolean;
};

export type ComponentDeepLink = {
  scheme: string;
  host?: string;
  path?: string;
  component: string;
  component_full: string;
  type: string;
};

export type ComponentConnection = {
  source: string;
  target: string;
  type: string;
};

export type ComponentMapResult = {
  package_name: string;
  components: {
    activities: ActivityComponentInfo[];
    services: ServiceComponentInfo[];
    receivers: ReceiverComponentInfo[];
    providers: ProviderComponentInfo[];
  };
  connections: ComponentConnection[];
  deep_links: ComponentDeepLink[];
  stats: {
    total_activities: number;
    total_services: number;
    total_receivers: number;
    total_providers: number;
    exported_activities: number;
    exported_services: number;
    exported_receivers: number;
    exported_providers: number;
    deep_links: number;
    connections: number;
  };
  risk_counts: Record<string, number>;
  attack_surface_score: number;
  summary: string;
  error?: string;
};

// ============================================================================
// Class Dependency Graph Types
// ============================================================================

export type DependencyGraphNode = {
  id: string;
  label: string;
  full_name: string;
  package: string;
  type: "activity" | "service" | "receiver" | "provider" | "fragment" | "adapter" | "interface" | "abstract" | "class";
  color: string;
  size: number;
  methods: number;
  lines: number;
  file_path: string;
};

export type DependencyGraphEdge = {
  from: string;
  to: string;
  type: "extends" | "implements" | "imports" | "calls";
  color: string;
  dashes?: boolean | number[];
  width?: number;
};

export type DependencyGraphStatistics = {
  total_classes: number;
  total_connections: number;
  node_types: Record<string, number>;
  edge_types: Record<string, number>;
  packages: Record<string, number>;
  hub_classes: Array<{ name: string; connections: number }>;
};

export type DependencyGraphResult = {
  nodes: DependencyGraphNode[];
  edges: DependencyGraphEdge[];
  statistics: DependencyGraphStatistics;
  legend: {
    node_colors: Record<string, string>;
    edge_types: Record<string, string>;
  };
  error?: string;
};

// ============================================================================
// Symbol Lookup Types (Jump to Definition)
// ============================================================================

export type SymbolResult = {
  type: "class" | "method" | "field";
  name: string;
  file: string;
  line: number;
  package?: string;
  full_name?: string;
  class?: string;
  signature?: string;
  return_type?: string;
  params?: string;
  field_type?: string;
};

export type SymbolLookupResult = {
  symbol: string;
  results: SymbolResult[];
  total_found: number;
  index_stats: {
    classes: number;
    methods: number;
    fields: number;
    files_indexed: number;
  };
  error?: string;
};
