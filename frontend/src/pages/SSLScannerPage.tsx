import React, { useState, useRef, useEffect } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  TextField,
  Paper,
  Chip,
  Alert,
  CircularProgress,
  alpha,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Collapse,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress,
  Divider,
  Menu,
  MenuItem,
  ListItemText,
  Tabs,
  Tab,
  useTheme,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from "@mui/material";
import { Link } from "react-router-dom";
import LockIcon from "@mui/icons-material/Lock";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import InfoIcon from "@mui/icons-material/Info";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import PortableWifiOffIcon from "@mui/icons-material/PortableWifiOff";
import BugReportIcon from "@mui/icons-material/BugReport";
import LinkIcon from "@mui/icons-material/Link";
import GppBadIcon from "@mui/icons-material/GppBad";
import DownloadIcon from "@mui/icons-material/Download";
import DescriptionIcon from "@mui/icons-material/Description";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import ArticleIcon from "@mui/icons-material/Article";
import TerminalIcon from "@mui/icons-material/Terminal";
import TargetIcon from "@mui/icons-material/GpsFixed";
import ChatIcon from "@mui/icons-material/Chat";
import SendIcon from "@mui/icons-material/Send";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import PersonIcon from "@mui/icons-material/Person";
import OpenInFullIcon from "@mui/icons-material/OpenInFull";
import CloseFullscreenIcon from "@mui/icons-material/CloseFullscreen";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import ListAltIcon from "@mui/icons-material/ListAlt";
import HistoryIcon from "@mui/icons-material/History";
import VisibilityIcon from "@mui/icons-material/Visibility";
import HttpsIcon from "@mui/icons-material/Https";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import ReactMarkdown from "react-markdown";
import { ChatCodeBlock } from "../components/ChatCodeBlock";
import { apiClient } from "../api/client";

// Common SSL/TLS ports
const COMMON_SSL_PORTS = [
  { port: 443, name: "HTTPS" },
  { port: 8443, name: "HTTPS Alt" },
  { port: 993, name: "IMAPS" },
  { port: 995, name: "POP3S" },
  { port: 465, name: "SMTPS" },
  { port: 587, name: "SMTP/TLS" },
  { port: 636, name: "LDAPS" },
  { port: 989, name: "FTPS Data" },
  { port: 990, name: "FTPS Control" },
  { port: 3389, name: "RDP" },
  { port: 5061, name: "SIP/TLS" },
  { port: 6697, name: "IRC/TLS" },
  { port: 8883, name: "MQTT/TLS" },
  { port: 9443, name: "WSS Alt" },
];

interface ScanTarget {
  host: string;
  port: number;
}

interface SSLCertificate {
  subject: string | null;
  issuer: string | null;
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  is_expired: boolean;
  days_until_expiry: number | null;
  is_self_signed: boolean;
  signature_algorithm: string | null;
  key_type: string | null;
  key_size: number | null;
  san: string[];
}

interface SSLFinding {
  severity: string;
  category: string;
  title: string;
  description: string;
  recommendation: string | null;
  cve: string | null;
}

interface VulnerabilityInfo {
  vuln_id: string;
  cve: string;
  name: string;
  severity: string;
  description: string;
  affected: string;
  cvss: number;
  exploit_difficulty: string;
  is_exploitable: boolean;
  evidence: string;
}

interface ChainInfo {
  chain_length: number;
  is_complete: boolean;
  is_trusted: boolean;
  root_ca: string | null;
  chain_errors: string[];
  certificates: any[];
}

interface SecurityHeaders {
  hsts_enabled: boolean;
  hsts_max_age: number | null;
  hsts_include_subdomains: boolean;
  hsts_preload: boolean;
  hpkp_enabled: boolean;
  content_security_policy: boolean;
  x_frame_options: boolean;
  x_content_type_options: boolean;
  x_xss_protection: boolean;
  missing_headers: string[];
  issues: string[];
  score: number;
}

interface OCSPStatus {
  checked: boolean;
  status: string;  // good, revoked, unknown, error
  revocation_time: string | null;
  revocation_reason: string | null;
  ocsp_url: string | null;
  errors: string[];
}

// New TLS 1.3 Analysis interfaces
interface TLS13CipherInfo {
  name: string;
  code: number;
  strength: string;
  key_size: number;
  mode: string;
  supported: boolean;
}

interface TLS13Analysis {
  supported: boolean;
  cipher_suites: TLS13CipherInfo[];
  supports_0rtt: boolean;
  early_data_size: number | null;
  supported_groups: string[];
  has_aes_gcm: boolean;
  has_chacha20: boolean;
  score: number;
  issues: string[];
}

// CT Log Verification
interface SCTInfo {
  log_id: string;
  timestamp: string | null;
  signature_algorithm: string | null;
  is_valid: boolean;
  log_name: string | null;
}

interface CTLogVerification {
  has_scts: boolean;
  sct_count: number;
  scts: SCTInfo[];
  embedded_in_cert: boolean;
  via_tls_extension: boolean;
  via_ocsp: boolean;
  all_valid: boolean;
  verified_logs: string[];
  issues: string[];
}

// Cipher Ordering Analysis
interface CipherOrderingAnalysis {
  server_enforces_order: boolean;
  client_order_honored: boolean;
  server_preferred_cipher: string | null;
  client_preferred_cipher: string | null;
  strongest_first: boolean;
  pfs_prioritized: boolean;
  weak_ciphers_deprioritized: boolean;
  cipher_order: any[];
  score: number;
  issues: string[];
  recommendations: string[];
}

// Session Ticket Analysis
interface SessionTicketAnalysis {
  supports_session_tickets: boolean;
  supports_session_ids: boolean;
  supports_0rtt: boolean;
  early_data_accepted: boolean;
  max_early_data_size: number | null;
  ticket_lifetime: number | null;
  replay_protection: boolean;
  issues: string[];
  recommendations: string[];
}

// SNI Mismatch Analysis
interface SNIMismatchAnalysis {
  requires_sni: boolean;
  sni_supported: boolean;
  default_cert_cn: string | null;
  requested_cert_cn: string | null;
  certificates_differ: boolean;
  vulnerable_to_confusion: boolean;
  allows_domain_fronting: boolean;
  virtual_host_detected: boolean;
  alternate_names: string[];
  risk_level: string;
  issues: string[];
}

// Protocol & Attack Detection Interfaces
interface DowngradeAttackAnalysis {
  poodle_sslv3_vulnerable: boolean;
  poodle_tls_vulnerable: boolean;
  freak_vulnerable: boolean;
  export_ciphers_supported: string[];
  logjam_vulnerable: boolean;
  weak_dh_params: boolean;
  dh_key_size: number | null;
  drown_vulnerable: boolean;
  sslv2_supported: boolean;
  supports_fallback_scsv: boolean;
  vulnerable_to_downgrade: boolean;
  risk_level: string;
  cve_ids: string[];
  issues: string[];
  recommendations: string[];
}

interface HeartbleedAnalysis {
  vulnerable: boolean;
  tested: boolean;
  tls_versions_tested: string[];
  memory_leaked: boolean;
  leak_size: number;
  cve_id: string;
  risk_level: string;
  issues: string[];
  recommendations: string[];
}

interface ROBOTAnalysis {
  vulnerable: boolean;
  oracle_type: string | null;
  tested: boolean;
  rsa_key_exchange_supported: boolean;
  vulnerable_ciphers: string[];
  cve_id: string;
  risk_level: string;
  issues: string[];
  recommendations: string[];
}

interface RenegotiationAnalysis {
  secure_renegotiation_supported: boolean;
  client_initiated_allowed: boolean;
  vulnerable_to_dos: boolean;
  vulnerable_to_mitm: boolean;
  cve_ids: string[];
  risk_level: string;
  issues: string[];
  recommendations: string[];
}

interface Sweet32Analysis {
  vulnerable: boolean;
  weak_block_ciphers: string[];
  triple_des_supported: boolean;
  blowfish_supported: boolean;
  idea_supported: boolean;
  cve_id: string;
  risk_level: string;
  issues: string[];
  recommendations: string[];
}

interface CompressionAttackAnalysis {
  crime_vulnerable: boolean;
  tls_compression_enabled: boolean;
  breach_vulnerable: boolean;
  http_compression_enabled: boolean;
  compression_methods: string[];
  spdy_compression: boolean;
  cve_ids: string[];
  risk_level: string;
  issues: string[];
  recommendations: string[];
}

interface ALPNAnalysis {
  alpn_supported: boolean;
  negotiated_protocol: string | null;
  supported_protocols: string[];
  http2_supported: boolean;
  http3_supported: boolean;
  grpc_supported: boolean;
  spdy_supported: boolean;
  issues: string[];
  recommendations: string[];
}

// === NEW ENHANCED ANALYSIS INTERFACES ===

// SSL Grade (like SSL Labs A+ to F)
interface SSLGrade {
  grade: string;
  numeric_score: number;
  grade_cap: string | null;
  cap_reasons: string[];
  deductions: Array<{ item: string; points: number; cap?: string; reason?: string; }>;
  grade_details: string;
  protocol_score: number;
  cipher_score: number;
  certificate_score: number;
  key_exchange_score: number;
}

// Mozilla TLS Compliance
interface MozillaComplianceResult {
  profile_tested: string;
  is_compliant: boolean;
  compliance_score: number;
  violations: Array<{ type: string; severity: string; issue: string; expected?: string; }>;
  recommendations: string[];
  protocol_compliance: boolean;
  cipher_compliance: boolean;
  certificate_compliance: boolean;
  hsts_compliance: boolean;
}

// Client Browser Compatibility
interface ClientCompatibilityResult {
  clients_tested: number;
  compatible_clients: Array<{ client: string; protocol: string | null; cipher: string | null; }>;
  incompatible_clients: Array<{ client: string; reason: string; }>;
  handshake_simulations: Array<{
    client_id: string;
    client_name: string;
    compatible: boolean;
    protocol_matched: string | null;
    cipher_matched: string | null;
    pq_support: boolean;
  }>;
}

// Post-Quantum Cryptography Analysis
interface PostQuantumAnalysis {
  pq_ready: boolean;
  hybrid_support: boolean;
  supported_kems: string[];
  supported_signatures: string[];
  nist_compliant: boolean;
  future_proof_score: number;
  recommendations: string[];
}

// STARTTLS Information
interface STARTTLSInfo {
  protocol: string;
  starttls_supported: boolean;
  starttls_required: boolean;
  plain_auth_before_tls: boolean;
  implicit_tls_supported: boolean;
  stripping_possible: boolean;
}

interface SSLScanResult {
  host: string;
  port: number;
  certificate: SSLCertificate | null;
  supported_protocols: string[];
  cipher_suites: string[];
  has_ssl: boolean;
  error: string | null;
  findings: SSLFinding[];
  vulnerabilities: VulnerabilityInfo[];
  chain_info: ChainInfo | null;
  security_headers: SecurityHeaders | null;
  ocsp_status: OCSPStatus | null;
  offensive_analysis: any | null;
  // New advanced analysis fields
  tls13_analysis: TLS13Analysis | null;
  ct_verification: CTLogVerification | null;
  cipher_ordering: CipherOrderingAnalysis | null;
  session_ticket_analysis: SessionTicketAnalysis | null;
  sni_analysis: SNIMismatchAnalysis | null;
  // Protocol & Attack Detection
  downgrade_attacks: DowngradeAttackAnalysis | null;
  heartbleed_analysis: HeartbleedAnalysis | null;
  robot_analysis: ROBOTAnalysis | null;
  renegotiation_analysis: RenegotiationAnalysis | null;
  sweet32_analysis: Sweet32Analysis | null;
  compression_attacks: CompressionAttackAnalysis | null;
  alpn_analysis: ALPNAnalysis | null;
  // NEW: Enhanced Analysis Features
  ssl_grade: SSLGrade | null;
  mozilla_compliance: MozillaComplianceResult | null;
  client_compatibility: ClientCompatibilityResult | null;
  post_quantum_analysis: PostQuantumAnalysis | null;
  starttls_info: STARTTLSInfo | null;
}

interface SSLScanSummary {
  total_hosts: number;
  hosts_with_ssl: number;
  expired_certs: number;
  self_signed_certs: number;
  weak_protocols: number;
  weak_ciphers: number;
  critical_findings: number;
  high_findings: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  exploitable_vulnerabilities: number;
  chain_issues: number;
}

interface ExploitationScenario {
  // Backend schema
  title?: string;
  target?: string;
  vulnerability?: string;
  difficulty?: string;
  prerequisites?: string;
  attack_steps?: string[];
  tools?: string[];
  expected_outcome?: string;
  detection_risk?: string;
  // Alternative frontend schema
  attack_name?: string;
  target_vulnerability?: string;
  exploit_difficulty?: string;
  required_tools?: string;
  example_commands?: string[];
  potential_impact?: string;
  indicators_of_compromise?: string[];
}

interface HighValueTarget {
  host: string;
  risk_level: string;
  weaknesses: string[];
  attack_priority: string;
  why_high_value: string;
  recommended_attack_vector: string;
}

interface ToolRecommendation {
  tool_name: string;
  purpose: string;
  target_host: string;
  usage_example?: string;
}

interface CertificateAttack {
  type: string;
  feasibility: string;
  description: string;
  target: string;
}

interface ProtocolAttack {
  vulnerability: string;
  target: string;
  exploitation_method: string;
  tools_required: string[];
}

interface AttackChainStep {
  order: number;
  action: string;
  target: string;
  expected_result: string;
}

interface QuickWin {
  target: string;
  attack: string;
  impact: string;
  command: string;
}

interface Recommendation {
  priority: string;
  action: string;
  rationale: string;
}

interface AIAnalysis {
  error?: string;
  structured_report?: {
    overall_risk_level?: string;
    risk_level?: string;
    risk_score?: number;
    executive_summary?: string;
    exploitation_scenarios?: ExploitationScenario[];
    high_value_targets?: HighValueTarget[];
    lateral_movement_opportunities?: any[];
    tool_recommendations?: ToolRecommendation[];
    quick_wins?: (string | QuickWin)[];
    certificate_attacks?: {
      summary?: string;
      attacks?: CertificateAttack[];
    };
    protocol_attacks?: {
      summary?: string;
      attacks?: ProtocolAttack[];
      total_vulnerable_hosts?: number;
      attacks_found?: Array<{
        host?: string;
        attack_type: string;
        cve?: string;
        severity?: string;
        exploit_available?: boolean;
        exploitation_steps?: string[];
        tools?: string[];
      }>;
      crypto_weaknesses?: string[];
    };
    recommended_attack_chain?: {
      description?: string;
      steps?: AttackChainStep[];
      total_effort?: string;
    };
    recommendations?: Recommendation[];
    // New AI report fields
    threat_assessment?: {
      overall_risk?: string;
      risk_score?: number;
      is_likely_malicious?: boolean;
      confidence?: number;
      summary?: string;
    };
    malware_indicators?: {
      c2_indicators_found?: boolean;
      details?: Array<{
        host?: string;
        indicator_type?: string;
        matched_threat?: string;
        confidence?: string;
      }>;
      recommendation?: string;
    };
    interception_analysis?: {
      can_intercept?: boolean;
      hosts_interceptable?: number;
      methods?: Array<{
        host?: string;
        method?: string;
        difficulty?: string;
        tools?: string[];
      }>;
      setup_steps?: string[];
    };
    certificate_intelligence?: {
      suspicious_certs?: number;
      findings?: Array<{
        host?: string;
        issue?: string;
        ioc_value?: string;
      }>;
    };
    attack_opportunities?: Array<{
      target?: string;
      attack?: string;
      difficulty?: string;
      impact?: string;
      command?: string;
    }>;
    next_steps?: Array<{
      priority: number;
      action: string;
      rationale: string;
    }>;
  };
  raw_response?: string;
}

interface SSLScanResponse {
  results: SSLScanResult[];
  summary: SSLScanSummary;
  ai_analysis: AIAnalysis | null;
  report_id: number | null;
}

const SSLScannerPage: React.FC = () => {
  const [targets, setTargets] = useState<ScanTarget[]>([{ host: "", port: 443 }]);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<SSLScanResponse | null>(null);
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const [portsMenuAnchor, setPortsMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedTargetIndex, setSelectedTargetIndex] = useState<number>(0);
  const [aiTabValue, setAiTabValue] = useState(0);
  const [exporting, setExporting] = useState<string | null>(null);

  // Main page tab state (New Scan | History)
  const [mainTabValue, setMainTabValue] = useState(0);
  
  // History state
  const [historyScans, setHistoryScans] = useState<Array<{
    id: number;
    title: string;
    targets: string;
    created_at: string;
    risk_level: string | null;
    risk_score: number | null;
    total_hosts: number | null;
    findings_count: number;
    project_id: number | null;
    project_name: string | null;
  }>>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selectedHistoryScan, setSelectedHistoryScan] = useState<any>(null);
  const [historyDetailLoading, setHistoryDetailLoading] = useState(false);

  // Bulk import state
  const [bulkImportOpen, setBulkImportOpen] = useState(false);
  const [bulkImportText, setBulkImportText] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // AI Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMaximized, setChatMaximized] = useState(false);
  const [chatMessages, setChatMessages] = useState<Array<{ role: "user" | "assistant"; content: string }>>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // JARM Database state
  const [jarmSearchOpen, setJarmSearchOpen] = useState(false);
  const [jarmSearchQuery, setJarmSearchQuery] = useState("");

  // User Guide state
  const [guideOpen, setGuideOpen] = useState(false);

  const theme = useTheme();

  // JARM Signature Database (subset for frontend search)
  const JARM_DATABASE = [
    { fingerprint: "07d14d16d21d21d07c42d41d00041d24", name: "Cobalt Strike", type: "c2_framework", severity: "critical" },
    { fingerprint: "07d14d16d21d21d00042d41d00041de5", name: "Cobalt Strike (Malleable)", type: "c2_framework", severity: "critical" },
    { fingerprint: "07d14d16d21d21d07c07d14d07d21d9b", name: "Cobalt Strike (Amazon)", type: "c2_framework", severity: "critical" },
    { fingerprint: "2ad2ad16d2ad2ad00042d42d00042d5a", name: "Metasploit", type: "c2_framework", severity: "critical" },
    { fingerprint: "29d29d00029d29d00042d42d000000d7", name: "Sliver C2", type: "c2_framework", severity: "critical" },
    { fingerprint: "29d29d00029d29d21c29d29d29d29dce", name: "Mythic C2", type: "c2_framework", severity: "critical" },
    { fingerprint: "29d29d00029d29d21c42d42d00041d9f", name: "Empire", type: "c2_framework", severity: "critical" },
    { fingerprint: "29d29d00029d29d00029d29d29d29d7f", name: "Covenant", type: "c2_framework", severity: "critical" },
    { fingerprint: "00000000000000000041d41d000000d9", name: "Havoc C2", type: "c2_framework", severity: "critical" },
    { fingerprint: "27d3ed3ed0003ed00042d43d00041df3", name: "Brute Ratel C4", type: "c2_framework", severity: "critical" },
    { fingerprint: "29d29d00029d29d00029d29d29d29dc5", name: "Merlin C2", type: "c2_framework", severity: "critical" },
    { fingerprint: "2ad2ad0002ad2ad00042d42d00000069", name: "PoshC2", type: "c2_framework", severity: "high" },
    { fingerprint: "07d14d16d21d21d00042d42d00042d4a", name: "Nighthawk", type: "c2_framework", severity: "critical" },
    { fingerprint: "29d29d00029d29d21c29d29d29d29dbc", name: "IcedID", type: "malware", severity: "critical" },
    { fingerprint: "2ad2ad00029d29d00029d29d29d29de7", name: "BazarLoader", type: "malware", severity: "critical" },
    { fingerprint: "2ad2ad0002ad2ad00042d42d00042d7f", name: "Dridex", type: "malware", severity: "critical" },
    { fingerprint: "29d29d00029d29d00042d42d00041d6b", name: "Emotet", type: "malware", severity: "critical" },
    { fingerprint: "2ad2ad0002ad2ad00041d41d00041d89", name: "TrickBot", type: "malware", severity: "critical" },
    { fingerprint: "29d29d00029d29d21c42d42d00042da7", name: "Qakbot", type: "malware", severity: "critical" },
    { fingerprint: "27d40d40d29d40d1dc42d43d00041d46", name: "nginx", type: "webserver", severity: "info" },
    { fingerprint: "29d29d00029d29d00041d41d00041d2a", name: "Apache", type: "webserver", severity: "info" },
    { fingerprint: "2ad2ad0002ad2ad22c42d42d00042d58", name: "IIS", type: "webserver", severity: "info" },
    { fingerprint: "29d3fd00029d29d00029d3fd29d29d6d", name: "Cloudflare", type: "cdn", severity: "info" },
    { fingerprint: "27d27d27d29d27d1dc41d43d00041d4b", name: "AWS ALB", type: "loadbalancer", severity: "info" },
  ];

  const filteredJarmSignatures = JARM_DATABASE.filter(sig =>
    jarmSearchQuery === "" ||
    sig.name.toLowerCase().includes(jarmSearchQuery.toLowerCase()) ||
    sig.fingerprint.toLowerCase().includes(jarmSearchQuery.toLowerCase()) ||
    sig.type.toLowerCase().includes(jarmSearchQuery.toLowerCase())
  );

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages]);

  // Load history when switching to history tab
  useEffect(() => {
    if (mainTabValue === 1) {
      loadHistory();
    }
  }, [mainTabValue]);

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const data = await apiClient.getSSLScanHistory();
      setHistoryScans(data.scans);
      setHistoryTotal(data.total);
    } catch (err: any) {
      console.error("Failed to load history:", err);
    } finally {
      setHistoryLoading(false);
    }
  };

  const loadHistoryScanDetail = async (scanId: number) => {
    setHistoryDetailLoading(true);
    try {
      const data = await apiClient.getSSLScanDetail(scanId);
      setSelectedHistoryScan(data);
    } catch (err: any) {
      console.error("Failed to load scan detail:", err);
    } finally {
      setHistoryDetailLoading(false);
    }
  };

  const handleDeleteHistoryScan = async (scanId: number) => {
    if (!confirm("Are you sure you want to delete this scan?")) return;
    try {
      await apiClient.deleteSSLScan(scanId);
      setHistoryScans(historyScans.filter(s => s.id !== scanId));
      if (selectedHistoryScan?.id === scanId) {
        setSelectedHistoryScan(null);
      }
    } catch (err: any) {
      console.error("Failed to delete scan:", err);
    }
  };

  const getRiskColor = (level: string | null) => {
    if (!level) return theme.palette.grey[500];
    switch (level.toLowerCase()) {
      case "critical": return "#dc2626";
      case "high": return "#ea580c";
      case "medium": return "#ca8a04";
      case "low": return "#16a34a";
      default: return theme.palette.grey[500];
    }
  };

  const addTarget = () => {
    setTargets([...targets, { host: "", port: 443 }]);
  };

  const removeTarget = (index: number) => {
    if (targets.length > 1) {
      setTargets(targets.filter((_, i) => i !== index));
    }
  };

  const updateTarget = (index: number, field: "host" | "port", value: string | number) => {
    const newTargets = [...targets];
    newTargets[index] = { ...newTargets[index], [field]: value };
    setTargets(newTargets);
  };

  // Bulk import: Parse host:port format from text
  const parseBulkImport = (text: string): ScanTarget[] => {
    const lines = text.split(/[\n,;]+/).map(line => line.trim()).filter(Boolean);
    const parsedTargets: ScanTarget[] = [];
    
    for (const line of lines) {
      // Skip comments and empty lines
      if (line.startsWith('#') || line.startsWith('//')) continue;
      
      // Parse formats: host:port, host port, or just host (default 443)
      const match = line.match(/^([a-zA-Z0-9.-]+)(?:[:|\s]+(\d+))?$/);
      if (match) {
        const host = match[1];
        const port = match[2] ? parseInt(match[2], 10) : 443;
        if (host && port > 0 && port <= 65535) {
          parsedTargets.push({ host, port });
        }
      }
    }
    
    return parsedTargets;
  };

  // Handle file upload for bulk import
  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setBulkImportText(content);
    };
    reader.readAsText(file);
    
    // Reset input so same file can be selected again
    event.target.value = '';
  };

  // Apply bulk import
  const applyBulkImport = () => {
    const parsed = parseBulkImport(bulkImportText);
    if (parsed.length === 0) {
      setError("No valid targets found. Use format: host:port (one per line)");
      return;
    }
    setTargets(parsed);
    setBulkImportOpen(false);
    setBulkImportText("");
  };

  // Export to CSV for bulk analysis
  const handleCSVExport = () => {
    if (!results?.results || results.results.length === 0) {
      setError("No scan results to export");
      return;
    }

    // Build CSV content
    const headers = [
      "Host",
      "Port",
      "Has SSL",
      "Certificate Subject",
      "Certificate Issuer",
      "Not Before",
      "Not After",
      "Days Until Expiry",
      "Is Expired",
      "Is Self Signed",
      "Signature Algorithm",
      "Key Type",
      "Key Size",
      "Protocols Supported",
      "Cipher Suites",
      "Critical Findings",
      "High Findings",
      "Medium Findings",
      "Low Findings",
      "HSTS Enabled",
      "HSTS Score",
      "OCSP Status",
      "TLS 1.3 Supported",
      "TLS 1.3 Score",
      "CT SCT Count",
      "Cipher Order Enforced",
      "PFS Prioritized",
      "SNI Risk Level",
      "Domain Fronting Possible",
      "Error"
    ];

    const rows = results.results.map((r: SSLScanResult) => {
      const cert = r.certificate;
      const criticalFindings = r.findings?.filter(f => f.severity === "critical").length || 0;
      const highFindings = r.findings?.filter(f => f.severity === "high").length || 0;
      const mediumFindings = r.findings?.filter(f => f.severity === "medium").length || 0;
      const lowFindings = r.findings?.filter(f => f.severity === "low").length || 0;

      return [
        r.host,
        r.port,
        r.has_ssl ? "Yes" : "No",
        cert?.subject || "",
        cert?.issuer || "",
        cert?.not_before || "",
        cert?.not_after || "",
        cert?.days_until_expiry ?? "",
        cert?.is_expired ? "Yes" : "No",
        cert?.is_self_signed ? "Yes" : "No",
        cert?.signature_algorithm || "",
        cert?.key_type || "",
        cert?.key_size || "",
        r.supported_protocols?.join("; ") || "",
        r.cipher_suites?.slice(0, 5).join("; ") || "",
        criticalFindings,
        highFindings,
        mediumFindings,
        lowFindings,
        r.security_headers?.hsts_enabled ? "Yes" : "No",
        r.security_headers?.score ?? "",
        r.ocsp_status?.status || "",
        r.tls13_analysis?.supported ? "Yes" : "No",
        r.tls13_analysis?.score ?? "",
        r.ct_verification?.sct_count ?? "",
        r.cipher_ordering?.server_enforces_order ? "Yes" : "No",
        r.cipher_ordering?.pfs_prioritized ? "Yes" : "No",
        r.sni_analysis?.risk_level || "",
        r.sni_analysis?.allows_domain_fronting ? "Yes" : "No",
        r.error || ""
      ].map(val => {
        // Escape CSV values
        const str = String(val);
        if (str.includes(",") || str.includes('"') || str.includes("\n")) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      }).join(",");
    });

    const csvContent = [headers.join(","), ...rows].join("\n");
    
    // Download
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ssl_scan_results_${new Date().toISOString().split("T")[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();
  };

  // Export report to different formats
  const handleExport = async (format: "markdown" | "pdf" | "docx") => {
    if (!results?.report_id) {
      setError("No report to export. Run a scan first.");
      return;
    }

    setExporting(format);
    try {
      const response = await fetch(`/api/network/reports/${results.report_id}/export/${format}`);
      if (!response.ok) throw new Error("Export failed");
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = format === "markdown" ? "md" : format;
      a.download = `ssl_scan_report_${results.report_id}.${ext}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err: any) {
      setError(err.message || "Export failed");
    } finally {
      setExporting(null);
    }
  };

  // Export AI Analysis Report with proper formatting
  const exportAIReport = async (format: "markdown" | "pdf" | "docx") => {
    if (!results?.ai_analysis?.structured_report) {
      setError("No AI analysis available to export");
      return;
    }

    const report = results.ai_analysis.structured_report;
    const timestamp = new Date().toISOString().split("T")[0];
    
    // Generate formatted markdown content
    const generateMarkdownReport = () => {
      let md = `# 🔐 SSL/TLS Security Analysis Report\n\n`;
      md += `**Generated:** ${new Date().toLocaleString()}\n\n`;
      md += `---\n\n`;
      
      // Executive Summary
      md += `## 📋 Executive Summary\n\n`;
      if (report.threat_assessment) {
        md += `- **Overall Risk Level:** ${report.threat_assessment.overall_risk || report.overall_risk_level || "N/A"}\n`;
        md += `- **Risk Score:** ${report.threat_assessment.risk_score ?? report.risk_score ?? "N/A"}/100\n`;
        md += `- **Malicious Activity:** ${report.threat_assessment.is_likely_malicious ? "⚠️ Yes" : "✅ No"}\n`;
        md += `- **Confidence:** ${((report.threat_assessment.confidence || 0) * 100).toFixed(0)}%\n\n`;
        if (report.threat_assessment.summary) {
          md += `> ${report.threat_assessment.summary}\n\n`;
        }
      } else if (report.executive_summary) {
        md += `${report.executive_summary}\n\n`;
      }
      
      // Protocol & Attack Detection
      if (report.protocol_attacks) {
        md += `## ⚔️ Protocol & Attack Detection\n\n`;
        md += `**Vulnerable Hosts:** ${report.protocol_attacks.total_vulnerable_hosts || 0}\n\n`;
        
        if (Array.isArray(report.protocol_attacks.attacks_found) && report.protocol_attacks.attacks_found.length > 0) {
          md += `### Attacks Found\n\n`;
          md += `| Host | Attack Type | CVE | Severity | Exploitable |\n`;
          md += `|------|-------------|-----|----------|-------------|\n`;
          report.protocol_attacks.attacks_found.forEach((attack: any) => {
            md += `| ${attack.host || "N/A"} | **${attack.attack_type}** | ${attack.cve || "-"} | ${attack.severity || "N/A"} | ${attack.exploit_available ? "✅ Yes" : "❌ No"} |\n`;
          });
          md += `\n`;
          
          // Exploitation steps for each attack
          report.protocol_attacks.attacks_found.forEach((attack: any) => {
            if (Array.isArray(attack.exploitation_steps) && attack.exploitation_steps.length > 0) {
              md += `#### ${attack.attack_type} Exploitation Steps\n\n`;
              attack.exploitation_steps.forEach((step: string, i: number) => {
                md += `${i + 1}. ${step}\n`;
              });
              if (Array.isArray(attack.tools) && attack.tools.length > 0) {
                md += `\n**Tools:** \`${attack.tools.join("`, `")}\`\n`;
              }
              md += `\n`;
            }
          });
        }
        
        if (Array.isArray(report.protocol_attacks.crypto_weaknesses) && report.protocol_attacks.crypto_weaknesses.length > 0) {
          md += `### Cryptographic Weaknesses\n\n`;
          report.protocol_attacks.crypto_weaknesses.forEach((weakness: string) => {
            md += `- ⚠️ ${weakness}\n`;
          });
          md += `\n`;
        }
      }
      
      // Malware Indicators
      if (report.malware_indicators) {
        md += `## 🦠 Malware & C2 Indicators\n\n`;
        md += `**C2 Indicators Found:** ${report.malware_indicators.c2_indicators_found ? "⚠️ Yes" : "✅ No"}\n\n`;
        
        if (Array.isArray(report.malware_indicators.details) && report.malware_indicators.details.length > 0) {
          md += `### Indicator Details\n\n`;
          report.malware_indicators.details.forEach((detail: any) => {
            md += `- **${detail.host}**\n`;
            md += `  - Type: ${detail.indicator_type}\n`;
            md += `  - Matched Threat: ${detail.matched_threat}\n`;
            md += `  - Confidence: ${detail.confidence}\n\n`;
          });
        }
        
        if (report.malware_indicators.recommendation) {
          md += `**Recommendation:** ${report.malware_indicators.recommendation}\n\n`;
        }
      }
      
      // Interception Analysis
      if (report.interception_analysis) {
        md += `## 🕵️ Interception Analysis\n\n`;
        md += `**Can Intercept Traffic:** ${report.interception_analysis.can_intercept ? "✅ Yes" : "❌ No"}\n`;
        md += `**Interceptable Hosts:** ${report.interception_analysis.hosts_interceptable || 0}\n\n`;
        
        if (Array.isArray(report.interception_analysis.methods) && report.interception_analysis.methods.length > 0) {
          md += `### Interception Methods\n\n`;
          report.interception_analysis.methods.forEach((method: any) => {
            md += `#### ${method.host}\n\n`;
            md += `- **Method:** ${method.method}\n`;
            md += `- **Difficulty:** ${method.difficulty}\n`;
            if (Array.isArray(method.tools) && method.tools.length > 0) {
              md += `- **Tools:** \`${method.tools.join("`, `")}\`\n`;
            }
            md += `\n`;
          });
        }
        
        if (Array.isArray(report.interception_analysis.setup_steps) && report.interception_analysis.setup_steps.length > 0) {
          md += `### Setup Steps\n\n`;
          report.interception_analysis.setup_steps.forEach((step: string, i: number) => {
            md += `${i + 1}. ${step}\n`;
          });
          md += `\n`;
        }
      }
      
      // Certificate Intelligence
      if (report.certificate_intelligence) {
        md += `## 🔏 Certificate Intelligence\n\n`;
        md += `**Suspicious Certificates:** ${report.certificate_intelligence.suspicious_certs || 0}\n\n`;
        
        if (Array.isArray(report.certificate_intelligence.findings) && report.certificate_intelligence.findings.length > 0) {
          md += `### Findings\n\n`;
          md += `| Host | Issue | IOC Value |\n`;
          md += `|------|-------|----------|\n`;
          report.certificate_intelligence.findings.forEach((finding: any) => {
            md += `| ${finding.host || "N/A"} | ${finding.issue || "N/A"} | \`${finding.ioc_value || "N/A"}\` |\n`;
          });
          md += `\n`;
        }
      }
      
      // Attack Opportunities
      if (Array.isArray(report.attack_opportunities) && report.attack_opportunities.length > 0) {
        md += `## 🎯 Attack Opportunities\n\n`;
        report.attack_opportunities.forEach((opp: any, i: number) => {
          md += `### ${i + 1}. ${opp.attack || opp.target}\n\n`;
          md += `- **Target:** ${opp.target}\n`;
          md += `- **Difficulty:** ${opp.difficulty}\n`;
          md += `- **Impact:** ${opp.impact}\n`;
          if (opp.command) {
            md += `- **Example Command:**\n\`\`\`bash\n${opp.command}\n\`\`\`\n`;
          }
          md += `\n`;
        });
      }
      
      // Exploitation Scenarios
      if (Array.isArray(report.exploitation_scenarios) && report.exploitation_scenarios.length > 0) {
        md += `## 💀 Exploitation Scenarios\n\n`;
        report.exploitation_scenarios.forEach((scenario: any, i: number) => {
          md += `### ${i + 1}. ${scenario.title || scenario.attack_name || "Attack Scenario"}\n\n`;
          md += `- **Target:** ${scenario.target || scenario.target_vulnerability || "N/A"}\n`;
          md += `- **Vulnerability:** ${scenario.vulnerability || "N/A"}\n`;
          md += `- **Difficulty:** ${scenario.difficulty || scenario.exploit_difficulty || "Unknown"}\n`;
          md += `- **Detection Risk:** ${scenario.detection_risk || "Unknown"}\n\n`;
          
          if (scenario.prerequisites) {
            md += `**Prerequisites:** ${scenario.prerequisites}\n\n`;
          }
          
          if (Array.isArray(scenario.attack_steps) && scenario.attack_steps.length > 0) {
            md += `**Attack Steps:**\n\n`;
            scenario.attack_steps.forEach((step: string, j: number) => {
              md += `${j + 1}. ${step}\n`;
            });
            md += `\n`;
          }
          
          if (Array.isArray(scenario.tools) && scenario.tools.length > 0) {
            md += `**Tools:** \`${scenario.tools.join("`, `")}\`\n\n`;
          }
          
          if (scenario.expected_outcome) {
            md += `**Expected Outcome:** ${scenario.expected_outcome}\n\n`;
          }
        });
      }
      
      // Next Steps
      if (Array.isArray(report.next_steps) && report.next_steps.length > 0) {
        md += `## 📌 Recommended Next Steps\n\n`;
        report.next_steps.forEach((step: any) => {
          md += `### Priority ${step.priority}: ${step.action}\n\n`;
          md += `*${step.rationale}*\n\n`;
        });
      }
      
      md += `---\n\n`;
      md += `*Report generated by VRAgent SSL/TLS Scanner with AI Analysis*\n`;
      
      return md;
    };

    const markdownContent = generateMarkdownReport();

    if (format === "markdown") {
      // Download as markdown
      const blob = new Blob([markdownContent], { type: "text/markdown;charset=utf-8" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ssl_ai_report_${timestamp}.md`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } else if (format === "pdf") {
      // Generate PDF using html2canvas and jspdf
      try {
        const { jsPDF } = await import("jspdf");
        const pdf = new jsPDF("p", "mm", "a4");
        const pageWidth = pdf.internal.pageSize.getWidth();
        const pageHeight = pdf.internal.pageSize.getHeight();
        const margin = 15;
        const lineHeight = 6;
        let y = margin;

        // Helper function to add text with word wrap
        const addText = (text: string, fontSize: number, isBold: boolean = false, color: [number, number, number] = [0, 0, 0]) => {
          pdf.setFontSize(fontSize);
          pdf.setFont("helvetica", isBold ? "bold" : "normal");
          pdf.setTextColor(color[0], color[1], color[2]);
          const lines = pdf.splitTextToSize(text, pageWidth - margin * 2);
          lines.forEach((line: string) => {
            if (y > pageHeight - margin) {
              pdf.addPage();
              y = margin;
            }
            pdf.text(line, margin, y);
            y += lineHeight;
          });
        };

        const addHeading = (text: string, level: number) => {
          y += 4;
          const sizes = [18, 14, 12, 11];
          addText(text, sizes[level - 1] || 11, true);
          y += 2;
        };

        const addBullet = (text: string) => {
          if (y > pageHeight - margin) {
            pdf.addPage();
            y = margin;
          }
          pdf.setFontSize(10);
          pdf.setFont("helvetica", "normal");
          pdf.text("•", margin, y);
          const lines = pdf.splitTextToSize(text, pageWidth - margin * 2 - 5);
          lines.forEach((line: string, i: number) => {
            if (y > pageHeight - margin) {
              pdf.addPage();
              y = margin;
            }
            pdf.text(line, margin + 5, y);
            y += lineHeight - 1;
          });
        };

        // Title
        addHeading("SSL/TLS Security Analysis Report", 1);
        addText(`Generated: ${new Date().toLocaleString()}`, 10, false, [100, 100, 100]);
        y += 5;

        // Executive Summary
        addHeading("Executive Summary", 2);
        if (report.threat_assessment) {
          addBullet(`Overall Risk Level: ${report.threat_assessment.overall_risk || report.overall_risk_level || "N/A"}`);
          addBullet(`Risk Score: ${report.threat_assessment.risk_score ?? report.risk_score ?? "N/A"}/100`);
          addBullet(`Malicious Activity: ${report.threat_assessment.is_likely_malicious ? "Yes" : "No"}`);
          if (report.threat_assessment.summary) {
            y += 2;
            addText(report.threat_assessment.summary, 10, false, [60, 60, 60]);
          }
        }
        y += 3;

        // Protocol Attacks
        if (report.protocol_attacks) {
          addHeading("Protocol & Attack Detection", 2);
          addBullet(`Vulnerable Hosts: ${report.protocol_attacks.total_vulnerable_hosts || 0}`);
          if (Array.isArray(report.protocol_attacks.attacks_found)) {
            report.protocol_attacks.attacks_found.forEach((attack: any) => {
              addBullet(`${attack.attack_type} on ${attack.host} (${attack.severity || "N/A"})${attack.cve ? ` - ${attack.cve}` : ""}`);
            });
          }
          y += 3;
        }

        // Malware Indicators
        if (report.malware_indicators) {
          addHeading("Malware & C2 Indicators", 2);
          addBullet(`C2 Indicators Found: ${report.malware_indicators.c2_indicators_found ? "Yes" : "No"}`);
          if (Array.isArray(report.malware_indicators.details)) {
            report.malware_indicators.details.forEach((detail: any) => {
              addBullet(`${detail.host}: ${detail.indicator_type} - ${detail.matched_threat}`);
            });
          }
          y += 3;
        }

        // Attack Opportunities
        if (Array.isArray(report.attack_opportunities) && report.attack_opportunities.length > 0) {
          addHeading("Attack Opportunities", 2);
          report.attack_opportunities.forEach((opp: any, i: number) => {
            addBullet(`${opp.target}: ${opp.attack} (${opp.difficulty}) - ${opp.impact}`);
          });
          y += 3;
        }

        // Next Steps
        if (Array.isArray(report.next_steps) && report.next_steps.length > 0) {
          addHeading("Recommended Next Steps", 2);
          report.next_steps.forEach((step: any) => {
            addBullet(`Priority ${step.priority}: ${step.action}`);
          });
        }

        pdf.save(`ssl_ai_report_${timestamp}.pdf`);
      } catch (err) {
        console.error("PDF generation failed:", err);
        setError("PDF generation failed. Try Markdown export instead.");
      }
    } else if (format === "docx") {
      // Generate DOCX using docx library
      try {
        const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, BorderStyle } = await import("docx");
        
        const children: any[] = [];
        
        // Title
        children.push(
          new Paragraph({
            text: "SSL/TLS Security Analysis Report",
            heading: HeadingLevel.TITLE,
            alignment: AlignmentType.CENTER,
          })
        );
        children.push(
          new Paragraph({
            children: [new TextRun({ text: `Generated: ${new Date().toLocaleString()}`, italics: true, color: "666666" })],
            alignment: AlignmentType.CENTER,
          })
        );
        children.push(new Paragraph({ text: "" }));

        // Executive Summary
        children.push(
          new Paragraph({ text: "Executive Summary", heading: HeadingLevel.HEADING_1 })
        );
        if (report.threat_assessment) {
          children.push(
            new Paragraph({
              children: [
                new TextRun({ text: "Overall Risk Level: ", bold: true }),
                new TextRun({ text: report.threat_assessment.overall_risk || report.overall_risk_level || "N/A" }),
              ],
              bullet: { level: 0 },
            })
          );
          children.push(
            new Paragraph({
              children: [
                new TextRun({ text: "Risk Score: ", bold: true }),
                new TextRun({ text: `${report.threat_assessment.risk_score ?? report.risk_score ?? "N/A"}/100` }),
              ],
              bullet: { level: 0 },
            })
          );
          children.push(
            new Paragraph({
              children: [
                new TextRun({ text: "Malicious Activity: ", bold: true }),
                new TextRun({ 
                  text: report.threat_assessment.is_likely_malicious ? "Yes" : "No",
                  color: report.threat_assessment.is_likely_malicious ? "CC0000" : "008800"
                }),
              ],
              bullet: { level: 0 },
            })
          );
          if (report.threat_assessment.summary) {
            children.push(
              new Paragraph({
                children: [new TextRun({ text: report.threat_assessment.summary, italics: true })],
                border: { left: { color: "CCCCCC", size: 12, style: BorderStyle.SINGLE } },
                indent: { left: 400 },
              })
            );
          }
        }
        children.push(new Paragraph({ text: "" }));

        // Protocol Attacks
        if (report.protocol_attacks) {
          children.push(
            new Paragraph({ text: "Protocol & Attack Detection", heading: HeadingLevel.HEADING_1 })
          );
          children.push(
            new Paragraph({
              children: [
                new TextRun({ text: "Vulnerable Hosts: ", bold: true }),
                new TextRun({ text: `${report.protocol_attacks.total_vulnerable_hosts || 0}` }),
              ],
              bullet: { level: 0 },
            })
          );
          if (Array.isArray(report.protocol_attacks.attacks_found)) {
            report.protocol_attacks.attacks_found.forEach((attack: any) => {
              children.push(
                new Paragraph({
                  children: [
                    new TextRun({ text: attack.attack_type, bold: true, color: "CC0000" }),
                    new TextRun({ text: ` on ${attack.host}` }),
                    new TextRun({ text: ` (${attack.severity || "N/A"})`, italics: true }),
                    attack.cve ? new TextRun({ text: ` - ${attack.cve}`, color: "666666" }) : new TextRun({ text: "" }),
                  ],
                  bullet: { level: 1 },
                })
              );
            });
          }
          children.push(new Paragraph({ text: "" }));
        }

        // Malware Indicators
        if (report.malware_indicators) {
          children.push(
            new Paragraph({ text: "Malware & C2 Indicators", heading: HeadingLevel.HEADING_1 })
          );
          children.push(
            new Paragraph({
              children: [
                new TextRun({ text: "C2 Indicators Found: ", bold: true }),
                new TextRun({ 
                  text: report.malware_indicators.c2_indicators_found ? "Yes" : "No",
                  color: report.malware_indicators.c2_indicators_found ? "CC0000" : "008800"
                }),
              ],
              bullet: { level: 0 },
            })
          );
          if (Array.isArray(report.malware_indicators.details)) {
            report.malware_indicators.details.forEach((detail: any) => {
              children.push(
                new Paragraph({
                  children: [
                    new TextRun({ text: detail.host, bold: true }),
                    new TextRun({ text: `: ${detail.indicator_type} - ${detail.matched_threat}` }),
                  ],
                  bullet: { level: 1 },
                })
              );
            });
          }
          children.push(new Paragraph({ text: "" }));
        }

        // Attack Opportunities
        if (Array.isArray(report.attack_opportunities) && report.attack_opportunities.length > 0) {
          children.push(
            new Paragraph({ text: "Attack Opportunities", heading: HeadingLevel.HEADING_1 })
          );
          report.attack_opportunities.forEach((opp: any) => {
            children.push(
              new Paragraph({
                children: [
                  new TextRun({ text: opp.target, bold: true }),
                  new TextRun({ text: `: ${opp.attack}` }),
                  new TextRun({ text: ` (${opp.difficulty})`, italics: true }),
                  new TextRun({ text: ` - ${opp.impact}` }),
                ],
                bullet: { level: 0 },
              })
            );
          });
          children.push(new Paragraph({ text: "" }));
        }

        // Next Steps
        if (Array.isArray(report.next_steps) && report.next_steps.length > 0) {
          children.push(
            new Paragraph({ text: "Recommended Next Steps", heading: HeadingLevel.HEADING_1 })
          );
          report.next_steps.forEach((step: any) => {
            children.push(
              new Paragraph({
                children: [
                  new TextRun({ text: `Priority ${step.priority}: `, bold: true }),
                  new TextRun({ text: step.action }),
                ],
                bullet: { level: 0 },
              })
            );
            children.push(
              new Paragraph({
                children: [new TextRun({ text: step.rationale, italics: true, color: "666666" })],
                indent: { left: 720 },
              })
            );
          });
        }

        const doc = new Document({
          sections: [{ properties: {}, children }],
        });

        const blob = await Packer.toBlob(doc);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `ssl_ai_report_${timestamp}.docx`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
      } catch (err) {
        console.error("DOCX generation failed:", err);
        setError("DOCX generation failed. Try Markdown export instead.");
      }
    }
  };

  // Add multiple ports for the same host
  const addCommonPorts = (host: string) => {
    if (!host.trim()) {
      setError("Please enter a host first");
      return;
    }
    const newTargets = COMMON_SSL_PORTS.map((p) => ({ host: host.trim(), port: p.port }));
    setTargets(newTargets);
  };

  // Parse port input that may contain ranges or comma-separated values
  const parsePortInput = (index: number, portStr: string) => {
    const host = targets[index].host;
    if (!host.trim()) {
      updateTarget(index, "port", parseInt(portStr) || 443);
      return;
    }

    // Check for comma-separated ports (e.g., "443,8443,993")
    if (portStr.includes(",")) {
      const ports = portStr.split(",").map((p) => parseInt(p.trim())).filter((p) => !isNaN(p) && p > 0 && p <= 65535);
      if (ports.length > 0) {
        const newTargets = [...targets];
        newTargets.splice(index, 1); // Remove current target
        const newEntries = ports.map((port) => ({ host: host.trim(), port }));
        newTargets.splice(index, 0, ...newEntries);
        setTargets(newTargets);
        return;
      }
    }

    // Check for port range (e.g., "443-445")
    if (portStr.includes("-")) {
      const [startStr, endStr] = portStr.split("-");
      const start = parseInt(startStr.trim());
      const end = parseInt(endStr.trim());
      if (!isNaN(start) && !isNaN(end) && start > 0 && end <= 65535 && start <= end && (end - start) <= 100) {
        const newTargets = [...targets];
        newTargets.splice(index, 1);
        const newEntries: ScanTarget[] = [];
        for (let port = start; port <= end; port++) {
          newEntries.push({ host: host.trim(), port });
        }
        newTargets.splice(index, 0, ...newEntries);
        setTargets(newTargets);
        return;
      }
    }

    // Single port
    updateTarget(index, "port", parseInt(portStr) || 443);
  };

  const handlePortsMenuOpen = (event: React.MouseEvent<HTMLElement>, index: number) => {
    setPortsMenuAnchor(event.currentTarget);
    setSelectedTargetIndex(index);
  };

  const handlePortsMenuClose = () => {
    setPortsMenuAnchor(null);
  };

  const handleSelectPort = (port: number) => {
    updateTarget(selectedTargetIndex, "port", port);
    handlePortsMenuClose();
  };

  const handleScan = async () => {
    const validTargets = targets.filter((t) => t.host.trim() !== "");
    if (validTargets.length === 0) {
      setError("Please enter at least one target host");
      return;
    }

    setScanning(true);
    setError(null);
    setResults(null);

    try {
      const response = await apiClient.scanSSL({
        targets: validTargets,
        timeout: 10,
        include_ai: true,
      });
      setResults(response);
    } catch (err: any) {
      setError(err.message || "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "#dc2626";
      case "high":
        return "#ea580c";
      case "medium":
        return "#ca8a04";
      case "low":
        return "#16a34a";
      default:
        return "#6b7280";
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return <ErrorIcon sx={{ color: "#dc2626" }} />;
      case "high":
        return <WarningIcon sx={{ color: "#ea580c" }} />;
      case "medium":
        return <WarningIcon sx={{ color: "#ca8a04" }} />;
      case "low":
        return <InfoIcon sx={{ color: "#16a34a" }} />;
      default:
        return <InfoIcon sx={{ color: "#6b7280" }} />;
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "N/A";
    try {
      return new Date(dateStr).toLocaleDateString();
    } catch {
      return dateStr;
    }
  };

  // AI Chat send function
  const handleChatSend = async () => {
    if (!chatInput.trim() || chatLoading) return;

    const userMessage = chatInput.trim();
    setChatInput("");
    setChatMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setChatLoading(true);
    setChatError(null);

    try {
      // Build context from SSL scan results
      const context = results
        ? `SSL/TLS Scan Results Summary:
Hosts Scanned: ${results.results?.length || 0}
${results.results?.map((host) => `
Host: ${host.host}:${host.port}
Certificate: ${host.certificate?.subject || "N/A"}
Issuer: ${host.certificate?.issuer || "N/A"}
Valid Until: ${host.certificate?.not_after || "N/A"}
Protocols: ${host.supported_protocols?.join(", ") || "N/A"}
Findings: ${host.findings?.length || 0}
Vulnerabilities: ${host.vulnerabilities?.length || 0}
`).join("\n") || "No hosts scanned"}

Summary:
Total Hosts: ${results.summary?.total_hosts || 0}
Critical Findings: ${results.summary?.critical_findings || 0}
High Findings: ${results.summary?.high_findings || 0}
Vulnerabilities: ${results.summary?.total_vulnerabilities || 0}

AI Analysis:
${results.ai_analysis?.structured_report?.executive_summary || results.ai_analysis?.error || "No AI analysis available"}
`
        : "No scan results available yet.";

      const response = await fetch("/api/network/ssl/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userMessage,
          context: context,
          scan_results: results,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to get response");
      }

      const data = await response.json();
      setChatMessages((prev) => [
        ...prev,
        { role: "assistant", content: data.response || "No response received." },
      ]);
    } catch (err: any) {
      setChatError(err.message || "Failed to send message");
      setChatMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Sorry, I encountered an error processing your request. Please try again." },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Button
          component={Link}
          to="/dynamic"
          startIcon={<ArrowBackIcon />}
          sx={{ mb: 2 }}
        >
          Back to Network Hub
        </Button>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              background: `linear-gradient(135deg, #10b981 0%, #059669 100%)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <LockIcon sx={{ fontSize: 32, color: "white" }} />
          </Box>
          <Box>
            <Typography variant="h4" fontWeight={700}>
              SSL/TLS Scanner
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Analyze SSL/TLS configuration and certificate security
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <Chip
            icon={<HelpOutlineIcon sx={{ fontSize: 16 }} />}
            label="User Guide"
            clickable
            size="small"
            onClick={() => setGuideOpen(true)}
            sx={{
              background: alpha("#0891b2", 0.1),
              border: `1px solid ${alpha("#0891b2", 0.3)}`,
              color: "#22d3ee",
              fontWeight: 500,
              "&:hover": {
                background: alpha("#0891b2", 0.2),
              },
            }}
          />
          <Chip
            component={Link}
            to="/learn/ssl-tls"
            icon={<MenuBookIcon sx={{ fontSize: 16 }} />}
            label="Learn About SSL/TLS Security →"
            clickable
            size="small"
            sx={{
              background: alpha("#10b981", 0.1),
              border: `1px solid ${alpha("#10b981", 0.3)}`,
              color: "#34d399",
              fontWeight: 500,
              "&:hover": {
                background: alpha("#10b981", 0.2),
              },
            }}
          />
        </Box>
      </Box>

      {/* Main Page Tabs */}
      <Tabs 
        value={mainTabValue} 
        onChange={(_, v) => setMainTabValue(v)} 
        sx={{ 
          mb: 3,
          "& .MuiTab-root": { textTransform: "none", fontWeight: 600 }
        }}
      >
        <Tab icon={<PlayArrowIcon />} iconPosition="start" label="New Scan" />
        <Tab icon={<HistoryIcon />} iconPosition="start" label={`Scan History (${historyTotal})`} />
      </Tabs>

      {/* New Scan Tab */}
      {mainTabValue === 0 && (
        <>
      {/* Input Section */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
            Scan Targets
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Enter the hosts and ports to scan. The scanner will check certificate validity,
            protocol support, cipher strength, and common SSL/TLS vulnerabilities.
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ mb: 3, display: "block" }}>
            💡 Tip: Enter comma-separated ports (443,8443,993) or port ranges (443-445) to scan multiple ports at once
          </Typography>

          {targets.map((target, index) => (
            <Box key={index} sx={{ display: "flex", gap: 2, mb: 2, alignItems: "center" }}>
              <TextField
                label="Host"
                placeholder="example.com or 192.168.1.1"
                value={target.host}
                onChange={(e) => updateTarget(index, "host", e.target.value)}
                size="small"
                sx={{ flex: 1 }}
              />
              <TextField
                label="Port(s)"
                placeholder="443 or 443,8443 or 443-445"
                value={target.port}
                onChange={(e) => parsePortInput(index, e.target.value)}
                size="small"
                sx={{ width: 180 }}
              />
              <Tooltip title="Select common SSL port">
                <IconButton
                  onClick={(e) => handlePortsMenuOpen(e, index)}
                  size="small"
                  sx={{ color: "#10b981" }}
                >
                  <PortableWifiOffIcon />
                </IconButton>
              </Tooltip>
              <IconButton
                onClick={() => removeTarget(index)}
                disabled={targets.length === 1}
                color="error"
              >
                <DeleteIcon />
              </IconButton>
            </Box>
          ))}

          <Box sx={{ display: "flex", gap: 2, mt: 3, flexWrap: "wrap" }}>
            <Button startIcon={<AddIcon />} onClick={addTarget} variant="outlined">
              Add Target
            </Button>
            <Button 
              startIcon={<UploadFileIcon />} 
              onClick={() => setBulkImportOpen(true)} 
              variant="outlined"
              color="info"
            >
              Bulk Import
            </Button>
            <Button 
              startIcon={<BugReportIcon />} 
              onClick={() => setJarmSearchOpen(true)} 
              variant="outlined"
              color="warning"
            >
              JARM Database
            </Button>
            <Button 
              startIcon={<PortableWifiOffIcon />} 
              onClick={() => addCommonPorts(targets[0]?.host || "")} 
              variant="outlined"
              color="secondary"
            >
              Scan All Common SSL Ports
            </Button>
            <Button
              startIcon={scanning ? <CircularProgress size={20} /> : <PlayArrowIcon />}
              onClick={handleScan}
              variant="contained"
              disabled={scanning}
              sx={{
                background: `linear-gradient(135deg, #10b981 0%, #059669 100%)`,
                "&:hover": {
                  background: `linear-gradient(135deg, #059669 0%, #047857 100%)`,
                },
              }}
            >
              {scanning ? "Scanning..." : "Start Scan"}
            </Button>
          </Box>
          
          {/* Target count indicator */}
          {targets.length > 1 && (
            <Box sx={{ mt: 2 }}>
              <Chip 
                icon={<ListAltIcon />} 
                label={`${targets.length} targets configured`}
                size="small"
                color="primary"
                variant="outlined"
              />
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Bulk Import Dialog */}
      <Dialog open={bulkImportOpen} onClose={() => setBulkImportOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <UploadFileIcon color="primary" />
          Bulk Import Targets
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Import multiple hosts at once. Supported formats:
          </Typography>
          <Box component="ul" sx={{ mt: 0, mb: 2, pl: 2, color: "text.secondary" }}>
            <li><code>host:port</code> - e.g., example.com:443</li>
            <li><code>host port</code> - e.g., example.com 8443</li>
            <li><code>host</code> - defaults to port 443</li>
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ mb: 2, display: "block" }}>
            One entry per line. Lines starting with # are ignored.
          </Typography>
          
          <input
            type="file"
            accept=".txt,.csv"
            ref={fileInputRef}
            onChange={handleFileUpload}
            style={{ display: "none" }}
          />
          
          <Button
            variant="outlined"
            startIcon={<UploadFileIcon />}
            onClick={() => fileInputRef.current?.click()}
            sx={{ mb: 2 }}
            fullWidth
          >
            Upload File (.txt or .csv)
          </Button>
          
          <TextField
            label="Paste hosts here"
            placeholder="example.com:443&#10;192.168.1.1:8443&#10;internal.corp"
            value={bulkImportText}
            onChange={(e) => setBulkImportText(e.target.value)}
            multiline
            rows={8}
            fullWidth
            sx={{ fontFamily: "monospace" }}
          />
          
          {bulkImportText && (
            <Box sx={{ mt: 1 }}>
              <Chip 
                label={`${parseBulkImport(bulkImportText).length} valid targets detected`}
                size="small"
                color={parseBulkImport(bulkImportText).length > 0 ? "success" : "warning"}
              />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setBulkImportOpen(false); setBulkImportText(""); }}>
            Cancel
          </Button>
          <Button 
            onClick={applyBulkImport} 
            variant="contained" 
            disabled={!bulkImportText.trim()}
          >
            Import {parseBulkImport(bulkImportText).length} Targets
          </Button>
        </DialogActions>
      </Dialog>

      {/* User Guide Dialog */}
      <Dialog open={guideOpen} onClose={() => setGuideOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1, borderBottom: 1, borderColor: "divider" }}>
          <HelpOutlineIcon sx={{ color: "#0891b2" }} />
          SSL/TLS Scanner User Guide
        </DialogTitle>
        <DialogContent sx={{ p: 0 }}>
          <Box sx={{ p: 3 }}>
            {/* Quick Start */}
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2, color: "#0891b2" }}>
              🚀 Quick Start
            </Typography>
            <Typography variant="body2" sx={{ mb: 2 }}>
              Enter a hostname and port, then click <strong>Start Scan</strong>. The scanner will analyze
              SSL/TLS configuration, certificate validity, cipher strength, and check for vulnerabilities.
            </Typography>

            {/* Test Targets */}
            <Paper variant="outlined" sx={{ p: 2, mb: 3, bgcolor: alpha("#0891b2", 0.05) }}>
              <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                📋 Ready-to-Use Test Targets (Legal)
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
                These are public test servers specifically designed for SSL testing. Copy and paste into the scan form:
              </Typography>
              <Box 
                sx={{ 
                  fontFamily: "monospace", 
                  fontSize: "0.75rem", 
                  bgcolor: "background.paper", 
                  p: 1.5, 
                  borderRadius: 1,
                  border: 1,
                  borderColor: "divider",
                  whiteSpace: "pre-wrap",
                  position: "relative",
                }}
              >
                {`badssl.com:443
expired.badssl.com:443
self-signed.badssl.com:443
wrong.host.badssl.com:443
untrusted-root.badssl.com:443
sha1-intermediate.badssl.com:443
rc4.badssl.com:443
3des.badssl.com:443
tls-v1-0.badssl.com:1010
tls-v1-1.badssl.com:1011`}
                <IconButton
                  size="small"
                  onClick={() => {
                    navigator.clipboard.writeText(`badssl.com:443
expired.badssl.com:443
self-signed.badssl.com:443
wrong.host.badssl.com:443
untrusted-root.badssl.com:443
sha1-intermediate.badssl.com:443
rc4.badssl.com:443
3des.badssl.com:443
tls-v1-0.badssl.com:1010
tls-v1-1.badssl.com:1011`);
                  }}
                  sx={{ position: "absolute", top: 4, right: 4 }}
                >
                  <ContentCopyIcon fontSize="small" />
                </IconButton>
              </Box>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                💡 Use <strong>Bulk Import</strong> button to add all at once
              </Typography>
            </Paper>

            {/* What Gets Analyzed */}
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2, color: "#0891b2" }}>
              🔍 What Gets Analyzed
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                    <VerifiedUserIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "text-bottom" }} />
                    Certificate Security
                  </Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2, fontSize: "0.8rem" }}>
                    <li>Validity period & expiration</li>
                    <li>Certificate chain validation</li>
                    <li>Self-signed detection</li>
                    <li>Hostname matching</li>
                    <li>Key strength (RSA/ECDSA)</li>
                    <li>Signature algorithm</li>
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                    <HttpsIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "text-bottom" }} />
                    Protocol & Ciphers
                  </Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2, fontSize: "0.8rem" }}>
                    <li>TLS 1.0, 1.1, 1.2, 1.3 support</li>
                    <li>SSLv2/v3 detection (bad)</li>
                    <li>Weak cipher suites</li>
                    <li>Forward secrecy support</li>
                    <li>Cipher preference order</li>
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                    <BugReportIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "text-bottom" }} />
                    Vulnerability Detection
                  </Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2, fontSize: "0.8rem" }}>
                    <li>Heartbleed (CVE-2014-0160)</li>
                    <li>ROBOT attack</li>
                    <li>POODLE, FREAK, Logjam</li>
                    <li>DROWN, Sweet32</li>
                    <li>CRIME/BREACH compression</li>
                    <li>Renegotiation attacks</li>
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                    <SecurityIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "text-bottom" }} />
                    Advanced Analysis
                  </Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2, fontSize: "0.8rem" }}>
                    <li>SSL Grade (A+ to F)</li>
                    <li>Mozilla TLS compliance</li>
                    <li>Client compatibility</li>
                    <li>Post-quantum readiness</li>
                    <li>JARM fingerprinting</li>
                    <li>STARTTLS detection</li>
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            {/* Port Guide */}
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2, color: "#0891b2" }}>
              🔌 Common SSL/TLS Ports
            </Typography>
            <TableContainer component={Paper} variant="outlined" sx={{ mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Port</TableCell>
                    <TableCell>Service</TableCell>
                    <TableCell>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow><TableCell>443</TableCell><TableCell>HTTPS</TableCell><TableCell>Standard web TLS</TableCell></TableRow>
                  <TableRow><TableCell>8443</TableCell><TableCell>HTTPS Alt</TableCell><TableCell>Alternative HTTPS</TableCell></TableRow>
                  <TableRow><TableCell>465</TableCell><TableCell>SMTPS</TableCell><TableCell>Secure SMTP</TableCell></TableRow>
                  <TableRow><TableCell>587</TableCell><TableCell>SMTP</TableCell><TableCell>STARTTLS submission</TableCell></TableRow>
                  <TableRow><TableCell>993</TableCell><TableCell>IMAPS</TableCell><TableCell>Secure IMAP</TableCell></TableRow>
                  <TableRow><TableCell>995</TableCell><TableCell>POP3S</TableCell><TableCell>Secure POP3</TableCell></TableRow>
                  <TableRow><TableCell>636</TableCell><TableCell>LDAPS</TableCell><TableCell>Secure LDAP</TableCell></TableRow>
                  <TableRow><TableCell>3389</TableCell><TableCell>RDP</TableCell><TableCell>Remote Desktop (TLS)</TableCell></TableRow>
                </TableBody>
              </Table>
            </TableContainer>

            {/* Tips */}
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="subtitle2" fontWeight={600}>💡 Pro Tips</Typography>
              <Box component="ul" sx={{ m: 0, pl: 2, fontSize: "0.85rem" }}>
                <li>Use <strong>Bulk Import</strong> to scan many targets from a file</li>
                <li>Port ranges like <code>443-445</code> scan multiple ports per host</li>
                <li>Enable <strong>AI Analysis</strong> for exploitation recommendations</li>
                <li>Use the <strong>JARM Database</strong> to identify C2 frameworks</li>
                <li>Export reports as Markdown/PDF for documentation</li>
              </Box>
            </Alert>

            <Alert severity="warning">
              <Typography variant="subtitle2" fontWeight={600}>⚠️ Legal Notice</Typography>
              <Typography variant="body2">
                Only scan systems you own or have explicit written authorization to test. 
                Unauthorized scanning may violate computer crime laws. The badssl.com endpoints 
                are explicitly provided for testing and are safe to scan.
              </Typography>
            </Alert>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setGuideOpen(false)} variant="contained">
            Got it!
          </Button>
        </DialogActions>
      </Dialog>

      {/* JARM Database Dialog */}
      <Dialog open={jarmSearchOpen} onClose={() => setJarmSearchOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <BugReportIcon color="warning" />
          JARM Signature Database
          <Chip label="C2 & Malware Detection" size="small" sx={{ ml: 1, bgcolor: alpha("#f59e0b", 0.15), color: "#d97706" }} />
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Search known JARM fingerprints to identify C2 frameworks, malware, and legitimate servers.
            JARM fingerprinting is used to identify TLS server configurations.
          </Typography>
          
          <TextField
            placeholder="Search by name, type, or fingerprint..."
            value={jarmSearchQuery}
            onChange={(e) => setJarmSearchQuery(e.target.value)}
            fullWidth
            size="small"
            sx={{ mb: 2 }}
            InputProps={{
              startAdornment: <SecurityIcon sx={{ mr: 1, color: "text.secondary" }} fontSize="small" />,
            }}
          />
          
          <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 400 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                  <TableCell sx={{ fontWeight: 600 }}>Name</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Severity</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>JARM Fingerprint (Partial)</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredJarmSignatures.map((sig, i) => (
                  <TableRow 
                    key={i} 
                    sx={{ 
                      "&:hover": { bgcolor: alpha("#f59e0b", 0.05) },
                      bgcolor: sig.type === "c2_framework" || sig.type === "malware" ? alpha("#ef4444", 0.03) : "transparent"
                    }}
                  >
                    <TableCell>
                      <Typography fontWeight={sig.severity === "critical" ? 600 : 400}>
                        {sig.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={sig.type.replace("_", " ")}
                        size="small"
                        sx={{
                          bgcolor: alpha(
                            sig.type === "c2_framework" ? "#dc2626" :
                            sig.type === "malware" ? "#9333ea" :
                            sig.type === "webserver" ? "#10b981" :
                            sig.type === "cdn" ? "#06b6d4" :
                            sig.type === "loadbalancer" ? "#3b82f6" : "#6b7280",
                            0.15
                          ),
                          color: sig.type === "c2_framework" ? "#dc2626" :
                                 sig.type === "malware" ? "#9333ea" :
                                 sig.type === "webserver" ? "#059669" :
                                 sig.type === "cdn" ? "#0891b2" :
                                 sig.type === "loadbalancer" ? "#2563eb" : "#4b5563",
                          fontWeight: 500,
                          textTransform: "capitalize"
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={sig.severity.toUpperCase()}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSeverityColor(sig.severity), 0.15),
                          color: getSeverityColor(sig.severity),
                          fontWeight: 600,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary" }}>
                        {sig.fingerprint}...
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          
          <Box sx={{ mt: 2, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <Typography variant="caption" color="text.secondary">
              Showing {filteredJarmSignatures.length} of {JARM_DATABASE.length} signatures
            </Typography>
            <Typography variant="caption" color="warning.main">
              ⚠️ C2/Malware signatures indicate potentially malicious infrastructure
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setJarmSearchOpen(false); setJarmSearchQuery(""); }}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Common Ports Menu */}
      <Menu
        anchorEl={portsMenuAnchor}
        open={Boolean(portsMenuAnchor)}
        onClose={handlePortsMenuClose}
      >
        {COMMON_SSL_PORTS.map((p) => (
          <MenuItem key={p.port} onClick={() => handleSelectPort(p.port)}>
            <ListItemText primary={`${p.port} - ${p.name}`} />
          </MenuItem>
        ))}
      </Menu>

      {/* Error */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Scanning Progress */}
      {scanning && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <CircularProgress size={24} />
            <Typography>Scanning SSL/TLS configuration...</Typography>
          </Box>
          <LinearProgress />
        </Paper>
      )}

      {/* Results */}
      {results && (
        <>
          {/* Summary */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                <Typography variant="h6" fontWeight={600}>
                  Scan Summary
                </Typography>
                {/* Export Buttons */}
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                  <Button
                    size="small"
                    startIcon={exporting === "markdown" ? <CircularProgress size={16} /> : <DescriptionIcon />}
                    onClick={() => handleExport("markdown")}
                    disabled={!results.report_id || exporting !== null}
                    variant="outlined"
                  >
                    Markdown
                  </Button>
                  <Button
                    size="small"
                    startIcon={exporting === "pdf" ? <CircularProgress size={16} /> : <PictureAsPdfIcon />}
                    onClick={() => handleExport("pdf")}
                    disabled={!results.report_id || exporting !== null}
                    variant="outlined"
                    color="error"
                  >
                    PDF
                  </Button>
                  <Button
                    size="small"
                    startIcon={exporting === "docx" ? <CircularProgress size={16} /> : <ArticleIcon />}
                    onClick={() => handleExport("docx")}
                    disabled={!results.report_id || exporting !== null}
                    variant="outlined"
                    color="primary"
                  >
                    Word
                  </Button>
                  <Button
                    size="small"
                    startIcon={<ListAltIcon />}
                    onClick={handleCSVExport}
                    disabled={!results.results || results.results.length === 0}
                    variant="outlined"
                    color="success"
                  >
                    CSV
                  </Button>
                </Box>
              </Box>
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#06b6d4", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#0891b2">
                      {results.summary.total_hosts}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Total Hosts
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#10b981", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#059669">
                      {results.summary.hosts_with_ssl}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      SSL Enabled
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#dc2626", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#dc2626">
                      {results.summary.critical_findings}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Critical Issues
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#ea580c", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#ea580c">
                      {results.summary.high_findings}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      High Issues
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#7c3aed", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#7c3aed">
                      {results.summary.total_vulnerabilities || 0}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Vulnerabilities
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#be123c", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#be123c">
                      {results.summary.exploitable_vulnerabilities || 0}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Exploitable
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>

              {/* Additional Stats */}
              <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mt: 3 }}>
                {results.summary.expired_certs > 0 && (
                  <Chip
                    icon={<ErrorIcon />}
                    label={`${results.summary.expired_certs} Expired Certs`}
                    color="error"
                    variant="outlined"
                  />
                )}
                {results.summary.self_signed_certs > 0 && (
                  <Chip
                    icon={<WarningIcon />}
                    label={`${results.summary.self_signed_certs} Self-Signed`}
                    color="warning"
                    variant="outlined"
                  />
                )}
                {results.summary.weak_protocols > 0 && (
                  <Chip
                    icon={<WarningIcon />}
                    label={`${results.summary.weak_protocols} Weak Protocols`}
                    color="warning"
                    variant="outlined"
                  />
                )}
                {results.summary.weak_ciphers > 0 && (
                  <Chip
                    icon={<WarningIcon />}
                    label={`${results.summary.weak_ciphers} Weak Ciphers`}
                    color="warning"
                    variant="outlined"
                  />
                )}
                {(results.summary.chain_issues || 0) > 0 && (
                  <Chip
                    icon={<LinkIcon />}
                    label={`${results.summary.chain_issues} Chain Issues`}
                    color="warning"
                    variant="outlined"
                  />
                )}
                {(results.summary.critical_vulnerabilities || 0) > 0 && (
                  <Chip
                    icon={<BugReportIcon />}
                    label={`${results.summary.critical_vulnerabilities} Critical CVEs`}
                    color="error"
                    variant="outlined"
                  />
                )}
              </Box>
            </CardContent>
          </Card>

          {/* Host Results */}
          <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
            Detailed Results
          </Typography>
          {results.results.map((result, index) => (
            <Accordion
              key={index}
              expanded={expandedHost === `${result.host}:${result.port}`}
              onChange={() =>
                setExpandedHost(
                  expandedHost === `${result.host}:${result.port}`
                    ? null
                    : `${result.host}:${result.port}`
                )
              }
              sx={{ mb: 2 }}
            >
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  {result.has_ssl ? (
                    result.findings.length === 0 ? (
                      <CheckCircleIcon sx={{ color: "#10b981" }} />
                    ) : result.findings.some((f) => f.severity === "critical") ? (
                      <ErrorIcon sx={{ color: "#dc2626" }} />
                    ) : (
                      <WarningIcon sx={{ color: "#ca8a04" }} />
                    )
                  ) : (
                    <ErrorIcon sx={{ color: "#dc2626" }} />
                  )}
                  <Box sx={{ flex: 1 }}>
                    <Typography fontWeight={600}>
                      {result.host}:{result.port}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {result.has_ssl
                        ? result.certificate?.subject || "SSL Enabled"
                        : result.error || "SSL Not Available"}
                    </Typography>
                  </Box>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    {result.findings.length > 0 && (
                      <Chip
                        label={`${result.findings.length} Issues`}
                        size="small"
                        sx={{
                          bgcolor: alpha(
                            getSeverityColor(
                              result.findings[0]?.severity || "info"
                            ),
                            0.15
                          ),
                          color: getSeverityColor(
                            result.findings[0]?.severity || "info"
                          ),
                        }}
                      />
                    )}
                    {result.supported_protocols.length > 0 && (
                      <Chip
                        label={result.supported_protocols.join(", ")}
                        size="small"
                        variant="outlined"
                      />
                    )}
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                {result.error ? (
                  <Alert severity="error">{result.error}</Alert>
                ) : (
                  <Grid container spacing={3}>
                    {/* Certificate Info */}
                    {result.certificate && (
                      <Grid item xs={12} md={6}>
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                          Certificate Details
                        </Typography>
                        <TableContainer component={Paper} variant="outlined">
                          <Table size="small">
                            <TableBody>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Subject
                                </TableCell>
                                <TableCell>{result.certificate.subject || "N/A"}</TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Issuer
                                </TableCell>
                                <TableCell>{result.certificate.issuer || "N/A"}</TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Valid From
                                </TableCell>
                                <TableCell>
                                  {formatDate(result.certificate.not_before)}
                                </TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Valid Until
                                </TableCell>
                                <TableCell>
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    {formatDate(result.certificate.not_after)}
                                    {result.certificate.is_expired && (
                                      <Chip label="EXPIRED" size="small" color="error" />
                                    )}
                                    {!result.certificate.is_expired &&
                                      result.certificate.days_until_expiry !== null &&
                                      result.certificate.days_until_expiry < 30 && (
                                        <Chip
                                          label={`${result.certificate.days_until_expiry} days`}
                                          size="small"
                                          color="warning"
                                        />
                                      )}
                                  </Box>
                                </TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Key
                                </TableCell>
                                <TableCell>
                                  {result.certificate.key_type} {result.certificate.key_size} bits
                                </TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Signature
                                </TableCell>
                                <TableCell>
                                  {result.certificate.signature_algorithm || "N/A"}
                                </TableCell>
                              </TableRow>
                              {result.certificate.san.length > 0 && (
                                <TableRow>
                                  <TableCell component="th" sx={{ fontWeight: 600 }}>
                                    SANs
                                  </TableCell>
                                  <TableCell>
                                    {result.certificate.san.slice(0, 5).join(", ")}
                                    {result.certificate.san.length > 5 &&
                                      ` (+${result.certificate.san.length - 5} more)`}
                                  </TableCell>
                                </TableRow>
                              )}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Grid>
                    )}

                    {/* Protocol & Cipher Info */}
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                        Supported Protocols
                      </Typography>
                      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                        {result.supported_protocols.map((proto) => (
                          <Chip
                            key={proto}
                            label={proto}
                            size="small"
                            color={
                              proto.includes("1.0") || proto.includes("1.1") || proto.includes("SSL")
                                ? "error"
                                : "success"
                            }
                            variant="outlined"
                          />
                        ))}
                      </Box>

                      <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                        Cipher Suites ({result.cipher_suites.length})
                      </Typography>
                      <Paper
                        variant="outlined"
                        sx={{
                          p: 1,
                          maxHeight: 150,
                          overflow: "auto",
                          fontSize: "0.75rem",
                          fontFamily: "monospace",
                        }}
                      >
                        {result.cipher_suites.map((cipher, i) => (
                          <Box
                            key={i}
                            sx={{
                              color: cipher.includes("NULL") ||
                                cipher.includes("RC4") ||
                                cipher.includes("DES") ||
                                cipher.includes("MD5")
                                ? "#dc2626"
                                : "inherit",
                            }}
                          >
                            {cipher}
                          </Box>
                        ))}
                      </Paper>
                    </Grid>

                    {/* Certificate Chain Info */}
                    {result.chain_info && (
                      <Grid item xs={12}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <LinkIcon fontSize="small" />
                          Certificate Chain
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 2 }}>
                          <Grid container spacing={2}>
                            <Grid item xs={6} sm={3}>
                              <Typography variant="caption" color="text.secondary">Chain Length</Typography>
                              <Typography fontWeight={600}>{result.chain_info.chain_length}</Typography>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Typography variant="caption" color="text.secondary">Complete</Typography>
                              <Typography fontWeight={600}>
                                {result.chain_info.is_complete ? (
                                  <Chip label="Yes" size="small" color="success" />
                                ) : (
                                  <Chip label="No" size="small" color="error" />
                                )}
                              </Typography>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Typography variant="caption" color="text.secondary">Trusted</Typography>
                              <Typography fontWeight={600}>
                                {result.chain_info.is_trusted ? (
                                  <Chip label="Yes" size="small" color="success" />
                                ) : (
                                  <Chip label="No" size="small" color="warning" />
                                )}
                              </Typography>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Typography variant="caption" color="text.secondary">Root CA</Typography>
                              <Typography fontWeight={600} sx={{ fontSize: "0.85rem" }}>
                                {result.chain_info.root_ca || "Unknown"}
                              </Typography>
                            </Grid>
                          </Grid>
                          {result.chain_info.chain_errors && result.chain_info.chain_errors.length > 0 && (
                            <Alert severity="warning" sx={{ mt: 2 }}>
                              <Typography variant="subtitle2" fontWeight={600}>Chain Issues:</Typography>
                              <ul style={{ margin: 0, paddingLeft: 20 }}>
                                {result.chain_info.chain_errors.map((err, i) => (
                                  <li key={i}><Typography variant="body2">{err}</Typography></li>
                                ))}
                              </ul>
                            </Alert>
                          )}
                        </Paper>
                      </Grid>
                    )}

                    {/* Security Headers (HSTS, etc.) */}
                    {result.security_headers && (
                      <Grid item xs={12} md={6}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <HttpsIcon fontSize="small" color="primary" />
                          Security Headers
                          <Chip 
                            label={`${result.security_headers.score}/100`}
                            size="small"
                            color={result.security_headers.score >= 70 ? "success" : result.security_headers.score >= 40 ? "warning" : "error"}
                            sx={{ ml: 1 }}
                          />
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 2 }}>
                          <Grid container spacing={1}>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                                {result.security_headers.hsts_enabled ? (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                ) : (
                                  <ErrorIcon fontSize="small" color="error" />
                                )}
                                <Typography variant="body2" fontWeight={500}>HSTS</Typography>
                              </Box>
                              {result.security_headers.hsts_enabled && (
                                <Box sx={{ ml: 3 }}>
                                  <Typography variant="caption" color="text.secondary">
                                    Max-Age: {result.security_headers.hsts_max_age?.toLocaleString() || "N/A"}s
                                  </Typography>
                                  {result.security_headers.hsts_include_subdomains && (
                                    <Chip label="includeSubDomains" size="small" sx={{ ml: 0.5, fontSize: "0.65rem" }} />
                                  )}
                                  {result.security_headers.hsts_preload && (
                                    <Chip label="preload" size="small" color="success" sx={{ ml: 0.5, fontSize: "0.65rem" }} />
                                  )}
                                </Box>
                              )}
                            </Grid>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                                {result.security_headers.content_security_policy ? (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                ) : (
                                  <WarningIcon fontSize="small" color="warning" />
                                )}
                                <Typography variant="body2" fontWeight={500}>CSP</Typography>
                              </Box>
                            </Grid>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {result.security_headers.x_frame_options ? (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                ) : (
                                  <WarningIcon fontSize="small" color="warning" />
                                )}
                                <Typography variant="body2" fontWeight={500}>X-Frame-Options</Typography>
                              </Box>
                            </Grid>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {result.security_headers.x_content_type_options ? (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                ) : (
                                  <WarningIcon fontSize="small" color="warning" />
                                )}
                                <Typography variant="body2" fontWeight={500}>X-Content-Type-Options</Typography>
                              </Box>
                            </Grid>
                          </Grid>
                          {result.security_headers.missing_headers && result.security_headers.missing_headers.length > 0 && (
                            <Alert severity="info" sx={{ mt: 2, py: 0.5 }} icon={<InfoIcon fontSize="small" />}>
                              <Typography variant="caption">
                                Missing: {result.security_headers.missing_headers.slice(0, 3).join(", ")}
                                {result.security_headers.missing_headers.length > 3 && ` (+${result.security_headers.missing_headers.length - 3} more)`}
                              </Typography>
                            </Alert>
                          )}
                        </Paper>
                      </Grid>
                    )}

                    {/* OCSP Revocation Status */}
                    {result.ocsp_status && (
                      <Grid item xs={12} md={6}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <VerifiedUserIcon fontSize="small" color={result.ocsp_status.status === "good" ? "success" : result.ocsp_status.status === "revoked" ? "error" : "warning"} />
                          Certificate Revocation (OCSP)
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 2 }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                            <Typography variant="body2" fontWeight={500}>Status:</Typography>
                            <Chip 
                              label={result.ocsp_status.status.toUpperCase()}
                              size="small"
                              color={result.ocsp_status.status === "good" ? "success" : result.ocsp_status.status === "revoked" ? "error" : "warning"}
                            />
                          </Box>
                          {result.ocsp_status.status === "revoked" && (
                            <Alert severity="error" sx={{ mt: 1 }}>
                              <Typography variant="body2">
                                Certificate was revoked{result.ocsp_status.revocation_time ? ` on ${result.ocsp_status.revocation_time}` : ""}.
                                {result.ocsp_status.revocation_reason && ` Reason: ${result.ocsp_status.revocation_reason}`}
                              </Typography>
                            </Alert>
                          )}
                          {result.ocsp_status.ocsp_url && (
                            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                              OCSP: {result.ocsp_status.ocsp_url}
                            </Typography>
                          )}
                          {result.ocsp_status.errors && result.ocsp_status.errors.length > 0 && (
                            <Typography variant="caption" color="warning.main" display="block" sx={{ mt: 0.5 }}>
                              ⚠️ {result.ocsp_status.errors[0]}
                            </Typography>
                          )}
                        </Paper>
                      </Grid>
                    )}

                    {/* TLS 1.3 Analysis */}
                    {result.tls13_analysis && (
                      <Grid item xs={12} md={6}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <LockIcon fontSize="small" color={result.tls13_analysis.supported ? "success" : "warning"} />
                          TLS 1.3 Analysis
                          <Chip 
                            label={`${result.tls13_analysis.score}/100`}
                            size="small"
                            sx={{
                              bgcolor: alpha(result.tls13_analysis.score >= 80 ? "#10b981" : result.tls13_analysis.score >= 50 ? "#f59e0b" : "#ef4444", 0.15),
                              color: result.tls13_analysis.score >= 80 ? "#059669" : result.tls13_analysis.score >= 50 ? "#d97706" : "#dc2626",
                              fontWeight: 600,
                              ml: 1
                            }}
                          />
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 2 }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                            <Typography variant="body2" fontWeight={500}>TLS 1.3 Support:</Typography>
                            <Chip 
                              label={result.tls13_analysis.supported ? "SUPPORTED" : "NOT SUPPORTED"}
                              size="small"
                              color={result.tls13_analysis.supported ? "success" : "warning"}
                            />
                          </Box>
                          {result.tls13_analysis.supported && (
                            <>
                              <Grid container spacing={1} sx={{ mb: 2 }}>
                                <Grid item xs={6}>
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    {result.tls13_analysis.has_aes_gcm ? (
                                      <CheckCircleIcon fontSize="small" color="success" />
                                    ) : (
                                      <WarningIcon fontSize="small" color="warning" />
                                    )}
                                    <Typography variant="body2">AES-GCM</Typography>
                                  </Box>
                                </Grid>
                                <Grid item xs={6}>
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    {result.tls13_analysis.has_chacha20 ? (
                                      <CheckCircleIcon fontSize="small" color="success" />
                                    ) : (
                                      <WarningIcon fontSize="small" color="warning" />
                                    )}
                                    <Typography variant="body2">ChaCha20-Poly1305</Typography>
                                  </Box>
                                </Grid>
                              </Grid>
                              {result.tls13_analysis.cipher_suites && result.tls13_analysis.cipher_suites.length > 0 && (
                                <Box sx={{ mt: 1 }}>
                                  <Typography variant="caption" color="text.secondary">Cipher Suites:</Typography>
                                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                                    {result.tls13_analysis.cipher_suites.map((cipher, i) => (
                                      <Chip key={i} label={cipher.name} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                                    ))}
                                  </Box>
                                </Box>
                              )}
                              {result.tls13_analysis.supports_0rtt && (
                                <Alert severity="info" sx={{ mt: 2, py: 0.5 }} icon={<WarningIcon fontSize="small" />}>
                                  <Typography variant="caption">
                                    0-RTT (Early Data) supported - potential replay attack risk
                                  </Typography>
                                </Alert>
                              )}
                            </>
                          )}
                        </Paper>
                      </Grid>
                    )}

                    {/* Certificate Transparency */}
                    {result.ct_verification && (
                      <Grid item xs={12} md={6}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <VerifiedUserIcon fontSize="small" color={result.ct_verification.has_scts ? "success" : "warning"} />
                          Certificate Transparency
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 2 }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                            <Typography variant="body2" fontWeight={500}>SCT Status:</Typography>
                            <Chip 
                              label={result.ct_verification.has_scts ? `${result.ct_verification.sct_count} SCT(s)` : "NO SCTs"}
                              size="small"
                              color={result.ct_verification.has_scts && result.ct_verification.sct_count >= 2 ? "success" : "warning"}
                            />
                          </Box>
                          {result.ct_verification.embedded_in_cert && (
                            <Typography variant="caption" color="success.main" display="block">
                              ✓ SCTs embedded in certificate
                            </Typography>
                          )}
                          {result.ct_verification.scts && result.ct_verification.scts.length > 0 && (
                            <Box sx={{ mt: 1 }}>
                              {result.ct_verification.scts.slice(0, 3).map((sct, i) => (
                                <Typography key={i} variant="caption" color="text.secondary" display="block">
                                  Log: {sct.log_id.substring(0, 16)}... ({sct.timestamp ? new Date(sct.timestamp).toLocaleDateString() : "N/A"})
                                </Typography>
                              ))}
                            </Box>
                          )}
                          {result.ct_verification.issues && result.ct_verification.issues.length > 0 && (
                            <Alert severity="warning" sx={{ mt: 1, py: 0.5 }}>
                              <Typography variant="caption">{result.ct_verification.issues[0]}</Typography>
                            </Alert>
                          )}
                        </Paper>
                      </Grid>
                    )}

                    {/* Cipher Ordering */}
                    {result.cipher_ordering && (
                      <Grid item xs={12} md={6}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <SecurityIcon fontSize="small" color={result.cipher_ordering.server_enforces_order ? "success" : "warning"} />
                          Cipher Suite Ordering
                          <Chip 
                            label={`${result.cipher_ordering.score}/100`}
                            size="small"
                            sx={{
                              bgcolor: alpha(result.cipher_ordering.score >= 80 ? "#10b981" : result.cipher_ordering.score >= 50 ? "#f59e0b" : "#ef4444", 0.15),
                              color: result.cipher_ordering.score >= 80 ? "#059669" : result.cipher_ordering.score >= 50 ? "#d97706" : "#dc2626",
                              fontWeight: 600,
                              ml: 1
                            }}
                          />
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 2 }}>
                          <Grid container spacing={1}>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {result.cipher_ordering.server_enforces_order ? (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                ) : (
                                  <WarningIcon fontSize="small" color="warning" />
                                )}
                                <Typography variant="body2">Server Order</Typography>
                              </Box>
                            </Grid>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {result.cipher_ordering.pfs_prioritized ? (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                ) : (
                                  <WarningIcon fontSize="small" color="warning" />
                                )}
                                <Typography variant="body2">PFS Priority</Typography>
                              </Box>
                            </Grid>
                          </Grid>
                          {result.cipher_ordering.server_preferred_cipher && (
                            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                              Preferred: {result.cipher_ordering.server_preferred_cipher}
                            </Typography>
                          )}
                          {result.cipher_ordering.issues && result.cipher_ordering.issues.length > 0 && (
                            <Alert severity="warning" sx={{ mt: 1, py: 0.5 }}>
                              <Typography variant="caption">{result.cipher_ordering.issues[0]}</Typography>
                            </Alert>
                          )}
                        </Paper>
                      </Grid>
                    )}

                    {/* Session Tickets / 0-RTT */}
                    {result.session_ticket_analysis && (
                      <Grid item xs={12} md={6}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <LockIcon fontSize="small" color="primary" />
                          Session Tickets & 0-RTT
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 2 }}>
                          <Grid container spacing={1}>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {result.session_ticket_analysis.supports_session_tickets ? (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                ) : (
                                  <InfoIcon fontSize="small" color="info" />
                                )}
                                <Typography variant="body2">Session Tickets</Typography>
                              </Box>
                            </Grid>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {result.session_ticket_analysis.supports_0rtt ? (
                                  <WarningIcon fontSize="small" color="warning" />
                                ) : (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                )}
                                <Typography variant="body2">0-RTT {result.session_ticket_analysis.supports_0rtt ? "Enabled" : "Disabled"}</Typography>
                              </Box>
                            </Grid>
                          </Grid>
                          {result.session_ticket_analysis.supports_0rtt && (
                            <Alert severity="warning" sx={{ mt: 2, py: 0.5 }}>
                              <Typography variant="caption">
                                0-RTT enabled - replay attack risk for non-idempotent requests
                              </Typography>
                            </Alert>
                          )}
                          {result.session_ticket_analysis.recommendations && result.session_ticket_analysis.recommendations.length > 0 && (
                            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                              💡 {result.session_ticket_analysis.recommendations[0]}
                            </Typography>
                          )}
                        </Paper>
                      </Grid>
                    )}

                    {/* SNI Analysis */}
                    {result.sni_analysis && (
                      <Grid item xs={12} md={6}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <LinkIcon fontSize="small" color={result.sni_analysis.risk_level === "low" ? "success" : result.sni_analysis.risk_level === "medium" ? "warning" : "error"} />
                          SNI Analysis
                          <Chip 
                            label={result.sni_analysis.risk_level.toUpperCase()}
                            size="small"
                            sx={{
                              bgcolor: alpha(result.sni_analysis.risk_level === "low" ? "#10b981" : result.sni_analysis.risk_level === "medium" ? "#f59e0b" : "#ef4444", 0.15),
                              color: result.sni_analysis.risk_level === "low" ? "#059669" : result.sni_analysis.risk_level === "medium" ? "#d97706" : "#dc2626",
                              fontWeight: 600,
                              ml: 1
                            }}
                          />
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 2 }}>
                          <Grid container spacing={1}>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {result.sni_analysis.requires_sni ? (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                ) : (
                                  <InfoIcon fontSize="small" color="info" />
                                )}
                                <Typography variant="body2">SNI {result.sni_analysis.requires_sni ? "Required" : "Optional"}</Typography>
                              </Box>
                            </Grid>
                            <Grid item xs={6}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {result.sni_analysis.allows_domain_fronting ? (
                                  <ErrorIcon fontSize="small" color="error" />
                                ) : (
                                  <CheckCircleIcon fontSize="small" color="success" />
                                )}
                                <Typography variant="body2">Domain Fronting</Typography>
                              </Box>
                            </Grid>
                          </Grid>
                          {result.sni_analysis.certificates_differ && (
                            <Alert severity="info" sx={{ mt: 2, py: 0.5 }}>
                              <Typography variant="caption">
                                Different certificates for SNI vs no-SNI connections
                              </Typography>
                            </Alert>
                          )}
                          {result.sni_analysis.allows_domain_fronting && (
                            <Alert severity="error" sx={{ mt: 2, py: 0.5 }}>
                              <Typography variant="caption">
                                ⚠️ Domain fronting possible - traffic can be disguised
                              </Typography>
                            </Alert>
                          )}
                          {result.sni_analysis.requested_cert_cn && (
                            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                              CN: {result.sni_analysis.requested_cert_cn}
                            </Typography>
                          )}
                        </Paper>
                      </Grid>
                    )}

                    {/* Protocol & Attack Detection Section */}
                    {(result.downgrade_attacks || result.heartbleed_analysis || result.robot_analysis || 
                      result.renegotiation_analysis || result.sweet32_analysis || result.compression_attacks || result.alpn_analysis) && (
                      <Grid item xs={12}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="h6" fontWeight={700} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <GppBadIcon color="error" />
                          Protocol & Attack Detection
                        </Typography>
                        
                        <Grid container spacing={2}>
                          {/* Downgrade Attacks */}
                          {result.downgrade_attacks && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: result.downgrade_attacks.vulnerable_to_downgrade ? "#dc2626" : "#10b981",
                                  bgcolor: alpha(result.downgrade_attacks.vulnerable_to_downgrade ? "#dc2626" : "#10b981", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  {result.downgrade_attacks.vulnerable_to_downgrade ? (
                                    <ErrorIcon fontSize="small" color="error" />
                                  ) : (
                                    <CheckCircleIcon fontSize="small" color="success" />
                                  )}
                                  Downgrade Attacks
                                  <Chip 
                                    label={result.downgrade_attacks.risk_level.toUpperCase()}
                                    size="small"
                                    sx={{
                                      bgcolor: alpha(result.downgrade_attacks.risk_level === "low" ? "#10b981" : result.downgrade_attacks.risk_level === "medium" ? "#f59e0b" : result.downgrade_attacks.risk_level === "high" ? "#ea580c" : "#dc2626", 0.15),
                                      color: result.downgrade_attacks.risk_level === "low" ? "#059669" : result.downgrade_attacks.risk_level === "medium" ? "#d97706" : result.downgrade_attacks.risk_level === "high" ? "#c2410c" : "#dc2626",
                                      fontWeight: 600,
                                    }}
                                  />
                                </Typography>
                                
                                <Grid container spacing={1}>
                                  <Grid item xs={6}>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {result.downgrade_attacks.poodle_sslv3_vulnerable ? (
                                        <ErrorIcon fontSize="small" color="error" />
                                      ) : (
                                        <CheckCircleIcon fontSize="small" color="success" />
                                      )}
                                      <Typography variant="caption">POODLE (SSLv3)</Typography>
                                    </Box>
                                  </Grid>
                                  <Grid item xs={6}>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {result.downgrade_attacks.drown_vulnerable ? (
                                        <ErrorIcon fontSize="small" color="error" />
                                      ) : (
                                        <CheckCircleIcon fontSize="small" color="success" />
                                      )}
                                      <Typography variant="caption">DROWN (SSLv2)</Typography>
                                    </Box>
                                  </Grid>
                                  <Grid item xs={6}>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {result.downgrade_attacks.freak_vulnerable ? (
                                        <ErrorIcon fontSize="small" color="error" />
                                      ) : (
                                        <CheckCircleIcon fontSize="small" color="success" />
                                      )}
                                      <Typography variant="caption">FREAK (Export)</Typography>
                                    </Box>
                                  </Grid>
                                  <Grid item xs={6}>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {result.downgrade_attacks.logjam_vulnerable ? (
                                        <ErrorIcon fontSize="small" color="error" />
                                      ) : (
                                        <CheckCircleIcon fontSize="small" color="success" />
                                      )}
                                      <Typography variant="caption">Logjam (DH)</Typography>
                                    </Box>
                                  </Grid>
                                </Grid>
                                
                                {result.downgrade_attacks.cve_ids && result.downgrade_attacks.cve_ids.length > 0 && (
                                  <Box sx={{ mt: 1, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                    {result.downgrade_attacks.cve_ids.map((cve, i) => (
                                      <Chip key={i} label={cve} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                                    ))}
                                  </Box>
                                )}
                              </Paper>
                            </Grid>
                          )}

                          {/* Heartbleed */}
                          {result.heartbleed_analysis && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: result.heartbleed_analysis.vulnerable ? "#dc2626" : "#10b981",
                                  bgcolor: alpha(result.heartbleed_analysis.vulnerable ? "#dc2626" : "#10b981", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  {result.heartbleed_analysis.vulnerable ? (
                                    <ErrorIcon fontSize="small" color="error" />
                                  ) : (
                                    <CheckCircleIcon fontSize="small" color="success" />
                                  )}
                                  Heartbleed (CVE-2014-0160)
                                  {result.heartbleed_analysis.vulnerable && (
                                    <Chip label="CRITICAL" size="small" sx={{ bgcolor: alpha("#dc2626", 0.15), color: "#dc2626", fontWeight: 600 }} />
                                  )}
                                </Typography>
                                
                                <Typography variant="body2">
                                  {result.heartbleed_analysis.vulnerable 
                                    ? `⚠️ VULNERABLE - Server leaked ${result.heartbleed_analysis.leak_size} bytes`
                                    : "✓ Not vulnerable to Heartbleed"
                                  }
                                </Typography>
                                
                                {result.heartbleed_analysis.tested && (
                                  <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                                    Tested: {result.heartbleed_analysis.tls_versions_tested.join(", ")}
                                  </Typography>
                                )}
                                
                                {result.heartbleed_analysis.vulnerable && result.heartbleed_analysis.recommendations.length > 0 && (
                                  <Alert severity="error" sx={{ mt: 1, py: 0.5 }}>
                                    <Typography variant="caption">
                                      {result.heartbleed_analysis.recommendations[0]}
                                    </Typography>
                                  </Alert>
                                )}
                              </Paper>
                            </Grid>
                          )}

                          {/* ROBOT Attack */}
                          {result.robot_analysis && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: result.robot_analysis.vulnerable ? "#ea580c" : "#10b981",
                                  bgcolor: alpha(result.robot_analysis.vulnerable ? "#ea580c" : "#10b981", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  {result.robot_analysis.vulnerable ? (
                                    <WarningIcon fontSize="small" color="warning" />
                                  ) : (
                                    <CheckCircleIcon fontSize="small" color="success" />
                                  )}
                                  ROBOT Attack (Bleichenbacher)
                                  {result.robot_analysis.vulnerable && result.robot_analysis.oracle_type && (
                                    <Chip 
                                      label={result.robot_analysis.oracle_type.toUpperCase()} 
                                      size="small" 
                                      sx={{ bgcolor: alpha("#ea580c", 0.15), color: "#ea580c", fontWeight: 600 }} 
                                    />
                                  )}
                                </Typography>
                                
                                <Typography variant="body2">
                                  {result.robot_analysis.rsa_key_exchange_supported 
                                    ? `RSA key exchange: ${result.robot_analysis.vulnerable_ciphers.length} ciphers`
                                    : "✓ No RSA key exchange ciphers"
                                  }
                                </Typography>
                                
                                {result.robot_analysis.vulnerable_ciphers.length > 0 && (
                                  <Box sx={{ mt: 1, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                    {result.robot_analysis.vulnerable_ciphers.slice(0, 3).map((cipher, i) => (
                                      <Chip key={i} label={cipher} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                                    ))}
                                    {result.robot_analysis.vulnerable_ciphers.length > 3 && (
                                      <Chip label={`+${result.robot_analysis.vulnerable_ciphers.length - 3} more`} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                                    )}
                                  </Box>
                                )}
                              </Paper>
                            </Grid>
                          )}

                          {/* Renegotiation */}
                          {result.renegotiation_analysis && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: result.renegotiation_analysis.vulnerable_to_mitm ? "#dc2626" : result.renegotiation_analysis.vulnerable_to_dos ? "#ea580c" : "#10b981",
                                  bgcolor: alpha(result.renegotiation_analysis.vulnerable_to_mitm ? "#dc2626" : result.renegotiation_analysis.vulnerable_to_dos ? "#ea580c" : "#10b981", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  {result.renegotiation_analysis.vulnerable_to_mitm ? (
                                    <ErrorIcon fontSize="small" color="error" />
                                  ) : result.renegotiation_analysis.vulnerable_to_dos ? (
                                    <WarningIcon fontSize="small" color="warning" />
                                  ) : (
                                    <CheckCircleIcon fontSize="small" color="success" />
                                  )}
                                  TLS Renegotiation
                                </Typography>
                                
                                <Grid container spacing={1}>
                                  <Grid item xs={6}>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {result.renegotiation_analysis.secure_renegotiation_supported ? (
                                        <CheckCircleIcon fontSize="small" color="success" />
                                      ) : (
                                        <ErrorIcon fontSize="small" color="error" />
                                      )}
                                      <Typography variant="caption">Secure Reneg.</Typography>
                                    </Box>
                                  </Grid>
                                  <Grid item xs={6}>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {result.renegotiation_analysis.client_initiated_allowed ? (
                                        <WarningIcon fontSize="small" color="warning" />
                                      ) : (
                                        <CheckCircleIcon fontSize="small" color="success" />
                                      )}
                                      <Typography variant="caption">Client Reneg.</Typography>
                                    </Box>
                                  </Grid>
                                </Grid>
                                
                                {result.renegotiation_analysis.vulnerable_to_mitm && (
                                  <Alert severity="error" sx={{ mt: 1, py: 0.5 }}>
                                    <Typography variant="caption">CVE-2009-3555: MITM during renegotiation</Typography>
                                  </Alert>
                                )}
                                {result.renegotiation_analysis.vulnerable_to_dos && !result.renegotiation_analysis.vulnerable_to_mitm && (
                                  <Alert severity="warning" sx={{ mt: 1, py: 0.5 }}>
                                    <Typography variant="caption">Client-initiated renegotiation DoS risk</Typography>
                                  </Alert>
                                )}
                              </Paper>
                            </Grid>
                          )}

                          {/* Sweet32 */}
                          {result.sweet32_analysis && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: result.sweet32_analysis.vulnerable ? "#ea580c" : "#10b981",
                                  bgcolor: alpha(result.sweet32_analysis.vulnerable ? "#ea580c" : "#10b981", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  {result.sweet32_analysis.vulnerable ? (
                                    <WarningIcon fontSize="small" color="warning" />
                                  ) : (
                                    <CheckCircleIcon fontSize="small" color="success" />
                                  )}
                                  Sweet32 (64-bit Block Ciphers)
                                  {result.sweet32_analysis.vulnerable && (
                                    <Chip label="CVE-2016-2183" size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                                  )}
                                </Typography>
                                
                                {result.sweet32_analysis.vulnerable ? (
                                  <>
                                    <Grid container spacing={1}>
                                      {result.sweet32_analysis.triple_des_supported && (
                                        <Grid item xs={4}>
                                          <Chip label="3DES" size="small" color="warning" sx={{ fontSize: "0.7rem" }} />
                                        </Grid>
                                      )}
                                      {result.sweet32_analysis.blowfish_supported && (
                                        <Grid item xs={4}>
                                          <Chip label="Blowfish" size="small" color="warning" sx={{ fontSize: "0.7rem" }} />
                                        </Grid>
                                      )}
                                      {result.sweet32_analysis.idea_supported && (
                                        <Grid item xs={4}>
                                          <Chip label="IDEA" size="small" color="warning" sx={{ fontSize: "0.7rem" }} />
                                        </Grid>
                                      )}
                                    </Grid>
                                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                                      {result.sweet32_analysis.weak_block_ciphers.length} weak cipher(s) found
                                    </Typography>
                                  </>
                                ) : (
                                  <Typography variant="body2">✓ No 64-bit block ciphers supported</Typography>
                                )}
                              </Paper>
                            </Grid>
                          )}

                          {/* CRIME/BREACH */}
                          {result.compression_attacks && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: result.compression_attacks.crime_vulnerable ? "#dc2626" : result.compression_attacks.breach_vulnerable ? "#ea580c" : "#10b981",
                                  bgcolor: alpha(result.compression_attacks.crime_vulnerable ? "#dc2626" : result.compression_attacks.breach_vulnerable ? "#ea580c" : "#10b981", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  {result.compression_attacks.crime_vulnerable || result.compression_attacks.breach_vulnerable ? (
                                    <WarningIcon fontSize="small" color={result.compression_attacks.crime_vulnerable ? "error" : "warning"} />
                                  ) : (
                                    <CheckCircleIcon fontSize="small" color="success" />
                                  )}
                                  CRIME / BREACH (Compression)
                                </Typography>
                                
                                <Grid container spacing={1}>
                                  <Grid item xs={6}>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {result.compression_attacks.tls_compression_enabled ? (
                                        <ErrorIcon fontSize="small" color="error" />
                                      ) : (
                                        <CheckCircleIcon fontSize="small" color="success" />
                                      )}
                                      <Typography variant="caption">TLS Compression</Typography>
                                    </Box>
                                  </Grid>
                                  <Grid item xs={6}>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {result.compression_attacks.http_compression_enabled ? (
                                        <WarningIcon fontSize="small" color="warning" />
                                      ) : (
                                        <CheckCircleIcon fontSize="small" color="success" />
                                      )}
                                      <Typography variant="caption">HTTP Compression</Typography>
                                    </Box>
                                  </Grid>
                                </Grid>
                                
                                {result.compression_attacks.compression_methods && result.compression_attacks.compression_methods.length > 0 && (
                                  <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                                    Methods: {result.compression_attacks.compression_methods.join(", ")}
                                  </Typography>
                                )}
                                
                                {result.compression_attacks.cve_ids && result.compression_attacks.cve_ids.length > 0 && (
                                  <Box sx={{ mt: 1, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                    {result.compression_attacks.cve_ids.map((cve, i) => (
                                      <Chip key={i} label={cve} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                                    ))}
                                  </Box>
                                )}
                              </Paper>
                            </Grid>
                          )}

                          {/* ALPN Protocols */}
                          {result.alpn_analysis && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: "#0891b2",
                                  bgcolor: alpha("#0891b2", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  <HttpsIcon fontSize="small" sx={{ color: "#0891b2" }} />
                                  ALPN Protocol Negotiation
                                  {result.alpn_analysis.alpn_supported && (
                                    <Chip label="SUPPORTED" size="small" sx={{ bgcolor: alpha("#0891b2", 0.15), color: "#0891b2", fontWeight: 600 }} />
                                  )}
                                </Typography>
                                
                                {result.alpn_analysis.alpn_supported ? (
                                  <>
                                    <Grid container spacing={1}>
                                      <Grid item xs={4}>
                                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                          {result.alpn_analysis.http2_supported ? (
                                            <CheckCircleIcon fontSize="small" color="success" />
                                          ) : (
                                            <InfoIcon fontSize="small" color="disabled" />
                                          )}
                                          <Typography variant="caption">HTTP/2</Typography>
                                        </Box>
                                      </Grid>
                                      <Grid item xs={4}>
                                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                          {result.alpn_analysis.grpc_supported ? (
                                            <CheckCircleIcon fontSize="small" color="success" />
                                          ) : (
                                            <InfoIcon fontSize="small" color="disabled" />
                                          )}
                                          <Typography variant="caption">gRPC</Typography>
                                        </Box>
                                      </Grid>
                                      <Grid item xs={4}>
                                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                          {result.alpn_analysis.spdy_supported ? (
                                            <WarningIcon fontSize="small" color="warning" />
                                          ) : (
                                            <CheckCircleIcon fontSize="small" color="success" />
                                          )}
                                          <Typography variant="caption">SPDY</Typography>
                                        </Box>
                                      </Grid>
                                    </Grid>
                                    
                                    {result.alpn_analysis.negotiated_protocol && (
                                      <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                                        Negotiated: <strong>{result.alpn_analysis.negotiated_protocol}</strong>
                                      </Typography>
                                    )}
                                    
                                    {result.alpn_analysis.supported_protocols && result.alpn_analysis.supported_protocols.length > 0 && (
                                      <Box sx={{ mt: 1, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                        {result.alpn_analysis.supported_protocols.map((proto, i) => (
                                          <Chip key={i} label={proto} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                                        ))}
                                      </Box>
                                    )}
                                  </>
                                ) : (
                                  <Typography variant="body2" color="text.secondary">ALPN not supported</Typography>
                                )}
                              </Paper>
                            </Grid>
                          )}
                        </Grid>
                      </Grid>
                    )}

                    {/* === NEW: Enhanced Analysis Features === */}
                    
                    {/* SSL Grade Display */}
                    {result.ssl_grade && (
                      <Grid item xs={12}>
                        <Divider sx={{ my: 2 }} />
                        <Paper 
                          sx={{ 
                            p: 3, 
                            background: `linear-gradient(135deg, ${
                              result.ssl_grade.grade === "A+" || result.ssl_grade.grade === "A" ? "#10b981" :
                              result.ssl_grade.grade === "B" ? "#0891b2" :
                              result.ssl_grade.grade === "C" ? "#ca8a04" :
                              result.ssl_grade.grade === "D" || result.ssl_grade.grade === "E" ? "#ea580c" :
                              "#dc2626"
                            } 0%, ${
                              result.ssl_grade.grade === "A+" || result.ssl_grade.grade === "A" ? "#059669" :
                              result.ssl_grade.grade === "B" ? "#0e7490" :
                              result.ssl_grade.grade === "C" ? "#a16207" :
                              result.ssl_grade.grade === "D" || result.ssl_grade.grade === "E" ? "#c2410c" :
                              "#b91c1c"
                            } 100%)`,
                            color: "white",
                            display: "flex",
                            alignItems: "center",
                            gap: 3,
                            borderRadius: 2,
                          }}
                        >
                          <Box 
                            sx={{ 
                              width: 80, 
                              height: 80, 
                              borderRadius: "50%", 
                              bgcolor: "rgba(255,255,255,0.2)",
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              flexShrink: 0,
                            }}
                          >
                            <Typography variant="h3" fontWeight={700}>
                              {result.ssl_grade.grade}
                            </Typography>
                          </Box>
                          <Box sx={{ flexGrow: 1 }}>
                            <Typography variant="h6" fontWeight={600}>
                              SSL/TLS Grade: {result.ssl_grade.grade}
                            </Typography>
                            <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>
                              {result.ssl_grade.grade_details || (result.ssl_grade.grade_cap ? `Capped at ${result.ssl_grade.grade_cap}` : `Score: ${result.ssl_grade.numeric_score}/100`)}
                            </Typography>
                            <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                              <Box>
                                <Typography variant="caption" sx={{ opacity: 0.8 }}>Protocol</Typography>
                                <Typography fontWeight={600}>{result.ssl_grade.protocol_score}/100</Typography>
                              </Box>
                              <Box>
                                <Typography variant="caption" sx={{ opacity: 0.8 }}>Key Exchange</Typography>
                                <Typography fontWeight={600}>{result.ssl_grade.key_exchange_score}/100</Typography>
                              </Box>
                              <Box>
                                <Typography variant="caption" sx={{ opacity: 0.8 }}>Cipher</Typography>
                                <Typography fontWeight={600}>{result.ssl_grade.cipher_score}/100</Typography>
                              </Box>
                              <Box>
                                <Typography variant="caption" sx={{ opacity: 0.8 }}>Certificate</Typography>
                                <Typography fontWeight={600}>{result.ssl_grade.certificate_score}/100</Typography>
                              </Box>
                              <Box>
                                <Typography variant="caption" sx={{ opacity: 0.8 }}>Overall</Typography>
                                <Typography fontWeight={600}>{result.ssl_grade.numeric_score}/100</Typography>
                              </Box>
                            </Box>
                          </Box>
                        </Paper>
                        
                        {result.ssl_grade.deductions && result.ssl_grade.deductions.length > 0 && (
                          <Box sx={{ mt: 2 }}>
                            <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                              Score Deductions
                            </Typography>
                            {result.ssl_grade.deductions.map((ded, i) => (
                              <Chip 
                                key={i}
                                label={`${ded.item}${ded.reason ? ` - ${ded.reason}` : ''} (${ded.points > 0 ? '+' : ''}${ded.points})${ded.cap ? ` [cap: ${ded.cap}]` : ''}`}
                                size="small"
                                sx={{ m: 0.5, bgcolor: alpha("#dc2626", 0.1), color: "#dc2626" }}
                              />
                            ))}
                          </Box>
                        )}
                        
                        {result.ssl_grade.cap_reasons && result.ssl_grade.cap_reasons.length > 0 && (
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="caption" color="error.main" fontWeight={600}>
                              Grade capped due to: {result.ssl_grade.cap_reasons.join(", ")}
                            </Typography>
                          </Box>
                        )}
                      </Grid>
                    )}

                    {/* Mozilla Compliance & Client Compatibility */}
                    {(result.mozilla_compliance || result.client_compatibility) && (
                      <Grid item xs={12}>
                        <Grid container spacing={2}>
                          {/* Mozilla Compliance */}
                          {result.mozilla_compliance && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: result.mozilla_compliance.is_compliant ? "#10b981" : "#ea580c",
                                  bgcolor: alpha(result.mozilla_compliance.is_compliant ? "#10b981" : "#ea580c", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  {result.mozilla_compliance.is_compliant ? (
                                    <VerifiedUserIcon fontSize="small" color="success" />
                                  ) : (
                                    <WarningIcon fontSize="small" color="warning" />
                                  )}
                                  Mozilla TLS Compliance
                                  <Chip 
                                    label={result.mozilla_compliance.profile_tested.toUpperCase()} 
                                    size="small" 
                                    sx={{ 
                                      bgcolor: alpha("#6366f1", 0.15), 
                                      color: "#6366f1",
                                      fontWeight: 600,
                                    }} 
                                  />
                                  <Chip
                                    label={`${Math.round(result.mozilla_compliance.compliance_score * 100)}%`}
                                    size="small"
                                    sx={{
                                      bgcolor: alpha(result.mozilla_compliance.is_compliant ? "#10b981" : "#ea580c", 0.15),
                                      color: result.mozilla_compliance.is_compliant ? "#10b981" : "#ea580c",
                                      fontWeight: 600,
                                    }}
                                  />
                                </Typography>
                                
                                {result.mozilla_compliance.is_compliant ? (
                                  <Typography variant="body2" color="success.main">
                                    ✓ Configuration meets Mozilla's {result.mozilla_compliance.profile_tested} profile requirements
                                  </Typography>
                                ) : (
                                  <>
                                    <Typography variant="body2" color="warning.main" sx={{ mb: 1 }}>
                                      {result.mozilla_compliance.violations.length} violation(s) found
                                    </Typography>
                                    <Box sx={{ maxHeight: 100, overflow: "auto" }}>
                                      {result.mozilla_compliance.violations.slice(0, 5).map((v, i) => (
                                        <Typography key={i} variant="caption" color="text.secondary" display="block">
                                          • [{v.severity}] {v.issue}
                                        </Typography>
                                      ))}
                                    </Box>
                                  </>
                                )}
                              </Paper>
                            </Grid>
                          )}

                          {/* Client Compatibility */}
                          {result.client_compatibility && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: "#6366f1",
                                  bgcolor: alpha("#6366f1", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  <SecurityIcon fontSize="small" sx={{ color: "#6366f1" }} />
                                  Client Compatibility ({result.client_compatibility.clients_tested} tested)
                                  <Chip 
                                    label={`${result.client_compatibility.compatible_clients.length}/${result.client_compatibility.clients_tested}`}
                                    size="small"
                                    sx={{ 
                                      bgcolor: alpha(result.client_compatibility.incompatible_clients.length === 0 ? "#10b981" : "#ea580c", 0.15),
                                      color: result.client_compatibility.incompatible_clients.length === 0 ? "#10b981" : "#ea580c",
                                      fontWeight: 600,
                                    }}
                                  />
                                </Typography>
                                
                                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                  {result.client_compatibility.handshake_simulations.map((sim) => (
                                    <Tooltip
                                      key={sim.client_id}
                                      title={sim.compatible 
                                        ? `Protocol: ${sim.protocol_matched || 'N/A'}, Cipher: ${sim.cipher_matched || 'N/A'}${sim.pq_support ? ' [PQ Ready]' : ''}`
                                        : "Incompatible - no protocol/cipher overlap"
                                      }
                                    >
                                      <Chip
                                        label={sim.client_name}
                                        size="small"
                                        sx={{
                                          bgcolor: alpha(sim.compatible ? "#10b981" : "#dc2626", 0.15),
                                          color: sim.compatible ? "#10b981" : "#dc2626",
                                          fontSize: "0.65rem",
                                        }}
                                        icon={sim.compatible ? 
                                          <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} /> : 
                                          <ErrorIcon sx={{ fontSize: 14, color: "#dc2626" }} />
                                        }
                                      />
                                    </Tooltip>
                                  ))}
                                </Box>
                              </Paper>
                            </Grid>
                          )}
                        </Grid>
                      </Grid>
                    )}

                    {/* Post-Quantum & STARTTLS */}
                    {(result.post_quantum_analysis || result.starttls_info) && (
                      <Grid item xs={12}>
                        <Grid container spacing={2}>
                          {/* Post-Quantum Crypto */}
                          {result.post_quantum_analysis && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: result.post_quantum_analysis.pq_ready ? "#8b5cf6" : "#6b7280",
                                  bgcolor: alpha(result.post_quantum_analysis.pq_ready ? "#8b5cf6" : "#6b7280", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  {result.post_quantum_analysis.pq_ready ? (
                                    <SecurityIcon fontSize="small" sx={{ color: "#8b5cf6" }} />
                                  ) : (
                                    <InfoIcon fontSize="small" color="disabled" />
                                  )}
                                  Post-Quantum Cryptography
                                  {result.post_quantum_analysis.pq_ready && (
                                    <Chip 
                                      label="PQ READY" 
                                      size="small" 
                                      sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }}
                                    />
                                  )}
                                  {result.post_quantum_analysis.nist_compliant && (
                                    <Chip 
                                      label="NIST" 
                                      size="small" 
                                      sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }}
                                    />
                                  )}
                                  <Chip 
                                    label={`${result.post_quantum_analysis.future_proof_score}%`}
                                    size="small"
                                    sx={{ 
                                      bgcolor: alpha(result.post_quantum_analysis.future_proof_score >= 70 ? "#10b981" : "#6b7280", 0.15),
                                      color: result.post_quantum_analysis.future_proof_score >= 70 ? "#10b981" : "#6b7280",
                                      fontWeight: 600,
                                    }}
                                  />
                                </Typography>
                                
                                {result.post_quantum_analysis.pq_ready ? (
                                  <>
                                    {result.post_quantum_analysis.supported_kems.length > 0 && (
                                      <Box sx={{ mb: 1 }}>
                                        <Typography variant="caption" color="text.secondary">KEMs:</Typography>
                                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                                          {result.post_quantum_analysis.supported_kems.map((kem, i) => (
                                            <Chip key={i} label={kem} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                                          ))}
                                        </Box>
                                      </Box>
                                    )}
                                    {result.post_quantum_analysis.supported_signatures.length > 0 && (
                                      <Box sx={{ mb: 1 }}>
                                        <Typography variant="caption" color="text.secondary">Signatures:</Typography>
                                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                                          {result.post_quantum_analysis.supported_signatures.map((sig, i) => (
                                            <Chip key={i} label={sig} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                                          ))}
                                        </Box>
                                      </Box>
                                    )}
                                    {result.post_quantum_analysis.hybrid_support && (
                                      <Typography variant="caption" color="success.main">
                                        ✓ Hybrid mode enabled (classical + PQ)
                                      </Typography>
                                    )}
                                  </>
                                ) : (
                                  <>
                                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                      Server does not support post-quantum cryptography
                                    </Typography>
                                    {result.post_quantum_analysis.recommendations.length > 0 && (
                                      <Typography variant="caption" color="text.secondary">
                                        💡 {result.post_quantum_analysis.recommendations[0]}
                                      </Typography>
                                    )}
                                  </>
                                )}
                              </Paper>
                            </Grid>
                          )}

                          {/* STARTTLS */}
                          {result.starttls_info && (
                            <Grid item xs={12} md={6}>
                              <Paper 
                                variant="outlined" 
                                sx={{ 
                                  p: 2,
                                  borderColor: result.starttls_info.starttls_supported ? "#0891b2" : "#6b7280",
                                  bgcolor: alpha(result.starttls_info.starttls_supported ? "#0891b2" : "#6b7280", 0.05)
                                }}
                              >
                                <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1 }}>
                                  {result.starttls_info.starttls_supported ? (
                                    <HttpsIcon fontSize="small" sx={{ color: "#0891b2" }} />
                                  ) : (
                                    <InfoIcon fontSize="small" color="disabled" />
                                  )}
                                  STARTTLS ({result.starttls_info.protocol})
                                  {result.starttls_info.starttls_supported && (
                                    <Chip 
                                      label="SUPPORTED" 
                                      size="small" 
                                      sx={{ bgcolor: alpha("#0891b2", 0.15), color: "#0891b2", fontWeight: 600 }}
                                    />
                                  )}
                                  {result.starttls_info.starttls_required && (
                                    <Chip 
                                      label="REQUIRED" 
                                      size="small" 
                                      sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }}
                                    />
                                  )}
                                </Typography>
                                
                                {result.starttls_info.starttls_supported ? (
                                  <>
                                    <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                                      {result.starttls_info.implicit_tls_supported && (
                                        <Typography variant="caption" color="success.main">
                                          ✓ Implicit TLS also supported on this port
                                        </Typography>
                                      )}
                                      {result.starttls_info.plain_auth_before_tls && (
                                        <Typography variant="caption" color="error.main">
                                          ⚠️ Plain authentication offered before TLS (security risk)
                                        </Typography>
                                      )}
                                      {result.starttls_info.stripping_possible && (
                                        <Typography variant="caption" color="warning.main">
                                          ⚠️ STARTTLS stripping attack possible (not required)
                                        </Typography>
                                      )}
                                    </Box>
                                  </>
                                ) : (
                                  <Typography variant="body2" color="text.secondary">
                                    STARTTLS not detected on this port
                                  </Typography>
                                )}
                              </Paper>
                            </Grid>
                          )}
                        </Grid>
                      </Grid>
                    )}

                    {/* Vulnerabilities */}
                    {result.vulnerabilities && result.vulnerabilities.length > 0 && (
                      <Grid item xs={12}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <BugReportIcon fontSize="small" color="error" />
                          Known Vulnerabilities ({result.vulnerabilities.length})
                        </Typography>
                        <TableContainer component={Paper} variant="outlined">
                          <Table size="small">
                            <TableHead>
                              <TableRow sx={{ bgcolor: alpha("#dc2626", 0.1) }}>
                                <TableCell sx={{ fontWeight: 600 }}>Vulnerability</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>CVE</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>Severity</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>CVSS</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>Exploit</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {result.vulnerabilities.map((vuln, i) => (
                                <TableRow key={i} sx={{ "&:hover": { bgcolor: alpha("#dc2626", 0.05) } }}>
                                  <TableCell>
                                    <Tooltip title={vuln.description}>
                                      <Typography fontWeight={500}>{vuln.name}</Typography>
                                    </Tooltip>
                                    {vuln.affected && (
                                      <Typography variant="caption" color="text.secondary" display="block">
                                        {vuln.affected}
                                      </Typography>
                                    )}
                                  </TableCell>
                                  <TableCell>
                                    <Chip 
                                      label={vuln.cve} 
                                      size="small" 
                                      variant="outlined"
                                      sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}
                                    />
                                  </TableCell>
                                  <TableCell>
                                    <Chip
                                      label={vuln.severity.toUpperCase()}
                                      size="small"
                                      sx={{
                                        bgcolor: alpha(getSeverityColor(vuln.severity), 0.15),
                                        color: getSeverityColor(vuln.severity),
                                        fontWeight: 600,
                                      }}
                                    />
                                  </TableCell>
                                  <TableCell>
                                    <Typography fontWeight={600} color={vuln.cvss >= 9 ? "#dc2626" : vuln.cvss >= 7 ? "#ea580c" : "#ca8a04"}>
                                      {vuln.cvss}
                                    </Typography>
                                  </TableCell>
                                  <TableCell>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {vuln.is_exploitable && (
                                        <Tooltip title="Exploitable">
                                          <GppBadIcon fontSize="small" color="error" />
                                        </Tooltip>
                                      )}
                                      <Typography variant="caption">
                                        {vuln.exploit_difficulty}
                                      </Typography>
                                    </Box>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Grid>
                    )}

                    {/* Findings */}
                    {result.findings.length > 0 && (
                      <Grid item xs={12}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2 }}>
                          Security Findings
                        </Typography>
                        {result.findings.map((finding, i) => (
                          <Paper
                            key={i}
                            sx={{
                              p: 2,
                              mb: 2,
                              borderLeft: `4px solid ${getSeverityColor(finding.severity)}`,
                              bgcolor: alpha(getSeverityColor(finding.severity), 0.05),
                            }}
                          >
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                              {getSeverityIcon(finding.severity)}
                              <Typography fontWeight={600}>{finding.title}</Typography>
                              <Chip
                                label={finding.severity.toUpperCase()}
                                size="small"
                                sx={{
                                  bgcolor: alpha(getSeverityColor(finding.severity), 0.15),
                                  color: getSeverityColor(finding.severity),
                                  fontWeight: 600,
                                }}
                              />
                              {finding.cve && (
                                <Chip label={finding.cve} size="small" variant="outlined" />
                              )}
                            </Box>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              {finding.description}
                            </Typography>
                            {finding.recommendation && (
                              <Alert severity="info" icon={<SecurityIcon />} sx={{ mt: 1 }}>
                                <Typography variant="body2">
                                  <strong>Recommendation:</strong> {finding.recommendation}
                                </Typography>
                              </Alert>
                            )}
                          </Paper>
                        ))}
                      </Grid>
                    )}
                  </Grid>
                )}
              </AccordionDetails>
            </Accordion>
          ))}

          {/* AI Exploitation Analysis */}
          {results.ai_analysis && (
            <Card sx={{ mt: 3 }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2, flexWrap: "wrap", gap: 1 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <GppBadIcon sx={{ color: "#dc2626" }} />
                    <Typography variant="h6" fontWeight={600}>
                      AI Exploitation Analysis
                    </Typography>
                    <Chip 
                      label="⚠️ OFFENSIVE SECURITY" 
                      size="small" 
                      sx={{ bgcolor: alpha("#dc2626", 0.15), color: "#dc2626", fontWeight: 600, ml: 1 }}
                    />
                  </Box>
                  
                  {/* Export Buttons */}
                  {results.ai_analysis.structured_report && (
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <Tooltip title="Export as Markdown">
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<ArticleIcon />}
                          onClick={() => exportAIReport("markdown")}
                          sx={{ minWidth: 100 }}
                        >
                          MD
                        </Button>
                      </Tooltip>
                      <Tooltip title="Export as PDF">
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<PictureAsPdfIcon />}
                          onClick={() => exportAIReport("pdf")}
                          sx={{ minWidth: 100 }}
                        >
                          PDF
                        </Button>
                      </Tooltip>
                      <Tooltip title="Export as Word Document">
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<DescriptionIcon />}
                          onClick={() => exportAIReport("docx")}
                          sx={{ minWidth: 100 }}
                        >
                          DOCX
                        </Button>
                      </Tooltip>
                    </Box>
                  )}
                </Box>
                
                {results.ai_analysis.error ? (
                  <Alert severity="warning">{results.ai_analysis.error}</Alert>
                ) : results.ai_analysis.structured_report ? (
                  <Box>
                    {/* Risk Summary */}
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
                      <Typography>Overall Risk:</Typography>
                      <Chip
                        label={results.ai_analysis.structured_report.overall_risk_level}
                        sx={{
                          bgcolor: alpha(
                            getSeverityColor(results.ai_analysis.structured_report.overall_risk_level?.toLowerCase() || "info"),
                            0.15
                          ),
                          color: getSeverityColor(results.ai_analysis.structured_report.overall_risk_level?.toLowerCase() || "info"),
                          fontWeight: 600,
                        }}
                      />
                      {results.ai_analysis.structured_report.risk_score !== undefined && (
                        <Typography color="text.secondary">
                          Score: {results.ai_analysis.structured_report.risk_score}/100
                        </Typography>
                      )}
                    </Box>
                    
                    {/* Executive Summary */}
                    {results.ai_analysis.structured_report.executive_summary && (
                      <Alert severity="info" sx={{ mb: 3 }}>
                        <Typography variant="body2">
                          {results.ai_analysis.structured_report.executive_summary}
                        </Typography>
                      </Alert>
                    )}
                    
                    {/* Tabs for different AI sections */}
                    <Tabs value={aiTabValue} onChange={(_, v) => setAiTabValue(v)} sx={{ mb: 2 }}>
                      <Tab label="🎯 Exploitation Scenarios" />
                      <Tab label="� Certificate & Protocol Attacks" />
                      <Tab label="🔗 Attack Chain" />
                      <Tab label="⚡ Quick Wins" />
                    </Tabs>
                    
                    {/* Exploitation Scenarios Tab */}
                    {aiTabValue === 0 && (
                      <Box>
                        {Array.isArray(results.ai_analysis.structured_report?.exploitation_scenarios) && 
                         results.ai_analysis.structured_report.exploitation_scenarios.length > 0 ? (
                          results.ai_analysis.structured_report.exploitation_scenarios.map((scenario: any, i: number) => (
                            <Paper
                              key={i}
                              sx={{
                                p: 2,
                                mb: 2,
                                borderLeft: `4px solid #dc2626`,
                                bgcolor: alpha("#dc2626", 0.03),
                              }}
                            >
                              <Typography variant="subtitle1" fontWeight={700} sx={{ mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                                <GppBadIcon fontSize="small" color="error" />
                                {scenario.title || scenario.attack_name || "Attack Scenario"}
                              </Typography>
                              <Grid container spacing={2} sx={{ mb: 2 }}>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Target</Typography>
                                  <Typography variant="body2" fontWeight={500}>{scenario.target || scenario.target_vulnerability || "N/A"}</Typography>
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Vulnerability</Typography>
                                  <Typography variant="body2" fontWeight={500}>{scenario.vulnerability || "N/A"}</Typography>
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Difficulty</Typography>
                                  <Chip 
                                    label={scenario.difficulty || scenario.exploit_difficulty || "Unknown"} 
                                    size="small" 
                                    color={(scenario.difficulty || scenario.exploit_difficulty) === "Easy" ? "error" : (scenario.difficulty || scenario.exploit_difficulty) === "Medium" ? "warning" : "default"}
                                  />
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Detection Risk</Typography>
                                  <Chip 
                                    label={scenario.detection_risk || "Unknown"} 
                                    size="small" 
                                    color={scenario.detection_risk === "Low" ? "success" : scenario.detection_risk === "Medium" ? "warning" : "error"}
                                    variant="outlined"
                                  />
                                </Grid>
                              </Grid>
                              
                              {scenario.prerequisites && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 0.5 }}>Prerequisites:</Typography>
                                  <Typography variant="body2" color="text.secondary">{scenario.prerequisites}</Typography>
                                </Box>
                              )}
                              
                              {Array.isArray(scenario.attack_steps) && scenario.attack_steps.length > 0 && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>Attack Steps:</Typography>
                                  <ol style={{ margin: 0, paddingLeft: 20 }}>
                                    {scenario.attack_steps.map((step: string, j: number) => (
                                      <li key={j}><Typography variant="body2">{step}</Typography></li>
                                    ))}
                                  </ol>
                                </Box>
                              )}
                              
                              {Array.isArray(scenario.tools) && scenario.tools.length > 0 && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>Tools:</Typography>
                                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                                    {scenario.tools.map((tool: string, j: number) => (
                                      <Chip key={j} icon={<TerminalIcon />} label={tool} size="small" variant="outlined" />
                                    ))}
                                  </Box>
                                </Box>
                              )}
                              
                              {scenario.expected_outcome && (
                                <Box>
                                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 0.5 }}>Expected Outcome:</Typography>
                                  <Typography variant="body2" color="error.main" fontWeight={500}>{scenario.expected_outcome}</Typography>
                                </Box>
                              )}
                            </Paper>
                          ))
                        ) : (
                          <Alert severity="info">No exploitation scenarios available in AI analysis.</Alert>
                        )}
                      </Box>
                    )}
                    
                    {/* Certificate & Protocol Attacks Tab */}
                    {aiTabValue === 1 && (
                      <Box>
                        {/* Certificate Attacks */}
                        {results.ai_analysis.structured_report?.certificate_attacks && (
                          <Box sx={{ mb: 3 }}>
                            <Typography variant="h6" fontWeight={700} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                              <SecurityIcon color="warning" /> Certificate Attacks
                            </Typography>
                            {results.ai_analysis.structured_report.certificate_attacks.summary && (
                              <Alert severity="warning" sx={{ mb: 2 }}>
                                <Typography variant="body2">{results.ai_analysis.structured_report.certificate_attacks.summary}</Typography>
                              </Alert>
                            )}
                            {Array.isArray(results.ai_analysis.structured_report.certificate_attacks.attacks) && 
                             results.ai_analysis.structured_report.certificate_attacks.attacks.length > 0 ? (
                              <Grid container spacing={2}>
                                {results.ai_analysis.structured_report.certificate_attacks.attacks.map((attack: any, i: number) => (
                                  <Grid item xs={12} sm={6} key={i}>
                                    <Paper variant="outlined" sx={{ p: 2, borderLeft: `4px solid #f59e0b` }}>
                                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                                        <Typography variant="subtitle2" fontWeight={700}>{attack.type}</Typography>
                                        <Chip 
                                          label={attack.feasibility} 
                                          size="small" 
                                          color={attack.feasibility === "High" ? "error" : attack.feasibility === "Medium" ? "warning" : "default"}
                                        />
                                      </Box>
                                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{attack.description}</Typography>
                                      {attack.target && <Chip label={`Target: ${attack.target}`} size="small" variant="outlined" />}
                                    </Paper>
                                  </Grid>
                                ))}
                              </Grid>
                            ) : (
                              <Typography variant="body2" color="text.secondary">No certificate attacks identified.</Typography>
                            )}
                          </Box>
                        )}
                        
                        {/* Protocol Attacks */}
                        {results.ai_analysis.structured_report?.protocol_attacks && (
                          <Box>
                            <Typography variant="h6" fontWeight={700} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                              <BugReportIcon color="error" /> Protocol Attacks
                            </Typography>
                            {results.ai_analysis.structured_report.protocol_attacks.summary && (
                              <Alert severity="error" sx={{ mb: 2 }}>
                                <Typography variant="body2">{results.ai_analysis.structured_report.protocol_attacks.summary}</Typography>
                              </Alert>
                            )}
                            {Array.isArray(results.ai_analysis.structured_report.protocol_attacks.attacks) && 
                             results.ai_analysis.structured_report.protocol_attacks.attacks.length > 0 ? (
                              <TableContainer component={Paper} variant="outlined">
                                <Table size="small">
                                  <TableHead>
                                    <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                                      <TableCell sx={{ fontWeight: 600 }}>Vulnerability</TableCell>
                                      <TableCell sx={{ fontWeight: 600 }}>Target</TableCell>
                                      <TableCell sx={{ fontWeight: 600 }}>Exploitation Method</TableCell>
                                      <TableCell sx={{ fontWeight: 600 }}>Tools</TableCell>
                                    </TableRow>
                                  </TableHead>
                                  <TableBody>
                                    {results.ai_analysis.structured_report.protocol_attacks.attacks.map((attack: any, i: number) => (
                                      <TableRow key={i}>
                                        <TableCell>
                                          <Chip label={attack.vulnerability} size="small" color="error" />
                                        </TableCell>
                                        <TableCell>{attack.target}</TableCell>
                                        <TableCell>
                                          <Typography variant="body2">{attack.exploitation_method}</Typography>
                                        </TableCell>
                                        <TableCell>
                                          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                                            {Array.isArray(attack.tools_required) && attack.tools_required.map((tool: string, j: number) => (
                                              <Chip key={j} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                                            ))}
                                          </Box>
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </TableContainer>
                            ) : (
                              <Typography variant="body2" color="text.secondary">No protocol attacks identified.</Typography>
                            )}
                          </Box>
                        )}
                        
                        {!results.ai_analysis.structured_report?.certificate_attacks && 
                         !results.ai_analysis.structured_report?.protocol_attacks && (
                          <Alert severity="info">No certificate or protocol attack analysis available.</Alert>
                        )}
                      </Box>
                    )}
                    
                    {/* Attack Chain Tab */}
                    {aiTabValue === 2 && (
                      <Box>
                        {results.ai_analysis.structured_report?.recommended_attack_chain ? (
                          <>
                            {results.ai_analysis.structured_report.recommended_attack_chain.description && (
                              <Alert severity="warning" sx={{ mb: 3 }}>
                                <Typography variant="body2" fontWeight={600}>
                                  {results.ai_analysis.structured_report.recommended_attack_chain.description}
                                </Typography>
                              </Alert>
                            )}
                            {Array.isArray(results.ai_analysis.structured_report.recommended_attack_chain.steps) && 
                             results.ai_analysis.structured_report.recommended_attack_chain.steps.length > 0 && (
                              <Box sx={{ mb: 3 }}>
                                <Typography variant="h6" fontWeight={700} sx={{ mb: 2 }}>Attack Chain Steps</Typography>
                                {results.ai_analysis.structured_report.recommended_attack_chain.steps.map((step: any, i: number) => (
                                  <Paper
                                    key={i}
                                    sx={{
                                      p: 2,
                                      mb: 2,
                                      borderLeft: `4px solid ${i === 0 ? "#10b981" : "#6366f1"}`,
                                      display: "flex",
                                      alignItems: "flex-start",
                                      gap: 2,
                                    }}
                                  >
                                    <Chip 
                                      label={step.order || i + 1} 
                                      size="small" 
                                      sx={{ 
                                        bgcolor: i === 0 ? "#10b981" : "#6366f1", 
                                        color: "white", 
                                        fontWeight: 700,
                                        minWidth: 32,
                                      }} 
                                    />
                                    <Box sx={{ flex: 1 }}>
                                      <Typography variant="subtitle2" fontWeight={700}>{step.action}</Typography>
                                      {step.target && (
                                        <Typography variant="body2" color="text.secondary">Target: {step.target}</Typography>
                                      )}
                                      {step.expected_result && (
                                        <Typography variant="body2" color="success.main" sx={{ mt: 0.5 }}>
                                          → {step.expected_result}
                                        </Typography>
                                      )}
                                    </Box>
                                  </Paper>
                                ))}
                              </Box>
                            )}
                            {results.ai_analysis.structured_report.recommended_attack_chain.total_effort && (
                              <Chip 
                                icon={<TargetIcon />}
                                label={`Total Effort: ${results.ai_analysis.structured_report.recommended_attack_chain.total_effort}`}
                                color="primary"
                                variant="outlined"
                              />
                            )}
                          </>
                        ) : (
                          <Alert severity="info">No recommended attack chain available in AI analysis.</Alert>
                        )}
                        
                        {/* Recommendations */}
                        {Array.isArray(results.ai_analysis.structured_report?.recommendations) && 
                         results.ai_analysis.structured_report.recommendations.length > 0 && (
                          <Box sx={{ mt: 3 }}>
                            <Typography variant="h6" fontWeight={700} sx={{ mb: 2 }}>Exploitation Recommendations</Typography>
                            <Grid container spacing={2}>
                              {results.ai_analysis.structured_report.recommendations.map((rec: any, i: number) => (
                                <Grid item xs={12} sm={6} key={i}>
                                  <Paper variant="outlined" sx={{ p: 2, height: "100%" }}>
                                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                                      <Chip 
                                        label={rec.priority} 
                                        size="small" 
                                        color={rec.priority === "Immediate" || rec.priority === "High" ? "error" : rec.priority === "Medium" ? "warning" : "default"}
                                      />
                                    </Box>
                                    <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 0.5 }}>{rec.action}</Typography>
                                    <Typography variant="body2" color="text.secondary">{rec.rationale}</Typography>
                                  </Paper>
                                </Grid>
                              ))}
                            </Grid>
                          </Box>
                        )}
                      </Box>
                    )}
                    
                    {/* Quick Wins Tab */}
                    {aiTabValue === 3 && (
                      <Box>
                        <Alert severity="success" sx={{ mb: 2 }}>
                          <Typography variant="body2" fontWeight={600}>
                            These are low-hanging fruit that can be exploited with minimal effort:
                          </Typography>
                        </Alert>
                        {Array.isArray(results.ai_analysis.structured_report?.quick_wins) && 
                         results.ai_analysis.structured_report.quick_wins.length > 0 ? (
                          <Grid container spacing={2}>
                            {results.ai_analysis.structured_report.quick_wins.map((win: any, i: number) => (
                              <Grid item xs={12} sm={6} key={i}>
                                <Paper
                                  variant="outlined"
                                  sx={{
                                    p: 2,
                                    borderLeft: `4px solid #10b981`,
                                    height: "100%",
                                  }}
                                >
                                  {typeof win === "string" ? (
                                    <Typography variant="body2">{win}</Typography>
                                  ) : (
                                    <>
                                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                                        <Typography variant="subtitle2" fontWeight={700}>{win.attack || "Quick Win"}</Typography>
                                        {win.target && <Chip label={win.target} size="small" variant="outlined" />}
                                      </Box>
                                      {win.impact && (
                                        <Typography variant="body2" color="error.main" sx={{ mb: 1 }}>
                                          Impact: {win.impact}
                                        </Typography>
                                      )}
                                      {win.command && (
                                        <Paper sx={{ p: 1, bgcolor: "#1e1e1e", borderRadius: 1, mt: 1 }}>
                                          <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#10b981", fontSize: "0.8rem" }}>
                                            $ {win.command}
                                          </Typography>
                                        </Paper>
                                      )}
                                    </>
                                  )}
                                </Paper>
                              </Grid>
                            ))}
                          </Grid>
                        ) : (
                          <Alert severity="info">No quick wins identified in AI analysis.</Alert>
                        )}
                      </Box>
                    )}
                  </Box>
                ) : (
                  <Typography color="text.secondary">No AI analysis available</Typography>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* AI Chat Popup */}
      {results && (
        <Paper
          elevation={8}
          sx={{
            position: "fixed",
            bottom: 16,
            right: 16,
            left: chatMaximized ? { xs: 16, md: 280 } : "auto",
            width: chatOpen ? (chatMaximized ? "auto" : { xs: "calc(100% - 32px)", sm: 400 }) : "auto",
            maxWidth: chatMaximized ? "none" : 400,
            zIndex: 1200,
            borderRadius: 3,
            overflow: "hidden",
            transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
          }}
        >
          {/* Chat Header */}
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              p: 1.5,
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.primary.dark} 100%)`,
              color: "white",
            }}
          >
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 1,
                cursor: "pointer",
                flex: 1,
              }}
              onClick={() => setChatOpen(!chatOpen)}
            >
              <ChatIcon />
              <Typography variant="subtitle1" fontWeight={600}>
                SSL Analysis Assistant
              </Typography>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              {chatOpen && (
                <IconButton
                  size="small"
                  onClick={() => setChatMaximized(!chatMaximized)}
                  sx={{ color: "white" }}
                >
                  {chatMaximized ? <CloseFullscreenIcon fontSize="small" /> : <OpenInFullIcon fontSize="small" />}
                </IconButton>
              )}
              <IconButton
                size="small"
                onClick={() => setChatOpen(!chatOpen)}
                sx={{ color: "white" }}
              >
                {chatOpen ? <ExpandMoreIcon /> : <ExpandLessIcon />}
              </IconButton>
            </Box>
          </Box>

          {/* Chat Content */}
          <Collapse in={chatOpen}>
            <Box sx={{ display: "flex", flexDirection: "column", height: chatMaximized ? "calc(66vh - 120px)" : 280 }}>
              {/* Messages */}
              <Box
                sx={{
                  flex: 1,
                  overflow: "auto",
                  p: 2,
                  bgcolor: alpha(theme.palette.background.paper, 0.98),
                }}
              >
                {chatMessages.length === 0 ? (
                  <Box sx={{ textAlign: "center", py: 3 }}>
                    <SmartToyIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                    <Typography variant="body2" color="text.secondary">
                      Ask me about the SSL/TLS scan results, certificate issues, or security recommendations.
                    </Typography>
                  </Box>
                ) : (
                  chatMessages.map((msg, idx) => (
                    <Box
                      key={idx}
                      sx={{
                        display: "flex",
                        gap: 1,
                        mb: 2,
                        flexDirection: msg.role === "user" ? "row-reverse" : "row",
                      }}
                    >
                      <Box
                        sx={{
                          width: 28,
                          height: 28,
                          borderRadius: "50%",
                          bgcolor: msg.role === "user" ? "primary.main" : "secondary.main",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          flexShrink: 0,
                        }}
                      >
                        {msg.role === "user" ? (
                          <PersonIcon sx={{ fontSize: 16, color: "white" }} />
                        ) : (
                          <SmartToyIcon sx={{ fontSize: 16, color: "white" }} />
                        )}
                      </Box>
                      <Paper
                        sx={{
                          p: 1.5,
                          maxWidth: "80%",
                          bgcolor: msg.role === "user" ? "primary.main" : alpha(theme.palette.background.default, 0.8),
                          color: msg.role === "user" ? "white" : "text.primary",
                          borderRadius: 2,
                          "& p": { m: 0 },
                          "& p:not(:last-child)": { mb: 1 },
                          "& ul, & ol": { pl: 2, m: 0 },
                          "& li": { mb: 0.5 },
                        }}
                      >
                        <ReactMarkdown
                          components={{
                            code: ({ className, children }) => (
                              <ChatCodeBlock className={className} theme={theme}>
                                {children}
                              </ChatCodeBlock>
                            ),
                          }}
                        >
                          {msg.content}
                        </ReactMarkdown>
                      </Paper>
                    </Box>
                  ))
                )}
                {chatLoading && (
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CircularProgress size={20} />
                    <Typography variant="body2" color="text.secondary">
                      Analyzing...
                    </Typography>
                  </Box>
                )}
                {chatError && (
                  <Alert severity="error" sx={{ mt: 1 }}>
                    {chatError}
                  </Alert>
                )}
                <div ref={chatEndRef} />
              </Box>

              {/* Input */}
              <Box
                sx={{
                  p: 1.5,
                  borderTop: 1,
                  borderColor: "divider",
                  bgcolor: "background.paper",
                }}
              >
                <Box sx={{ display: "flex", gap: 1 }}>
                  <TextField
                    fullWidth
                    size="small"
                    placeholder="Ask about the SSL scan results..."
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyPress={(e) => e.key === "Enter" && !e.shiftKey && handleChatSend()}
                    disabled={chatLoading}
                    sx={{
                      "& .MuiOutlinedInput-root": {
                        borderRadius: 2,
                      },
                    }}
                  />
                  <IconButton
                    color="primary"
                    onClick={handleChatSend}
                    disabled={!chatInput.trim() || chatLoading}
                  >
                    <SendIcon />
                  </IconButton>
                </Box>
              </Box>
            </Box>
          </Collapse>
        </Paper>
      )}
      </>
      )}

      {/* History Tab */}
      {mainTabValue === 1 && (
        <Box>
          {historyLoading ? (
            <Box sx={{ textAlign: "center", py: 6 }}>
              <CircularProgress />
              <Typography color="text.secondary" sx={{ mt: 2 }}>Loading scan history...</Typography>
            </Box>
          ) : historyScans.length === 0 ? (
            <Paper sx={{ p: 6, textAlign: "center" }}>
              <HistoryIcon sx={{ fontSize: 64, color: "text.secondary", mb: 2 }} />
              <Typography variant="h6" gutterBottom>No Scan History</Typography>
              <Typography color="text.secondary" sx={{ mb: 2 }}>
                Run your first SSL scan to see it here
              </Typography>
              <Button variant="contained" onClick={() => setMainTabValue(0)}>
                Run New Scan
              </Button>
            </Paper>
          ) : (
            <Grid container spacing={3}>
              {/* History List */}
              <Grid item xs={12} md={selectedHistoryScan ? 5 : 12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
                      Scan History ({historyTotal} scans)
                    </Typography>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Title</TableCell>
                            <TableCell>Targets</TableCell>
                            <TableCell>Risk</TableCell>
                            <TableCell>Date</TableCell>
                            <TableCell align="right">Actions</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {historyScans.map((scan) => (
                            <TableRow 
                              key={scan.id}
                              hover
                              selected={selectedHistoryScan?.id === scan.id}
                              sx={{ cursor: "pointer" }}
                              onClick={() => loadHistoryScanDetail(scan.id)}
                            >
                              <TableCell>
                                <Box>
                                  <Typography variant="body2" fontWeight={600}>
                                    {scan.title}
                                  </Typography>
                                  {scan.project_name && (
                                    <Chip 
                                      label={scan.project_name} 
                                      size="small" 
                                      variant="outlined"
                                      sx={{ mt: 0.5, height: 20, fontSize: "0.7rem" }}
                                    />
                                  )}
                                </Box>
                              </TableCell>
                              <TableCell>
                                <Typography variant="caption" color="text.secondary" sx={{ 
                                  display: "block",
                                  maxWidth: 200,
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap"
                                }}>
                                  {scan.targets}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                {scan.risk_level && (
                                  <Chip 
                                    label={scan.risk_level}
                                    size="small"
                                    sx={{
                                      bgcolor: alpha(getRiskColor(scan.risk_level), 0.15),
                                      color: getRiskColor(scan.risk_level),
                                      fontWeight: 600,
                                      height: 24,
                                    }}
                                  />
                                )}
                              </TableCell>
                              <TableCell>
                                <Typography variant="caption">
                                  {new Date(scan.created_at).toLocaleDateString()}
                                </Typography>
                              </TableCell>
                              <TableCell align="right">
                                <Tooltip title="View Details">
                                  <IconButton size="small" onClick={(e) => { e.stopPropagation(); loadHistoryScanDetail(scan.id); }}>
                                    <VisibilityIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                                <Tooltip title="Delete">
                                  <IconButton size="small" color="error" onClick={(e) => { e.stopPropagation(); handleDeleteHistoryScan(scan.id); }}>
                                    <DeleteIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </CardContent>
                </Card>
              </Grid>

              {/* Selected Scan Detail */}
              {selectedHistoryScan && (
                <Grid item xs={12} md={7}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
                        <Box>
                          <Typography variant="h6" fontWeight={600}>
                            {selectedHistoryScan.title}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {new Date(selectedHistoryScan.created_at).toLocaleString()}
                          </Typography>
                        </Box>
                        <IconButton onClick={() => setSelectedHistoryScan(null)}>
                          <CloseFullscreenIcon />
                        </IconButton>
                      </Box>

                      <Divider sx={{ my: 2 }} />

                      {/* Summary Stats */}
                      {selectedHistoryScan.summary && (
                        <Grid container spacing={2} sx={{ mb: 3 }}>
                          <Grid item xs={6} sm={3}>
                            <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.info.main, 0.1) }}>
                              <Typography variant="h5" fontWeight={700}>{selectedHistoryScan.summary.total_hosts || 0}</Typography>
                              <Typography variant="caption">Hosts Scanned</Typography>
                            </Paper>
                          </Grid>
                          <Grid item xs={6} sm={3}>
                            <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#dc2626", 0.1) }}>
                              <Typography variant="h5" fontWeight={700} color="#dc2626">{selectedHistoryScan.summary.expired_certs || 0}</Typography>
                              <Typography variant="caption">Expired Certs</Typography>
                            </Paper>
                          </Grid>
                          <Grid item xs={6} sm={3}>
                            <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ea580c", 0.1) }}>
                              <Typography variant="h5" fontWeight={700} color="#ea580c">{selectedHistoryScan.summary.weak_protocols || 0}</Typography>
                              <Typography variant="caption">Weak Protocols</Typography>
                            </Paper>
                          </Grid>
                          <Grid item xs={6} sm={3}>
                            <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ca8a04", 0.1) }}>
                              <Typography variant="h5" fontWeight={700} color="#ca8a04">{selectedHistoryScan.summary.total_vulnerabilities || 0}</Typography>
                              <Typography variant="caption">Vulnerabilities</Typography>
                            </Paper>
                          </Grid>
                        </Grid>
                      )}

                      {/* Findings */}
                      {selectedHistoryScan.findings && selectedHistoryScan.findings.length > 0 && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="subtitle1" fontWeight={600} gutterBottom>
                            Findings by Host
                          </Typography>
                          {selectedHistoryScan.findings.map((hostData: any, idx: number) => (
                            <Accordion key={idx} sx={{ mb: 1 }}>
                              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                <Typography fontWeight={600}>{hostData.host}:{hostData.port}</Typography>
                                <Chip 
                                  label={`${hostData.findings?.length || 0} findings`}
                                  size="small"
                                  sx={{ ml: 2 }}
                                />
                              </AccordionSummary>
                              <AccordionDetails>
                                {hostData.findings?.map((finding: any, fidx: number) => (
                                  <Paper key={fidx} sx={{ p: 1.5, mb: 1, borderLeft: `3px solid ${getRiskColor(finding.severity)}` }}>
                                    <Typography variant="body2" fontWeight={600}>{finding.title}</Typography>
                                    <Typography variant="caption" color="text.secondary">{finding.description}</Typography>
                                  </Paper>
                                ))}
                              </AccordionDetails>
                            </Accordion>
                          ))}
                        </Box>
                      )}

                      {/* AI Analysis */}
                      {selectedHistoryScan.ai_analysis && (
                        <Box>
                          <Typography variant="subtitle1" fontWeight={600} gutterBottom>
                            AI Analysis
                          </Typography>
                          <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                            <ReactMarkdown>
                              {selectedHistoryScan.ai_analysis.structured_report?.executive_summary || 
                               selectedHistoryScan.ai_analysis.executive_summary ||
                               "No AI analysis available"}
                            </ReactMarkdown>
                          </Paper>
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              )}
            </Grid>
          )}
        </Box>
      )}
    </Box>
  );
};

export default SSLScannerPage;
