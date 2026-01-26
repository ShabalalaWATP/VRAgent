import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Grid,
  Divider,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import StorageIcon from "@mui/icons-material/Storage";
import CloudQueueIcon from "@mui/icons-material/CloudQueue";
import CodeIcon from "@mui/icons-material/Code";
import ApiIcon from "@mui/icons-material/Api";
import MemoryIcon from "@mui/icons-material/Memory";
import SecurityIcon from "@mui/icons-material/Security";
import SpeedIcon from "@mui/icons-material/Speed";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import WebhookIcon from "@mui/icons-material/Webhook";
import PsychologyIcon from "@mui/icons-material/Psychology";
import LayersIcon from "@mui/icons-material/Layers";
import DataObjectIcon from "@mui/icons-material/DataObject";
import BugReportIcon from "@mui/icons-material/BugReport";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import BuildIcon from "@mui/icons-material/Build";
import GroupIcon from "@mui/icons-material/Group";
import ViewKanbanIcon from "@mui/icons-material/ViewKanban";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import HttpIcon from "@mui/icons-material/Http";
import RouterIcon from "@mui/icons-material/Router";
import DnsIcon from "@mui/icons-material/Dns";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import TerminalIcon from "@mui/icons-material/Terminal";
import AndroidIcon from "@mui/icons-material/Android";
import DescriptionIcon from "@mui/icons-material/Description";
import ChatIcon from "@mui/icons-material/Chat";
import PersonIcon from "@mui/icons-material/Person";
import FiberManualRecordIcon from "@mui/icons-material/FiberManualRecord";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import ShuffleIcon from "@mui/icons-material/Shuffle";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

interface FeatureInfo {
  name: string;
  icon: React.ReactNode;
  description: string;
  capabilities: string[];
  files?: string[];
  color: string;
}

interface ServiceInfo {
  name: string;
  file: string;
  description: string;
  responsibilities: string[];
  dependencies?: string[];
  color: string;
}

const backendServices: ServiceInfo[] = [
  {
    name: "Scan Service",
    file: "scan_service.py",
    description: "Orchestrates the entire scanning pipeline with parallel phase execution using ThreadPoolExecutor.",
    responsibilities: [
      "Manages the 14-phase scanning workflow with progress tracking",
      "Runs SAST, Docker, IaC, and dependency scanning in parallel (Phase 4-7)",
      "Smart scanner selection based on detected languages",
      "ParallelPhaseTracker coordinates concurrent phase progress",
      "Broadcasts real-time progress via WebSocket + Redis pub/sub",
    ],
    dependencies: ["codebase_service", "dependency_service", "semgrep_service", "docker_scan_service", "iac_scan_service"],
    color: "#3b82f6",
  },
  {
    name: "Codebase Service",
    file: "codebase_service.py",
    description: "Handles code extraction with security protections and intelligent chunking for embeddings.",
    responsibilities: [
      "Extracts archives with zip bomb protection (500MB/10K file limits)",
      "Path traversal protection validates all extracted paths",
      "Streaming extraction handles large codebases efficiently",
      "Intelligent chunking respects function/class boundaries",
      "Security-relevant code prioritized for embedding",
    ],
    color: "#8b5cf6",
  },
  {
    name: "Embedding Service",
    file: "embedding_service.py",
    description: "Generates vector embeddings using Gemini for semantic code search.",
    responsibilities: [
      "Uses gemini-embedding-001 model (768 dimensions)",
      "SHA-256 content hashing enables embedding reuse",
      "Batch processing for efficient API usage",
      "Stored in PostgreSQL with pgvector extension",
      "Can be disabled via SKIP_EMBEDDINGS for faster scans",
    ],
    color: "#ec4899",
  },
  {
    name: "Dependency Service",
    file: "dependency_service.py",
    description: "Parses dependency manifests across 8 ecosystems with lock file support.",
    responsibilities: [
      "Parses: requirements.txt, Pipfile, pyproject.toml (Python)",
      "Parses: package.json, package-lock.json, yarn.lock (npm)",
      "Parses: pom.xml, build.gradle (Java), go.mod/sum (Go)",
      "Parses: Gemfile (Ruby), Cargo.toml (Rust), composer.json (PHP)",
      "Deduplicates dependencies from multiple manifest files",
    ],
    color: "#10b981",
  },
  {
    name: "Transitive Deps Service",
    file: "transitive_deps_service.py",
    description: "Analyzes lock files to build complete dependency trees.",
    responsibilities: [
      "Parses package-lock.json, yarn.lock, pnpm-lock.yaml",
      "Parses poetry.lock, Pipfile.lock, go.sum",
      "Identifies direct vs transitive dependencies",
      "Maps vulnerable paths through dependency tree",
      "Calculates dependency depth for prioritization",
    ],
    color: "#f59e0b",
  },
  {
    name: "Reachability Service",
    file: "reachability_service.py",
    description: "Determines if vulnerable dependencies are actually used in reachable code paths.",
    responsibilities: [
      "Analyzes import statements across all source files",
      "Checks if vulnerable package functions are called",
      "Marks unreachable vulnerabilities for deprioritization",
      "Provides import evidence for reachable vulns",
      "Reduces false positives from unused dependencies",
    ],
    color: "#7c3aed",
  },
  {
    name: "CVE Service",
    file: "cve_service.py",
    description: "Queries OSV.dev for known vulnerabilities in dependencies.",
    responsibilities: [
      "Batch queries OSV API (100 deps per request)",
      "Maps ecosystem names to OSV format",
      "Extracts CVE/GHSA IDs, severity, affected versions",
      "Handles rate limiting with concurrent batches",
      "Aggregates advisories from multiple sources",
    ],
    dependencies: ["nvd_service", "epss_service"],
    color: "#ef4444",
  },
  {
    name: "NVD Service",
    file: "nvd_service.py",
    description: "Enriches CVEs with detailed data from NIST NVD and CISA KEV.",
    responsibilities: [
      "Fetches full CVSS v3/v4 vectors and scores",
      "Retrieves CWE weakness classifications",
      "Checks CISA KEV (Known Exploited Vulnerabilities)",
      "KEV matches auto-escalate to HIGH severity",
      "Caches responses for 24 hours",
    ],
    color: "#dc2626",
  },
  {
    name: "EPSS Service",
    file: "epss_service.py",
    description: "Scores CVEs by real-world exploitation probability using FIRST's EPSS.",
    responsibilities: [
      "Batch queries EPSS API for all CVEs",
      "Returns exploitation probability (0-100%)",
      "Provides percentile ranking vs all CVEs",
      "High EPSS scores escalate severity",
      "Caches scores for 24 hours",
    ],
    color: "#f97316",
  },
  {
    name: "Semgrep Service",
    file: "semgrep_service.py",
    description: "Runs Semgrep with 2000+ security rules across 30+ languages.",
    responsibilities: [
      "Executes with OWASP, CWE, and framework rulesets",
      "Parses SARIF output into normalized findings",
      "Supports taint tracking for data flow analysis",
      "Configurable rule severity and timeout",
      "Primary SAST scanner for all languages",
    ],
    color: "#6366f1",
  },
  {
    name: "Secret Service",
    file: "secret_service.py",
    description: "Scans for 50+ types of hardcoded secrets with high-confidence patterns.",
    responsibilities: [
      "Detects AWS, Azure, GCP, OpenAI API keys",
      "Finds GitHub, GitLab, Slack, Discord tokens",
      "Identifies Stripe, Twilio, SendGrid keys",
      "Detects RSA, SSH, PGP private keys",
      "Database connection strings and passwords",
    ],
    color: "#dc2626",
  },
  {
    name: "Docker Scan Service",
    file: "docker_scan_service.py",
    description: "Scans Docker resources using Trivy and custom Dockerfile linting.",
    responsibilities: [
      "Trivy scans images for OS-level vulnerabilities",
      "Custom Dockerfile rules detect misconfigurations",
      "Checks for running as root, exposed ports",
      "Detects secrets in build args",
      "Validates base image versioning",
    ],
    color: "#2496ed",
  },
  {
    name: "IaC Scan Service",
    file: "iac_scan_service.py",
    description: "Infrastructure as Code scanning with Checkov and tfsec.",
    responsibilities: [
      "Checkov scans Terraform, K8s, CloudFormation, Helm",
      "tfsec provides additional Terraform checks",
      "Detects public S3, unencrypted storage, IAM issues",
      "Identifies missing network policies in K8s",
      "Supports ARM templates for Azure",
    ],
    color: "#7c3aed",
  },
  {
    name: "AI Analysis Service",
    file: "ai_analysis_service.py",
    description: "Three-stage analysis: heuristics, Agentic corroboration, then LLM for complex cases.",
    responsibilities: [
      "Heuristic patterns detect obvious false positives (test files, mock code)",
      "Agentic AI corroboration cross-references scanner + agentic findings",
      "Severity adjustment for context (auth, admin, ORM, parameterized queries)",
      "8 pre-defined attack chain patterns for multi-vuln exploits",
      "LLM analysis limited to MAX_FINDINGS=50 most critical",
    ],
    color: "#8b5cf6",
  },
  {
    name: "Exploit Service",
    file: "exploit_service.py",
    description: "Generates exploit scenarios using templates and LLM.",
    responsibilities: [
      "16+ pre-built exploit templates for common vulns",
      "Templates for SQLi, XSS, RCE, SSRF, XXE, etc.",
      "LLM generates scenarios for novel vuln types",
      "Includes attack steps, PoC outlines, impact",
      "Provides remediation code examples",
    ],
    dependencies: ["ai_analysis_service"],
    color: "#ef4444",
  },
  {
    name: "Export Service",
    file: "export_service.py",
    description: "Generates security reports in Markdown, PDF, and DOCX formats.",
    responsibilities: [
      "Uses cached AI summaries for instant exports",
      "Includes severity breakdown with charts",
      "Adds CVSS scores, EPSS, KEV status",
      "Creates hyperlinks to CVE/CWE references",
      "Generates professional PDF reports",
    ],
    color: "#059669",
  },
  {
    name: "SBOM Service",
    file: "sbom_service.py",
    description: "Generates Software Bill of Materials in CycloneDX 1.5 format.",
    responsibilities: [
      "CycloneDX 1.5 JSON/XML export",
      "Package URLs (purl) for all dependencies",
      "Includes license information when available",
      "Maps vulnerabilities to components",
      "Compliant with industry standards",
    ],
    color: "#0891b2",
  },
  {
    name: "Deduplication Service",
    file: "deduplication_service.py",
    description: "Cross-scanner deduplication to eliminate redundant findings.",
    responsibilities: [
      "Merges same file+line+type findings across scanners",
      "Preserves scanner sources for audit trail",
      "Takes severity from highest-confidence scanner",
      "Tracks merge statistics",
      "Reduces noise in final report",
    ],
    color: "#84cc16",
  },
];

const languageScanners = [
  { language: "Python", scanner: "Bandit", service: "bandit_service.py", detects: "eval/exec, shell injection, hardcoded passwords, weak crypto (MD5, SHA1)" },
  { language: "JavaScript/TypeScript", scanner: "ESLint Security", service: "eslint_service.py", detects: "XSS, eval injection, prototype pollution, regex DoS" },
  { language: "Java/Kotlin", scanner: "SpotBugs + FindSecBugs", service: "spotbugs_service.py", detects: "SQL injection, XXE, LDAP injection, Spring security issues" },
  { language: "Go", scanner: "gosec", service: "gosec_service.py", detects: "SQL injection, command injection, path traversal, insecure TLS" },
  { language: "C/C++", scanner: "clang-tidy", service: "clangtidy_service.py", detects: "Buffer overflows, format strings, memory safety, use-after-free" },
  { language: "All Languages", scanner: "Semgrep", service: "semgrep_service.py", detects: "2000+ rules: OWASP Top 10, CWE Top 25, taint tracking" },
  { language: "All Files", scanner: "Secret Scanner", service: "secret_service.py", detects: "50+ patterns: AWS, GCP, Azure, OpenAI, private keys, DB strings" },
  { language: "Dockerfiles", scanner: "Trivy + Custom Rules", service: "docker_scan_service.py", detects: "Image vulns, running as root, exposed ports, secrets in args" },
  { language: "Terraform/K8s/CF", scanner: "Checkov + tfsec", service: "iac_scan_service.py", detects: "Public S3, unencrypted storage, overly permissive IAM, missing policies" },
];

const dockerServices = [
  { name: "frontend", port: "3000", tech: "React + Vite + nginx", description: "User interface served via nginx" },
  { name: "backend", port: "8000", tech: "FastAPI + Uvicorn", description: "REST API and WebSocket server" },
  { name: "worker", port: "-", tech: "Python + RQ", description: "Background job processor for scans" },
  { name: "db", port: "5432", tech: "PostgreSQL + pgvector", description: "Primary database with vector extension" },
  { name: "redis", port: "6379", tech: "Redis 7", description: "Job queue and WebSocket pub/sub" },
];

const dataModels = [
  { model: "Project", description: "A scanned codebase with metadata", fields: "id, name, description, created_at" },
  { model: "ScanRun", description: "A single scan execution", fields: "id, project_id, status, started_at, completed_at, risk_score" },
  { model: "Finding", description: "A security vulnerability discovered", fields: "id, scan_run_id, type, severity, file_path, line, message, cwe, cve" },
  { model: "Dependency", description: "A third-party package", fields: "id, scan_run_id, ecosystem, name, version, vulnerabilities" },
  { model: "ExploitScenario", description: "AI-generated attack narrative", fields: "id, finding_id, narrative, impact, poc, mitigations" },
  { model: "Webhook", description: "Notification endpoint", fields: "id, project_id, url, type, active" },
];

// ============ FEATURE HUB DATA ============

const securityScanFeatures: FeatureInfo[] = [
  {
    name: "Static Code Analysis (SAST)",
    icon: <BugReportIcon />,
    description: "Multi-scanner security analysis with 14-phase pipeline and parallel execution.",
    capabilities: [
      "12+ security scanners (Semgrep, Bandit, ESLint, GoSec, SpotBugs, Brakeman, etc.)",
      "Language auto-detection triggers appropriate scanners",
      "ThreadPoolExecutor parallel scanning (2× CPU cores)",
      "Real-time progress via WebSocket + Redis pub/sub",
      "Cross-scanner deduplication to reduce noise",
    ],
    files: ["scan_service.py", "semgrep_service.py", "bandit_service.py"],
    color: "#3b82f6",
  },
  {
    name: "Agentic AI Scanning",
    icon: <SmartToyIcon />,
    description: "Deep AI-powered vulnerability hunting with source-to-sink analysis.",
    capabilities: [
      "Always-enabled agentic scanning mode",
      "Progressive file analysis (80→30→12 files)",
      "Entry point discovery and call flow tracing",
      "CWE mapping and severity classification",
      "Cross-references SAST findings for validation",
    ],
    files: ["agentic_scan_service.py", "agentic_scan.py"],
    color: "#8b5cf6",
  },
  {
    name: "VulnHuntr",
    icon: <PsychologyIcon />,
    description: "LLM-powered vulnerability hunting with source-to-sink data flow tracing.",
    capabilities: [
      "Deep LLM analysis for vulnerability confirmation",
      "Python source/sink pattern matching",
      "Quick scan mode for code snippets",
      "Markdown report generation",
      "False positive reduction through AI verification",
    ],
    files: ["vulnhuntr_service.py", "vulnhuntr.py"],
    color: "#ec4899",
  },
  {
    name: "Exploitability Analysis",
    icon: <WarningIcon />,
    description: "AI-generated attack chains and exploit scenarios with severity ranking.",
    capabilities: [
      "Multiple analysis modes: full, summary, auto",
      "Attack chain diagram generation (Mermaid)",
      "16+ pre-built exploit templates (SQLi, XSS, RCE, etc.)",
      "Executive summary generation",
      "Remediation code examples",
    ],
    files: ["exploit_service.py", "exploitability.py"],
    color: "#ef4444",
  },
  {
    name: "Three-Stage AI Analysis",
    icon: <LayersIcon />,
    description: "Heuristics → Agentic corroboration → LLM for smart false positive reduction.",
    capabilities: [
      "Heuristic patterns detect obvious false positives (test files, mock code)",
      "Agentic AI cross-references scanner findings",
      "Context-aware severity adjustment (auth, admin, ORM)",
      "8 pre-defined attack chain patterns",
      "LLM analysis limited to top 50 critical findings",
    ],
    files: ["ai_analysis_service.py"],
    color: "#7c3aed",
  },
  {
    name: "Dependency Security",
    icon: <AccountTreeIcon />,
    description: "Full dependency tree analysis with CVE lookup and reachability checking.",
    capabilities: [
      "8 ecosystem support (npm, pip, Maven, Go, Ruby, Rust, PHP, .NET)",
      "OSV.dev batch queries (100 deps/request)",
      "Transitive dependency tree building from lock files",
      "Reachability analysis - check if vulns are actually used",
      "EPSS scoring + CISA KEV auto-escalation",
    ],
    files: ["dependency_service.py", "cve_service.py", "reachability_service.py"],
    color: "#10b981",
  },
];

const reverseEngineeringFeatures: FeatureInfo[] = [
  {
    name: "Binary Analysis",
    icon: <MemoryIcon />,
    description: "Deep analysis of EXE, ELF, DLL, SO files with Ghidra decompilation.",
    capabilities: [
      "Ghidra headless decompilation",
      "Rich header analysis and symbol extraction",
      "Fuzzy hashing (SSDEEP, TLSH, imphash)",
      "YARA rule matching",
      "CAPA capability analysis",
    ],
    files: ["ghidra_service.py", "reverse_engineering.py"],
    color: "#6366f1",
  },
  {
    name: "APK/Mobile Analysis",
    icon: <AndroidIcon />,
    description: "Android application security analysis with Androguard, JADX decompilation, and FRIDA script generation.",
    capabilities: [
      "Androguard static analysis and APK parsing",
      "JADX decompilation to Java source code",
      "Manifest parsing, permission analysis, and component identification",
      "FRIDA script generation for SSL bypass, root detection bypass, method hooking",
      "Certificate validation, signing info, and native library extraction",
    ],
    files: ["reverse_engineering.py", "reverse_engineering_service.py"],
    color: "#10b981",
  },
  {
    name: "Docker Image Analysis",
    icon: <LayersIcon />,
    description: "Layer-by-layer Docker image security inspection.",
    capabilities: [
      "Layer-by-layer filesystem analysis",
      "Configuration inspection",
      "Per-layer vulnerability scanning",
      "Secrets detection in layers",
      "Base image tracing",
    ],
    files: ["docker_scan_service.py"],
    color: "#2496ed",
  },
  {
    name: "AI-Powered RE Analysis",
    icon: <PsychologyIcon />,
    description: "Multi-pass vulnerability hunting with FRIDA dynamic instrumentation and attack surface mapping.",
    capabilities: [
      "Multi-pass vulnerability hunting with legitimacy filtering and false positive reduction",
      "Attack surface mapping with entry point discovery and call flow tracing",
      "FRIDA script generation for dynamic analysis, hooking, and runtime manipulation",
      "Unicorn emulation scripts for sandbox execution and behavior analysis",
      "CVE lookup, correlation, and exploitability assessment",
    ],
    files: ["reverse_engineering.py", "reverse_engineering_service.py"],
    color: "#8b5cf6",
  },
  {
    name: "11-Phase Unified Scan",
    icon: <SecurityIcon />,
    description: "Complete binary security assessment pipeline.",
    capabilities: [
      "Static analysis → Ghidra decompilation → Pattern scanning",
      "CVE lookup → Sensitive data discovery → AI verification",
      "Attack surface mapping → Frida script generation",
      "Unicorn emulation → Report generation",
      "Comprehensive security report output",
    ],
    files: ["reverse_engineering.py"],
    color: "#ef4444",
  },
];

const networkFeatures: FeatureInfo[] = [
  {
    name: "Dynamic Scanner",
    icon: <SmartToyIcon />,
    description: "AI-orchestrated automated pentesting combining 8+ security tools with intelligent routing.",
    capabilities: [
      "Integrated tools: Nmap, OWASP ZAP, Nuclei, OpenVAS, SQLMap, Wapiti, Gobuster, ExploitDB",
      "AI-Led mode with intelligent scan strategy and tool selection",
      "12-phase pipeline: Recon → Routing → Web/Network Scanning → CVE Detection → Exploit Mapping → AI Analysis",
      "Advanced features: Authenticated scanning, API testing (OpenAPI/GraphQL), OOB testing, validation pass",
      "Generates attack narratives, exploit chains, and prioritized remediation guidance",
    ],
    files: ["dynamic_scan_service.py", "dynamic_scan_agent.py", "dynamic_scan.py"],
    color: "#8b5cf6",
  },
  {
    name: "PCAP Analysis",
    icon: <NetworkCheckIcon />,
    description: "Multi-file network capture analysis with protocol inspection.",
    capabilities: [
      "Multi-file PCAP upload and analysis",
      "Protocol distribution analysis",
      "Top talkers identification",
      "DNS query extraction",
      "Credential detection in traffic",
    ],
    files: ["pcap_service.py", "network.py", "pcap.py"],
    color: "#3b82f6",
  },
  {
    name: "Nmap Integration",
    icon: <RouterIcon />,
    description: "Network scanning with service detection and OS fingerprinting.",
    capabilities: [
      "Nmap scan file analysis",
      "Live network scanning",
      "Service detection and version enumeration",
      "OS fingerprinting",
      "Network topology visualization",
    ],
    files: ["nmap_service.py", "network.py"],
    color: "#10b981",
  },
  {
    name: "SSL/TLS Scanner",
    icon: <VpnKeyIcon />,
    description: "SSL/TLS vulnerability detection and certificate validation.",
    capabilities: [
      "POODLE, BEAST, Heartbleed, ROBOT detection",
      "Certificate validation and chain analysis",
      "Protocol version enumeration",
      "Cipher suite analysis",
      "Security recommendations",
    ],
    files: ["network.py"],
    color: "#f59e0b",
  },
  {
    name: "DNS Reconnaissance",
    icon: <DnsIcon />,
    description: "Comprehensive DNS enumeration and security analysis.",
    capabilities: [
      "DNS enumeration (A, AAAA, MX, NS, TXT, etc.)",
      "Subdomain discovery",
      "Zone transfer attempts",
      "Security analysis (SPF, DMARC, DKIM, DNSSEC, CAA)",
      "WHOIS lookup for domains and IPs",
    ],
    files: ["dns_service.py", "dns.py"],
    color: "#7c3aed",
  },
  {
    name: "Traceroute & Nmap Analyzer",
    icon: <AccountTreeIcon />,
    description: "Network path analysis with latency and hop visualization, plus Nmap port scanning.",
    capabilities: [
      "Real-time streaming traceroute",
      "Nmap port scanning with 10+ scan profiles",
      "Nmap output file analysis (XML/nmap/gnmap)",
      "AI-generated path and port analysis",
      "Service version detection",
    ],
    files: ["traceroute_service.py", "traceroute.py", "nmap_service.py", "network.py"],
    color: "#ec4899",
  },
  {
    name: "MITM Proxy Workbench",
    icon: <ShuffleIcon />,
    description: "Intercepting proxy with rule-based traffic modification.",
    capabilities: [
      "Multiple proxy instance management",
      "Interception modes: passthrough, intercept, auto_modify",
      "8 preset rules (CORS bypass, CSP removal, script injection)",
      "Natural language rule creation via AI",
      "AI-powered traffic analysis",
    ],
    files: ["mitm_service.py", "mitm.py"],
    color: "#ef4444",
  },
];

const apiTestingFeatures: FeatureInfo[] = [
  {
    name: "API Security Testing",
    icon: <HttpIcon />,
    description: "Full API security assessment with OWASP API Top 10 coverage.",
    capabilities: [
      "Authentication and authorization testing",
      "CORS and rate limiting analysis",
      "Input validation testing",
      "GraphQL security testing",
      "WebSocket security testing",
    ],
    files: ["api_tester_service.py", "api_tester.py"],
    color: "#3b82f6",
  },
  {
    name: "OpenAPI/Swagger Import",
    icon: <DescriptionIcon />,
    description: "Import and parse API specifications for automated testing.",
    capabilities: [
      "OpenAPI/Swagger spec parsing",
      "Automatic endpoint discovery",
      "Parameter extraction",
      "Test case generation",
      "Batch testing support",
    ],
    files: ["api_tester_service.py"],
    color: "#10b981",
  },
  {
    name: "JWT Analysis",
    icon: <VpnKeyIcon />,
    description: "JSON Web Token security analysis and vulnerability detection.",
    capabilities: [
      "Algorithm vulnerability detection",
      "Weak secret detection",
      "Expiration validation",
      "Claim analysis",
      "Token manipulation testing",
    ],
    files: ["api_tester_service.py"],
    color: "#f59e0b",
  },
];

const fuzzingFeatures: FeatureInfo[] = [
  {
    name: "Binary Fuzzer",
    icon: <MemoryIcon />,
    description: "Coverage-guided binary fuzzing with AFL++, Honggfuzz, and libFuzzer for native code vulnerability discovery.",
    capabilities: [
      "Fuzzing engines: AFL++, Honggfuzz, libFuzzer with intelligent engine selection",
      "Detects: Buffer overflow, UAF, integer overflow, format string, double-free, heap corruption",
      "Automatic crash triage and deduplication with stack trace analysis",
      "Exploitability assessment and PoC generation with minimal reproducer inputs",
      "Coverage tracking, corpus minimization, and mutation strategies",
    ],
    files: ["binary_fuzzer_service.py", "binary_fuzzer.py"],
    color: "#10b981",
  },
  {
    name: "Web Fuzzer",
    icon: <TerminalIcon />,
    description: "High-performance web application fuzzing with multiple attack modes.",
    capabilities: [
      "Attack modes: sniper, batteringram, pitchfork, clusterbomb",
      "Position marker support for targeted fuzzing",
      "Concurrent threading (up to 50 threads)",
      "Real-time streaming via SSE/WebSocket",
      "Status code matching and regex filtering",
    ],
    files: ["fuzzing_service.py", "fuzzing_advanced.py", "fuzzing.py"],
    color: "#ef4444",
  },
  {
    name: "Built-in Wordlists",
    icon: <DataObjectIcon />,
    description: "Comprehensive payload libraries for common attack vectors.",
    capabilities: [
      "SQL Injection payloads",
      "XSS payloads",
      "Path traversal (LFI) payloads",
      "Command injection payloads",
      "SSTI payloads",
    ],
    files: ["fuzzing_service.py"],
    color: "#8b5cf6",
  },
  {
    name: "Payload Transformations",
    icon: <BuildIcon />,
    description: "Advanced encoding and mutation capabilities.",
    capabilities: [
      "Multiple encodings (URL, Base64, HTML, Unicode, Hex)",
      "Payload generators (number/char range, date, UUID)",
      "Payload mutations (case, encoding, whitespace)",
      "Null byte and comment injection",
      "Concatenation variants",
    ],
    files: ["fuzzing_advanced.py"],
    color: "#7c3aed",
  },
  {
    name: "Smart Detection",
    icon: <PsychologyIcon />,
    description: "Intelligent vulnerability detection and analysis.",
    capabilities: [
      "Signature-based vulnerability detection",
      "Anomaly detection (time, length, status, content)",
      "Response clustering and categorization",
      "WAF detection",
      "Differential analysis",
    ],
    files: ["fuzzing_advanced.py"],
    color: "#3b82f6",
  },
];

const collaborationFeatures: FeatureInfo[] = [
  {
    name: "Contacts & Friends",
    icon: <GroupIcon />,
    description: "Connect with other security researchers and team members.",
    capabilities: [
      "User search and suggested connections",
      "Friend/contact request system",
      "Public profile viewing",
      "Private notes about contacts",
      "Connection management",
    ],
    files: ["social.py", "messaging_service.py"],
    color: "#3b82f6",
  },
  {
    name: "Direct Messaging",
    icon: <ChatIcon />,
    description: "Real-time 1-on-1 conversations with rich features.",
    capabilities: [
      "Real-time message delivery via WebSocket",
      "Message editing and deletion",
      "Read receipts and typing indicators",
      "Message threading (replies)",
      "Unread counts and notifications",
    ],
    files: ["social.py", "messaging_service.py"],
    color: "#10b981",
  },
  {
    name: "Group Chat",
    icon: <GroupIcon />,
    description: "Team collaboration with role-based permissions.",
    capabilities: [
      "Create groups with multiple members",
      "Member roles (owner, admin, member)",
      "Add/remove/promote members",
      "Group settings and avatars",
      "Shared conversation history",
    ],
    files: ["social.py"],
    color: "#8b5cf6",
  },
  {
    name: "Advanced Messaging",
    icon: <ChatIcon />,
    description: "Rich messaging features for team collaboration.",
    capabilities: [
      "Message reactions (emoji)",
      "Message pinning and bookmarks",
      "Message forwarding and search",
      "@mentions with user resolution",
      "Polls (single/multiple choice, anonymous)",
    ],
    files: ["social.py"],
    color: "#f59e0b",
  },
  {
    name: "Content Sharing",
    icon: <SecurityIcon />,
    description: "Share security findings and reports with team members.",
    capabilities: [
      "Share findings to conversations",
      "Share reports to conversations",
      "File uploads (up to 1GB)",
      "Support for security file types",
      "GIF integration",
    ],
    files: ["social.py"],
    color: "#ef4444",
  },
  {
    name: "User Presence",
    icon: <FiberManualRecordIcon />,
    description: "Real-time online status and availability indicators.",
    capabilities: [
      "Online/offline/away status",
      "Last seen timestamps",
      "Real-time status updates via WebSocket",
      "Bulk presence queries",
      "Status indicators on contacts",
    ],
    files: ["presence_service.py", "websocket.py"],
    color: "#22c55e",
  },
  {
    name: "Kanban Boards",
    icon: <ViewKanbanIcon />,
    description: "Visual task management for security projects.",
    capabilities: [
      "Board creation per project",
      "Customizable columns with WIP limits",
      "Drag-and-drop card management",
      "Create cards from security findings",
      "Card comments and assignees",
    ],
    files: ["kanban_service.py", "kanban.py"],
    color: "#7c3aed",
  },
];

export default function ArchitecturePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const CodeBlock = ({ code, id }: { code: string; id: string }) => (
    <Box sx={{ position: "relative", mt: 1 }}>
      <Paper
        sx={{
          p: 2,
          bgcolor: alpha(theme.palette.common.black, 0.85),
          borderRadius: 2,
          fontFamily: "monospace",
          fontSize: "0.8rem",
          color: "#e2e8f0",
          overflow: "auto",
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
        }}
      >
        <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{code}</pre>
      </Paper>
      <Tooltip title={copiedCmd === id ? "Copied!" : "Copy"}>
        <IconButton
          size="small"
          onClick={() => handleCopy(code, id)}
          sx={{
            position: "absolute",
            top: 8,
            right: 8,
            color: copiedCmd === id ? "success.main" : "grey.500",
            bgcolor: alpha(theme.palette.background.paper, 0.8),
          }}
        >
          <ContentCopyIcon fontSize="small" />
        </IconButton>
      </Tooltip>
    </Box>
  );

  const FeatureCard = ({ feature }: { feature: FeatureInfo }) => (
    <Card
      sx={{
        height: "100%",
        borderRadius: 3,
        border: `1px solid ${alpha(feature.color, 0.2)}`,
        transition: "all 0.2s",
        "&:hover": {
          borderColor: feature.color,
          transform: "translateY(-4px)",
          boxShadow: `0 8px 24px ${alpha(feature.color, 0.15)}`,
        },
      }}
    >
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
          <Box
            sx={{
              width: 40,
              height: 40,
              borderRadius: 2,
              bgcolor: alpha(feature.color, 0.15),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: feature.color,
            }}
          >
            {feature.icon}
          </Box>
          <Typography variant="h6" sx={{ fontWeight: 700, fontSize: "1rem" }}>
            {feature.name}
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.6 }}>
          {feature.description}
        </Typography>
        <List dense sx={{ p: 0 }}>
          {feature.capabilities.map((cap, i) => (
            <ListItem key={i} sx={{ px: 0, py: 0.25 }}>
              <ListItemIcon sx={{ minWidth: 24 }}>
                <CheckCircleIcon sx={{ fontSize: 14, color: feature.color }} />
              </ListItemIcon>
              <ListItemText
                primary={cap}
                primaryTypographyProps={{ variant: "caption", color: "text.secondary" }}
              />
            </ListItem>
          ))}
        </List>
        {feature.files && (
          <Box sx={{ mt: 2, display: "flex", gap: 0.5, flexWrap: "wrap" }}>
            {feature.files.map((file) => (
              <Chip
                key={file}
                label={file}
                size="small"
                sx={{ fontSize: "0.65rem", fontFamily: "monospace", height: 20 }}
              />
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  );

  const pageContext = `This page covers VRAgent's complete system architecture including:
- Static Analysis: 14-phase SAST pipeline, Agentic AI, VulnHuntr, exploitability analysis with 12+ scanners
- Reverse Engineering Hub: Binary analysis with Ghidra, APK/mobile with Androguard & FRIDA, Docker images, YARA & CAPA
- Dynamic Analysis: Dynamic Scanner (OWASP ZAP, OpenVAS, Nuclei, SQLMap), PCAP, Nmap, SSL/TLS, DNS recon, MITM proxy
- API Security Testing: OWASP API Top 10, JWT analysis, OpenAPI import, GraphQL security
- Security Fuzzing: Binary Fuzzer (AFL++, Honggfuzz, libFuzzer), Web Fuzzer, multi-mode payload generation
- Collaboration: Contacts, messaging, group chat, user presence, Kanban boards
- Docker services and deployment architecture
- Backend services and data models`;

  return (
    <LearnPageLayout pageTitle="VRAgent Architecture" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <Chip
        component={Link}
        to="/learn"
        icon={<ArrowBackIcon />}
        label="Back to Learning Hub"
        clickable
        variant="outlined"
        sx={{ borderRadius: 2, mb: 3 }}
      />

      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: 3,
              bgcolor: alpha("#6366f1", 0.15),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <AccountTreeIcon sx={{ fontSize: 32, color: "#6366f1" }} />
          </Box>
          <Box>
            <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
              VRAgent Architecture
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Deep dive into how VRAgent is built and how components interact
            </Typography>
          </Box>
        </Box>

        {/* Tech Stack Quick View */}
        <Paper
          sx={{
            p: 2,
            borderRadius: 3,
            display: "flex",
            flexWrap: "wrap",
            gap: 1.5,
            justifyContent: "center",
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          {[
            { label: "React 18", color: "#61dafb" },
            { label: "FastAPI", color: "#009688" },
            { label: "PostgreSQL", color: "#336791" },
            { label: "pgvector", color: "#336791" },
            { label: "Redis", color: "#dc382d" },
            { label: "Docker", color: "#2496ed" },
            { label: "Gemini AI", color: "#8b5cf6" },
            { label: "Semgrep", color: "#10b981" },
            { label: "Ghidra", color: "#ef4444" },
            { label: "Trivy", color: "#2496ed" },
            { label: "Checkov", color: "#7c3aed" },
            { label: "Nmap", color: "#f59e0b" },
            { label: "WebSocket", color: "#3b82f6" },
          ].map((tech) => (
            <Chip
              key={tech.label}
              label={tech.label}
              size="small"
              sx={{
                bgcolor: alpha(tech.color, 0.15),
                color: tech.color,
                fontWeight: 600,
                border: `1px solid ${alpha(tech.color, 0.3)}`,
              }}
            />
          ))}
        </Paper>
      </Box>

      {/* Tabs */}
      <Paper sx={{ borderRadius: 3, overflow: "hidden", mb: 4 }}>
        <Tabs
          value={tabValue}
          onChange={(_, v) => setTabValue(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            "& .MuiTab-root": { fontWeight: 600, textTransform: "none", minHeight: 56 },
          }}
        >
          <Tab label="🏗️ Overview" />
          <Tab label="🔍 Static Analysis" />
          <Tab label="🔬 Reverse Engineering" />
          <Tab label="🌐 Dynamic Analysis" />
          <Tab label="🧪 API & Fuzzing" />
          <Tab label="👥 Collaboration" />
          <Tab label="⚙️ Backend Services" />
          <Tab label="🐳 Docker" />
        </Tabs>
      </Paper>

      {/* System Overview */}
      <TabPanel value={tabValue} index={0}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          System Architecture Overview
        </Typography>
        
        {/* ASCII Architecture Diagram */}
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4, bgcolor: alpha(theme.palette.common.black, 0.85) }}>
          <Typography
            component="pre"
            sx={{
              fontFamily: "monospace",
              fontSize: { xs: "0.5rem", sm: "0.65rem", md: "0.75rem" },
              color: "#e2e8f0",
              overflow: "auto",
              lineHeight: 1.4,
              m: 0,
            }}
          >
{`┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              VRAgent Platform Architecture                           │
└─────────────────────────────────────────────────────────────────────────────────────┘

                                    ┌─────────────────┐
                                    │   Web Browser   │
                                    │  (React + MUI)  │
                                    └────────┬────────┘
                                             │
           ┌─────────────────────────────────┼─────────────────────────────────┐
           │                                 │                                 │
           ▼                                 ▼                                 ▼
┌─────────────────┐              ┌─────────────────┐              ┌─────────────────┐
│  REST API       │              │   WebSocket     │              │  SSE Streaming  │
│  (CRUD, Auth)   │              │  (Real-time)    │              │  (Progress)     │
└────────┬────────┘              └────────┬────────┘              └────────┬────────┘
         │                                │                                │
         └────────────────────────────────┼────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              FastAPI Backend (Port 8000)                            │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
│  │   Scans     │  │  Reverse    │  │   Network   │  │     API     │  │  Fuzzing  │ │
│  │   Router    │  │  Eng Router │  │   Router    │  │   Tester    │  │  Router   │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘ │
│         │                │                │                │               │       │
│  ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐  ┌─────┴─────┐ │
│  │ Social      │  │ Kanban      │  │ Auth        │  │ Projects    │  │ Webhooks  │ │
│  │ Router      │  │ Router      │  │ Router      │  │ Router      │  │ Router    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │
│                                                                                     │
└──────────────────────────────────────┬──────────────────────────────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│   PostgreSQL    │          │      Redis      │          │   Background    │
│   + pgvector    │          │   Queue/PubSub  │          │     Worker      │
│   Port: 5432    │          │   Port: 6379    │          │    (RQ Jobs)    │
└─────────────────┘          └─────────────────┘          └────────┬────────┘
                                                                   │
         ┌─────────────────────────────────────────────────────────┤
         │                                                         │
         ▼                                                         ▼
┌─────────────────────────────────────┐     ┌─────────────────────────────────────────┐
│        Security Scanners            │     │           External Services             │
├─────────────────────────────────────┤     ├─────────────────────────────────────────┤
│ • Semgrep (2000+ rules)             │     │ • Gemini AI (Analysis + Embeddings)     │
│ • Bandit (Python)                   │     │ • OSV.dev (CVE Database)                │
│ • ESLint Security (JS/TS)           │     │ • NVD (NIST Vuln Data)                  │
│ • GoSec (Go)                        │     │ • EPSS (Exploit Probability)            │
│ • SpotBugs + FindSecBugs (Java)     │     │ • CISA KEV (Known Exploited)            │
│ • Brakeman (Ruby)                   │     │ • Slack/Teams/Discord (Webhooks)        │
│ • clang-tidy (C/C++)                │     │                                         │
│ • Trivy (Docker/Container)          │     │                                         │
│ • Checkov + tfsec (IaC)             │     │                                         │
│ • Secret Scanner (50+ patterns)     │     │                                         │
│ • Ghidra (Binary Analysis)          │     │                                         │
│ • Nmap (Network Scanning)           │     │                                         │
└─────────────────────────────────────┘     └─────────────────────────────────────────┘`}
          </Typography>
        </Paper>

        {/* Feature Highlights */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Platform Capabilities
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {[
            {
              title: "Static Analysis",
              icon: <SecurityIcon />,
              description: "14-phase pipeline with 12+ SAST scanners, agentic AI, VulnHuntr, and exploitability analysis.",
              color: "#3b82f6",
            },
            {
              title: "Reverse Engineering",
              icon: <MemoryIcon />,
              description: "Binary analysis with Ghidra, APK decompilation with Androguard/FRIDA, Docker layer inspection, YARA & CAPA.",
              color: "#ef4444",
            },
            {
              title: "Dynamic Analysis",
              icon: <NetworkCheckIcon />,
              description: "AI Dynamic Scanner (ZAP, OpenVAS, Nuclei, SQLMap), PCAP, Nmap, SSL/TLS, DNS recon, MITM proxy.",
              color: "#10b981",
            },
            {
              title: "API Security",
              icon: <HttpIcon />,
              description: "OWASP API Top 10 testing, JWT analysis, OpenAPI/GraphQL import, and automated endpoint discovery.",
              color: "#f59e0b",
            },
            {
              title: "Security Fuzzing",
              icon: <TerminalIcon />,
              description: "Binary Fuzzer (AFL++, Honggfuzz, libFuzzer), web fuzzer with payload mutations, smart detection, WAF bypass.",
              color: "#8b5cf6",
            },
            {
              title: "Collaboration",
              icon: <GroupIcon />,
              description: "Real-time messaging, group chat, user presence, Kanban boards, and security content sharing.",
              color: "#ec4899",
            },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.title}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha(item.color, 0.2)}`,
                  transition: "all 0.2s",
                  "&:hover": { borderColor: item.color },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                  <Box sx={{ color: item.color }}>{item.icon}</Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    {item.title}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                  {item.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Key Architectural Decisions */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Architectural Patterns
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {[
            {
              title: "Microservices via Docker",
              icon: <CloudQueueIcon />,
              description: "Each component runs in an isolated container for easy scaling and deployment. All services communicate over a Docker network.",
              color: "#2496ed",
            },
            {
              title: "Async Job Processing",
              icon: <SpeedIcon />,
              description: "Scans run in a background worker via Redis Queue (RQ). This keeps the API responsive and allows long-running scans.",
              color: "#dc382d",
            },
            {
              title: "Real-time Updates",
              icon: <WebhookIcon />,
              description: "WebSocket + Redis pub/sub provide live progress. ParallelPhaseTracker coordinates concurrent phase updates.",
              color: "#f59e0b",
            },
            {
              title: "Three-Stage AI Analysis",
              icon: <PsychologyIcon />,
              description: "Heuristics → Agentic corroboration → LLM (Gemini). Cross-references SAST findings with deep AI scan to reduce false positives.",
              color: "#8b5cf6",
            },
            {
              title: "Smart Scanner Selection",
              icon: <SecurityIcon />,
              description: "Language detection triggers appropriate scanners. 12+ scanners run in parallel via ThreadPoolExecutor (2× CPU cores).",
              color: "#ef4444",
            },
            {
              title: "Embedding Reuse",
              icon: <StorageIcon />,
              description: "SHA-256 content hashing enables embedding reuse between scans. pgvector stores 768-dim Gemini embeddings.",
              color: "#336791",
            },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.title}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha(item.color, 0.2)}`,
                  transition: "all 0.2s",
                  "&:hover": { borderColor: item.color },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                  <Box sx={{ color: item.color }}>{item.icon}</Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    {item.title}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                  {item.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Static Analysis Tab */}
      <TabPanel value={tabValue} index={1}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Static Analysis (SAST)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Comprehensive static code analysis with 12+ scanners, AI-powered vulnerability hunting, and intelligent false positive reduction.
        </Typography>

        <Grid container spacing={3}>
          {securityScanFeatures.map((feature) => (
            <Grid item xs={12} md={6} key={feature.name}>
              <FeatureCard feature={feature} />
            </Grid>
          ))}
        </Grid>

        {/* Scanner Table */}
        <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2 }}>
          Language-Specific Scanners
        </Typography>
        <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Language</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Scanner</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Service File</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Detects</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {languageScanners.map((scanner) => (
                <TableRow key={scanner.scanner}>
                  <TableCell>
                    <Chip label={scanner.language} size="small" />
                  </TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{scanner.scanner}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{scanner.service}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{scanner.detects}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* Reverse Engineering Tab */}
      <TabPanel value={tabValue} index={2}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Reverse Engineering Hub
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Deep analysis of binaries, APKs, and Docker images with Ghidra integration and AI-powered vulnerability hunting.
        </Typography>

        <Grid container spacing={3}>
          {reverseEngineeringFeatures.map((feature) => (
            <Grid item xs={12} md={6} key={feature.name}>
              <FeatureCard feature={feature} />
            </Grid>
          ))}
        </Grid>

        {/* Supported File Types */}
        <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2 }}>
          Supported File Types
        </Typography>
        <Grid container spacing={2}>
          {[
            { type: "Windows Executables", extensions: ".exe, .dll, .sys", color: "#3b82f6" },
            { type: "Linux/macOS Binaries", extensions: "ELF, .so, Mach-O", color: "#10b981" },
            { type: "Android Apps", extensions: ".apk, .aab", color: "#22c55e" },
            { type: "Docker Images", extensions: "docker://image:tag", color: "#2496ed" },
            { type: "Archives", extensions: ".zip, .tar, .gz", color: "#f59e0b" },
            { type: "YARA Rules", extensions: ".yar, .yara", color: "#8b5cf6" },
          ].map((item) => (
            <Grid item xs={6} sm={4} md={2} key={item.type}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  textAlign: "center",
                  border: `1px solid ${alpha(item.color, 0.2)}`,
                }}
              >
                <Typography variant="caption" sx={{ fontWeight: 700, display: "block", color: item.color }}>
                  {item.type}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                  {item.extensions}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Dynamic Analysis Tab */}
      <TabPanel value={tabValue} index={3}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Dynamic Analysis Hub
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Runtime security analysis including AI-orchestrated Dynamic Scanner, PCAP inspection, Nmap scanning, SSL/TLS auditing, DNS reconnaissance, and MITM proxy.
        </Typography>

        <Grid container spacing={3}>
          {networkFeatures.map((feature) => (
            <Grid item xs={12} md={6} key={feature.name}>
              <FeatureCard feature={feature} />
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* API & Fuzzing Tab */}
      <TabPanel value={tabValue} index={4}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          API Security & Fuzzing
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Automated API security testing and advanced fuzzing capabilities for web application security assessment.
        </Typography>

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          API Security Testing
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {apiTestingFeatures.map((feature) => (
            <Grid item xs={12} md={4} key={feature.name}>
              <FeatureCard feature={feature} />
            </Grid>
          ))}
        </Grid>

        <Divider sx={{ my: 4 }} />

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Security Fuzzing
        </Typography>
        <Grid container spacing={3}>
          {fuzzingFeatures.map((feature) => (
            <Grid item xs={12} md={6} key={feature.name}>
              <FeatureCard feature={feature} />
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Collaboration Tab */}
      <TabPanel value={tabValue} index={5}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Collaboration Features
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Real-time communication, project management, and security content sharing for team collaboration.
        </Typography>

        <Grid container spacing={3}>
          {collaborationFeatures.map((feature) => (
            <Grid item xs={12} md={6} lg={4} key={feature.name}>
              <FeatureCard feature={feature} />
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Backend Services Tab */}
      <TabPanel value={tabValue} index={6}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Backend Services
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The backend is organized into focused services, each handling a specific responsibility. Located in <code>backend/services/</code>.
        </Typography>

        <Grid container spacing={3}>
          {backendServices.map((svc) => (
            <Grid item xs={12} md={6} key={svc.name}>
              <Accordion
                sx={{
                  borderRadius: "12px !important",
                  border: `1px solid ${alpha(svc.color, 0.2)}`,
                  "&:before": { display: "none" },
                  overflow: "hidden",
                }}
              >
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box
                      sx={{
                        width: 8,
                        height: 40,
                        borderRadius: 1,
                        bgcolor: svc.color,
                      }}
                    />
                    <Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {svc.name}
                      </Typography>
                      <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary" }}>
                        {svc.file}
                      </Typography>
                    </Box>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {svc.description}
                  </Typography>
                  <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 1 }}>
                    Responsibilities:
                  </Typography>
                  <Box component="ul" sx={{ pl: 2, m: 0 }}>
                    {svc.responsibilities.map((r, i) => (
                      <Typography component="li" variant="caption" key={i} sx={{ mb: 0.5 }}>
                        {r}
                      </Typography>
                    ))}
                  </Box>
                  {svc.dependencies && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
                        Dependencies:
                      </Typography>
                      <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                        {svc.dependencies.map((dep) => (
                          <Chip key={dep} label={dep} size="small" sx={{ fontSize: "0.65rem", height: 20 }} />
                        ))}
                      </Box>
                    </Box>
                  )}
                </AccordionDetails>
              </Accordion>
            </Grid>
          ))}
        </Grid>

        {/* Data Models */}
        <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2 }}>
          Core Data Models
        </Typography>
        <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Model</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Key Fields</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {dataModels.map((model) => (
                <TableRow key={model.model}>
                  <TableCell>
                    <Chip label={model.model} color="primary" size="small" sx={{ fontWeight: 600 }} />
                  </TableCell>
                  <TableCell>{model.description}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{model.fields}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* Docker Services Tab */}
      <TabPanel value={tabValue} index={7}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Docker Services
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          VRAgent runs as 5 Docker containers orchestrated via docker-compose. All services include health checks for reliability.
        </Typography>

        <TableContainer component={Paper} sx={{ borderRadius: 3, mb: 4 }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Service</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Port</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Technology</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {dockerServices.map((svc) => (
                <TableRow key={svc.name} sx={{ "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.03) } }}>
                  <TableCell>
                    <Chip label={svc.name} size="small" sx={{ fontWeight: 600, fontFamily: "monospace" }} />
                  </TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{svc.port}</TableCell>
                  <TableCell>{svc.tech}</TableCell>
                  <TableCell>{svc.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Docker Compose Configuration
        </Typography>
        <CodeBlock
          id="docker-compose"
          code={`# Key services from docker-compose.yml

services:
  db:
    image: pgvector/pgvector:pg16    # PostgreSQL with vector extension
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vragent"]

  redis:
    image: redis:7-alpine             # Job queue and pub/sub
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]

  backend:
    build: ./backend
    ports: ["8000:8000"]
    depends_on:
      db: { condition: service_healthy }
      redis: { condition: service_healthy }

  worker:
    build: ./backend
    command: python -m backend.worker  # RQ worker process
    depends_on: [db, redis]

  frontend:
    build: ./frontend
    ports: ["3000:80"]                 # nginx serves React app
    depends_on: [backend]

volumes:
  postgres_data:    # Persistent database storage
  redis_data:       # Redis persistence (optional)
  upload_data:      # Uploaded code archives`}
        />

        <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2 }}>
          Common Docker Commands
        </Typography>
        <Grid container spacing={2}>
          {[
            { cmd: "docker-compose up -d", desc: "Start all services" },
            { cmd: "docker-compose down", desc: "Stop all services" },
            { cmd: "docker-compose logs -f backend", desc: "View backend logs" },
            { cmd: "docker-compose ps", desc: "Check service status" },
            { cmd: "docker-compose exec backend alembic upgrade head", desc: "Run migrations" },
            { cmd: "docker-compose down -v", desc: "Stop and delete all data" },
          ].map((item, i) => (
            <Grid item xs={12} sm={6} key={i}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  bgcolor: alpha(theme.palette.common.black, 0.8),
                  cursor: "pointer",
                  "&:hover": { bgcolor: alpha(theme.palette.common.black, 0.9) },
                }}
                onClick={() => handleCopy(item.cmd, `cmd-${i}`)}
              >
                <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#e2e8f0", mb: 0.5 }}>
                  {item.cmd}
                </Typography>
                <Typography variant="caption" sx={{ color: "grey.500" }}>
                  {item.desc} {copiedCmd === `cmd-${i}` && "✓ Copied!"}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Footer */}
      <Paper
        sx={{
          mt: 4,
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha("#6366f1", 0.1)}, ${alpha(theme.palette.background.paper, 0.8)})`,
          border: `1px solid ${alpha("#6366f1", 0.2)}`,
        }}
      >
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
          🔧 Want to Contribute?
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          VRAgent is open source! Check out the repository to explore the code and contribute.
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
          <Chip
            label="Back to Learning Hub"
            clickable
            onClick={() => navigate("/learn")}
            sx={{ fontWeight: 600 }}
          />
          <Chip
            label="How Scanning Works →"
            clickable
            onClick={() => navigate("/learn/scanning")}
            sx={{ bgcolor: "#6366f1", color: "white", fontWeight: 600, "&:hover": { bgcolor: "#4f46e5" } }}
          />
        </Box>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
