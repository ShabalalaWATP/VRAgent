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
} from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
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
      "Manages the 9-phase scanning workflow with progress tracking",
      "Runs SAST, Docker, IaC, and dependency scanning in parallel",
      "Coordinates embedding generation with reuse from previous scans",
      "Handles cross-scanner deduplication of findings",
      "Broadcasts real-time progress via WebSocket",
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
      "Content hash comparison enables embedding reuse",
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
    description: "Heuristic + LLM analysis for false positives, severity adjustment, and summaries.",
    responsibilities: [
      "Heuristic patterns detect obvious false positives",
      "Severity adjustment for context (auth, admin, internal)",
      "Attack chain discovery from related findings",
      "LLM analysis limited to MAX_FINDINGS=50",
      "Background summary generation after scan completes",
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

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <IconButton onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
          <ArrowBackIcon />
        </IconButton>
        
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
            { label: "Trivy", color: "#2496ed" },
            { label: "Checkov", color: "#7c3aed" },
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
          <Tab label="🏗️ System Overview" />
          <Tab label="🐳 Docker Services" />
          <Tab label="⚙️ Backend Services" />
          <Tab label="🔍 Scanners" />
          <Tab label="📊 Data Models" />
          <Tab label="🔄 Scan Pipeline" />
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
              fontSize: { xs: "0.6rem", sm: "0.75rem", md: "0.85rem" },
              color: "#e2e8f0",
              overflow: "auto",
              lineHeight: 1.4,
              m: 0,
            }}
          >
{`┌─────────────────────────────────────────────────────────────────────────────┐
│                              VRAgent Architecture                           │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────────┐                        ┌─────────────────────────────┐
    │   Web Browser   │                        │      External Services      │
    │  (User Client)  │                        │                             │
    └────────┬────────┘                        │  • OSV.dev (CVE database)   │
             │                                 │  • NVD (NIST)               │
             │ HTTP/WebSocket                  │  • EPSS (Exploit scores)    │
             ▼                                 │  • Gemini AI                │
    ┌─────────────────┐                        │  • Slack/Teams/Discord      │
    │    Frontend     │                        └─────────────────────────────┘
    │  React + Vite   │                                      ▲
    │  Port: 3000     │                                      │
    │  (nginx)        │                                      │ HTTPS
    └────────┬────────┘                                      │
             │                                               │
             │ HTTP API                        ┌─────────────┴───────────────┐
             ▼                                 │                             │
    ┌─────────────────┐      Job Queue         │     ┌─────────────────┐     │
    │    Backend      │◄─────────────────────► │     │     Worker      │     │
    │    FastAPI      │        Redis           │     │    RQ Jobs      │     │
    │  Port: 8000     │◄─────────────────────► │     │  (Background)   │     │
    └────────┬────────┘      Pub/Sub           │     └─────────────────┘     │
             │                                 │              │               │
             │ SQL                             │              │               │
             ▼                                 │              ▼               │
    ┌─────────────────┐                        │     ┌─────────────────┐     │
    │   PostgreSQL    │◄───────────────────────┼─────│   Scan Engine   │     │
    │   + pgvector    │                        │     │   • Semgrep     │     │
    │  Port: 5432     │                        │     │   • Bandit      │     │
    └─────────────────┘                        │     │   • ESLint      │     │
                                               │     │   • gosec       │     │
    ┌─────────────────┐                        │     │   • SpotBugs    │     │
    │     Redis       │◄───────────────────────┘     │   • clang-tidy  │     │
    │  Port: 6379     │                              │   • Secrets     │     │
    │  (Queue+Cache)  │                              └─────────────────┘     │
    └─────────────────┘                                                       │
                                                                              │
    ┌─────────────────────────────────────────────────────────────────────────┘
    │
    │  All services run in Docker containers on a shared network (vragent-network)
    │  Volumes: postgres_data, redis_data, upload_data
    │
    └─────────────────────────────────────────────────────────────────────────────`}
          </Typography>
        </Paper>

        {/* Key Architectural Decisions */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Key Architectural Decisions
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
              description: "WebSocket connections provide live scan progress. Redis pub/sub enables worker-to-API communication.",
              color: "#f59e0b",
            },
            {
              title: "AI-Augmented Analysis",
              icon: <PsychologyIcon />,
              description: "Google Gemini generates exploit narratives and code summaries. Results are cached to minimize API costs.",
              color: "#8b5cf6",
            },
            {
              title: "Multi-Scanner Pipeline",
              icon: <SecurityIcon />,
              description: "Language-specific scanners run in parallel for comprehensive coverage. Results are normalized into a common format.",
              color: "#ef4444",
            },
            {
              title: "Vector Database Ready",
              icon: <StorageIcon />,
              description: "PostgreSQL with pgvector extension enables semantic search over code. Embeddings are generated via Gemini.",
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

        {/* Data Flow */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Request Flow: Starting a Scan
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3 }}>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {[
              { step: 1, action: "User clicks 'Start Scan'", component: "Frontend", detail: "POST /projects/{id}/scan" },
              { step: 2, action: "API creates ScanRun record", component: "Backend", detail: "Status: PENDING" },
              { step: 3, action: "Job enqueued to Redis", component: "Backend → Redis", detail: "RQ job with scan_run_id" },
              { step: 4, action: "Worker picks up job", component: "Worker", detail: "Starts 9-phase pipeline" },
              { step: 5, action: "Code extracted & chunked", component: "Worker", detail: "Zip bomb + path traversal protection" },
              { step: 6, action: "Embeddings generated (or reused)", component: "Worker → Gemini", detail: "768-dim vectors via gemini-embedding-001" },
              { step: 7, action: "Parallel scan phases execute", component: "Worker", detail: "SAST + Docker + IaC + Deps concurrently" },
              { step: 8, action: "Findings deduplicated", component: "Worker", detail: "Cross-scanner merge" },
              { step: 9, action: "CVE lookup + enrichment", component: "Worker → OSV/NVD/EPSS/KEV", detail: "Parallel enrichment for all vulns" },
              { step: 10, action: "Reachability analysis", component: "Worker", detail: "Import analysis for unused deps" },
              { step: 11, action: "AI analysis (heuristics + LLM)", component: "Worker → Gemini", detail: "Top 50 findings to LLM" },
              { step: 12, action: "Scan complete, webhooks fired", component: "Worker", detail: "Status: COMPLETED" },
              { step: 13, action: "Background summary generation", component: "Worker → Gemini", detail: "Async after scan for instant exports" },
            ].map((item) => (
              <Box key={item.step} sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                <Chip
                  label={item.step}
                  size="small"
                  sx={{ bgcolor: alpha("#6366f1", 0.15), color: "#6366f1", fontWeight: 700, minWidth: 32 }}
                />
                <Box sx={{ flex: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {item.action}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {item.component} — {item.detail}
                  </Typography>
                </Box>
              </Box>
            ))}
          </Box>
        </Paper>
      </TabPanel>

      {/* Docker Services */}
      <TabPanel value={tabValue} index={1}>
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

      {/* Backend Services */}
      <TabPanel value={tabValue} index={2}>
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
      </TabPanel>

      {/* Scanners */}
      <TabPanel value={tabValue} index={3}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Security Scanners
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          VRAgent automatically runs the appropriate scanners based on detected languages. All scanner outputs are normalized into a common finding format.
        </Typography>

        <TableContainer component={Paper} sx={{ borderRadius: 3, mb: 4 }}>
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

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Scanner Execution Flow
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, mb: 4 }}>
          <CodeBlock
            id="scanner-flow"
            code={`# Simplified scanner execution in scan_service.py

async def run_scanners(project_path: str, languages: set[str]):
    findings = []
    
    # Always run Semgrep (multi-language)
    findings.extend(await semgrep_service.scan(project_path))
    
    # Always run secret scanner
    findings.extend(await secret_service.scan(project_path))
    
    # Run language-specific scanners
    if "Python" in languages:
        findings.extend(await bandit_service.scan(project_path))
    
    if "JavaScript" in languages or "TypeScript" in languages:
        findings.extend(await eslint_service.scan(project_path))
    
    if "Go" in languages:
        findings.extend(await gosec_service.scan(project_path))
    
    if "Java" in languages or "Kotlin" in languages:
        findings.extend(await spotbugs_service.scan(project_path))
    
    if "C" in languages or "C++" in languages:
        findings.extend(await clangtidy_service.scan(project_path))
    
    return deduplicate_findings(findings)`}
          />
        </Paper>

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Finding Normalization
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Each scanner outputs findings in different formats. VRAgent normalizes all findings to a common schema:
        </Typography>
        <CodeBlock
          id="finding-schema"
          code={`# Normalized finding structure

{
    "type": "sql_injection",           # Vulnerability category
    "severity": "HIGH",                # CRITICAL, HIGH, MEDIUM, LOW
    "message": "SQL query built from user input",
    "file_path": "src/db/queries.py",
    "line_start": 42,
    "line_end": 45,
    "code_snippet": "query = f'SELECT * FROM users WHERE id = {user_id}'",
    "scanner": "bandit",               # Which scanner found it
    "rule_id": "B608",                 # Scanner-specific rule
    "cwe": "CWE-89",                   # Weakness classification
    "cve": null,                       # CVE if applicable
    "confidence": "HIGH"               # Scanner confidence
}`}
        />
      </TabPanel>

      {/* Data Models */}
      <TabPanel value={tabValue} index={4}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Data Models
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          VRAgent uses SQLAlchemy ORM with PostgreSQL. Models are defined in <code>backend/models/models.py</code>.
        </Typography>

        <TableContainer component={Paper} sx={{ borderRadius: 3, mb: 4 }}>
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

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Entity Relationship
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.common.black, 0.85) }}>
          <Typography
            component="pre"
            sx={{
              fontFamily: "monospace",
              fontSize: "0.8rem",
              color: "#e2e8f0",
              overflow: "auto",
              m: 0,
            }}
          >
{`┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│   Project   │──────<│   ScanRun   │──────<│   Finding   │
│             │ 1:N   │             │ 1:N   │             │
│ id          │       │ id          │       │ id          │
│ name        │       │ project_id  │       │ scan_run_id │
│ description │       │ status      │       │ type        │
│ created_at  │       │ risk_score  │       │ severity    │
└─────────────┘       │ started_at  │       │ file_path   │
      │               │ completed_at│       │ message     │
      │               └─────────────┘       │ cwe, cve    │
      │                     │               └─────────────┘
      │                     │                     │
      │                     │                     │ 1:1
      │                     │                     ▼
      │                     │               ┌─────────────┐
      │                     │               │  Exploit    │
      │                     │               │  Scenario   │
      │               1:N   │               │             │
      │                     ▼               │ finding_id  │
      │               ┌─────────────┐       │ narrative   │
      │               │ Dependency  │       │ impact      │
      │               │             │       │ poc         │
      │               │ scan_run_id │       │ mitigations │
      │               │ ecosystem   │       └─────────────┘
      │               │ name        │
      │               │ version     │
      │               │ vulns (JSON)│
      │               └─────────────┘
      │ 1:N
      ▼
┌─────────────┐
│   Webhook   │
│             │
│ project_id  │
│ url         │
│ type        │
│ active      │
└─────────────┘`}
          </Typography>
        </Paper>
      </TabPanel>

      {/* Scan Pipeline */}
      <TabPanel value={tabValue} index={5}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          The 9-Phase Scan Pipeline
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The pipeline uses parallel execution where possible. Phases 1-3 are sequential, Phase 4 runs all scanning types concurrently, then phases 5-9 are sequential with parallel API calls.
        </Typography>

        <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {[
            { phase: 1, name: "Code Acquisition", desc: "Clone repo or extract archive with zip bomb + path traversal protection", duration: "5-30s", service: "git_service / codebase_service" },
            { phase: 2, name: "Code Parsing & Chunking", desc: "Stream parse files, create semantic chunks (500 tokens max)", duration: "10-60s", service: "codebase_service" },
            { phase: 3, name: "Embedding Generation", desc: "gemini-embedding-001 (768 dims), reuses unchanged embeddings", duration: "20-60s", service: "embedding_service" },
            { phase: 4, name: "Parallel Scan Phases", desc: "SAST + Docker + IaC + Dependencies run concurrently via ThreadPoolExecutor", duration: "60-300s", service: "scan_service → all scanners" },
            { phase: 5, name: "Cross-Scanner Deduplication", desc: "Merge same file+line+type findings from multiple scanners", duration: "2-5s", service: "deduplication_service" },
            { phase: 6, name: "Transitive Dependency Analysis", desc: "Parse lock files to build full dependency trees", duration: "5-15s", service: "transitive_deps_service" },
            { phase: 7, name: "CVE Lookup + Parallel Enrichment", desc: "OSV.dev → then NVD + EPSS + CISA KEV in parallel", duration: "30-90s", service: "cve_service → nvd/epss_service" },
            { phase: 8, name: "Reachability Analysis", desc: "Check if vulnerable deps are actually imported/used", duration: "10-30s", service: "reachability_service" },
            { phase: 9, name: "AI Analysis", desc: "Heuristics first, then LLM for top 50 findings + exploit templates", duration: "30-120s", service: "ai_analysis_service" },
          ].map((phase, i) => (
            <Paper
              key={phase.phase}
              sx={{
                p: 3,
                borderRadius: 3,
                border: `1px solid ${alpha(theme.palette.primary.main, 0.1)}`,
                display: "flex",
                alignItems: "flex-start",
                gap: 3,
                transition: "all 0.2s",
                "&:hover": {
                  borderColor: theme.palette.primary.main,
                  transform: "translateX(8px)",
                },
              }}
            >
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: "50%",
                  bgcolor: phase.phase === 4 ? alpha("#10b981", 0.15) : alpha(theme.palette.primary.main, 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 800, color: phase.phase === 4 ? "#10b981" : "primary.main" }}>
                  {phase.phase}
                </Typography>
              </Box>
              <Box sx={{ flex: 1 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 0.5 }}>
                  {phase.name}
                  {phase.phase === 4 && <Chip label="PARALLEL" size="small" sx={{ ml: 1, bgcolor: "#10b981", color: "white", fontSize: "0.65rem" }} />}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {phase.desc}
                </Typography>
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                  <Chip label={phase.duration} size="small" sx={{ fontSize: "0.7rem" }} />
                  <Chip
                    label={phase.service}
                    size="small"
                    sx={{ fontSize: "0.7rem", fontFamily: "monospace", bgcolor: alpha(theme.palette.primary.main, 0.1) }}
                  />
                </Box>
              </Box>
              {i < 8 && (
                <Typography
                  sx={{
                    color: "text.disabled",
                    fontSize: "1.5rem",
                    alignSelf: "center",
                  }}
                >
                  →
                </Typography>
              )}
            </Paper>
          ))}
        </Box>

        <Paper
          sx={{
            mt: 4,
            p: 3,
            borderRadius: 3,
            bgcolor: alpha(theme.palette.success.main, 0.1),
            border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "success.main" }}>
            ✅ Scan Complete
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Risk score calculated, findings saved, webhooks fired. AI summaries generate in background for instant report exports.
          </Typography>
        </Paper>
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
  );
}
