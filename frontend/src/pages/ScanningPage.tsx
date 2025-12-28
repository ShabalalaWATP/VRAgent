import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  IconButton,
  Grid,
  LinearProgress,
  Tooltip,
  Divider,
} from "@mui/material";
import { useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SecurityIcon from "@mui/icons-material/Security";
import SpeedIcon from "@mui/icons-material/Speed";
import BugReportIcon from "@mui/icons-material/BugReport";
import StorageIcon from "@mui/icons-material/Storage";
import CodeIcon from "@mui/icons-material/Code";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import AssessmentIcon from "@mui/icons-material/Assessment";
import PsychologyIcon from "@mui/icons-material/Psychology";
import DescriptionIcon from "@mui/icons-material/Description";
import LayersIcon from "@mui/icons-material/Layers";

interface ScanPhase {
  name: string;
  description: string;
  details: string[];
  tools?: string[];
  outputs?: string[];
  icon: React.ReactNode;
  duration: string;
  color: string;
  progressRange: string;
}

const scanPhases: ScanPhase[] = [
  {
    name: "Archive Extraction",
    description:
      "Your uploaded ZIP/TAR archive is securely extracted to an isolated sandbox directory with protection against archive-based attacks.",
    details: [
      "ZIP/TAR/GZ archives extracted to isolated /tmp sandbox directory",
      "Zip bomb protection limits extraction to 500MB and 10,000 files max",
      "Path traversal protection validates all extracted file paths (../../ blocked)",
      "Binary files auto-excluded: .png, .jpg, .exe, .dll, .wasm, .pyc, .min.js",
      "Directories skipped: node_modules, __pycache__, .git, venv, dist, build",
      "Max file size: 1MB per file (larger files skipped as likely generated)",
    ],
    outputs: [
      "Extracted source directory",
      "File count and skip statistics",
    ],
    icon: <StorageIcon />,
    duration: "5-30 sec",
    progressRange: "0-5%",
    color: "#6366f1",
  },
  {
    name: "Parallel File Processing",
    description:
      "Source files are processed in parallel using ThreadPoolExecutor with MAX_FILE_PROCESSORS workers for I/O-bound file reading.",
    details: [
      "ThreadPoolExecutor with 8-16 parallel workers (2x CPU cores)",
      "Files split into semantic chunks (~500 tokens each, max 50 per file)",
      "Language detection for 60+ file types determines scanner selection",
      "Content hash computed (SHA-256) for embedding reuse detection",
      "Chunks buffered (100 at a time) and batch-inserted to PostgreSQL",
      "MAX_TOTAL_CHUNKS limit (configurable) prevents memory exhaustion",
      "Static pattern checks run inline: eval(), exec(), shell=True, passwords",
    ],
    tools: ["ThreadPoolExecutor", "SHA-256 hashing", "AST parsing"],
    outputs: [
      "Code chunks with file/line references",
      "Language breakdown (Python, JS, Go, etc.)",
      "Initial static pattern findings",
    ],
    icon: <CodeIcon />,
    duration: "10-60 sec",
    progressRange: "5-30%",
    color: "#8b5cf6",
  },
  {
    name: "Embedding Generation",
    description:
      "Vector embeddings are generated for code chunks using Gemini, with smart reuse from previous scans when code is unchanged.",
    details: [
      "Gemini text-embedding-004 model (768-dimensional vectors)",
      "Existing embeddings queried by (file_path, start_line, code_hash) key",
      "Unchanged code chunks reuse embeddings from previous scans",
      "Only new/modified chunks sent to Gemini API (cost optimization)",
      "Stored in PostgreSQL with pgvector extension for similarity search",
      "Can be disabled via SKIP_EMBEDDINGS=true for faster scans",
    ],
    tools: ["Gemini Embedding API", "pgvector", "Content hash comparison"],
    outputs: [
      "768-dimension embeddings per chunk",
      "Reuse statistics (X reused, Y generated)",
      "Vector-indexed chunks for semantic search",
    ],
    icon: <LayersIcon />,
    duration: "20-60 sec",
    progressRange: "30-45%",
    color: "#ec4899",
  },
  {
    name: "Parallel Scan Phases",
    description:
      "Four independent phases run concurrently: SAST scanners, Docker scanning, IaC scanning, and dependency parsing—all using ThreadPoolExecutor.",
    details: [
      "ParallelPhaseTracker coordinates progress across 4 concurrent phases",
      "SAST: Up to 11 scanners run in parallel (Semgrep, Bandit, gosec, etc.)",
      "Smart scanner selection: Only runs scanners for detected languages",
      "Docker: Trivy image scanning + custom Dockerfile linting rules",
      "IaC: Checkov + tfsec for Terraform, K8s, CloudFormation, Helm, ARM",
      "Dependencies: Parsed from package.json, requirements.txt, go.mod, Cargo.toml, etc.",
      "Per-scanner timeout (configurable) prevents hanging on large codebases",
    ],
    tools: ["Semgrep", "Bandit", "ESLint", "gosec", "SpotBugs", "clang-tidy", "Cppcheck", "PHPCS", "Brakeman", "Cargo Audit", "Secret Scanner", "Trivy", "Checkov", "tfsec"],
    outputs: [
      "SAST findings from applicable scanners",
      "Docker vulnerability + misconfiguration findings",
      "IaC security issues with framework detection",
      "Dependency list with versions and ecosystems",
    ],
    icon: <SecurityIcon />,
    duration: "60-300 sec",
    progressRange: "45-70%",
    color: "#10b981",
  },
  {
    name: "Cross-Scanner Deduplication",
    description:
      "Findings from multiple scanners are deduplicated to eliminate redundant reports of the same vulnerability at the same location.",
    details: [
      "Matching by file_path + line_number + vulnerability_type",
      "Scanner sources preserved in merged finding for audit trail",
      "Severity taken from highest-confidence scanner in merge",
      "Cross-file correlation detects related issues (e.g., same auth bypass in multiple files)",
      "Dedup stats tracked: X findings → Y after merging Z duplicates",
    ],
    outputs: [
      "Deduplicated findings list",
      "Merge statistics (duplicates_merged count)",
      "Cross-file correlations (related issues)",
    ],
    icon: <AssessmentIcon />,
    duration: "2-5 sec",
    progressRange: "70-72%",
    color: "#0891b2",
  },
  {
    name: "Transitive Dependency Analysis",
    description:
      "Lock files are parsed to build complete dependency trees, identifying whether vulnerabilities are in direct or transitive dependencies.",
    details: [
      "npm: package-lock.json, yarn.lock, pnpm-lock.yaml",
      "Python: poetry.lock, Pipfile.lock, pip freeze",
      "Go: go.sum for module dependency resolution",
      "Rust: Cargo.lock for crate dependency trees",
      "Calculates dependency depth (1 = direct, 2+ = transitive)",
      "Maps vulnerable path: your-code → direct-dep → vulnerable-transitive-dep",
    ],
    tools: ["Lock file parsers", "Dependency tree builder", "Path analyzer"],
    outputs: [
      "Dependency tree per ecosystem",
      "Direct vs transitive classification",
      "Dependency chain for each vulnerability",
    ],
    icon: <BugReportIcon />,
    duration: "5-15 sec",
    progressRange: "72-77%",
    color: "#f59e0b",
  },
  {
    name: "CVE Lookup & Parallel Enrichment",
    description:
      "Dependencies are batch-queried against OSV.dev, then enriched in parallel with NVD, EPSS, and CISA KEV data.",
    details: [
      "OSV.dev API batch queries (100 deps/request) for CVE/GHSA matches",
      "Parallel enrichment: NVD + EPSS + KEV fetched concurrently",
      "NVD: Full CVSS v3/v4 vectors, CWE classifications, descriptions",
      "EPSS: Real-world exploitation probability (0-100%) and percentile",
      "CISA KEV: Known Exploited Vulnerabilities actively attacked in the wild",
      "KEV vulnerabilities auto-escalated to HIGH severity",
      "Combined priority score merges CVSS + EPSS + KEV for triage",
    ],
    tools: ["OSV.dev API", "NVD API", "FIRST EPSS API", "CISA KEV catalog"],
    outputs: [
      "CVE matches with descriptions",
      "CVSS scores (0.0-10.0) with vectors",
      "EPSS probability and percentile",
      "KEV flag for active exploitation",
      "Combined priority label (Critical/High/Medium/Low)",
    ],
    icon: <VpnKeyIcon />,
    duration: "30-90 sec",
    progressRange: "78-89%",
    color: "#ef4444",
  },
  {
    name: "Reachability Analysis",
    description:
      "Determines whether vulnerable dependencies are actually imported and called in your code, enabling smarter severity adjustment.",
    details: [
      "Scans import statements: import X, from X import Y, require('X')",
      "Checks if vulnerable package modules/functions are called",
      "Confidence levels: high (import found), medium (similar name), low (no evidence)",
      "Unreachable vulns with high confidence: severity downgraded (critical → medium)",
      "Provides reachability summary: X reachable, Y unreachable",
    ],
    tools: ["Import analyzer", "Call site detector", "Reachability checker"],
    outputs: [
      "Reachability status per vulnerability",
      "Import locations and call locations",
      "Severity adjustments for unreachable vulns",
    ],
    icon: <DescriptionIcon />,
    duration: "10-30 sec",
    progressRange: "84-86%",
    color: "#7c3aed",
  },
  {
    name: "Agentic AI Scan",
    description:
      "AI-guided multi-pass deep analysis that uses CVE and SAST context to intelligently prioritize and analyze code for vulnerabilities.",
    details: [
      "Receives external intelligence from CVE/SAST phases before analyzing code",
      "Pass 1: Triage (60 files × 3K chars; Enhanced: 80 × 4K) - quick security scoring",
      "Pass 2: Focused (20 files × 7K chars; Enhanced: 30 × 10K) - deeper file inspection",
      "Pass 3: Deep (8 files × 18K chars; Enhanced: 12 × 30K) - full file analysis",
      "Progressive depth: AI sees more content per file as passes narrow down",
      "AI-guided data flow tracing across function calls and file boundaries",
      "Synthesis phase: Correlates findings across all passes, deduplicates, scores confidence",
    ],
    tools: ["Gemini 2.0 Flash", "Multi-pass analyzer", "Data flow tracer", "CVE/SAST context"],
    outputs: [
      "AI-discovered vulnerabilities with exploit scenarios",
      "Data flow traces showing taint propagation",
      "Confidence scores based on CVE/SAST corroboration",
      "CWE and OWASP classifications",
    ],
    icon: <PsychologyIcon />,
    duration: "60-180 sec",
    progressRange: "86-90%",
    color: "#f97316",
  },
  {
    name: "AI-Enhanced Analysis",
    description:
      "Final AI analysis correlates SAST, CVE, and Agentic findings to detect false positives and discover attack chains.",
    details: [
      "Heuristic FP detection first: test files, mock code, __test__, suppression comments",
      "Context-aware severity: auth checks present, admin-only routes, internal endpoints",
      "Attack chain discovery: Combines related findings into exploitable paths",
      "LLM analysis for top 20 most critical findings (configurable MAX_LLM_FINDINGS)",
      "Agentic AI corroboration: Cross-references SAST findings with Agentic results",
      "Findings with FP score ≥0.6 (and not agentic-corroborated) marked for filtering",
    ],
    tools: ["Gemini 2.0 Flash", "Heuristic patterns", "Agentic correlation"],
    outputs: [
      "False positive scores (0.0-1.0) with reasons",
      "Attack chain mappings with impact/likelihood",
      "Severity adjustments with explanations",
      "Agentic corroboration status",
    ],
    icon: <PsychologyIcon />,
    duration: "30-120 sec",
    progressRange: "90-94%",
    color: "#dc2626",
  },
  {
    name: "Report Generation & Webhooks",
    description:
      "Final report is compiled with all findings, AI analysis, and statistics. Webhooks notify external systems of scan completion.",
    details: [
      "Report aggregates: findings, attack chains, AI summary, scan stats",
      "Sensitive data inventory: Scans for PII, credentials, API keys in code",
      "Scan stats include: deduplication, transitive analysis, reachability, Docker, IaC",
      "Webhooks: POST to configured URLs with project_id, findings_count, severity_counts",
      "WebSocket broadcast: 'complete' phase with total findings and duration",
    ],
    tools: ["Report service", "Sensitive data scanner", "Webhook notifier"],
    outputs: [
      "Complete scan report with all metadata",
      "Sensitive data inventory",
      "Webhook notifications sent",
      "Scan duration and performance stats",
    ],
    icon: <AssessmentIcon />,
    duration: "5-10 sec",
    progressRange: "94-100%",
    color: "#059669",
  },
];

const scannerDetails = [
  {
    name: "Semgrep",
    languages: ["Python", "JavaScript", "TypeScript", "Go", "Java", "Ruby", "PHP", "C", "C++", "C#", "Kotlin", "Rust", "30+ total"],
    description:
      "VRAgent's primary SAST scanner. Lightweight semantic analysis with 2000+ security rules. Runs on all projects as fallback coverage.",
    strengths: ["30+ languages", "2000+ rules", "Taint tracking", "Low false positives", "SARIF output"],
    smartSelection: "Always runs (universal coverage)",
    whatItFinds: [
      "SQL Injection (CWE-89)",
      "Cross-Site Scripting (CWE-79)",
      "Command Injection (CWE-78)",
      "Path Traversal (CWE-22)",
      "Insecure Deserialization (CWE-502)",
      "SSRF (CWE-918)",
      "XXE Injection (CWE-611)",
      "Broken Authentication patterns",
    ],
    color: "#10b981",
  },
  {
    name: "Bandit",
    languages: ["Python"],
    description:
      "Python-specific security linter with AST-based analysis. Only runs when Python files detected in project.",
    strengths: ["Python-native AST", "Low overhead", "Confidence scoring", "Extensive rules"],
    smartSelection: "Runs when: 'python' in detected languages",
    whatItFinds: [
      "eval() and exec() usage",
      "Hardcoded passwords",
      "SQL via string formatting",
      "Insecure hashlib (MD5, SHA1)",
      "subprocess shell=True",
      "Pickle deserialization",
      "Binding to 0.0.0.0",
      "Random without secrets module",
    ],
    color: "#3b82f6",
  },
  {
    name: "ESLint Security",
    languages: ["JavaScript", "TypeScript", "JSX", "TSX"],
    description:
      "eslint-plugin-security for JavaScript/TypeScript. Only runs when JS/TS files detected.",
    strengths: ["Native JS/TS", "React support", "IDE integration", "Auto-fixable rules"],
    smartSelection: "Runs when: 'javascript' or 'typescript' in detected languages",
    whatItFinds: [
      "eval() and Function()",
      "Prototype pollution",
      "Regular expression DoS",
      "Object injection",
      "Non-literal require()",
      "Unsafe innerHTML (XSS)",
      "document.write()",
      "Math.random() for security",
    ],
    color: "#f59e0b",
  },
  {
    name: "gosec",
    languages: ["Go"],
    description:
      "Go Security Checker inspects Go source code by AST scanning. Only runs when Go files detected.",
    strengths: ["Go-native AST", "Fast scanning", "Low false positives", "SARIF output"],
    smartSelection: "Runs when: 'go' in detected languages",
    whatItFinds: [
      "Hardcoded credentials",
      "SQL injection",
      "Command injection",
      "Directory traversal",
      "Weak cryptography",
      "Insecure TLS (MinVersion)",
      "Integer overflow",
      "File permission issues",
    ],
    color: "#06b6d4",
  },
  {
    name: "SpotBugs + FindSecBugs",
    languages: ["Java", "Kotlin", "Scala", "Groovy"],
    description:
      "SpotBugs with FindSecBugs plugin analyzes JVM bytecode. Only runs when Java/Kotlin files detected.",
    strengths: ["Bytecode analysis", "Spring support", "300+ patterns", "Maven/Gradle integration"],
    smartSelection: "Runs when: 'java' or 'kotlin' in detected languages",
    whatItFinds: [
      "SQL/LDAP/XPath Injection",
      "Command Injection",
      "XXE Vulnerabilities",
      "Insecure cookies",
      "Weak cryptography",
      "Trust boundary violations",
      "Predictable randoms",
      "Spring Security misconfigs",
    ],
    color: "#ef4444",
  },
  {
    name: "clang-tidy + Cppcheck",
    languages: ["C", "C++", "Objective-C"],
    description:
      "Two complementary scanners: clang-tidy for compiler-integrated analysis, Cppcheck for additional coverage. Only run when C/C++ files detected.",
    strengths: ["Compiler-integrated", "Memory analysis", "Buffer checks", "Standards compliance"],
    smartSelection: "Runs when: 'c' or 'cpp' in detected languages",
    whatItFinds: [
      "Buffer overflows (CWE-120)",
      "Format string vulnerabilities",
      "Integer overflows",
      "Use-after-free (CWE-416)",
      "Null pointer dereferences",
      "Memory leaks (CWE-401)",
      "Unsafe strcpy/sprintf",
      "Double-free vulnerabilities",
    ],
    color: "#8b5cf6",
  },
  {
    name: "PHPCS Security + Progpilot",
    languages: ["PHP", "PHTML"],
    description:
      "PHP security scanning with CodeSniffer security rules and Progpilot taint analysis. Only runs when PHP files detected.",
    strengths: ["Taint analysis", "WordPress patterns", "Framework detection", "Code style security"],
    smartSelection: "Runs when: 'php' in detected languages",
    whatItFinds: [
      "SQL Injection",
      "XSS vulnerabilities",
      "File inclusion",
      "Code injection",
      "CSRF vulnerabilities",
      "Insecure file operations",
      "WordPress security issues",
      "Laravel/Symfony misconfigs",
    ],
    color: "#777bb4",
  },
  {
    name: "Brakeman",
    languages: ["Ruby", "Rails", "ERB"],
    description:
      "Ruby on Rails security scanner with framework-specific checks. Only runs when Ruby files detected.",
    strengths: ["Rails-specific", "Fast analysis", "Low false positives", "CI integration"],
    smartSelection: "Runs when: 'ruby' in detected languages",
    whatItFinds: [
      "SQL Injection",
      "Cross-site Scripting",
      "Mass Assignment",
      "Command Injection",
      "Unsafe redirects",
      "Session settings",
      "File access issues",
      "Insecure dependencies",
    ],
    color: "#cc342d",
  },
  {
    name: "Cargo Audit",
    languages: ["Rust"],
    description:
      "Rust crate vulnerability scanner using RustSec Advisory Database. Only runs when Rust files detected.",
    strengths: ["RustSec database", "Cargo.lock parsing", "CVSS scores", "Fast scanning"],
    smartSelection: "Runs when: 'rust' in detected languages",
    whatItFinds: [
      "Known CVEs in dependencies",
      "Unmaintained crates",
      "Yanked versions",
      "Memory safety issues",
      "Cryptographic weaknesses",
      "RUSTSEC advisories",
    ],
    color: "#dea584",
  },
  {
    name: "Secret Scanner",
    languages: ["All files"],
    description:
      "Custom regex-based scanner with 50+ patterns for API keys, tokens, and credentials. Always runs on all projects.",
    strengths: ["50+ patterns", "Multi-cloud", "Private keys", "Database strings"],
    smartSelection: "Always runs (all projects)",
    whatItFinds: [
      "AWS Access Keys & Secrets",
      "Azure/GCP Service Keys",
      "GitHub/GitLab Tokens",
      "Slack/Discord Webhooks",
      "Stripe/Twilio API Keys",
      "OpenAI/Anthropic Keys",
      "RSA/SSH/PGP Private Keys",
      "Database Connection Strings",
    ],
    color: "#dc2626",
  },
  {
    name: "Trivy (Docker)",
    languages: ["Dockerfiles", "Container Images"],
    description:
      "Trivy scans Docker images for OS-level vulnerabilities. Custom Dockerfile linting rules check for misconfigurations.",
    strengths: ["Image scanning", "OS vulns", "Config checks", "Fast scanning"],
    smartSelection: "Runs when: Dockerfile or docker-compose.yml detected",
    whatItFinds: [
      "Vulnerable base images",
      "Outdated OS packages",
      "Running as root",
      "Exposed ports",
      "Missing health checks",
      "COPY vs ADD misuse",
      "Secrets in build args",
      "Unversioned base images",
    ],
    color: "#2496ed",
  },
  {
    name: "Checkov + tfsec (IaC)",
    languages: ["Terraform", "Kubernetes", "CloudFormation", "Helm", "ARM", "Bicep"],
    description:
      "Infrastructure as Code scanning for cloud misconfigurations. Detects issues in Terraform, K8s manifests, and cloud templates.",
    strengths: ["Multi-framework", "Cloud-native", "Policy-as-code", "CIS benchmarks"],
    smartSelection: "Runs when: .tf, .yaml (K8s), cloudformation, or ARM templates detected",
    whatItFinds: [
      "Public S3 buckets",
      "Unencrypted storage",
      "Missing logging",
      "Overly permissive IAM",
      "K8s privileged containers",
      "Missing network policies",
      "Insecure TLS settings",
      "Missing tags/labels",
    ],
    color: "#7c3aed",
  },
];

const scannerStats = [
  { label: "Languages", value: "60+", icon: <CodeIcon /> },
  { label: "SAST Scanners", value: "11", icon: <SecurityIcon /> },
  { label: "Secret Patterns", value: "50+", icon: <VpnKeyIcon /> },
  { label: "CVE Databases", value: "4", icon: <BugReportIcon /> },
];

export default function ScanningPage() {
  const theme = useTheme();
  const navigate = useNavigate();

  const pageContext = `VRAgent scanning methodology page. This page explains the comprehensive security scanning process including static analysis (SAST), dependency scanning (SCA), secret detection, infrastructure scanning, and AI-enhanced analysis. Users can learn about each scan phase and the tools used.`;

  return (
    <LearnPageLayout pageTitle="VRAgent Scanning" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <IconButton onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
        <ArrowBackIcon />
      </IconButton>

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          🔍 How Scanning Works
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 800 }}>
          A complete technical walkthrough of VRAgent's security scanning pipeline - from code acquisition to AI-enhanced vulnerability analysis.
        </Typography>
      </Box>

      {/* Stats Banner */}
      <Grid container spacing={2} sx={{ mb: 5 }}>
        {scannerStats.map((stat) => (
          <Grid item xs={6} md={3} key={stat.label}>
            <Paper
              sx={{
                p: 3,
                textAlign: "center",
                background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.08)}, ${alpha(theme.palette.secondary.main, 0.04)})`,
                border: `1px solid ${alpha(theme.palette.primary.main, 0.15)}`,
                borderRadius: 3,
              }}
            >
              <Box sx={{ color: "primary.main", mb: 1 }}>{stat.icon}</Box>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "primary.main" }}>
                {stat.value}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 500 }}>
                {stat.label}
              </Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* Pipeline Overview */}
      <Paper sx={{ p: 4, mb: 5, background: alpha(theme.palette.info.main, 0.02), borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <LayersIcon sx={{ fontSize: 32, color: "info.main" }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Pipeline Overview
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          When you initiate a scan, your code passes through <strong>10 distinct phases</strong>. The key innovation is <strong>Phase 4</strong> where SAST, Docker, IaC, and dependency scanning all run <strong>in parallel</strong> using ThreadPoolExecutor. Smart scanner selection only runs scanners for detected languages, optimizing scan time.
        </Typography>
        
        {/* Visual Pipeline */}
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, justifyContent: "center", mb: 3 }}>
          {scanPhases.map((phase, index) => (
            <Box key={phase.name} sx={{ display: "flex", alignItems: "center" }}>
              <Tooltip title={`${phase.name} (${phase.progressRange})`}>
                <Box
                  sx={{
                    width: 44,
                    height: 44,
                    borderRadius: "50%",
                    bgcolor: phase.color,
                    color: "white",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 700,
                    cursor: "pointer",
                    transition: "all 0.2s",
                    boxShadow: `0 4px 12px ${alpha(phase.color, 0.4)}`,
                    "&:hover": { transform: "scale(1.15)" },
                  }}
                >
                  {index + 1}
                </Box>
              </Tooltip>
              {index < scanPhases.length - 1 && (
                <Box sx={{ width: { xs: 15, md: 30 }, height: 2, bgcolor: alpha(theme.palette.divider, 0.3) }} />
              )}
            </Box>
          ))}
        </Box>

        {/* Key Architecture Points */}
        <Divider sx={{ my: 2 }} />
        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.1) }}>
              <Typography variant="subtitle2" fontWeight="bold" color="#10b981">⚡ Parallel Execution</Typography>
              <Typography variant="body2">ThreadPoolExecutor runs SAST (11 scanners), Docker, IaC, and deps concurrently. ParallelPhaseTracker coordinates progress.</Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.1) }}>
              <Typography variant="subtitle2" fontWeight="bold" color="#8b5cf6">🎯 Smart Selection</Typography>
              <Typography variant="body2">Language detection determines which scanners run. No Python files? Bandit skipped. Saves time on multi-language repos.</Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.1) }}>
              <Typography variant="subtitle2" fontWeight="bold" color="#ef4444">🔄 Embedding Reuse</Typography>
              <Typography variant="body2">Content hash (SHA-256) enables reuse of embeddings from previous scans when code unchanged. Reduces API costs.</Typography>
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Scanning Pipeline */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 4 }}>
          📊 The 10-Phase Scanning Pipeline
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Phases 1-3 run sequentially (extraction → parsing → embeddings). <strong>Phase 4 runs SAST/Docker/IaC/Deps in parallel</strong> using ThreadPoolExecutor with ParallelPhaseTracker. Phases 5-10 run sequentially for dedup, enrichment, and AI analysis.
        </Typography>

        <Stepper orientation="vertical">
          {scanPhases.map((phase, index) => (
            <Step key={phase.name} active={true} completed={true}>
              <StepLabel
                StepIconComponent={() => (
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: "50%",
                      background: `linear-gradient(135deg, ${phase.color}, ${alpha(phase.color, 0.7)})`,
                      color: "white",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      boxShadow: `0 4px 14px ${alpha(phase.color, 0.4)}`,
                    }}
                  >
                    {phase.icon}
                  </Box>
                )}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>
                    {phase.name}
                  </Typography>
                  <Chip
                    label={phase.duration}
                    size="small"
                    sx={{ bgcolor: alpha(phase.color, 0.1), color: phase.color, fontWeight: 600 }}
                  />
                  <Chip
                    label={phase.progressRange}
                    size="small"
                    variant="outlined"
                    sx={{ borderColor: alpha(phase.color, 0.5), color: phase.color, fontWeight: 500, fontSize: "0.7rem" }}
                  />
                </Box>
              </StepLabel>
              <StepContent>
                <Typography color="text.secondary" sx={{ mb: 3 }}>
                  {phase.description}
                </Typography>

                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: phase.color }}>
                      What happens:
                    </Typography>
                    {phase.details.map((detail, i) => (
                      <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
                        <CheckCircleIcon sx={{ fontSize: 18, color: phase.color, mt: 0.2 }} />
                        <Typography variant="body2">{detail}</Typography>
                      </Box>
                    ))}
                  </Grid>

                  <Grid item xs={12} md={6}>
                    {phase.tools && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>
                          Tools:
                        </Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                          {phase.tools.map((tool) => (
                            <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ borderColor: phase.color, color: phase.color }} />
                          ))}
                        </Box>
                      </Box>
                    )}
                    {phase.outputs && (
                      <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha(phase.color, 0.05), border: `1px solid ${alpha(phase.color, 0.2)}` }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: phase.color }}>
                          📤 Outputs:
                        </Typography>
                        {phase.outputs.map((output) => (
                          <Typography key={output} variant="body2" sx={{ mb: 0.5 }}>→ {output}</Typography>
                        ))}
                      </Box>
                    )}
                  </Grid>
                </Grid>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </Paper>

      {/* Scanner Details */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <SecurityIcon sx={{ fontSize: 32, color: "primary.main" }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            🛠️ Security Scanner Arsenal
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          VRAgent employs <strong>12 specialized security scanners</strong> covering SAST, secrets, Docker, and IaC. All applicable scanners run in parallel using ThreadPoolExecutor with configurable MAX_PARALLEL_SCANNERS (default: 2× CPU cores).
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 4, p: 2, borderRadius: 2, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
          💡 <strong>Smart Scanner Selection:</strong> Language detection via file extensions determines which scanners run. No Python files? Bandit is skipped. No Go files? gosec is skipped. This optimizes scan time while ensuring coverage for detected languages.
        </Typography>

        {scannerDetails.map((scanner) => (
          <Accordion key={scanner.name} sx={{ mb: 2, border: `1px solid ${alpha(scanner.color, 0.2)}`, borderRadius: "8px !important", "&:before": { display: "none" } }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ borderLeft: `4px solid ${scanner.color}` }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%", flexWrap: "wrap" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, minWidth: 140 }}>{scanner.name}</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, flex: 1 }}>
                  {scanner.languages.slice(0, 5).map((lang) => (
                    <Chip key={lang} label={lang} size="small" sx={{ fontSize: "0.7rem", height: 22, bgcolor: alpha(scanner.color, 0.1), color: scanner.color }} />
                  ))}
                  {scanner.languages.length > 5 && (
                    <Chip label={`+${scanner.languages.length - 5}`} size="small" variant="outlined" sx={{ fontSize: "0.7rem", height: 22 }} />
                  )}
                </Box>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>{scanner.description}</Typography>
              {scanner.smartSelection && (
                <Box sx={{ mb: 2, p: 1.5, borderRadius: 1, bgcolor: alpha(scanner.color, 0.05), border: `1px dashed ${alpha(scanner.color, 0.3)}` }}>
                  <Typography variant="body2" sx={{ fontWeight: 600, color: scanner.color }}>
                    🎯 Smart Selection: <span style={{ fontWeight: 400 }}>{scanner.smartSelection}</span>
                  </Typography>
                </Box>
              )}
              <Grid container spacing={3}>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "success.main" }}>💪 Strengths</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {scanner.strengths.map((s) => (
                      <Chip key={s} label={s} size="small" sx={{ bgcolor: alpha(theme.palette.success.main, 0.1), color: "success.main" }} />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12} md={8}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "error.main" }}>🔴 Detects</Typography>
                  <Grid container spacing={1}>
                    {scanner.whatItFinds.map((finding) => (
                      <Grid item xs={12} sm={6} key={finding}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: scanner.color }} />
                          <Typography variant="body2">{finding}</Typography>
                        </Box>
                      </Grid>
                    ))}
                  </Grid>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        ))}
      </Paper>

      {/* Language Coverage */}
      <Paper sx={{ p: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🌐 Language Coverage</Typography>
        <Grid container spacing={2}>
          {[
            { lang: "Python", coverage: 100, color: "#3776ab" },
            { lang: "JavaScript/TS", coverage: 100, color: "#f7df1e" },
            { lang: "Java/Kotlin", coverage: 100, color: "#ed8b00" },
            { lang: "Go", coverage: 100, color: "#00add8" },
            { lang: "C/C++", coverage: 85, color: "#00599c" },
            { lang: "Ruby", coverage: 100, color: "#cc342d" },
            { lang: "PHP", coverage: 100, color: "#777bb4" },
            { lang: "Rust", coverage: 100, color: "#dea584" },
            { lang: "C#/.NET", coverage: 100, color: "#512bd4" },
          ].map((row) => (
            <Grid item xs={6} md={4} key={row.lang}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha(row.color, 0.05), border: `1px solid ${alpha(row.color, 0.2)}` }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>{row.lang}</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 700, color: row.coverage === 100 ? "success.main" : "warning.main" }}>{row.coverage}%</Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={row.coverage}
                  sx={{
                    height: 6,
                    borderRadius: 3,
                    bgcolor: alpha(row.color, 0.1),
                    "& .MuiLinearProgress-bar": { bgcolor: row.coverage === 100 ? "success.main" : "warning.main", borderRadius: 3 },
                  }}
                />
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
