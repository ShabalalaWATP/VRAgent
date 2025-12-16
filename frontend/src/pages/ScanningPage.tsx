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
}

const scanPhases: ScanPhase[] = [
  {
    name: "Code Acquisition",
    description:
      "Your code is securely retrieved and prepared for analysis with protection against archive-based attacks.",
    details: [
      "Git repositories are cloned using secure HTTPS or SSH protocols",
      "ZIP/TAR archives are extracted to an isolated sandbox directory",
      "Zip bomb protection limits extraction to 500MB and 10,000 files max",
      "Path traversal protection validates all extracted file paths",
      "Streaming extraction handles large codebases efficiently",
      "Binary files (images, executables, media) are automatically excluded",
    ],
    outputs: [
      "Project directory structure map",
      "Detected languages and their file counts",
      "Repository metadata (commits, branches, remotes)",
      "File size and complexity metrics",
    ],
    icon: <StorageIcon />,
    duration: "5-30 sec",
    color: "#6366f1",
  },
  {
    name: "Code Parsing & Chunking",
    description:
      "Source files are intelligently parsed and chunked for embedding generation and security-relevant prioritization.",
    details: [
      "Files parsed with streaming for memory-efficient processing",
      "Code split into semantic chunks (max 500 tokens per chunk)",
      "Security-relevant code prioritized: authentication, crypto, database queries",
      "Intelligent splitting respects function/class boundaries when possible",
      "Chunks buffered and batch-inserted for database efficiency",
      "Language detection determines which scanners to run",
    ],
    tools: ["Custom streaming parser", "Chunk buffer (100 chunks)", "Batch database inserts"],
    outputs: [
      "Code chunks with file/line references",
      "Language breakdown with percentages",
      "Framework and library detection",
      "Entry point mapping for attack surface",
    ],
    icon: <CodeIcon />,
    duration: "10-60 sec",
    color: "#8b5cf6",
  },
  {
    name: "Embedding Generation",
    description:
      "Vector embeddings are generated for code chunks, enabling semantic search and AI-powered code understanding.",
    details: [
      "Uses Gemini gemini-embedding-001 model (768 dimensions)",
      "Embeddings reused from previous scans when code unchanged",
      "Content hash comparison enables smart embedding reuse",
      "Security-relevant code chunks prioritized for embedding",
      "Stored in PostgreSQL with pgvector for similarity search",
      "Can be disabled via SKIP_EMBEDDINGS=true for faster scans",
    ],
    tools: ["Gemini Embedding API", "pgvector extension", "Content hashing"],
    outputs: [
      "768-dimension embeddings per chunk",
      "Embedding reuse statistics",
      "Vector-ready for semantic queries",
    ],
    icon: <LayersIcon />,
    duration: "20-60 sec",
    color: "#ec4899",
  },
  {
    name: "Parallel Scan Phases",
    description:
      "SAST scanners, Docker scanning, IaC scanning, and dependency parsing all run concurrently using ThreadPoolExecutor.",
    details: [
      "7 SAST scanners run in parallel with configurable MAX_PARALLEL_SCANNERS",
      "Docker scanning: Trivy for image vulns + custom Dockerfile linting rules",
      "IaC scanning: Checkov and tfsec for Terraform, K8s, CloudFormation, ARM",
      "Dependency parsing for 8 ecosystems runs concurrently",
      "Each phase reports progress independently via ParallelPhaseTracker",
      "Scanner availability checked before execution to skip unavailable tools",
    ],
    tools: ["Semgrep", "Bandit", "ESLint", "gosec", "SpotBugs", "clang-tidy", "Cppcheck", "PHPCS Security", "Brakeman", "Cargo Audit", "Secrets", "Trivy", "Checkov", "tfsec"],
    outputs: [
      "SAST findings from all applicable scanners",
      "Docker vulnerability and misconfiguration findings",
      "IaC security issues with framework detection",
      "Dependency list with versions and ecosystems",
    ],
    icon: <SecurityIcon />,
    duration: "60-300 sec",
    color: "#10b981",
  },
  {
    name: "Cross-Scanner Deduplication",
    description:
      "Findings from multiple scanners are deduplicated to eliminate redundant reports of the same vulnerability.",
    details: [
      "Same file+line+type findings merged across scanners",
      "Scanner sources preserved for audit trail",
      "Severity taken from highest-confidence scanner",
      "Duplicate count tracked in dedup_stats",
      "Preserves unique findings while reducing noise",
    ],
    outputs: [
      "Deduplicated findings list",
      "Merge statistics (X duplicates merged)",
      "Unified severity ratings",
    ],
    icon: <AssessmentIcon />,
    duration: "2-5 sec",
    color: "#0891b2",
  },
  {
    name: "Transitive Dependency Analysis",
    description:
      "Parses lock files to build complete dependency trees, identifying vulnerable transitive dependencies.",
    details: [
      "Parses package-lock.json, yarn.lock, pnpm-lock.yaml for npm",
      "Parses poetry.lock, Pipfile.lock for Python",
      "Parses go.sum for Go module dependencies",
      "Identifies which vulnerable packages are direct vs transitive",
      "Calculates dependency depth for prioritization",
      "Maps vulnerable paths from your code to the affected package",
    ],
    tools: ["Lock file parsers", "Dependency tree builder", "Path analyzer"],
    outputs: [
      "Complete dependency tree per ecosystem",
      "Direct vs transitive classification",
      "Vulnerable dependency paths",
    ],
    icon: <BugReportIcon />,
    duration: "5-15 sec",
    color: "#f59e0b",
  },
  {
    name: "CVE Lookup & Enrichment",
    description:
      "Dependencies are queried against multiple vulnerability databases, then enriched with detailed CVE information.",
    details: [
      "Batch queries OSV.dev API (100 deps per request) for CVE/GHSA matches",
      "Parallel enrichment fetches NVD, EPSS, and CISA KEV data simultaneously",
      "NVD provides full CVSS v3/v4 vectors and CWE classifications",
      "EPSS scores show real-world exploitation probability (0-100%)",
      "CISA KEV (Known Exploited Vulnerabilities) flags actively exploited CVEs",
      "KEV vulnerabilities automatically escalated to HIGH severity",
    ],
    tools: ["OSV.dev API", "NVD API", "EPSS API", "CISA KEV"],
    outputs: [
      "CVE matches with descriptions",
      "CVSS scores (0.0-10.0) with vectors",
      "EPSS probability and percentile",
      "KEV status for prioritization",
      "Combined priority score",
    ],
    icon: <VpnKeyIcon />,
    duration: "30-90 sec",
    color: "#ef4444",
  },
  {
    name: "Reachability Analysis",
    description:
      "Determines whether vulnerable dependencies are actually used in reachable code paths.",
    details: [
      "Analyzes import statements to find which packages are actually imported",
      "Checks if vulnerable package functions are called in your code",
      "Marks unreachable vulnerabilities for deprioritization",
      "Reduces false positives from unused dependencies",
      "Provides reachability summary (X reachable, Y unreachable)",
    ],
    tools: ["Import analyzer", "Call graph builder", "Reachability checker"],
    outputs: [
      "Reachability status per vulnerability",
      "Import evidence for reachable vulns",
      "Unreachable vuln count for filtering",
    ],
    icon: <DescriptionIcon />,
    duration: "10-30 sec",
    color: "#7c3aed",
  },
  {
    name: "AI Analysis & Report",
    description:
      "Google Gemini AI analyzes findings for false positives, attack chains, and generates exploit scenarios in the background.",
    details: [
      "Heuristic false positive detection runs first (test files, mock code, suppression comments)",
      "Severity adjustment for context (auth checks, admin-only, internal endpoints)",
      "Attack chain discovery combines related findings into exploitable paths",
      "LLM analysis limited to MAX_FINDINGS=50 most critical vulnerabilities",
      "AI summaries generated in background after scan completes",
      "Pre-built exploit templates for 16+ vuln types (SQLi, XSS, RCE, etc.)",
    ],
    tools: ["Gemini 2.0 Flash", "Heuristic patterns", "Exploit templates"],
    outputs: [
      "Executive security summary",
      "False positive assessments",
      "Attack chain mappings",
      "Exploit scenarios with PoC outlines",
      "Remediation guidance",
    ],
    icon: <PsychologyIcon />,
    duration: "30-120 sec",
    color: "#dc2626",
  },
];

const scannerDetails = [
  {
    name: "Semgrep",
    languages: ["Python", "JavaScript", "TypeScript", "Go", "Java", "Ruby", "PHP", "C", "C++", "C#", "Kotlin", "Rust", "30+ total"],
    description:
      "VRAgent's primary SAST scanner. Lightweight semantic analysis with 2000+ security rules. Supports OWASP Top 10, CWE Top 25, and framework-specific patterns.",
    strengths: ["30+ languages", "2000+ rules", "Taint tracking", "Low false positives", "SARIF output"],
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
      "Python-specific security linter with AST-based analysis. Excellent for detecting Python-idiomatic vulnerabilities like pickle deserialization and subprocess shell injection.",
    strengths: ["Python-native AST", "Low overhead", "Confidence scoring", "Extensive rules"],
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
      "eslint-plugin-security for JavaScript/TypeScript. Detects DOM-based XSS, prototype pollution, and Node.js-specific vulnerabilities.",
    strengths: ["Native JS/TS", "React support", "IDE integration", "Auto-fixable rules"],
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
      "Go Security Checker inspects Go source code by AST scanning. Excellent for detecting Go-specific issues like improper TLS configuration.",
    strengths: ["Go-native AST", "Fast scanning", "Low false positives", "SARIF output"],
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
      "SpotBugs with FindSecBugs plugin analyzes JVM bytecode for security issues. Detects Spring-specific vulnerabilities and OWASP risks.",
    strengths: ["Bytecode analysis", "Spring support", "300+ patterns", "Maven/Gradle integration"],
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
    name: "clang-tidy",
    languages: ["C", "C++", "Objective-C"],
    description:
      "Clang-based linter with security-focused checks. Critical for memory safety issues that can lead to RCE or information disclosure.",
    strengths: ["Compiler-integrated", "Memory analysis", "Buffer checks", "Standards compliance"],
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
    name: "Secret Scanner",
    languages: ["All files"],
    description:
      "Custom regex-based scanner with 50+ patterns for API keys, tokens, and credentials. High-confidence patterns minimize false positives.",
    strengths: ["50+ patterns", "Multi-cloud", "Private keys", "Database strings"],
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
      "Trivy scans Docker images for OS-level vulnerabilities. Combined with custom Dockerfile linting rules for misconfigurations.",
    strengths: ["Image scanning", "OS vulns", "Config checks", "Fast scanning"],
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
    languages: ["Terraform", "Kubernetes", "CloudFormation", "Helm", "ARM"],
    description:
      "Infrastructure as Code scanning for cloud misconfigurations. Detects issues in Terraform, K8s manifests, and cloud templates.",
    strengths: ["Multi-framework", "Cloud-native", "Policy-as-code", "CIS benchmarks"],
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
  { label: "Languages", value: "30+", icon: <CodeIcon /> },
  { label: "SAST Rules", value: "2,500+", icon: <BugReportIcon /> },
  { label: "Secret Patterns", value: "50+", icon: <VpnKeyIcon /> },
  { label: "CVE Database", value: "250K+", icon: <SecurityIcon /> },
];

export default function ScanningPage() {
  const theme = useTheme();
  const navigate = useNavigate();

  return (
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
          When you initiate a scan, your code passes through <strong>9 distinct phases</strong>, with SAST, Docker, IaC, and dependency scanning running in <strong>parallel</strong> for maximum performance. The entire process typically takes <strong>2-8 minutes</strong> depending on codebase size.
        </Typography>
        
        {/* Visual Pipeline */}
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, justifyContent: "center" }}>
          {scanPhases.map((phase, index) => (
            <Box key={phase.name} sx={{ display: "flex", alignItems: "center" }}>
              <Tooltip title={`${phase.name} (${phase.duration})`}>
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
      </Paper>

      {/* Scanning Pipeline */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 4 }}>
          📊 The 9-Phase Scanning Pipeline
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Phases 1-3 run sequentially, then Phase 4 runs all scanning types in parallel (SAST, Docker, IaC, Dependencies), followed by sequential enrichment and AI analysis.
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
        <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
          VRAgent employs 9 specialized security scanners covering SAST, secrets, Docker, and IaC. All scanners run in parallel using ThreadPoolExecutor with configurable concurrency.
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
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>{scanner.description}</Typography>
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
  );
}
