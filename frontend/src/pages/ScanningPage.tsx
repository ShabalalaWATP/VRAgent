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
      "Your code is securely retrieved and prepared for analysis. VRAgent supports multiple input methods for maximum flexibility.",
    details: [
      "Git repositories are cloned using secure HTTPS or SSH protocols",
      "ZIP/TAR archives are extracted to an isolated sandbox directory",
      "File permissions are validated to prevent path traversal attacks",
      "Project structure is analyzed to detect multi-language repositories",
      "Large binary files and media are automatically excluded from analysis",
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
    name: "Codebase Intelligence",
    description:
      "Deep analysis of your codebase reveals its architecture, dependencies, and potential attack surface before scanning begins.",
    details: [
      "Counts total files, lines of code, and code complexity metrics",
      "Identifies all programming languages and their distribution percentages",
      "Detects frameworks (React, Django, Spring, Express, etc.)",
      "Maps all dependency manifest files for comprehensive SCA",
      "Identifies entry points (APIs, web routes, CLI handlers)",
      "Calculates cyclomatic complexity for risk assessment",
    ],
    tools: ["Custom AST parsers", "Language detection", "Dependency graph analyzer"],
    outputs: [
      "Language breakdown with percentages",
      "Framework and library detection report",
      "Entry point mapping for attack surface analysis",
      "Code quality metrics baseline",
    ],
    icon: <CodeIcon />,
    duration: "10-60 sec",
    color: "#8b5cf6",
  },
  {
    name: "Dependency Analysis",
    description:
      "Every third-party package is examined for known vulnerabilities using multiple authoritative databases.",
    details: [
      "Parses 15+ dependency formats (package.json, requirements.txt, pom.xml, Cargo.toml, go.mod, Gemfile, etc.)",
      "Resolves transitive dependencies to find hidden vulnerabilities",
      "Queries NVD (National Vulnerability Database) for CVE matches",
      "Fetches EPSS scores to assess real-world exploitation likelihood",
      "Checks exploit databases (ExploitDB, Metasploit) for weaponized vulnerabilities",
      "Identifies packages with known malware or typosquatting risks",
    ],
    tools: ["NVD API", "EPSS API", "OSV Database", "GitHub Advisory DB"],
    outputs: [
      "Complete dependency tree with versions",
      "CVE matches with full descriptions",
      "CVSS severity scores (0.0-10.0)",
      "EPSS exploitation probability percentages",
    ],
    icon: <BugReportIcon />,
    duration: "30-120 sec",
    color: "#ec4899",
  },
  {
    name: "SBOM Generation",
    description:
      "Creates a comprehensive Software Bill of Materials - your application's complete ingredient list for compliance and supply chain security.",
    details: [
      "Lists every direct and transitive dependency with exact versions",
      "Records package sources, checksums, and download URLs",
      "Identifies open-source licenses (MIT, GPL, Apache, etc.)",
      "Flags license compatibility issues for legal compliance",
      "Creates machine-readable SBOM in CycloneDX and SPDX formats",
    ],
    tools: ["CycloneDX Generator", "SPDX Tools", "License Classifier"],
    outputs: [
      "Complete component inventory",
      "License compliance report",
      "Dependency relationship graph",
      "Exportable SBOM for audits",
    ],
    icon: <DescriptionIcon />,
    duration: "15-45 sec",
    color: "#f59e0b",
  },
  {
    name: "Secret Detection",
    description:
      "Hunts for accidentally committed secrets, API keys, passwords, and sensitive credentials that could compromise your systems.",
    details: [
      "700+ regex patterns for API keys (AWS, GCP, Azure, Stripe, etc.)",
      "Entropy analysis to detect high-randomness strings that may be secrets",
      "Git history scanning to find secrets in previous commits",
      "Environment variable and config file analysis",
      "Private key and certificate detection (RSA, SSH, PGP)",
      "Database connection string and password detection",
    ],
    tools: ["TruffleHog patterns", "GitLeaks rules", "Custom entropy scanner"],
    outputs: [
      "Secret findings with exact locations",
      "Secret type classification",
      "Confidence scores for each detection",
      "Severity ratings and remediation guidance",
    ],
    icon: <VpnKeyIcon />,
    duration: "20-90 sec",
    color: "#ef4444",
  },
  {
    name: "SAST Analysis",
    description:
      "Static Application Security Testing examines your source code for vulnerabilities without execution, using multiple specialized scanners.",
    details: [
      "Multi-scanner approach ensures comprehensive coverage",
      "Language-specific rules for idiomatic vulnerability patterns",
      "Taint analysis tracks untrusted data through code paths",
      "Control flow analysis identifies logic vulnerabilities",
      "Data flow analysis finds injection and exposure risks",
      "Configuration analysis for framework security settings",
    ],
    tools: ["Semgrep", "Bandit", "ESLint Security", "GoSec", "SpotBugs", "Clang-Tidy"],
    outputs: [
      "Vulnerability findings with code locations",
      "CWE classifications for each finding",
      "Severity ratings (Critical/High/Medium/Low)",
      "Remediation suggestions with secure alternatives",
    ],
    icon: <SecurityIcon />,
    duration: "60-300 sec",
    color: "#10b981",
  },
  {
    name: "Result Aggregation",
    description:
      "All scanner outputs are unified, deduplicated, and normalized into a single coherent security report.",
    details: [
      "Merges findings from all 6+ scanners into unified format",
      "Intelligent deduplication removes redundant findings",
      "Cross-references findings with CVE/CWE databases",
      "Normalizes severity ratings across different scanner scales",
      "Calculates composite risk scores for prioritization",
    ],
    outputs: [
      "Unified findings list with consistent schema",
      "Severity distribution breakdown",
      "Finding categories and counts",
      "Risk score calculations",
    ],
    icon: <AssessmentIcon />,
    duration: "5-15 sec",
    color: "#0891b2",
  },
  {
    name: "AI Analysis",
    description:
      "Google Gemini AI provides expert-level security analysis, identifying attack chains, false positives, and exploitation scenarios.",
    details: [
      "Generates executive security summary for stakeholders",
      "Identifies multi-vulnerability attack chains",
      "Creates realistic exploit scenarios from attacker's perspective",
      "Detects likely false positives using code context",
      "Maps findings to MITRE ATT&CK tactics and techniques",
      "Provides detailed remediation guidance",
    ],
    tools: ["Google Gemini 2.0 Flash", "Custom security prompts"],
    outputs: [
      "Executive security summary",
      "Attack vector analysis",
      "Exploit development scenarios",
      "False positive assessments",
      "Attack chain mappings",
    ],
    icon: <PsychologyIcon />,
    duration: "30-90 sec",
    color: "#7c3aed",
  },
  {
    name: "Report Generation",
    description:
      "The final security report is compiled with all findings, visualizations, and AI insights in multiple export formats.",
    details: [
      "Compiles all scan results into a structured report",
      "Generates severity breakdown charts and visualizations",
      "Includes AI-generated insights and recommendations",
      "Creates executive summary for non-technical stakeholders",
      "Supports multiple export formats (Markdown, PDF, DOCX)",
    ],
    outputs: [
      "Complete security assessment report",
      "Exportable documents in multiple formats",
      "Visual dashboards and charts",
      "Actionable remediation roadmap",
    ],
    icon: <DescriptionIcon />,
    duration: "10-30 sec",
    color: "#dc2626",
  },
];

const scannerDetails = [
  {
    name: "Semgrep",
    languages: ["Python", "JavaScript", "TypeScript", "Go", "Java", "Ruby", "PHP", "C", "C++", "C#", "Kotlin", "Rust"],
    description:
      "Lightweight, fast, and powerful pattern-based static analysis. Uses a domain-specific language for writing security rules that feel like searching code.",
    strengths: ["Speed", "Low false positives", "Easy custom rules", "CI/CD friendly"],
    whatItFinds: [
      "SQL Injection (CWE-89)",
      "Cross-Site Scripting (CWE-79)",
      "Command Injection (CWE-78)",
      "Path Traversal (CWE-22)",
      "Insecure Deserialization (CWE-502)",
      "SSRF (CWE-918)",
      "Hardcoded Secrets (CWE-798)",
      "XXE Injection (CWE-611)",
    ],
    color: "#10b981",
  },
  {
    name: "Bandit",
    languages: ["Python"],
    description:
      "Python-specific security linter designed to find common security issues. Part of the OpenStack Security Project with extensive rule coverage.",
    strengths: ["Python-specific", "Low overhead", "AST-based analysis", "Extensive rules"],
    whatItFinds: [
      "Use of assert in production",
      "Hardcoded passwords",
      "SQL injection via string formatting",
      "Insecure hash functions (MD5, SHA1)",
      "Subprocess shell injection",
      "Pickle usage (insecure deserialization)",
      "Binding to 0.0.0.0",
      "Use of eval() and exec()",
    ],
    color: "#3b82f6",
  },
  {
    name: "ESLint Security",
    languages: ["JavaScript", "TypeScript", "JSX", "TSX"],
    description:
      "Security-focused ESLint plugins combining eslint-plugin-security and eslint-plugin-no-unsanitized for comprehensive JavaScript/TypeScript analysis.",
    strengths: ["Native JS/TS support", "Framework-aware", "React/Vue support", "IDE integration"],
    whatItFinds: [
      "eval() and Function() usage",
      "Prototype pollution",
      "Regular expression DoS (ReDoS)",
      "Object injection attacks",
      "Non-literal require()",
      "Unsafe innerHTML (XSS)",
      "document.write() usage",
      "Insecure random generation",
    ],
    color: "#f59e0b",
  },
  {
    name: "GoSec",
    languages: ["Go"],
    description:
      "Go Security Checker inspects Go source code by scanning the AST (Abstract Syntax Tree) for security problems using a set of rules.",
    strengths: ["Go-specific", "AST analysis", "Fast scanning", "Low false positives"],
    whatItFinds: [
      "Hardcoded credentials",
      "SQL injection",
      "Command injection",
      "Directory traversal",
      "Weak cryptography",
      "Insecure TLS configs",
      "Integer overflow",
      "SSRF vulnerabilities",
    ],
    color: "#06b6d4",
  },
  {
    name: "SpotBugs + FindSecBugs",
    languages: ["Java", "Kotlin", "Scala", "Groovy"],
    description:
      "SpotBugs static analysis tool with the FindSecBugs plugin provides comprehensive security analysis for JVM bytecode.",
    strengths: ["Bytecode analysis", "Framework support", "300+ patterns", "Maven/Gradle integration"],
    whatItFinds: [
      "SQL/LDAP/XPath Injection",
      "Command Injection",
      "XXE Vulnerabilities",
      "Insecure cookie handling",
      "Weak cryptography",
      "Trust boundary violations",
      "Predictable random generators",
      "Spring security issues",
    ],
    color: "#ef4444",
  },
  {
    name: "Clang-Tidy",
    languages: ["C", "C++", "Objective-C"],
    description:
      "Clang-based C/C++ linter with security-focused checks including buffer overflows, memory safety, and undefined behavior detection.",
    strengths: ["Compiler-integrated", "Deep analysis", "Memory safety", "Standards compliance"],
    whatItFinds: [
      "Buffer overflows (CWE-120)",
      "Format string vulnerabilities",
      "Integer overflows",
      "Use-after-free (CWE-416)",
      "Null pointer dereferences",
      "Memory leaks (CWE-401)",
      "Unsafe string functions",
      "Double-free vulnerabilities",
    ],
    color: "#8b5cf6",
  },
];

const scannerStats = [
  { label: "Languages", value: "20+", icon: <CodeIcon /> },
  { label: "Rules", value: "5,000+", icon: <BugReportIcon /> },
  { label: "Secret Patterns", value: "700+", icon: <VpnKeyIcon /> },
  { label: "CVE Database", value: "200K+", icon: <SecurityIcon /> },
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
          When you initiate a scan, your code passes through <strong>9 distinct phases</strong>, each building on the previous to create a comprehensive security assessment. The entire process typically takes <strong>2-8 minutes</strong> depending on codebase size.
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
            🛠️ SAST Scanner Arsenal
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
          VRAgent employs multiple specialized security scanners, each optimized for specific languages and vulnerability types. This multi-scanner approach ensures comprehensive coverage.
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
