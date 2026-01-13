import React, { useState } from "react";
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
  Grid,
  LinearProgress,
  Tooltip,
  Divider,
  Button,
  Tabs,
  Tab,
  Card,
  CardContent,
  Alert,
  IconButton,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
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
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import LinkIcon from "@mui/icons-material/Link";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import VerifiedIcon from "@mui/icons-material/Verified";
import TimelineIcon from "@mui/icons-material/Timeline";
import AnalyticsIcon from "@mui/icons-material/Analytics";

// ============================================================================
// Scan Phase Data
// ============================================================================

interface ScanPhase {
  name: string;
  description: string;
  details: string[];
  tools?: string[];
  outputs?: string[];
  icon: React.ReactNode;
  duration: string;
  progressRange: string;
  color: string;
}

const scanPhases: ScanPhase[] = [
  {
    name: "Archive Extraction",
    description: "ZIP/TAR archives securely extracted with protection against archive-based attacks.",
    details: [
      "ZIP/TAR/GZ archives extracted to isolated /tmp sandbox",
      "Zip bomb protection: 500MB max, 10,000 files max",
      "Path traversal protection (../../ blocked)",
      "Binary files excluded: .png, .jpg, .exe, .dll, .wasm",
      "Directories skipped: node_modules, __pycache__, .git, venv",
    ],
    outputs: ["Extracted source directory", "File count statistics"],
    icon: <StorageIcon />,
    duration: "5-30s",
    progressRange: "0-5%",
    color: "#6366f1",
  },
  {
    name: "Parallel File Processing",
    description: "Files processed in parallel with ThreadPoolExecutor, chunked for semantic analysis.",
    details: [
      "8-16 parallel workers (2× CPU cores)",
      "Files split into ~500 token chunks (max 50/file)",
      "Language detection for 60+ file types",
      "SHA-256 hash for embedding reuse detection",
      "Static pattern checks: eval(), exec(), passwords",
    ],
    tools: ["ThreadPoolExecutor", "SHA-256", "AST parsing"],
    outputs: ["Code chunks with file/line refs", "Language breakdown"],
    icon: <CodeIcon />,
    duration: "10-60s",
    progressRange: "5-30%",
    color: "#8b5cf6",
  },
  {
    name: "Embedding Generation",
    description: "Vector embeddings generated with Gemini, reusing unchanged code from previous scans.",
    details: [
      "Gemini text-embedding-004 (768-dimensional)",
      "Embeddings reused when code hash matches",
      "Only new/modified chunks sent to API",
      "Stored in PostgreSQL with pgvector extension",
    ],
    tools: ["Gemini Embedding API", "pgvector"],
    outputs: ["768-dim embeddings per chunk", "Reuse statistics"],
    icon: <LayersIcon />,
    duration: "20-60s",
    progressRange: "30-45%",
    color: "#ec4899",
  },
  {
    name: "Parallel SAST/SCA/IaC",
    description: "SAST, Docker, IaC, and dependency scanning run concurrently using ThreadPoolExecutor.",
    details: [
      "ParallelPhaseTracker coordinates 4 concurrent phases",
      "Up to 11 SAST scanners run in parallel",
      "Smart selection: Only runs scanners for detected languages",
      "Docker: Trivy + custom Dockerfile linting",
      "IaC: Checkov + tfsec for Terraform, K8s, CloudFormation",
      "Dependencies: package.json, requirements.txt, go.mod, etc.",
    ],
    tools: ["Semgrep", "Bandit", "ESLint", "gosec", "SpotBugs", "clang-tidy", "Trivy", "Checkov", "tfsec"],
    outputs: ["SAST findings", "Docker vulns", "IaC issues", "Dependency list"],
    icon: <SecurityIcon />,
    duration: "60-300s",
    progressRange: "45-70%",
    color: "#10b981",
  },
  {
    name: "Deduplication & Dependencies",
    description: "Findings deduplicated, dependencies saved, and transitive dependency trees built.",
    details: [
      "Matching by file_path + line_number + vuln_type",
      "Scanner sources preserved for audit trail",
      "Severity from highest-confidence scanner",
      "Transitive dependency tree analysis from lock files",
      "Identifies depth in dependency chain (direct vs transitive)",
    ],
    tools: ["Deduplication engine", "Lock file parsers"],
    outputs: ["Deduplicated findings", "Dependency trees", "Package statistics"],
    icon: <AssessmentIcon />,
    duration: "5-15s",
    progressRange: "70-78%",
    color: "#0891b2",
  },
  {
    name: "CVE Lookup & Enrichment",
    description: "Dependencies batch-queried against OSV.dev, enriched with NVD, EPSS, and CISA KEV in parallel.",
    details: [
      "OSV.dev batch queries (100 deps/request)",
      "Parallel enrichment: NVD + EPSS + KEV simultaneously",
      "NVD: CVSS v3/v4 scores, CWE classifications, references",
      "EPSS: Real-world exploitation probability (0-100%)",
      "CISA KEV: Known Exploited Vulnerabilities auto-escalated to high",
      "Combined priority score: CVSS + EPSS + KEV",
      "Transitive vulns tagged with dependency chain",
    ],
    tools: ["OSV.dev", "NVD API", "FIRST EPSS", "CISA KEV"],
    outputs: ["CVE matches", "CVSS scores", "EPSS probability", "KEV flags", "Transitive info"],
    icon: <VpnKeyIcon />,
    duration: "30-90s",
    progressRange: "78-86%",
    color: "#ef4444",
  },
  {
    name: "Reachability Analysis",
    description: "Determines if vulnerable dependencies are actually imported and called in your code.",
    details: [
      "Scans import statements across all files",
      "Checks if vulnerable functions are called",
      "Confidence: high (import found), medium (similar name), low (no evidence)",
      "Unreachable vulns with high confidence → severity downgraded",
    ],
    outputs: ["Reachability status per vuln", "Severity adjustments"],
    icon: <DescriptionIcon />,
    duration: "10-30s",
    progressRange: "86-89%",
    color: "#7c3aed",
  },
  {
    name: "Agentic AI Deep Scan",
    description: "Multi-pass AI analysis with CVE/SAST context—progressive depth as passes narrow down.",
    details: [
      "Receives CVE/SAST/dependency context before analyzing",
      "Pass 1 (Quick): 180 files × 5K chars - identifies entry points",
      "Pass 2 (Focused): 60 files × 12K chars - traces data flows",
      "Pass 3 (Deep): 22 files × 50K chars - comprehensive audit",
      "Pass 4 (Ultra): 7 files × 100K chars - large files only",
      "AI-guided data flow tracing across function calls",
      "External intelligence: knows which files import vulnerable deps",
      "Synthesis: correlates findings, deduplicates, scores confidence",
    ],
    tools: ["Gemini 2.0 Flash", "Multi-pass analyzer", "Data flow tracer", "External intelligence"],
    outputs: ["AI-discovered vulnerabilities", "Data flow traces", "Confidence scores"],
    icon: <PsychologyIcon />,
    duration: "60-180s",
    progressRange: "89-91%",
    color: "#f97316",
  },
  {
    name: "Final Deduplication",
    description: "Second deduplication pass ensures Agentic findings don't duplicate SAST results.",
    details: [
      "Cross-references Agentic AI findings with SAST findings",
      "Merges duplicates, preserving both sources for audit",
      "Marks duplicate findings in database (is_duplicate flag)",
      "Ensures report and findings API stay in sync",
    ],
    outputs: ["Final deduplicated findings", "Merge statistics"],
    icon: <AssessmentIcon />,
    duration: "2-5s",
    progressRange: "91-92%",
    color: "#0891b2",
  },
  {
    name: "AI Analysis & Corroboration",
    description: "Heuristics filter FPs, Agentic AI corroborates SAST, attack chains detected.",
    details: [
      "Heuristic FP detection: test files, mock code, suppressions",
      "Context-aware severity: auth checks, admin-only routes",
      "Agentic corroboration: cross-refs SAST with Agentic results",
      "Corroborated findings = high confidence (likely real)",
      "Uncorroborated + high FP score → filtered from report",
      "LLM analysis for top 20 most critical findings",
      "8 pre-defined attack chain patterns matched",
    ],
    tools: ["Gemini 2.0 Flash", "Heuristics", "Agentic correlation"],
    outputs: ["FP scores (0.0-1.0)", "Attack chains", "Severity adjustments"],
    icon: <VerifiedIcon />,
    duration: "30-120s",
    progressRange: "92-94%",
    color: "#dc2626",
  },
  {
    name: "Report Generation",
    description: "Final report compiled with findings, AI analysis, statistics, and sensitive data inventory.",
    details: [
      "Report aggregates: findings, attack chains, AI summary",
      "Sensitive data inventory: PII, credentials, API keys",
      "Includes deduplication, transitive, and reachability stats",
      "External intelligence summary: CVEs, SAST, vulnerable imports",
      "Docker and IaC scan statistics",
    ],
    outputs: ["Complete scan report", "Sensitive data inventory", "Scan statistics"],
    icon: <AssessmentIcon />,
    duration: "5-10s",
    progressRange: "94-98%",
    color: "#059669",
  },
  {
    name: "Exploitability & Webhooks",
    description: "Auto-generates exploitability scenarios for high/critical findings, then notifies external systems.",
    details: [
      "Exploitability scenarios for high/critical findings",
      "Executive summary + exploit templates generated",
      "Severity breakdown sent to webhooks",
      "WebSocket broadcast with total findings and duration",
      "Report ID and project info included in notifications",
    ],
    outputs: ["Exploitability scenarios", "Webhook notifications", "WebSocket completion event"],
    icon: <BugReportIcon />,
    duration: "10-30s",
    progressRange: "98-100%",
    color: "#b91c1c",
  },
];

// ============================================================================
// Scanner Details
// ============================================================================

interface ScannerDetail {
  name: string;
  languages: string[];
  description: string;
  strengths: string[];
  smartSelection: string;
  color: string;
  expandedInfo: {
    ruleCount?: string;
    howItWorks: string[];
    limitations: string[];
    commonFindings: string[];
  };
}

const scannerDetails: ScannerDetail[] = [
  {
    name: "Semgrep",
    languages: ["Python", "JavaScript", "TypeScript", "Go", "Java", "Ruby", "PHP", "C", "C++", "30+ total"],
    description: "Primary SAST scanner with 2000+ security rules. Runs on all projects.",
    strengths: ["30+ languages", "2000+ rules", "Taint tracking", "Low false positives"],
    smartSelection: "Always runs (universal coverage)",
    color: "#10b981",
    expandedInfo: {
      ruleCount: "2,000+ security rules",
      howItWorks: [
        "Pattern-based analysis using semantic grep syntax",
        "Taint tracking follows data from sources (user input) to sinks (dangerous functions)",
        "Supports custom rules via YAML configuration",
        "Incremental scanning for faster repeat runs",
      ],
      limitations: [
        "May miss complex control flow vulnerabilities",
        "Custom business logic flaws not covered by rules",
        "Requires rules to be written for new vulnerability patterns",
      ],
      commonFindings: [
        "SQL Injection (taint tracking from request → query)",
        "Command Injection (user input → os.system, subprocess)",
        "XSS (unsanitized output to HTML)",
        "Hardcoded secrets (API keys, passwords)",
        "Insecure deserialization (pickle, yaml.load)",
      ],
    },
  },
  {
    name: "Bandit",
    languages: ["Python"],
    description: "Python-specific security linter with AST-based analysis.",
    strengths: ["Python-native AST", "Confidence scoring", "Extensive rules"],
    smartSelection: "Runs when: 'python' in detected languages",
    color: "#3b82f6",
    expandedInfo: {
      ruleCount: "40+ security checks",
      howItWorks: [
        "Parses Python code into Abstract Syntax Tree (AST)",
        "Walks AST nodes looking for security anti-patterns",
        "Assigns confidence (HIGH/MEDIUM/LOW) to each finding",
        "Supports # nosec comments to suppress false positives",
      ],
      limitations: [
        "Python-only (no other languages)",
        "Cannot follow data flow across function boundaries",
        "May flag safe uses of 'dangerous' functions",
      ],
      commonFindings: [
        "Use of assert for security checks (B101)",
        "Hardcoded passwords/secrets (B105-B107)",
        "subprocess with shell=True (B602)",
        "SQL injection via string formatting (B608)",
        "Weak cryptographic hashes MD5/SHA1 (B303)",
      ],
    },
  },
  {
    name: "ESLint Security",
    languages: ["JavaScript", "TypeScript", "JSX", "TSX"],
    description: "eslint-plugin-security for JavaScript/TypeScript.",
    strengths: ["Native JS/TS", "React support", "Auto-fixable rules"],
    smartSelection: "Runs when: 'javascript' or 'typescript' detected",
    color: "#f59e0b",
    expandedInfo: {
      ruleCount: "20+ security rules",
      howItWorks: [
        "Extends ESLint with eslint-plugin-security",
        "Analyzes JavaScript/TypeScript AST for security issues",
        "Integrates with existing ESLint configuration",
        "Can auto-fix some issues automatically",
      ],
      limitations: [
        "No taint tracking (cannot follow data flow)",
        "Limited to syntactic patterns",
        "May miss DOM-based XSS without context",
      ],
      commonFindings: [
        "eval() usage (detect-eval-with-expression)",
        "Non-literal RegExp (detect-non-literal-regexp)",
        "Object injection (detect-object-injection)",
        "Unsafe innerHTML assignment",
        "Prototype pollution patterns",
      ],
    },
  },
  {
    name: "gosec",
    languages: ["Go"],
    description: "Go Security Checker with AST scanning.",
    strengths: ["Go-native AST", "Fast scanning", "Low false positives"],
    smartSelection: "Runs when: 'go' in detected languages",
    color: "#06b6d4",
    expandedInfo: {
      ruleCount: "30+ security rules",
      howItWorks: [
        "Parses Go source using go/ast package",
        "Checks for insecure function calls and patterns",
        "Understands Go idioms and standard library",
        "Outputs SARIF format for integration",
      ],
      limitations: [
        "Go-only scanner",
        "Cannot analyze compiled binaries",
        "Limited taint tracking",
      ],
      commonFindings: [
        "SQL injection via string concatenation (G201)",
        "Unescaped HTML templates (G203)",
        "Weak random number generation (G404)",
        "Hardcoded credentials (G101)",
        "TLS InsecureSkipVerify (G402)",
      ],
    },
  },
  {
    name: "SpotBugs + FindSecBugs",
    languages: ["Java", "Kotlin", "Scala"],
    description: "JVM bytecode analysis with Spring support.",
    strengths: ["Bytecode analysis", "Spring support", "300+ patterns"],
    smartSelection: "Runs when: 'java' or 'kotlin' detected",
    color: "#ef4444",
    expandedInfo: {
      ruleCount: "300+ security patterns",
      howItWorks: [
        "Analyzes compiled .class files (bytecode level)",
        "FindSecBugs plugin adds security-specific detectors",
        "Understands Spring, Hibernate, and other frameworks",
        "Can analyze JAR/WAR files directly",
      ],
      limitations: [
        "Requires compiled bytecode (not source-only)",
        "Build system must produce .class files",
        "May miss issues in reflection-heavy code",
      ],
      commonFindings: [
        "SQL Injection in JDBC queries",
        "XSS in JSP/Servlet responses",
        "Insecure deserialization (ObjectInputStream)",
        "Weak cryptography (DES, ECB mode)",
        "Path traversal in file operations",
      ],
    },
  },
  {
    name: "clang-tidy",
    languages: ["C", "C++", "Objective-C"],
    description: "Compiler-integrated analysis with LLVM tooling.",
    strengths: ["Compiler-integrated", "Deep analysis", "Buffer checks"],
    smartSelection: "Runs when: 'c' or 'cpp' detected",
    color: "#8b5cf6",
    expandedInfo: {
      ruleCount: "100+ checks (bugprone, security, modernize)",
      howItWorks: [
        "Uses Clang's AST for deep code understanding",
        "Applies bugprone-*, security-*, and cert-* checks",
        "Understands C++ templates and complex types",
        "Can apply automatic fixes for some issues",
      ],
      limitations: [
        "Requires compilation database for accurate analysis",
        "Slower than pattern-based scanners",
        "May struggle with macro-heavy code",
      ],
      commonFindings: [
        "Buffer overflows (bugprone-stringop-overflow)",
        "Use-after-free patterns",
        "Integer overflow in calculations",
        "Uninitialized variables",
        "Format string vulnerabilities",
      ],
    },
  },
  {
    name: "Cppcheck",
    languages: ["C", "C++"],
    description: "Static analysis for memory errors and undefined behavior.",
    strengths: ["Memory analysis", "No compile needed", "Low FP rate"],
    smartSelection: "Runs when: 'c' or 'cpp' detected",
    color: "#a855f7",
    expandedInfo: {
      ruleCount: "200+ checks",
      howItWorks: [
        "Analyzes source code without compilation",
        "Focuses on memory management issues",
        "Checks for undefined behavior and portability",
        "Complements clang-tidy with different detection patterns",
      ],
      limitations: [
        "Cannot resolve complex preprocessor macros",
        "Limited understanding of templates",
        "May miss context-dependent issues",
      ],
      commonFindings: [
        "Memory leaks (memleak)",
        "Buffer overruns (bufferAccessOutOfBounds)",
        "Null pointer dereference (nullPointer)",
        "Uninitialized variables (uninitvar)",
        "Resource leaks (resourceLeak)",
      ],
    },
  },
  {
    name: "PHP Security Scanner",
    languages: ["PHP"],
    description: "ProgPilot-based PHP security analysis with taint tracking.",
    strengths: ["Taint tracking", "Framework aware", "Data flow analysis"],
    smartSelection: "Runs when: 'php' in detected languages",
    color: "#777bb4",
    expandedInfo: {
      ruleCount: "50+ vulnerability patterns",
      howItWorks: [
        "Uses ProgPilot engine for taint analysis",
        "Tracks data flow from sources ($_GET, $_POST) to sinks",
        "Understands Laravel, Symfony, and other frameworks",
        "Analyzes include/require chains",
      ],
      limitations: [
        "May not understand all custom sanitization",
        "Dynamic PHP features can confuse analysis",
        "Framework-specific patterns may vary",
      ],
      commonFindings: [
        "SQL Injection via unsanitized input",
        "XSS through echo/print statements",
        "Command injection via exec(), system()",
        "File inclusion vulnerabilities",
        "Insecure deserialization (unserialize)",
      ],
    },
  },
  {
    name: "Brakeman",
    languages: ["Ruby", "Rails"],
    description: "Ruby on Rails security scanner with framework intelligence.",
    strengths: ["Rails-native", "Fast scanning", "Confidence levels"],
    smartSelection: "Runs when: 'ruby' in detected languages",
    color: "#cc342d",
    expandedInfo: {
      ruleCount: "40+ Rails-specific checks",
      howItWorks: [
        "Understands Rails conventions and MVC structure",
        "Analyzes controllers, models, views, and routes",
        "Tracks data from params to database/response",
        "No runtime required - pure static analysis",
      ],
      limitations: [
        "Rails-focused (limited for non-Rails Ruby)",
        "May miss issues in gems/dependencies",
        "Cannot analyze dynamically generated code",
      ],
      commonFindings: [
        "SQL Injection in ActiveRecord",
        "XSS in ERB templates (raw, html_safe)",
        "Mass assignment vulnerabilities",
        "CSRF protection issues",
        "Redirect to user-controlled URLs",
      ],
    },
  },
  {
    name: "Cargo Audit",
    languages: ["Rust"],
    description: "Rust crate vulnerability scanner using RustSec advisory database.",
    strengths: ["RustSec database", "Cargo.lock analysis", "Fast"],
    smartSelection: "Runs when: 'rust' in detected languages",
    color: "#f97316",
    expandedInfo: {
      ruleCount: "RustSec Advisory Database (1000+ advisories)",
      howItWorks: [
        "Parses Cargo.lock to identify exact crate versions",
        "Cross-references with RustSec Advisory Database",
        "Identifies vulnerable dependencies including transitive",
        "Provides upgrade recommendations",
      ],
      limitations: [
        "Only checks known vulnerabilities (not SAST)",
        "Requires Cargo.lock to be present",
        "Cannot detect logic bugs or custom code issues",
      ],
      commonFindings: [
        "Memory safety issues in crates",
        "Outdated crates with known CVEs",
        "Unmaintained dependencies",
        "Soundness bugs in unsafe code",
      ],
    },
  },
  {
    name: "Secret Scanner",
    languages: ["All files"],
    description: "50+ regex patterns for API keys, tokens, and credentials.",
    strengths: ["50+ patterns", "Multi-cloud", "Private keys", "Database strings"],
    smartSelection: "Always runs (all projects)",
    color: "#dc2626",
    expandedInfo: {
      ruleCount: "50+ secret patterns",
      howItWorks: [
        "Regex patterns for known secret formats",
        "Entropy analysis for high-randomness strings",
        "Context-aware: skips test/example files by default",
        "Detects AWS, GCP, Azure, GitHub, Stripe, and more",
      ],
      limitations: [
        "Cannot verify if secrets are active/valid",
        "May miss custom secret formats",
        "High entropy strings may be false positives",
      ],
      commonFindings: [
        "AWS Access Keys (AKIA...)",
        "GitHub Personal Access Tokens",
        "Private SSH/PGP keys",
        "Database connection strings",
        "API keys (Stripe, Twilio, SendGrid)",
      ],
    },
  },
  {
    name: "Trivy (Docker)",
    languages: ["Dockerfiles", "Container Images"],
    description: "Docker image scanning + Dockerfile linting.",
    strengths: ["Image scanning", "OS vulns", "Config checks"],
    smartSelection: "Runs when: Dockerfile detected",
    color: "#2496ed",
    expandedInfo: {
      ruleCount: "OS + Language vulnerability databases",
      howItWorks: [
        "Scans Dockerfiles for misconfigurations",
        "Analyzes container image layers for vulnerabilities",
        "Checks OS packages (apt, apk, yum)",
        "Scans language dependencies inside images",
      ],
      limitations: [
        "Image scanning requires Docker daemon",
        "Cannot scan private registries without auth",
        "Runtime behavior not analyzed",
      ],
      commonFindings: [
        "Running as root user",
        "Vulnerable base images (outdated OS)",
        "Exposed secrets in image layers",
        "Unnecessary packages installed",
        "Missing health checks",
      ],
    },
  },
  {
    name: "Checkov + tfsec (IaC)",
    languages: ["Terraform", "Kubernetes", "CloudFormation", "Helm", "ARM"],
    description: "Infrastructure as Code scanning for cloud misconfigurations.",
    strengths: ["Multi-framework", "Cloud-native", "CIS benchmarks"],
    smartSelection: "Runs when: .tf, K8s YAML, or cloud templates detected",
    color: "#7c3aed",
    expandedInfo: {
      ruleCount: "1000+ IaC policies",
      howItWorks: [
        "Parses Terraform, K8s manifests, and cloud templates",
        "Checks against CIS Benchmarks and best practices",
        "tfsec provides Terraform-specific deep analysis",
        "Supports custom policies via Python/Rego",
      ],
      limitations: [
        "Cannot verify actual cloud state",
        "May flag intentional configurations as issues",
        "Some policies are opinionated",
      ],
      commonFindings: [
        "S3 buckets without encryption",
        "Security groups with 0.0.0.0/0",
        "IAM policies with excessive permissions",
        "K8s pods running as root",
        "Missing resource limits in containers",
      ],
    },
  },
];

// ============================================================================
// AI Features
// ============================================================================

interface AIFeature {
  id: string;
  title: string;
  icon: React.ReactNode;
  description: string;
  howItWorks: string[];
  color: string;
}

const aiFeatures: AIFeature[] = [
  {
    id: "ai_triage",
    title: "AI File Triage (Pass 0)",
    icon: <AssessmentIcon />,
    description: "Before scanning, AI examines ALL file names to intelligently prioritize which files to analyze—smarter than pattern matching.",
    howItWorks: [
      "AI receives list of all files with paths, extensions, sizes",
      "Assigns security relevance score (0-10) to each file",
      "Prioritizes: auth/, crypto/, api/, handlers/, middleware/",
      "Deprioritizes: tests/, docs/, assets/, migrations/",
      "Cross-references with external intel (files importing vulnerable deps)",
      "Parallel processing: 4 batches of 200 files simultaneously",
      "Output: Sorted list of files by security risk for subsequent passes",
    ],
    color: "#14b8a6",
  },
  {
    id: "multi_pass",
    title: "Multi-Pass Deep Scan",
    icon: <LayersIcon />,
    description: "Progressive 4-pass analysis: AI scans many files briefly, then focuses with more content on high-risk files.",
    howItWorks: [
      "Pass 1 (Quick): 180 files × 5K chars - identifies entry points, scores files 0-10",
      "Pass 2 (Focused): 60 files × 12K chars - traces data flows, cross-refs CVE/SAST",
      "Pass 3 (Deep): 22 files × 50K chars - comprehensive audit, every function",
      "Pass 4 (Ultra): 7 files × 100K chars - files >50K only, full content",
      "Enhanced mode doubles these limits for thorough analysis",
    ],
    color: "#f97316",
  },
  {
    id: "external_intelligence",
    title: "External Intelligence Integration",
    icon: <PsychologyIcon />,
    description: "AI receives CVE, SAST, and dependency context BEFORE analyzing code—knows where vulnerable imports exist.",
    howItWorks: [
      "CVE findings from OSV.dev/NVD fed to AI before code analysis",
      "SAST findings from all scanners included as context",
      "Dependency graph shows which files import vulnerable packages",
      "AI prioritizes files that import requests, flask, django-auth, etc.",
      "Security findings summary helps AI understand threat landscape",
      "External intel enables AI to corroborate or refute SAST findings",
    ],
    color: "#8b5cf6",
  },
  {
    id: "agentic_corroboration",
    title: "Agentic Corroboration",
    icon: <VerifiedIcon />,
    description: "Cross-references traditional SAST findings with Agentic AI deep scan. Findings confirmed by both are highly likely real.",
    howItWorks: [
      "SAST scanners and Agentic AI find vulnerabilities independently",
      "Results cross-referenced by file location, vuln type, description",
      "Corroborated = FP score reduced by 0.3-0.4 (likely real)",
      "Not corroborated = FP score increased by 0.15-0.45 (may be FP)",
      "Vuln type normalization: 'sql injection' = 'sqli' = 'sql'",
    ],
    color: "#06b6d4",
  },
  {
    id: "false_positives",
    title: "False Positive Detection",
    icon: <VisibilityOffIcon />,
    description: "Three-stage approach: heuristic patterns first, then Agentic corroboration, then LLM for complex cases.",
    howItWorks: [
      "Heuristics (instant): test_*.py, mock code, example/, # nosec comments",
      "Context patterns: @login_required, @admin_only → severity reduced",
      "ORM usage, parameterized queries → may be FP",
      "Hardcoded secrets from env vars → severity reduced to LOW",
      "Agentic corroboration adds confidence to real findings",
      "LLM analyzes top 20 complex cases only",
    ],
    color: "#f59e0b",
  },
  {
    id: "attack_chains",
    title: "Attack Chain Discovery",
    icon: <LinkIcon />,
    description: "8+ pre-defined attack chain patterns combine related findings into exploitable paths.",
    howItWorks: [
      "SQLi → Database Takeover → Data Exfiltration",
      "SQLi + Auth Bypass → Full Account Takeover",
      "SSRF → Internal Service Access → Cloud Credential Theft",
      "XSS + Auth → Session Hijacking → Account Takeover",
      "Command Injection → RCE → Full Server Compromise",
      "Path Traversal → Sensitive File Access → Credential Theft",
      "LLM refines chains and discovers non-obvious combinations",
    ],
    color: "#10b981",
  },
  {
    id: "severity_adjustment",
    title: "Severity Adjustment",
    icon: <SecurityIcon />,
    description: "Context-aware severity based on code patterns and real-world threat intelligence.",
    howItWorks: [
      "Auth checks present (@login_required) → severity reduced",
      "Admin-only functionality → severity reduced",
      "Internal/localhost endpoints → severity reduced",
      "CISA KEV (actively exploited) → always HIGH+",
      "EPSS > 0.7 (70%+ exploit probability) → escalate to HIGH",
      "Pattern-based: ORM, shlex.quote → severity reduced",
    ],
    color: "#3b82f6",
  },
  {
    id: "exploit_scenarios",
    title: "Exploit Scenarios",
    icon: <AutoAwesomeIcon />,
    description: "16+ pre-built exploit templates provide instant scenarios. LLM only for novel cases.",
    howItWorks: [
      "SQLi: sqlmap enumeration, UNION extraction, xp_cmdshell RCE",
      "XSS: Cookie theft, session hijacking, keylogging",
      "SSRF: Cloud metadata access, internal port scanning",
      "Command injection: Reverse shell, persistence",
      "Path traversal: /etc/passwd, source code theft",
      "Templates include tools (Burp, sqlmap) and impact assessment",
    ],
    color: "#dc2626",
  },
];

// ============================================================================
// Stats
// ============================================================================

const scannerStats = [
  { label: "Languages", value: "60+", icon: <CodeIcon /> },
  { label: "SAST Scanners", value: "13", icon: <SecurityIcon /> },
  { label: "Secret Patterns", value: "50+", icon: <VpnKeyIcon /> },
  { label: "CVE Databases", value: "4", icon: <BugReportIcon /> },
];

// ============================================================================
// Main Component
// ============================================================================

export default function SecurityScanGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  const [expandedScanner, setExpandedScanner] = useState<string | false>(false);

  const pageContext = `Comprehensive guide to VRAgent's security scanning pipeline. Covers the 10-phase scanning process (extraction, parallel SAST, CVE enrichment, reachability, Agentic AI deep scan), 11 SAST scanners with smart language selection, and AI analysis features (multi-pass scanning, agentic corroboration, false positive detection, attack chain discovery, severity adjustment, exploit scenarios). Learn how VRAgent uses Google Gemini AI to transform raw vulnerability data into actionable security intelligence.`;

  return (
    <LearnPageLayout pageTitle="Security Scan Guide" pageContext={pageContext}>
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
          <Typography
            variant="h3"
            sx={{
              fontWeight: 800,
              mb: 2,
              background: `linear-gradient(135deg, ${theme.palette.primary.main}, #8b5cf6)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}
          >
            🔍 Security Scan &amp; AI Analysis Guide
          </Typography>
          <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
            Complete technical walkthrough of VRAgent's security scanning pipeline—from code extraction through multi-pass Agentic AI analysis with Google Gemini.
          </Typography>
        </Box>

        {/* Stats Banner */}
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {scannerStats.map((stat) => (
            <Grid item xs={6} md={3} key={stat.label}>
              <Paper
                sx={{
                  p: 2.5,
                  textAlign: "center",
                  background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.08)}, ${alpha("#8b5cf6", 0.04)})`,
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

        {/* Tabs */}
        <Paper sx={{ mb: 4, borderRadius: 3 }}>
          <Tabs
            value={activeTab}
            onChange={(_, v) => setActiveTab(v)}
            variant="fullWidth"
            sx={{
              borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              "& .MuiTab-root": { py: 2, fontWeight: 600 },
            }}
          >
            <Tab icon={<TimelineIcon />} label="10-Phase Pipeline" iconPosition="start" />
            <Tab icon={<SecurityIcon />} label="SAST Scanners" iconPosition="start" />
            <Tab icon={<PsychologyIcon />} label="AI Analysis" iconPosition="start" />
          </Tabs>
        </Paper>

        {/* Tab 0: Pipeline */}
        {activeTab === 0 && (
          <>
            {/* Pipeline Overview */}
            <Paper sx={{ p: 3, mb: 4, background: alpha(theme.palette.info.main, 0.02), borderRadius: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <LayersIcon sx={{ fontSize: 28, color: "info.main" }} />
                <Typography variant="h6" fontWeight={700}>Pipeline Overview</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Your code passes through <strong>10 distinct phases</strong>. The key innovation is <strong>Phase 4</strong> where SAST, Docker, IaC, and dependency scanning run <strong>in parallel</strong> using ThreadPoolExecutor. Smart scanner selection only runs scanners for detected languages.
              </Typography>
              
              {/* Visual Pipeline */}
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, justifyContent: "center", mb: 3 }}>
                {scanPhases.map((phase, index) => (
                  <Box key={phase.name} sx={{ display: "flex", alignItems: "center" }}>
                    <Tooltip title={`${phase.name} (${phase.progressRange})`}>
                      <Box
                        sx={{
                          width: 40,
                          height: 40,
                          borderRadius: "50%",
                          bgcolor: phase.color,
                          color: "white",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontWeight: 700,
                          fontSize: "0.85rem",
                          cursor: "pointer",
                          boxShadow: `0 4px 12px ${alpha(phase.color, 0.4)}`,
                          "&:hover": { transform: "scale(1.1)" },
                          transition: "transform 0.2s",
                        }}
                      >
                        {index + 1}
                      </Box>
                    </Tooltip>
                    {index < scanPhases.length - 1 && (
                      <Box sx={{ width: { xs: 8, md: 20 }, height: 2, bgcolor: alpha(theme.palette.divider, 0.3) }} />
                    )}
                  </Box>
                ))}
              </Box>

              {/* Key Points */}
              <Divider sx={{ my: 2 }} />
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.1) }}>
                    <Typography variant="subtitle2" fontWeight="bold" color="#10b981">⚡ Parallel Execution</Typography>
                    <Typography variant="body2">ThreadPoolExecutor runs SAST (11 scanners), Docker, IaC, and deps concurrently.</Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <Typography variant="subtitle2" fontWeight="bold" color="#8b5cf6">🎯 Smart Selection</Typography>
                    <Typography variant="body2">Language detection determines which scanners run. No Python? Bandit skipped.</Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.1) }}>
                    <Typography variant="subtitle2" fontWeight="bold" color="#ef4444">🔄 Embedding Reuse</Typography>
                    <Typography variant="body2">SHA-256 hash enables embedding reuse from previous scans when code unchanged.</Typography>
                  </Box>
                </Grid>
              </Grid>
            </Paper>

            {/* Phase Stepper */}
            <Paper sx={{ p: 3, borderRadius: 3 }}>
              <Typography variant="h6" fontWeight={700} sx={{ mb: 3 }}>
                📊 The 10-Phase Scanning Pipeline
              </Typography>
              <Stepper orientation="vertical">
                {scanPhases.map((phase, index) => (
                  <Step key={phase.name} active completed>
                    <StepLabel
                      StepIconComponent={() => (
                        <Box
                          sx={{
                            width: 44,
                            height: 44,
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
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, flexWrap: "wrap" }}>
                        <Typography variant="subtitle1" fontWeight={700}>{phase.name}</Typography>
                        <Chip label={phase.duration} size="small" sx={{ bgcolor: alpha(phase.color, 0.1), color: phase.color, fontWeight: 600, height: 24 }} />
                        <Chip label={phase.progressRange} size="small" variant="outlined" sx={{ borderColor: alpha(phase.color, 0.5), color: phase.color, height: 24, fontSize: "0.7rem" }} />
                      </Box>
                    </StepLabel>
                    <StepContent>
                      <Typography color="text.secondary" sx={{ mb: 2 }}>{phase.description}</Typography>
                      <Grid container spacing={2}>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1, color: phase.color }}>What happens:</Typography>
                          {phase.details.map((detail, i) => (
                            <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                              <CheckCircleIcon sx={{ fontSize: 16, color: phase.color, mt: 0.3 }} />
                              <Typography variant="body2">{detail}</Typography>
                            </Box>
                          ))}
                        </Grid>
                        <Grid item xs={12} md={6}>
                          {phase.tools && (
                            <Box sx={{ mb: 1.5 }}>
                              <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1 }}>Tools:</Typography>
                              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                {phase.tools.map((tool) => (
                                  <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ borderColor: phase.color, color: phase.color, height: 24 }} />
                                ))}
                              </Box>
                            </Box>
                          )}
                          {phase.outputs && (
                            <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(phase.color, 0.05), border: `1px solid ${alpha(phase.color, 0.2)}` }}>
                              <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 0.5, color: phase.color }}>📤 Outputs:</Typography>
                              {phase.outputs.map((output) => (
                                <Typography key={output} variant="body2" sx={{ mb: 0.25 }}>→ {output}</Typography>
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
          </>
        )}

        {/* Tab 1: Scanners */}
        {activeTab === 1 && (
          <Paper sx={{ p: 3, borderRadius: 3 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <SecurityIcon sx={{ fontSize: 28, color: "primary.main" }} />
              <Typography variant="h6" fontWeight={700}>🛠️ Security Scanner Arsenal</Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              VRAgent employs <strong>13 specialized security scanners</strong> covering SAST, secrets, Docker, and IaC. All applicable scanners run in parallel using ThreadPoolExecutor.
            </Typography>
            <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
              <strong>Smart Scanner Selection:</strong> Language detection via file extensions determines which scanners run. No Python files? Bandit is skipped. This optimizes scan time while ensuring coverage.
            </Alert>

            {scannerDetails.map((scanner) => (
              <Accordion
                key={scanner.name}
                expanded={expandedScanner === scanner.name}
                onChange={(_, isExpanded) => setExpandedScanner(isExpanded ? scanner.name : false)}
                sx={{ mb: 1.5, border: `1px solid ${alpha(scanner.color, 0.2)}`, borderRadius: "8px !important", "&:before": { display: "none" } }}
              >
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ borderLeft: `4px solid ${scanner.color}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%", flexWrap: "wrap" }}>
                    <Typography variant="subtitle1" fontWeight={700} sx={{ minWidth: 160 }}>{scanner.name}</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, flex: 1 }}>
                      {scanner.languages.slice(0, 4).map((lang) => (
                        <Chip key={lang} label={lang} size="small" sx={{ fontSize: "0.7rem", height: 22, bgcolor: alpha(scanner.color, 0.1), color: scanner.color }} />
                      ))}
                      {scanner.languages.length > 4 && (
                        <Chip label={`+${scanner.languages.length - 4}`} size="small" variant="outlined" sx={{ fontSize: "0.7rem", height: 22 }} />
                      )}
                    </Box>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{scanner.description}</Typography>
                  
                  {/* Smart Selection */}
                  <Box sx={{ mb: 2, p: 1.5, borderRadius: 1, bgcolor: alpha(scanner.color, 0.05), border: `1px dashed ${alpha(scanner.color, 0.3)}` }}>
                    <Typography variant="body2" sx={{ fontWeight: 600, color: scanner.color }}>
                      🎯 {scanner.smartSelection}
                    </Typography>
                  </Box>

                  {/* Rule Count */}
                  {scanner.expandedInfo.ruleCount && (
                    <Box sx={{ mb: 2 }}>
                      <Chip 
                        label={`📊 ${scanner.expandedInfo.ruleCount}`} 
                        size="small" 
                        sx={{ bgcolor: alpha(scanner.color, 0.15), color: scanner.color, fontWeight: 600 }} 
                      />
                    </Box>
                  )}

                  <Grid container spacing={2}>
                    {/* How It Works */}
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1, color: "success.main" }}>⚙️ How It Works</Typography>
                      <Box sx={{ pl: 1 }}>
                        {scanner.expandedInfo.howItWorks.map((item, i) => (
                          <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "success.main", mt: 0.4 }} />
                            <Typography variant="body2">{item}</Typography>
                          </Box>
                        ))}
                      </Box>
                    </Grid>

                    {/* Common Findings */}
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1, color: "warning.main" }}>🔍 Common Findings</Typography>
                      <Box sx={{ pl: 1 }}>
                        {scanner.expandedInfo.commonFindings.map((item, i) => (
                          <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                            <BugReportIcon sx={{ fontSize: 14, color: "warning.main", mt: 0.4 }} />
                            <Typography variant="body2">{item}</Typography>
                          </Box>
                        ))}
                      </Box>
                    </Grid>
                  </Grid>

                  {/* Limitations */}
                  <Box sx={{ mt: 2, p: 1.5, borderRadius: 1, bgcolor: alpha(theme.palette.error.main, 0.05), border: `1px solid ${alpha(theme.palette.error.main, 0.1)}` }}>
                    <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1, color: "error.main" }}>⚠️ Limitations</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {scanner.expandedInfo.limitations.map((item, i) => (
                        <Chip 
                          key={i} 
                          label={item} 
                          size="small" 
                          variant="outlined"
                          sx={{ fontSize: "0.7rem", borderColor: alpha(theme.palette.error.main, 0.3), color: "text.secondary" }} 
                        />
                      ))}
                    </Box>
                  </Box>

                  {/* Strengths */}
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1, color: "success.main" }}>💪 Strengths</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {scanner.strengths.map((s) => (
                        <Chip key={s} label={s} size="small" sx={{ bgcolor: alpha(theme.palette.success.main, 0.1), color: "success.main" }} />
                      ))}
                    </Box>
                  </Box>
                </AccordionDetails>
              </Accordion>
            ))}
          </Paper>
        )}

        {/* Tab 2: AI Analysis */}
        {activeTab === 2 && (
          <>
            {/* AI Overview */}
            <Paper sx={{ p: 3, mb: 4, background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.05)}, ${alpha("#ec4899", 0.05)})`, borderRadius: 3 }}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={8}>
                  <Typography variant="h6" fontWeight={700} sx={{ mb: 2 }}>
                    🧠 How AI Enhances Security Analysis
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
                    VRAgent uses a <strong>three-stage approach</strong>: fast heuristic patterns first, <strong>Agentic AI corroboration</strong> to cross-reference SAST findings with deep AI analysis, then <strong>Google Gemini 2.0 Flash</strong> for complex cases. This hybrid approach reduces false positives while catching real vulnerabilities.
                  </Typography>
                  <Alert severity="info" sx={{ mb: 2, borderRadius: 2 }}>
                    <strong>🔒 Privacy:</strong> Only vulnerability metadata is sent to AI—not your full source code. File paths, findings, and snippets are shared, but complete source files stay on your server.
                  </Alert>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    <Chip label="Gemini 2.0 Flash" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6", fontWeight: 600 }} />
                    <Chip label="AI File Triage" sx={{ bgcolor: alpha("#14b8a6", 0.1), color: "#14b8a6", fontWeight: 600 }} />
                    <Chip label="Agentic Corroboration" sx={{ bgcolor: alpha("#06b6d4", 0.1), color: "#06b6d4", fontWeight: 600 }} />
                    <Chip label="External Intelligence" sx={{ bgcolor: alpha("#f97316", 0.1), color: "#f97316", fontWeight: 600 }} />
                    <Chip label="8 Attack Chain Patterns" variant="outlined" />
                  </Box>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Box sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5), p: 2, borderRadius: 2, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
                    <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1.5 }}>AI Analysis Flow</Typography>
                    {[
                      { icon: "�", label: "AI Triage prioritizes files" },
                      { icon: "🔍", label: "Scanners + Agentic AI find vulns" },
                      { icon: "⚡", label: "Heuristics filter obvious FPs" },
                      { icon: "✅", label: "Agentic corroboration cross-refs" },
                      { icon: "📊", label: "Top 20 findings → LLM" },
                      { icon: "🔗", label: "8 attack chain patterns" },
                      { icon: "📝", label: "Templates generate exploits" },
                    ].map((step, i) => (
                      <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                        <Typography>{step.icon}</Typography>
                        <Typography variant="body2">{step.label}</Typography>
                      </Box>
                    ))}
                  </Box>
                </Grid>
              </Grid>
            </Paper>

            {/* AI Feature Cards */}
            <Typography variant="h6" fontWeight={700} sx={{ mb: 2 }}>🎯 8 AI Analysis Capabilities</Typography>
            <Grid container spacing={2}>
              {aiFeatures.map((feature) => (
                <Grid item xs={12} md={6} key={feature.id}>
                  <Paper sx={{ p: 3, borderRadius: 3, height: "100%", borderTop: `4px solid ${feature.color}` }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                      <Box sx={{ p: 1, borderRadius: 2, bgcolor: alpha(feature.color, 0.1), color: feature.color }}>
                        {feature.icon}
                      </Box>
                      <Typography variant="subtitle1" fontWeight={700}>{feature.title}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {feature.description}
                    </Typography>
                    <Divider sx={{ my: 1.5 }} />
                    <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, color: feature.color }}>How it works:</Typography>
                    {feature.howItWorks.map((item, i) => (
                      <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: feature.color, mt: 0.4 }} />
                        <Typography variant="body2">{item}</Typography>
                      </Box>
                    ))}
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </>
        )}

        {/* Bottom Navigation */}
        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Container>
    </LearnPageLayout>
  );
}
