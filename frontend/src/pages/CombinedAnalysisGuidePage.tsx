import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Typography,
  Paper,
  Card,
  CardContent,
  Grid,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert,
  alpha,
  useTheme,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  Button,
} from "@mui/material";
import {
  ArrowBack as BackIcon,
  Analytics as AnalyticsIcon,
  Security as SecurityIcon,
  NetworkCheck as NetworkIcon,
  BugReport as BugIcon,
  Memory as MemoryIcon,
  CheckCircle as CheckIcon,
  AutoAwesome as AIIcon,
  Description as DocumentIcon,
  Assessment as AssessmentIcon,
  MergeType as MergeIcon,
  Lightbulb as LightbulbIcon,
  Chat as ChatIcon,
  ExpandMore as ExpandMoreIcon,
  Code as CodeIcon,
  Timeline as TimelineIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Psychology as PsychologyIcon,
  Link as LinkIcon,
  Warning as WarningIcon,
} from "@mui/icons-material";
import { Link, useNavigate } from "react-router-dom";

// ============================================================================
// Data Types
// ============================================================================

interface FeatureItem {
  icon: React.ReactNode;
  title: string;
  description: string;
  details?: string[];
}

interface WorkflowStep {
  step: number;
  title: string;
  description: string;
  icon: React.ReactNode;
  details: string[];
}

interface ReportSection {
  title: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  contents: string[];
}

// ============================================================================
// Static Data
// ============================================================================

const SCAN_SOURCES: FeatureItem[] = [
  {
    icon: <SecurityIcon sx={{ color: "#3b82f6" }} />,
    title: "Security Scans (SAST)",
    description: "Static code analysis findings, CVEs, exploit scenarios with PoC scripts.",
    details: [
      "All SAST scanner findings (Semgrep, Bandit, ESLint, etc.)",
      "CVE matches with CVSS, EPSS, and KEV enrichment",
      "Exploit scenarios with working PoC scripts",
      "Codebase architecture & attack surface maps",
      "Entry points analysis with auth requirements",
    ],
  },
  {
    icon: <NetworkIcon sx={{ color: "#0ea5e9" }} />,
    title: "Network Reports (PCAP/Nmap)",
    description: "Packet captures, port scans, and network traffic analysis.",
    details: [
      "Nmap port scans with OS/service fingerprinting",
      "PCAP deep packet inspection with protocol analysis",
      "Credential extraction from network traffic",
      "Hosts analysis and network topology mapping",
      "AI-generated offensive insights",
    ],
  },
  {
    icon: <WarningIcon sx={{ color: "#ef4444" }} />,
    title: "SSL/TLS Scans",
    description: "Certificate validation, cipher analysis, and cryptographic vulnerability detection.",
    details: [
      "Certificate chain and expiry validation",
      "Protocol support analysis (TLS 1.0-1.3)",
      "Weak cipher and vulnerability detection (BEAST, POODLE, Heartbleed)",
      "Self-signed and certificate mismatch detection",
      "Offensive analysis for MITM opportunities",
    ],
  },
  {
    icon: <LinkIcon sx={{ color: "#06b6d4" }} />,
    title: "DNS Reconnaissance",
    description: "Domain enumeration, subdomain discovery, and DNS security analysis.",
    details: [
      "Zone transfer vulnerability testing",
      "Subdomain takeover risk assessment",
      "Dangling CNAME detection",
      "SPF/DMARC/DKIM email security checks",
      "Cloud provider and ASN identification",
    ],
  },
  {
    icon: <TimelineIcon sx={{ color: "#8b5cf6" }} />,
    title: "Traceroute Scans",
    description: "Network path analysis and infrastructure mapping.",
    details: [
      "Full hop-by-hop network path mapping",
      "Latency analysis and packet loss detection",
      "Firewall and filtering identification",
      "Network segment inference from hostnames",
      "AI security observations on network architecture",
    ],
  },
  {
    icon: <MemoryIcon sx={{ color: "#a855f7" }} />,
    title: "Reverse Engineering",
    description: "Binary, APK, and Docker image security analysis.",
    details: [
      "APK manifest, permissions, and certificate analysis",
      "Binary PE/ELF headers with dangerous function detection",
      "Docker layer inspection and secrets extraction",
      "Decompiled code vulnerability findings",
      "CVE scanning for embedded libraries",
    ],
  },
  {
    icon: <BugIcon sx={{ color: "#f97316" }} />,
    title: "API Fuzzing Sessions",
    description: "HTTP/API endpoint fuzzing for input validation issues.",
    details: [
      "Parameter fuzzing and injection testing",
      "Response anomaly detection",
      "Input validation bypass attempts",
      "Edge case and boundary testing",
      "Rate limiting and auth bypass tests",
    ],
  },
  {
    icon: <PsychologyIcon sx={{ color: "#ec4899" }} />,
    title: "Agentic Fuzzer Reports",
    description: "AI-driven intelligent fuzzing with LLM decision making.",
    details: [
      "LLM-guided intelligent payload generation",
      "Multi-iteration adaptive fuzzing",
      "Correlation analysis across endpoints",
      "Executive summary with exploitation guidance",
      "Technique tracking and coverage metrics",
    ],
  },
  {
    icon: <CodeIcon sx={{ color: "#10b981" }} />,
    title: "Dynamic Scans (DAST)",
    description: "Runtime vulnerability scanning with active exploitation testing.",
    details: [
      "Active spider and scanner results",
      "OWASP Top 10 vulnerability detection",
      "URL discovery and site mapping",
      "Alert categorization by risk level",
      "Evidence collection for each finding",
    ],
  },
  {
    icon: <MemoryIcon sx={{ color: "#dc2626" }} />,
    title: "Binary Fuzzer (AFL++)",
    description: "Coverage-guided binary fuzzing for memory corruption.",
    details: [
      "Crash triage with exploitability assessment",
      "Memory error detection (ASan/MSan integration)",
      "Coverage tracking and corpus management",
      "Stack trace analysis for each crash",
      "AI-generated security insights on crashes",
    ],
  },
];

const WORKFLOW_STEPS: WorkflowStep[] = [
  {
    step: 1,
    title: "Select Data Sources",
    description: "Choose from 10 scan types to include in your combined analysis.",
    icon: <CheckIcon />,
    details: [
      "Browse available security scans (SAST findings with exploit scenarios)",
      "Select network analysis reports (Nmap, PCAP with credential extraction)",
      "Include SSL/TLS scans (certificate, cipher, vulnerability analysis)",
      "Add DNS reconnaissance (subdomain takeover, zone transfer risks)",
      "Include traceroute scans (network path and infrastructure mapping)",
      "Add reverse engineering findings (APK, Binary, Docker analysis)",
      "Include API fuzzing sessions (input validation, injection tests)",
      "Select Agentic Fuzzer reports (AI-driven intelligent scanning)",
      "Add Dynamic Scans (DAST runtime vulnerability testing)",
      "Include Binary Fuzzer sessions (AFL++ crash and memory corruption)",
    ],
  },
  {
    step: 2,
    title: "Add Context & Documents",
    description: "Provide project info and upload supporting documents for AI context.",
    icon: <DocumentIcon />,
    details: [
      "Enter project context: tech stack, architecture, deployment environment",
      "Specify user requirements: compliance needs, priority focus areas",
      "Upload supporting documents (PDFs, Word docs, architecture diagrams)",
      "Documents processed by AI for deep contextual analysis (125K chars each)",
      "Add threat models, API specs, or security requirements",
      "User requirements passed to ALL 9 AI agents for tailored output",
    ],
  },
  {
    step: 3,
    title: "Configure Analysis Options",
    description: "Enable advanced features for comprehensive exploit analysis.",
    icon: <AssessmentIcon />,
    details: [
      "Include Exploit Recommendations: Detailed PoC scripts with usage instructions",
      "Include Attack Surface Map: Professional Mermaid diagram with icons",
      "Include Risk Prioritization: CVSS + EPSS + corroboration confidence scoring",
      "Enable Beginner Attack Guides: Step-by-step tutorials with troubleshooting",
      "Smart context prioritization: Critical findings NEVER truncated",
      "Token budget management ensures quality over quantity",
    ],
  },
  {
    step: 4,
    title: "9 Parallel AI Agents Analyze",
    description: "Specialized AI agents process data in parallel for comprehensive coverage.",
    icon: <AIIcon />,
    details: [
      "🎯 Agent 1 - Executive Summary: Overall risk posture and business impact",
      "💻 Agent 2 - PoC Scripts: Working Python/bash exploit code with 30+ lines each",
      "📚 Agent 3 - Attack Guides: 7+ step beginner tutorials with troubleshooting",
      "⚠️ Agent 4 - Prioritized Vulns: Ranked findings with exploitation steps",
      "🔗 Agent 5 - Cross-Analysis: Correlates ALL 10 scan types for attack chains",
      "🗺️ Agent 6 - Attack Surface: Professional Mermaid diagram with styling",
      "⛓️ Agent 7 - Attack Chains: Multi-step vulnerability combinations",
      "🔓 Agent 8 - Exploit Development: Advanced exploitation opportunities",
      "📝 Agent 9 - Source Code: Deep code analysis with secure fixes",
      "✅ Agent 10 - Synthesis: Quality validation and consistency checking",
    ],
  },
];

const REPORT_SECTIONS: ReportSection[] = [
  {
    title: "Executive Summary",
    description: "High-level security posture with corroboration highlights",
    icon: <AssessmentIcon />,
    color: "#3b82f6",
    contents: [
      "Overall risk level (Critical/High/Medium/Low) with justification",
      "High-confidence findings (detected by multiple scan sources)",
      "Key risk areas with business impact analysis",
      "Top priority recommendations with action timelines",
      "Corroboration summary highlighting multi-source validated issues",
    ],
  },
  {
    title: "Prioritized Vulnerabilities",
    description: "Risk-ranked findings with corroboration confidence scoring",
    icon: <WarningIcon />,
    color: "#ef4444",
    contents: [
      "Vulnerabilities ranked by combined risk + corroboration score",
      "Corroborated findings (2+ sources) flagged as HIGH CONFIDENCE",
      "5+ detailed exploitation steps per vulnerability",
      "CVSS estimates with exploitability ratings",
      "Remediation priority and timeline recommendations",
    ],
  },
  {
    title: "Cross-Analysis Findings",
    description: "Vulnerabilities correlated across ALL 10 scan types",
    icon: <MergeIcon />,
    color: "#8b5cf6",
    contents: [
      "Findings that span multiple scan sources (SAST + DAST + Fuzzing)",
      "Code vulnerabilities linked to network exposure",
      "SSL weaknesses correlated with code crypto issues",
      "DNS/subdomain issues linked to exposed services",
      "Confidence levels: High (3+ sources), Medium (2 sources)",
    ],
  },
  {
    title: "PoC Scripts",
    description: "Working proof-of-concept exploit code (30+ lines each)",
    icon: <CodeIcon />,
    color: "#10b981",
    contents: [
      "Complete Python/bash/curl scripts ready to execute",
      "Usage instructions with command examples",
      "Expected output and success indicators",
      "Customization notes for different scenarios",
      "Aligned with prioritized vulnerabilities",
    ],
  },
  {
    title: "Beginner Attack Guides",
    description: "Step-by-step exploitation tutorials with troubleshooting",
    icon: <LightbulbIcon />,
    color: "#f59e0b",
    contents: [
      "7+ numbered steps per vulnerability",
      "Tool installation and setup instructions",
      "Expected output at each step",
      "Troubleshooting tips for common issues",
      "Success indicators and 'what you can do after'",
    ],
  },
  {
    title: "Attack Surface Diagram",
    description: "Professional Mermaid flowchart with icons and severity styling",
    icon: <TimelineIcon />,
    color: "#06b6d4",
    contents: [
      "Mermaid flowchart with attacker, entry points, vulns, and impact",
      "Color-coded severity classes (Critical=red, High=orange)",
      "Icons for different component types (🎭 Attacker, 📍 Entry, ⚠️ Vuln)",
      "Data flow from input to impact",
      "Subgraphs for logical grouping",
    ],
  },
  {
    title: "Attack Chains",
    description: "Multi-step vulnerability combinations for maximum impact",
    icon: <LinkIcon />,
    color: "#ec4899",
    contents: [
      "Kill chain mapping (Initial Access → Impact)",
      "Step-by-step chain with vulnerability at each stage",
      "Likelihood assessment (High/Medium/Low)",
      "Final impact description",
      "Entry point and prerequisites",
    ],
  },
  {
    title: "Exploit Development Areas",
    description: "Advanced areas for custom exploit development",
    icon: <PsychologyIcon />,
    color: "#a855f7",
    contents: [
      "Memory corruption opportunities from binary fuzzing",
      "Logic flaws suitable for custom exploits",
      "Full PoC scripts with testing notes",
      "Detection evasion techniques",
      "Prerequisites and complexity ratings",
    ],
  },
  {
    title: "Source Code Findings",
    description: "Deep code analysis with vulnerable and fixed code examples",
    icon: <CodeIcon />,
    color: "#22c55e",
    contents: [
      "Vulnerability with file path and line numbers",
      "Vulnerable code snippet highlighted",
      "Exploitation example showing exact attack",
      "Secure code fix with corrected implementation",
      "Correlation with other scan findings",
    ],
  },
];

const KEY_FEATURES: FeatureItem[] = [
  {
    icon: <MergeIcon sx={{ color: "#8b5cf6" }} />,
    title: "10-Source Cross-Correlation",
    description: "AI correlates findings from ALL 10 scan types: SAST, Network, SSL, DNS, Traceroute, RE, API Fuzzing, Agentic Fuzzer, DAST, and Binary Fuzzer.",
  },
  {
    icon: <CheckIcon sx={{ color: "#10b981" }} />,
    title: "Corroboration Confidence Scoring",
    description: "Findings detected by multiple independent scanners are flagged as HIGH CONFIDENCE - validated across 2-3+ sources for reliability.",
  },
  {
    icon: <LightbulbIcon sx={{ color: "#f59e0b" }} />,
    title: "Beginner Attack Guides",
    description: "Step-by-step tutorials with tool installation, expected output, troubleshooting, and success indicators for each vulnerability.",
  },
  {
    icon: <AssessmentIcon sx={{ color: "#ef4444" }} />,
    title: "Smart Context Prioritization",
    description: "Token budget management ensures Critical/High findings are NEVER truncated. Lower severity summarized intelligently.",
  },
  {
    icon: <ChatIcon sx={{ color: "#ec4899" }} />,
    title: "AI Chat with Full Report Access",
    description: "Ask questions about the report, request clarifications, explore alternative exploitation methods, or generate additional PoCs.",
  },
  {
    icon: <CodeIcon sx={{ color: "#3b82f6" }} />,
    title: "Enhanced Source Code Search",
    description: "Semantic pattern matching searches codebase using vulnerability-specific regex patterns for accurate correlation.",
  },
  {
    icon: <UploadIcon sx={{ color: "#06b6d4" }} />,
    title: "User Requirements Routing",
    description: "Your specific requirements are passed to ALL 9 AI agents, ensuring every section addresses your focus areas.",
  },
  {
    icon: <AIIcon sx={{ color: "#a855f7" }} />,
    title: "10-Agent Parallel Architecture",
    description: "9 specialized agents + 1 synthesis agent run in parallel. Synthesis agent validates consistency and fills gaps.",
  },
];

// ============================================================================
// Main Component
// ============================================================================

const CombinedAnalysisGuidePage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);

  const pageContext = `Comprehensive guide to VRAgent's Combined Analysis feature:
- How to merge security scans, network reports, RE findings, and fuzzing sessions
- 10 parallel AI agents (9 specialized + 1 synthesis): Executive Summary, PoC Scripts, Attack Guides, Prioritized Vulns, Cross-Analysis, Attack Surface, Attack Chains, Exploit Development, Source Code Findings, and Synthesis Agent
- Cross-analysis correlates ALL 10 scan types: SAST, Network/PCAP, SSL/TLS, DNS, Traceroute, Reverse Engineering, API Fuzzing, Agentic Fuzzer, DAST, Binary Fuzzer
- Corroboration confidence scoring: findings from 2+ sources flagged HIGH CONFIDENCE, 3+ sources = very high confidence
- Smart token budget management: critical findings NEVER truncated, intelligent prioritization
- Source Code Findings agent generates secure code fixes and exploitation examples
- Supporting document upload (PDFs, docs) processed by AI
- User requirements passed to key agents for customized output
- Report sections: executive summary, prioritized vulnerabilities, PoC scripts, attack guides, cross-analysis, attack surface diagrams, attack chains, exploit development, source code findings
- AI chat assistant for interactive exploration
- Cross-source correlation linking code vulns to network exposure
- Synthesis agent validates consistency and fills gaps across all sections`;

  return (
    <LearnPageLayout pageTitle="Combined Analysis Guide" pageContext={pageContext}>
      <Box sx={{ p: 3, maxWidth: 1200, mx: "auto" }}>
        {/* Back Link */}
        <Box sx={{ mb: 3 }}>
          <Chip
            component={Link}
            to="/learn"
            icon={<BackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2 }}
          />
        </Box>

        {/* Header */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Box
            sx={{
              p: 2,
              borderRadius: 3,
              background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.2)} 0%, ${alpha("#6366f1", 0.2)} 100%)`,
            }}
          >
            <AnalyticsIcon sx={{ fontSize: 48, color: "#8b5cf6" }} />
          </Box>
          <Box>
            <Typography variant="h4" fontWeight={700}>
              Combined Analysis
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Merge multiple data sources into one AI-powered comprehensive security report
            </Typography>
          </Box>
        </Box>

        {/* What It Does */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Typography variant="h6" fontWeight={600} gutterBottom>
            What is Combined Analysis?
          </Typography>
          <Typography variant="body1" color="text.secondary" paragraph>
            Combined Analysis aggregates findings from <strong>10 different scan types</strong>—SAST, Network/PCAP, 
            SSL/TLS, DNS, Traceroute, Reverse Engineering, API Fuzzing, Agentic Fuzzer, DAST, and Binary Fuzzer—and 
            uses <strong>10 parallel AI agents</strong> powered by Google Gemini to correlate them into a single 
            comprehensive report. Instead of reviewing each scan separately, you get cross-referenced attack paths, 
            working PoC scripts, and step-by-step exploitation guides with beginner-friendly troubleshooting.
          </Typography>
          <Alert severity="info" sx={{ borderRadius: 2, mb: 2 }}>
            <strong>Multi-Agent Architecture:</strong> Combined Analysis runs 10 specialized AI agents in parallel—Executive 
            Summary, PoC Scripts, Attack Guides, Prioritized Vulns, Cross-Analysis (10 sources), Attack Surface, Attack 
            Chains, Exploit Development, Source Code Findings, and a <strong>Synthesis Agent</strong> that validates 
            consistency and fills gaps.
          </Alert>
          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <strong>Corroboration = Confidence:</strong> Findings detected by 2+ independent scan sources are automatically 
            flagged as <strong>HIGH CONFIDENCE</strong>. Multi-source validation means these vulnerabilities are highly 
            likely to be real and exploitable, prioritized above single-source findings.
          </Alert>
        </Paper>

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
            <Tab icon={<MergeIcon />} label="Data Sources" iconPosition="start" />
            <Tab icon={<TimelineIcon />} label="Workflow" iconPosition="start" />
            <Tab icon={<AssessmentIcon />} label="Report Sections" iconPosition="start" />
          </Tabs>
        </Paper>

        {/* Tab 0: Data Sources */}
        {activeTab === 0 && (
          <>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
              What Can You Combine?
            </Typography>
            <Grid container spacing={2} sx={{ mb: 4 }}>
              {SCAN_SOURCES.map((source, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Card sx={{ height: "100%", borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
                    <CardContent>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                        {source.icon}
                        <Typography variant="subtitle1" fontWeight={600}>
                          {source.title}
                        </Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {source.description}
                      </Typography>
                      {source.details && (
                        <>
                          <Divider sx={{ my: 1.5 }} />
                          <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>Includes:</Typography>
                          {source.details.map((detail, i) => (
                            <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                              <CheckIcon sx={{ fontSize: 14, color: "success.main", mt: 0.3 }} />
                              <Typography variant="body2">{detail}</Typography>
                            </Box>
                          ))}
                        </>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </>
        )}

        {/* Tab 1: Workflow */}
        {activeTab === 1 && (
          <>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
              4-Step Generation Workflow
            </Typography>
            {WORKFLOW_STEPS.map((step) => (
              <Paper key={step.step} sx={{ p: 3, mb: 2, borderRadius: 3, borderLeft: `4px solid #8b5cf6` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 40,
                      height: 40,
                      borderRadius: "50%",
                      bgcolor: alpha("#8b5cf6", 0.15),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <Typography variant="h6" fontWeight={700} color="#8b5cf6">
                      {step.step}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" fontWeight={600}>
                      {step.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {step.description}
                    </Typography>
                  </Box>
                </Box>
                <Box sx={{ pl: 7 }}>
                  {step.details.map((detail, i) => (
                    <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                      <CheckIcon sx={{ fontSize: 14, color: "#8b5cf6", mt: 0.3 }} />
                      <Typography variant="body2">{detail}</Typography>
                    </Box>
                  ))}
                </Box>
              </Paper>
            ))}
          </>
        )}

        {/* Tab 2: Report Sections */}
        {activeTab === 2 && (
          <>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
              9 Report Sections Generated
            </Typography>
            <Grid container spacing={2} sx={{ mb: 4 }}>
              {REPORT_SECTIONS.map((section, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Accordion sx={{ borderRadius: "12px !important", border: `1px solid ${alpha(section.color, 0.2)}`, "&:before": { display: "none" } }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ borderLeft: `4px solid ${section.color}` }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                        <Box sx={{ color: section.color }}>{section.icon}</Box>
                        <Box>
                          <Typography variant="subtitle2" fontWeight={600}>{section.title}</Typography>
                          <Typography variant="caption" color="text.secondary">{section.description}</Typography>
                        </Box>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      {section.contents.map((content, i) => (
                        <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                          <CheckIcon sx={{ fontSize: 14, color: section.color, mt: 0.3 }} />
                          <Typography variant="body2">{content}</Typography>
                        </Box>
                      ))}
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              ))}
            </Grid>
          </>
        )}

        {/* Key Features */}
        <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
          Key Features
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {KEY_FEATURES.map((feature, idx) => (
            <Grid item xs={12} sm={6} key={idx}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 2,
                  bgcolor: alpha(theme.palette.background.paper, 0.5),
                  height: "100%",
                }}
              >
                <Box sx={{ p: 1, borderRadius: 2, bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                  {feature.icon}
                </Box>
                <Box>
                  <Typography variant="subtitle2" fontWeight={600}>
                    {feature.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {feature.description}
                  </Typography>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Export Options */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <DownloadIcon sx={{ color: "primary.main" }} />
            <Typography variant="h6" fontWeight={600}>Export Options</Typography>
          </Box>
          <Grid container spacing={2}>
            {[
              { format: "PDF", desc: "Full formatted report with diagrams" },
              { format: "Word (DOCX)", desc: "Editable document for customization" },
              { format: "Markdown", desc: "Plain text for documentation systems" },
              { format: "JSON", desc: "Structured data for integration" },
            ].map((exp, i) => (
              <Grid item xs={6} md={3} key={i}>
                <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha(theme.palette.primary.main, 0.05), textAlign: "center" }}>
                  <Typography variant="subtitle2" fontWeight={600}>{exp.format}</Typography>
                  <Typography variant="caption" color="text.secondary">{exp.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Quick Tips */}
        <Alert severity="success" sx={{ borderRadius: 2, mb: 4 }}>
          <Typography variant="subtitle2" fontWeight={600} gutterBottom>
            💡 Tips for Better Results
          </Typography>
          <Typography variant="body2">
            • <strong>Include 3+ scan types</strong> for HIGH CONFIDENCE corroboration (findings from multiple sources)<br />
            • <strong>Add project context</strong> (tech stack, deployment) for relevant attack scenarios<br />
            • <strong>Upload threat models</strong> or architecture docs as supporting documents<br />
            • <strong>Enable all options</strong> (exploits, attack surface, prioritization) for comprehensive reports<br />
            • <strong>Use the AI chat</strong> to drill down into findings or request additional PoCs<br />
            • <strong>Check corroboration tags</strong> in prioritized findings—multi-source = higher confidence
          </Typography>
        </Alert>

        {/* Bottom Navigation */}
        <Box sx={{ textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<BackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default CombinedAnalysisGuidePage;
