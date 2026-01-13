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
    title: "Security Scans",
    description: "SAST findings, vulnerabilities, CVEs, and secrets detection from code analysis.",
    details: [
      "All SAST scanner findings (Semgrep, Bandit, ESLint, etc.)",
      "CVE matches with CVSS, EPSS, and KEV data",
      "Attack chains and exploit scenarios",
      "AI-generated security summary",
      "False positive analysis results",
    ],
  },
  {
    icon: <NetworkIcon sx={{ color: "#0ea5e9" }} />,
    title: "Network Reports",
    description: "Nmap scans, PCAP analysis, SSL/TLS checks, DNS enumeration, and API testing results.",
    details: [
      "Nmap port scans with service detection",
      "PCAP packet captures with protocol analysis",
      "SSL/TLS certificate and cipher findings",
      "DNS enumeration and zone transfer results",
      "API endpoint testing results",
    ],
  },
  {
    icon: <MemoryIcon sx={{ color: "#a855f7" }} />,
    title: "Reverse Engineering",
    description: "Binary analysis, APK inspection, and Docker image security findings.",
    details: [
      "APK manifest, permissions, and certificate analysis",
      "Binary PE/ELF headers and strings extraction",
      "Docker layer inspection and secrets detection",
      "Decompiled code vulnerability findings",
      "Attack surface mapping",
    ],
  },
  {
    icon: <BugIcon sx={{ color: "#f97316" }} />,
    title: "Fuzzing Sessions",
    description: "Security fuzzer crashes, input validation issues, and edge case discoveries.",
    details: [
      "Crash reports with stack traces",
      "Input validation failures",
      "Edge case discoveries",
      "Response anomalies",
      "Timing and resource issues",
    ],
  },
];

const WORKFLOW_STEPS: WorkflowStep[] = [
  {
    step: 1,
    title: "Select Data Sources",
    description: "Choose which scans, reports, and sessions to include in your combined analysis.",
    icon: <CheckIcon />,
    details: [
      "Browse available security scans for your project",
      "Select network analysis reports (Nmap, PCAP, SSL, DNS)",
      "Include reverse engineering findings (APK, Binary, Docker)",
      "Add fuzzing session results for comprehensive coverage",
      "Mix and match sources from different time periods",
    ],
  },
  {
    step: 2,
    title: "Add Context & Documents",
    description: "Provide project info and upload supporting documents for deeper analysis.",
    icon: <DocumentIcon />,
    details: [
      "Enter project context: tech stack, architecture, deployment info",
      "Specify user requirements: compliance needs, priority areas",
      "Upload supporting documents (PDFs, Word docs, architecture diagrams)",
      "Documents are processed by AI for context (up to 125K chars each)",
      "Add threat models or security requirements for targeted analysis",
    ],
  },
  {
    step: 3,
    title: "Configure Options",
    description: "Enable advanced features for exploit recommendations and risk analysis.",
    icon: <AssessmentIcon />,
    details: [
      "Include Exploit Recommendations: Get actionable PoC scripts",
      "Include Attack Surface Map: Visual diagram of entry points",
      "Include Risk Prioritization: CVSS + EPSS + business context",
      "Enable Beginner Attack Guides: Step-by-step exploitation tutorials",
      "Configure output format and detail level",
    ],
  },
  {
    step: 4,
    title: "Generate Report",
    description: "9 parallel AI agents analyze all sources and produce a unified report.",
    icon: <AIIcon />,
    details: [
      "9 specialized AI agents run in parallel:",
      "→ Executive Summary Agent: Overall risk posture",
      "→ PoC Scripts Agent: Working exploit code",
      "→ Attack Guides Agent: Step-by-step tutorials",
      "→ Prioritized Vulns Agent: Risk-ranked findings",
      "→ Cross-Analysis Agent: Multi-source correlation (all 7 scan types)",
      "→ Attack Surface Agent: Mermaid diagram generation",
      "→ Attack Chains Agent: Kill chain mapping",
      "→ Exploit Dev Agent: Advanced exploitation areas",
      "→ Source Code Findings Agent: Deep code analysis with PoC fixes",
    ],
  },
];

const REPORT_SECTIONS: ReportSection[] = [
  {
    title: "Executive Summary",
    description: "High-level security posture overview for stakeholders",
    icon: <AssessmentIcon />,
    color: "#3b82f6",
    contents: [
      "Overall risk level (Critical/High/Medium/Low)",
      "Key findings summary with severity counts",
      "Top 3 priority issues requiring immediate attention",
      "Attack surface overview",
      "Recommendations for remediation priority",
    ],
  },
  {
    title: "Prioritized Vulnerabilities",
    description: "Risk-ranked findings with detailed exploitation steps",
    icon: <WarningIcon />,
    color: "#ef4444",
    contents: [
      "Vulnerabilities sorted by combined risk score",
      "CVSS, EPSS, and KEV status for each",
      "5+ detailed exploitation steps per vulnerability",
      "Required tools and techniques",
      "Expected impact and business risk",
    ],
  },
  {
    title: "Cross-Analysis Findings",
    description: "Vulnerabilities correlated across multiple scan sources",
    icon: <MergeIcon />,
    color: "#8b5cf6",
    contents: [
      "Findings that appear in multiple scan types",
      "Code vulnerabilities linked to network exposure",
      "Dependency CVEs matched with actual usage",
      "Binary/APK issues correlated with source code",
      "Correlation confidence scores",
    ],
  },
  {
    title: "PoC Scripts",
    description: "Working proof-of-concept exploit code",
    icon: <CodeIcon />,
    color: "#10b981",
    contents: [
      "30+ lines of working Python/Bash/curl code per script",
      "Pre-built payloads for common vulnerabilities",
      "Command-line examples ready to execute",
      "Tool recommendations (sqlmap, Burp, Nmap)",
      "Expected output and success indicators",
    ],
  },
  {
    title: "Attack Guides",
    description: "Step-by-step beginner-friendly exploitation tutorials",
    icon: <LightbulbIcon />,
    color: "#f59e0b",
    contents: [
      "7+ detailed steps per vulnerability",
      "Beginner-friendly explanations",
      "Screenshot placeholders and expected output",
      "Tool setup and configuration",
      "Common pitfalls and troubleshooting",
    ],
  },
  {
    title: "Attack Surface Diagram",
    description: "Visual Mermaid diagram of entry points and attack paths",
    icon: <TimelineIcon />,
    color: "#06b6d4",
    contents: [
      "Mermaid flowchart of attack vectors",
      "Entry points mapped to vulnerabilities",
      "Data flow from input to impact",
      "Network topology with exposed services",
      "Interactive diagram in report viewer",
    ],
  },
  {
    title: "Attack Chains",
    description: "Multi-step exploitation paths combining findings",
    icon: <LinkIcon />,
    color: "#ec4899",
    contents: [
      "Kill chain mapping (Initial Access → Impact)",
      "Chained vulnerabilities for maximum impact",
      "Prerequisite and dependency analysis",
      "Time-to-exploit estimates",
      "Detection and mitigation checkpoints",
    ],
  },
  {
    title: "Exploit Development Areas",
    description: "Advanced areas for custom exploit development",
    icon: <PsychologyIcon />,
    color: "#a855f7",
    contents: [
      "Memory corruption opportunities",
      "Logic flaws suitable for custom exploits",
      "Race conditions and timing attacks",
      "Cryptographic weaknesses",
      "Recommended research areas",
    ],
  },
  {
    title: "Source Code Findings",
    description: "Deep analysis of source code with secure code fixes",
    icon: <CodeIcon />,
    color: "#22c55e",
    contents: [
      "Vulnerability identification with file path and line numbers",
      "Complete exploitation examples showing attack vectors",
      "Secure code fix showing corrected implementation",
      "Correlation with scan findings (SAST, network, fuzzing)",
      "Detailed remediation steps for each issue",
    ],
  },
];

const KEY_FEATURES: FeatureItem[] = [
  {
    icon: <MergeIcon sx={{ color: "#8b5cf6" }} />,
    title: "Cross-Source Correlation",
    description: "AI correlates findings from ALL 7 scan types: Security, Network, SSL, DNS, Traceroute, RE, and Fuzzing into unified attack paths.",
  },
  {
    icon: <LightbulbIcon sx={{ color: "#f59e0b" }} />,
    title: "Attack Scenario Generation",
    description: "Generates realistic attack chains combining multiple findings into exploitable paths with step-by-step guides.",
  },
  {
    icon: <AssessmentIcon sx={{ color: "#10b981" }} />,
    title: "Risk Prioritization",
    description: "Ranks findings by real-world impact using CVSS, EPSS, KEV status, and business context—not just severity.",
  },
  {
    icon: <ChatIcon sx={{ color: "#ec4899" }} />,
    title: "AI Chat Assistant",
    description: "Ask questions about the report, request clarifications, explore alternative exploitation methods, or generate additional PoCs.",
  },
  {
    icon: <CodeIcon sx={{ color: "#3b82f6" }} />,
    title: "Source Code Deep Dive",
    description: "AI analyzes your codebase and generates secure code fixes with exploitation examples for each vulnerability found.",
  },
  {
    icon: <UploadIcon sx={{ color: "#06b6d4" }} />,
    title: "User Requirements Integration",
    description: "Provide custom requirements that are passed to key AI agents, tailoring the analysis to your specific needs.",
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
- 9 parallel AI agents: Executive Summary, PoC Scripts, Attack Guides, Prioritized Vulns, Cross-Analysis, Attack Surface, Attack Chains, Exploit Development, Source Code Findings
- Cross-analysis correlates ALL 7 scan types: Security, Network, SSL, DNS, Traceroute, RE, Fuzzing
- Source Code Findings agent generates secure code fixes and exploitation examples
- Supporting document upload (PDFs, docs) processed by AI
- User requirements passed to key agents for customized output
- Report sections: prioritized vulnerabilities, PoC scripts, attack guides, attack surface diagrams, source code findings
- AI chat assistant for interactive exploration
- Cross-source correlation linking code vulns to network exposure`;

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
            Combined Analysis aggregates findings from multiple VRAgent tools—security scans, network analysis, 
            reverse engineering, and fuzzing—and uses <strong>8 parallel AI agents</strong> powered by Google Gemini 
            to correlate them into a single comprehensive report. Instead of reviewing each scan separately, 
            you get cross-referenced attack paths, working PoC scripts, and step-by-step exploitation guides.
          </Typography>
          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <strong>Multi-Agent Architecture:</strong> Combined Analysis runs 8 specialized AI agents in parallel—Executive Summary, 
            PoC Scripts, Attack Guides, Prioritized Vulns, Cross-Analysis, Attack Surface, Attack Chains, and Exploit Development—ensuring 
            comprehensive coverage and faster generation.
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
              8 Report Sections Generated
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
            • <strong>Include 2-3+ scan types</strong> for meaningful cross-correlation<br />
            • <strong>Add project context</strong> (tech stack, deployment) for relevant attack scenarios<br />
            • <strong>Upload threat models</strong> or architecture docs as supporting documents<br />
            • <strong>Enable all options</strong> (exploits, attack surface, prioritization) for comprehensive reports<br />
            • <strong>Use the AI chat</strong> to drill down into findings or request additional PoCs
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
