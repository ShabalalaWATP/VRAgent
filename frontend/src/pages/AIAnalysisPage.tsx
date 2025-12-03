import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  IconButton,
  Tabs,
  Tab,
  Chip,
  Divider,
  Alert,
  Grid,
  Card,
  CardContent,
} from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import LinkIcon from "@mui/icons-material/Link";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";

interface AIFeature {
  id: string;
  title: string;
  icon: React.ReactNode;
  description: string;
  prompt: string;
  exampleOutput: string;
  outputFormat: string;
  color: string;
}

const aiFeatures: AIFeature[] = [
  {
    id: "security_summary",
    title: "Security Summary",
    icon: <SecurityIcon />,
    description:
      "Generates an executive-level summary of all security findings, highlighting the most critical issues and overall risk posture. Perfect for presenting to stakeholders.",
    prompt: `You are a senior red team security consultant writing a security assessment to help the blue team understand vulnerabilities from an attacker's perspective. Analyze these findings and provide:

1. **Executive Summary** - 2-3 sentences on overall security posture
2. **Critical Issues** - Top 3-5 most dangerous findings an attacker would target first
3. **Attack Surface Analysis** - Key entry points and exposed functionality  
4. **Risk Assessment** - Overall risk level (Critical/High/Medium/Low) with justification
5. **Quick Wins** - Immediate actions that would reduce attack surface

Focus on what an attacker would exploit first. Be specific about impact.

FINDINGS DATA:
{findings_json}`,
    exampleOutput: `## Executive Summary
This application has **HIGH** security risk with 3 critical SQL injection vulnerabilities and exposed AWS credentials. An attacker could achieve full database access within minutes.

## Critical Issues (Attacker Priority)
1. **SQL Injection in /api/users** - Direct database access, trivial to exploit
2. **Hardcoded AWS Keys** - Full cloud infrastructure compromise
3. **Command Injection in file upload** - Remote code execution possible

## Attack Surface Analysis
- 12 API endpoints exposed, 4 with injectable parameters
- Authentication bypass possible via JWT none algorithm
- File upload accepts arbitrary extensions

## Risk Assessment: CRITICAL
Multiple chained vulnerabilities enable complete system takeover.

## Quick Wins
1. Parameterize SQL queries immediately
2. Rotate and remove hardcoded credentials
3. Implement input validation on all endpoints`,
    outputFormat: "Markdown with sections",
    color: "#3b82f6",
  },
  {
    id: "attack_vectors",
    title: "Attack Vectors",
    icon: <BugReportIcon />,
    description:
      "Identifies specific attack paths and techniques an attacker could use to exploit vulnerabilities. Includes exploitation complexity and required access levels.",
    prompt: `You are an offensive security expert analyzing vulnerabilities for attack potential. For these findings, identify:

1. **Primary Attack Vectors** - Most likely attack paths
2. **Exploitation Complexity** - How difficult to exploit (Trivial/Easy/Moderate/Hard)
3. **Required Access** - What attacker needs (None/Network/Authenticated/Local)
4. **Potential Impact** - What attacker achieves (RCE/Data Access/Privilege Escalation/DoS)
5. **Chaining Opportunities** - How vulnerabilities can be combined

Format as actionable attack paths. Be specific about techniques.

FINDINGS:
{findings_json}`,
    exampleOutput: `## Primary Attack Vectors

### Vector 1: SQL Injection → Data Exfiltration
- **Entry Point**: /api/search?q=
- **Technique**: Union-based SQL injection
- **Complexity**: Trivial (no WAF, error messages exposed)
- **Impact**: Full database dump, credential theft

### Vector 2: File Upload → RCE
- **Entry Point**: /upload endpoint
- **Technique**: Upload PHP webshell, bypass extension filter
- **Complexity**: Easy (known bypass techniques)
- **Impact**: Remote code execution as www-data

## Chaining Opportunity
SQLi (creds) → Admin Login → File Upload → RCE → Privilege Escalation`,
    outputFormat: "Attack path diagrams",
    color: "#ef4444",
  },
  {
    id: "exploit_scenarios",
    title: "Exploit Scenarios",
    icon: <AutoAwesomeIcon />,
    description:
      "Creates detailed, step-by-step exploit scenarios showing how an attacker would compromise the system. Educational for defenders to understand attacker methodology.",
    prompt: `You are a penetration tester creating detailed exploit scenarios. For each critical/high vulnerability, create a scenario with:

1. **Title** - Descriptive attack name
2. **Narrative** - Story of how attack unfolds
3. **Preconditions** - What attacker needs before starting
4. **Step-by-Step Exploitation**:
   - Reconnaissance steps
   - Exploit preparation
   - Execution steps
   - Post-exploitation
5. **Proof of Concept Outline** - Pseudocode or command structure
6. **Impact Assessment** - What attacker gains

Make it educational for defenders to understand attacker methodology.

VULNERABILITY:
{finding_json}`,
    exampleOutput: `# Exploit Scenario: Database Takeover via SQL Injection

## Narrative
An external attacker discovers the search functionality accepts unsanitized input. Using automated tools, they extract the entire user database including password hashes.

## Preconditions
- Network access to application
- Basic SQL injection knowledge
- SQLMap or similar tool

## Step-by-Step Exploitation

### 1. Reconnaissance
\`\`\`
curl "https://target.com/api/search?q=test'"
# Error reveals: MySQL syntax error
\`\`\`

### 2. Enumerate Database
\`\`\`
sqlmap -u "https://target.com/api/search?q=test" --tables
# Found: users, sessions, payments
\`\`\`

### 3. Extract Data
\`\`\`
sqlmap -u "..." -T users --dump
# Retrieved: 5000 user records with bcrypt hashes
\`\`\`

## Impact
- Complete database compromise
- User credential theft
- Regulatory violations (GDPR, PCI-DSS)`,
    outputFormat: "Detailed scenario with code",
    color: "#8b5cf6",
  },
  {
    id: "false_positives",
    title: "False Positive Analysis",
    icon: <VisibilityOffIcon />,
    description:
      "Analyzes findings to identify likely false positives based on code context, helping you focus on real issues and save remediation time.",
    prompt: `You are a security analyst reviewing scan results for false positives. Analyze each finding and assess:

1. **Likely False Positive** - Is this probably not a real issue?
2. **Confidence** - How confident (High/Medium/Low)
3. **Reasoning** - Why you think it's false positive or real
4. **Verification Steps** - How to confirm either way

Consider:
- Context of the code (test files, comments, dead code)
- Common false positive patterns for this vulnerability type
- Framework protections that might mitigate the issue

FINDINGS:
{findings_json}`,
    exampleOutput: `## False Positive Analysis

### Finding: SQL Injection in test_database.py
- **Assessment**: LIKELY FALSE POSITIVE
- **Confidence**: High
- **Reasoning**: File is in /tests/ directory, query is for test fixtures only
- **Verification**: Confirm file is excluded from production build

### Finding: Hardcoded Password in config.example.py
- **Assessment**: LIKELY FALSE POSITIVE  
- **Confidence**: High
- **Reasoning**: ".example" files are templates, real config uses env vars
- **Verification**: Check .gitignore includes actual config files

### Finding: XSS in UserProfile component
- **Assessment**: REAL ISSUE
- **Confidence**: Medium
- **Reasoning**: dangerouslySetInnerHTML used with user-controlled bio field
- **Verification**: Test with XSS payload in bio field`,
    outputFormat: "Analysis per finding",
    color: "#f59e0b",
  },
  {
    id: "attack_chains",
    title: "Attack Chain Mapping",
    icon: <LinkIcon />,
    description:
      "Identifies how multiple vulnerabilities can be chained together for maximum impact. Maps to the Cyber Kill Chain and shows combined exploitation paths.",
    prompt: `You are an advanced threat analyst mapping attack chains. Analyze how these vulnerabilities could be combined:

Create attack chains showing:
1. **Chain Name** - Descriptive title
2. **Kill Chain Stage Mapping** - Where each vuln fits in Lockheed Martin kill chain
3. **Step Sequence** - Order of exploitation
4. **Combined Impact** - What's achieved by chaining
5. **Likelihood** - How likely an attacker would use this chain

Look for:
- Initial access + privilege escalation combinations
- Data access + exfiltration paths  
- Persistence + lateral movement options

VULNERABILITIES:
{findings_json}`,
    exampleOutput: `## Attack Chain: External to Domain Admin

### Chain Overview
Combines 4 vulnerabilities for complete infrastructure compromise

### Kill Chain Mapping
| Stage | Vulnerability Used |
|-------|-------------------|
| Delivery | SQL Injection (initial access) |
| Exploitation | Credential theft from DB |
| Installation | File upload for webshell |
| C2 | Reverse shell from webshell |
| Actions | Lateral movement with stolen creds |

### Step Sequence
1. **SQLi** → Extract admin password hash
2. **Crack hash** → Gain admin portal access  
3. **File upload** → Deploy webshell
4. **Pivot** → Use stolen creds on internal systems

### Combined Impact
- Initial: Web application access
- Final: Complete domain compromise
- Data at risk: All systems, all data

### Likelihood: HIGH
All vulns are easily exploitable with public tools`,
    outputFormat: "Chain diagram and steps",
    color: "#10b981",
  },
];

export default function AIAnalysisPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [selectedTab, setSelectedTab] = useState(0);
  const [copiedPrompt, setCopiedPrompt] = useState(false);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPrompt(true);
    setTimeout(() => setCopiedPrompt(false), 2000);
  };

  const selectedFeature = aiFeatures[selectedTab];

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
            background: `linear-gradient(135deg, #8b5cf6, #ec4899)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          🧠 AI Analysis Explained
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 800 }}>
          Discover how VRAgent uses Google Gemini AI to transform raw vulnerability data into actionable security intelligence.
        </Typography>
      </Box>

      {/* Overview */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.05)}, ${alpha("#ec4899", 0.05)})` }}>
        <Grid container spacing={4}>
          <Grid item xs={12} md={8}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
              How AI Enhances Security Analysis
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3, lineHeight: 1.8 }}>
              After traditional scanners identify vulnerabilities, VRAgent sends the findings to <strong>Google Gemini 2.0 Flash</strong> for advanced analysis. The AI provides context that automated scanners can't - understanding how vulnerabilities relate to each other, identifying likely false positives, and creating realistic attack scenarios from an attacker's perspective.
            </Typography>

            <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>🔒 Privacy Note:</strong> Only vulnerability metadata is sent to the AI - not your actual source code. The AI sees finding types, severities, file paths, and descriptions, but never the code itself.
              </Typography>
            </Alert>

            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="Google Gemini 2.0 Flash" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6", fontWeight: 600 }} />
              <Chip label="5 Analysis Types" variant="outlined" />
              <Chip label="Red Team Perspective" variant="outlined" />
              <Chip label="Attack Chain Mapping" variant="outlined" />
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5), p: 3, borderRadius: 2, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>AI Analysis Flow</Typography>
              {[
                { icon: "🔍", label: "Scanners find vulnerabilities" },
                { icon: "📋", label: "Findings aggregated & normalized" },
                { icon: "🧠", label: "Sent to Gemini AI" },
                { icon: "✨", label: "AI generates insights" },
                { icon: "📊", label: "Added to security report" },
              ].map((step, i) => (
                <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1.5 }}>
                  <Typography variant="h6">{step.icon}</Typography>
                  <Typography variant="body2">{step.label}</Typography>
                </Box>
              ))}
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Feature Cards Overview */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        🎯 5 AI Analysis Capabilities
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {aiFeatures.map((feature, index) => (
          <Grid item xs={12} sm={6} md={2.4} key={feature.id}>
            <Card
              onClick={() => setSelectedTab(index)}
              sx={{
                cursor: "pointer",
                height: "100%",
                border: `2px solid ${selectedTab === index ? feature.color : "transparent"}`,
                bgcolor: selectedTab === index ? alpha(feature.color, 0.05) : "background.paper",
                transition: "all 0.2s",
                "&:hover": { bgcolor: alpha(feature.color, 0.05), transform: "translateY(-2px)" },
              }}
            >
              <CardContent sx={{ textAlign: "center", py: 3 }}>
                <Box sx={{ color: feature.color, mb: 1 }}>{feature.icon}</Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  {feature.title}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Feature Detail */}
      <Paper sx={{ mb: 4, borderRadius: 3, overflow: "hidden" }}>
        <Box sx={{ p: 4, bgcolor: alpha(selectedFeature.color, 0.05), borderBottom: `3px solid ${selectedFeature.color}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(selectedFeature.color, 0.1), color: selectedFeature.color }}>
              {selectedFeature.icon}
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                {selectedFeature.title}
              </Typography>
              <Chip label={selectedFeature.outputFormat} size="small" sx={{ mt: 0.5, bgcolor: alpha(selectedFeature.color, 0.1), color: selectedFeature.color }} />
            </Box>
          </Box>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.7 }}>
            {selectedFeature.description}
          </Typography>
        </Box>

        <Box sx={{ p: 4 }}>
          <Grid container spacing={4}>
            {/* Prompt Section */}
            <Grid item xs={12} lg={6}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  📝 Prompt Sent to AI
                </Typography>
                <IconButton
                  size="small"
                  onClick={() => copyToClipboard(selectedFeature.prompt)}
                  sx={{ bgcolor: alpha(selectedFeature.color, 0.1), "&:hover": { bgcolor: alpha(selectedFeature.color, 0.2) } }}
                >
                  {copiedPrompt ? <CheckIcon fontSize="small" sx={{ color: "success.main" }} /> : <ContentCopyIcon fontSize="small" />}
                </IconButton>
              </Box>
              <Box
                sx={{
                  p: 3,
                  borderRadius: 2,
                  bgcolor: alpha(theme.palette.background.default, 0.5),
                  border: `1px solid ${alpha(selectedFeature.color, 0.2)}`,
                  fontFamily: "monospace",
                  fontSize: "0.8rem",
                  whiteSpace: "pre-wrap",
                  overflow: "auto",
                  maxHeight: 450,
                  lineHeight: 1.6,
                }}
              >
                {selectedFeature.prompt}
              </Box>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                <strong>Note:</strong> {"{findings_json}"} is replaced with actual vulnerability data at runtime
              </Typography>
            </Grid>

            {/* Example Output Section */}
            <Grid item xs={12} lg={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                📤 Example AI Response
              </Typography>
              <Box
                sx={{
                  p: 3,
                  borderRadius: 2,
                  bgcolor: alpha("#10b981", 0.03),
                  border: `1px solid ${alpha("#10b981", 0.2)}`,
                  fontFamily: "monospace",
                  fontSize: "0.8rem",
                  whiteSpace: "pre-wrap",
                  overflow: "auto",
                  maxHeight: 450,
                  lineHeight: 1.6,
                }}
              >
                {selectedFeature.exampleOutput}
              </Box>
            </Grid>
          </Grid>
        </Box>
      </Paper>

      {/* Best Practices */}
      <Paper sx={{ p: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          💡 Getting the Most from AI Analysis
        </Typography>
        <Grid container spacing={3}>
          {[
            { title: "Review Executive Summaries", desc: "Start with the AI-generated summary to quickly understand overall risk posture before diving into individual findings.", color: "#3b82f6" },
            { title: "Validate Attack Chains", desc: "AI-identified attack chains show how vulnerabilities combine. Prioritize fixes that break multiple chains.", color: "#ef4444" },
            { title: "Check False Positives", desc: "Review AI's false positive assessments before spending time on remediation. Verify with manual testing.", color: "#f59e0b" },
            { title: "Use Exploit Scenarios", desc: "Share exploit scenarios with developers to help them understand real-world impact and motivate fixes.", color: "#10b981" },
          ].map((tip) => (
            <Grid item xs={12} md={6} key={tip.title}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha(tip.color, 0.05), border: `1px solid ${alpha(tip.color, 0.15)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: tip.color, mb: 1 }}>
                  {tip.title}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {tip.desc}
                </Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
  );
}
