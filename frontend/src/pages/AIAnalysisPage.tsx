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
    id: "false_positives",
    title: "False Positive Detection",
    icon: <VisibilityOffIcon />,
    description:
      "VRAgent uses a two-stage approach: fast heuristic pattern matching first, then LLM analysis for complex cases. This reduces noise without expensive API calls for obvious cases.",
    prompt: `# Stage 1: Heuristic Patterns (runs first, no LLM needed)

FALSE_POSITIVE_PATTERNS = [
    # Test files - often contain intentional vulnerabilities for testing
    r"test_.*\\.py$", r".*_test\\.py$", r".*\\.test\\.(js|ts)$",
    r"__tests__/", r"spec/", r"tests/",
    
    # Mock/stub code - not production code
    r"mock", r"stub", r"fake", r"fixture",
    
    # Suppression comments - developer acknowledged and accepted
    r"# nosec", r"// NOSONAR", r"# pragma: no cover",
    r"@SuppressWarnings", r"eslint-disable",
    
    # Example/template code
    r"example", r"sample", r"demo", r"template",
]

# Stage 2: LLM Analysis (only for non-obvious findings)
# Limited to MAX_FINDINGS_FOR_LLM = 50 most critical findings`,
    exampleOutput: `## False Positive Analysis Results

### Heuristic Detections (Instant, No LLM):
| Finding | Pattern Matched | Status |
|---------|-----------------|--------|
| SQLi in test_db.py | test_.*\\.py$ | ✅ Likely FP |
| XSS in mock_handler.ts | mock pattern | ✅ Likely FP |
| Hardcoded key in example.py | example pattern | ✅ Likely FP |

### LLM-Analyzed (Complex Cases):
| Finding | Analysis | Confidence |
|---------|----------|------------|
| eval() in parser.py | Real issue - user input flows to eval | HIGH |
| SQL in admin_query.py | POSSIBLE FP - parameterized query used | MEDIUM |

### Summary:
- 12 findings auto-filtered by heuristics
- 8 findings sent to LLM for analysis
- 3 confirmed false positives, 5 real issues`,
    outputFormat: "Heuristic + LLM hybrid",
    color: "#f59e0b",
  },
  {
    id: "severity_adjustment",
    title: "Severity Adjustment",
    icon: <SecurityIcon />,
    description:
      "Context-aware severity adjustment based on code patterns. Findings in admin-only code, behind auth checks, or internal endpoints are automatically deprioritized.",
    prompt: `# Severity Reduction Patterns in ai_analysis_service.py

SEVERITY_REDUCTION_PATTERNS = [
    # Authentication/authorization checks present
    r"@login_required", r"@authenticated", r"isAuthenticated",
    r"requireAuth", r"checkPermission", r"hasRole",
    
    # Admin-only functionality
    r"@admin_only", r"@staff_required", r"role.*admin",
    r"is_superuser", r"isAdmin",
    
    # Internal/private endpoints
    r"internal", r"private", r"localhost",
    r"127\\.0\\.0\\.1", r"0\\.0\\.0\\.0",
    
    # Debug/development only
    r"DEBUG", r"development", r"if.*debug",
]

# Severity escalation for:
# - CISA KEV (Known Exploited Vulnerabilities) → always HIGH+
# - EPSS > 0.7 (70%+ exploitation probability) → escalate to HIGH`,
    exampleOutput: `## Severity Adjustments Applied

### Downgraded Findings:
| Finding | Original | Adjusted | Reason |
|---------|----------|----------|--------|
| SQLi in admin_panel.py | HIGH | MEDIUM | @admin_only decorator |
| XSS in debug_view.js | HIGH | LOW | DEBUG mode check |
| SSRF in internal_api.py | HIGH | MEDIUM | localhost only |

### Escalated Findings:
| Finding | Original | Adjusted | Reason |
|---------|----------|----------|--------|
| CVE-2024-1234 | MEDIUM | HIGH | In CISA KEV catalog |
| CVE-2023-5678 | MEDIUM | HIGH | EPSS 0.89 (89% likely) |

### Net Effect:
- 5 findings downgraded (better context)
- 2 findings escalated (real-world threat)`,
    outputFormat: "Pattern-based adjustment",
    color: "#3b82f6",
  },
  {
    id: "attack_chains",
    title: "Attack Chain Discovery",
    icon: <LinkIcon />,
    description:
      "Combines related findings into exploitable attack chains. Uses heuristic grouping first, then LLM for narrative generation.",
    prompt: `# Attack Chain Heuristics in ai_analysis_service.py

ATTACK_CHAIN_PATTERNS = {
    "auth_bypass_to_rce": {
        "entry": ["auth_bypass", "broken_auth", "jwt_none"],
        "middle": ["privilege_escalation", "idor"],
        "exit": ["command_injection", "code_execution", "rce"]
    },
    "sqli_to_data_breach": {
        "entry": ["sql_injection"],
        "exit": ["sensitive_data", "pii_exposure", "credential_theft"]
    },
    "ssrf_to_cloud_compromise": {
        "entry": ["ssrf"],
        "middle": ["metadata_access"],
        "exit": ["cloud_credentials", "iam_escalation"]
    },
    "file_upload_to_rce": {
        "entry": ["unrestricted_upload", "file_upload"],
        "exit": ["webshell", "rce", "code_execution"]
    }
}

# LLM generates narrative only after heuristics identify chains`,
    exampleOutput: `## Attack Chains Discovered

### Chain 1: Authentication Bypass → RCE (CRITICAL)
**Kill Chain Stages:** Initial Access → Execution

1. **JWT None Algorithm** (auth_routes.py:45)
   - Allows forging admin tokens without signature
   
2. **Admin File Upload** (admin_api.py:120)
   - Admin endpoint accepts arbitrary file types
   
3. **Command Injection** (processor.py:88)
   - Uploaded files processed with shell commands

**Combined Impact:** Unauthenticated RCE
**Exploitation Complexity:** LOW (public tools available)

---

### Chain 2: SSRF → Cloud Takeover (HIGH)
1. SSRF in webhook handler → 2. AWS metadata access → 3. IAM credential theft

**Combined Impact:** Full AWS account compromise`,
    outputFormat: "Chain diagram + narrative",
    color: "#10b981",
  },
  {
    id: "exploit_scenarios",
    title: "Exploit Scenarios",
    icon: <AutoAwesomeIcon />,
    description:
      "Pre-built exploit templates for 16+ vulnerability types provide instant scenarios. LLM only called for novel or complex vulnerabilities.",
    prompt: `# Exploit Templates in exploit_service.py (partial list)

EXPLOIT_TEMPLATES = {
    "sql_injection": {
        "title": "Database Takeover via SQL Injection",
        "steps": [
            "1. Identify injectable parameter",
            "2. Determine database type via error messages",
            "3. Extract schema using UNION or blind techniques",
            "4. Dump sensitive tables (users, credentials)",
            "5. Escalate to OS command execution if xp_cmdshell/INTO OUTFILE"
        ],
        "tools": ["sqlmap", "Burp Suite"],
        "impact": "Data breach, credential theft, potential RCE"
    },
    "command_injection": { ... },
    "xss_reflected": { ... },
    "xss_stored": { ... },
    "path_traversal": { ... },
    "ssrf": { ... },
    "xxe": { ... },
    "deserialization": { ... },
    "weak_crypto_md5": { ... },
    "weak_crypto_sha1": { ... },
    "hardcoded_secret": { ... },
    "prototype_pollution": { ... },
    "buffer_overflow": { ... },
    # ... 16+ templates total
}`,
    exampleOutput: `## Exploit Scenario: SQL Injection in Search API

### Template-Generated (Instant):
**Vulnerability:** SQL Injection in /api/search endpoint
**File:** src/api/search.py:42

### Attack Steps:
\`\`\`bash
# 1. Confirm injection
curl "https://target/api/search?q=test' OR '1'='1"

# 2. Enumerate with sqlmap
sqlmap -u "https://target/api/search?q=test" --dbs

# 3. Extract users table
sqlmap -u "..." -D app -T users --dump
\`\`\`

### Impact Assessment:
- **Confidentiality:** Complete database access
- **Integrity:** Data modification possible
- **Availability:** DROP TABLE possible

### Remediation:
\`\`\`python
# VULNERABLE
query = f"SELECT * FROM items WHERE name LIKE '%{search}%'"

# SECURE
query = "SELECT * FROM items WHERE name LIKE %s"
cursor.execute(query, (f"%{search}%",))
\`\`\``,
    outputFormat: "Template + custom PoC",
    color: "#8b5cf6",
  },
  {
    id: "security_summary",
    title: "Security Summary",
    icon: <BugReportIcon />,
    description:
      "AI-generated executive summary and application overview. Generated in background after scan completes for instant report loading.",
    prompt: `# Background Summary Generation (ai_analysis_service.py)

# Summaries generated asynchronously after scan completes
# Cached in database for instant export/viewing

async def generate_summaries_background(scan_run_id: int):
    """Generate AI summaries in background worker."""
    
    # 1. Application Overview - what does this code do?
    app_overview = await generate_app_overview(code_chunks)
    
    # 2. Security Summary - overall risk posture
    security_summary = await generate_security_summary(
        findings,
        vulnerabilities,
        attack_chains
    )
    
    # 3. Cache in database
    await save_summaries(scan_run_id, app_overview, security_summary)
    
    # Summaries ready for instant export/viewing`,
    exampleOutput: `## Application Overview (AI-Generated)

This appears to be a **Node.js e-commerce API** built with Express.js and PostgreSQL. Key components include:

- **Authentication:** JWT-based auth with refresh tokens
- **Payment Processing:** Stripe integration for payments
- **File Storage:** AWS S3 for product images
- **API Design:** RESTful endpoints under /api/v1

---

## Security Summary

### Risk Level: HIGH

**Critical Issues (Fix Immediately):**
1. SQL Injection in product search - direct database compromise
2. Hardcoded Stripe API key - financial data at risk

**High Priority:**
3. JWT secret in source code - authentication bypass possible
4. Missing rate limiting - DoS and brute force vulnerable

**Key Statistics:**
- 23 total findings (3 Critical, 8 High, 12 Medium)
- 45 dependencies with 7 known CVEs
- 2 attack chains identified`,
    outputFormat: "Cached summary",
    color: "#ef4444",
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
              VRAgent uses a <strong>hybrid approach</strong> combining fast heuristic pattern matching with <strong>Google Gemini 2.0 Flash</strong> for complex analysis. Heuristics handle obvious cases instantly (test files, mock code, suppression comments), while LLM analysis is reserved for the <strong>top 50 most critical findings</strong> to optimize cost and speed.
            </Typography>

            <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>🔒 Privacy Note:</strong> Only vulnerability metadata is sent to the AI - not your actual source code. The AI sees finding types, severities, file paths, and code snippets, but full source files stay on your server.
              </Typography>
            </Alert>

            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="Gemini 2.0 Flash" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6", fontWeight: 600 }} />
              <Chip label="Heuristics First" variant="outlined" />
              <Chip label="50 Finding Limit" variant="outlined" />
              <Chip label="16+ Exploit Templates" variant="outlined" />
              <Chip label="Background Generation" variant="outlined" />
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5), p: 3, borderRadius: 2, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>AI Analysis Flow</Typography>
              {[
                { icon: "🔍", label: "Scanners find vulnerabilities" },
                { icon: "⚡", label: "Heuristics filter obvious FPs" },
                { icon: "📊", label: "Top 50 findings selected" },
                { icon: "🧠", label: "Gemini analyzes complex cases" },
                { icon: "📝", label: "Templates generate exploits" },
                { icon: "💾", label: "Summaries cached for export" },
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
          💡 How VRAgent AI Analysis Works
        </Typography>
        <Grid container spacing={3}>
          {[
            { title: "Heuristics Run First", desc: "Pattern matching instantly filters test files, mock code, and suppressed findings - no LLM needed for obvious cases.", color: "#f59e0b" },
            { title: "LLM for Top 50 Only", desc: "Only the 50 most critical findings go to Gemini AI. This balances thoroughness with API cost and speed.", color: "#3b82f6" },
            { title: "16+ Exploit Templates", desc: "Pre-built templates for SQLi, XSS, RCE, and more provide instant exploit scenarios without waiting for LLM generation.", color: "#8b5cf6" },
            { title: "Background Summary Generation", desc: "AI summaries generate after scan completes and are cached in the database for instant report exports.", color: "#10b981" },
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
