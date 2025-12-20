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
import LearnPageLayout from "../components/LearnPageLayout";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import LinkIcon from "@mui/icons-material/Link";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import VerifiedIcon from "@mui/icons-material/Verified";

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
      "VRAgent uses a three-stage approach: heuristic patterns first, then Agentic AI corroboration, then LLM analysis for complex cases. Findings corroborated by the Agentic AI deep scan are highly likely to be real.",
    prompt: `# Stage 1: Heuristic Patterns (runs first, no LLM needed)

FALSE_POSITIVE_PATTERNS = [
    # Test files - often contain intentional vulnerabilities
    (r'test[_/]|_test\\.py|\\.test\\.[jt]sx?|spec\\.[jt]sx?', 'Test file'),
    
    # Mock/test code - not production code
    (r'mock|stub|fake|dummy', 'Mock/test code'),
    
    # Example/template code
    (r'example|sample|demo|tutorial', 'Example/demo code'),
    
    # Vendored/minified code
    (r'\\.min\\.js|vendor[/\\\\]|node_modules', 'Vendored/minified'),
    
    # Explicit suppressions
    (r'# nosec|// nosec|NOSONAR|@SuppressWarnings', 'Explicitly suppressed'),
]

# Stage 2: Agentic AI Corroboration
# Scanner findings are cross-referenced with Agentic AI deep scan:
# - If Agentic AI ALSO found it: FP score REDUCED (likely real)
# - If Agentic AI did NOT find it: FP score INCREASED (may be FP)

# Stage 3: LLM Analysis (only for top 50 priority findings)
# MAX_FINDINGS_FOR_LLM = 50`,
    exampleOutput: `## False Positive Analysis Results

### Heuristic Detections (Instant, No LLM):
| Finding | Pattern Matched | Status |
|---------|-----------------|--------|
| SQLi in test_db.py | test_.*\\.py$ | ✅ Likely FP |
| XSS in mock_handler.ts | mock pattern | ✅ Likely FP |
| Hardcoded key in example.py | example pattern | ✅ Likely FP |

### Agentic AI Corroboration:
| Finding | Corroborated? | FP Score Adjustment |
|---------|---------------|---------------------|
| SQLi in query.py | ⚠️ YES (95% conf) | -0.4 (likely real) |
| XSS in render.js | ⚡ NO | +0.15 (may be FP) |
| SSRF in api.py | ⚠️ YES (87% conf) | -0.35 (likely real) |

### LLM-Analyzed (Top 50 Complex Cases):
| Finding | Analysis | Confidence |
|---------|----------|------------|
| eval() in parser.py | Real issue - user input flows to eval | HIGH |
| SQL in admin_query.py | POSSIBLE FP - parameterized query used | MEDIUM |

### Summary:
- 12 findings auto-filtered by heuristics
- 8/20 scanner findings corroborated by Agentic AI
- 5 confirmed false positives, 15 real issues`,
    outputFormat: "Heuristic + Agentic + LLM",
    color: "#f59e0b",
  },
  {
    id: "severity_adjustment",
    title: "Severity Adjustment",
    icon: <SecurityIcon />,
    description:
      "Context-aware severity adjustment based on code patterns and real-world threat intelligence. Findings in admin-only code or behind auth are deprioritized, while CVEs in CISA KEV or with high EPSS scores are escalated.",
    prompt: `# Severity Reduction Patterns in ai_analysis_service.py

SEVERITY_REDUCTION_PATTERNS = [
    # Authentication/authorization checks present
    (r'@require[sd]?_?auth|@login_required|@authenticated', 
     'Requires authentication'),
    
    # Admin-only functionality
    (r'@admin[_]?only|@require[sd]?_?admin|is_superuser', 
     'Admin-only access'),
    
    # Internal/private endpoints
    (r'internal[_]?only|private[_]?api|localhost|127\\.0\\.0\\.1', 
     'Internal/private endpoint'),
    
    # Auth check present in code
    (r'if\\s+.*\\.is_authenticated|if\\s+request\\.user', 
     'Auth check present'),
]

# Pattern-based Analysis (instant, no LLM):
# - SQLi with parameterized queries → may be FP
# - ORM usage (SQLAlchemy, Django, Sequelize) → severity reduced
# - XSS with sanitization → severity reduced
# - Hardcoded secrets from env vars → severity reduced to LOW
# - Command injection with shlex.quote → severity reduced

# Severity escalation for real-world threats:
# - CISA KEV (Known Exploited Vulnerabilities) → always HIGH+
# - EPSS > 0.7 (70%+ exploitation probability) → escalate to HIGH`,
    exampleOutput: `## Severity Adjustments Applied

### Pattern-Based Adjustments (Instant):
| Finding | Original | Adjusted | Reason |
|---------|----------|----------|--------|
| SQLi in query.py | HIGH | MEDIUM | Uses ORM abstraction layer |
| Secret in config.py | HIGH | LOW | Loaded from env var at runtime |
| CMD injection | HIGH | MEDIUM | Uses shlex.quote escaping |

### Context-Based Reductions:
| Finding | Original | Adjusted | Reason |
|---------|----------|----------|--------|
| SQLi in admin_panel.py | HIGH | MEDIUM | @admin_only decorator |
| XSS in debug_view.js | HIGH | LOW | DEBUG mode check present |
| SSRF in internal_api.py | HIGH | MEDIUM | localhost only |

### Threat Intel Escalations:
| Finding | Original | Adjusted | Reason |
|---------|----------|----------|--------|
| CVE-2024-1234 | MEDIUM | HIGH | In CISA KEV catalog |
| CVE-2023-5678 | MEDIUM | HIGH | EPSS 0.89 (89% likely) |

### Net Effect:
- 5 findings downgraded (better context)
- 2 findings escalated (real-world threat)`,
    outputFormat: "Pattern + Threat Intel",
    color: "#3b82f6",
  },
  {
    id: "attack_chains",
    title: "Attack Chain Discovery",
    icon: <LinkIcon />,
    description:
      "Combines related findings into exploitable attack chains using heuristic pattern matching for 8+ known chain types, followed by LLM refinement for non-obvious combinations.",
    prompt: `# Attack Chain Heuristics in ai_analysis_service.py

# 8 Pre-defined Attack Chain Patterns:
chain_patterns = [
    {
        "requires": ["sqli"],
        "title": "SQL Injection to Data Exfiltration",
        "impact": "Complete database compromise, data breach",
        "likelihood": "high",
    },
    {
        "requires": ["sqli", "auth"],
        "title": "SQL Injection + Auth Bypass Chain",
        "impact": "Full authentication bypass, account takeover",
        "likelihood": "high",
    },
    {
        "requires": ["idor", "auth"],
        "title": "IDOR + Broken Auth to Account Takeover",
        "impact": "Unauthorized data access, manipulation",
        "likelihood": "medium",
    },
    {
        "requires": ["xss", "auth"],
        "title": "XSS to Session Hijacking",
        "impact": "Session hijacking, account takeover",
        "likelihood": "medium",
    },
    {
        "requires": ["ssrf"],
        "title": "SSRF to Internal Service Access",
        "impact": "Cloud credential theft, lateral movement",
        "likelihood": "high",
    },
    {
        "requires": ["secret"],
        "title": "Exposed Secrets to System Compromise",
        "impact": "Direct system access, service abuse",
        "likelihood": "high",
    },
    {
        "requires": ["command_injection"],
        "title": "Command Injection to RCE",
        "impact": "Full server compromise, lateral movement",
        "likelihood": "critical",
    },
    {
        "requires": ["path_traversal"],
        "title": "Path Traversal to Sensitive File Access",
        "impact": "Credential theft, source code leak",
        "likelihood": "medium",
    },
]

# LLM refines chains and discovers non-obvious combinations`,
    exampleOutput: `## Attack Chains Discovered

### Chain 1: SQL Injection + Auth Bypass (CRITICAL)
**Kill Chain Stages:** Initial Access → Privilege Escalation

1. **SQL Injection** (queries.py:45)
   - Raw SQL with user input in search endpoint
   
2. **Broken Authentication** (auth.py:120)
   - Weak password validation, no rate limiting

**Combined Impact:** Full authentication bypass, account takeover
**Likelihood:** HIGH

---

### Chain 2: SSRF to Cloud Takeover (HIGH)
1. SSRF in webhook handler → 2. AWS metadata access → 3. IAM credential theft

**Combined Impact:** Full AWS account compromise
**Likelihood:** HIGH

---

### Chain 3: Exposed Secrets → System Compromise (HIGH)
1. Hardcoded AWS keys → 2. S3 bucket access → 3. Data exfiltration

**Combined Impact:** Direct system access, data breach
**Likelihood:** HIGH`,
    outputFormat: "Heuristic + LLM refinement",
    color: "#10b981",
  },
  {
    id: "agentic_corroboration",
    title: "Agentic Corroboration",
    icon: <VerifiedIcon />,
    description:
      "Cross-references traditional SAST scanner findings with the Agentic AI deep scan. Findings confirmed by both methods are highly likely to be real vulnerabilities, while uncorroborated findings may be false positives.",
    prompt: `# Agentic AI Corroboration in ai_analysis_service.py

# Step 1: Separate findings by source
scanner_findings, agentic_findings = _separate_findings(findings)

# Step 2: Cross-reference scanner findings with agentic results
def _findings_match(scanner_finding, agentic_finding) -> bool:
    """Match criteria:
    1. Same or similar vulnerability type (normalized)
    2. Same or nearby file location (within 50 lines)
    3. Similar summary/description (3+ meaningful words)
    """
    
# Step 3: Adjust false positive scores based on corroboration
if is_corroborated:
    # Reduce FP score - agentic AI confirmed this finding
    fp_reduction = min(0.4, agentic_confidence * 0.5)
    fp_score = max(0.0, fp_score - fp_reduction)
else:
    # Increase FP score - agentic AI didn't find this
    agentic_coverage_factor = min(0.3, len(agentic_findings) * 0.03)
    fp_score = min(1.0, fp_score + 0.15 + agentic_coverage_factor)

# Vulnerability type normalization handles variations:
# "sql injection" = "sqli" = "sql"
# "cross site scripting" = "xss" = "reflected xss"
# "command injection" = "os command injection" = "shell injection"`,
    exampleOutput: `## Agentic Corroboration Results

### Findings by Corroboration Status:

#### ⚠️ CORROBORATED (High Confidence - Likely Real):
| Scanner Finding | Agentic Finding | Confidence |
|-----------------|-----------------|------------|
| SQLi in query.py:42 | SQL Injection in query.py:40 | 95% |
| SSRF in webhook.py:88 | Server-Side Request Forgery | 87% |
| XSS in render.js:156 | Cross-Site Scripting | 92% |

→ These 3 findings were found by BOTH scanner AND Agentic AI
→ FP scores reduced by 0.3-0.4 (highly likely real)

#### ⚡ NOT CORROBORATED (Lower Confidence):
| Scanner Finding | Reason Not Matched |
|-----------------|-------------------|
| Hardcoded secret in test.py | Test file pattern |
| Weak crypto in utils.py | Not in critical path |
| Path traversal in docs.py | Example code |

→ These 5 findings were NOT found by Agentic AI
→ FP scores increased by 0.15-0.45 (may be false positives)

### Summary:
- 8 scanner findings total
- 3 corroborated by Agentic AI (37.5%)
- 5 not corroborated (consider review)`,
    outputFormat: "Cross-validation report",
    color: "#06b6d4",
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

  const pageContext = `AI analysis capabilities page. This page showcases VRAgent's AI-powered security analysis features including vulnerability classification, exploit chain analysis, false positive detection, remediation suggestions, and severity assessment powered by Google Gemini.`;

  return (
    <LearnPageLayout pageTitle="AI Analysis" pageContext={pageContext}>
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
              VRAgent uses a <strong>three-stage approach</strong>: fast heuristic patterns first, <strong>Agentic AI corroboration</strong> to cross-reference SAST findings with deep AI analysis, then <strong>Google Gemini 2.0 Flash</strong> for complex cases. This hybrid approach reduces false positives while ensuring real vulnerabilities are caught.
            </Typography>

            <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>🔒 Privacy Note:</strong> Only vulnerability metadata is sent to the AI - not your actual source code. The AI sees finding types, severities, file paths, and code snippets, but full source files stay on your server.
              </Typography>
            </Alert>

            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="Gemini 2.0 Flash" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6", fontWeight: 600 }} />
              <Chip label="Agentic Corroboration" sx={{ bgcolor: alpha("#06b6d4", 0.1), color: "#06b6d4", fontWeight: 600 }} />
              <Chip label="Heuristics First" variant="outlined" />
              <Chip label="50 Finding LLM Limit" variant="outlined" />
              <Chip label="8 Attack Chain Patterns" variant="outlined" />
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5), p: 3, borderRadius: 2, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>AI Analysis Flow</Typography>
              {[
                { icon: "🔍", label: "Scanners + Agentic AI find vulns" },
                { icon: "⚡", label: "Heuristics filter obvious FPs" },
                { icon: "✅", label: "Agentic corroboration cross-refs" },
                { icon: "📊", label: "Top 50 findings to LLM" },
                { icon: "🔗", label: "8 attack chain patterns matched" },
                { icon: "📝", label: "Templates generate exploits" },
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
        🎯 6 AI Analysis Capabilities
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {aiFeatures.map((feature, index) => (
          <Grid item xs={12} sm={6} md={2} key={feature.id}>
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
            { title: "Agentic Corroboration", desc: "Scanner findings cross-referenced with Agentic AI deep scan. Corroborated findings are highly likely real; uncorroborated may be FPs.", color: "#06b6d4" },
            { title: "LLM for Top 50 Only", desc: "Only the 50 most critical findings go to Gemini AI. This balances thoroughness with API cost and speed.", color: "#3b82f6" },
            { title: "8 Attack Chain Patterns", desc: "Pre-defined chain patterns (SQLi→Data Breach, SSRF→Cloud Takeover, etc.) identify multi-vulnerability exploits instantly.", color: "#10b981" },
            { title: "Pattern-Based Analysis", desc: "Common patterns (ORM usage, parameterized queries, env vars) instantly adjust severity without LLM.", color: "#8b5cf6" },
            { title: "Type Normalization", desc: "Vulnerability types are normalized (sql injection = sqli = sql) for accurate cross-scanner matching.", color: "#ef4444" },
          ].map((tip) => (
            <Grid item xs={12} md={4} key={tip.title}>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
