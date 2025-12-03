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
    description: "Orchestrates the entire scanning pipeline, coordinating all other services in sequence.",
    responsibilities: [
      "Manages the 9-phase scanning workflow",
      "Coordinates scanner execution based on detected languages",
      "Tracks scan progress and status via WebSocket",
      "Handles errors gracefully and reports partial results",
      "Calculates final risk scores using weighted formula",
    ],
    dependencies: ["codebase_service", "dependency_service", "secret_service", "semgrep_service", "exploit_service"],
    color: "#3b82f6",
  },
  {
    name: "Codebase Service",
    file: "codebase_service.py",
    description: "Handles code extraction, parsing, and analysis. First step in the scanning pipeline.",
    responsibilities: [
      "Extracts ZIP archives with path traversal protection",
      "Detects programming languages by file extension",
      "Counts lines of code, files, and directories",
      "Identifies frameworks from manifest files",
      "Builds the codebase tree structure for UI",
    ],
    color: "#8b5cf6",
  },
  {
    name: "Dependency Service",
    file: "dependency_service.py",
    description: "Parses dependency manifests for 7 ecosystems and extracts version information.",
    responsibilities: [
      "Parses requirements.txt, package.json, pom.xml, go.mod, Gemfile, Cargo.toml, composer.json",
      "Handles lock files for precise version resolution",
      "Normalizes package names across ecosystems",
      "Deduplicates dependencies from multiple sources",
      "Maps dependencies to ecosystem for CVE lookup",
    ],
    color: "#10b981",
  },
  {
    name: "CVE Service",
    file: "cve_service.py",
    description: "Queries OSV.dev to find known vulnerabilities in dependencies.",
    responsibilities: [
      "Batch queries OSV API (100 deps per request)",
      "Maps ecosystem names to OSV format",
      "Extracts CVE IDs, severity, and affected versions",
      "Handles rate limiting with concurrent batches",
      "Aggregates CVE, GHSA, and ecosystem advisories",
    ],
    dependencies: ["nvd_service", "epss_service"],
    color: "#ef4444",
  },
  {
    name: "NVD Service",
    file: "nvd_service.py",
    description: "Enriches CVE data with detailed information from NIST's National Vulnerability Database.",
    responsibilities: [
      "Fetches full CVSS v3/v4 vector strings",
      "Retrieves CWE weakness classifications",
      "Gets reference links to advisories and patches",
      "Caches responses for 24 hours",
      "Handles rate limiting (5 or 50 req/30s)",
    ],
    color: "#f59e0b",
  },
  {
    name: "EPSS Service",
    file: "epss_service.py",
    description: "Scores vulnerabilities by real-world exploitation probability using FIRST's EPSS API.",
    responsibilities: [
      "Batch queries EPSS API for all CVEs",
      "Returns exploitation probability (0-1 scale)",
      "Provides percentile ranking vs all CVEs",
      "Caches scores for 24 hours",
      "Prioritizes actively exploited vulnerabilities",
    ],
    color: "#ec4899",
  },
  {
    name: "Semgrep Service",
    file: "semgrep_service.py",
    description: "Runs Semgrep SAST scanner with 30+ security rulesets for multi-language analysis.",
    responsibilities: [
      "Executes Semgrep with language-specific rulesets",
      "Parses SARIF output into normalized findings",
      "Applies OWASP, CWE, and framework-specific rules",
      "Performs taint tracking for data flow analysis",
      "Maps findings to files and line numbers",
    ],
    color: "#6366f1",
  },
  {
    name: "Secret Service",
    file: "secret_service.py",
    description: "Scans for 50+ types of hardcoded secrets and credentials.",
    responsibilities: [
      "Detects AWS, Azure, GCP, OpenAI, and other API keys",
      "Finds private keys (RSA, SSH, PGP)",
      "Identifies database connection strings",
      "Reports file location and matched pattern",
      "High-confidence regex with low false positives",
    ],
    color: "#dc2626",
  },
  {
    name: "Exploit Service",
    file: "exploit_service.py",
    description: "Generates AI-powered exploitability analysis using Google Gemini.",
    responsibilities: [
      "Groups findings by vulnerability category",
      "Uses 30+ built-in exploit templates for common vulns",
      "Calls Gemini API for novel vulnerability types",
      "Generates attack narratives with PoC outlines",
      "Provides impact assessment and mitigations",
    ],
    dependencies: ["ai_analysis_service"],
    color: "#7c3aed",
  },
  {
    name: "AI Analysis Service",
    file: "ai_analysis_service.py",
    description: "Generates AI-powered summaries of the application and its security posture.",
    responsibilities: [
      "Creates application overview explaining what the code does",
      "Generates security analysis summarizing risks",
      "Caches summaries in database for instant exports",
      "Uses Gemini with optimized prompts",
      "Handles context length limits gracefully",
    ],
    color: "#8b5cf6",
  },
  {
    name: "Export Service",
    file: "export_service.py",
    description: "Generates professional security reports in multiple formats.",
    responsibilities: [
      "Exports to Markdown, PDF, and DOCX formats",
      "Includes AI summaries and exploit scenarios",
      "Generates severity breakdown tables",
      "Adds CVSS scores and EPSS probabilities",
      "Creates hyperlinks to CVE/CWE references",
    ],
    color: "#059669",
  },
  {
    name: "SBOM Service",
    file: "sbom_service.py",
    description: "Generates Software Bill of Materials in industry-standard formats.",
    responsibilities: [
      "Exports CycloneDX 1.5 format",
      "Exports SPDX 2.3 format",
      "Lists all detected dependencies",
      "Includes license information when available",
      "Maps vulnerabilities to components",
    ],
    color: "#0891b2",
  },
  {
    name: "WebSocket Service",
    file: "websocket_service.py",
    description: "Provides real-time scan progress updates to the frontend.",
    responsibilities: [
      "Manages WebSocket connections per scan",
      "Broadcasts phase transitions and progress",
      "Uses Redis pub/sub for worker communication",
      "Handles client disconnects gracefully",
      "Supports project-level subscriptions",
    ],
    color: "#f97316",
  },
  {
    name: "Webhook Service",
    file: "webhook_service.py",
    description: "Sends scan notifications to external services.",
    responsibilities: [
      "Supports Slack, Teams, Discord, and custom endpoints",
      "Sends scan complete notifications with summary",
      "Includes finding counts and risk score",
      "Retries failed deliveries",
      "Validates webhook URLs",
    ],
    color: "#84cc16",
  },
];

const languageScanners = [
  { language: "Python", scanner: "Bandit", service: "bandit_service.py", detects: "SQL injection, shell injection, hardcoded passwords, weak crypto" },
  { language: "JavaScript/TypeScript", scanner: "ESLint Security", service: "eslint_service.py", detects: "XSS, eval injection, prototype pollution, regex DoS" },
  { language: "Java/Kotlin", scanner: "SpotBugs + FindSecBugs", service: "spotbugs_service.py", detects: "SQL injection, XXE, LDAP injection, Spring security issues" },
  { language: "Go", scanner: "gosec", service: "gosec_service.py", detects: "SQL injection, command injection, path traversal, crypto issues" },
  { language: "C/C++", scanner: "clang-tidy", service: "clangtidy_service.py", detects: "Buffer overflows, format strings, insecure functions, memory safety" },
  { language: "All Languages", scanner: "Semgrep", service: "semgrep_service.py", detects: "30+ rulesets: OWASP Top 10, CWE Top 25, taint tracking" },
  { language: "All Files", scanner: "Secret Scanner", service: "secret_service.py", detects: "50+ secret types: AWS, GCP, Azure, OpenAI, private keys" },
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
            { label: "Redis", color: "#dc382d" },
            { label: "Docker", color: "#2496ed" },
            { label: "Gemini AI", color: "#8b5cf6" },
            { label: "WebSocket", color: "#f59e0b" },
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
              { step: 5, action: "Progress updates broadcast", component: "Worker → Redis → Backend → WS", detail: "Real-time to browser" },
              { step: 6, action: "Scanners execute in parallel", component: "Worker", detail: "Semgrep, Bandit, etc." },
              { step: 7, action: "Results saved to database", component: "Worker → PostgreSQL", detail: "Findings, dependencies" },
              { step: 8, action: "AI analysis runs (if enabled)", component: "Worker → Gemini", detail: "Exploit narratives" },
              { step: 9, action: "Scan complete notification", component: "Worker", detail: "Status: COMPLETED, webhooks fired" },
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
          Every scan follows a deterministic 9-phase pipeline. Progress is broadcast via WebSocket at each phase transition.
        </Typography>

        <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {[
            { phase: 1, name: "Code Acquisition", desc: "Clone repo or extract ZIP archive to isolated directory", duration: "5-30s", service: "git_service / codebase_service" },
            { phase: 2, name: "Codebase Intelligence", desc: "Detect languages, frameworks, count files and LOC", duration: "10-60s", service: "codebase_service" },
            { phase: 3, name: "Dependency Parsing", desc: "Parse manifest files for 7 ecosystems", duration: "5-20s", service: "dependency_service" },
            { phase: 4, name: "CVE Lookup", desc: "Query OSV.dev for known vulnerabilities in dependencies", duration: "10-60s", service: "cve_service" },
            { phase: 5, name: "NVD Enrichment", desc: "Fetch CVSS vectors, CWE mappings from NIST", duration: "30-120s", service: "nvd_service" },
            { phase: 6, name: "EPSS Scoring", desc: "Get exploitation probability for each CVE", duration: "5-15s", service: "epss_service" },
            { phase: 7, name: "Static Analysis", desc: "Run Semgrep, Bandit, ESLint, gosec, etc.", duration: "60-300s", service: "*_service" },
            { phase: 8, name: "Secret Detection", desc: "Scan for 50+ hardcoded secret types", duration: "10-30s", service: "secret_service" },
            { phase: 9, name: "AI Analysis", desc: "Generate summaries and exploit narratives", duration: "30-120s", service: "exploit_service" },
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
                  bgcolor: alpha(theme.palette.primary.main, 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 800, color: "primary.main" }}>
                  {phase.phase}
                </Typography>
              </Box>
              <Box sx={{ flex: 1 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 0.5 }}>
                  {phase.name}
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
            Risk score calculated, findings saved, webhooks fired. Report available for viewing and export.
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
