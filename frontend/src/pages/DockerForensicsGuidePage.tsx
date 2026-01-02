import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import { Link } from "react-router-dom";
import {
  Box,
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
  Chip,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  Card,
  CardContent,
  alpha,
  Divider,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import LayersIcon from "@mui/icons-material/Layers";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import BugReportIcon from "@mui/icons-material/BugReport";
import StorageIcon from "@mui/icons-material/Storage";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import VisibilityIcon from "@mui/icons-material/Visibility";
import SearchIcon from "@mui/icons-material/Search";
import DeleteIcon from "@mui/icons-material/Delete";
import LockIcon from "@mui/icons-material/Lock";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SchoolIcon from "@mui/icons-material/School";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import HistoryIcon from "@mui/icons-material/History";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import DescriptionIcon from "@mui/icons-material/Description";
import { useNavigate } from "react-router-dom";

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

const CodeBlock: React.FC<{ code: string; language?: string; title?: string }> = ({
  code,
  language = "bash",
  title,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        bgcolor: "#0d1117",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(14, 165, 233, 0.2)",
        overflow: "hidden",
      }}
    >
      {title && (
        <Box sx={{ px: 2, py: 1, bgcolor: "rgba(14, 165, 233, 0.1)", borderBottom: "1px solid rgba(14, 165, 233, 0.2)" }}>
          <Typography variant="subtitle2" sx={{ color: "#0ea5e9", fontWeight: 600 }}>{title}</Typography>
        </Box>
      )}
      <Box sx={{ position: "absolute", top: title ? 40 : 8, right: 8, zIndex: 1 }}>
        <Tooltip title={copied ? "Copied!" : "Copy code"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: copied ? "#22c55e" : "#6b7280" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          p: 2,
          m: 0,
          overflow: "auto",
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: "0.875rem",
          color: "#e6edf3",
          lineHeight: 1.6,
          "& .comment": { color: "#8b949e" },
          "& .keyword": { color: "#ff7b72" },
          "& .string": { color: "#a5d6ff" },
          "& .variable": { color: "#ffa657" },
        }}
      >
        <code>{code}</code>
      </Box>
    </Paper>
  );
};

const DockerForensicsGuidePage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const layerCommands = [
    { command: "docker history <image>", description: "Show image layer history with commands", category: "Inspection" },
    { command: "docker inspect <image>", description: "View full image metadata and configuration", category: "Inspection" },
    { command: "docker save <image> -o image.tar", description: "Export image to tarball for analysis", category: "Export" },
    { command: "docker image ls --digests", description: "List images with digest (content hash)", category: "Listing" },
    { command: "docker manifest inspect <image>", description: "View multi-arch manifest details", category: "Inspection" },
    { command: "docker diff <container>", description: "Show filesystem changes in running container", category: "Analysis" },
  ];

  const forensicsTools = [
    { name: "dive", description: "Interactive TUI for exploring image layers", purpose: "Layer analysis, efficiency" },
    { name: "crane", description: "Google's image manipulation tool", purpose: "Registry operations, copying" },
    { name: "skopeo", description: "Image operations without Docker daemon", purpose: "Copy, inspect registries" },
    { name: "trivy", description: "Comprehensive vulnerability scanner", purpose: "CVE scanning, secrets" },
    { name: "syft", description: "SBOM generator for containers", purpose: "Software inventory" },
    { name: "grype", description: "Vulnerability scanner for SBOMs", purpose: "CVE matching" },
    { name: "container-diff", description: "Diff container images and filesystems", purpose: "Change analysis" },
    { name: "dockerfile-from-image", description: "Reverse engineer Dockerfile", purpose: "Dockerfile reconstruction" },
  ];

  const secretPatterns = [
    { type: "AWS Keys", pattern: "AKIA[0-9A-Z]{16}", description: "AWS Access Key IDs" },
    { type: "Private Keys", pattern: "-----BEGIN .* PRIVATE KEY-----", description: "SSH/SSL private keys" },
    { type: "Generic API Keys", pattern: "[a-zA-Z0-9_-]{32,64}", description: "Long alphanumeric strings" },
    { type: "JWT Tokens", pattern: "eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.", description: "JSON Web Tokens" },
    { type: "GitHub Tokens", pattern: "ghp_[a-zA-Z0-9]{36}", description: "GitHub Personal Access Tokens" },
    { type: "Database URLs", pattern: "postgres://|mysql://|mongodb://", description: "Database connection strings" },
    { type: "Environment Files", pattern: "\\.env|\\.env\\.local", description: "Environment configuration files" },
  ];

  const supplyChainRisks = [
    { risk: "Base Image Vulnerabilities", severity: "HIGH", mitigation: "Use minimal/distroless images, scan regularly" },
    { risk: "Hardcoded Secrets", severity: "CRITICAL", mitigation: "Use build args, multi-stage builds, secret managers" },
    { risk: "Unnecessary Packages", severity: "MEDIUM", mitigation: "Multi-stage builds, minimal base images" },
    { risk: "Root User", severity: "HIGH", mitigation: "Use USER directive, non-root containers" },
    { risk: "Unverified Base Images", severity: "HIGH", mitigation: "Use official/verified images, content trust" },
    { risk: "Outdated Dependencies", severity: "MEDIUM", mitigation: "Pin versions, automate updates" },
  ];

  const attackVectorCategories = [
    {
      title: "Container Escape",
      color: "#dc2626",
      icon: <LockIcon />,
      description: "Findings that weaken isolation and allow host-level access.",
      signals: [
        "Privileged containers or host namespace flags",
        "Docker socket or hostPath mounts",
        "Host device access (/dev, /proc, /sys)",
      ],
    },
    {
      title: "Privilege Escalation",
      color: "#f97316",
      icon: <SecurityIcon />,
      description: "Ways to elevate within the container or gain root capabilities.",
      signals: [
        "Root user or unsafe capabilities",
        "SUID/SGID binaries in layers",
        "Writable system paths or config drift",
      ],
    },
    {
      title: "Secrets Exposure",
      color: "#ef4444",
      icon: <BugReportIcon />,
      description: "Credentials and tokens leaked in layers or build commands.",
      signals: [
        "API keys or tokens in RUN/COPY layers",
        "Private keys and certificates",
        ".env or config files with secrets",
      ],
    },
    {
      title: "Lateral Movement",
      color: "#f59e0b",
      icon: <SearchIcon />,
      description: "Artifacts that enable pivoting to cloud or internal services.",
      signals: [
        "Cloud credentials or SSH keys",
        "Kubeconfig or registry auth",
        "Hardcoded internal endpoints",
      ],
    },
    {
      title: "Network Exposure",
      color: "#0ea5e9",
      icon: <VisibilityIcon />,
      description: "Exposed services, ports, or admin surfaces in the image.",
      signals: [
        "Unexpected open ports",
        "Debug endpoints in config",
        "Embedded admin tooling",
      ],
    },
    {
      title: "Supply Chain",
      color: "#8b5cf6",
      icon: <BuildIcon />,
      description: "Risk from base images, packages, and provenance gaps.",
      signals: [
        "Unpinned or unknown base images",
        "Outdated packages or CVE indicators",
        "Unsigned artifacts or downloads",
      ],
    },
  ];

  const inspectorChecklist = [
    "Start with the risk score and critical/high issue counts.",
    "Review secrets and the layer command that introduced them.",
    "Prioritize escape, privilege escalation, and lateral movement paths.",
    "Confirm base image and exposed services, then export the report.",
  ];

  const pageContext = `This page covers Docker Inspector workflows, including image metadata, layer inventory, secrets detection, attack-vector risk scoring, AI security analysis, and report-ready findings. It also includes practical commands for manual layer extraction, secret scanning, and container supply chain hygiene.`;

  return (
    <LearnPageLayout pageTitle="Docker Inspector Guide" pageContext={pageContext}>
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2, mb: 2 }}
        />
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: 2,
              background: "linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <LayersIcon sx={{ fontSize: 36, color: "white" }} />
          </Box>
          <Box>
            <Typography variant="h3" fontWeight={700} sx={{ color: "text.primary" }}>
              Docker Inspector Guide
            </Typography>
            <Typography variant="h6" sx={{ color: "text.secondary" }}>
              Layer inspection, secrets, attack vectors, and AI risk scoring
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <Chip icon={<LayersIcon />} label="Layers" size="small" sx={{ bgcolor: alpha("#0ea5e9", 0.1), color: "#0ea5e9" }} />
          <Chip icon={<LockIcon />} label="Secrets" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
          <Chip icon={<SecurityIcon />} label="Supply Chain" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
          <Chip icon={<BugReportIcon />} label="Attack Vectors" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
        </Box>
      </Box>

      {/* Main Tabs */}
      <Paper sx={{ borderRadius: 3, overflow: "hidden" }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            borderBottom: 1,
            borderColor: "divider",
            bgcolor: alpha("#0ea5e9", 0.02),
            "& .MuiTab-root": {
              textTransform: "none",
              fontWeight: 600,
              minHeight: 60,
            },
          }}
        >
          <Tab icon={<LayersIcon />} label="Layer Analysis" iconPosition="start" />
          <Tab icon={<SearchIcon />} label="Secret Detection" iconPosition="start" />
          <Tab icon={<BugReportIcon />} label="Risk & Attack Vectors" iconPosition="start" />
          <Tab icon={<SecurityIcon />} label="Supply Chain Security" iconPosition="start" />
          <Tab icon={<CodeIcon />} label="Tools & Commands" iconPosition="start" />
          <Tab icon={<SchoolIcon />} label="Best Practices" iconPosition="start" />
        </Tabs>

        <Box sx={{ p: 3 }}>
          {/* Tab 0: Layer Analysis */}
          <TabPanel value={tabValue} index={0}>
            <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LayersIcon sx={{ color: "#0ea5e9" }} />
              Understanding Docker Image Layers
            </Typography>
            
            <Alert severity="info" sx={{ mb: 3 }}>
              Docker images are composed of multiple read-only layers. Each instruction in a Dockerfile creates a new layer. 
              Understanding layers is crucial for security analysis and optimization.
            </Alert>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Card sx={{ height: "100%", border: "1px solid", borderColor: "divider" }}>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} gutterBottom>
                      <HistoryIcon sx={{ mr: 1, verticalAlign: "middle", color: "#0ea5e9" }} />
                      What Creates Layers?
                    </Typography>
                    <List dense>
                      <ListItem>
                        <ListItemIcon><CodeIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
                        <ListItemText 
                          primary="FROM instruction" 
                          secondary="Base image layers are inherited"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CodeIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
                        <ListItemText 
                          primary="RUN commands" 
                          secondary="Each RUN creates a new layer with filesystem changes"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CodeIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
                        <ListItemText 
                          primary="COPY/ADD instructions" 
                          secondary="Files added to image create new layers"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CodeIcon sx={{ color: "#8b5cf6" }} /></ListItemIcon>
                        <ListItemText 
                          primary="ENV, LABEL, EXPOSE" 
                          secondary="Metadata layers (very small)"
                        />
                      </ListItem>
                    </List>
                  </CardContent>
                </Card>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Card sx={{ height: "100%", border: "1px solid", borderColor: "divider" }}>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} gutterBottom>
                      <WarningIcon sx={{ mr: 1, verticalAlign: "middle", color: "#ef4444" }} />
                      Security Implications
                    </Typography>
                    <List dense>
                      <ListItem>
                        <ListItemIcon><BugReportIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
                        <ListItemText 
                          primary="Deleted files persist in layers" 
                          secondary="Files removed in later layers are still in the image"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><LockIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
                        <ListItemText 
                          primary="Secrets can leak" 
                          secondary="Even if removed, secrets exist in earlier layers"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><StorageIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
                        <ListItemText 
                          primary="Build cache exposure" 
                          secondary="Intermediate layers may contain sensitive data"
                        />
                      </ListItem>
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Inspecting Image History
              </Typography>
              <CodeBlock 
                title="View layer history" 
                code={`# Show all layers with commands (truncated)
docker history nginx:latest

# Show full commands (not truncated)
docker history --no-trunc nginx:latest

# Format output as JSON
docker history --format json nginx:latest

# Show layer sizes
docker history --format "{{.CreatedBy}}\\t{{.Size}}" nginx:latest`}
              />
            </Box>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Extracting and Analyzing Layers
              </Typography>
              <CodeBlock 
                title="Export and extract image layers" 
                code={`# Save image to tar archive
docker save myimage:latest -o myimage.tar

# Extract the archive
mkdir myimage_extracted
tar -xvf myimage.tar -C myimage_extracted

# Structure will contain:
# - manifest.json (layer order and config)
# - <hash>.json (image config)
# - <hash>/layer.tar (each layer's filesystem)

# Extract a specific layer
cd myimage_extracted
tar -xvf <layer_hash>/layer.tar -C layer_contents/

# Search for secrets in extracted layers
grep -r "password\\|secret\\|key\\|token" layer_contents/`}
              />
            </Box>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Using Dive for Interactive Analysis
              </Typography>
              <CodeBlock 
                title="Interactive layer exploration with dive" 
                code={`# Install dive
brew install dive  # macOS
# or
wget https://github.com/wagoodman/dive/releases/download/v0.10.0/dive_0.10.0_linux_amd64.deb
sudo dpkg -i dive_0.10.0_linux_amd64.deb

# Analyze an image
dive nginx:latest

# Analyze with CI mode (exit code based on efficiency)
CI=true dive myimage:latest --ci-config .dive-ci.yaml

# Dive controls:
# Tab      - Switch between layers and file tree
# Ctrl+A   - Show added files only
# Ctrl+R   - Show removed files only
# Ctrl+M   - Show modified files only
# Ctrl+U   - Show unchanged files
# Ctrl+F   - Filter files by name`}
              />
            </Box>
          </TabPanel>

          {/* Tab 1: Secret Detection */}
          <TabPanel value={tabValue} index={1}>
            <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SearchIcon sx={{ color: "#ef4444" }} />
              Detecting Secrets in Docker Images
            </Typography>

            <Alert severity="warning" sx={{ mb: 3 }}>
              <strong>Critical:</strong> Secrets embedded in Docker images persist across all layers even if "deleted". 
              Always use multi-stage builds and never include secrets in your Dockerfile directly.
            </Alert>

            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ mt: 3 }}>
              Common Secret Patterns
            </Typography>
            <TableContainer component={Paper} sx={{ mb: 4 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                    <TableCell sx={{ fontWeight: 600 }}>Secret Type</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Pattern</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Description</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {secretPatterns.map((secret) => (
                    <TableRow key={secret.type}>
                      <TableCell><Chip label={secret.type} size="small" sx={{ bgcolor: alpha("#ef4444", 0.1) }} /></TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{secret.pattern}</TableCell>
                      <TableCell>{secret.description}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Manual Secret Hunting
              </Typography>
              <CodeBlock 
                title="Search for secrets in exported image" 
                code={`# Export and extract image
docker save myimage:latest | tar -x

# Search for common secret patterns
# AWS Keys
grep -r "AKIA[0-9A-Z]{16}" .

# Private keys
find . -name "*.pem" -o -name "*.key" -o -name "id_rsa"
grep -r "BEGIN.*PRIVATE KEY" .

# Environment files
find . -name ".env*" -o -name "*.env"

# Generic secrets
grep -rE "(password|secret|api_key|token)\\s*[:=]" .

# Base64 encoded secrets (may be credentials)
grep -rE "[A-Za-z0-9+/]{40,}={0,2}" .

# Docker config files (may have registry creds)
find . -name "config.json" | xargs grep -l "auth"`}
              />
            </Box>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Automated Secret Scanning with Trivy
              </Typography>
              <CodeBlock 
                title="Scan for secrets with Trivy" 
                code={`# Install trivy
brew install aquasecurity/trivy/trivy  # macOS

# Scan image for secrets
trivy image --scanners secret myimage:latest

# Scan with detailed output
trivy image --scanners secret --format json myimage:latest

# Scan specific layer (by extracting)
trivy fs --scanners secret ./extracted_layer/

# Scan for both vulnerabilities and secrets
trivy image --scanners vuln,secret myimage:latest

# Use custom secret patterns
trivy image --scanners secret --secret-config ./secret-rules.yaml myimage:latest`}
              />
            </Box>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Using TruffleHog for Deep Secret Scanning
              </Typography>
              <CodeBlock 
                title="TruffleHog container scanning" 
                code={`# Install trufflehog
pip install trufflehog

# Scan Git history in container
docker save myimage:latest -o image.tar
tar -xf image.tar
trufflehog filesystem ./

# Or use docker image directly
docker run --rm -v "$PWD:/target" trufflesecurity/trufflehog filesystem /target

# Scan with entropy analysis (finds high-entropy strings)
trufflehog filesystem ./ --entropy

# Output as JSON for processing
trufflehog filesystem ./ --json > secrets.json`}
              />
            </Box>
          </TabPanel>

          {/* Tab 2: Risk & Attack Vectors */}
          <TabPanel value={tabValue} index={2}>
            <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <BugReportIcon sx={{ color: "#f59e0b" }} />
              Risk Scoring & Attack Vectors
            </Typography>

            <Alert severity="info" sx={{ mb: 3 }}>
              Docker Inspector correlates layer commands, secrets, and misconfigurations into a risk score and
              categorized attack vectors. Use these signals to prioritize the fastest paths to impact.
            </Alert>

            <Grid container spacing={3}>
              {attackVectorCategories.map((category) => (
                <Grid item xs={12} md={6} key={category.title}>
                  <Card sx={{ height: "100%", border: "1px solid", borderColor: alpha(category.color, 0.3), bgcolor: alpha(category.color, 0.05) }}>
                    <CardContent>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1.5 }}>
                        <Box sx={{ color: category.color }}>{category.icon}</Box>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: category.color }}>
                          {category.title}
                        </Typography>
                      </Box>
                      <Typography variant="body2" sx={{ color: "text.secondary", mb: 1.5 }}>
                        {category.description}
                      </Typography>
                      <List dense>
                        {category.signals.map((signal) => (
                          <ListItem key={signal} sx={{ py: 0.2, px: 0 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon sx={{ fontSize: 14, color: category.color }} />
                            </ListItemIcon>
                            <ListItemText primary={signal} primaryTypographyProps={{ variant: "body2" }} />
                          </ListItem>
                        ))}
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, mt: 4, borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.25)}`, bgcolor: alpha("#f59e0b", 0.05) }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Triage workflow
              </Typography>
              <List dense>
                {inspectorChecklist.map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <TipsAndUpdatesIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </TabPanel>

          {/* Tab 3: Supply Chain Security */}
          <TabPanel value={tabValue} index={3}>
            <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SecurityIcon sx={{ color: "#22c55e" }} />
              Container Supply Chain Security
            </Typography>

            <Alert severity="error" sx={{ mb: 3 }}>
              Container supply chain attacks are increasingly common. Compromised base images, malicious dependencies, 
              and leaked secrets can have severe security implications.
            </Alert>

            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ mt: 3 }}>
              Common Supply Chain Risks
            </Typography>
            <TableContainer component={Paper} sx={{ mb: 4 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                    <TableCell sx={{ fontWeight: 600 }}>Risk</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Severity</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Mitigation</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {supplyChainRisks.map((risk) => (
                    <TableRow key={risk.risk}>
                      <TableCell>{risk.risk}</TableCell>
                      <TableCell>
                        <Chip 
                          label={risk.severity} 
                          size="small" 
                          sx={{ 
                            bgcolor: alpha(
                              risk.severity === "CRITICAL" ? "#ef4444" : 
                              risk.severity === "HIGH" ? "#f59e0b" : "#22c55e", 
                              0.1
                            ),
                            color: risk.severity === "CRITICAL" ? "#ef4444" : 
                                   risk.severity === "HIGH" ? "#f59e0b" : "#22c55e"
                          }} 
                        />
                      </TableCell>
                      <TableCell>{risk.mitigation}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Verifying Image Integrity
              </Typography>
              <CodeBlock 
                title="Content trust and signature verification" 
                code={`# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1

# Pull only signed images
docker pull myregistry/myimage:latest  # Will fail if unsigned

# Check image digest (content-addressable)
docker images --digests myimage:latest

# Verify digest matches expected
docker pull myregistry/myimage@sha256:abc123...

# Inspect image signatures (notary)
notary -d ~/.docker/trust list myregistry/myimage

# Cosign verification (sigstore)
cosign verify myregistry/myimage:latest

# Check image provenance (SLSA)
cosign verify-attestation --type slsaprovenance myregistry/myimage:latest`}
              />
            </Box>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Generating and Analyzing SBOMs
              </Typography>
              <CodeBlock 
                title="Software Bill of Materials" 
                code={`# Generate SBOM with Syft
syft myimage:latest -o cyclonedx-json > sbom.json
syft myimage:latest -o spdx-json > sbom-spdx.json

# Scan SBOM for vulnerabilities with Grype
grype sbom:./sbom.json

# Docker Scout (native to Docker)
docker scout sbom myimage:latest
docker scout cves myimage:latest

# Compare SBOMs between image versions
syft diff myimage:v1 myimage:v2

# Analyze SBOM contents
jq '.components[] | {name, version, purl}' sbom.json | head -20`}
              />
            </Box>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Base Image Security
              </Typography>
              <CodeBlock 
                title="Analyzing and securing base images" 
                code={`# Use minimal/distroless images
# Instead of: FROM ubuntu:latest
# Use: FROM gcr.io/distroless/base-debian11

# Scan base image
trivy image ubuntu:latest
trivy image gcr.io/distroless/base-debian11

# Check for latest CVE patches
docker scout cves --only-base nginx:latest

# Use specific digest instead of tag
FROM nginx@sha256:abc123...

# Multi-stage to minimize final image
FROM node:18 AS builder
COPY . .
RUN npm ci && npm run build

FROM gcr.io/distroless/nodejs18-debian11
COPY --from=builder /app/dist /app
CMD ["app/server.js"]`}
              />
            </Box>
          </TabPanel>

          {/* Tab 4: Tools & Commands */}
          <TabPanel value={tabValue} index={4}>
            <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon sx={{ color: "#8b5cf6" }} />
              Essential Tools & Commands
            </Typography>

            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ mt: 3 }}>
              Docker Native Commands
            </Typography>
            <TableContainer component={Paper} sx={{ mb: 4 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 600 }}>Command</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Category</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {layerCommands.map((cmd) => (
                    <TableRow key={cmd.command}>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>{cmd.command}</TableCell>
                      <TableCell>{cmd.description}</TableCell>
                      <TableCell><Chip label={cmd.category} size="small" /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ mt: 4 }}>
              Third-Party Security Tools
            </Typography>
            <Grid container spacing={2}>
              {forensicsTools.map((tool) => (
                <Grid item xs={12} md={6} key={tool.name}>
                  <Card sx={{ height: "100%", border: "1px solid", borderColor: "divider" }}>
                    <CardContent>
                      <Typography variant="h6" fontWeight={600} sx={{ color: "#8b5cf6" }}>
                        {tool.name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        {tool.description}
                      </Typography>
                      <Chip label={tool.purpose} size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1) }} />
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Complete Forensics Workflow
              </Typography>
              <CodeBlock 
                title="Full image analysis workflow" 
                code={`#!/bin/bash
# Complete Docker image forensics workflow

IMAGE="target-image:latest"
WORKDIR="./forensics_output"
mkdir -p $WORKDIR

echo "[1/7] Exporting image..."
docker save $IMAGE -o $WORKDIR/image.tar

echo "[2/7] Extracting layers..."
cd $WORKDIR && tar -xf image.tar

echo "[3/7] Getting image history..."
docker history --no-trunc $IMAGE > history.txt

echo "[4/7] Extracting full config..."
docker inspect $IMAGE > config.json

echo "[5/7] Scanning for vulnerabilities..."
trivy image --format json $IMAGE > vulns.json

echo "[6/7] Scanning for secrets..."
trivy image --scanners secret --format json $IMAGE > secrets.json

echo "[7/7] Generating SBOM..."
syft $IMAGE -o cyclonedx-json > sbom.json

echo "Done! Results in $WORKDIR/"
ls -la $WORKDIR/`}
              />
            </Box>
          </TabPanel>

          {/* Tab 5: Best Practices */}
          <TabPanel value={tabValue} index={5}>
            <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SchoolIcon sx={{ color: "#06b6d4" }} />
              Security Best Practices
            </Typography>

            <Alert severity="success" sx={{ mb: 3 }}>
              Following these best practices will significantly improve your container security posture and 
              reduce the risk of supply chain attacks.
            </Alert>

            <Accordion defaultExpanded sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight={600}>
                  <CheckCircleIcon sx={{ mr: 1, color: "#22c55e", verticalAlign: "middle" }} />
                  Use Multi-Stage Builds
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Multi-stage builds allow you to use separate images for building and running, 
                  keeping build tools and secrets out of the final image.
                </Typography>
                <CodeBlock 
                  code={`# Multi-stage build example
FROM node:18 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Final stage - minimal image
FROM gcr.io/distroless/nodejs18-debian11
COPY --from=builder /app/dist /app
CMD ["app/index.js"]`}
                />
              </AccordionDetails>
            </Accordion>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight={600}>
                  <CheckCircleIcon sx={{ mr: 1, color: "#22c55e", verticalAlign: "middle" }} />
                  Never Hardcode Secrets
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Use Docker secrets, build-time secrets (BuildKit), or external secret management.
                </Typography>
                <CodeBlock 
                  code={`# Bad - secret persists in layer
RUN echo "password123" > /app/.env

# Good - use BuildKit secrets (not stored in layer)
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret

# Build with:
docker build --secret id=mysecret,src=./secret.txt .

# Or use runtime environment variables
docker run -e API_KEY=$API_KEY myimage`}
                />
              </AccordionDetails>
            </Accordion>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight={600}>
                  <CheckCircleIcon sx={{ mr: 1, color: "#22c55e", verticalAlign: "middle" }} />
                  Run as Non-Root User
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Always specify a non-root user in your Dockerfile to limit container privileges.
                </Typography>
                <CodeBlock 
                  code={`FROM node:18-slim

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app
COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

CMD ["node", "server.js"]`}
                />
              </AccordionDetails>
            </Accordion>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight={600}>
                  <CheckCircleIcon sx={{ mr: 1, color: "#22c55e", verticalAlign: "middle" }} />
                  Pin Image Versions
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Never use :latest tag in production. Pin to specific digests for reproducibility.
                </Typography>
                <CodeBlock 
                  code={`# Bad - unpredictable
FROM node:latest

# Better - pinned version
FROM node:18.19.0-slim

# Best - pinned to digest (immutable)
FROM node@sha256:abc123def456...

# Get digest:
docker pull node:18.19.0-slim
docker inspect --format='{{index .RepoDigests 0}}' node:18.19.0-slim`}
                />
              </AccordionDetails>
            </Accordion>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight={600}>
                  <CheckCircleIcon sx={{ mr: 1, color: "#22c55e", verticalAlign: "middle" }} />
                  Integrate Security Scanning in CI/CD
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Automate vulnerability and secret scanning in your build pipeline.
                </Typography>
                <CodeBlock 
                  code={`# GitHub Actions example
name: Container Security
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build image
        run: docker build -t myapp:\$\{{ github.sha \}} .
      
      - name: Scan for vulnerabilities
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:\$\{{ github.sha \}}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
      
      - name: Scan for secrets
        run: trivy image --scanners secret myapp:\$\{{ github.sha \}}`}
                />
              </AccordionDetails>
            </Accordion>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h6" fontWeight={600} gutterBottom>
              Quick Reference: Security Checklist
            </Typography>
            <Grid container spacing={2}>
              {[
                "Use minimal/distroless base images",
                "Multi-stage builds to exclude build deps",
                "No secrets in Dockerfiles or layers",
                "Run as non-root user (USER directive)",
                "Pin base image versions/digests",
                "Scan images in CI/CD pipeline",
                "Enable Docker Content Trust",
                "Generate and verify SBOMs",
                "Regular base image updates",
                "Use .dockerignore to exclude sensitive files"
              ].map((item, index) => (
                <Grid item xs={12} sm={6} key={index}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 20 }} />
                    <Typography variant="body2">{item}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </TabPanel>
        </Box>
      </Paper>

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
};

export default DockerForensicsGuidePage;
