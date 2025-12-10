import React, { useState } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  TextField,
  Paper,
  Chip,
  Alert,
  CircularProgress,
  alpha,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Collapse,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress,
  Divider,
  Menu,
  MenuItem,
  ListItemText,
  Tabs,
  Tab,
} from "@mui/material";
import { Link } from "react-router-dom";
import LockIcon from "@mui/icons-material/Lock";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import InfoIcon from "@mui/icons-material/Info";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import PortableWifiOffIcon from "@mui/icons-material/PortableWifiOff";
import BugReportIcon from "@mui/icons-material/BugReport";
import LinkIcon from "@mui/icons-material/Link";
import GppBadIcon from "@mui/icons-material/GppBad";
import DownloadIcon from "@mui/icons-material/Download";
import DescriptionIcon from "@mui/icons-material/Description";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import ArticleIcon from "@mui/icons-material/Article";
import TerminalIcon from "@mui/icons-material/Terminal";
import TargetIcon from "@mui/icons-material/GpsFixed";
import { apiClient } from "../api/client";

// Common SSL/TLS ports
const COMMON_SSL_PORTS = [
  { port: 443, name: "HTTPS" },
  { port: 8443, name: "HTTPS Alt" },
  { port: 993, name: "IMAPS" },
  { port: 995, name: "POP3S" },
  { port: 465, name: "SMTPS" },
  { port: 587, name: "SMTP/TLS" },
  { port: 636, name: "LDAPS" },
  { port: 989, name: "FTPS Data" },
  { port: 990, name: "FTPS Control" },
  { port: 3389, name: "RDP" },
  { port: 5061, name: "SIP/TLS" },
  { port: 6697, name: "IRC/TLS" },
  { port: 8883, name: "MQTT/TLS" },
  { port: 9443, name: "WSS Alt" },
];

interface ScanTarget {
  host: string;
  port: number;
}

interface SSLCertificate {
  subject: string | null;
  issuer: string | null;
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  is_expired: boolean;
  days_until_expiry: number | null;
  is_self_signed: boolean;
  signature_algorithm: string | null;
  key_type: string | null;
  key_size: number | null;
  san: string[];
}

interface SSLFinding {
  severity: string;
  category: string;
  title: string;
  description: string;
  recommendation: string | null;
  cve: string | null;
}

interface VulnerabilityInfo {
  vuln_id: string;
  cve: string;
  name: string;
  severity: string;
  description: string;
  affected: string;
  cvss: number;
  exploit_difficulty: string;
  is_exploitable: boolean;
  evidence: string;
}

interface ChainInfo {
  chain_length: number;
  is_complete: boolean;
  is_trusted: boolean;
  root_ca: string | null;
  chain_errors: string[];
  certificates: any[];
}

interface SSLScanResult {
  host: string;
  port: number;
  certificate: SSLCertificate | null;
  supported_protocols: string[];
  cipher_suites: string[];
  has_ssl: boolean;
  error: string | null;
  findings: SSLFinding[];
  vulnerabilities: VulnerabilityInfo[];
  chain_info: ChainInfo | null;
}

interface SSLScanSummary {
  total_hosts: number;
  hosts_with_ssl: number;
  expired_certs: number;
  self_signed_certs: number;
  weak_protocols: number;
  weak_ciphers: number;
  critical_findings: number;
  high_findings: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  exploitable_vulnerabilities: number;
  chain_issues: number;
}

interface ExploitationScenario {
  // Backend schema
  title?: string;
  target?: string;
  vulnerability?: string;
  difficulty?: string;
  prerequisites?: string;
  attack_steps?: string[];
  tools?: string[];
  expected_outcome?: string;
  detection_risk?: string;
  // Alternative frontend schema
  attack_name?: string;
  target_vulnerability?: string;
  exploit_difficulty?: string;
  required_tools?: string;
  example_commands?: string[];
  potential_impact?: string;
  indicators_of_compromise?: string[];
}

interface HighValueTarget {
  host: string;
  risk_level: string;
  weaknesses: string[];
  attack_priority: string;
  why_high_value: string;
  recommended_attack_vector: string;
}

interface ToolRecommendation {
  tool_name: string;
  purpose: string;
  target_host: string;
  usage_example?: string;
}

interface CertificateAttack {
  type: string;
  feasibility: string;
  description: string;
  target: string;
}

interface ProtocolAttack {
  vulnerability: string;
  target: string;
  exploitation_method: string;
  tools_required: string[];
}

interface AttackChainStep {
  order: number;
  action: string;
  target: string;
  expected_result: string;
}

interface QuickWin {
  target: string;
  attack: string;
  impact: string;
  command: string;
}

interface Recommendation {
  priority: string;
  action: string;
  rationale: string;
}

interface AIAnalysis {
  error?: string;
  structured_report?: {
    overall_risk_level?: string;
    risk_level?: string;
    risk_score?: number;
    executive_summary?: string;
    exploitation_scenarios?: ExploitationScenario[];
    high_value_targets?: HighValueTarget[];
    lateral_movement_opportunities?: any[];
    tool_recommendations?: ToolRecommendation[];
    quick_wins?: (string | QuickWin)[];
    certificate_attacks?: {
      summary?: string;
      attacks?: CertificateAttack[];
    };
    protocol_attacks?: {
      summary?: string;
      attacks?: ProtocolAttack[];
    };
    recommended_attack_chain?: {
      description?: string;
      steps?: AttackChainStep[];
      total_effort?: string;
    };
    recommendations?: Recommendation[];
  };
  raw_response?: string;
}

interface SSLScanResponse {
  results: SSLScanResult[];
  summary: SSLScanSummary;
  ai_analysis: AIAnalysis | null;
  report_id: number | null;
}

const SSLScannerPage: React.FC = () => {
  const [targets, setTargets] = useState<ScanTarget[]>([{ host: "", port: 443 }]);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<SSLScanResponse | null>(null);
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const [portsMenuAnchor, setPortsMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedTargetIndex, setSelectedTargetIndex] = useState<number>(0);
  const [aiTabValue, setAiTabValue] = useState(0);
  const [exporting, setExporting] = useState<string | null>(null);

  const addTarget = () => {
    setTargets([...targets, { host: "", port: 443 }]);
  };

  const removeTarget = (index: number) => {
    if (targets.length > 1) {
      setTargets(targets.filter((_, i) => i !== index));
    }
  };

  const updateTarget = (index: number, field: "host" | "port", value: string | number) => {
    const newTargets = [...targets];
    newTargets[index] = { ...newTargets[index], [field]: value };
    setTargets(newTargets);
  };

  // Export report to different formats
  const handleExport = async (format: "markdown" | "pdf" | "docx") => {
    if (!results?.report_id) {
      setError("No report to export. Run a scan first.");
      return;
    }

    setExporting(format);
    try {
      const response = await fetch(`/api/network/reports/${results.report_id}/export/${format}`);
      if (!response.ok) throw new Error("Export failed");
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = format === "markdown" ? "md" : format;
      a.download = `ssl_scan_report_${results.report_id}.${ext}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err: any) {
      setError(err.message || "Export failed");
    } finally {
      setExporting(null);
    }
  };

  // Add multiple ports for the same host
  const addCommonPorts = (host: string) => {
    if (!host.trim()) {
      setError("Please enter a host first");
      return;
    }
    const newTargets = COMMON_SSL_PORTS.map((p) => ({ host: host.trim(), port: p.port }));
    setTargets(newTargets);
  };

  // Parse port input that may contain ranges or comma-separated values
  const parsePortInput = (index: number, portStr: string) => {
    const host = targets[index].host;
    if (!host.trim()) {
      updateTarget(index, "port", parseInt(portStr) || 443);
      return;
    }

    // Check for comma-separated ports (e.g., "443,8443,993")
    if (portStr.includes(",")) {
      const ports = portStr.split(",").map((p) => parseInt(p.trim())).filter((p) => !isNaN(p) && p > 0 && p <= 65535);
      if (ports.length > 0) {
        const newTargets = [...targets];
        newTargets.splice(index, 1); // Remove current target
        const newEntries = ports.map((port) => ({ host: host.trim(), port }));
        newTargets.splice(index, 0, ...newEntries);
        setTargets(newTargets);
        return;
      }
    }

    // Check for port range (e.g., "443-445")
    if (portStr.includes("-")) {
      const [startStr, endStr] = portStr.split("-");
      const start = parseInt(startStr.trim());
      const end = parseInt(endStr.trim());
      if (!isNaN(start) && !isNaN(end) && start > 0 && end <= 65535 && start <= end && (end - start) <= 100) {
        const newTargets = [...targets];
        newTargets.splice(index, 1);
        const newEntries: ScanTarget[] = [];
        for (let port = start; port <= end; port++) {
          newEntries.push({ host: host.trim(), port });
        }
        newTargets.splice(index, 0, ...newEntries);
        setTargets(newTargets);
        return;
      }
    }

    // Single port
    updateTarget(index, "port", parseInt(portStr) || 443);
  };

  const handlePortsMenuOpen = (event: React.MouseEvent<HTMLElement>, index: number) => {
    setPortsMenuAnchor(event.currentTarget);
    setSelectedTargetIndex(index);
  };

  const handlePortsMenuClose = () => {
    setPortsMenuAnchor(null);
  };

  const handleSelectPort = (port: number) => {
    updateTarget(selectedTargetIndex, "port", port);
    handlePortsMenuClose();
  };

  const handleScan = async () => {
    const validTargets = targets.filter((t) => t.host.trim() !== "");
    if (validTargets.length === 0) {
      setError("Please enter at least one target host");
      return;
    }

    setScanning(true);
    setError(null);
    setResults(null);

    try {
      const response = await apiClient.scanSSL({
        targets: validTargets,
        timeout: 10,
        include_ai: true,
      });
      setResults(response);
    } catch (err: any) {
      setError(err.message || "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "#dc2626";
      case "high":
        return "#ea580c";
      case "medium":
        return "#ca8a04";
      case "low":
        return "#16a34a";
      default:
        return "#6b7280";
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return <ErrorIcon sx={{ color: "#dc2626" }} />;
      case "high":
        return <WarningIcon sx={{ color: "#ea580c" }} />;
      case "medium":
        return <WarningIcon sx={{ color: "#ca8a04" }} />;
      case "low":
        return <InfoIcon sx={{ color: "#16a34a" }} />;
      default:
        return <InfoIcon sx={{ color: "#6b7280" }} />;
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "N/A";
    try {
      return new Date(dateStr).toLocaleDateString();
    } catch {
      return dateStr;
    }
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Button
          component={Link}
          to="/network"
          startIcon={<ArrowBackIcon />}
          sx={{ mb: 2 }}
        >
          Back to Network Hub
        </Button>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              background: `linear-gradient(135deg, #10b981 0%, #059669 100%)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <LockIcon sx={{ fontSize: 32, color: "white" }} />
          </Box>
          <Box>
            <Typography variant="h4" fontWeight={700}>
              SSL/TLS Scanner
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Analyze SSL/TLS configuration and certificate security
            </Typography>
          </Box>
        </Box>
        <Chip
          component={Link}
          to="/learn/ssl-tls"
          icon={<MenuBookIcon sx={{ fontSize: 16 }} />}
          label="Learn About SSL/TLS Security →"
          clickable
          size="small"
          sx={{
            background: alpha("#10b981", 0.1),
            border: `1px solid ${alpha("#10b981", 0.3)}`,
            color: "#34d399",
            fontWeight: 500,
            "&:hover": {
              background: alpha("#10b981", 0.2),
            },
          }}
        />
      </Box>

      {/* Input Section */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
            Scan Targets
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Enter the hosts and ports to scan. The scanner will check certificate validity,
            protocol support, cipher strength, and common SSL/TLS vulnerabilities.
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ mb: 3, display: "block" }}>
            💡 Tip: Enter comma-separated ports (443,8443,993) or port ranges (443-445) to scan multiple ports at once
          </Typography>

          {targets.map((target, index) => (
            <Box key={index} sx={{ display: "flex", gap: 2, mb: 2, alignItems: "center" }}>
              <TextField
                label="Host"
                placeholder="example.com or 192.168.1.1"
                value={target.host}
                onChange={(e) => updateTarget(index, "host", e.target.value)}
                size="small"
                sx={{ flex: 1 }}
              />
              <TextField
                label="Port(s)"
                placeholder="443 or 443,8443 or 443-445"
                value={target.port}
                onChange={(e) => parsePortInput(index, e.target.value)}
                size="small"
                sx={{ width: 180 }}
              />
              <Tooltip title="Select common SSL port">
                <IconButton
                  onClick={(e) => handlePortsMenuOpen(e, index)}
                  size="small"
                  sx={{ color: "#10b981" }}
                >
                  <PortableWifiOffIcon />
                </IconButton>
              </Tooltip>
              <IconButton
                onClick={() => removeTarget(index)}
                disabled={targets.length === 1}
                color="error"
              >
                <DeleteIcon />
              </IconButton>
            </Box>
          ))}

          <Box sx={{ display: "flex", gap: 2, mt: 3, flexWrap: "wrap" }}>
            <Button startIcon={<AddIcon />} onClick={addTarget} variant="outlined">
              Add Target
            </Button>
            <Button 
              startIcon={<PortableWifiOffIcon />} 
              onClick={() => addCommonPorts(targets[0]?.host || "")} 
              variant="outlined"
              color="secondary"
            >
              Scan All Common SSL Ports
            </Button>
            <Button
              startIcon={scanning ? <CircularProgress size={20} /> : <PlayArrowIcon />}
              onClick={handleScan}
              variant="contained"
              disabled={scanning}
              sx={{
                background: `linear-gradient(135deg, #10b981 0%, #059669 100%)`,
                "&:hover": {
                  background: `linear-gradient(135deg, #059669 0%, #047857 100%)`,
                },
              }}
            >
              {scanning ? "Scanning..." : "Start Scan"}
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Common Ports Menu */}
      <Menu
        anchorEl={portsMenuAnchor}
        open={Boolean(portsMenuAnchor)}
        onClose={handlePortsMenuClose}
      >
        {COMMON_SSL_PORTS.map((p) => (
          <MenuItem key={p.port} onClick={() => handleSelectPort(p.port)}>
            <ListItemText primary={`${p.port} - ${p.name}`} />
          </MenuItem>
        ))}
      </Menu>

      {/* Error */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Scanning Progress */}
      {scanning && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <CircularProgress size={24} />
            <Typography>Scanning SSL/TLS configuration...</Typography>
          </Box>
          <LinearProgress />
        </Paper>
      )}

      {/* Results */}
      {results && (
        <>
          {/* Summary */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                <Typography variant="h6" fontWeight={600}>
                  Scan Summary
                </Typography>
                {/* Export Buttons */}
                <Box sx={{ display: "flex", gap: 1 }}>
                  <Button
                    size="small"
                    startIcon={exporting === "markdown" ? <CircularProgress size={16} /> : <DescriptionIcon />}
                    onClick={() => handleExport("markdown")}
                    disabled={!results.report_id || exporting !== null}
                    variant="outlined"
                  >
                    Markdown
                  </Button>
                  <Button
                    size="small"
                    startIcon={exporting === "pdf" ? <CircularProgress size={16} /> : <PictureAsPdfIcon />}
                    onClick={() => handleExport("pdf")}
                    disabled={!results.report_id || exporting !== null}
                    variant="outlined"
                    color="error"
                  >
                    PDF
                  </Button>
                  <Button
                    size="small"
                    startIcon={exporting === "docx" ? <CircularProgress size={16} /> : <ArticleIcon />}
                    onClick={() => handleExport("docx")}
                    disabled={!results.report_id || exporting !== null}
                    variant="outlined"
                    color="primary"
                  >
                    Word
                  </Button>
                </Box>
              </Box>
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#06b6d4", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#0891b2">
                      {results.summary.total_hosts}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Total Hosts
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#10b981", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#059669">
                      {results.summary.hosts_with_ssl}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      SSL Enabled
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#dc2626", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#dc2626">
                      {results.summary.critical_findings}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Critical Issues
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#ea580c", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#ea580c">
                      {results.summary.high_findings}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      High Issues
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#7c3aed", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#7c3aed">
                      {results.summary.total_vulnerabilities || 0}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Vulnerabilities
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3} md={2}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      background: alpha("#be123c", 0.1),
                    }}
                  >
                    <Typography variant="h4" fontWeight={700} color="#be123c">
                      {results.summary.exploitable_vulnerabilities || 0}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Exploitable
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>

              {/* Additional Stats */}
              <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mt: 3 }}>
                {results.summary.expired_certs > 0 && (
                  <Chip
                    icon={<ErrorIcon />}
                    label={`${results.summary.expired_certs} Expired Certs`}
                    color="error"
                    variant="outlined"
                  />
                )}
                {results.summary.self_signed_certs > 0 && (
                  <Chip
                    icon={<WarningIcon />}
                    label={`${results.summary.self_signed_certs} Self-Signed`}
                    color="warning"
                    variant="outlined"
                  />
                )}
                {results.summary.weak_protocols > 0 && (
                  <Chip
                    icon={<WarningIcon />}
                    label={`${results.summary.weak_protocols} Weak Protocols`}
                    color="warning"
                    variant="outlined"
                  />
                )}
                {results.summary.weak_ciphers > 0 && (
                  <Chip
                    icon={<WarningIcon />}
                    label={`${results.summary.weak_ciphers} Weak Ciphers`}
                    color="warning"
                    variant="outlined"
                  />
                )}
                {(results.summary.chain_issues || 0) > 0 && (
                  <Chip
                    icon={<LinkIcon />}
                    label={`${results.summary.chain_issues} Chain Issues`}
                    color="warning"
                    variant="outlined"
                  />
                )}
                {(results.summary.critical_vulnerabilities || 0) > 0 && (
                  <Chip
                    icon={<BugReportIcon />}
                    label={`${results.summary.critical_vulnerabilities} Critical CVEs`}
                    color="error"
                    variant="outlined"
                  />
                )}
              </Box>
            </CardContent>
          </Card>

          {/* Host Results */}
          <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
            Detailed Results
          </Typography>
          {results.results.map((result, index) => (
            <Accordion
              key={index}
              expanded={expandedHost === `${result.host}:${result.port}`}
              onChange={() =>
                setExpandedHost(
                  expandedHost === `${result.host}:${result.port}`
                    ? null
                    : `${result.host}:${result.port}`
                )
              }
              sx={{ mb: 2 }}
            >
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  {result.has_ssl ? (
                    result.findings.length === 0 ? (
                      <CheckCircleIcon sx={{ color: "#10b981" }} />
                    ) : result.findings.some((f) => f.severity === "critical") ? (
                      <ErrorIcon sx={{ color: "#dc2626" }} />
                    ) : (
                      <WarningIcon sx={{ color: "#ca8a04" }} />
                    )
                  ) : (
                    <ErrorIcon sx={{ color: "#dc2626" }} />
                  )}
                  <Box sx={{ flex: 1 }}>
                    <Typography fontWeight={600}>
                      {result.host}:{result.port}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {result.has_ssl
                        ? result.certificate?.subject || "SSL Enabled"
                        : result.error || "SSL Not Available"}
                    </Typography>
                  </Box>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    {result.findings.length > 0 && (
                      <Chip
                        label={`${result.findings.length} Issues`}
                        size="small"
                        sx={{
                          bgcolor: alpha(
                            getSeverityColor(
                              result.findings[0]?.severity || "info"
                            ),
                            0.15
                          ),
                          color: getSeverityColor(
                            result.findings[0]?.severity || "info"
                          ),
                        }}
                      />
                    )}
                    {result.supported_protocols.length > 0 && (
                      <Chip
                        label={result.supported_protocols.join(", ")}
                        size="small"
                        variant="outlined"
                      />
                    )}
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                {result.error ? (
                  <Alert severity="error">{result.error}</Alert>
                ) : (
                  <Grid container spacing={3}>
                    {/* Certificate Info */}
                    {result.certificate && (
                      <Grid item xs={12} md={6}>
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                          Certificate Details
                        </Typography>
                        <TableContainer component={Paper} variant="outlined">
                          <Table size="small">
                            <TableBody>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Subject
                                </TableCell>
                                <TableCell>{result.certificate.subject || "N/A"}</TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Issuer
                                </TableCell>
                                <TableCell>{result.certificate.issuer || "N/A"}</TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Valid From
                                </TableCell>
                                <TableCell>
                                  {formatDate(result.certificate.not_before)}
                                </TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Valid Until
                                </TableCell>
                                <TableCell>
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    {formatDate(result.certificate.not_after)}
                                    {result.certificate.is_expired && (
                                      <Chip label="EXPIRED" size="small" color="error" />
                                    )}
                                    {!result.certificate.is_expired &&
                                      result.certificate.days_until_expiry !== null &&
                                      result.certificate.days_until_expiry < 30 && (
                                        <Chip
                                          label={`${result.certificate.days_until_expiry} days`}
                                          size="small"
                                          color="warning"
                                        />
                                      )}
                                  </Box>
                                </TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Key
                                </TableCell>
                                <TableCell>
                                  {result.certificate.key_type} {result.certificate.key_size} bits
                                </TableCell>
                              </TableRow>
                              <TableRow>
                                <TableCell component="th" sx={{ fontWeight: 600 }}>
                                  Signature
                                </TableCell>
                                <TableCell>
                                  {result.certificate.signature_algorithm || "N/A"}
                                </TableCell>
                              </TableRow>
                              {result.certificate.san.length > 0 && (
                                <TableRow>
                                  <TableCell component="th" sx={{ fontWeight: 600 }}>
                                    SANs
                                  </TableCell>
                                  <TableCell>
                                    {result.certificate.san.slice(0, 5).join(", ")}
                                    {result.certificate.san.length > 5 &&
                                      ` (+${result.certificate.san.length - 5} more)`}
                                  </TableCell>
                                </TableRow>
                              )}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Grid>
                    )}

                    {/* Protocol & Cipher Info */}
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                        Supported Protocols
                      </Typography>
                      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                        {result.supported_protocols.map((proto) => (
                          <Chip
                            key={proto}
                            label={proto}
                            size="small"
                            color={
                              proto.includes("1.0") || proto.includes("1.1") || proto.includes("SSL")
                                ? "error"
                                : "success"
                            }
                            variant="outlined"
                          />
                        ))}
                      </Box>

                      <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                        Cipher Suites ({result.cipher_suites.length})
                      </Typography>
                      <Paper
                        variant="outlined"
                        sx={{
                          p: 1,
                          maxHeight: 150,
                          overflow: "auto",
                          fontSize: "0.75rem",
                          fontFamily: "monospace",
                        }}
                      >
                        {result.cipher_suites.map((cipher, i) => (
                          <Box
                            key={i}
                            sx={{
                              color: cipher.includes("NULL") ||
                                cipher.includes("RC4") ||
                                cipher.includes("DES") ||
                                cipher.includes("MD5")
                                ? "#dc2626"
                                : "inherit",
                            }}
                          >
                            {cipher}
                          </Box>
                        ))}
                      </Paper>
                    </Grid>

                    {/* Certificate Chain Info */}
                    {result.chain_info && (
                      <Grid item xs={12}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <LinkIcon fontSize="small" />
                          Certificate Chain
                        </Typography>
                        <Paper variant="outlined" sx={{ p: 2 }}>
                          <Grid container spacing={2}>
                            <Grid item xs={6} sm={3}>
                              <Typography variant="caption" color="text.secondary">Chain Length</Typography>
                              <Typography fontWeight={600}>{result.chain_info.chain_length}</Typography>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Typography variant="caption" color="text.secondary">Complete</Typography>
                              <Typography fontWeight={600}>
                                {result.chain_info.is_complete ? (
                                  <Chip label="Yes" size="small" color="success" />
                                ) : (
                                  <Chip label="No" size="small" color="error" />
                                )}
                              </Typography>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Typography variant="caption" color="text.secondary">Trusted</Typography>
                              <Typography fontWeight={600}>
                                {result.chain_info.is_trusted ? (
                                  <Chip label="Yes" size="small" color="success" />
                                ) : (
                                  <Chip label="No" size="small" color="warning" />
                                )}
                              </Typography>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Typography variant="caption" color="text.secondary">Root CA</Typography>
                              <Typography fontWeight={600} sx={{ fontSize: "0.85rem" }}>
                                {result.chain_info.root_ca || "Unknown"}
                              </Typography>
                            </Grid>
                          </Grid>
                          {result.chain_info.chain_errors && result.chain_info.chain_errors.length > 0 && (
                            <Alert severity="warning" sx={{ mt: 2 }}>
                              <Typography variant="subtitle2" fontWeight={600}>Chain Issues:</Typography>
                              <ul style={{ margin: 0, paddingLeft: 20 }}>
                                {result.chain_info.chain_errors.map((err, i) => (
                                  <li key={i}><Typography variant="body2">{err}</Typography></li>
                                ))}
                              </ul>
                            </Alert>
                          )}
                        </Paper>
                      </Grid>
                    )}

                    {/* Vulnerabilities */}
                    {result.vulnerabilities && result.vulnerabilities.length > 0 && (
                      <Grid item xs={12}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                          <BugReportIcon fontSize="small" color="error" />
                          Known Vulnerabilities ({result.vulnerabilities.length})
                        </Typography>
                        <TableContainer component={Paper} variant="outlined">
                          <Table size="small">
                            <TableHead>
                              <TableRow sx={{ bgcolor: alpha("#dc2626", 0.1) }}>
                                <TableCell sx={{ fontWeight: 600 }}>Vulnerability</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>CVE</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>Severity</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>CVSS</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>Exploit</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {result.vulnerabilities.map((vuln, i) => (
                                <TableRow key={i} sx={{ "&:hover": { bgcolor: alpha("#dc2626", 0.05) } }}>
                                  <TableCell>
                                    <Tooltip title={vuln.description}>
                                      <Typography fontWeight={500}>{vuln.name}</Typography>
                                    </Tooltip>
                                    {vuln.affected && (
                                      <Typography variant="caption" color="text.secondary" display="block">
                                        {vuln.affected}
                                      </Typography>
                                    )}
                                  </TableCell>
                                  <TableCell>
                                    <Chip 
                                      label={vuln.cve} 
                                      size="small" 
                                      variant="outlined"
                                      sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}
                                    />
                                  </TableCell>
                                  <TableCell>
                                    <Chip
                                      label={vuln.severity.toUpperCase()}
                                      size="small"
                                      sx={{
                                        bgcolor: alpha(getSeverityColor(vuln.severity), 0.15),
                                        color: getSeverityColor(vuln.severity),
                                        fontWeight: 600,
                                      }}
                                    />
                                  </TableCell>
                                  <TableCell>
                                    <Typography fontWeight={600} color={vuln.cvss >= 9 ? "#dc2626" : vuln.cvss >= 7 ? "#ea580c" : "#ca8a04"}>
                                      {vuln.cvss}
                                    </Typography>
                                  </TableCell>
                                  <TableCell>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                      {vuln.is_exploitable && (
                                        <Tooltip title="Exploitable">
                                          <GppBadIcon fontSize="small" color="error" />
                                        </Tooltip>
                                      )}
                                      <Typography variant="caption">
                                        {vuln.exploit_difficulty}
                                      </Typography>
                                    </Box>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Grid>
                    )}

                    {/* Findings */}
                    {result.findings.length > 0 && (
                      <Grid item xs={12}>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2 }}>
                          Security Findings
                        </Typography>
                        {result.findings.map((finding, i) => (
                          <Paper
                            key={i}
                            sx={{
                              p: 2,
                              mb: 2,
                              borderLeft: `4px solid ${getSeverityColor(finding.severity)}`,
                              bgcolor: alpha(getSeverityColor(finding.severity), 0.05),
                            }}
                          >
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                              {getSeverityIcon(finding.severity)}
                              <Typography fontWeight={600}>{finding.title}</Typography>
                              <Chip
                                label={finding.severity.toUpperCase()}
                                size="small"
                                sx={{
                                  bgcolor: alpha(getSeverityColor(finding.severity), 0.15),
                                  color: getSeverityColor(finding.severity),
                                  fontWeight: 600,
                                }}
                              />
                              {finding.cve && (
                                <Chip label={finding.cve} size="small" variant="outlined" />
                              )}
                            </Box>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              {finding.description}
                            </Typography>
                            {finding.recommendation && (
                              <Alert severity="info" icon={<SecurityIcon />} sx={{ mt: 1 }}>
                                <Typography variant="body2">
                                  <strong>Recommendation:</strong> {finding.recommendation}
                                </Typography>
                              </Alert>
                            )}
                          </Paper>
                        ))}
                      </Grid>
                    )}
                  </Grid>
                )}
              </AccordionDetails>
            </Accordion>
          ))}

          {/* AI Exploitation Analysis */}
          {results.ai_analysis && (
            <Card sx={{ mt: 3 }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <GppBadIcon sx={{ color: "#dc2626" }} />
                  <Typography variant="h6" fontWeight={600}>
                    AI Exploitation Analysis
                  </Typography>
                  <Chip 
                    label="⚠️ OFFENSIVE SECURITY" 
                    size="small" 
                    sx={{ bgcolor: alpha("#dc2626", 0.15), color: "#dc2626", fontWeight: 600, ml: 1 }}
                  />
                </Box>
                
                {results.ai_analysis.error ? (
                  <Alert severity="warning">{results.ai_analysis.error}</Alert>
                ) : results.ai_analysis.structured_report ? (
                  <Box>
                    {/* Risk Summary */}
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
                      <Typography>Overall Risk:</Typography>
                      <Chip
                        label={results.ai_analysis.structured_report.overall_risk_level}
                        sx={{
                          bgcolor: alpha(
                            getSeverityColor(results.ai_analysis.structured_report.overall_risk_level?.toLowerCase() || "info"),
                            0.15
                          ),
                          color: getSeverityColor(results.ai_analysis.structured_report.overall_risk_level?.toLowerCase() || "info"),
                          fontWeight: 600,
                        }}
                      />
                      {results.ai_analysis.structured_report.risk_score !== undefined && (
                        <Typography color="text.secondary">
                          Score: {results.ai_analysis.structured_report.risk_score}/100
                        </Typography>
                      )}
                    </Box>
                    
                    {/* Executive Summary */}
                    {results.ai_analysis.structured_report.executive_summary && (
                      <Alert severity="info" sx={{ mb: 3 }}>
                        <Typography variant="body2">
                          {results.ai_analysis.structured_report.executive_summary}
                        </Typography>
                      </Alert>
                    )}
                    
                    {/* Tabs for different AI sections */}
                    <Tabs value={aiTabValue} onChange={(_, v) => setAiTabValue(v)} sx={{ mb: 2 }}>
                      <Tab label="🎯 Exploitation Scenarios" />
                      <Tab label="� Certificate & Protocol Attacks" />
                      <Tab label="🔗 Attack Chain" />
                      <Tab label="⚡ Quick Wins" />
                    </Tabs>
                    
                    {/* Exploitation Scenarios Tab */}
                    {aiTabValue === 0 && (
                      <Box>
                        {Array.isArray(results.ai_analysis.structured_report?.exploitation_scenarios) && 
                         results.ai_analysis.structured_report.exploitation_scenarios.length > 0 ? (
                          results.ai_analysis.structured_report.exploitation_scenarios.map((scenario: any, i: number) => (
                            <Paper
                              key={i}
                              sx={{
                                p: 2,
                                mb: 2,
                                borderLeft: `4px solid #dc2626`,
                                bgcolor: alpha("#dc2626", 0.03),
                              }}
                            >
                              <Typography variant="subtitle1" fontWeight={700} sx={{ mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                                <GppBadIcon fontSize="small" color="error" />
                                {scenario.title || scenario.attack_name || "Attack Scenario"}
                              </Typography>
                              <Grid container spacing={2} sx={{ mb: 2 }}>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Target</Typography>
                                  <Typography variant="body2" fontWeight={500}>{scenario.target || scenario.target_vulnerability || "N/A"}</Typography>
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Vulnerability</Typography>
                                  <Typography variant="body2" fontWeight={500}>{scenario.vulnerability || "N/A"}</Typography>
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Difficulty</Typography>
                                  <Chip 
                                    label={scenario.difficulty || scenario.exploit_difficulty || "Unknown"} 
                                    size="small" 
                                    color={(scenario.difficulty || scenario.exploit_difficulty) === "Easy" ? "error" : (scenario.difficulty || scenario.exploit_difficulty) === "Medium" ? "warning" : "default"}
                                  />
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Detection Risk</Typography>
                                  <Chip 
                                    label={scenario.detection_risk || "Unknown"} 
                                    size="small" 
                                    color={scenario.detection_risk === "Low" ? "success" : scenario.detection_risk === "Medium" ? "warning" : "error"}
                                    variant="outlined"
                                  />
                                </Grid>
                              </Grid>
                              
                              {scenario.prerequisites && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 0.5 }}>Prerequisites:</Typography>
                                  <Typography variant="body2" color="text.secondary">{scenario.prerequisites}</Typography>
                                </Box>
                              )}
                              
                              {Array.isArray(scenario.attack_steps) && scenario.attack_steps.length > 0 && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>Attack Steps:</Typography>
                                  <ol style={{ margin: 0, paddingLeft: 20 }}>
                                    {scenario.attack_steps.map((step: string, j: number) => (
                                      <li key={j}><Typography variant="body2">{step}</Typography></li>
                                    ))}
                                  </ol>
                                </Box>
                              )}
                              
                              {Array.isArray(scenario.tools) && scenario.tools.length > 0 && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>Tools:</Typography>
                                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                                    {scenario.tools.map((tool: string, j: number) => (
                                      <Chip key={j} icon={<TerminalIcon />} label={tool} size="small" variant="outlined" />
                                    ))}
                                  </Box>
                                </Box>
                              )}
                              
                              {scenario.expected_outcome && (
                                <Box>
                                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 0.5 }}>Expected Outcome:</Typography>
                                  <Typography variant="body2" color="error.main" fontWeight={500}>{scenario.expected_outcome}</Typography>
                                </Box>
                              )}
                            </Paper>
                          ))
                        ) : (
                          <Alert severity="info">No exploitation scenarios available in AI analysis.</Alert>
                        )}
                      </Box>
                    )}
                    
                    {/* Certificate & Protocol Attacks Tab */}
                    {aiTabValue === 1 && (
                      <Box>
                        {/* Certificate Attacks */}
                        {results.ai_analysis.structured_report?.certificate_attacks && (
                          <Box sx={{ mb: 3 }}>
                            <Typography variant="h6" fontWeight={700} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                              <SecurityIcon color="warning" /> Certificate Attacks
                            </Typography>
                            {results.ai_analysis.structured_report.certificate_attacks.summary && (
                              <Alert severity="warning" sx={{ mb: 2 }}>
                                <Typography variant="body2">{results.ai_analysis.structured_report.certificate_attacks.summary}</Typography>
                              </Alert>
                            )}
                            {Array.isArray(results.ai_analysis.structured_report.certificate_attacks.attacks) && 
                             results.ai_analysis.structured_report.certificate_attacks.attacks.length > 0 ? (
                              <Grid container spacing={2}>
                                {results.ai_analysis.structured_report.certificate_attacks.attacks.map((attack: any, i: number) => (
                                  <Grid item xs={12} sm={6} key={i}>
                                    <Paper variant="outlined" sx={{ p: 2, borderLeft: `4px solid #f59e0b` }}>
                                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                                        <Typography variant="subtitle2" fontWeight={700}>{attack.type}</Typography>
                                        <Chip 
                                          label={attack.feasibility} 
                                          size="small" 
                                          color={attack.feasibility === "High" ? "error" : attack.feasibility === "Medium" ? "warning" : "default"}
                                        />
                                      </Box>
                                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{attack.description}</Typography>
                                      {attack.target && <Chip label={`Target: ${attack.target}`} size="small" variant="outlined" />}
                                    </Paper>
                                  </Grid>
                                ))}
                              </Grid>
                            ) : (
                              <Typography variant="body2" color="text.secondary">No certificate attacks identified.</Typography>
                            )}
                          </Box>
                        )}
                        
                        {/* Protocol Attacks */}
                        {results.ai_analysis.structured_report?.protocol_attacks && (
                          <Box>
                            <Typography variant="h6" fontWeight={700} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                              <BugReportIcon color="error" /> Protocol Attacks
                            </Typography>
                            {results.ai_analysis.structured_report.protocol_attacks.summary && (
                              <Alert severity="error" sx={{ mb: 2 }}>
                                <Typography variant="body2">{results.ai_analysis.structured_report.protocol_attacks.summary}</Typography>
                              </Alert>
                            )}
                            {Array.isArray(results.ai_analysis.structured_report.protocol_attacks.attacks) && 
                             results.ai_analysis.structured_report.protocol_attacks.attacks.length > 0 ? (
                              <TableContainer component={Paper} variant="outlined">
                                <Table size="small">
                                  <TableHead>
                                    <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                                      <TableCell sx={{ fontWeight: 600 }}>Vulnerability</TableCell>
                                      <TableCell sx={{ fontWeight: 600 }}>Target</TableCell>
                                      <TableCell sx={{ fontWeight: 600 }}>Exploitation Method</TableCell>
                                      <TableCell sx={{ fontWeight: 600 }}>Tools</TableCell>
                                    </TableRow>
                                  </TableHead>
                                  <TableBody>
                                    {results.ai_analysis.structured_report.protocol_attacks.attacks.map((attack: any, i: number) => (
                                      <TableRow key={i}>
                                        <TableCell>
                                          <Chip label={attack.vulnerability} size="small" color="error" />
                                        </TableCell>
                                        <TableCell>{attack.target}</TableCell>
                                        <TableCell>
                                          <Typography variant="body2">{attack.exploitation_method}</Typography>
                                        </TableCell>
                                        <TableCell>
                                          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                                            {Array.isArray(attack.tools_required) && attack.tools_required.map((tool: string, j: number) => (
                                              <Chip key={j} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                                            ))}
                                          </Box>
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </TableContainer>
                            ) : (
                              <Typography variant="body2" color="text.secondary">No protocol attacks identified.</Typography>
                            )}
                          </Box>
                        )}
                        
                        {!results.ai_analysis.structured_report?.certificate_attacks && 
                         !results.ai_analysis.structured_report?.protocol_attacks && (
                          <Alert severity="info">No certificate or protocol attack analysis available.</Alert>
                        )}
                      </Box>
                    )}
                    
                    {/* Attack Chain Tab */}
                    {aiTabValue === 2 && (
                      <Box>
                        {results.ai_analysis.structured_report?.recommended_attack_chain ? (
                          <>
                            {results.ai_analysis.structured_report.recommended_attack_chain.description && (
                              <Alert severity="warning" sx={{ mb: 3 }}>
                                <Typography variant="body2" fontWeight={600}>
                                  {results.ai_analysis.structured_report.recommended_attack_chain.description}
                                </Typography>
                              </Alert>
                            )}
                            {Array.isArray(results.ai_analysis.structured_report.recommended_attack_chain.steps) && 
                             results.ai_analysis.structured_report.recommended_attack_chain.steps.length > 0 && (
                              <Box sx={{ mb: 3 }}>
                                <Typography variant="h6" fontWeight={700} sx={{ mb: 2 }}>Attack Chain Steps</Typography>
                                {results.ai_analysis.structured_report.recommended_attack_chain.steps.map((step: any, i: number) => (
                                  <Paper
                                    key={i}
                                    sx={{
                                      p: 2,
                                      mb: 2,
                                      borderLeft: `4px solid ${i === 0 ? "#10b981" : "#6366f1"}`,
                                      display: "flex",
                                      alignItems: "flex-start",
                                      gap: 2,
                                    }}
                                  >
                                    <Chip 
                                      label={step.order || i + 1} 
                                      size="small" 
                                      sx={{ 
                                        bgcolor: i === 0 ? "#10b981" : "#6366f1", 
                                        color: "white", 
                                        fontWeight: 700,
                                        minWidth: 32,
                                      }} 
                                    />
                                    <Box sx={{ flex: 1 }}>
                                      <Typography variant="subtitle2" fontWeight={700}>{step.action}</Typography>
                                      {step.target && (
                                        <Typography variant="body2" color="text.secondary">Target: {step.target}</Typography>
                                      )}
                                      {step.expected_result && (
                                        <Typography variant="body2" color="success.main" sx={{ mt: 0.5 }}>
                                          → {step.expected_result}
                                        </Typography>
                                      )}
                                    </Box>
                                  </Paper>
                                ))}
                              </Box>
                            )}
                            {results.ai_analysis.structured_report.recommended_attack_chain.total_effort && (
                              <Chip 
                                icon={<TargetIcon />}
                                label={`Total Effort: ${results.ai_analysis.structured_report.recommended_attack_chain.total_effort}`}
                                color="primary"
                                variant="outlined"
                              />
                            )}
                          </>
                        ) : (
                          <Alert severity="info">No recommended attack chain available in AI analysis.</Alert>
                        )}
                        
                        {/* Recommendations */}
                        {Array.isArray(results.ai_analysis.structured_report?.recommendations) && 
                         results.ai_analysis.structured_report.recommendations.length > 0 && (
                          <Box sx={{ mt: 3 }}>
                            <Typography variant="h6" fontWeight={700} sx={{ mb: 2 }}>Exploitation Recommendations</Typography>
                            <Grid container spacing={2}>
                              {results.ai_analysis.structured_report.recommendations.map((rec: any, i: number) => (
                                <Grid item xs={12} sm={6} key={i}>
                                  <Paper variant="outlined" sx={{ p: 2, height: "100%" }}>
                                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                                      <Chip 
                                        label={rec.priority} 
                                        size="small" 
                                        color={rec.priority === "Immediate" || rec.priority === "High" ? "error" : rec.priority === "Medium" ? "warning" : "default"}
                                      />
                                    </Box>
                                    <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 0.5 }}>{rec.action}</Typography>
                                    <Typography variant="body2" color="text.secondary">{rec.rationale}</Typography>
                                  </Paper>
                                </Grid>
                              ))}
                            </Grid>
                          </Box>
                        )}
                      </Box>
                    )}
                    
                    {/* Quick Wins Tab */}
                    {aiTabValue === 3 && (
                      <Box>
                        <Alert severity="success" sx={{ mb: 2 }}>
                          <Typography variant="body2" fontWeight={600}>
                            These are low-hanging fruit that can be exploited with minimal effort:
                          </Typography>
                        </Alert>
                        {Array.isArray(results.ai_analysis.structured_report?.quick_wins) && 
                         results.ai_analysis.structured_report.quick_wins.length > 0 ? (
                          <Grid container spacing={2}>
                            {results.ai_analysis.structured_report.quick_wins.map((win: any, i: number) => (
                              <Grid item xs={12} sm={6} key={i}>
                                <Paper
                                  variant="outlined"
                                  sx={{
                                    p: 2,
                                    borderLeft: `4px solid #10b981`,
                                    height: "100%",
                                  }}
                                >
                                  {typeof win === "string" ? (
                                    <Typography variant="body2">{win}</Typography>
                                  ) : (
                                    <>
                                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                                        <Typography variant="subtitle2" fontWeight={700}>{win.attack || "Quick Win"}</Typography>
                                        {win.target && <Chip label={win.target} size="small" variant="outlined" />}
                                      </Box>
                                      {win.impact && (
                                        <Typography variant="body2" color="error.main" sx={{ mb: 1 }}>
                                          Impact: {win.impact}
                                        </Typography>
                                      )}
                                      {win.command && (
                                        <Paper sx={{ p: 1, bgcolor: "#1e1e1e", borderRadius: 1, mt: 1 }}>
                                          <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#10b981", fontSize: "0.8rem" }}>
                                            $ {win.command}
                                          </Typography>
                                        </Paper>
                                      )}
                                    </>
                                  )}
                                </Paper>
                              </Grid>
                            ))}
                          </Grid>
                        ) : (
                          <Alert severity="info">No quick wins identified in AI analysis.</Alert>
                        )}
                      </Box>
                    )}
                  </Box>
                ) : (
                  <Typography color="text.secondary">No AI analysis available</Typography>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </Box>
  );
};

export default SSLScannerPage;
