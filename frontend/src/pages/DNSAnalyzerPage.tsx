import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Button,
  CircularProgress,
  Alert,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress,
  Tooltip,
  Card,
  CardContent,
  Grid,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  Tabs,
  Tab,
  IconButton,
  Breadcrumbs,
  Link as MuiLink,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Snackbar,
  Collapse,
} from "@mui/material";
import { Link } from "react-router-dom";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import DnsIcon from "@mui/icons-material/Dns";
import SearchIcon from "@mui/icons-material/Search";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import InfoIcon from "@mui/icons-material/Info";
import HubIcon from "@mui/icons-material/Hub";
import HistoryIcon from "@mui/icons-material/History";
import DeleteIcon from "@mui/icons-material/Delete";
import VisibilityIcon from "@mui/icons-material/Visibility";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import EmailIcon from "@mui/icons-material/Email";
import StorageIcon from "@mui/icons-material/Storage";
import PublicIcon from "@mui/icons-material/Public";
import SendIcon from "@mui/icons-material/Send";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import PersonIcon from "@mui/icons-material/Person";
import ChatIcon from "@mui/icons-material/Chat";
import LanguageIcon from "@mui/icons-material/Language";
import GppBadIcon from "@mui/icons-material/GppBad";
import GppGoodIcon from "@mui/icons-material/GppGood";
import SubdirectoryArrowRightIcon from "@mui/icons-material/SubdirectoryArrowRight";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import StopIcon from "@mui/icons-material/Stop";
import ManageSearchIcon from "@mui/icons-material/ManageSearch";
import BusinessIcon from "@mui/icons-material/Business";
import CalendarTodayIcon from "@mui/icons-material/CalendarToday";
import RouterIcon from "@mui/icons-material/Router";
import ReactMarkdown from "react-markdown";
import ForceGraph2D from "react-force-graph-2d";
import {
  apiClient,
  DNSScanType,
  DNSReconResult,
  SavedDNSReport,
  WhoisDomainResult,
  WhoisIPResult,
} from "../api/client";

// Severity colors
const severityColors: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

// Record type colors
const recordTypeColors: Record<string, string> = {
  A: "#3b82f6",
  AAAA: "#06b6d4",
  MX: "#8b5cf6",
  NS: "#f59e0b",
  TXT: "#10b981",
  SOA: "#ec4899",
  CNAME: "#6366f1",
  SRV: "#f97316",
  CAA: "#dc2626",
  PTR: "#84cc16",
};

// Phase labels for progress
const phaseLabels: Record<string, string> = {
  records: "Querying DNS Records",
  subdomains: "Enumerating Subdomains",
  zone_transfer: "Testing Zone Transfer",
  security: "Analyzing Security",
  reverse_dns: "Reverse DNS Lookups",
  ai_analysis: "AI Analysis",
  complete: "Complete",
};

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

interface ScanProgress {
  phase: string;
  progress: number;
  message: string;
}

// Copy to clipboard helper
function useCopyToClipboard() {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, []);

  return { copy, copied };
}

// Copy button component
function CopyButton({ text, size = "small" }: { text: string; size?: "small" | "medium" }) {
  const { copy, copied } = useCopyToClipboard();
  
  return (
    <Tooltip title={copied ? "Copied!" : "Copy to clipboard"}>
      <IconButton
        size={size}
        onClick={(e) => {
          e.stopPropagation();
          copy(text);
        }}
        sx={{ 
          opacity: 0.6, 
          "&:hover": { opacity: 1 },
          color: copied ? "success.main" : "inherit",
        }}
      >
        <ContentCopyIcon fontSize={size === "small" ? "small" : "medium"} />
      </IconButton>
    </Tooltip>
  );
}

// Network graph component
function DNSNetworkGraph({ result }: { result: DNSReconResult }) {
  const theme = useTheme();
  const graphRef = useRef<any>();
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });
  
  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const { width } = containerRef.current.getBoundingClientRect();
        setDimensions({ width: width || 800, height: 500 });
      }
    };
    
    updateDimensions();
    window.addEventListener("resize", updateDimensions);
    return () => window.removeEventListener("resize", updateDimensions);
  }, []);
  
  // Build graph data
  const graphData = useMemo(() => {
    const nodes: Array<{ id: string; name: string; type: string; color: string; size: number }> = [];
    const links: Array<{ source: string; target: string; label?: string }> = [];
    const nodeSet = new Set<string>();
    
    // Add domain as central node
    const domainId = `domain:${result.domain}`;
    nodes.push({
      id: domainId,
      name: result.domain,
      type: "domain",
      color: "#f59e0b",
      size: 20,
    });
    nodeSet.add(domainId);
    
    // Add nameservers
    result.nameservers.forEach((ns) => {
      const nsId = `ns:${ns}`;
      if (!nodeSet.has(nsId)) {
        nodes.push({
          id: nsId,
          name: ns,
          type: "nameserver",
          color: "#f59e0b",
          size: 12,
        });
        nodeSet.add(nsId);
      }
      links.push({ source: domainId, target: nsId, label: "NS" });
    });
    
    // Add mail servers
    result.mail_servers.forEach((mx) => {
      const mxId = `mx:${mx.server}`;
      if (!nodeSet.has(mxId)) {
        nodes.push({
          id: mxId,
          name: mx.server,
          type: "mail",
          color: "#8b5cf6",
          size: 12,
        });
        nodeSet.add(mxId);
      }
      links.push({ source: domainId, target: mxId, label: `MX:${mx.priority}` });
    });
    
    // Add IPs from main domain
    result.records
      .filter((r) => r.record_type === "A" || r.record_type === "AAAA")
      .forEach((record) => {
        const ipId = `ip:${record.value}`;
        if (!nodeSet.has(ipId)) {
          nodes.push({
            id: ipId,
            name: record.value,
            type: "ip",
            color: "#10b981",
            size: 10,
          });
          nodeSet.add(ipId);
        }
        links.push({ source: domainId, target: ipId, label: record.record_type });
      });
    
    // Add subdomains (limit to 30 for performance)
    result.subdomains.slice(0, 30).forEach((sub) => {
      const subId = `subdomain:${sub.full_domain}`;
      if (!nodeSet.has(subId)) {
        nodes.push({
          id: subId,
          name: sub.subdomain,
          type: "subdomain",
          color: "#3b82f6",
          size: 8,
        });
        nodeSet.add(subId);
        links.push({ source: domainId, target: subId });
      }
      
      // Add IPs for subdomain
      sub.ip_addresses.forEach((ip) => {
        const ipId = `ip:${ip}`;
        if (!nodeSet.has(ipId)) {
          nodes.push({
            id: ipId,
            name: ip,
            type: "ip",
            color: "#10b981",
            size: 10,
          });
          nodeSet.add(ipId);
        }
        links.push({ source: subId, target: ipId });
      });
      
      // Add CNAME
      if (sub.cname) {
        const cnameId = `cname:${sub.cname}`;
        if (!nodeSet.has(cnameId)) {
          nodes.push({
            id: cnameId,
            name: sub.cname,
            type: "cname",
            color: "#6366f1",
            size: 8,
          });
          nodeSet.add(cnameId);
        }
        links.push({ source: subId, target: cnameId, label: "CNAME" });
      }
    });
    
    return { nodes, links };
  }, [result]);
  
  // Zoom to fit on load
  useEffect(() => {
    if (graphRef.current && graphData.nodes.length > 0) {
      setTimeout(() => {
        graphRef.current?.zoomToFit(400, 50);
      }, 500);
    }
  }, [graphData, dimensions]);
  
  return (
    <Box 
      ref={containerRef}
      sx={{ height: 500, border: `1px solid ${alpha(theme.palette.divider, 0.2)}`, borderRadius: 2, overflow: "hidden", position: "relative" }}
    >
      {dimensions.width > 0 && (
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          nodeLabel={(node: any) => `${node.type}: ${node.name}`}
          nodeColor={(node: any) => node.color}
          nodeVal={(node: any) => node.size}
          linkColor={() => alpha(theme.palette.text.primary, 0.2)}
          linkWidth={1}
          linkDirectionalParticles={1}
          linkDirectionalParticleWidth={2}
          nodeCanvasObject={(node: any, ctx, globalScale) => {
            const label = node.name.length > 20 ? node.name.slice(0, 18) + "..." : node.name;
            const fontSize = Math.max(10 / globalScale, 3);
            ctx.font = `${fontSize}px Sans-Serif`;
            
            // Draw node
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.size / 2, 0, 2 * Math.PI);
            ctx.fillStyle = node.color;
            ctx.fill();
            
            // Draw label
            ctx.fillStyle = theme.palette.text.primary;
            ctx.textAlign = "center";
            ctx.textBaseline = "top";
            ctx.fillText(label, node.x, node.y + node.size / 2 + 2);
          }}
          backgroundColor="transparent"
          width={dimensions.width}
          height={dimensions.height}
        />
      )}
      
      {/* Legend */}
      <Box sx={{ position: "absolute", bottom: 16, left: 16, display: "flex", gap: 2, flexWrap: "wrap", bgcolor: alpha(theme.palette.background.paper, 0.9), p: 1, borderRadius: 1 }}>
        {[
          { type: "Domain", color: "#f59e0b" },
          { type: "Subdomain", color: "#3b82f6" },
          { type: "IP", color: "#10b981" },
          { type: "Mail", color: "#8b5cf6" },
          { type: "NS", color: "#f59e0b" },
          { type: "CNAME", color: "#6366f1" },
        ].map((item) => (
          <Box key={item.type} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <Box sx={{ width: 12, height: 12, borderRadius: "50%", bgcolor: item.color }} />
            <Typography variant="caption">{item.type}</Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

export default function DNSAnalyzerPage() {
  const theme = useTheme();
  
  // State
  const [activeTab, setActiveTab] = useState(0);
  const [domain, setDomain] = useState("");
  const [domainValid, setDomainValid] = useState<boolean | null>(null);
  const [domainError, setDomainError] = useState<string | null>(null);
  const [scanTypes, setScanTypes] = useState<DNSScanType[]>([]);
  const [selectedScanType, setSelectedScanType] = useState("standard");
  const [customSubdomains, setCustomSubdomains] = useState("");
  const [scanTitle, setScanTitle] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<DNSReconResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Progress state
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const scanControllerRef = useRef<AbortController | null>(null);
  
  // Snackbar for copy feedback
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string }>({ open: false, message: "" });
  
  // Saved reports
  const [savedReports, setSavedReports] = useState<SavedDNSReport[]>([]);
  const [savedReportsTotal, setSavedReportsTotal] = useState(0);
  const [loadingReports, setLoadingReports] = useState(false);
  
  // AI Chat
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  
  // Graph view
  const [showGraph, setShowGraph] = useState(false);

  // WHOIS Lookup state
  const [whoisTarget, setWhoisTarget] = useState("");
  const [whoisType, setWhoisType] = useState<"domain" | "ip">("domain");
  const [whoisLoading, setWhoisLoading] = useState(false);
  const [whoisDomainResult, setWhoisDomainResult] = useState<WhoisDomainResult | null>(null);
  const [whoisIPResult, setWhoisIPResult] = useState<WhoisIPResult | null>(null);
  const [whoisError, setWhoisError] = useState<string | null>(null);
  const [showRawWhois, setShowRawWhois] = useState(false);

  // Load scan types on mount
  useEffect(() => {
    const loadScanTypes = async () => {
      try {
        const types = await apiClient.getDnsScanTypes();
        setScanTypes(types);
      } catch (err) {
        console.error("Failed to load scan types:", err);
      }
    };
    loadScanTypes();
  }, []);

  // Load saved reports when tab changes
  const loadSavedReports = useCallback(async () => {
    setLoadingReports(true);
    try {
      const response = await apiClient.getDnsReports(0, 20);
      setSavedReports(response.reports);
      setSavedReportsTotal(response.total);
    } catch (err) {
      console.error("Failed to load reports:", err);
    } finally {
      setLoadingReports(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 1) {
      loadSavedReports();
    }
  }, [activeTab, loadSavedReports]);

  // Auto-scroll chat to bottom when new messages arrive
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages]);

  // Validate domain
  const validateDomain = async (value: string) => {
    if (!value.trim()) {
      setDomainValid(null);
      setDomainError(null);
      return;
    }
    try {
      const result = await apiClient.validateDomain(value);
      setDomainValid(result.valid);
      setDomainError(result.error || null);
    } catch {
      setDomainValid(false);
      setDomainError("Validation failed");
    }
  };

  useEffect(() => {
    const timeout = setTimeout(() => {
      if (domain) validateDomain(domain);
    }, 500);
    return () => clearTimeout(timeout);
  }, [domain]);

  // Run scan with streaming progress
  const handleRunScan = () => {
    if (!domainValid || !domain.trim()) return;
    
    setScanning(true);
    setError(null);
    setResult(null);
    setChatMessages([]);
    setProgress({ phase: "starting", progress: 0, message: "Starting scan..." });
    
    const customSubs = customSubdomains
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    scanControllerRef.current = apiClient.runDnsScanWithProgress(
      {
        domain: domain.trim(),
        scan_type: selectedScanType,
        custom_subdomains: customSubs.length > 0 ? customSubs : undefined,
        save_report: true,
        report_title: scanTitle || undefined,
        run_ai_analysis: true,
      },
      // Progress callback
      (phase, progressValue, message) => {
        setProgress({ phase, progress: progressValue, message });
      },
      // Result callback
      (scanResult) => {
        setResult(scanResult);
        setScanning(false);
        setProgress(null);
        scanControllerRef.current = null;
      },
      // Error callback
      (errorMessage) => {
        setError(errorMessage);
        setScanning(false);
        setProgress(null);
        scanControllerRef.current = null;
      }
    );
  };

  // Cancel scan
  const handleCancelScan = () => {
    if (scanControllerRef.current) {
      scanControllerRef.current.abort();
      scanControllerRef.current = null;
      setScanning(false);
      setProgress(null);
      setError("Scan cancelled");
    }
  };

  // Load saved report
  const handleLoadReport = async (reportId: number) => {
    setScanning(true);
    setError(null);
    try {
      const report = await apiClient.getDnsReport(reportId);
      setResult(report);
      setActiveTab(0);
    } catch (err: any) {
      setError(err.message || "Failed to load report");
    } finally {
      setScanning(false);
    }
  };

  // Delete report
  const handleDeleteReport = async (reportId: number) => {
    try {
      await apiClient.deleteDnsReport(reportId);
      loadSavedReports();
    } catch (err) {
      console.error("Failed to delete report:", err);
    }
  };

  // Copy all data
  const handleCopyAll = (dataType: "records" | "subdomains" | "ips") => {
    if (!result) return;
    
    let text = "";
    if (dataType === "records") {
      text = result.records.map((r) => `${r.record_type}\t${r.name}\t${r.value}`).join("\n");
    } else if (dataType === "subdomains") {
      text = result.subdomains.map((s) => s.full_domain).join("\n");
    } else if (dataType === "ips") {
      text = result.unique_ips.join("\n");
    }
    
    navigator.clipboard.writeText(text);
    setSnackbar({ open: true, message: `Copied ${dataType} to clipboard!` });
  };

  // AI Chat
  const handleSendChat = async () => {
    if (!chatInput.trim() || !result || chatLoading) return;
    
    const userMessage = chatInput.trim();
    setChatInput("");
    setChatMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setChatLoading(true);
    setChatError(null);
    
    try {
      const response = await apiClient.chatAboutDns(
        userMessage,
        {
          domain: result.domain,
          total_records: result.total_records,
          total_subdomains: result.total_subdomains,
          nameservers: result.nameservers,
          mail_servers: result.mail_servers,
          zone_transfer_possible: result.zone_transfer_possible,
          security: result.security,
          subdomains: result.subdomains.slice(0, 20),
          unique_ips: result.unique_ips.slice(0, 20),
          ai_analysis: result.ai_analysis,
        },
        chatMessages.map((m) => ({ role: m.role, content: m.content }))
      );
      
      setChatMessages((prev) => [
        ...prev,
        { role: "assistant", content: response.response },
      ]);
    } catch (err: any) {
      setChatError(err.message || "Failed to send message");
    } finally {
      setChatLoading(false);
    }
  };

  // Handle Enter key in chat
  const handleChatKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendChat();
    }
  };

  // WHOIS Lookup handler
  const handleWhoisLookup = async () => {
    if (!whoisTarget.trim()) return;
    
    setWhoisLoading(true);
    setWhoisError(null);
    setWhoisDomainResult(null);
    setWhoisIPResult(null);
    
    try {
      if (whoisType === "domain") {
        const result = await apiClient.whoisDomain(whoisTarget.trim());
        if (result.error) {
          setWhoisError(result.error);
        } else {
          setWhoisDomainResult(result);
        }
      } else {
        const result = await apiClient.whoisIP(whoisTarget.trim());
        if (result.error) {
          setWhoisError(result.error);
        } else {
          setWhoisIPResult(result);
        }
      }
    } catch (err: any) {
      setWhoisError(err.message || "WHOIS lookup failed");
    } finally {
      setWhoisLoading(false);
    }
  };

  // Copy WHOIS data to clipboard
  const handleCopyWhoisData = () => {
    let text = "";
    if (whoisDomainResult) {
      text = `Domain: ${whoisDomainResult.domain}\n`;
      if (whoisDomainResult.registrar) text += `Registrar: ${whoisDomainResult.registrar}\n`;
      if (whoisDomainResult.creation_date) text += `Created: ${whoisDomainResult.creation_date}\n`;
      if (whoisDomainResult.expiration_date) text += `Expires: ${whoisDomainResult.expiration_date}\n`;
      if (whoisDomainResult.registrant_organization) text += `Organization: ${whoisDomainResult.registrant_organization}\n`;
      if (whoisDomainResult.name_servers.length) text += `Name Servers: ${whoisDomainResult.name_servers.join(", ")}\n`;
    } else if (whoisIPResult) {
      text = `IP: ${whoisIPResult.ip_address}\n`;
      if (whoisIPResult.organization) text += `Organization: ${whoisIPResult.organization}\n`;
      if (whoisIPResult.network_name) text += `Network: ${whoisIPResult.network_name}\n`;
      if (whoisIPResult.cidr) text += `CIDR: ${whoisIPResult.cidr}\n`;
      if (whoisIPResult.asn) text += `ASN: ${whoisIPResult.asn}\n`;
      if (whoisIPResult.country) text += `Country: ${whoisIPResult.country}\n`;
    }
    navigator.clipboard.writeText(text);
    setSnackbar({ open: true, message: "WHOIS data copied to clipboard!" });
  };

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Breadcrumbs separator={<NavigateNextIcon fontSize="small" />} sx={{ mb: 2 }}>
          <MuiLink component={Link} to="/network" color="inherit" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <HubIcon fontSize="small" />
            Network Analysis
          </MuiLink>
          <Typography color="text.primary" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <DnsIcon fontSize="small" />
            DNS Reconnaissance
          </Typography>
        </Breadcrumbs>
        
        <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
          DNS Reconnaissance
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Enumerate DNS records, discover subdomains, test zone transfers, and analyze email security (SPF, DMARC, DKIM).
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          sx={{ borderBottom: 1, borderColor: "divider" }}
        >
          <Tab icon={<SearchIcon />} iconPosition="start" label="New Scan" />
          <Tab
            icon={<HistoryIcon />}
            iconPosition="start"
            label={`Saved Reports${savedReportsTotal > 0 ? ` (${savedReportsTotal})` : ""}`}
          />
          <Tab icon={<ManageSearchIcon />} iconPosition="start" label="WHOIS Lookup" />
        </Tabs>
      </Paper>

      {/* Tab 0: New Scan */}
      {activeTab === 0 && (
        <>
          {/* Scan Configuration */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" sx={{ mb: 3, fontWeight: 600 }}>
              Scan Configuration
            </Typography>
            
            <Grid container spacing={3}>
              {/* Domain Input */}
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Target Domain"
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  error={domainValid === false}
                  helperText={domainError || "Enter a domain name to scan"}
                  InputProps={{
                    startAdornment: <LanguageIcon sx={{ mr: 1, color: "text.secondary" }} />,
                    endAdornment: domainValid === true ? (
                      <Chip label="Valid" size="small" color="success" />
                    ) : null,
                  }}
                  disabled={scanning}
                />
              </Grid>

              {/* Scan Type */}
              <Grid item xs={12} md={6}>
                <FormControl fullWidth disabled={scanning}>
                  <InputLabel>Scan Type</InputLabel>
                  <Select
                    value={selectedScanType}
                    label="Scan Type"
                    onChange={(e) => setSelectedScanType(e.target.value)}
                  >
                    {scanTypes.map((type) => (
                      <MenuItem key={type.id} value={type.id}>
                        <Box sx={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
                          <Box>
                            <Typography variant="body1" fontWeight={500}>{type.name}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {type.description}
                            </Typography>
                          </Box>
                          <Chip
                            label={type.estimated_time}
                            size="small"
                            variant="outlined"
                            sx={{ ml: 2, minWidth: 80 }}
                          />
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                  <FormHelperText>
                    {scanTypes.find((t) => t.id === selectedScanType)?.description}
                  </FormHelperText>
                </FormControl>
              </Grid>

              {/* Custom Subdomains */}
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Custom Subdomains (optional)"
                  placeholder="api, dev, staging, admin..."
                  value={customSubdomains}
                  onChange={(e) => setCustomSubdomains(e.target.value)}
                  helperText="Comma-separated list of additional subdomains to check"
                  multiline
                  rows={2}
                  disabled={scanning}
                />
              </Grid>

              {/* Report Title */}
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Report Title (optional)"
                  placeholder="My DNS Scan"
                  value={scanTitle}
                  onChange={(e) => setScanTitle(e.target.value)}
                  helperText="Custom title for the saved report"
                  disabled={scanning}
                />
              </Grid>
            </Grid>

            {/* Scan Type Info */}
            {selectedScanType && !scanning && (
              <Alert severity="info" sx={{ mt: 3 }} icon={<DnsIcon />}>
                <Typography variant="body2">
                  <strong>{scanTypes.find((t) => t.id === selectedScanType)?.name}:</strong>{" "}
                  {scanTypes.find((t) => t.id === selectedScanType)?.description}
                  <br />
                  <Typography component="span" variant="caption" color="text.secondary">
                    Record types: {scanTypes.find((t) => t.id === selectedScanType)?.record_types.join(", ")}
                    {" • "}
                    Subdomains: {scanTypes.find((t) => t.id === selectedScanType)?.subdomain_count || "None"}
                    {" • "}
                    Security check: {scanTypes.find((t) => t.id === selectedScanType)?.check_security ? "Yes" : "No"}
                  </Typography>
                </Typography>
              </Alert>
            )}

            {/* Buttons */}
            <Box sx={{ mt: 3, display: "flex", gap: 2 }}>
              <Button
                variant="contained"
                size="large"
                onClick={handleRunScan}
                disabled={scanning || !domainValid || !domain.trim()}
                sx={{
                  py: 1.5,
                  px: 4,
                  background: `linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #0891b2 0%, #0e7490 100%)`,
                  },
                }}
                startIcon={scanning ? <CircularProgress size={20} color="inherit" /> : <PlayArrowIcon />}
              >
                {scanning ? "Scanning..." : "Start DNS Scan"}
              </Button>
              
              {scanning && (
                <Button
                  variant="outlined"
                  color="error"
                  size="large"
                  onClick={handleCancelScan}
                  startIcon={<StopIcon />}
                >
                  Cancel
                </Button>
              )}
            </Box>
          </Paper>

          {/* Error */}
          {error && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {error}
            </Alert>
          )}

          {/* Scanning Progress */}
          {scanning && progress && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <CircularProgress size={24} />
                <Box sx={{ flex: 1 }}>
                  <Typography variant="h6">Scanning {domain}...</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {phaseLabels[progress.phase] || progress.phase}: {progress.message}
                  </Typography>
                </Box>
                <Typography variant="h6" sx={{ minWidth: 60, textAlign: "right" }}>
                  {progress.progress}%
                </Typography>
              </Box>
              
              <LinearProgress 
                variant="determinate" 
                value={progress.progress} 
                sx={{ 
                  height: 8, 
                  borderRadius: 4,
                  bgcolor: alpha(theme.palette.primary.main, 0.1),
                  "& .MuiLinearProgress-bar": {
                    borderRadius: 4,
                    background: `linear-gradient(90deg, #06b6d4 0%, #0891b2 50%, #0e7490 100%)`,
                  },
                }} 
              />
              
              {/* Phase indicators */}
              <Box sx={{ display: "flex", justifyContent: "space-between", mt: 2, flexWrap: "wrap", gap: 1 }}>
                {["records", "subdomains", "zone_transfer", "security", "ai_analysis"].map((phase) => {
                  const isActive = progress.phase === phase;
                  const phaseOrder = ["records", "subdomains", "zone_transfer", "security", "ai_analysis"];
                  const isPast = phaseOrder.indexOf(progress.phase) > phaseOrder.indexOf(phase);
                  return (
                    <Chip
                      key={phase}
                      label={phaseLabels[phase]}
                      size="small"
                      color={isActive ? "primary" : isPast ? "success" : "default"}
                      variant={isActive ? "filled" : "outlined"}
                      icon={isPast ? <CheckCircleIcon /> : undefined}
                    />
                  );
                })}
              </Box>
            </Paper>
          )}

          {/* Results */}
          {result && !scanning && (
            <Box>
              {/* Summary Cards */}
              <Grid container spacing={3} sx={{ mb: 3 }}>
                <Grid item xs={6} sm={3}>
                  <Card sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                    <CardContent sx={{ textAlign: "center" }}>
                      <StorageIcon sx={{ fontSize: 40, color: theme.palette.primary.main, mb: 1 }} />
                      <Typography variant="h4" fontWeight={700}>{result.total_records}</Typography>
                      <Typography variant="body2" color="text.secondary">DNS Records</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Card sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <CardContent sx={{ textAlign: "center" }}>
                      <SubdirectoryArrowRightIcon sx={{ fontSize: 40, color: "#8b5cf6", mb: 1 }} />
                      <Typography variant="h4" fontWeight={700}>{result.total_subdomains}</Typography>
                      <Typography variant="body2" color="text.secondary">Subdomains Found</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Card sx={{ bgcolor: alpha("#10b981", 0.1) }}>
                    <CardContent sx={{ textAlign: "center" }}>
                      <PublicIcon sx={{ fontSize: 40, color: "#10b981", mb: 1 }} />
                      <Typography variant="h4" fontWeight={700}>{result.unique_ips.length}</Typography>
                      <Typography variant="body2" color="text.secondary">Unique IPs</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Card sx={{ bgcolor: result.zone_transfer_possible ? alpha("#dc2626", 0.1) : alpha("#22c55e", 0.1) }}>
                    <CardContent sx={{ textAlign: "center" }}>
                      {result.zone_transfer_possible ? (
                        <GppBadIcon sx={{ fontSize: 40, color: "#dc2626", mb: 1 }} />
                      ) : (
                        <GppGoodIcon sx={{ fontSize: 40, color: "#22c55e", mb: 1 }} />
                      )}
                      <Typography variant="h6" fontWeight={700}>
                        {result.zone_transfer_possible ? "VULNERABLE" : "Protected"}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">Zone Transfer</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>

              {/* Zone Transfer Warning */}
              {result.zone_transfer_possible && (
                <Alert severity="error" sx={{ mb: 3 }}>
                  <Typography variant="subtitle2" fontWeight={700}>⚠️ CRITICAL: Zone Transfer Allowed!</Typography>
                  <Typography variant="body2">
                    This domain allows DNS zone transfers (AXFR), exposing all DNS records to attackers.
                    This is a serious misconfiguration that should be fixed immediately.
                  </Typography>
                </Alert>
              )}

              {/* Network Graph Toggle */}
              <Paper sx={{ p: 2, mb: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <AccountTreeIcon />
                    DNS Network Graph
                  </Typography>
                  <Button
                    variant={showGraph ? "contained" : "outlined"}
                    onClick={() => setShowGraph(!showGraph)}
                    startIcon={<AccountTreeIcon />}
                  >
                    {showGraph ? "Hide Graph" : "Show Graph"}
                  </Button>
                </Box>
                
                {showGraph && (
                  <Box sx={{ mt: 2 }}>
                    <DNSNetworkGraph result={result} />
                  </Box>
                )}
              </Paper>

              {/* Email Security Score */}
              {result.security && (
                <Paper sx={{ p: 3, mb: 3 }}>
                  <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                    <EmailIcon />
                    Email Security Score
                  </Typography>
                  
                  <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                    <Box sx={{ position: "relative", display: "inline-flex" }}>
                      <CircularProgress
                        variant="determinate"
                        value={result.security.mail_security_score}
                        size={100}
                        thickness={8}
                        sx={{
                          color: result.security.mail_security_score >= 70 ? "#22c55e" :
                                 result.security.mail_security_score >= 40 ? "#eab308" : "#dc2626"
                        }}
                      />
                      <Box
                        sx={{
                          position: "absolute",
                          top: 0, left: 0, bottom: 0, right: 0,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                        }}
                      >
                        <Typography variant="h5" fontWeight={700}>
                          {result.security.mail_security_score}
                        </Typography>
                      </Box>
                    </Box>
                    
                    <Box sx={{ flex: 1 }}>
                      <Grid container spacing={2}>
                        <Grid item xs={6} sm={3}>
                          <Chip
                            icon={result.security.has_spf ? <CheckCircleIcon /> : <ErrorIcon />}
                            label="SPF"
                            color={result.security.has_spf ? "success" : "error"}
                            variant={result.security.has_spf ? "filled" : "outlined"}
                          />
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Chip
                            icon={result.security.has_dmarc ? <CheckCircleIcon /> : <ErrorIcon />}
                            label="DMARC"
                            color={result.security.has_dmarc ? "success" : "error"}
                            variant={result.security.has_dmarc ? "filled" : "outlined"}
                          />
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Chip
                            icon={result.security.has_dkim ? <CheckCircleIcon /> : <ErrorIcon />}
                            label="DKIM"
                            color={result.security.has_dkim ? "success" : "error"}
                            variant={result.security.has_dkim ? "filled" : "outlined"}
                          />
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Chip
                            icon={result.security.has_dnssec ? <CheckCircleIcon /> : <WarningIcon />}
                            label="DNSSEC"
                            color={result.security.has_dnssec ? "success" : "warning"}
                            variant={result.security.has_dnssec ? "filled" : "outlined"}
                          />
                        </Grid>
                      </Grid>
                    </Box>
                  </Box>

                  {/* Security Issues */}
                  {result.security.overall_issues.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: "#dc2626" }}>
                        Issues Found:
                      </Typography>
                      <List dense>
                        {result.security.overall_issues.map((issue, i) => (
                          <ListItem key={i}>
                            <ListItemIcon sx={{ minWidth: 32 }}>
                              <WarningIcon fontSize="small" color="error" />
                            </ListItemIcon>
                            <ListItemText primary={issue} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}

                  {/* Recommendations */}
                  {result.security.recommendations.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: "#3b82f6" }}>
                        Recommendations:
                      </Typography>
                      <List dense>
                        {result.security.recommendations.map((rec, i) => (
                          <ListItem key={i}>
                            <ListItemIcon sx={{ minWidth: 32 }}>
                              <InfoIcon fontSize="small" color="info" />
                            </ListItemIcon>
                            <ListItemText primary={rec} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                </Paper>
              )}

              {/* DNS Records */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, flex: 1 }}>
                    <Typography variant="h6" fontWeight={600}>
                      DNS Records ({result.total_records})
                    </Typography>
                    <Button
                      size="small"
                      startIcon={<ContentCopyIcon />}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopyAll("records");
                      }}
                    >
                      Copy All
                    </Button>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Type</TableCell>
                          <TableCell>Name</TableCell>
                          <TableCell>Value</TableCell>
                          <TableCell>TTL</TableCell>
                          <TableCell>Priority</TableCell>
                          <TableCell width={50}></TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.records.map((record, i) => (
                          <TableRow key={i} hover>
                            <TableCell>
                              <Chip
                                label={record.record_type}
                                size="small"
                                sx={{
                                  bgcolor: alpha(recordTypeColors[record.record_type] || "#888", 0.15),
                                  color: recordTypeColors[record.record_type] || "#888",
                                  fontWeight: 700,
                                  fontFamily: "monospace",
                                }}
                              />
                            </TableCell>
                            <TableCell sx={{ fontFamily: "monospace" }}>{record.name}</TableCell>
                            <TableCell sx={{ fontFamily: "monospace", maxWidth: 400, wordBreak: "break-all" }}>
                              {record.value}
                            </TableCell>
                            <TableCell>{record.ttl || "-"}</TableCell>
                            <TableCell>{record.priority ?? "-"}</TableCell>
                            <TableCell>
                              <CopyButton text={record.value} />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              {/* Nameservers & Mail */}
              <Grid container spacing={3} sx={{ mt: 0 }}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                        <DnsIcon fontSize="small" />
                        Nameservers ({result.nameservers.length})
                      </Typography>
                      <CopyButton text={result.nameservers.join("\n")} />
                    </Box>
                    {result.nameservers.map((ns, i) => (
                      <Box key={i} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                        <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                          {ns}
                        </Typography>
                        <CopyButton text={ns} />
                      </Box>
                    ))}
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                        <EmailIcon fontSize="small" />
                        Mail Servers ({result.mail_servers.length})
                      </Typography>
                      <CopyButton text={result.mail_servers.map((mx) => mx.server).join("\n")} />
                    </Box>
                    {result.mail_servers.map((mx, i) => (
                      <Box key={i} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                        <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                          {mx.priority} {mx.server}
                        </Typography>
                        <CopyButton text={mx.server} />
                      </Box>
                    ))}
                  </Paper>
                </Grid>
              </Grid>

              {/* Unique IPs */}
              {result.unique_ips.length > 0 && (
                <Paper sx={{ p: 2, mt: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                      <PublicIcon fontSize="small" />
                      Unique IP Addresses ({result.unique_ips.length})
                    </Typography>
                    <Button
                      size="small"
                      startIcon={<ContentCopyIcon />}
                      onClick={() => handleCopyAll("ips")}
                    >
                      Copy All
                    </Button>
                  </Box>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.unique_ips.map((ip, i) => (
                      <Chip
                        key={i}
                        label={ip}
                        size="small"
                        sx={{ fontFamily: "monospace" }}
                        onDelete={() => navigator.clipboard.writeText(ip)}
                        deleteIcon={<ContentCopyIcon fontSize="small" />}
                      />
                    ))}
                  </Box>
                </Paper>
              )}

              {/* Subdomains */}
              {result.subdomains.length > 0 && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, flex: 1 }}>
                      <Typography variant="h6" fontWeight={600}>
                        Subdomains Found ({result.total_subdomains})
                      </Typography>
                      <Button
                        size="small"
                        startIcon={<ContentCopyIcon />}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCopyAll("subdomains");
                        }}
                      >
                        Copy All
                      </Button>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer sx={{ maxHeight: 400 }}>
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow>
                            <TableCell>Subdomain</TableCell>
                            <TableCell>IP Addresses</TableCell>
                            <TableCell>CNAME</TableCell>
                            <TableCell width={50}></TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {result.subdomains.map((sub, i) => (
                            <TableRow key={i} hover>
                              <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>
                                {sub.full_domain}
                              </TableCell>
                              <TableCell sx={{ fontFamily: "monospace" }}>
                                {sub.ip_addresses.join(", ") || "-"}
                              </TableCell>
                              <TableCell sx={{ fontFamily: "monospace" }}>
                                {sub.cname || "-"}
                              </TableCell>
                              <TableCell>
                                <CopyButton text={sub.full_domain} />
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* AI Analysis */}
              {result.ai_analysis && !result.ai_analysis.error && (
                <Accordion sx={{ mt: 3 }} defaultExpanded>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <SmartToyIcon />
                      AI Security Analysis
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    {/* Executive Summary */}
                    {result.ai_analysis.executive_summary && (
                      <Paper sx={{ p: 2, mb: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                        <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>Executive Summary</Typography>
                        <Typography variant="body2">{result.ai_analysis.executive_summary}</Typography>
                      </Paper>
                    )}

                    {/* Key Findings */}
                    {result.ai_analysis.key_findings && result.ai_analysis.key_findings.length > 0 && (
                      <Box sx={{ mb: 3 }}>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600 }}>Key Findings</Typography>
                        {result.ai_analysis.key_findings.map((finding: any, i: number) => (
                          <Paper key={i} sx={{ p: 2, mb: 1, borderLeft: `4px solid ${severityColors[finding.severity] || "#888"}` }}>
                            <Typography variant="subtitle2" fontWeight={600}>{finding.finding}</Typography>
                            <Typography variant="body2" color="text.secondary">{finding.description}</Typography>
                            {finding.recommendation && (
                              <Typography variant="body2" sx={{ mt: 1, color: "#3b82f6" }}>
                                💡 {finding.recommendation}
                              </Typography>
                            )}
                          </Paper>
                        ))}
                      </Box>
                    )}

                    {/* Next Steps */}
                    {result.ai_analysis.next_steps && result.ai_analysis.next_steps.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>Recommended Next Steps</Typography>
                        <List dense>
                          {result.ai_analysis.next_steps.map((step: string, i: number) => (
                            <ListItem key={i}>
                              <ListItemIcon sx={{ minWidth: 32 }}>
                                <CheckCircleIcon fontSize="small" color="success" />
                              </ListItemIcon>
                              <ListItemText primary={step} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              )}
            </Box>
          )}
        </>
      )}

      {/* Tab 1: Saved Reports */}
      {activeTab === 1 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ mb: 3, fontWeight: 600 }}>
            Saved DNS Reports
          </Typography>

          {loadingReports ? (
            <Box sx={{ textAlign: "center", py: 4 }}>
              <CircularProgress />
            </Box>
          ) : savedReports.length === 0 ? (
            <Alert severity="info">
              No saved DNS reports yet. Run a scan to create one.
            </Alert>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Domain</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>Records</TableCell>
                    <TableCell>Subdomains</TableCell>
                    <TableCell>Zone Transfer</TableCell>
                    <TableCell>Email Score</TableCell>
                    <TableCell>Date</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {savedReports.map((report) => (
                    <TableRow key={report.id} hover>
                      <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>
                        {report.domain}
                      </TableCell>
                      <TableCell>{report.title || "-"}</TableCell>
                      <TableCell>{report.total_records}</TableCell>
                      <TableCell>{report.total_subdomains}</TableCell>
                      <TableCell>
                        {report.zone_transfer_possible ? (
                          <Chip label="VULNERABLE" size="small" color="error" />
                        ) : (
                          <Chip label="Protected" size="small" color="success" variant="outlined" />
                        )}
                      </TableCell>
                      <TableCell>
                        {report.mail_security_score !== undefined ? (
                          <Chip
                            label={`${report.mail_security_score}/100`}
                            size="small"
                            sx={{
                              bgcolor: alpha(
                                report.mail_security_score >= 70 ? "#22c55e" :
                                report.mail_security_score >= 40 ? "#eab308" : "#dc2626",
                                0.15
                              ),
                              color: report.mail_security_score >= 70 ? "#22c55e" :
                                     report.mail_security_score >= 40 ? "#eab308" : "#dc2626",
                            }}
                          />
                        ) : "-"}
                      </TableCell>
                      <TableCell>
                        {new Date(report.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <Tooltip title="View Report">
                          <IconButton size="small" onClick={() => handleLoadReport(report.id)}>
                            <VisibilityIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton size="small" color="error" onClick={() => handleDeleteReport(report.id)}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>
      )}

      {/* Tab 2: WHOIS Lookup */}
      {activeTab === 2 && (
        <Box>
          {/* WHOIS Input */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" sx={{ mb: 3, fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
              <ManageSearchIcon />
              WHOIS Lookup
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Look up domain registration information or IP address ownership details.
            </Typography>
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label={whoisType === "domain" ? "Domain Name" : "IP Address"}
                  placeholder={whoisType === "domain" ? "example.com" : "8.8.8.8"}
                  value={whoisTarget}
                  onChange={(e) => setWhoisTarget(e.target.value)}
                  disabled={whoisLoading}
                  onKeyDown={(e) => e.key === "Enter" && handleWhoisLookup()}
                  InputProps={{
                    startAdornment: whoisType === "domain" ? 
                      <LanguageIcon sx={{ mr: 1, color: "text.secondary" }} /> :
                      <RouterIcon sx={{ mr: 1, color: "text.secondary" }} />,
                  }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Lookup Type</InputLabel>
                  <Select
                    value={whoisType}
                    label="Lookup Type"
                    onChange={(e) => {
                      setWhoisType(e.target.value as "domain" | "ip");
                      setWhoisTarget("");
                      setWhoisDomainResult(null);
                      setWhoisIPResult(null);
                      setWhoisError(null);
                    }}
                    disabled={whoisLoading}
                  >
                    <MenuItem value="domain">Domain WHOIS</MenuItem>
                    <MenuItem value="ip">IP WHOIS</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={3}>
                <Button
                  fullWidth
                  variant="contained"
                  size="large"
                  onClick={handleWhoisLookup}
                  disabled={whoisLoading || !whoisTarget.trim()}
                  sx={{
                    height: 56,
                    background: `linear-gradient(135deg, #f59e0b 0%, #d97706 100%)`,
                    "&:hover": {
                      background: `linear-gradient(135deg, #d97706 0%, #b45309 100%)`,
                    },
                  }}
                  startIcon={whoisLoading ? <CircularProgress size={20} color="inherit" /> : <SearchIcon />}
                >
                  {whoisLoading ? "Looking up..." : "Lookup"}
                </Button>
              </Grid>
            </Grid>

            {/* Quick lookup suggestions */}
            <Box sx={{ mt: 2 }}>
              <Typography variant="caption" color="text.secondary" sx={{ mr: 1 }}>
                Quick lookups:
              </Typography>
              {whoisType === "domain" ? (
                <>
                  {["google.com", "github.com", "cloudflare.com"].map((d) => (
                    <Chip
                      key={d}
                      label={d}
                      size="small"
                      variant="outlined"
                      sx={{ mr: 1, mb: 1, cursor: "pointer" }}
                      onClick={() => setWhoisTarget(d)}
                    />
                  ))}
                </>
              ) : (
                <>
                  {["8.8.8.8", "1.1.1.1", "208.67.222.222"].map((ip) => (
                    <Chip
                      key={ip}
                      label={ip}
                      size="small"
                      variant="outlined"
                      sx={{ mr: 1, mb: 1, cursor: "pointer" }}
                      onClick={() => setWhoisTarget(ip)}
                    />
                  ))}
                </>
              )}
            </Box>
          </Paper>

          {/* WHOIS Error */}
          {whoisError && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {whoisError}
            </Alert>
          )}

          {/* Domain WHOIS Results */}
          {whoisDomainResult && !whoisDomainResult.error && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3 }}>
                <Typography variant="h6" fontWeight={600}>
                  WHOIS Results: {whoisDomainResult.domain}
                </Typography>
                <Box>
                  <Button
                    size="small"
                    startIcon={<ContentCopyIcon />}
                    onClick={handleCopyWhoisData}
                    sx={{ mr: 1 }}
                  >
                    Copy
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => setShowRawWhois(!showRawWhois)}
                  >
                    {showRawWhois ? "Hide Raw" : "Show Raw"}
                  </Button>
                </Box>
              </Box>

              <Grid container spacing={3}>
                {/* Registrar Info */}
                <Grid item xs={12} md={6}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                    <CardContent>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#3b82f6", display: "flex", alignItems: "center", gap: 1 }}>
                        <StorageIcon fontSize="small" />
                        Registrar Information
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                        <Box>
                          <Typography variant="caption" color="text.secondary">Registrar</Typography>
                          <Typography variant="body2" fontWeight={500}>{whoisDomainResult.registrar || "N/A"}</Typography>
                        </Box>
                        {whoisDomainResult.registrar_url && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Registrar URL</Typography>
                            <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
                              {whoisDomainResult.registrar_url}
                            </Typography>
                          </Box>
                        )}
                        {whoisDomainResult.dnssec && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">DNSSEC</Typography>
                            <Chip 
                              label={whoisDomainResult.dnssec} 
                              size="small" 
                              color={whoisDomainResult.dnssec.toLowerCase().includes("signed") ? "success" : "default"}
                            />
                          </Box>
                        )}
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Dates */}
                <Grid item xs={12} md={6}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                    <CardContent>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
                        <CalendarTodayIcon fontSize="small" />
                        Registration Dates
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                        <Box>
                          <Typography variant="caption" color="text.secondary">Created</Typography>
                          <Typography variant="body2" fontWeight={500}>{whoisDomainResult.creation_date || "N/A"}</Typography>
                        </Box>
                        <Box>
                          <Typography variant="caption" color="text.secondary">Expires</Typography>
                          <Typography variant="body2" fontWeight={500} sx={{ color: whoisDomainResult.expiration_date ? "#f59e0b" : "inherit" }}>
                            {whoisDomainResult.expiration_date || "N/A"}
                          </Typography>
                        </Box>
                        <Box>
                          <Typography variant="caption" color="text.secondary">Updated</Typography>
                          <Typography variant="body2" fontWeight={500}>{whoisDomainResult.updated_date || "N/A"}</Typography>
                        </Box>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Registrant Info */}
                {(whoisDomainResult.registrant_organization || whoisDomainResult.registrant_name || whoisDomainResult.registrant_country) && (
                  <Grid item xs={12} md={6}>
                    <Card sx={{ height: "100%", bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
                          <BusinessIcon fontSize="small" />
                          Registrant Information
                        </Typography>
                        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                          {whoisDomainResult.registrant_organization && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Organization</Typography>
                              <Typography variant="body2" fontWeight={500}>{whoisDomainResult.registrant_organization}</Typography>
                            </Box>
                          )}
                          {whoisDomainResult.registrant_name && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Name</Typography>
                              <Typography variant="body2" fontWeight={500}>{whoisDomainResult.registrant_name}</Typography>
                            </Box>
                          )}
                          {whoisDomainResult.registrant_country && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Country</Typography>
                              <Typography variant="body2" fontWeight={500}>{whoisDomainResult.registrant_country}</Typography>
                            </Box>
                          )}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}

                {/* Name Servers */}
                {whoisDomainResult.name_servers.length > 0 && (
                  <Grid item xs={12} md={6}>
                    <Card sx={{ height: "100%", bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
                          <DnsIcon fontSize="small" />
                          Name Servers ({whoisDomainResult.name_servers.length})
                        </Typography>
                        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                          {whoisDomainResult.name_servers.map((ns, i) => (
                            <Box key={i} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                              <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{ns}</Typography>
                              <CopyButton text={ns} />
                            </Box>
                          ))}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}

                {/* Domain Status */}
                {whoisDomainResult.status.length > 0 && (
                  <Grid item xs={12}>
                    <Card sx={{ bgcolor: alpha("#6366f1", 0.05), border: `1px solid ${alpha("#6366f1", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#6366f1" }}>
                          Domain Status ({whoisDomainResult.status.length})
                        </Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                          {whoisDomainResult.status.map((status, i) => (
                            <Chip
                              key={i}
                              label={status}
                              size="small"
                              sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}
                            />
                          ))}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}
              </Grid>

              {/* Raw WHOIS */}
              {showRawWhois && whoisDomainResult.raw_text && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle2" fontWeight={600}>Raw WHOIS Data</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Paper sx={{ p: 2, bgcolor: "#1e1e1e", maxHeight: 400, overflow: "auto" }}>
                      <Typography
                        component="pre"
                        sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}
                      >
                        {whoisDomainResult.raw_text}
                      </Typography>
                    </Paper>
                  </AccordionDetails>
                </Accordion>
              )}
            </Paper>
          )}

          {/* IP WHOIS Results */}
          {whoisIPResult && !whoisIPResult.error && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3 }}>
                <Typography variant="h6" fontWeight={600}>
                  IP WHOIS Results: {whoisIPResult.ip_address}
                </Typography>
                <Box>
                  <Button
                    size="small"
                    startIcon={<ContentCopyIcon />}
                    onClick={handleCopyWhoisData}
                    sx={{ mr: 1 }}
                  >
                    Copy
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => setShowRawWhois(!showRawWhois)}
                  >
                    {showRawWhois ? "Hide Raw" : "Show Raw"}
                  </Button>
                </Box>
              </Box>

              <Grid container spacing={3}>
                {/* Network Info */}
                <Grid item xs={12} md={6}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                    <CardContent>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#3b82f6", display: "flex", alignItems: "center", gap: 1 }}>
                        <RouterIcon fontSize="small" />
                        Network Information
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                        {whoisIPResult.network_name && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Network Name</Typography>
                            <Typography variant="body2" fontWeight={500}>{whoisIPResult.network_name}</Typography>
                          </Box>
                        )}
                        {whoisIPResult.network_range && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Network Range</Typography>
                            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{whoisIPResult.network_range}</Typography>
                          </Box>
                        )}
                        {whoisIPResult.cidr && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">CIDR</Typography>
                            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{whoisIPResult.cidr}</Typography>
                          </Box>
                        )}
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Organization Info */}
                <Grid item xs={12} md={6}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                    <CardContent>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
                        <BusinessIcon fontSize="small" />
                        Organization
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                        {whoisIPResult.organization && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Organization</Typography>
                            <Typography variant="body2" fontWeight={500}>{whoisIPResult.organization}</Typography>
                          </Box>
                        )}
                        {whoisIPResult.country && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Country</Typography>
                            <Typography variant="body2" fontWeight={500}>{whoisIPResult.country}</Typography>
                          </Box>
                        )}
                        {whoisIPResult.registrar && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Registry (RIR)</Typography>
                            <Chip label={whoisIPResult.registrar} size="small" color="primary" variant="outlined" />
                          </Box>
                        )}
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* ASN Info */}
                {(whoisIPResult.asn || whoisIPResult.asn_name) && (
                  <Grid item xs={12} md={6}>
                    <Card sx={{ height: "100%", bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
                          <HubIcon fontSize="small" />
                          ASN Information
                        </Typography>
                        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                          {whoisIPResult.asn && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">ASN</Typography>
                              <Typography variant="body2" fontWeight={500} sx={{ fontFamily: "monospace" }}>{whoisIPResult.asn}</Typography>
                            </Box>
                          )}
                          {whoisIPResult.asn_name && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">ASN Name</Typography>
                              <Typography variant="body2" fontWeight={500}>{whoisIPResult.asn_name}</Typography>
                            </Box>
                          )}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}

                {/* Contacts */}
                {(whoisIPResult.abuse_contact || whoisIPResult.tech_contact) && (
                  <Grid item xs={12} md={6}>
                    <Card sx={{ height: "100%", bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
                          <EmailIcon fontSize="small" />
                          Contact Information
                        </Typography>
                        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                          {whoisIPResult.abuse_contact && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Abuse Contact</Typography>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{whoisIPResult.abuse_contact}</Typography>
                                <CopyButton text={whoisIPResult.abuse_contact} />
                              </Box>
                            </Box>
                          )}
                          {whoisIPResult.tech_contact && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Tech Contact</Typography>
                              <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{whoisIPResult.tech_contact}</Typography>
                            </Box>
                          )}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}

                {/* Description */}
                {whoisIPResult.description.length > 0 && (
                  <Grid item xs={12}>
                    <Card sx={{ bgcolor: alpha("#6366f1", 0.05), border: `1px solid ${alpha("#6366f1", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#6366f1" }}>
                          Description
                        </Typography>
                        {whoisIPResult.description.map((desc, i) => (
                          <Typography key={i} variant="body2" color="text.secondary">
                            {desc}
                          </Typography>
                        ))}
                      </CardContent>
                    </Card>
                  </Grid>
                )}
              </Grid>

              {/* Raw WHOIS */}
              {showRawWhois && whoisIPResult.raw_text && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle2" fontWeight={600}>Raw WHOIS Data</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Paper sx={{ p: 2, bgcolor: "#1e1e1e", maxHeight: 400, overflow: "auto" }}>
                      <Typography
                        component="pre"
                        sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}
                      >
                        {whoisIPResult.raw_text}
                      </Typography>
                    </Paper>
                  </AccordionDetails>
                </Accordion>
              )}
            </Paper>
          )}
        </Box>
      )}

      {/* Snackbar for copy feedback */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={2000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        message={snackbar.message}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      />

      {/* Floating Chat Window - Visible when results are available */}
      {result && (
        <Paper
          sx={{
            position: "fixed",
            bottom: 0,
            right: 24,
            width: chatOpen ? 450 : 200,
            maxHeight: chatOpen ? "60vh" : "auto",
            zIndex: 1200,
            borderRadius: "12px 12px 0 0",
            boxShadow: "0 -4px 20px rgba(0,0,0,0.15)",
            overflow: "hidden",
            transition: "all 0.3s ease",
          }}
        >
          {/* Chat Header */}
          <Box
            onClick={() => setChatOpen(!chatOpen)}
            sx={{
              p: 2,
              bgcolor: theme.palette.primary.main,
              color: "white",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              "&:hover": { bgcolor: theme.palette.primary.dark },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ChatIcon />
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                Ask About DNS Results
              </Typography>
            </Box>
            <IconButton size="small" sx={{ color: "white" }}>
              {chatOpen ? <ExpandMoreIcon /> : <ExpandLessIcon />}
            </IconButton>
          </Box>

          {/* Chat Content */}
          <Collapse in={chatOpen}>
            {/* Messages Area */}
            <Box
              sx={{
                height: "calc(60vh - 140px)",
                maxHeight: 400,
                overflowY: "auto",
                p: 2,
                bgcolor: alpha(theme.palette.background.default, 0.5),
              }}
            >
              {/* Welcome message */}
              {chatMessages.length === 0 && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <SmartToyIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Ask me anything about this DNS scan!
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {[
                      "What security risks did you find?",
                      "Explain the email security score",
                      "What subdomains are most interesting?",
                      "Summarize the DNS configuration",
                    ].map((suggestion, i) => (
                      <Chip
                        key={i}
                        label={suggestion}
                        variant="outlined"
                        size="small"
                        onClick={() => setChatInput(suggestion)}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) } }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              {/* Chat Messages */}
              {chatMessages.map((msg, i) => (
                <Box
                  key={i}
                  sx={{
                    display: "flex",
                    justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                    mb: 2,
                  }}
                >
                  <Box
                    sx={{
                      maxWidth: "85%",
                      display: "flex",
                      gap: 1,
                      flexDirection: msg.role === "user" ? "row-reverse" : "row",
                    }}
                  >
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        bgcolor: msg.role === "user" ? theme.palette.primary.main : theme.palette.secondary.main,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        flexShrink: 0,
                      }}
                    >
                      {msg.role === "user" ? (
                        <PersonIcon sx={{ fontSize: 18, color: "white" }} />
                      ) : (
                        <SmartToyIcon sx={{ fontSize: 18, color: "white" }} />
                      )}
                    </Box>
                    <Paper
                      sx={{
                        p: 1.5,
                        bgcolor: msg.role === "user" ? theme.palette.primary.main : theme.palette.background.paper,
                        color: msg.role === "user" ? "white" : "text.primary",
                        borderRadius: 2,
                        "& p": { m: 0 },
                        "& p:not(:last-child)": { mb: 1 },
                        "& code": {
                          bgcolor: alpha(msg.role === "user" ? "#fff" : theme.palette.primary.main, 0.2),
                          px: 0.5,
                          borderRadius: 0.5,
                          fontFamily: "monospace",
                          fontSize: "0.85em",
                        },
                        "& ul, & ol": { pl: 2, m: 0 },
                        "& li": { mb: 0.5 },
                      }}
                    >
                      <ReactMarkdown>{msg.content}</ReactMarkdown>
                    </Paper>
                  </Box>
                </Box>
              ))}

              {/* Loading indicator */}
              {chatLoading && (
                <Box sx={{ display: "flex", justifyContent: "flex-start", mb: 2 }}>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        bgcolor: theme.palette.secondary.main,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <SmartToyIcon sx={{ fontSize: 18, color: "white" }} />
                    </Box>
                    <Paper sx={{ p: 1.5, borderRadius: 2 }}>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        <CircularProgress size={8} />
                        <CircularProgress size={8} sx={{ animationDelay: "0.2s" }} />
                        <CircularProgress size={8} sx={{ animationDelay: "0.4s" }} />
                      </Box>
                    </Paper>
                  </Box>
                </Box>
              )}

              {/* Error message */}
              {chatError && (
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setChatError(null)}>
                  {chatError}
                </Alert>
              )}

              <div ref={chatEndRef} />
            </Box>

            {/* Input Area */}
            <Box
              sx={{
                p: 2,
                borderTop: `1px solid ${theme.palette.divider}`,
                bgcolor: theme.palette.background.paper,
              }}
            >
              <Box sx={{ display: "flex", gap: 1 }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Ask about the DNS findings..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={handleChatKeyDown}
                  disabled={chatLoading}
                  sx={{
                    "& .MuiOutlinedInput-root": {
                      borderRadius: 3,
                    },
                  }}
                />
                <IconButton
                  color="primary"
                  onClick={handleSendChat}
                  disabled={!chatInput.trim() || chatLoading}
                  sx={{
                    bgcolor: theme.palette.primary.main,
                    color: "white",
                    "&:hover": { bgcolor: theme.palette.primary.dark },
                    "&.Mui-disabled": { bgcolor: "grey.300" },
                  }}
                >
                  <SendIcon />
                </IconButton>
              </Box>
            </Box>
          </Collapse>
        </Paper>
      )}
    </Container>
  );
}
