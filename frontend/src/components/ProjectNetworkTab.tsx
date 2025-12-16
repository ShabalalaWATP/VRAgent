import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Alert,
  CircularProgress,
  alpha,
  useTheme,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  TextField,
  InputAdornment,
  Tabs,
  Tab,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import RadarIcon from "@mui/icons-material/Radar";
import DeleteIcon from "@mui/icons-material/Delete";
import DownloadIcon from "@mui/icons-material/Download";
import VisibilityIcon from "@mui/icons-material/Visibility";
import RefreshIcon from "@mui/icons-material/Refresh";
import DescriptionIcon from "@mui/icons-material/Description";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import ArticleIcon from "@mui/icons-material/Article";
import HubIcon from "@mui/icons-material/Hub";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import LockIcon from "@mui/icons-material/Lock";
import DnsIcon from "@mui/icons-material/Dns";
import SearchIcon from "@mui/icons-material/Search";
import PortableWifiOffIcon from "@mui/icons-material/PortableWifiOff";
import ApiIcon from "@mui/icons-material/Api";
import { apiClient, SavedNetworkReport } from "../api/client";

// Comprehensive Network Ports Database
interface PortInfo {
  port: number;
  protocol: string;
  service: string;
  description: string;
  category: string;
  security: "secure" | "insecure" | "varies" | "deprecated";
}

const NETWORK_PORTS: PortInfo[] = [
  // Well-known ports (0-1023)
  { port: 20, protocol: "TCP", service: "FTP Data", description: "File Transfer Protocol - Data transfer", category: "File Transfer", security: "insecure" },
  { port: 21, protocol: "TCP", service: "FTP Control", description: "File Transfer Protocol - Command/control", category: "File Transfer", security: "insecure" },
  { port: 22, protocol: "TCP", service: "SSH", description: "Secure Shell - Encrypted remote access", category: "Remote Access", security: "secure" },
  { port: 23, protocol: "TCP", service: "Telnet", description: "Unencrypted remote terminal access", category: "Remote Access", security: "insecure" },
  { port: 25, protocol: "TCP", service: "SMTP", description: "Simple Mail Transfer Protocol - Email sending", category: "Email", security: "insecure" },
  { port: 53, protocol: "TCP/UDP", service: "DNS", description: "Domain Name System - Name resolution", category: "Infrastructure", security: "varies" },
  { port: 67, protocol: "UDP", service: "DHCP Server", description: "Dynamic Host Configuration Protocol - Server", category: "Infrastructure", security: "varies" },
  { port: 68, protocol: "UDP", service: "DHCP Client", description: "Dynamic Host Configuration Protocol - Client", category: "Infrastructure", security: "varies" },
  { port: 69, protocol: "UDP", service: "TFTP", description: "Trivial File Transfer Protocol", category: "File Transfer", security: "insecure" },
  { port: 80, protocol: "TCP", service: "HTTP", description: "Hypertext Transfer Protocol - Web traffic", category: "Web", security: "insecure" },
  { port: 88, protocol: "TCP/UDP", service: "Kerberos", description: "Network authentication protocol", category: "Authentication", security: "secure" },
  { port: 110, protocol: "TCP", service: "POP3", description: "Post Office Protocol v3 - Email retrieval", category: "Email", security: "insecure" },
  { port: 111, protocol: "TCP/UDP", service: "RPC", description: "Remote Procedure Call - Sun RPC", category: "Infrastructure", security: "insecure" },
  { port: 119, protocol: "TCP", service: "NNTP", description: "Network News Transfer Protocol", category: "Messaging", security: "insecure" },
  { port: 123, protocol: "UDP", service: "NTP", description: "Network Time Protocol - Time synchronization", category: "Infrastructure", security: "varies" },
  { port: 135, protocol: "TCP", service: "MS-RPC", description: "Microsoft RPC Endpoint Mapper", category: "Windows", security: "varies" },
  { port: 137, protocol: "UDP", service: "NetBIOS-NS", description: "NetBIOS Name Service", category: "Windows", security: "insecure" },
  { port: 138, protocol: "UDP", service: "NetBIOS-DGM", description: "NetBIOS Datagram Service", category: "Windows", security: "insecure" },
  { port: 139, protocol: "TCP", service: "NetBIOS-SSN", description: "NetBIOS Session Service", category: "Windows", security: "insecure" },
  { port: 143, protocol: "TCP", service: "IMAP", description: "Internet Message Access Protocol - Email", category: "Email", security: "insecure" },
  { port: 161, protocol: "UDP", service: "SNMP", description: "Simple Network Management Protocol", category: "Management", security: "varies" },
  { port: 162, protocol: "UDP", service: "SNMP Trap", description: "SNMP Trap notifications", category: "Management", security: "varies" },
  { port: 179, protocol: "TCP", service: "BGP", description: "Border Gateway Protocol - Internet routing", category: "Infrastructure", security: "varies" },
  { port: 194, protocol: "TCP", service: "IRC", description: "Internet Relay Chat", category: "Messaging", security: "insecure" },
  { port: 389, protocol: "TCP/UDP", service: "LDAP", description: "Lightweight Directory Access Protocol", category: "Authentication", security: "insecure" },
  { port: 443, protocol: "TCP", service: "HTTPS", description: "HTTP over TLS/SSL - Secure web traffic", category: "Web", security: "secure" },
  { port: 445, protocol: "TCP", service: "SMB", description: "Server Message Block - File sharing", category: "File Transfer", security: "varies" },
  { port: 464, protocol: "TCP/UDP", service: "Kerberos Change", description: "Kerberos password change", category: "Authentication", security: "secure" },
  { port: 465, protocol: "TCP", service: "SMTPS", description: "SMTP over SSL - Secure email sending", category: "Email", security: "secure" },
  { port: 500, protocol: "UDP", service: "IKE", description: "Internet Key Exchange - VPN", category: "VPN", security: "secure" },
  { port: 514, protocol: "UDP", service: "Syslog", description: "System logging protocol", category: "Management", security: "insecure" },
  { port: 515, protocol: "TCP", service: "LPD", description: "Line Printer Daemon - Printing", category: "Printing", security: "insecure" },
  { port: 520, protocol: "UDP", service: "RIP", description: "Routing Information Protocol", category: "Infrastructure", security: "insecure" },
  { port: 587, protocol: "TCP", service: "SMTP Submission", description: "Email submission with STARTTLS", category: "Email", security: "secure" },
  { port: 631, protocol: "TCP/UDP", service: "IPP", description: "Internet Printing Protocol - CUPS", category: "Printing", security: "varies" },
  { port: 636, protocol: "TCP", service: "LDAPS", description: "LDAP over SSL - Secure directory", category: "Authentication", security: "secure" },
  { port: 873, protocol: "TCP", service: "rsync", description: "Remote file synchronization", category: "File Transfer", security: "varies" },
  { port: 993, protocol: "TCP", service: "IMAPS", description: "IMAP over SSL - Secure email", category: "Email", security: "secure" },
  { port: 995, protocol: "TCP", service: "POP3S", description: "POP3 over SSL - Secure email", category: "Email", security: "secure" },
  // Registered ports (1024-49151)
  { port: 1080, protocol: "TCP", service: "SOCKS", description: "SOCKS proxy protocol", category: "Proxy", security: "varies" },
  { port: 1194, protocol: "UDP", service: "OpenVPN", description: "OpenVPN tunnel", category: "VPN", security: "secure" },
  { port: 1433, protocol: "TCP", service: "MS-SQL", description: "Microsoft SQL Server", category: "Database", security: "varies" },
  { port: 1434, protocol: "UDP", service: "MS-SQL Monitor", description: "MS SQL Server Browser", category: "Database", security: "varies" },
  { port: 1521, protocol: "TCP", service: "Oracle DB", description: "Oracle Database listener", category: "Database", security: "varies" },
  { port: 1701, protocol: "UDP", service: "L2TP", description: "Layer 2 Tunneling Protocol", category: "VPN", security: "secure" },
  { port: 1723, protocol: "TCP", service: "PPTP", description: "Point-to-Point Tunneling Protocol", category: "VPN", security: "deprecated" },
  { port: 1812, protocol: "UDP", service: "RADIUS Auth", description: "RADIUS Authentication", category: "Authentication", security: "secure" },
  { port: 1813, protocol: "UDP", service: "RADIUS Acct", description: "RADIUS Accounting", category: "Authentication", security: "secure" },
  { port: 1883, protocol: "TCP", service: "MQTT", description: "Message Queuing Telemetry Transport", category: "IoT", security: "insecure" },
  { port: 2049, protocol: "TCP/UDP", service: "NFS", description: "Network File System", category: "File Transfer", security: "varies" },
  { port: 2375, protocol: "TCP", service: "Docker", description: "Docker REST API (unencrypted)", category: "Container", security: "insecure" },
  { port: 2376, protocol: "TCP", service: "Docker TLS", description: "Docker REST API (TLS)", category: "Container", security: "secure" },
  { port: 3000, protocol: "TCP", service: "Dev Server", description: "Common development server port", category: "Development", security: "varies" },
  { port: 3128, protocol: "TCP", service: "Squid Proxy", description: "Squid HTTP proxy", category: "Proxy", security: "varies" },
  { port: 3306, protocol: "TCP", service: "MySQL", description: "MySQL Database", category: "Database", security: "varies" },
  { port: 3389, protocol: "TCP", service: "RDP", description: "Remote Desktop Protocol", category: "Remote Access", security: "varies" },
  { port: 5000, protocol: "TCP", service: "UPnP", description: "Universal Plug and Play", category: "Infrastructure", security: "insecure" },
  { port: 5060, protocol: "TCP/UDP", service: "SIP", description: "Session Initiation Protocol - VoIP", category: "VoIP", security: "insecure" },
  { port: 5061, protocol: "TCP", service: "SIP TLS", description: "SIP over TLS - Secure VoIP", category: "VoIP", security: "secure" },
  { port: 5432, protocol: "TCP", service: "PostgreSQL", description: "PostgreSQL Database", category: "Database", security: "varies" },
  { port: 5672, protocol: "TCP", service: "AMQP", description: "Advanced Message Queuing Protocol", category: "Messaging", security: "varies" },
  { port: 5900, protocol: "TCP", service: "VNC", description: "Virtual Network Computing", category: "Remote Access", security: "insecure" },
  { port: 6379, protocol: "TCP", service: "Redis", description: "Redis in-memory data store", category: "Database", security: "varies" },
  { port: 6443, protocol: "TCP", service: "Kubernetes API", description: "Kubernetes API Server", category: "Container", security: "secure" },
  { port: 8000, protocol: "TCP", service: "HTTP Alt", description: "Alternative HTTP port", category: "Web", security: "insecure" },
  { port: 8080, protocol: "TCP", service: "HTTP Proxy", description: "HTTP proxy/alternative port", category: "Web", security: "insecure" },
  { port: 8443, protocol: "TCP", service: "HTTPS Alt", description: "Alternative HTTPS port", category: "Web", security: "secure" },
  { port: 8883, protocol: "TCP", service: "MQTT TLS", description: "MQTT over TLS", category: "IoT", security: "secure" },
  { port: 9000, protocol: "TCP", service: "PHP-FPM", description: "PHP FastCGI Process Manager", category: "Web", security: "varies" },
  { port: 9090, protocol: "TCP", service: "Prometheus", description: "Prometheus monitoring", category: "Management", security: "varies" },
  { port: 9092, protocol: "TCP", service: "Kafka", description: "Apache Kafka broker", category: "Messaging", security: "varies" },
  { port: 9200, protocol: "TCP", service: "Elasticsearch", description: "Elasticsearch HTTP", category: "Database", security: "varies" },
  { port: 11211, protocol: "TCP", service: "Memcached", description: "Memcached cache server", category: "Database", security: "insecure" },
  { port: 27017, protocol: "TCP", service: "MongoDB", description: "MongoDB database", category: "Database", security: "varies" },
  { port: 51820, protocol: "UDP", service: "WireGuard", description: "WireGuard VPN", category: "VPN", security: "secure" },
];

interface ProjectNetworkTabProps {
  projectId: number;
  projectName: string;
}

const ProjectNetworkTab: React.FC<ProjectNetworkTabProps> = ({ projectId, projectName }) => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [reports, setReports] = useState<SavedNetworkReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);
  const [exportAnchorEl, setExportAnchorEl] = useState<null | HTMLElement>(null);
  const [exportReportId, setExportReportId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [portSearch, setPortSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");

  // Get unique categories from ports
  const categories = ["all", ...Array.from(new Set(NETWORK_PORTS.map(p => p.category))).sort()];

  // Filter ports based on search and category
  const filteredPorts = NETWORK_PORTS.filter(p => {
    const matchesSearch = portSearch === "" || 
      p.port.toString().includes(portSearch) ||
      p.service.toLowerCase().includes(portSearch.toLowerCase()) ||
      p.description.toLowerCase().includes(portSearch.toLowerCase()) ||
      p.protocol.toLowerCase().includes(portSearch.toLowerCase());
    const matchesCategory = categoryFilter === "all" || p.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  const getSecurityColor = (security: string) => {
    switch (security) {
      case "secure": return "#10b981";
      case "insecure": return "#ef4444";
      case "deprecated": return "#6b7280";
      default: return "#f59e0b";
    }
  };

  const getSecurityLabel = (security: string) => {
    switch (security) {
      case "secure": return "Secure";
      case "insecure": return "Insecure";
      case "deprecated": return "Deprecated";
      default: return "Varies";
    }
  };

  const fetchReports = async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch reports filtered by project
      const data = await apiClient.getNetworkReports(undefined, projectId);
      setReports(data);
    } catch (err: any) {
      setError(err.message || "Failed to load reports");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [projectId]);

  const handleDelete = async (reportId: number) => {
    try {
      await apiClient.deleteNetworkReport(reportId);
      setReports(reports.filter((r) => r.id !== reportId));
      setDeleteConfirm(null);
    } catch (err: any) {
      setError(err.message || "Failed to delete report");
    }
  };

  const handleExportClick = (event: React.MouseEvent<HTMLElement>, reportId: number) => {
    setExportAnchorEl(event.currentTarget);
    setExportReportId(reportId);
  };

  const handleExportClose = () => {
    setExportAnchorEl(null);
    setExportReportId(null);
  };

  const handleExport = async (format: "markdown" | "pdf" | "docx") => {
    if (!exportReportId) return;
    try {
      const blob = await apiClient.exportNetworkReport(exportReportId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `network_report_${exportReportId}.${format === "markdown" ? "md" : format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message || "Export failed");
    }
    handleExportClose();
  };

  const getRiskColor = (level: string | null) => {
    switch (level?.toLowerCase()) {
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

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  // Helper to pass project context to tool pages via query params
  const getToolLink = (basePath: string) => `${basePath}?projectId=${projectId}&projectName=${encodeURIComponent(projectName)}`;

  return (
    <Box>
      {/* Tool Cards - 4x2 Grid */}
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {/* PCAP Analyzer */}
        <Grid item xs={12} sm={6} md={3}>
          <Card
            sx={{
              height: "100%",
              display: "flex",
              flexDirection: "column",
              background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.1)} 0%, ${alpha("#0891b2", 0.05)} 100%)`,
              border: `1px solid ${alpha("#06b6d4", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#06b6d4", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3, display: "flex", flexDirection: "column", flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <NetworkCheckIcon sx={{ fontSize: 28, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="subtitle1" fontWeight={700} sx={{ lineHeight: 1.2 }}>
                    PCAP Analyzer
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Packet Capture Analysis
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1 }}>
                Upload .pcap files from Wireshark or tcpdump. Analyzes protocols, detects suspicious
                traffic patterns and credential exposure.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                <Chip label=".pcap" size="small" variant="outlined" />
                <Chip label=".pcapng" size="small" variant="outlined" />
              </Box>
              <Button
                component={Link}
                to={getToolLink("/network/pcap")}
                variant="contained"
                fullWidth
                sx={{
                  mt: "auto",
                  background: `linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #0891b2 0%, #0e7490 100%)`,
                  },
                }}
              >
                Open PCAP Analyzer
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Nmap Analyzer */}
        <Grid item xs={12} sm={6} md={3}>
          <Card
            sx={{
              height: "100%",
              display: "flex",
              flexDirection: "column",
              background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)} 0%, ${alpha("#7c3aed", 0.05)} 100%)`,
              border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#8b5cf6", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3, display: "flex", flexDirection: "column", flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <RadarIcon sx={{ fontSize: 28, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="subtitle1" fontWeight={700} sx={{ lineHeight: 1.2 }}>
                    Nmap Analyzer
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Network Scan Analysis
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1 }}>
                Upload Nmap scan outputs. Identifies open ports, vulnerable services, and provides
                prioritized remediation recommendations.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                <Chip label=".xml" size="small" variant="outlined" />
                <Chip label=".nmap" size="small" variant="outlined" />
              </Box>
              <Button
                component={Link}
                to={getToolLink("/network/nmap")}
                variant="contained"
                fullWidth
                sx={{
                  mt: "auto",
                  background: `linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)`,
                  },
                }}
              >
                Open Nmap Analyzer
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* SSL/TLS Scanner */}
        <Grid item xs={12} sm={6} md={3}>
          <Card
            sx={{
              height: "100%",
              display: "flex",
              flexDirection: "column",
              background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)} 0%, ${alpha("#059669", 0.05)} 100%)`,
              border: `1px solid ${alpha("#10b981", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#10b981", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3, display: "flex", flexDirection: "column", flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #10b981 0%, #059669 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <LockIcon sx={{ fontSize: 28, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="subtitle1" fontWeight={700} sx={{ lineHeight: 1.2 }}>
                    SSL/TLS Scanner
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Certificate & Cipher Analysis
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1 }}>
                Scan SSL/TLS configuration of any host. Checks certificate validity, protocol support,
                cipher strength, and known vulnerabilities.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                <Chip label="TLS 1.2/1.3" size="small" variant="outlined" />
                <Chip label="Certs" size="small" variant="outlined" />
              </Box>
              <Button
                component={Link}
                to={getToolLink("/network/ssl")}
                variant="contained"
                fullWidth
                sx={{
                  mt: "auto",
                  background: `linear-gradient(135deg, #10b981 0%, #059669 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #059669 0%, #047857 100%)`,
                  },
                }}
              >
                Open SSL Scanner
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* DNS Reconnaissance */}
        <Grid item xs={12} sm={6} md={3}>
          <Card
            sx={{
              height: "100%",
              display: "flex",
              flexDirection: "column",
              background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.1)} 0%, ${alpha("#d97706", 0.05)} 100%)`,
              border: `1px solid ${alpha("#f59e0b", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#f59e0b", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3, display: "flex", flexDirection: "column", flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #f59e0b 0%, #d97706 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <DnsIcon sx={{ fontSize: 28, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="subtitle1" fontWeight={700} sx={{ lineHeight: 1.2 }}>
                    DNS Reconnaissance
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Domain Enumeration & Security
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1 }}>
                Enumerate DNS records, discover subdomains, test zone transfers, and analyze email
                security (SPF, DMARC, DKIM).
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                <Chip label="A/AAAA/MX" size="small" variant="outlined" />
                <Chip label="Subdomains" size="small" variant="outlined" />
              </Box>
              <Button
                component={Link}
                to={getToolLink("/network/dns")}
                variant="contained"
                fullWidth
                sx={{
                  mt: "auto",
                  background: `linear-gradient(135deg, #f59e0b 0%, #d97706 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #d97706 0%, #b45309 100%)`,
                  },
                }}
              >
                Open DNS Recon
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Traceroute Visualization */}
        <Grid item xs={12} sm={6} md={3}>
          <Card
            sx={{
              height: "100%",
              display: "flex",
              flexDirection: "column",
              background: `linear-gradient(135deg, ${alpha("#ec4899", 0.1)} 0%, ${alpha("#db2777", 0.05)} 100%)`,
              border: `1px solid ${alpha("#ec4899", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#ec4899", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3, display: "flex", flexDirection: "column", flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #ec4899 0%, #db2777 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <HubIcon sx={{ fontSize: 28, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="subtitle1" fontWeight={700} sx={{ lineHeight: 1.2 }}>
                    Traceroute
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Network Path Visualization
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1 }}>
                Visualize network paths, identify routing bottlenecks, measure hop-by-hop latency, and
                analyze packet loss along routes.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                <Chip label="Path Viz" size="small" variant="outlined" />
                <Chip label="Latency" size="small" variant="outlined" />
              </Box>
              <Button
                component={Link}
                to={getToolLink("/network/traceroute")}
                variant="contained"
                fullWidth
                sx={{
                  mt: "auto",
                  background: `linear-gradient(135deg, #ec4899 0%, #db2777 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #db2777 0%, #be185d 100%)`,
                  },
                }}
              >
                Open Traceroute
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* API Endpoint Tester */}
        <Grid item xs={12} sm={6} md={3}>
          <Card
            sx={{
              height: "100%",
              display: "flex",
              flexDirection: "column",
              background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.1)} 0%, ${alpha("#2563eb", 0.05)} 100%)`,
              border: `1px solid ${alpha("#3b82f6", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#3b82f6", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3, display: "flex", flexDirection: "column", flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <ApiIcon sx={{ fontSize: 28, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="subtitle1" fontWeight={700} sx={{ lineHeight: 1.2 }}>
                    API Tester
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Endpoint Security Testing
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1 }}>
                Test REST API endpoints for security vulnerabilities. Checks authentication, CORS, 
                rate limiting, input validation, and security headers.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                <Chip label="Auth" size="small" variant="outlined" />
                <Chip label="CORS" size="small" variant="outlined" />
                <Chip label="SQLi/XSS" size="small" variant="outlined" />
              </Box>
              <Button
                component={Link}
                to={getToolLink("/network/api-tester")}
                variant="contained"
                fullWidth
                sx={{
                  mt: "auto",
                  background: `linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)`,
                  },
                }}
              >
                Open API Tester
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Security Fuzzer */}
        <Grid item xs={12} sm={6} md={3}>
          <Card
            sx={{
              height: "100%",
              display: "flex",
              flexDirection: "column",
              background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)} 0%, ${alpha("#ea580c", 0.05)} 100%)`,
              border: `1px solid ${alpha("#f97316", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#f97316", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3, display: "flex", flexDirection: "column", flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #f97316 0%, #ea580c 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="white">
                    <path d="M14 12h-4v-2h4m0 6h-4v-2h4m6-6h-2.81a5.985 5.985 0 0 0-1.82-1.96L17 4.41 15.59 3l-2.17 2.17a6.002 6.002 0 0 0-2.83 0L8.41 3 7 4.41l1.62 1.63C7.88 6.55 7.26 7.22 6.81 8H4v2h2.09c-.05.33-.09.66-.09 1v1H4v2h2v1c0 .34.04.67.09 1H4v2h2.81c1.04 1.79 2.97 3 5.19 3s4.15-1.21 5.19-3H20v-2h-2.09c.05-.33.09-.66.09-1v-1h2v-2h-2v-1c0-.34-.04-.67-.09-1H20V8z"/>
                  </svg>
                </Box>
                <Box>
                  <Typography variant="subtitle1" fontWeight={700} sx={{ lineHeight: 1.2 }}>
                    Security Fuzzer
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Payload Injection Testing
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1 }}>
                Advanced fuzzing tool with multiple attack modes (Sniper, Battering Ram, Pitchfork, Cluster Bomb). 
                Built-in wordlists for SQLi, XSS, LFI, and more.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                <Chip label="SQLi/XSS" size="small" variant="outlined" />
                <Chip label="LFI/RFI" size="small" variant="outlined" />
                <Chip label="Intruder" size="small" variant="outlined" />
              </Box>
              <Button
                component={Link}
                to={getToolLink("/network/fuzzer")}
                variant="contained"
                fullWidth
                sx={{
                  mt: "auto",
                  background: `linear-gradient(135deg, #f97316 0%, #ea580c 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #ea580c 0%, #c2410c 100%)`,
                  },
                }}
              >
                Open Fuzzer
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* MITM Workbench */}
        <Grid item xs={12} sm={6} md={3}>
          <Card
            sx={{
              height: "100%",
              display: "flex",
              flexDirection: "column",
              background: `linear-gradient(135deg, ${alpha("#eab308", 0.1)} 0%, ${alpha("#ca8a04", 0.05)} 100%)`,
              border: `1px solid ${alpha("#eab308", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#eab308", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3, display: "flex", flexDirection: "column", flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #eab308 0%, #ca8a04 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="white">
                    <path d="M7.5 21H2V9h5.5v12zm7.25-18h-5.5v18h5.5V3zM22 11h-5.5v10H22V11z"/>
                  </svg>
                </Box>
                <Box>
                  <Typography variant="subtitle1" fontWeight={700} sx={{ lineHeight: 1.2 }}>
                    MITM Workbench
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Traffic Interception
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1 }}>
                Man-in-the-Middle proxy for intercepting, inspecting, and modifying HTTP/HTTPS traffic 
                between application components. Supports rule-based auto-modification.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
                <Chip label="HTTP Proxy" size="small" variant="outlined" />
                <Chip label="Intercept" size="small" variant="outlined" />
                <Chip label="Modify" size="small" variant="outlined" />
              </Box>
              <Box sx={{ mt: "auto" }}>
                <Chip
                  component={Link}
                  to="/learn/mitm"
                  icon={<MenuBookIcon sx={{ fontSize: 14 }} />}
                  label="Learn MITM →"
                  clickable
                  size="small"
                  sx={{
                    mb: 1.5,
                    background: alpha("#eab308", 0.1),
                    border: `1px solid ${alpha("#eab308", 0.3)}`,
                    color: "#eab308",
                    fontWeight: 500,
                    "&:hover": {
                      background: alpha("#eab308", 0.2),
                    },
                  }}
                />
                <Button
                  component={Link}
                  to={getToolLink("/network/mitm")}
                  variant="contained"
                  fullWidth
                  sx={{
                    background: `linear-gradient(135deg, #eab308 0%, #ca8a04 100%)`,
                    "&:hover": {
                      background: `linear-gradient(135deg, #ca8a04 0%, #a16207 100%)`,
                    },
                  }}
                >
                  Open MITM Workbench
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs for Reports and Ports Glossary */}
      <Box sx={{ borderBottom: 1, borderColor: "divider", mb: 3 }}>
        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)}>
          <Tab label={`${projectName} Reports`} />
          <Tab 
            label="Network Ports Glossary" 
            icon={<PortableWifiOffIcon sx={{ fontSize: 22 }} />} 
            iconPosition="start"
            sx={{
              fontSize: "1.1rem",
              fontWeight: 700,
              px: 3,
              py: 1.5,
              minHeight: 56,
              background: activeTab === 1 
                ? "linear-gradient(135deg, rgba(6, 182, 212, 0.15) 0%, rgba(139, 92, 246, 0.15) 100%)" 
                : "linear-gradient(135deg, rgba(6, 182, 212, 0.08) 0%, rgba(139, 92, 246, 0.08) 100%)",
              borderRadius: "12px 12px 0 0",
              border: "1px solid",
              borderColor: activeTab === 1 ? "rgba(6, 182, 212, 0.4)" : "rgba(6, 182, 212, 0.2)",
              borderBottom: "none",
              mr: 1,
              transition: "all 0.3s ease",
              "&:hover": {
                background: "linear-gradient(135deg, rgba(6, 182, 212, 0.2) 0%, rgba(139, 92, 246, 0.2) 100%)",
                borderColor: "rgba(6, 182, 212, 0.5)",
              },
              "& .MuiTab-iconWrapper": {
                color: "#06b6d4",
              },
            }}
          />
        </Tabs>
      </Box>

      {/* Tab 0: Project Reports */}
      {activeTab === 0 && (
        <>
          <Box sx={{ mb: 2, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <Typography variant="h5" fontWeight={600}>
              Network Analysis Reports for {projectName}
            </Typography>
            <Button startIcon={<RefreshIcon />} onClick={fetchReports} disabled={loading}>
              Refresh
            </Button>
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {loading ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
              <CircularProgress />
            </Box>
          ) : reports.length === 0 ? (
            <Paper sx={{ p: 4, textAlign: "center" }}>
              <Typography color="text.secondary">
                No network analysis reports for this project yet. Use the tools above to start analyzing.
              </Typography>
            </Paper>
          ) : (
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Type</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>Files</TableCell>
                    <TableCell>Risk Level</TableCell>
                    <TableCell>Findings</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {reports.map((report) => (
                    <TableRow key={report.id} hover>
                      <TableCell>
                        <Chip
                          label={report.analysis_type.toUpperCase()}
                          size="small"
                          sx={{
                            bgcolor:
                              report.analysis_type === "pcap"
                                ? alpha("#06b6d4", 0.15)
                                : report.analysis_type === "dns"
                                ? alpha("#f59e0b", 0.15)
                                : report.analysis_type === "traceroute"
                                ? alpha("#ec4899", 0.15)
                                : alpha("#8b5cf6", 0.15),
                            color: 
                              report.analysis_type === "pcap" 
                                ? "#0891b2" 
                                : report.analysis_type === "dns"
                                ? "#d97706"
                                : report.analysis_type === "traceroute"
                                ? "#db2777"
                                : "#7c3aed",
                            fontWeight: 600,
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight={500}>
                          {report.title}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{
                            maxWidth: 200,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            display: "block",
                          }}
                        >
                          {report.filename || "-"}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {report.risk_level ? (
                          <Chip
                            label={report.risk_level}
                            size="small"
                            sx={{
                              bgcolor: alpha(getRiskColor(report.risk_level), 0.15),
                              color: getRiskColor(report.risk_level),
                              fontWeight: 600,
                            }}
                          />
                        ) : (
                          "-"
                        )}
                      </TableCell>
                      <TableCell>{report.findings_count}</TableCell>
                      <TableCell>
                        <Typography variant="caption">{formatDate(report.created_at)}</Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Report">
                          <IconButton
                            size="small"
                            onClick={() =>
                              navigate(
                                `/network/${report.analysis_type}?reportId=${report.id}`
                              )
                            }
                          >
                            <VisibilityIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Export">
                          <IconButton
                            size="small"
                            onClick={(e) => handleExportClick(e, report.id)}
                          >
                            <DownloadIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => setDeleteConfirm(report.id)}
                          >
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
        </>
      )}

      {/* Tab 1: Network Ports Glossary */}
      {activeTab === 1 && (
        <Box>
          <Box sx={{ mb: 3 }}>
            <Typography variant="h5" fontWeight={600} sx={{ mb: 1 }}>
              Network Ports Glossary
            </Typography>
            <Typography variant="body2" color="text.secondary">
              A comprehensive reference of common network ports, their services, and security considerations.
              Use this to identify services during network analysis and understand security implications.
            </Typography>
          </Box>

          {/* Search and Filter */}
          <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
            <TextField
              placeholder="Search by port, service, or description..."
              value={portSearch}
              onChange={(e) => setPortSearch(e.target.value)}
              size="small"
              sx={{ minWidth: 300, flex: 1 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
            />
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              {categories.map((cat) => (
                <Chip
                  key={cat}
                  label={cat === "all" ? "All Categories" : cat}
                  onClick={() => setCategoryFilter(cat)}
                  variant={categoryFilter === cat ? "filled" : "outlined"}
                  color={categoryFilter === cat ? "primary" : "default"}
                  size="small"
                />
              ))}
            </Box>
          </Box>

          {/* Results count */}
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Showing {filteredPorts.length} of {NETWORK_PORTS.length} ports
          </Typography>

          {/* Ports Table */}
          <TableContainer component={Paper} sx={{ maxHeight: 600 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 600, width: 80 }}>Port</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 80 }}>Protocol</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 150 }}>Service</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 120 }}>Category</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 100 }}>Security</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredPorts.map((port) => (
                  <TableRow key={`${port.port}-${port.protocol}`} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={600} fontFamily="monospace">
                        {port.port}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={port.protocol} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {port.service}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {port.description}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={port.category} 
                        size="small" 
                        sx={{ 
                          bgcolor: alpha("#6366f1", 0.1),
                          color: "#818cf8",
                          fontSize: "0.7rem"
                        }} 
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={getSecurityLabel(port.security)}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSecurityColor(port.security), 0.15),
                          color: getSecurityColor(port.security),
                          fontWeight: 600,
                          fontSize: "0.7rem"
                        }}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Legend */}
          <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#6366f1", 0.05), borderRadius: 2 }}>
            <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
              Security Status Legend
            </Typography>
            <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Chip label="Secure" size="small" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981" }} />
                <Typography variant="caption">Encrypted or secure by design</Typography>
              </Box>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Chip label="Insecure" size="small" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444" }} />
                <Typography variant="caption">Unencrypted or vulnerable</Typography>
              </Box>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Chip label="Varies" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b" }} />
                <Typography variant="caption">Security depends on configuration</Typography>
              </Box>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Chip label="Deprecated" size="small" sx={{ bgcolor: alpha("#6b7280", 0.15), color: "#6b7280" }} />
                <Typography variant="caption">Should not be used</Typography>
              </Box>
            </Box>
          </Box>
        </Box>
      )}

      {/* Export Menu */}
      <Menu
        anchorEl={exportAnchorEl}
        open={Boolean(exportAnchorEl)}
        onClose={handleExportClose}
      >
        <MenuItem onClick={() => handleExport("markdown")}>
          <ListItemIcon>
            <DescriptionIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Markdown (.md)</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleExport("pdf")}>
          <ListItemIcon>
            <PictureAsPdfIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>PDF (.pdf)</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleExport("docx")}>
          <ListItemIcon>
            <ArticleIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Word (.docx)</ListItemText>
        </MenuItem>
      </Menu>

      {/* Delete Confirmation */}
      <Dialog open={deleteConfirm !== null} onClose={() => setDeleteConfirm(null)}>
        <DialogTitle>Delete Report?</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete this report? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          <Button
            onClick={() => deleteConfirm && handleDelete(deleteConfirm)}
            color="error"
            variant="contained"
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ProjectNetworkTab;
