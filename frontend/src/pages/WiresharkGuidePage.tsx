import React from "react";
import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Grid,
  Card,
  CardContent,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Divider,
  Button,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  keyframes,
  Tabs,
  Tab,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import FilterListIcon from "@mui/icons-material/FilterList";
import VisibilityIcon from "@mui/icons-material/Visibility";
import SecurityIcon from "@mui/icons-material/Security";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import DownloadIcon from "@mui/icons-material/Download";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StopIcon from "@mui/icons-material/Stop";
import SaveIcon from "@mui/icons-material/Save";
import SearchIcon from "@mui/icons-material/Search";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SchoolIcon from "@mui/icons-material/School";
import SettingsIcon from "@mui/icons-material/Settings";
import MouseIcon from "@mui/icons-material/Mouse";
import KeyboardIcon from "@mui/icons-material/Keyboard";
import TimelineIcon from "@mui/icons-material/Timeline";
import BarChartIcon from "@mui/icons-material/BarChart";
import BugReportIcon from "@mui/icons-material/BugReport";
import WarningIcon from "@mui/icons-material/Warning";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import DnsIcon from "@mui/icons-material/Dns";
import HttpIcon from "@mui/icons-material/Http";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import ColorLensIcon from "@mui/icons-material/ColorLens";
import LayersIcon from "@mui/icons-material/Layers";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import ApiIcon from "@mui/icons-material/Api";
import KeyIcon from "@mui/icons-material/Key";
import TokenIcon from "@mui/icons-material/Token";
import DataObjectIcon from "@mui/icons-material/DataObject";
import StorageIcon from "@mui/icons-material/Storage";
import InsertDriveFileIcon from "@mui/icons-material/InsertDriveFile";
import DeviceHubIcon from "@mui/icons-material/DeviceHub";
import RouterIcon from "@mui/icons-material/Router";
import TerminalIcon from "@mui/icons-material/Terminal";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import ShieldIcon from "@mui/icons-material/Shield";
import HubIcon from "@mui/icons-material/Hub";
import LearnPageLayout from "../components/LearnPageLayout";

// Tab panel component
interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

// Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
`;

export default function WiresharkGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();

  const displayFilters = [
    { filter: "ip.addr == 192.168.1.1", description: "Traffic to/from specific IP", category: "IP" },
    { filter: "ip.src == 10.0.0.5", description: "Traffic FROM specific IP only", category: "IP" },
    { filter: "ip.dst == 8.8.8.8", description: "Traffic TO specific IP only", category: "IP" },
    { filter: "tcp.port == 80", description: "HTTP traffic (port 80)", category: "Port" },
    { filter: "tcp.port == 443", description: "HTTPS traffic (port 443)", category: "Port" },
    { filter: "udp.port == 53", description: "DNS traffic (port 53)", category: "Port" },
    { filter: "tcp.port >= 1 and tcp.port <= 1024", description: "Well-known ports only", category: "Port" },
    { filter: "dns", description: "All DNS traffic", category: "Protocol" },
    { filter: "http", description: "All HTTP traffic", category: "Protocol" },
    { filter: "tls or ssl", description: "All encrypted TLS/SSL traffic", category: "Protocol" },
    { filter: "icmp", description: "Ping/ICMP traffic", category: "Protocol" },
    { filter: "arp", description: "ARP requests/replies", category: "Protocol" },
    { filter: "tcp.flags.syn == 1", description: "TCP SYN packets (new connections)", category: "Flags" },
    { filter: "tcp.flags.rst == 1", description: "TCP RST packets (connection resets)", category: "Flags" },
    { filter: "tcp.flags.fin == 1", description: "TCP FIN packets (connection close)", category: "Flags" },
    { filter: "frame contains \"password\"", description: "Packets containing 'password'", category: "Content" },
    { filter: "http.request.method == \"POST\"", description: "HTTP POST requests", category: "Content" },
    { filter: "http.request.uri contains \"login\"", description: "Login page requests", category: "Content" },
    { filter: "tcp.analysis.retransmission", description: "Retransmitted packets", category: "Analysis" },
    { filter: "tcp.analysis.zero_window", description: "Zero window (flow control)", category: "Analysis" },
  ];

  const captureFilters = [
    { filter: "host 192.168.1.1", description: "Traffic to/from specific host" },
    { filter: "src host 10.0.0.5", description: "Traffic FROM specific host" },
    { filter: "dst host 8.8.8.8", description: "Traffic TO specific host" },
    { filter: "port 80", description: "Traffic on port 80" },
    { filter: "port 80 or port 443", description: "HTTP and HTTPS traffic" },
    { filter: "portrange 1-1024", description: "Well-known ports" },
    { filter: "net 192.168.1.0/24", description: "Traffic from/to subnet" },
    { filter: "tcp", description: "Only TCP traffic" },
    { filter: "udp", description: "Only UDP traffic" },
    { filter: "icmp", description: "Only ICMP (ping) traffic" },
    { filter: "not broadcast and not multicast", description: "Exclude broadcast/multicast" },
    { filter: "less 128", description: "Packets smaller than 128 bytes" },
    { filter: "greater 1000", description: "Packets larger than 1000 bytes" },
  ];

  const gettingStartedSteps = [
    {
      label: "Download & Install Wireshark",
      description: "Download Wireshark from wireshark.org. It's free and available for Windows, macOS, and Linux. On Windows, also install Npcap when prompted (required for packet capture).",
      icon: <DownloadIcon />,
      tips: ["Choose the stable release for production use", "Npcap is required on Windows", "On Linux, you may need to add yourself to the wireshark group"],
    },
    {
      label: "Select a Network Interface",
      description: "When you open Wireshark, you'll see a list of network interfaces. Each shows a live graph of traffic activity. Select the interface you want to capture from.",
      icon: <SettingsIcon />,
      tips: ["Wi-Fi adapter for wireless traffic", "Ethernet for wired connections", "Look for the interface with activity (moving graph)", "'any' captures from all interfaces (Linux)"],
    },
    {
      label: "Start Capturing Packets",
      description: "Click the blue shark fin button (or double-click an interface) to start capturing. Packets will start flowing into the main window in real-time.",
      icon: <PlayArrowIcon />,
      tips: ["The packet list updates in real-time", "You can capture for as long as needed", "Watch the packet counter in the status bar"],
    },
    {
      label: "Stop & Save Your Capture",
      description: "Click the red square button to stop capturing. Save your capture file (File → Save As) in .pcapng format for later analysis.",
      icon: <StopIcon />,
      tips: ["Use .pcapng format (newest, most features)", "Name files descriptively with date/time", "You can resume capturing after stopping"],
    },
    {
      label: "Apply Display Filters",
      description: "Use the filter bar at the top to narrow down to interesting traffic. Type a filter and press Enter. The bar turns green if valid, red if invalid.",
      icon: <FilterListIcon />,
      tips: ["Start with simple filters like 'http' or 'dns'", "Green bar = valid filter", "Red bar = syntax error", "Use the dropdown for filter history"],
    },
    {
      label: "Analyze Packets",
      description: "Click any packet to see its details in the middle pane. Expand protocol layers to see headers and data. The bottom pane shows raw hex/ASCII.",
      icon: <SearchIcon />,
      tips: ["Click + to expand protocol details", "Right-click for context options", "Follow streams to see conversations", "Use Statistics menu for overviews"],
    },
  ];

  const interfacePanels = [
    {
      name: "Packet List (Top)",
      description: "Shows all captured packets in a table format. Each row is one packet with key info like time, source, destination, protocol, and a brief summary.",
      color: "#3b82f6",
      icon: <LayersIcon />,
    },
    {
      name: "Packet Details (Middle)",
      description: "When you select a packet, this shows its full breakdown by protocol layer: Frame, Ethernet, IP, TCP/UDP, and application protocols.",
      color: "#8b5cf6",
      icon: <SearchIcon />,
    },
    {
      name: "Packet Bytes (Bottom)",
      description: "Raw hexadecimal and ASCII view of the selected packet. Useful for seeing exact byte values and finding hidden data.",
      color: "#10b981",
      icon: <KeyboardIcon />,
    },
  ];

  const securityUseCases = [
    {
      title: "🔓 Credential Hunting",
      description: "Find plaintext usernames and passwords in unencrypted traffic like HTTP Basic Auth, FTP, Telnet, or poorly configured applications.",
      filter: "http.authbasic or ftp or telnet",
      icon: <LockOpenIcon />,
      color: "#ef4444",
      steps: ["Apply the filter", "Look for Authorization headers", "Check FTP USER/PASS commands", "Export credentials found"],
    },
    {
      title: "🌐 Suspicious DNS Activity",
      description: "Identify DNS tunneling, data exfiltration via DNS, or connections to malicious domains.",
      filter: "dns.qry.name contains \"suspicious\" or dns.qry.name matches \".*\\\\d+.*\"",
      icon: <DnsIcon />,
      color: "#f59e0b",
      steps: ["Look for unusually long domain names", "Check for high frequency of queries", "Identify queries to rare TLDs", "Compare against threat intel"],
    },
    {
      title: "📤 Data Exfiltration",
      description: "Detect large outbound transfers, unusual protocols on standard ports, or connections to suspicious external IPs.",
      filter: "tcp.len > 1000 and ip.dst != 10.0.0.0/8",
      icon: <WarningIcon />,
      color: "#dc2626",
      steps: ["Filter for large packets leaving network", "Check Statistics → Conversations", "Look for unusual destination IPs", "Examine packet contents"],
    },
    {
      title: "🔍 Port Scanning Detection",
      description: "Identify reconnaissance attempts with many SYN packets to different ports without completing handshakes.",
      filter: "tcp.flags.syn == 1 and tcp.flags.ack == 0",
      icon: <BugReportIcon />,
      color: "#8b5cf6",
      steps: ["Apply SYN-only filter", "Check for single source, many ports", "Look for sequential port access", "Note timing patterns"],
    },
    {
      title: "🎯 Malware Beaconing",
      description: "Find command & control traffic by looking for regular, periodic connections to external hosts.",
      filter: "ip.dst != 10.0.0.0/8 and tcp.flags.syn == 1",
      icon: <TimelineIcon />,
      color: "#06b6d4",
      steps: ["Use Statistics → Conversations", "Sort by packet count", "Look for regular intervals", "Check destination reputation"],
    },
    {
      title: "🌍 HTTP Analysis",
      description: "Examine web traffic for suspicious requests, file downloads, or injection attempts.",
      filter: "http.request or http.response",
      icon: <HttpIcon />,
      color: "#10b981",
      steps: ["Filter for HTTP traffic", "Check request URIs for patterns", "Look at User-Agent strings", "Export HTTP objects"],
    },
  ];

  const keyboardShortcuts = [
    { shortcut: "Ctrl + E", action: "Start/Stop capture" },
    { shortcut: "Ctrl + K", action: "Stop capture" },
    { shortcut: "Ctrl + F", action: "Find packet" },
    { shortcut: "Ctrl + G", action: "Go to packet number" },
    { shortcut: "Ctrl + →", action: "Next packet in conversation" },
    { shortcut: "Ctrl + ←", action: "Previous packet in conversation" },
    { shortcut: "Ctrl + Shift + E", action: "Export packets" },
    { shortcut: "Ctrl + /", action: "Set/edit filter" },
  ];

  const statisticsMenuItems = [
    { item: "Statistics → Capture File Properties", description: "Overview of capture duration, packet counts, and data volume" },
    { item: "Statistics → Protocol Hierarchy", description: "Breakdown of all protocols in the capture by percentage" },
    { item: "Statistics → Conversations", description: "List of all host-to-host communications with packet/byte counts" },
    { item: "Statistics → Endpoints", description: "All unique IPs, Ethernet addresses, TCP/UDP ports seen" },
    { item: "Statistics → I/O Graph", description: "Visual timeline of traffic volume over capture duration" },
    { item: "Statistics → Flow Graph", description: "Sequence diagram of packet exchanges between hosts" },
  ];

  // State for tabs
  const [advancedTab, setAdvancedTab] = React.useState(0);

  // VRAgent Advanced PCAP Features Data
  const offensiveFeatures = [
    {
      icon: <ApiIcon />,
      title: "API Endpoint Discovery",
      description: "Automatically extracts all API endpoints from HTTP/HTTPS traffic with method, path, parameters, and body",
      color: "#3b82f6",
      details: ["HTTP method & URL extraction", "Query parameter parsing", "Request body analysis", "Content-Type detection"],
    },
    {
      icon: <TokenIcon />,
      title: "Auth Token Extraction",
      description: "Identifies and analyzes authentication mechanisms: JWT, Bearer, API keys, Basic Auth, OAuth, session cookies",
      color: "#8b5cf6",
      details: ["JWT claim decoding", "Weakness detection (none alg, short exp)", "Token hash tracking", "Credential exposure alerts"],
    },
    {
      icon: <GppMaybeIcon />,
      title: "Sensitive Data Detection",
      description: "Scans traffic for PII, credentials, and secrets with 15+ pattern categories",
      color: "#ef4444",
      details: ["PII (email, phone, SSN, credit card)", "API keys (AWS, GitHub, generic)", "Passwords & private keys", "SQL errors & stack traces"],
    },
    {
      icon: <ShieldIcon />,
      title: "Protocol Weakness Analysis",
      description: "Detects insecure protocol usage and misconfigurations",
      color: "#f59e0b",
      details: ["Cleartext HTTP detection", "Unencrypted FTP/Telnet/SMTP", "Weak TLS configurations", "Missing HSTS headers"],
    },
  ];

  const tlsFingerprintFeatures = [
    {
      type: "JA3",
      description: "Client TLS fingerprint derived from ClientHello parameters",
      usage: "Identify malware, C2 tools, and client applications",
      color: "#06b6d4",
      fields: ["TLS version", "Cipher suites", "Extensions", "Elliptic curves", "Point formats"],
    },
    {
      type: "JA3S",
      description: "Server TLS fingerprint from ServerHello response",
      usage: "Detect server-side malware or suspicious server configurations",
      color: "#10b981",
      fields: ["TLS version", "Selected cipher", "Extensions"],
    },
  ];

  const protocolParsers = [
    {
      icon: <HubIcon />,
      name: "WebSocket",
      description: "Full WebSocket session and frame analysis",
      features: ["Frame opcode detection", "Message reconstruction", "Binary/text payload parsing", "Ping/pong/close tracking"],
      color: "#8b5cf6",
    },
    {
      icon: <ApiIcon />,
      name: "gRPC",
      description: "HTTP/2 gRPC call extraction",
      features: ["Service/method extraction", "Request/response matching", "Streaming detection", "Error status tracking"],
      color: "#3b82f6",
    },
    {
      icon: <RouterIcon />,
      name: "MQTT",
      description: "IoT MQTT protocol analysis",
      features: ["Topic extraction", "Client ID tracking", "Publish/subscribe messages", "QoS level detection"],
      color: "#10b981",
    },
    {
      icon: <DeviceHubIcon />,
      name: "CoAP",
      description: "Constrained Application Protocol for IoT",
      features: ["Resource URI extraction", "Method detection (GET/POST/PUT/DELETE)", "Response codes", "Block transfers"],
      color: "#f59e0b",
    },
  ];

  const databaseProtocols = [
    { name: "MySQL", port: "3306", features: ["Query extraction", "Response parsing", "Authentication detection"] },
    { name: "PostgreSQL", port: "5432", features: ["Query extraction", "Error messages", "Protocol state tracking"] },
    { name: "Redis", port: "6379", features: ["RESP protocol parsing", "Command extraction", "Key enumeration"] },
    { name: "MongoDB", port: "27017", features: ["Wire protocol decoding", "Query document extraction", "Collection detection"] },
  ];

  const captureProfiles = [
    { name: "All Traffic", filter: "", description: "Capture all network traffic", intensity: 1 },
    { name: "HTTP/HTTPS", filter: "port 80 or port 443 or port 8080", description: "Web traffic only", intensity: 2 },
    { name: "DNS", filter: "port 53", description: "DNS queries and responses", intensity: 2 },
    { name: "Auth Protocols", filter: "port 21 or port 22 or port 23 or port 3389 or port 445", description: "FTP, SSH, Telnet, RDP, SMB", intensity: 3 },
    { name: "Email", filter: "port 25 or port 110 or port 143 or port 465 or port 587 or port 993 or port 995", description: "SMTP, POP3, IMAP", intensity: 3 },
    { name: "Database", filter: "port 3306 or port 5432 or port 1433 or port 27017", description: "MySQL, PostgreSQL, MSSQL, MongoDB", intensity: 3 },
    { name: "Suspicious Ports", filter: "port 4444 or port 5555 or port 6666 or port 1234 or port 31337 or port 8888", description: "Common backdoor/exploit ports", intensity: 4 },
    { name: "ICMP", filter: "icmp", description: "Ping and ICMP messages", intensity: 2 },
  ];

  const highValuePatterns = [
    { category: "Authentication", patterns: ["/auth", "/login", "/logout", "/signin", "/signup", "/register", "/oauth", "/token"] },
    { category: "Admin", patterns: ["/admin", "/dashboard", "/manage", "/console", "/control", "/settings", "/config"] },
    { category: "Payment", patterns: ["/payment", "/checkout", "/billing", "/invoice", "/subscribe", "/charge", "/order"] },
    { category: "User Data", patterns: ["/user", "/profile", "/account", "/me", "/self"] },
    { category: "File Operations", patterns: ["/upload", "/download", "/file", "/export", "/import", "/backup"] },
    { category: "Debug/Internal", patterns: ["/debug", "/test", "/dev", "/staging", "/internal", "/_", "/actuator", "/swagger", "/graphql"] },
  ];

  const pageContext = `Wireshark Complete Guide - The definitive network protocol analyzer tutorial. Covers: display filters (IP, port, protocol, flags, content), capture techniques (interface selection, ring buffers, remote capture), packet analysis (HTTP, DNS, TCP/TLS dissection), advanced techniques (following streams, conversations, expert info), coloring rules, protocol dissectors, command-line tools (tshark, dumpcap), keyboard shortcuts, and security analysis patterns. Essential for network troubleshooting, security monitoring, forensics, and protocol debugging.`;

  return (
    <LearnPageLayout pageTitle="Wireshark Complete Guide" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Link */}
      <Box sx={{ mb: 3 }}>
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2 }}
        />
      </Box>

      {/* Hero Header */}
      <Paper
        sx={{
          p: 5,
          mb: 5,
          borderRadius: 4,
          background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.15)} 0%, ${alpha("#3b82f6", 0.1)} 50%, ${alpha("#8b5cf6", 0.05)} 100%)`,
          border: `1px solid ${alpha("#06b6d4", 0.3)}`,
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Floating background elements */}
        <Box
          sx={{
            position: "absolute",
            top: -50,
            right: -50,
            width: 200,
            height: 200,
            borderRadius: "50%",
            background: `radial-gradient(circle, ${alpha("#06b6d4", 0.2)} 0%, transparent 70%)`,
            animation: `${float} 6s ease-in-out infinite`,
          }}
        />
        <Box
          sx={{
            position: "absolute",
            bottom: -30,
            left: "20%",
            width: 150,
            height: 150,
            borderRadius: "50%",
            background: `radial-gradient(circle, ${alpha("#3b82f6", 0.15)} 0%, transparent 70%)`,
            animation: `${float} 5s ease-in-out infinite`,
            animationDelay: "1s",
          }}
        />

        <Box sx={{ position: "relative", zIndex: 1 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
            <Box
              sx={{
                width: 80,
                height: 80,
                borderRadius: 3,
                background: `linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#06b6d4", 0.4)}`,
                animation: `${float} 4s ease-in-out infinite`,
              }}
            >
              <NetworkCheckIcon sx={{ fontSize: 44, color: "white" }} />
            </Box>
            <Box>
              <Typography
                variant="h3"
                sx={{
                  fontWeight: 800,
                  background: `linear-gradient(135deg, #06b6d4 0%, #3b82f6 50%, #8b5cf6 100%)`,
                  backgroundSize: "200% auto",
                  backgroundClip: "text",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  animation: `${shimmer} 4s linear infinite`,
                }}
              >
                Wireshark Essentials
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                Complete Beginner's Guide to Network Packet Analysis
              </Typography>
            </Box>
          </Box>

          <Typography variant="body1" sx={{ maxWidth: 700, mb: 3, fontSize: "1.1rem", lineHeight: 1.7 }}>
            Wireshark is the world's most popular network protocol analyzer. This guide will teach you 
            everything from installation to advanced security analysis—whether you're a beginner or 
            looking to sharpen your skills.
          </Typography>

          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
            <Button
              variant="contained"
              startIcon={<RocketLaunchIcon />}
              onClick={() => navigate("/network/pcap")}
              sx={{
                background: `linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)`,
                px: 3,
                py: 1.5,
                fontWeight: 600,
                boxShadow: `0 4px 20px ${alpha("#06b6d4", 0.4)}`,
                "&:hover": {
                  boxShadow: `0 6px 30px ${alpha("#06b6d4", 0.5)}`,
                },
              }}
            >
              Open PCAP Analyzer
            </Button>
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              component="a"
              href="https://www.wireshark.org/download.html"
              target="_blank"
              sx={{
                borderColor: alpha("#06b6d4", 0.5),
                color: "#22d3ee",
                "&:hover": {
                  borderColor: "#06b6d4",
                  bgcolor: alpha("#06b6d4", 0.1),
                },
              }}
            >
              Download Wireshark
            </Button>
          </Box>
        </Box>
      </Paper>

      {/* What is Wireshark */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SchoolIcon sx={{ color: "#3b82f6", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            What is Wireshark?
          </Typography>
        </Box>
        <Typography variant="body1" paragraph sx={{ fontSize: "1.05rem" }}>
          Wireshark is a free, open-source <strong>network protocol analyzer</strong> (also called a "packet sniffer"). 
          It captures network traffic passing through your computer's network interface and lets you inspect 
          every packet in detail—seeing exactly what data is being sent and received.
        </Typography>
        <Grid container spacing={3} sx={{ mb: 3 }}>
          {[
            { label: "Network Troubleshooting", desc: "Diagnose connectivity issues, slow performance, and protocol errors", color: "#3b82f6" },
            { label: "Security Analysis", desc: "Detect intrusions, malware communications, and data breaches", color: "#ef4444" },
            { label: "Protocol Learning", desc: "See exactly how TCP, HTTP, DNS, and other protocols work", color: "#10b981" },
            { label: "Forensic Investigation", desc: "Analyze captured traffic for evidence in security incidents", color: "#f59e0b" },
          ].map((item) => (
            <Grid item xs={12} sm={6} key={item.label}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha(item.color, 0.2)}`,
                  bgcolor: alpha(item.color, 0.03),
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 600, color: item.color, mb: 0.5 }}>
                  {item.label}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {item.desc}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
        <Paper
          sx={{
            p: 2,
            borderRadius: 2,
            bgcolor: alpha("#8b5cf6", 0.05),
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>💡 VRAgent Integration:</strong> VRAgent's PCAP Analyzer uses <strong>tshark</strong> (Wireshark's 
            command-line version) to process your captures and adds AI-powered security analysis on top. 
            You can capture in Wireshark, save the .pcap file, and upload it to VRAgent for automated analysis!
          </Typography>
        </Paper>
      </Paper>

      {/* Interface Overview */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <LayersIcon sx={{ color: "#6366f1", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Understanding the Interface
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Wireshark's main window is divided into three panels. Understanding each one is key to effective analysis:
        </Typography>
        <Grid container spacing={2}>
          {interfacePanels.map((panel) => (
            <Grid item xs={12} md={4} key={panel.name}>
              <Card
                sx={{
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(panel.color, 0.3)}`,
                  borderTop: `4px solid ${panel.color}`,
                }}
              >
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                    <Box sx={{ color: panel.color }}>{panel.icon}</Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      {panel.name}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {panel.description}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Getting Started - Stepper */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <RocketLaunchIcon sx={{ color: "#10b981", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Getting Started: Your First Capture
          </Typography>
        </Box>
        <Stepper orientation="vertical">
          {gettingStartedSteps.map((step, index) => (
            <Step key={step.label} active={true}>
              <StepLabel
                StepIconComponent={() => (
                  <Box
                    sx={{
                      width: 40,
                      height: 40,
                      borderRadius: "50%",
                      bgcolor: alpha("#10b981", 0.1),
                      color: "#10b981",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
                      fontSize: "1rem",
                    }}
                  >
                    {index + 1}
                  </Box>
                )}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ color: "#10b981" }}>{step.icon}</Box>
                  {step.label}
                </Typography>
              </StepLabel>
              <StepContent>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {step.description}
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {step.tips.map((tip, idx) => (
                    <Chip
                      key={idx}
                      label={tip}
                      size="small"
                      sx={{
                        bgcolor: alpha("#10b981", 0.1),
                        color: "#10b981",
                        fontSize: "0.75rem",
                      }}
                    />
                  ))}
                </Box>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </Paper>

      {/* Display Filters - Expanded */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <FilterListIcon sx={{ color: "#8b5cf6", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Display Filters
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Display filters let you focus on specific traffic <strong>after</strong> capture. Type them in the filter bar 
          and press Enter. The bar turns <span style={{ color: "#10b981", fontWeight: 600 }}>green</span> if valid 
          or <span style={{ color: "#ef4444", fontWeight: 600 }}>red</span> if there's a syntax error.
        </Typography>
        
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {["IP", "Port", "Protocol", "Flags", "Content", "Analysis"].map((cat) => (
            <Grid item xs={6} sm={4} md={2} key={cat}>
              <Chip
                label={cat}
                sx={{
                  width: "100%",
                  bgcolor: alpha("#8b5cf6", 0.1),
                  color: "#8b5cf6",
                  fontWeight: 600,
                }}
              />
            </Grid>
          ))}
        </Grid>

        <TableContainer sx={{ maxHeight: 400 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Filter</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Category</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {displayFilters.map((row) => (
                <TableRow key={row.filter} hover>
                  <TableCell>
                    <code style={{ 
                      backgroundColor: alpha("#8b5cf6", 0.1), 
                      padding: "4px 10px", 
                      borderRadius: 4,
                      fontSize: "0.85rem",
                      display: "inline-block",
                    }}>
                      {row.filter}
                    </code>
                  </TableCell>
                  <TableCell>{row.description}</TableCell>
                  <TableCell>
                    <Chip label={row.category} size="small" variant="outlined" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Paper
          sx={{
            p: 2,
            mt: 3,
            borderRadius: 2,
            bgcolor: alpha("#f59e0b", 0.05),
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>💡 Pro Tip:</strong> Combine filters with <code style={{ backgroundColor: alpha("#f59e0b", 0.2), padding: "2px 6px", borderRadius: 4 }}>and</code>, <code style={{ backgroundColor: alpha("#f59e0b", 0.2), padding: "2px 6px", borderRadius: 4 }}>or</code>, and <code style={{ backgroundColor: alpha("#f59e0b", 0.2), padding: "2px 6px", borderRadius: 4 }}>not</code>. 
            Example: <code style={{ backgroundColor: alpha("#f59e0b", 0.2), padding: "2px 6px", borderRadius: 4 }}>http and ip.addr == 192.168.1.1</code>
          </Typography>
        </Paper>
      </Paper>

      {/* Capture Filters */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <VisibilityIcon sx={{ color: "#10b981", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Capture Filters (BPF Syntax)
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Capture filters use <strong>Berkeley Packet Filter (BPF)</strong> syntax and are set <em>before</em> you 
          start capturing. They reduce file size by only capturing matching traffic—useful for long captures or 
          limited disk space.
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Filter</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {captureFilters.map((row) => (
                <TableRow key={row.filter} hover>
                  <TableCell>
                    <code style={{ 
                      backgroundColor: alpha("#10b981", 0.1), 
                      padding: "4px 10px", 
                      borderRadius: 4,
                      fontSize: "0.85rem",
                    }}>
                      {row.filter}
                    </code>
                  </TableCell>
                  <TableCell>{row.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <Paper
          sx={{
            p: 2,
            mt: 3,
            borderRadius: 2,
            bgcolor: alpha("#ef4444", 0.05),
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>⚠️ Important:</strong> Capture filters have different syntax than display filters! 
            Use <code>host</code> instead of <code>ip.addr</code>, <code>port</code> instead of <code>tcp.port</code>, etc.
          </Typography>
        </Paper>
      </Paper>

      {/* Security Use Cases */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SecurityIcon sx={{ color: "#ef4444", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Security Analysis Use Cases
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Here are common security scenarios and how to investigate them in Wireshark:
        </Typography>
        <Grid container spacing={3}>
          {securityUseCases.map((useCase) => (
            <Grid item xs={12} md={6} key={useCase.title}>
              <Accordion
                sx={{
                  borderRadius: 2,
                  border: `1px solid ${alpha(useCase.color, 0.2)}`,
                  "&:before": { display: "none" },
                  overflow: "hidden",
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon />}
                  sx={{
                    bgcolor: alpha(useCase.color, 0.05),
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box sx={{ color: useCase.color }}>{useCase.icon}</Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      {useCase.title}
                    </Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {useCase.description}
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" color="text.secondary">Example Filter:</Typography>
                    <Box>
                      <code style={{ 
                        backgroundColor: alpha(useCase.color, 0.1), 
                        padding: "6px 12px", 
                        borderRadius: 4,
                        fontSize: "0.8rem",
                        display: "inline-block",
                        marginTop: 4,
                      }}>
                        {useCase.filter}
                      </code>
                    </Box>
                  </Box>
                  <Typography variant="caption" color="text.secondary">Investigation Steps:</Typography>
                  <List dense disablePadding>
                    {useCase.steps.map((step, idx) => (
                      <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: useCase.color }} />
                        </ListItemIcon>
                        <ListItemText 
                          primary={step} 
                          primaryTypographyProps={{ variant: "body2" }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* VRAgent Advanced PCAP Features */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#ef4444", 0.05)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)`,
          border: `1px solid ${alpha("#ef4444", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
          <FingerprintIcon sx={{ color: "#ef4444", fontSize: 32 }} />
          <Box>
            <Typography variant="h5" sx={{ fontWeight: 700 }}>
              VRAgent Advanced PCAP Analysis
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Offensive security features powered by VRAgent's PCAP Analyzer
            </Typography>
          </Box>
        </Box>

        <Tabs
          value={advancedTab}
          onChange={(_, v) => setAdvancedTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            borderBottom: 1,
            borderColor: "divider",
            mt: 2,
            "& .MuiTab-root": { fontWeight: 600, textTransform: "none" },
          }}
        >
          <Tab icon={<GppMaybeIcon />} iconPosition="start" label="Attack Surface" />
          <Tab icon={<FingerprintIcon />} iconPosition="start" label="TLS Fingerprints" />
          <Tab icon={<HubIcon />} iconPosition="start" label="Protocol Parsers" />
          <Tab icon={<StorageIcon />} iconPosition="start" label="Database Traffic" />
          <Tab icon={<InsertDriveFileIcon />} iconPosition="start" label="File Extraction" />
        </Tabs>

        {/* Attack Surface Tab */}
        <TabPanel value={advancedTab} index={0}>
          <Typography variant="body1" sx={{ mb: 3 }}>
            VRAgent automatically analyzes PCAP files from an <strong>offensive security perspective</strong> to identify 
            API endpoints, authentication tokens, sensitive data leaks, and protocol weaknesses.
          </Typography>
          
          <Grid container spacing={3}>
            {offensiveFeatures.map((feature) => (
              <Grid item xs={12} md={6} key={feature.title}>
                <Paper
                  sx={{
                    p: 3,
                    borderRadius: 2,
                    border: `1px solid ${alpha(feature.color, 0.3)}`,
                    bgcolor: alpha(feature.color, 0.02),
                    height: "100%",
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                    <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      {feature.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {feature.description}
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75 }}>
                    {feature.details.map((detail, idx) => (
                      <Chip
                        key={idx}
                        label={detail}
                        size="small"
                        sx={{
                          bgcolor: alpha(feature.color, 0.1),
                          color: feature.color,
                          fontSize: "0.7rem",
                        }}
                      />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* High-Value Endpoint Detection */}
          <Paper
            sx={{
              p: 3,
              mt: 3,
              borderRadius: 2,
              bgcolor: alpha("#f59e0b", 0.05),
              border: `1px solid ${alpha("#f59e0b", 0.2)}`,
            }}
          >
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <SecurityIcon sx={{ color: "#f59e0b" }} />
              High-Value Endpoint Detection
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              VRAgent automatically identifies attack-priority endpoints based on URL patterns:
            </Typography>
            <Grid container spacing={2}>
              {highValuePatterns.map((cat) => (
                <Grid item xs={12} sm={6} md={4} key={cat.category}>
                  <Box>
                    <Typography variant="caption" sx={{ fontWeight: 600, color: "#f59e0b" }}>
                      {cat.category}
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                      {cat.patterns.slice(0, 4).map((p) => (
                        <Chip
                          key={p}
                          label={p}
                          size="small"
                          variant="outlined"
                          sx={{ fontSize: "0.65rem", height: 20 }}
                        />
                      ))}
                      {cat.patterns.length > 4 && (
                        <Chip label={`+${cat.patterns.length - 4}`} size="small" sx={{ fontSize: "0.65rem", height: 20 }} />
                      )}
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Export Formats */}
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1.5 }}>
              Export Formats
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.05) }}>
                  <Typography variant="body2" sx={{ fontWeight: 600, color: "#10b981", mb: 1 }}>
                    <TerminalIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                    cURL Commands
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Auto-generated curl commands for every API endpoint discovered, including headers, auth, and body
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05) }}>
                  <Typography variant="body2" sx={{ fontWeight: 600, color: "#8b5cf6", mb: 1 }}>
                    <BugReportIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                    Burp Suite Requests
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Raw HTTP requests formatted for Burp Repeater import, ready for manual testing
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* TLS Fingerprints Tab */}
        <TabPanel value={advancedTab} index={1}>
          <Typography variant="body1" sx={{ mb: 3 }}>
            <strong>JA3/JA3S fingerprinting</strong> creates unique identifiers for TLS clients and servers, 
            enabling detection of malware, C2 tools, and suspicious applications regardless of IP or domain.
          </Typography>

          <Grid container spacing={3}>
            {tlsFingerprintFeatures.map((fp) => (
              <Grid item xs={12} md={6} key={fp.type}>
                <Paper
                  sx={{
                    p: 3,
                    borderRadius: 2,
                    border: `1px solid ${alpha(fp.color, 0.3)}`,
                    bgcolor: alpha(fp.color, 0.02),
                    height: "100%",
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                    <FingerprintIcon sx={{ color: fp.color, fontSize: 28 }} />
                    <Box>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: fp.color }}>
                        {fp.type}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {fp.type === "JA3" ? "Client Fingerprint" : "Server Fingerprint"}
                      </Typography>
                    </Box>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {fp.description}
                  </Typography>
                  <Typography variant="caption" sx={{ fontWeight: 600 }}>Use Case:</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>{fp.usage}</Typography>
                  <Typography variant="caption" sx={{ fontWeight: 600 }}>Derived From:</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                    {fp.fields.map((field) => (
                      <Chip
                        key={field}
                        label={field}
                        size="small"
                        sx={{ bgcolor: alpha(fp.color, 0.1), color: fp.color, fontSize: "0.7rem" }}
                      />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Paper
            sx={{
              p: 2,
              mt: 3,
              borderRadius: 2,
              bgcolor: alpha("#ef4444", 0.05),
              border: `1px solid ${alpha("#ef4444", 0.2)}`,
            }}
          >
            <Typography variant="body2">
              <strong>🎯 Threat Hunting:</strong> JA3 fingerprints can identify known malware families like 
              Cobalt Strike, Metasploit, and RATs even when they use legitimate domains or change IPs. 
              VRAgent compares fingerprints against known malicious signatures.
            </Typography>
          </Paper>
        </TabPanel>

        {/* Protocol Parsers Tab */}
        <TabPanel value={advancedTab} index={2}>
          <Typography variant="body1" sx={{ mb: 3 }}>
            VRAgent includes <strong>deep protocol parsers</strong> for modern application protocols 
            beyond standard HTTP, enabling analysis of WebSocket, gRPC, and IoT communications.
          </Typography>

          <Grid container spacing={3}>
            {protocolParsers.map((parser) => (
              <Grid item xs={12} sm={6} key={parser.name}>
                <Paper
                  sx={{
                    p: 3,
                    borderRadius: 2,
                    border: `1px solid ${alpha(parser.color, 0.3)}`,
                    bgcolor: alpha(parser.color, 0.02),
                    height: "100%",
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                    <Box sx={{ color: parser.color }}>{parser.icon}</Box>
                    <Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {parser.name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {parser.description}
                      </Typography>
                    </Box>
                  </Box>
                  <List dense disablePadding>
                    {parser.features.map((feature, idx) => (
                      <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 20 }}>
                          <CheckCircleIcon sx={{ fontSize: 14, color: parser.color }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={feature}
                          primaryTypographyProps={{ variant: "body2" }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* HTTP/2 and QUIC */}
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1.5 }}>
              Also Supported
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>HTTP/2 Streams</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Multiplexed stream analysis, header compression (HPACK), server push detection
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>QUIC Connections</Typography>
                  <Typography variant="caption" color="text.secondary">
                    UDP-based transport detection, connection ID tracking, version identification
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* Database Traffic Tab */}
        <TabPanel value={advancedTab} index={3}>
          <Typography variant="body1" sx={{ mb: 3 }}>
            VRAgent can <strong>extract database queries</strong> from network traffic, revealing what data 
            applications are accessing and potential injection points.
          </Typography>

          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Database</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Port</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Extraction Capabilities</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {databaseProtocols.map((db) => (
                  <TableRow key={db.name} hover>
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <StorageIcon sx={{ fontSize: 18, color: "#6366f1" }} />
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{db.name}</Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip label={db.port} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {db.features.map((f) => (
                          <Chip key={f} label={f} size="small" sx={{ fontSize: "0.7rem" }} />
                        ))}
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Paper
            sx={{
              p: 2,
              mt: 3,
              borderRadius: 2,
              bgcolor: alpha("#ef4444", 0.05),
              border: `1px solid ${alpha("#ef4444", 0.2)}`,
            }}
          >
            <Typography variant="body2">
              <strong>⚠️ Security Note:</strong> Database queries in network traffic often reveal sensitive 
              information. VRAgent highlights SQL injection patterns, credential queries, and data enumeration attempts.
            </Typography>
          </Paper>
        </TabPanel>

        {/* File Extraction Tab */}
        <TabPanel value={advancedTab} index={4}>
          <Typography variant="body1" sx={{ mb: 3 }}>
            VRAgent can <strong>extract files</strong> transferred over HTTP, FTP, SMB, and other protocols, 
            calculating hashes for threat intelligence correlation.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 2,
                  border: `1px solid ${alpha("#3b82f6", 0.3)}`,
                  bgcolor: alpha("#3b82f6", 0.02),
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                  <InsertDriveFileIcon sx={{ color: "#3b82f6" }} />
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    File Carving
                  </Typography>
                </Box>
                <List dense>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary="Automatic file type detection via magic bytes" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary="HTTP response body extraction" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary="TCP stream reassembly for split transfers" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary="Gzip/deflate decompression" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 2,
                  border: `1px solid ${alpha("#10b981", 0.3)}`,
                  bgcolor: alpha("#10b981", 0.02),
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                  <FingerprintIcon sx={{ color: "#10b981" }} />
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    Hash Calculation
                  </Typography>
                </Box>
                <List dense>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary="MD5 hash for legacy systems" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary="SHA-256 hash for modern correlation" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary="VirusTotal / threat intel ready" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary="Filename and MIME type preservation" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                </List>
              </Paper>
            </Grid>
          </Grid>

          {/* Timeline */}
          <Paper
            sx={{
              p: 3,
              mt: 3,
              borderRadius: 2,
              bgcolor: alpha("#f59e0b", 0.05),
              border: `1px solid ${alpha("#f59e0b", 0.2)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
              <TimelineIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                Timeline Events
              </Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              VRAgent builds a chronological timeline of network events for forensic analysis:
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {["HTTP Requests/Responses", "DNS Queries", "TLS Handshakes", "Authentication Events", 
                "File Transfers", "Connection Resets", "Protocol Anomalies"].map((event) => (
                <Chip
                  key={event}
                  label={event}
                  size="small"
                  sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }}
                />
              ))}
            </Box>
          </Paper>
        </TabPanel>
      </Paper>

      {/* Capture Profiles */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <LayersIcon sx={{ color: "#06b6d4", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            VRAgent Capture Profiles
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          VRAgent supports <strong>live capture profiles</strong> with pre-configured BPF filters for different analysis scenarios:
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Profile</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>BPF Filter</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Intensity</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {captureProfiles.map((profile) => (
                <TableRow key={profile.name} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>{profile.name}</Typography>
                  </TableCell>
                  <TableCell>
                    {profile.filter ? (
                      <code style={{ 
                        backgroundColor: alpha("#06b6d4", 0.1), 
                        padding: "4px 8px", 
                        borderRadius: 4,
                        fontSize: "0.75rem",
                      }}>
                        {profile.filter}
                      </code>
                    ) : (
                      <Typography variant="caption" color="text.secondary">All traffic</Typography>
                    )}
                  </TableCell>
                  <TableCell>{profile.description}</TableCell>
                  <TableCell>
                    <Box sx={{ display: "flex", gap: 0.25 }}>
                      {[1, 2, 3, 4].map((level) => (
                        <Box
                          key={level}
                          sx={{
                            width: 16,
                            height: 8,
                            borderRadius: 1,
                            bgcolor: level <= profile.intensity 
                              ? profile.intensity >= 4 ? "#ef4444" 
                                : profile.intensity >= 3 ? "#f59e0b" 
                                : "#10b981"
                              : alpha("#6366f1", 0.1),
                          }}
                        />
                      ))}
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Statistics Menu */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <BarChartIcon sx={{ color: "#6366f1", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Essential Statistics Menu Items
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          The Statistics menu provides powerful views of your capture data:
        </Typography>
        <Grid container spacing={2}>
          {statisticsMenuItems.map((item) => (
            <Grid item xs={12} md={6} key={item.item}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha("#6366f1", 0.2)}`,
                }}
              >
                <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#6366f1", mb: 0.5 }}>
                  {item.item}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {item.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Keyboard Shortcuts */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <KeyboardIcon sx={{ color: "#f59e0b", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Keyboard Shortcuts
          </Typography>
        </Box>
        <Grid container spacing={2}>
          {keyboardShortcuts.map((shortcut) => (
            <Grid item xs={6} md={3} key={shortcut.shortcut}>
              <Paper
                sx={{
                  p: 2,
                  textAlign: "center",
                  borderRadius: 2,
                  border: `1px solid ${alpha("#f59e0b", 0.2)}`,
                }}
              >
                <Typography
                  variant="subtitle2"
                  sx={{
                    fontFamily: "monospace",
                    bgcolor: alpha("#f59e0b", 0.1),
                    px: 1.5,
                    py: 0.5,
                    borderRadius: 1,
                    display: "inline-block",
                    mb: 1,
                    fontWeight: 700,
                  }}
                >
                  {shortcut.shortcut}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {shortcut.action}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Tips & Tricks */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.1)}, ${alpha("#f59e0b", 0.05)})`,
          border: `1px solid ${alpha("#f59e0b", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <TipsAndUpdatesIcon sx={{ color: "#f59e0b", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Pro Tips & Tricks
          </Typography>
        </Box>
        <Grid container spacing={2}>
          {[
            { tip: "Right-click any packet → Follow → TCP Stream to see the full conversation in readable format", icon: <MouseIcon /> },
            { tip: "Use Edit → Preferences → Columns to customize what info shows in the packet list", icon: <SettingsIcon /> },
            { tip: "File → Export Objects → HTTP lets you extract all files (images, downloads) from HTTP traffic", icon: <FolderOpenIcon /> },
            { tip: "View → Coloring Rules to highlight suspicious traffic patterns automatically", icon: <ColorLensIcon /> },
            { tip: "Right-click a packet field → Apply as Filter to quickly filter on that value", icon: <FilterListIcon /> },
            { tip: "Use Statistics → Resolved Addresses to see DNS names for IPs in your capture", icon: <DnsIcon /> },
            { tip: "Analyze → Expert Information shows warnings, errors, and anomalies Wireshark detected", icon: <WarningIcon /> },
            { tip: "Save filtered results with File → Export Specified Packets to create smaller, focused captures", icon: <SaveIcon /> },
          ].map((item, idx) => (
            <Grid item xs={12} md={6} key={idx}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                <Box sx={{ color: "#f59e0b", mt: 0.25 }}>{item.icon}</Box>
                <Typography variant="body2">{item.tip}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* CTA Footer */}
      <Paper
        sx={{
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.1)} 0%, ${alpha("#3b82f6", 0.05)} 100%)`,
          border: `1px solid ${alpha("#06b6d4", 0.2)}`,
        }}
      >
        <NetworkCheckIcon sx={{ fontSize: 48, color: "#06b6d4", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Ready to Analyze Some Traffic?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          Capture some packets in Wireshark, save the .pcap file, and upload it to VRAgent's PCAP Analyzer 
          for AI-powered security analysis!
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<RocketLaunchIcon />}
            onClick={() => navigate("/network/pcap")}
            sx={{
              background: `linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)`,
              px: 4,
              py: 1.5,
              fontWeight: 700,
              fontSize: "1rem",
              boxShadow: `0 4px 20px ${alpha("#06b6d4", 0.4)}`,
              "&:hover": {
                boxShadow: `0 6px 30px ${alpha("#06b6d4", 0.5)}`,
              },
            }}
          >
            Open PCAP Analyzer
          </Button>
          <Button
            variant="outlined"
            size="large"
            component={Link}
            to="/learn/network-hub"
            sx={{
              borderColor: alpha("#8b5cf6", 0.5),
              color: "#a78bfa",
              px: 3,
              py: 1.5,
              "&:hover": {
                borderColor: "#8b5cf6",
                bgcolor: alpha("#8b5cf6", 0.1),
              },
            }}
          >
            Back to Network Hub Guide
          </Button>
        </Box>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
