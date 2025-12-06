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

  return (
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
  );
}
