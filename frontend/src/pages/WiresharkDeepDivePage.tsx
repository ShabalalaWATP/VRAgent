import React, { useState } from "react";
import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  useMediaQuery,
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
  Breadcrumbs,
  Link as MuiLink,
  Alert,
  Drawer,
  Fab,
  IconButton,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import FilterListIcon from "@mui/icons-material/FilterList";
import VisibilityIcon from "@mui/icons-material/Visibility";
import SecurityIcon from "@mui/icons-material/Security";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SchoolIcon from "@mui/icons-material/School";
import SettingsIcon from "@mui/icons-material/Settings";
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
import StorageIcon from "@mui/icons-material/Storage";
import DeviceHubIcon from "@mui/icons-material/DeviceHub";
import RouterIcon from "@mui/icons-material/Router";
import TerminalIcon from "@mui/icons-material/Terminal";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import ShieldIcon from "@mui/icons-material/Shield";
import HubIcon from "@mui/icons-material/Hub";
import SpeedIcon from "@mui/icons-material/Speed";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import ExtensionIcon from "@mui/icons-material/Extension";
import MemoryIcon from "@mui/icons-material/Memory";
import InfoIcon from "@mui/icons-material/Info";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import TroubleshootIcon from "@mui/icons-material/Troubleshoot";
import AnalyticsIcon from "@mui/icons-material/Analytics";
import DataObjectIcon from "@mui/icons-material/DataObject";
import DescriptionIcon from "@mui/icons-material/Description";
import StreamIcon from "@mui/icons-material/Stream";
import PhoneIcon from "@mui/icons-material/Phone";
import LockIcon from "@mui/icons-material/Lock";
import WifiIcon from "@mui/icons-material/Wifi";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import MenuIcon from "@mui/icons-material/Menu";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import ScienceIcon from "@mui/icons-material/Science";
import HistoryEduIcon from "@mui/icons-material/HistoryEdu";
import AssessmentIcon from "@mui/icons-material/Assessment";
import QuizIcon from "@mui/icons-material/Quiz";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import Avatar from "@mui/material/Avatar";
import ListItemButton from "@mui/material/ListItemButton";
import LearnPageLayout from "../components/LearnPageLayout";

// Section Navigation Items
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
  { id: "display-filters", label: "Display Filters", icon: <FilterListIcon /> },
  { id: "capture-filters", label: "Capture Filters (BPF)", icon: <TerminalIcon /> },
  { id: "tshark", label: "TShark CLI", icon: <CodeIcon /> },
  { id: "statistics", label: "Statistics & Analysis", icon: <BarChartIcon /> },
  { id: "protocol-dissection", label: "Protocol Dissection", icon: <LayersIcon /> },
  { id: "packet-workflow", label: "Packet Analysis Workflow", icon: <PlayArrowIcon /> },
  { id: "advanced-features", label: "Advanced Features", icon: <BuildIcon /> },
  { id: "security-analysis", label: "Security Analysis", icon: <SecurityIcon /> },
  { id: "forensic-scenarios", label: "Forensic Scenarios", icon: <HistoryEduIcon /> },
  { id: "performance-analysis", label: "Performance Analysis", icon: <SpeedIcon /> },
  { id: "protocol-guides", label: "Protocol-Specific Guides", icon: <HubIcon /> },
  { id: "voip", label: "VoIP Analysis", icon: <PhoneIcon /> },
  { id: "lua-scripting", label: "Lua Scripting", icon: <ExtensionIcon /> },
  { id: "best-practices", label: "Best Practices", icon: <TipsAndUpdatesIcon /> },
  { id: "resources", label: "Resources", icon: <MenuBookIcon /> },
];

// Theme colors
const pageTheme = {
  primary: "#0ea5e9",
  primaryLight: "#38bdf8",
  secondary: "#8b5cf6",
  accent: "#f59e0b",
  success: "#10b981",
  warning: "#f59e0b",
  info: "#3b82f6",
  error: "#ef4444",
  bgDark: "#0a0a0f",
  bgCard: "#12121a",
  bgNested: "#0f1024",
  bgCode: "#1a1a2e",
  border: "rgba(14, 165, 233, 0.2)",
  text: "#e2e8f0",
  textMuted: "#94a3b8",
};

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

// ==================== DATA DEFINITIONS ====================

// Display Filters - Comprehensive Reference
const DISPLAY_FILTERS = {
  basic: [
    { filter: "ip.addr == 192.168.1.1", description: "Traffic to/from specific IP", category: "IP Addressing" },
    { filter: "ip.src == 10.0.0.5 && ip.dst == 10.0.0.10", description: "Specific source to destination", category: "IP Addressing" },
    { filter: "ip.addr == 192.168.1.0/24", description: "Entire subnet traffic", category: "IP Addressing" },
    { filter: "!(ip.addr == 10.0.0.0/8)", description: "Exclude private range", category: "IP Addressing" },
    { filter: "eth.addr == aa:bb:cc:dd:ee:ff", description: "Filter by MAC address", category: "Ethernet" },
    { filter: "eth.type == 0x0800", description: "IPv4 frames only", category: "Ethernet" },
  ],
  protocol: [
    { filter: "tcp", description: "All TCP traffic", category: "Transport" },
    { filter: "udp", description: "All UDP traffic", category: "Transport" },
    { filter: "icmp", description: "ICMP (ping, traceroute)", category: "Network" },
    { filter: "arp", description: "ARP requests/replies", category: "Link" },
    { filter: "dns", description: "DNS queries and responses", category: "Application" },
    { filter: "http", description: "HTTP traffic (port 80)", category: "Application" },
    { filter: "tls", description: "TLS/SSL encrypted traffic", category: "Application" },
    { filter: "ssh", description: "SSH sessions", category: "Application" },
    { filter: "ftp", description: "FTP control channel", category: "Application" },
    { filter: "smtp", description: "Email (SMTP)", category: "Application" },
    { filter: "dhcp", description: "DHCP traffic", category: "Application" },
    { filter: "sip", description: "SIP VoIP signaling", category: "Application" },
    { filter: "rtp", description: "RTP media streams", category: "Application" },
  ],
  tcp: [
    { filter: "tcp.port == 443", description: "HTTPS traffic", category: "Port" },
    { filter: "tcp.port == 80 || tcp.port == 8080", description: "HTTP on common ports", category: "Port" },
    { filter: "tcp.srcport >= 1024", description: "Ephemeral source ports", category: "Port" },
    { filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0", description: "SYN packets (new connections)", category: "Flags" },
    { filter: "tcp.flags.fin == 1", description: "FIN packets (connection close)", category: "Flags" },
    { filter: "tcp.flags.rst == 1", description: "RST packets (connection reset)", category: "Flags" },
    { filter: "tcp.flags.push == 1", description: "PSH flag (immediate delivery)", category: "Flags" },
    { filter: "tcp.window_size == 0", description: "Zero window (flow control)", category: "Analysis" },
    { filter: "tcp.analysis.retransmission", description: "Retransmitted packets", category: "Analysis" },
    { filter: "tcp.analysis.duplicate_ack", description: "Duplicate ACKs", category: "Analysis" },
    { filter: "tcp.analysis.lost_segment", description: "Lost segments detected", category: "Analysis" },
    { filter: "tcp.analysis.fast_retransmission", description: "Fast retransmissions", category: "Analysis" },
    { filter: "tcp.analysis.zero_window", description: "Zero window probes", category: "Analysis" },
    { filter: "tcp.stream eq 5", description: "Specific TCP stream", category: "Stream" },
  ],
  http: [
    { filter: "http.request", description: "HTTP requests only", category: "Request" },
    { filter: "http.response", description: "HTTP responses only", category: "Response" },
    { filter: "http.request.method == \"GET\"", description: "GET requests", category: "Request" },
    { filter: "http.request.method == \"POST\"", description: "POST requests", category: "Request" },
    { filter: "http.request.uri contains \"login\"", description: "URIs containing 'login'", category: "Request" },
    { filter: "http.host contains \"example\"", description: "Host header contains 'example'", category: "Request" },
    { filter: "http.response.code == 200", description: "Successful responses", category: "Response" },
    { filter: "http.response.code >= 400", description: "Error responses (4xx, 5xx)", category: "Response" },
    { filter: "http.response.code == 401", description: "Unauthorized responses", category: "Response" },
    { filter: "http.content_type contains \"json\"", description: "JSON responses", category: "Content" },
    { filter: "http.content_length > 10000", description: "Large HTTP payloads", category: "Content" },
    { filter: "http.user_agent contains \"curl\"", description: "Curl user agent", category: "Header" },
    { filter: "http.cookie", description: "Requests with cookies", category: "Header" },
    { filter: "http.authorization", description: "Authorization headers", category: "Header" },
  ],
  dns: [
    { filter: "dns.qry.name", description: "All DNS queries", category: "Query" },
    { filter: "dns.qry.name == \"example.com\"", description: "Specific domain query", category: "Query" },
    { filter: "dns.qry.name contains \"malware\"", description: "Domain contains string", category: "Query" },
    { filter: "dns.qry.type == 1", description: "A record queries", category: "Query" },
    { filter: "dns.qry.type == 28", description: "AAAA record queries", category: "Query" },
    { filter: "dns.qry.type == 15", description: "MX record queries", category: "Query" },
    { filter: "dns.qry.type == 16", description: "TXT record queries", category: "Query" },
    { filter: "dns.flags.response == 1", description: "DNS responses only", category: "Response" },
    { filter: "dns.flags.rcode == 3", description: "NXDOMAIN responses", category: "Response" },
    { filter: "dns.resp.len > 512", description: "Large DNS responses", category: "Response" },
    { filter: "dns.count.answers > 10", description: "Many answer records", category: "Response" },
  ],
  tls: [
    { filter: "tls.handshake", description: "TLS handshake messages", category: "Handshake" },
    { filter: "tls.handshake.type == 1", description: "Client Hello", category: "Handshake" },
    { filter: "tls.handshake.type == 2", description: "Server Hello", category: "Handshake" },
    { filter: "tls.handshake.type == 11", description: "Certificate message", category: "Handshake" },
    { filter: "tls.handshake.extensions.server_name", description: "SNI extension present", category: "Extension" },
    { filter: "tls.handshake.extensions.server_name contains \"example\"", description: "SNI contains string", category: "Extension" },
    { filter: "tls.record.version == 0x0303", description: "TLS 1.2", category: "Version" },
    { filter: "tls.record.version == 0x0304", description: "TLS 1.3", category: "Version" },
    { filter: "ssl.alert_message", description: "TLS alert messages", category: "Alert" },
    { filter: "x509af.validity.notAfter", description: "Certificate expiry present", category: "Certificate" },
  ],
  security: [
    { filter: "frame contains \"password\"", description: "Packets containing 'password'", category: "Credential" },
    { filter: "frame contains \"username\"", description: "Packets containing 'username'", category: "Credential" },
    { filter: "http.authbasic", description: "HTTP Basic Auth headers", category: "Credential" },
    { filter: "ftp.request.command == \"PASS\"", description: "FTP password commands", category: "Credential" },
    { filter: "telnet", description: "Telnet traffic (plaintext)", category: "Cleartext" },
    { filter: "pop", description: "POP3 email (often plaintext)", category: "Cleartext" },
    { filter: "imap", description: "IMAP email traffic", category: "Cleartext" },
    { filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size <= 1024", description: "Possible SYN scan", category: "Scan" },
    { filter: "icmp.type == 8", description: "ICMP echo requests (ping)", category: "Scan" },
    { filter: "arp.duplicate-address-detected", description: "Duplicate IP detection", category: "Attack" },
  ],
};

// Capture Filters (BPF)
const CAPTURE_FILTERS = [
  { filter: "host 192.168.1.1", description: "Traffic to/from specific host", category: "Host" },
  { filter: "src host 10.0.0.5", description: "Traffic from specific source", category: "Host" },
  { filter: "dst host 8.8.8.8", description: "Traffic to specific destination", category: "Host" },
  { filter: "net 192.168.1.0/24", description: "Traffic from/to subnet", category: "Network" },
  { filter: "src net 10.0.0.0/8", description: "Traffic from private range", category: "Network" },
  { filter: "port 80", description: "Traffic on port 80", category: "Port" },
  { filter: "port 80 or port 443", description: "HTTP and HTTPS traffic", category: "Port" },
  { filter: "portrange 1-1024", description: "Well-known ports only", category: "Port" },
  { filter: "dst port 53", description: "Traffic to DNS port", category: "Port" },
  { filter: "tcp", description: "Only TCP traffic", category: "Protocol" },
  { filter: "udp", description: "Only UDP traffic", category: "Protocol" },
  { filter: "icmp", description: "Only ICMP traffic", category: "Protocol" },
  { filter: "ip proto 47", description: "GRE protocol", category: "Protocol" },
  { filter: "ether proto 0x0806", description: "ARP frames only", category: "Ethernet" },
  { filter: "ether host aa:bb:cc:dd:ee:ff", description: "Specific MAC address", category: "Ethernet" },
  { filter: "not broadcast and not multicast", description: "Exclude broadcast/multicast", category: "Exclusion" },
  { filter: "not arp", description: "Exclude ARP traffic", category: "Exclusion" },
  { filter: "less 128", description: "Small packets (<128 bytes)", category: "Size" },
  { filter: "greater 1000", description: "Large packets (>1000 bytes)", category: "Size" },
  { filter: "tcp[tcpflags] & (tcp-syn) != 0", description: "TCP SYN flag set", category: "Advanced" },
  { filter: "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn", description: "SYN only (no ACK)", category: "Advanced" },
  { filter: "ip[2:2] > 576", description: "IP packets > 576 bytes", category: "Advanced" },
];

// TShark Commands
const TSHARK_COMMANDS = [
  {
    category: "Basic Capture",
    commands: [
      { cmd: "tshark -i eth0", desc: "Capture on interface eth0" },
      { cmd: "tshark -i eth0 -w capture.pcap", desc: "Capture to file" },
      { cmd: "tshark -i eth0 -c 100", desc: "Capture 100 packets" },
      { cmd: "tshark -i eth0 -a duration:60", desc: "Capture for 60 seconds" },
      { cmd: "tshark -i eth0 -f \"port 80\"", desc: "Capture filter for port 80" },
    ],
  },
  {
    category: "Reading & Analysis",
    commands: [
      { cmd: "tshark -r capture.pcap", desc: "Read and display capture file" },
      { cmd: "tshark -r capture.pcap -Y \"http\"", desc: "Apply display filter" },
      { cmd: "tshark -r capture.pcap -c 50", desc: "Show first 50 packets" },
      { cmd: "tshark -r capture.pcap -q -z io,stat,1", desc: "I/O statistics per second" },
      { cmd: "tshark -r capture.pcap -q -z conv,tcp", desc: "TCP conversations summary" },
    ],
  },
  {
    category: "Field Extraction",
    commands: [
      { cmd: "tshark -r capture.pcap -T fields -e ip.src -e ip.dst", desc: "Extract IP addresses" },
      { cmd: "tshark -r capture.pcap -T fields -e http.host -e http.request.uri", desc: "Extract HTTP requests" },
      { cmd: "tshark -r capture.pcap -T fields -e dns.qry.name | sort | uniq -c", desc: "Count unique DNS queries" },
      { cmd: "tshark -r capture.pcap -T fields -e frame.time -e ip.src -E header=y", desc: "With column headers" },
      { cmd: "tshark -r capture.pcap -T json", desc: "Output as JSON" },
    ],
  },
  {
    category: "Statistics",
    commands: [
      { cmd: "tshark -r capture.pcap -q -z endpoints,ip", desc: "IP endpoint statistics" },
      { cmd: "tshark -r capture.pcap -q -z http,tree", desc: "HTTP request tree" },
      { cmd: "tshark -r capture.pcap -q -z dns,tree", desc: "DNS query statistics" },
      { cmd: "tshark -r capture.pcap -q -z expert", desc: "Expert info summary" },
      { cmd: "tshark -r capture.pcap -q -z follow,tcp,ascii,0", desc: "Follow TCP stream 0" },
    ],
  },
  {
    category: "Advanced",
    commands: [
      { cmd: "tshark -r capture.pcap -o \"ssl.keylog_file:keys.log\"", desc: "Decrypt TLS with keylog" },
      { cmd: "tshark -r capture.pcap -2 -R \"http\" -w filtered.pcap", desc: "Two-pass filter and save" },
      { cmd: "tshark -G fields | grep http", desc: "List available HTTP fields" },
      { cmd: "tshark -r capture.pcap --export-objects http,./exported", desc: "Export HTTP objects" },
      { cmd: "mergecap -w merged.pcap file1.pcap file2.pcap", desc: "Merge capture files" },
    ],
  },
];

// Statistics Menu Deep Dive
const STATISTICS_FEATURES = [
  {
    menu: "Capture File Properties",
    path: "Statistics > Capture File Properties",
    description: "Overview of the capture including duration, packet count, average packet size, and capture interface details.",
    useCase: "First step in any analysis - understand what you're working with",
    icon: <DescriptionIcon />,
    color: "#3b82f6",
  },
  {
    menu: "Protocol Hierarchy",
    path: "Statistics > Protocol Hierarchy",
    description: "Tree view showing all protocols in the capture with packet counts and percentages for each layer.",
    useCase: "Identify unexpected protocols, understand traffic composition",
    icon: <LayersIcon />,
    color: "#8b5cf6",
  },
  {
    menu: "Conversations",
    path: "Statistics > Conversations",
    description: "All communication pairs (Ethernet, IPv4, IPv6, TCP, UDP) with packet/byte counts and duration.",
    useCase: "Find top talkers, identify unusual communication patterns",
    icon: <DeviceHubIcon />,
    color: "#10b981",
  },
  {
    menu: "Endpoints",
    path: "Statistics > Endpoints",
    description: "All unique addresses seen (MAC, IP, TCP/UDP ports) with traffic statistics.",
    useCase: "Discover all hosts in capture, identify servers vs clients",
    icon: <RouterIcon />,
    color: "#f59e0b",
  },
  {
    menu: "I/O Graph",
    path: "Statistics > I/O Graph",
    description: "Customizable traffic timeline graphs. Add multiple plot lines with different filters.",
    useCase: "Visualize traffic patterns, correlate events, find spikes",
    icon: <TimelineIcon />,
    color: "#ef4444",
  },
  {
    menu: "Flow Graph",
    path: "Statistics > Flow Graph",
    description: "Sequence diagram showing packet exchanges between hosts. Choose between basic and TCP-focused views.",
    useCase: "Visualize handshakes, understand request/response flows",
    icon: <StreamIcon />,
    color: "#06b6d4",
  },
  {
    menu: "Expert Information",
    path: "Analyze > Expert Information",
    description: "Wireshark's analysis of potential issues: errors, warnings, notes. Grouped by severity.",
    useCase: "Quickly identify problems, troubleshoot network issues",
    icon: <TroubleshootIcon />,
    color: "#dc2626",
  },
  {
    menu: "Service Response Time",
    path: "Statistics > Service Response Time",
    description: "Response time analysis for various protocols (HTTP, DNS, SMB, etc.).",
    useCase: "Performance analysis, SLA monitoring, latency troubleshooting",
    icon: <SpeedIcon />,
    color: "#22c55e",
  },
];

// Expert Info Severity Levels
const EXPERT_INFO_LEVELS = [
  {
    severity: "Error",
    color: "#ef4444",
    icon: "X",
    description: "Serious problems that typically indicate malformed packets or protocol violations",
    examples: ["Malformed packet", "Checksum error", "Illegal value in field"],
  },
  {
    severity: "Warning",
    color: "#f59e0b",
    icon: "!",
    description: "Unusual conditions that may indicate problems but could be normal in some contexts",
    examples: ["TCP window full", "Connection reset", "Retransmission"],
  },
  {
    severity: "Note",
    color: "#3b82f6",
    icon: "i",
    description: "Notable events that are generally informational",
    examples: ["TCP window update", "Duplicate ACK", "Keep-alive"],
  },
  {
    severity: "Chat",
    color: "#6b7280",
    icon: "c",
    description: "Basic protocol information about the communication",
    examples: ["Connection established", "Connection terminated", "Sequence numbers"],
  },
];

// Protocol Dissection Deep Dive
const PROTOCOL_LAYERS = [
  {
    layer: "Frame",
    description: "Capture metadata including frame number, timestamp, capture length, and interface information",
    keyFields: ["frame.number", "frame.time", "frame.len", "frame.cap_len", "frame.protocols"],
    color: "#6b7280",
  },
  {
    layer: "Ethernet II",
    description: "Data link layer with source/destination MAC addresses and EtherType for payload identification",
    keyFields: ["eth.src", "eth.dst", "eth.type", "eth.addr"],
    color: "#8b5cf6",
  },
  {
    layer: "IPv4/IPv6",
    description: "Network layer with addressing, TTL, fragmentation, and protocol identification",
    keyFields: ["ip.src", "ip.dst", "ip.ttl", "ip.proto", "ip.len", "ip.flags", "ipv6.src", "ipv6.dst"],
    color: "#3b82f6",
  },
  {
    layer: "TCP",
    description: "Transport layer providing reliable, ordered delivery with flow control and connection management",
    keyFields: ["tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack", "tcp.flags", "tcp.window_size", "tcp.stream"],
    color: "#10b981",
  },
  {
    layer: "UDP",
    description: "Transport layer providing connectionless, best-effort delivery",
    keyFields: ["udp.srcport", "udp.dstport", "udp.length", "udp.checksum"],
    color: "#22c55e",
  },
  {
    layer: "Application",
    description: "Protocol-specific dissection (HTTP, DNS, TLS, etc.) with decoded fields and values",
    keyFields: ["http.request.method", "http.host", "dns.qry.name", "tls.handshake.type"],
    color: "#f59e0b",
  },
];

// Coloring Rules
const COLOR_RULES = [
  { name: "Bad TCP", color: "#000000", bgcolor: "#ff0000", description: "TCP errors, resets, RST packets" },
  { name: "Checksum Errors", color: "#000000", bgcolor: "#ff5f5f", description: "Invalid checksums" },
  { name: "HTTP", color: "#000000", bgcolor: "#b4e1b4", description: "HTTP traffic (green)" },
  { name: "HTTPS/TLS", color: "#000000", bgcolor: "#acd6ff", description: "Encrypted HTTPS traffic (blue)" },
  { name: "TCP SYN/FIN", color: "#000000", bgcolor: "#a0a0a0", description: "Connection setup/teardown" },
  { name: "DNS", color: "#000000", bgcolor: "#fff3b2", description: "DNS queries and responses (yellow)" },
  { name: "ICMP", color: "#000000", bgcolor: "#ffc0ff", description: "ICMP messages (pink)" },
  { name: "ARP", color: "#000000", bgcolor: "#faf0d7", description: "ARP requests/replies (tan)" },
  { name: "Broadcast", color: "#000000", bgcolor: "#f0f0f0", description: "Broadcast traffic (gray)" },
];

// Keyboard Shortcuts
const KEYBOARD_SHORTCUTS = [
  { category: "Capture", shortcuts: [
    { key: "Ctrl + E", action: "Start/Stop capture" },
    { key: "Ctrl + K", action: "Stop capture" },
    { key: "Ctrl + R", action: "Restart capture" },
  ]},
  { category: "Navigation", shortcuts: [
    { key: "Ctrl + G", action: "Go to packet number" },
    { key: "Ctrl + F", action: "Find packet" },
    { key: "Ctrl + N", action: "Find next" },
    { key: "Ctrl + B", action: "Find previous" },
    { key: "Ctrl + Right", action: "Next packet in conversation" },
    { key: "Ctrl + Left", action: "Previous packet in conversation" },
    { key: "Ctrl + .", action: "Next packet in same TCP stream" },
    { key: "Ctrl + ,", action: "Previous packet in same TCP stream" },
  ]},
  { category: "Display", shortcuts: [
    { key: "Ctrl + /", action: "Set focus to filter bar" },
    { key: "Ctrl + Down", action: "Apply as filter (selected)" },
    { key: "Ctrl + Shift + Down", action: "Prepare as filter (selected)" },
    { key: "Ctrl + H", action: "Toggle packet bytes pane" },
    { key: "Ctrl + T", action: "Toggle packet details pane" },
  ]},
  { category: "Marking", shortcuts: [
    { key: "Ctrl + M", action: "Mark/Unmark packet" },
    { key: "Shift + Ctrl + N", action: "Next marked packet" },
    { key: "Shift + Ctrl + B", action: "Previous marked packet" },
    { key: "Ctrl + Shift + M", action: "Unmark all packets" },
  ]},
  { category: "Export", shortcuts: [
    { key: "Ctrl + Shift + E", action: "Export specified packets" },
    { key: "Ctrl + S", action: "Save capture file" },
    { key: "Ctrl + Shift + S", action: "Save as" },
  ]},
];

// TLS Decryption Steps
const TLS_DECRYPTION_METHODS = [
  {
    method: "Pre-Master Secret Log (SSLKEYLOGFILE)",
    difficulty: "Easy",
    description: "Browser/application exports session keys during TLS handshake. Works with Perfect Forward Secrecy.",
    steps: [
      "Set environment variable: export SSLKEYLOGFILE=/path/to/keys.log",
      "Start browser/application",
      "Capture traffic with Wireshark",
      "In Wireshark: Edit > Preferences > Protocols > TLS",
      "Set '(Pre)-Master-Secret log filename' to your keys.log",
      "Apply and watch TLS traffic decrypt in real-time",
    ],
    platforms: ["Chrome", "Firefox", "curl (with OpenSSL)", "Python requests"],
    color: "#10b981",
  },
  {
    method: "RSA Private Key",
    difficulty: "Medium",
    description: "Import server's RSA private key. Only works with RSA key exchange (not ECDHE/DHE).",
    steps: [
      "Obtain server's private key (PEM format)",
      "In Wireshark: Edit > Preferences > Protocols > TLS",
      "Click 'Edit' next to RSA keys list",
      "Add entry: IP, Port, Protocol, Key File path",
      "Apply - RSA-encrypted traffic will be decrypted",
    ],
    platforms: ["Servers using RSA key exchange only"],
    color: "#f59e0b",
    warning: "Does not work with Perfect Forward Secrecy (ECDHE/DHE)",
  },
  {
    method: "Decryption via Proxy (mitmproxy)",
    difficulty: "Advanced",
    description: "Use a MITM proxy to intercept and re-encrypt traffic. Requires installing proxy CA certificate.",
    steps: [
      "Install mitmproxy: pip install mitmproxy",
      "Run: mitmproxy --mode transparent or mitmdump",
      "Configure client to trust mitmproxy CA certificate",
      "Export traffic: mitmdump -w capture.pcap",
      "Open in Wireshark with decrypted content",
    ],
    platforms: ["Any client you can configure"],
    color: "#8b5cf6",
  },
];

// File Carving Objects
const EXPORTABLE_OBJECTS = [
  { protocol: "HTTP", description: "Web downloads, images, scripts, API responses", path: "File > Export Objects > HTTP" },
  { protocol: "IMF", description: "Email messages from IMAP/POP3", path: "File > Export Objects > IMF" },
  { protocol: "SMB", description: "Windows file shares, document transfers", path: "File > Export Objects > SMB" },
  { protocol: "TFTP", description: "TFTP file transfers", path: "File > Export Objects > TFTP" },
  { protocol: "DICOM", description: "Medical imaging files", path: "File > Export Objects > DICOM" },
];

// Security Analysis Patterns
const SECURITY_PATTERNS = [
  {
    attack: "Port Scanning (SYN Scan)",
    description: "Many SYN packets to different ports without completing handshakes",
    filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    indicators: ["Single source, many destination ports", "Sequential port access", "No data exchange", "Many RST responses"],
    icon: <BugReportIcon />,
    color: "#ef4444",
  },
  {
    attack: "DNS Tunneling",
    description: "Data exfiltration through DNS queries using encoded subdomains",
    filter: "dns.qry.name.len > 50 || dns.qry.type == 16",
    indicators: ["Unusually long domain names", "High frequency DNS queries", "TXT record queries", "Single destination DNS server"],
    icon: <DnsIcon />,
    color: "#f59e0b",
  },
  {
    attack: "ARP Spoofing",
    description: "Attacker sends fake ARP replies to intercept traffic",
    filter: "arp.duplicate-address-detected || arp.opcode == 2",
    indicators: ["Multiple MACs for same IP", "Gratuitous ARP floods", "IP-MAC mapping changes", "ARP replies without requests"],
    icon: <WifiIcon />,
    color: "#dc2626",
  },
  {
    attack: "Beaconing (C2)",
    description: "Regular, periodic connections to command & control servers",
    filter: "ip.dst != 10.0.0.0/8 && tcp.flags.syn == 1",
    indicators: ["Regular time intervals", "Consistent packet sizes", "Same destination IP", "Low data volume"],
    icon: <TimelineIcon />,
    color: "#8b5cf6",
  },
  {
    attack: "Data Exfiltration",
    description: "Large outbound data transfers to external hosts",
    filter: "tcp.len > 1400 && !(ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16)",
    indicators: ["Large outbound transfers", "Unusual destination IPs", "Non-standard ports", "Encrypted traffic to unknown hosts"],
    icon: <GppMaybeIcon />,
    color: "#dc2626",
  },
  {
    attack: "Credential Harvesting",
    description: "Plaintext credentials in unencrypted protocols",
    filter: "http.authbasic || ftp.request.command == \"PASS\" || telnet",
    indicators: ["HTTP Basic Auth headers", "FTP USER/PASS commands", "Telnet sessions", "SMTP AUTH commands"],
    icon: <LockOpenIcon />,
    color: "#ef4444",
  },
];

// VoIP Analysis
const VOIP_ANALYSIS = [
  {
    feature: "RTP Streams",
    path: "Telephony > RTP > RTP Streams",
    description: "List all RTP audio/video streams with jitter, packet loss, and codec info",
  },
  {
    feature: "VoIP Calls",
    path: "Telephony > VoIP Calls",
    description: "Complete call list with SIP signaling and associated RTP streams",
  },
  {
    feature: "Play Streams",
    path: "Telephony > RTP > RTP Player",
    description: "Playback captured audio from RTP streams (G.711, G.722, etc.)",
  },
  {
    feature: "SIP Flows",
    path: "Telephony > SIP Flows",
    description: "Visualize SIP call setup, including INVITE, 200 OK, ACK, BYE",
  },
];

// Custom Columns
const USEFUL_CUSTOM_COLUMNS = [
  { title: "Delta Time (Displayed)", field: "frame.time_delta_displayed", description: "Time since previous displayed packet" },
  { title: "TCP Stream", field: "tcp.stream", description: "TCP stream index for filtering" },
  { title: "HTTP Host", field: "http.host", description: "HTTP Host header value" },
  { title: "DNS Query", field: "dns.qry.name", description: "DNS query name" },
  { title: "TLS SNI", field: "tls.handshake.extensions_server_name", description: "TLS Server Name Indication" },
  { title: "TCP Flags", field: "tcp.flags", description: "TCP flag summary (hex)" },
  { title: "Window Size", field: "tcp.window_size_value", description: "TCP window size" },
  { title: "Payload Length", field: "tcp.len", description: "TCP payload length" },
];

// ==================== COMPONENT ====================

export default function WiresharkDeepDivePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);

  // State for tabs
  const [filterTab, setFilterTab] = React.useState(0);
  const [analysisTab, setAnalysisTab] = React.useState(0);
  const [advancedTab, setAdvancedTab] = React.useState(0);

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    setNavDrawerOpen(false);
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const pageContext = `Comprehensive Wireshark deep dive covering:
- Display filters: IP, protocol, TCP, HTTP, DNS, TLS, security filters
- Capture filters (BPF syntax) for efficient packet capture
- TShark command-line analysis and field extraction
- Protocol dissection and layer analysis
- Statistics: Protocol Hierarchy, Conversations, Endpoints, I/O Graph, Flow Graph
- Expert Information for troubleshooting
- TLS/SSL decryption methods (SSLKEYLOGFILE, RSA keys, MITM proxy)
- File carving and object export (HTTP, SMB, IMF)
- Security analysis: port scanning, DNS tunneling, ARP spoofing, C2 beaconing
- VoIP analysis: RTP streams, SIP flows, audio playback
- Custom columns, color rules, profiles, and keyboard shortcuts
- Lua scripting for custom dissectors
- Performance analysis and troubleshooting patterns`;

  // Sidebar navigation component
  const sidebarNav = (
    <Box sx={{ position: "sticky", top: 24 }}>
      <Paper
        sx={{
          bgcolor: pageTheme.bgCard,
          border: `1px solid ${pageTheme.border}`,
          borderRadius: 2,
          p: 2,
        }}
      >
        <Typography variant="subtitle2" sx={{ color: pageTheme.primary, mb: 2, fontWeight: 600 }}>
          NAVIGATION
        </Typography>
        <List dense disablePadding>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              component="button"
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1,
                mb: 0.5,
                cursor: "pointer",
                border: "none",
                bgcolor: "transparent",
                width: "100%",
                textAlign: "left",
                "&:hover": {
                  bgcolor: alpha(pageTheme.primary, 0.1),
                },
              }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: pageTheme.primary }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  variant: "body2",
                  sx: { color: pageTheme.text },
                }}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );

  return (
    <LearnPageLayout pageTitle="Wireshark Deep Dive" pageContext={pageContext}>
      <Box sx={{ bgcolor: pageTheme.bgDark, minHeight: "100vh", py: 4 }}>
        <Container maxWidth="xl">
          <Grid container spacing={3}>
            {/* Sidebar - Desktop */}
            <Grid item md={3} sx={{ display: { xs: "none", md: "block" } }}>
              {sidebarNav}
            </Grid>

            {/* Main Content */}
            <Grid item xs={12} md={9}>
              {/* Back Link */}
              <Chip
                component={Link}
                to="/learn"
                icon={<ArrowBackIcon />}
                label="Back to Learning Hub"
                clickable
                variant="outlined"
                sx={{
                  mb: 3,
                  borderColor: pageTheme.primary,
                  color: pageTheme.primary,
                  "&:hover": {
                    bgcolor: alpha(pageTheme.primary, 0.1),
                    borderColor: pageTheme.primaryLight,
                  },
                }}
              />

        {/* Breadcrumbs */}
        <Breadcrumbs separator={<NavigateNextIcon fontSize="small" />} sx={{ mb: 2 }}>
          <MuiLink component={Link} to="/learn" color="inherit" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <MenuBookIcon fontSize="small" />
            Learn
          </MuiLink>
          <Typography color="text.primary" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <NetworkCheckIcon fontSize="small" />
            Wireshark Deep Dive
          </Typography>
        </Breadcrumbs>

        {/* Hero Section */}
        <Box id="intro">
        <Paper
          sx={{
            p: 5,
            mb: 5,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#0ea5e9", 0.15)} 0%, ${alpha("#6366f1", 0.1)} 50%, ${alpha("#8b5cf6", 0.05)} 100%)`,
            border: `1px solid ${alpha("#0ea5e9", 0.3)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          {/* Floating background decorations */}
          <Box
            sx={{
              position: "absolute",
              top: -50,
              right: -50,
              width: 200,
              height: 200,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#0ea5e9", 0.2)} 0%, transparent 70%)`,
              animation: `${float} 6s ease-in-out infinite`,
            }}
          />
          <Box
            sx={{
              position: "absolute",
              bottom: -30,
              left: "30%",
              width: 150,
              height: 150,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.15)} 0%, transparent 70%)`,
              animation: `${float} 8s ease-in-out infinite`,
              animationDelay: "-2s",
            }}
          />

          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#0ea5e9", 0.4)}`,
                  animation: `${float} 4s ease-in-out infinite`,
                }}
              >
                <NetworkCheckIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, color: pageTheme.text }}>
                  Wireshark Deep Dive
                </Typography>
                <Typography variant="h6" sx={{ mt: 0.5, color: pageTheme.textMuted }}>
                  Master packet analysis for network forensics, security research, and troubleshooting
                </Typography>
              </Box>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, maxWidth: 800, color: pageTheme.text }}>
              This comprehensive guide covers everything you need to become proficient with Wireshark - from basic filtering
              to advanced TLS decryption, security analysis, and custom Lua scripting. Learn to extract the exact information
              you need from network captures. Wireshark is the world's most widely used network protocol analyzer, essential 
              for cybersecurity professionals, network engineers, and forensic analysts alike.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, maxWidth: 800, color: pageTheme.text }}>
              <strong>Why Wireshark?</strong> In the world of network analysis, Wireshark stands as the gold standard tool. 
              Whether you're investigating a security incident, troubleshooting network performance issues, analyzing malware 
              communication, or learning about network protocols, Wireshark provides unparalleled visibility into what's 
              happening on your network. This deep dive will take you from basic filtering to advanced techniques used by 
              professional security analysts and incident responders.
            </Typography>

            <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
              <Chip label="Display Filters" sx={{ bgcolor: alpha(pageTheme.primary, 0.2), color: pageTheme.primary }} />
              <Chip label="Capture Filters (BPF)" sx={{ bgcolor: alpha(pageTheme.secondary, 0.2), color: pageTheme.secondary }} />
              <Chip label="TShark CLI" sx={{ bgcolor: alpha(pageTheme.accent, 0.2), color: pageTheme.accent }} />
              <Chip label="TLS Decryption" sx={{ bgcolor: alpha(pageTheme.info, 0.2), color: pageTheme.info }} />
              <Chip label="Security Analysis" sx={{ bgcolor: alpha(pageTheme.error, 0.2), color: pageTheme.error }} />
              <Chip label="Statistics & Graphs" sx={{ bgcolor: alpha(pageTheme.success, 0.2), color: pageTheme.success }} />
            </Box>
          </Box>
        </Paper>
        </Box>

        {/* Quick Stats */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          {[
            { value: "100+", label: "Display Filters", icon: <FilterListIcon />, color: "#3b82f6" },
            { value: "20+", label: "Capture Filters", icon: <TerminalIcon />, color: "#10b981" },
            { value: "25+", label: "TShark Commands", icon: <CodeIcon />, color: "#8b5cf6" },
            { value: "6", label: "Security Patterns", icon: <SecurityIcon />, color: "#ef4444" },
          ].map((stat, idx) => (
            <Grid item xs={6} md={3} key={idx}>
              <Paper
                sx={{
                  p: 3,
                  textAlign: "center",
                  borderRadius: 3,
                  border: `1px solid ${alpha(stat.color, 0.2)}`,
                  background: `linear-gradient(135deg, ${alpha(stat.color, 0.05)} 0%, transparent 100%)`,
                  bgcolor: pageTheme.bgCard,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    boxShadow: `0 8px 30px ${alpha(stat.color, 0.2)}`,
                  },
                }}
              >
                <Box sx={{ color: stat.color, mb: 1 }}>{stat.icon}</Box>
                <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                  {stat.value}
                </Typography>
                <Typography variant="body2" sx={{ color: pageTheme.textMuted }}>
                  {stat.label}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== DISPLAY FILTERS SECTION ==================== */}
        <Box id="display-filters">
        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: pageTheme.bgCard, border: `1px solid ${pageTheme.border}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
            <FilterListIcon sx={{ color: "#3b82f6" }} />
            Display Filters Reference
          </Typography>
          <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
            Display filters narrow down packets after capture. Use these in the filter bar (green = valid, red = invalid).
          </Typography>
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
            <strong>Understanding Display Filters:</strong> Display filters are one of Wireshark's most powerful features. 
            Unlike capture filters which limit what packets are saved to disk, display filters work on captured data, 
            allowing you to hide irrelevant packets while keeping them available for later analysis. The filter bar at 
            the top of Wireshark's main window turns green when you enter a valid filter expression and red when the 
            syntax is incorrect. You can combine filters using logical operators (&&, ||, !) to create complex queries 
            that zero in on exactly the traffic you need to analyze.
          </Typography>

          <Tabs
            value={filterTab}
            onChange={(_, v) => setFilterTab(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ borderBottom: 1, borderColor: "divider", mb: 2 }}
          >
            <Tab label="Basic & IP" sx={{ color: pageTheme.text }} />
            <Tab label="Protocols" sx={{ color: pageTheme.text }} />
            <Tab label="TCP Analysis" sx={{ color: pageTheme.text }} />
            <Tab label="HTTP" sx={{ color: pageTheme.text }} />
            <Tab label="DNS" sx={{ color: pageTheme.text }} />
            <Tab label="TLS/SSL" sx={{ color: pageTheme.text }} />
            <Tab label="Security" sx={{ color: pageTheme.text }} />
          </Tabs>

          <TabPanel value={filterTab} index={0}>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: "40%", color: pageTheme.text }}>Filter</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "15%", color: pageTheme.text }}>Category</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {DISPLAY_FILTERS.basic.map((f, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell>
                        <Box component="code" sx={{ bgcolor: alpha("#3b82f6", 0.1), px: 1, py: 0.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem", color: pageTheme.text }}>
                          {f.filter}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: pageTheme.text }}>{f.description}</TableCell>
                      <TableCell><Chip label={f.category} size="small" sx={{ bgcolor: alpha(pageTheme.primary, 0.2), color: pageTheme.primary }} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>

          <TabPanel value={filterTab} index={1}>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: "30%", color: pageTheme.text }}>Filter</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "15%", color: pageTheme.text }}>Layer</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {DISPLAY_FILTERS.protocol.map((f, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell>
                        <Box component="code" sx={{ bgcolor: alpha("#8b5cf6", 0.1), px: 1, py: 0.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem", color: pageTheme.text }}>
                          {f.filter}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: pageTheme.text }}>{f.description}</TableCell>
                      <TableCell><Chip label={f.category} size="small" sx={{ bgcolor: alpha(pageTheme.secondary, 0.2), color: pageTheme.secondary }} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>

          <TabPanel value={filterTab} index={2}>
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>TCP Analysis filters</strong> are automatically added by Wireshark's dissector and help identify network issues.
              </Typography>
            </Alert>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: "45%", color: pageTheme.text }}>Filter</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "15%", color: pageTheme.text }}>Type</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {DISPLAY_FILTERS.tcp.map((f, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell>
                        <Box component="code" sx={{ bgcolor: alpha("#10b981", 0.1), px: 1, py: 0.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem", color: pageTheme.text }}>
                          {f.filter}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: pageTheme.text }}>{f.description}</TableCell>
                      <TableCell><Chip label={f.category} size="small" sx={{ bgcolor: alpha(pageTheme.success, 0.2), color: pageTheme.success }} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>

          <TabPanel value={filterTab} index={3}>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: "45%", color: pageTheme.text }}>Filter</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "15%", color: pageTheme.text }}>Type</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {DISPLAY_FILTERS.http.map((f, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell>
                        <Box component="code" sx={{ bgcolor: alpha("#22c55e", 0.1), px: 1, py: 0.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem", color: pageTheme.text }}>
                          {f.filter}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: pageTheme.text }}>{f.description}</TableCell>
                      <TableCell><Chip label={f.category} size="small" sx={{ bgcolor: alpha("#22c55e", 0.2), color: "#22c55e" }} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>

          <TabPanel value={filterTab} index={4}>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: "45%", color: pageTheme.text }}>Filter</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "15%", color: pageTheme.text }}>Type</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {DISPLAY_FILTERS.dns.map((f, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell>
                        <Box component="code" sx={{ bgcolor: alpha("#f59e0b", 0.1), px: 1, py: 0.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem", color: pageTheme.text }}>
                          {f.filter}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: pageTheme.text }}>{f.description}</TableCell>
                      <TableCell><Chip label={f.category} size="small" sx={{ bgcolor: alpha(pageTheme.accent, 0.2), color: pageTheme.accent }} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>

          <TabPanel value={filterTab} index={5}>
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>TLS filters</strong> work on handshake metadata. To see decrypted content, configure TLS decryption (see Advanced section).
              </Typography>
            </Alert>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: "50%", color: pageTheme.text }}>Filter</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "15%", color: pageTheme.text }}>Type</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {DISPLAY_FILTERS.tls.map((f, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell>
                        <Box component="code" sx={{ bgcolor: alpha("#06b6d4", 0.1), px: 1, py: 0.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem", color: pageTheme.text }}>
                          {f.filter}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: pageTheme.text }}>{f.description}</TableCell>
                      <TableCell><Chip label={f.category} size="small" sx={{ bgcolor: alpha("#06b6d4", 0.2), color: "#06b6d4" }} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>

          <TabPanel value={filterTab} index={6}>
            <Alert severity="warning" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>Security Note:</strong> These filters help identify suspicious activity. Always ensure you have proper authorization before analyzing network traffic.
              </Typography>
            </Alert>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: "50%", color: pageTheme.text }}>Filter</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "15%", color: pageTheme.text }}>Type</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {DISPLAY_FILTERS.security.map((f, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell>
                        <Box component="code" sx={{ bgcolor: alpha("#ef4444", 0.1), px: 1, py: 0.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem", color: pageTheme.text }}>
                          {f.filter}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: pageTheme.text }}>{f.description}</TableCell>
                      <TableCell><Chip label={f.category} size="small" sx={{ bgcolor: alpha(pageTheme.error, 0.2), color: pageTheme.error }} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>

          {/* Filter Syntax Tips */}
          <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: pageTheme.text }}>Filter Syntax Tips</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <List dense disablePadding>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} /></ListItemIcon>
                    <ListItemText primary="&& or and - Logical AND" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} /></ListItemIcon>
                    <ListItemText primary="|| or or - Logical OR" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} /></ListItemIcon>
                    <ListItemText primary="! or not - Logical NOT" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                  </ListItem>
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <List dense disablePadding>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} /></ListItemIcon>
                    <ListItemText primary="contains - String contains (case-sensitive)" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} /></ListItemIcon>
                    <ListItemText primary="matches - Regular expression match" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                  </ListItem>
                  <ListItem disableGutters>
                    <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} /></ListItemIcon>
                    <ListItemText primary="== eq, != ne, > gt, < lt, >= ge, <= le" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                  </ListItem>
                </List>
              </Grid>
            </Grid>
          </Paper>
        </Paper>
        </Box>

        {/* ==================== CAPTURE FILTERS (BPF) ==================== */}
        <Box id="capture-filters">
        <Accordion defaultExpanded sx={{ mb: 2, bgcolor: pageTheme.bgCard, border: `1px solid ${pageTheme.border}` }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: pageTheme.text }} />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
              <TerminalIcon sx={{ color: "#10b981" }} />
              Capture Filters (BPF Syntax)
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>Capture filters</strong> use Berkeley Packet Filter (BPF) syntax and are applied BEFORE packets are captured.
                They reduce capture file size and improve performance but cannot be changed after capture starts.
              </Typography>
            </Alert>
            
            <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
              <strong>When to Use Capture Filters:</strong> Capture filters are essential when dealing with high-volume traffic 
              or when you need to focus on specific traffic from the start. Unlike display filters, capture filters use the 
              Berkeley Packet Filter (BPF) syntax, which is a low-level filtering language used by many packet capture tools. 
              The key advantage is efficiency - packets that don't match the capture filter are never written to disk, saving 
              storage space and processing time. However, this comes with a tradeoff: once a capture is started, you can't 
              see packets that were filtered out. Therefore, use capture filters when you're certain about what you need, 
              and display filters when you want flexibility to explore all captured traffic.
            </Typography>

            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: "40%", color: pageTheme.text }}>Capture Filter</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "15%", color: pageTheme.text }}>Category</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {CAPTURE_FILTERS.map((f, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell>
                        <Box component="code" sx={{ bgcolor: alpha("#10b981", 0.1), px: 1, py: 0.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem", color: pageTheme.text }}>
                          {f.filter}
                        </Box>
                      </TableCell>
                      <TableCell>{f.description}</TableCell>
                      <TableCell><Chip label={f.category} size="small" /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: "#f59e0b" }}>
                BPF vs Display Filter Syntax
              </Typography>
              <Typography variant="body2" sx={{ mb: 2, color: pageTheme.text }}>
                Capture filters (BPF) and display filters use different syntax:
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5, color: pageTheme.text }}>Capture (BPF)</Typography>
                  <Box component="code" sx={{ display: "block", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem" }}>
                    host 192.168.1.1 and port 80
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5, color: pageTheme.text }}>Display</Typography>
                  <Box component="code" sx={{ display: "block", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontFamily: "monospace", fontSize: "0.85rem" }}>
                    ip.addr == 192.168.1.1 && tcp.port == 80
                  </Box>
                </Grid>
              </Grid>
            </Paper>
          </AccordionDetails>
        </Accordion>
        </Box>

        {/* ==================== TSHARK COMMANDS ==================== */}
        <Box id="tshark">
        <Accordion sx={{ mb: 2, bgcolor: pageTheme.bgCard, border: `1px solid ${pageTheme.border}` }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: pageTheme.text }} />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
              <CodeIcon sx={{ color: "#8b5cf6" }} />
              TShark Command-Line Reference
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 2, color: pageTheme.text }}>
              TShark is Wireshark's command-line equivalent. It's essential for scripting, automation, and analyzing large captures on remote servers.
            </Typography>
            
            <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
              <strong>Why TShark?</strong> While Wireshark's graphical interface is excellent for interactive analysis, TShark 
              opens up powerful possibilities for automation and processing large captures. It can be used on headless servers 
              where a GUI isn't available, integrated into scripts for automated analysis, and used to process captures that 
              would overwhelm a graphical interface. TShark uses the same dissection logic as Wireshark, so anything you can 
              analyze in Wireshark can also be analyzed with TShark. The key to effective TShark usage is mastering field 
              extraction and statistics generation, which allow you to extract exactly the data you need in a format suitable 
              for further processing.
            </Typography>

            {TSHARK_COMMANDS.map((category) => (
              <Paper key={category.category} sx={{ p: 2, mb: 2, bgcolor: "#1e1e1e" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#8b5cf6", mb: 1 }}>
                  {category.category}
                </Typography>
                {category.commands.map((cmd, idx) => (
                  <Box key={idx} sx={{ mb: 1 }}>
                    <Box component="code" sx={{ color: "#4ec9b0", fontFamily: "monospace", fontSize: "0.85rem" }}>
                      $ {cmd.cmd}
                    </Box>
                    <Typography variant="caption" sx={{ display: "block", color: "#6b7280", ml: 2 }}>
                      # {cmd.desc}
                    </Typography>
                  </Box>
                ))}
              </Paper>
            ))}
          </AccordionDetails>
        </Accordion>
        </Box>

        {/* ==================== STATISTICS & ANALYSIS ==================== */}
        <Box id="statistics">
        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: pageTheme.bgCard, border: `1px solid ${pageTheme.border}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
            <BarChartIcon sx={{ color: "#f59e0b" }} />
            Statistics & Analysis Tools
          </Typography>
          <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
            Wireshark's Statistics menu provides powerful tools for understanding traffic patterns and identifying issues.
          </Typography>
          
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
            <strong>The Power of Statistics:</strong> While filtering shows you individual packets, Wireshark's statistics 
            tools give you the big picture. They allow you to identify patterns that would be impossible to see by 
            examining packets one at a time. For example, the Conversations view can instantly show you which pairs of 
            hosts are communicating most heavily, while the I/O Graph lets you visualize traffic patterns over time 
            to spot anomalies or correlate events. Expert Information aggregates all the issues Wireshark has detected, 
            making it your first stop when troubleshooting network problems. Understanding these tools is what separates 
            a novice from an expert packet analyst.
          </Typography>

          <Grid container spacing={3}>
            {STATISTICS_FEATURES.map((feature) => (
              <Grid item xs={12} sm={6} md={4} key={feature.menu}>
                <Card
                  sx={{
                    height: "100%",
                    borderRadius: 2,
                    bgcolor: pageTheme.bgNested,
                    border: `1px solid ${alpha(feature.color, 0.2)}`,
                    transition: "all 0.3s ease",
                    "&:hover": {
                      transform: "translateY(-4px)",
                      boxShadow: `0 8px 30px ${alpha(feature.color, 0.2)}`,
                    },
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 600, color: pageTheme.text }}>
                        {feature.menu}
                      </Typography>
                    </Box>
                    <Typography variant="caption" sx={{ color: feature.color, display: "block", mb: 1 }}>
                      {feature.path}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1, color: pageTheme.textMuted }}>
                      {feature.description}
                    </Typography>
                    <Divider sx={{ my: 1, borderColor: alpha(pageTheme.text, 0.1) }} />
                    <Typography variant="caption" sx={{ color: pageTheme.textMuted }}>
                      <strong>Use Case:</strong> {feature.useCase}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* Expert Information */}
          <Box sx={{ mt: 4 }}>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
              <TroubleshootIcon sx={{ color: "#dc2626" }} />
              Expert Information Severity Levels
            </Typography>
            <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
              <strong>Understanding Expert Information:</strong> Wireshark's Expert Information system automatically 
              analyzes your capture for potential problems, unusual patterns, and informational events. It's like 
              having an experienced network analyst looking over your shoulder, pointing out things you might miss. 
              The severity levels help you prioritize what to investigate first - start with Errors (serious protocol 
              violations), then Warnings (unusual but possibly normal conditions), and finally Notes and Chat for 
              informational purposes. Always check Expert Information when investigating a problem; it often points 
              directly to the root cause.
            </Typography>
            <Grid container spacing={2}>
              {EXPERT_INFO_LEVELS.map((level) => (
                <Grid item xs={12} sm={6} md={3} key={level.severity}>
                  <Paper
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      border: `2px solid ${level.color}`,
                      bgcolor: alpha(level.color, 0.05),
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box
                        sx={{
                          width: 24,
                          height: 24,
                          borderRadius: "50%",
                          bgcolor: level.color,
                          color: "white",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontSize: "0.75rem",
                          fontWeight: 700,
                        }}
                      >
                        {level.icon}
                      </Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: level.color }}>
                        {level.severity}
                      </Typography>
                    </Box>
                    <Typography variant="caption" sx={{ display: "block", mb: 1, color: pageTheme.textMuted }}>
                      {level.description}
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {level.examples.map((ex, idx) => (
                        <Chip key={idx} label={ex} size="small" sx={{ fontSize: "0.65rem", height: 20, bgcolor: alpha(level.color, 0.2), color: pageTheme.text }} />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>
        </Box>

        {/* ==================== PROTOCOL DISSECTION ==================== */}
        <Box id="protocol-dissection">
        <Accordion sx={{ mb: 2, bgcolor: pageTheme.bgCard, border: `1px solid ${pageTheme.border}` }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: pageTheme.text }} />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
              <LayersIcon sx={{ color: "#8b5cf6" }} />
              Protocol Dissection & Layers
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 2, color: pageTheme.text }}>
              Understanding how Wireshark dissects packets layer by layer is fundamental to effective analysis.
            </Typography>
            
            <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
              <strong>The OSI Model in Practice:</strong> When Wireshark captures a packet, it doesn't just show you raw 
              bytes - it decodes each layer according to the protocol specification. Starting from the physical frame 
              metadata, through Ethernet, IP, transport layers (TCP/UDP), and finally the application layer (HTTP, DNS, 
              etc.), each layer is dissected and its fields are presented in a human-readable format. Understanding this 
              layered structure is crucial because many network issues occur at specific layers, and knowing where to look 
              dramatically speeds up troubleshooting. The packet details pane shows this layer-by-layer breakdown, and 
              you can expand each section to see specific field values.
            </Typography>

            <Grid container spacing={2}>
              {PROTOCOL_LAYERS.map((layer) => (
                <Grid item xs={12} md={6} key={layer.layer}>
                  <Paper
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      borderLeft: `4px solid ${layer.color}`,
                      bgcolor: alpha(layer.color, 0.02),
                    }}
                  >
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: layer.color, mb: 0.5 }}>
                      {layer.layer}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1, color: pageTheme.textMuted }}>
                      {layer.description}
                    </Typography>
                    <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5, color: pageTheme.text }}>Key Fields:</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {layer.keyFields.map((field) => (
                        <Chip
                          key={field}
                          label={field}
                          size="small"
                          sx={{
                            fontFamily: "monospace",
                            fontSize: "0.7rem",
                            bgcolor: alpha(layer.color, 0.1),
                            color: pageTheme.text,
                          }}
                        />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>
        </Box>

        {/* ==================== ADVANCED FEATURES ==================== */}
        <Box id="advanced-features">
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: pageTheme.bgCard,
            background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)} 0%, ${alpha("#6366f1", 0.05)} 100%)`,
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
            <BuildIcon sx={{ color: "#8b5cf6" }} />
            Advanced Features
          </Typography>
          <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
            Master these advanced capabilities to unlock Wireshark's full potential.
          </Typography>
          
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
            <strong>Going Beyond Basic Analysis:</strong> The features in this section separate casual users from power users. 
            TLS decryption is perhaps the most valuable skill, as modern web traffic is almost entirely encrypted. Without 
            the ability to decrypt TLS, you're limited to analyzing metadata and connection patterns. File carving lets you 
            extract actual files transferred over the network - invaluable for malware analysis or incident response. 
            Custom columns and color rules help you tailor Wireshark to your specific workflow, while keyboard shortcuts 
            dramatically increase your analysis speed. Invest time in learning these features and you'll analyze captures 
            in a fraction of the time.
          </Typography>

          <Tabs
            value={advancedTab}
            onChange={(_, v) => setAdvancedTab(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ borderBottom: 1, borderColor: "divider" }}
          >
            <Tab icon={<LockIcon />} iconPosition="start" label="TLS Decryption" sx={{ color: pageTheme.text }} />
            <Tab icon={<FolderOpenIcon />} iconPosition="start" label="File Carving" sx={{ color: pageTheme.text }} />
            <Tab icon={<ColorLensIcon />} iconPosition="start" label="Color Rules" sx={{ color: pageTheme.text }} />
            <Tab icon={<KeyboardIcon />} iconPosition="start" label="Shortcuts" sx={{ color: pageTheme.text }} />
            <Tab icon={<SettingsIcon />} iconPosition="start" label="Custom Columns" sx={{ color: pageTheme.text }} />
          </Tabs>

          {/* TLS Decryption */}
          <TabPanel value={advancedTab} index={0}>
            <Typography variant="body1" sx={{ mb: 2, color: pageTheme.text }}>
              TLS decryption allows you to see inside encrypted HTTPS traffic - essential for debugging and security analysis.
            </Typography>
            
            <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
              <strong>The SSLKEYLOGFILE Method:</strong> This is the most reliable method for decrypting modern TLS traffic. 
              When you set the SSLKEYLOGFILE environment variable, browsers like Chrome and Firefox will write session 
              keys to a log file. Wireshark can then use these keys to decrypt the captured traffic. This works with 
              Perfect Forward Secrecy (PFS) cipher suites, which are now standard. The key insight is that you must 
              capture the traffic WHILE the SSLKEYLOGFILE is being written - you can't decrypt old captures with new 
              key logs.
            </Typography>

            {TLS_DECRYPTION_METHODS.map((method) => (
              <Paper
                key={method.method}
                sx={{
                  p: 3,
                  mb: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha(method.color, 0.3)}`,
                  bgcolor: alpha(method.color, 0.02),
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: pageTheme.text }}>
                    {method.method}
                  </Typography>
                  <Chip label={method.difficulty} size="small" sx={{ bgcolor: alpha(method.color, 0.2), color: pageTheme.text }} />
                </Box>
                <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
                  {method.description}
                </Typography>
                {method.warning && (
                  <Alert severity="warning" sx={{ mb: 2 }}>
                    {method.warning}
                  </Alert>
                )}
                <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 1, color: pageTheme.text }}>Steps:</Typography>
                <List dense disablePadding>
                  {method.steps.map((step, idx) => (
                    <ListItem key={idx} disableGutters>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <Typography variant="caption" sx={{ fontWeight: 600, color: method.color }}>
                          {idx + 1}.
                        </Typography>
                      </ListItemIcon>
                      <ListItemText primary={step} primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                    </ListItem>
                  ))}
                </List>
                <Divider sx={{ my: 2, borderColor: alpha(pageTheme.text, 0.1) }} />
                <Typography variant="caption" sx={{ fontWeight: 600, color: pageTheme.text }}>Supported: </Typography>
                {method.platforms.map((p) => (
                  <Chip key={p} label={p} size="small" sx={{ mr: 0.5, fontSize: "0.65rem", bgcolor: alpha(method.color, 0.1), color: pageTheme.text }} />
                ))}
              </Paper>
            ))}
          </TabPanel>

          {/* File Carving */}
          <TabPanel value={advancedTab} index={1}>
            <Typography variant="body1" sx={{ mb: 2, color: pageTheme.text }}>
              Export transferred files directly from packet captures. This is invaluable for malware analysis and forensics.
            </Typography>
            
            <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
              <strong>File Carving in Practice:</strong> When files are transferred over a network, they're broken into 
              packets and reassembled at the destination. Wireshark can reverse this process and reconstruct the original 
              files. This is incredibly useful for security analysis - you can extract downloaded malware samples, 
              exfiltrated documents, or any other files that crossed the wire. The Export Objects feature handles the 
              heavy lifting, automatically identifying and extracting files from supported protocols. For protocols not 
              directly supported, you can use "Follow Stream" to manually extract data.
            </Typography>

            <TableContainer component={Paper} sx={{ mb: 3, bgcolor: pageTheme.bgNested }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Protocol</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, color: pageTheme.text }}>Menu Path</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {EXPORTABLE_OBJECTS.map((obj) => (
                    <TableRow key={obj.protocol} hover>
                      <TableCell><Chip label={obj.protocol} size="small" sx={{ bgcolor: alpha(pageTheme.primary, 0.2), color: pageTheme.primary }} /></TableCell>
                      <TableCell sx={{ color: pageTheme.text }}>{obj.description}</TableCell>
                      <TableCell>
                        <Box component="code" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: pageTheme.text }}>
                          {obj.path}
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Alert severity="info">
              <Typography variant="body2">
                <strong>Tip:</strong> Right-click on any packet and select "Follow" → "TCP Stream" (or HTTP, TLS) to view the
                reconstructed conversation and optionally save it as raw data.
              </Typography>
            </Alert>
          </TabPanel>

          {/* Color Rules */}
          <TabPanel value={advancedTab} index={2}>
            <Typography variant="body1" sx={{ mb: 2, color: pageTheme.text }}>
              Wireshark uses color coding to quickly highlight different types of traffic. Customize via View → Coloring Rules.
            </Typography>
            
            <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
              <strong>Visual Pattern Recognition:</strong> Color rules are one of Wireshark's most underappreciated features. 
              Our brains are excellent at pattern recognition, and color-coded packets let you instantly identify traffic 
              types. Red packets (errors) immediately draw your attention. Green HTTP traffic stands out from blue HTTPS. 
              By customizing color rules for your specific analysis needs, you can spot anomalies at a glance. For example, 
              during a security investigation, you might add a custom rule to highlight traffic to suspicious IP ranges 
              in bright orange.
            </Typography>

            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Rule Name</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Colors</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {COLOR_RULES.map((rule) => (
                    <TableRow key={rule.name} hover>
                      <TableCell>{rule.name}</TableCell>
                      <TableCell>
                        <Box
                          sx={{
                            width: 80,
                            height: 24,
                            bgcolor: rule.bgcolor,
                            color: rule.color,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            borderRadius: 1,
                            fontSize: "0.75rem",
                            fontWeight: 600,
                          }}
                        >
                          Sample
                        </Box>
                      </TableCell>
                      <TableCell>{rule.description}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>

          {/* Keyboard Shortcuts */}
          <TabPanel value={advancedTab} index={3}>
            <Typography variant="body1" sx={{ mb: 3 }}>
              Master these keyboard shortcuts to analyze captures efficiently.
            </Typography>

            <Grid container spacing={3}>
              {KEYBOARD_SHORTCUTS.map((group) => (
                <Grid item xs={12} sm={6} md={4} key={group.category}>
                  <Paper sx={{ p: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>
                      {group.category}
                    </Typography>
                    {group.shortcuts.map((sc, idx) => (
                      <Box key={idx} sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                        <Box
                          component="kbd"
                          sx={{
                            bgcolor: alpha("#6b7280", 0.1),
                            px: 1,
                            py: 0.25,
                            borderRadius: 1,
                            fontFamily: "monospace",
                            fontSize: "0.8rem",
                            border: `1px solid ${alpha("#6b7280", 0.2)}`,
                          }}
                        >
                          {sc.key}
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          {sc.action}
                        </Typography>
                      </Box>
                    ))}
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </TabPanel>

          {/* Custom Columns */}
          <TabPanel value={advancedTab} index={4}>
            <Typography variant="body1" sx={{ mb: 3 }}>
              Add custom columns to display specific fields directly in the packet list. Right-click column header → Column Preferences.
            </Typography>

            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Column Title</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Field Name</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {USEFUL_CUSTOM_COLUMNS.map((col) => (
                    <TableRow key={col.field} hover>
                      <TableCell>{col.title}</TableCell>
                      <TableCell>
                        <Box component="code" sx={{ fontFamily: "monospace", fontSize: "0.85rem", bgcolor: alpha("#8b5cf6", 0.1), px: 1, py: 0.25, borderRadius: 1 }}>
                          {col.field}
                        </Box>
                      </TableCell>
                      <TableCell>{col.description}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>Tip:</strong> Use Edit → Configuration Profiles to save different column layouts and settings for different analysis scenarios.
              </Typography>
            </Alert>
          </TabPanel>
        </Paper>
        </Box>

        {/* ==================== PACKET ANALYSIS WORKFLOW ==================== */}
        <Box id="packet-workflow">
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: pageTheme.bgCard,
            background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.1)} 0%, ${alpha("#0891b2", 0.05)} 100%)`,
            border: `1px solid ${alpha("#06b6d4", 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
            <PlayArrowIcon sx={{ color: "#06b6d4" }} />
            Packet Analysis Workflow
          </Typography>
          <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
            A systematic approach to analyzing network captures effectively.
          </Typography>
          
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
            <strong>Methodology Matters:</strong> Successful packet analysis isn't just about knowing filters - it's about 
            having a systematic approach. Whether you're troubleshooting network issues, investigating security incidents, 
            or reverse engineering protocols, following a consistent methodology ensures you don't miss critical details. 
            The workflow below represents a battle-tested approach used by professional analysts that scales from simple 
            problems to complex multi-day investigations.
          </Typography>

          <Grid container spacing={3}>
            {[
              {
                step: 1,
                title: "Initial Assessment",
                description: "Start by understanding the scope: capture duration, file size, and basic traffic composition. Use Statistics → Protocol Hierarchy to get an overview.",
                tips: ["Note capture time range", "Identify unexpected protocols", "Check for high error rates"],
                color: "#06b6d4",
              },
              {
                step: 2,
                title: "Traffic Profiling",
                description: "Identify major traffic sources and destinations. Use Statistics → Conversations to find top talkers and unusual communication patterns.",
                tips: ["Export conversation list for analysis", "Look for asymmetric traffic", "Check for unusual port usage"],
                color: "#0ea5e9",
              },
              {
                step: 3,
                title: "Deep Dive Analysis",
                description: "Apply targeted filters based on your hypothesis. Follow TCP streams to understand application-level behavior.",
                tips: ["Mark packets of interest (Ctrl+M)", "Use time reference to measure latency", "Document filter expressions used"],
                color: "#3b82f6",
              },
              {
                step: 4,
                title: "Evidence Collection",
                description: "Extract relevant evidence: exported objects, filtered captures, stream data. Ensure chain of custody for forensic cases.",
                tips: ["Save filtered packets to new file", "Export HTTP/SMB/FTP objects", "Screenshot important findings"],
                color: "#6366f1",
              },
              {
                step: 5,
                title: "Correlation & Reporting",
                description: "Correlate findings with other data sources (logs, threat intel). Document timeline and conclusions clearly.",
                tips: ["Create packet number references", "Include filter expressions", "Note limitations of analysis"],
                color: "#8b5cf6",
              },
            ].map((item) => (
              <Grid item xs={12} key={item.step}>
                <Paper sx={{ p: 3, bgcolor: pageTheme.bgNested, border: `1px solid ${alpha(item.color, 0.3)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Avatar sx={{ bgcolor: item.color, width: 40, height: 40, fontWeight: 700 }}>
                      {item.step}
                    </Avatar>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: pageTheme.text }}>
                      {item.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" sx={{ mb: 2, color: pageTheme.text }}>
                    {item.description}
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {item.tips.map((tip, idx) => (
                      <Chip
                        key={idx}
                        size="small"
                        icon={<CheckCircleIcon sx={{ fontSize: 14 }} />}
                        label={tip}
                        sx={{ bgcolor: alpha(item.color, 0.1), color: pageTheme.text }}
                      />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>
        </Box>

        {/* ==================== FORENSIC SCENARIOS ==================== */}
        <Box id="forensic-scenarios">
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: pageTheme.bgCard,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.1)} 0%, ${alpha("#d97706", 0.05)} 100%)`,
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
            <HistoryEduIcon sx={{ color: "#f59e0b" }} />
            Forensic Investigation Scenarios
          </Typography>
          <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
            Real-world scenarios and the techniques to investigate them.
          </Typography>
          
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
            <strong>Applied Forensics:</strong> Theory becomes practical when applied to real investigation scenarios. 
            Below are common incident types you'll encounter, along with the specific techniques and filters that help 
            uncover the truth. Each scenario requires a different approach and different indicators - mastering these 
            patterns will prepare you for actual incident response situations.
          </Typography>

          <Grid container spacing={3}>
            {[
              {
                scenario: "Data Exfiltration Investigation",
                description: "Detecting unauthorized data transfers to external destinations.",
                filters: [
                  "ip.dst != 10.0.0.0/8 && ip.dst != 172.16.0.0/12 && ip.dst != 192.168.0.0/16",
                  "dns.qry.name contains 'base64'",
                  "tcp.len > 1000 && ip.dst != <internal_range>",
                ],
                indicators: ["Large outbound transfers", "Unusual protocols", "Off-hours activity", "DNS tunneling"],
                icon: <UploadFileIcon />,
                color: "#ef4444",
              },
              {
                scenario: "Malware Command & Control",
                description: "Identifying communication between infected hosts and attacker infrastructure.",
                filters: [
                  "http.request.method == POST && http.content_length > 0",
                  "dns.flags.response == 0 && !dns.qry.name contains 'microsoft'",
                  "tcp.port == 443 && !tls.handshake.extensions_server_name",
                ],
                indicators: ["Periodic beaconing", "Encoded payloads", "Non-standard TLS", "IP-based HTTPS"],
                icon: <BugReportIcon />,
                color: "#f59e0b",
              },
              {
                scenario: "Lateral Movement Detection",
                description: "Finding evidence of attackers moving between internal systems.",
                filters: [
                  "smb2.cmd == 1 || smb2.cmd == 5",
                  "dcerpc.opnum == 23 || dcerpc.opnum == 24",
                  "ntlmssp.auth.username",
                ],
                indicators: ["Unusual SMB access", "Remote execution (PsExec)", "Admin share access", "Pass-the-hash"],
                icon: <SwapHorizIcon />,
                color: "#8b5cf6",
              },
              {
                scenario: "Credential Theft Analysis",
                description: "Detecting attempts to capture or transmit stolen credentials.",
                filters: [
                  "http.authorization contains 'Basic'",
                  "ftp.request.command == 'PASS'",
                  "smtp.auth.password",
                ],
                indicators: ["Cleartext passwords", "Failed auth attempts", "Kerberoasting", "LLMNR/NBT-NS poisoning"],
                icon: <VpnKeyIcon />,
                color: "#10b981",
              },
            ].map((item) => (
              <Grid item xs={12} md={6} key={item.scenario}>
                <Card sx={{ height: "100%", bgcolor: pageTheme.bgNested, border: `1px solid ${alpha(item.color, 0.3)}` }}>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                      <Box sx={{ color: item.color }}>{item.icon}</Box>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: pageTheme.text }}>
                        {item.scenario}
                      </Typography>
                    </Box>
                    <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
                      {item.description}
                    </Typography>
                    
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: pageTheme.text }}>
                      Key Filters:
                    </Typography>
                    {item.filters.map((filter, idx) => (
                      <Box
                        key={idx}
                        component="code"
                        sx={{
                          display: "block",
                          bgcolor: "#1e1e1e",
                          color: "#d4d4d4",
                          p: 0.5,
                          borderRadius: 1,
                          fontFamily: "monospace",
                          fontSize: "0.75rem",
                          mb: 0.5,
                          overflow: "auto",
                        }}
                      >
                        {filter}
                      </Box>
                    ))}
                    
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mt: 2, mb: 1, color: pageTheme.text }}>
                      Look For:
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {item.indicators.map((ind, idx) => (
                        <Chip key={idx} size="small" label={ind} sx={{ bgcolor: alpha(item.color, 0.1), color: pageTheme.text, fontSize: "0.7rem" }} />
                      ))}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
        </Box>

        {/* ==================== PERFORMANCE ANALYSIS ==================== */}
        <Box id="performance-analysis">
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: pageTheme.bgCard,
            background: `linear-gradient(135deg, ${alpha("#22c55e", 0.1)} 0%, ${alpha("#16a34a", 0.05)} 100%)`,
            border: `1px solid ${alpha("#22c55e", 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
            <SpeedIcon sx={{ color: "#22c55e" }} />
            Network Performance Analysis
          </Typography>
          <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
            Using Wireshark to diagnose network performance issues.
          </Typography>
          
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
            <strong>Beyond Security:</strong> While security analysis is a primary use case, Wireshark is equally valuable 
            for diagnosing network performance problems. Slow applications, dropped connections, and throughput issues often 
            have root causes visible in packet captures. Understanding TCP behavior, measuring latency, and identifying 
            bottlenecks requires specific techniques and metrics that differ from security analysis.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: pageTheme.bgNested, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: pageTheme.text }}>
                  TCP Performance Metrics
                </Typography>
                <List dense>
                  {[
                    { metric: "Round Trip Time (RTT)", filter: "tcp.analysis.ack_rtt", desc: "Measures network latency" },
                    { metric: "Retransmissions", filter: "tcp.analysis.retransmission", desc: "Indicates packet loss" },
                    { metric: "Zero Window", filter: "tcp.analysis.zero_window", desc: "Receiver buffer exhaustion" },
                    { metric: "Window Update", filter: "tcp.analysis.window_update", desc: "Flow control adjustments" },
                    { metric: "Out-of-Order", filter: "tcp.analysis.out_of_order", desc: "Packets arriving non-sequentially" },
                    { metric: "Duplicate ACK", filter: "tcp.analysis.duplicate_ack", desc: "Fast retransmit trigger" },
                  ].map((item) => (
                    <ListItem key={item.metric} disableGutters sx={{ flexDirection: "column", alignItems: "flex-start" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, color: pageTheme.text }}>
                        {item.metric}
                      </Typography>
                      <Box component="code" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#22c55e" }}>
                        {item.filter}
                      </Box>
                      <Typography variant="caption" sx={{ color: pageTheme.textMuted }}>
                        {item.desc}
                      </Typography>
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: pageTheme.bgNested, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: pageTheme.text }}>
                  Performance Tools
                </Typography>
                <List dense>
                  {[
                    { tool: "Statistics → TCP Stream Graphs → Round Trip Time", desc: "Visualize RTT over time" },
                    { tool: "Statistics → TCP Stream Graphs → Throughput", desc: "Measure actual data rates" },
                    { tool: "Statistics → TCP Stream Graphs → Window Scaling", desc: "Analyze flow control" },
                    { tool: "Statistics → IO Graphs", desc: "Plot any metric over time" },
                    { tool: "Statistics → Service Response Time", desc: "Application-level latency" },
                    { tool: "Analyze → Expert Information", desc: "Automatic problem detection" },
                  ].map((item, idx) => (
                    <ListItem key={idx} disableGutters sx={{ flexDirection: "column", alignItems: "flex-start", mb: 1 }}>
                      <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#22c55e", fontSize: "0.85rem" }}>
                        {item.tool}
                      </Typography>
                      <Typography variant="caption" sx={{ color: pageTheme.textMuted }}>
                        {item.desc}
                      </Typography>
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Alert severity="success" sx={{ mt: 3 }}>
                <Typography variant="body2">
                  <strong>Pro Tip:</strong> Use Statistics → Endpoints to identify which hosts are generating the most traffic.
                  Sort by bytes to find bandwidth hogs, or by packet count to find chatty protocols.
                </Typography>
              </Alert>
            </Grid>
          </Grid>
        </Paper>
        </Box>

        {/* ==================== PROTOCOL SPECIFIC GUIDES ==================== */}
        <Box id="protocol-guides">
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: pageTheme.bgCard,
            background: `linear-gradient(135deg, ${alpha("#a855f7", 0.1)} 0%, ${alpha("#9333ea", 0.05)} 100%)`,
            border: `1px solid ${alpha("#a855f7", 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
            <HubIcon sx={{ color: "#a855f7" }} />
            Protocol-Specific Analysis Guides
          </Typography>
          <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
            Deep-dive reference for analyzing common protocols.
          </Typography>
          
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
            <strong>Protocol Expertise:</strong> Different protocols require different analysis approaches. Understanding the 
            structure and behavior of common protocols helps you quickly identify anomalies and extract useful information. 
            Below are quick references for protocols you'll encounter frequently in security and network analysis.
          </Typography>

          <Grid container spacing={3}>
            {[
              {
                protocol: "HTTP/HTTPS",
                description: "Web traffic analysis including requests, responses, and content",
                filters: ["http.request.method", "http.response.code", "http.host", "http.user_agent", "tls.handshake.extensions_server_name"],
                tips: ["Use Export Objects → HTTP for files", "Follow HTTP streams for full conversations", "Check for unusual User-Agents"],
                color: "#3b82f6",
              },
              {
                protocol: "DNS",
                description: "Domain resolution and potential tunneling or exfiltration",
                filters: ["dns.qry.name", "dns.resp.type", "dns.flags.rcode", "dns.qry.type == 16 (TXT)", "dns.resp.len > 100"],
                tips: ["Look for high entropy domain names", "Check for TXT record abuse", "Monitor query volumes per host"],
                color: "#10b981",
              },
              {
                protocol: "SMB/CIFS",
                description: "Windows file sharing and lateral movement detection",
                filters: ["smb2.filename", "smb2.cmd", "smb2.create.action", "smb2.share_type", "ntlmssp.auth.username"],
                tips: ["Track admin share (C$, ADMIN$) access", "Look for remote execution artifacts", "Monitor unusual file access patterns"],
                color: "#f59e0b",
              },
              {
                protocol: "TLS/SSL",
                description: "Encrypted traffic metadata analysis",
                filters: ["tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ciphersuite", "tls.record.version"],
                tips: ["Identify SNI for destination insight", "Check certificate validity", "Look for weak cipher usage"],
                color: "#ef4444",
              },
            ].map((item) => (
              <Grid item xs={12} md={6} key={item.protocol}>
                <Card sx={{ height: "100%", bgcolor: pageTheme.bgNested, border: `1px solid ${alpha(item.color, 0.3)}` }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: item.color }}>
                      {item.protocol}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
                      {item.description}
                    </Typography>
                    
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: pageTheme.text }}>
                      Essential Filters:
                    </Typography>
                    <Box sx={{ mb: 2 }}>
                      {item.filters.map((filter, idx) => (
                        <Chip
                          key={idx}
                          size="small"
                          label={filter}
                          sx={{
                            bgcolor: "#1e1e1e",
                            color: "#d4d4d4",
                            fontFamily: "monospace",
                            fontSize: "0.7rem",
                            m: 0.25,
                          }}
                        />
                      ))}
                    </Box>
                    
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: pageTheme.text }}>
                      Analysis Tips:
                    </Typography>
                    <List dense disablePadding>
                      {item.tips.map((tip, idx) => (
                        <ListItem key={idx} disableGutters sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <TipsAndUpdatesIcon sx={{ fontSize: 14, color: item.color }} />
                          </ListItemIcon>
                          <ListItemText primary={tip} primaryTypographyProps={{ variant: "caption", color: pageTheme.text }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
        </Box>

        {/* ==================== SECURITY ANALYSIS ==================== */}
        <Box id="security-analysis">
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: pageTheme.bgCard,
            background: `linear-gradient(135deg, ${alpha("#ef4444", 0.1)} 0%, ${alpha("#dc2626", 0.05)} 100%)`,
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
            <SecurityIcon sx={{ color: "#ef4444" }} />
            Security Analysis Patterns
          </Typography>
          <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
            Common attack patterns and how to identify them in packet captures.
          </Typography>
          
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
            <strong>Threat Hunting with Wireshark:</strong> Wireshark is an invaluable tool for security analysts. Whether 
            you're investigating an incident, hunting for threats, or analyzing malware behavior, understanding how attacks 
            manifest in network traffic is crucial. The patterns below represent common attack signatures that you should 
            be able to recognize. Remember that attackers constantly evolve their techniques, so these filters should be 
            starting points for your investigation, not definitive detection rules. Always correlate multiple indicators 
            and consider the context of the traffic you're analyzing.
          </Typography>

          <Grid container spacing={3}>
            {SECURITY_PATTERNS.map((pattern) => (
              <Grid item xs={12} md={6} key={pattern.attack}>
                <Card
                  sx={{
                    height: "100%",
                    borderRadius: 2,
                    bgcolor: pageTheme.bgNested,
                    border: `1px solid ${alpha(pattern.color, 0.3)}`,
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: pattern.color }}>{pattern.icon}</Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: pageTheme.text }}>
                        {pattern.attack}
                      </Typography>
                    </Box>
                    <Typography variant="body2" sx={{ mb: 2, color: pageTheme.textMuted }}>
                      {pattern.description}
                    </Typography>

                    <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5, color: pageTheme.text }}>Filter:</Typography>
                    <Box
                      component="code"
                      sx={{
                        display: "block",
                        bgcolor: "#1e1e1e",
                        color: "#d4d4d4",
                        p: 1,
                        borderRadius: 1,
                        fontFamily: "monospace",
                        fontSize: "0.8rem",
                        mb: 2,
                        overflow: "auto",
                      }}
                    >
                      {pattern.filter}
                    </Box>

                    <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5, color: pageTheme.text }}>Indicators:</Typography>
                    <List dense disablePadding>
                      {pattern.indicators.map((ind, idx) => (
                        <ListItem key={idx} disableGutters sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <WarningIcon sx={{ fontSize: 14, color: pattern.color }} />
                          </ListItemIcon>
                          <ListItemText primary={ind} primaryTypographyProps={{ variant: "caption", color: pageTheme.text }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
        </Box>

        {/* ==================== VOIP ANALYSIS ==================== */}
        <Box id="voip">
        <Accordion sx={{ mb: 2, bgcolor: pageTheme.bgCard, border: `1px solid ${pageTheme.border}` }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: pageTheme.text }} />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
              <PhoneIcon sx={{ color: "#22c55e" }} />
              VoIP & RTP Analysis
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 2, color: pageTheme.text }}>
              Wireshark has specialized tools for analyzing Voice over IP traffic including SIP signaling and RTP media streams.
            </Typography>
            
            <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
              <strong>VoIP Forensics:</strong> Voice over IP analysis is a specialized skill that's increasingly relevant 
              as organizations move away from traditional phone systems. Wireshark can capture and analyze SIP signaling 
              (which sets up and tears down calls) and RTP streams (which carry the actual audio). Beyond basic capture, 
              Wireshark can actually play back captured audio, detect quality issues like jitter and packet loss, and 
              help troubleshoot call quality problems. In security contexts, VoIP analysis can reveal unauthorized calls, 
              toll fraud, or eavesdropping attempts.
            </Typography>

            <Grid container spacing={2}>
              {VOIP_ANALYSIS.map((feature) => (
                <Grid item xs={12} sm={6} key={feature.feature}>
                  <Paper sx={{ p: 2, bgcolor: pageTheme.bgNested, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, color: pageTheme.text }}>{feature.feature}</Typography>
                    <Typography variant="caption" sx={{ color: "#22c55e", display: "block", mb: 0.5 }}>
                      {feature.path}
                    </Typography>
                    <Typography variant="body2" sx={{ color: pageTheme.textMuted }}>
                      {feature.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>Audio Playback:</strong> Wireshark can play back captured VoIP audio directly. Use Telephony → RTP → RTP Player,
                then select streams and click Play Streams.
              </Typography>
            </Alert>
          </AccordionDetails>
        </Accordion>
        </Box>

        {/* ==================== SCRIPTING ==================== */}
        <Box id="lua-scripting">
        <Accordion sx={{ mb: 2, bgcolor: pageTheme.bgCard, border: `1px solid ${pageTheme.border}` }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: pageTheme.text }} />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
              <ExtensionIcon sx={{ color: "#f59e0b" }} />
              Lua Scripting & Dissectors
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 2, color: pageTheme.text }}>
              Wireshark supports Lua scripting for custom protocol dissectors, post-dissector analysis, and automation.
            </Typography>
            
            <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
              <strong>Extending Wireshark's Capabilities:</strong> While Wireshark supports hundreds of protocols out of 
              the box, you may encounter proprietary protocols or need custom analysis logic. Lua scripting allows you to 
              create custom protocol dissectors that appear in Wireshark's packet details pane, tap into packet processing 
              to extract specific data, and automate repetitive analysis tasks. This is particularly valuable in industrial 
              environments with custom protocols, or for security researchers analyzing new malware communication patterns.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: "#1e1e1e" }}>
              <Typography variant="subtitle2" sx={{ color: "#4ec9b0", mb: 1 }}>Example: Custom HTTP Header Extractor</Typography>
              <Box component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`-- Save as extract_auth.lua in Wireshark plugins folder
local tap = Listener.new("http")

function tap.packet(pinfo, tvb)
    local http_auth = Field.new("http.authorization")
    local auth = http_auth()
    if auth then
        print(string.format("Frame %d: Auth = %s",
              pinfo.number, tostring(auth)))
    end
end

function tap.draw()
    print("Analysis complete")
end`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: pageTheme.text }}>Lua Plugin Locations</Typography>
                  <List dense disablePadding>
                    <ListItem disableGutters>
                      <ListItemText primary="Windows: %APPDATA%\Wireshark\plugins" primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", color: pageTheme.text }} />
                    </ListItem>
                    <ListItem disableGutters>
                      <ListItemText primary="macOS: ~/.local/lib/wireshark/plugins" primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", color: pageTheme.text }} />
                    </ListItem>
                    <ListItem disableGutters>
                      <ListItemText primary="Linux: ~/.local/lib/wireshark/plugins" primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", color: pageTheme.text }} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: pageTheme.text }}>Useful Lua Functions</Typography>
                  <List dense disablePadding>
                    <ListItem disableGutters>
                      <ListItemText primary="Proto.new() - Create custom protocol" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                    </ListItem>
                    <ListItem disableGutters>
                      <ListItemText primary="Listener.new() - Create tap listener" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                    </ListItem>
                    <ListItem disableGutters>
                      <ListItemText primary="Field.new() - Access protocol fields" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                    </ListItem>
                    <ListItem disableGutters>
                      <ListItemText primary="DissectorTable.get() - Register dissector" primaryTypographyProps={{ variant: "body2", color: pageTheme.text }} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>
        </Box>

        {/* ==================== BEST PRACTICES ==================== */}
        <Box id="best-practices">
        <Paper
          sx={{
            p: 3,
            mb: 4,
            bgcolor: pageTheme.bgCard,
            background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)} 0%, ${alpha("#059669", 0.05)} 100%)`,
            border: `1px solid ${alpha("#10b981", 0.3)}`,
            borderRadius: 3,
          }}
        >
          <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1, color: pageTheme.text }}>
            <TipsAndUpdatesIcon color="success" />
            Best Practices & Tips
          </Typography>
          
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text }}>
            <strong>Developing Professional Habits:</strong> Network analysis proficiency comes from developing consistent 
            practices that ensure accuracy, efficiency, and thoroughness. The tips below have been gathered from experienced 
            analysts and represent the collective wisdom of the security and networking communities. Following these 
            guidelines will help you avoid common pitfalls, maintain evidence integrity during incident response, and 
            develop workflows that scale as your capture files grow larger and your investigations become more complex.
          </Typography>
          
          <Grid container spacing={2}>
            {[
              "Use capture filters for large-volume captures to reduce file size",
              "Always note the capture time, interface, and purpose in filenames",
              "Check Protocol Hierarchy first to understand traffic composition",
              "Use Conversations view to identify top talkers quickly",
              "Mark interesting packets (Ctrl+M) for later reference",
              "Create profiles for different analysis scenarios (security, performance, etc.)",
              "Use ring buffers for continuous capture without filling disk",
              "Export objects early - some analysis may corrupt findings",
              "Document your findings as you go - packet numbers, timestamps, filters used",
              "Validate findings with multiple indicators before concluding",
              "Use display filter macros for complex, frequently-used filters",
              "Regularly update Wireshark for new protocol dissectors and security fixes",
            ].map((tip, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                  <CheckCircleIcon fontSize="small" color="success" sx={{ mt: 0.25 }} />
                  <Typography variant="body2" sx={{ color: pageTheme.text }}>{tip}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>
        </Box>

        {/* ==================== RELATED RESOURCES ==================== */}
        <Box id="resources">
        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, textAlign: "center", bgcolor: pageTheme.bgCard, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
          <HubIcon sx={{ fontSize: 48, color: "#0ea5e9", mb: 2 }} />
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, color: pageTheme.text }}>
            Continue Learning
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, color: pageTheme.textMuted }}>
            Explore related topics and tools for network analysis.
          </Typography>
          
          <Typography variant="body2" sx={{ mb: 3, color: pageTheme.text, maxWidth: 800, mx: "auto" }}>
            Wireshark mastery is just one component of effective network security analysis. The related pages below will 
            help you expand your skills in complementary areas including protocol exploitation, network attacks, and the 
            VRAgent platform's built-in PCAP analysis capabilities. For the best learning experience, combine this theoretical 
            knowledge with hands-on practice in lab environments where you can safely generate and analyze traffic patterns.
          </Typography>
          
          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", justifyContent: "center" }}>
            <Button variant="outlined" component={Link} to="/learn/network-hub" sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}>
              Dynamic Analysis Hub
            </Button>
            <Button variant="outlined" component={Link} to="/learn/wireshark" sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}>
              VRAgent PCAP Analyzer
            </Button>
            <Button variant="outlined" component={Link} to="/learn/network-protocol-exploitation" sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}>
              Network Protocol Exploitation
            </Button>
            <Button variant="outlined" component={Link} to="/learn/arp-dns-poisoning" sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}>
              ARP/DNS Poisoning
            </Button>
          </Box>
        </Paper>
        </Box>

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
            </Grid>
          </Grid>
        </Container>
      </Box>

      {/* Mobile Navigation Drawer */}
      <Drawer
        anchor="left"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        sx={{
          display: { xs: "block", md: "none" },
          "& .MuiDrawer-paper": {
            width: 280,
            bgcolor: pageTheme.bgCard,
            borderRight: `1px solid ${pageTheme.border}`,
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
            <Typography variant="h6" sx={{ color: pageTheme.text, fontWeight: 700 }}>
              Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} sx={{ color: pageTheme.text }}>
              <CloseIcon />
            </IconButton>
          </Box>
          <List>
            {sectionNavItems.map((item) => (
              <ListItem key={item.id} disablePadding>
                <ListItemButton
                  onClick={() => {
                    scrollToSection(item.id);
                    setNavDrawerOpen(false);
                  }}
                  sx={{
                    borderRadius: 1,
                    mb: 0.5,
                    "&:hover": { bgcolor: alpha("#8b5cf6", 0.1) },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 36, color: "#8b5cf6" }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.label}
                    primaryTypographyProps={{ variant: "body2", color: pageTheme.text }}
                  />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>

      {/* Mobile FABs */}
      <Box
        sx={{
          position: "fixed",
          bottom: 16,
          right: 16,
          display: { xs: "flex", md: "none" },
          flexDirection: "column",
          gap: 1,
          zIndex: 1000,
        }}
      >
        <Fab
          size="small"
          onClick={scrollToTop}
          sx={{
            bgcolor: pageTheme.bgCard,
            color: "#8b5cf6",
            border: `1px solid ${pageTheme.border}`,
            "&:hover": { bgcolor: alpha("#8b5cf6", 0.1) },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
        <Fab
          size="small"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            bgcolor: "#8b5cf6",
            color: "white",
            "&:hover": { bgcolor: "#7c3aed" },
          }}
        >
          <MenuIcon />
        </Fab>
      </Box>
    </LearnPageLayout>
  );
}
