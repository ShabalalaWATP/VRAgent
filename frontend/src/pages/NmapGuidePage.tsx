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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Button,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  keyframes,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import RadarIcon from "@mui/icons-material/Radar";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SpeedIcon from "@mui/icons-material/Speed";
import SearchIcon from "@mui/icons-material/Search";
import SecurityIcon from "@mui/icons-material/Security";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import DownloadIcon from "@mui/icons-material/Download";
import TerminalIcon from "@mui/icons-material/Terminal";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import SaveIcon from "@mui/icons-material/Save";
import VisibilityIcon from "@mui/icons-material/Visibility";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SchoolIcon from "@mui/icons-material/School";
import SettingsIcon from "@mui/icons-material/Settings";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import DnsIcon from "@mui/icons-material/Dns";
import StorageIcon from "@mui/icons-material/Storage";
import PublicIcon from "@mui/icons-material/Public";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import BugReportIcon from "@mui/icons-material/BugReport";
import WarningIcon from "@mui/icons-material/Warning";
import ComputerIcon from "@mui/icons-material/Computer";
import RouterIcon from "@mui/icons-material/Router";
import LayersIcon from "@mui/icons-material/Layers";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import FlagIcon from "@mui/icons-material/Flag";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import AnalyticsIcon from "@mui/icons-material/Analytics";
import ShieldIcon from "@mui/icons-material/Shield";

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

const radarSweep = keyframes`
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
`;

export default function NmapGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();

  const scanTypes = [
    { flag: "-sS", name: "SYN Scan (Stealth)", description: "Sends SYN, waits for SYN/ACK, never completes handshake. Hard to detect, requires root/admin.", speed: "Fast", category: "TCP" },
    { flag: "-sT", name: "TCP Connect", description: "Full TCP 3-way handshake. Logged by target, but no root needed. Use when -sS isn't available.", speed: "Medium", category: "TCP" },
    { flag: "-sU", name: "UDP Scan", description: "Scans UDP ports. Slow because UDP doesn't acknowledge. Critical for DNS, SNMP, DHCP discovery.", speed: "Slow", category: "UDP" },
    { flag: "-sA", name: "ACK Scan", description: "Sends ACK packets to map firewall rules. Determines if ports are filtered vs unfiltered.", speed: "Fast", category: "TCP" },
    { flag: "-sW", name: "Window Scan", description: "Like ACK scan but examines TCP window field. Can detect open ports on some systems.", speed: "Fast", category: "TCP" },
    { flag: "-sN", name: "NULL Scan", description: "Sends packets with no flags set. Can bypass some firewalls. Unix systems respond differently.", speed: "Fast", category: "Stealth" },
    { flag: "-sF", name: "FIN Scan", description: "Sends FIN packet. Similar to NULL, useful for evading certain IDS systems.", speed: "Fast", category: "Stealth" },
    { flag: "-sX", name: "Xmas Scan", description: "Sends FIN+PSH+URG flags (lit up like a Christmas tree). Stealthy but detectable.", speed: "Fast", category: "Stealth" },
    { flag: "-sV", name: "Version Detection", description: "Probes open ports to determine service/version. Essential for vulnerability assessment.", speed: "Medium", category: "Detection" },
    { flag: "-O", name: "OS Detection", description: "Analyzes TCP/IP fingerprint to identify operating system. Requires at least one open + one closed port.", speed: "Medium", category: "Detection" },
    { flag: "-A", name: "Aggressive Scan", description: "Enables -O, -sV, -sC, --traceroute. Comprehensive but noisy and slow.", speed: "Slow", category: "Detection" },
    { flag: "-sn", name: "Ping Scan", description: "Host discovery only—no port scan. Uses ICMP echo, TCP SYN/ACK, ARP on local networks.", speed: "Fast", category: "Discovery" },
    { flag: "-sC", name: "Script Scan", description: "Runs default NSE scripts. Equivalent to --script=default. Good balance of info and safety.", speed: "Medium", category: "Scripts" },
    { flag: "-sI", name: "Idle/Zombie Scan", description: "Uses a zombie host to scan target. Ultimate stealth—target never sees your IP.", speed: "Slow", category: "Stealth" },
  ];

  const commonCommands = [
    { command: "nmap 192.168.1.1", description: "Basic scan of top 1000 TCP ports", category: "Basic" },
    { command: "nmap -p- 192.168.1.1", description: "Scan all 65535 ports (thorough but slow)", category: "Basic" },
    { command: "nmap -p 22,80,443,3306 target", description: "Scan specific ports only", category: "Basic" },
    { command: "nmap -p 1-1000 target", description: "Scan port range", category: "Basic" },
    { command: "nmap -sV -sC target", description: "Version detection + default scripts (recommended)", category: "Standard" },
    { command: "nmap -A target", description: "Aggressive: OS + version + scripts + traceroute", category: "Standard" },
    { command: "nmap -sn 192.168.1.0/24", description: "Discover all live hosts on subnet", category: "Discovery" },
    { command: "nmap -sn -PS22,80,443 target", description: "Ping scan using TCP SYN on specific ports", category: "Discovery" },
    { command: "nmap --top-ports 100 target", description: "Scan only top 100 most common ports", category: "Performance" },
    { command: "nmap -T4 target", description: "Faster timing template (T0-T5, default is T3)", category: "Performance" },
    { command: "nmap -Pn target", description: "Skip host discovery (assume host is up)", category: "Firewall" },
    { command: "nmap -f target", description: "Fragment packets to evade firewalls", category: "Firewall" },
    { command: "nmap --script vuln target", description: "Run all vulnerability detection scripts", category: "Security" },
    { command: "nmap --script=http-enum target", description: "Enumerate web server directories/files", category: "Security" },
    { command: "nmap -oX scan.xml target", description: "Save output as XML (for VRAgent import)", category: "Output" },
    { command: "nmap -oA scan target", description: "Save in all formats (.nmap, .xml, .gnmap)", category: "Output" },
  ];

  const nsScripts = [
    { 
      category: "default", 
      flag: "--script=default or -sC",
      description: "Safe, useful scripts that run automatically. Includes http-title, ssh-hostkey, ssl-cert, etc.",
      examples: ["http-title", "ssh-hostkey", "ssl-cert", "dns-nsid"],
      color: "#10b981",
    },
    { 
      category: "vuln", 
      flag: "--script=vuln",
      description: "Check for known vulnerabilities like Heartbleed, EternalBlue, Shellshock.",
      examples: ["http-vuln-cve2017-5638", "smb-vuln-ms17-010", "ssl-heartbleed"],
      color: "#ef4444",
    },
    { 
      category: "exploit", 
      flag: "--script=exploit",
      description: "Actively attempt to exploit vulnerabilities. Use only on authorized targets!",
      examples: ["http-shellshock", "ftp-vsftpd-backdoor"],
      color: "#dc2626",
    },
    { 
      category: "auth", 
      flag: "--script=auth",
      description: "Check for authentication issues, default credentials, anonymous access.",
      examples: ["ftp-anon", "http-auth", "mysql-empty-password"],
      color: "#f59e0b",
    },
    { 
      category: "brute", 
      flag: "--script=brute",
      description: "Brute force password attacks. Slow and noisy—use with caution.",
      examples: ["ssh-brute", "http-brute", "ftp-brute"],
      color: "#8b5cf6",
    },
    { 
      category: "discovery", 
      flag: "--script=discovery",
      description: "Gather more information about the target network and services.",
      examples: ["dns-brute", "http-enum", "smb-enum-shares"],
      color: "#3b82f6",
    },
    { 
      category: "safe", 
      flag: "--script=safe",
      description: "Scripts guaranteed not to crash services or cause issues. Good for production.",
      examples: ["ssh-auth-methods", "http-headers", "ssl-enum-ciphers"],
      color: "#06b6d4",
    },
    { 
      category: "broadcast", 
      flag: "--script=broadcast",
      description: "Discover hosts and services via broadcast messages on local network.",
      examples: ["broadcast-dhcp-discover", "broadcast-netbios-master-browser"],
      color: "#a855f7",
    },
  ];

  const gettingStartedSteps = [
    {
      label: "Install Nmap",
      description: "Download from nmap.org. Windows installer includes Zenmap GUI. On Linux: apt install nmap. On macOS: brew install nmap.",
      icon: <DownloadIcon />,
      tips: ["Zenmap is included on Windows", "Linux may need sudo for SYN scans", "Check with: nmap --version"],
    },
    {
      label: "Identify Your Target",
      description: "Know what you're scanning. Can be a single IP (192.168.1.1), hostname (scanme.nmap.org), range (192.168.1.1-50), or CIDR subnet (192.168.1.0/24).",
      icon: <PublicIcon />,
      tips: ["Only scan systems you own or have permission", "scanme.nmap.org is Nmap's practice target", "Use CIDR for entire networks"],
    },
    {
      label: "Start with Host Discovery",
      description: "First, find out what hosts are alive on the network. Use nmap -sn to ping sweep without port scanning.",
      icon: <SearchIcon />,
      tips: ["nmap -sn 192.168.1.0/24", "Lists all responding hosts", "Faster than full port scan"],
    },
    {
      label: "Run a Basic Port Scan",
      description: "Scan the target for open ports. The default scans top 1000 ports. Add -p- for all 65535 ports.",
      icon: <RadarIcon />,
      tips: ["nmap target (top 1000 ports)", "nmap -p- target (all ports)", "Takes longer but more thorough"],
    },
    {
      label: "Add Version Detection",
      description: "Use -sV to identify what services and versions are running on open ports. Critical for finding vulnerable software.",
      icon: <LayersIcon />,
      tips: ["nmap -sV target", "Shows Apache 2.4.41, OpenSSH 8.2, etc.", "Combine with -sC for scripts"],
    },
    {
      label: "Save Your Results",
      description: "Always save scan output for later analysis. Use -oX for XML (importable to VRAgent), -oN for normal text, or -oA for all formats.",
      icon: <SaveIcon />,
      tips: ["nmap -oX scan.xml target", "XML works with VRAgent", "-oA saves .nmap, .xml, .gnmap"],
    },
  ];

  const timingTemplates = [
    { level: "T0", name: "Paranoid", delay: "5 min between probes", use: "IDS evasion, extremely slow" },
    { level: "T1", name: "Sneaky", delay: "15 sec between probes", use: "IDS evasion" },
    { level: "T2", name: "Polite", delay: "0.4 sec between probes", use: "Less bandwidth, slower" },
    { level: "T3", name: "Normal", delay: "Default", use: "Default speed, balanced" },
    { level: "T4", name: "Aggressive", delay: "10ms delay, 1250 parallelism", use: "Fast, reliable networks" },
    { level: "T5", name: "Insane", delay: "5ms delay, max parallelism", use: "Very fast, may miss ports" },
  ];

  const outputFormats = [
    { flag: "-oN file.txt", description: "Normal output (human readable)", format: "Text" },
    { flag: "-oX file.xml", description: "XML output (for tools like VRAgent)", format: "XML" },
    { flag: "-oG file.gnmap", description: "Grepable output (easy parsing)", format: "Grep" },
    { flag: "-oA basename", description: "All three formats at once", format: "All" },
    { flag: "-oS file.txt", description: "Script kiddie output (1337 speak)", format: "Fun" },
  ];

  const realWorldScenarios = [
    {
      title: "🔍 Quick Network Inventory",
      description: "Discover all live hosts and their open services on your local network.",
      commands: [
        "nmap -sn 192.168.1.0/24",
        "nmap -sV --top-ports 20 192.168.1.0/24",
      ],
      icon: <RouterIcon />,
      color: "#3b82f6",
    },
    {
      title: "🛡️ Vulnerability Assessment",
      description: "Find potential security issues on a target system.",
      commands: [
        "nmap -sV --script vuln target",
        "nmap -p 445 --script smb-vuln* target",
      ],
      icon: <ShieldIcon />,
      color: "#ef4444",
    },
    {
      title: "🌐 Web Server Audit",
      description: "Enumerate a web server for directories, methods, and vulnerabilities.",
      commands: [
        "nmap -p 80,443 --script http-enum target",
        "nmap -p 80 --script http-methods,http-headers target",
      ],
      icon: <PublicIcon />,
      color: "#10b981",
    },
    {
      title: "🔐 Service Version Hunt",
      description: "Identify exact versions of services for CVE research.",
      commands: [
        "nmap -sV -p- target -oX versions.xml",
        "nmap -sV --version-intensity 5 target",
      ],
      icon: <LayersIcon />,
      color: "#8b5cf6",
    },
    {
      title: "🕵️ Stealth Scan",
      description: "Scan while minimizing detection by IDS/IPS systems.",
      commands: [
        "nmap -sS -T2 -f target",
        "nmap -sS -D RND:10 target",
      ],
      icon: <VisibilityIcon />,
      color: "#f59e0b",
    },
    {
      title: "📊 Full Pentest Scan",
      description: "Comprehensive scan for penetration testing (authorized only!).",
      commands: [
        "nmap -A -T4 -p- -oA fullscan target",
        "nmap -sC -sV -O --script=default,vuln target",
      ],
      icon: <BugReportIcon />,
      color: "#dc2626",
    },
  ];

  const portStates = [
    { state: "open", description: "Service is accepting connections", color: "#10b981" },
    { state: "closed", description: "Port is accessible but no service listening", color: "#ef4444" },
    { state: "filtered", description: "Firewall blocking—can't determine state", color: "#f59e0b" },
    { state: "unfiltered", description: "Accessible but open/closed unknown (ACK scan)", color: "#6b7280" },
    { state: "open|filtered", description: "Could be either—no response received", color: "#8b5cf6" },
    { state: "closed|filtered", description: "Could be either (IP ID idle scan)", color: "#a855f7" },
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
          background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.15)} 0%, ${alpha("#6366f1", 0.1)} 50%, ${alpha("#3b82f6", 0.05)} 100%)`,
          border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
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
            background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.2)} 0%, transparent 70%)`,
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
            background: `radial-gradient(circle, ${alpha("#6366f1", 0.15)} 0%, transparent 70%)`,
            animation: `${float} 5s ease-in-out infinite`,
            animationDelay: "1s",
          }}
        />
        {/* Radar sweep effect */}
        <Box
          sx={{
            position: "absolute",
            top: "50%",
            right: 80,
            width: 120,
            height: 120,
            marginTop: "-60px",
            borderRadius: "50%",
            border: `2px solid ${alpha("#8b5cf6", 0.2)}`,
            "&::after": {
              content: '""',
              position: "absolute",
              top: "50%",
              left: "50%",
              width: "50%",
              height: "2px",
              background: `linear-gradient(90deg, ${alpha("#8b5cf6", 0.8)}, transparent)`,
              transformOrigin: "left center",
              animation: `${radarSweep} 3s linear infinite`,
            },
            display: { xs: "none", md: "block" },
          }}
        />

        <Box sx={{ position: "relative", zIndex: 1 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
            <Box
              sx={{
                width: 80,
                height: 80,
                borderRadius: 3,
                background: `linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#8b5cf6", 0.4)}`,
                animation: `${float} 4s ease-in-out infinite`,
              }}
            >
              <RadarIcon sx={{ fontSize: 44, color: "white" }} />
            </Box>
            <Box>
              <Typography
                variant="h3"
                sx={{
                  fontWeight: 800,
                  background: `linear-gradient(135deg, #8b5cf6 0%, #6366f1 50%, #3b82f6 100%)`,
                  backgroundSize: "200% auto",
                  backgroundClip: "text",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  animation: `${shimmer} 4s linear infinite`,
                }}
              >
                Nmap Essentials
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                The Network Mapper — Your Swiss Army Knife for Network Discovery
              </Typography>
            </Box>
          </Box>

          <Typography variant="body1" sx={{ maxWidth: 700, mb: 3, fontSize: "1.1rem", lineHeight: 1.7 }}>
            Nmap is the world's most powerful network scanning tool. From simple host discovery to 
            complex vulnerability assessments, this guide will take you from beginner to proficient 
            in network reconnaissance.
          </Typography>

          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
            <Button
              variant="contained"
              startIcon={<RocketLaunchIcon />}
              onClick={() => navigate("/network/nmap")}
              sx={{
                background: `linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)`,
                px: 3,
                py: 1.5,
                fontWeight: 600,
                boxShadow: `0 4px 20px ${alpha("#8b5cf6", 0.4)}`,
                "&:hover": {
                  boxShadow: `0 6px 30px ${alpha("#8b5cf6", 0.5)}`,
                },
              }}
            >
              Open Nmap Analyzer
            </Button>
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              component="a"
              href="https://nmap.org/download.html"
              target="_blank"
              sx={{
                borderColor: alpha("#8b5cf6", 0.5),
                color: "#a78bfa",
                "&:hover": {
                  borderColor: "#8b5cf6",
                  bgcolor: alpha("#8b5cf6", 0.1),
                },
              }}
            >
              Download Nmap
            </Button>
          </Box>
        </Box>
      </Paper>

      {/* Stats Bar */}
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { label: "65,535", subtitle: "Possible Ports", icon: <StorageIcon />, color: "#3b82f6" },
          { label: "600+", subtitle: "NSE Scripts", icon: <CodeIcon />, color: "#8b5cf6" },
          { label: "25+", subtitle: "Years Development", icon: <AccessTimeIcon />, color: "#10b981" },
          { label: "#1", subtitle: "Network Scanner", icon: <FlagIcon />, color: "#f59e0b" },
        ].map((stat) => (
          <Grid item xs={6} md={3} key={stat.label}>
            <Paper
              sx={{
                p: 2,
                textAlign: "center",
                borderRadius: 2,
                border: `1px solid ${alpha(stat.color, 0.2)}`,
                background: alpha(stat.color, 0.03),
              }}
            >
              <Box sx={{ color: stat.color, mb: 0.5 }}>{stat.icon}</Box>
              <Typography variant="h5" sx={{ fontWeight: 700, color: stat.color }}>
                {stat.label}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {stat.subtitle}
              </Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* What is Nmap */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SchoolIcon sx={{ color: "#8b5cf6", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            What is Nmap?
          </Typography>
        </Box>
        <Typography variant="body1" paragraph sx={{ fontSize: "1.05rem" }}>
          <strong>Nmap</strong> ("Network Mapper") is a free, open-source utility for network discovery 
          and security auditing. Created by Gordon Lyon (Fyodor) in 1997, it's become the industry 
          standard for network reconnaissance used by security professionals worldwide.
        </Typography>
        <Grid container spacing={3} sx={{ mb: 3 }}>
          {[
            { label: "Host Discovery", desc: "Find what devices are live on a network", color: "#3b82f6", icon: <RouterIcon /> },
            { label: "Port Scanning", desc: "Identify open ports and services", color: "#10b981", icon: <StorageIcon /> },
            { label: "Version Detection", desc: "Determine software versions running", color: "#8b5cf6", icon: <LayersIcon /> },
            { label: "OS Fingerprinting", desc: "Identify target operating systems", color: "#f59e0b", icon: <ComputerIcon /> },
            { label: "Vulnerability Scanning", desc: "Find known security issues via NSE", color: "#ef4444", icon: <BugReportIcon /> },
            { label: "Network Mapping", desc: "Build topology and route information", color: "#06b6d4", icon: <NetworkCheckIcon /> },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.label}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha(item.color, 0.2)}`,
                  bgcolor: alpha(item.color, 0.03),
                  height: "100%",
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                  <Box sx={{ color: item.color }}>{item.icon}</Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: item.color }}>
                    {item.label}
                  </Typography>
                </Box>
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
            <strong>💡 VRAgent Integration:</strong> VRAgent's Nmap Analyzer can run scans directly 
            and parse XML output for AI-powered security insights. Import your existing scan files 
            or run new scans from the interface!
          </Typography>
        </Paper>

        {/* Network Graph Feature Highlight */}
        <Paper
          sx={{
            p: 2,
            mt: 2,
            borderRadius: 2,
            bgcolor: alpha("#06b6d4", 0.05),
            border: `1px solid ${alpha("#06b6d4", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>🕸️ Network Graph Visualization:</strong> VRAgent includes an interactive force-directed 
            network graph that visualizes your scan results. See discovered hosts as nodes connected to the 
            scanner, with services branching from each host. Nodes are color-coded by risk level (hosts) and 
            service type (ports). Perfect for understanding network topology and identifying high-risk systems!
          </Typography>
        </Paper>
      </Paper>

      {/* Getting Started - Stepper */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <RocketLaunchIcon sx={{ color: "#10b981", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Getting Started: Your First Scan
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
                        fontFamily: tip.startsWith("nmap") ? "monospace" : "inherit",
                      }}
                    />
                  ))}
                </Box>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </Paper>

      {/* Port States */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <FlagIcon sx={{ color: "#6366f1", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Understanding Port States
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Nmap categorizes ports into different states. Understanding these helps interpret scan results:
        </Typography>
        <Grid container spacing={2}>
          {portStates.map((port) => (
            <Grid item xs={12} sm={6} md={4} key={port.state}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  borderLeft: `4px solid ${port.color}`,
                  bgcolor: alpha(port.color, 0.03),
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: port.color, fontFamily: "monospace" }}>
                  {port.state}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {port.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Scan Types - Expanded */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <SpeedIcon sx={{ color: "#3b82f6", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Scan Types Reference
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Nmap offers many scan types for different scenarios. Choose based on your needs:
        </Typography>

        <Grid container spacing={1} sx={{ mb: 3 }}>
          {["TCP", "UDP", "Stealth", "Detection", "Discovery", "Scripts"].map((cat) => (
            <Grid item key={cat}>
              <Chip
                label={cat}
                size="small"
                sx={{
                  bgcolor: alpha("#3b82f6", 0.1),
                  color: "#3b82f6",
                  fontWeight: 600,
                }}
              />
            </Grid>
          ))}
        </Grid>

        <TableContainer sx={{ maxHeight: 450 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Flag</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Name</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Speed</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Type</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scanTypes.map((row) => (
                <TableRow key={row.flag} hover>
                  <TableCell>
                    <code style={{ 
                      backgroundColor: alpha("#3b82f6", 0.1), 
                      padding: "4px 10px", 
                      borderRadius: 4,
                      fontSize: "0.85rem",
                      fontWeight: 600,
                    }}>
                      {row.flag}
                    </code>
                  </TableCell>
                  <TableCell sx={{ fontWeight: 500 }}>{row.name}</TableCell>
                  <TableCell sx={{ maxWidth: 300 }}>{row.description}</TableCell>
                  <TableCell>
                    <Chip 
                      label={row.speed} 
                      size="small"
                      sx={{
                        bgcolor: row.speed === "Fast" ? alpha("#10b981", 0.1) : 
                                 row.speed === "Medium" ? alpha("#f59e0b", 0.1) : alpha("#ef4444", 0.1),
                        color: row.speed === "Fast" ? "#10b981" : 
                               row.speed === "Medium" ? "#f59e0b" : "#ef4444",
                        fontWeight: 600,
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip label={row.category} size="small" variant="outlined" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Common Commands */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <TerminalIcon sx={{ color: "#10b981", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Essential Commands
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Copy-paste ready commands for common scanning scenarios:
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {commonCommands.map((row) => (
                <TableRow key={row.command} hover>
                  <TableCell>
                    <code style={{ 
                      backgroundColor: alpha("#10b981", 0.1), 
                      padding: "4px 10px", 
                      borderRadius: 4,
                      fontSize: "0.8rem",
                      display: "inline-block",
                    }}>
                      {row.command}
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
      </Paper>

      {/* Timing Templates */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <AccessTimeIcon sx={{ color: "#f59e0b", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Timing Templates (-T)
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Control scan speed vs stealth. Higher = faster but noisier:
        </Typography>
        <Grid container spacing={2}>
          {timingTemplates.map((t, idx) => (
            <Grid item xs={12} sm={6} md={4} key={t.level}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha("#f59e0b", 0.2 + idx * 0.1)}`,
                  bgcolor: alpha("#f59e0b", 0.02 + idx * 0.01),
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <code style={{ 
                    backgroundColor: alpha("#f59e0b", 0.15), 
                    padding: "2px 8px", 
                    borderRadius: 4,
                    fontWeight: 700,
                    color: "#f59e0b",
                  }}>
                    {t.level}
                  </code>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                    {t.name}
                  </Typography>
                </Box>
                <Typography variant="caption" display="block" color="text.secondary">
                  {t.delay}
                </Typography>
                <Typography variant="body2" sx={{ mt: 0.5 }}>
                  {t.use}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
        <Paper
          sx={{
            p: 2,
            mt: 3,
            borderRadius: 2,
            bgcolor: alpha("#10b981", 0.05),
            border: `1px solid ${alpha("#10b981", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>💡 Recommendation:</strong> Use <code style={{ backgroundColor: alpha("#10b981", 0.2), padding: "2px 6px", borderRadius: 4 }}>-T4</code> for 
            local/trusted networks. Use <code style={{ backgroundColor: alpha("#f59e0b", 0.2), padding: "2px 6px", borderRadius: 4 }}>-T2</code> or lower when 
            stealth matters. <code style={{ backgroundColor: alpha("#ef4444", 0.2), padding: "2px 6px", borderRadius: 4 }}>-T5</code> may drop packets on slow links.
          </Typography>
        </Paper>
      </Paper>

      {/* NSE Scripts */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <CodeIcon sx={{ color: "#ef4444", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Nmap Scripting Engine (NSE)
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          NSE extends Nmap with powerful Lua scripts for vulnerability detection, exploitation, and more. 
          Over 600 scripts are included by default.
        </Typography>
        <Grid container spacing={2}>
          {nsScripts.map((script) => (
            <Grid item xs={12} md={6} key={script.category}>
              <Accordion
                sx={{
                  borderRadius: 2,
                  border: `1px solid ${alpha(script.color, 0.2)}`,
                  "&:before": { display: "none" },
                  overflow: "hidden",
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon />}
                  sx={{ bgcolor: alpha(script.color, 0.05) }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <code style={{ 
                      backgroundColor: alpha(script.color, 0.15), 
                      padding: "4px 10px", 
                      borderRadius: 4,
                      fontWeight: 600,
                      color: script.color,
                      fontSize: "0.85rem",
                    }}>
                      {script.category}
                    </code>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {script.description}
                  </Typography>
                  <Typography variant="caption" display="block" sx={{ mb: 1, fontWeight: 600 }}>
                    Usage: <code style={{ backgroundColor: alpha(script.color, 0.1), padding: "2px 6px", borderRadius: 4 }}>{script.flag}</code>
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Examples: {script.examples.join(", ")}
                  </Typography>
                </AccordionDetails>
              </Accordion>
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
            <strong>⚠️ Warning:</strong> Scripts in <code>exploit</code> and <code>brute</code> categories can 
            cause service disruption or legal issues. Only use on systems you own or have explicit authorization to test!
          </Typography>
        </Paper>
      </Paper>

      {/* Real World Scenarios */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <BuildIcon sx={{ color: "#6366f1", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Real-World Scenarios
          </Typography>
        </Box>
        <Grid container spacing={3}>
          {realWorldScenarios.map((scenario) => (
            <Grid item xs={12} md={6} key={scenario.title}>
              <Card
                sx={{
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(scenario.color, 0.2)}`,
                  borderTop: `4px solid ${scenario.color}`,
                }}
              >
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                    <Box sx={{ color: scenario.color }}>{scenario.icon}</Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      {scenario.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {scenario.description}
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {scenario.commands.map((cmd, idx) => (
                      <code
                        key={idx}
                        style={{
                          backgroundColor: alpha(scenario.color, 0.1),
                          padding: "6px 10px",
                          borderRadius: 4,
                          fontSize: "0.8rem",
                          display: "block",
                        }}
                      >
                        {cmd}
                      </code>
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Output Formats */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SaveIcon sx={{ color: "#06b6d4", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Output Formats
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Save scan results for later analysis and tool integration:
        </Typography>
        <Grid container spacing={2}>
          {outputFormats.map((fmt) => (
            <Grid item xs={12} sm={6} md={4} key={fmt.flag}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha("#06b6d4", 0.2)}`,
                }}
              >
                <code style={{ 
                  backgroundColor: alpha("#06b6d4", 0.1), 
                  padding: "4px 10px", 
                  borderRadius: 4,
                  fontSize: "0.85rem",
                  display: "inline-block",
                  marginBottom: 8,
                }}>
                  {fmt.flag}
                </code>
                <Typography variant="body2" color="text.secondary">
                  {fmt.description}
                </Typography>
                <Chip label={fmt.format} size="small" sx={{ mt: 1 }} variant="outlined" />
              </Paper>
            </Grid>
          ))}
        </Grid>
        <Paper
          sx={{
            p: 2,
            mt: 3,
            borderRadius: 2,
            bgcolor: alpha("#8b5cf6", 0.05),
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>🚀 VRAgent Tip:</strong> Use <code style={{ backgroundColor: alpha("#8b5cf6", 0.2), padding: "2px 6px", borderRadius: 4 }}>-oX scan.xml</code> for 
            XML output—VRAgent's Nmap Analyzer can parse this format and provide AI-powered analysis of your scan results!
          </Typography>
        </Paper>
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
            Pro Tips & Best Practices
          </Typography>
        </Box>
        <Grid container spacing={2}>
          {[
            { tip: "Always use -oX to save XML output for importing into security tools and VRAgent", icon: <SaveIcon /> },
            { tip: "Use -T4 on reliable networks for 5x faster scans without sacrificing accuracy", icon: <SpeedIcon /> },
            { tip: "Combine -sV -sC (-A is shortcut) for comprehensive service enumeration", icon: <LayersIcon /> },
            { tip: "Use --top-ports 100 for quick scans—covers 95% of services you'll find", icon: <AnalyticsIcon /> },
            { tip: "Add -Pn when ICMP is blocked—skips host discovery and scans anyway", icon: <RouterIcon /> },
            { tip: "Use --script-help=* to explore available NSE scripts and their options", icon: <CodeIcon /> },
            { tip: "Run -sU -sS together to scan both UDP and TCP (UDP often overlooked!)", icon: <StorageIcon /> },
            { tip: "Use --reason flag to understand why ports are marked as they are", icon: <SearchIcon /> },
            { tip: "Practice on scanme.nmap.org—Nmap's official test target", icon: <PublicIcon /> },
            { tip: "Always get written authorization before scanning production networks", icon: <SecurityIcon /> },
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
          background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)} 0%, ${alpha("#6366f1", 0.05)} 100%)`,
          border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
        }}
      >
        <RadarIcon sx={{ fontSize: 48, color: "#8b5cf6", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Ready to Scan?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 600, mx: "auto" }}>
          Run Nmap scans directly from VRAgent or upload existing XML files for AI-powered 
          security analysis, interactive network graph visualization, and vulnerability insights!
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<RocketLaunchIcon />}
            onClick={() => navigate("/network/nmap")}
            sx={{
              background: `linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)`,
              px: 4,
              py: 1.5,
              fontWeight: 700,
              fontSize: "1rem",
              boxShadow: `0 4px 20px ${alpha("#8b5cf6", 0.4)}`,
              "&:hover": {
                boxShadow: `0 6px 30px ${alpha("#8b5cf6", 0.5)}`,
              },
            }}
          >
            Open Nmap Analyzer
          </Button>
          <Button
            variant="outlined"
            size="large"
            component={Link}
            to="/learn/network-hub"
            sx={{
              borderColor: alpha("#06b6d4", 0.5),
              color: "#22d3ee",
              px: 3,
              py: 1.5,
              "&:hover": {
                borderColor: "#06b6d4",
                bgcolor: alpha("#06b6d4", 0.1),
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
