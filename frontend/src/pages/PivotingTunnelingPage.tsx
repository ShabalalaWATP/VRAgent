import React, { useState } from "react";
import {
  Box,
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
  Chip,
  Button,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  alpha,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import RouteIcon from "@mui/icons-material/Route";
import SecurityIcon from "@mui/icons-material/Security";
import HubIcon from "@mui/icons-material/Hub";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ShieldIcon from "@mui/icons-material/Shield";
import SearchIcon from "@mui/icons-material/Search";
import QuizIcon from "@mui/icons-material/Quiz";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

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

const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "bash",
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
        p: 2,
        bgcolor: "#121424",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(59, 130, 246, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#3b82f6", color: "#0b1020" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#e2e8f0" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          overflow: "auto",
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          pt: 2,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#3b82f6";

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Basics",
    question: "What is pivoting?",
    options: [
      "Routing traffic through a compromised host to reach other systems",
      "Escalating privileges on a single host",
      "Encrypting data before exfiltration",
      "Disabling network segmentation",
    ],
    correctAnswer: 0,
    explanation: "Pivoting uses a foothold to access other networks or hosts.",
  },
  {
    id: 2,
    topic: "Basics",
    question: "What is tunneling in a security context?",
    options: [
      "Encapsulating traffic inside another protocol or connection",
      "Installing a new operating system",
      "Creating a new local user account",
      "Clearing event logs",
    ],
    correctAnswer: 0,
    explanation: "Tunneling wraps traffic to pass through restricted paths.",
  },
  {
    id: 3,
    topic: "Basics",
    question: "A pivot host is best described as:",
    options: [
      "A compromised system used as a relay to other targets",
      "A public DNS server",
      "A firewall appliance",
      "A backup server",
    ],
    correctAnswer: 0,
    explanation: "Pivot hosts relay traffic into other network segments.",
  },
  {
    id: 4,
    topic: "Port Forwarding",
    question: "Local port forwarding with SSH is typically done with:",
    options: [
      "ssh -L",
      "ssh -R",
      "ssh -D",
      "ssh -A",
    ],
    correctAnswer: 0,
    explanation: "ssh -L forwards a local port to a remote destination.",
  },
  {
    id: 5,
    topic: "Port Forwarding",
    question: "Remote port forwarding with SSH is typically done with:",
    options: [
      "ssh -R",
      "ssh -L",
      "ssh -D",
      "ssh -N",
    ],
    correctAnswer: 0,
    explanation: "ssh -R exposes a remote port back to a local service.",
  },
  {
    id: 6,
    topic: "Port Forwarding",
    question: "Dynamic port forwarding creates:",
    options: [
      "A SOCKS proxy",
      "A static HTTP proxy",
      "A reverse shell",
      "A DNS server",
    ],
    correctAnswer: 0,
    explanation: "ssh -D sets up a SOCKS proxy for flexible routing.",
  },
  {
    id: 7,
    topic: "Proxies",
    question: "What does a SOCKS proxy provide?",
    options: [
      "Generic TCP forwarding through a proxy server",
      "Only HTTP traffic forwarding",
      "Encrypted file storage",
      "Automatic privilege escalation",
    ],
    correctAnswer: 0,
    explanation: "SOCKS proxies relay arbitrary TCP connections.",
  },
  {
    id: 8,
    topic: "Proxies",
    question: "Why use Proxychains?",
    options: [
      "To force tools to route through a proxy",
      "To disable firewall rules",
      "To remove authentication requirements",
      "To generate SSL certificates",
    ],
    correctAnswer: 0,
    explanation: "Proxychains routes tool traffic through configured proxies.",
  },
  {
    id: 9,
    topic: "Tools",
    question: "Chisel is commonly used for:",
    options: [
      "HTTP-based tunneling and port forwarding",
      "Password cracking",
      "Memory forensics",
      "Wireless analysis",
    ],
    correctAnswer: 0,
    explanation: "Chisel tunnels TCP traffic over HTTP/HTTPS.",
  },
  {
    id: 10,
    topic: "Tools",
    question: "Ligolo-ng is used for:",
    options: [
      "Agent-based pivoting with tunneling",
      "Local privilege escalation only",
      "Host-based firewall management",
      "Email phishing campaigns",
    ],
    correctAnswer: 0,
    explanation: "Ligolo-ng provides agent-based tunneling and pivoting.",
  },
  {
    id: 11,
    topic: "Tools",
    question: "What does socat commonly provide?",
    options: [
      "Flexible relay and port forwarding capabilities",
      "Disk encryption",
      "Credential dumping",
      "Packet capture only",
    ],
    correctAnswer: 0,
    explanation: "socat can bridge ports and relay traffic.",
  },
  {
    id: 12,
    topic: "Tools",
    question: "Netcat is often used for:",
    options: [
      "Simple TCP relay or port forwarding",
      "Full packet decryption",
      "Password hashing",
      "DNS zone transfers",
    ],
    correctAnswer: 0,
    explanation: "Netcat can create basic listeners and relays.",
  },
  {
    id: 13,
    topic: "Networking",
    question: "Why is segmentation important for defense?",
    options: [
      "It limits lateral movement paths",
      "It disables all logging",
      "It ensures passwords never expire",
      "It prevents patching",
    ],
    correctAnswer: 0,
    explanation: "Segmentation reduces reachable targets from a foothold.",
  },
  {
    id: 14,
    topic: "Networking",
    question: "A jump host is used to:",
    options: [
      "Centralize and monitor administrative access",
      "Replace all firewalls",
      "Disable authentication",
      "Encrypt all traffic automatically",
    ],
    correctAnswer: 0,
    explanation: "Jump hosts control admin access into sensitive networks.",
  },
  {
    id: 15,
    topic: "Networking",
    question: "Why is egress filtering effective against tunneling?",
    options: [
      "It restricts outbound connections and protocols",
      "It disables inbound firewall rules",
      "It forces use of weak encryption",
      "It allows unrestricted access",
    ],
    correctAnswer: 0,
    explanation: "Egress filters limit how tunneling can reach the internet.",
  },
  {
    id: 16,
    topic: "Detection",
    question: "A long-lived outbound connection may indicate:",
    options: [
      "A tunnel or proxy session",
      "A normal DHCP lease renewal",
      "A BIOS update",
      "A file system scan",
    ],
    correctAnswer: 0,
    explanation: "Long-lived connections are common in tunneling.",
  },
  {
    id: 17,
    topic: "Detection",
    question: "Why monitor for new listening ports on servers?",
    options: [
      "Tunneling tools often open new listeners",
      "They always indicate patching",
      "They are required for backups",
      "They only appear after reboots",
    ],
    correctAnswer: 0,
    explanation: "New listeners can indicate port forwards or relays.",
  },
  {
    id: 18,
    topic: "Detection",
    question: "Why is unusual DNS activity relevant to tunneling?",
    options: [
      "DNS can be used as a covert channel",
      "DNS is never logged",
      "DNS cannot be filtered",
      "DNS only works on internal networks",
    ],
    correctAnswer: 0,
    explanation: "DNS tunneling uses high-volume or high-entropy queries.",
  },
  {
    id: 19,
    topic: "Detection",
    question: "What is a common sign of HTTP tunneling?",
    options: [
      "Long, high-volume sessions to a single host",
      "Short DNS lookups only",
      "No outbound traffic at all",
      "Only ICMP echo replies",
    ],
    correctAnswer: 0,
    explanation: "HTTP tunnels often create sustained connections to a relay.",
  },
  {
    id: 20,
    topic: "Detection",
    question: "Why is protocol mismatch suspicious?",
    options: [
      "HTTP headers that do not match typical client behavior",
      "TLS certificates that are valid",
      "User logins during the day",
      "Routine software updates",
    ],
    correctAnswer: 0,
    explanation: "Tunnels often present unusual headers or behaviors.",
  },
  {
    id: 21,
    topic: "Port Forwarding",
    question: "What is the main difference between port forwarding and tunneling?",
    options: [
      "Port forwarding exposes a specific port; tunneling can carry broader traffic",
      "Port forwarding always uses DNS",
      "Tunneling only works on Linux",
      "Port forwarding requires a GUI",
    ],
    correctAnswer: 0,
    explanation: "Port forwarding is narrower; tunneling is more flexible.",
  },
  {
    id: 22,
    topic: "Proxies",
    question: "A reverse proxy is often used to:",
    options: [
      "Expose internal services to external access",
      "Disable inbound traffic",
      "Encrypt disks",
      "Change registry values",
    ],
    correctAnswer: 0,
    explanation: "Reverse proxies expose internal services externally.",
  },
  {
    id: 23,
    topic: "Proxies",
    question: "What is a key risk of open proxy servers?",
    options: [
      "They can be abused to route malicious traffic",
      "They are required for authentication",
      "They only affect DNS traffic",
      "They prevent network scanning",
    ],
    correctAnswer: 0,
    explanation: "Open proxies allow attackers to route traffic through the environment.",
  },
  {
    id: 24,
    topic: "Pivoting",
    question: "Pivoting commonly requires:",
    options: [
      "Valid credentials or agent access on an intermediate host",
      "A zero-day on every target",
      "Physical access to the server room",
      "No network access at all",
    ],
    correctAnswer: 0,
    explanation: "A foothold is needed to relay traffic to new targets.",
  },
  {
    id: 25,
    topic: "Pivoting",
    question: "Why are admin shares or remote management protocols relevant to pivoting?",
    options: [
      "They provide paths for remote execution or access",
      "They disable encryption",
      "They prevent logging",
      "They only work locally",
    ],
    correctAnswer: 0,
    explanation: "Remote management protocols enable lateral access.",
  },
  {
    id: 26,
    topic: "Networking",
    question: "What is split tunneling?",
    options: [
      "Only specific traffic is routed through a tunnel",
      "All traffic is blocked",
      "Tunnels are disabled during work hours",
      "Traffic is encrypted twice by default",
    ],
    correctAnswer: 0,
    explanation: "Split tunneling routes only selected traffic through a tunnel.",
  },
  {
    id: 27,
    topic: "Networking",
    question: "Why can VPNs be abused for lateral movement?",
    options: [
      "They can provide broad internal access once authenticated",
      "They disable host logging",
      "They remove the need for credentials",
      "They patch systems automatically",
    ],
    correctAnswer: 0,
    explanation: "VPNs often grant access to internal networks.",
  },
  {
    id: 28,
    topic: "Detection",
    question: "What is a useful telemetry source for tunneling detection?",
    options: [
      "Netflow or firewall logs",
      "Printer logs only",
      "BIOS logs only",
      "Screen capture logs",
    ],
    correctAnswer: 0,
    explanation: "Netflow and firewall logs show long-lived connections and ports.",
  },
  {
    id: 29,
    topic: "Detection",
    question: "Why monitor for unusual port usage?",
    options: [
      "Tunnels often use non-standard ports",
      "All ports are used equally in normal traffic",
      "Ports are never logged",
      "Port scanning is not possible",
    ],
    correctAnswer: 0,
    explanation: "Non-standard ports can indicate tunneling or proxying.",
  },
  {
    id: 30,
    topic: "Detection",
    question: "Why check for tools like `ssh` on servers that do not normally use them?",
    options: [
      "Unexpected tools may indicate pivoting setup",
      "ssh always disables logging",
      "ssh is required for Windows updates",
      "ssh only runs on routers",
    ],
    correctAnswer: 0,
    explanation: "Unexpected tools on servers can indicate tunneling activity.",
  },
  {
    id: 31,
    topic: "Tools",
    question: "Which option in SSH suppresses command execution and opens forwarding only?",
    options: [
      "-N",
      "-C",
      "-A",
      "-t",
    ],
    correctAnswer: 0,
    explanation: "-N tells SSH not to execute a remote command.",
  },
  {
    id: 32,
    topic: "Tools",
    question: "Which SSH option enables agent forwarding?",
    options: [
      "-A",
      "-L",
      "-R",
      "-D",
    ],
    correctAnswer: 0,
    explanation: "-A forwards the SSH agent to the remote host.",
  },
  {
    id: 33,
    topic: "Tools",
    question: "Why is agent forwarding risky in a pivot chain?",
    options: [
      "A compromised host can use the forwarded agent",
      "It disables encryption",
      "It blocks all tunneling",
      "It resets SSH keys",
    ],
    correctAnswer: 0,
    explanation: "Forwarded agents can be abused to access other hosts.",
  },
  {
    id: 34,
    topic: "Tools",
    question: "Which SSH option creates a SOCKS proxy?",
    options: [
      "-D",
      "-L",
      "-R",
      "-O",
    ],
    correctAnswer: 0,
    explanation: "-D opens a dynamic SOCKS proxy port.",
  },
  {
    id: 35,
    topic: "Detection",
    question: "What is a typical sign of port forwarding activity?",
    options: [
      "A local listener bound to loopback with sustained connections",
      "Only ICMP traffic",
      "No local listening ports",
      "Short DNS queries only",
    ],
    correctAnswer: 0,
    explanation: "Local listeners with sustained connections can indicate forwarding.",
  },
  {
    id: 36,
    topic: "Pivoting",
    question: "Why is credential reuse important for pivoting defense?",
    options: [
      "Reuse allows fast movement between hosts",
      "Reuse improves security",
      "Reuse prevents privilege escalation",
      "Reuse disables monitoring",
    ],
    correctAnswer: 0,
    explanation: "Credential reuse enables easy lateral movement and pivoting.",
  },
  {
    id: 37,
    topic: "Defense",
    question: "Network segmentation combined with MFA helps by:",
    options: [
      "Limiting access and adding authentication barriers",
      "Disabling all logging",
      "Allowing open admin shares",
      "Increasing bandwidth",
    ],
    correctAnswer: 0,
    explanation: "Segmentation and MFA reduce lateral movement opportunities.",
  },
  {
    id: 38,
    topic: "Defense",
    question: "Why restrict admin tools to jump hosts?",
    options: [
      "It centralizes monitoring and limits tool spread",
      "It disables authentication",
      "It removes the need for patching",
      "It forces encryption off",
    ],
    correctAnswer: 0,
    explanation: "Centralized access reduces exposure and improves oversight.",
  },
  {
    id: 39,
    topic: "Defense",
    question: "Why is logging east-west traffic important?",
    options: [
      "It reveals lateral movement and pivoting",
      "It only tracks internet traffic",
      "It is not useful in IR",
      "It disables segmentation",
    ],
    correctAnswer: 0,
    explanation: "East-west logs show internal movement patterns.",
  },
  {
    id: 40,
    topic: "Defense",
    question: "What is a simple defense against unauthorized tunnels?",
    options: [
      "Restrict outbound protocols and ports",
      "Disable all DNS",
      "Allow any outbound traffic",
      "Remove endpoint logging",
    ],
    correctAnswer: 0,
    explanation: "Egress restrictions reduce tunnel options.",
  },
  {
    id: 41,
    topic: "Detection",
    question: "Why is unusual TLS fingerprinting relevant?",
    options: [
      "Tunneling tools may use uncommon TLS stacks",
      "TLS fingerprints are never logged",
      "TLS fingerprints disable encryption",
      "TLS is unrelated to tunneling",
    ],
    correctAnswer: 0,
    explanation: "Unusual TLS fingerprints can indicate custom tunnels.",
  },
  {
    id: 42,
    topic: "Detection",
    question: "Why check for unexpected services listening on high ports?",
    options: [
      "Tunnels often bind to high, non-standard ports",
      "High ports are always benign",
      "High ports cannot be scanned",
      "High ports only carry DNS",
    ],
    correctAnswer: 0,
    explanation: "High-port listeners may indicate relays or tunnels.",
  },
  {
    id: 43,
    topic: "Detection",
    question: "What is a typical signal of SOCKS pivoting?",
    options: [
      "Internal scan traffic originating from a pivot host",
      "Only local logon events",
      "Decreased DNS queries",
      "No network connections",
    ],
    correctAnswer: 0,
    explanation: "Internal scanning through a pivot suggests SOCKS usage.",
  },
  {
    id: 44,
    topic: "Networking",
    question: "Why are internal DNS names useful for pivoting?",
    options: [
      "They help resolve internal resources once inside",
      "They disable authentication",
      "They are required for internet access",
      "They prevent logging",
    ],
    correctAnswer: 0,
    explanation: "Internal DNS resolution helps target internal services.",
  },
  {
    id: 45,
    topic: "Pivoting",
    question: "What is double pivoting?",
    options: [
      "Pivoting through multiple intermediate hosts",
      "Running two scanners at once",
      "Using two DNS servers",
      "Disabling two firewalls",
    ],
    correctAnswer: 0,
    explanation: "Double pivoting chains multiple pivots to reach deeper networks.",
  },
  {
    id: 46,
    topic: "Pivoting",
    question: "Why might attackers use reverse tunnels?",
    options: [
      "To access a local service from an external host",
      "To disable TLS",
      "To avoid authentication",
      "To prevent logging",
    ],
    correctAnswer: 0,
    explanation: "Reverse tunnels expose internal services externally.",
  },
  {
    id: 47,
    topic: "Tools",
    question: "Which tool can create SSH-based SOCKS proxies on Linux?",
    options: [
      "OpenSSH",
      "Task Scheduler",
      "PowerShell",
      "IIS",
    ],
    correctAnswer: 0,
    explanation: "OpenSSH supports dynamic SOCKS forwarding.",
  },
  {
    id: 48,
    topic: "Tools",
    question: "Why use `-C` with SSH?",
    options: [
      "To enable compression over the tunnel",
      "To disable encryption",
      "To force a TTY",
      "To reset keys",
    ],
    correctAnswer: 0,
    explanation: "Compression can reduce bandwidth usage for tunnels.",
  },
  {
    id: 49,
    topic: "Detection",
    question: "Why is traffic to uncommon cloud storage endpoints suspicious?",
    options: [
      "They can be used as exfil or tunnel relays",
      "They are always required for Windows updates",
      "They are part of DNS resolution",
      "They replace endpoint detection",
    ],
    correctAnswer: 0,
    explanation: "Unusual cloud endpoints can indicate covert channels.",
  },
  {
    id: 50,
    topic: "Detection",
    question: "Why compare user behavior to baseline activity?",
    options: [
      "Pivoting often deviates from normal access patterns",
      "Baselines disable alerts",
      "Baselines remove need for logs",
      "Baselines prevent port scans",
    ],
    correctAnswer: 0,
    explanation: "Baselines help identify anomalies.",
  },
  {
    id: 51,
    topic: "Defense",
    question: "Why restrict inbound RDP to jump hosts?",
    options: [
      "It limits exposure and simplifies monitoring",
      "It disables firewall rules",
      "It prevents logging",
      "It increases bandwidth",
    ],
    correctAnswer: 0,
    explanation: "Limiting RDP reduces attack surface and improves oversight.",
  },
  {
    id: 52,
    topic: "Defense",
    question: "Why use separate admin accounts for administration?",
    options: [
      "It reduces credential reuse across systems",
      "It removes the need for MFA",
      "It disables network segmentation",
      "It improves internet speed",
    ],
    correctAnswer: 0,
    explanation: "Separate accounts reduce the impact of a compromised credential.",
  },
  {
    id: 53,
    topic: "Defense",
    question: "Why monitor for new routes or network adapters?",
    options: [
      "Tunneling tools may create virtual interfaces",
      "They are always created by updates",
      "They only appear on laptops",
      "They indicate hardware failure",
    ],
    correctAnswer: 0,
    explanation: "Virtual adapters can be used for tunnels or VPNs.",
  },
  {
    id: 54,
    topic: "Defense",
    question: "What is an effective response to suspected tunneling?",
    options: [
      "Contain the host and inspect active connections",
      "Ignore and wait for alerts to clear",
      "Disable all logging",
      "Reboot without investigation",
    ],
    correctAnswer: 0,
    explanation: "Containment and inspection are key for verifying tunnels.",
  },
  {
    id: 55,
    topic: "Detection",
    question: "What is a typical sign of SSH tunneling?",
    options: [
      "SSH connections with port forwarding options",
      "Only local logons",
      "Short-lived DNS queries",
      "No TCP traffic",
    ],
    correctAnswer: 0,
    explanation: "SSH forwarding options indicate tunneling.",
  },
  {
    id: 56,
    topic: "Tools",
    question: "Which tool is often used for TCP relays in pivot chains?",
    options: [
      "socat",
      "whoami",
      "hostname",
      "ipconfig",
    ],
    correctAnswer: 0,
    explanation: "socat provides flexible TCP relay capabilities.",
  },
  {
    id: 57,
    topic: "Networking",
    question: "Why is DNS tunneling slower than HTTP tunneling?",
    options: [
      "DNS limits payload size and throughput",
      "DNS is always encrypted",
      "DNS does not support queries",
      "DNS uses TCP only",
    ],
    correctAnswer: 0,
    explanation: "DNS has small payload limits and higher overhead.",
  },
  {
    id: 58,
    topic: "Networking",
    question: "Which protocol is commonly allowed through egress filters?",
    options: [
      "HTTPS",
      "SMB",
      "RDP",
      "Telnet",
    ],
    correctAnswer: 0,
    explanation: "HTTPS is commonly allowed, making it a common tunnel target.",
  },
  {
    id: 59,
    topic: "Detection",
    question: "Why inspect proxy logs for authentication anomalies?",
    options: [
      "Tunnels may authenticate from unusual hosts or accounts",
      "Proxy logs are not useful for security",
      "Authentication is never logged",
      "Proxies only see DNS",
    ],
    correctAnswer: 0,
    explanation: "Unexpected proxy auth can indicate tunnel use.",
  },
  {
    id: 60,
    topic: "Basics",
    question: "Pivoting is most associated with which phase of an intrusion?",
    options: [
      "Lateral movement",
      "Initial reconnaissance only",
      "Post-incident recovery",
      "Patch management",
    ],
    correctAnswer: 0,
    explanation: "Pivoting expands access inside the environment.",
  },
  {
    id: 61,
    topic: "Defense",
    question: "Why monitor for port forwarding processes?",
    options: [
      "They may indicate unauthorized tunnels",
      "They improve patching",
      "They stop credential theft",
      "They eliminate malware",
    ],
    correctAnswer: 0,
    explanation: "Port forwarding processes are common in tunneling.",
  },
  {
    id: 62,
    topic: "Defense",
    question: "Why enforce MFA on jump hosts?",
    options: [
      "It reduces credential reuse and theft impact",
      "It disables logging",
      "It blocks network segmentation",
      "It removes the need for backups",
    ],
    correctAnswer: 0,
    explanation: "MFA adds a strong barrier for admin access.",
  },
  {
    id: 63,
    topic: "Detection",
    question: "What is a useful indicator for pivoting in endpoint logs?",
    options: [
      "Unusual remote access tools launched by non-admin users",
      "Normal user logons",
      "Standard update processes",
      "Regular browser activity",
    ],
    correctAnswer: 0,
    explanation: "Unexpected remote tools can suggest pivoting attempts.",
  },
  {
    id: 64,
    topic: "Basics",
    question: "Why is pivoting often required in segmented networks?",
    options: [
      "Direct access to all subnets is not allowed",
      "All hosts are publicly reachable",
      "Segmentation disables routing",
      "Segmentation removes all firewalls",
    ],
    correctAnswer: 0,
    explanation: "Segmentation limits direct reach, requiring pivots.",
  },
  {
    id: 65,
    topic: "Tools",
    question: "Why might attackers prefer HTTPS tunnels?",
    options: [
      "HTTPS blends with normal web traffic",
      "HTTPS is always blocked by egress filters",
      "HTTPS is faster than all other protocols",
      "HTTPS disables authentication",
    ],
    correctAnswer: 0,
    explanation: "HTTPS traffic is common and often allowed.",
  },
  {
    id: 66,
    topic: "Defense",
    question: "Why disable unused services on servers?",
    options: [
      "It reduces available pivoting paths",
      "It increases outbound bandwidth",
      "It prevents logging",
      "It forces password reuse",
    ],
    correctAnswer: 0,
    explanation: "Fewer services means fewer lateral movement options.",
  },
  {
    id: 67,
    topic: "Detection",
    question: "What might indicate a new tunnel setup on a host?",
    options: [
      "New local listeners and unusual outbound sessions",
      "Only logons at noon",
      "No process creation events",
      "No network traffic",
    ],
    correctAnswer: 0,
    explanation: "New listeners and outbound sessions can signal tunneling.",
  },
  {
    id: 68,
    topic: "Defense",
    question: "Why is asset inventory important for pivot detection?",
    options: [
      "It clarifies which tools and ports are expected",
      "It disables all alerts",
      "It prevents patches",
      "It removes all logs",
    ],
    correctAnswer: 0,
    explanation: "Inventory helps identify abnormal tooling or ports.",
  },
  {
    id: 69,
    topic: "Detection",
    question: "Why inspect outbound traffic for high entropy data?",
    options: [
      "It may indicate tunneling or encoded payloads",
      "It indicates normal backups",
      "It indicates DNS misconfiguration",
      "It indicates firewall updates",
    ],
    correctAnswer: 0,
    explanation: "High entropy data can be a sign of tunneling or exfiltration.",
  },
  {
    id: 70,
    topic: "Defense",
    question: "Which control reduces unauthorized tunneling?",
    options: [
      "Least privilege and strict egress rules",
      "Disabling all authentication",
      "Allowing all outbound ports",
      "Removing endpoint monitoring",
    ],
    correctAnswer: 0,
    explanation: "Least privilege and egress rules limit tunnel setup.",
  },
  {
    id: 71,
    topic: "Basics",
    question: "A tunnel is typically created to:",
    options: [
      "Bypass network restrictions or segmentation",
      "Increase disk performance",
      "Change user passwords",
      "Disable antivirus",
    ],
    correctAnswer: 0,
    explanation: "Tunnels bypass restrictions and allow access to other systems.",
  },
  {
    id: 72,
    topic: "Tools",
    question: "Why use `ssh -J`?",
    options: [
      "To connect through a jump host",
      "To enable compression only",
      "To disable key checking",
      "To reset host keys",
    ],
    correctAnswer: 0,
    explanation: "ssh -J specifies a jump host for proxying connections.",
  },
  {
    id: 73,
    topic: "Detection",
    question: "What is a common sign of DNS tunneling?",
    options: [
      "High volume of long, random-looking subdomains",
      "Only HTTP traffic",
      "No DNS queries",
      "Only ICMP traffic",
    ],
    correctAnswer: 0,
    explanation: "DNS tunneling often uses long or high-entropy subdomains.",
  },
  {
    id: 74,
    topic: "Defense",
    question: "Why inspect process command lines for tunneling tools?",
    options: [
      "Command lines reveal forwarding parameters and endpoints",
      "Command lines are always empty",
      "Command lines prevent logging",
      "Command lines only show file names",
    ],
    correctAnswer: 0,
    explanation: "Command-line arguments show tunnel configuration details.",
  },
  {
    id: 75,
    topic: "Basics",
    question: "Which statement best summarizes pivoting?",
    options: [
      "Using one compromised system to access others",
      "Encrypting files at rest",
      "Updating firewall firmware",
      "Resetting user passwords",
    ],
    correctAnswer: 0,
    explanation: "Pivoting expands access beyond the initial foothold.",
  },
];

const PivotingTunnelingPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const objectives = [
    "Explain pivoting and tunneling in plain language.",
    "Identify common use cases and risks.",
    "Understand where tunnels show up in telemetry.",
    "Review safe detection and hardening ideas.",
    "Practice a safe, lab-only walkthrough.",
  ];

  const beginnerPath = [
    "1) Read the glossary and simple definitions.",
    "2) Learn the difference between pivoting and tunneling.",
    "3) Review common signals and safe checks.",
    "4) Study defenses and segmentation guidance.",
    "5) Complete the lab walkthrough in an isolated network.",
  ];
  const whatItIsNot = [
    "It is not an offensive how-to for bypassing controls.",
    "It is not about running tunnels on production networks.",
    "It is focused on detection and defensive awareness.",
  ];
  const whyItMatters = [
    "Pivoting can bypass perimeter defenses by using internal hosts.",
    "Tunneling can hide traffic inside allowed protocols.",
    "Both techniques can blur the true source of activity.",
  ];

  const glossary = [
    { term: "Pivoting", desc: "Using one system to reach another network segment." },
    { term: "Tunneling", desc: "Encapsulating traffic inside another protocol." },
    { term: "Relay", desc: "Forwarding traffic through an intermediate host." },
    { term: "Proxy", desc: "A service that forwards traffic on your behalf." },
    { term: "Jump host", desc: "A controlled system used to access internal networks." },
  ];
  const pivotTypes = [
    { type: "Network pivot", desc: "Use a host as a gateway to another subnet." },
    { type: "Application pivot", desc: "Use an app proxy to reach internal services." },
    { type: "Account pivot", desc: "Use stolen credentials to access new systems." },
  ];

  const simpleDefinitions = [
    "Pivoting is like using one hallway to reach rooms you could not access directly.",
    "Tunneling is like hiding one conversation inside another to pass through filters.",
  ];

  const misconceptions = [
    {
      myth: "Tunnels are always malicious.",
      reality: "Legitimate admins use VPNs and proxies for remote access.",
    },
    {
      myth: "If a tunnel is encrypted, it is safe.",
      reality: "Encryption can also hide malicious traffic from inspection.",
    },
    {
      myth: "Blocking a single port stops all tunneling.",
      reality: "Tunnels can use many protocols and ports.",
    },
  ];
  const impactExamples = [
    "Internal databases reachable from a compromised workstation.",
    "Sensitive services exposed through a misconfigured jump host.",
    "Hidden C2 traffic inside allowed web traffic.",
  ];

  const commonUseCases = [
    {
      title: "Legitimate remote access",
      desc: "Admins use jump hosts or VPNs to reach internal systems.",
      risk: "If misconfigured, it can expose internal networks.",
    },
    {
      title: "Incident response",
      desc: "Secure access to affected hosts for analysis and containment.",
      risk: "Ensure strong auth and logging are enabled.",
    },
    {
      title: "Malicious lateral movement",
      desc: "Attackers pivot through a compromised host to reach deeper assets.",
      risk: "Bypasses perimeter controls and obscures source IPs.",
    },
  ];

  const techniquesHighLevel = [
    { name: "Port forwarding", idea: "Forward traffic from one port to another." },
    { name: "Proxy chains", idea: "Route traffic through one or more proxies." },
    { name: "VPN tunnels", idea: "Create encrypted connections to internal networks." },
    { name: "HTTP(S) tunnels", idea: "Encapsulate traffic inside web protocols." },
    { name: "DNS tunnels", idea: "Encode traffic inside DNS queries." },
  ];
  const techniqueRisks = [
    { technique: "Port forwarding", visibility: "Internal connections appear from pivot host.", risk: "Bypasses network segmentation rules." },
    { technique: "Proxy chains", visibility: "Multiple hops and altered source context.", risk: "Obscures origin and attribution." },
    { technique: "VPN tunnels", visibility: "New tunnel interfaces and long-lived sessions.", risk: "Expands access scope if misconfigured." },
    { technique: "HTTP(S) tunnels", visibility: "Unusual payload sizes and persistent sessions.", risk: "Blends with allowed web traffic." },
    { technique: "DNS tunnels", visibility: "High query volume and long subdomains.", risk: "Exfiltration over DNS paths." },
  ];
  const attckMapping = [
    { tactic: "Lateral Movement", technique: "T1021", example: "Remote services via a pivot host." },
    { tactic: "Command and Control", technique: "T1071", example: "Tunneling over web protocols." },
    { tactic: "Exfiltration", technique: "T1041", example: "Data over C2 channel or tunnel." },
    { tactic: "Defense Evasion", technique: "T1573", example: "Encrypted channels to hide traffic." },
  ];
  const detectionMatrix = [
    {
      stage: "Access",
      signal: "New host talking to sensitive services.",
      evidence: "Netflow logs and firewall rules.",
    },
    {
      stage: "Tunnel setup",
      signal: "Long-lived connections with steady traffic.",
      evidence: "Proxy logs and endpoint process data.",
    },
    {
      stage: "Pivot usage",
      signal: "Traffic to internal networks from user endpoints.",
      evidence: "Internal routing logs and EDR alerts.",
    },
  ];
  const investigationChecklist = [
    "Identify the first host that initiated the tunnel.",
    "Confirm user account and authentication method.",
    "Validate the destination segment and asset criticality.",
    "Check for other endpoints with similar patterns.",
    "Correlate DNS, proxy, and EDR timeline.",
  ];
  const baselineQuestions = [
    "Is this host a known jump box or admin workstation?",
    "Is this traffic normal for this role or team?",
    "Has this destination been seen before?",
    "Are there approved maintenance windows?",
    "Is there a matching change ticket?",
  ];
  const reportingChecklist = [
    "Summarize pivot path and affected segments.",
    "Document all evidence sources and timestamps.",
    "List impacted assets and business owners.",
    "State containment actions and approvals.",
    "Recommend control improvements.",
  ];

  const signals = [
    "Internal traffic originating from a non-standard host.",
    "Unexpected connections between segments or VLANs.",
    "Long-lived connections with steady outbound traffic.",
    "High DNS query volume or unusual query sizes.",
    "New proxy services listening on endpoints.",
  ];
  const behaviorSignals = [
    "High DNS query volume with long subdomains.",
    "Unusual HTTP methods or large POST bodies to rare hosts.",
    "Persistent outbound connections over uncommon ports.",
    "Internal scans originating from user devices.",
  ];

  const telemetry = [
    "Firewall and proxy logs (source, destination, bytes).",
    "Netflow or Zeek logs for lateral movement.",
    "Endpoint process and listening port inventory.",
    "DNS logs and query size anomalies.",
    "VPN and remote access logs.",
  ];
  const telemetryCoverage = [
    { area: "Endpoint", detail: "Process, service, and socket telemetry." },
    { area: "Network", detail: "Flow logs, IDS, and internal routing." },
    { area: "DNS", detail: "Query length, volume, and NXDOMAIN rates." },
    { area: "Proxy", detail: "User agents, methods, and session duration." },
    { area: "Auth", detail: "VPN, SSO, and jump host logins." },
  ];
  const logSources = [
    { source: "Firewall", detail: "Cross-segment traffic and new destinations." },
    { source: "Proxy", detail: "Long-lived HTTP/S sessions and large payloads." },
    { source: "DNS", detail: "Query volume, length, and NXDOMAIN spikes." },
    { source: "EDR", detail: "New listeners and unusual parent processes." },
  ];
  const detectionPitfalls = [
    "Treating all tunnels as malicious and flagging legitimate VPN use.",
    "Missing lateral movement because logs lack east-west visibility.",
    "Ignoring time alignment issues across data sources.",
    "Focusing on ports only and missing protocol-based tunneling.",
    "Not correlating host process data with network flows.",
  ];
  const tuningIdeas = [
    "Baseline normal proxy and VPN usage by team.",
    "Alert on first-time cross-segment access patterns.",
    "Flag new listening services on user endpoints.",
    "Enrich flows with asset criticality and owner tags.",
    "Track DNS query length distributions by host.",
  ];

  const defenses = [
    "Use segmentation and restrict east-west traffic.",
    "Require MFA for remote access and jump hosts.",
    "Limit admin tools to approved hosts.",
    "Monitor for new listening services on endpoints.",
    "Block unauthorized DNS or HTTP tunneling tools.",
  ];
  const hardeningChecklist = [
    "Require MFA for VPN and jump hosts.",
    "Restrict local admin rights on endpoints.",
    "Disable unused services and unused ports.",
    "Apply egress filtering and allowlists.",
    "Monitor for new listening services on endpoints.",
  ];
  const policyGuidance = [
    "Document approved jump hosts and proxy services.",
    "Enforce least-privilege routes between segments.",
    "Separate admin access from user browsing paths.",
    "Apply strict egress rules for sensitive segments.",
    "Review tunnel approvals on a fixed cadence.",
  ];

  const segmentationGuidance = [
    "Separate user, server, and admin networks.",
    "Use allowlists for inter-segment access.",
    "Restrict management ports to jump hosts only.",
    "Log and review all cross-segment connections.",
  ];
  const responseSteps = [
    "Identify the pivot host and isolate it if needed.",
    "Capture logs and process trees for evidence.",
    "Review firewall rules and remove unauthorized routes.",
    "Reset exposed credentials and rotate tokens.",
    "Document the timeline and update detections.",
  ];
  const responseChecklist = [
    "Confirm scope and impacted segments.",
    "Validate indicators with at least two sources.",
    "Coordinate containment with system owners.",
    "Preserve evidence before remediation.",
    "Add or tune detections after closure.",
  ];

  const evidenceChecklist = [
    "Source and destination IPs and ports",
    "Process name and parent process on the pivot host",
    "Bytes transferred and connection duration",
    "DNS query patterns or anomalies",
    "Authentication context and user account",
  ];
  const labArtifacts = [
    "Baseline network map and allowed paths",
    "Sample log entries showing normal traffic",
    "List of approved remote access tools",
    "Screenshots of detection dashboards",
    "Final report with findings and recommendations",
  ];
  const reportTemplate = `Host: <pivot host>
Date: <utc>
Observed signal: <what was seen>
Source/Destination: <IPs/ports>
Process: <name and parent>
Evidence: <logs, screenshots>
Risk: <impact>
Recommendation: <block, monitor, segment>`;

  const safeChecks = `# Windows: list listening ports
netstat -ano | findstr LISTENING

# Windows: active connections
netstat -ano | findstr ESTABLISHED

# Linux: listening ports
ss -lntp

# Linux: active connections
ss -ntp

# macOS: active connections
netstat -anv | head -n 20`;

  const labSteps = [
    "Use an isolated lab with two small networks.",
    "Map which systems can talk to each other (baseline).",
    "Create a diagram of allowed paths and blocked paths.",
    "Observe connections and log normal traffic.",
    "Write a report describing what would be suspicious.",
  ];

  const safeBoundaries = [
    "Do not set up tunnels on real networks without approval.",
    "Avoid tools or steps that bypass security controls.",
    "Keep the lab isolated and use test data only.",
    "Document findings rather than attempting exploitation.",
  ];

  const pageContext = `This page covers network pivoting and tunneling techniques, including port forwarding, proxy chains, VPN tunnels, HTTP/DNS tunnels, detection signals, and defensive controls. Topics include lateral movement, traffic routing through compromised hosts, ATT&CK mapping, detection pitfalls, tuning ideas, response checklists, and network segmentation.`;

  return (
    <LearnPageLayout pageTitle="Pivoting and Tunneling" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
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
          <RouteIcon sx={{ fontSize: 42, color: "#3b82f6" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #3b82f6 0%, #60a5fa 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Pivoting and Tunneling
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Pivoting and tunneling describe ways traffic is routed through other systems or hidden inside other protocols.
        </Typography>
        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            In simple terms, pivoting is using one computer to reach another network you could not reach directly.
            Tunneling is wrapping one kind of traffic inside another to pass through filters. Both can be used for
            legitimate administration or abused by attackers. This page focuses on understanding the concepts,
            spotting warning signs, and building safer defenses.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
            Think of pivoting like using a secure door to access a hallway behind it. Tunneling is like hiding a
            smaller package inside a larger, allowed shipment. Knowing the patterns helps you detect misuse.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            Everything here is beginner-friendly and defensive. Use safe checks and lab-only exercises.
          </Typography>
        </Paper>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<HubIcon />} label="Pivoting" size="small" />
          <Chip icon={<RouteIcon />} label="Tunneling" size="small" />
          <Chip icon={<SecurityIcon />} label="Detection" size="small" />
          <Chip icon={<ShieldIcon />} label="Defenses" size="small" />
          <Chip icon={<WarningIcon />} label="Risk Signals" size="small" />
        </Box>

        <Paper sx={{ bgcolor: "#111424", borderRadius: 2 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              "& .MuiTab-root": { color: "grey.400" },
              "& .Mui-selected": { color: "#3b82f6" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<HubIcon />} label="Concepts" />
            <Tab icon={<RouteIcon />} label="Techniques" />
            <Tab icon={<SearchIcon />} label="Detection" />
            <Tab icon={<ShieldIcon />} label="Defenses" />
            <Tab icon={<WarningIcon />} label="Beginner Lab" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Learning Objectives
                </Typography>
                <List dense>
                  {objectives.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Beginner Path
                </Typography>
                <List dense>
                  {beginnerPath.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  What This Is Not
                </Typography>
                <List dense>
                  {whatItIsNot.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Term</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Meaning</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {glossary.map((item) => (
                        <TableRow key={item.term}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.term}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Simple Definitions
                </Typography>
                <List dense>
                  {simpleDefinitions.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Why It Matters
                </Typography>
                <List dense>
                  {whyItMatters.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Pivot Types
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Type</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {pivotTypes.map((item) => (
                        <TableRow key={item.type}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Impact Examples
                </Typography>
                <List dense>
                  {impactExamples.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Common Misconceptions
                </Typography>
                <Grid container spacing={2}>
                  {misconceptions.map((item) => (
                    <Grid item xs={12} md={4} key={item.myth}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(59,130,246,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>
                          Myth
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                          {item.myth}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ color: "#a5b4fc", mb: 0.5 }}>
                          Reality
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>
                          {item.reality}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                Pivoting uses a host you already control to reach internal assets. Tunneling hides traffic inside
                a different protocol to pass through network restrictions.
              </Typography>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Common Use Cases
                </Typography>
                <Grid container spacing={2}>
                  {commonUseCases.map((item) => (
                    <Grid item xs={12} md={4} key={item.title}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(59,130,246,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 600 }}>
                          {item.title}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                          {item.desc}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "#94a3b8" }}>
                          Risk: {item.risk}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Policy and Context
                </Typography>
                <List dense>
                  {policyGuidance.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Technique Risk and Visibility
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#3b82f6" }}>Technique</TableCell>
                        <TableCell sx={{ color: "#3b82f6" }}>Visibility</TableCell>
                        <TableCell sx={{ color: "#3b82f6" }}>Risk</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {techniqueRisks.map((item) => (
                        <TableRow key={item.technique}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.technique}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.visibility}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  ATT&CK Mapping (High-Level)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Tactic</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Technique</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Example</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {attckMapping.map((item) => (
                        <TableRow key={item.technique}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.tactic}</TableCell>
                          <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>{item.technique}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.example}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#3b82f6" }}>Technique</TableCell>
                      <TableCell sx={{ color: "#3b82f6" }}>High-level idea</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {techniquesHighLevel.map((item) => (
                      <TableRow key={item.name}>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.name}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.idea}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Baseline Questions
                </Typography>
                <List dense>
                  {baselineQuestions.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Detection Signals
                </Typography>
                <List dense>
                  {signals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Detection Pitfalls
                </Typography>
                <List dense>
                  {detectionPitfalls.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon sx={{ color: "#f59e0b" }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Tuning Ideas
                </Typography>
                <List dense>
                  {tuningIdeas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Behavior Signals
                </Typography>
                <List dense>
                  {behaviorSignals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Telemetry Sources
                </Typography>
                <List dense>
                  {telemetry.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Telemetry Coverage Map
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Area</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>What it tells you</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {telemetryCoverage.map((item) => (
                        <TableRow key={item.area}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.area}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.detail}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Log Sources (Examples)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Source</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>What to look for</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {logSources.map((item) => (
                        <TableRow key={item.source}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.source}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.detail}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Detection Matrix (Simple)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Stage</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Signal</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Evidence</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {detectionMatrix.map((item) => (
                        <TableRow key={item.stage}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.stage}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.signal}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.evidence}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Evidence Checklist
                </Typography>
                <List dense>
                  {evidenceChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Investigation Checklist
                </Typography>
                <List dense>
                  {investigationChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Read-only Checks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={safeChecks} language="bash" />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Defensive Controls
                </Typography>
                <List dense>
                  {defenses.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Hardening Checklist
                </Typography>
                <List dense>
                  {hardeningChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Segmentation Guidance
                </Typography>
                <List dense>
                  {segmentationGuidance.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Response Steps
                </Typography>
                <List dense>
                  {responseSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Response Checklist
                </Typography>
                <List dense>
                  {responseChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Reporting Checklist
                </Typography>
                <List dense>
                  {reportingChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Beginner Lab Walkthrough (Safe)
                </Typography>
                <List dense>
                  {labSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Lab Evidence to Collect
                </Typography>
                <List dense>
                  {labArtifacts.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Report Template
                </Typography>
                <CodeBlock code={reportTemplate} language="text" />
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Safe Boundaries
                </Typography>
                <List dense>
                  {safeBoundaries.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>
        </Paper>

        <Paper
          id="quiz-section"
          sx={{
            mt: 4,
            p: 4,
            borderRadius: 3,
            border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
            Knowledge Check
          </Typography>
          <QuizSection
            questions={quizQuestions}
            accentColor={QUIZ_ACCENT_COLOR}
            title="Pivoting and Tunneling Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#3b82f6", color: "#3b82f6" }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default PivotingTunnelingPage;
