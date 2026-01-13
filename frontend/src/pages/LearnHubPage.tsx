import { useState, useMemo, useEffect, useRef, useCallback } from "react";
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
  CardActionArea,
  Chip,
  Divider,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Collapse,
  IconButton,
  Tooltip,
  Badge,
  TextField,
  InputAdornment,
  Fab,
  Zoom,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Drawer,
  useMediaQuery,
  ClickAwayListener,
  Popper,
  Fade,
} from "@mui/material";
import { useNavigate } from "react-router-dom";
import ClearIcon from "@mui/icons-material/Clear";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import KeyboardIcon from "@mui/icons-material/Keyboard";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import ArrowForwardIcon from "@mui/icons-material/ArrowForward";
import LearnPageLayout from "../components/LearnPageLayout";
import SchoolIcon from "@mui/icons-material/School";
import SecurityIcon from "@mui/icons-material/Security";
import PsychologyIcon from "@mui/icons-material/Psychology";
import LinkIcon from "@mui/icons-material/Link";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import WarningIcon from "@mui/icons-material/Warning";
import BugReportIcon from "@mui/icons-material/BugReport";
import TerminalIcon from "@mui/icons-material/Terminal";
import CodeIcon from "@mui/icons-material/Code";
import PhoneAndroidIcon from "@mui/icons-material/PhoneAndroid";
import PhoneIphoneIcon from "@mui/icons-material/PhoneIphone";
import LockIcon from "@mui/icons-material/Lock";
import FolderSpecialIcon from "@mui/icons-material/FolderSpecial";
import RadarIcon from "@mui/icons-material/Radar";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import SearchIcon from "@mui/icons-material/Search";
import ApiIcon from "@mui/icons-material/Api";
import MemoryIcon from "@mui/icons-material/Memory";
import HubIcon from "@mui/icons-material/Hub";
import WifiIcon from "@mui/icons-material/Wifi";
import DnsIcon from "@mui/icons-material/Dns";
import RouteIcon from "@mui/icons-material/Route";
import TravelExploreIcon from "@mui/icons-material/TravelExplore";
import AndroidIcon from "@mui/icons-material/Android";
import BuildIcon from "@mui/icons-material/Build";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import LayersIcon from "@mui/icons-material/Layers";
import WorkspacePremiumIcon from "@mui/icons-material/WorkspacePremium";
import CloudIcon from "@mui/icons-material/Cloud";
import CloudOffIcon from "@mui/icons-material/CloudOff";
import ShieldIcon from "@mui/icons-material/Shield";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import SettingsRemoteIcon from "@mui/icons-material/SettingsRemote";
import RouterIcon from "@mui/icons-material/Router";
import StorageIcon from "@mui/icons-material/Storage";
import SupportAgentIcon from "@mui/icons-material/SupportAgent";
import FilterListIcon from "@mui/icons-material/FilterList";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import VisibilityIcon from "@mui/icons-material/Visibility";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import LocalPoliceIcon from "@mui/icons-material/LocalPolice";
import LanguageIcon from "@mui/icons-material/Language";
import ScienceIcon from "@mui/icons-material/Science";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import ComputerIcon from "@mui/icons-material/Computer";
import DesktopWindowsIcon from "@mui/icons-material/DesktopWindows";
import WebIcon from "@mui/icons-material/Web";
import LocalCafeIcon from "@mui/icons-material/LocalCafe";
import SpeedIcon from "@mui/icons-material/Speed";
import DataObjectIcon from "@mui/icons-material/DataObject";
import SettingsIcon from "@mui/icons-material/Settings";
import AppleIcon from "@mui/icons-material/Apple";
import ViewInArIcon from "@mui/icons-material/ViewInAr";
import IntegrationInstructionsIcon from "@mui/icons-material/IntegrationInstructions";
import AnalyticsIcon from "@mui/icons-material/Analytics";

interface LearnCard {
  title: string;
  description: string;
  icon: React.ReactNode;
  path: string;
  color: string;
  tags: string[];
  badge?: string;
}

interface CategorySection {
  id: string;
  title: string;
  emoji: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  gradientEnd: string;
  cards: LearnCard[];
}

// ========== CATEGORY: About VRAgent ==========
const appCards: LearnCard[] = [
  {
    title: "Security Scan & AI Analysis Guide",
    description: "Complete guide to VRAgent's 10-phase scanning pipeline, 11 SAST scanners, and AI-powered analysis with Agentic corroboration, attack chains, and exploit scenarios.",
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    path: "/learn/scanning",
    color: "#3b82f6",
    tags: ["SAST", "Gemini AI", "Agentic", "Multi-Pass"],
    badge: "Start Here",
  },
  {
    title: "VRAgent Architecture",
    description: "Deep dive into Docker services, backend architecture, data models, and the scan pipeline.",
    icon: <AccountTreeIcon sx={{ fontSize: 40 }} />,
    path: "/learn/architecture",
    color: "#6366f1",
    tags: ["Docker", "FastAPI", "PostgreSQL"],
  },
  {
    title: "Network Analysis Hub Guide",
    description: "Learn what the Network Analysis Hub does: 10 tools including Nmap, PCAP, SSL, DNS, Traceroute, API Tester, Security Fuzzer, Agentic Fuzzer, Binary Fuzzer, and MITM.",
    icon: <HubIcon sx={{ fontSize: 40 }} />,
    path: "/learn/network-hub",
    color: "#0ea5e9",
    tags: ["Nmap", "PCAP", "API Tester", "Fuzzing"],
  },
  {
    title: "Wireshark PCAP Guide",
    description: "VRAgent's PCAP Analyzer: packet capture analysis, display filters, protocol dissection, and security findings.",
    icon: <WifiIcon sx={{ fontSize: 40 }} />,
    path: "/learn/wireshark",
    color: "#06b6d4",
    tags: ["Filters", "BPF", "Packets"],
  },
  {
    title: "Nmap Scanner Guide",
    description: "VRAgent's Nmap integration: port scanning, service detection, NSE scripts, and vulnerability discovery.",
    icon: <RadarIcon sx={{ fontSize: 40 }} />,
    path: "/learn/nmap",
    color: "#8b5cf6",
    tags: ["Port Scanning", "NSE", "Discovery"],
  },
  {
    title: "SSL/TLS Scanner Guide",
    description: "VRAgent's SSL Scanner: 12 CVE checks, certificate chain validation, cipher analysis, and AI exploitation paths.",
    icon: <LockIcon sx={{ fontSize: 40 }} />,
    path: "/learn/ssl-tls",
    color: "#10b981",
    tags: ["Certificates", "Vulnerabilities", "Ciphers"],
  },
  {
    title: "DNS Analyzer Guide",
    description: "VRAgent's DNS tool: enumeration, subdomain discovery, zone transfers, and email security analysis (SPF, DMARC, DKIM).",
    icon: <DnsIcon sx={{ fontSize: 40 }} />,
    path: "/learn/dns",
    color: "#f59e0b",
    tags: ["DNS", "Subdomains", "Email Security"],
  },
  {
    title: "Traceroute Analyzer Guide",
    description: "VRAgent's Traceroute: network path analysis, hop-by-hop diagnostics, latency interpretation, and visualization.",
    icon: <RouteIcon sx={{ fontSize: 40 }} />,
    path: "/learn/traceroute",
    color: "#ec4899",
    tags: ["Path Analysis", "Latency", "Visualization"],
  },
  {
    title: "API Endpoint Tester Guide",
    description: "VRAgent's API Tester: AI Auto-Test with CIDR scanning, JWT/WebSocket testing, batch operations, and multi-format exports.",
    icon: <ApiIcon sx={{ fontSize: 40 }} />,
    path: "/learn/api-testing",
    color: "#22c55e",
    tags: ["CIDR Scanning", "JWT", "WebSocket"],
  },
  {
    title: "Fuzzing Tools Guide",
    description: "Master all VRAgent fuzzers: Security Fuzzer, Agentic Fuzzer & Binary Fuzzer with Smart Detection.",
    icon: <RadarIcon sx={{ fontSize: 40 }} />,
    path: "/learn/fuzzing-tool",
    color: "#f97316",
    tags: ["Security Fuzzer", "Agentic Fuzzer", "Binary Fuzzer"],
  },
  {
    title: "MITM Workbench Guide",
    description: "VRAgent's MITM Proxy: traffic interception, AI-powered rule creation, request modification, and security testing.",
    icon: <HubIcon sx={{ fontSize: 40 }} />,
    path: "/learn/mitm",
    color: "#ef4444",
    tags: ["Proxy", "Interception", "AI Rules"],
  },
  {
    title: "Reverse Engineering Hub Guide",
    description: "VRAgent's RE Hub: APK analysis, binary inspection, Docker Inspector, and AI-powered insights.",
    icon: <BuildIcon sx={{ fontSize: 40 }} />,
    path: "/learn/reverse-engineering",
    color: "#a855f7",
    tags: ["APK", "Binary", "Docker"],
  },
  {
    title: "APK Analysis Guide",
    description: "VRAgent's APK Analyzer: permissions, certificates, manifest parsing, attack surface mapping, and obfuscation detection.",
    icon: <AndroidIcon sx={{ fontSize: 40 }} />,
    path: "/learn/apk-analysis",
    color: "#22c55e",
    tags: ["Android", "Permissions", "Security"],
  },
  {
    title: "Binary Analysis Guide",
    description: "VRAgent's Binary Analyzer: PE/ELF inspection, strings extraction, import analysis, Rich headers, and disassembly.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/binary-analysis",
    color: "#f59e0b",
    tags: ["PE", "ELF", "Disassembly"],
  },
  {
    title: "Docker Inspector Guide",
    description: "VRAgent's Docker Inspector: layer inventory, secrets detection, attack vectors, and AI security analysis.",
    icon: <LayersIcon sx={{ fontSize: 40 }} />,
    path: "/learn/docker-forensics",
    color: "#0ea5e9",
    tags: ["Layers", "Secrets", "Risk"],
  },
  {
    title: "Combined Analysis Guide",
    description: "Merge security scans, network reports, RE findings, and fuzzing sessions into one AI-powered report with 9 specialized agents.",
    icon: <AnalyticsIcon sx={{ fontSize: 40 }} />,
    path: "/learn/combined-analysis",
    color: "#8b5cf6",
    tags: ["AI Report", "Cross-Correlation", "9 Agents"],
  },
];

// ========== CATEGORY: IT Fundamentals ==========
const itFundamentalsCards: LearnCard[] = [
  {
    title: "Windows Fundamentals",
    description: "Comprehensive guide to Windows: file system, registry, services, users & permissions, command line, boot process, and essential tools.",
    icon: <DesktopWindowsIcon sx={{ fontSize: 40 }} />,
    path: "/learn/windows-basics",
    color: "#0078d4",
    tags: ["Windows", "NTFS", "Registry", "PowerShell"],
    badge: "New",
  },
  {
    title: "Linux Fundamentals",
    description: "Essential Linux concepts: file system hierarchy, users & groups, permissions, processes, package management, and shell basics.",
    icon: <TerminalIcon sx={{ fontSize: 40 }} />,
    path: "/learn/linux-fundamentals",
    color: "#f97316",
    tags: ["Linux", "Bash", "Permissions", "CLI"],
    badge: "New",
  },
  {
    title: "Computer Networking",
    description: "Network fundamentals: OSI/TCP-IP models, IP addressing, subnetting, protocols, ports, DNS, wireless, and essential commands.",
    icon: <RouterIcon sx={{ fontSize: 40 }} />,
    path: "/learn/networking",
    color: "#0ea5e9",
    tags: ["TCP/IP", "OSI", "DNS", "Subnetting"],
    badge: "New",
  },
  {
    title: "Computer Science Fundamentals",
    description: "Core CS concepts: data structures, algorithms, Big O notation, OOP principles, SOLID, design patterns, and memory management.",
    icon: <SchoolIcon sx={{ fontSize: 40 }} />,
    path: "/learn/cs-fundamentals",
    color: "#6366f1",
    tags: ["Data Structures", "Algorithms", "OOP", "SOLID"],
    badge: "New",
  },
  {
    title: "IT Hardware",
    description: "Computer components, cables, connectors, peripherals, and troubleshooting. Essential knowledge for CompTIA A+ and IT support.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/it-hardware",
    color: "#8b5cf6",
    tags: ["Hardware", "Components", "Cables", "A+"],
    badge: "New",
  },
  {
    title: "Cloud Computing",
    description: "Cloud fundamentals: service models (IaaS, PaaS, SaaS), deployment types, major providers (AWS, Azure, GCP), and cloud security basics.",
    icon: <CloudIcon sx={{ fontSize: 40 }} />,
    path: "/learn/cloud-computing",
    color: "#0ea5e9",
    tags: ["AWS", "Azure", "GCP", "IaaS"],
    badge: "New",
  },
  {
    title: "Systems Administration",
    description: "Server management fundamentals: Windows Server & Linux, Active Directory, DNS/DHCP, backups, monitoring, and automation.",
    icon: <DnsIcon sx={{ fontSize: 40 }} />,
    path: "/learn/systems-admin",
    color: "#3b82f6",
    tags: ["Servers", "AD", "Linux", "DevOps"],
    badge: "New",
  },
  {
    title: "Artificial Intelligence",
    description: "AI/ML fundamentals: core concepts, data, maths, deep learning, NLP, LLMs, computer vision, MLOps, AI security, and AI for cybersecurity.",
    icon: <PsychologyIcon sx={{ fontSize: 40 }} />,
    path: "/learn/artificial-intelligence",
    color: "#8b5cf6",
    tags: ["AI", "ML", "LLMs", "Deep Learning"],
    badge: "New",
  },
];

// ========== CATEGORY: Network Security ==========
const networkCards: LearnCard[] = [
  {
    title: "Network Protocol Exploitation",
    description: "Defensive guide to protocol abuse patterns, detection signals, and hardening priorities.",
    icon: <RouterIcon sx={{ fontSize: 40 }} />,
    path: "/learn/network-protocol-exploitation",
    color: "#14b8a6",
    tags: ["TCP", "UDP", "TLS", "Detection"],
  },
  {
    title: "ARP/DNS Poisoning",
    description: "Understand spoofing risks, detection signals, and defensive monitoring.",
    icon: <WifiIcon sx={{ fontSize: 40 }} />,
    path: "/learn/arp-dns-poisoning",
    color: "#0ea5e9",
    tags: ["ARP", "DNS", "MITM"],
  },
  {
    title: "DDoS Attack Techniques",
    description: "Distributed denial of service attacks: volumetric, protocol, application layer, amplification, and mitigation.",
    icon: <CloudOffIcon sx={{ fontSize: 40 }} />,
    path: "/learn/ddos-techniques",
    color: "#991b1b",
    tags: ["Network", "Attacks", "Mitigation"],
  },
  {
    title: "Wireless Pentesting",
    description: "WiFi security testing: WEP/WPA cracking, evil twin attacks, Bluetooth exploitation, and RF protocols.",
    icon: <WifiIcon sx={{ fontSize: 40 }} />,
    path: "/learn/wireless-pentesting",
    color: "#0891b2",
    tags: ["WiFi", "Bluetooth", "RF"],
  },
];

// ========== CATEGORY: Reverse Engineering ==========
const reverseEngineeringCards: LearnCard[] = [
  {
    title: "Intro to Reverse Engineering",
    description: "Comprehensive introduction: what RE is, why it matters, legal/ethical considerations, mindset, and methodology overview.",
    icon: <SearchIcon sx={{ fontSize: 40 }} />,
    path: "/learn/intro-to-re",
    color: "#dc2626",
    tags: ["Fundamentals", "Malware", "Methodology"],
    badge: "Start Here",
  },
  {
    title: "Debugging 101",
    description: "Beginner-friendly guide to breakpoints, stepping, and memory inspection.",
    icon: <BugReportIcon sx={{ fontSize: 40 }} />,
    path: "/learn/debugging-101",
    color: "#3b82f6",
    tags: ["Breakpoints", "Stack", "Workflow"],
  },
  {
    title: "Ghidra Reverse Engineering",
    description: "NSA's open-source RE tool: disassembly, decompilation, scripting, and binary analysis fundamentals.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/ghidra",
    color: "#dc2626",
    tags: ["Disassembly", "Decompiler", "NSA"],
  },
  {
    title: "Binary Ninja Essentials",
    description: "IL-first workflow with HLIL/MLIL/LLIL, type recovery, and Python scripting for automation.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/binary-ninja",
    color: "#14b8a6",
    tags: ["IL", "Scripting", "Types"],
    badge: "New",
  },
  {
    title: "IDA Pro Essentials",
    description: "Industry-standard disassembly and decompilation: navigation, xrefs, types, IDAPython, and debugging basics.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/ida-pro",
    color: "#2563eb",
    tags: ["IDA", "Decompiler", "IDAPython"],
    badge: "New",
  },
  {
    title: "Android Reverse Engineering",
    description: "Android RE fundamentals: APK structure, JADX, Frida, static/dynamic analysis, and common vulnerabilities.",
    icon: <PhoneAndroidIcon sx={{ fontSize: 40 }} />,
    path: "/learn/android-reverse-engineering",
    color: "#22c55e",
    tags: ["Android", "Frida", "JADX"],
  },
  {
    title: "iOS Reverse Engineering Fundamentals",
    description: "iOS app analysis: Mach-O, code signing, Objective-C/Swift metadata, and dynamic instrumentation basics.",
    icon: <PhoneIphoneIcon sx={{ fontSize: 40 }} />,
    path: "/learn/ios-reverse-engineering",
    color: "#3b82f6",
    tags: ["iOS", "Mach-O", "LLDB"],
    badge: "New",
  },
  {
    title: "Windows Internals for RE",
    description: "PE format, TEB/PEB, API patterns, hooking, DLL injection, and anti-debugging techniques.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/windows-internals",
    color: "#8b5cf6",
    tags: ["PE", "TEB/PEB", "Injection"],
  },
  {
    title: "Linux Internals for RE",
    description: "ELF format deep dive, process memory layout, syscalls, dynamic linking (PLT/GOT), GDB debugging, binary protections (ASLR, PIE, NX), libc internals, and exploitation patterns.",
    icon: <TerminalIcon sx={{ fontSize: 40 }} />,
    path: "/learn/linux-internals",
    color: "#f97316",
    tags: ["ELF", "GDB", "Exploitation"],
    badge: "New",
  },
  {
    title: "Malware Analysis",
    description: "Comprehensive guide to analyzing malicious software: static/dynamic analysis, sandboxing, debugging, unpacking, YARA rules, and threat intelligence.",
    icon: <BugReportIcon sx={{ fontSize: 40 }} />,
    path: "/learn/malware-analysis",
    color: "#ef4444",
    tags: ["Malware", "Sandbox", "YARA", "Threat Intel"],
    badge: "New",
  },
  {
    title: "Anti-Debugging Techniques",
    description: "Comprehensive guide to anti-debugging: API checks, PEB flags, timing attacks, exception handling, VM detection, and bypass strategies.",
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    path: "/learn/anti-debugging",
    color: "#f97316",
    tags: ["Anti-Debug", "Evasion", "Protection", "Bypass"],
    badge: "New",
  },
  {
    title: "Firmware Reverse Engineering Fundamentals",
    description: "Embedded device analysis: firmware extraction, filesystems, bootloaders, emulation, and IoT security basics.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/firmware-re",
    color: "#06b6d4",
    tags: ["Firmware", "IoT", "Hardware"],
    badge: "New",
  },
];

// ========== CATEGORY: Vulnerability Research ==========
const vulnResearchCards: LearnCard[] = [
  {
    title: "Buffer Overflow",
    description: "Memory corruption fundamentals: stack/heap overflows, exploitation techniques, protections, and prevention.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/buffer-overflow",
    color: "#dc2626",
    tags: ["Memory", "Exploitation", "C/C++"],
    badge: "New",
  },
  {
    title: "Return-Oriented Programming (ROP)",
    description: "Beginner-friendly guide to ROP concepts, risks, and modern mitigations.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/rop",
    color: "#2563eb",
    tags: ["Memory Safety", "Mitigations", "Crashes"],
  },
  {
    title: "Deserialization Attacks",
    description: "Understand unsafe object parsing, detection signals, and safer serialization patterns.",
    icon: <AccountTreeIcon sx={{ fontSize: 40 }} />,
    path: "/learn/deserialization-attacks",
    color: "#3b82f6",
    tags: ["Serialization", "Object Graphs", "Defense"],
  },
  {
    title: "Fuzzing Deep Dive",
    description: "Automated bug hunting with coverage-guided fuzzing. AFL++, libFuzzer, crash triage.",
    icon: <RadarIcon sx={{ fontSize: 40 }} />,
    path: "/learn/fuzzing",
    color: "#ef4444",
    tags: ["AFL++", "Automation", "Crashes"],
  },
  {
    title: "CVE, CWE, CVSS & EPSS",
    description: "Understand vulnerability identification and scoring systems. Interactive CVSS calculator.",
    icon: <BugReportIcon sx={{ fontSize: 40 }} />,
    path: "/learn/cve-cwe-cvss",
    color: "#ea580c",
    tags: ["Scoring", "Severity", "Prioritization"],
  },
  {
    title: "Heap Exploitation",
    description: "Dynamic memory corruption: UAF, double-free, heap spray, tcache poisoning, House of techniques.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/heap-exploitation",
    color: "#ef4444",
    tags: ["Memory", "glibc", "Exploitation"],
  },
  {
    title: "Integer Overflows & Underflows",
    description: "Arithmetic boundary bugs: overflow, underflow, signed/unsigned issues, width truncation.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/integer-overflow",
    color: "#f59e0b",
    tags: ["Arithmetic", "Memory", "C/C++"],
  },
  {
    title: "Out-of-Bounds Read/Write",
    description: "Array boundary violations: info leaks, arbitrary R/W primitives, exploitation techniques.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/oob-read-write",
    color: "#8b5cf6",
    tags: ["Memory", "Arrays", "Info Leak"],
  },
];

// ========== CATEGORY: Web Security ==========
const webSecurityCards: LearnCard[] = [
  {
    title: "OWASP Top 10",
    description: "The industry standard for web application security. Deep dive into the 10 most critical risks.",
    icon: <WarningIcon sx={{ fontSize: 40 }} />,
    path: "/learn/owasp",
    color: "#dc2626",
    tags: ["Web Security", "2021", "Prevention"],
  },
  {
    title: "Web Pentesting Guide",
    description: "Comprehensive methodology for web app security assessments. From recon to reporting.",
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    path: "/learn/pentest-guide",
    color: "#dc2626",
    tags: ["Methodology", "Attacks", "Reporting"],
  },
  {
    title: "SQL Injection (SQLi)",
    description: "Beginner-friendly deep dive into SQLi mechanics, detection signals, and secure fixes.",
    icon: <StorageIcon sx={{ fontSize: 40 }} />,
    path: "/learn/sql-injection",
    color: "#f59e0b",
    tags: ["SQLi", "Queries", "Prevention"],
  },
  {
    title: "Server-Side Request Forgery (SSRF)",
    description: "Understand SSRF attacks: cloud metadata theft, internal service access, bypass techniques and prevention.",
    icon: <CloudIcon sx={{ fontSize: 40 }} />,
    path: "/learn/ssrf",
    color: "#f97316",
    tags: ["Web Security", "Cloud", "OWASP"],
  },
  {
    title: "API Security Testing",
    description: "REST & GraphQL security testing. BOLA, authentication bypass, injection, rate limits.",
    icon: <ApiIcon sx={{ fontSize: 40 }} />,
    path: "/learn/api-security",
    color: "#3b82f6",
    tags: ["REST", "GraphQL", "OWASP API"],
  },
  {
    title: "Auth & Crypto Foundations",
    description: "Authentication, cryptography, sessions, JWTs, OAuth, TLS, and access control.",
    icon: <LockIcon sx={{ fontSize: 40 }} />,
    path: "/learn/auth-crypto",
    color: "#059669",
    tags: ["Auth", "Crypto", "JWT", "OAuth"],
  },
  {
    title: "Command Injection",
    description: "OS command execution attacks: shell metacharacters, blind injection, and prevention.",
    icon: <TerminalIcon sx={{ fontSize: 40 }} />,
    path: "/learn/command-injection",
    color: "#ef4444",
    tags: ["Injection", "RCE", "OWASP A03"],
  },
  {
    title: "Cross-Site Scripting (XSS)",
    description: "Client-side injection: reflected, stored, DOM XSS, payloads, and CSP prevention.",
    icon: <CodeIcon sx={{ fontSize: 40 }} />,
    path: "/learn/xss",
    color: "#f59e0b",
    tags: ["XSS", "Client-Side", "CSP"],
  },
];

// ========== CATEGORY: Offensive Security / Red Team ==========
const offensiveSecurityCards: LearnCard[] = [
  {
    title: "Cyber Kill Chain",
    description: "Master the 7 phases of the Lockheed Martin Cyber Kill Chain. Understand how attackers operate.",
    icon: <LinkIcon sx={{ fontSize: 40 }} />,
    path: "/learn/kill-chain",
    color: "#ef4444",
    tags: ["Attack Phases", "Defense", "Threat Intel"],
  },
  {
    title: "MITRE ATT&CK",
    description: "Explore the knowledge base of adversary tactics and techniques. 14 tactics, 200+ techniques.",
    icon: <GpsFixedIcon sx={{ fontSize: 40 }} />,
    path: "/learn/mitre-attack",
    color: "#f59e0b",
    tags: ["TTPs", "Threat Modeling", "Detection"],
  },
  {
    title: "C2 Frameworks",
    description: "Command & Control fundamentals: Cobalt Strike, Sliver, Havoc, infrastructure, OPSEC, and detection.",
    icon: <SettingsRemoteIcon sx={{ fontSize: 40 }} />,
    path: "/learn/c2-frameworks",
    color: "#dc2626",
    tags: ["Red Team", "Beacon", "Infrastructure"],
  },
  {
    title: "Privilege Escalation",
    description: "Linux & Windows privesc techniques: SUID, sudo, kernel exploits, token impersonation, GTFOBins, LOLBAS.",
    icon: <AdminPanelSettingsIcon sx={{ fontSize: 40 }} />,
    path: "/learn/privilege-escalation",
    color: "#ef4444",
    tags: ["Linux", "Windows", "GTFOBins"],
  },
  {
    title: "Lateral Movement",
    description: "Techniques for network pivoting: Windows protocols, LOLBins, credential attacks, and evasion.",
    icon: <AccountTreeIcon sx={{ fontSize: 40 }} />,
    path: "/learn/lateral-movement",
    color: "#ef4444",
    tags: ["LOLBins", "PtH", "WinRM"],
  },
  {
    title: "Living off the Land",
    description: "LOLBAS/GTFOBins fundamentals, safe inventory, and detection signals for built-in tool abuse.",
    icon: <TerminalIcon sx={{ fontSize: 40 }} />,
    path: "/learn/living-off-the-land",
    color: "#f97316",
    tags: ["LOLBAS", "GTFOBins", "Detection"],
  },
  {
    title: "Windows Persistence Mechanisms",
    description: "Understand run keys, services, scheduled tasks, and safe enumeration of persistence artifacts.",
    icon: <AutorenewIcon sx={{ fontSize: 40 }} />,
    path: "/learn/windows-persistence",
    color: "#3b82f6",
    tags: ["Run Keys", "Scheduled Tasks", "Services"],
  },
  {
    title: "Pivoting & Tunneling",
    description: "Beginner-friendly guide to traffic routing, tunnels, detection, and defenses.",
    icon: <RouteIcon sx={{ fontSize: 40 }} />,
    path: "/learn/pivoting-tunneling",
    color: "#3b82f6",
    tags: ["Pivoting", "Tunneling", "Detection"],
  },
  {
    title: "Credential Harvesting",
    description: "Beginner-focused guide to credential risks, storage locations, detection signals, and prevention.",
    icon: <VpnKeyIcon sx={{ fontSize: 40 }} />,
    path: "/learn/credential-harvesting",
    color: "#a855f7",
    tags: ["Phishing", "Secrets", "Detection"],
  },
  {
    title: "Data Exfiltration",
    description: "Learn common exfil paths, detection signals, and safe prevention practices.",
    icon: <CloudUploadIcon sx={{ fontSize: 40 }} />,
    path: "/learn/data-exfiltration",
    color: "#0ea5e9",
    tags: ["Egress", "DLP", "Telemetry"],
  },
  {
    title: "OSINT & Reconnaissance",
    description: "Open source intelligence gathering: subdomain enumeration, email discovery, Google dorks, and OSINT tools.",
    icon: <TravelExploreIcon sx={{ fontSize: 40 }} />,
    path: "/learn/osint",
    color: "#f97316",
    tags: ["Passive Recon", "Subdomains", "Shodan"],
  },
  {
    title: "Container & Kubernetes Exploitation",
    description: "Offensive testing paths for containers and clusters: runtime misconfigurations, RBAC, and escape themes.",
    icon: <CloudIcon sx={{ fontSize: 40 }} />,
    path: "/learn/container-k8s",
    color: "#38bdf8",
    tags: ["Containers", "Kubernetes", "RBAC"],
  },
];

// ========== CATEGORY: Defensive Security / Blue Team ==========
const defensiveSecurityCards: LearnCard[] = [
  {
    title: "Cyber Threat Intelligence",
    description: "Comprehensive guide to CTI: 70+ threat actors, attribution frameworks, tracking methods, and intelligence tradecraft.",
    icon: <GpsFixedIcon sx={{ fontSize: 40 }} />,
    path: "/learn/cti",
    color: "#dc2626",
    tags: ["APT Groups", "Attribution", "STIX/TAXII"],
  },
  {
    title: "Incident Response",
    description: "NIST-based IR framework: 6 phases, playbooks, detection strategies, and forensic collection.",
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    path: "/learn/incident-response",
    color: "#dc2626",
    tags: ["NIST", "DFIR", "Playbooks"],
  },
  {
    title: "Digital Forensics",
    description: "Evidence acquisition, disk imaging, memory analysis, timeline creation, and Windows artifacts.",
    icon: <SearchIcon sx={{ fontSize: 40 }} />,
    path: "/learn/digital-forensics",
    color: "#14b8a6",
    tags: ["DFIR", "Memory", "Timeline"],
  },
  {
    title: "Antivirus Detection",
    description: "Beginner-friendly guide to signatures, behavior monitoring, and safe platform checks.",
    icon: <ShieldIcon sx={{ fontSize: 40 }} />,
    path: "/learn/anti-virus-detection",
    color: "#22c55e",
    tags: ["Signatures", "Behavior", "Triage"],
  },
  {
    title: "Data & Secrets Guide",
    description: "File uploads/downloads, data storage, logs, backups, secrets hunting, and exfiltration.",
    icon: <FolderSpecialIcon sx={{ fontSize: 40 }} />,
    path: "/learn/data-secrets",
    color: "#d97706",
    tags: ["File Upload", "Secrets", "Exfil"],
  },
  {
    title: "SIEM Fundamentals",
    description: "Security Information and Event Management: log collection, correlation, alerting, and SIEM platforms.",
    icon: <StorageIcon sx={{ fontSize: 40 }} />,
    path: "/learn/siem",
    color: "#3b82f6",
    tags: ["Splunk", "Elastic", "Sentinel"],
  },
  {
    title: "SOC Analyst Workflow",
    description: "Security Operations Center processes: triage, investigation, escalation, and shift handoffs.",
    icon: <SupportAgentIcon sx={{ fontSize: 40 }} />,
    path: "/learn/soc-workflow",
    color: "#10b981",
    tags: ["SOC", "Triage", "Tier 1-3"],
  },
  {
    title: "Threat Hunting Fundamentals",
    description: "Proactive threat detection: hypothesis-driven hunting, data sources, and ATT&CK mapping.",
    icon: <TravelExploreIcon sx={{ fontSize: 40 }} />,
    path: "/learn/threat-hunting",
    color: "#8b5cf6",
    tags: ["Hunting", "ATT&CK", "TTPs"],
  },
];

// ========== CATEGORY: Mobile Security ==========
const mobileSecurityCards: LearnCard[] = [
  {
    title: "Android Pentesting",
    description: "Beginner friendly Android app testing: lab setup, attack surface mapping, storage, network, and runtime checks.",
    icon: <AndroidIcon sx={{ fontSize: 40 }} />,
    path: "/learn/android-pentesting",
    color: "#22c55e",
    tags: ["Android", "Pentesting", "MASTG"],
    badge: "New",
  },
  {
    title: "iOS Pentesting",
    description: "iOS app security testing: static/dynamic analysis, Frida, jailbreak bypass, and data storage.",
    icon: <PhoneAndroidIcon sx={{ fontSize: 40 }} />,
    path: "/learn/ios-pentesting",
    color: "#6366f1",
    tags: ["iOS", "Mobile", "Frida", "Jailbreak"],
  },
  {
    title: "OWASP Mobile Top 10",
    description: "Critical security risks for mobile applications (2024). Platform-specific guidance.",
    icon: <PhoneAndroidIcon sx={{ fontSize: 40 }} />,
    path: "/learn/owasp-mobile",
    color: "#8b5cf6",
    tags: ["Mobile", "Android", "iOS"],
  },
  {
    title: "Mobile App Pentesting",
    description: "Android & iOS security testing. Frida, SSL pinning bypass, data storage analysis.",
    icon: <PhoneAndroidIcon sx={{ fontSize: 40 }} />,
    path: "/learn/mobile-pentest",
    color: "#10b981",
    tags: ["Android", "iOS", "Frida"],
  },
];

// ========== CATEGORY: Software Engineering ==========
const softwareEngineeringCards: LearnCard[] = [
  {
    title: "Software Engineering Fundamentals",
    description: "Beginner guide to tools, IDEs, Git/GitHub, workflows, and software engineering roles across web, mobile, backend, cloud, and security.",
    icon: <SchoolIcon sx={{ fontSize: 40 }} />,
    path: "/learn/software-engineering-fundamentals",
    color: "#f97316",
    tags: ["Beginner", "Git", "IDEs", "Workflows"],
    badge: "New",
  },
  {
    title: "Secure by Design",
    description: "Build security into software from the ground up: security principles, threat modeling, STRIDE, OWASP Top 10, secure coding, and cryptography.",
    icon: <ShieldIcon sx={{ fontSize: 40 }} />,
    path: "/learn/secure-by-design",
    color: "#dc2626",
    tags: ["Security", "OWASP", "Threat Modeling", "Cryptography"],
    badge: "New",
  },
  {
    title: "Python Fundamentals",
    description: "Beginner-friendly Python guide: setup, syntax, data types, control flow, functions, files, and basic OOP.",
    icon: <ScienceIcon sx={{ fontSize: 40 }} />,
    path: "/learn/python-fundamentals",
    color: "#3776ab",
    tags: ["Python", "Beginner", "Syntax", "Automation"],
    badge: "New",
  },
  {
    title: "Assembly Language",
    description: "Master the language of the machine: x86/x64 registers, memory, instructions, and CPU architecture.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/assembly",
    color: "#f97316",
    tags: ["x86", "x64", "Registers", "CPU"],
    badge: "New",
  },
  {
    title: "HTML & CSS Fundamentals",
    description: "Build the foundation of the web: document structure, semantic HTML, CSS styling, Flexbox, Grid, and responsive design.",
    icon: <WebIcon sx={{ fontSize: 40 }} />,
    path: "/learn/html-css",
    color: "#e91e63",
    tags: ["HTML5", "CSS3", "Flexbox", "Grid"],
    badge: "New",
  },
  {
    title: "JavaScript Fundamentals",
    description: "Master JavaScript from basics to frameworks: ES6+, DOM, async programming, React, Node.js, TypeScript, and testing.",
    icon: <DataObjectIcon sx={{ fontSize: 40 }} />,
    path: "/learn/javascript",
    color: "#f7df1e",
    tags: ["ES6+", "React", "Node.js", "TypeScript"],
    badge: "New",
  },
  {
    title: "C Programming",
    description: "Master the foundation of modern computing: memory management, pointers, data structures, and system-level programming.",
    icon: <TerminalIcon sx={{ fontSize: 40 }} />,
    path: "/learn/c-programming",
    color: "#5c6bc0",
    tags: ["Pointers", "Memory", "Systems", "Low-Level"],
    badge: "New",
  },
  {
    title: "C++ Programming",
    description: "Master object-oriented programming, templates, STL, smart pointers, and modern C++ features for high-performance applications.",
    icon: <SpeedIcon sx={{ fontSize: 40 }} />,
    path: "/learn/cpp-programming",
    color: "#e91e63",
    tags: ["OOP", "Templates", "STL", "Modern C++"],
    badge: "New",
  },
  {
    title: "Go Programming",
    description: "Master the language of cloud infrastructure: goroutines, channels, interfaces, and building scalable services with Go.",
    icon: <CloudIcon sx={{ fontSize: 40 }} />,
    path: "/learn/go-programming",
    color: "#00ADD8",
    tags: ["Golang", "Concurrency", "Cloud", "DevOps"],
    badge: "New",
  },
  {
    title: "Rust Programming",
    description: "Learn the systems language loved by developers: ownership, memory safety without garbage collection, and fearless concurrency.",
    icon: <SettingsIcon sx={{ fontSize: 40 }} />,
    path: "/learn/rust-programming",
    color: "#DEA584",
    tags: ["Systems", "Memory Safety", "Concurrency", "WASM"],
    badge: "New",
  },
  {
    title: "Java Programming",
    description: "Master the enterprise standard: object-oriented programming, JVM architecture, Spring Boot, and building scalable applications.",
    icon: <LocalCafeIcon sx={{ fontSize: 40 }} />,
    path: "/learn/java-programming",
    color: "#E76F00",
    tags: ["OOP", "Enterprise", "Spring", "Android"],
    badge: "New",
  },
  {
    title: "PHP Programming",
    description: "Master the web's most widely deployed language: server-side scripting, database integration, frameworks, and modern PHP development.",
    icon: <StorageIcon sx={{ fontSize: 40 }} />,
    path: "/learn/php-programming",
    color: "#777BB4",
    tags: ["Web", "Laravel", "MySQL", "WordPress"],
    badge: "New",
  },
  {
    title: "C# Programming",
    description: "Master the .NET ecosystem: object-oriented programming, LINQ, async patterns, ASP.NET Core, and cross-platform development.",
    icon: <ViewInArIcon sx={{ fontSize: 40 }} />,
    path: "/learn/csharp-programming",
    color: "#512BD4",
    tags: [".NET", "Unity", "ASP.NET", "Enterprise"],
    badge: "New",
  },
  {
    title: "Kotlin Programming",
    description: "Master Android's preferred language: null safety, coroutines, functional programming, and multiplatform development.",
    icon: <AndroidIcon sx={{ fontSize: 40 }} />,
    path: "/learn/kotlin-programming",
    color: "#7F52FF",
    tags: ["Android", "Multiplatform", "Coroutines", "JetBrains"],
    badge: "New",
  },
  {
    title: "Swift Programming",
    description: "Master Apple's modern programming language: optionals, protocols, SwiftUI, Combine, and building iOS/macOS applications.",
    icon: <PhoneIphoneIcon sx={{ fontSize: 40 }} />,
    path: "/learn/swift-programming",
    color: "#F05138",
    tags: ["iOS", "macOS", "SwiftUI", "Apple"],
    badge: "New",
  },
  {
    title: "Git & Version Control",
    description: "Master Git fundamentals: repositories, commits, branches, merging, rebasing, workflows, GitHub/GitLab, and collaboration best practices.",
    icon: <AccountTreeIcon sx={{ fontSize: 40 }} />,
    path: "/learn/git-version-control",
    color: "#f14e32",
    tags: ["Git", "GitHub", "Branching", "Collaboration"],
    badge: "New",
  },
];

// ========== CATEGORY: Project & Service Management ==========
const projectServiceManagementCards: LearnCard[] = [
  {
    title: "Agile Project Management",
    description: "Master Agile methodologies: Scrum, Kanban, user stories, estimation, sprints, retrospectives, and scaling frameworks like SAFe.",
    icon: <SpeedIcon sx={{ fontSize: 40 }} />,
    path: "/learn/agile-pm",
    color: "#6366f1",
    tags: ["Scrum", "Kanban", "Sprints", "User Stories"],
    badge: "New",
  },
  {
    title: "The Scrum Guide",
    description: "The definitive guide to Scrum: theory, values, roles (Product Owner, Scrum Master, Developers), events, artifacts, and Definition of Done.",
    icon: <AutorenewIcon sx={{ fontSize: 40 }} />,
    path: "/learn/scrum",
    color: "#0891b2",
    tags: ["Framework", "Sprints", "Roles", "Artifacts"],
    badge: "New",
  },
  {
    title: "PRINCE2 Guide",
    description: "Master PRINCE2 project management: 7 principles, 7 themes, 7 processes, roles, management products, tailoring, and certification paths.",
    icon: <AccountTreeIcon sx={{ fontSize: 40 }} />,
    path: "/learn/prince2",
    color: "#7c3aed",
    tags: ["Methodology", "Governance", "AXELOS", "Processes"],
    badge: "New",
  },
  {
    title: "ITIL 4 Guide",
    description: "Master IT Service Management: Service Value System, 7 guiding principles, Service Value Chain, 34 practices, and certification paths.",
    icon: <SupportAgentIcon sx={{ fontSize: 40 }} />,
    path: "/learn/itil-v4",
    color: "#059669",
    tags: ["ITSM", "Practices", "AXELOS", "Service Value"],
    badge: "New",
  },
];

// ========== CATEGORY: Career & Certifications ==========
const careerCards: LearnCard[] = [
  {
    title: "Cyber Security Certifications",
    description: "Certification map by subject and difficulty, covering SANS, OffSec, CompTIA, CREST, CEH, and more.",
    icon: <WorkspacePremiumIcon sx={{ fontSize: 40 }} />,
    path: "/learn/certifications",
    color: "#0ea5e9",
    tags: ["SANS", "OffSec", "CompTIA", "CREST"],
  },
  {
    title: "Cybersecurity Career Paths",
    description: "Explore career tracks: Red Team, Blue Team, Security Engineering, and GRC with role progression.",
    icon: <TrendingUpIcon sx={{ fontSize: 40 }} />,
    path: "/learn/career-paths",
    color: "#f59e0b",
    tags: ["Careers", "Red Team", "Blue Team", "GRC"],
  },
  {
    title: "Building a Security Portfolio",
    description: "Stand out with GitHub projects, CTF achievements, blog writing, and bug bounty work.",
    icon: <FolderSpecialIcon sx={{ fontSize: 40 }} />,
    path: "/learn/portfolio",
    color: "#6366f1",
    tags: ["Portfolio", "GitHub", "CTF", "Blog"],
  },
];

// ========== CATEGORY: Reference ==========
const referenceCards: LearnCard[] = [
  {
    title: "Security Glossary",
    description: "Comprehensive dictionary of 120+ cybersecurity terms with definitions and category filtering.",
    icon: <MenuBookIcon sx={{ fontSize: 40 }} />,
    path: "/learn/glossary",
    color: "#10b981",
    tags: ["Definitions", "Reference", "Terms"],
  },
  {
    title: "Commands Reference",
    description: "Essential Linux, PowerShell, Nmap, and Wireshark commands. Copy-to-clipboard ready.",
    icon: <TerminalIcon sx={{ fontSize: 40 }} />,
    path: "/learn/commands",
    color: "#6366f1",
    tags: ["Linux", "PowerShell", "Nmap"],
  },
];

// ========== ALL CATEGORIES ==========
const allCategories: CategorySection[] = [
  {
    id: "about-vragent",
    title: "About VRAgent",
    emoji: "🛡️",
    description: "Complete guides to VRAgent's tools: scanning pipeline, AI analysis, Network Hub (Nmap, PCAP, SSL, DNS, Traceroute, API Tester, Fuzzer, MITM), and RE Hub (APK, Binary, Docker).",
    icon: <RocketLaunchIcon sx={{ fontSize: 32 }} />,
    color: "#6366f1",
    gradientEnd: "#8b5cf6",
    cards: appCards,
  },
  {
    id: "it-fundamentals",
    title: "IT Fundamentals",
    emoji: "💻",
    description: "Core IT concepts every security professional should know: operating systems, networking basics, and system administration.",
    icon: <ComputerIcon sx={{ fontSize: 32 }} />,
    color: "#0078d4",
    gradientEnd: "#00a2ed",
    cards: itFundamentalsCards,
  },
  {
    id: "network-security",
    title: "Network Security",
    emoji: "🌐",
    description: "Advanced network security concepts: protocol exploitation, wireless attacks, DDoS, and network-level threats.",
    icon: <HubIcon sx={{ fontSize: 32 }} />,
    color: "#0ea5e9",
    gradientEnd: "#06b6d4",
    cards: networkCards,
  },
  {
    id: "reverse-engineering",
    title: "Reverse Engineering",
    emoji: "🔬",
    description: "Reverse engineering fundamentals: debugging, Ghidra, and Android analysis techniques.",
    icon: <BuildIcon sx={{ fontSize: 32 }} />,
    color: "#a855f7",
    gradientEnd: "#8b5cf6",
    cards: reverseEngineeringCards,
  },
  {
    id: "vulnerability-research",
    title: "Vulnerability Research",
    emoji: "🔍",
    description: "Explore memory corruption, exploit development, fuzzing, and vulnerability analysis techniques.",
    icon: <ScienceIcon sx={{ fontSize: 32 }} />,
    color: "#ef4444",
    gradientEnd: "#dc2626",
    cards: vulnResearchCards,
  },
  {
    id: "web-security",
    title: "Web Security",
    emoji: "🕸️",
    description: "Web application security testing, OWASP vulnerabilities, API security, and authentication bypasses.",
    icon: <LanguageIcon sx={{ fontSize: 32 }} />,
    color: "#22c55e",
    gradientEnd: "#16a34a",
    cards: webSecurityCards,
  },
  {
    id: "offensive-security",
    title: "Offensive Security / Red Team",
    emoji: "⚔️",
    description: "Attack methodologies, privilege escalation, lateral movement, C2 frameworks, and adversary emulation.",
    icon: <GpsFixedIcon sx={{ fontSize: 32 }} />,
    color: "#dc2626",
    gradientEnd: "#ef4444",
    cards: offensiveSecurityCards,
  },
  {
    id: "defensive-security",
    title: "Defensive Security / Blue Team",
    emoji: "🛡️",
    description: "Threat intelligence, incident response, digital forensics, and defensive monitoring strategies.",
    icon: <LocalPoliceIcon sx={{ fontSize: 32 }} />,
    color: "#3b82f6",
    gradientEnd: "#2563eb",
    cards: defensiveSecurityCards,
  },
  {
    id: "mobile-security",
    title: "Mobile Security",
    emoji: "📱",
    description: "Android and iOS security testing, mobile app pentesting, and OWASP Mobile Top 10.",
    icon: <PhoneAndroidIcon sx={{ fontSize: 32 }} />,
    color: "#10b981",
    gradientEnd: "#059669",
    cards: mobileSecurityCards,
  },
  {
    id: "software-engineering",
    title: "Software Engineering",
    emoji: "⚙️",
    description: "Core software engineering concepts: HTML/CSS, assembly language, compilers, and low-level programming.",
    icon: <MemoryIcon sx={{ fontSize: 32 }} />,
    color: "#f97316",
    gradientEnd: "#ea580c",
    cards: softwareEngineeringCards,
  },
  {
    id: "project-service-management",
    title: "Project & Service Management",
    emoji: "📋",
    description: "Project management methodologies, service delivery frameworks, and team collaboration practices for successful software delivery.",
    icon: <IntegrationInstructionsIcon sx={{ fontSize: 32 }} />,
    color: "#6366f1",
    gradientEnd: "#8b5cf6",
    cards: projectServiceManagementCards,
  },
  {
    id: "career",
    title: "Career & Certifications",
    emoji: "🏆",
    description: "Certification paths and career development resources for security professionals.",
    icon: <WorkspacePremiumIcon sx={{ fontSize: 32 }} />,
    color: "#f59e0b",
    gradientEnd: "#d97706",
    cards: careerCards,
  },
  {
    id: "reference",
    title: "Quick Reference",
    emoji: "📚",
    description: "Handy glossaries and command references to keep at your fingertips during assessments.",
    icon: <MenuBookIcon sx={{ fontSize: 32 }} />,
    color: "#10b981",
    gradientEnd: "#6366f1",
    cards: referenceCards,
  },
];

interface CardGridProps {
  cards: LearnCard[];
  columns?: { xs: number; sm: number; md: number; lg: number };
  centered?: boolean;
}

function CardGrid({ cards, columns = { xs: 12, sm: 6, md: 4, lg: 3 }, centered = false }: CardGridProps) {
  const navigate = useNavigate();
  
  return (
    <Grid container spacing={3} justifyContent={centered ? "center" : "flex-start"}>
      {cards.map((card) => (
        <Grid item xs={columns.xs} sm={columns.sm} md={columns.md} lg={columns.lg} key={card.path}>
          <Card
            sx={{
              height: "100%",
              borderRadius: 3,
              border: `1px solid ${alpha(card.color, 0.15)}`,
              transition: "all 0.3s ease",
              position: "relative",
              overflow: "visible",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 12px 40px ${alpha(card.color, 0.15)}`,
                borderColor: card.color,
              },
            }}
          >
            {card.badge && (
              <Chip
                label={card.badge}
                size="small"
                sx={{
                  position: "absolute",
                  top: -10,
                  right: 16,
                  bgcolor: card.color,
                  color: "white",
                  fontWeight: 700,
                  fontSize: "0.7rem",
                }}
              />
            )}
            <CardActionArea
              onClick={() => navigate(card.path)}
              sx={{ height: "100%", display: "flex", flexDirection: "column", alignItems: "stretch" }}
            >
              <CardContent sx={{ flex: 1, display: "flex", flexDirection: "column", p: 3 }}>
                <Box
                  sx={{
                    width: 56,
                    height: 56,
                    borderRadius: 2,
                    bgcolor: alpha(card.color, 0.1),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    mb: 2,
                    color: card.color,
                  }}
                >
                  {card.icon}
                </Box>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1.5, lineHeight: 1.3 }}>
                  {card.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1, lineHeight: 1.6 }}>
                  {card.description}
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {card.tags.map((tag) => (
                    <Chip
                      key={tag}
                      label={tag}
                      size="small"
                      sx={{
                        fontSize: "0.65rem",
                        height: 22,
                        bgcolor: alpha(card.color, 0.08),
                        color: card.color,
                        fontWeight: 500,
                      }}
                    />
                  ))}
                </Box>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
      ))}
    </Grid>
  );
}

export default function LearnHubPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const isLargeScreen = useMediaQuery(theme.breakpoints.up("lg"));
  const isMediumScreen = useMediaQuery(theme.breakpoints.up("md"));
  
  // Search state
  const [searchQuery, setSearchQuery] = useState("");
  const [searchFocused, setSearchFocused] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchAnchorRef = useRef<HTMLDivElement>(null);
  
  // Quick navigation state
  const [quickNavOpen, setQuickNavOpen] = useState(false);
  const [showBackToTop, setShowBackToTop] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  
  // Filter state - all categories visible by default
  const [visibleCategories, setVisibleCategories] = useState<Record<string, boolean>>(
    () => Object.fromEntries(allCategories.map((cat) => [cat.id, true]))
  );
  const [filterExpanded, setFilterExpanded] = useState(false);

  // Flatten all cards for search
  const allCards = useMemo(() => {
    return allCategories.flatMap((category) =>
      category.cards.map((card) => ({
        ...card,
        category: category.title,
        categoryId: category.id,
        categoryEmoji: category.emoji,
        categoryColor: category.color,
      }))
    );
  }, []);

  // Fuzzy search function
  const fuzzyMatch = useCallback((text: string, query: string): boolean => {
    const lowerText = text.toLowerCase();
    const lowerQuery = query.toLowerCase();
    
    // Direct substring match
    if (lowerText.includes(lowerQuery)) return true;
    
    // Fuzzy character match
    let queryIndex = 0;
    for (let i = 0; i < lowerText.length && queryIndex < lowerQuery.length; i++) {
      if (lowerText[i] === lowerQuery[queryIndex]) {
        queryIndex++;
      }
    }
    return queryIndex === lowerQuery.length;
  }, []);

  // Search results
  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return [];
    
    const query = searchQuery.trim();
    return allCards
      .filter((card) => {
        // Search in title, description, tags, and category
        return (
          fuzzyMatch(card.title, query) ||
          fuzzyMatch(card.description, query) ||
          card.tags.some((tag) => fuzzyMatch(tag, query)) ||
          fuzzyMatch(card.category, query)
        );
      })
      .slice(0, 12); // Limit to 12 results
  }, [searchQuery, allCards, fuzzyMatch]);

  // Keyboard shortcut for search (Ctrl+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
      if (e.key === "Escape" && searchFocused) {
        setSearchQuery("");
        searchInputRef.current?.blur();
      }
    };
    
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [searchFocused]);

  // Scroll detection for back-to-top button and active section
  useEffect(() => {
    const handleScroll = () => {
      setShowBackToTop(window.scrollY > 400);
      
      // Detect active section
      const sections = allCategories.map((cat) => document.getElementById(`category-${cat.id}`));
      let currentSection = "";
      
      for (const section of sections) {
        if (section) {
          const rect = section.getBoundingClientRect();
          if (rect.top <= 150) {
            currentSection = section.id.replace("category-", "");
          }
        }
      }
      setActiveSection(currentSection);
    };
    
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const scrollToCategory = (categoryId: string) => {
    const element = document.getElementById(`category-${categoryId}`);
    if (element) {
      const offset = 100; // Account for sticky header
      const elementPosition = element.getBoundingClientRect().top;
      const offsetPosition = elementPosition + window.pageYOffset - offset;
      
      window.scrollTo({ top: offsetPosition, behavior: "smooth" });
    }
    setQuickNavOpen(false);
  };

  const handleSearchResultClick = (path: string) => {
    setSearchQuery("");
    setSearchFocused(false);
    navigate(path);
  };

  const handleToggleCategory = (categoryId: string) => {
    setVisibleCategories((prev) => ({
      ...prev,
      [categoryId]: !prev[categoryId],
    }));
  };

  const handleShowAll = () => {
    setVisibleCategories(Object.fromEntries(allCategories.map((cat) => [cat.id, true])));
  };

  const handleHideAll = () => {
    setVisibleCategories(Object.fromEntries(allCategories.map((cat) => [cat.id, false])));
  };

  const visibleCount = useMemo(
    () => Object.values(visibleCategories).filter(Boolean).length,
    [visibleCategories]
  );

  const totalCards = useMemo(
    () => allCategories.reduce((sum, cat) => sum + cat.cards.length, 0),
    []
  );

  const visibleCards = useMemo(
    () =>
      allCategories
        .filter((cat) => visibleCategories[cat.id])
        .reduce((sum, cat) => sum + cat.cards.length, 0),
    [visibleCategories]
  );

  const pageContext = `VRAgent Security Learning Hub - A comprehensive cybersecurity learning platform with ${allCategories.length} categories and ${totalCards} learning topics. Categories include: About VRAgent (scanning, AI analysis, tools), Network Security (Wireshark, Nmap, protocols), Reverse Engineering (debugging, Ghidra), Vulnerability Research (buffer overflows, ROP), Web Security (OWASP Top 10, SQLi, SSRF), Offensive Security (MITRE ATT&CK, C2, lateral movement), Defensive Security (threat intelligence, incident response, forensics), Mobile Security (OWASP Mobile Top 10, pentesting), Career & Certifications (OSCP, CISSP, CTF), and Quick Reference (glossary, commands). This hub provides structured learning paths for security professionals at all levels.`;

  // Quick Navigation Sidebar Content
  const QuickNavContent = (
    <Box sx={{ width: isLargeScreen ? 280 : 300, p: 2 }}>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon color="primary" /> Quick Navigation
        </Typography>
        {!isLargeScreen && (
          <IconButton size="small" onClick={() => setQuickNavOpen(false)}>
            <CloseIcon />
          </IconButton>
        )}
      </Box>
      <List dense sx={{ py: 0 }}>
        {allCategories.map((category) => (
          <ListItem key={category.id} disablePadding>
            <ListItemButton
              onClick={() => scrollToCategory(category.id)}
              selected={activeSection === category.id}
              sx={{
                borderRadius: 2,
                mb: 0.5,
                py: 1,
                border: `1px solid ${alpha(category.color, activeSection === category.id ? 0.3 : 0)}`,
                bgcolor: activeSection === category.id ? alpha(category.color, 0.1) : "transparent",
                "&:hover": {
                  bgcolor: alpha(category.color, 0.1),
                },
                "&.Mui-selected": {
                  bgcolor: alpha(category.color, 0.15),
                  "&:hover": { bgcolor: alpha(category.color, 0.2) },
                },
              }}
            >
              <ListItemIcon sx={{ minWidth: 36, color: category.color }}>
                <Typography variant="body1">{category.emoji}</Typography>
              </ListItemIcon>
              <ListItemText
                primary={category.title}
                secondary={`${category.cards.length} topics`}
                primaryTypographyProps={{
                  variant: "body2",
                  fontWeight: activeSection === category.id ? 700 : 500,
                  color: activeSection === category.id ? category.color : "text.primary",
                }}
                secondaryTypographyProps={{
                  variant: "caption",
                }}
              />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </Box>
  );

  return (
    <LearnPageLayout pageTitle="Security Learning Hub" pageContext={pageContext}>
      {/* Quick Nav Sidebar - Fixed on large screens */}
      {isLargeScreen && (
        <Box
          sx={{
            position: "fixed",
            left: 0,
            top: 80,
            height: "calc(100vh - 80px)",
            overflowY: "auto",
            zIndex: 100,
            borderRight: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            bgcolor: alpha(theme.palette.background.paper, 0.95),
            backdropFilter: "blur(10px)",
            "&::-webkit-scrollbar": { width: 6 },
            "&::-webkit-scrollbar-thumb": { 
              bgcolor: alpha(theme.palette.primary.main, 0.2),
              borderRadius: 3,
            },
          }}
        >
          {QuickNavContent}
        </Box>
      )}

      {/* Quick Nav Drawer - For smaller screens */}
      <Drawer
        anchor="left"
        open={quickNavOpen && !isLargeScreen}
        onClose={() => setQuickNavOpen(false)}
        PaperProps={{
          sx: { bgcolor: theme.palette.background.paper },
        }}
      >
        {QuickNavContent}
      </Drawer>

      {/* Main Content - offset on large screens for sidebar */}
      <Box sx={{ ml: isLargeScreen ? "280px" : 0 }}>
        <Container maxWidth="lg" sx={{ py: 4 }}>
          {/* Header */}
          <Box sx={{ textAlign: "center", mb: 4 }}>
            <Box
              sx={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                width: 80,
                height: 80,
                borderRadius: "50%",
                background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)}, ${alpha(theme.palette.secondary.main, 0.2)})`,
                mb: 2,
                boxShadow: `0 8px 32px ${alpha(theme.palette.primary.main, 0.3)}`,
                border: `3px solid ${alpha(theme.palette.primary.main, 0.3)}`,
              }}
            >
              <SchoolIcon sx={{ fontSize: 40, color: "primary.main" }} />
            </Box>
            <Typography
              variant="h3"
              sx={{
                fontWeight: 800,
                mb: 1,
                background: `linear-gradient(135deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
                backgroundClip: "text",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}
            >
              Security Learning Hub
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 600, mx: "auto", mb: 3 }}>
              Master cybersecurity concepts, frameworks, and tools.
            </Typography>

            {/* Global Search Bar */}
            <Box ref={searchAnchorRef} sx={{ maxWidth: 600, mx: "auto", position: "relative" }}>
              <TextField
                inputRef={searchInputRef}
                fullWidth
                placeholder="Search topics, tags, categories... (Ctrl+K)"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onFocus={() => setSearchFocused(true)}
                onBlur={() => setTimeout(() => setSearchFocused(false), 200)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon sx={{ color: searchFocused ? "primary.main" : "text.secondary" }} />
                    </InputAdornment>
                  ),
                  endAdornment: (
                    <InputAdornment position="end">
                      {searchQuery ? (
                        <IconButton size="small" onClick={() => setSearchQuery("")}>
                          <ClearIcon fontSize="small" />
                        </IconButton>
                      ) : (
                        <Chip
                          label="Ctrl+K"
                          size="small"
                          icon={<KeyboardIcon sx={{ fontSize: 14 }} />}
                          sx={{
                            height: 24,
                            fontSize: "0.7rem",
                            bgcolor: alpha(theme.palette.primary.main, 0.1),
                            "& .MuiChip-icon": { ml: 0.5 },
                          }}
                        />
                      )}
                    </InputAdornment>
                  ),
                }}
                sx={{
                  "& .MuiOutlinedInput-root": {
                    borderRadius: 3,
                    bgcolor: alpha(theme.palette.background.paper, 0.8),
                    backdropFilter: "blur(10px)",
                    transition: "all 0.3s ease",
                    "&:hover": {
                      bgcolor: theme.palette.background.paper,
                    },
                    "&.Mui-focused": {
                      bgcolor: theme.palette.background.paper,
                      boxShadow: `0 4px 20px ${alpha(theme.palette.primary.main, 0.15)}`,
                    },
                  },
                }}
              />

              {/* Search Results Dropdown */}
              <Popper
                open={searchFocused && searchResults.length > 0}
                anchorEl={searchAnchorRef.current}
                placement="bottom-start"
                transition
                style={{ zIndex: 1300, width: searchAnchorRef.current?.offsetWidth }}
              >
                {({ TransitionProps }) => (
                  <Fade {...TransitionProps} timeout={200}>
                    <Paper
                      sx={{
                        mt: 1,
                        borderRadius: 3,
                        boxShadow: `0 8px 32px ${alpha(theme.palette.common.black, 0.15)}`,
                        border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                        maxHeight: 400,
                        overflow: "auto",
                      }}
                    >
                      <Box sx={{ p: 1.5, borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
                        <Typography variant="caption" color="text.secondary">
                          {searchResults.length} result{searchResults.length !== 1 ? "s" : ""} found
                        </Typography>
                      </Box>
                      <List dense sx={{ py: 0 }}>
                        {searchResults.map((result, index) => (
                          <ListItem key={result.path} disablePadding>
                            <ListItemButton
                              onClick={() => handleSearchResultClick(result.path)}
                              sx={{
                                py: 1.5,
                                px: 2,
                                borderBottom: index < searchResults.length - 1 ? `1px solid ${alpha(theme.palette.divider, 0.05)}` : "none",
                                "&:hover": {
                                  bgcolor: alpha(result.color, 0.08),
                                },
                              }}
                            >
                              <Box sx={{ flex: 1 }}>
                                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                                    {result.title}
                                  </Typography>
                                  <Chip
                                    label={`${result.categoryEmoji} ${result.category}`}
                                    size="small"
                                    sx={{
                                      height: 20,
                                      fontSize: "0.65rem",
                                      bgcolor: alpha(result.categoryColor, 0.1),
                                      color: result.categoryColor,
                                    }}
                                  />
                                </Box>
                                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
                                  {result.description.length > 80
                                    ? result.description.substring(0, 80) + "..."
                                    : result.description}
                                </Typography>
                                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                                  {result.tags.slice(0, 3).map((tag) => (
                                    <Chip
                                      key={tag}
                                      label={tag}
                                      size="small"
                                      sx={{
                                        height: 18,
                                        fontSize: "0.6rem",
                                        bgcolor: alpha(result.color, 0.08),
                                        color: result.color,
                                      }}
                                    />
                                  ))}
                                </Box>
                              </Box>
                              <ArrowForwardIcon sx={{ color: "text.secondary", fontSize: 18 }} />
                            </ListItemButton>
                          </ListItem>
                        ))}
                      </List>
                    </Paper>
                  </Fade>
                )}
              </Popper>

              {/* No results message */}
              <Popper
                open={searchFocused && searchQuery.length > 0 && searchResults.length === 0}
                anchorEl={searchAnchorRef.current}
                placement="bottom-start"
                transition
                style={{ zIndex: 1300, width: searchAnchorRef.current?.offsetWidth }}
              >
                {({ TransitionProps }) => (
                  <Fade {...TransitionProps} timeout={200}>
                    <Paper
                      sx={{
                        mt: 1,
                        p: 3,
                        borderRadius: 3,
                        textAlign: "center",
                        boxShadow: `0 8px 32px ${alpha(theme.palette.common.black, 0.15)}`,
                      }}
                    >
                      <Typography variant="body2" color="text.secondary">
                        No results found for "{searchQuery}"
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Try different keywords or browse categories below
                      </Typography>
                    </Paper>
                  </Fade>
                )}
              </Popper>
            </Box>
          </Box>

          {/* Quick Access to Tool Hubs */}
          <Paper
            elevation={0}
            sx={{
              p: 3,
              mb: 4,
              borderRadius: 3,
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.secondary.main, 0.05)} 100%)`,
              border: `1px solid ${alpha(theme.palette.primary.main, 0.1)}`,
            }}
          >
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <RocketLaunchIcon sx={{ color: theme.palette.primary.main }} />
              Quick Access to Tool Hubs
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={4}>
                <Card
                  sx={{
                    cursor: "pointer",
                    transition: "all 0.2s ease",
                    border: `1px solid ${alpha("#6366f1", 0.2)}`,
                    "&:hover": {
                      transform: "translateY(-2px)",
                      boxShadow: `0 4px 20px ${alpha("#6366f1", 0.2)}`,
                      borderColor: "#6366f1",
                    },
                  }}
                  onClick={() => navigate("/")}
                >
                  <CardActionArea sx={{ p: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Box
                        sx={{
                          width: 48,
                          height: 48,
                          borderRadius: 2,
                          bgcolor: alpha("#6366f1", 0.1),
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                        }}
                      >
                        <FolderSpecialIcon sx={{ fontSize: 28, color: "#6366f1" }} />
                      </Box>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                          Projects
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Manage & scan your repositories
                        </Typography>
                      </Box>
                    </Box>
                  </CardActionArea>
                </Card>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Card
                  sx={{
                    cursor: "pointer",
                    transition: "all 0.2s ease",
                    border: `1px solid ${alpha("#0ea5e9", 0.2)}`,
                    "&:hover": {
                      transform: "translateY(-2px)",
                      boxShadow: `0 4px 20px ${alpha("#0ea5e9", 0.2)}`,
                      borderColor: "#0ea5e9",
                    },
                  }}
                  onClick={() => navigate("/network")}
                >
                  <CardActionArea sx={{ p: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Box
                        sx={{
                          width: 48,
                          height: 48,
                          borderRadius: 2,
                          bgcolor: alpha("#0ea5e9", 0.1),
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                        }}
                      >
                        <HubIcon sx={{ fontSize: 28, color: "#0ea5e9" }} />
                      </Box>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                          Network Analysis Hub
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Nmap, PCAP, SSL, DNS, API Tester
                        </Typography>
                      </Box>
                    </Box>
                  </CardActionArea>
                </Card>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Card
                  sx={{
                    cursor: "pointer",
                    transition: "all 0.2s ease",
                    border: `1px solid ${alpha("#a855f7", 0.2)}`,
                    "&:hover": {
                      transform: "translateY(-2px)",
                      boxShadow: `0 4px 20px ${alpha("#a855f7", 0.2)}`,
                      borderColor: "#a855f7",
                    },
                  }}
                  onClick={() => navigate("/reverse")}
                >
                  <CardActionArea sx={{ p: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Box
                        sx={{
                          width: 48,
                          height: 48,
                          borderRadius: 2,
                          bgcolor: alpha("#a855f7", 0.1),
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                        }}
                      >
                        <BuildIcon sx={{ fontSize: 28, color: "#a855f7" }} />
                      </Box>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                          Reverse Engineering Hub
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          APK, Binary, Docker analysis
                        </Typography>
                      </Box>
                    </Box>
                  </CardActionArea>
                </Card>
              </Grid>
            </Grid>
          </Paper>

          {/* Quick Jump Chips - Horizontal scroll on mobile */}
          <Box
            sx={{
              mb: 3,
              display: "flex",
              gap: 1,
              flexWrap: { xs: "nowrap", md: "wrap" },
              overflowX: { xs: "auto", md: "visible" },
              pb: { xs: 1, md: 0 },
              justifyContent: { md: "center" },
              "&::-webkit-scrollbar": { height: 4 },
              "&::-webkit-scrollbar-thumb": {
                bgcolor: alpha(theme.palette.primary.main, 0.2),
                borderRadius: 2,
              },
            }}
          >
            {allCategories.map((category) => (
              <Chip
                key={category.id}
                label={`${category.emoji} ${category.title}`}
                clickable
                onClick={() => scrollToCategory(category.id)}
                sx={{
                  fontWeight: 600,
                  flexShrink: 0,
                  borderColor: activeSection === category.id ? category.color : alpha(category.color, 0.3),
                  bgcolor: activeSection === category.id ? alpha(category.color, 0.15) : alpha(category.color, 0.05),
                  color: activeSection === category.id ? category.color : "text.primary",
                  transition: "all 0.2s ease",
                  "&:hover": {
                    bgcolor: alpha(category.color, 0.15),
                    borderColor: category.color,
                  },
                }}
                variant="outlined"
              />
            ))}
          </Box>

      {/* Stats Bar */}
      <Paper
        sx={{
          p: 3,
          mb: 4,
          borderRadius: 3,
          display: "flex",
          justifyContent: "center",
          flexWrap: "wrap",
          gap: 4,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.03)}, ${alpha(theme.palette.secondary.main, 0.03)})`,
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        {[
          { value: allCategories.length.toString(), label: "Categories" },
          { value: totalCards.toString(), label: "Learning Topics" },
          { value: "120+", label: "Glossary Terms" },
          { value: "200+", label: "Commands" },
        ].map((stat, i) => (
          <Box key={i} sx={{ textAlign: "center", minWidth: 100 }}>
            <Typography variant="h4" sx={{ fontWeight: 800, color: "primary.main" }}>
              {stat.value}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {stat.label}
            </Typography>
          </Box>
        ))}
      </Paper>

      {/* Category Filter */}
      <Paper
        sx={{
          mb: 4,
          borderRadius: 3,
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          overflow: "hidden",
        }}
      >
        <Box
          onClick={() => setFilterExpanded(!filterExpanded)}
          sx={{
            p: 2,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            cursor: "pointer",
            background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.05)}, ${alpha(theme.palette.primary.main, 0.03)})`,
            "&:hover": {
              background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.08)}, ${alpha(theme.palette.primary.main, 0.05)})`,
            },
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <Badge badgeContent={visibleCount} color="primary">
              <FilterListIcon sx={{ color: "primary.main" }} />
            </Badge>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
              Category Filter
            </Typography>
            <Typography variant="body2" color="text.secondary">
              ({visibleCards} of {totalCards} topics visible)
            </Typography>
          </Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Tooltip title="Show All">
              <IconButton
                size="small"
                onClick={(e) => {
                  e.stopPropagation();
                  handleShowAll();
                }}
              >
                <VisibilityIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <Tooltip title="Hide All">
              <IconButton
                size="small"
                onClick={(e) => {
                  e.stopPropagation();
                  handleHideAll();
                }}
              >
                <VisibilityOffIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            {filterExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </Box>
        </Box>
        <Collapse in={filterExpanded}>
          <Box sx={{ p: 2, borderTop: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <FormGroup row sx={{ gap: 1, flexWrap: "wrap" }}>
              {allCategories.map((category) => (
                <FormControlLabel
                  key={category.id}
                  control={
                    <Checkbox
                      checked={visibleCategories[category.id]}
                      onChange={() => handleToggleCategory(category.id)}
                      sx={{
                        color: category.color,
                        "&.Mui-checked": { color: category.color },
                      }}
                    />
                  }
                  label={
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                      <Typography variant="body2">{category.emoji}</Typography>
                      <Typography variant="body2">{category.title}</Typography>
                      <Chip
                        label={category.cards.length}
                        size="small"
                        sx={{
                          height: 18,
                          fontSize: "0.65rem",
                          ml: 0.5,
                          bgcolor: alpha(category.color, 0.1),
                          color: category.color,
                        }}
                      />
                    </Box>
                  }
                  sx={{
                    mr: 2,
                    mb: 1,
                    p: 0.5,
                    borderRadius: 1,
                    border: `1px solid ${alpha(category.color, visibleCategories[category.id] ? 0.3 : 0.1)}`,
                    bgcolor: visibleCategories[category.id] ? alpha(category.color, 0.05) : "transparent",
                    transition: "all 0.2s ease",
                  }}
                />
              ))}
            </FormGroup>
          </Box>
        </Collapse>
      </Paper>

      {/* Category Sections */}
      {allCategories.map((category, index) => (
        <Collapse key={category.id} in={visibleCategories[category.id]}>
          <Box id={`category-${category.id}`} sx={{ mb: 6, scrollMarginTop: 100 }}>
            <Paper
              sx={{
                p: 3,
                mb: 3,
                borderRadius: 3,
                background: `linear-gradient(135deg, ${alpha(category.color, 0.1)}, ${alpha(category.gradientEnd, 0.05)})`,
                border: `1px solid ${alpha(category.color, 0.2)}`,
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <Box sx={{ color: category.color }}>{category.icon}</Box>
                <Typography variant="h5" sx={{ fontWeight: 700 }}>
                  {category.emoji} {category.title}
                </Typography>
                <Chip
                  label={`${category.cards.length} topics`}
                  size="small"
                  sx={{
                    bgcolor: alpha(category.color, 0.15),
                    color: category.color,
                    fontWeight: 600,
                  }}
                />
              </Box>
              <Typography variant="body2" color="text.secondary">
                {category.description}
              </Typography>
            </Paper>
            
            <CardGrid 
              cards={category.cards} 
              columns={category.cards.length <= 3 ? { xs: 12, sm: 6, md: 4, lg: 4 } : { xs: 12, sm: 6, md: 4, lg: 3 }}
              centered={category.cards.length === 2}
            />
          </Box>
          
          {index < allCategories.length - 1 && visibleCategories[allCategories[index + 1]?.id] && (
            <Divider sx={{ my: 5 }} />
          )}
        </Collapse>
      ))}

      {/* No Categories Message */}
      {visibleCount === 0 && (
        <Paper
          sx={{
            p: 6,
            textAlign: "center",
            borderRadius: 3,
            border: `1px dashed ${alpha(theme.palette.divider, 0.3)}`,
          }}
        >
          <VisibilityOffIcon sx={{ fontSize: 60, color: "text.disabled", mb: 2 }} />
          <Typography variant="h6" color="text.secondary" sx={{ mb: 2 }}>
            All categories are hidden
          </Typography>
          <Chip
            label="Show All Categories"
            clickable
            onClick={handleShowAll}
            sx={{
              bgcolor: "primary.main",
              color: "white",
              fontWeight: 600,
              "&:hover": { bgcolor: "primary.dark" },
            }}
          />
        </Paper>
      )}

      {/* Footer CTA */}
      <Paper
        sx={{
          mt: 6,
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.05)}, ${alpha(theme.palette.success.main, 0.05)})`,
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
          🚀 Ready to Scan Your Code?
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Now that you understand how VRAgent works, start scanning your projects for vulnerabilities.
        </Typography>
        <Chip
          label="Go to Projects →"
          clickable
          onClick={() => navigate("/")}
          sx={{
            bgcolor: "primary.main",
            color: "white",
            fontWeight: 600,
            px: 2,
            "&:hover": { bgcolor: "primary.dark" },
          }}
        />
      </Paper>
        </Container>
      </Box>

      {/* Floating Action Buttons */}
      {/* Quick Nav Button - only on smaller screens */}
      {!isLargeScreen && (
        <Tooltip title="Quick Navigation" placement="left">
          <Fab
            color="primary"
            size="medium"
            onClick={() => setQuickNavOpen(true)}
            sx={{
              position: "fixed",
              bottom: 90,
              right: 20,
              zIndex: 1000,
              boxShadow: `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`,
            }}
          >
            <ListAltIcon />
          </Fab>
        </Tooltip>
      )}

      {/* Back to Top Button */}
      <Zoom in={showBackToTop}>
        <Tooltip title="Back to Top" placement="left">
          <Fab
            color="secondary"
            size="small"
            onClick={scrollToTop}
            sx={{
              position: "fixed",
              bottom: 20,
              right: 20,
              zIndex: 1000,
              boxShadow: `0 4px 20px ${alpha(theme.palette.secondary.main, 0.4)}`,
            }}
          >
            <KeyboardArrowUpIcon />
          </Fab>
        </Tooltip>
      </Zoom>
    </LearnPageLayout>
  );
}
