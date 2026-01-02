import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  IconButton,
  Chip,
  Grid,
  Tabs,
  Tab,
  TextField,
  InputAdornment,
  Link,
  Card,
  CardContent,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Button,
} from "@mui/material";
import { useState, useMemo } from "react";
import { Link as RouterLink, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SearchIcon from "@mui/icons-material/Search";
import LaunchIcon from "@mui/icons-material/Launch";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import TrendingDownIcon from "@mui/icons-material/TrendingDown";
import TrendingFlatIcon from "@mui/icons-material/TrendingFlat";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import SecurityIcon from "@mui/icons-material/Security";
import QuizIcon from "@mui/icons-material/Quiz";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

// Page context for AI chat
const pageContext = `This is a comprehensive Cyber Threat Intelligence (CTI) page covering:

1. Threat Actors Database:
- Nation-State APT groups (APT28, APT29, Lazarus Group, APT41, Hafnium, etc.)
- Ransomware Groups (LockBit, BlackCat/ALPHV, Cl0p, Wizard Spider, etc.)
- Cybercrime Organizations (FIN7, Evil Corp, Scattered Spider)
- Hacktivists and their campaigns
- Actor profiles with TTPs, tools, targets, and notable campaigns

2. CTI Methodology & Frameworks:
- Intelligence Cycle (Direction, Collection, Processing, Analysis, Dissemination)
- Diamond Model of Intrusion Analysis
- Attribution Confidence Levels
- STIX & TAXII Standards
- Traffic Light Protocol (TLP)
- Admiralty Code for source reliability
- Cognitive Biases in Analysis
- Analysis Techniques (ACH, Link Analysis, etc.)

3. IOCs & MITRE ATT&CK:
- Indicator of Compromise types (Hashes, IPs, Domains, URLs, etc.)
- MITRE ATT&CK Tactics and Techniques
- Common Malware Families
- Pyramid of Pain concept

4. Threat Landscape (2024-2025):
- Current threat trends and statistics
- Emerging threats (AI-powered attacks, supply chain, identity attacks)
- Geopolitical cyber context (Ukraine, China-Taiwan, Middle East, DPRK)

5. Tracking & Tools:
- Tracking methods and pivot techniques
- Intelligence sources (free and commercial)
- Government CTI resources

6. Defensive Intelligence:
- Defensive recommendations by actor type
- Detection priority matrix
- Incident response quick reference
- Threat hunting hypotheses`;
import {
  actorCategories,
  ctiMethodology,
  tlpLevels,
  admiraltyCode,
  biases,
  trackingMethods,
  pivotTechniques,
  iocTypes,
  mitreTactics,
  intelligenceSources,
  analysisTechniques,
  threatLandscape,
  attributionConfidence,
  malwareFamilies,
  defensiveRecommendations,
  reportTemplates,
} from "../data/ctiData";

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#dc2626";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "Cyber threat intelligence (CTI) is best described as:",
    options: [
      "A list of antivirus vendors",
      "Evidence-based knowledge about threats used to reduce risk",
      "A firewall configuration",
      "A vulnerability scan report",
    ],
    correctAnswer: 1,
    explanation: "CTI focuses on evidence-based insights that support decisions and defenses.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "The intelligence cycle follows which order?",
    options: [
      "Analysis, Dissemination, Collection, Processing, Direction",
      "Direction, Collection, Processing, Analysis, Dissemination",
      "Collection, Direction, Dissemination, Analysis, Processing",
      "Processing, Collection, Dissemination, Direction, Analysis",
    ],
    correctAnswer: 1,
    explanation: "The standard order is direction, collection, processing, analysis, dissemination.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "Strategic intelligence primarily focuses on:",
    options: [
      "Immediate IOCs for blocking",
      "Long-term trends and business risk",
      "Exploit development",
      "Packet capture analysis",
    ],
    correctAnswer: 1,
    explanation: "Strategic intel informs leadership decisions and long-term planning.",
  },
  {
    id: 4,
    topic: "Fundamentals",
    question: "Tactical intelligence commonly includes:",
    options: [
      "Budget forecasts",
      "Hash values, IPs, and domains",
      "Annual strategy reports",
      "Vendor contracts",
    ],
    correctAnswer: 1,
    explanation: "Tactical intel focuses on indicators used for detection and blocking.",
  },
  {
    id: 5,
    topic: "Fundamentals",
    question: "Operational intelligence is most concerned with:",
    options: [
      "Campaign details and adversary procedures",
      "Only malware hashes",
      "Company financials",
      "Static firewall rules",
    ],
    correctAnswer: 0,
    explanation: "Operational intel covers how and when attackers operate in campaigns.",
  },
  {
    id: 6,
    topic: "Fundamentals",
    question: "An IOC is:",
    options: [
      "A behavior indicating an attack in progress",
      "An artifact that indicates a potential compromise",
      "A legal approval for monitoring",
      "A user authentication token",
    ],
    correctAnswer: 1,
    explanation: "IOCs are artifacts like hashes, IPs, or domains linked to compromise.",
  },
  {
    id: 7,
    topic: "Fundamentals",
    question: "TTP stands for:",
    options: [
      "Tools, Tactics, Plans",
      "Tactics, Techniques, and Procedures",
      "Threat Tracking Protocol",
      "Telemetry Transfer Process",
    ],
    correctAnswer: 1,
    explanation: "TTPs describe how adversaries operate.",
  },
  {
    id: 8,
    topic: "Fundamentals",
    question: "MITRE ATT&CK is:",
    options: [
      "A vulnerability scanner",
      "A knowledge base of adversary tactics and techniques",
      "An antivirus engine",
      "A network firewall",
    ],
    correctAnswer: 1,
    explanation: "ATT&CK documents real-world adversary behaviors.",
  },
  {
    id: 9,
    topic: "Fundamentals",
    question: "The Cyber Kill Chain includes which stage?",
    options: ["Encryption", "Weaponization", "Patch management", "Service discovery"],
    correctAnswer: 1,
    explanation: "Weaponization is a standard kill chain stage.",
  },
  {
    id: 10,
    topic: "Fundamentals",
    question: "The Diamond Model focuses on relationships between:",
    options: [
      "Users, passwords, and tokens",
      "Adversary, capability, infrastructure, and victim",
      "Servers, clients, and routers",
      "Policies, audits, and controls",
    ],
    correctAnswer: 1,
    explanation: "The Diamond Model links adversary, capability, infrastructure, and victim.",
  },
  {
    id: 11,
    topic: "Standards",
    question: "STIX is used to:",
    options: [
      "Encrypt files",
      "Structure and represent threat intelligence",
      "Scan endpoints",
      "Block web traffic",
    ],
    correctAnswer: 1,
    explanation: "STIX standardizes the representation of threat intel data.",
  },
  {
    id: 12,
    topic: "Standards",
    question: "TAXII provides:",
    options: [
      "Transport for sharing threat intelligence",
      "A malware sandbox",
      "A cryptographic algorithm",
      "A password manager",
    ],
    correctAnswer: 0,
    explanation: "TAXII is the transport mechanism for sharing STIX data.",
  },
  {
    id: 13,
    topic: "Standards",
    question: "TLP Red means:",
    options: [
      "Share freely",
      "Share within community",
      "Share only with named recipients",
      "Share with vendors only",
    ],
    correctAnswer: 2,
    explanation: "TLP Red is the most restrictive and limited to named recipients.",
  },
  {
    id: 14,
    topic: "Standards",
    question: "TLP Amber indicates:",
    options: [
      "Public information",
      "Limited sharing within an organization and trusted partners",
      "Share on social media",
      "No sharing restrictions",
    ],
    correctAnswer: 1,
    explanation: "Amber restricts sharing to need-to-know recipients.",
  },
  {
    id: 15,
    topic: "Standards",
    question: "TLP Green typically allows sharing with:",
    options: [
      "The general public",
      "The broader community but not publicly",
      "Only one analyst",
      "No one",
    ],
    correctAnswer: 1,
    explanation: "Green allows limited community sharing but not public release.",
  },
  {
    id: 16,
    topic: "Standards",
    question: "TLP White (or Clear) means:",
    options: [
      "Share freely without restrictions",
      "Do not share at all",
      "Share only with vendors",
      "Share only with law enforcement",
    ],
    correctAnswer: 0,
    explanation: "White/Clear allows unrestricted sharing.",
  },
  {
    id: 17,
    topic: "Standards",
    question: "The Admiralty Code is used for:",
    options: [
      "Ranking malware families",
      "Rating source reliability and information credibility",
      "Classifying vulnerabilities",
      "Encoding indicators",
    ],
    correctAnswer: 1,
    explanation: "Admiralty Code combines source reliability with info credibility.",
  },
  {
    id: 18,
    topic: "Standards",
    question: "In the Admiralty Code, an A1 rating means:",
    options: [
      "Unreliable source, unlikely info",
      "Reliable source, confirmed information",
      "Unknown source, possible info",
      "Reliable source, false info",
    ],
    correctAnswer: 1,
    explanation: "A1 indicates a reliable source and confirmed information.",
  },
  {
    id: 19,
    topic: "Standards",
    question: "MISP is best described as:",
    options: [
      "A threat intelligence sharing platform",
      "A password vault",
      "A backup system",
      "A firewall",
    ],
    correctAnswer: 0,
    explanation: "MISP supports sharing and managing threat intelligence.",
  },
  {
    id: 20,
    topic: "Standards",
    question: "Traffic Light Protocol is used to:",
    options: [
      "Measure network latency",
      "Control handling and sharing of intelligence",
      "Encrypt communications",
      "Detect phishing",
    ],
    correctAnswer: 1,
    explanation: "TLP provides handling guidance for information sharing.",
  },
  {
    id: 21,
    topic: "Sources",
    question: "OSINT stands for:",
    options: [
      "Open Source Intelligence",
      "Operational Security Intelligence",
      "Outbound System Integration",
      "Online Security Intercepts",
    ],
    correctAnswer: 0,
    explanation: "OSINT comes from publicly available sources.",
  },
  {
    id: 22,
    topic: "Sources",
    question: "HUMINT refers to:",
    options: [
      "Human intelligence from people or insiders",
      "Hardware monitoring",
      "HTTP metadata",
      "Hypervisor telemetry",
    ],
    correctAnswer: 0,
    explanation: "HUMINT is intelligence gathered from human sources.",
  },
  {
    id: 23,
    topic: "Sources",
    question: "SIGINT refers to:",
    options: [
      "Signals and communications intelligence",
      "Signature-based antivirus",
      "Security information goals",
      "System integrity metrics",
    ],
    correctAnswer: 0,
    explanation: "SIGINT focuses on signals and communications data.",
  },
  {
    id: 24,
    topic: "Sources",
    question: "A common internal telemetry source for CTI is:",
    options: [
      "EDR and SIEM logs",
      "Employee badge data only",
      "Printer queues",
      "Desktop wallpapers",
    ],
    correctAnswer: 0,
    explanation: "EDR and SIEM data are core sources for threat intelligence.",
  },
  {
    id: 25,
    topic: "Sources",
    question: "Malware sandboxing helps by providing:",
    options: [
      "Behavioral indicators and artifacts",
      "Only file sizes",
      "Only password hashes",
      "Only DNS records",
    ],
    correctAnswer: 0,
    explanation: "Sandboxes reveal behavior such as network calls and file changes.",
  },
  {
    id: 26,
    topic: "Sources",
    question: "Sinkhole data is useful for:",
    options: [
      "Identifying victims and infected hosts",
      "Creating backups",
      "Encrypting traffic",
      "Blocking phishing emails",
    ],
    correctAnswer: 0,
    explanation: "Sinkholes collect connections from infected hosts.",
  },
  {
    id: 27,
    topic: "Sources",
    question: "Honeypots are used to:",
    options: [
      "Attract attackers and observe behavior",
      "Patch systems",
      "Replace firewalls",
      "Store backups",
    ],
    correctAnswer: 0,
    explanation: "Honeypots provide intelligence on attacker tactics.",
  },
  {
    id: 28,
    topic: "Sources",
    question: "Passive DNS is helpful for:",
    options: [
      "Historical domain to IP resolution tracking",
      "Blocking malware locally",
      "Encrypting DNS queries",
      "Scanning ports",
    ],
    correctAnswer: 0,
    explanation: "Passive DNS reveals historical infrastructure relationships.",
  },
  {
    id: 29,
    topic: "Sources",
    question: "A threat feed is:",
    options: [
      "A streaming source of indicators and intel",
      "A firewall rule set",
      "A data backup service",
      "An antivirus quarantine",
    ],
    correctAnswer: 0,
    explanation: "Feeds deliver indicators or intel for automated use.",
  },
  {
    id: 30,
    topic: "Sources",
    question: "Collection requirements should be driven by:",
    options: [
      "Stakeholder questions and decisions",
      "Random sampling",
      "Only vendor recommendations",
      "Available storage space",
    ],
    correctAnswer: 0,
    explanation: "Requirements define what intel is needed to make decisions.",
  },
  {
    id: 31,
    topic: "Analysis",
    question: "ACH stands for:",
    options: [
      "Analysis of Competing Hypotheses",
      "Automated Correlation Hub",
      "Adversary Chain History",
      "Advanced Cyber Heuristics",
    ],
    correctAnswer: 0,
    explanation: "ACH is a structured method to reduce bias in analysis.",
  },
  {
    id: 32,
    topic: "Analysis",
    question: "Link analysis is used to:",
    options: [
      "Identify relationships between entities",
      "Encrypt intel reports",
      "Scan file hashes",
      "Configure proxies",
    ],
    correctAnswer: 0,
    explanation: "Link analysis connects actors, infrastructure, and events.",
  },
  {
    id: 33,
    topic: "Analysis",
    question: "Mapping behaviors to the Kill Chain helps:",
    options: [
      "Identify attack stages and control gaps",
      "Increase password complexity",
      "Compress logs",
      "Speed up scanning",
    ],
    correctAnswer: 0,
    explanation: "Kill Chain mapping highlights where defenses can break the chain.",
  },
  {
    id: 34,
    topic: "Analysis",
    question: "The top of the Pyramid of Pain represents:",
    options: ["File hashes", "IP addresses", "TTPs", "Domains"],
    correctAnswer: 2,
    explanation: "TTPs are hardest for adversaries to change.",
  },
  {
    id: 35,
    topic: "Analysis",
    question: "The bottom of the Pyramid of Pain represents:",
    options: ["TTPs", "Tools", "File hashes", "Network patterns"],
    correctAnswer: 2,
    explanation: "Hashes are easy for attackers to change.",
  },
  {
    id: 36,
    topic: "Analysis",
    question: "Confirmation bias is:",
    options: [
      "Favoring evidence that supports existing beliefs",
      "Testing multiple hypotheses",
      "Ignoring all prior context",
      "A method for sharing intel",
    ],
    correctAnswer: 0,
    explanation: "Confirmation bias can skew analysis toward expected outcomes.",
  },
  {
    id: 37,
    topic: "Analysis",
    question: "Anchoring bias occurs when analysts:",
    options: [
      "Rely too heavily on the first piece of information",
      "Ignore all evidence",
      "Only use automated tools",
      "Share data publicly",
    ],
    correctAnswer: 0,
    explanation: "Anchoring bias overweights initial information.",
  },
  {
    id: 38,
    topic: "Analysis",
    question: "Confidence levels should be based on:",
    options: [
      "Source reliability and corroboration",
      "Personal opinions",
      "Number of pages in the report",
      "Vendor branding",
    ],
    correctAnswer: 0,
    explanation: "Higher confidence requires reliable, corroborated evidence.",
  },
  {
    id: 39,
    topic: "Analysis",
    question: "Attribution should be made when:",
    options: [
      "Multiple independent lines of evidence align",
      "One IP address matches",
      "The malware name is familiar",
      "A single tweet claims it",
    ],
    correctAnswer: 0,
    explanation: "Attribution needs multiple corroborated indicators.",
  },
  {
    id: 40,
    topic: "Analysis",
    question: "A common attribution pitfall is:",
    options: [
      "Infrastructure reuse by multiple actors",
      "Using timelines",
      "Documenting sources",
      "Validating evidence",
    ],
    correctAnswer: 0,
    explanation: "Shared infrastructure can mislead attribution.",
  },
  {
    id: 41,
    topic: "Indicators",
    question: "Which is an example of an IOC?",
    options: [
      "Process injection behavior",
      "A file hash tied to malware",
      "A phishing tactic",
      "User awareness training",
    ],
    correctAnswer: 1,
    explanation: "File hashes are classic indicators of compromise.",
  },
  {
    id: 42,
    topic: "Indicators",
    question: "Which is an example of an IOA?",
    options: [
      "Suspicious PowerShell execution pattern",
      "A static IP address",
      "A file hash",
      "A domain registration record",
    ],
    correctAnswer: 0,
    explanation: "IOAs describe behaviors that indicate an attack in progress.",
  },
  {
    id: 43,
    topic: "Indicators",
    question: "High-fidelity indicators are those that:",
    options: [
      "Generate low false positives",
      "Are easy for attackers to change",
      "Never expire",
      "Only appear in reports",
    ],
    correctAnswer: 0,
    explanation: "High-fidelity indicators are reliable and specific.",
  },
  {
    id: 44,
    topic: "Indicators",
    question: "Low-fidelity indicators often:",
    options: [
      "Produce many false positives",
      "Are always unique",
      "Never overlap with benign activity",
      "Replace TTP analysis",
    ],
    correctAnswer: 0,
    explanation: "Low-fidelity indicators can be noisy.",
  },
  {
    id: 45,
    topic: "Indicators",
    question: "Enrichment adds value to indicators by:",
    options: [
      "Adding context like WHOIS, geolocation, or reputation",
      "Removing context entirely",
      "Encrypting the indicator",
      "Shortening the indicator",
    ],
    correctAnswer: 0,
    explanation: "Context helps analysts assess relevance and risk.",
  },
  {
    id: 46,
    topic: "Indicators",
    question: "Indicator decay means:",
    options: [
      "Indicators lose usefulness over time",
      "Indicators never expire",
      "Indicators become more reliable",
      "Indicators are encrypted",
    ],
    correctAnswer: 0,
    explanation: "Indicators can become outdated as adversaries change infrastructure.",
  },
  {
    id: 47,
    topic: "Indicators",
    question: "Which is generally harder for attackers to change?",
    options: ["File hash", "IP address", "TTPs", "Domain name"],
    correctAnswer: 2,
    explanation: "TTPs are more durable than specific infrastructure.",
  },
  {
    id: 48,
    topic: "Indicators",
    question: "Detection engineering uses CTI to:",
    options: [
      "Create detections and rules from intel",
      "Reduce log storage",
      "Disable monitoring",
      "Replace incident response",
    ],
    correctAnswer: 0,
    explanation: "CTI can be translated into detection logic.",
  },
  {
    id: 49,
    topic: "Indicators",
    question: "YARA rules are primarily used for:",
    options: [
      "Pattern matching in files or memory",
      "DNS resolution",
      "Port scanning",
      "Packet filtering",
    ],
    correctAnswer: 0,
    explanation: "YARA identifies patterns in files and memory.",
  },
  {
    id: 50,
    topic: "Indicators",
    question: "Sigma rules are designed for:",
    options: [
      "SIEM detection portability",
      "Encryption",
      "Network routing",
      "Endpoint isolation",
    ],
    correctAnswer: 0,
    explanation: "Sigma provides a generic rule format for SIEM detections.",
  },
  {
    id: 51,
    topic: "Reporting",
    question: "An executive summary should be:",
    options: [
      "Highly technical and long",
      "Concise and focused on impact and actions",
      "Only a list of IPs",
      "A dump of log files",
    ],
    correctAnswer: 1,
    explanation: "Executives need concise impact and recommendations.",
  },
  {
    id: 52,
    topic: "Reporting",
    question: "An intelligence requirement is:",
    options: [
      "A question that intelligence must answer",
      "A malware signature",
      "A firewall rule",
      "A backup policy",
    ],
    correctAnswer: 0,
    explanation: "Requirements define what information stakeholders need.",
  },
  {
    id: 53,
    topic: "Reporting",
    question: "A collection plan outlines:",
    options: [
      "Sources, methods, and timing for gathering intel",
      "Only the final report format",
      "Employee job roles",
      "Patch schedules",
    ],
    correctAnswer: 0,
    explanation: "Collection plans map where and how intel will be gathered.",
  },
  {
    id: 54,
    topic: "Reporting",
    question: "Dissemination means:",
    options: [
      "Sharing intelligence with the right audience",
      "Deleting indicators",
      "Encrypting logs",
      "Blocking a domain",
    ],
    correctAnswer: 0,
    explanation: "Dissemination is the distribution of intelligence outputs.",
  },
  {
    id: 55,
    topic: "Reporting",
    question: "Actionable intelligence should include:",
    options: [
      "Recommended actions or decisions",
      "Only raw data",
      "No context",
      "Only screenshots",
    ],
    correctAnswer: 0,
    explanation: "Actionable intel informs a decision or response.",
  },
  {
    id: 56,
    topic: "Reporting",
    question: "Confidence scores help consumers:",
    options: [
      "Understand how much to trust the assessment",
      "Ignore the report",
      "Increase data volume",
      "Delete logs",
    ],
    correctAnswer: 0,
    explanation: "Confidence communicates evidence strength.",
  },
  {
    id: 57,
    topic: "Reporting",
    question: "The feedback loop in the intel cycle is used to:",
    options: [
      "Refine requirements and improve future reporting",
      "Replace collection",
      "Delete intelligence",
      "Stop dissemination",
    ],
    correctAnswer: 0,
    explanation: "Feedback helps improve future intelligence outputs.",
  },
  {
    id: 58,
    topic: "Reporting",
    question: "Audience-specific reporting means:",
    options: [
      "Tailoring detail and language to the audience",
      "Using the same report for everyone",
      "Removing context",
      "Only using charts",
    ],
    correctAnswer: 0,
    explanation: "Different stakeholders require different levels of detail.",
  },
  {
    id: 59,
    topic: "Reporting",
    question: "STIX and TAXII automation mainly improves:",
    options: [
      "Machine-readable sharing and processing",
      "Password strength",
      "Endpoint performance",
      "Disk encryption",
    ],
    correctAnswer: 0,
    explanation: "Automation supports faster, standardized sharing.",
  },
  {
    id: 60,
    topic: "Reporting",
    question: "TLP markings should be:",
    options: [
      "Preserved when sharing intelligence",
      "Removed to simplify reports",
      "Ignored by recipients",
      "Replaced with colors not in the standard",
    ],
    correctAnswer: 0,
    explanation: "Handling instructions must remain intact.",
  },
  {
    id: 61,
    topic: "Operational Use",
    question: "Strategic intelligence is used for:",
    options: [
      "Long-term risk and investment decisions",
      "Immediate blocking rules",
      "Regex tuning",
      "Endpoint isolation",
    ],
    correctAnswer: 0,
    explanation: "Strategic intel supports leadership and planning.",
  },
  {
    id: 62,
    topic: "Operational Use",
    question: "Tactical intelligence is used for:",
    options: [
      "Immediate detection and response actions",
      "Long-term budgeting",
      "Vendor contract reviews",
      "Security awareness posters",
    ],
    correctAnswer: 0,
    explanation: "Tactical intel helps defenders take quick action.",
  },
  {
    id: 63,
    topic: "Operational Use",
    question: "Operational intelligence supports:",
    options: [
      "Campaign tracking and adversary tradecraft",
      "Only hash blocking",
      "Printer maintenance",
      "Firewall firmware updates",
    ],
    correctAnswer: 0,
    explanation: "Operational intel provides mid-term campaign context.",
  },
  {
    id: 64,
    topic: "Operational Use",
    question: "Threat hunting hypotheses are:",
    options: [
      "Testable ideas based on known adversary behavior",
      "Random searches without focus",
      "Backups of logs",
      "Public press releases",
    ],
    correctAnswer: 0,
    explanation: "Hunting uses hypotheses to guide focused searches.",
  },
  {
    id: 65,
    topic: "Operational Use",
    question: "Mapping detections to MITRE ATT&CK helps:",
    options: [
      "Standardize coverage and identify gaps",
      "Hide detection logic",
      "Increase alert noise",
      "Replace incident response",
    ],
    correctAnswer: 0,
    explanation: "ATT&CK mapping shows coverage and missing techniques.",
  },
  {
    id: 66,
    topic: "Operational Use",
    question: "A detection priority matrix is used to:",
    options: [
      "Focus monitoring on high-risk techniques",
      "Choose antivirus vendors",
      "Compress logs",
      "Block all traffic",
    ],
    correctAnswer: 0,
    explanation: "It guides where to focus detection investment.",
  },
  {
    id: 67,
    topic: "Operational Use",
    question: "Actor profiling typically includes:",
    options: [
      "Motivation, targets, capabilities, and tools",
      "Only the malware hash",
      "Only the country name",
      "Only CVE lists",
    ],
    correctAnswer: 0,
    explanation: "Profiles summarize actor behavior and objectives.",
  },
  {
    id: 68,
    topic: "Operational Use",
    question: "Infrastructure overlap can indicate:",
    options: [
      "Related campaigns or shared tooling",
      "Improved password strength",
      "A clean system",
      "No meaningful relationship",
    ],
    correctAnswer: 0,
    explanation: "Shared infrastructure can link activity clusters.",
  },
  {
    id: 69,
    topic: "Operational Use",
    question: "A key attribution pitfall is:",
    options: [
      "Assuming tool reuse proves identity",
      "Using multiple sources",
      "Validating evidence",
      "Documenting confidence",
    ],
    correctAnswer: 0,
    explanation: "Tools can be reused or shared by different actors.",
  },
  {
    id: 70,
    topic: "Operational Use",
    question: "Sharing IOCs without context can lead to:",
    options: [
      "Misprioritization and false positives",
      "Guaranteed blocking success",
      "Automatic attribution",
      "Fewer alerts",
    ],
    correctAnswer: 0,
    explanation: "Context is needed to assess relevance and impact.",
  },
  {
    id: 71,
    topic: "Governance",
    question: "Data classification in CTI ensures:",
    options: [
      "Handling rules match sensitivity",
      "All intel is public",
      "Indicators never expire",
      "Only tools are used",
    ],
    correctAnswer: 0,
    explanation: "Classification controls who can access and share intel.",
  },
  {
    id: 72,
    topic: "Governance",
    question: "Deconfliction in CTI means:",
    options: [
      "Avoiding duplicate or conflicting efforts",
      "Deleting evidence",
      "Ignoring sources",
      "Only sharing public data",
    ],
    correctAnswer: 0,
    explanation: "Deconfliction prevents overlap and protects sensitive operations.",
  },
  {
    id: 73,
    topic: "Governance",
    question: "Disrupting earlier kill chain stages generally:",
    options: [
      "Reduces overall impact",
      "Has no effect",
      "Increases dwell time",
      "Blocks only DNS",
    ],
    correctAnswer: 0,
    explanation: "Earlier disruption reduces attacker progress and damage.",
  },
  {
    id: 74,
    topic: "Governance",
    question: "Low confidence assessments indicate:",
    options: [
      "Limited or weak supporting evidence",
      "Certain attribution",
      "Confirmed intelligence",
      "No analysis required",
    ],
    correctAnswer: 0,
    explanation: "Low confidence means the evidence is limited or uncertain.",
  },
  {
    id: 75,
    topic: "Governance",
    question: "The Pyramid of Pain encourages defenders to:",
    options: [
      "Focus on detections that are harder for attackers to change",
      "Only track file hashes",
      "Ignore behavior analytics",
      "Disable detection tools",
    ],
    correctAnswer: 0,
    explanation: "Moving up the pyramid increases attacker cost and disruption.",
  },
];

export default function CyberThreatIntelPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [selectedCategory, setSelectedCategory] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [tabValue, setTabValue] = useState(0);

  const filteredActors = useMemo(() => {
    if (!searchQuery.trim()) return actorCategories[selectedCategory].actors;
    const query = searchQuery.toLowerCase();
    return actorCategories[selectedCategory].actors.filter(
      (a) =>
        a.name.toLowerCase().includes(query) ||
        a.aliases.some((al) => al.toLowerCase().includes(query)) ||
        a.origin.toLowerCase().includes(query) ||
        a.description.toLowerCase().includes(query)
    );
  }, [selectedCategory, searchQuery]);

  const allActors = useMemo(() => {
    return actorCategories.flatMap((c) => c.actors);
  }, []);

  const globalSearch = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const query = searchQuery.toLowerCase();
    return allActors.filter(
      (a) =>
        a.name.toLowerCase().includes(query) ||
        a.aliases.some((al) => al.toLowerCase().includes(query)) ||
        a.origin.toLowerCase().includes(query)
    );
  }, [searchQuery, allActors]);

  return (
    <LearnPageLayout pageTitle="Cyber Threat Intelligence" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <Chip
        component={RouterLink}
        to="/learn"
        icon={<ArrowBackIcon />}
        label="Back to Learning Hub"
        clickable
        variant="outlined"
        sx={{ borderRadius: 2, mb: 3 }}
      />

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, #dc2626, #f59e0b, #3b82f6)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          🕵️ Cyber Threat Intelligence
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          Understanding threat actors, attribution methods, and intelligence tradecraft for defensive and offensive security operations.
        </Typography>
      </Box>

      {/* Main Tabs */}
      <Tabs value={tabValue} onChange={(_, v) => setTabValue(v)} sx={{ mb: 4 }} variant="scrollable" scrollButtons="auto">
        <Tab label="🎭 Threat Actors" />
        <Tab label="🔬 CTI Methodology" />
        <Tab label="📊 IOCs & MITRE" />
        <Tab label="🌐 Threat Landscape" />
        <Tab label="📡 Tracking & Tools" />
        <Tab label="🛡️ Defensive Intel" />
      </Tabs>

      {/* TAB 0: Threat Actors */}
      {tabValue === 0 && (
        <>
          {/* Stats */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#dc2626", 0.05)}, ${alpha("#3b82f6", 0.05)})` }}>
            <Grid container spacing={3} justifyContent="center">
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "error.main" }}>{allActors.length}+</Typography>
                  <Typography variant="body2" color="text.secondary">Threat Actors</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "warning.main" }}>{actorCategories.length}</Typography>
                  <Typography variant="body2" color="text.secondary">Categories</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "info.main" }}>15+</Typography>
                  <Typography variant="body2" color="text.secondary">Nations</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "success.main" }}>2025</Typography>
                  <Typography variant="body2" color="text.secondary">Updated</Typography>
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Search */}
          <TextField
            fullWidth
            size="small"
            placeholder="Search actors, aliases, origins..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: <InputAdornment position="start"><SearchIcon color="action" /></InputAdornment>,
            }}
            sx={{ mb: 3, maxWidth: 500 }}
          />

          {/* Global Search Results */}
          {searchQuery.trim() && globalSearch.length > 0 && (
            <Alert severity="info" sx={{ mb: 3 }}>
              Found {globalSearch.length} actors matching "{searchQuery}" across all categories
            </Alert>
          )}

          {/* Category Cards */}
          <Box sx={{ display: "flex", overflowX: "auto", gap: 1.5, mb: 4, pb: 2 }}>
            {actorCategories.map((cat, index) => (
              <Card
                key={cat.id}
                onClick={() => { setSelectedCategory(index); setSearchQuery(""); }}
                sx={{
                  minWidth: 130,
                  flexShrink: 0,
                  cursor: "pointer",
                  border: `2px solid ${selectedCategory === index ? cat.color : "transparent"}`,
                  bgcolor: selectedCategory === index ? alpha(cat.color, 0.1) : "background.paper",
                  transition: "all 0.2s",
                  "&:hover": { bgcolor: alpha(cat.color, 0.05), transform: "translateY(-2px)" },
                }}
              >
                <CardContent sx={{ textAlign: "center", p: 2, "&:last-child": { pb: 2 } }}>
                  <Typography variant="h5" sx={{ mb: 0.5 }}>{cat.icon}</Typography>
                  <Typography variant="caption" sx={{ fontWeight: 600, color: cat.color, display: "block", fontSize: "0.7rem" }}>
                    {cat.name.split(" ")[0]}
                  </Typography>
                  <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.65rem" }}>
                    {cat.actors.length} actors
                  </Typography>
                </CardContent>
              </Card>
            ))}
          </Box>

          {/* Selected Category Detail */}
          <Paper sx={{ mb: 4, borderRadius: 3, overflow: "hidden" }}>
            <Box sx={{ p: 3, bgcolor: alpha(actorCategories[selectedCategory].color, 0.05), borderBottom: `3px solid ${actorCategories[selectedCategory].color}` }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <Typography variant="h4">{actorCategories[selectedCategory].icon}</Typography>
                <Typography variant="h5" sx={{ fontWeight: 700 }}>{actorCategories[selectedCategory].name}</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">{actorCategories[selectedCategory].description}</Typography>
            </Box>

            {/* Actor List */}
            <Box sx={{ p: 3 }}>
              {filteredActors.length === 0 ? (
                <Alert severity="info">No actors match your search.</Alert>
              ) : (
                <Grid container spacing={2}>
                  {filteredActors.map((actor) => (
                    <Grid item xs={12} md={6} key={actor.name}>
                      <Paper
                        sx={{
                          p: 2,
                          height: "100%",
                          border: `1px solid ${alpha(actorCategories[selectedCategory].color, 0.2)}`,
                          transition: "all 0.2s",
                          "&:hover": { borderColor: actorCategories[selectedCategory].color, bgcolor: alpha(actorCategories[selectedCategory].color, 0.02) },
                        }}
                      >
                        {/* Header with name, type, and status */}
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{actor.name}</Typography>
                            {actor.active !== undefined && (
                              <Chip 
                                label={actor.active ? "Active" : "Inactive"} 
                                size="small" 
                                sx={{ 
                                  fontSize: "0.55rem", 
                                  height: 18,
                                  bgcolor: actor.active ? alpha("#10b981", 0.15) : alpha("#6b7280", 0.15),
                                  color: actor.active ? "#10b981" : "#6b7280",
                                  fontWeight: 700
                                }} 
                              />
                            )}
                          </Box>
                          <Chip label={actor.type} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha(actorCategories[selectedCategory].color, 0.1), color: actorCategories[selectedCategory].color }} />
                        </Box>

                        {/* Aliases */}
                        {actor.aliases.length > 0 && (
                          <Typography variant="caption" color="text.disabled" sx={{ display: "block", mb: 1 }}>
                            aka: {actor.aliases.slice(0, 4).join(", ")}{actor.aliases.length > 4 ? ` (+${actor.aliases.length - 4} more)` : ""}
                          </Typography>
                        )}

                        {/* Origin, First Seen, Targets */}
                        <Box sx={{ display: "flex", gap: 0.5, mb: 1, flexWrap: "wrap", alignItems: "center" }}>
                          <Chip label={actor.origin} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          {actor.firstSeen && (
                            <Chip 
                              label={`Since ${actor.firstSeen}`} 
                              size="small" 
                              sx={{ 
                                fontSize: "0.6rem", 
                                height: 20, 
                                bgcolor: alpha("#8b5cf6", 0.1),
                                color: "#8b5cf6",
                                fontWeight: 600
                              }} 
                            />
                          )}
                          {actor.targets.slice(0, 2).map((t) => (
                            <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          ))}
                          {actor.targets.length > 2 && (
                            <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.6rem" }}>
                              +{actor.targets.length - 2} more
                            </Typography>
                          )}
                        </Box>

                        {/* Description */}
                        <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem", lineHeight: 1.5, mb: 1.5 }}>
                          {actor.description}
                        </Typography>

                        {/* Notable Campaigns */}
                        {actor.notableCampaigns && actor.notableCampaigns.length > 0 && (
                          <Box sx={{ mt: 1, p: 1, bgcolor: alpha("#ef4444", 0.05), borderRadius: 1, borderLeft: `3px solid #ef4444` }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "#ef4444", mb: 0.5 }}>
                              🎯 Notable Campaigns
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>
                              {actor.notableCampaigns.join(" • ")}
                            </Typography>
                          </Box>
                        )}

                        {/* TTPs */}
                        {actor.ttps && actor.ttps.length > 0 && (
                          <Box sx={{ mt: 1, p: 1, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 1, borderLeft: `3px solid #f59e0b` }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "#f59e0b", mb: 0.5 }}>
                              ⚔️ Key TTPs
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {actor.ttps.slice(0, 6).map((ttp, i) => (
                                <Chip 
                                  key={i} 
                                  label={ttp} 
                                  size="small" 
                                  sx={{ 
                                    fontSize: "0.6rem", 
                                    height: 18,
                                    bgcolor: alpha("#f59e0b", 0.1)
                                  }} 
                                />
                              ))}
                              {actor.ttps.length > 6 && (
                                <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.6rem", alignSelf: "center" }}>
                                  +{actor.ttps.length - 6} more
                                </Typography>
                              )}
                            </Box>
                          </Box>
                        )}

                        {/* Tools & Malware */}
                        {actor.tools && actor.tools.length > 0 && (
                          <Box sx={{ mt: 1, p: 1, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 1, borderLeft: `3px solid #3b82f6` }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "#3b82f6", mb: 0.5 }}>
                              🛠️ Tools & Malware
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {actor.tools.slice(0, 6).map((tool, i) => (
                                <Chip 
                                  key={i} 
                                  label={tool} 
                                  size="small" 
                                  variant="outlined"
                                  sx={{ 
                                    fontSize: "0.6rem", 
                                    height: 18,
                                    borderColor: alpha("#3b82f6", 0.3)
                                  }} 
                                />
                              ))}
                              {actor.tools.length > 6 && (
                                <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.6rem", alignSelf: "center" }}>
                                  +{actor.tools.length - 6} more
                                </Typography>
                              )}
                            </Box>
                          </Box>
                        )}
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              )}
            </Box>
          </Paper>
        </>
      )}

      {/* TAB 1: CTI Methodology */}
      {tabValue === 1 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🔬 CTI Methodology & Frameworks</Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            {ctiMethodology.map((section) => (
              <Grid item xs={12} md={6} key={section.title}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha(section.color, 0.2)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Typography variant="h4">{section.icon}</Typography>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{section.title}</Typography>
                  </Box>
                  {section.steps.map((step, i) => (
                    <Box key={i} sx={{ display: "flex", gap: 1.5, mb: 1.5 }}>
                      <Typography variant="body2" sx={{ color: section.color, fontWeight: 700, minWidth: 20 }}>{i + 1}.</Typography>
                      <Typography variant="body2" color="text.secondary">{step}</Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Diamond Model */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>💎 Diamond Model of Intrusion Analysis</Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Box sx={{ textAlign: "center", mb: 3 }}>
                  <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
                    Four core features connected by relationships:
                  </Typography>
                  <Box sx={{ display: "flex", justifyContent: "center", gap: 3, flexWrap: "wrap" }}>
                    {[
                      { label: "Adversary", color: "#ef4444", desc: "Threat actor" },
                      { label: "Infrastructure", color: "#f59e0b", desc: "C2, domains, IPs" },
                      { label: "Capability", color: "#3b82f6", desc: "Tools, malware" },
                      { label: "Victim", color: "#10b981", desc: "Target org/system" },
                    ].map((node) => (
                      <Box key={node.label} sx={{ textAlign: "center" }}>
                        <Box sx={{ width: 80, height: 80, borderRadius: 2, bgcolor: alpha(node.color, 0.1), border: `2px solid ${node.color}`, display: "flex", alignItems: "center", justifyContent: "center", mb: 1 }}>
                          <Typography variant="body2" sx={{ fontWeight: 700, color: node.color }}>{node.label}</Typography>
                        </Box>
                        <Typography variant="caption" color="text.secondary">{node.desc}</Typography>
                      </Box>
                    ))}
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Meta-Features</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {[
                    "Timestamp - When activity occurred",
                    "Phase - Kill chain stage",
                    "Result - Success/failure",
                    "Direction - Adversary→Victim or bidirectional",
                    "Methodology - How capability was deployed",
                    "Resources - What adversary needed",
                  ].map((meta) => (
                    <Typography key={meta} variant="body2" color="text.secondary">• {meta}</Typography>
                  ))}
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Attribution Confidence */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 Attribution Confidence Levels</Typography>
            <Grid container spacing={3}>
              {attributionConfidence.map((level) => (
                <Grid item xs={12} sm={6} md={3} key={level.level}>
                  <Paper 
                    variant="outlined" 
                    sx={{ 
                      p: 2, 
                      height: "100%",
                      borderColor: level.color,
                      borderWidth: 2,
                      bgcolor: alpha(level.color, 0.05)
                    }}
                  >
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: level.color, mb: 0.5 }}>
                      {level.level}
                    </Typography>
                    <Typography variant="h5" sx={{ fontWeight: 800, mb: 1 }}>{level.percentage}</Typography>
                    <Divider sx={{ my: 1.5 }} />
                    {level.indicators.map((ind, i) => (
                      <Typography key={i} variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
                        • {ind}
                      </Typography>
                    ))}
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* STIX/TAXII */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📋 STIX & TAXII Standards</Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>STIX (Structured Threat Information eXpression)</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Standardized language for describing cyber threat information:
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {["Attack Pattern", "Campaign", "Course of Action", "Identity", "Indicator", "Intrusion Set", "Malware", "Observed Data", "Report", "Threat Actor", "Tool", "Vulnerability"].map((obj) => (
                    <Chip key={obj} label={obj} size="small" sx={{ fontSize: "0.65rem" }} />
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>TAXII (Trusted Automated eXchange of Intelligence Information)</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Transport protocol for exchanging STIX data:
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {[
                    "Collections - Sets of CTI objects",
                    "Channels - Publish/subscribe feeds",
                    "API Roots - Service endpoints",
                  ].map((item) => (
                    <Typography key={item} variant="body2" color="text.secondary">• {item}</Typography>
                  ))}
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* TLP & Biases */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🚦 Traffic Light Protocol (TLP)</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                  {tlpLevels.map((tlp) => (
                    <Box key={tlp.level} sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Chip label={tlp.level} size="small" sx={{ bgcolor: tlp.color, color: tlp.level === "TLP:CLEAR" ? "black" : "white", fontWeight: 700, minWidth: 100 }} />
                      <Typography variant="caption" color="text.secondary">{tlp.desc}</Typography>
                    </Box>
                  ))}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🧠 Cognitive Biases in Analysis</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                  {biases.map((bias) => (
                    <Box key={bias.name}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "error.main" }}>{bias.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{bias.desc}</Typography>
                    </Box>
                  ))}
                </Box>
              </Paper>
            </Grid>
          </Grid>

          {/* Admiralty Code */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>⚓ Admiralty Code (Source Reliability & Credibility)</Typography>
            <Grid container spacing={4}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "primary.main" }}>Source Reliability</Typography>
                <TableContainer component={Paper} variant="outlined">
                  <Table size="small">
                    <TableBody>
                      {admiraltyCode.reliability.map((item) => (
                        <TableRow key={item.grade}>
                          <TableCell sx={{ fontWeight: 700, width: 50, textAlign: "center", bgcolor: alpha(theme.palette.primary.main, 0.1) }}>{item.grade}</TableCell>
                          <TableCell>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.label}</Typography>
                            <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "secondary.main" }}>Information Credibility</Typography>
                <TableContainer component={Paper} variant="outlined">
                  <Table size="small">
                    <TableBody>
                      {admiraltyCode.credibility.map((item) => (
                        <TableRow key={item.grade}>
                          <TableCell sx={{ fontWeight: 700, width: 50, textAlign: "center", bgcolor: alpha(theme.palette.secondary.main, 0.1) }}>{item.grade}</TableCell>
                          <TableCell>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.label}</Typography>
                            <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>
            </Grid>
          </Paper>

          {/* Analysis Techniques */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🔍 Analysis Techniques</Typography>
          {analysisTechniques.map((technique) => (
            <Accordion key={technique.name} sx={{ mb: 1, borderRadius: 2, "&:before": { display: "none" } }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{technique.name}</Typography>
                  <Chip 
                    label={technique.difficulty} 
                    size="small" 
                    sx={{ 
                      ml: "auto", 
                      mr: 2,
                      bgcolor: technique.difficulty === "Advanced" ? alpha("#ef4444", 0.1) : 
                               technique.difficulty === "Intermediate" ? alpha("#f59e0b", 0.1) : alpha("#10b981", 0.1),
                      color: technique.difficulty === "Advanced" ? "#ef4444" : 
                             technique.difficulty === "Intermediate" ? "#f59e0b" : "#10b981"
                    }} 
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{technique.description}</Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Steps:</Typography>
                    {technique.steps.map((step, i) => (
                      <Typography key={i} variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                        {i + 1}. {step}
                      </Typography>
                    ))}
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Tools:</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {technique.tools.map((tool) => (
                        <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                      ))}
                    </Box>
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}
        </>
      )}

      {/* TAB 2: IOCs & MITRE */}
      {tabValue === 2 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📊 Indicators of Compromise (IOCs)</Typography>
          
          {/* IOC Types */}
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {iocTypes.map((ioc) => (
              <Grid item xs={12} sm={6} md={4} key={ioc.name}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="h5">{ioc.icon}</Typography>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{ioc.name}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, fontSize: "0.8rem" }}>
                    {ioc.description}
                  </Typography>
                  <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>Detection Methods:</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {ioc.detectionMethods.map((method) => (
                      <Chip key={method} label={method} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* MITRE ATT&CK Tactics */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>⚔️ MITRE ATT&CK Tactics</Typography>
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              The MITRE ATT&CK framework provides a comprehensive matrix of adversary tactics and techniques based on real-world observations.
            </Typography>
            <Grid container spacing={1}>
              {mitreTactics.map((tactic) => (
                <Grid item xs={6} sm={4} md={3} key={tactic.id}>
                  <Tooltip title={tactic.description} arrow>
                    <Paper 
                      sx={{ 
                        p: 1.5, 
                        textAlign: "center", 
                        cursor: "pointer",
                        border: `2px solid ${tactic.color}`,
                        bgcolor: alpha(tactic.color, 0.05),
                        transition: "all 0.2s",
                        "&:hover": { bgcolor: alpha(tactic.color, 0.15), transform: "translateY(-2px)" }
                      }}
                    >
                      <Typography variant="caption" sx={{ fontWeight: 700, color: tactic.color, display: "block" }}>
                        {tactic.id}
                      </Typography>
                      <Typography variant="body2" sx={{ fontWeight: 600, fontSize: "0.75rem" }}>
                        {tactic.name}
                      </Typography>
                      <Typography variant="caption" color="text.disabled">
                        {tactic.techniques} techniques
                      </Typography>
                    </Paper>
                  </Tooltip>
                </Grid>
              ))}
            </Grid>
            <Box sx={{ mt: 3, textAlign: "center" }}>
              <Link href="https://attack.mitre.org/" target="_blank" rel="noopener">
                <Chip 
                  label="Explore Full MITRE ATT&CK Matrix →" 
                  clickable 
                  color="primary" 
                  sx={{ fontWeight: 600 }}
                />
              </Link>
            </Box>
          </Paper>

          {/* Common Malware Families */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🦠 Common Malware Families</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {malwareFamilies.map((malware) => (
              <Grid item xs={12} md={6} key={malware.name}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{malware.name}</Typography>
                    <Chip label={malware.type} size="small" color="error" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, fontSize: "0.8rem" }}>
                    {malware.description}
                  </Typography>
                  <Box sx={{ mb: 1 }}>
                    <Typography variant="caption" sx={{ fontWeight: 700 }}>Capabilities: </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {malware.capabilities.join(", ")}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 1 }}>
                    <Typography variant="caption" sx={{ fontWeight: 700 }}>Used By: </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {malware.usedBy.join(", ")}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" sx={{ fontWeight: 700 }}>Detection: </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                      {malware.detection.map((d) => (
                        <Chip key={d} label={d} size="small" sx={{ fontSize: "0.6rem", height: 18 }} />
                      ))}
                    </Box>
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Pyramid of Pain Visual */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📐 Pyramid of Pain</Typography>
          <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3, textAlign: "center" }}>
              The higher up the pyramid, the more painful for adversaries to change these indicators.
            </Typography>
            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 1 }}>
              {[
                { level: "TTPs", pain: "Tough!", color: "#ef4444", width: "30%", desc: "Behaviors and patterns - hardest to change" },
                { level: "Tools", pain: "Challenging", color: "#f97316", width: "45%", desc: "Custom malware and exploit kits" },
                { level: "Network/Host Artifacts", pain: "Annoying", color: "#f59e0b", width: "55%", desc: "User-agents, registry keys, C2 patterns" },
                { level: "Domain Names", pain: "Simple", color: "#eab308", width: "65%", desc: "Attacker-controlled domains" },
                { level: "IP Addresses", pain: "Easy", color: "#84cc16", width: "75%", desc: "C2 servers and proxies" },
                { level: "Hash Values", pain: "Trivial", color: "#22c55e", width: "85%", desc: "File hashes - easily changed" },
              ].map((item) => (
                <Tooltip key={item.level} title={item.desc} arrow placement="right">
                  <Paper 
                    sx={{ 
                      width: item.width, 
                      py: 1.5, 
                      px: 2,
                      bgcolor: alpha(item.color, 0.1), 
                      border: `2px solid ${item.color}`,
                      textAlign: "center",
                      cursor: "help"
                    }}
                  >
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>
                      {item.level}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">{item.pain}</Typography>
                  </Paper>
                </Tooltip>
              ))}
            </Box>
          </Paper>
        </>
      )}

      {/* TAB 3: Threat Landscape */}
      {tabValue === 3 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🌐 2024-2025 Threat Landscape</Typography>
          
          {/* Threat Trends */}
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {threatLandscape.map((threat) => (
              <Grid item xs={12} sm={6} md={4} key={threat.category}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{threat.category}</Typography>
                    <Chip 
                      icon={
                        threat.trend === "increasing" ? <TrendingUpIcon sx={{ fontSize: 16 }} /> :
                        threat.trend === "decreasing" ? <TrendingDownIcon sx={{ fontSize: 16 }} /> :
                        <TrendingFlatIcon sx={{ fontSize: 16 }} />
                      }
                      label={threat.trend}
                      size="small"
                      sx={{ 
                        bgcolor: threat.trend === "increasing" ? alpha("#ef4444", 0.1) :
                                 threat.trend === "decreasing" ? alpha("#10b981", 0.1) : alpha("#f59e0b", 0.1),
                        color: threat.trend === "increasing" ? "#ef4444" :
                               threat.trend === "decreasing" ? "#10b981" : "#f59e0b",
                        "& .MuiChip-icon": { 
                          color: threat.trend === "increasing" ? "#ef4444" :
                                 threat.trend === "decreasing" ? "#10b981" : "#f59e0b"
                        }
                      }}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, fontSize: "0.8rem" }}>
                    {threat.description}
                  </Typography>
                  <Divider sx={{ my: 1 }} />
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                    {threat.keyStats.map((stat, i) => (
                      <Typography key={i} variant="caption" color="text.secondary">
                        • {stat}
                      </Typography>
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Key Statistics */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#dc2626", 0.05)}, ${alpha("#3b82f6", 0.05)})` }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📈 Key Statistics (2024)</Typography>
            <Grid container spacing={3}>
              {[
                { stat: "$9.5T", label: "Global cybercrime cost", color: "#ef4444" },
                { stat: "277", label: "Days avg breach detection", color: "#f59e0b" },
                { stat: "$4.88M", label: "Average data breach cost", color: "#3b82f6" },
                { stat: "3,205", label: "Data breaches reported", color: "#10b981" },
                { stat: "24B+", label: "Credentials exposed", color: "#8b5cf6" },
                { stat: "560K", label: "New malware daily", color: "#ec4899" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.label}>
                  <Box sx={{ textAlign: "center" }}>
                    <Typography variant="h4" sx={{ fontWeight: 800, color: item.color }}>{item.stat}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.label}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Emerging Threats */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>⚠️ Emerging Threats to Watch</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { 
                title: "AI-Powered Attacks", 
                description: "LLMs generating phishing content, deepfakes for fraud, and automated vulnerability discovery",
                icon: "🤖",
                severity: "High"
              },
              { 
                title: "Quantum Computing Threats", 
                description: "Harvest-now-decrypt-later attacks, urgency for post-quantum cryptography adoption",
                icon: "⚛️",
                severity: "Medium"
              },
              { 
                title: "Supply Chain Compromise", 
                description: "Targeting open source dependencies, build pipelines, and software update mechanisms",
                icon: "📦",
                severity: "Critical"
              },
              { 
                title: "Identity Infrastructure Attacks", 
                description: "Targeting Azure AD/Entra, Okta, and identity providers for widespread access",
                icon: "🆔",
                severity: "Critical"
              },
              { 
                title: "Edge & IoT Exploitation", 
                description: "Compromising routers, VPN appliances, and IoT devices for initial access and botnets",
                icon: "📡",
                severity: "High"
              },
              { 
                title: "Cloud-Native Threats", 
                description: "Kubernetes attacks, serverless function abuse, and cloud IAM exploitation",
                icon: "☁️",
                severity: "High"
              },
            ].map((threat) => (
              <Grid item xs={12} sm={6} md={4} key={threat.title}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="h5">{threat.icon}</Typography>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{threat.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1, fontSize: "0.8rem" }}>
                    {threat.description}
                  </Typography>
                  <Chip 
                    label={`Severity: ${threat.severity}`} 
                    size="small"
                    sx={{ 
                      bgcolor: threat.severity === "Critical" ? alpha("#ef4444", 0.1) :
                               threat.severity === "High" ? alpha("#f59e0b", 0.1) : alpha("#3b82f6", 0.1),
                      color: threat.severity === "Critical" ? "#ef4444" :
                             threat.severity === "High" ? "#f59e0b" : "#3b82f6",
                      fontSize: "0.65rem"
                    }}
                  />
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Geopolitical Context */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🌍 Geopolitical Cyber Context</Typography>
          <Paper sx={{ p: 3, borderRadius: 3 }}>
            <Grid container spacing={3}>
              {[
                { region: "🇺🇦 Ukraine Conflict", impact: "Ongoing Russian destructive operations, hacktivism on both sides, spillover risks to NATO" },
                { region: "🇨🇳 China-Taiwan", impact: "Pre-positioning in critical infrastructure, IP theft acceleration, telecom targeting (Salt Typhoon)" },
                { region: "🇮🇷 Middle East", impact: "Israel-Iran cyber escalation, attacks on water/energy infrastructure, CyberAv3ngers" },
                { region: "🇰🇵 DPRK Sanctions", impact: "Cryptocurrency theft for regime funding, IT worker fraud schemes, Lazarus evolution" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.region}>
                  <Box sx={{ display: "flex", gap: 2 }}>
                    <Typography variant="h6">{item.region.split(" ")[0]}</Typography>
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.region.split(" ").slice(1).join(" ")}</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>{item.impact}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </>
      )}

      {/* TAB 4: Tracking & Tools */}
      {tabValue === 4 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📡 Tracking Methods & Tools</Typography>

          {/* Tracking Methods Table */}
          <TableContainer component={Paper} sx={{ mb: 4, borderRadius: 3 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Method</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Tools</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {trackingMethods.map((row) => (
                  <TableRow key={row.method}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.method}</TableCell>
                    <TableCell>{row.description}</TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {row.tools.split(", ").map((tool) => (
                          <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                        ))}
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Pivot Searching */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🔍 Pivot Searching Techniques</Typography>
            <Grid container spacing={2}>
              {pivotTechniques.map((tech) => (
                <Grid item xs={12} sm={6} md={4} key={tech.name}>
                  <Box sx={{ p: 2, border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main", mb: 1 }}>{tech.name}</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {tech.pivots.map((p) => (
                        <Chip key={p} label={p} size="small" sx={{ fontSize: "0.65rem" }} />
                      ))}
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Intelligence Sources */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📚 Intelligence Sources Database</Typography>
          
          {/* Free Sources */}
          <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `2px solid ${alpha("#10b981", 0.3)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
              <Chip label="FREE" size="small" sx={{ bgcolor: "#10b981", color: "white", fontWeight: 700 }} />
              <Typography variant="h6" sx={{ fontWeight: 700 }}>Open Source & Free Tools</Typography>
            </Box>
            <Grid container spacing={2}>
              {intelligenceSources.filter(s => s.free).map((source) => (
                <Grid item xs={12} sm={6} md={4} key={source.name}>
                  <Link href={source.url} target="_blank" rel="noopener" underline="none">
                    <Paper 
                      variant="outlined"
                      sx={{ 
                        p: 1.5, 
                        height: "100%", 
                        transition: "all 0.2s", 
                        "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05), borderColor: "primary.main" } 
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main" }}>{source.name}</Typography>
                        <LaunchIcon fontSize="small" color="action" sx={{ fontSize: 12, ml: "auto" }} />
                      </Box>
                      <Chip label={source.category} size="small" sx={{ fontSize: "0.6rem", height: 18, mb: 0.5 }} />
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", fontSize: "0.7rem" }}>
                        {source.description}
                      </Typography>
                    </Paper>
                  </Link>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Commercial Sources */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `2px solid ${alpha("#f59e0b", 0.3)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
              <Chip label="COMMERCIAL" size="small" sx={{ bgcolor: "#f59e0b", color: "white", fontWeight: 700 }} />
              <Typography variant="h6" sx={{ fontWeight: 700 }}>Commercial Platforms</Typography>
            </Box>
            <Grid container spacing={2}>
              {intelligenceSources.filter(s => !s.free).map((source) => (
                <Grid item xs={12} sm={6} md={4} key={source.name}>
                  <Link href={source.url} target="_blank" rel="noopener" underline="none">
                    <Paper 
                      variant="outlined"
                      sx={{ 
                        p: 1.5, 
                        height: "100%", 
                        transition: "all 0.2s", 
                        "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05), borderColor: "primary.main" } 
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main" }}>{source.name}</Typography>
                        <LaunchIcon fontSize="small" color="action" sx={{ fontSize: 12, ml: "auto" }} />
                      </Box>
                      <Chip label={source.category} size="small" sx={{ fontSize: "0.6rem", height: 18, mb: 0.5 }} />
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", fontSize: "0.7rem" }}>
                        {source.description}
                      </Typography>
                    </Paper>
                  </Link>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Government Resources */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🏛️ Government CTI Resources</Typography>
          <Grid container spacing={2}>
            {[
              { name: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", country: "🇺🇸" },
              { name: "FBI IC3", url: "https://www.ic3.gov/", country: "🇺🇸" },
              { name: "NCSC UK Advisories", url: "https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports", country: "🇬🇧" },
              { name: "ANSSI France", url: "https://www.cert.ssi.gouv.fr/", country: "🇫🇷" },
              { name: "BSI Germany", url: "https://www.bsi.bund.de/", country: "🇩🇪" },
              { name: "ACSC Australia", url: "https://www.cyber.gov.au/", country: "🇦🇺" },
              { name: "CCCS Canada", url: "https://www.cyber.gc.ca/", country: "🇨🇦" },
              { name: "JPCERT Japan", url: "https://www.jpcert.or.jp/english/", country: "🇯🇵" },
              { name: "ENISA Europe", url: "https://www.enisa.europa.eu/", country: "🇪🇺" },
            ].map((resource) => (
              <Grid item xs={12} sm={6} md={4} key={resource.name}>
                <Link href={resource.url} target="_blank" rel="noopener" underline="none">
                  <Paper sx={{ p: 2, transition: "all 0.2s", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Typography variant="body1">{resource.country}</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{resource.name}</Typography>
                      <LaunchIcon fontSize="small" color="action" sx={{ fontSize: 14, ml: "auto" }} />
                    </Box>
                  </Paper>
                </Link>
              </Grid>
            ))}
          </Grid>
        </>
      )}

      {/* TAB 5: Defensive Intel */}
      {tabValue === 5 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🛡️ Defensive Intelligence & Recommendations</Typography>

          {/* Defensive Recommendations by Actor Type */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            {Object.entries(defensiveRecommendations).map(([actorType, data]) => (
              <Grid item xs={12} md={6} key={actorType}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Typography variant="h5">
                      {actorType === "nation-state" ? "🏛️" : 
                       actorType === "ransomware" ? "💀" : 
                       actorType === "hacktivist" ? "✊" : "💰"}
                    </Typography>
                    <Box>
                      <Typography variant="h6" sx={{ fontWeight: 700, textTransform: "capitalize" }}>
                        {actorType.replace("-", " ")} Defense
                      </Typography>
                      <Chip 
                        label={`Priority: ${data.priority}`} 
                        size="small"
                        sx={{ 
                          bgcolor: data.priority === "Critical" ? alpha("#ef4444", 0.1) :
                                   data.priority === "High" ? alpha("#f59e0b", 0.1) : alpha("#3b82f6", 0.1),
                          color: data.priority === "Critical" ? "#ef4444" :
                                 data.priority === "High" ? "#f59e0b" : "#3b82f6",
                          fontSize: "0.7rem"
                        }}
                      />
                    </Box>
                  </Box>
                  <List dense>
                    {data.recommendations.map((rec, i) => (
                      <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "success.main" }} />
                        </ListItemIcon>
                        <ListItemText 
                          primary={rec} 
                          primaryTypographyProps={{ variant: "body2", fontSize: "0.8rem" }} 
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Report Templates */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📝 Intelligence Report Templates</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {Object.values(reportTemplates).map((template) => (
              <Grid item xs={12} md={6} key={template.name}>
                <Paper sx={{ p: 2, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>{template.name}</Typography>
                  <Box sx={{ display: "flex", gap: 1, mb: 1.5 }}>
                    <Chip label={template.audience} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                    <Chip label={template.frequency} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha("#3b82f6", 0.1) }} />
                  </Box>
                  <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>Sections:</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {template.sections.map((section, i) => (
                      <Typography key={i} variant="caption" color="text.secondary">
                        {i + 1}. {section}{i < template.sections.length - 1 ? " •" : ""}
                      </Typography>
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Quick Reference: Detection Priorities */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 Detection Priority Matrix</Typography>
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Grid container spacing={2}>
              {[
                { category: "Initial Access", techniques: ["Phishing", "Valid Accounts", "Exploit Public-Facing App", "External Remote Services"], priority: "Critical" },
                { category: "Execution", techniques: ["PowerShell", "Windows Command Shell", "Scheduled Task", "User Execution"], priority: "High" },
                { category: "Persistence", techniques: ["Registry Run Keys", "Scheduled Task", "Account Creation", "Web Shell"], priority: "Critical" },
                { category: "Defense Evasion", techniques: ["Process Injection", "Masquerading", "Indicator Removal", "Obfuscated Files"], priority: "High" },
                { category: "Credential Access", techniques: ["LSASS Memory", "Kerberoasting", "Brute Force", "Credentials from Stores"], priority: "Critical" },
                { category: "Lateral Movement", techniques: ["Remote Services", "SMB/Admin Shares", "Remote Desktop", "Pass-the-Hash"], priority: "Critical" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.category}>
                  <Box sx={{ p: 2, border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.category}</Typography>
                      <Chip 
                        label={item.priority} 
                        size="small"
                        sx={{ 
                          bgcolor: item.priority === "Critical" ? alpha("#ef4444", 0.1) : alpha("#f59e0b", 0.1),
                          color: item.priority === "Critical" ? "#ef4444" : "#f59e0b",
                          fontSize: "0.65rem"
                        }}
                      />
                    </Box>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {item.techniques.map((tech) => (
                        <Chip key={tech} label={tech} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                      ))}
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Incident Response Quick Reference */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🚨 Incident Response Quick Reference</Typography>
          <Grid container spacing={2}>
            {[
              { 
                phase: "1. Preparation", 
                icon: "📋",
                tasks: ["IR plan documented", "Contact lists updated", "Playbooks ready", "Tools deployed", "Backups verified"],
                color: "#3b82f6"
              },
              { 
                phase: "2. Identification", 
                icon: "🔍",
                tasks: ["Alert triage", "Scope assessment", "IOC extraction", "Timeline building", "Severity classification"],
                color: "#8b5cf6"
              },
              { 
                phase: "3. Containment", 
                icon: "🔒",
                tasks: ["Network isolation", "Account disable", "Block IOCs", "Preserve evidence", "Communication plan"],
                color: "#f59e0b"
              },
              { 
                phase: "4. Eradication", 
                icon: "🗑️",
                tasks: ["Malware removal", "Persistence cleanup", "Patch vulnerabilities", "Credential reset", "Verify removal"],
                color: "#ef4444"
              },
              { 
                phase: "5. Recovery", 
                icon: "🔄",
                tasks: ["System restoration", "Service validation", "Monitoring increase", "User communication", "Staged return"],
                color: "#10b981"
              },
              { 
                phase: "6. Lessons Learned", 
                icon: "📚",
                tasks: ["Incident report", "Detection gaps", "Process improvements", "Training needs", "Control updates"],
                color: "#6366f1"
              },
            ].map((phase) => (
              <Grid item xs={12} sm={6} md={4} key={phase.phase}>
                <Paper 
                  sx={{ 
                    p: 2, 
                    height: "100%", 
                    borderRadius: 2,
                    borderTop: `4px solid ${phase.color}`
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                    <Typography variant="h5">{phase.icon}</Typography>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: phase.color }}>{phase.phase}</Typography>
                  </Box>
                  {phase.tasks.map((task, i) => (
                    <Typography key={i} variant="body2" color="text.secondary" sx={{ mb: 0.5, fontSize: "0.8rem" }}>
                      • {task}
                    </Typography>
                  ))}
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Threat Hunting Hypotheses */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 3 }}>🎣 Threat Hunting Hypothesis Examples</Typography>
          <Paper sx={{ p: 3, borderRadius: 3 }}>
            <Grid container spacing={2}>
              {[
                { hypothesis: "Attackers are using LOLBins for defense evasion", query: "Search for unusual parent-child process relationships with native Windows binaries" },
                { hypothesis: "Compromised credentials are being used for lateral movement", query: "Look for authentication anomalies, impossible travel, and service account usage" },
                { hypothesis: "Data staging occurring before exfiltration", query: "Monitor for large file creations, compression, and unusual network destinations" },
                { hypothesis: "Persistence mechanisms exist from prior compromise", query: "Audit scheduled tasks, services, registry run keys, and startup folders" },
                { hypothesis: "Web shells deployed on internet-facing servers", query: "Search for suspicious file modifications in web directories and anomalous web server process spawning" },
                { hypothesis: "Attackers maintaining C2 via DNS tunneling", query: "Analyze DNS query volumes, TXT record requests, and unusual subdomain patterns" },
              ].map((item, i) => (
                <Grid item xs={12} md={6} key={i}>
                  <Box sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.02), borderRadius: 2, border: "1px solid", borderColor: "divider" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main", mb: 0.5 }}>
                      Hypothesis: {item.hypothesis}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>
                      <strong>Hunt:</strong> {item.query}
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </>
      )}

      <Paper
        id="quiz-section"
        sx={{
          mt: 5,
          p: 4,
          borderRadius: 3,
          border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
          bgcolor: alpha(QUIZ_ACCENT_COLOR, 0.03),
        }}
      >
        <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
          Knowledge Check
        </Typography>
        <QuizSection
          questions={quizQuestions}
          accentColor={QUIZ_ACCENT_COLOR}
          title="Cyber Threat Intelligence Knowledge Check"
          description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
          questionsPerQuiz={QUIZ_QUESTION_COUNT}
        />
      </Paper>

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
    </Container>
    </LearnPageLayout>
  );
}
