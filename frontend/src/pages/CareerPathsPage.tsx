import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
  Tabs,
  Tab,
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
  Divider,
  Card,
  CardContent,
  Alert,
  Tooltip,
  Rating,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import LocalPoliceIcon from "@mui/icons-material/LocalPolice";
import BuildIcon from "@mui/icons-material/Build";
import BusinessIcon from "@mui/icons-material/Business";
import SchoolIcon from "@mui/icons-material/School";
import WorkIcon from "@mui/icons-material/Work";
import ArrowForwardIcon from "@mui/icons-material/ArrowForward";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import AttachMoneyIcon from "@mui/icons-material/AttachMoney";
import TimelineIcon from "@mui/icons-material/Timeline";
import QuestionAnswerIcon from "@mui/icons-material/QuestionAnswer";
import PsychologyIcon from "@mui/icons-material/Psychology";
import CodeIcon from "@mui/icons-material/Code";
import CloudIcon from "@mui/icons-material/Cloud";
import StorageIcon from "@mui/icons-material/Storage";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import SearchIcon from "@mui/icons-material/Search";
import AssessmentIcon from "@mui/icons-material/Assessment";
import GroupsIcon from "@mui/icons-material/Groups";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import HomeIcon from "@mui/icons-material/Home";
import PublicIcon from "@mui/icons-material/Public";
import HandshakeIcon from "@mui/icons-material/Handshake";
import CampaignIcon from "@mui/icons-material/Campaign";
import StarIcon from "@mui/icons-material/Star";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import PersonIcon from "@mui/icons-material/Person";
import DiversityIcon from "@mui/icons-material/Diversity3";
import LocalLibraryIcon from "@mui/icons-material/LocalLibrary";
import MonetizationOnIcon from "@mui/icons-material/MonetizationOn";
import WarningIcon from "@mui/icons-material/Warning";
import FactoryIcon from "@mui/icons-material/Factory";
import GavelIcon from "@mui/icons-material/Gavel";
import AutoGraphIcon from "@mui/icons-material/AutoGraph";
import MilitaryTechIcon from "@mui/icons-material/MilitaryTech";
import ScienceIcon from "@mui/icons-material/Science";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import DevicesIcon from "@mui/icons-material/Devices";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import RouterIcon from "@mui/icons-material/Router";
import PolicyIcon from "@mui/icons-material/Policy";
import BiotechIcon from "@mui/icons-material/Biotech";
import TerminalIcon from "@mui/icons-material/Terminal";
import InsightsIcon from "@mui/icons-material/Insights";
import IntegrationInstructionsIcon from "@mui/icons-material/IntegrationInstructions";
import VpnLockIcon from "@mui/icons-material/VpnLock";
import DnsIcon from "@mui/icons-material/Dns";
import { useNavigate } from "react-router-dom";

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

interface CareerPath {
  title: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  roles: string[];
  skills: string[];
  certifications: string[];
  salaryRange: string;
  demand: number;
  dayInLife: string[];
}

const careerPaths: CareerPath[] = [
  {
    title: "Offensive Security (Red Team)",
    icon: <BugReportIcon sx={{ fontSize: 40 }} />,
    color: "#ef4444",
    description: "Find vulnerabilities before attackers do. Penetration testing, ethical hacking, and red team operations. This path requires strong technical skills, creativity, and the ability to think like an attacker.",
    roles: [
      "Junior Penetration Tester",
      "Penetration Tester",
      "Senior Penetration Tester",
      "Red Team Operator",
      "Red Team Lead",
      "Principal Security Consultant",
    ],
    skills: ["Network pentesting", "Web app testing", "Social engineering", "Exploit development", "Report writing", "Active Directory attacks", "Cloud pentesting", "Mobile app testing"],
    certifications: ["CEH", "OSCP", "OSWE", "OSED", "GPEN", "CRTO", "CRTP", "GXPN"],
    salaryRange: "$75K - $250K+",
    demand: 92,
    dayInLife: [
      "Scope and plan engagement with client stakeholders",
      "Perform reconnaissance and OSINT gathering",
      "Enumerate targets and identify attack vectors",
      "Exploit vulnerabilities and establish persistence",
      "Pivot through networks and escalate privileges",
      "Exfiltrate data to demonstrate impact",
      "Document findings with detailed remediation steps",
      "Present findings to technical and executive teams",
    ],
  },
  {
    title: "Defensive Security (Blue Team)",
    icon: <LocalPoliceIcon sx={{ fontSize: 40 }} />,
    color: "#3b82f6",
    description: "Detect, respond to, and prevent cyber attacks. Security operations, incident response, and threat hunting. This path is ideal for those who enjoy investigation, analysis, and protecting organizations.",
    roles: [
      "SOC Analyst (Tier 1)",
      "SOC Analyst (Tier 2/3)",
      "Incident Responder",
      "Threat Hunter",
      "Detection Engineer",
      "SOC Manager",
      "Director of Security Operations",
    ],
    skills: ["SIEM administration", "Log analysis", "Threat intelligence", "Malware analysis", "Forensics", "Detection engineering", "SOAR automation", "Threat hunting"],
    certifications: ["Security+", "CySA+", "GCIH", "GCFA", "BTL1", "BTL2", "GCIA", "GNFA"],
    salaryRange: "$60K - $200K+",
    demand: 95,
    dayInLife: [
      "Monitor SIEM dashboards and triage alerts",
      "Investigate security incidents and determine scope",
      "Hunt for threats using IOCs, TTPs, and behavioral analytics",
      "Create and tune detection rules and playbooks",
      "Coordinate incident response activities",
      "Analyze malware samples and extract indicators",
      "Document incidents and create after-action reports",
      "Brief leadership on security posture and incidents",
    ],
  },
  {
    title: "Security Engineering",
    icon: <BuildIcon sx={{ fontSize: 40 }} />,
    color: "#8b5cf6",
    description: "Build secure systems and infrastructure. DevSecOps, cloud security, and security architecture. This path combines development skills with security expertise to build security into systems from the ground up.",
    roles: [
      "Security Engineer",
      "DevSecOps Engineer",
      "Cloud Security Engineer",
      "Platform Security Engineer",
      "Security Architect",
      "Staff Security Engineer",
      "Principal Security Engineer",
    ],
    skills: ["Infrastructure as Code", "CI/CD security", "Cloud platforms (AWS/Azure/GCP)", "Container security", "Zero trust architecture", "Secure coding", "Automation", "Security tooling development"],
    certifications: ["AWS Security Specialty", "AZ-500", "GCP Security", "CCSP", "CISSP", "TOGAF", "CKS"],
    salaryRange: "$90K - $300K+",
    demand: 98,
    dayInLife: [
      "Design and implement security controls and guardrails",
      "Integrate security scanning into CI/CD pipelines",
      "Review architecture proposals for security gaps",
      "Automate security testing and compliance checks",
      "Respond to security findings and develop fixes",
      "Mentor development teams on secure coding practices",
      "Evaluate and implement security tools",
      "Participate in architecture review boards",
    ],
  },
  {
    title: "Governance, Risk & Compliance",
    icon: <BusinessIcon sx={{ fontSize: 40 }} />,
    color: "#f59e0b",
    description: "Manage security programs, policies, and compliance. Risk assessment, auditing, and security leadership. This path is ideal for those who enjoy strategy, communication, and business alignment.",
    roles: [
      "Security Analyst (GRC)",
      "Compliance Analyst",
      "Risk Analyst",
      "Security Auditor",
      "Security Manager",
      "Director of Security",
      "CISO",
    ],
    skills: ["Risk frameworks (NIST, ISO)", "Policy writing", "Audit management", "Vendor assessment", "Executive communication", "Security metrics", "Program management", "Regulatory compliance"],
    certifications: ["CISM", "CRISC", "CISA", "CISSP", "ISO 27001 Lead Auditor", "CGEIT", "CDPSE"],
    salaryRange: "$70K - $450K+",
    demand: 88,
    dayInLife: [
      "Conduct risk assessments and gap analyses",
      "Write and update security policies and procedures",
      "Manage compliance audits (SOC2, ISO, PCI, HIPAA)",
      "Assess third-party vendor security posture",
      "Track and report on security metrics and KPIs",
      "Present risk reports to executives and board",
      "Develop and manage security awareness programs",
      "Coordinate with legal, privacy, and business teams",
    ],
  },
  {
    title: "Vulnerability Research",
    icon: <BiotechIcon sx={{ fontSize: 40 }} />,
    color: "#7c3aed",
    description: "Discover new vulnerabilities, develop exploits, and advance the state of security knowledge. This elite track requires deep technical skills, patience, and creativity to find what others miss.",
    roles: [
      "Junior Security Researcher",
      "Vulnerability Researcher",
      "Senior Security Researcher",
      "Principal Researcher",
      "Research Team Lead",
      "Distinguished Researcher",
    ],
    skills: ["Reverse engineering", "Fuzzing (AFL, LibFuzzer)", "Binary exploitation", "Protocol analysis", "Source code auditing", "CVE disclosure process", "Exploit development", "Assembly (x86/x64/ARM)", "Debugging (GDB, WinDbg)", "Symbolic execution"],
    certifications: ["OSCP", "OSED", "OSEE", "GXPN", "GREM", "Advanced degrees (MS/PhD)"],
    salaryRange: "$120K - $400K+",
    demand: 75,
    dayInLife: [
      "Review target software/firmware for attack surface",
      "Develop and refine fuzzing harnesses",
      "Analyze crash dumps and triage for exploitability",
      "Reverse engineer binaries to understand logic",
      "Develop proof-of-concept exploits",
      "Write detailed vulnerability reports",
      "Coordinate responsible disclosure with vendors",
      "Present research at conferences or internal meetings",
      "Stay current with latest exploitation techniques",
      "Mentor junior researchers on methodology",
    ],
  },
  {
    title: "Network Security Engineering",
    icon: <RouterIcon sx={{ fontSize: 40 }} />,
    color: "#0891b2",
    description: "Design, implement, and maintain secure network infrastructure. This foundational track combines networking expertise with security knowledge to protect organizational communications and data flows.",
    roles: [
      "Network Security Analyst",
      "Network Security Engineer",
      "Senior Network Security Engineer",
      "Network Security Architect",
      "Principal Network Engineer",
      "Director of Network Security",
    ],
    skills: ["Firewall management (Palo Alto, Fortinet, Cisco)", "IDS/IPS deployment", "Network segmentation", "Zero Trust networking", "VPN technologies", "SD-WAN security", "Network traffic analysis", "DDoS mitigation", "DNS security", "802.1X/NAC", "BGP security"],
    certifications: ["CCNA/CCNP Security", "PCNSE", "Fortinet NSE", "CISSP", "Network+", "JNCIS-SEC"],
    salaryRange: "$85K - $220K+",
    demand: 90,
    dayInLife: [
      "Review and approve firewall rule change requests",
      "Monitor network traffic for anomalies and threats",
      "Implement network segmentation for new projects",
      "Respond to IDS/IPS alerts and tune signatures",
      "Configure and maintain VPN infrastructure",
      "Conduct network security assessments",
      "Design secure network architectures for new offices",
      "Troubleshoot connectivity issues with security context",
      "Document network security policies and standards",
      "Collaborate with IT on infrastructure changes",
    ],
  },
];

// Specialized tracks beyond the main six
const specializedTracks = [
  {
    title: "Application Security (AppSec)",
    icon: <CodeIcon />,
    color: "#ec4899",
    description: "Secure software development lifecycle, code review, threat modeling, and application vulnerability management.",
    skills: ["SAST/DAST tools", "Secure code review", "Threat modeling", "API security", "OWASP Top 10", "Dependency scanning", "Security champions programs"],
    certs: ["CSSLP", "GWEB", "OSWE", "CASE", "GWAPT"],
    salary: "$100K - $250K+",
    growth: "Very High",
  },
  {
    title: "Cloud Security",
    icon: <CloudIcon />,
    color: "#06b6d4",
    description: "Secure cloud infrastructure across AWS, Azure, GCP. Identity, networking, workload protection, and cloud-native security.",
    skills: ["IAM policies", "VPC security", "Container security", "Serverless security", "Cloud-native tools", "CSPM", "CWPP", "Infrastructure as Code"],
    certs: ["AWS Security Specialty", "AZ-500", "GCP Security", "CCSP", "CKS"],
    salary: "$110K - $280K+",
    growth: "Very High",
  },
  {
    title: "Threat Intelligence",
    icon: <SearchIcon />,
    color: "#f97316",
    description: "Analyze threat actors, campaigns, and TTPs. Produce actionable intelligence for defensive operations and strategic planning.",
    skills: ["OSINT", "Malware analysis", "MITRE ATT&CK", "Dark web monitoring", "Intel reporting", "Attribution", "Threat actor tracking", "Intelligence platforms"],
    certs: ["GCTI", "CTIA", "FOR578", "GOSI", "GREM"],
    salary: "$85K - $200K+",
    growth: "High",
  },
  {
    title: "Digital Forensics",
    icon: <StorageIcon />,
    color: "#14b8a6",
    description: "Investigate security incidents, collect and analyze evidence, and support legal proceedings with expert testimony.",
    skills: ["Disk forensics", "Memory analysis", "Network forensics", "Mobile forensics", "Chain of custody", "Timeline analysis", "Artifact analysis", "Expert testimony"],
    certs: ["GCFE", "GCFA", "EnCE", "CCE", "CHFI", "GNFA"],
    salary: "$75K - $180K+",
    growth: "Moderate",
  },
  {
    title: "Malware Analysis",
    icon: <BugReportIcon />,
    color: "#dc2626",
    description: "Reverse engineer malware, understand attacker tools and techniques, and develop detection signatures and countermeasures.",
    skills: ["Static analysis", "Dynamic analysis", "Assembly/x86/x64", "Sandbox analysis", "Yara rules", "Unpacking", "Debugging", "C2 analysis"],
    certs: ["GREM", "GCTI", "FOR610", "eCMAP", "OSED"],
    salary: "$90K - $220K+",
    growth: "High",
  },
  {
    title: "Identity & Access Management",
    icon: <VerifiedUserIcon />,
    color: "#8b5cf6",
    description: "Design and manage identity systems, SSO, MFA, privileged access management, and zero trust identity architectures.",
    skills: ["Active Directory", "Azure AD/Entra ID", "Okta/Auth0", "PAM solutions", "Zero trust identity", "Federation", "RBAC/ABAC", "Identity governance"],
    certs: ["SC-300", "Okta Certified", "CyberArk Defender", "CISSP", "CIAM"],
    salary: "$95K - $220K+",
    growth: "Very High",
  },
  {
    title: "Security Research",
    icon: <ScienceIcon />,
    color: "#7c3aed",
    description: "Discover new vulnerabilities, develop exploits, publish research, and advance the state of security knowledge.",
    skills: ["Vulnerability research", "Fuzzing", "Exploit development", "Reverse engineering", "Protocol analysis", "CVE disclosure", "Academic writing", "Conference speaking"],
    certs: ["OSCP", "OSED", "OSEE", "GXPN", "Advanced degrees"],
    salary: "$120K - $350K+",
    growth: "Moderate",
  },
  {
    title: "OT/ICS Security",
    icon: <FactoryIcon />,
    color: "#059669",
    description: "Secure industrial control systems, SCADA, and operational technology in critical infrastructure environments.",
    skills: ["PLC programming", "SCADA systems", "Network segmentation", "OT protocols (Modbus, DNP3)", "Safety systems", "Purdue Model", "Asset inventory", "OT monitoring"],
    certs: ["GICSP", "GRID", "CSSA", "ISA/IEC 62443"],
    salary: "$100K - $250K+",
    growth: "Very High",
  },
  {
    title: "Privacy Engineering",
    icon: <GavelIcon />,
    color: "#0891b2",
    description: "Implement privacy by design, data protection controls, and regulatory compliance (GDPR, CCPA, HIPAA).",
    skills: ["Privacy by design", "Data mapping", "DPIA", "Consent management", "Data minimization", "Anonymization", "GDPR/CCPA/HIPAA", "Privacy-enhancing technologies"],
    certs: ["CIPM", "CIPT", "CIPP", "CDPSE", "FIP"],
    salary: "$100K - $240K+",
    growth: "Very High",
  },
  {
    title: "Bug Bounty Hunter",
    icon: <MonetizationOnIcon />,
    color: "#eab308",
    description: "Independent security researcher finding vulnerabilities in organizations' systems for financial rewards.",
    skills: ["Web app testing", "API testing", "Mobile testing", "Recon automation", "Report writing", "Chaining vulnerabilities", "Business logic flaws", "Persistence"],
    certs: ["OSCP", "OSWE", "BSCP", "eWPT"],
    salary: "$50K - $500K+ (variable)",
    growth: "High",
  },
  {
    title: "Security Data Scientist",
    icon: <InsightsIcon />,
    color: "#06b6d4",
    description: "Apply ML/AI techniques to detect threats, analyze patterns, and build predictive security models.",
    skills: ["Python/R", "Machine learning", "Anomaly detection", "Data pipelines", "Statistical analysis", "NLP for security", "Feature engineering", "Model deployment"],
    certs: ["AWS ML Specialty", "Google ML Engineer", "Data Science certs", "Security background"],
    salary: "$110K - $280K+",
    growth: "Explosive",
  },
  {
    title: "Security Tool Developer",
    icon: <IntegrationInstructionsIcon />,
    color: "#f97316",
    description: "Build internal security tools, SIEM integrations, and automation for security operations.",
    skills: ["Python/Go/Rust", "API development", "Database design", "DevOps", "Security domain knowledge", "UI/UX for security tools", "Testing", "Documentation"],
    certs: ["Software development certs", "Cloud certs", "Security+/OSCP"],
    salary: "$100K - $230K+",
    growth: "Very High",
  },
  {
    title: "Cryptographic Engineer",
    icon: <VpnLockIcon />,
    color: "#8b5cf6",
    description: "Implement cryptographic solutions, PKI infrastructure, and secure communications systems.",
    skills: ["Cryptographic protocols", "PKI/Certificate management", "HSM management", "TLS/mTLS", "Key management", "Post-quantum crypto", "Code signing", "Encryption at rest/transit"],
    certs: ["Cryptography courses", "CISSP", "Vendor-specific (Thales, etc.)"],
    salary: "$120K - $280K+",
    growth: "High",
  },
  {
    title: "DevSecOps Engineer",
    icon: <IntegrationInstructionsIcon />,
    color: "#6366f1",
    description: "Integrate security into CI/CD pipelines, automate security testing, and build secure infrastructure as code.",
    skills: ["CI/CD security", "SAST/DAST integration", "Container security", "IaC (Terraform/Pulumi)", "Secret management", "GitOps", "Policy as Code", "Security automation"],
    certs: ["AWS DevOps", "AZ-400", "CKS", "Terraform Associate", "GitLab Security"],
    salary: "$110K - $250K+",
    growth: "Explosive",
  },
  {
    title: "Mobile Security Engineer",
    icon: <DevicesIcon />,
    color: "#10b981",
    description: "Secure iOS and Android applications, perform mobile pentesting, and implement mobile threat defense.",
    skills: ["iOS/Android internals", "Mobile pentesting", "Reverse engineering (APK/IPA)", "OWASP Mobile Top 10", "MDM/EMM", "App store security", "Runtime protection", "Jailbreak/Root detection"],
    certs: ["GMOB", "eMAPT", "OWASP MSTG", "Mobile app pentesting courses"],
    salary: "$100K - $230K+",
    growth: "High",
  },
  {
    title: "Automotive Security",
    icon: <DnsIcon />,
    color: "#f43f5e",
    description: "Secure connected vehicles, ECUs, CAN bus, and automotive systems against cyber threats.",
    skills: ["CAN bus security", "ECU pentesting", "V2X security", "ISO 21434/UNECE R155", "Automotive protocols", "Hardware hacking", "Firmware analysis", "Telematics security"],
    certs: ["Automotive cybersecurity training", "Hardware hacking courses", "Embedded security certs"],
    salary: "$110K - $260K+",
    growth: "Very High",
  },
];

// Salary data by role and experience
const salaryData = [
  { role: "SOC Analyst (Tier 1)", entry: "$55K-70K", mid: "$70K-90K", senior: "$90K-115K", location: "US Average", remote: "Moderate" },
  { role: "SOC Analyst (Tier 2/3)", entry: "$70K-90K", mid: "$90K-120K", senior: "$120K-150K", location: "US Average", remote: "Moderate" },
  { role: "Penetration Tester", entry: "$70K-90K", mid: "$90K-140K", senior: "$140K-200K", location: "US Average", remote: "High" },
  { role: "Security Engineer", entry: "$85K-110K", mid: "$110K-160K", senior: "$160K-220K", location: "US Average", remote: "Very High" },
  { role: "Network Security Engineer", entry: "$75K-100K", mid: "$100K-145K", senior: "$145K-200K", location: "US Average", remote: "Moderate" },
  { role: "Cloud Security Engineer", entry: "$95K-125K", mid: "$125K-175K", senior: "$175K-280K", location: "US Average", remote: "Very High" },
  { role: "DevSecOps Engineer", entry: "$90K-120K", mid: "$120K-165K", senior: "$165K-230K", location: "US Average", remote: "Very High" },
  { role: "Application Security Engineer", entry: "$95K-120K", mid: "$120K-165K", senior: "$165K-250K", location: "US Average", remote: "Very High" },
  { role: "Vulnerability Researcher", entry: "$100K-130K", mid: "$130K-200K", senior: "$200K-350K+", location: "US Average", remote: "High" },
  { role: "Security Architect", entry: "$130K-160K", mid: "$160K-210K", senior: "$210K-300K", location: "US Average", remote: "High" },
  { role: "GRC Analyst", entry: "$60K-80K", mid: "$80K-115K", senior: "$115K-160K", location: "US Average", remote: "Very High" },
  { role: "Threat Hunter", entry: "$85K-110K", mid: "$110K-150K", senior: "$150K-200K", location: "US Average", remote: "High" },
  { role: "Malware Analyst", entry: "$80K-100K", mid: "$100K-145K", senior: "$145K-220K", location: "US Average", remote: "Moderate" },
  { role: "Security Data Scientist", entry: "$95K-120K", mid: "$120K-170K", senior: "$170K-250K", location: "US Average", remote: "Very High" },
  { role: "Cryptographic Engineer", entry: "$100K-130K", mid: "$130K-180K", senior: "$180K-280K", location: "US Average", remote: "High" },
  { role: "Security Manager", entry: "$110K-140K", mid: "$140K-175K", senior: "$175K-225K", location: "US Average", remote: "Moderate" },
  { role: "Director of Security", entry: "N/A", mid: "$175K-225K", senior: "$225K-300K", location: "US Average", remote: "Low" },
  { role: "CISO", entry: "N/A", mid: "$200K-300K", senior: "$300K-500K+", location: "US Average", remote: "Low" },
];

// Regional salary multipliers
const regionalMultipliers = [
  { region: "San Francisco Bay Area", multiplier: "1.4-1.6x", notes: "Highest salaries, high COL" },
  { region: "New York City", multiplier: "1.3-1.5x", notes: "Finance sector premiums" },
  { region: "Seattle", multiplier: "1.25-1.4x", notes: "Big tech presence" },
  { region: "Washington D.C.", multiplier: "1.2-1.4x", notes: "Government/defense premiums" },
  { region: "Boston", multiplier: "1.15-1.3x", notes: "Healthcare, education sectors" },
  { region: "Austin/Denver", multiplier: "1.1-1.25x", notes: "Growing tech hubs" },
  { region: "Remote (US-based)", multiplier: "0.9-1.1x", notes: "Location-adjusted or full pay" },
  { region: "UK (London)", multiplier: "£60K-£150K", notes: "Varies significantly by role" },
  { region: "Germany", multiplier: "€55K-€130K", notes: "Strong job protection" },
  { region: "Australia", multiplier: "A$80K-A$200K", notes: "Mining/finance pay well" },
  { region: "UK (Outside London)", multiplier: "£45K-£110K", notes: "Lower COL, growing remote options" },
  { region: "Netherlands", multiplier: "€50K-€120K", notes: "Strong tech sector, English-friendly" },
  { region: "Singapore", multiplier: "S$70K-S$180K", notes: "APAC hub, finance and tech" },
  { region: "Canada (Toronto)", multiplier: "C$80K-C$180K", notes: "Growing tech hub, finance sector" },
  { region: "Ireland (Dublin)", multiplier: "€55K-€130K", notes: "Big tech EMEA HQs" },
];

// UK-specific salary data
const ukSalaryData = [
  { role: "SOC Analyst (Tier 1)", junior: "£28K-38K", mid: "£38K-50K", senior: "£50K-65K", london: "+20-30%" },
  { role: "SOC Analyst (Tier 2/3)", junior: "£38K-48K", mid: "£48K-65K", senior: "£65K-85K", london: "+20-30%" },
  { role: "Penetration Tester", junior: "£35K-50K", mid: "£50K-75K", senior: "£75K-110K", london: "+15-25%" },
  { role: "Security Engineer", junior: "£45K-60K", mid: "£60K-85K", senior: "£85K-120K", london: "+20-30%" },
  { role: "Cloud Security Engineer", junior: "£50K-65K", mid: "£65K-95K", senior: "£95K-140K", london: "+20-30%" },
  { role: "DevSecOps Engineer", junior: "£48K-62K", mid: "£62K-90K", senior: "£90K-130K", london: "+20-30%" },
  { role: "GRC Analyst", junior: "£32K-45K", mid: "£45K-65K", senior: "£65K-95K", london: "+15-25%" },
  { role: "Security Architect", junior: "£70K-90K", mid: "£90K-120K", senior: "£120K-160K", london: "+20-30%" },
  { role: "CISO", junior: "N/A", mid: "£120K-180K", senior: "£180K-300K+", london: "+25-40%" },
];

// Learning roadmaps - with links to /learn/certifications for detailed course info
const learningRoadmaps = {
  beginner: {
    title: "Beginner (0-1 years)",
    color: "#22c55e",
    steps: [
      { skill: "Networking Fundamentals", resources: "CompTIA Network+ (N10-009), Cisco CCNA, CCNA NetAcad (Intro to Networks, Switching & Routing), Professor Messer (free), Cisco Packet Tracer labs", time: "2-3 months", certLink: true },
      { skill: "Linux Basics", resources: "CompTIA Linux+ (XK0-005), LPIC-1, LPI Linux Essentials, LFCS, TryHackMe Linux Fundamentals, OverTheWire Bandit, Linux Journey (free)", time: "1-2 months", certLink: true },
      { skill: "Windows Fundamentals", resources: "MS-900 M365 Fundamentals, AZ-900 Azure Fundamentals, TryHackMe Windows Rooms, Microsoft Learn paths (free)", time: "1-2 months", certLink: true },
      { skill: "Security Fundamentals", resources: "CompTIA Security+ (SY0-701), ISC2 CC (Certified in Cybersecurity), SC-900 Security Fundamentals, SANS SEC301, SEC275, Cisco NetAcad Intro to Cybersecurity, GSEC prep", time: "2-3 months", certLink: true },
      { skill: "Scripting (Python/Bash)", resources: "PCEP Python Entry-Level, Python Institute PCAP, Automate the Boring Stuff (free), Codecademy Python, Bash scripting tutorials, SEC573 Python for Pen Testers", time: "2-3 months", certLink: true },
      { skill: "Web Application Basics", resources: "PortSwigger Web Security Academy (free - 200+ labs), OWASP WebGoat, OWASP Juice Shop, TryHackMe Web Fundamentals, HackerOne Bug Bounty Hunter intro", time: "2-3 months", certLink: true },
      { skill: "Security Tools Introduction", resources: "Wireshark certification, Nmap basics, Burp Suite Community, TryHackMe tool rooms, Metasploit Unleashed (free), CyberDefenders beginner challenges", time: "1-2 months", certLink: false },
      { skill: "SOC Fundamentals", resources: "BTL1 (Blue Team Level 1), LetsDefend SOC Analyst path, TryHackMe SOC Level 1, Security Blue Team intro courses, SC-200 prep materials", time: "2-3 months", certLink: true },
    ],
  },
  intermediate: {
    title: "Intermediate (1-3 years)",
    color: "#f59e0b",
    steps: [
      { skill: "Penetration Testing", resources: "OSCP (PEN-200), eJPT, eCPPT, PJPT, PNPT (TCM), HackTheBox CPTS, CompTIA PenTest+, CEH, GPEN (SEC560), Proving Grounds, PentesterLab Pro", time: "6-12 months", certLink: true },
      { skill: "SIEM & Log Analysis", resources: "Splunk Core Certified User/Power User, GCIA (SEC503), Elastic Certified Analyst, GMON (SEC511), Microsoft SC-200, IBM QRadar training, Chronicle SIEM, LetsDefend SIEM paths", time: "2-3 months", certLink: true },
      { skill: "Network Security", resources: "CCNP Security (SCOR + concentration), PCNSA, PCNSE, NSE4/NSE5 (Fortinet), JNCIS-SEC (Juniper), F5 Certified Admin, Check Point CCSA, Palo Alto Beacon courses", time: "3-4 months", certLink: true },
      { skill: "Cloud Security", resources: "AWS Security Specialty, AZ-500 Azure Security Engineer, GCP Professional Cloud Security Engineer, CCSK (CSA), GPCS (SEC510), SC-300 Identity, Prisma Cloud Certified", time: "3-4 months", certLink: true },
      { skill: "Incident Response", resources: "GCIH (SEC504), GCFA (FOR508), BTL1/BTL2, FOR500, FOR572, CyberDefenders IR challenges, LetsDefend IR path, ECIH (EC-Council), GCED (SEC501)", time: "3-4 months", certLink: true },
      { skill: "Threat Intelligence", resources: "GCTI (FOR578), MITRE ATT&CK Defender training, AttackIQ Academy (free), CTIA (EC-Council), Recorded Future training, SANS FOR589, OpenCTI community", time: "2-3 months", certLink: true },
      { skill: "Active Directory Security", resources: "CRTP (Pentester Academy), CRTO (Zero-Point), CRTE, GCWN (SEC505), HTB Pro Labs (Dante, Offshore), AD Attack & Defense courses, Altered Security labs", time: "3-4 months", certLink: true },
      { skill: "Container & Kubernetes Security", resources: "CKA, CKS (Certified Kubernetes Security), Docker DCA, CKAD, Kubernetes Goat, kube-hunter, Falco training, Aqua Security courses, NeuVector training", time: "2-3 months", certLink: true },
      { skill: "Application Security", resources: "OSWA (WEB-200), OSWE (WEB-300), GWEB (SEC522), GWAPT (SEC542), BSCP (Burp Suite Certified), eWPT, eWPTX, CASE (EC-Council), CSSLP, GMOB (SEC575 Mobile)", time: "3-4 months", certLink: true },
      { skill: "DevSecOps & CI/CD Security", resources: "AZ-400 DevOps Engineer, AWS DevOps Pro, GCSA (SEC540), GitLab Security Specialist, Terraform Associate, Vault Associate, GitHub Advanced Security, Jenkins security", time: "3-4 months", certLink: true },
      { skill: "Digital Forensics", resources: "GCFE (FOR500), GCFA (FOR508), GIAC GASF, EnCase EnCE, AccessData ACE, X-Ways training, Autopsy/Sleuth Kit, Magnet AXIOM certification", time: "3-4 months", certLink: true },
    ],
  },
  advanced: {
    title: "Advanced (3+ years)",
    color: "#ef4444",
    steps: [
      { skill: "Exploit Development", resources: "OSED (EXP-301), OSEE (EXP-401), GXPN (SEC660), SEC760 Advanced Exploit Dev, Corelan bootcamp, pwn.college, Exploit Education Phoenix/Nebula, ROP Emporium", time: "6-12 months", certLink: true },
      { skill: "Advanced Vulnerability Research", resources: "OSEE (EXP-401), SEC760, fuzzing with AFL++/LibFuzzer/Honggfuzz, symbolic execution (angr/Manticore), variant analysis, Project Zero methodology, Google VRP", time: "6-12 months", certLink: true },
      { skill: "Malware Analysis & RE", resources: "GREM (FOR610), FOR710 Reverse Engineering, GCFA, GMON, eCMAP, eCRE, Practical Malware Analysis (book), FLARE-ON challenges, Malware Unicorn workshops", time: "4-6 months", certLink: true },
      { skill: "Network Security Architecture", resources: "CCIE Security, CCIE Enterprise, CCDE, PCNSE (Palo Alto Expert), NSE7/NSE8 (Fortinet Expert), JNCIE-SEC, Zero Trust architecture design, SASE/SSE design", time: "4-6 months", certLink: true },
      { skill: "Security Architecture", resources: "CISSP, CISSP-ISSAP (Architecture), SC-100 Cybersecurity Architect, CCSP, TOGAF, SABSA, AWS Solutions Architect Pro, AZ-305, GSLC", time: "6-12 months", certLink: true },
      { skill: "Red Team Operations", resources: "OSEP (PEN-300), OSCE3, CRTO, CRTE, CRTL, GRTP (SEC565), SEC599 Purple Team, CCSAS (CREST), Cobalt Strike training, C2 development, adversary simulation", time: "6-12 months", certLink: true },
      { skill: "Detection Engineering", resources: "GDAT, GSOM, Blue Team Level 2, Sigma rules development, YARA rule writing, Splunk .conf workshops, Elastic detection rules, Chronicle detection engineering", time: "3-6 months", certLink: true },
      { skill: "Security Program Management", resources: "CISM, CGEIT, GSLC (SEC566), CISSP-ISSMP (Management), CRISC, ISO 27001 Lead Implementer, NIST CSF implementation, security metrics & KPIs", time: "6-12 months", certLink: true },
      { skill: "Leadership & Strategy", resources: "CISM, CGEIT, CISSP-ISSMP, CCISO (EC-Council), NACD Cyber-Risk Oversight, MBA programs, board presentation skills, executive communication, CISO Compass", time: "Ongoing", certLink: true },
      { skill: "AI/ML Security", resources: "GAIC (coming), Adversarial ML training, LLM security courses, NVIDIA AI security, AI red teaming, OWASP AI Security, prompt injection defense, model security", time: "3-6 months", certLink: true },
    ],
  },
};

// Interview questions by category
const interviewQuestions = {
  technical: [
    { q: "Explain the TCP 3-way handshake and why it's important for security", level: "Entry", topic: "Networking" },
    { q: "What is the difference between symmetric and asymmetric encryption? When would you use each?", level: "Entry", topic: "Cryptography" },
    { q: "Explain the CIA triad and give an example of each", level: "Entry", topic: "Fundamentals" },
    { q: "What is the difference between authentication and authorization?", level: "Entry", topic: "Identity" },
    { q: "How would you investigate a potential phishing incident?", level: "Mid", topic: "IR" },
    { q: "Explain SQL injection and how to prevent it in modern applications", level: "Mid", topic: "AppSec" },
    { q: "Walk me through your approach to a penetration test from scoping to reporting", level: "Mid", topic: "Offensive" },
    { q: "How does SSL/TLS work? What makes TLS 1.3 more secure than 1.2?", level: "Mid", topic: "Cryptography" },
    { q: "Explain the difference between vulnerability scanning and penetration testing", level: "Mid", topic: "Offensive" },
    { q: "How does Kerberoasting work and how would you detect it?", level: "Senior", topic: "AD Security" },
    { q: "Explain MITRE ATT&CK and how you use it in your daily work", level: "Senior", topic: "Threat Intel" },
    { q: "Design a zero-trust architecture for a cloud-native application", level: "Senior", topic: "Architecture" },
    { q: "How would you implement a detection engineering program from scratch?", level: "Senior", topic: "Detection" },
    { q: "Explain pass-the-hash, pass-the-ticket, and overpass-the-hash attacks", level: "Senior", topic: "AD Security" },
    { q: "How would you secure a Kubernetes cluster in production?", level: "Senior", topic: "Cloud" },
    { q: "Walk me through a memory forensics investigation process", level: "Senior", topic: "Forensics" },
    { q: "Explain the difference between stack and heap buffer overflows", level: "Mid", topic: "VulnResearch" },
    { q: "How does ASLR work and what are techniques to bypass it?", level: "Senior", topic: "VulnResearch" },
    { q: "Describe your approach to fuzzing a new target", level: "Senior", topic: "VulnResearch" },
    { q: "What is the CVE disclosure process and timeline considerations?", level: "Mid", topic: "VulnResearch" },
    { q: "Explain firewall rule ordering and why it matters", level: "Entry", topic: "NetworkSec" },
    { q: "What is network segmentation and how does it improve security?", level: "Entry", topic: "NetworkSec" },
    { q: "How would you design a Zero Trust network architecture?", level: "Senior", topic: "NetworkSec" },
    { q: "Explain the difference between IDS and IPS deployment modes", level: "Mid", topic: "NetworkSec" },
    { q: "What are the security considerations for SD-WAN deployment?", level: "Senior", topic: "NetworkSec" },
    { q: "Explain the NCSC's 10 Steps to Cyber Security and how you'd implement them", level: "Mid", topic: "UK GRC" },
    { q: "How does Cyber Essentials Plus differ from Cyber Essentials? What's the assessment process?", level: "Entry", topic: "UK Compliance" },
    { q: "What are the key differences between GDPR and UK GDPR post-Brexit?", level: "Mid", topic: "Privacy" },
    { q: "Explain how you would secure a GenAI/LLM deployment in production", level: "Senior", topic: "AI Security" },
    { q: "What is prompt injection and how do you defend against it?", level: "Mid", topic: "AI Security" },
    { q: "Walk through securing a DevSecOps pipeline from code commit to production", level: "Mid", topic: "DevSecOps" },
    { q: "Explain SBOM (Software Bill of Materials) and its security implications", level: "Mid", topic: "Supply Chain" },
    { q: "How would you implement a Zero Trust architecture step by step?", level: "Senior", topic: "Architecture" },
    { q: "What's the difference between EDR, XDR, and MDR? When would you use each?", level: "Mid", topic: "Detection" },
  ],
  behavioral: [
    { q: "Tell me about a time you handled a critical security incident under pressure", level: "All", topic: "IR" },
    { q: "How do you stay current with security threats, vulnerabilities, and industry trends?", level: "All", topic: "Growth" },
    { q: "Describe a situation where you had to explain a complex technical issue to non-technical stakeholders", level: "All", topic: "Communication" },
    { q: "Tell me about a time you made a mistake that impacted security. What did you learn?", level: "All", topic: "Growth" },
    { q: "How do you prioritize when you have multiple security issues to address simultaneously?", level: "Mid", topic: "Decision Making" },
    { q: "Tell me about a time you disagreed with a security decision. How did you handle it?", level: "Mid", topic: "Conflict" },
    { q: "Describe a situation where you had to push back on a business request for security reasons", level: "Mid", topic: "Influence" },
    { q: "How do you balance security requirements with business needs and user experience?", level: "Senior", topic: "Strategy" },
    { q: "Tell me about a security program or initiative you built from the ground up", level: "Senior", topic: "Leadership" },
    { q: "How do you mentor junior team members and build a security culture?", level: "Senior", topic: "Leadership" },
  ],
  scenario: [
    { q: "You receive an alert that a user's account is exfiltrating data to an unknown IP. Walk me through your response.", level: "Mid", topic: "IR" },
    { q: "A developer pushes code with hardcoded AWS credentials to a public repo. How do you handle it?", level: "Mid", topic: "AppSec" },
    { q: "You discover a critical vulnerability in production during a pentest engagement. What do you do?", level: "Mid", topic: "Ethics" },
    { q: "Leadership wants to deploy a new SaaS tool urgently. How do you assess its security quickly?", level: "Mid", topic: "Risk" },
    { q: "You find evidence that an employee is selling company data. What's your process?", level: "Mid", topic: "IR" },
    { q: "A ransomware attack encrypts critical systems. Walk me through your response in the first 4 hours.", level: "Senior", topic: "IR" },
    { q: "You're building a security program for a startup from scratch. Where do you start?", level: "Senior", topic: "Strategy" },
    { q: "The board asks you to quantify cyber risk in financial terms. How do you approach this?", level: "Senior", topic: "Risk" },
    { q: "A nation-state APT has compromised your network. How do you approach eradication?", level: "Senior", topic: "IR" },
    { q: "You discover a 0-day in commercial software during authorized testing. Walk through your process.", level: "Senior", topic: "VulnResearch" },
    { q: "A misconfigured firewall rule is allowing unexpected traffic. How do you investigate and remediate?", level: "Mid", topic: "NetworkSec" },
    { q: "Design a network security architecture for a company acquiring another company.", level: "Senior", topic: "NetworkSec" },
    { q: "Your fuzzer found a crash. Walk through triaging it for exploitability.", level: "Senior", topic: "VulnResearch" },
  ],
  handson: [
    { q: "Here's a PCAP file. Find evidence of malicious activity and explain what happened.", level: "Mid", topic: "Analysis" },
    { q: "This web application has vulnerabilities. Find them and demonstrate exploitation.", level: "Mid", topic: "Offensive" },
    { q: "Review this code and identify security vulnerabilities", level: "Mid", topic: "AppSec" },
    { q: "Here's a memory dump. Perform analysis and identify indicators of compromise.", level: "Senior", topic: "Forensics" },
    { q: "Write a detection rule (Sigma/YARA/Splunk) for this attack technique", level: "Senior", topic: "Detection" },
    { q: "Architect a secure cloud infrastructure for this scenario (whiteboard)", level: "Senior", topic: "Architecture" },
    { q: "Here's a binary with a vulnerability. Find it and write an exploit.", level: "Senior", topic: "VulnResearch" },
    { q: "Review these firewall rules and identify security issues", level: "Mid", topic: "NetworkSec" },
    { q: "Set up a network segmentation design for this scenario (whiteboard)", level: "Senior", topic: "NetworkSec" },
    { q: "Analyze this crash dump and determine root cause", level: "Senior", topic: "VulnResearch" },
  ],
};

// Networking and community resources
const networkingResources = [
  { name: "DEF CON", type: "Conference", description: "World's largest hacker conference in Las Vegas", cost: "~$300" },
  { name: "Black Hat", type: "Conference", description: "Premier security conference with cutting-edge research", cost: "$$$" },
  { name: "BSides", type: "Conference", description: "Community-driven local security conferences worldwide", cost: "Free-$50" },
  { name: "OWASP Local Chapters", type: "Meetup", description: "Application security focused local meetups", cost: "Free" },
  { name: "ISSA/ISACA Chapters", type: "Professional", description: "Professional associations with local chapters", cost: "Membership" },
  { name: "Discord Communities", type: "Online", description: "InfoSec Prep, TCM Security, NahamSec, etc.", cost: "Free" },
  { name: "Twitter/X Security", type: "Social", description: "Follow researchers, learn about new vulnerabilities", cost: "Free" },
  { name: "LinkedIn", type: "Professional", description: "Connect with professionals, share your work", cost: "Free" },
  { name: "Reddit Communities", type: "Online", description: "r/netsec, r/cybersecurity, r/AskNetSec", cost: "Free" },
  { name: "CTF Teams", type: "Community", description: "Join or create a team for competitions", cost: "Free" },
  { name: "VulnResearch Communities", type: "Online", description: "Project Zero blog, exploit.education forums, fuzzing Discord", cost: "Free" },
  { name: "Network Security Groups", type: "Professional", description: "NANOG, vendor user groups (Palo Alto Ignite, etc.)", cost: "Varies" },
  { name: "Security Research Labs", type: "Community", description: "University partnerships, open source research projects", cost: "Free" },
  { name: "UK Cyber Security Forum", type: "UK Community", description: "UK-focused security community and events", cost: "Free" },
  { name: "CREST UK", type: "Professional", description: "UK industry body for penetration testing companies", cost: "Membership" },
  { name: "NCSC Industry 100", type: "UK Government", description: "Secondment opportunities with UK NCSC", cost: "Apply" },
  { name: "44CON", type: "UK Conference", description: "Premier UK security conference in London", cost: "£500+" },
  { name: "SteelCon", type: "UK Conference", description: "Sheffield-based security conference", cost: "£50" },
  { name: "Security BSides London", type: "UK Conference", description: "Community security conference in London", cost: "Free-£20" },
  { name: "Women in Cyber Security (WiCyS)", type: "Diversity", description: "Supporting women in cybersecurity careers", cost: "Membership" },
  { name: "Blacks in Cybersecurity (BIC)", type: "Diversity", description: "Supporting Black professionals in security", cost: "Free" },
  { name: "The Diana Initiative", type: "Diversity", description: "DEF CON affiliated conference for diversity in infosec", cost: "Free" },
  { name: "CyberMentor Discord", type: "Online", description: "Heath Adams / TCM Security community", cost: "Free" },
  { name: "Offensive Security Discord", type: "Online", description: "Official OffSec community for cert holders", cost: "Free" },
];

// Mentorship guidance
const mentorshipGuidance = {
  finding: [
    "Attend local security meetups (BSides, OWASP, ISSA)",
    "Engage thoughtfully on Twitter/LinkedIn with security professionals",
    "Participate in Discord communities and build relationships",
    "Ask for informal coffee chats, not formal mentorship initially",
    "Provide value first - share resources, help with projects",
    "Be specific about what you want to learn",
  ],
  being: [
    "Document and share your learning journey publicly",
    "Answer questions in communities where you have knowledge",
    "Create tutorials and guides for topics you've mastered",
    "Speak at local meetups (even 5-minute lightning talks)",
    "Pair with peers on CTFs and practice exercises",
    "Remember everyone was a beginner once",
  ],
};

// Remote work considerations
const remoteWorkData = {
  highlyRemote: [
    "Security Engineer", "DevSecOps Engineer", "Cloud Security Engineer",
    "GRC Analyst", "Compliance Analyst", "AppSec Engineer", "Threat Intelligence Analyst",
    "Vulnerability Researcher", "Security Data Scientist", "Security Tool Developer",
  ],
  moderatelyRemote: [
    "Penetration Tester", "SOC Analyst", "Threat Hunter", "Security Architect",
    "Malware Analyst", "Detection Engineer", "Cryptographic Engineer",
  ],
  lessRemote: [
    "CISO", "Security Director", "Physical Security", "OT/ICS Security",
    "Incident Responder (on-call)", "Forensics (on-site)", "Network Security Engineer (on-prem focus)",
  ],
  tips: [
    "Build a strong online presence (GitHub, blog, LinkedIn)",
    "Get certifications that demonstrate independent capability",
    "Develop excellent written communication skills",
    "Be proactive with documentation and status updates",
    "Create a dedicated workspace with proper security",
    "Invest in your home network security as a showcase",
    "Prepare for timezone flexibility in global teams",
  ],
};

// Career transition paths
const careerTransitions = [
  { from: "IT Support / Help Desk", to: "SOC Analyst", path: "Security+, home lab, TryHackMe SOC paths, apply to Tier 1 roles", time: "6-12 months", difficulty: 2 },
  { from: "Network Admin", to: "Security Engineer", path: "Cloud certs, automation skills (Python/Ansible), security-focused projects", time: "6-12 months", difficulty: 2 },
  { from: "Software Developer", to: "AppSec Engineer", path: "OWASP training, secure code review practice, CSSLP/GWEB", time: "3-6 months", difficulty: 2 },
  { from: "SOC Analyst", to: "Threat Hunter", path: "GCIH, deep ATT&CK expertise, detection engineering skills", time: "1-2 years", difficulty: 3 },
  { from: "SOC Analyst", to: "Penetration Tester", path: "OSCP, CTFs, build home lab, create portfolio", time: "1-2 years", difficulty: 4 },
  { from: "Sys Admin", to: "Cloud Security Engineer", path: "AWS/Azure certs, IaC skills (Terraform), cloud security projects", time: "6-12 months", difficulty: 3 },
  { from: "Military / Intelligence", to: "Threat Intelligence", path: "GCTI, clearance leverage, OSINT skills", time: "3-6 months", difficulty: 2 },
  { from: "Non-Tech Background", to: "GRC Analyst", path: "Security+, CISA, policy writing practice, compliance frameworks", time: "1-2 years", difficulty: 3 },
  { from: "QA/Testing", to: "Security Engineer", path: "Security testing focus, automation, SAST/DAST tools", time: "6-12 months", difficulty: 3 },
  { from: "Data Analyst", to: "Detection Engineer", path: "SIEM skills, query languages, threat detection logic", time: "6-12 months", difficulty: 3 },
  { from: "Project Manager", to: "Security Program Manager", path: "Security+, CISSP, understand security domains", time: "1-2 years", difficulty: 3 },
  { from: "Legal/Compliance", to: "Privacy/Security GRC", path: "CIPM/CIPP, GDPR expertise, security fundamentals", time: "1-2 years", difficulty: 2 },
  { from: "Network Engineer", to: "Network Security Engineer", path: "Security certs (CCNA Security, PCNSE), firewall experience, security mindset", time: "6-12 months", difficulty: 2 },
  { from: "Penetration Tester", to: "Vulnerability Researcher", path: "OSED/OSEE, reverse engineering, fuzzing skills, research methodology", time: "1-2 years", difficulty: 4 },
  { from: "Software Developer", to: "Vulnerability Researcher", path: "Low-level languages (C/C++), reverse engineering, binary exploitation", time: "1-3 years", difficulty: 5 },
  { from: "Security Engineer", to: "Network Security Architect", path: "Zero Trust expertise, advanced networking, SASE/SSE knowledge", time: "1-2 years", difficulty: 3 },
  { from: "Firewall Admin", to: "Network Security Engineer", path: "Multiple vendor experience, automation skills, security architecture", time: "6-12 months", difficulty: 2 },
  { from: "Cloud Engineer", to: "Cloud Security Engineer", path: "Security certifications (AWS Security, AZ-500), security mindset, IAM deep dive", time: "6-12 months", difficulty: 2 },
  { from: "Data Engineer", to: "Security Data Scientist", path: "Security domain knowledge, threat detection ML, anomaly detection", time: "1-2 years", difficulty: 3 },
  { from: "Mobile Developer", to: "Mobile Security Engineer", path: "OWASP Mobile, app pentesting, reverse engineering basics", time: "6-12 months", difficulty: 3 },
  { from: "DevOps Engineer", to: "DevSecOps Engineer", path: "Security scanning tools, SAST/DAST, container security, policy as code", time: "6-12 months", difficulty: 2 },
  { from: "AI/ML Engineer", to: "AI Security Specialist", path: "Adversarial ML, LLM security, model security, prompt injection defense", time: "6-12 months", difficulty: 3 },
  { from: "Hardware Engineer", to: "Hardware Security Researcher", path: "Side-channel attacks, fault injection, embedded security, chip security", time: "1-2 years", difficulty: 4 },
  { from: "Teacher/Trainer", to: "Security Awareness Lead", path: "Security fundamentals, phishing simulation tools, metrics and reporting", time: "1-2 years", difficulty: 2 },
];

// Industry trends
const industryTrends = [
  { trend: "AI/ML in Security", impact: "Very High", description: "AI-powered threat detection, automated response, LLM security, and adversarial AI attacks", growth: "Explosive" },
  { trend: "Cloud-Native Security", impact: "Very High", description: "Securing Kubernetes, serverless, service mesh, and microservices architectures", growth: "Very High" },
  { trend: "Zero Trust Architecture", impact: "Very High", description: "Identity-centric security, microsegmentation, continuous verification, ZTNA", growth: "Very High" },
  { trend: "Supply Chain Security", impact: "Very High", description: "SBOM, dependency scanning, third-party risk management, secure SDLC", growth: "Very High" },
  { trend: "API Security", impact: "High", description: "Protecting the growing attack surface of APIs and microservices communication", growth: "Very High" },
  { trend: "Identity Security", impact: "Very High", description: "Identity threat detection, ITDR, passwordless, phishing-resistant MFA", growth: "Very High" },
  { trend: "Detection Engineering", impact: "High", description: "Custom detection development, Sigma rules, threat hunting automation", growth: "High" },
  { trend: "OT/IoT Security", impact: "Growing", description: "Securing industrial control systems, medical devices, and connected infrastructure", growth: "High" },
  { trend: "Privacy Engineering", impact: "High", description: "Data protection, privacy by design, regulatory compliance (GDPR, CCPA, CPRA)", growth: "High" },
  { trend: "Security Automation (SOAR)", impact: "Very High", description: "Orchestration, automated response, infrastructure as code, AI-assisted ops", growth: "Very High" },
  { trend: "Ransomware Defense", impact: "Very High", description: "Backup strategies, EDR/XDR, incident response readiness, cyber insurance", growth: "High" },
  { trend: "Extended Detection & Response (XDR)", impact: "High", description: "Unified security across endpoints, network, cloud, and identity", growth: "Very High" },
  { trend: "AI/LLM Security", impact: "Very High", description: "Securing AI systems, prompt injection defense, model security, and adversarial ML", growth: "Explosive" },
  { trend: "CTEM (Continuous Threat Exposure Management)", impact: "High", description: "Proactive exposure management beyond traditional vulnerability management", growth: "Very High" },
  { trend: "Passwordless Authentication", impact: "High", description: "FIDO2/WebAuthn, passkeys, and phishing-resistant MFA adoption", growth: "Very High" },
  { trend: "Platform Engineering Security", impact: "High", description: "Securing internal developer platforms and golden paths", growth: "High" },
  { trend: "Quantum-Safe Cryptography", impact: "Growing", description: "Preparing for post-quantum cryptographic threats and migration", growth: "Moderate" },
  { trend: "Cyber Insurance Requirements", impact: "High", description: "Meeting insurer security requirements and demonstrating controls", growth: "High" },
];

// Common mistakes to avoid
const commonMistakes = [
  { mistake: "Certification collecting without hands-on skills", fix: "Balance certs with practical labs, CTFs, and projects" },
  { mistake: "Applying only to 100% matching job descriptions", fix: "Apply if you meet 60-70% of requirements, skills can be learned" },
  { mistake: "Ignoring soft skills and communication", fix: "Practice writing, presenting, and explaining technical concepts simply" },
  { mistake: "Not building a public presence", fix: "Blog, tweet, contribute to open source, speak at meetups" },
  { mistake: "Waiting to be 'ready' before applying", fix: "Apply early, interview for practice, learn from rejections" },
  { mistake: "Undervaluing non-security experience", fix: "Your IT/dev experience is valuable, highlight transferable skills" },
  { mistake: "Focusing on tools over concepts", fix: "Understand the 'why' behind tools, principles transfer across platforms" },
  { mistake: "Not networking or building relationships", fix: "Attend events, engage online, build genuine connections over time" },
  { mistake: "Expecting immediate senior roles", fix: "Be patient, entry roles build foundation, progression takes 2-5 years" },
  { mistake: "Ignoring business context", fix: "Understand how security enables business, speak the language of risk" },
];

const entryTips = [
  "Start with foundational certs: Security+, Network+, or equivalent",
  "Build a home lab: VMs, vulnerable machines, detection tools",
  "Practice on CTF platforms: HackTheBox, TryHackMe, LetsDefend",
  "Contribute to open source security projects on GitHub",
  "Write about what you learn (blog, LinkedIn, Medium)",
  "Network at local security meetups (BSides, OWASP, ISSA)",
  "Apply for internships and junior roles - don't wait until you're 'ready'",
  "Create a portfolio website showcasing projects and writeups",
  "Get comfortable with failure - CTFs, interviews, and learning involve failing forward",
  "Find a mentor or study group for accountability and guidance",
  "For vuln research path: Start with pwn.college and ROP Emporium",
  "For network security path: Set up pfSense/OPNsense home firewall lab",
  "Learn a programming language deeply (Python for automation, C for vuln research)",
  "Understand the business context - security serves business objectives",
  "Document everything - your notes become your knowledge base",
];

// Resume tips
const resumeTips = [
  { category: "Format & Structure", tips: ["Keep to 1-2 pages maximum", "Use clean, ATS-friendly format (avoid graphics)", "Include links to GitHub/portfolio/LinkedIn", "Put contact info and relevant links at the top", "Use consistent formatting throughout"] },
  { category: "Skills Section", tips: ["List tools you've actually used with context", "Include certifications with dates achieved", "Separate technical skills from soft skills", "Prioritize skills mentioned in job posting", "Be specific: 'Splunk' not just 'SIEM experience'"] },
  { category: "Experience Description", tips: ["Use action verbs (detected, analyzed, implemented, reduced)", "Quantify impact when possible (reduced incidents by 40%)", "Include home lab and CTF experience as valid experience", "Focus on achievements, not just responsibilities", "Tailor bullet points to each application"] },
  { category: "Projects & Portfolio", tips: ["Detail your home lab setup and what you learned", "List CTF achievements and notable rankings", "Include bug bounty findings (with permission)", "Link to GitHub repos with security tools/scripts", "Showcase writeups and blog posts"] },
  { category: "Certifications", tips: ["List relevant certs with completion dates", "Include in-progress certifications (expected date)", "Prioritize recognized certs (OSCP > random online cert)", "Don't over-list low-value certifications", "Verify your cert links work"] },
];

// Top platforms for learning and practice
const learningPlatforms = [
  { name: "TryHackMe", type: "Hands-on Labs", level: "Beginner-Intermediate", cost: "Free/$14/mo", focus: "Structured learning paths with guided rooms", rating: 5 },
  { name: "HackTheBox", type: "Hands-on Labs", level: "Intermediate-Advanced", cost: "Free/$18/mo", focus: "Real-world pentesting, less guidance", rating: 5 },
  { name: "HackTheBox Academy", type: "Courses + Labs", level: "All Levels", cost: "$18/mo", focus: "Structured courses with practical labs", rating: 5 },
  { name: "PortSwigger Web Academy", type: "Web Security", level: "All Levels", cost: "Free", focus: "Best free web app security training", rating: 5 },
  { name: "LetsDefend", type: "Blue Team Labs", level: "Beginner-Intermediate", cost: "Free/$25/mo", focus: "SOC analyst training with realistic alerts", rating: 4 },
  { name: "CyberDefenders", type: "Blue Team Labs", level: "Intermediate-Advanced", cost: "Free", focus: "Forensics & IR challenges with real data", rating: 4 },
  { name: "PentesterLab", type: "Web Security", level: "Intermediate", cost: "$20/mo", focus: "Progressive web app pentesting exercises", rating: 4 },
  { name: "Proving Grounds", type: "Hands-on Labs", level: "Intermediate", cost: "$19/mo", focus: "OffSec practice boxes for OSCP prep", rating: 4 },
  { name: "AttackIQ Academy", type: "Courses", level: "All Levels", cost: "Free", focus: "MITRE ATT&CK and purple team training", rating: 4 },
  { name: "Offensive Security (OffSec)", type: "Certifications", level: "Intermediate-Advanced", cost: "$$$", focus: "Industry gold standard: OSCP, OSWE, OSED", rating: 5 },
  { name: "SANS Institute", type: "Certifications", level: "All Levels", cost: "$$$$", focus: "Comprehensive GIAC certifications", rating: 5 },
  { name: "TCM Security", type: "Courses", level: "Beginner-Intermediate", cost: "$30/mo or courses", focus: "Practical ethical hacking, affordable", rating: 4 },
  { name: "Azeria Labs", type: "ARM Exploitation", level: "Intermediate-Advanced", cost: "Free", focus: "ARM assembly and exploitation", rating: 4 },
  { name: "LiveOverflow", type: "YouTube", level: "Intermediate", cost: "Free", focus: "Binary exploitation, CTF walkthroughs", rating: 5 },
  { name: "Corelan", type: "Exploit Dev", level: "Intermediate-Advanced", cost: "Free tutorials", focus: "Windows exploit development fundamentals", rating: 5 },
  { name: "Palo Alto Beacon", type: "Network Security", level: "All Levels", cost: "Free", focus: "Firewall and network security training", rating: 4 },
  { name: "Fortinet NSE Institute", type: "Network Security", level: "All Levels", cost: "Free", focus: "Network security fundamentals to advanced", rating: 4 },
  { name: "INE", type: "Courses + Labs", level: "All Levels", cost: "$49/mo", focus: "Pentesting, eJPT/eCPPT certifications", rating: 4 },
  { name: "pwn.college", type: "CTF/Labs", level: "Intermediate-Advanced", cost: "Free", focus: "Binary exploitation and vulnerability research", rating: 5 },
  { name: "Root-Me", type: "CTF Platform", level: "All Levels", cost: "Free", focus: "French/English challenges across all domains", rating: 4 },
  { name: "VulnHub", type: "Vulnerable VMs", level: "Intermediate", cost: "Free", focus: "Downloadable vulnerable machines for practice", rating: 4 },
  { name: "Immersive Labs", type: "Enterprise Training", level: "All Levels", cost: "Enterprise", focus: "UK-based platform used by many UK organizations", rating: 4 },
  { name: "QA Cybersecurity", type: "UK Training", level: "All Levels", cost: "£££", focus: "UK-based training provider with classroom options", rating: 4 },
  { name: "SANS Cyber Ranges", type: "Simulations", level: "Intermediate-Advanced", cost: "Included with SANS courses", focus: "NetWars, Cyber42, and other competitions", rating: 5 },
  { name: "Blue Team Labs Online", type: "Blue Team Labs", level: "Intermediate", cost: "Free/Paid", focus: "Defensive security challenges and investigations", rating: 4 },
  { name: "Exploit Education", type: "Binary Exploitation", level: "Intermediate-Advanced", cost: "Free", focus: "Phoenix, Nebula, and other exploitation VMs", rating: 5 },
  { name: "ROP Emporium", type: "Binary Exploitation", level: "Intermediate", cost: "Free", focus: "Return-oriented programming challenges", rating: 4 },
  { name: "Nightmare", type: "Binary Exploitation", level: "Intermediate-Advanced", cost: "Free", focus: "CTF binary exploitation writeups and challenges", rating: 4 },
  { name: "Certified Secure", type: "UK Courses", level: "All Levels", cost: "££", focus: "UK-based, NCSC certified training provider", rating: 4 },
];

// Day in the life expanded scenarios
const dayInLifeScenarios = [
  {
    role: "SOC Analyst (Tier 1)",
    schedule: [
      { time: "08:00", task: "Shift handoff - review overnight incidents and alerts" },
      { time: "08:30", task: "Check SIEM dashboard, triage new alerts" },
      { time: "09:00", task: "Investigate suspicious login alert - document findings" },
      { time: "10:00", task: "Escalate confirmed incident to Tier 2" },
      { time: "10:30", task: "Work through alert queue, close false positives" },
      { time: "12:00", task: "Lunch break (stay available for critical alerts)" },
      { time: "13:00", task: "Attend threat intel briefing" },
      { time: "14:00", task: "Continue alert triage and investigations" },
      { time: "15:00", task: "Document recurring false positive for tuning request" },
      { time: "16:00", task: "Prepare shift handoff notes" },
    ],
  },
  {
    role: "Penetration Tester",
    schedule: [
      { time: "08:00", task: "Review scope and ROE for current engagement" },
      { time: "09:00", task: "Continue enumeration - run Nmap, directory fuzzing" },
      { time: "10:00", task: "Discover web app vulnerability, develop exploit" },
      { time: "11:00", task: "Gain initial foothold, document methodology" },
      { time: "12:00", task: "Team lunch - discuss findings with colleagues" },
      { time: "13:00", task: "Privilege escalation attempts, lateral movement" },
      { time: "15:00", task: "Client check-in call - update on progress" },
      { time: "15:30", task: "Continue exploitation, pursue domain admin" },
      { time: "17:00", task: "Document findings, update evidence folder" },
      { time: "17:30", task: "Plan next day's attack paths" },
    ],
  },
  {
    role: "Security Engineer",
    schedule: [
      { time: "08:00", task: "Check overnight alerts, review deployment pipelines" },
      { time: "09:00", task: "Stand-up meeting with dev team" },
      { time: "09:30", task: "Review PR for security implications" },
      { time: "10:30", task: "Implement new detection rule in SIEM" },
      { time: "11:30", task: "Troubleshoot failing security scan in CI/CD" },
      { time: "12:00", task: "Lunch" },
      { time: "13:00", task: "Architecture review meeting for new service" },
      { time: "14:00", task: "Write Terraform for new security controls" },
      { time: "15:30", task: "Investigate security tool alert, tune rule" },
      { time: "16:30", task: "Documentation and knowledge base updates" },
    ],
  },
  {
    role: "Vulnerability Researcher",
    schedule: [
      { time: "08:00", task: "Review overnight fuzzing results and crash logs" },
      { time: "09:00", task: "Triage crashes - reproducibility and exploitability" },
      { time: "10:00", task: "Deep dive into promising crash - root cause analysis" },
      { time: "11:00", task: "Reverse engineer relevant code paths in IDA/Ghidra" },
      { time: "12:00", task: "Lunch - read latest security research papers" },
      { time: "13:00", task: "Develop proof-of-concept exploit" },
      { time: "15:00", task: "Team sync - share findings, discuss approaches" },
      { time: "16:00", task: "Write up vulnerability report with technical details" },
      { time: "17:00", task: "Refine fuzzing harnesses, start new campaigns" },
    ],
  },
  {
    role: "Network Security Engineer",
    schedule: [
      { time: "08:00", task: "Review overnight IDS/IPS alerts and blocked traffic" },
      { time: "09:00", task: "Process firewall change requests queue" },
      { time: "10:00", task: "Implement approved network segmentation changes" },
      { time: "11:00", task: "Troubleshoot VPN connectivity issues for remote site" },
      { time: "12:00", task: "Lunch" },
      { time: "13:00", task: "Architecture review for new data center network" },
      { time: "14:00", task: "Update firewall rules documentation" },
      { time: "15:00", task: "Tune IDS signatures to reduce false positives" },
      { time: "16:00", task: "Plan firmware upgrades for network security devices" },
      { time: "17:00", task: "Handoff notes and on-call preparation" },
    ],
  },
  {
    role: "GRC Analyst",
    schedule: [
      { time: "09:00", task: "Review and respond to vendor security questionnaires" },
      { time: "10:00", task: "Update risk register with new findings from pentest" },
      { time: "11:00", task: "Draft policy updates for remote work security" },
      { time: "12:00", task: "Lunch" },
      { time: "13:00", task: "Prepare evidence for upcoming ISO 27001 audit" },
      { time: "14:00", task: "Conduct third-party vendor risk assessment" },
      { time: "15:00", task: "Meet with legal team on GDPR data mapping" },
      { time: "16:00", task: "Create monthly security metrics dashboard" },
      { time: "17:00", task: "Review Cyber Essentials Plus certification status" },
    ],
  },
  {
    role: "DevSecOps Engineer",
    schedule: [
      { time: "08:30", task: "Review overnight SAST/DAST scan results" },
      { time: "09:00", task: "Daily standup with development team" },
      { time: "09:30", task: "Triage critical security findings in CI pipeline" },
      { time: "10:30", task: "Implement new secret scanning in GitHub Actions" },
      { time: "12:00", task: "Lunch - catch up on security newsletters" },
      { time: "13:00", task: "Review PR for Terraform security configurations" },
      { time: "14:00", task: "Update container base images and scan for vulns" },
      { time: "15:00", task: "Create secure coding training for developers" },
      { time: "16:00", task: "Debug failing security gates in pipeline" },
      { time: "17:00", task: "Document new security automation workflows" },
    ],
  },
  {
    role: "Cloud Security Engineer",
    schedule: [
      { time: "08:00", task: "Check cloud security posture dashboards (CSPM)" },
      { time: "09:00", task: "Investigate GuardDuty/Defender alerts" },
      { time: "10:00", task: "Review IAM policy change requests" },
      { time: "11:00", task: "Implement new landing zone security controls" },
      { time: "12:00", task: "Lunch" },
      { time: "13:00", task: "Architecture review for new serverless project" },
      { time: "14:00", task: "Write Terraform modules for security guardrails" },
      { time: "15:00", task: "Conduct cloud security training session" },
      { time: "16:00", task: "Review and approve network peering requests" },
      { time: "17:00", task: "Update runbooks for cloud IR procedures" },
    ],
  },
];

export default function CareerPathsPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `Comprehensive Cybersecurity Career Paths Guide - An extensive resource covering six main career tracks (Offensive Security/Red Team, Defensive Security/Blue Team, Security Engineering, Governance Risk & Compliance, Vulnerability Research, Network Security Engineering) plus 17 specialized tracks (AppSec, Cloud Security, Threat Intelligence, Digital Forensics, Malware Analysis, IAM, Security Research, OT/ICS Security, Privacy Engineering, Bug Bounty, Security Data Scientist, Security Tool Developer, Cryptographic Engineer, DevSecOps, Mobile Security, Automotive Security). Includes detailed 2024-2025 salary data for both US and UK markets with regional multipliers, learning roadmaps from beginner to advanced with specific resources and timelines, comprehensive interview preparation with 65+ technical/behavioral/scenario/hands-on questions including AI security and UK compliance topics, career transition guides with difficulty ratings for 25 transition paths, industry trends including AI/LLM security and CTEM, networking and mentorship guidance with UK-specific communities, remote work considerations, resume tips, and 24+ recommended learning platforms including UK providers. Features day-in-the-life scenarios for 9 distinct roles and certification recommendations. Updated for current market conditions with focus on emerging areas like AI security, DevSecOps, and cloud-native security.`;

  return (
    <LearnPageLayout pageTitle="Cybersecurity Career Paths" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ mb: 2 }}
          >
            Back to Learning Hub
          </Button>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Box
              sx={{
                width: 64,
                height: 64,
                borderRadius: 2,
                bgcolor: alpha("#f59e0b", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <TrendingUpIcon sx={{ fontSize: 36, color: "#f59e0b" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Cybersecurity Career Guide
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Your comprehensive guide to building a successful cybersecurity career (US & UK)
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Careers" color="primary" size="small" />
            <Chip label="Red Team" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
            <Chip label="Blue Team" size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
            <Chip label="Engineering" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
            <Chip label="GRC" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
            <Chip label="US Salaries" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
            <Chip label="UK Salaries" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
            <Chip label="Roadmaps" size="small" sx={{ bgcolor: alpha("#ec4899", 0.1), color: "#ec4899" }} />
            <Chip label="AI Security" size="small" sx={{ bgcolor: alpha("#6366f1", 0.1), color: "#6366f1" }} />
            <Chip label="Remote Work" size="small" sx={{ bgcolor: alpha("#06b6d4", 0.1), color: "#06b6d4" }} />
          </Box>
        </Box>

        {/* Key Stats */}
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { label: "Unfilled Jobs (2024)", value: "3.5M+", icon: <WorkIcon />, color: "#ef4444" },
            { label: "Avg US Salary", value: "$125K", icon: <AttachMoneyIcon />, color: "#22c55e" },
            { label: "Avg UK Salary", value: "£65K", icon: <AttachMoneyIcon />, color: "#22c55e" },
            { label: "Career Tracks", value: "23+", icon: <TimelineIcon />, color: "#f59e0b" },
            { label: "Remote Roles", value: "70%+", icon: <HomeIcon />, color: "#8b5cf6" },
            { label: "Interview Q's", value: "65+", icon: <QuestionAnswerIcon />, color: "#ec4899" },
          ].map((stat) => (
            <Grid item xs={6} md={2} key={stat.label}>
              <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, transition: "all 0.3s", "&:hover": { transform: "translateY(-2px)", boxShadow: 3 } }}>
                <Box sx={{ color: stat.color, mb: 1 }}>{stat.icon}</Box>
                <Typography variant="h5" sx={{ fontWeight: 800, color: stat.color }}>{stat.value}</Typography>
                <Typography variant="caption" color="text.secondary">{stat.label}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Education CTA Banner */}
        <Paper
          sx={{
            p: 2,
            mb: 3,
            borderRadius: 2,
            background: `linear-gradient(135deg, ${alpha("#22c55e", 0.1)} 0%, ${alpha("#3b82f6", 0.1)} 100%)`,
            border: `1px solid ${alpha("#22c55e", 0.3)}`,
            display: "flex",
            flexDirection: { xs: "column", md: "row" },
            alignItems: "center",
            justifyContent: "space-between",
            gap: 2,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <SchoolIcon sx={{ fontSize: 40, color: "#22c55e" }} />
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>
                Ready to Start Learning?
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Browse 500+ certifications and courses across 15+ categories to accelerate your career
              </Typography>
            </Box>
          </Box>
          <Button
            variant="contained"
            color="success"
            size="large"
            endIcon={<ArrowForwardIcon />}
            onClick={() => navigate("/learn/certifications")}
            sx={{ whiteSpace: "nowrap" }}
          >
            Browse Certifications & Courses
          </Button>
        </Paper>

        {/* Tabs */}
        <Paper sx={{ borderRadius: 3, mb: 3 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ borderBottom: 1, borderColor: "divider" }}
          >
            <Tab label="Career Tracks" icon={<SecurityIcon />} iconPosition="start" />
            <Tab label="Specialized Roles" icon={<PsychologyIcon />} iconPosition="start" />
            <Tab label="Salary Guide" icon={<AttachMoneyIcon />} iconPosition="start" />
            <Tab label="Learning Roadmaps" icon={<TimelineIcon />} iconPosition="start" />
            <Tab label="Interview Prep" icon={<QuestionAnswerIcon />} iconPosition="start" />
            <Tab label="Career Transitions" icon={<ArrowForwardIcon />} iconPosition="start" />
            <Tab label="Industry Trends" icon={<TrendingUpIcon />} iconPosition="start" />
            <Tab label="Networking & Mentorship" icon={<HandshakeIcon />} iconPosition="start" />
            <Tab label="Remote Work" icon={<HomeIcon />} iconPosition="start" />
            <Tab label="Getting Started" icon={<SchoolIcon />} iconPosition="start" />
          </Tabs>

          {/* Tab 0: Main Career Tracks */}
          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                These six tracks represent the primary career paths in cybersecurity. Most professionals specialize in one area but understanding all domains makes you more effective. Vulnerability Research and Network Security are foundational specializations that underpin many other security functions.
              </Alert>

              <Grid container spacing={3}>
                {careerPaths.map((path) => (
                  <Grid item xs={12} md={6} key={path.title}>
                    <Paper
                      sx={{
                        p: 3,
                        height: "100%",
                        borderRadius: 3,
                        border: `1px solid ${alpha(path.color, 0.2)}`,
                        transition: "all 0.3s ease",
                        "&:hover": {
                          borderColor: path.color,
                          boxShadow: `0 8px 30px ${alpha(path.color, 0.15)}`,
                        },
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                        <Box
                          sx={{
                            width: 56,
                            height: 56,
                            borderRadius: 2,
                            bgcolor: alpha(path.color, 0.1),
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            color: path.color,
                          }}
                        >
                          {path.icon}
                        </Box>
                        <Box sx={{ flex: 1 }}>
                          <Typography variant="h6" sx={{ fontWeight: 700 }}>
                            {path.title}
                          </Typography>
                          <Chip label={path.salaryRange} size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e", fontWeight: 600 }} />
                        </Box>
                      </Box>

                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {path.description}
                      </Typography>

                      {/* Demand indicator */}
                      <Box sx={{ mb: 2 }}>
                        <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
                          <Typography variant="caption" color="text.secondary">Market Demand</Typography>
                          <Typography variant="caption" sx={{ color: path.color, fontWeight: 600 }}>{path.demand}%</Typography>
                        </Box>
                        <LinearProgress
                          variant="determinate"
                          value={path.demand}
                          sx={{
                            height: 6,
                            borderRadius: 3,
                            bgcolor: alpha(path.color, 0.1),
                            "& .MuiLinearProgress-bar": { bgcolor: path.color, borderRadius: 3 },
                          }}
                        />
                      </Box>

                      {/* Career Progression */}
                      <Accordion sx={{ bgcolor: "transparent", boxShadow: "none", "&:before": { display: "none" } }}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 0 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600, color: path.color }}>
                            Career Progression
                          </Typography>
                        </AccordionSummary>
                        <AccordionDetails sx={{ px: 0 }}>
                          <Box sx={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 0.5 }}>
                            {path.roles.map((role, i) => (
                              <React.Fragment key={role}>
                                <Chip label={role} size="small" sx={{ fontSize: "0.7rem", height: 24, bgcolor: alpha(path.color, 0.08) }} />
                                {i < path.roles.length - 1 && <ArrowForwardIcon sx={{ fontSize: 14, color: "text.disabled" }} />}
                              </React.Fragment>
                            ))}
                          </Box>
                        </AccordionDetails>
                      </Accordion>

                      {/* Day in the Life */}
                      <Accordion sx={{ bgcolor: "transparent", boxShadow: "none", "&:before": { display: "none" } }}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 0 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                            Day in the Life
                          </Typography>
                        </AccordionSummary>
                        <AccordionDetails sx={{ px: 0 }}>
                          <List dense disablePadding>
                            {path.dayInLife.map((task, i) => (
                              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 24 }}>
                                  <CheckCircleIcon sx={{ fontSize: 14, color: path.color }} />
                                </ListItemIcon>
                                <ListItemText primary={task} primaryTypographyProps={{ variant: "caption" }} />
                              </ListItem>
                            ))}
                          </List>
                        </AccordionDetails>
                      </Accordion>

                      <Divider sx={{ my: 1.5 }} />

                      {/* Key Skills */}
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                        Key Skills:
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                        {path.skills.map((skill) => (
                          <Chip key={skill} label={skill} size="small" variant="outlined" sx={{ fontSize: "0.65rem", height: 22 }} />
                        ))}
                      </Box>

                      {/* Certifications */}
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                        Popular Certifications:
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1.5 }}>
                        {path.certifications.map((cert) => (
                          <Chip
                            key={cert}
                            label={cert}
                            size="small"
                            sx={{ fontSize: "0.65rem", height: 22, bgcolor: alpha(path.color, 0.1), color: path.color, fontWeight: 600 }}
                          />
                        ))}
                      </Box>
                      <Button
                        size="small"
                        variant="text"
                        onClick={() => navigate("/learn/certifications")}
                        endIcon={<ArrowForwardIcon />}
                        sx={{ fontSize: "0.7rem", color: path.color }}
                      >
                        View All Related Courses
                      </Button>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </TabPanel>

          {/* Tab 1: Specialized Roles */}
          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Beyond the four main tracks, these specialized roles focus on specific domains and often command premium salaries due to their expertise requirements. Many professionals move into these after gaining experience in a core track.
              </Alert>

              <Grid container spacing={2}>
                {specializedTracks.map((track) => (
                  <Grid item xs={12} md={6} lg={4} key={track.title}>
                    <Card sx={{ height: "100%", borderRadius: 2, border: `1px solid ${alpha(track.color, 0.2)}`, transition: "all 0.3s", "&:hover": { borderColor: track.color, transform: "translateY(-2px)" } }}>
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                          <Box sx={{ color: track.color }}>{track.icon}</Box>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{track.title}</Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, minHeight: 60 }}>
                          {track.description}
                        </Typography>
                        <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
                          <Chip label={track.salary} size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e", fontWeight: 600 }} />
                          <Chip label={`Growth: ${track.growth}`} size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6", fontWeight: 600 }} />
                        </Box>
                        <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>Key Skills:</Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1.5 }}>
                          {track.skills.slice(0, 5).map((skill) => (
                            <Chip key={skill} label={skill} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          ))}
                        </Box>
                        <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>Certifications:</Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1.5 }}>
                          {track.certs.map((cert) => (
                            <Chip key={cert} label={cert} size="small" sx={{ fontSize: "0.6rem", height: 20, bgcolor: alpha(track.color, 0.1), color: track.color }} />
                          ))}
                        </Box>
                        <Button
                          size="small"
                          variant="text"
                          onClick={() => navigate("/learn/certifications")}
                          endIcon={<ArrowForwardIcon />}
                          sx={{ fontSize: "0.65rem", p: 0, color: track.color }}
                        >
                          Find Courses
                        </Button>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </TabPanel>

          {/* Tab 2: Salary Guide */}
          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Salaries vary significantly by location, company size, industry, and remote work policy. These figures represent US averages for 2024-2025. See regional multipliers below for location adjustments.
              </Alert>

              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Role</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#22c55e" }}>Entry Level (0-2 yrs)</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>Mid Level (2-5 yrs)</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#ef4444" }}>Senior (5+ yrs)</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#3b82f6" }}>Remote Friendly</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {salaryData.map((row) => (
                      <TableRow key={row.role} hover>
                        <TableCell sx={{ fontWeight: 600 }}>{row.role}</TableCell>
                        <TableCell sx={{ color: "#22c55e" }}>{row.entry}</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>{row.mid}</TableCell>
                        <TableCell sx={{ color: "#ef4444" }}>{row.senior}</TableCell>
                        <TableCell>
                          <Chip 
                            label={row.remote} 
                            size="small" 
                            sx={{ 
                              bgcolor: alpha(
                                row.remote === "Very High" ? "#22c55e" : 
                                row.remote === "High" ? "#3b82f6" : 
                                row.remote === "Moderate" ? "#f59e0b" : "#ef4444", 
                                0.1
                              ),
                              color: row.remote === "Very High" ? "#22c55e" : 
                                row.remote === "High" ? "#3b82f6" : 
                                row.remote === "Moderate" ? "#f59e0b" : "#ef4444",
                              fontSize: "0.7rem"
                            }} 
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              {/* Regional Multipliers */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <PublicIcon sx={{ color: "#3b82f6" }} /> Regional Salary Multipliers
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Region</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Multiplier / Range</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {regionalMultipliers.map((row) => (
                      <TableRow key={row.region} hover>
                        <TableCell sx={{ fontWeight: 600 }}>{row.region}</TableCell>
                        <TableCell sx={{ color: "#3b82f6", fontWeight: 600 }}>{row.multiplier}</TableCell>
                        <TableCell sx={{ color: "text.secondary" }}>{row.notes}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              {/* UK Salary Guide */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                🇬🇧 UK Salary Guide (2024-2025)
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Role</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#22c55e" }}>Junior (0-2 yrs)</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>Mid (2-5 yrs)</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#ef4444" }}>Senior (5+ yrs)</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#8b5cf6" }}>London Premium</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {ukSalaryData.map((row) => (
                      <TableRow key={row.role} hover>
                        <TableCell sx={{ fontWeight: 600 }}>{row.role}</TableCell>
                        <TableCell sx={{ color: "#22c55e" }}>{row.junior}</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>{row.mid}</TableCell>
                        <TableCell sx={{ color: "#ef4444" }}>{row.senior}</TableCell>
                        <TableCell sx={{ color: "#8b5cf6", fontWeight: 600 }}>{row.london}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              <Alert severity="info" sx={{ mb: 3 }}>
                <strong>UK Market Note:</strong> UK cybersecurity salaries have grown 15-25% since 2022. Finance sector (City of London) and government contractors (with SC/DV clearance) typically pay 20-40% above market. Remote roles are increasingly common but some enterprise clients require UK-based with occasional office presence.
              </Alert>

              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <AttachMoneyIcon sx={{ color: "#22c55e" }} /> Salary Boosters
                    </Typography>
                    <List dense>
                      {[
                        "OSCP/OSWE certification (+$10-25K)",
                        "Cloud certifications (AWS/Azure Security)",
                        "Security clearance (+$15-40K)",
                        "Management/leadership experience",
                        "Niche expertise (malware, cloud, OT/ICS)",
                        "Big tech or finance industry",
                        "Remote work from lower COL areas (arbitrage)",
                        "On-call/incident response premium",
                        "Strong track record with metrics",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#22c55e" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <AssessmentIcon sx={{ color: "#3b82f6" }} /> Highest Paying Industries
                    </Typography>
                    <List dense>
                      {[
                        "Finance & Banking (+20-40%)",
                        "Big Tech (FAANG/MAANG)",
                        "Cryptocurrency/Web3/FinTech",
                        "Defense & Government Contractors",
                        "Healthcare (especially with clearance)",
                        "Consulting (Big 4, boutique security)",
                        "Critical Infrastructure/Energy",
                        "Hedge Funds & Trading Firms",
                        "Gaming (large studios)",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Alert severity="success" sx={{ mt: 3 }}>
                <strong>Negotiation Tip:</strong> Always research salary ranges before interviews. Use levels.fyi, Glassdoor, and Blind for data. Don't give a number first - let them make an offer. Most offers have 10-20% negotiation room.
              </Alert>
            </Box>
          </TabPanel>

          {/* Tab 3: Learning Roadmaps */}
          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                These roadmaps provide a structured approach to building cybersecurity skills. Timelines assume part-time study (10-15 hours/week) alongside work or school. Adjust based on your availability.
              </Alert>

              {Object.values(learningRoadmaps).map((roadmap) => (
                <Accordion key={roadmap.title} defaultExpanded={roadmap.title.includes("Beginner")}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: roadmap.color }}>
                      {roadmap.title}
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 700 }}>Skill Area</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Recommended Resources</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Est. Time</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Courses</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {roadmap.steps.map((step: { skill: string; resources: string; time: string; certLink?: boolean }, i: number) => (
                            <TableRow key={i} hover>
                              <TableCell sx={{ fontWeight: 600 }}>{step.skill}</TableCell>
                              <TableCell sx={{ color: "text.secondary" }}>{step.resources}</TableCell>
                              <TableCell>
                                <Chip label={step.time} size="small" sx={{ bgcolor: alpha(roadmap.color, 0.1), color: roadmap.color, fontWeight: 600 }} />
                              </TableCell>
                              <TableCell>
                                {step.certLink && (
                                  <Button
                                    size="small"
                                    variant="outlined"
                                    onClick={() => navigate("/learn/certifications")}
                                    sx={{ fontSize: "0.7rem", py: 0.25, minWidth: "auto" }}
                                  >
                                    View Certs
                                  </Button>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              ))}

              {/* Certification Progression by Career Path */}
              <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                    <SchoolIcon sx={{ color: "#22c55e" }} /> Certification Progression Paths
                  </Typography>
                  <Button
                    variant="contained"
                    color="success"
                    size="small"
                    endIcon={<ArrowForwardIcon />}
                    onClick={() => navigate("/learn/certifications")}
                  >
                    Browse All Certifications
                  </Button>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Comprehensive certification paths aligned with career progression. Click "Browse All Certifications" for detailed course information, prerequisites, and providers.
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>🔴 Red Team / Offensive Security</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> Security+, eJPT, CEH, PJPT, PenTest+, HTB CPTS, CPSA (CREST)<br />
                        <strong>Mid:</strong> OSCP (PEN-200), CRTP, CRTO, GPEN, eCPPT, PNPT, CRT (CREST), OSWP, GRTP, SEC560, SEC565<br />
                        <strong>Advanced:</strong> OSEP (PEN-300), OSED (EXP-301), OSCE3, GXPN, CRTE, CRTL, CCT INF/APP (CREST), SEC660, SEC599
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>🔵 Blue Team / SOC / Incident Response</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> Security+, CySA+, BTL1, SC-200, SOC Analyst L1 (HTB), LetsDefend paths<br />
                        <strong>Mid:</strong> GCIH (SEC504), GCFA (FOR508), GCIA (SEC503), GMON (SEC511), GCED, GCTI (FOR578), GNFA<br />
                        <strong>Advanced:</strong> GCFE, GREM (FOR610), BTL2, GDSA, FOR500, FOR572, FOR610, GDAT
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#ff9900", 0.05), border: `1px solid ${alpha("#ff9900", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff9900", mb: 1 }}>☁️ Cloud Security & DevSecOps</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> AWS Cloud Practitioner, AZ-900, GCP Digital Leader, CCSK, SEC388<br />
                        <strong>Mid:</strong> AWS Security Specialty, AZ-500, AZ-400, GCP Security Engineer, CKA, CKS, GPCS (SEC510), Terraform Associate, Vault Associate, SEC540<br />
                        <strong>Advanced:</strong> CCSP, SC-100, AWS Solutions Architect Pro, GCSA, SEC549, Professional Cloud DevOps Engineer
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>🏗️ Security Engineering & Architecture</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> Security+, Linux+, GSEC (SEC401), RHCSA, LPIC-1, MS-900<br />
                        <strong>Mid:</strong> GCWN (SEC505), AZ-104, AZ-204, RHCE, CKA, Docker DCA, SEC406<br />
                        <strong>Advanced:</strong> CISSP, SC-100, CCSP, TOGAF, SABSA, GSLC, AZ-305, RHCA
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>🌐 Application & Web Security</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> PortSwigger Web Academy (free), OWASP WebGoat, HackerOne Bug Bounty Hunter<br />
                        <strong>Mid:</strong> OSWA (WEB-200), GWAPT (SEC542), GWEB (SEC522), eWPT, BSCP, GMOB (SEC575)<br />
                        <strong>Advanced:</strong> OSWE (WEB-300), CSSLP, CASE, GASF, API Security certs
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>📋 GRC / Compliance / Privacy</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> Security+, ISC2 CC, CISA, ISO 27001 Foundation, Cyber Essentials<br />
                        <strong>Mid:</strong> CRISC, CDPSE, CIPM, CIPP/E, ISO 27001 Lead Implementer/Auditor, PCIP<br />
                        <strong>Advanced:</strong> CISSP, CISM, CGEIT, CCAK, CCSP, GSLC, CISSP-ISSMP
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#0ea5e9", 0.05), border: `1px solid ${alpha("#0ea5e9", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>🌐 Network Security</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> Network+, CCNA, NSE1-3, JNCIA-Junos, Aruba Certified Associate<br />
                        <strong>Mid:</strong> CCNP Security, PCNSA, NSE4, JNCIS-SEC, F5 Certified Admin, VCP-NV<br />
                        <strong>Advanced:</strong> CCIE Security, PCNSE, NSE7/8, JNCIE-SEC, CCIE Enterprise, CCDE
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>🔬 Vulnerability Research & Malware Analysis</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> Security+, pwn.college, ROP Emporium, Exploit Education<br />
                        <strong>Mid:</strong> GREM (FOR610), GCFA, eCRE, eCMAP, Malware Analysis courses<br />
                        <strong>Advanced:</strong> OSED (EXP-301), OSEE (EXP-401), GXPN (SEC660), SEC760, FOR710
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>🏭 OT/ICS & IoT Security</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> Security+, ICS-CERT training, GICSP foundations<br />
                        <strong>Mid:</strong> GICSP (ICS515), GRID (ICS515), ISA/IEC 62443 Cybersecurity Certificate<br />
                        <strong>Advanced:</strong> GCIP, ICS410, ICS515, CSSA (ICS security)
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} lg={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#84cc16", 0.05), border: `1px solid ${alpha("#84cc16", 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#84cc16", mb: 1 }}>🇬🇧 UK-Specific Certifications</Typography>
                      <Typography variant="caption" component="div" sx={{ lineHeight: 1.9 }}>
                        <strong>Entry:</strong> Cyber Essentials, NCSC Certified Training, CREST CPSA<br />
                        <strong>Mid:</strong> CREST CRT, CHECK Team Member, NCSC Certified Professional<br />
                        <strong>Advanced:</strong> CREST CCT INF/APP, CHECK Team Leader, CCSAS, CCSAM
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Paper>

              <Paper sx={{ p: 2, mt: 3, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                  🎓 Recommended Learning Platforms
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 700 }}>Platform</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Level</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Cost</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Focus</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Rating</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {learningPlatforms.map((platform) => (
                        <TableRow key={platform.name} hover>
                          <TableCell sx={{ fontWeight: 600 }}>{platform.name}</TableCell>
                          <TableCell>{platform.type}</TableCell>
                          <TableCell>{platform.level}</TableCell>
                          <TableCell sx={{ color: platform.cost === "Free" ? "#22c55e" : "inherit" }}>{platform.cost}</TableCell>
                          <TableCell sx={{ color: "text.secondary", maxWidth: 200 }}>{platform.focus}</TableCell>
                          <TableCell>
                            <Rating value={platform.rating} readOnly size="small" />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              {/* Day in the Life Scenarios */}
              <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <WorkIcon sx={{ color: "#f59e0b" }} /> Day in the Life: Role Scenarios
              </Typography>
              <Grid container spacing={2}>
                {dayInLifeScenarios.map((scenario) => (
                  <Grid item xs={12} md={4} key={scenario.role}>
                    <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                        {scenario.role}
                      </Typography>
                      <List dense disablePadding>
                        {scenario.schedule.map((item, i) => (
                          <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                            <ListItemText 
                              primary={
                                <Box sx={{ display: "flex", gap: 1 }}>
                                  <Typography variant="caption" sx={{ fontWeight: 600, color: "#8b5cf6", minWidth: 45 }}>{item.time}</Typography>
                                  <Typography variant="caption">{item.task}</Typography>
                                </Box>
                              }
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </TabPanel>

          {/* Tab 4: Interview Prep */}
          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Security interviews typically include technical questions, behavioral scenarios, and hands-on assessments. Prepare for all types. Many companies now include practical exercises (CTF-style challenges, code review, architecture design).
              </Alert>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>
                    🔧 Technical Questions ({interviewQuestions.technical.length})
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700, width: "55%" }}>Question</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Level</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Topic</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {interviewQuestions.technical.map((item, i) => (
                          <TableRow key={i} hover>
                            <TableCell>{item.q}</TableCell>
                            <TableCell>
                              <Chip
                                label={item.level}
                                size="small"
                                sx={{
                                  bgcolor: alpha(item.level === "Entry" ? "#22c55e" : item.level === "Mid" ? "#f59e0b" : "#ef4444", 0.1),
                                  color: item.level === "Entry" ? "#22c55e" : item.level === "Mid" ? "#f59e0b" : "#ef4444",
                                }}
                              />
                            </TableCell>
                            <TableCell>
                              <Chip label={item.topic} size="small" variant="outlined" />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>
                    💬 Behavioral Questions ({interviewQuestions.behavioral.length})
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700, width: "60%" }}>Question</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Level</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Topic</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {interviewQuestions.behavioral.map((item, i) => (
                          <TableRow key={i} hover>
                            <TableCell>{item.q}</TableCell>
                            <TableCell>
                              <Chip
                                label={item.level}
                                size="small"
                                sx={{
                                  bgcolor: alpha(item.level === "All" ? "#3b82f6" : item.level === "Mid" ? "#f59e0b" : "#ef4444", 0.1),
                                  color: item.level === "All" ? "#3b82f6" : item.level === "Mid" ? "#f59e0b" : "#ef4444",
                                }}
                              />
                            </TableCell>
                            <TableCell>
                              <Chip label={item.topic} size="small" variant="outlined" />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Alert severity="success" sx={{ mt: 2 }}>
                    <strong>STAR Method:</strong> Structure your answers with <strong>S</strong>ituation (context), <strong>T</strong>ask (your responsibility), <strong>A</strong>ction (what you did), <strong>R</strong>esult (outcome with metrics if possible).
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                    🎯 Scenario-Based Questions ({interviewQuestions.scenario.length})
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700, width: "65%" }}>Scenario</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Level</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Topic</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {interviewQuestions.scenario.map((item, i) => (
                          <TableRow key={i} hover>
                            <TableCell>{item.q}</TableCell>
                            <TableCell>
                              <Chip
                                label={item.level}
                                size="small"
                                sx={{
                                  bgcolor: alpha(item.level === "Mid" ? "#f59e0b" : "#ef4444", 0.1),
                                  color: item.level === "Mid" ? "#f59e0b" : "#ef4444",
                                }}
                              />
                            </TableCell>
                            <TableCell>
                              <Chip label={item.topic} size="small" variant="outlined" />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#ec4899" }}>
                    🛠️ Hands-On Assessments ({interviewQuestions.handson.length})
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="warning" sx={{ mb: 2 }}>
                    Many companies now include practical assessments. Practice CTFs, code review, and whiteboarding to prepare.
                  </Alert>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700, width: "65%" }}>Assessment Type</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Level</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Topic</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {interviewQuestions.handson.map((item, i) => (
                          <TableRow key={i} hover>
                            <TableCell>{item.q}</TableCell>
                            <TableCell>
                              <Chip
                                label={item.level}
                                size="small"
                                sx={{
                                  bgcolor: alpha(item.level === "Mid" ? "#f59e0b" : "#ef4444", 0.1),
                                  color: item.level === "Mid" ? "#f59e0b" : "#ef4444",
                                }}
                              />
                            </TableCell>
                            <TableCell>
                              <Chip label={item.topic} size="small" variant="outlined" />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Paper sx={{ p: 2, mt: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                  ✅ Interview Preparation Checklist
                </Typography>
                <Grid container spacing={2}>
                  {[
                    "Review the job description and required skills thoroughly",
                    "Research the company's security posture and recent news",
                    "Prepare 3-5 STAR stories covering different scenarios",
                    "Practice explaining technical concepts to non-technical people",
                    "Prepare thoughtful questions for each interviewer",
                    "Set up a clean, professional environment (for video)",
                    "Test your audio/video before the call",
                    "Have your resume and notes easily accessible",
                    "Practice with mock interviews (peers, mentors, or online)",
                    "Prepare a 2-minute introduction/elevator pitch",
                    "Review common tools and frameworks for the role",
                    "Get a good night's sleep before the interview",
                  ].map((item, i) => (
                    <Grid item xs={12} md={6} key={i}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#22c55e" }} />
                        <Typography variant="body2">{item}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 5: Career Transitions */}
          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Many cybersecurity professionals transition from related IT fields. Your existing experience is valuable – here's how to leverage it. The difficulty rating (1-5) indicates how challenging the transition typically is.
              </Alert>

              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>From</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>To</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Transition Path</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Timeline</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Difficulty</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {careerTransitions.map((transition, i) => (
                      <TableRow key={i} hover>
                        <TableCell sx={{ fontWeight: 600 }}>{transition.from}</TableCell>
                        <TableCell sx={{ color: "#3b82f6", fontWeight: 600 }}>{transition.to}</TableCell>
                        <TableCell sx={{ color: "text.secondary", maxWidth: 300 }}>{transition.path}</TableCell>
                        <TableCell>
                          <Chip label={transition.time} size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
                        </TableCell>
                        <TableCell>
                          <Rating value={transition.difficulty} readOnly size="small" max={5} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <EmojiEventsIcon sx={{ color: "#22c55e" }} /> Transferable Skills
                    </Typography>
                    <List dense>
                      {[
                        "Networking knowledge (routing, firewalls, protocols)",
                        "System administration (Windows/Linux)",
                        "Scripting and automation (Python, PowerShell, Bash)",
                        "Problem-solving and troubleshooting methodology",
                        "Documentation and technical writing",
                        "Understanding of business operations and processes",
                        "Compliance and audit experience",
                        "Customer service and communication skills",
                        "Project management and organization",
                        "Understanding of software development lifecycle",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#22c55e" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <WarningIcon sx={{ color: "#ef4444" }} /> Common Transition Mistakes
                    </Typography>
                    <List dense>
                      {commonMistakes.slice(0, 10).map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.5 }}>
                          <ListItemText 
                            primary={item.mistake}
                            secondary={<Typography variant="caption" sx={{ color: "#22c55e" }}>Fix: {item.fix}</Typography>}
                            primaryTypographyProps={{ variant: "body2", fontWeight: 600 }} 
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Alert severity="success" sx={{ mt: 3 }}>
                <strong>Pro Tip:</strong> When transitioning, focus on bridging your current expertise to security. A network admin understands network traffic – that's the foundation for security monitoring. A developer understands code – that's the foundation for secure coding and AppSec.
              </Alert>
            </Box>
          </TabPanel>

          {/* Tab 6: Industry Trends */}
          <TabPanel value={tabValue} index={6}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Staying current with industry trends helps you anticipate skill demands and position yourself for emerging opportunities. Focus on trends rated "Very High" for maximum career impact.
              </Alert>

              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Trend</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Career Impact</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Job Growth</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {industryTrends.map((trend, i) => (
                      <TableRow key={i} hover>
                        <TableCell sx={{ fontWeight: 600 }}>{trend.trend}</TableCell>
                        <TableCell>
                          <Chip
                            label={trend.impact}
                            size="small"
                            sx={{
                              bgcolor: alpha(trend.impact === "Very High" ? "#ef4444" : trend.impact === "High" ? "#f59e0b" : "#22c55e", 0.1),
                              color: trend.impact === "Very High" ? "#ef4444" : trend.impact === "High" ? "#f59e0b" : "#22c55e",
                              fontWeight: 600,
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={trend.growth}
                            size="small"
                            variant="outlined"
                            sx={{
                              borderColor: trend.growth === "Explosive" || trend.growth === "Very High" ? "#22c55e" : "#3b82f6",
                              color: trend.growth === "Explosive" || trend.growth === "Very High" ? "#22c55e" : "#3b82f6",
                            }}
                          />
                        </TableCell>
                        <TableCell sx={{ color: "text.secondary", maxWidth: 350 }}>{trend.description}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                      🔥 Hot Skills for 2024-2025
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {[
                        "Kubernetes Security", "AI/ML Security", "LLM Security", "Cloud-Native",
                        "Zero Trust", "SBOM/Supply Chain", "API Security", "Threat Hunting",
                        "Detection Engineering", "Security Automation", "Privacy Engineering",
                        "OT/ICS Security", "Identity Security (ITDR)", "Container Security",
                        "Fuzzing/VulnResearch", "Network Segmentation", "SASE/SSE", "Post-Quantum Crypto",
                      ].map((skill) => (
                        <Chip key={skill} label={skill} size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                      📰 Stay Updated
                    </Typography>
                    <List dense>
                      {[
                        "Krebs on Security (news & analysis)",
                        "The Hacker News (daily security news)",
                        "SANS Reading Room (research papers)",
                        "Security Weekly (podcasts)",
                        "Darknet Diaries (storytelling podcast)",
                        "Risky Business (news podcast)",
                        "Twitter/X security community (#infosec)",
                        "r/netsec, r/cybersecurity, r/AskNetSec",
                        "tl;dr sec newsletter",
                        "Morning Brew Cybersecurity edition",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Alert severity="warning" sx={{ mt: 3 }}>
                <strong>AI Impact:</strong> AI is transforming security roles. Focus on skills that complement AI (critical thinking, creative problem-solving, business context) rather than tasks AI can automate. Learn to use AI tools effectively as force multipliers.
              </Alert>
            </Box>
          </TabPanel>

          {/* Tab 7: Networking & Mentorship */}
          <TabPanel value={tabValue} index={7}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Building relationships in the security community is often more valuable than certifications. Many jobs are filled through referrals before they're posted publicly.
              </Alert>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <CampaignIcon sx={{ color: "#8b5cf6" }} /> Networking Resources
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Resource</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Cost</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {networkingResources.map((resource, i) => (
                      <TableRow key={i} hover>
                        <TableCell sx={{ fontWeight: 600 }}>{resource.name}</TableCell>
                        <TableCell>
                          <Chip label={resource.type} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell sx={{ color: "text.secondary" }}>{resource.description}</TableCell>
                        <TableCell sx={{ color: resource.cost === "Free" ? "#22c55e" : "inherit" }}>{resource.cost}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <PersonIcon sx={{ color: "#3b82f6" }} /> Finding a Mentor
                    </Typography>
                    <List dense>
                      {mentorshipGuidance.finding.map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.5 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <DiversityIcon sx={{ color: "#22c55e" }} /> Being a Mentor / Giving Back
                    </Typography>
                    <List dense>
                      {mentorshipGuidance.being.map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.5 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#22c55e" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Paper sx={{ p: 2, mt: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                  💡 Networking Best Practices
                </Typography>
                <Grid container spacing={2}>
                  {[
                    "Give before you ask - share resources, help others",
                    "Be genuine - don't network just to get something",
                    "Follow up after meeting people (LinkedIn, email)",
                    "Engage consistently, not just when job hunting",
                    "Share your learning journey publicly",
                    "Attend the same events regularly to build familiarity",
                    "Offer to help organize local meetups",
                    "Create content that helps others",
                  ].map((item, i) => (
                    <Grid item xs={12} md={6} key={i}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <LightbulbIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                        <Typography variant="body2">{item}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 8: Remote Work */}
          <TabPanel value={tabValue} index={8}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Remote work has become standard in many security roles. Understanding which roles are remote-friendly and how to succeed remotely can expand your opportunities significantly.
              </Alert>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
                      <HomeIcon /> Highly Remote-Friendly
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {remoteWorkData.highlyRemote.map((role) => (
                        <Chip key={role} label={role} size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
                      <DevicesIcon /> Moderately Remote-Friendly
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {remoteWorkData.moderatelyRemote.map((role) => (
                        <Chip key={role} label={role} size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.2)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
                      <AdminPanelSettingsIcon /> Less Remote-Friendly
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {remoteWorkData.lessRemote.map((role) => (
                        <Chip key={role} label={role} size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              </Grid>

              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}`, mb: 3 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                  🏠 Remote Work Success Tips
                </Typography>
                <Grid container spacing={2}>
                  {remoteWorkData.tips.map((tip, i) => (
                    <Grid item xs={12} md={6} key={i}>
                      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6", mt: 0.25 }} />
                        <Typography variant="body2">{tip}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                      🌍 Geographic Arbitrage
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Some companies pay market rate regardless of location. Living in a lower cost-of-living area while earning big-city salaries can significantly increase your effective income.
                    </Typography>
                    <List dense>
                      {[
                        "Research company pay philosophy (location-based vs. role-based)",
                        "Consider states with no income tax (TX, FL, WA, NV)",
                        "Factor in cost of living, not just salary",
                        "Some companies adjust salary if you relocate",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#8b5cf6" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                      ⚠️ Remote Work Challenges
                    </Typography>
                    <List dense>
                      {[
                        "Harder to build relationships and get visibility",
                        "May miss out on informal learning opportunities",
                        "Time zone differences can complicate collaboration",
                        "Self-discipline required for productivity",
                        "Work-life boundary management is harder",
                        "Some companies are returning to office (RTO)",
                        "Career advancement may be slower without face time",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <WarningIcon sx={{ fontSize: 14, color: "#ec4899" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              </Grid>
            </Box>
          </TabPanel>

          {/* Tab 9: Getting Started */}
          <TabPanel value={tabValue} index={9}>
            <Box sx={{ p: 2 }}>
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, ${alpha("#22c55e", 0.05)}, ${alpha("#10b981", 0.05)})`,
                  border: `1px solid ${alpha("#22c55e", 0.2)}`,
                  mb: 3,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <WorkIcon sx={{ color: "#22c55e" }} /> Breaking Into Cybersecurity
                </Typography>
                <List dense>
                  {entryTips.map((tip, i) => (
                    <ListItem key={i} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckCircleIcon sx={{ fontSize: 18, color: "#22c55e" }} />
                      </ListItemIcon>
                      <ListItemText primary={tip} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📄 Resume Tips</Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {resumeTips.map((section) => (
                  <Grid item xs={12} md={6} key={section.category}>
                    <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>
                        {section.category}
                      </Typography>
                      <List dense disablePadding>
                        {section.tips.map((tip, i) => (
                          <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                            <ListItemIcon sx={{ minWidth: 20 }}>
                              <CheckCircleIcon sx={{ fontSize: 12, color: "#22c55e" }} />
                            </ListItemIcon>
                            <ListItemText primary={tip} primaryTypographyProps={{ variant: "caption" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Alert severity="success" sx={{ mb: 3 }}>
                <strong>Pro Tip:</strong> Your home lab IS experience. Document everything you build and learn. A well-maintained GitHub with security projects can be as valuable as formal work experience for entry-level roles.
              </Alert>

              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                  🏠 Essential Home Lab Setup
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { item: "Virtualization", desc: "VMware Workstation/VirtualBox for running VMs" },
                    { item: "Kali Linux", desc: "Primary pentesting distribution with tools pre-installed" },
                    { item: "Windows VM", desc: "For AD testing, malware analysis, Windows security" },
                    { item: "Vulnerable VMs", desc: "DVWA, Metasploitable, VulnHub machines" },
                    { item: "Security Tools", desc: "Burp Suite, Wireshark, Nmap, Metasploit" },
                    { item: "SIEM Setup", desc: "ELK Stack or Splunk Free for log analysis" },
                    { item: "Network Lab", desc: "pfSense/OPNsense firewall, VLANs, IDS/IPS (Suricata)" },
                    { item: "Fuzzing Setup", desc: "AFL++, LibFuzzer, target binaries for practice" },
                    { item: "Debug Environment", desc: "GDB with pwndbg/GEF, WinDbg for Windows" },
                  ].map((lab, i) => (
                    <Grid item xs={12} md={6} key={i}>
                      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6", mt: 0.5 }} />
                        <Box>
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>{lab.item}</Typography>
                          <Typography variant="caption" color="text.secondary">{lab.desc}</Typography>
                        </Box>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>
          </TabPanel>
        </Paper>

        {/* Related Pages */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            📚 Related Learning
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip
              label="Security Certifications →"
              clickable
              onClick={() => navigate("/learn/certifications")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="Build Your Portfolio →"
              clickable
              onClick={() => navigate("/learn/portfolio")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="SOC Workflow →"
              clickable
              onClick={() => navigate("/learn/soc-workflow")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="Incident Response →"
              clickable
              onClick={() => navigate("/learn/incident-response")}
              sx={{ fontWeight: 600 }}
            />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
