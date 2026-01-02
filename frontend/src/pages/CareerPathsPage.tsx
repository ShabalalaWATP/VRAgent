import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import { Link } from "react-router-dom";
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
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
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
import CalendarMonthIcon from "@mui/icons-material/CalendarMonth";
import LocalFireDepartmentIcon from "@mui/icons-material/LocalFireDepartment";
import FavoriteIcon from "@mui/icons-material/Favorite";
import ComputerIcon from "@mui/icons-material/Computer";
import MemoryIcon from "@mui/icons-material/Memory";
import DownloadIcon from "@mui/icons-material/Download";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import SettingsIcon from "@mui/icons-material/Settings";
import ChecklistIcon from "@mui/icons-material/Checklist";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutline";
import WorkspacePremiumIcon from "@mui/icons-material/WorkspacePremium";
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

interface LearningPathItem {
  course: string;
  provider: string;
  description: string;
  duration: string;
  link?: string;
}

interface CareerLearningPath {
  beginner: LearningPathItem[];
  intermediate: LearningPathItem[];
  advanced: LearningPathItem[];
}

interface CareerAdvice {
  gettingStarted: string[];
  commonMistakes: string[];
  successTips: string[];
  dayOneActionPlan: string[];
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
  learningPath: CareerLearningPath;
  careerAdvice: CareerAdvice;
  certPathType: string; // Maps to CyberSecurityCertificationsPage CareerPathType
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
    certPathType: "offensive",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", description: "Foundation in security concepts, threats, and tools", duration: "2-3 months", link: "/learn/certifications" },
        { course: "CompTIA Network+", provider: "CompTIA", description: "Networking fundamentals essential for pentesting", duration: "2-3 months", link: "/learn/certifications" },
        { course: "TryHackMe Complete Beginner Path", provider: "TryHackMe", description: "Hands-on introduction to hacking fundamentals", duration: "1-2 months", link: "/learn/certifications" },
        { course: "eJPT (eLearnSecurity Junior Penetration Tester)", provider: "INE", description: "Entry-level penetration testing certification", duration: "2-3 months", link: "/learn/certifications" },
        { course: "TCM Practical Ethical Hacking", provider: "TCM Security", description: "Practical beginner-friendly pentesting course", duration: "1-2 months", link: "/learn/certifications" },
      ],
      intermediate: [
        { course: "OSCP (Offensive Security Certified Professional)", provider: "Offensive Security", description: "Industry gold standard for penetration testing", duration: "6-12 months", link: "/learn/certifications" },
        { course: "PNPT (Practical Network Penetration Tester)", provider: "TCM Security", description: "Practical pentesting with AD focus", duration: "3-4 months", link: "/learn/certifications" },
        { course: "CRTP (Certified Red Team Professional)", provider: "Altered Security", description: "Active Directory attacks and enumeration", duration: "2-3 months", link: "/learn/certifications" },
        { course: "eCPPT (Certified Professional Penetration Tester)", provider: "INE", description: "Advanced penetration testing methodology", duration: "3-4 months", link: "/learn/certifications" },
        { course: "GPEN (GIAC Penetration Tester)", provider: "SANS", description: "Comprehensive penetration testing certification", duration: "2-3 months", link: "/learn/certifications" },
        { course: "HackTheBox CPTS", provider: "HackTheBox", description: "Advanced pentesting with real-world scenarios", duration: "4-6 months", link: "/learn/certifications" },
      ],
      advanced: [
        { course: "OSEP (PEN-300)", provider: "Offensive Security", description: "Advanced evasion and red team operations", duration: "6-9 months", link: "/learn/certifications" },
        { course: "CRTO (Certified Red Team Operator)", provider: "Zero-Point Security", description: "Cobalt Strike and advanced red team tactics", duration: "3-4 months", link: "/learn/certifications" },
        { course: "OSWE (Web Expert)", provider: "Offensive Security", description: "Advanced web application exploitation", duration: "4-6 months", link: "/learn/certifications" },
        { course: "GXPN (GIAC Exploit Researcher)", provider: "SANS", description: "Advanced exploit development and research", duration: "3-4 months", link: "/learn/certifications" },
        { course: "OSCE3 (Triple Offensive Security)", provider: "Offensive Security", description: "OSEP + OSWE + OSED combination", duration: "12-18 months", link: "/learn/certifications" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Build a home lab with vulnerable VMs (VulnHub, HackTheBox)",
        "Practice on CTF platforms daily (TryHackMe, HackTheBox)",
        "Learn Python scripting for automation and tool development",
        "Master Linux command line and bash scripting",
        "Study the OWASP Top 10 and practice on WebGoat/Juice Shop",
        "Network with other pentesters on Discord communities",
      ],
      commonMistakes: [
        "Jumping to OSCP without proper foundations",
        "Relying only on automated tools without understanding",
        "Neglecting report writing and communication skills",
        "Not documenting methodologies and findings properly",
        "Ignoring defensive security knowledge",
      ],
      successTips: [
        "Always think about the 'why' behind vulnerabilities, not just the 'how'",
        "Develop your own methodology and checklists",
        "Create writeups for CTFs and share your learning journey",
        "Build relationships with blue team - they're your allies",
        "Stay current with new CVEs and exploitation techniques",
        "Practice explaining technical findings to non-technical audiences",
      ],
      dayOneActionPlan: [
        "Sign up for TryHackMe and start the 'Pre Security' path",
        "Download and install Kali Linux in a VM",
        "Set up a GitHub account for your security projects",
        "Join the TryHackMe and HackTheBox Discord servers",
        "Start learning basic networking (TCP/IP, DNS, HTTP)",
        "Watch John Hammond or IppSec videos on YouTube",
      ],
    },
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
    certPathType: "defensive",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", description: "Foundation security concepts and SOC fundamentals", duration: "2-3 months", link: "/learn/certifications" },
        { course: "CompTIA CySA+", provider: "CompTIA", description: "Security analytics and threat detection basics", duration: "2-3 months", link: "/learn/certifications" },
        { course: "TryHackMe SOC Level 1 Path", provider: "TryHackMe", description: "Hands-on SOC analyst training", duration: "2-3 months", link: "/learn/certifications" },
        { course: "LetsDefend SOC Analyst Path", provider: "LetsDefend", description: "Realistic SOC training with alert triage", duration: "2-3 months", link: "/learn/certifications" },
        { course: "Blue Team Level 1 (BTL1)", provider: "Security Blue Team", description: "Entry-level defensive security certification", duration: "2-3 months", link: "/learn/certifications" },
        { course: "ISC2 CC (Certified in Cybersecurity)", provider: "ISC2", description: "Free foundational security certification", duration: "1-2 months", link: "/learn/certifications" },
      ],
      intermediate: [
        { course: "GCIH (GIAC Certified Incident Handler)", provider: "SANS SEC504", description: "Incident handling and hacker techniques", duration: "3-4 months", link: "/learn/certifications" },
        { course: "GCFA (GIAC Certified Forensic Analyst)", provider: "SANS FOR508", description: "Digital forensics and incident response", duration: "3-4 months", link: "/learn/certifications" },
        { course: "Blue Team Level 2 (BTL2)", provider: "Security Blue Team", description: "Advanced incident response and threat hunting", duration: "3-4 months", link: "/learn/certifications" },
        { course: "Microsoft SC-200", provider: "Microsoft", description: "Security operations analyst certification", duration: "2-3 months", link: "/learn/certifications" },
        { course: "Splunk Core Certified Power User", provider: "Splunk", description: "Advanced SIEM skills with Splunk", duration: "1-2 months", link: "/learn/certifications" },
        { course: "Elastic Certified Analyst", provider: "Elastic", description: "Security analytics with Elastic Stack", duration: "2-3 months", link: "/learn/certifications" },
        { course: "GCTI (GIAC Cyber Threat Intelligence)", provider: "SANS FOR578", description: "Threat intelligence collection and analysis", duration: "3-4 months", link: "/learn/certifications" },
      ],
      advanced: [
        { course: "GCIA (GIAC Certified Intrusion Analyst)", provider: "SANS SEC503", description: "Network traffic analysis and intrusion detection", duration: "3-4 months", link: "/learn/certifications" },
        { course: "GNFA (GIAC Network Forensic Analyst)", provider: "SANS FOR572", description: "Advanced network forensics", duration: "3-4 months", link: "/learn/certifications" },
        { course: "GREM (GIAC Reverse Engineering Malware)", provider: "SANS FOR610", description: "Malware analysis and reverse engineering", duration: "4-6 months", link: "/learn/certifications" },
        { course: "GDAT (GIAC Defending Advanced Threats)", provider: "SANS", description: "Advanced threat detection and hunting", duration: "3-4 months", link: "/learn/certifications" },
        { course: "CISSP", provider: "ISC2", description: "Senior security management certification", duration: "4-6 months", link: "/learn/certifications" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Set up a home SIEM lab (Splunk Free, Elastic Stack, or Wazuh)",
        "Practice with Blue Team Labs Online challenges",
        "Learn to read and analyze logs (Windows Event Logs, Syslog)",
        "Study the MITRE ATT&CK framework thoroughly",
        "Practice malware analysis basics in a sandbox",
        "Build familiarity with common attack patterns",
      ],
      commonMistakes: [
        "Alert fatigue - learn to prioritize and not burn out",
        "Not documenting investigation steps and findings",
        "Tunnel vision - always consider the broader context",
        "Ignoring soft skills and communication",
        "Not automating repetitive tasks",
      ],
      successTips: [
        "Develop your own investigation playbooks and checklists",
        "Learn to write effective detection rules (Sigma, YARA)",
        "Build relationships with red team to understand attack techniques",
        "Practice explaining incidents to non-technical stakeholders",
        "Stay current with threat intelligence feeds and advisories",
        "Contribute to the community with writeups and detection rules",
      ],
      dayOneActionPlan: [
        "Sign up for LetsDefend free tier and start SOC training",
        "Set up Splunk Free in a VM for hands-on SIEM practice",
        "Start the TryHackMe 'SOC Level 1' learning path",
        "Join the Blue Team Discord and Reddit communities",
        "Learn to read Windows Event Logs (start with 4624, 4625, 4688)",
        "Study MITRE ATT&CK tactics - start with Initial Access and Execution",
      ],
    },
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
    certPathType: "engineering",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", description: "Security fundamentals for engineers", duration: "2-3 months", link: "/learn/certifications" },
        { course: "AWS Cloud Practitioner", provider: "AWS", description: "Cloud fundamentals prerequisite", duration: "1 month", link: "/learn/certifications" },
        { course: "AZ-900 Azure Fundamentals", provider: "Microsoft", description: "Azure cloud basics", duration: "1 month", link: "/learn/certifications" },
        { course: "Linux Essentials / Linux+", provider: "LPI/CompTIA", description: "Linux administration skills", duration: "2 months", link: "/learn/certifications" },
        { course: "Docker Fundamentals", provider: "Docker", description: "Containerization basics", duration: "1 month", link: "/learn/certifications" },
        { course: "Git & GitHub Security", provider: "Various", description: "Version control and secrets management", duration: "2 weeks", link: "/learn/certifications" },
      ],
      intermediate: [
        { course: "AWS Security Specialty", provider: "AWS", description: "AWS security services and best practices", duration: "3-4 months", link: "/learn/certifications" },
        { course: "AZ-500 Azure Security Engineer", provider: "Microsoft", description: "Azure security implementation", duration: "3-4 months", link: "/learn/certifications" },
        { course: "GCP Professional Cloud Security Engineer", provider: "Google", description: "Google Cloud security", duration: "3-4 months", link: "/learn/certifications" },
        { course: "CKS (Certified Kubernetes Security)", provider: "CNCF", description: "Kubernetes security specialist", duration: "2-3 months", link: "/learn/certifications" },
        { course: "Terraform Associate", provider: "HashiCorp", description: "Infrastructure as Code security", duration: "1-2 months", link: "/learn/certifications" },
        { course: "GCSA (GIAC Cloud Security Automation)", provider: "SANS SEC540", description: "DevSecOps and cloud security automation", duration: "3-4 months", link: "/learn/certifications" },
        { course: "SC-300 Identity and Access Administrator", provider: "Microsoft", description: "Azure AD and identity security", duration: "2-3 months", link: "/learn/certifications" },
      ],
      advanced: [
        { course: "CCSP (Certified Cloud Security Professional)", provider: "ISC2", description: "Advanced cloud security certification", duration: "4-6 months", link: "/learn/certifications" },
        { course: "CISSP", provider: "ISC2", description: "Security management and architecture", duration: "4-6 months", link: "/learn/certifications" },
        { course: "CISSP-ISSAP (Architecture)", provider: "ISC2", description: "Security architecture specialization", duration: "3-4 months", link: "/learn/certifications" },
        { course: "SC-100 Cybersecurity Architect", provider: "Microsoft", description: "Azure security architecture expert", duration: "3-4 months", link: "/learn/certifications" },
        { course: "AWS Solutions Architect Professional", provider: "AWS", description: "Advanced AWS architecture with security", duration: "3-4 months", link: "/learn/certifications" },
        { course: "TOGAF Certification", provider: "The Open Group", description: "Enterprise architecture framework", duration: "2-3 months", link: "/learn/certifications" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Learn Python and/or Go for security automation",
        "Set up a cloud lab (AWS Free Tier, Azure Free Account)",
        "Practice Infrastructure as Code with Terraform",
        "Study OWASP Top 10 and secure coding principles",
        "Build CI/CD pipelines with security gates",
        "Learn containerization (Docker, Kubernetes basics)",
      ],
      commonMistakes: [
        "Building security tools that developers won't use",
        "Not understanding the developer workflow and pain points",
        "Over-engineering security controls that slow development",
        "Ignoring the business context and risk priorities",
        "Not keeping security tools and controls maintained",
      ],
      successTips: [
        "Make security easy for developers - be an enabler, not a blocker",
        "Automate everything you can - manual gates don't scale",
        "Build relationships with dev teams and understand their challenges",
        "Document your architecture decisions and security patterns",
        "Stay current with cloud provider security features",
        "Contribute to internal security libraries and templates",
      ],
      dayOneActionPlan: [
        "Set up an AWS Free Tier account and enable CloudTrail",
        "Install Docker and run your first container",
        "Create a GitHub repo and set up a basic CI/CD pipeline",
        "Deploy a simple app to AWS/Azure with security controls",
        "Learn Terraform basics with a simple infrastructure project",
        "Follow key DevSecOps practitioners on Twitter/LinkedIn",
      ],
    },
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
    certPathType: "grc",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", description: "Security fundamentals for GRC professionals", duration: "2-3 months", link: "/learn/certifications" },
        { course: "ISC2 CC (Certified in Cybersecurity)", provider: "ISC2", description: "Free foundational security certification", duration: "1-2 months", link: "/learn/certifications" },
        { course: "ISO 27001 Foundation", provider: "Various", description: "Understanding information security management", duration: "1 month", link: "/learn/certifications" },
        { course: "NIST Cybersecurity Framework", provider: "NIST", description: "Free framework training and implementation", duration: "2-4 weeks", link: "/learn/certifications" },
        { course: "SC-900 Security Fundamentals", provider: "Microsoft", description: "Security, compliance, and identity basics", duration: "1 month", link: "/learn/certifications" },
        { course: "Cyber Essentials", provider: "NCSC UK", description: "UK government security baseline certification", duration: "2-4 weeks", link: "/learn/certifications" },
      ],
      intermediate: [
        { course: "CISA (Certified Information Systems Auditor)", provider: "ISACA", description: "IT audit and control certification", duration: "4-6 months", link: "/learn/certifications" },
        { course: "CRISC (Certified in Risk and Information Systems Control)", provider: "ISACA", description: "IT risk management certification", duration: "4-6 months", link: "/learn/certifications" },
        { course: "ISO 27001 Lead Implementer", provider: "Various", description: "Implement ISMS in organizations", duration: "2-3 months", link: "/learn/certifications" },
        { course: "CDPSE (Certified Data Privacy Solutions Engineer)", provider: "ISACA", description: "Privacy engineering and data protection", duration: "3-4 months", link: "/learn/certifications" },
        { course: "CIPM/CIPP (Privacy Management/Professional)", provider: "IAPP", description: "Privacy program management", duration: "2-3 months", link: "/learn/certifications" },
        { course: "SOC 2 Practitioner", provider: "Various", description: "SOC 2 audit preparation and management", duration: "1-2 months", link: "/learn/certifications" },
        { course: "PCI DSS Training", provider: "PCI Council", description: "Payment card industry compliance", duration: "1-2 months", link: "/learn/certifications" },
      ],
      advanced: [
        { course: "CISM (Certified Information Security Manager)", provider: "ISACA", description: "Security management and governance", duration: "4-6 months", link: "/learn/certifications" },
        { course: "CISSP", provider: "ISC2", description: "Comprehensive security management certification", duration: "4-6 months", link: "/learn/certifications" },
        { course: "CISSP-ISSMP (Management)", provider: "ISC2", description: "Security management specialization", duration: "3-4 months", link: "/learn/certifications" },
        { course: "CGEIT (Certified in Governance of Enterprise IT)", provider: "ISACA", description: "IT governance expertise", duration: "4-6 months", link: "/learn/certifications" },
        { course: "ISO 27001 Lead Auditor", provider: "Various", description: "Audit ISMS implementations", duration: "2-3 months", link: "/learn/certifications" },
        { course: "CCISO (Certified Chief Information Security Officer)", provider: "EC-Council", description: "CISO-level leadership certification", duration: "4-6 months", link: "/learn/certifications" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Learn a compliance framework deeply (SOC 2, ISO 27001, or NIST)",
        "Practice writing clear, concise security policies",
        "Develop strong Excel/spreadsheet skills for risk tracking",
        "Understand how business decisions impact security risk",
        "Study regulatory requirements relevant to your industry",
        "Build communication skills for stakeholder management",
      ],
      commonMistakes: [
        "Being too technical and not speaking business language",
        "Creating policies that no one reads or follows",
        "Not understanding the business context and priorities",
        "Checkbox compliance vs. actual security improvement",
        "Not building relationships with other business functions",
      ],
      successTips: [
        "Learn to quantify and communicate risk in business terms",
        "Build relationships across the organization (legal, HR, IT)",
        "Stay current with regulatory changes and industry trends",
        "Develop board-level presentation and communication skills",
        "Focus on continuous improvement, not just compliance",
        "Understand the technical security controls you're auditing",
      ],
      dayOneActionPlan: [
        "Download and read the NIST Cybersecurity Framework",
        "Study the SOC 2 Trust Services Criteria",
        "Practice writing a simple security policy document",
        "Learn about risk assessment methodologies (FAIR, qualitative)",
        "Join ISACA or ISC2 local chapters for networking",
        "Start learning about GDPR and major privacy regulations",
      ],
    },
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
    certPathType: "vulnresearch",
    learningPath: {
      beginner: [
        { course: "C Programming Fundamentals", provider: "Various", description: "Essential for understanding memory corruption", duration: "2-3 months", link: "/learn/certifications" },
        { course: "x86/x64 Assembly Basics", provider: "pwn.college/OpenSecurityTraining", description: "Understanding low-level code execution", duration: "2-3 months", link: "/learn/certifications" },
        { course: "ROP Emporium", provider: "ROP Emporium", description: "Return-oriented programming fundamentals", duration: "1-2 months", link: "/learn/certifications" },
        { course: "pwn.college Intro Challenges", provider: "pwn.college", description: "Binary exploitation fundamentals", duration: "3-4 months", link: "/learn/certifications" },
        { course: "Nightmare Binary Exploitation", provider: "GitHub/Nightmare", description: "Comprehensive binary exploitation course", duration: "3-4 months", link: "/learn/certifications" },
        { course: "OSCP", provider: "Offensive Security", description: "Foundation before specializing in research", duration: "6-12 months", link: "/learn/certifications" },
      ],
      intermediate: [
        { course: "OSED (EXP-301)", provider: "Offensive Security", description: "Windows exploit development fundamentals", duration: "4-6 months", link: "/learn/certifications" },
        { course: "GXPN (GIAC Exploit Researcher)", provider: "SANS SEC660", description: "Advanced penetration testing and exploit writing", duration: "3-4 months", link: "/learn/certifications" },
        { course: "GREM (GIAC Reverse Engineering Malware)", provider: "SANS FOR610", description: "Reverse engineering and malware analysis", duration: "3-4 months", link: "/learn/certifications" },
        { course: "Corelan Exploit Development", provider: "Corelan", description: "Classic Windows exploitation tutorials", duration: "2-3 months", link: "/learn/certifications" },
        { course: "Fuzzing with AFL++", provider: "AFL++/Self-study", description: "Modern fuzzing techniques and automation", duration: "2-3 months", link: "/learn/certifications" },
        { course: "Ghidra/IDA Pro Mastery", provider: "Various", description: "Advanced reverse engineering with disassemblers", duration: "2-3 months", link: "/learn/certifications" },
        { course: "HeapLAB", provider: "Max Kamper", description: "Linux heap exploitation techniques", duration: "2-3 months", link: "/learn/certifications" },
      ],
      advanced: [
        { course: "OSEE (EXP-401)", provider: "Offensive Security", description: "Advanced Windows exploitation (elite cert)", duration: "6-12 months", link: "/learn/certifications" },
        { course: "SANS SEC760", provider: "SANS", description: "Advanced exploit development for pentesters", duration: "4-6 months", link: "/learn/certifications" },
        { course: "Browser Exploitation", provider: "Self-study/Conferences", description: "JavaScript engine and browser security", duration: "6-12 months", link: "/learn/certifications" },
        { course: "Kernel Exploitation", provider: "Self-study/Courses", description: "Operating system kernel vulnerabilities", duration: "6-12 months", link: "/learn/certifications" },
        { course: "Symbolic Execution (angr, Manticore)", provider: "Self-study", description: "Automated vulnerability discovery", duration: "3-4 months", link: "/learn/certifications" },
        { course: "iOS/Android Security Research", provider: "Various", description: "Mobile platform vulnerability research", duration: "6-12 months", link: "/learn/certifications" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Master C programming and understand memory management",
        "Learn x86/x64 assembly language thoroughly",
        "Practice on pwn.college and ROP Emporium challenges",
        "Set up a debugging environment (GDB with pwndbg/peda)",
        "Study classic vulnerability types (buffer overflow, use-after-free)",
        "Read past CVE writeups and exploit techniques",
      ],
      commonMistakes: [
        "Skipping fundamentals (C, assembly) to jump to advanced topics",
        "Not understanding exploitation mitigations (ASLR, DEP, stack canaries)",
        "Giving up too early on difficult problems",
        "Not documenting your research process and findings",
        "Working in isolation instead of engaging with the community",
      ],
      successTips: [
        "Be patient - finding vulnerabilities takes time and persistence",
        "Develop a systematic methodology for target analysis",
        "Follow security researchers on Twitter and read their blogs",
        "Attend and speak at conferences (even small ones)",
        "Participate in bug bounty programs for real-world experience",
        "Contribute to open-source security tools and research",
        "Build relationships with vendor security teams",
      ],
      dayOneActionPlan: [
        "Start learning C with 'The C Programming Language' book",
        "Sign up for pwn.college and complete intro challenges",
        "Install a Linux VM with GDB, pwntools, and pwndbg",
        "Practice basic buffer overflow on simple challenges",
        "Read 'Hacking: The Art of Exploitation' by Jon Erickson",
        "Follow LiveOverflow on YouTube for binary exploitation content",
      ],
    },
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
    certPathType: "network",
    learningPath: {
      beginner: [
        { course: "CompTIA Network+", provider: "CompTIA", description: "Networking fundamentals essential for security", duration: "2-3 months", link: "/learn/certifications" },
        { course: "CompTIA Security+", provider: "CompTIA", description: "Security concepts with networking context", duration: "2-3 months", link: "/learn/certifications" },
        { course: "CCNA (Cisco Certified Network Associate)", provider: "Cisco", description: "Cisco networking fundamentals", duration: "3-4 months", link: "/learn/certifications" },
        { course: "Palo Alto Networks Fundamentals", provider: "Palo Alto/Beacon", description: "Next-gen firewall basics", duration: "1-2 months", link: "/learn/certifications" },
        { course: "Fortinet NSE 1-3", provider: "Fortinet", description: "Free foundational network security training", duration: "1-2 months", link: "/learn/certifications" },
        { course: "pfSense/OPNsense Home Lab", provider: "Self-study", description: "Hands-on firewall experience", duration: "1-2 months", link: "/learn/certifications" },
      ],
      intermediate: [
        { course: "CCNP Security (SCOR + Concentration)", provider: "Cisco", description: "Advanced Cisco security technologies", duration: "6-9 months", link: "/learn/certifications" },
        { course: "PCNSA/PCNSE (Palo Alto)", provider: "Palo Alto Networks", description: "Palo Alto firewall administration and engineering", duration: "3-4 months", link: "/learn/certifications" },
        { course: "Fortinet NSE 4-6", provider: "Fortinet", description: "FortiGate administration and security", duration: "3-4 months", link: "/learn/certifications" },
        { course: "GCIA (GIAC Certified Intrusion Analyst)", provider: "SANS SEC503", description: "Network traffic analysis and IDS", duration: "3-4 months", link: "/learn/certifications" },
        { course: "F5 Certified Administrator", provider: "F5", description: "Load balancer and WAF administration", duration: "2-3 months", link: "/learn/certifications" },
        { course: "Check Point CCSA", provider: "Check Point", description: "Check Point firewall administration", duration: "2-3 months", link: "/learn/certifications" },
        { course: "Wireshark WCNA", provider: "Wireshark", description: "Advanced packet analysis certification", duration: "2-3 months", link: "/learn/certifications" },
      ],
      advanced: [
        { course: "CCIE Security", provider: "Cisco", description: "Expert-level Cisco security certification", duration: "12-18 months", link: "/learn/certifications" },
        { course: "PCNSE (Expert)", provider: "Palo Alto Networks", description: "Palo Alto expert-level certification", duration: "4-6 months", link: "/learn/certifications" },
        { course: "Fortinet NSE 7-8", provider: "Fortinet", description: "Expert-level Fortinet certification", duration: "6-9 months", link: "/learn/certifications" },
        { course: "JNCIE-SEC (Juniper Expert)", provider: "Juniper", description: "Juniper expert security certification", duration: "6-9 months", link: "/learn/certifications" },
        { course: "CISSP", provider: "ISC2", description: "Security management with network focus", duration: "4-6 months", link: "/learn/certifications" },
        { course: "Zero Trust Architecture Design", provider: "Various/NIST", description: "Modern network security architecture", duration: "2-3 months", link: "/learn/certifications" },
        { course: "SASE/SSE Architecture", provider: "Vendor-specific", description: "Secure access service edge design", duration: "2-3 months", link: "/learn/certifications" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Set up a home lab with pfSense or OPNsense firewall",
        "Master TCP/IP fundamentals and common protocols",
        "Learn to read packet captures in Wireshark",
        "Understand network segmentation and VLANs",
        "Practice with GNS3 or EVE-NG for network simulation",
        "Study the OSI model and how security applies at each layer",
      ],
      commonMistakes: [
        "Not understanding the network before securing it",
        "Creating firewall rules without proper documentation",
        "Over-blocking that impacts business operations",
        "Ignoring logging and monitoring capabilities",
        "Not testing changes in a lab environment first",
      ],
      successTips: [
        "Always document your firewall rules and their business purpose",
        "Build strong relationships with network operations teams",
        "Stay current with emerging threats targeting networks",
        "Learn multiple vendor platforms - don't be single-vendor focused",
        "Understand the business context for network changes",
        "Develop automation skills (Python, Ansible) for scale",
      ],
      dayOneActionPlan: [
        "Download and install Wireshark - capture and analyze packets",
        "Set up pfSense in a VM and configure basic firewall rules",
        "Start studying for Network+ or CCNA certification",
        "Practice subnetting and CIDR notation",
        "Learn to read firewall logs and understand rule ordering",
        "Join the Palo Alto Beacon or Fortinet NSE free training",
      ],
    },
  },
];

// Specialized tracks beyond the main six
interface SpecializedLearningPath {
  beginner: { course: string; provider: string; duration: string }[];
  intermediate: { course: string; provider: string; duration: string }[];
  advanced: { course: string; provider: string; duration: string }[];
}

interface SpecializedCareerAdvice {
  gettingStarted: string[];
  dayOneActions: string[];
  successTips: string[];
}

interface SpecializedTrack {
  title: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  skills: string[];
  certs: string[];
  salary: string;
  growth: string;
  certPathType: string; // Maps to CyberSecurityCertificationsPage CareerPathType for deep linking
  learningPath?: SpecializedLearningPath;
  careerAdvice?: SpecializedCareerAdvice;
}

const specializedTracks: SpecializedTrack[] = [
  {
    title: "Application Security (AppSec)",
    icon: <CodeIcon />,
    color: "#ec4899",
    description: "Secure software development lifecycle, code review, threat modeling, and application vulnerability management.",
    skills: ["SAST/DAST tools", "Secure code review", "Threat modeling", "API security", "OWASP Top 10", "Dependency scanning", "Security champions programs"],
    certs: ["CSSLP", "GWEB", "OSWE", "CASE", "GWAPT"],
    salary: "$100K - $250K+",
    growth: "Very High",
    certPathType: "appsec",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "PortSwigger Web Security Academy", provider: "PortSwigger (Free)", duration: "2-3 months" },
        { course: "OWASP Top 10 Training", provider: "OWASP/Various", duration: "2-4 weeks" },
        { course: "TryHackMe Web Fundamentals", provider: "TryHackMe", duration: "1-2 months" },
        { course: "JavaScript/Python Basics", provider: "Various", duration: "2-3 months" },
      ],
      intermediate: [
        { course: "GWEB (GIAC Web Application Penetration Tester)", provider: "SANS SEC542", duration: "3-4 months" },
        { course: "GWAPT (GIAC Web App Penetration Tester)", provider: "SANS SEC542", duration: "3-4 months" },
        { course: "CSSLP (Certified Secure Software Lifecycle Professional)", provider: "ISC2", duration: "3-4 months" },
        { course: "Burp Suite Certified Practitioner (BSCP)", provider: "PortSwigger", duration: "2-3 months" },
        { course: "eWPT (Web Penetration Tester)", provider: "INE", duration: "2-3 months" },
        { course: "Threat Modeling Training", provider: "Various/STRIDE", duration: "1-2 months" },
      ],
      advanced: [
        { course: "OSWE (Web Expert)", provider: "Offensive Security", duration: "4-6 months" },
        { course: "eWPTX (Advanced Web Tester)", provider: "INE", duration: "3-4 months" },
        { course: "GXPN (GIAC Exploit Researcher)", provider: "SANS SEC660", duration: "3-4 months" },
        { course: "CASE (.NET/Java)", provider: "EC-Council", duration: "2-3 months" },
        { course: "Advanced API Security", provider: "Various", duration: "1-2 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Complete PortSwigger Web Security Academy (free, 200+ labs)",
        "Learn to read and understand code in multiple languages",
        "Practice with OWASP WebGoat and Juice Shop",
        "Study the OWASP Testing Guide and ASVS",
        "Set up Burp Suite and learn to intercept traffic",
      ],
      dayOneActions: [
        "Sign up for PortSwigger Academy and complete first 10 labs",
        "Install Burp Suite Community and set up browser proxy",
        "Download and run OWASP Juice Shop locally",
        "Start learning JavaScript or Python fundamentals",
        "Join the OWASP Slack and local chapter",
      ],
      successTips: [
        "Build relationships with developers - be an enabler, not a blocker",
        "Learn to communicate findings in developer-friendly terms",
        "Automate repetitive security checks in CI/CD pipelines",
        "Stay current with new web frameworks and their security features",
        "Create reusable secure coding guidelines for your organization",
      ],
    },
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
    certPathType: "cloud-security",
    learningPath: {
      beginner: [
        { course: "AWS Cloud Practitioner", provider: "AWS", duration: "1-2 months" },
        { course: "AZ-900 Azure Fundamentals", provider: "Microsoft", duration: "1-2 months" },
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "CompTIA Cloud+", provider: "CompTIA", duration: "2-3 months" },
        { course: "Docker Fundamentals", provider: "Docker", duration: "1 month" },
      ],
      intermediate: [
        { course: "AWS Security Specialty", provider: "AWS", duration: "3-4 months" },
        { course: "AZ-500 Azure Security Engineer", provider: "Microsoft", duration: "3-4 months" },
        { course: "GCP Professional Cloud Security Engineer", provider: "Google", duration: "3-4 months" },
        { course: "CKS (Certified Kubernetes Security)", provider: "CNCF", duration: "2-3 months" },
        { course: "Terraform Associate", provider: "HashiCorp", duration: "1-2 months" },
        { course: "SC-300 Identity Administrator", provider: "Microsoft", duration: "2-3 months" },
      ],
      advanced: [
        { course: "CCSP (Certified Cloud Security Professional)", provider: "ISC2", duration: "4-6 months" },
        { course: "AWS Solutions Architect Professional", provider: "AWS", duration: "3-4 months" },
        { course: "GCSA (Cloud Security Automation)", provider: "SANS SEC540", duration: "3-4 months" },
        { course: "SC-100 Cybersecurity Architect", provider: "Microsoft", duration: "3-4 months" },
        { course: "Multi-Cloud Security Architecture", provider: "Various", duration: "2-3 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Set up AWS Free Tier and Azure Free accounts for hands-on practice",
        "Learn Infrastructure as Code (Terraform or CloudFormation)",
        "Understand IAM policies and least privilege principles",
        "Practice with vulnerable cloud labs (CloudGoat, flAWS)",
        "Study the shared responsibility model deeply",
      ],
      dayOneActions: [
        "Create an AWS Free Tier account and enable CloudTrail",
        "Deploy a simple EC2 instance with security groups",
        "Set up an IAM user with least privilege policies",
        "Install Terraform and deploy a basic resource",
        "Review AWS Well-Architected Security Pillar documentation",
      ],
      successTips: [
        "Understand cloud-native security tools before third-party solutions",
        "Automate security guardrails and compliance checks",
        "Learn multiple cloud platforms - don't be single-vendor focused",
        "Build relationships with cloud architecture and DevOps teams",
        "Stay current with new cloud services and their security implications",
      ],
    },
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
    certPathType: "threat-intel",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "MITRE ATT&CK Defender Training", provider: "AttackIQ (Free)", duration: "1-2 months" },
        { course: "OSINT Fundamentals", provider: "Various/SANS SEC487", duration: "2-3 months" },
        { course: "TryHackMe Cyber Threat Intel Path", provider: "TryHackMe", duration: "1-2 months" },
        { course: "SOC Analyst Training", provider: "LetsDefend", duration: "2-3 months" },
      ],
      intermediate: [
        { course: "GCTI (GIAC Cyber Threat Intelligence)", provider: "SANS FOR578", duration: "3-4 months" },
        { course: "GOSI (GIAC Open Source Intelligence)", provider: "SANS SEC487", duration: "3-4 months" },
        { course: "CTIA (Certified Threat Intelligence Analyst)", provider: "EC-Council", duration: "2-3 months" },
        { course: "Malware Analysis Fundamentals", provider: "Various", duration: "2-3 months" },
        { course: "Recorded Future/ThreatConnect Training", provider: "Vendor", duration: "1-2 months" },
      ],
      advanced: [
        { course: "GREM (Reverse Engineering Malware)", provider: "SANS FOR610", duration: "4-6 months" },
        { course: "FOR589 Cybercrime Intel", provider: "SANS", duration: "3-4 months" },
        { course: "Advanced Attribution Techniques", provider: "Various", duration: "2-3 months" },
        { course: "Strategic Intelligence Analysis", provider: "Various", duration: "2-3 months" },
        { course: "Intelligence Program Management", provider: "Various", duration: "1-2 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Master the MITRE ATT&CK framework thoroughly",
        "Practice OSINT techniques with safe, legal targets",
        "Follow threat researchers and intel teams on Twitter",
        "Read threat reports from major security vendors",
        "Learn to write clear, actionable intelligence reports",
      ],
      dayOneActions: [
        "Sign up for AttackIQ Academy (free ATT&CK training)",
        "Start following major threat intel accounts on Twitter",
        "Read 5 recent threat reports from CrowdStrike, Mandiant, etc.",
        "Set up a threat intel RSS feed aggregator",
        "Practice using Maltego Community Edition for OSINT",
      ],
      successTips: [
        "Focus on producing actionable intelligence, not just data",
        "Build relationships with SOC and IR teams to understand their needs",
        "Learn to communicate findings to both technical and executive audiences",
        "Specialize in specific threat actors or regions for deeper expertise",
        "Contribute to the community with responsible intel sharing",
      ],
    },
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
    certPathType: "forensics",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "CompTIA CySA+", provider: "CompTIA", duration: "2-3 months" },
        { course: "Autopsy Basics", provider: "Basis Technology (Free)", duration: "1 month" },
        { course: "TryHackMe Forensics Path", provider: "TryHackMe", duration: "2-3 months" },
        { course: "CyberDefenders Forensic Challenges", provider: "CyberDefenders (Free)", duration: "2-3 months" },
      ],
      intermediate: [
        { course: "GCFE (GIAC Certified Forensic Examiner)", provider: "SANS FOR500", duration: "3-4 months" },
        { course: "GCFA (GIAC Certified Forensic Analyst)", provider: "SANS FOR508", duration: "3-4 months" },
        { course: "EnCE (EnCase Certified Examiner)", provider: "OpenText", duration: "2-3 months" },
        { course: "CHFI (Computer Hacking Forensic Investigator)", provider: "EC-Council", duration: "2-3 months" },
        { course: "X-Ways Forensics Training", provider: "X-Ways", duration: "1-2 months" },
      ],
      advanced: [
        { course: "GNFA (GIAC Network Forensic Analyst)", provider: "SANS FOR572", duration: "3-4 months" },
        { course: "FOR610 Reverse Engineering Malware", provider: "SANS", duration: "4-6 months" },
        { course: "GASF (Advanced Smartphone Forensics)", provider: "SANS FOR585", duration: "3-4 months" },
        { course: "CCE (Certified Computer Examiner)", provider: "ISFCE", duration: "3-4 months" },
        { course: "Expert Witness Training", provider: "Various", duration: "1-2 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Set up a forensics lab with free tools (Autopsy, Volatility, FTK Imager)",
        "Practice with CyberDefenders and DFIR challenges",
        "Learn Windows and Linux artifacts inside and out",
        "Understand chain of custody and evidence handling procedures",
        "Practice writing detailed forensic reports",
      ],
      dayOneActions: [
        "Download and install Autopsy forensics platform",
        "Download FTK Imager for disk imaging practice",
        "Set up a Windows VM and learn registry artifacts",
        "Start the CyberDefenders free forensics challenges",
        "Read 'The Art of Memory Forensics' introduction",
      ],
      successTips: [
        "Documentation is everything - develop meticulous note-taking habits",
        "Learn to explain technical findings in plain language for legal proceedings",
        "Build relationships with legal teams to understand case requirements",
        "Stay current with new forensic artifacts and tools",
        "Practice testifying and presenting findings professionally",
      ],
    },
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
    certPathType: "malware-analysis",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "x86 Assembly Basics", provider: "OpenSecurityTraining2", duration: "2-3 months" },
        { course: "Malware Analysis Basics", provider: "Malware Unicorn (Free)", duration: "1-2 months" },
        { course: "Any.Run Sandbox Training", provider: "Any.Run (Free)", duration: "1 month" },
        { course: "TryHackMe Malware Analysis", provider: "TryHackMe", duration: "2-3 months" },
      ],
      intermediate: [
        { course: "GREM (Reverse Engineering Malware)", provider: "SANS FOR610", duration: "4-6 months" },
        { course: "eCMAP (Certified Malware Analysis Professional)", provider: "INE", duration: "3-4 months" },
        { course: "Practical Malware Analysis (book)", provider: "Self-study", duration: "3-4 months" },
        { course: "YARA Rule Development", provider: "Various", duration: "1-2 months" },
        { course: "IDA Pro/Ghidra Mastery", provider: "Various", duration: "2-3 months" },
      ],
      advanced: [
        { course: "FOR710 Reverse Engineering", provider: "SANS", duration: "4-6 months" },
        { course: "OSED (Exploit Developer)", provider: "Offensive Security", duration: "4-6 months" },
        { course: "Advanced Malware Traffic Analysis", provider: "Various", duration: "2-3 months" },
        { course: "Threat Hunting with Malware Analysis", provider: "Various", duration: "2-3 months" },
        { course: "C2 Framework Analysis", provider: "Self-study", duration: "2-3 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Set up an isolated malware analysis VM environment",
        "Learn x86/x64 assembly language fundamentals",
        "Practice with safe malware samples from MalwareBazaar",
        "Master Ghidra (free) before investing in IDA Pro",
        "Learn to write YARA rules for malware detection",
      ],
      dayOneActions: [
        "Set up a Windows analysis VM with FlareVM",
        "Install Ghidra and complete the intro tutorials",
        "Download samples from MalwareBazaar for practice",
        "Complete Malware Unicorn's free RE101 course",
        "Set up Any.Run free account for dynamic analysis",
      ],
      successTips: [
        "Build a personal malware sample library (safely stored)",
        "Share your YARA rules and analysis with the community",
        "Develop expertise in specific malware families or regions",
        "Build relationships with threat intel teams for collaboration",
        "Stay current with new obfuscation and evasion techniques",
      ],
    },
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
    certPathType: "iam",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "SC-900 Security Fundamentals", provider: "Microsoft", duration: "1 month" },
        { course: "Active Directory Basics", provider: "TryHackMe/Various", duration: "1-2 months" },
        { course: "Azure AD Fundamentals", provider: "Microsoft Learn (Free)", duration: "1-2 months" },
        { course: "Identity Fundamentals", provider: "Various", duration: "1-2 months" },
      ],
      intermediate: [
        { course: "SC-300 Identity & Access Administrator", provider: "Microsoft", duration: "2-3 months" },
        { course: "Okta Certified Professional", provider: "Okta", duration: "2-3 months" },
        { course: "CyberArk Defender", provider: "CyberArk", duration: "2-3 months" },
        { course: "SailPoint IdentityNow Training", provider: "SailPoint", duration: "2-3 months" },
        { course: "SAML/OIDC/OAuth Deep Dive", provider: "Various", duration: "1-2 months" },
      ],
      advanced: [
        { course: "CISSP (Identity Domain Focus)", provider: "ISC2", duration: "4-6 months" },
        { course: "CIAM (Certified Identity & Access Manager)", provider: "Identity Management Institute", duration: "3-4 months" },
        { course: "Zero Trust Architecture Design", provider: "Various", duration: "2-3 months" },
        { course: "Identity Governance & Administration", provider: "Vendor-specific", duration: "2-3 months" },
        { course: "PAM Architecture", provider: "Vendor-specific", duration: "2-3 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Set up a home lab with Active Directory and Azure AD",
        "Learn SAML, OIDC, and OAuth protocols deeply",
        "Understand privileged access management concepts",
        "Study Zero Trust identity principles",
        "Practice with identity attack scenarios (AD attacks)",
      ],
      dayOneActions: [
        "Set up an Azure Free account and create an Entra ID tenant",
        "Deploy Windows Server and configure Active Directory",
        "Complete Microsoft Learn SC-300 learning paths",
        "Set up conditional access policies in Azure AD",
        "Learn to read SAML tokens and OIDC flows",
      ],
      successTips: [
        "Understand both the security and user experience sides of IAM",
        "Build relationships with HR and IT to understand identity lifecycle",
        "Stay current with identity threats and attack techniques",
        "Learn vendor-specific platforms deeply (Okta, Azure AD, CyberArk)",
        "Focus on automation and self-service to scale IAM operations",
      ],
    },
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
    certPathType: "vuln-research",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "OSCP (Penetration Testing)", provider: "Offensive Security", duration: "4-6 months" },
        { course: "C/C++ Programming Fundamentals", provider: "Various", duration: "3-4 months" },
        { course: "x86/x64 Assembly", provider: "OpenSecurityTraining2", duration: "2-3 months" },
        { course: "Reverse Engineering Fundamentals", provider: "Various", duration: "2-3 months" },
      ],
      intermediate: [
        { course: "OSED (Exploit Developer)", provider: "Offensive Security", duration: "4-6 months" },
        { course: "GXPN (Exploit Researcher)", provider: "SANS SEC660", duration: "3-4 months" },
        { course: "Fuzzing Fundamentals", provider: "Various", duration: "2-3 months" },
        { course: "Binary Exploitation", provider: "pwn.college/Various", duration: "3-4 months" },
        { course: "Protocol Analysis & Reversing", provider: "Various", duration: "2-3 months" },
      ],
      advanced: [
        { course: "OSEE (Exploitation Expert)", provider: "Offensive Security", duration: "6-12 months" },
        { course: "Advanced Windows Exploitation", provider: "SANS/OffSec", duration: "4-6 months" },
        { course: "Kernel Exploitation", provider: "Various", duration: "4-6 months" },
        { course: "Browser/Hypervisor Exploitation", provider: "Self-study/Conferences", duration: "6-12 months" },
        { course: "Graduate Research Program", provider: "University", duration: "2-4 years" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Master programming in C/C++ and understand memory management",
        "Learn assembly language and binary analysis deeply",
        "Start with CTF competitions to build practical skills",
        "Read published CVEs and understand how vulnerabilities were found",
        "Follow security researchers on Twitter and read their blog posts",
      ],
      dayOneActions: [
        "Sign up for pwn.college and start the binary exploitation modules",
        "Set up a fuzzing environment with AFL or libFuzzer",
        "Pick an open source project and start reading its code",
        "Join the 0x00sec or OpenSecurityTraining2 Discord communities",
        "Start a research blog to document your learning journey",
      ],
      successTips: [
        "Specialize in a specific area (browser, kernel, mobile, IoT)",
        "Build relationships with vendors for responsible disclosure",
        "Publish your research at conferences (start with local ones)",
        "Contribute to open source security tools",
        "Consider a Master's or PhD for advanced research roles",
      ],
    },
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
    certPathType: "ot-ics",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "ICS/SCADA Fundamentals", provider: "CISA (Free)", duration: "1-2 months" },
        { course: "CompTIA Network+", provider: "CompTIA", duration: "2-3 months" },
        { course: "PLC Basics", provider: "Various/Udemy", duration: "1-2 months" },
        { course: "SANS ICS Concepts", provider: "SANS (Free resources)", duration: "1 month" },
      ],
      intermediate: [
        { course: "GICSP (Global ICS Professional)", provider: "SANS ICS410", duration: "3-4 months" },
        { course: "ISA/IEC 62443 Cybersecurity Fundamentals", provider: "ISA", duration: "2-3 months" },
        { course: "GRID (Response & Defense)", provider: "SANS ICS515", duration: "3-4 months" },
        { course: "OT Network Monitoring", provider: "Dragos/Claroty Training", duration: "1-2 months" },
        { course: "Purdue Model & Segmentation", provider: "Various", duration: "1-2 months" },
      ],
      advanced: [
        { course: "SANS ICS515 Visibility & Detection", provider: "SANS", duration: "3-4 months" },
        { course: "SANS ICS456 Critical Infrastructure", provider: "SANS", duration: "3-4 months" },
        { course: "ICS Red Team Training", provider: "SANS ICS613", duration: "3-4 months" },
        { course: "ISA/IEC 62443 Expert", provider: "ISA", duration: "3-4 months" },
        { course: "CSSA (Certified SCADA Security Architect)", provider: "IACRB", duration: "3-4 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Learn networking fundamentals - OT is heavily network-dependent",
        "Understand the difference between IT and OT security priorities (safety first)",
        "Study the Purdue Model and ICS architecture",
        "Complete CISA's free ICS training resources",
        "Learn about common OT protocols (Modbus, DNP3, EtherNet/IP)",
      ],
      dayOneActions: [
        "Complete CISA's free ICS cybersecurity training",
        "Set up a virtual PLC environment (OpenPLC, GRFICSv2)",
        "Read NIST SP 800-82 Guide to ICS Security",
        "Join the ICS-CERT mailing list for vulnerability alerts",
        "Study recent ICS incidents (Triton, Colonial Pipeline)",
      ],
      successTips: [
        "Understand that availability and safety trump confidentiality in OT",
        "Build relationships with plant engineers and operators",
        "Learn to communicate in operational terms, not just security terms",
        "Gain hands-on experience with actual industrial equipment",
        "Consider industry specialization (energy, manufacturing, water)",
      ],
    },
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
    certPathType: "privacy",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "Privacy Law Fundamentals", provider: "IAPP (Free)", duration: "1-2 months" },
        { course: "GDPR Basics", provider: "Various", duration: "1-2 months" },
        { course: "Data Protection Fundamentals", provider: "Various", duration: "1-2 months" },
        { course: "Software Development Basics", provider: "Various", duration: "2-3 months" },
      ],
      intermediate: [
        { course: "CIPP (Certified Information Privacy Professional)", provider: "IAPP", duration: "2-3 months" },
        { course: "CIPM (Privacy Manager)", provider: "IAPP", duration: "2-3 months" },
        { course: "CIPT (Privacy Technologist)", provider: "IAPP", duration: "2-3 months" },
        { course: "Data Mapping & Classification", provider: "Various", duration: "1-2 months" },
        { course: "Privacy Impact Assessments", provider: "IAPP/Various", duration: "1-2 months" },
      ],
      advanced: [
        { course: "FIP (Fellow of Information Privacy)", provider: "IAPP", duration: "Ongoing" },
        { course: "CDPSE (Data Privacy Solutions Engineer)", provider: "ISACA", duration: "3-4 months" },
        { course: "Privacy-Enhancing Technologies (PETs)", provider: "Various", duration: "2-3 months" },
        { course: "Differential Privacy Implementation", provider: "Academic/Various", duration: "2-3 months" },
        { course: "International Privacy Laws (multi-jurisdiction)", provider: "IAPP", duration: "3-4 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Learn the major privacy regulations (GDPR, CCPA, HIPAA)",
        "Understand the technical implementation of privacy principles",
        "Study Privacy by Design framework",
        "Learn data classification and mapping techniques",
        "Join IAPP and attend local KnowledgeNet meetings",
      ],
      dayOneActions: [
        "Create a free IAPP account and access their learning resources",
        "Read the full text of GDPR Articles 1-50",
        "Study the seven Privacy by Design principles",
        "Map out data flows in a sample application",
        "Review NIST Privacy Framework",
      ],
      successTips: [
        "Bridge the gap between legal and engineering teams",
        "Learn to translate legal requirements into technical specifications",
        "Stay current with evolving privacy regulations globally",
        "Build relationships with DPOs and legal counsel",
        "Focus on automation and scalable privacy solutions",
      ],
    },
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
    certPathType: "bug-bounty",
    learningPath: {
      beginner: [
        { course: "PortSwigger Web Security Academy", provider: "PortSwigger (Free)", duration: "2-3 months" },
        { course: "TryHackMe Bug Bounty Path", provider: "TryHackMe", duration: "2-3 months" },
        { course: "Hacker101 CTF", provider: "HackerOne (Free)", duration: "1-2 months" },
        { course: "Nahamsec's Beginner Bug Bounty Course", provider: "YouTube (Free)", duration: "1-2 months" },
        { course: "OWASP Top 10 Deep Dive", provider: "Various", duration: "1-2 months" },
      ],
      intermediate: [
        { course: "BSCP (Burp Suite Certified Practitioner)", provider: "PortSwigger", duration: "2-3 months" },
        { course: "eWPT (Web Penetration Tester)", provider: "INE", duration: "2-3 months" },
        { course: "Recon Automation with Tools", provider: "Bug Bounty Bootcamp/Various", duration: "1-2 months" },
        { course: "API Security Testing", provider: "APIsec University", duration: "1-2 months" },
        { course: "Bug Bounty Bootcamp (Book)", provider: "Self-study", duration: "2-3 months" },
      ],
      advanced: [
        { course: "OSWE (Web Expert)", provider: "Offensive Security", duration: "4-6 months" },
        { course: "Advanced Bug Bounty Techniques", provider: "PentesterLab", duration: "Ongoing" },
        { course: "Mobile Bug Bounty (iOS/Android)", provider: "Various", duration: "2-3 months" },
        { course: "Source Code Review for Bugs", provider: "Various", duration: "2-3 months" },
        { course: "Exploit Chain Development", provider: "Self-study", duration: "Ongoing" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Complete PortSwigger Academy (all free labs)",
        "Start on HackerOne or Bugcrowd with VDP programs",
        "Build a solid recon methodology and document it",
        "Focus on one vulnerability class until you master it",
        "Read disclosed reports on HackerOne Hacktivity",
      ],
      dayOneActions: [
        "Create accounts on HackerOne and Bugcrowd",
        "Sign up for PortSwigger Web Security Academy",
        "Watch Nahamsec's 'Beginner Bug Bounty' playlist",
        "Pick one program and start with recon",
        "Install and learn Burp Suite basics",
      ],
      successTips: [
        "Be patient - first bounties often take months of learning",
        "Build a unique methodology for finding bugs others miss",
        "Network with other hunters (Twitter, Discord, live hacking events)",
        "Write high-quality reports - good reports get better bounties",
        "Consider live hacking events for networking and learning",
      ],
    },
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
    certPathType: "data-science",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "Python for Data Science", provider: "DataCamp/Coursera", duration: "2-3 months" },
        { course: "Statistics & Probability", provider: "Khan Academy (Free)", duration: "2-3 months" },
        { course: "Machine Learning Fundamentals", provider: "Coursera/Andrew Ng", duration: "3-4 months" },
        { course: "SQL for Data Analysis", provider: "Various", duration: "1-2 months" },
      ],
      intermediate: [
        { course: "AWS ML Specialty", provider: "AWS", duration: "3-4 months" },
        { course: "Google Professional ML Engineer", provider: "Google", duration: "3-4 months" },
        { course: "Deep Learning Specialization", provider: "Coursera/deeplearning.ai", duration: "3-4 months" },
        { course: "Security Log Analysis with ML", provider: "Various", duration: "2-3 months" },
        { course: "Feature Engineering for Security", provider: "Self-study", duration: "2-3 months" },
      ],
      advanced: [
        { course: "NLP for Security Applications", provider: "Various", duration: "2-3 months" },
        { course: "Adversarial Machine Learning", provider: "Academic/Various", duration: "2-3 months" },
        { course: "MLOps for Security Models", provider: "Various", duration: "2-3 months" },
        { course: "Graph Neural Networks for Threat Detection", provider: "Academic/Self-study", duration: "3-4 months" },
        { course: "Security Research with ML (conferences)", provider: "Academic/Industry", duration: "Ongoing" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Build strong foundations in both security and data science",
        "Learn Python deeply - it's the lingua franca of ML",
        "Study how security logs and data are structured",
        "Practice with public security datasets (CICIDS, CTU-13)",
        "Understand the security domain before applying ML",
      ],
      dayOneActions: [
        "Start Andrew Ng's ML course on Coursera",
        "Set up a Python data science environment (Anaconda, Jupyter)",
        "Download the CICIDS2017 dataset and explore it",
        "Join Kaggle and explore security-related competitions",
        "Start learning pandas and scikit-learn libraries",
      ],
      successTips: [
        "Domain knowledge is more important than ML expertise alone",
        "Focus on explainable models - security teams need to understand decisions",
        "Build relationships with SOC teams to understand real problems",
        "Learn to deploy models in production, not just notebooks",
        "Stay current with adversarial ML and model attacks",
      ],
    },
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
    certPathType: "tool-dev",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "Python Programming", provider: "Various", duration: "2-3 months" },
        { course: "Git & Version Control", provider: "Various", duration: "1 month" },
        { course: "REST API Fundamentals", provider: "Various", duration: "1-2 months" },
        { course: "SQL & Database Basics", provider: "Various", duration: "1-2 months" },
      ],
      intermediate: [
        { course: "Go Programming for Security Tools", provider: "Various", duration: "2-3 months" },
        { course: "Docker & Containerization", provider: "Docker", duration: "1-2 months" },
        { course: "OSCP (for domain knowledge)", provider: "Offensive Security", duration: "4-6 months" },
        { course: "FastAPI/Flask Web Development", provider: "Various", duration: "2-3 months" },
        { course: "Security Automation with Python", provider: "Various", duration: "2-3 months" },
      ],
      advanced: [
        { course: "Rust for Security Tools", provider: "Various", duration: "3-4 months" },
        { course: "Kubernetes & Orchestration", provider: "CNCF", duration: "2-3 months" },
        { course: "Security Tool Architecture", provider: "Self-study", duration: "Ongoing" },
        { course: "Open Source Project Management", provider: "Various", duration: "1-2 months" },
        { course: "Performance Optimization", provider: "Various", duration: "2-3 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Learn Python deeply - most security tools start here",
        "Study existing open source security tools (Nmap, Burp extensions, etc.)",
        "Understand the problems SOC/pentest teams face daily",
        "Build small automation scripts that solve real problems",
        "Learn to write clean, documented, testable code",
      ],
      dayOneActions: [
        "Set up a Python development environment with pytest",
        "Clone and study the code of tools like httpx, nuclei, or subfinder",
        "Build a simple port scanner or subdomain enumerator",
        "Create a GitHub repo and start contributing to open source",
        "Learn the basics of API design and documentation",
      ],
      successTips: [
        "Build tools that solve real problems you've experienced",
        "Open source your tools to build reputation and get feedback",
        "Learn Go or Rust - many modern security tools use these",
        "Work closely with security teams to understand their workflows",
        "Focus on UX - good tools are intuitive to use",
      ],
    },
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
    certPathType: "crypto",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "Cryptography I", provider: "Stanford/Coursera", duration: "2-3 months" },
        { course: "Mathematics for Cryptography", provider: "Various", duration: "2-3 months" },
        { course: "PKI Fundamentals", provider: "Various", duration: "1-2 months" },
        { course: "TLS/SSL Deep Dive", provider: "Various", duration: "1-2 months" },
      ],
      intermediate: [
        { course: "Cryptography II", provider: "Stanford/Coursera", duration: "2-3 months" },
        { course: "Applied Cryptography (Schneier book)", provider: "Self-study", duration: "3-4 months" },
        { course: "PKI Implementation", provider: "Vendor-specific", duration: "2-3 months" },
        { course: "HSM Management & Configuration", provider: "Thales/Various", duration: "2-3 months" },
        { course: "CISSP (Cryptography Domain)", provider: "ISC2", duration: "4-6 months" },
      ],
      advanced: [
        { course: "Post-Quantum Cryptography", provider: "Academic/NIST", duration: "3-4 months" },
        { course: "Cryptographic Protocol Analysis", provider: "Academic", duration: "3-4 months" },
        { course: "Secure Multi-Party Computation", provider: "Academic", duration: "2-3 months" },
        { course: "Hardware Security Modules Advanced", provider: "Vendor", duration: "2-3 months" },
        { course: "Zero-Knowledge Proofs", provider: "Academic/Self-study", duration: "3-4 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Build strong math foundations (number theory, algebra)",
        "Take Stanford's free Cryptography course on Coursera",
        "Learn to implement basic cryptographic primitives",
        "Understand why 'don't roll your own crypto' is important",
        "Study TLS handshakes and certificate chains deeply",
      ],
      dayOneActions: [
        "Sign up for Stanford's Cryptography I on Coursera",
        "Set up OpenSSL and create your own CA and certificates",
        "Read about the TLS 1.3 handshake process",
        "Implement simple encryption/decryption in Python (using libraries)",
        "Study NIST's post-quantum cryptography candidates",
      ],
      successTips: [
        "Always use established, audited cryptographic libraries",
        "Understand compliance requirements (FIPS, PCI-DSS, etc.)",
        "Stay current with cryptographic vulnerabilities and deprecations",
        "Build relationships with compliance and audit teams",
        "Follow the post-quantum migration roadmap closely",
      ],
    },
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
    certPathType: "devsecops",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "Linux Fundamentals", provider: "Various", duration: "1-2 months" },
        { course: "Git & GitHub Actions", provider: "Various", duration: "1-2 months" },
        { course: "Docker Fundamentals", provider: "Docker", duration: "1-2 months" },
        { course: "CI/CD Concepts", provider: "Various", duration: "1-2 months" },
      ],
      intermediate: [
        { course: "Terraform Associate", provider: "HashiCorp", duration: "2-3 months" },
        { course: "CKS (Kubernetes Security)", provider: "CNCF", duration: "2-3 months" },
        { course: "AWS DevOps Professional", provider: "AWS", duration: "3-4 months" },
        { course: "SAST/DAST Tool Integration", provider: "Various", duration: "1-2 months" },
        { course: "Secret Management (Vault)", provider: "HashiCorp", duration: "1-2 months" },
      ],
      advanced: [
        { course: "AZ-400 Azure DevOps Expert", provider: "Microsoft", duration: "3-4 months" },
        { course: "GitOps with ArgoCD/Flux", provider: "Various", duration: "2-3 months" },
        { course: "Policy as Code (OPA/Rego)", provider: "Various", duration: "2-3 months" },
        { course: "Supply Chain Security (SLSA, Sigstore)", provider: "Various", duration: "2-3 months" },
        { course: "Security Champion Program Development", provider: "Various", duration: "1-2 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Learn DevOps fundamentals first, then add security",
        "Understand CI/CD pipelines deeply (GitHub Actions, GitLab CI, Jenkins)",
        "Practice with Infrastructure as Code (Terraform, Pulumi)",
        "Learn container security (Docker, Kubernetes)",
        "Understand the SDLC and where security fits in",
      ],
      dayOneActions: [
        "Set up a GitHub repo with Actions for a simple app",
        "Integrate a SAST tool (Semgrep, CodeQL) into your pipeline",
        "Learn Terraform basics and deploy something to AWS/Azure",
        "Set up container scanning with Trivy or Grype",
        "Create a simple secret management workflow",
      ],
      successTips: [
        "Be a partner to developers, not a blocker",
        "Automate everything - manual security doesn't scale",
        "Build security guardrails that are easy to follow",
        "Measure and report on security metrics in pipelines",
        "Stay current with supply chain security developments",
      ],
    },
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
    certPathType: "appsec",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "OWASP Mobile Top 10", provider: "OWASP (Free)", duration: "1 month" },
        { course: "Android Development Basics", provider: "Google/Various", duration: "2-3 months" },
        { course: "iOS Development Basics", provider: "Apple/Various", duration: "2-3 months" },
        { course: "Mobile App Architecture", provider: "Various", duration: "1-2 months" },
      ],
      intermediate: [
        { course: "GMOB (GIAC Mobile Device Security)", provider: "SANS SEC575", duration: "3-4 months" },
        { course: "eMAPT (Mobile Application Penetration Tester)", provider: "INE", duration: "3-4 months" },
        { course: "OWASP MSTG Study", provider: "OWASP (Free)", duration: "2-3 months" },
        { course: "Frida & Objection Training", provider: "Various", duration: "1-2 months" },
        { course: "APK/IPA Reverse Engineering", provider: "Various", duration: "2-3 months" },
      ],
      advanced: [
        { course: "Advanced iOS Security", provider: "Various", duration: "3-4 months" },
        { course: "Android Internals Deep Dive", provider: "Various", duration: "3-4 months" },
        { course: "Mobile Malware Analysis", provider: "Various", duration: "2-3 months" },
        { course: "MDM/EMM Security Architecture", provider: "Vendor-specific", duration: "2-3 months" },
        { course: "Mobile Threat Defense Implementation", provider: "Various", duration: "2-3 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Learn either Android or iOS development basics first",
        "Study the OWASP Mobile Security Testing Guide thoroughly",
        "Set up a mobile testing lab (rooted Android, jailbroken iOS)",
        "Practice with intentionally vulnerable apps (DIVA, iGoat)",
        "Learn to use Frida, Objection, and MobSF",
      ],
      dayOneActions: [
        "Download and read the OWASP Mobile Top 10",
        "Set up Android Studio and create a simple app",
        "Install DIVA (Damn Insecure and Vulnerable App) on an emulator",
        "Learn to decompile an APK with jadx or apktool",
        "Set up Frida and hook your first function",
      ],
      successTips: [
        "Maintain both Android and iOS testing capabilities",
        "Stay current with OS security updates and new protections",
        "Build relationships with mobile development teams",
        "Understand both offensive testing and defensive controls",
        "Follow mobile security researchers on Twitter",
      ],
    },
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
    certPathType: "ot-ics",
    learningPath: {
      beginner: [
        { course: "CompTIA Security+", provider: "CompTIA", duration: "2-3 months" },
        { course: "Embedded Systems Basics", provider: "Various", duration: "2-3 months" },
        { course: "CAN Bus Fundamentals", provider: "Various", duration: "1-2 months" },
        { course: "Automotive Architecture Overview", provider: "SAE/Various", duration: "1-2 months" },
        { course: "C Programming for Embedded", provider: "Various", duration: "2-3 months" },
      ],
      intermediate: [
        { course: "Car Hacking (book by Craig Smith)", provider: "Self-study", duration: "2-3 months" },
        { course: "ISO 21434 Cybersecurity Engineering", provider: "SAE/Various", duration: "2-3 months" },
        { course: "Hardware Hacking Fundamentals", provider: "Various", duration: "2-3 months" },
        { course: "Firmware Analysis & Extraction", provider: "Various", duration: "2-3 months" },
        { course: "Automotive Ethernet & Protocols", provider: "Vector/Various", duration: "1-2 months" },
      ],
      advanced: [
        { course: "UNECE R155/R156 Compliance", provider: "Industry/Various", duration: "2-3 months" },
        { course: "ECU Penetration Testing", provider: "Specialized training", duration: "3-4 months" },
        { course: "V2X Security (Vehicle-to-Everything)", provider: "Industry/Academic", duration: "2-3 months" },
        { course: "Automotive TARA (Threat Analysis)", provider: "Industry", duration: "2-3 months" },
        { course: "Advanced Embedded Exploitation", provider: "Various", duration: "3-4 months" },
      ],
    },
    careerAdvice: {
      gettingStarted: [
        "Learn embedded systems and C programming",
        "Study CAN bus protocol and automotive architecture",
        "Read 'The Car Hacker's Handbook' by Craig Smith",
        "Get hands-on with hardware (Arduino, Raspberry Pi, logic analyzers)",
        "Understand ISO 21434 and automotive security standards",
      ],
      dayOneActions: [
        "Order a CAN bus adapter (CANtact, Macchina M2, etc.)",
        "Set up a virtual CAN environment on Linux",
        "Read the first chapters of Car Hacker's Handbook",
        "Study the CAN bus protocol specification",
        "Follow automotive security researchers (@0xCharlie, etc.)",
      ],
      successTips: [
        "Build relationships with automotive OEMs and suppliers",
        "Understand both IT and OT aspects of vehicle security",
        "Stay current with EV and connected vehicle developments",
        "Learn the regulatory landscape (UNECE, ISO standards)",
        "Consider specializing in specific domains (telematics, infotainment, powertrain)",
      ],
    },
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

// Individual Career Guidance Data
const careerAssessmentQuestions = [
  {
    id: "preference",
    question: "What type of work excites you most?",
    options: [
      { value: "offensive", label: "Breaking things, finding vulnerabilities, simulating attacks", tracks: ["Red Team", "Vulnerability Research", "Bug Bounty Hunter", "Security Research"] },
      { value: "defensive", label: "Protecting systems, detecting threats, incident response", tracks: ["Blue Team", "Digital Forensics", "Threat Intelligence", "Security Engineering"] },
      { value: "building", label: "Building secure systems, automation, tooling", tracks: ["Security Engineering", "DevSecOps Engineer", "Security Tool Developer", "Cloud Security"] },
      { value: "compliance", label: "Policy, risk management, compliance frameworks", tracks: ["GRC", "Privacy Engineering", "Identity & Access Management"] },
    ],
  },
  {
    id: "background",
    question: "What's your current technical background?",
    options: [
      { value: "developer", label: "Software development / programming", tracks: ["AppSec", "DevSecOps Engineer", "Security Tool Developer", "Vulnerability Research"] },
      { value: "sysadmin", label: "System administration / IT operations", tracks: ["Security Engineering", "Cloud Security", "Blue Team", "Identity & Access Management"] },
      { value: "network", label: "Network engineering / administration", tracks: ["Network Security", "OT/ICS Security", "Cloud Security", "Blue Team"] },
      { value: "none", label: "Non-technical / career changer", tracks: ["GRC", "Blue Team", "Threat Intelligence", "Privacy Engineering"] },
    ],
  },
  {
    id: "workstyle",
    question: "How do you prefer to work?",
    options: [
      { value: "solo", label: "Deep, focused solo work on complex problems", tracks: ["Vulnerability Research", "Malware Analysis", "Security Research", "Cryptographic Engineer"] },
      { value: "team", label: "Collaborative team environments", tracks: ["Blue Team", "Security Engineering", "DevSecOps Engineer", "Cloud Security"] },
      { value: "client", label: "Client-facing, varied projects", tracks: ["Red Team", "GRC", "Privacy Engineering", "Digital Forensics"] },
      { value: "independent", label: "Independent work with flexible schedule", tracks: ["Bug Bounty Hunter", "Security Research", "Security Tool Developer"] },
    ],
  },
  {
    id: "learning",
    question: "What's your approach to learning?",
    options: [
      { value: "hands-on", label: "Hands-on labs, CTFs, breaking things", tracks: ["Red Team", "Vulnerability Research", "Bug Bounty Hunter", "AppSec"] },
      { value: "structured", label: "Structured courses and certifications", tracks: ["GRC", "Cloud Security", "Identity & Access Management", "Blue Team"] },
      { value: "research", label: "Reading papers, deep technical dives", tracks: ["Security Research", "Malware Analysis", "Cryptographic Engineer", "Threat Intelligence"] },
      { value: "building", label: "Learning by building projects", tracks: ["Security Tool Developer", "DevSecOps Engineer", "Security Engineering"] },
    ],
  },
];

const careerMilestones = {
  "0-6months": [
    "Complete CompTIA Security+ or equivalent foundational certification",
    "Set up a home lab with virtualization (VirtualBox/VMware)",
    "Complete TryHackMe or HackTheBox beginner paths",
    "Build a portfolio website or GitHub showcasing your learning",
    "Join local security meetups (BSides, OWASP, ISSA)",
    "Start documenting your learning journey (blog/notes)",
    "Apply for internships or entry-level positions",
  ],
  "6-12months": [
    "Land your first security role (even if not 'perfect')",
    "Earn a role-specific certification (CySA+, CEH, or track-specific)",
    "Complete 50+ CTF challenges or vulnerable machines",
    "Contribute to an open-source security project",
    "Attend your first security conference",
    "Build at least one security tool or automation script",
    "Establish a study group or find a mentor",
  ],
  "1-2years": [
    "Achieve intermediate certification (OSCP, CKS, GCIH, etc.)",
    "Specialize in a specific track or domain",
    "Present at a local meetup or conference",
    "Build a reputation in the community (blog, Twitter, Discord)",
    "Earn a promotion or move to a more advanced role",
    "Mentor someone new to the field",
  ],
  "3-5years": [
    "Achieve advanced certifications (OSWE, GXPN, CISSP, etc.)",
    "Lead projects or small teams",
    "Speak at major conferences (BSides, DEF CON villages)",
    "Consider management vs. technical leadership path",
    "Develop deep expertise in chosen specialization",
    "Build industry recognition (CVEs, tools, research)",
  ],
};

const careerMistakesDetailed = [
  {
    mistake: "Chasing every certification",
    solution: "Focus on quality over quantity. Pick certifications that align with your target role. OSCP for pentesting, CKS for Kubernetes, GCIH for IR. One respected cert > five generic ones.",
  },
  {
    mistake: "Neglecting fundamentals",
    solution: "Master networking, Linux, and programming basics. Advanced skills build on fundamentals. If you don't understand TCP/IP, you can't effectively hunt threats or pentest.",
  },
  {
    mistake: "Tutorial hell - only watching courses",
    solution: "Balance learning with doing. For every hour of videos, spend two hours practicing. Build projects, solve CTFs, contribute to open source.",
  },
  {
    mistake: "Applying only to 'junior' roles",
    solution: "Job titles are inconsistent. A 'Security Analyst I' at one company may require more than a 'Senior Analyst' elsewhere. Apply broadly and let them decide.",
  },
  {
    mistake: "Not documenting your learning",
    solution: "Write about what you learn, even if it's 'basic'. Your blog shows thinking and communication skills. Future employers want to see how you approach problems.",
  },
  {
    mistake: "Waiting until you're 'ready'",
    solution: "You'll never feel 100% ready. Start applying when you meet ~60% of requirements. Worst case: you get interview practice. Best case: you get the job.",
  },
  {
    mistake: "Ignoring soft skills",
    solution: "Communication, writing, and collaboration skills separate good analysts from great ones. Practice explaining technical concepts simply. Join Toastmasters if needed.",
  },
  {
    mistake: "Being too passive in your search",
    solution: "Don't just apply online. Network at events, reach out on LinkedIn, contribute to communities. Most jobs are filled through referrals before public posting.",
  },
];

const weeklyStudyPlan = {
  beginner: [
    { day: "Monday", activity: "TryHackMe/HackTheBox - 1-2 rooms/boxes", hours: "2-3" },
    { day: "Tuesday", activity: "Certification study (Security+/CySA+)", hours: "2" },
    { day: "Wednesday", activity: "Programming practice (Python)", hours: "1-2" },
    { day: "Thursday", activity: "Home lab work / documentation", hours: "2" },
    { day: "Friday", activity: "Read security news, blogs, writeups", hours: "1" },
    { day: "Weekend", activity: "Project work, CTF competitions, or rest", hours: "3-4" },
  ],
  intermediate: [
    { day: "Monday", activity: "HackTheBox/Proving Grounds - medium boxes", hours: "3" },
    { day: "Tuesday", activity: "Advanced certification study (OSCP/GCIH)", hours: "2-3" },
    { day: "Wednesday", activity: "Tool development or automation project", hours: "2" },
    { day: "Thursday", activity: "Reading research papers, threat reports", hours: "1-2" },
    { day: "Friday", activity: "Community engagement (write blog, Discord)", hours: "1" },
    { day: "Weekend", activity: "Deep dive project or CTF competition", hours: "4-6" },
  ],
};

const burnoutPrevention = [
  "Set boundaries - security doesn't require 24/7 engagement",
  "Take breaks from screens - physical activity helps retention",
  "Celebrate small wins - completing a room, solving a challenge",
  "Find study buddies - accountability and shared frustration help",
  "Remember why you started - passion makes the journey sustainable",
  "Quality > quantity - focused 2 hours beats distracted 6 hours",
  "Take days completely off - rest is part of the process",
  "Don't compare your progress to others - everyone's path is different",
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

// Home Lab Setup Guide Data
interface HomeLabSetup {
  track: string;
  icon: string;
  color: string;
  description: string;
  minBudget: string;
  recommendedBudget: string;
  hardware: { item: string; purpose: string; cost: string }[];
  software: { name: string; purpose: string; cost: string }[];
  vms: { name: string; purpose: string; link: string }[];
  cloudAlternatives: { service: string; purpose: string; cost: string }[];
  practiceTargets: { name: string; description: string; link: string }[];
  firstWeekSetup: string[];
  tips: string[];
}

const homeLabSetups: HomeLabSetup[] = [
  {
    track: "Offensive Security / Red Team",
    icon: "🔴",
    color: "#ef4444",
    description: "Attack simulation, vulnerability exploitation, and penetration testing practice environment.",
    minBudget: "$0 (cloud-only)",
    recommendedBudget: "$300-500",
    hardware: [
      { item: "Laptop/Desktop (16GB+ RAM, SSD)", purpose: "Run multiple VMs simultaneously", cost: "$400-800 used" },
      { item: "External SSD (500GB+)", purpose: "Store VM images and tools", cost: "$50-80" },
      { item: "Alfa AWUS036ACH WiFi Adapter", purpose: "WiFi pentesting (monitor mode)", cost: "$50-70" },
      { item: "USB Rubber Ducky / Bash Bunny", purpose: "Physical attack simulations", cost: "$50-100" },
      { item: "Raspberry Pi 4 (4GB+)", purpose: "Portable attack platform, network tap", cost: "$55-75" },
    ],
    software: [
      { name: "Kali Linux", purpose: "Primary attack OS with pre-installed tools", cost: "Free" },
      { name: "Parrot OS", purpose: "Alternative to Kali, lighter weight", cost: "Free" },
      { name: "VMware Workstation Pro / VirtualBox", purpose: "Hypervisor for running VMs", cost: "Free / $199" },
      { name: "Burp Suite Community/Pro", purpose: "Web application testing", cost: "Free / $449/yr" },
      { name: "Cobalt Strike (eval/cracked for lab)", purpose: "C2 framework practice", cost: "$$$" },
      { name: "Metasploit Framework", purpose: "Exploitation framework", cost: "Free" },
      { name: "BloodHound", purpose: "Active Directory attack path mapping", cost: "Free" },
    ],
    vms: [
      { name: "Metasploitable 2/3", purpose: "Intentionally vulnerable Linux", link: "https://sourceforge.net/projects/metasploitable/" },
      { name: "DVWA", purpose: "Web app vulnerabilities practice", link: "https://github.com/digininja/DVWA" },
      { name: "VulnHub Machines", purpose: "Hundreds of vulnerable VMs", link: "https://vulnhub.com" },
      { name: "Windows Server Eval", purpose: "AD lab (180-day trial)", link: "https://microsoft.com/evalcenter" },
      { name: "YOURCOMPANY's YOURNETWORK AD Lab", purpose: "Realistic corporate environment", link: "https://github.com/Orange-Cyberdefense/GOAD" },
    ],
    cloudAlternatives: [
      { service: "HackTheBox", purpose: "Ready-made vulnerable machines", cost: "$14-50/mo" },
      { service: "TryHackMe", purpose: "Guided hacking rooms", cost: "Free-$14/mo" },
      { service: "PentesterLab", purpose: "Web app pentesting", cost: "$20/mo" },
      { service: "AWS Free Tier", purpose: "Cloud pentesting lab", cost: "Free (limited)" },
      { service: "Proving Grounds", purpose: "OSCP-style practice boxes", cost: "$19/mo" },
    ],
    practiceTargets: [
      { name: "DVWA (Damn Vulnerable Web App)", description: "PHP web app with OWASP Top 10 vulns", link: "https://github.com/digininja/DVWA" },
      { name: "OWASP Juice Shop", description: "Modern insecure web app (Node.js)", link: "https://owasp.org/www-project-juice-shop/" },
      { name: "Hack The Box", description: "Live machines of varying difficulty", link: "https://hackthebox.com" },
      { name: "VulnHub", description: "Downloadable vulnerable VMs", link: "https://vulnhub.com" },
      { name: "GOAD (Game of Active Directory)", description: "Full AD lab with multiple domains", link: "https://github.com/Orange-Cyberdefense/GOAD" },
      { name: "WebGoat", description: "OWASP learning platform", link: "https://owasp.org/www-project-webgoat/" },
    ],
    firstWeekSetup: [
      "Day 1: Install VMware/VirtualBox, download Kali Linux ISO",
      "Day 2: Set up Kali VM (4GB RAM, 80GB disk), update and snapshot",
      "Day 3: Download and run DVWA in Docker or VM",
      "Day 4: Install Metasploitable 2, practice basic Metasploit",
      "Day 5: Set up Burp Suite, configure browser proxy",
      "Day 6: Complete TryHackMe 'Tutorial' and 'Starting Out' rooms",
      "Day 7: Download first VulnHub machine, attempt without walkthrough",
    ],
    tips: [
      "Take snapshots before major changes - you WILL break things",
      "Document every command and its purpose in your notes",
      "Use NAT networking for attack VMs, isolated networks for targets",
      "Never attack machines outside your lab without authorization",
      "Create a 'tools' folder with your favorite scripts and configs",
      "Use tmux or screen for persistent terminal sessions",
    ],
  },
  {
    track: "Defensive Security / Blue Team",
    icon: "🔵",
    color: "#3b82f6",
    description: "Detection, monitoring, and incident response practice environment with SIEM and log analysis.",
    minBudget: "$0 (cloud-based)",
    recommendedBudget: "$200-400",
    hardware: [
      { item: "Laptop/Desktop (16GB+ RAM)", purpose: "Run SIEM stack and target VMs", cost: "$400-800 used" },
      { item: "32GB+ RAM recommended", purpose: "ELK stack is memory hungry", cost: "+$50-100 upgrade" },
      { item: "External SSD (1TB)", purpose: "Store logs, pcaps, and VM images", cost: "$80-120" },
      { item: "Network TAP / Managed Switch", purpose: "Capture network traffic", cost: "$30-100" },
      { item: "Raspberry Pi 4", purpose: "Honeypot or network sensor", cost: "$55-75" },
    ],
    software: [
      { name: "Security Onion", purpose: "Full defensive stack (SIEM, IDS, etc)", cost: "Free" },
      { name: "Elastic Stack (ELK)", purpose: "Log aggregation and SIEM", cost: "Free" },
      { name: "Splunk Free", purpose: "Industry SIEM (500MB/day limit)", cost: "Free" },
      { name: "Wazuh", purpose: "Open-source SIEM/XDR", cost: "Free" },
      { name: "Velociraptor", purpose: "Endpoint visibility and DFIR", cost: "Free" },
      { name: "Zeek (formerly Bro)", purpose: "Network analysis framework", cost: "Free" },
      { name: "Suricata", purpose: "IDS/IPS engine", cost: "Free" },
      { name: "YARA", purpose: "Malware pattern matching", cost: "Free" },
    ],
    vms: [
      { name: "Security Onion ISO", purpose: "All-in-one defensive platform", link: "https://securityonionsolutions.com" },
      { name: "DetectionLab", purpose: "Pre-built AD with logging", link: "https://github.com/clong/DetectionLab" },
      { name: "Windows 10 Eval", purpose: "Endpoint to monitor", link: "https://microsoft.com/evalcenter" },
      { name: "Ubuntu Server", purpose: "Syslog, web server to monitor", link: "https://ubuntu.com/download/server" },
      { name: "Malware Traffic Analysis VMs", purpose: "Pre-infected pcap analysis", link: "https://malware-traffic-analysis.net" },
    ],
    cloudAlternatives: [
      { service: "LetsDefend", purpose: "SOC analyst simulator", cost: "Free-$25/mo" },
      { service: "CyberDefenders", purpose: "Blue team challenges", cost: "Free" },
      { service: "Blue Team Labs Online", purpose: "IR & forensics challenges", cost: "Free/Paid" },
      { service: "Elastic Cloud", purpose: "Managed ELK stack", cost: "$95/mo+" },
      { service: "Splunk Cloud Trial", purpose: "15-day cloud SIEM", cost: "Free trial" },
    ],
    practiceTargets: [
      { name: "Boss of the SOC (BOTS)", description: "Splunk-based CTF datasets", link: "https://github.com/splunk/botsv1" },
      { name: "Malware Traffic Analysis", description: "Pcap analysis exercises", link: "https://malware-traffic-analysis.net" },
      { name: "LetsDefend Alerts", description: "Realistic SOC alert triage", link: "https://letsdefend.io" },
      { name: "CyberDefenders Labs", description: "DFIR and malware challenges", link: "https://cyberdefenders.org" },
      { name: "SANS Holiday Hack", description: "Annual blue team CTF", link: "https://holidayhackchallenge.com" },
    ],
    firstWeekSetup: [
      "Day 1: Download Security Onion ISO, prepare VM (16GB RAM, 200GB disk)",
      "Day 2: Install Security Onion in standalone mode, complete setup wizard",
      "Day 3: Set up Windows 10 VM with Sysmon, forward logs to Security Onion",
      "Day 4: Generate test traffic, verify logs appear in Kibana",
      "Day 5: Download Boss of the SOC dataset, import into Splunk Free",
      "Day 6: Complete first LetsDefend alert investigation",
      "Day 7: Set up Velociraptor server, deploy agent to Windows VM",
    ],
    tips: [
      "Start with Security Onion - it bundles everything you need",
      "Learn to write Sigma rules for detection engineering",
      "Keep a 'detection playbook' of alerts and response steps",
      "Practice with real malware pcaps from Malware Traffic Analysis",
      "Set up Windows logging properly (Sysmon config is critical)",
      "Create dashboards for key metrics you want to track",
    ],
  },
  {
    track: "Cloud Security",
    icon: "☁️",
    color: "#06b6d4",
    description: "Cloud-native security practice across AWS, Azure, and GCP with IaC and container security.",
    minBudget: "$0 (free tiers)",
    recommendedBudget: "$50-100/mo",
    hardware: [
      { item: "Any computer with internet", purpose: "Cloud is remote by nature", cost: "Existing" },
      { item: "Second monitor (optional)", purpose: "Console + terminal side by side", cost: "$100-200" },
    ],
    software: [
      { name: "AWS CLI", purpose: "Interact with AWS services", cost: "Free" },
      { name: "Azure CLI", purpose: "Interact with Azure services", cost: "Free" },
      { name: "gcloud CLI", purpose: "Interact with GCP services", cost: "Free" },
      { name: "Terraform", purpose: "Infrastructure as Code", cost: "Free" },
      { name: "kubectl", purpose: "Kubernetes management", cost: "Free" },
      { name: "Docker Desktop", purpose: "Container development", cost: "Free" },
      { name: "ScoutSuite", purpose: "Multi-cloud security auditing", cost: "Free" },
      { name: "Prowler", purpose: "AWS security assessment", cost: "Free" },
      { name: "Checkov", purpose: "IaC security scanning", cost: "Free" },
    ],
    vms: [
      { name: "CloudGoat", purpose: "Vulnerable AWS scenarios", link: "https://github.com/RhinoSecurityLabs/cloudgoat" },
      { name: "Terragoat", purpose: "Vulnerable Terraform examples", link: "https://github.com/bridgecrewio/terragoat" },
      { name: "AWSGoat", purpose: "AWS security learning", link: "https://github.com/ine-labs/AWSGoat" },
      { name: "AzureGoat", purpose: "Azure security learning", link: "https://github.com/ine-labs/AzureGoat" },
      { name: "GCPGoat", purpose: "GCP security learning", link: "https://github.com/ine-labs/GCPGoat" },
      { name: "Kubernetes Goat", purpose: "K8s security playground", link: "https://github.com/madhuakula/kubernetes-goat" },
    ],
    cloudAlternatives: [
      { service: "AWS Free Tier", purpose: "12 months free resources", cost: "Free" },
      { service: "Azure Free Account", purpose: "$200 credit + free services", cost: "Free" },
      { service: "GCP Free Tier", purpose: "$300 credit + always-free", cost: "Free" },
      { service: "Civo (K8s)", purpose: "Cheap Kubernetes clusters", cost: "$5/mo" },
      { service: "DigitalOcean", purpose: "Simple cloud VMs", cost: "$4/mo" },
    ],
    practiceTargets: [
      { name: "CloudGoat Scenarios", description: "AWS privilege escalation, data exfil", link: "https://github.com/RhinoSecurityLabs/cloudgoat" },
      { name: "flAWS.cloud", description: "AWS CTF with increasing difficulty", link: "http://flaws.cloud" },
      { name: "flAWS2.cloud", description: "Attacker & defender perspectives", link: "http://flaws2.cloud" },
      { name: "YOURCLOUDCTF", description: "Community cloud challenges", link: "https://yourcloudctf.com" },
      { name: "Kubernetes Goat", description: "K8s misconfigurations to exploit", link: "https://madhuakula.com/kubernetes-goat/" },
      { name: "Sadcloud", description: "Terraform for deploying insecure AWS", link: "https://github.com/nccgroup/sadcloud" },
    ],
    firstWeekSetup: [
      "Day 1: Create AWS free tier account, enable MFA, set billing alerts",
      "Day 2: Install AWS CLI, configure credentials, test basic commands",
      "Day 3: Complete flAWS.cloud Level 1-3 challenges",
      "Day 4: Install Terraform, deploy a simple EC2 instance with code",
      "Day 5: Run Prowler scan against your AWS account",
      "Day 6: Set up CloudGoat, complete first scenario",
      "Day 7: Create Azure/GCP accounts, explore their consoles",
    ],
    tips: [
      "Set up billing alerts IMMEDIATELY - cloud costs can spiral",
      "Use separate accounts for learning vs production",
      "Enable CloudTrail/Activity logging from day one",
      "Learn IAM deeply - it's the foundation of cloud security",
      "Practice destroying everything with 'terraform destroy'",
      "Use aws-vault or similar for credential management",
    ],
  },
  {
    track: "Malware Analysis & Reverse Engineering",
    icon: "🦠",
    color: "#dc2626",
    description: "Safe environment for analyzing malware samples, reverse engineering, and understanding attacker tools.",
    minBudget: "$0 (VM-only)",
    recommendedBudget: "$300-600",
    hardware: [
      { item: "Dedicated analysis machine", purpose: "Isolated from main network", cost: "$300-500 used" },
      { item: "32GB+ RAM", purpose: "Run analysis VMs smoothly", cost: "+$100" },
      { item: "Air-gapped option", purpose: "Physical isolation for real malware", cost: "Old laptop" },
      { item: "External HDD (cold storage)", purpose: "Malware sample archive", cost: "$50-80" },
    ],
    software: [
      { name: "REMnux", purpose: "Malware analysis Linux distro", cost: "Free" },
      { name: "FlareVM", purpose: "Windows malware analysis distro", cost: "Free" },
      { name: "Ghidra", purpose: "NSA's reverse engineering tool", cost: "Free" },
      { name: "IDA Free", purpose: "Industry standard disassembler", cost: "Free" },
      { name: "x64dbg/x32dbg", purpose: "Windows debugger", cost: "Free" },
      { name: "Process Monitor/Explorer", purpose: "Dynamic analysis", cost: "Free" },
      { name: "Detect It Easy (DIE)", purpose: "Packer/compiler detection", cost: "Free" },
      { name: "PE-bear/CFF Explorer", purpose: "PE file analysis", cost: "Free" },
      { name: "YARA", purpose: "Pattern matching rules", cost: "Free" },
      { name: "Cutter", purpose: "Radare2 GUI (open source)", cost: "Free" },
    ],
    vms: [
      { name: "REMnux", purpose: "Analysis Linux distro", link: "https://remnux.org" },
      { name: "FlareVM", purpose: "Windows analysis environment", link: "https://github.com/mandiant/flare-vm" },
      { name: "Windows Sandbox", purpose: "Disposable Windows instances", link: "Built into Win 10/11 Pro" },
      { name: "YOURMALBOX Toolkit", purpose: "Automated analysis sandbox", link: "https://any.run" },
    ],
    cloudAlternatives: [
      { service: "Any.Run", purpose: "Interactive cloud sandbox", cost: "Free (limited)" },
      { service: "Hybrid Analysis", purpose: "Free malware sandbox", cost: "Free" },
      { service: "Joe Sandbox", purpose: "Detailed automated analysis", cost: "Free (limited)" },
      { service: "VirusTotal", purpose: "Multi-AV scanning", cost: "Free" },
      { service: "Tria.ge", purpose: "Sandbox analysis", cost: "Free" },
    ],
    practiceTargets: [
      { name: "MalwareBazaar", description: "Free malware sample repository", link: "https://bazaar.abuse.ch" },
      { name: "theZoo", description: "Live malware samples (careful!)", link: "https://github.com/ytisf/theZoo" },
      { name: "Malware Unicorn Workshops", description: "RE tutorials and crackmes", link: "https://malwareunicorn.org" },
      { name: "CrackMe challenges", description: "Reverse engineering practice", link: "https://crackmes.one" },
      { name: "YOURCTF RE Challenges", description: "CTF reverse engineering", link: "Various CTF archives" },
      { name: "Practical Malware Analysis Labs", description: "Book companion exercises", link: "Book purchase" },
    ],
    firstWeekSetup: [
      "Day 1: Download REMnux and FlareVM, set up isolated VMs",
      "Day 2: Configure isolated network (no internet for analysis VMs)",
      "Day 3: Install Ghidra, work through official tutorial",
      "Day 4: Analyze a simple crackme from crackmes.one",
      "Day 5: Set up Any.Run account, submit safe sample for analysis",
      "Day 6: Complete Malware Unicorn's RE101 workshop",
      "Day 7: Download sample from MalwareBazaar, do static analysis only",
    ],
    tips: [
      "NEVER run malware on your main machine or connected network",
      "Use snapshots extensively - revert after each sample",
      "Start with static analysis before dynamic (safer)",
      "Keep detailed notes with hashes, IOCs, and behaviors",
      "Learn x86/x64 assembly basics before diving deep",
      "Join malware analysis discords for sample sharing and help",
      "Password-protect all malware samples (standard: 'infected')",
    ],
  },
  {
    track: "Digital Forensics & Incident Response",
    icon: "🔍",
    color: "#14b8a6",
    description: "Evidence acquisition, analysis, and incident investigation practice environment.",
    minBudget: "$0 (software-only)",
    recommendedBudget: "$200-400",
    hardware: [
      { item: "Write-blocker", purpose: "Forensic disk acquisition", cost: "$200-300" },
      { item: "USB drive collection", purpose: "Boot forensic OS", cost: "$30-50" },
      { item: "External dock/cables", purpose: "Connect various drive types", cost: "$50-100" },
      { item: "Extra RAM (32GB+)", purpose: "Memory analysis needs RAM", cost: "+$100" },
      { item: "Large storage (4TB+)", purpose: "Evidence and image storage", cost: "$80-120" },
    ],
    software: [
      { name: "Autopsy", purpose: "Open source forensic suite", cost: "Free" },
      { name: "FTK Imager", purpose: "Forensic imaging (free)", cost: "Free" },
      { name: "Volatility 3", purpose: "Memory forensics", cost: "Free" },
      { name: "KAPE", purpose: "Rapid triage and collection", cost: "Free" },
      { name: "Eric Zimmerman Tools", purpose: "Windows artifact parsers", cost: "Free" },
      { name: "Plaso/log2timeline", purpose: "Timeline creation", cost: "Free" },
      { name: "Velociraptor", purpose: "Endpoint investigation", cost: "Free" },
      { name: "SIFT Workstation", purpose: "SANS forensics distro", cost: "Free" },
      { name: "Sleuth Kit", purpose: "Command-line forensics", cost: "Free" },
    ],
    vms: [
      { name: "SIFT Workstation", purpose: "SANS forensic analysis VM", link: "https://www.sans.org/tools/sift-workstation/" },
      { name: "REMnux", purpose: "Malware/memory analysis", link: "https://remnux.org" },
      { name: "Tsurugi Linux", purpose: "DFIR-focused distro", link: "https://tsurugi-linux.org" },
      { name: "Windows Eval", purpose: "Create your own artifacts", link: "https://microsoft.com/evalcenter" },
    ],
    cloudAlternatives: [
      { service: "CyberDefenders", purpose: "DFIR challenges with evidence", cost: "Free" },
      { service: "Blue Team Labs Online", purpose: "IR investigations", cost: "Free/Paid" },
      { service: "13Cubed challenges", purpose: "Memory forensics practice", cost: "Free" },
      { service: "DFIR.Training", purpose: "Curated forensics resources", cost: "Free" },
    ],
    practiceTargets: [
      { name: "CyberDefenders Labs", description: "Real forensic evidence challenges", link: "https://cyberdefenders.org" },
      { name: "DFIR CTF Images", description: "Community forensic images", link: "https://aboutdfir.com" },
      { name: "Ali Hadi's Challenges", description: "Memory & disk forensics", link: "https://www.yourvolatility.com/challenges" },
      { name: "Magnet CTFs", description: "Annual forensics competition", link: "https://magnetforensics.com" },
      { name: "SANS DFIR Posters", description: "Reference materials & exercises", link: "https://www.sans.org/posters" },
    ],
    firstWeekSetup: [
      "Day 1: Download SIFT Workstation or Tsurugi, set up VM",
      "Day 2: Install Autopsy, work through tutorial with sample image",
      "Day 3: Download Eric Zimmerman tools, practice on your own Windows",
      "Day 4: Install Volatility 3, analyze sample memory dump",
      "Day 5: Complete first CyberDefenders forensics challenge",
      "Day 6: Learn KAPE - set up collection and analysis targets",
      "Day 7: Create your own disk image using FTK Imager, analyze it",
    ],
    tips: [
      "Always document chain of custody, even for practice",
      "Hash everything before and after analysis",
      "Learn Windows artifacts deeply - Registry, Event Logs, MFT",
      "Build a timeline early in any investigation",
      "Keep a 'known good' baseline of normal system artifacts",
      "Practice writing reports explaining technical findings simply",
    ],
  },
  {
    track: "Network Security",
    icon: "🌐",
    color: "#0891b2",
    description: "Network monitoring, firewall configuration, and traffic analysis practice environment.",
    minBudget: "$50-100",
    recommendedBudget: "$300-500",
    hardware: [
      { item: "Managed switch (8+ ports)", purpose: "VLAN configuration practice", cost: "$50-100 used" },
      { item: "Old PC for pfSense/OPNsense", purpose: "Firewall/router lab", cost: "$50-100 used" },
      { item: "Mini PC (2+ NICs)", purpose: "Dedicated firewall appliance", cost: "$150-250" },
      { item: "Access points (for WiFi lab)", purpose: "Wireless security practice", cost: "$30-50 used" },
      { item: "Network TAP", purpose: "Passive traffic capture", cost: "$30-100" },
      { item: "Raspberry Pi", purpose: "Network sensor/Pi-hole", cost: "$55-75" },
    ],
    software: [
      { name: "pfSense/OPNsense", purpose: "Open source firewall", cost: "Free" },
      { name: "Wireshark", purpose: "Packet analysis", cost: "Free" },
      { name: "Zeek", purpose: "Network security monitoring", cost: "Free" },
      { name: "Snort/Suricata", purpose: "IDS/IPS", cost: "Free" },
      { name: "NetworkMiner", purpose: "Network forensics", cost: "Free" },
      { name: "GNS3/EVE-NG", purpose: "Network emulation", cost: "Free" },
      { name: "Pi-hole", purpose: "DNS filtering/monitoring", cost: "Free" },
      { name: "Nmap", purpose: "Network scanning", cost: "Free" },
    ],
    vms: [
      { name: "pfSense VM", purpose: "Virtual firewall", link: "https://pfsense.org" },
      { name: "Security Onion", purpose: "Network monitoring stack", link: "https://securityonionsolutions.com" },
      { name: "GNS3 VM", purpose: "Network emulation", link: "https://gns3.com" },
      { name: "EVE-NG", purpose: "Network simulation", link: "https://eve-ng.net" },
      { name: "VyOS", purpose: "Open source router", link: "https://vyos.io" },
    ],
    cloudAlternatives: [
      { service: "AWS VPC", purpose: "Cloud networking practice", cost: "Free tier" },
      { service: "Azure Virtual Network", purpose: "Cloud network security", cost: "Free tier" },
      { service: "Packet Tracer", purpose: "Cisco simulation (free)", cost: "Free" },
      { service: "Network Chuck Labs", purpose: "Guided networking practice", cost: "Course price" },
    ],
    practiceTargets: [
      { name: "Malware Traffic Analysis", description: "Pcap analysis exercises", link: "https://malware-traffic-analysis.net" },
      { name: "Wireshark Sample Captures", description: "Official sample pcaps", link: "https://wiki.wireshark.org/SampleCaptures" },
      { name: "PacketTotal", description: "Pcap sharing/analysis", link: "https://packettotal.com" },
      { name: "PicoCTF Networking", description: "Network challenges", link: "https://picoctf.org" },
      { name: "Security Onion docs", description: "NSM deployment guide", link: "https://docs.securityonion.net" },
    ],
    firstWeekSetup: [
      "Day 1: Install Wireshark, capture traffic on your network",
      "Day 2: Download and analyze pcaps from Malware Traffic Analysis",
      "Day 3: Set up pfSense/OPNsense VM with WAN+LAN interfaces",
      "Day 4: Configure firewall rules, test traffic blocking",
      "Day 5: Install Suricata on pfSense, enable IDS rules",
      "Day 6: Set up GNS3, build simple network topology",
      "Day 7: Set up Pi-hole for DNS filtering and monitoring",
    ],
    tips: [
      "Understand TCP/IP deeply - it's fundamental to everything",
      "Learn to read Wireshark captures efficiently (display filters)",
      "Practice firewall rules on paper before implementing",
      "Segment your home network for realistic practice",
      "Keep your lab isolated from production home network",
      "Document your network topology - you'll forget configurations",
    ],
  },
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

        {/* Quick Navigation - Career Path Certification Links */}
        <Paper sx={{ p: 3, borderRadius: 3, mb: 3, bgcolor: alpha(theme.palette.info.main, 0.03), border: `1px solid ${alpha(theme.palette.info.main, 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WorkspacePremiumIcon sx={{ color: theme.palette.info.main }} />
            Quick Navigation: Find Certifications by Career Path
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Click any career path below to jump directly to relevant certifications filtered by specialty area.
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            <Chip
              label="🔴 Red Team / Pentesting"
              clickable
              onClick={() => navigate("/learn/certifications?path=red-team")}
              sx={{ fontWeight: 600, bgcolor: alpha("#ef4444", 0.1), color: "#ef4444", "&:hover": { bgcolor: alpha("#ef4444", 0.2) } }}
            />
            <Chip
              label="🔵 Blue Team / SOC"
              clickable
              onClick={() => navigate("/learn/certifications?path=blue-team")}
              sx={{ fontWeight: 600, bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6", "&:hover": { bgcolor: alpha("#3b82f6", 0.2) } }}
            />
            <Chip
              label="☁️ Cloud Security"
              clickable
              onClick={() => navigate("/learn/certifications?path=cloud-security")}
              sx={{ fontWeight: 600, bgcolor: alpha("#06b6d4", 0.1), color: "#06b6d4", "&:hover": { bgcolor: alpha("#06b6d4", 0.2) } }}
            />
            <Chip
              label="📱 Application Security"
              clickable
              onClick={() => navigate("/learn/certifications?path=appsec")}
              sx={{ fontWeight: 600, bgcolor: alpha("#ec4899", 0.1), color: "#ec4899", "&:hover": { bgcolor: alpha("#ec4899", 0.2) } }}
            />
            <Chip
              label="🔒 GRC & Compliance"
              clickable
              onClick={() => navigate("/learn/certifications?path=grc")}
              sx={{ fontWeight: 600, bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b", "&:hover": { bgcolor: alpha("#f59e0b", 0.2) } }}
            />
            <Chip
              label="🔬 Vulnerability Research"
              clickable
              onClick={() => navigate("/learn/certifications?path=vuln-research")}
              sx={{ fontWeight: 600, bgcolor: alpha("#7c3aed", 0.1), color: "#7c3aed", "&:hover": { bgcolor: alpha("#7c3aed", 0.2) } }}
            />
            <Chip
              label="🕵️ Threat Intelligence"
              clickable
              onClick={() => navigate("/learn/certifications?path=threat-intel")}
              sx={{ fontWeight: 600, bgcolor: alpha("#f97316", 0.1), color: "#f97316", "&:hover": { bgcolor: alpha("#f97316", 0.2) } }}
            />
            <Chip
              label="🔍 Digital Forensics"
              clickable
              onClick={() => navigate("/learn/certifications?path=forensics")}
              sx={{ fontWeight: 600, bgcolor: alpha("#14b8a6", 0.1), color: "#14b8a6", "&:hover": { bgcolor: alpha("#14b8a6", 0.2) } }}
            />
            <Chip
              label="🦠 Malware Analysis"
              clickable
              onClick={() => navigate("/learn/certifications?path=malware-analysis")}
              sx={{ fontWeight: 600, bgcolor: alpha("#dc2626", 0.1), color: "#dc2626", "&:hover": { bgcolor: alpha("#dc2626", 0.2) } }}
            />
            <Chip
              label="🔑 Identity & IAM"
              clickable
              onClick={() => navigate("/learn/certifications?path=iam")}
              sx={{ fontWeight: 600, bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6", "&:hover": { bgcolor: alpha("#8b5cf6", 0.2) } }}
            />
            <Chip
              label="🏭 OT/ICS Security"
              clickable
              onClick={() => navigate("/learn/certifications?path=ot-ics")}
              sx={{ fontWeight: 600, bgcolor: alpha("#059669", 0.1), color: "#059669", "&:hover": { bgcolor: alpha("#059669", 0.2) } }}
            />
            <Chip
              label="🛡️ DevSecOps"
              clickable
              onClick={() => navigate("/learn/certifications?path=devsecops")}
              sx={{ fontWeight: 600, bgcolor: alpha("#6366f1", 0.1), color: "#6366f1", "&:hover": { bgcolor: alpha("#6366f1", 0.2) } }}
            />
            <Chip
              label="🏆 Bug Bounty"
              clickable
              onClick={() => navigate("/learn/certifications?path=bug-bounty")}
              sx={{ fontWeight: 600, bgcolor: alpha("#eab308", 0.1), color: "#eab308", "&:hover": { bgcolor: alpha("#eab308", 0.2) } }}
            />
            <Chip
              label="🔐 Cryptography"
              clickable
              onClick={() => navigate("/learn/certifications?path=crypto")}
              sx={{ fontWeight: 600, bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6", "&:hover": { bgcolor: alpha("#8b5cf6", 0.2) } }}
            />
          </Box>
          <Divider sx={{ my: 2 }} />
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
            <strong>Filter by skill level:</strong>
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip
              label="🟢 Beginner Certifications"
              clickable
              onClick={() => navigate("/learn/certifications?level=Beginner")}
              sx={{ fontWeight: 600, bgcolor: alpha("#22c55e", 0.1), color: "#22c55e", "&:hover": { bgcolor: alpha("#22c55e", 0.2) } }}
            />
            <Chip
              label="🟡 Intermediate Certifications"
              clickable
              onClick={() => navigate("/learn/certifications?level=Intermediate")}
              sx={{ fontWeight: 600, bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b", "&:hover": { bgcolor: alpha("#f59e0b", 0.2) } }}
            />
            <Chip
              label="🔴 Advanced Certifications"
              clickable
              onClick={() => navigate("/learn/certifications?level=Advanced")}
              sx={{ fontWeight: 600, bgcolor: alpha("#ef4444", 0.1), color: "#ef4444", "&:hover": { bgcolor: alpha("#ef4444", 0.2) } }}
            />
          </Box>
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
            <Tab label="Personal Guidance" icon={<PersonIcon />} iconPosition="start" />
            <Tab label="Home Lab" icon={<ComputerIcon />} iconPosition="start" />
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

                      {/* Structured Learning Path - NEW */}
                      <Accordion sx={{ bgcolor: "transparent", boxShadow: "none", "&:before": { display: "none" } }}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 0 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
                            <SchoolIcon sx={{ fontSize: 16 }} /> Learning Path (Beginner → Advanced)
                          </Typography>
                        </AccordionSummary>
                        <AccordionDetails sx={{ px: 0 }}>
                          {/* Beginner */}
                          <Box sx={{ mb: 2 }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, color: "#22c55e", display: "flex", alignItems: "center", gap: 0.5, mb: 1 }}>
                              🟢 BEGINNER COURSES
                            </Typography>
                            {path.learningPath.beginner.map((course, idx) => (
                              <Box key={idx} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.75, pl: 1, borderLeft: `2px solid ${alpha("#22c55e", 0.3)}` }}>
                                <Box sx={{ flex: 1 }}>
                                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block" }}>{course.course}</Typography>
                                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>{course.provider} • {course.duration}</Typography>
                                </Box>
                              </Box>
                            ))}
                          </Box>
                          {/* Intermediate */}
                          <Box sx={{ mb: 2 }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, color: "#f59e0b", display: "flex", alignItems: "center", gap: 0.5, mb: 1 }}>
                              🟡 INTERMEDIATE COURSES
                            </Typography>
                            {path.learningPath.intermediate.map((course, idx) => (
                              <Box key={idx} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.75, pl: 1, borderLeft: `2px solid ${alpha("#f59e0b", 0.3)}` }}>
                                <Box sx={{ flex: 1 }}>
                                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block" }}>{course.course}</Typography>
                                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>{course.provider} • {course.duration}</Typography>
                                </Box>
                              </Box>
                            ))}
                          </Box>
                          {/* Advanced */}
                          <Box>
                            <Typography variant="caption" sx={{ fontWeight: 700, color: "#ef4444", display: "flex", alignItems: "center", gap: 0.5, mb: 1 }}>
                              🔴 ADVANCED COURSES
                            </Typography>
                            {path.learningPath.advanced.map((course, idx) => (
                              <Box key={idx} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.75, pl: 1, borderLeft: `2px solid ${alpha("#ef4444", 0.3)}` }}>
                                <Box sx={{ flex: 1 }}>
                                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block" }}>{course.course}</Typography>
                                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>{course.provider} • {course.duration}</Typography>
                                </Box>
                              </Box>
                            ))}
                          </Box>
                          <Button
                            size="small"
                            variant="contained"
                            onClick={() => navigate("/learn/certifications")}
                            endIcon={<ArrowForwardIcon />}
                            sx={{ mt: 1.5, fontSize: "0.7rem", bgcolor: path.color }}
                          >
                            Browse All Certifications
                          </Button>
                        </AccordionDetails>
                      </Accordion>

                      {/* Career Advice - NEW */}
                      <Accordion sx={{ bgcolor: "transparent", boxShadow: "none", "&:before": { display: "none" } }}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 0 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#ec4899", display: "flex", alignItems: "center", gap: 1 }}>
                            <LightbulbIcon sx={{ fontSize: 16 }} /> Career Advice & Tips
                          </Typography>
                        </AccordionSummary>
                        <AccordionDetails sx={{ px: 0 }}>
                          {/* Day One Action Plan */}
                          <Box sx={{ mb: 2, p: 1.5, bgcolor: alpha(path.color, 0.05), borderRadius: 1, border: `1px solid ${alpha(path.color, 0.2)}` }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, color: path.color, display: "block", mb: 1 }}>
                              🚀 DAY ONE ACTION PLAN
                            </Typography>
                            {path.careerAdvice.dayOneActionPlan.map((action, idx) => (
                              <Box key={idx} sx={{ display: "flex", gap: 0.5, mb: 0.5 }}>
                                <Typography variant="caption" sx={{ color: path.color }}>{idx + 1}.</Typography>
                                <Typography variant="caption">{action}</Typography>
                              </Box>
                            ))}
                          </Box>
                          {/* Getting Started */}
                          <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>Getting Started:</Typography>
                          <List dense disablePadding sx={{ mb: 1.5 }}>
                            {path.careerAdvice.gettingStarted.map((tip, idx) => (
                              <ListItem key={idx} sx={{ py: 0, px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 20 }}>
                                  <CheckCircleIcon sx={{ fontSize: 12, color: "#22c55e" }} />
                                </ListItemIcon>
                                <ListItemText primary={tip} primaryTypographyProps={{ variant: "caption" }} />
                              </ListItem>
                            ))}
                          </List>
                          {/* Common Mistakes */}
                          <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5, color: "#ef4444" }}>⚠️ Common Mistakes to Avoid:</Typography>
                          <List dense disablePadding sx={{ mb: 1.5 }}>
                            {path.careerAdvice.commonMistakes.map((mistake, idx) => (
                              <ListItem key={idx} sx={{ py: 0, px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 20 }}>
                                  <WarningIcon sx={{ fontSize: 12, color: "#ef4444" }} />
                                </ListItemIcon>
                                <ListItemText primary={mistake} primaryTypographyProps={{ variant: "caption" }} />
                              </ListItem>
                            ))}
                          </List>
                          {/* Success Tips */}
                          <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5, color: "#22c55e" }}>✨ Success Tips:</Typography>
                          <List dense disablePadding>
                            {path.careerAdvice.successTips.map((tip, idx) => (
                              <ListItem key={idx} sx={{ py: 0, px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 20 }}>
                                  <StarIcon sx={{ fontSize: 12, color: "#f59e0b" }} />
                                </ListItemIcon>
                                <ListItemText primary={tip} primaryTypographyProps={{ variant: "caption" }} />
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
                  <Grid item xs={12} md={6} key={track.title}>
                    <Card sx={{ height: "100%", borderRadius: 2, border: `1px solid ${alpha(track.color, 0.2)}`, transition: "all 0.3s", "&:hover": { borderColor: track.color } }}>
                      <CardContent sx={{ p: 2 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                          <Box sx={{ color: track.color }}>{track.icon}</Box>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{track.title}</Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {track.description}
                        </Typography>
                        <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
                          <Chip label={track.salary} size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e", fontWeight: 600 }} />
                          <Chip label={`Growth: ${track.growth}`} size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6", fontWeight: 600 }} />
                        </Box>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1.5 }}>
                          <Typography variant="caption" sx={{ fontWeight: 600, width: "100%", mb: 0.5 }}>Key Skills:</Typography>
                          {track.skills.slice(0, 6).map((skill) => (
                            <Chip key={skill} label={skill} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          ))}
                        </Box>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                          <Typography variant="caption" sx={{ fontWeight: 600, width: "100%", mb: 0.5 }}>Certifications:</Typography>
                          {track.certs.map((cert) => (
                            <Chip key={cert} label={cert} size="small" sx={{ fontSize: "0.6rem", height: 20, bgcolor: alpha(track.color, 0.1), color: track.color }} />
                          ))}
                        </Box>

                        {/* Learning Path Accordion - Only show if track has learningPath */}
                        {track.learningPath && (
                          <Accordion sx={{ mb: 1, bgcolor: alpha(track.color, 0.03), "&:before": { display: "none" }, borderRadius: 1, border: `1px solid ${alpha(track.color, 0.1)}` }}>
                            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: track.color }} />}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <SchoolIcon sx={{ fontSize: 16, color: track.color }} />
                                <Typography variant="body2" sx={{ fontWeight: 600 }}>Learning Path (Beginner → Advanced)</Typography>
                              </Box>
                            </AccordionSummary>
                            <AccordionDetails sx={{ pt: 0 }}>
                              {/* Beginner Level */}
                              <Box sx={{ mb: 2 }}>
                                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                                  <Chip label="Beginner" size="small" sx={{ bgcolor: "#22c55e", color: "white", fontWeight: 600, fontSize: "0.65rem" }} />
                                </Box>
                                {track.learningPath.beginner.map((item, idx) => (
                                  <Box key={idx} sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", py: 0.5, borderBottom: idx < track.learningPath!.beginner.length - 1 ? "1px solid" : "none", borderColor: "divider" }}>
                                    <Box>
                                      <Typography variant="body2" sx={{ fontWeight: 500, fontSize: "0.75rem" }}>{item.course}</Typography>
                                      <Typography variant="caption" color="text.secondary">{item.provider}</Typography>
                                    </Box>
                                    <Typography variant="caption" sx={{ color: track.color, fontWeight: 500 }}>{item.duration}</Typography>
                                  </Box>
                                ))}
                              </Box>

                              {/* Intermediate Level */}
                              <Box sx={{ mb: 2 }}>
                                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                                  <Chip label="Intermediate" size="small" sx={{ bgcolor: "#f59e0b", color: "white", fontWeight: 600, fontSize: "0.65rem" }} />
                                </Box>
                                {track.learningPath.intermediate.map((item, idx) => (
                                  <Box key={idx} sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", py: 0.5, borderBottom: idx < track.learningPath!.intermediate.length - 1 ? "1px solid" : "none", borderColor: "divider" }}>
                                    <Box>
                                      <Typography variant="body2" sx={{ fontWeight: 500, fontSize: "0.75rem" }}>{item.course}</Typography>
                                      <Typography variant="caption" color="text.secondary">{item.provider}</Typography>
                                    </Box>
                                    <Typography variant="caption" sx={{ color: track.color, fontWeight: 500 }}>{item.duration}</Typography>
                                  </Box>
                                ))}
                              </Box>

                              {/* Advanced Level */}
                              <Box>
                                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                                  <Chip label="Advanced" size="small" sx={{ bgcolor: "#ef4444", color: "white", fontWeight: 600, fontSize: "0.65rem" }} />
                                </Box>
                                {track.learningPath.advanced.map((item, idx) => (
                                  <Box key={idx} sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", py: 0.5, borderBottom: idx < track.learningPath!.advanced.length - 1 ? "1px solid" : "none", borderColor: "divider" }}>
                                    <Box>
                                      <Typography variant="body2" sx={{ fontWeight: 500, fontSize: "0.75rem" }}>{item.course}</Typography>
                                      <Typography variant="caption" color="text.secondary">{item.provider}</Typography>
                                    </Box>
                                    <Typography variant="caption" sx={{ color: track.color, fontWeight: 500 }}>{item.duration}</Typography>
                                  </Box>
                                ))}
                              </Box>
                            </AccordionDetails>
                          </Accordion>
                        )}

                        {/* Career Advice Accordion - Only show if track has careerAdvice */}
                        {track.careerAdvice && (
                          <Accordion sx={{ mb: 1, bgcolor: alpha(track.color, 0.03), "&:before": { display: "none" }, borderRadius: 1, border: `1px solid ${alpha(track.color, 0.1)}` }}>
                            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: track.color }} />}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <TipsAndUpdatesIcon sx={{ fontSize: 16, color: track.color }} />
                                <Typography variant="body2" sx={{ fontWeight: 600 }}>Career Advice & Tips</Typography>
                              </Box>
                            </AccordionSummary>
                            <AccordionDetails sx={{ pt: 0 }}>
                              <Box sx={{ mb: 2 }}>
                                <Typography variant="caption" sx={{ fontWeight: 700, color: track.color, display: "flex", alignItems: "center", gap: 0.5, mb: 1 }}>
                                  <PlayArrowIcon sx={{ fontSize: 14 }} /> Getting Started
                                </Typography>
                                {track.careerAdvice.gettingStarted.map((tip, idx) => (
                                  <Typography key={idx} variant="body2" sx={{ fontSize: "0.75rem", mb: 0.5, display: "flex", alignItems: "flex-start", gap: 0.5 }}>
                                    <Box component="span" sx={{ color: track.color }}>•</Box> {tip}
                                  </Typography>
                                ))}
                              </Box>

                              <Box sx={{ mb: 2 }}>
                                <Typography variant="caption" sx={{ fontWeight: 700, color: "#22c55e", display: "flex", alignItems: "center", gap: 0.5, mb: 1 }}>
                                  <CheckCircleIcon sx={{ fontSize: 14 }} /> Day One Actions
                                </Typography>
                                {track.careerAdvice.dayOneActions.map((action, idx) => (
                                  <Typography key={idx} variant="body2" sx={{ fontSize: "0.75rem", mb: 0.5, display: "flex", alignItems: "flex-start", gap: 0.5 }}>
                                    <Box component="span" sx={{ color: "#22c55e" }}>{idx + 1}.</Box> {action}
                                  </Typography>
                                ))}
                              </Box>

                              <Box>
                                <Typography variant="caption" sx={{ fontWeight: 700, color: "#f59e0b", display: "flex", alignItems: "center", gap: 0.5, mb: 1 }}>
                                  <StarIcon sx={{ fontSize: 14 }} /> Success Tips
                                </Typography>
                                {track.careerAdvice.successTips.map((tip, idx) => (
                                  <Typography key={idx} variant="body2" sx={{ fontSize: "0.75rem", mb: 0.5, display: "flex", alignItems: "flex-start", gap: 0.5 }}>
                                    <Box component="span" sx={{ color: "#f59e0b" }}>★</Box> {tip}
                                  </Typography>
                                ))}
                              </Box>
                            </AccordionDetails>
                          </Accordion>
                        )}

                        <Button
                          size="small"
                          variant="contained"
                          onClick={() => navigate(`/learn/certifications?path=${track.certPathType}`)}
                          endIcon={<ArrowForwardIcon />}
                          sx={{ fontSize: "0.7rem", mt: 1, bgcolor: track.color, "&:hover": { bgcolor: alpha(track.color, 0.8) } }}
                          fullWidth
                        >
                          Find {track.title} Courses
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

          {/* Tab 10: Personal Guidance */}
          <TabPanel value={tabValue} index={10}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                <strong>Personalized Career Development</strong> - Use these tools to create a customized learning plan, avoid common pitfalls, and track your progress toward your cybersecurity career goals.
              </Alert>

              {/* Career Path Finder */}
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.05)}, ${alpha("#6366f1", 0.05)})`,
                  border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                  mb: 3,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <PsychologyIcon sx={{ color: "#8b5cf6" }} /> Career Path Finder
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                  Answer these questions to discover which cybersecurity tracks align best with your interests and background.
                </Typography>
                
                {careerAssessmentQuestions.map((q) => (
                  <Box key={q.id} sx={{ mb: 3 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1.5 }}>
                      {q.question}
                    </Typography>
                    <Grid container spacing={1}>
                      {q.options.map((option) => (
                        <Grid item xs={12} md={6} key={option.value}>
                          <Paper
                            sx={{
                              p: 1.5,
                              borderRadius: 2,
                              border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                              cursor: "pointer",
                              transition: "all 0.2s",
                              "&:hover": { 
                                bgcolor: alpha("#8b5cf6", 0.05), 
                                borderColor: "#8b5cf6",
                                transform: "translateX(4px)"
                              },
                            }}
                          >
                            <Typography variant="body2" sx={{ fontWeight: 500, mb: 0.5 }}>
                              {option.label}
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {option.tracks.map((track) => (
                                <Chip
                                  key={track}
                                  label={track}
                                  size="small"
                                  sx={{ fontSize: "0.6rem", height: 18, bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }}
                                />
                              ))}
                            </Box>
                          </Paper>
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                ))}
              </Paper>

              {/* Career Milestones Timeline */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <TimelineIcon sx={{ color: "#22c55e" }} /> Career Milestones by Phase
              </Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {Object.entries(careerMilestones).map(([phase, milestones]) => (
                  <Grid item xs={12} md={6} lg={3} key={phase}>
                    <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                      <Chip
                        label={phase === "0-6months" ? "0-6 Months" : phase === "6-12months" ? "6-12 Months" : phase === "1-2years" ? "1-2 Years" : "3-5 Years"}
                        size="small"
                        sx={{
                          mb: 1.5,
                          fontWeight: 700,
                          bgcolor: phase === "0-6months" ? "#22c55e" : phase === "6-12months" ? "#3b82f6" : phase === "1-2years" ? "#f59e0b" : "#8b5cf6",
                          color: "white",
                        }}
                      />
                      <List dense disablePadding>
                        {milestones.map((milestone, i) => (
                          <ListItem key={i} sx={{ py: 0.5, px: 0, alignItems: "flex-start" }}>
                            <ListItemIcon sx={{ minWidth: 20, mt: 0.5 }}>
                              <Box
                                sx={{
                                  width: 6,
                                  height: 6,
                                  borderRadius: "50%",
                                  bgcolor: phase === "0-6months" ? "#22c55e" : phase === "6-12months" ? "#3b82f6" : phase === "1-2years" ? "#f59e0b" : "#8b5cf6",
                                }}
                              />
                            </ListItemIcon>
                            <ListItemText primary={milestone} primaryTypographyProps={{ variant: "caption" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              {/* Common Mistakes */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#ef4444" }} /> Common Mistakes to Avoid
              </Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {careerMistakesDetailed.map((item, i) => (
                  <Grid item xs={12} md={6} key={i}>
                    <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.2)}`, height: "100%" }}>
                      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
                        <ErrorOutlineIcon sx={{ fontSize: 18, color: "#ef4444", mt: 0.25 }} />
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444" }}>
                          {item.mistake}
                        </Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ ml: 3.5 }}>
                        <Box component="span" sx={{ color: "#22c55e", fontWeight: 600 }}>→ </Box>
                        {item.solution}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              {/* Weekly Study Plan */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <CalendarMonthIcon sx={{ color: "#3b82f6" }} /> Sample Weekly Study Plans
              </Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {Object.entries(weeklyStudyPlan).map(([level, schedule]) => (
                  <Grid item xs={12} md={6} key={level}>
                    <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(level === "beginner" ? "#22c55e" : "#f59e0b", 0.3)}` }}>
                      <Chip
                        label={level === "beginner" ? "Beginner (10-15 hrs/week)" : "Intermediate (15-20 hrs/week)"}
                        size="small"
                        sx={{ mb: 2, fontWeight: 700, bgcolor: level === "beginner" ? "#22c55e" : "#f59e0b", color: "white" }}
                      />
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ fontWeight: 700, py: 0.5 }}>Day</TableCell>
                              <TableCell sx={{ fontWeight: 700, py: 0.5 }}>Activity</TableCell>
                              <TableCell sx={{ fontWeight: 700, py: 0.5 }}>Hours</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {schedule.map((day, i) => (
                              <TableRow key={i}>
                                <TableCell sx={{ py: 0.5, fontWeight: 600 }}>{day.day}</TableCell>
                                <TableCell sx={{ py: 0.5, fontSize: "0.75rem" }}>{day.activity}</TableCell>
                                <TableCell sx={{ py: 0.5 }}>{day.hours}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              {/* Burnout Prevention */}
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}`, mb: 3 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <LocalFireDepartmentIcon sx={{ color: "#f59e0b" }} /> Burnout Prevention & Mental Health
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Learning security is a marathon, not a sprint. Sustainable progress beats burnout every time.
                </Typography>
                <Grid container spacing={2}>
                  {burnoutPrevention.map((tip, i) => (
                    <Grid item xs={12} md={6} key={i}>
                      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                        <FavoriteIcon sx={{ fontSize: 16, color: "#f59e0b", mt: 0.25 }} />
                        <Typography variant="body2">{tip}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Success Stories Framework */}
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, mb: 3 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <EmojiEventsIcon sx={{ color: "#22c55e" }} /> Keys to Career Success
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { icon: "🎯", title: "Define Clear Goals", desc: "Know what role you want in 1, 3, and 5 years. Work backwards to create actionable steps." },
                    { icon: "📝", title: "Document Everything", desc: "Your notes, writeups, and projects become your portfolio. Future you will thank present you." },
                    { icon: "🤝", title: "Build Relationships", desc: "The security community is small. Help others, share knowledge, and your reputation will grow." },
                    { icon: "🔄", title: "Embrace Failure", desc: "Failed challenges, rejected applications, and bugs you couldn't find are all learning opportunities." },
                    { icon: "⏰", title: "Be Patient", desc: "Most successful security professionals took 2-5 years to reach intermediate level. Trust the process." },
                    { icon: "🧠", title: "Stay Curious", desc: "The best in this field never stop learning. Embrace the constantly evolving landscape." },
                  ].map((item, i) => (
                    <Grid item xs={12} md={6} lg={4} key={i}>
                      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                        <Typography sx={{ fontSize: 24 }}>{item.icon}</Typography>
                        <Box>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                          <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                        </Box>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Quick Action Checklist */}
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.05)}, ${alpha("#8b5cf6", 0.05)})`,
                  border: `1px solid ${alpha("#3b82f6", 0.2)}`,
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  <ChecklistIcon sx={{ color: "#3b82f6" }} /> Your First Week Action Checklist
                </Typography>
                <Grid container spacing={1}>
                  {[
                    "Create accounts on TryHackMe and HackTheBox",
                    "Set up a learning blog (GitHub Pages, Notion, or Medium)",
                    "Join a security Discord (TryHackMe, HackTheBox, InfoSec Prep)",
                    "Download and install VirtualBox + Kali Linux",
                    "Complete your first TryHackMe room",
                    "Subscribe to 2-3 security newsletters",
                    "Follow 10 security professionals on Twitter/X",
                    "Sign up for your local BSides or OWASP chapter",
                    "Create a study schedule and stick to it for one week",
                    "Find one person to be your accountability partner",
                  ].map((action, i) => (
                    <Grid item xs={12} md={6} key={i}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Box
                          sx={{
                            width: 20,
                            height: 20,
                            borderRadius: 1,
                            border: `2px solid ${alpha("#3b82f6", 0.5)}`,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: "0.7rem",
                            color: "#3b82f6",
                            fontWeight: 700,
                          }}
                        >
                          {i + 1}
                        </Box>
                        <Typography variant="body2">{action}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Alert severity="success" sx={{ mt: 3 }}>
                <strong>Remember:</strong> Every expert was once a beginner. The security community is welcoming to newcomers who show genuine interest and effort. Start today, stay consistent, and you'll be amazed at your progress in 6-12 months.
              </Alert>
            </Box>
          </TabPanel>

          {/* Tab 11: Home Lab Setup Guide */}
          <TabPanel value={tabValue} index={11}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                <strong>🏠 Build Your Security Lab!</strong> A home lab is essential for hands-on practice. Whether you have $0 or $500 to spend, there's a setup that works for you. Start small and expand as you learn.
              </Alert>

              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <ComputerIcon sx={{ color: theme.palette.primary.main }} />
                Home Lab Setup Guide by Career Track
              </Typography>

              {homeLabSetups.map((lab, index) => (
                <Accordion 
                  key={lab.track} 
                  defaultExpanded={index === 0}
                  sx={{ 
                    mb: 2, 
                    borderRadius: 2, 
                    overflow: "hidden",
                    "&:before": { display: "none" },
                    boxShadow: 2
                  }}
                >
                  <AccordionSummary 
                    expandIcon={<ExpandMoreIcon />}
                    sx={{ 
                      bgcolor: alpha(lab.color, 0.1),
                      "&:hover": { bgcolor: alpha(lab.color, 0.15) }
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                      <Typography variant="h5">{lab.icon}</Typography>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="h6" sx={{ fontWeight: 700 }}>
                          {lab.track}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {lab.description}
                        </Typography>
                      </Box>
                      <Box sx={{ display: "flex", gap: 1 }}>
                        <Chip 
                          label={`Min: ${lab.minBudget}`} 
                          size="small" 
                          sx={{ bgcolor: alpha("#22c55e", 0.2), fontWeight: 600 }}
                        />
                        <Chip 
                          label={`Rec: ${lab.recommendedBudget}`} 
                          size="small" 
                          sx={{ bgcolor: alpha("#3b82f6", 0.2), fontWeight: 600 }}
                        />
                      </Box>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails sx={{ p: 3 }}>
                    <Grid container spacing={3}>
                      {/* Hardware Requirements */}
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.paper, 0.8), height: "100%" }}>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                            <MemoryIcon color="primary" /> Hardware
                          </Typography>
                          <List dense>
                            {lab.hardware.map((item, idx) => (
                              <ListItem key={idx} sx={{ px: 0 }}>
                                <ListItemText
                                  primary={
                                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{item.item}</Typography>
                                      <Chip label={item.cost} size="small" sx={{ fontSize: "0.7rem" }} />
                                    </Box>
                                  }
                                  secondary={item.purpose}
                                />
                              </ListItem>
                            ))}
                          </List>
                        </Paper>
                      </Grid>

                      {/* Software Tools */}
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.paper, 0.8), height: "100%" }}>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                            <SettingsIcon color="secondary" /> Software & Tools
                          </Typography>
                          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                            {lab.software.map((sw, idx) => (
                              <Tooltip key={idx} title={`${sw.purpose} (${sw.cost})`} arrow>
                                <Chip 
                                  label={sw.name} 
                                  size="small"
                                  sx={{ 
                                    fontWeight: 500,
                                    bgcolor: sw.cost === "Free" ? alpha("#22c55e", 0.15) : alpha("#f59e0b", 0.15)
                                  }}
                                />
                              </Tooltip>
                            ))}
                          </Box>
                        </Paper>
                      </Grid>

                      {/* Virtual Machines */}
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.paper, 0.8), height: "100%" }}>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                            <DownloadIcon color="info" /> VMs & ISOs
                          </Typography>
                          <List dense>
                            {lab.vms.map((vm, idx) => (
                              <ListItem 
                                key={idx} 
                                sx={{ px: 0 }}
                                secondaryAction={
                                  <Button 
                                    size="small" 
                                    href={vm.link} 
                                    target="_blank"
                                    endIcon={<OpenInNewIcon fontSize="small" />}
                                  >
                                    Get
                                  </Button>
                                }
                              >
                                <ListItemText
                                  primary={<Typography variant="body2" sx={{ fontWeight: 600 }}>{vm.name}</Typography>}
                                  secondary={vm.purpose}
                                />
                              </ListItem>
                            ))}
                          </List>
                        </Paper>
                      </Grid>

                      {/* Cloud Alternatives */}
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.paper, 0.8), height: "100%" }}>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                            <CloudIcon color="info" /> Cloud Alternatives
                          </Typography>
                          <List dense>
                            {lab.cloudAlternatives.map((cloud, idx) => (
                              <ListItem key={idx} sx={{ px: 0 }}>
                                <ListItemText
                                  primary={
                                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{cloud.service}</Typography>
                                      <Chip 
                                        label={cloud.cost} 
                                        size="small" 
                                        sx={{ 
                                          fontSize: "0.7rem",
                                          bgcolor: cloud.cost.includes("Free") ? alpha("#22c55e", 0.2) : alpha("#f59e0b", 0.2)
                                        }} 
                                      />
                                    </Box>
                                  }
                                  secondary={cloud.purpose}
                                />
                              </ListItem>
                            ))}
                          </List>
                        </Paper>
                      </Grid>

                      {/* Practice Targets */}
                      <Grid item xs={12}>
                        <Paper sx={{ p: 2, bgcolor: alpha(lab.color, 0.05), border: `1px solid ${alpha(lab.color, 0.2)}` }}>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                            🎯 Practice Targets
                          </Typography>
                          <Grid container spacing={1}>
                            {lab.practiceTargets.map((target, idx) => (
                              <Grid item xs={12} sm={6} md={4} key={idx}>
                                <Button
                                  variant="outlined"
                                  fullWidth
                                  href={target.link}
                                  target="_blank"
                                  sx={{ 
                                    textTransform: "none", 
                                    justifyContent: "flex-start",
                                    borderColor: alpha(lab.color, 0.3),
                                    "&:hover": { borderColor: lab.color, bgcolor: alpha(lab.color, 0.05) }
                                  }}
                                >
                                  <Box sx={{ textAlign: "left" }}>
                                    <Typography variant="body2" sx={{ fontWeight: 600 }}>{target.name}</Typography>
                                    <Typography variant="caption" color="text.secondary">{target.description}</Typography>
                                  </Box>
                                </Button>
                              </Grid>
                            ))}
                          </Grid>
                        </Paper>
                      </Grid>

                      {/* First Week Setup */}
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                            📅 Your First Week Setup Plan
                          </Typography>
                          <List dense>
                            {lab.firstWeekSetup.map((step, idx) => (
                              <ListItem key={idx} sx={{ px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 32 }}>
                                  <Box
                                    sx={{
                                      width: 22,
                                      height: 22,
                                      borderRadius: "50%",
                                      bgcolor: alpha("#22c55e", 0.2),
                                      display: "flex",
                                      alignItems: "center",
                                      justifyContent: "center",
                                      fontSize: "0.75rem",
                                      fontWeight: 700,
                                      color: "#22c55e",
                                    }}
                                  >
                                    {idx + 1}
                                  </Box>
                                </ListItemIcon>
                                <ListItemText primary={<Typography variant="body2">{step}</Typography>} />
                              </ListItem>
                            ))}
                          </List>
                        </Paper>
                      </Grid>

                      {/* Pro Tips */}
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                            💡 Pro Tips
                          </Typography>
                          <List dense>
                            {lab.tips.map((tip, idx) => (
                              <ListItem key={idx} sx={{ px: 0 }}>
                                <ListItemIcon sx={{ minWidth: 28 }}>
                                  <LightbulbIcon sx={{ fontSize: 18, color: "#f59e0b" }} />
                                </ListItemIcon>
                                <ListItemText primary={<Typography variant="body2">{tip}</Typography>} />
                              </ListItem>
                            ))}
                          </List>
                        </Paper>
                      </Grid>
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              ))}

              {/* General Lab Tips */}
              <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.primary.main, 0.05), borderRadius: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  🛠️ Universal Lab Best Practices
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ p: 2, bgcolor: "background.paper", borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: theme.palette.primary.main }}>
                        💾 Virtualization Setup
                      </Typography>
                      <List dense>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="VMware Workstation Pro/Player or VirtualBox" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Allocate 4-8GB RAM per VM minimum" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Use SSD for VM storage (huge speed boost)" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Take snapshots before major changes" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Use NAT or Host-Only networks for isolation" /></ListItem>
                      </List>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ p: 2, bgcolor: "background.paper", borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: theme.palette.secondary.main }}>
                        🔐 Safety First
                      </Typography>
                      <List dense>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="NEVER connect vulnerable VMs to the internet" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Isolate lab network from home network" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Password-protect malware samples ('infected')" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Never attack systems without authorization" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Keep host machine patched and secure" /></ListItem>
                      </List>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ p: 2, bgcolor: "background.paper", borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: theme.palette.warning.main }}>
                        📝 Documentation
                      </Typography>
                      <List dense>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Keep a lab notebook (Notion, Obsidian, wiki)" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Document every command and its purpose" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Screenshot important configurations" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Save network diagrams of your setup" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Your notes become your knowledge base" /></ListItem>
                      </List>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>

              {/* Budget Guides */}
              <Paper sx={{ p: 3, mt: 3, borderRadius: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                  💰 Budget-Based Setup Guides
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                        🆓 $0 Budget (Cloud-Only)
                      </Typography>
                      <List dense>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="VirtualBox (free hypervisor)" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="TryHackMe free rooms" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="HackTheBox free tier" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="LetsDefend free alerts" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="AWS/Azure/GCP free tiers" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="VulnHub downloadable VMs" /></ListItem>
                      </List>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                        💵 $100-300 Budget
                      </Typography>
                      <List dense>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Used laptop/PC (16GB RAM)" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="External SSD for VMs" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Raspberry Pi for projects" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Managed switch (used)" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="HackTheBox/TryHackMe subscription" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Basic WiFi adapter (Alfa)" /></ListItem>
                      </List>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#a855f7", 0.1), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 1 }}>
                        🚀 $500+ Budget (Serious Lab)
                      </Typography>
                      <List dense>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Dedicated lab machine (32GB+ RAM)" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Mini PC for pfSense/OPNsense" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Managed switch + access point" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Multiple Raspberry Pis" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="Hardware write-blocker (forensics)" /></ListItem>
                        <ListItem sx={{ px: 0 }}><ListItemText primary="All premium platform subscriptions" /></ListItem>
                      </List>
                    </Paper>
                  </Grid>
                </Grid>
              </Paper>

              <Alert severity="success" sx={{ mt: 3 }}>
                <strong>Start Today!</strong> You don't need a perfect setup to begin learning. Start with free tools and platforms, then expand your lab as your skills grow. The best lab is the one you actually use!
              </Alert>
            </Box>
          </TabPanel>
        </Paper>

        {/* Related Pages */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            📚 Related Learning Resources
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: theme.palette.primary.main }}>
                Learning Paths
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                <Chip
                  label="🎓 Security Certifications"
                  clickable
                  onClick={() => navigate("/learn/certifications")}
                  sx={{ fontWeight: 600 }}
                />
                <Chip
                  label="🟢 Beginner Certs"
                  clickable
                  onClick={() => navigate("/learn/certifications?level=Beginner")}
                  sx={{ fontWeight: 600, bgcolor: alpha("#22c55e", 0.1) }}
                />
                <Chip
                  label="🔴 Advanced Certs"
                  clickable
                  onClick={() => navigate("/learn/certifications?level=Advanced")}
                  sx={{ fontWeight: 600, bgcolor: alpha("#ef4444", 0.1) }}
                />
                <Chip
                  label="💼 Build Your Portfolio"
                  clickable
                  onClick={() => navigate("/learn/portfolio")}
                  sx={{ fontWeight: 600 }}
                />
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: theme.palette.secondary.main }}>
                Hands-On Skills
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                <Chip
                  label="🔵 SOC Workflow"
                  clickable
                  onClick={() => navigate("/learn/soc-workflow")}
                  sx={{ fontWeight: 600 }}
                />
                <Chip
                  label="🚨 Incident Response"
                  clickable
                  onClick={() => navigate("/learn/incident-response")}
                  sx={{ fontWeight: 600 }}
                />
                <Chip
                  label="🔴 Red Team Certs"
                  clickable
                  onClick={() => navigate("/learn/certifications?path=red-team")}
                  sx={{ fontWeight: 600, bgcolor: alpha("#ef4444", 0.1) }}
                />
                <Chip
                  label="☁️ Cloud Security Certs"
                  clickable
                  onClick={() => navigate("/learn/certifications?path=cloud-security")}
                  sx={{ fontWeight: 600, bgcolor: alpha("#06b6d4", 0.1) }}
                />
              </Box>
            </Grid>
          </Grid>
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
