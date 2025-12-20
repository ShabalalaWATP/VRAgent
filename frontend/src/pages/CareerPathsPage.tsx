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
    description: "Find vulnerabilities before attackers do. Penetration testing, ethical hacking, and red team operations.",
    roles: [
      "Junior Penetration Tester",
      "Penetration Tester",
      "Senior Penetration Tester",
      "Red Team Operator",
      "Red Team Lead",
    ],
    skills: ["Network pentesting", "Web app testing", "Social engineering", "Exploit development", "Report writing"],
    certifications: ["CEH", "OSCP", "OSWE", "GPEN", "CRTO"],
    salaryRange: "$75K - $200K+",
    demand: 92,
    dayInLife: [
      "Scope and plan engagement with client",
      "Perform reconnaissance and enumeration",
      "Exploit vulnerabilities and pivot through networks",
      "Document findings and write detailed reports",
      "Present findings to technical and executive teams",
    ],
  },
  {
    title: "Defensive Security (Blue Team)",
    icon: <LocalPoliceIcon sx={{ fontSize: 40 }} />,
    color: "#3b82f6",
    description: "Detect, respond to, and prevent cyber attacks. Security operations, incident response, and threat hunting.",
    roles: [
      "SOC Analyst (Tier 1-3)",
      "Incident Responder",
      "Threat Hunter",
      "Detection Engineer",
      "SOC Manager",
    ],
    skills: ["SIEM administration", "Log analysis", "Threat intelligence", "Malware analysis", "Forensics"],
    certifications: ["Security+", "CySA+", "GCIH", "GCFA", "BTL1/BTL2"],
    salaryRange: "$60K - $170K+",
    demand: 95,
    dayInLife: [
      "Monitor SIEM dashboards and alerts",
      "Triage and investigate security incidents",
      "Hunt for threats using IOCs and TTPs",
      "Create and tune detection rules",
      "Coordinate incident response activities",
    ],
  },
  {
    title: "Security Engineering",
    icon: <BuildIcon sx={{ fontSize: 40 }} />,
    color: "#8b5cf6",
    description: "Build secure systems and infrastructure. DevSecOps, cloud security, and security architecture.",
    roles: [
      "Security Engineer",
      "DevSecOps Engineer",
      "Cloud Security Engineer",
      "Security Architect",
      "Principal Security Engineer",
    ],
    skills: ["Infrastructure as Code", "CI/CD security", "Cloud platforms", "Container security", "Zero trust"],
    certifications: ["AWS Security", "Azure Security", "CCSP", "CISSP", "TOGAF"],
    salaryRange: "$90K - $220K+",
    demand: 98,
    dayInLife: [
      "Design and implement security controls",
      "Integrate security into CI/CD pipelines",
      "Review architecture proposals for security",
      "Automate security testing and monitoring",
      "Mentor development teams on secure coding",
    ],
  },
  {
    title: "Governance, Risk & Compliance",
    icon: <BusinessIcon sx={{ fontSize: 40 }} />,
    color: "#f59e0b",
    description: "Manage security programs, policies, and compliance. Risk assessment, auditing, and security leadership.",
    roles: [
      "Security Analyst (GRC)",
      "Compliance Analyst",
      "Risk Analyst",
      "Security Manager",
      "CISO",
    ],
    skills: ["Risk frameworks", "Policy writing", "Audit management", "Vendor assessment", "Executive communication"],
    certifications: ["CISM", "CRISC", "CISA", "CISSP", "ISO 27001 Lead Auditor"],
    salaryRange: "$70K - $350K+",
    demand: 88,
    dayInLife: [
      "Conduct risk assessments and gap analyses",
      "Write and update security policies",
      "Manage compliance audits (SOC2, ISO, PCI)",
      "Assess third-party vendor security",
      "Report to executives on security posture",
    ],
  },
];

// Specialized tracks beyond the main four
const specializedTracks = [
  {
    title: "Application Security (AppSec)",
    icon: <CodeIcon />,
    color: "#ec4899",
    description: "Secure software development lifecycle, code review, and application vulnerability management.",
    skills: ["SAST/DAST tools", "Secure code review", "Threat modeling", "API security", "OWASP Top 10"],
    certs: ["CSSLP", "GWEB", "OSWE", "CASE"],
    salary: "$100K - $200K+",
  },
  {
    title: "Cloud Security",
    icon: <CloudIcon />,
    color: "#06b6d4",
    description: "Secure cloud infrastructure across AWS, Azure, GCP. Identity, networking, and workload protection.",
    skills: ["IAM policies", "VPC security", "Container security", "Serverless security", "Cloud-native tools"],
    certs: ["AWS Security Specialty", "AZ-500", "GCP Security", "CCSP"],
    salary: "$110K - $220K+",
  },
  {
    title: "Threat Intelligence",
    icon: <SearchIcon />,
    color: "#f97316",
    description: "Analyze threat actors, campaigns, and TTPs. Produce actionable intelligence for defensive operations.",
    skills: ["OSINT", "Malware analysis", "MITRE ATT&CK", "Dark web monitoring", "Intel reporting"],
    certs: ["GCTI", "CTIA", "FOR578", "GOSI"],
    salary: "$85K - $170K+",
  },
  {
    title: "Digital Forensics",
    icon: <StorageIcon />,
    color: "#14b8a6",
    description: "Investigate security incidents, collect evidence, and support legal proceedings.",
    skills: ["Disk forensics", "Memory analysis", "Network forensics", "Mobile forensics", "Chain of custody"],
    certs: ["GCFE", "GCFA", "EnCE", "CCE", "CHFI"],
    salary: "$75K - $160K+",
  },
  {
    title: "Malware Analysis",
    icon: <BugReportIcon />,
    color: "#dc2626",
    description: "Reverse engineer malware, understand attacker tools, and develop detection signatures.",
    skills: ["Static analysis", "Dynamic analysis", "Assembly/x86", "Sandbox analysis", "Yara rules"],
    certs: ["GREM", "GCTI", "FOR610", "eCMAP"],
    salary: "$90K - $180K+",
  },
  {
    title: "Identity & Access Management",
    icon: <VerifiedUserIcon />,
    color: "#8b5cf6",
    description: "Design and manage identity systems, SSO, MFA, and privileged access management.",
    skills: ["Active Directory", "Azure AD/Entra", "Okta/Auth0", "PAM solutions", "Zero trust identity"],
    certs: ["SC-300", "Okta Certified", "CyberArk Defender", "CISSP"],
    salary: "$95K - $190K+",
  },
];

// Salary data by role and experience
const salaryData = [
  { role: "SOC Analyst (Tier 1)", entry: "$55K-70K", mid: "$70K-90K", senior: "$90K-115K", location: "US Average" },
  { role: "SOC Analyst (Tier 2/3)", entry: "$70K-90K", mid: "$90K-120K", senior: "$120K-150K", location: "US Average" },
  { role: "Penetration Tester", entry: "$70K-90K", mid: "$90K-130K", senior: "$130K-180K", location: "US Average" },
  { role: "Security Engineer", entry: "$85K-110K", mid: "$110K-150K", senior: "$150K-200K", location: "US Average" },
  { role: "Cloud Security Engineer", entry: "$95K-120K", mid: "$120K-160K", senior: "$160K-220K", location: "US Average" },
  { role: "DevSecOps Engineer", entry: "$90K-115K", mid: "$115K-155K", senior: "$155K-200K", location: "US Average" },
  { role: "Security Architect", entry: "$120K-150K", mid: "$150K-190K", senior: "$190K-250K", location: "US Average" },
  { role: "GRC Analyst", entry: "$60K-80K", mid: "$80K-110K", senior: "$110K-150K", location: "US Average" },
  { role: "Threat Hunter", entry: "$80K-100K", mid: "$100K-140K", senior: "$140K-180K", location: "US Average" },
  { role: "CISO", entry: "N/A", mid: "$180K-250K", senior: "$250K-400K+", location: "US Average" },
];

// Learning roadmaps
const learningRoadmaps = {
  beginner: {
    title: "Beginner (0-1 years)",
    color: "#22c55e",
    steps: [
      { skill: "Networking Fundamentals", resources: "CompTIA Network+, Professor Messer", time: "2-3 months" },
      { skill: "Linux Basics", resources: "Linux Journey, OverTheWire Bandit", time: "1-2 months" },
      { skill: "Security Fundamentals", resources: "CompTIA Security+, TryHackMe Pre-Security", time: "2-3 months" },
      { skill: "Scripting (Python/Bash)", resources: "Automate the Boring Stuff, Linux command line", time: "2-3 months" },
      { skill: "Web Application Basics", resources: "PortSwigger Web Academy (free labs)", time: "2-3 months" },
    ],
  },
  intermediate: {
    title: "Intermediate (1-3 years)",
    color: "#f59e0b",
    steps: [
      { skill: "Penetration Testing", resources: "OSCP, HackTheBox, PentesterLab", time: "6-12 months" },
      { skill: "SIEM & Log Analysis", resources: "Splunk Fundamentals, Elastic SIEM", time: "2-3 months" },
      { skill: "Cloud Security", resources: "AWS/Azure Security certifications", time: "3-4 months" },
      { skill: "Incident Response", resources: "GCIH, BTL1, LetsDefend", time: "3-4 months" },
      { skill: "Threat Intelligence", resources: "MITRE ATT&CK, GCTI", time: "2-3 months" },
    ],
  },
  advanced: {
    title: "Advanced (3+ years)",
    color: "#ef4444",
    steps: [
      { skill: "Exploit Development", resources: "OSED, Corelan tutorials", time: "6-12 months" },
      { skill: "Malware Analysis", resources: "GREM, Practical Malware Analysis book", time: "4-6 months" },
      { skill: "Security Architecture", resources: "CISSP, TOGAF, SABSA", time: "6-12 months" },
      { skill: "Red Team Operations", resources: "CRTO, CRTP, Adversary simulation", time: "6-12 months" },
      { skill: "Leadership & Strategy", resources: "CISM, MBA, Executive communication", time: "Ongoing" },
    ],
  },
};

// Interview questions by category
const interviewQuestions = {
  technical: [
    { q: "Explain the TCP 3-way handshake", level: "Entry", topic: "Networking" },
    { q: "What is the difference between symmetric and asymmetric encryption?", level: "Entry", topic: "Cryptography" },
    { q: "How would you investigate a potential phishing incident?", level: "Mid", topic: "IR" },
    { q: "Explain SQL injection and how to prevent it", level: "Mid", topic: "AppSec" },
    { q: "Walk me through your approach to a penetration test", level: "Mid", topic: "Offensive" },
    { q: "How does Kerberoasting work?", level: "Senior", topic: "AD Security" },
    { q: "Explain MITRE ATT&CK and how you use it", level: "Senior", topic: "Threat Intel" },
    { q: "Design a zero-trust architecture for a cloud-native application", level: "Senior", topic: "Architecture" },
  ],
  behavioral: [
    { q: "Tell me about a time you handled a critical security incident", level: "All", topic: "IR" },
    { q: "How do you stay current with security threats and trends?", level: "All", topic: "Growth" },
    { q: "Describe a situation where you had to explain a technical issue to non-technical stakeholders", level: "All", topic: "Communication" },
    { q: "How do you prioritize when you have multiple security issues to address?", level: "Mid", topic: "Decision Making" },
    { q: "Tell me about a time you disagreed with a security decision", level: "Mid", topic: "Conflict" },
    { q: "How do you balance security with business needs?", level: "Senior", topic: "Strategy" },
  ],
  scenario: [
    { q: "You receive an alert that a user's account is exfiltrating data. Walk me through your response.", level: "Mid", topic: "IR" },
    { q: "A developer pushes code with hardcoded credentials. How do you handle it?", level: "Mid", topic: "AppSec" },
    { q: "You discover a critical vulnerability in production during a pentest. What do you do?", level: "Mid", topic: "Ethics" },
    { q: "Leadership wants to deploy a new SaaS tool. How do you assess its security?", level: "Mid", topic: "Risk" },
    { q: "You're building a security program from scratch. Where do you start?", level: "Senior", topic: "Strategy" },
  ],
};

// Career transition paths
const careerTransitions = [
  { from: "IT Support / Help Desk", to: "SOC Analyst", path: "Security+, home lab, TryHackMe, apply to Tier 1 roles", time: "6-12 months" },
  { from: "Network Admin", to: "Security Engineer", path: "Cloud certs, automation skills, security projects", time: "6-12 months" },
  { from: "Software Developer", to: "AppSec Engineer", path: "OWASP training, code review skills, CSSLP/GWEB", time: "3-6 months" },
  { from: "SOC Analyst", to: "Threat Hunter", path: "GCIH, ATT&CK expertise, detection engineering", time: "1-2 years" },
  { from: "SOC Analyst", to: "Penetration Tester", path: "OSCP, CTFs, home lab, build portfolio", time: "1-2 years" },
  { from: "Sys Admin", to: "Cloud Security", path: "AWS/Azure certs, IaC skills, cloud projects", time: "6-12 months" },
  { from: "Military / Intelligence", to: "Threat Intelligence", path: "GCTI, clearance leverage, OSINT skills", time: "3-6 months" },
  { from: "Non-Tech Background", to: "GRC Analyst", path: "Security+, CISA, policy writing, compliance frameworks", time: "1-2 years" },
];

// Industry trends
const industryTrends = [
  { trend: "AI/ML in Security", impact: "High", description: "AI-powered threat detection, automated response, and adversarial AI attacks" },
  { trend: "Cloud-Native Security", impact: "Very High", description: "Securing Kubernetes, serverless, and microservices architectures" },
  { trend: "Zero Trust Architecture", impact: "Very High", description: "Identity-centric security, microsegmentation, continuous verification" },
  { trend: "Supply Chain Security", impact: "High", description: "SBOM, dependency scanning, third-party risk management" },
  { trend: "API Security", impact: "High", description: "Protecting the growing attack surface of APIs and microservices" },
  { trend: "OT/IoT Security", impact: "Growing", description: "Securing industrial control systems and connected devices" },
  { trend: "Privacy Engineering", impact: "Growing", description: "Data protection, privacy by design, regulatory compliance (GDPR, CCPA)" },
  { trend: "Security Automation", impact: "Very High", description: "SOAR, infrastructure as code, automated remediation" },
];

const entryTips = [
  "Start with foundational certs: Security+, Network+",
  "Build a home lab: VMs, vulnerable machines, tools",
  "Practice on CTF platforms: HackTheBox, TryHackMe",
  "Contribute to open source security projects",
  "Write about what you learn (blog, LinkedIn)",
  "Network at local security meetups and conferences",
  "Apply for internships and junior roles early",
];

// Resume tips
const resumeTips = [
  { category: "Format", tips: ["Keep to 1-2 pages", "Use clean, ATS-friendly format", "Include links to GitHub/portfolio"] },
  { category: "Skills Section", tips: ["List tools you've actually used", "Include certifications with dates", "Separate technical from soft skills"] },
  { category: "Experience", tips: ["Use action verbs (detected, analyzed, implemented)", "Quantify impact when possible", "Include home lab and CTF experience"] },
  { category: "Projects", tips: ["Detail your home lab setup", "List CTF achievements and rankings", "Include any bug bounty findings"] },
];

// Top platforms for learning and practice
const learningPlatforms = [
  { name: "TryHackMe", type: "Hands-on Labs", level: "Beginner-Intermediate", cost: "Free/$14/mo", focus: "Structured learning paths" },
  { name: "HackTheBox", type: "Hands-on Labs", level: "Intermediate-Advanced", cost: "Free/$18/mo", focus: "Real-world pentesting" },
  { name: "PortSwigger Web Academy", type: "Web Security", level: "All Levels", cost: "Free", focus: "Web app vulnerabilities" },
  { name: "LetsDefend", type: "Blue Team Labs", level: "Beginner-Intermediate", cost: "Free/$25/mo", focus: "SOC analyst training" },
  { name: "CyberDefenders", type: "Blue Team Labs", level: "Intermediate", cost: "Free", focus: "Forensics & IR challenges" },
  { name: "PentesterLab", type: "Web Security", level: "Intermediate", cost: "$20/mo", focus: "Web app pentesting" },
  { name: "Offensive Security (OffSec)", type: "Certifications", level: "Intermediate-Advanced", cost: "$$$", focus: "OSCP, OSWE, OSED" },
  { name: "SANS Institute", type: "Certifications", level: "All Levels", cost: "$$$$", focus: "GIAC certifications" },
];

export default function CareerPathsPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `Cybersecurity Career Paths Guide - Comprehensive guide covering four main career tracks (Offensive Security, Defensive Security, Security Engineering, GRC) plus specialized tracks (AppSec, Cloud Security, Threat Intelligence, Digital Forensics, Malware Analysis, IAM). Includes detailed salary data by role and experience level, learning roadmaps from beginner to advanced, interview preparation with technical/behavioral/scenario questions, career transition guides, industry trends, resume tips, and recommended learning platforms. Features day-in-the-life descriptions for each role and certification recommendations.`;

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
                Cybersecurity Career Paths
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Comprehensive guide to building your cybersecurity career
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Careers" color="primary" size="small" />
            <Chip label="Red Team" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
            <Chip label="Blue Team" size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
            <Chip label="GRC" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
            <Chip label="Salaries" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
            <Chip label="Roadmaps" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
          </Box>
        </Box>

        {/* Key Stats */}
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { label: "Unfilled Jobs (2024)", value: "3.5M+", icon: <WorkIcon />, color: "#ef4444" },
            { label: "Avg Salary (US)", value: "$120K", icon: <AttachMoneyIcon />, color: "#22c55e" },
            { label: "Job Growth Rate", value: "+35%", icon: <TrendingUpIcon />, color: "#3b82f6" },
            { label: "Career Tracks", value: "10+", icon: <TimelineIcon />, color: "#f59e0b" },
          ].map((stat) => (
            <Grid item xs={6} md={3} key={stat.label}>
              <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2 }}>
                <Box sx={{ color: stat.color, mb: 1 }}>{stat.icon}</Box>
                <Typography variant="h5" sx={{ fontWeight: 800, color: stat.color }}>{stat.value}</Typography>
                <Typography variant="caption" color="text.secondary">{stat.label}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

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
            <Tab label="Getting Started" icon={<SchoolIcon />} iconPosition="start" />
          </Tabs>

          {/* Tab 0: Main Career Tracks */}
          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                These four tracks represent the primary career paths in cybersecurity. Most professionals specialize in one area but understanding all domains makes you more effective.
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
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {path.certifications.map((cert) => (
                          <Chip
                            key={cert}
                            label={cert}
                            size="small"
                            sx={{ fontSize: "0.65rem", height: 22, bgcolor: alpha(path.color, 0.1), color: path.color, fontWeight: 600 }}
                          />
                        ))}
                      </Box>
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
                Beyond the four main tracks, these specialized roles focus on specific domains and often command premium salaries due to their expertise requirements.
              </Alert>

              <Grid container spacing={2}>
                {specializedTracks.map((track) => (
                  <Grid item xs={12} md={6} lg={4} key={track.title}>
                    <Card sx={{ height: "100%", borderRadius: 2, border: `1px solid ${alpha(track.color, 0.2)}` }}>
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                          <Box sx={{ color: track.color }}>{track.icon}</Box>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{track.title}</Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, minHeight: 48 }}>
                          {track.description}
                        </Typography>
                        <Chip label={track.salary} size="small" sx={{ mb: 2, bgcolor: alpha("#22c55e", 0.1), color: "#22c55e", fontWeight: 600 }} />
                        <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>Key Skills:</Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1.5 }}>
                          {track.skills.slice(0, 4).map((skill) => (
                            <Chip key={skill} label={skill} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          ))}
                        </Box>
                        <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>Certifications:</Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                          {track.certs.map((cert) => (
                            <Chip key={cert} label={cert} size="small" sx={{ fontSize: "0.6rem", height: 20, bgcolor: alpha(track.color, 0.1), color: track.color }} />
                          ))}
                        </Box>
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
                Salaries vary significantly by location, company size, and industry. These figures represent US averages for 2024. Add 20-40% for major tech hubs (SF, NYC, Seattle).
              </Alert>

              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Role</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#22c55e" }}>Entry Level (0-2 yrs)</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>Mid Level (2-5 yrs)</TableCell>
                      <TableCell sx={{ fontWeight: 700, color: "#ef4444" }}>Senior (5+ yrs)</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {salaryData.map((row) => (
                      <TableRow key={row.role} hover>
                        <TableCell sx={{ fontWeight: 600 }}>{row.role}</TableCell>
                        <TableCell sx={{ color: "#22c55e" }}>{row.entry}</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>{row.mid}</TableCell>
                        <TableCell sx={{ color: "#ef4444" }}>{row.senior}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <AttachMoneyIcon sx={{ color: "#22c55e" }} /> Salary Boosters
                    </Typography>
                    <List dense>
                      {[
                        "OSCP/OSWE certification (+$10-20K)",
                        "Cloud certifications (AWS/Azure)",
                        "Security clearance (+$15-30K)",
                        "Management/leadership experience",
                        "Niche expertise (malware, cloud, OT)",
                        "Big tech or finance industry",
                        "Remote work from lower COL areas",
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
                        "Finance & Banking (+20-30%)",
                        "Big Tech (FAANG)",
                        "Defense & Government Contractors",
                        "Healthcare (with clearance)",
                        "Consulting (Big 4)",
                        "Cryptocurrency/Web3",
                        "Critical Infrastructure",
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
            </Box>
          </TabPanel>

          {/* Tab 3: Learning Roadmaps */}
          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                These roadmaps provide a structured approach to building cybersecurity skills. Timelines assume part-time study (10-15 hours/week) alongside work or school.
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
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {roadmap.steps.map((step, i) => (
                            <TableRow key={i} hover>
                              <TableCell sx={{ fontWeight: 600 }}>{step.skill}</TableCell>
                              <TableCell sx={{ color: "text.secondary" }}>{step.resources}</TableCell>
                              <TableCell>
                                <Chip label={step.time} size="small" sx={{ bgcolor: alpha(roadmap.color, 0.1), color: roadmap.color, fontWeight: 600 }} />
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              ))}

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
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {learningPlatforms.map((platform) => (
                        <TableRow key={platform.name} hover>
                          <TableCell sx={{ fontWeight: 600 }}>{platform.name}</TableCell>
                          <TableCell>{platform.type}</TableCell>
                          <TableCell>{platform.level}</TableCell>
                          <TableCell sx={{ color: platform.cost === "Free" ? "#22c55e" : "inherit" }}>{platform.cost}</TableCell>
                          <TableCell sx={{ color: "text.secondary" }}>{platform.focus}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Box>
          </TabPanel>

          {/* Tab 4: Interview Prep */}
          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Security interviews typically include technical questions, behavioral scenarios, and hands-on assessments. Prepare for all three types.
              </Alert>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>
                    🔧 Technical Questions
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
                    💬 Behavioral Questions
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700, width: "70%" }}>Question</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Topic</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {interviewQuestions.behavioral.map((item, i) => (
                          <TableRow key={i} hover>
                            <TableCell>{item.q}</TableCell>
                            <TableCell>
                              <Chip label={item.topic} size="small" variant="outlined" />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Alert severity="success" sx={{ mt: 2 }}>
                    <strong>STAR Method:</strong> Structure your answers with Situation, Task, Action, Result for maximum impact.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                    🎯 Scenario-Based Questions
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700, width: "70%" }}>Scenario</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Topic</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {interviewQuestions.scenario.map((item, i) => (
                          <TableRow key={i} hover>
                            <TableCell>{item.q}</TableCell>
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
                    "Review the job description thoroughly",
                    "Research the company's security posture",
                    "Prepare 2-3 STAR stories",
                    "Practice explaining technical concepts simply",
                    "Have questions ready for the interviewer",
                    "Set up a clean, professional environment (video)",
                    "Test your audio/video before the call",
                    "Have your resume and notes accessible",
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
                Many cybersecurity professionals transition from related IT fields. Your existing experience is valuable – here's how to leverage it.
              </Alert>

              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>From</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>To</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Transition Path</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Timeline</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {careerTransitions.map((transition, i) => (
                      <TableRow key={i} hover>
                        <TableCell sx={{ fontWeight: 600 }}>{transition.from}</TableCell>
                        <TableCell sx={{ color: "#3b82f6", fontWeight: 600 }}>{transition.to}</TableCell>
                        <TableCell sx={{ color: "text.secondary" }}>{transition.path}</TableCell>
                        <TableCell>
                          <Chip label={transition.time} size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
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
                        "Networking knowledge (routing, firewalls)",
                        "System administration (Windows/Linux)",
                        "Scripting and automation",
                        "Problem-solving and troubleshooting",
                        "Documentation and communication",
                        "Understanding of business operations",
                        "Compliance and audit experience",
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
                      <GroupsIcon sx={{ color: "#ef4444" }} /> Common Transition Mistakes
                    </Typography>
                    <List dense>
                      {[
                        "Waiting for the 'perfect' certification",
                        "Not building hands-on experience",
                        "Undervaluing existing IT experience",
                        "Applying only to senior roles",
                        "Neglecting networking and community",
                        "Not tailoring resume to security",
                        "Giving up after a few rejections",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#ef4444" }} />
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

          {/* Tab 6: Industry Trends */}
          <TabPanel value={tabValue} index={6}>
            <Box sx={{ p: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                Staying current with industry trends helps you anticipate skill demands and position yourself for emerging opportunities.
              </Alert>

              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Trend</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Impact</TableCell>
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
                        <TableCell sx={{ color: "text.secondary" }}>{trend.description}</TableCell>
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
                        "Kubernetes Security", "AI/ML Security", "Cloud-Native", "Zero Trust",
                        "SBOM/Supply Chain", "API Security", "Threat Hunting", "Detection Engineering",
                        "Security Automation", "Privacy Engineering", "OT/ICS Security",
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
                        "Krebs on Security (news)",
                        "The Hacker News (news)",
                        "SANS Reading Room (research)",
                        "Security Weekly (podcasts)",
                        "Darknet Diaries (podcast)",
                        "Twitter/X security community",
                        "r/netsec, r/cybersecurity",
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
            </Box>
          </TabPanel>

          {/* Tab 7: Getting Started */}
          <TabPanel value={tabValue} index={7}>
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
