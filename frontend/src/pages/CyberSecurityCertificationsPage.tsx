import React, { useState, useMemo, useRef, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Divider,
  alpha,
  Tooltip,
  TextField,
  InputAdornment,
  IconButton,
  ButtonGroup,
  Badge,
  Collapse,
} from "@mui/material";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import WorkspacePremiumIcon from "@mui/icons-material/WorkspacePremium";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import ScienceIcon from "@mui/icons-material/Science";
import LanguageIcon from "@mui/icons-material/Language";
import PhoneAndroidIcon from "@mui/icons-material/PhoneAndroid";
import MemoryIcon from "@mui/icons-material/Memory";
import SearchIcon from "@mui/icons-material/Search";
import LocalPoliceIcon from "@mui/icons-material/LocalPolice";
import CloudIcon from "@mui/icons-material/Cloud";
import GavelIcon from "@mui/icons-material/Gavel";
import RouterIcon from "@mui/icons-material/Router";
import StorageIcon from "@mui/icons-material/Storage";
import TerminalIcon from "@mui/icons-material/Terminal";
import BuildIcon from "@mui/icons-material/Build";
import AssessmentIcon from "@mui/icons-material/Assessment";
import PsychologyIcon from "@mui/icons-material/Psychology";
import DnsIcon from "@mui/icons-material/Dns";
import IntegrationInstructionsIcon from "@mui/icons-material/IntegrationInstructions";
import GroupsIcon from "@mui/icons-material/Groups";
import ClearIcon from "@mui/icons-material/Clear";
import UnfoldMoreIcon from "@mui/icons-material/UnfoldMore";
import UnfoldLessIcon from "@mui/icons-material/UnfoldLess";
import FilterListIcon from "@mui/icons-material/FilterList";
import SchoolIcon from "@mui/icons-material/School";
import CategoryIcon from "@mui/icons-material/Category";
import BusinessIcon from "@mui/icons-material/Business";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

type Level = "Beginner" | "Intermediate" | "Advanced";

// Career path types for linking certifications to career tracks
type CareerPathType = 
  | "red-team" 
  | "blue-team" 
  | "security-engineering" 
  | "grc" 
  | "vuln-research" 
  | "network-security"
  | "appsec"
  | "cloud-security"
  | "threat-intel"
  | "forensics"
  | "malware-analysis"
  | "iam"
  | "ot-ics"
  | "privacy"
  | "bug-bounty"
  | "data-science"
  | "tool-dev"
  | "crypto"
  | "devsecops";

const careerPathMeta: Record<CareerPathType, { label: string; color: string; description: string }> = {
  "red-team": { label: "Red Team", color: "#ef4444", description: "Offensive Security / Penetration Testing" },
  "blue-team": { label: "Blue Team", color: "#3b82f6", description: "Defensive Security / SOC / IR" },
  "security-engineering": { label: "Security Engineering", color: "#8b5cf6", description: "DevSecOps / Platform Security" },
  "grc": { label: "GRC", color: "#f59e0b", description: "Governance, Risk & Compliance" },
  "vuln-research": { label: "Vuln Research", color: "#7c3aed", description: "Vulnerability Research / Exploit Dev" },
  "network-security": { label: "Network Security", color: "#0891b2", description: "Network Security Engineering" },
  "appsec": { label: "AppSec", color: "#ec4899", description: "Application Security" },
  "cloud-security": { label: "Cloud Security", color: "#06b6d4", description: "Cloud Security Engineering" },
  "threat-intel": { label: "Threat Intel", color: "#f97316", description: "Threat Intelligence" },
  "forensics": { label: "Forensics", color: "#14b8a6", description: "Digital Forensics" },
  "malware-analysis": { label: "Malware Analysis", color: "#dc2626", description: "Malware Analysis & RE" },
  "iam": { label: "IAM", color: "#8b5cf6", description: "Identity & Access Management" },
  "ot-ics": { label: "OT/ICS", color: "#059669", description: "OT/ICS Security" },
  "privacy": { label: "Privacy", color: "#0891b2", description: "Privacy Engineering" },
  "bug-bounty": { label: "Bug Bounty", color: "#eab308", description: "Bug Bounty Hunting" },
  "data-science": { label: "Security Data Science", color: "#06b6d4", description: "ML/AI for Security" },
  "tool-dev": { label: "Tool Dev", color: "#f97316", description: "Security Tool Development" },
  "crypto": { label: "Cryptography", color: "#8b5cf6", description: "Cryptographic Engineering" },
  "devsecops": { label: "DevSecOps", color: "#6366f1", description: "DevSecOps / Pipeline Security" },
};

interface CertificationItem {
  name: string;
  provider: string;
  notes?: string;
  careerPaths?: CareerPathType[];
}

interface SubjectSection {
  title: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  tracks: Record<Level, CertificationItem[]>;
}

const levelOrder: Level[] = ["Beginner", "Intermediate", "Advanced"];

const levelMeta: Record<Level, { color: string; hint: string }> = {
  Beginner: { color: "#22c55e", hint: "Foundations and entry level exams" },
  Intermediate: { color: "#f59e0b", hint: "Role-ready depth and practical labs" },
  Advanced: { color: "#ef4444", hint: "Expert level and specialization" },
};

const providers = [
  "SANS / GIAC",
  "CompTIA",
  "QA",
  "CREST",
  "OffSec",
  "EC-Council (CEH)",
  "ISC2",
  "ISACA",
  "INE / eLearnSecurity",
  "Hack The Box",
  "TCM Security",
  "PortSwigger",
  "Microsoft",
  "AWS",
  "Google Cloud",
  "Google (Coursera)",
  "Cisco",
  "Cisco NetAcad",
  "Security Blue Team",
  "IACIS",
  "OpenText",
  "Cloud Security Alliance",
  "Magnet Forensics",
  "OWASP",
  "NowSecure Academy",
  "PECB",
  "Red Hat",
  "Linux Foundation",
  "LPI",
  "VMware",
  "VMware/Broadcom",
  "Juniper",
  "Palo Alto Networks",
  "Fortinet",
  "HashiCorp",
  "Kubernetes (CNCF)",
  "CNCF",
  "Docker",
  "Terraform",
  "Splunk",
  "Elastic",
  "ServiceNow",
  "Salesforce",
  "Oracle",
  "IBM",
  "IBM (Coursera)",
  "PMI",
  "PeopleCert/AXELOS",
  "PeopleCert/APMG",
  "APM",
  "Scaled Agile",
  "Scrum Alliance",
  "Scrum.org",
  "DevOps Institute",
  "GitLab",
  "GitHub",
  "Databricks",
  "Snowflake",
  "MongoDB",
  "CrowdStrike",
  "Picus Security",
  "HarvardX (edX)",
  "Harvard Extension",
  "University of Cape Town",
  "Oxford Saïd Business School",
  "LSE (London School of Economics)",
  "Cambridge Judge Business School",
  "Makers Academy",
  "Northcoders",
  "Le Wagon",
  "General Assembly",
  "Code Institute",
  "Code First Girls",
  "School of Code",
  "Python Institute",
  "FreeCodeCamp",
  "Meta (Coursera)",
  "Udacity",
  "DeepLearning.AI",
  "Fast.ai",
  "TensorFlow",
  "BrainStation",
  "Cambridge Spark",
  "iSAQB",
  "MIT Professional Education",
  "Imperial College London",
  "Stanford Online",
  "Unity",
  "The Open Group",
  "BCS",
];

const subjects: SubjectSection[] = [
  {
    title: "IT Fundamentals & General Technology",
    description: "Foundation certifications covering IT basics, security fundamentals, and entry-level technology skills for all career paths.",
    icon: <SecurityIcon sx={{ fontSize: 32 }} />,
    color: "#38bdf8",
    tracks: {
      Beginner: [
        { name: "CompTIA Tech+ (FC0-U71)", provider: "CompTIA", careerPaths: ["blue-team", "security-engineering"], notes: "Entry-level | No prerequisites | IT concepts, infrastructure, software dev, databases, and security basics" },
        { name: "CompTIA ITF+ (IT Fundamentals) (FC0-U61)", provider: "CompTIA", careerPaths: ["blue-team", "security-engineering"], notes: "Entry-level | No prerequisites | IT literacy, basic concepts for career exploration" },
        { name: "CompTIA A+ (Core 1: 220-1101, Core 2: 220-1102)", provider: "CompTIA", careerPaths: ["blue-team", "security-engineering"], notes: "Foundation | No prerequisites | Hardware, software, troubleshooting, operational procedures" },
        { name: "IT Essentials", provider: "Cisco NetAcad", careerPaths: ["blue-team", "security-engineering"], notes: "70 hours | CompTIA A+ aligned | PC hardware, OS, networking basics, and troubleshooting" },
        { name: "Introduction to Cybersecurity", provider: "Cisco NetAcad", careerPaths: ["blue-team", "grc"], notes: "15 hours | No prerequisites | Security fundamentals, threats, and career pathways overview" },
        { name: "Certified in Cybersecurity (CC)", provider: "ISC2", careerPaths: ["grc", "blue-team", "security-engineering"], notes: "Entry-level | No prerequisites | Core security concepts and best practices" },
        { name: "SC-900 Security Fundamentals", provider: "Microsoft", careerPaths: ["blue-team", "security-engineering", "grc"], notes: "Foundational | Microsoft security, compliance, and identity concepts" },
        { name: "SEC275 Foundations: Computers, Technology, & Security", provider: "SANS", careerPaths: ["blue-team", "security-engineering"], notes: "5 days | No prerequisites | Intro to hardware, OS, networking, and security basics" },
        { name: "SEC301 Introduction to Cyber Security", provider: "SANS", careerPaths: ["blue-team", "security-engineering", "grc"], notes: "5 days | No prerequisites | Security principles, threats, and defensive technologies overview" },
      ],
      Intermediate: [
        { name: "CompTIA Security+ (SY0-701)", provider: "CompTIA", careerPaths: ["blue-team", "red-team", "grc", "security-engineering"], notes: "Foundation | Network+ recommended | Security concepts, threats, architecture, operations, and governance" },
        { name: "Security+ Bootcamp", provider: "QA", careerPaths: ["blue-team", "red-team", "grc", "security-engineering"], notes: "UK training | Accelerated Security+ preparation" },
        { name: "GSEC", provider: "SANS / GIAC", careerPaths: ["blue-team", "security-engineering", "grc"], notes: "GIAC Security Essentials | Broad security knowledge validation" },
        { name: "SSCP", provider: "ISC2", careerPaths: ["security-engineering", "grc", "blue-team"], notes: "Systems Security Certified Practitioner | Operational security focus" },
        { name: "Cybersecurity Essentials", provider: "Cisco NetAcad", careerPaths: ["blue-team", "security-engineering"], notes: "30 hours | Intro to Cybersecurity | CIA triad, cryptography, access control, and defense" },
        { name: "SEC401 Security Essentials – Network, Endpoint, and Cloud (GSEC)", provider: "SANS", careerPaths: ["blue-team", "security-engineering", "network-security"], notes: "6 days | GSEC certification | Defense in depth, network security, cryptography, incident handling" },
        { name: "LDR414 SANS Training Program for the CISSP Certification (GISP)", provider: "SANS", careerPaths: ["grc", "security-engineering"], notes: "6 days | GISP certification | All 8 CISSP domains with exam preparation focus" },
      ],
      Advanced: [
        { name: "CISSP", provider: "ISC2", careerPaths: ["grc", "security-engineering", "blue-team", "red-team"], notes: "Gold standard | 5 years experience | 8 security domains" },
        { name: "CISM", provider: "ISACA", careerPaths: ["grc", "security-engineering"], notes: "Management focused | Security program management" },
        { name: "CompTIA SecurityX (CAS-005, formerly CASP+)", provider: "CompTIA", careerPaths: ["security-engineering", "grc", "cloud-security"], notes: "Expert | 10+ years experience | Risk management, enterprise security architecture, operations, and governance" },
        { name: "GSLC (Security Leadership)", provider: "SANS / GIAC", careerPaths: ["grc", "security-engineering"], notes: "Security leadership and management" },
      ],
    },
  },
  {
    title: "Networking & Infrastructure",
    description: "Network engineering, routing, switching, virtualization, and infrastructure certifications from Cisco, Juniper, VMware, and other vendors.",
    icon: <RouterIcon sx={{ fontSize: 32 }} />,
    color: "#0ea5e9",
    tracks: {
      Beginner: [
        { name: "CompTIA Network+ (N10-009)", provider: "CompTIA", careerPaths: ["network-security", "blue-team", "security-engineering"], notes: "Foundation | A+ recommended | Network architecture, operations, security, and troubleshooting" },
        { name: "CCNA", provider: "Cisco", careerPaths: ["network-security", "security-engineering"], notes: "Industry gold standard | 200-301 exam | Networking fundamentals and Cisco technologies" },
        { name: "CCNA: Introduction to Networks", provider: "Cisco NetAcad", careerPaths: ["network-security", "security-engineering"], notes: "70 hours | CCNA Part 1 | IPv4/IPv6, Ethernet, and routing fundamentals" },
        { name: "CCNA: Switching, Routing, and Wireless Essentials", provider: "Cisco NetAcad", careerPaths: ["network-security", "security-engineering"], notes: "70 hours | CCNA Part 2 | VLANs, inter-VLAN routing, STP, and wireless" },
        { name: "JNCIA-Junos", provider: "Juniper", careerPaths: ["network-security"], notes: "Entry-level | Junos OS fundamentals and CLI navigation" },
        { name: "NSE1-3 Associate", provider: "Fortinet", careerPaths: ["network-security"], notes: "Free | Fortinet fundamentals and network security basics" },
        { name: "VMware Certified Technical Associate (VCTA)", provider: "VMware", careerPaths: ["security-engineering", "cloud-security"], notes: "Entry-level | Virtualization concepts and vSphere basics" },
        { name: "CompTIA Server+ (SK0-005)", provider: "CompTIA", careerPaths: ["blue-team", "security-engineering", "cloud-security"], notes: "Intermediate | Server hardware, software, storage, and security" },
        { name: "Aruba Certified Networking Associate", provider: "HPE Aruba", careerPaths: ["network-security"], notes: "HPE/Aruba networking | Wireless and switching fundamentals" },
        { name: "MikroTik MTCNA", provider: "MikroTik", careerPaths: ["network-security"], notes: "MikroTik RouterOS | Network administration fundamentals" },
      ],
      Intermediate: [
        { name: "CCNP Enterprise", provider: "Cisco", careerPaths: ["network-security", "security-engineering"], notes: "Professional | ENCOR + concentration | Enterprise networking mastery" },
        { name: "CCNP Enterprise: Core Networking (ENCOR)", provider: "Cisco NetAcad", careerPaths: ["network-security", "security-engineering"], notes: "140 hours | CCNA required | Advanced routing, wireless, SD-WAN, and security" },
        { name: "CCNP Security", provider: "Cisco", careerPaths: ["network-security", "security-engineering"], notes: "Professional | SCOR + concentration | Cisco security solutions" },
        { name: "JNCIS-ENT", provider: "Juniper", careerPaths: ["network-security"], notes: "Professional | Enterprise routing, switching, and protocols" },
        { name: "NSE4 Network Security Professional", provider: "Fortinet", careerPaths: ["network-security", "security-engineering"], notes: "FortiGate administration | Firewall policies and VPN" },
        { name: "VCP-DCV (Data Center Virtualization)", provider: "VMware", careerPaths: ["security-engineering", "cloud-security"], notes: "Professional | vSphere 8 administration and management" },
        { name: "VCP-NV (Network Virtualization)", provider: "VMware", careerPaths: ["network-security", "cloud-security"], notes: "Professional | NSX network virtualization and microsegmentation" },
        { name: "PCNSA", provider: "Palo Alto Networks", careerPaths: ["network-security", "security-engineering"], notes: "Administrator | Palo Alto firewall configuration and policies" },
        { name: "F5 Certified Administrator", provider: "F5 Networks", careerPaths: ["network-security", "appsec"], notes: "BIG-IP | Load balancing, WAF, and application delivery" },
        { name: "Nutanix Certified Professional", provider: "Nutanix", careerPaths: ["cloud-security", "security-engineering"], notes: "HCI | Hyperconverged infrastructure administration" },
      ],
      Advanced: [
        { name: "CCIE Enterprise Infrastructure", provider: "Cisco", careerPaths: ["network-security", "security-engineering"], notes: "Expert | 8-hour lab exam | Complex enterprise network design and troubleshooting" },
        { name: "CCIE Security", provider: "Cisco", careerPaths: ["network-security", "security-engineering"], notes: "Expert | 8-hour lab | Comprehensive security architecture mastery" },
        { name: "CCIE Data Center", provider: "Cisco", careerPaths: ["network-security", "cloud-security"], notes: "Expert | 8-hour lab | Data center technologies and ACI" },
        { name: "CCDE (Cisco Certified Design Expert)", provider: "Cisco", careerPaths: ["network-security", "security-engineering"], notes: "Expert | Infrastructure design and architecture" },
        { name: "JNCIE-ENT", provider: "Juniper", careerPaths: ["network-security"], notes: "Expert | 8-hour lab | Juniper enterprise networking mastery" },
        { name: "PCNSE", provider: "Palo Alto Networks", careerPaths: ["network-security", "security-engineering"], notes: "Expert | Design, deploy, and troubleshoot Palo Alto solutions" },
        { name: "NSE8 Network Security Expert", provider: "Fortinet", careerPaths: ["network-security", "security-engineering"], notes: "Expert | Fortinet Security Fabric architecture" },
        { name: "VCAP-DCV (Advanced Professional)", provider: "VMware", careerPaths: ["security-engineering", "cloud-security"], notes: "Advanced | vSphere design and deployment expertise" },
        { name: "VCDX (VMware Certified Design Expert)", provider: "VMware", careerPaths: ["security-engineering", "cloud-security"], notes: "Highest VMware cert | Design defense before expert panel" },
      ],
    },
  },
  {
    title: "System Administration",
    description: "Windows Server, Linux administration, Active Directory, and enterprise system management certifications.",
    icon: <TerminalIcon sx={{ fontSize: 32 }} />,
    color: "#0078d4",
    tracks: {
      Beginner: [
        { name: "CompTIA Linux+ (XK0-005)", provider: "CompTIA", careerPaths: ["blue-team", "red-team", "security-engineering"], notes: "Vendor-neutral | Linux administration, security, scripting, and troubleshooting" },
        { name: "Linux Essentials", provider: "LPI", careerPaths: ["security-engineering"], notes: "Entry-level | Linux fundamentals and open source concepts" },
        { name: "LPIC-1", provider: "LPI", careerPaths: ["security-engineering", "devsecops"], notes: "Professional | Two exams | Linux system administration essentials" },
        { name: "LFCS (Linux Foundation Certified Sysadmin)", provider: "Linux Foundation", careerPaths: ["security-engineering", "devsecops"], notes: "Hands-on exam | Real-world Linux administration skills" },
        { name: "Red Hat Certified System Administrator (RHCSA)", provider: "Red Hat", careerPaths: ["security-engineering", "devsecops"], notes: "Industry standard | Hands-on | RHEL system administration" },
        { name: "MS-900 Microsoft 365 Fundamentals", provider: "Microsoft", careerPaths: ["security-engineering"], notes: "Entry-level | Microsoft 365 services and cloud concepts" },
        { name: "SEC406 Linux Security for InfoSec Professionals", provider: "SANS", careerPaths: ["blue-team", "red-team", "security-engineering"], notes: "5 days | Linux hardening, auditing, and security tools" },
      ],
      Intermediate: [
        { name: "AZ-800/801 Windows Server Hybrid Admin", provider: "Microsoft", careerPaths: ["security-engineering"], notes: "Two exams | Windows Server 2022 administration and hybrid environments" },
        { name: "MD-102 Endpoint Administrator", provider: "Microsoft", careerPaths: ["blue-team", "security-engineering"], notes: "Intune | Endpoint management, security, and deployment" },
        { name: "MS-102 Microsoft 365 Administrator", provider: "Microsoft", careerPaths: ["security-engineering"], notes: "Expert | M365 tenant management and security configuration" },
        { name: "LPIC-2", provider: "LPI", careerPaths: ["security-engineering", "devsecops"], notes: "Advanced | Two exams | Linux networking, security, and kernel" },
        { name: "Red Hat Certified Engineer (RHCE)", provider: "Red Hat", careerPaths: ["security-engineering", "devsecops"], notes: "Advanced | Ansible automation and RHEL administration" },
        { name: "LFCE (Linux Foundation Certified Engineer)", provider: "Linux Foundation", careerPaths: ["security-engineering", "devsecops"], notes: "Advanced | Hands-on | Enterprise Linux engineering" },
        { name: "Ubuntu Certified Professional", provider: "Canonical", careerPaths: ["security-engineering"], notes: "Ubuntu/Debian | Administration and deployment" },
        { name: "SUSE Certified Administrator", provider: "SUSE", careerPaths: ["security-engineering"], notes: "SLES | Enterprise Linux administration" },
        { name: "SEC505 Securing Windows and PowerShell Automation (GCWN)", provider: "SANS", careerPaths: ["blue-team", "security-engineering"], notes: "6 days | GCWN cert | AD security, GPO hardening, and PowerShell" },
      ],
      Advanced: [
        { name: "AZ-305 Azure Solutions Architect", provider: "Microsoft", careerPaths: ["cloud-security", "security-engineering"], notes: "Expert | Azure architecture design and best practices" },
        { name: "AZ-500 Azure Security Engineer", provider: "Microsoft", careerPaths: ["cloud-security", "security-engineering"], notes: "Security | Identity, platform protection, and security operations" },
        { name: "AZ-700 Network Engineer Associate", provider: "Microsoft", careerPaths: ["network-security", "cloud-security"], notes: "Networking | Azure networking design and implementation" },
        { name: "LPIC-3 (Security, Virtualization, Mixed Env)", provider: "LPI", careerPaths: ["security-engineering", "devsecops", "cloud-security"], notes: "Expert | Specialization tracks | Linux enterprise expertise" },
        { name: "Red Hat Certified Architect (RHCA)", provider: "Red Hat", careerPaths: ["security-engineering", "cloud-security"], notes: "Highest Red Hat cert | 5+ specialist credentials required" },
        { name: "Red Hat Certified Specialist in Security", provider: "Red Hat", careerPaths: ["security-engineering", "red-team"], notes: "Specialist | Linux security hardening and compliance" },
        { name: "Red Hat Certified Specialist in Ansible", provider: "Red Hat", careerPaths: ["devsecops", "security-engineering"], notes: "Specialist | Ansible automation and playbook development" },
      ],
    },
  },
  {
    title: "Cloud Computing & DevOps",
    description: "AWS, Azure, Google Cloud, Kubernetes, containers, CI/CD, infrastructure as code, and cloud security certifications.",
    icon: <CloudIcon sx={{ fontSize: 32 }} />,
    color: "#ff9900",
    tracks: {
      Beginner: [
        { name: "AWS Cloud Practitioner", provider: "AWS", careerPaths: ["cloud-security", "security-engineering"], notes: "Entry-level | AWS services, pricing, architecture, and support plans" },
        { name: "AZ-900 Azure Fundamentals", provider: "Microsoft", careerPaths: ["cloud-security", "security-engineering"], notes: "Entry-level | Azure services, pricing, SLAs, and cloud concepts" },
        { name: "DP-900 Data Fundamentals", provider: "Microsoft", careerPaths: ["cloud-security"], notes: "Entry-level | Azure data services, relational/non-relational data" },
        { name: "AI-900 AI Fundamentals", provider: "Microsoft", careerPaths: ["cloud-security"], notes: "Entry-level | Azure AI services and machine learning concepts" },
        { name: "Google Cloud Digital Leader", provider: "Google Cloud", careerPaths: ["cloud-security"], notes: "Entry-level | GCP products, digital transformation, and business value" },
        { name: "Associate Cloud Engineer", provider: "Google Cloud", careerPaths: ["cloud-security", "security-engineering"], notes: "Hands-on | GCP console, CLI, and cloud resource management" },
        { name: "DevOps Fundamentals", provider: "DevOps Institute", careerPaths: ["devsecops", "security-engineering"], notes: "Foundation | DevOps culture, practices, and continuous delivery" },
        { name: "Docker Certified Associate", provider: "Docker", careerPaths: ["devsecops", "cloud-security"], notes: "Practical | Container orchestration, networking, and security" },
        { name: "GitLab Certified Associate", provider: "GitLab", careerPaths: ["devsecops", "appsec"], notes: "Entry-level | GitLab CI/CD pipelines and DevSecOps workflows" },
        { name: "Terraform Associate", provider: "HashiCorp", careerPaths: ["devsecops", "cloud-security"], notes: "IaC | Terraform workflow, state management, and modules" },
        { name: "CCSK", provider: "Cloud Security Alliance", careerPaths: ["cloud-security", "grc"], notes: "Industry standard | Cloud security fundamentals and best practices" },
        { name: "SEC388 Introduction to Cloud Computing and Security", provider: "SANS", careerPaths: ["cloud-security", "security-engineering"], notes: "3 days | AWS/Azure/GCP fundamentals and security concepts" },
      ],
      Intermediate: [
        { name: "AWS Solutions Architect Associate", provider: "AWS", careerPaths: ["cloud-security", "security-engineering"], notes: "Professional | Designing resilient, high-performing AWS architectures" },
        { name: "AWS Developer Associate", provider: "AWS", careerPaths: ["appsec", "devsecops"], notes: "Professional | AWS SDK, Lambda, and application development" },
        { name: "AWS SysOps Administrator Associate", provider: "AWS", careerPaths: ["cloud-security", "security-engineering"], notes: "Professional | AWS operations, monitoring, and troubleshooting" },
        { name: "AZ-104 Azure Administrator", provider: "Microsoft", careerPaths: ["cloud-security", "security-engineering"], notes: "Professional | Azure resource management and administration" },
        { name: "AZ-204 Azure Developer", provider: "Microsoft", careerPaths: ["appsec", "devsecops"], notes: "Professional | Azure PaaS services and application development" },
        { name: "AZ-500 Security Engineer", provider: "Microsoft", careerPaths: ["cloud-security", "security-engineering", "blue-team"], notes: "Security | Identity, network security, and threat protection in Azure" },
        { name: "Professional Cloud Architect", provider: "Google Cloud", careerPaths: ["cloud-security", "security-engineering"], notes: "Professional | GCP solution design and architecture best practices" },
        { name: "Professional Cloud Security Engineer", provider: "Google Cloud", careerPaths: ["cloud-security", "security-engineering", "blue-team"], notes: "Security | GCP security controls, compliance, and threat management" },
        { name: "CKA (Certified Kubernetes Administrator)", provider: "CNCF", careerPaths: ["devsecops", "cloud-security", "security-engineering"], notes: "Hands-on | K8s cluster management, networking, and troubleshooting" },
        { name: "CKAD (Kubernetes Application Developer)", provider: "CNCF", careerPaths: ["devsecops", "appsec"], notes: "Hands-on | K8s application design, deployment, and configuration" },
        { name: "AZ-400 DevOps Engineer Expert", provider: "Microsoft", careerPaths: ["devsecops", "cloud-security"], notes: "Expert | Azure DevOps pipelines, IaC, and continuous delivery" },
        { name: "Vault Associate", provider: "HashiCorp", careerPaths: ["devsecops", "security-engineering"], notes: "Security | Secrets management, encryption, and access control" },
        { name: "SEC510 Public Cloud Security: AWS, Azure, and GCP (GPCS)", provider: "SANS", careerPaths: ["cloud-security", "security-engineering"], notes: "6 days | GPCS cert | Multi-cloud security architecture and controls" },
        { name: "SEC540 Cloud Security and DevSecOps Automation (GCSA)", provider: "SANS", careerPaths: ["devsecops", "cloud-security"], notes: "5 days | GCSA cert | CI/CD security, IaC scanning, and automation" },
        { name: "Prisma Certified Cloud Security Engineer", provider: "Palo Alto Networks", careerPaths: ["cloud-security", "network-security"], notes: "Vendor | Cloud security posture management and workload protection" },
      ],
      Advanced: [
        { name: "AWS Solutions Architect Professional", provider: "AWS", careerPaths: ["cloud-security", "security-engineering"], notes: "Expert | Complex multi-tier AWS architectures and migrations" },
        { name: "AWS DevOps Engineer Professional", provider: "AWS", careerPaths: ["devsecops", "cloud-security"], notes: "Expert | CI/CD, automation, and AWS DevOps best practices" },
        { name: "AWS Security Specialty", provider: "AWS", careerPaths: ["cloud-security", "security-engineering", "blue-team"], notes: "Specialist | AWS security controls, encryption, and incident response" },
        { name: "AZ-305 Solutions Architect Expert", provider: "Microsoft", careerPaths: ["cloud-security", "security-engineering"], notes: "Expert | Azure solution design and architecture best practices" },
        { name: "SC-100 Cybersecurity Architect", provider: "Microsoft", careerPaths: ["security-engineering", "cloud-security"], notes: "Expert | Zero Trust, security strategy, and enterprise architecture" },
        { name: "Professional Cloud DevOps Engineer", provider: "Google Cloud", careerPaths: ["devsecops", "cloud-security"], notes: "Expert | GCP CI/CD, SRE practices, and service reliability" },
        { name: "Professional Machine Learning Engineer", provider: "Google Cloud", careerPaths: ["cloud-security"], notes: "Specialist | ML model deployment, Vertex AI, and MLOps" },
        { name: "CKS (Certified Kubernetes Security)", provider: "CNCF", careerPaths: ["devsecops", "cloud-security", "security-engineering"], notes: "Security | K8s cluster hardening, runtime security, and supply chain" },
        { name: "CCSP", provider: "ISC2", careerPaths: ["cloud-security", "grc", "security-engineering"], notes: "Expert | Cloud security architecture, design, and operations" },
        { name: "SEC549 Enterprise Cloud Security Architecture", provider: "SANS", careerPaths: ["cloud-security", "security-engineering"], notes: "4 days | Multi-cloud security architecture and governance" },
        { name: "GPCS", provider: "SANS / GIAC", careerPaths: ["cloud-security"], notes: "SEC510 cert | Public cloud security across AWS, Azure, and GCP" },
        { name: "Site Reliability Engineering Foundation", provider: "DevOps Institute", careerPaths: ["devsecops", "security-engineering"], notes: "Foundation | SRE principles, SLOs/SLIs, and reliability engineering" },
      ],
    },
  },
  {
    title: "Offensive Security & Penetration Testing",
    description: "Red team, penetration testing, ethical hacking, and adversary simulation certifications from OffSec, CREST, SANS, and industry leaders.",
    icon: <BugReportIcon sx={{ fontSize: 32 }} />,
    color: "#ef4444",
    tracks: {
      Beginner: [
        { name: "CompTIA PenTest+ (PT0-003)", provider: "CompTIA", careerPaths: ["red-team", "appsec", "bug-bounty"], notes: "Security+ & Network+ recommended | Penetration testing methodology and vulnerability assessment" },
        { name: "eJPT", provider: "INE / eLearnSecurity", careerPaths: ["red-team", "appsec"], notes: "Entry-level | 72-hour practical exam | Network pentesting fundamentals" },
        { name: "PJPT", provider: "TCM Security", careerPaths: ["red-team", "bug-bounty"], notes: "Practical cert | Internal network pentesting and AD basics" },
        { name: "CEH (Certified Ethical Hacker)", provider: "EC-Council", careerPaths: ["red-team", "bug-bounty"], notes: "Industry recognized | Ethical hacking methodology and tools" },
        { name: "HTB Certified Penetration Testing Specialist", provider: "Hack The Box", careerPaths: ["red-team", "appsec"], notes: "Hands-on | Real-world lab scenarios and practical skills" },
        { name: "CREST Practitioner Security Analyst (CPSA)", provider: "CREST", careerPaths: ["red-team", "appsec"], notes: "UK standard | Entry-level | Foundation for CRT certification" },
        { name: "Ethical Hacker", provider: "Cisco NetAcad", careerPaths: ["red-team", "appsec"], notes: "40 hours | Pentesting fundamentals and security assessment" },
        { name: "SEC-100: CyberCore - Security Essentials", provider: "OffSec", careerPaths: ["blue-team", "security-engineering"], notes: "Entry level | Core security concepts and Linux fundamentals" },
        { name: "PEN-103: Kali Linux Revealed (KLCP)", provider: "OffSec", careerPaths: ["red-team", "security-engineering"], notes: "KLCP certification | Kali Linux administration and customization" },
        { name: "PEN-100: Network Penetration Testing Essentials", provider: "OffSec", careerPaths: ["red-team", "network-security"], notes: "Entry pentest | Network attacks, enumeration, and exploitation basics" },
        { name: "SEC467 Social Engineering for Security Professionals", provider: "SANS", careerPaths: ["red-team", "security-engineering"], notes: "2 days | Phishing, pretexting, vishing, and influence tactics" },
      ],
      Intermediate: [
        { name: "OSCP (PEN-200)", provider: "OffSec", careerPaths: ["red-team", "vuln-research", "bug-bounty", "appsec"], notes: "Industry gold standard | 24-hour hands-on exam | AD attacks included" },
        { name: "CPTS", provider: "Hack The Box", careerPaths: ["red-team", "appsec"], notes: "Professional pentesting | Practical skills with real-world scenarios" },
        { name: "eCPPT", provider: "INE / eLearnSecurity", careerPaths: ["red-team"], notes: "Professional | 14-day practical exam | Network and web pentesting" },
        { name: "PNPT", provider: "TCM Security", careerPaths: ["red-team"], notes: "Practical | 5-day exam | Network pentesting and AD exploitation" },
        { name: "CREST Registered Penetration Tester (CRT)", provider: "CREST", careerPaths: ["red-team"], notes: "UK industry standard | CPSA required | Infrastructure and web testing" },
        { name: "CREST Certified Red Team Specialist (CCRTS)", provider: "CREST", careerPaths: ["red-team"], notes: "Specialist | Adversary simulation and red team operations" },
        { name: "GRTP", provider: "SANS / GIAC", careerPaths: ["red-team"], notes: "SEC565 cert | Red team operations and adversary emulation" },
        { name: "CRTA (Certified Red Team Analyst)", provider: "CyberWarFare Labs", careerPaths: ["red-team"], notes: "Red team tradecraft | C2 frameworks and operational security" },
        { name: "CRTO", provider: "Zero-Point Security", careerPaths: ["red-team"], notes: "Red team operator | Cobalt Strike mastery and evasion techniques" },
        { name: "PEN-210: Foundational Wireless Network Attacks (OSWP)", provider: "OffSec", careerPaths: ["red-team", "network-security"], notes: "OSWP certification | WiFi attacks, WPA/WPA2, and wireless security" },
        { name: "SEC560 Enterprise Penetration Testing (GPEN)", provider: "SANS", careerPaths: ["red-team", "appsec"], notes: "6 days | GPEN certification | Enterprise pentest methodology" },
        { name: "SEC565 Red Team Operations and Adversary Emulation (GRTP)", provider: "SANS", careerPaths: ["red-team"], notes: "6 days | GRTP certification | APT emulation and C2 frameworks" },
        { name: "SEC580 Metasploit for Enterprise Penetration Testing", provider: "SANS", careerPaths: ["red-team"], notes: "6 days | Advanced Metasploit, custom modules, and automation" },
        { name: "SEC588 Cloud Penetration Testing (GCPN)", provider: "SANS", careerPaths: ["red-team", "cloud-security"], notes: "6 days | GCPN certification | AWS/Azure/GCP pentesting" },
        { name: "SEC617 Wireless Penetration Testing and Ethical Hacking (GAWN)", provider: "SANS", careerPaths: ["red-team", "network-security"], notes: "6 days | GAWN certification | WiFi, Bluetooth, and IoT attacks" },
      ],
      Advanced: [
        { name: "OSEP (PEN-300)", provider: "OffSec", careerPaths: ["red-team", "vuln-research"], notes: "Expert | AV evasion, process injection, and advanced AD attacks" },
        { name: "OSCE3", provider: "OffSec", careerPaths: ["red-team", "vuln-research"], notes: "Elite certification bundle | OSEP + OSWE + OSED combined" },
        { name: "GPEN", provider: "SANS / GIAC", careerPaths: ["red-team"], notes: "SEC560 cert | Enterprise penetration testing and methodology" },
        { name: "GXPN", provider: "SANS / GIAC", careerPaths: ["red-team", "vuln-research"], notes: "SEC660 cert | Expert pentester and exploit development" },
        { name: "CREST Certified Infrastructure Tester (CCT INF)", provider: "CREST", careerPaths: ["red-team", "network-security"], notes: "Expert | CRT required | Infrastructure pentesting mastery" },
        { name: "CREST Certified Web Application Tester (CCT APP)", provider: "CREST", careerPaths: ["red-team", "appsec"], notes: "Expert | CRT required | Web application pentesting mastery" },
        { name: "CREST Certified Simulated Attack Specialist (CCSAS)", provider: "CREST", careerPaths: ["red-team"], notes: "Expert | Advanced adversary simulation and threat emulation" },
        { name: "CREST Certified Simulated Attack Manager (CCSAM)", provider: "CREST", careerPaths: ["red-team", "grc"], notes: "Leadership | Red team engagement management and strategy" },
        { name: "CREST Certified Red Team Manager (CCRTM)", provider: "CREST", careerPaths: ["red-team", "grc"], notes: "Leadership | Managing red team programs and operations" },
        { name: "CRTP", provider: "Pentester Academy", careerPaths: ["red-team"], notes: "Red team professional | Active Directory attacks and persistence" },
        { name: "CRTE (Certified Red Team Expert)", provider: "Pentester Academy", careerPaths: ["red-team"], notes: "Expert | Advanced AD exploitation, forest attacks, and trusts" },
        { name: "CRTL (Certified Red Team Lead)", provider: "Zero-Point Security", careerPaths: ["red-team"], notes: "Leadership | Red team program development and management" },
        { name: "SEC660 Advanced Penetration Testing, Exploit Writing, and Ethical Hacking (GXPN)", provider: "SANS", careerPaths: ["red-team", "vuln-research"], notes: "6 days | GXPN certification | Exploit development and advanced attacks" },
        { name: "SEC599 Defeating Advanced Adversaries – Purple Team Tactics & Kill Chain Defences", provider: "SANS", careerPaths: ["red-team", "blue-team"], notes: "6 days | Purple team exercises and MITRE ATT&CK alignment" },
      ],
    },
  },
  {
    title: "Application & Web Security",
    description: "Web application testing, API security, mobile pentesting, bug bounty, and application security certifications.",
    icon: <LanguageIcon sx={{ fontSize: 32 }} />,
    color: "#22c55e",
    tracks: {
      Beginner: [
        { name: "Web Security Academy", provider: "PortSwigger", careerPaths: ["appsec", "bug-bounty", "red-team"], notes: "Free | 200+ labs | OWASP Top 10, SQLi, XSS, CSRF, and modern web attacks" },
        { name: "OWASP Juice Shop and WebGoat", provider: "OWASP", careerPaths: ["appsec", "bug-bounty"], notes: "Free | Intentionally vulnerable apps for hands-on learning" },
        { name: "Bug Bounty Hunter", provider: "HackerOne", careerPaths: ["bug-bounty", "appsec"], notes: "Free | Platform introduction, reporting, and methodology basics" },
        { name: "Bugcrowd University", provider: "Bugcrowd", careerPaths: ["bug-bounty"], notes: "Free | Video courses on recon, web testing, and bug hunting" },
        { name: "OWASP MSTG / MASVS", provider: "OWASP", careerPaths: ["appsec", "red-team"], notes: "Industry standard | Mobile security testing guide and verification" },
        { name: "Mobile Security Foundations", provider: "NowSecure Academy", careerPaths: ["appsec"], notes: "Free tier | iOS/Android security fundamentals and testing basics" },
        { name: "WEB-100: Web Application Assessment Essentials", provider: "OffSec", careerPaths: ["appsec", "bug-bounty"], notes: "Foundation | OWASP fundamentals and common web vulnerabilities" },
        { name: "SJD-100: Secure Java Development Essentials", provider: "OffSec", careerPaths: ["appsec", "devsecops"], notes: "Developer-focused | Secure coding practices for Java applications" },
      ],
      Intermediate: [
        { name: "GWAPT", provider: "SANS / GIAC", careerPaths: ["appsec", "red-team"], notes: "SEC542 cert | Web app pentesting methodology and advanced techniques" },
        { name: "CBBH", provider: "Hack The Box", careerPaths: ["bug-bounty", "appsec"], notes: "Certified Bug Bounty Hunter | Practical vulnerability hunting" },
        { name: "eWPT", provider: "INE / eLearnSecurity", careerPaths: ["appsec", "bug-bounty"], notes: "Practical cert | 14-day hands-on exam | Web app pentesting" },
        { name: "OSWA (WEB-200)", provider: "OffSec", careerPaths: ["appsec", "bug-bounty", "red-team"], notes: "Web assessor | SQLi, XSS, SSRF, and authentication attacks" },
        { name: "eMAPT", provider: "INE / eLearnSecurity", careerPaths: ["appsec", "red-team"], notes: "Practical cert | iOS/Android pentesting and mobile security" },
        { name: "API Security Architect", provider: "APIsec", careerPaths: ["appsec", "security-engineering"], notes: "Design focus | API security architecture and best practices" },
        { name: "APISEC Certified Professional", provider: "APIsec University", careerPaths: ["appsec"], notes: "Testing focus | API security testing methodology and tools" },
        { name: "Android Security Internals", provider: "Pentester Academy", careerPaths: ["appsec", "vuln-research"], notes: "Deep dive | Android architecture, app security, and exploitation" },
        { name: "SEC522 Application Security: Securing Web Apps, APIs, and Microservices (GWEB)", provider: "SANS", careerPaths: ["appsec", "devsecops"], notes: "6 days | GWEB certification | Secure SDLC and OWASP Top 10" },
        { name: "SEC542 Web App Penetration Testing and Ethical Hacking (GWAPT)", provider: "SANS", careerPaths: ["appsec", "red-team", "bug-bounty"], notes: "6 days | GWAPT certification | Comprehensive web app testing" },
        { name: "SEC575 iOS and Android Application Security Analysis and Penetration Testing (GMOB)", provider: "SANS", careerPaths: ["appsec", "red-team"], notes: "6 days | GMOB certification | Mobile app analysis and testing" },
        { name: "SEC554 Blockchain and Smart Contract Security", provider: "SANS", careerPaths: ["appsec", "vuln-research"], notes: "5 days | Solidity security, DeFi attacks, and smart contract auditing" },
      ],
      Advanced: [
        { name: "OSWE (WEB-300)", provider: "OffSec", careerPaths: ["appsec", "bug-bounty", "vuln-research"], notes: "Expert | Source code review, auth bypass, and deserialization attacks" },
        { name: "Burp Suite Certified Practitioner (BSCP)", provider: "PortSwigger", careerPaths: ["appsec", "bug-bounty"], notes: "Official cert | 4-hour practical | Advanced Burp Suite mastery" },
        { name: "eWPTX", provider: "INE / eLearnSecurity", careerPaths: ["appsec"], notes: "Expert | Advanced web app exploitation and custom payloads" },
        { name: "GWEB", provider: "SANS / GIAC", careerPaths: ["appsec"], notes: "SEC522 cert | Web application security and secure development" },
        { name: "GMOB", provider: "SANS / GIAC", careerPaths: ["appsec"], notes: "SEC575 cert | Mobile application security and analysis" },
        { name: "CDSA", provider: "Hack The Box", careerPaths: ["appsec", "blue-team"], notes: "Defensive | Application security from the defender's perspective" },
        { name: "Real World Bug Bounty", provider: "PentesterLab", careerPaths: ["bug-bounty"], notes: "Advanced | Complex vulnerability chains and real-world scenarios" },
        { name: "Advanced Mobile Security", provider: "NowSecure Academy", careerPaths: ["appsec", "vuln-research"], notes: "Expert | Binary analysis, runtime manipulation, and advanced attacks" },
        { name: "iOS App Pentesting", provider: "TCM Security", careerPaths: ["appsec", "red-team"], notes: "Practical | iOS-specific testing, jailbreak techniques, and analysis" },
        { name: "SEC547 Defending Product Supply Chains", provider: "SANS", careerPaths: ["appsec", "devsecops", "security-engineering"], notes: "3 days | SBOM analysis, dependency security, and supply chain defense" },
        { name: "SEC568 Combating Supply Chain Attacks with Product Security Testing", provider: "SANS", careerPaths: ["appsec", "devsecops"], notes: "4 days | Supply chain attack detection and product security" },
      ],
    },
  },
  {
    title: "Vulnerability Research & Exploit Development",
    description: "Binary exploitation, exploit development, vulnerability research, and security research certifications.",
    icon: <ScienceIcon sx={{ fontSize: 32 }} />,
    color: "#f97316",
    tracks: {
      Beginner: [
        { name: "x86/x64 Intro", provider: "OpenSecurityTraining", careerPaths: ["vuln-research", "malware-analysis"], notes: "Free | 40+ hours | x86/x64 assembly fundamentals, CPU architecture, and debugging basics" },
        { name: "Binary Exploitation Fundamentals", provider: "pwn.college", careerPaths: ["vuln-research"], notes: "Free | CTF-style progressive challenges | Buffer overflows, shellcode, and memory corruption basics" },
        { name: "Corelan Exploit Writing Tutorial", provider: "Corelan", careerPaths: ["vuln-research"], notes: "Free online series | Classic Windows exploit development, stack overflows, and SEH exploitation" },
      ],
      Intermediate: [
        { name: "OSED (EXP-301)", provider: "OffSec", careerPaths: ["vuln-research", "red-team"], notes: "Expert | 48-hour exam | Buffer overflows, DEP/ASLR bypass, ROP chains, egghunters, and custom shellcoding" },
        { name: "Binary Exploitation track", provider: "pwn.college", careerPaths: ["vuln-research"], notes: "Advanced | Complex CTF challenges | Format strings, heap exploitation, and modern mitigation bypasses" },
        { name: "Corelan Advanced", provider: "Corelan", careerPaths: ["vuln-research"], notes: "In-person training | Advanced Windows exploitation, heap spraying, and browser exploit techniques" },
        { name: "Heap Exploitation", provider: "Azeria Labs", careerPaths: ["vuln-research"], notes: "Free | Heap-based vulnerabilities, glibc internals, tcache, fastbin, and use-after-free exploitation" },
        { name: "Windows Kernel Exploitation", provider: "Offensive Security Research", careerPaths: ["vuln-research"], notes: "Advanced | Kernel-level attacks, pool overflow, driver vulnerabilities, and privilege escalation" },
      ],
      Advanced: [
        { name: "OSEE (EXP-401)", provider: "OffSec", careerPaths: ["vuln-research"], notes: "Elite | 72-hour exam | Kernel exploits, driver vulnerabilities, advanced heap techniques, and sandbox escapes" },
        { name: "SEC760 Advanced Exploit Development for Penetration Testers", provider: "SANS", careerPaths: ["vuln-research"], notes: "6 days | Cutting-edge exploitation, modern mitigation bypass, kernel exploits, and 0-day development" },
        { name: "Advanced Pwn track", provider: "pwn.college", careerPaths: ["vuln-research"], notes: "Elite | Advanced kernel exploitation, race conditions, and complex vulnerability chains" },
        { name: "Azeria Labs ARM Exploitation", provider: "Azeria Labs", careerPaths: ["vuln-research"], notes: "Free | ARM architecture exploitation, mobile/IoT targets, and ARM-specific techniques" },
        { name: "Browser Exploitation", provider: "Zero Day Initiative", careerPaths: ["vuln-research"], notes: "Expert | V8/SpiderMonkey internals, JIT bugs, renderer exploitation, and sandbox escapes" },
        { name: "Hypervisor Exploitation", provider: "Offensive Security Research", careerPaths: ["vuln-research"], notes: "Expert | VM escape techniques, hypervisor internals, and virtualization security research" },
      ],
    },
  },
  {
    title: "Reverse Engineering and Malware Analysis",
    description: "Static and dynamic analysis paths for reverse engineering and malware triage.",
    icon: <MemoryIcon sx={{ fontSize: 32 }} />,
    color: "#8b5cf6",
    tracks: {
      Beginner: [
        { name: "eCRE", provider: "INE / eLearnSecurity", careerPaths: ["malware-analysis", "vuln-research"], notes: "Entry-level | Reverse engineering fundamentals, x86 assembly, and static analysis basics" },
        { name: "Practical Malware Analysis and Triage (PMAT)", provider: "TCM Security", careerPaths: ["malware-analysis", "blue-team"], notes: "Hands-on | Malware triage workflow, basic static/dynamic analysis, and safe lab setup" },
        { name: "Intro to Reverse Engineering", provider: "OpenSecurityTraining", careerPaths: ["malware-analysis", "vuln-research"], notes: "Free | x86 assembly foundations, debugging basics, and binary analysis concepts" },
        { name: "Malware Traffic Analysis", provider: "malware-traffic-analysis.net", careerPaths: ["malware-analysis", "blue-team"], notes: "Free exercises | PCAP analysis, network-based malware detection, and traffic patterns" },
        { name: "Reverse Engineering 101", provider: "Malware Unicorn", careerPaths: ["malware-analysis", "vuln-research"], notes: "Free workshop | Binary analysis fundamentals, PE format, and disassembly basics" },
        { name: "Ghidra Basics", provider: "NSA / Ghidra", careerPaths: ["malware-analysis", "vuln-research"], notes: "Free | NSA's reverse engineering tool, decompilation, and function analysis" },
      ],
      Intermediate: [
        { name: "FOR610 Reverse-Engineering Malware: Malware Analysis Tools and Techniques", provider: "SANS", careerPaths: ["malware-analysis"], notes: "6 days | GREM prep | Safe malware handling, behavioral analysis, and code examination" },
        { name: "GREM", provider: "SANS / GIAC", careerPaths: ["malware-analysis", "vuln-research", "threat-intel"], notes: "Industry standard | Malware RE certification | Document analysis, packers, and obfuscation" },
        { name: "Malware Analysis Fundamentals", provider: "Mandiant", careerPaths: ["malware-analysis", "threat-intel"], notes: "Vendor training | Real-world samples, APT techniques, and threat actor TTPs" },
        { name: "eCMAP", provider: "INE / eLearnSecurity", careerPaths: ["malware-analysis"], notes: "Practical cert | Advanced static analysis, debugging, and malware unpacking" },
        { name: "Advanced x86 Disassembly", provider: "OpenSecurityTraining", careerPaths: ["malware-analysis", "vuln-research"], notes: "Free | Advanced assembly patterns, compiler optimizations, and code reconstruction" },
        { name: "IDA Pro Essentials", provider: "Hex-Rays", careerPaths: ["malware-analysis", "vuln-research"], notes: "Industry tool | IDA scripting, plugins, and advanced disassembly techniques" },
        { name: "Zero2Automated Malware Analysis", provider: "Zero2Automated", careerPaths: ["malware-analysis"], notes: "Self-paced | Automation, unpacking, and modern malware analysis techniques" },
      ],
      Advanced: [
        { name: "FOR710 Reverse-Engineering Malware: Advanced Code Analysis", provider: "SANS", careerPaths: ["malware-analysis", "vuln-research"], notes: "5 days | Expert | Advanced unpacking, anti-analysis bypass, and complex malware" },
        { name: "Advanced Malware Analysis", provider: "Mandiant", careerPaths: ["malware-analysis", "threat-intel"], notes: "Expert | APT-level analysis, custom tooling, and nation-state malware" },
        { name: "OSED", provider: "OffSec", careerPaths: ["vuln-research", "malware-analysis"], notes: "EXP-301 | Windows exploit dev, shellcoding, and ROP chain construction" },
        { name: "Android Malware Reverse Engineering", provider: "Pentester Academy", careerPaths: ["malware-analysis"], notes: "Mobile focus | APK analysis, Dalvik bytecode, and Android malware families" },
        { name: "Firmware Reverse Engineering", provider: "Attify", careerPaths: ["vuln-research", "ot-ics"], notes: "IoT/embedded | Firmware extraction, analysis, and embedded device security" },
        { name: "Kernel Mode Rootkit Analysis", provider: "CrowdStrike", careerPaths: ["malware-analysis", "vuln-research"], notes: "Expert | Kernel-level threats, rootkit detection, and advanced persistence" },
      ],
    },
  },
  {
    title: "Digital Forensics",
    description: "Evidence handling, acquisition, and forensic analysis certifications for DFIR work.",
    icon: <SearchIcon sx={{ fontSize: 32 }} />,
    color: "#14b8a6",
    tracks: {
      Beginner: [
        { name: "CHFI", provider: "EC-Council", careerPaths: ["forensics", "blue-team"], notes: "Entry-level | Computer forensics methodology, evidence handling, and investigation procedures" },
        { name: "GCFE", provider: "SANS / GIAC", careerPaths: ["forensics"], notes: "FOR500 cert | Windows forensics fundamentals, artifact analysis, and timeline creation" },
        { name: "Digital Forensics Fundamentals", provider: "QA", careerPaths: ["forensics"], notes: "UK training | Evidence acquisition, chain of custody, and basic analysis techniques" },
        { name: "Autopsy Basics and Hands-On", provider: "Basis Technology", careerPaths: ["forensics"], notes: "Free | Open-source forensic tool, disk imaging, and file system analysis" },
        { name: "Computer Hacking Forensic Investigator", provider: "EC-Council", careerPaths: ["forensics", "blue-team"], notes: "Comprehensive | Network forensics, mobile forensics, and malware investigation" },
        { name: "Cyber Forensics Associate", provider: "IACIS", careerPaths: ["forensics"], notes: "Law enforcement standard | Digital evidence fundamentals and legal procedures" },
      ],
      Intermediate: [
        { name: "EnCE", provider: "OpenText", careerPaths: ["forensics"], notes: "EnCase certified | Industry-standard tool proficiency, evidence processing, and reporting" },
        { name: "CFCE", provider: "IACIS", careerPaths: ["forensics"], notes: "Peer-reviewed | Law enforcement standard, practical exam, and comprehensive forensics" },
        { name: "MCFE", provider: "Magnet Forensics", careerPaths: ["forensics"], notes: "Magnet AXIOM | Mobile and computer forensics, cloud evidence, and artifact analysis" },
        { name: "ACE (AccessData Certified Examiner)", provider: "Exterro", careerPaths: ["forensics"], notes: "FTK certified | Forensic toolkit proficiency, e-discovery, and case management" },
        { name: "FOR500 Windows Forensic Analysis", provider: "SANS", careerPaths: ["forensics", "blue-team"], notes: "6 days | GCFE prep | Registry, file system, browser forensics, and timeline analysis" },
        { name: "FOR508 Advanced IR, Threat Hunting & Forensics", provider: "SANS", careerPaths: ["forensics", "blue-team"], notes: "6 days | GCFA prep | APT hunting, memory forensics, and enterprise-scale IR" },
        { name: "AXIOM Certified Examiner", provider: "Magnet Forensics", careerPaths: ["forensics"], notes: "Advanced | Cloud forensics, social media artifacts, and advanced AXIOM features" },
      ],
      Advanced: [
        { name: "GCFA", provider: "SANS / GIAC", careerPaths: ["forensics", "blue-team"], notes: "FOR508 cert | Expert | Advanced threat hunting, memory forensics, and APT analysis" },
        { name: "GNFA", provider: "SANS / GIAC", careerPaths: ["forensics", "network-security"], notes: "FOR572 cert | Network forensics, packet analysis, and network-based threat detection" },
        { name: "GASF", provider: "SANS / GIAC", careerPaths: ["forensics"], notes: "FOR585 cert | Smartphone forensics, app analysis, and mobile device examination" },
        { name: "X-Ways Forensics Training", provider: "X-Ways", careerPaths: ["forensics"], notes: "Expert tool | Advanced disk analysis, file carving, and professional forensics" },
        { name: "Cellebrite Certified Operator", provider: "Cellebrite", careerPaths: ["forensics"], notes: "Mobile expert | Physical extraction, UFED, and advanced mobile forensics" },
        { name: "FOR518 Mac and iOS Forensic Analysis", provider: "SANS", careerPaths: ["forensics"], notes: "6 days | Apple forensics, APFS, macOS artifacts, and iOS investigation" },
        { name: "FOR585 Smartphone Forensic Analysis In-Depth", provider: "SANS", careerPaths: ["forensics"], notes: "6 days | GASF prep | iOS/Android deep-dive, app forensics, and mobile malware" },
        { name: "GCFR (Cloud Forensics)", provider: "SANS / GIAC", careerPaths: ["forensics", "cloud-security"], notes: "FOR509 cert | AWS/Azure/GCP forensics, cloud artifacts, and IR in the cloud" },
      ],
    },
  },
  {
    title: "Defensive Security & SOC Analysis",
    description: "Blue team, incident response, threat intelligence, and security operations center certifications for defenders.",
    icon: <LocalPoliceIcon sx={{ fontSize: 32 }} />,
    color: "#e11d48",
    tracks: {
      Beginner: [
        { name: "CySA+", provider: "CompTIA", careerPaths: ["blue-team", "threat-intel"], notes: "Foundation | Security+ recommended | Threat detection, analysis, and incident response basics" },
        { name: "BTL1 (Blue Team Level 1)", provider: "Security Blue Team", careerPaths: ["blue-team", "forensics"], notes: "Entry-level | 24-hour practical exam | SIEM, log analysis, phishing, and IR fundamentals" },
        { name: "Incident Response Fundamentals", provider: "QA", careerPaths: ["blue-team"], notes: "UK training provider | IR methodology, evidence handling, and initial response" },
        { name: "Splunk Core Certified User", provider: "Splunk", careerPaths: ["blue-team", "data-science"], notes: "Foundation | Search, reports, dashboards, and basic SPL queries" },
        { name: "LetsDefend SOC Analyst", provider: "LetsDefend", careerPaths: ["blue-team"], notes: "Hands-on SOC training | Alert triage, case management, and practical scenarios" },
        { name: "TryHackMe SOC Level 1", provider: "TryHackMe", careerPaths: ["blue-team"], notes: "Gamified learning | SOC fundamentals, tools, and detection techniques" },
        { name: "SOC Analyst Level 1", provider: "Hack The Box", careerPaths: ["blue-team"], notes: "Practical certification | Alert handling, SIEM, and basic threat analysis" },
        { name: "GCTI Foundation", provider: "SANS / GIAC", careerPaths: ["threat-intel", "blue-team"], notes: "Threat intelligence basics | Intelligence cycle, sources, and analysis fundamentals" },
      ],
      Intermediate: [
        { name: "GCIH (Incident Handler)", provider: "SANS / GIAC", careerPaths: ["blue-team", "forensics", "threat-intel"], notes: "SEC504 certification | Incident handling, attack techniques, and response methodologies" },
        { name: "ECIH", provider: "EC-Council", careerPaths: ["blue-team"], notes: "EC-Council incident handler | IR process, forensics basics, and evidence handling" },
        { name: "SC-200 Security Operations Analyst", provider: "Microsoft", careerPaths: ["blue-team", "cloud-security"], notes: "Microsoft Defender, Sentinel, and cloud SOC operations" },
        { name: "BTL2 (Blue Team Level 2)", provider: "Security Blue Team", careerPaths: ["blue-team", "forensics"], notes: "Advanced | Threat hunting, advanced IR, and deeper forensic analysis" },
        { name: "CDSA (Certified Defensive Security Analyst)", provider: "Hack The Box", careerPaths: ["blue-team"], notes: "Practical defensive cert | Advanced detection, hunting, and response" },
        { name: "Splunk Core Certified Power User", provider: "Splunk", careerPaths: ["blue-team", "data-science"], notes: "Advanced SPL, data models, and complex search optimization" },
        { name: "Elastic Certified Analyst", provider: "Elastic", careerPaths: ["blue-team"], notes: "ELK stack | Kibana, log analysis, and security analytics" },
        { name: "CrowdStrike Certified Falcon Administrator", provider: "CrowdStrike", careerPaths: ["blue-team"], notes: "EDR platform | Falcon deployment, configuration, and threat response" },
        { name: "Carbon Black Certified Professional", provider: "VMware", careerPaths: ["blue-team"], notes: "EDR administration | Endpoint protection and threat detection" },
        { name: "SentinelOne Certified Administrator", provider: "SentinelOne", careerPaths: ["blue-team"], notes: "AI-powered EDR | Platform management and incident investigation" },
        { name: "GCTI (Cyber Threat Intelligence)", provider: "SANS / GIAC", careerPaths: ["threat-intel", "blue-team"], notes: "FOR578 certification | Intelligence analysis, attribution, and reporting" },
        { name: "FOR578 Cyber Threat Intelligence", provider: "SANS", careerPaths: ["threat-intel", "blue-team"], notes: "6 days | Intelligence cycle, structured analysis, and threat landscape" },
      ],
      Advanced: [
        { name: "GCFA (Forensic Analyst)", provider: "SANS / GIAC", careerPaths: ["blue-team", "forensics"], notes: "FOR508 certification | Advanced IR, threat hunting, and timeline analysis" },
        { name: "GCED (Enterprise Defender)", provider: "SANS / GIAC", careerPaths: ["blue-team", "security-engineering"], notes: "SEC501 certification | Defense architecture, detection, and security engineering" },
        { name: "GMON (Continuous Monitoring)", provider: "SANS / GIAC", careerPaths: ["blue-team", "security-engineering"], notes: "SEC511 certification | SOC operations, detection engineering, and analytics" },
        { name: "CREST Certified Incident Manager (CCIM)", provider: "CREST", careerPaths: ["blue-team", "grc"], notes: "Expert level | UK standard | IR leadership, management, and coordination" },
        { name: "FOR508 Advanced IR, Threat Hunting & Forensics", provider: "SANS", careerPaths: ["blue-team", "forensics"], notes: "6 days | GCFA prep | APT hunting, memory forensics, and enterprise IR" },
        { name: "FOR608 Enterprise-Class Incident Response", provider: "SANS", careerPaths: ["blue-team", "forensics", "threat-intel"], notes: "5 days | Large-scale IR, automation, and enterprise threat hunting" },
        { name: "Splunk Certified Architect", provider: "Splunk", careerPaths: ["blue-team", "security-engineering", "data-science"], notes: "Expert | Enterprise SIEM architecture, scaling, and optimization" },
        { name: "Splunk Enterprise Security Admin", provider: "Splunk", careerPaths: ["blue-team", "security-engineering"], notes: "Advanced | ES deployment, correlation rules, and security analytics" },
        { name: "Elastic Certified Engineer", provider: "Elastic", careerPaths: ["blue-team", "data-science"], notes: "Expert | ELK stack architecture, performance tuning, and security use cases" },
        { name: "GRID (Intrusion Detection)", provider: "SANS / GIAC", careerPaths: ["blue-team", "network-security"], notes: "ICS515 certification | ICS network monitoring and detection" },
        { name: "Picus Security Validation Expert", provider: "Picus Security", careerPaths: ["blue-team", "red-team"], notes: "BAS platform | Breach simulation, control validation, and purple team" },
      ],
    },
  },
  {
    title: "AI and Machine Learning",
    description: "Comprehensive AI/ML certifications from beginner to advanced, covering fundamentals, data science, deep learning, and specialized AI engineering.",
    icon: <PsychologyIcon sx={{ fontSize: 32 }} />,
    color: "#a855f7",
    tracks: {
      Beginner: [
        { name: "Data Science: Machine Learning", provider: "HarvardX (edX)", careerPaths: ["data-science"], notes: "8 weeks | R programming | Supervised learning, cross-validation, and model selection" },
        { name: "Artificial Intelligence: Implications for Business Strategy", provider: "HarvardX (edX)", careerPaths: ["grc", "security-engineering"], notes: "6 weeks | No prerequisites | AI strategy, use cases, and business transformation" },
        { name: "Data Science: R Basics", provider: "HarvardX (edX)", careerPaths: ["data-science"], notes: "8 weeks | Free | R fundamentals, data wrangling, and visualization basics" },
        { name: "Azure AI Fundamentals (AI-900)", provider: "Microsoft", careerPaths: ["cloud-security", "data-science"], notes: "Foundational | AI/ML concepts, Azure AI services, and responsible AI principles" },
        { name: "AWS Certified AI Practitioner (AIF)", provider: "AWS", careerPaths: ["cloud-security", "data-science"], notes: "Foundational | AI/ML fundamentals, AWS AI services, and generative AI basics" },
        { name: "AI Essentials", provider: "Google (Coursera)", careerPaths: ["data-science", "security-engineering"], notes: "Foundational | AI concepts, generative AI, and practical applications" },
        { name: "AI for Everyone", provider: "DeepLearning.AI", careerPaths: ["grc", "security-engineering"], notes: "4 weeks | No prerequisites | AI concepts for non-technical professionals" },
        { name: "AI Foundations for Business Specialization", provider: "IBM (Coursera)", careerPaths: ["grc", "data-science"], notes: "3 months | Business focus | AI strategy, ethics, and enterprise applications" },
        { name: "Data Analytics with AI Bootcamp", provider: "Code Institute", careerPaths: ["data-science"], notes: "UK | Beginner track | Python, data analysis, and AI fundamentals" },
        { name: "Data Analytics Bootcamp", provider: "General Assembly", careerPaths: ["data-science"], notes: "10-12 weeks | SQL, Python, Tableau, and data visualization" },
        { name: "AI Programming with Python Nanodegree", provider: "Udacity", careerPaths: ["data-science", "tool-dev"], notes: "3 months | Python, NumPy, Pandas, and neural network fundamentals" },
      ],
      Intermediate: [
        { name: "Data Science: Linear Regression", provider: "HarvardX (edX)", careerPaths: ["data-science"], notes: "8 weeks | R required | Regression models, confounding, and prediction" },
        { name: "Data Science: Productivity Tools", provider: "HarvardX (edX)", careerPaths: ["data-science", "devsecops"], notes: "8 weeks | R basics | Unix, Git, R Markdown, and reproducible research" },
        { name: "Professional Certificate in Computer Science for Artificial Intelligence", provider: "HarvardX (edX)", careerPaths: ["data-science", "security-engineering"], notes: "6 months | CS50 recommended | AI algorithms, machine learning, and neural networks" },
        { name: "Azure AI Engineer Associate (AI-102)", provider: "Microsoft", careerPaths: ["cloud-security", "data-science"], notes: "Professional | Azure Cognitive Services, bot development, and NLP solutions" },
        { name: "Azure Data Scientist Associate (DP-100)", provider: "Microsoft", careerPaths: ["data-science", "cloud-security"], notes: "Professional | Azure ML, model training, and MLOps with Azure" },
        { name: "AWS Certified Machine Learning Engineer - Associate", provider: "AWS", careerPaths: ["cloud-security", "data-science"], notes: "Professional | ML pipelines, model deployment, and AWS ML services" },
        { name: "Google Cloud Professional Data Engineer", provider: "Google Cloud", careerPaths: ["data-science", "cloud-security"], notes: "Professional | BigQuery, Dataflow, and data pipeline design" },
        { name: "Machine Learning Specialization", provider: "DeepLearning.AI", careerPaths: ["data-science"], notes: "3 months | Python required | Supervised/unsupervised learning, neural networks, and TensorFlow" },
        { name: "Practical Deep Learning for Coders", provider: "Fast.ai", careerPaths: ["data-science", "tool-dev"], notes: "Free | 7 weeks | Top-down deep learning, PyTorch, and practical projects" },
        { name: "TensorFlow Developer Certificate", provider: "TensorFlow", careerPaths: ["data-science", "tool-dev"], notes: "Professional | TensorFlow 2.x, CNNs, RNNs, and NLP with TensorFlow" },
        { name: "Data Science & AI Bootcamp", provider: "Le Wagon", careerPaths: ["data-science"], notes: "9-24 weeks | UK/Global | Python, ML, deep learning, and MLOps" },
        { name: "Data Engineering & AI Bootcamp", provider: "Northcoders", careerPaths: ["data-science", "devsecops"], notes: "13 weeks | UK | Python, SQL, cloud data, and AI pipelines" },
        { name: "Data Science Bootcamp", provider: "BrainStation", careerPaths: ["data-science"], notes: "12 weeks | UK | Python, ML, data visualization, and capstone project" },
        { name: "Level 4 Data Analyst Apprenticeship", provider: "Cambridge Spark", careerPaths: ["data-science"], notes: "UK Apprenticeship | Python, SQL, statistics, and business analytics" },
        { name: "AI Product Manager Nanodegree", provider: "Udacity", careerPaths: ["grc", "data-science"], notes: "3 months | Product management for AI, data strategy, and ML product lifecycle" },
      ],
      Advanced: [
        { name: "Professional Certificate in Tiny Machine Learning (TinyML)", provider: "HarvardX (edX)", careerPaths: ["data-science", "security-engineering"], notes: "4 courses | ML on embedded devices, edge AI, and IoT applications" },
        { name: "High-Dimensional Data Analysis", provider: "HarvardX (edX)", careerPaths: ["data-science"], notes: "4 weeks | Advanced statistics | PCA, clustering, and high-dimensional techniques" },
        { name: "Advanced Bioconductor", provider: "HarvardX (edX)", careerPaths: ["data-science"], notes: "4 weeks | R/Bioconductor | Advanced genomic data analysis and visualization" },
        { name: "AWS Certified Machine Learning - Specialty (MLS-C01)", provider: "AWS", careerPaths: ["cloud-security", "data-science"], notes: "Expert | Deep learning, ML problem framing, and AWS ML architecture" },
        { name: "Google Cloud Professional Machine Learning Engineer", provider: "Google Cloud", careerPaths: ["data-science", "cloud-security"], notes: "Expert | ML model design, Vertex AI, and production ML systems" },
        { name: "Deep Learning Specialization", provider: "DeepLearning.AI", careerPaths: ["data-science"], notes: "5 courses | CNNs, RNNs, transformers, and deep learning research techniques" },
        { name: "Generative AI with Large Language Models (LLMs)", provider: "DeepLearning.AI", careerPaths: ["data-science", "security-engineering"], notes: "3 weeks | LLM training, fine-tuning, RLHF, and deployment strategies" },
        { name: "Deep Learning Nanodegree", provider: "Udacity", careerPaths: ["data-science"], notes: "4 months | Neural networks, CNNs, RNNs, GANs, and reinforcement learning" },
        { name: "Artificial Intelligence Nanodegree", provider: "Udacity", careerPaths: ["data-science", "security-engineering"], notes: "6 months | Search, planning, probability, and advanced AI algorithms" },
        { name: "Professional Certificate in Machine Learning and AI", provider: "Imperial College London", careerPaths: ["data-science", "security-engineering"], notes: "Executive education | ML/AI for technical leaders, research methods" },
        { name: "Designing and Building AI Products and Services", provider: "MIT Professional Education", careerPaths: ["data-science", "grc"], notes: "Short course | AI product strategy, design thinking, and implementation" },
        { name: "Artificial Intelligence Graduate Certificate", provider: "Stanford Online", careerPaths: ["data-science", "security-engineering"], notes: "Graduate level | AI theory, deep learning, and advanced ML research" },
      ],
    },
  },
  {
    title: "Project Management, Leadership & GRC",
    description: "Governance, risk, compliance, project management, Agile/Scrum, and security leadership certifications from PMI, AXELOS, ISACA, Scrum Alliance, and leading institutions.",
    icon: <BuildIcon sx={{ fontSize: 32 }} />,
    color: "#f59e0b",
    tracks: {
      Beginner: [
        // Project Management Foundations
        { name: "PRINCE2® 7 Foundation", provider: "PeopleCert/AXELOS", careerPaths: ["grc", "security-engineering"], notes: "Entry-level | No prerequisites | Project methodology, principles, processes, and themes" },
        { name: "APM Project Fundamentals Qualification (PFQ)", provider: "APM", careerPaths: ["grc"], notes: "UK standard | No prerequisites | Project lifecycle, roles, and key terminology" },
        { name: "PMI Certified Associate in Project Management (CAPM)", provider: "PMI", careerPaths: ["grc"], notes: "Entry-level | 23 hours PM education | Project management fundamentals and PMI framework" },
        { name: "CompTIA Project+", provider: "CompTIA", careerPaths: ["grc"], notes: "Vendor-neutral | No prerequisites | Project lifecycle, communication, and resource management" },
        { name: "Google Project Management Professional Certificate", provider: "Google (Coursera)", careerPaths: ["grc", "devsecops"], notes: "6 months | Online | Agile, Scrum, project planning, and stakeholder management" },
        { name: "Project Management Foundations", provider: "University of Cape Town", careerPaths: ["grc"], notes: "8 weeks | Online short course | PM fundamentals, scheduling, and risk basics" },
        // Agile & Scrum Foundations
        { name: "AgilePM® Foundation", provider: "PeopleCert/APMG", careerPaths: ["grc", "devsecops"], notes: "Entry-level | No prerequisites | DSDM Agile framework, not Scrum-focused" },
        { name: "Certified ScrumMaster (CSM)", provider: "Scrum Alliance", careerPaths: ["grc", "devsecops", "security-engineering"], notes: "2-day course | Scrum framework, facilitation, servant leadership, and team dynamics" },
        { name: "Certified Scrum Product Owner (CSPO)", provider: "Scrum Alliance", careerPaths: ["grc", "appsec"], notes: "2-day course | Product vision, backlog management, stakeholder collaboration, and value delivery" },
        { name: "Certified Scrum Developer (CSD)", provider: "Scrum Alliance", careerPaths: ["devsecops", "appsec", "tool-dev"], notes: "5-day course | Agile engineering practices, TDD, CI/CD, and technical excellence" },
        { name: "Agile Essentials", provider: "Scrum Alliance", careerPaths: ["grc", "devsecops"], notes: "Foundational | Self-paced | Introduction to Agile values, principles, and common frameworks" },
        { name: "Scrum Essentials", provider: "Scrum Alliance", careerPaths: ["grc", "devsecops"], notes: "Foundational | Self-paced | Core Scrum concepts, roles, events, and artifacts" },
        // ITSM & Service Management
        { name: "ITIL 4 Foundation", provider: "PeopleCert/AXELOS", careerPaths: ["grc", "security-engineering"], notes: "Entry-level | Service management | ITSM framework, guiding principles, and practices" },
        // GRC Foundations
        { name: "ISO 27001 Foundation", provider: "PECB", careerPaths: ["grc"], notes: "Information security | ISMS fundamentals, requirements, and implementation basics" },
        { name: "Security+", provider: "CompTIA", careerPaths: ["grc", "blue-team", "security-engineering"], notes: "Foundation | Security concepts, threats, architecture, operations, and governance" },
        // Leadership Foundations
        { name: "Certified Agile Leadership (CAL 1)", provider: "Scrum Alliance", careerPaths: ["grc", "security-engineering"], notes: "2-day course | Leadership mindset, organizational agility, and cultural transformation" },
        { name: "Remote Work Revolution for Everyone", provider: "HarvardX (edX)", careerPaths: ["grc"], notes: "4 weeks | Free | Remote collaboration, productivity, and virtual team management" },
        { name: "Exercising Leadership: Foundational Principles", provider: "HarvardX (edX)", careerPaths: ["grc", "security-engineering"], notes: "4 weeks | Free | Adaptive leadership, mobilizing change, and influencing stakeholders" },
      ],
      Intermediate: [
        // Project Management
        { name: "PRINCE2® 7 Practitioner", provider: "PeopleCert/AXELOS", careerPaths: ["grc", "security-engineering"], notes: "Professional | Foundation required | Tailoring PRINCE2, applying themes, and managing stages" },
        { name: "APM Project Management Qualification (PMQ)", provider: "APM", careerPaths: ["grc"], notes: "UK standard | 2-3 years experience | Comprehensive PM knowledge across lifecycle" },
        { name: "PMP (Project Management Professional)", provider: "PMI", careerPaths: ["grc", "security-engineering"], notes: "Gold standard | 3+ years experience | Predictive, agile, and hybrid project management" },
        { name: "PMI Risk Management Professional (PMI-RMP)", provider: "PMI", careerPaths: ["grc"], notes: "Specialist | 3+ years risk experience | Risk identification, assessment, and response planning" },
        { name: "PMI Scheduling Professional (PMI-SP)", provider: "PMI", careerPaths: ["grc"], notes: "Specialist | 3+ years scheduling experience | Schedule development, control, and maintenance" },
        // Agile & Scrum
        { name: "AgilePM® Practitioner", provider: "PeopleCert/APMG", careerPaths: ["grc", "devsecops"], notes: "Professional | Foundation required | Applying DSDM Agile in practice" },
        { name: "PRINCE2 Agile® Practitioner", provider: "PeopleCert/AXELOS", careerPaths: ["grc", "devsecops"], notes: "Professional | PRINCE2 or PMP required | Blending PRINCE2 governance with agile delivery" },
        { name: "PMI-ACP (Agile Certified Practitioner)", provider: "PMI", careerPaths: ["devsecops", "security-engineering"], notes: "Professional | Agile experience | Scrum, Kanban, Lean, XP, and agile practices" },
        { name: "Advanced Certified ScrumMaster (A-CSM)", provider: "Scrum Alliance", careerPaths: ["grc", "devsecops", "security-engineering"], notes: "CSM + 1 year experience | Advanced facilitation, coaching, and organizational change" },
        { name: "Advanced Certified Scrum Product Owner (A-CSPO)", provider: "Scrum Alliance", careerPaths: ["grc", "appsec"], notes: "CSPO + 1 year experience | Strategic product management, advanced stakeholder engagement" },
        { name: "Certified Agile Facilitator (CAF)", provider: "Scrum Alliance", careerPaths: ["grc", "security-engineering"], notes: "2-day course | Meeting facilitation, group dynamics, and collaborative decision-making" },
        { name: "Certified Agile Skills - Scaling (CASS)", provider: "Scrum Alliance", careerPaths: ["grc", "security-engineering"], notes: "2-day course | Scaling Agile across teams, portfolio management, and enterprise agility" },
        // ITSM & Service Management
        { name: "ITIL 4 Managing Professional", provider: "PeopleCert/AXELOS", careerPaths: ["grc", "blue-team"], notes: "Professional | Foundation required | CDS, DSV, HVIT, and DPI modules" },
        // GRC & Compliance
        { name: "CISA (IS Auditor)", provider: "ISACA", careerPaths: ["grc"], notes: "Professional | 5+ years experience | IS audit, control, governance, and assurance" },
        { name: "ISO 27001 Lead Implementer", provider: "PECB", careerPaths: ["grc"], notes: "Professional | ISMS implementation, risk assessment, and certification preparation" },
        { name: "ISO 27001 Lead Auditor", provider: "PECB", careerPaths: ["grc"], notes: "Professional | ISMS auditing, audit planning, and reporting" },
        { name: "COBIT Foundation", provider: "ISACA", careerPaths: ["grc"], notes: "IT governance framework | Enterprise IT governance and management" },
        { name: "CDPSE (Data Privacy Solutions Engineer)", provider: "ISACA", careerPaths: ["grc"], notes: "Privacy engineering | Privacy by design, data lifecycle, and privacy technologies" },
        // Executive Education
        { name: "Leading Strategic Projects Programme", provider: "Oxford Saïd Business School", careerPaths: ["grc"], notes: "8 weeks | Executive education | Strategic project leadership and stakeholder management" },
        { name: "Project Management for Strategic Advantage", provider: "LSE (London School of Economics)", careerPaths: ["grc"], notes: "8 weeks | Online | Strategic PM, governance, and organizational alignment" },
      ],
      Advanced: [
        // Programme & Portfolio Management
        { name: "MSP® (Managing Successful Programmes)", provider: "PeopleCert/AXELOS", careerPaths: ["grc"], notes: "Programme management | Transformational change and benefits realization" },
        { name: "MoP® (Management of Portfolios) Practitioner", provider: "PeopleCert/AXELOS", careerPaths: ["grc"], notes: "Portfolio management | Strategic alignment, prioritization, and investment decisions" },
        { name: "P3O® (Portfolio, Programme and Project Offices)", provider: "PeopleCert/AXELOS", careerPaths: ["grc"], notes: "PMO setup | Governance structures and organizational PM capability" },
        { name: "APM Project Professional Qualification (PPQ)", provider: "APM", careerPaths: ["grc"], notes: "Chartered pathway | 5+ years experience | Advanced PM competencies" },
        { name: "PMI Program Management Professional (PgMP)", provider: "PMI", careerPaths: ["grc"], notes: "Expert | 6+ years programme experience | Managing multiple related projects" },
        { name: "PMI Portfolio Management Professional (PfMP)", provider: "PMI", careerPaths: ["grc"], notes: "Expert | 8+ years portfolio experience | Portfolio governance and optimization" },
        // Agile Leadership
        { name: "Certified Scrum Professional - ScrumMaster (CSP-SM)", provider: "Scrum Alliance", careerPaths: ["grc", "security-engineering"], notes: "Expert | A-CSM + 2 years | Advanced Scrum mastery and organizational coaching" },
        { name: "Certified Scrum Professional - Product Owner (CSP-PO)", provider: "Scrum Alliance", careerPaths: ["grc", "appsec"], notes: "Expert | A-CSPO + 2 years | Strategic product leadership and business value optimization" },
        { name: "Certified Agile Leadership (CAL 2)", provider: "Scrum Alliance", careerPaths: ["grc", "security-engineering"], notes: "Expert | CAL 1 required | Advanced leadership, systems thinking, and transformation" },
        { name: "Certified Enterprise Coach (CEC)", provider: "Scrum Alliance", careerPaths: ["grc"], notes: "Master | Extensive experience | Enterprise-level Agile transformation" },
        { name: "Certified Team Coach (CTC)", provider: "Scrum Alliance", careerPaths: ["grc", "security-engineering"], notes: "Master | Professional team coaching and advanced facilitation" },
        { name: "SAFe Program Consultant (SPC)", provider: "Scaled Agile", careerPaths: ["devsecops", "security-engineering"], notes: "SAFe expertise | Implementing SAFe and Lean-Agile transformation" },
        // ITSM Leadership
        { name: "ITIL 4 Strategic Leader", provider: "PeopleCert/AXELOS", careerPaths: ["grc"], notes: "Expert | Digital strategy and organizational leadership" },
        { name: "ITIL 4 Master", provider: "PeopleCert/AXELOS", careerPaths: ["grc"], notes: "Master level | Extensive ITIL experience | Mastery demonstration" },
        // GRC Leadership
        { name: "CISM (Security Manager)", provider: "ISACA", careerPaths: ["grc"], notes: "Expert | Security governance, risk management, program development" },
        { name: "CRISC (Risk & Information Systems Control)", provider: "ISACA", careerPaths: ["grc"], notes: "Expert | IT risk identification, assessment, and response" },
        { name: "CGEIT (Enterprise IT Governance)", provider: "ISACA", careerPaths: ["grc"], notes: "Expert | Strategic management, benefits delivery, and optimization" },
        { name: "CCISO (Chief Information Security Officer)", provider: "EC-Council", careerPaths: ["grc"], notes: "Executive | CISO competencies, security program leadership" },
        // Executive Education
        { name: "General Management Programme", provider: "Cambridge Judge Business School", careerPaths: ["grc"], notes: "8-12 months | Strategic leadership, finance, and organizational management" },
      ],
    },
  },
  {
    title: "Software Engineering & Development",
    description: "Computer science fundamentals, software engineering bootcamps, and development certifications from Harvard, UK coding bootcamps, and industry leaders.",
    icon: <IntegrationInstructionsIcon sx={{ fontSize: 32 }} />,
    color: "#a855f7",
    tracks: {
      Beginner: [
        { name: "CS50x: Introduction to Computer Science", provider: "HarvardX (edX)", careerPaths: ["appsec", "security-engineering", "tool-dev"], notes: "12 weeks | Free | C, Python, SQL, web development, and computational thinking fundamentals" },
        { name: "CS50P: Introduction to Programming with Python", provider: "HarvardX (edX)", careerPaths: ["tool-dev", "security-engineering", "data-science"], notes: "10 weeks | Free | Python fundamentals, libraries, unit testing, and file I/O" },
        { name: "CS50 SQL: Introduction to Databases with SQL", provider: "HarvardX (edX)", careerPaths: ["appsec", "data-science"], notes: "6 weeks | Free | Database design, SQL queries, and data modeling" },
        { name: "CS50B: Computer Science for Business Professionals", provider: "HarvardX (edX)", careerPaths: ["grc", "security-engineering"], notes: "6 weeks | Free | CS concepts for non-technical professionals, technology strategy" },
        { name: "CS50S: Introduction to Programming with Scratch", provider: "HarvardX (edX)", careerPaths: ["tool-dev"], notes: "3 weeks | Free | Visual programming, computational thinking, and problem-solving basics" },
        { name: "Software Engineering Bootcamp", provider: "Makers Academy", careerPaths: ["appsec", "devsecops", "tool-dev"], notes: "16 weeks | London/Hybrid | TDD, OOP, Agile, Ruby, JavaScript, and pair programming" },
        { name: "Software Development Bootcamp", provider: "Northcoders", careerPaths: ["appsec", "devsecops"], notes: "13 weeks | Manchester/Leeds/Remote | JavaScript, Node.js, React, PostgreSQL, and TDD" },
        { name: "Web Development Bootcamp", provider: "Le Wagon", careerPaths: ["appsec", "devsecops"], notes: "9-24 weeks | London/Global | Ruby on Rails, JavaScript, SQL, and product development" },
        { name: "Software Engineering Immersive", provider: "General Assembly", careerPaths: ["appsec", "devsecops"], notes: "12-24 weeks | London, UK | HTML, CSS, JavaScript, React, Node.js, and MongoDB" },
        { name: "Nanodegree (Full-Stack/Data)", provider: "Code First Girls", careerPaths: ["appsec", "devsecops", "data-science"], notes: "Free/Sponsored | UK | Women-focused coding education, web dev, data, and software" },
        { name: "Software Development Bootcamp", provider: "School of Code", careerPaths: ["appsec", "devsecops"], notes: "16 weeks | UK Remote | Free bootcamp, full-stack JavaScript, and career support" },
        { name: "Certified Entry-Level Python Programmer (PCEP)", provider: "Python Institute", careerPaths: ["tool-dev", "security-engineering"], notes: "Entry-level | Python syntax, data types, control flow, and functions basics" },
        { name: "GitHub Foundations Certification", provider: "GitHub", careerPaths: ["devsecops", "tool-dev"], notes: "Foundational | Git basics, GitHub features, collaboration, and repositories" },
        { name: "Linux Foundation Certified IT Associate (LFCA)", provider: "Linux Foundation", careerPaths: ["blue-team", "security-engineering"], notes: "Entry-level | Linux basics, cloud, DevOps, and security fundamentals" },
        { name: "AWS Certified Cloud Practitioner", provider: "AWS", careerPaths: ["cloud-security", "devsecops"], notes: "Cloud fundamentals | Entry-level AWS certification for developers" },
        { name: "Azure Fundamentals (AZ-900)", provider: "Microsoft", careerPaths: ["cloud-security", "devsecops"], notes: "Cloud fundamentals | Core Azure concepts, services, and pricing" },
        { name: "Responsive Web Design Certification", provider: "FreeCodeCamp", careerPaths: ["appsec"], notes: "Free | 300 hours | HTML, CSS, accessibility, and responsive design projects" },
        { name: "Front-End Developer Professional Certificate", provider: "Meta (Coursera)", careerPaths: ["appsec"], notes: "7 months | Online | HTML, CSS, JavaScript, React, and UX design" },
        { name: "IT Automation with Python Professional Certificate", provider: "Google (Coursera)", careerPaths: ["tool-dev", "devsecops", "security-engineering"], notes: "6 months | Online | Python automation, Git, and IT troubleshooting" },
      ],
      Intermediate: [
        { name: "CS50W: Web Programming with Python and JavaScript", provider: "HarvardX (edX)", careerPaths: ["appsec", "devsecops"], notes: "12 weeks | CS50 recommended | Django, React, SQL, Git, and web security basics" },
        { name: "CS50AI: Introduction to Artificial Intelligence with Python", provider: "HarvardX (edX)", careerPaths: ["data-science", "security-engineering"], notes: "7 weeks | Python required | Search, knowledge, ML, neural networks, and NLP" },
        { name: "CS50M: Mobile App Development with React Native", provider: "HarvardX (edX)", careerPaths: ["appsec"], notes: "13 weeks | CS50 or JavaScript | Cross-platform mobile development and deployment" },
        { name: "CS50 Cybersecurity: Introduction to Cybersecurity", provider: "HarvardX (edX)", careerPaths: ["blue-team", "red-team", "appsec"], notes: "5 weeks | Free | Securing accounts, data, systems, software, and networks" },
        { name: "Professional Certificate in Computer Science for Game Development", provider: "HarvardX (edX)", careerPaths: ["tool-dev"], notes: "6 months | CS50 recommended | Unity, Lua, game design patterns, and 3D graphics" },
        { name: "Certified Kubernetes Application Developer (CKAD)", provider: "CNCF", careerPaths: ["devsecops", "cloud-security"], notes: "K8s developer skills | Design, build, and deploy cloud-native applications" },
        { name: "HashiCorp Certified: Terraform Associate", provider: "HashiCorp", careerPaths: ["devsecops", "security-engineering"], notes: "IaC certification | Infrastructure provisioning and management with Terraform" },
        { name: "AWS Certified Developer – Associate", provider: "AWS", careerPaths: ["devsecops", "cloud-security"], notes: "Cloud development | Build and maintain AWS applications" },
        { name: "Azure Developer Associate (AZ-204)", provider: "Microsoft", careerPaths: ["devsecops", "cloud-security"], notes: "Cloud development | Build and deploy Azure solutions" },
        { name: "Google Cloud Professional Cloud Developer", provider: "Google Cloud", careerPaths: ["devsecops", "cloud-security"], notes: "Cloud development | Design, build, and deploy GCP applications" },
        { name: "Oracle Certified Professional: Java SE Developer", provider: "Oracle", careerPaths: ["appsec", "tool-dev"], notes: "Professional | Java SE 11/17+ | OOP, collections, streams, and concurrency" },
        { name: "MongoDB Associate Developer Exam", provider: "MongoDB", careerPaths: ["appsec", "data-science"], notes: "Database developer | CRUD, indexing, aggregation, and data modeling" },
        { name: "Spring Certified Professional", provider: "VMware/Broadcom", careerPaths: ["appsec", "devsecops"], notes: "Java Spring Boot | Dependency injection, Spring MVC, security, and data" },
        { name: "Unity Certified Associate: Programmer", provider: "Unity", careerPaths: ["tool-dev"], notes: "Game development | C#, Unity scripting, physics, and game mechanics" },
        { name: "React Nanodegree", provider: "Udacity", careerPaths: ["appsec"], notes: "4 months | React, Redux, React Native, and front-end architecture" },
        { name: "C++ Developer Nanodegree", provider: "Udacity", careerPaths: ["tool-dev", "security-engineering"], notes: "4 months | Modern C++, memory management, concurrency, and system programming" },
      ],
      Advanced: [
        { name: "Professional Certificate in Data Science", provider: "HarvardX (edX)", careerPaths: ["data-science", "security-engineering"], notes: "1.5 years | R, statistics, machine learning, and data visualization series" },
        { name: "Certified Kubernetes Administrator (CKA)", provider: "CNCF", careerPaths: ["devsecops", "cloud-security"], notes: "Container orchestration | K8s cluster management and troubleshooting" },
        { name: "Certified Kubernetes Security Specialist (CKS)", provider: "CNCF", careerPaths: ["devsecops", "cloud-security"], notes: "K8s security | Secure cluster setup, hardening, and runtime security" },
        { name: "AWS Certified Solutions Architect – Professional", provider: "AWS", careerPaths: ["cloud-security", "security-engineering"], notes: "Expert cloud architecture | Complex multi-tier AWS solutions" },
        { name: "AWS Certified DevOps Engineer – Professional", provider: "AWS", careerPaths: ["devsecops", "cloud-security"], notes: "Expert DevOps | CI/CD, monitoring, automation, and infrastructure as code" },
        { name: "Google Cloud Professional Cloud Architect", provider: "Google Cloud", careerPaths: ["cloud-security", "security-engineering"], notes: "Expert level | Design and plan GCP cloud solutions architecture" },
        { name: "Microsoft Certified: DevOps Engineer Expert (AZ-400)", provider: "Microsoft", careerPaths: ["devsecops", "cloud-security"], notes: "Expert DevOps | Azure DevOps, CI/CD, and infrastructure automation" },
        { name: "iSAQB® Certified Professional for Software Architecture - Foundation", provider: "iSAQB", careerPaths: ["security-engineering", "appsec"], notes: "Foundation | Software architecture principles, patterns, and documentation" },
        { name: "iSAQB® Certified Professional for Software Architecture - Advanced", provider: "iSAQB", careerPaths: ["security-engineering", "appsec"], notes: "Advanced | Specialized modules in security, flexibility, and reliability" },
        { name: "TOGAF 10 Certification", provider: "The Open Group", careerPaths: ["security-engineering", "grc"], notes: "Enterprise architecture | Framework for enterprise architecture development" },
        { name: "Open Certified Architect (Open CA)", provider: "The Open Group", careerPaths: ["security-engineering", "grc"], notes: "Expert | Experience-based board review for practicing architects" },
        { name: "CISSP (Architecture Focus)", provider: "ISC2", careerPaths: ["security-engineering", "grc"], notes: "Expert | Security architecture domains within CISSP certification" },
        { name: "Software Architecture: Principles and Practices", provider: "MIT Professional Education", careerPaths: ["security-engineering", "appsec"], notes: "Short course | Architecture patterns, microservices, and system design" },
        { name: "Software Security Foundations Professional Certificate", provider: "Stanford Online", careerPaths: ["appsec", "security-engineering"], notes: "Professional cert | Secure coding, vulnerability analysis, and security design" },
      ],
    },
  },
];

const CyberSecurityCertificationsPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedLevel, setSelectedLevel] = useState<Level | "all">("all");
  const [selectedCareerPath, setSelectedCareerPath] = useState<CareerPathType | "all">("all");
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set([subjects[0]?.title]));
  const [showFilters, setShowFilters] = useState(false);
  const sectionRefs = useRef<Record<string, HTMLDivElement | null>>({});

  // Read URL query parameters on mount for deep linking from Career Paths page
  useEffect(() => {
    const pathParam = searchParams.get("path");
    const levelParam = searchParams.get("level");
    
    if (pathParam && Object.keys(careerPathMeta).includes(pathParam)) {
      setSelectedCareerPath(pathParam as CareerPathType);
      setShowFilters(true);
    }
    
    if (levelParam && ["Beginner", "Intermediate", "Advanced"].includes(levelParam)) {
      setSelectedLevel(levelParam as Level);
      setShowFilters(true);
    }
  }, [searchParams]);

  // Calculate statistics
  const stats = useMemo(() => {
    let totalCerts = 0;
    let beginnerCount = 0;
    let intermediateCount = 0;
    let advancedCount = 0;
    const providerSet = new Set<string>();

    subjects.forEach((subject) => {
      Object.entries(subject.tracks).forEach(([level, certs]) => {
        totalCerts += certs.length;
        certs.forEach((cert) => providerSet.add(cert.provider));
        if (level === "Beginner") beginnerCount += certs.length;
        if (level === "Intermediate") intermediateCount += certs.length;
        if (level === "Advanced") advancedCount += certs.length;
      });
    });

    return {
      totalCerts,
      beginnerCount,
      intermediateCount,
      advancedCount,
      totalProviders: providerSet.size,
      totalSubjects: subjects.length,
    };
  }, []);

  // Filter subjects and certifications based on search and filters
  const filteredSubjects = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();
    
    return subjects.map((subject) => {
      const filteredTracks: Record<Level, CertificationItem[]> = {
        Beginner: [],
        Intermediate: [],
        Advanced: [],
      };

      levelOrder.forEach((level) => {
        if (selectedLevel !== "all" && selectedLevel !== level) return;
        
        filteredTracks[level] = subject.tracks[level].filter((cert) => {
          // Filter by career path
          if (selectedCareerPath !== "all" && !cert.careerPaths?.includes(selectedCareerPath)) {
            return false;
          }
          
          // Filter by search query
          if (query) {
            const searchFields = [
              cert.name.toLowerCase(),
              cert.provider.toLowerCase(),
              cert.notes?.toLowerCase() || "",
              subject.title.toLowerCase(),
              ...(cert.careerPaths?.map((p) => careerPathMeta[p].label.toLowerCase()) || []),
            ];
            return searchFields.some((field) => field.includes(query));
          }
          return true;
        });
      });

      const hasResults = Object.values(filteredTracks).some((arr) => arr.length > 0);
      
      return {
        ...subject,
        tracks: filteredTracks,
        hasResults,
      };
    }).filter((s) => s.hasResults);
  }, [searchQuery, selectedLevel, selectedCareerPath]);

  const handleExpandAll = () => {
    setExpandedSections(new Set(subjects.map((s) => s.title)));
  };

  const handleCollapseAll = () => {
    setExpandedSections(new Set());
  };

  const toggleSection = (title: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(title)) {
        next.delete(title);
      } else {
        next.add(title);
      }
      return next;
    });
  };

  const scrollToSection = (title: string) => {
    setExpandedSections((prev) => new Set([...prev, title]));
    setTimeout(() => {
      sectionRefs.current[title]?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 100);
  };

  const clearFilters = () => {
    setSearchQuery("");
    setSelectedLevel("all");
    setSelectedCareerPath("all");
  };

  const hasActiveFilters = searchQuery || selectedLevel !== "all" || selectedCareerPath !== "all";

  const pageContext = `This page provides a comprehensive guide to education and certifications organized by subject area. 

SUBJECT AREAS:
- IT Fundamentals & General Technology: CompTIA foundations, security basics, hardware/software concepts
- Networking & Infrastructure: Cisco, Juniper, wireless, network security, firewalls, virtualization
- System Administration: Windows Server, Active Directory, Linux, Red Hat, shell scripting
- Cloud Computing & DevOps: AWS, Azure, GCP, Kubernetes, Docker, CI/CD, IaC, DevSecOps
- Software Engineering & Development: Programming languages, bootcamps, software architecture, CS fundamentals
- AI and Machine Learning: Data science, ML/DL certifications, AI engineering, neural networks
- Project Management, Leadership & GRC: PRINCE2, PMP, Agile/Scrum, GRC, ISACA, ISO 27001, ITIL
- Defensive Security & SOC Analysis: Blue team, incident response, SOC, threat intelligence, SIEM
- Offensive Security & Penetration Testing: Red team, pentesting, OffSec (OSCP/OSEP), CREST, ethical hacking
- Application & Web Security: OWASP, web pentesting, bug bounty, mobile security, secure SDLC
- Vulnerability Research & Exploit Development: Binary exploitation, exploit development, GXPN, OSEE
- Reverse Engineering & Malware Analysis: RE tools, malware analysis, GREM, IDA Pro, Ghidra
- Digital Forensics: DFIR, evidence acquisition, memory forensics, GCFA, GCFE

PROVIDERS: SANS/GIAC, CompTIA, OffSec, CREST, ISC2, ISACA, EC-Council, Microsoft, AWS, Google Cloud, Hack The Box, Cisco, HarvardX, DeepLearning.AI, Scrum Alliance, PMI, AXELOS, and many others.

All certifications organized by Beginner/Intermediate/Advanced levels with career path mappings.`;

  return (
    <LearnPageLayout pageTitle="Education & Certifications" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a12", py: 4 }}>
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
          <WorkspacePremiumIcon sx={{ fontSize: 42, color: "#38bdf8" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #38bdf8 0%, #6366f1 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Education & Certifications
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Comprehensive learning paths organized by subject area with beginner, intermediate, and advanced options.
        </Typography>

        {/* Statistics Summary */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[
            { label: "Total Certifications", value: stats.totalCerts, icon: <SchoolIcon />, color: "#38bdf8" },
            { label: "Subject Areas", value: stats.totalSubjects, icon: <CategoryIcon />, color: "#22c55e" },
            { label: "Training Providers", value: stats.totalProviders, icon: <BusinessIcon />, color: "#f59e0b" },
          ].map((stat) => (
            <Grid item xs={4} key={stat.label}>
              <Paper
                sx={{
                  p: 2,
                  bgcolor: alpha(stat.color, 0.08),
                  borderRadius: 2,
                  border: `1px solid ${alpha(stat.color, 0.2)}`,
                  textAlign: "center",
                }}
              >
                <Box sx={{ color: stat.color, mb: 0.5 }}>{stat.icon}</Box>
                <Typography variant="h4" sx={{ color: stat.color, fontWeight: 700 }}>
                  {stat.value}
                </Typography>
                <Typography variant="caption" sx={{ color: "grey.400" }}>
                  {stat.label}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Level Distribution */}
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          {levelOrder.map((level) => (
            <Chip
              key={level}
              label={`${level} (${level === "Beginner" ? stats.beginnerCount : level === "Intermediate" ? stats.intermediateCount : stats.advancedCount})`}
              size="small"
              onClick={() => setSelectedLevel(selectedLevel === level ? "all" : level)}
              sx={{
                bgcolor: selectedLevel === level ? levelMeta[level].color : alpha(levelMeta[level].color, 0.15),
                color: selectedLevel === level ? "#fff" : levelMeta[level].color,
                fontWeight: 700,
                cursor: "pointer",
                "&:hover": { bgcolor: alpha(levelMeta[level].color, 0.35) },
              }}
            />
          ))}
          {selectedLevel !== "all" && (
            <Chip
              label="Clear"
              size="small"
              onClick={() => setSelectedLevel("all")}
              onDelete={() => setSelectedLevel("all")}
              sx={{ bgcolor: "rgba(239,68,68,0.15)", color: "#ef4444" }}
            />
          )}
        </Box>

        {/* Search and Filter Bar */}
        <Paper
          sx={{
            p: 2,
            mb: 3,
            bgcolor: "#111522",
            borderRadius: 2,
            border: "1px solid rgba(56,189,248,0.3)",
          }}
        >
          <Box sx={{ display: "flex", gap: 2, alignItems: "center", flexWrap: "wrap" }}>
            <TextField
              placeholder="Search certifications, providers, or topics..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              size="small"
              sx={{
                flex: 1,
                minWidth: 280,
                "& .MuiOutlinedInput-root": {
                  bgcolor: "#0c0f1c",
                  color: "grey.200",
                  "& fieldset": { borderColor: "rgba(148,163,184,0.2)" },
                  "&:hover fieldset": { borderColor: "#38bdf8" },
                  "&.Mui-focused fieldset": { borderColor: "#38bdf8" },
                },
                "& .MuiInputBase-input::placeholder": { color: "grey.500" },
              }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon sx={{ color: "grey.500" }} />
                  </InputAdornment>
                ),
                endAdornment: searchQuery && (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => setSearchQuery("")}>
                      <ClearIcon sx={{ color: "grey.500", fontSize: 18 }} />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
            <Button
              variant="outlined"
              startIcon={<FilterListIcon />}
              onClick={() => setShowFilters(!showFilters)}
              sx={{
                borderColor: showFilters ? "#6366f1" : "rgba(148,163,184,0.3)",
                color: showFilters ? "#6366f1" : "grey.400",
                bgcolor: showFilters ? alpha("#6366f1", 0.1) : "transparent",
              }}
            >
              Filters {hasActiveFilters && "•"}
            </Button>
            <ButtonGroup size="small">
              <Button
                onClick={handleExpandAll}
                startIcon={<UnfoldMoreIcon />}
                sx={{ borderColor: "rgba(148,163,184,0.3)", color: "grey.400" }}
              >
                Expand All
              </Button>
              <Button
                onClick={handleCollapseAll}
                startIcon={<UnfoldLessIcon />}
                sx={{ borderColor: "rgba(148,163,184,0.3)", color: "grey.400" }}
              >
                Collapse
              </Button>
            </ButtonGroup>
          </Box>

          {/* Advanced Filters Panel */}
          <Collapse in={showFilters}>
            <Box sx={{ mt: 2, pt: 2, borderTop: "1px solid rgba(148,163,184,0.15)" }}>
              <Typography variant="subtitle2" sx={{ color: "grey.400", mb: 1 }}>
                Filter by Career Path
              </Typography>
              <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mb: 2 }}>
                <Chip
                  label="All Paths"
                  size="small"
                  onClick={() => setSelectedCareerPath("all")}
                  sx={{
                    bgcolor: selectedCareerPath === "all" ? "#6366f1" : "rgba(99,102,241,0.15)",
                    color: selectedCareerPath === "all" ? "#fff" : "#6366f1",
                    cursor: "pointer",
                  }}
                />
                {Object.entries(careerPathMeta).map(([key, meta]) => (
                  <Chip
                    key={key}
                    label={meta.label}
                    size="small"
                    onClick={() => setSelectedCareerPath(selectedCareerPath === key as CareerPathType ? "all" : key as CareerPathType)}
                    sx={{
                      bgcolor: selectedCareerPath === key ? meta.color : alpha(meta.color, 0.12),
                      color: selectedCareerPath === key ? "#fff" : meta.color,
                      cursor: "pointer",
                      "&:hover": { bgcolor: alpha(meta.color, 0.3) },
                    }}
                  />
                ))}
              </Box>
              {hasActiveFilters && (
                <Button
                  size="small"
                  startIcon={<ClearIcon />}
                  onClick={clearFilters}
                  sx={{ color: "#ef4444" }}
                >
                  Clear All Filters
                </Button>
              )}
            </Box>
          </Collapse>

          {/* Search Results Summary */}
          {hasActiveFilters && (
            <Box sx={{ mt: 2, pt: 2, borderTop: "1px solid rgba(148,163,184,0.15)" }}>
              <Typography variant="body2" sx={{ color: "grey.400" }}>
                Showing{" "}
                <Box component="span" sx={{ color: "#38bdf8", fontWeight: 700 }}>
                  {filteredSubjects.reduce((acc, s) => acc + Object.values(s.tracks).flat().length, 0)}
                </Box>
                {" "}certifications across{" "}
                <Box component="span" sx={{ color: "#22c55e", fontWeight: 700 }}>
                  {filteredSubjects.length}
                </Box>
                {" "}subject areas
              </Typography>
            </Box>
          )}
        </Paper>

        {/* Quick Navigation */}
        <Paper
          sx={{
            p: 2,
            mb: 3,
            bgcolor: "#0f1424",
            borderRadius: 2,
            border: "1px solid rgba(148,163,184,0.15)",
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
            <BookmarkIcon sx={{ color: "#38bdf8", fontSize: 20 }} />
            <Typography variant="subtitle2" sx={{ color: "grey.300" }}>
              Quick Navigation
            </Typography>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            {subjects.map((subject) => (
              <Chip
                key={subject.title}
                label={subject.title}
                size="small"
                onClick={() => scrollToSection(subject.title)}
                sx={{
                  bgcolor: alpha(subject.color, 0.12),
                  color: subject.color,
                  cursor: "pointer",
                  fontSize: "0.75rem",
                  "&:hover": { bgcolor: alpha(subject.color, 0.25) },
                }}
              />
            ))}
          </Box>
        </Paper>

        {/* How to use this page */}
        <Paper
          sx={{
            p: 3,
            mb: 3,
            bgcolor: "#111522",
            borderRadius: 2,
            border: "1px solid rgba(148,163,184,0.2)",
          }}
        >
          <Typography variant="h6" sx={{ color: "grey.200", mb: 1 }}>
            How to use this page
          </Typography>
          <Grid container spacing={2}>
            {[
              {
                title: "🎯 Pick a domain",
                copy: "Choose the subject that matches your role goals or the work you are doing today.",
                color: "#38bdf8",
              },
              {
                title: "📈 Match the level",
                copy: "Start with beginner certs, then progress to intermediate and advanced as you build depth.",
                color: "#22c55e",
              },
              {
                title: "✅ Validate requirements",
                copy: "Always check the provider site for prerequisites, exam updates, and recert rules.",
                color: "#f59e0b",
              },
            ].map((item) => (
              <Grid item xs={12} md={4} key={item.title}>
                <Paper
                  sx={{
                    p: 2,
                    bgcolor: "#0c0f1c",
                    borderRadius: 2,
                    border: `1px solid ${alpha(item.color, 0.25)}`,
                    height: "100%",
                  }}
                >
                  <Typography variant="subtitle2" sx={{ color: item.color, mb: 1 }}>
                    {item.title}
                  </Typography>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    {item.copy}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper
          sx={{
            p: 2.5,
            mb: 4,
            bgcolor: "#0f1424",
            borderRadius: 2,
            border: "1px solid rgba(148,163,184,0.2)",
          }}
        >
          <Typography variant="subtitle1" sx={{ color: "grey.200", mb: 1 }}>
            Providers covered
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 1 }}>
            {providers.map((provider) => (
              <Chip
                key={provider}
                label={provider}
                size="small"
                sx={{
                  bgcolor: "rgba(56,189,248,0.08)",
                  color: "grey.200",
                }}
              />
            ))}
          </Box>
          <Typography variant="caption" sx={{ color: "grey.500" }}>
            Provider names and exam details change. Validate prerequisites and current exam versions on official sites.
          </Typography>
        </Paper>

        {/* Career Paths Legend */}
        <Paper
          sx={{
            p: 2.5,
            mb: 4,
            bgcolor: "#111522",
            borderRadius: 2,
            border: "1px solid rgba(99,102,241,0.3)",
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
            <TrendingUpIcon sx={{ color: "#6366f1" }} />
            <Typography variant="subtitle1" sx={{ color: "grey.200", fontWeight: 700 }}>
              Career Path Links
            </Typography>
          </Box>
          <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
            Each certification shows relevant career paths. Click any career tag to explore that track in detail.
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            {Object.entries(careerPathMeta).slice(0, 10).map(([key, meta]) => (
              <Tooltip key={key} title={meta.description} arrow>
                <Chip
                  label={meta.label}
                  size="small"
                  icon={<TrendingUpIcon sx={{ fontSize: 12 }} />}
                  onClick={() => navigate("/learn/career-paths")}
                  sx={{
                    bgcolor: alpha(meta.color, 0.12),
                    color: meta.color,
                    cursor: "pointer",
                    "&:hover": { bgcolor: alpha(meta.color, 0.25) },
                    "& .MuiChip-icon": { color: meta.color },
                  }}
                />
              </Tooltip>
            ))}
            <Chip
              label="+ More..."
              size="small"
              onClick={() => navigate("/learn/career-paths")}
              sx={{
                bgcolor: "rgba(99,102,241,0.12)",
                color: "#6366f1",
                cursor: "pointer",
                "&:hover": { bgcolor: "rgba(99,102,241,0.25)" },
              }}
            />
          </Box>
        </Paper>

        {/* No Results Message */}
        {filteredSubjects.length === 0 && (
          <Paper
            sx={{
              p: 4,
              mb: 3,
              bgcolor: "#111522",
              borderRadius: 2,
              border: "1px solid rgba(239,68,68,0.3)",
              textAlign: "center",
            }}
          >
            <SearchIcon sx={{ fontSize: 48, color: "grey.600", mb: 2 }} />
            <Typography variant="h6" sx={{ color: "grey.400", mb: 1 }}>
              No certifications found
            </Typography>
            <Typography variant="body2" sx={{ color: "grey.500", mb: 2 }}>
              Try adjusting your search query or filters
            </Typography>
            <Button
              variant="outlined"
              startIcon={<ClearIcon />}
              onClick={clearFilters}
              sx={{ borderColor: "#38bdf8", color: "#38bdf8" }}
            >
              Clear Filters
            </Button>
          </Paper>
        )}

        {filteredSubjects.map((subject) => (
          <Accordion
            key={subject.title}
            expanded={expandedSections.has(subject.title)}
            onChange={() => toggleSection(subject.title)}
            ref={(el) => (sectionRefs.current[subject.title] = el)}
            sx={{
              mb: 2,
              bgcolor: "#0f1422",
              borderRadius: 2,
              border: `1px solid ${alpha(subject.color, 0.25)}`,
              "&:before": { display: "none" },
              scrollMarginTop: "80px",
            }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: subject.color }} />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                <Box
                  sx={{
                    width: 44,
                    height: 44,
                    borderRadius: 2,
                    bgcolor: alpha(subject.color, 0.15),
                    color: subject.color,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  {subject.icon}
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Typography variant="h6" sx={{ color: "grey.100", fontWeight: 700 }}>
                      {subject.title}
                    </Typography>
                    <Badge
                      badgeContent={Object.values(subject.tracks).flat().length}
                      sx={{
                        "& .MuiBadge-badge": {
                          bgcolor: alpha(subject.color, 0.2),
                          color: subject.color,
                          fontWeight: 700,
                          fontSize: "0.7rem",
                        },
                      }}
                    />
                  </Box>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>
                    {subject.description}
                  </Typography>
                </Box>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {levelOrder.map((level) => (
                  <Grid item xs={12} md={4} key={`${subject.title}-${level}`}>
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: "#0c0f1c",
                        borderRadius: 2,
                        border: `1px solid ${alpha(levelMeta[level].color, 0.3)}`,
                        height: "100%",
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                        <Chip
                          label={level}
                          size="small"
                          sx={{
                            bgcolor: alpha(levelMeta[level].color, 0.18),
                            color: levelMeta[level].color,
                            fontWeight: 700,
                          }}
                        />
                        <Typography variant="caption" sx={{ color: "grey.500" }}>
                          {levelMeta[level].hint}
                        </Typography>
                      </Box>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                        {subject.tracks[level].map((item, itemIndex) => (
                          <Box
                            key={`${item.provider}-${item.name}-${itemIndex}`}
                            sx={{ display: "flex", flexDirection: "column", gap: 0.4 }}
                          >
                            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 1 }}>
                              <Typography variant="body2" sx={{ color: "grey.200", fontWeight: 600 }}>
                                {item.name}
                              </Typography>
                              <Chip
                                label={item.provider}
                                size="small"
                                sx={{
                                  bgcolor: alpha(subject.color, 0.18),
                                  color: subject.color,
                                  fontWeight: 600,
                                }}
                              />
                            </Box>
                            {item.careerPaths && item.careerPaths.length > 0 && (
                              <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 0.5 }}>
                                {item.careerPaths.map((path) => (
                                  <Tooltip
                                    key={path}
                                    title={`${careerPathMeta[path].description} - Click to view career guide`}
                                    arrow
                                  >
                                    <Chip
                                      label={careerPathMeta[path].label}
                                      size="small"
                                      icon={<TrendingUpIcon sx={{ fontSize: 12 }} />}
                                      onClick={() => navigate("/learn/career-paths")}
                                      sx={{
                                        height: 20,
                                        fontSize: "0.65rem",
                                        bgcolor: alpha(careerPathMeta[path].color, 0.12),
                                        color: careerPathMeta[path].color,
                                        cursor: "pointer",
                                        "&:hover": {
                                          bgcolor: alpha(careerPathMeta[path].color, 0.25),
                                        },
                                        "& .MuiChip-icon": {
                                          color: careerPathMeta[path].color,
                                        },
                                      }}
                                    />
                                  </Tooltip>
                                ))}
                              </Box>
                            )}
                            {item.notes && (
                              <Typography variant="caption" sx={{ color: "grey.500" }}>
                                {item.notes}
                              </Typography>
                            )}
                            {itemIndex < subject.tracks[level].length - 1 && (
                              <Divider sx={{ borderColor: "rgba(148,163,184,0.15)", mt: 0.5 }} />
                            )}
                          </Box>
                        ))}
                      </Box>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        ))}

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#38bdf8", color: "#38bdf8" }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default CyberSecurityCertificationsPage;
