import React from "react";
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
} from "@mui/material";
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
import { useNavigate } from "react-router-dom";

type Level = "Beginner" | "Intermediate" | "Advanced";

interface CertificationItem {
  name: string;
  provider: string;
  notes?: string;
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
  "Cisco",
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
  "Juniper",
  "Palo Alto Networks",
  "Fortinet",
  "HashiCorp",
  "Kubernetes (CNCF)",
  "Docker",
  "Terraform",
  "Splunk",
  "Elastic",
  "ServiceNow",
  "Salesforce",
  "Oracle",
  "IBM",
  "PMI",
  "ITIL / Axelos",
  "Scrum Alliance",
  "DevOps Institute",
  "GitLab",
  "Databricks",
  "Snowflake",
  "MongoDB",
  "CrowdStrike",
  "Picus Security",
];

const subjects: SubjectSection[] = [
  {
    title: "General Security Foundations",
    description: "Baseline certifications for core security concepts, networking, and security fundamentals.",
    icon: <SecurityIcon sx={{ fontSize: 32 }} />,
    color: "#38bdf8",
    tracks: {
      Beginner: [
        { name: "A+", provider: "CompTIA" },
        { name: "Network+", provider: "CompTIA" },
        { name: "Certified in Cybersecurity (CC)", provider: "ISC2" },
        { name: "CCNA", provider: "Cisco" },
        { name: "Security+ Bootcamp", provider: "QA" },
        { name: "ITF+ (IT Fundamentals)", provider: "CompTIA" },
        { name: "Cisco CyberOps Associate", provider: "Cisco" },
        { name: "CNSP (Certified Network Security Practitioner)", provider: "The SecOps Group" },
      ],
      Intermediate: [
        { name: "Security+", provider: "CompTIA" },
        { name: "CEH (Certified Ethical Hacker)", provider: "EC-Council" },
        { name: "GSEC", provider: "SANS / GIAC" },
        { name: "SSCP", provider: "ISC2" },
        { name: "CPSA", provider: "CREST" },
        { name: "NSE4 Network Security Professional", provider: "Fortinet" },
        { name: "Cisco CyberOps Professional", provider: "Cisco" },
        { name: "CNSE (Certified Network Security Engineer)", provider: "The SecOps Group" },
        { name: "CCSE (Check Point Certified Security Expert)", provider: "Check Point" },
      ],
      Advanced: [
        { name: "CISSP", provider: "ISC2" },
        { name: "CISM", provider: "ISACA" },
        { name: "CASP+", provider: "CompTIA" },
        { name: "GCIH", provider: "SANS / GIAC" },
        { name: "NSE7 Enterprise Firewall", provider: "Fortinet" },
        { name: "GSLC (Security Leadership)", provider: "SANS / GIAC" },
        { name: "CCNP Security", provider: "Cisco" },
      ],
    },
  },
  {
    title: "Networking Fundamentals",
    description: "Core networking certifications covering protocols, routing, switching, and network design.",
    icon: <RouterIcon sx={{ fontSize: 32 }} />,
    color: "#0ea5e9",
    tracks: {
      Beginner: [
        { name: "Network+", provider: "CompTIA" },
        { name: "CCNA", provider: "Cisco" },
        { name: "JNCIA-Junos", provider: "Juniper" },
        { name: "NSE1-3 Associate", provider: "Fortinet" },
        { name: "MTA Networking Fundamentals", provider: "Microsoft" },
        { name: "Aruba Certified Networking Associate", provider: "HPE Aruba" },
        { name: "MikroTik MTCNA", provider: "MikroTik" },
      ],
      Intermediate: [
        { name: "CCNP Enterprise", provider: "Cisco" },
        { name: "JNCIS-ENT", provider: "Juniper" },
        { name: "NSE4 Network Security Professional", provider: "Fortinet" },
        { name: "VCP-NV (Network Virtualization)", provider: "VMware" },
        { name: "PCNSA", provider: "Palo Alto Networks" },
        { name: "Aruba Certified Switching Professional", provider: "HPE Aruba" },
        { name: "CCNP Service Provider", provider: "Cisco" },
        { name: "F5 Certified Administrator", provider: "F5 Networks" },
      ],
      Advanced: [
        { name: "CCIE Enterprise Infrastructure", provider: "Cisco" },
        { name: "JNCIE-ENT", provider: "Juniper" },
        { name: "PCNSE", provider: "Palo Alto Networks" },
        { name: "NSE8 Network Security Expert", provider: "Fortinet" },
        { name: "CCIE Security", provider: "Cisco" },
        { name: "CCIE Data Center", provider: "Cisco" },
        { name: "Aruba Certified Design Expert", provider: "HPE Aruba" },
      ],
    },
  },
  {
    title: "System Administration - Windows",
    description: "Microsoft Windows Server administration, Active Directory, and enterprise management.",
    icon: <DnsIcon sx={{ fontSize: 32 }} />,
    color: "#0078d4",
    tracks: {
      Beginner: [
        { name: "MTA Windows Server Administration", provider: "Microsoft" },
        { name: "AZ-900 Azure Fundamentals", provider: "Microsoft" },
        { name: "MS-900 Microsoft 365 Fundamentals", provider: "Microsoft" },
        { name: "SC-900 Security Fundamentals", provider: "Microsoft" },
      ],
      Intermediate: [
        { name: "AZ-104 Azure Administrator", provider: "Microsoft" },
        { name: "AZ-800/801 Windows Server Hybrid Admin", provider: "Microsoft" },
        { name: "MD-102 Endpoint Administrator", provider: "Microsoft" },
        { name: "MS-102 Microsoft 365 Administrator", provider: "Microsoft" },
        { name: "AZ-140 Azure Virtual Desktop", provider: "Microsoft" },
      ],
      Advanced: [
        { name: "AZ-305 Azure Solutions Architect", provider: "Microsoft" },
        { name: "AZ-400 DevOps Engineer Expert", provider: "Microsoft" },
        { name: "AZ-500 Azure Security Engineer", provider: "Microsoft" },
        { name: "SC-100 Cybersecurity Architect", provider: "Microsoft" },
        { name: "AZ-700 Network Engineer Associate", provider: "Microsoft" },
      ],
    },
  },
  {
    title: "System Administration - Linux",
    description: "Linux administration, Red Hat enterprise systems, and open-source infrastructure.",
    icon: <TerminalIcon sx={{ fontSize: 32 }} />,
    color: "#cc0000",
    tracks: {
      Beginner: [
        { name: "Linux+", provider: "CompTIA" },
        { name: "LPIC-1", provider: "LPI" },
        { name: "Linux Essentials", provider: "LPI" },
        { name: "LFCS (Linux Foundation Certified Sysadmin)", provider: "Linux Foundation" },
        { name: "Red Hat Certified System Administrator (RHCSA)", provider: "Red Hat" },
      ],
      Intermediate: [
        { name: "LPIC-2", provider: "LPI" },
        { name: "Red Hat Certified Engineer (RHCE)", provider: "Red Hat" },
        { name: "LFCE (Linux Foundation Certified Engineer)", provider: "Linux Foundation" },
        { name: "Ubuntu Certified Professional", provider: "Canonical" },
        { name: "SUSE Certified Administrator", provider: "SUSE" },
      ],
      Advanced: [
        { name: "LPIC-3 (Security, Virtualization, Mixed Env)", provider: "LPI" },
        { name: "Red Hat Certified Architect (RHCA)", provider: "Red Hat" },
        { name: "Red Hat Certified Specialist in Security", provider: "Red Hat" },
        { name: "Red Hat Certified Specialist in Ansible", provider: "Red Hat" },
        { name: "SUSE Certified Engineer", provider: "SUSE" },
      ],
    },
  },
  {
    title: "Cloud Computing - AWS",
    description: "Amazon Web Services certifications from foundational to specialty tracks.",
    icon: <CloudIcon sx={{ fontSize: 32 }} />,
    color: "#ff9900",
    tracks: {
      Beginner: [
        { name: "AWS Cloud Practitioner", provider: "AWS" },
        { name: "AWS AI Practitioner", provider: "AWS" },
      ],
      Intermediate: [
        { name: "AWS Solutions Architect Associate", provider: "AWS" },
        { name: "AWS Developer Associate", provider: "AWS" },
        { name: "AWS SysOps Administrator Associate", provider: "AWS" },
        { name: "AWS Data Engineer Associate", provider: "AWS" },
        { name: "AWS Machine Learning Engineer Associate", provider: "AWS" },
      ],
      Advanced: [
        { name: "AWS Solutions Architect Professional", provider: "AWS" },
        { name: "AWS DevOps Engineer Professional", provider: "AWS" },
        { name: "AWS Security Specialty", provider: "AWS" },
        { name: "AWS Advanced Networking Specialty", provider: "AWS" },
        { name: "AWS Machine Learning Specialty", provider: "AWS" },
        { name: "AWS Database Specialty", provider: "AWS" },
      ],
    },
  },
  {
    title: "Cloud Computing - Azure",
    description: "Microsoft Azure certifications covering administration, development, and architecture.",
    icon: <CloudIcon sx={{ fontSize: 32 }} />,
    color: "#0078d4",
    tracks: {
      Beginner: [
        { name: "AZ-900 Azure Fundamentals", provider: "Microsoft" },
        { name: "DP-900 Data Fundamentals", provider: "Microsoft" },
        { name: "AI-900 AI Fundamentals", provider: "Microsoft" },
        { name: "PL-900 Power Platform Fundamentals", provider: "Microsoft" },
      ],
      Intermediate: [
        { name: "AZ-104 Azure Administrator", provider: "Microsoft" },
        { name: "AZ-204 Azure Developer", provider: "Microsoft" },
        { name: "DP-203 Data Engineer", provider: "Microsoft" },
        { name: "AZ-500 Security Engineer", provider: "Microsoft" },
        { name: "AI-102 AI Engineer", provider: "Microsoft" },
      ],
      Advanced: [
        { name: "AZ-305 Solutions Architect Expert", provider: "Microsoft" },
        { name: "AZ-400 DevOps Engineer Expert", provider: "Microsoft" },
        { name: "DP-300 Database Administrator", provider: "Microsoft" },
        { name: "SC-100 Cybersecurity Architect", provider: "Microsoft" },
        { name: "AZ-700 Network Engineer", provider: "Microsoft" },
      ],
    },
  },
  {
    title: "Cloud Computing - Google Cloud",
    description: "Google Cloud Platform certifications for cloud engineers, architects, and specialists.",
    icon: <CloudIcon sx={{ fontSize: 32 }} />,
    color: "#4285f4",
    tracks: {
      Beginner: [
        { name: "Cloud Digital Leader", provider: "Google Cloud" },
        { name: "Associate Cloud Engineer", provider: "Google Cloud" },
      ],
      Intermediate: [
        { name: "Professional Cloud Architect", provider: "Google Cloud" },
        { name: "Professional Data Engineer", provider: "Google Cloud" },
        { name: "Professional Cloud Developer", provider: "Google Cloud" },
        { name: "Professional Cloud Security Engineer", provider: "Google Cloud" },
      ],
      Advanced: [
        { name: "Professional Cloud DevOps Engineer", provider: "Google Cloud" },
        { name: "Professional Cloud Network Engineer", provider: "Google Cloud" },
        { name: "Professional Machine Learning Engineer", provider: "Google Cloud" },
        { name: "Professional Cloud Database Engineer", provider: "Google Cloud" },
        { name: "Professional Workspace Administrator", provider: "Google Cloud" },
      ],
    },
  },
  {
    title: "DevOps and Site Reliability",
    description: "DevOps, CI/CD, infrastructure as code, and SRE certifications.",
    icon: <IntegrationInstructionsIcon sx={{ fontSize: 32 }} />,
    color: "#6366f1",
    tracks: {
      Beginner: [
        { name: "DevOps Fundamentals", provider: "DevOps Institute" },
        { name: "Docker Certified Associate", provider: "Docker" },
        { name: "GitLab Certified Associate", provider: "GitLab" },
        { name: "Terraform Associate", provider: "HashiCorp" },
      ],
      Intermediate: [
        { name: "CKA (Certified Kubernetes Administrator)", provider: "CNCF" },
        { name: "CKAD (Kubernetes Application Developer)", provider: "CNCF" },
        { name: "AZ-400 DevOps Engineer Expert", provider: "Microsoft" },
        { name: "AWS DevOps Engineer Professional", provider: "AWS" },
        { name: "Vault Associate", provider: "HashiCorp" },
        { name: "Consul Associate", provider: "HashiCorp" },
      ],
      Advanced: [
        { name: "CKS (Certified Kubernetes Security)", provider: "CNCF" },
        { name: "Site Reliability Engineering Foundation", provider: "DevOps Institute" },
        { name: "Terraform Professional", provider: "HashiCorp", notes: "Coming soon" },
        { name: "GitLab Certified Professional", provider: "GitLab" },
        { name: "Platform Engineer", provider: "Linux Foundation" },
      ],
    },
  },
  {
    title: "Virtualization and Data Center",
    description: "VMware, Hyper-V, and data center infrastructure certifications.",
    icon: <StorageIcon sx={{ fontSize: 32 }} />,
    color: "#607d8b",
    tracks: {
      Beginner: [
        { name: "VMware Certified Technical Associate (VCTA)", provider: "VMware" },
        { name: "SC-900 Security Fundamentals", provider: "Microsoft" },
        { name: "Server+", provider: "CompTIA" },
      ],
      Intermediate: [
        { name: "VCP-DCV (Data Center Virtualization)", provider: "VMware" },
        { name: "VCP-NV (Network Virtualization)", provider: "VMware" },
        { name: "AZ-800/801 Windows Server Hybrid Admin", provider: "Microsoft" },
        { name: "Nutanix Certified Professional", provider: "Nutanix" },
      ],
      Advanced: [
        { name: "VCAP-DCV (Advanced Professional)", provider: "VMware" },
        { name: "VCDX (VMware Certified Design Expert)", provider: "VMware" },
        { name: "NetApp Certified Data Administrator", provider: "NetApp" },
        { name: "Dell EMC Proven Professional", provider: "Dell EMC" },
      ],
    },
  },
  {
    title: "Database Administration",
    description: "Database administration certifications for SQL, NoSQL, and cloud databases.",
    icon: <StorageIcon sx={{ fontSize: 32 }} />,
    color: "#e91e63",
    tracks: {
      Beginner: [
        { name: "DP-900 Azure Data Fundamentals", provider: "Microsoft" },
        { name: "Oracle Database Foundations", provider: "Oracle" },
        { name: "MongoDB Associate Developer", provider: "MongoDB" },
        { name: "AWS Cloud Practitioner", provider: "AWS" },
      ],
      Intermediate: [
        { name: "DP-300 Azure Database Administrator", provider: "Microsoft" },
        { name: "Oracle Database Administrator Certified Professional", provider: "Oracle" },
        { name: "MongoDB Associate DBA", provider: "MongoDB" },
        { name: "AWS Database Specialty", provider: "AWS" },
        { name: "PostgreSQL Certified Professional", provider: "EDB" },
        { name: "Snowflake SnowPro Core", provider: "Snowflake" },
      ],
      Advanced: [
        { name: "Oracle Database Maximum Availability Architecture", provider: "Oracle" },
        { name: "Databricks Certified Data Engineer", provider: "Databricks" },
        { name: "Snowflake SnowPro Advanced", provider: "Snowflake" },
        { name: "Cassandra Administrator Associate", provider: "DataStax" },
        { name: "Redis Certified Developer", provider: "Redis" },
      ],
    },
  },
  {
    title: "Penetration Testing and Red Team",
    description: "Offensive testing certifications focused on real-world pentest workflows and red team tradecraft.",
    icon: <BugReportIcon sx={{ fontSize: 32 }} />,
    color: "#ef4444",
    tracks: {
      Beginner: [
        { name: "PJPT", provider: "TCM Security" },
        { name: "eJPT", provider: "INE / eLearnSecurity" },
        { name: "PenTest+", provider: "CompTIA" },
        { name: "PenTest+ Bootcamp", provider: "QA" },
        { name: "CEH (Certified Ethical Hacker)", provider: "EC-Council" },
        { name: "CNSP", provider: "The SecOps Group" },
        { name: "HTB Certified Penetration Testing Specialist", provider: "Hack The Box" },
      ],
      Intermediate: [
        { name: "OSCP", provider: "OffSec" },
        { name: "CPTS", provider: "Hack The Box" },
        { name: "eCPPT", provider: "INE / eLearnSecurity" },
        { name: "CRT", provider: "CREST" },
        { name: "PNPT", provider: "TCM Security" },
        { name: "GRTP", provider: "SANS / GIAC" },
        { name: "CRTA (Certified Red Team Analyst)", provider: "CyberWarFare Labs" },
        { name: "eCPTX", provider: "INE / eLearnSecurity" },
      ],
      Advanced: [
        { name: "OSEP", provider: "OffSec" },
        { name: "OSCE3", provider: "OffSec" },
        { name: "GPEN", provider: "SANS / GIAC" },
        { name: "CCT", provider: "CREST" },
        { name: "CRTO", provider: "Zero-Point Security" },
        { name: "CRTP", provider: "Pentester Academy" },
        { name: "CRTE (Certified Red Team Expert)", provider: "Pentester Academy" },
        { name: "CRTL (Certified Red Team Lead)", provider: "Zero-Point Security" },
        { name: "GXPN", provider: "SANS / GIAC" },
      ],
    },
  },
  {
    title: "Vulnerability Research and Exploit Development",
    description: "Exploit development and vulnerability research paths from foundations to advanced exploitation.",
    icon: <ScienceIcon sx={{ fontSize: 32 }} />,
    color: "#f97316",
    tracks: {
      Beginner: [
        { name: "GSEC", provider: "SANS / GIAC" },
        { name: "OSCP", provider: "OffSec" },
        { name: "eJPT", provider: "INE / eLearnSecurity" },
        { name: "x86/x64 Intro", provider: "OpenSecurityTraining" },
        { name: "Corelan Exploit Writing Tutorial", provider: "Corelan" },
        { name: "Binary Exploitation Fundamentals", provider: "pwn.college" },
      ],
      Intermediate: [
        { name: "OSED", provider: "OffSec" },
        { name: "GXPN", provider: "SANS / GIAC" },
        { name: "Binary Exploitation track", provider: "pwn.college" },
        { name: "OSCE3", provider: "OffSec" },
        { name: "Corelan Advanced", provider: "Corelan" },
        { name: "Heap Exploitation", provider: "Azeria Labs" },
        { name: "Windows Kernel Exploitation", provider: "Offensive Security Research" },
      ],
      Advanced: [
        { name: "SEC760 Advanced Exploit Development", provider: "SANS" },
        { name: "Advanced Pwn track", provider: "pwn.college" },
        { name: "OSEE", provider: "OffSec" },
        { name: "Azeria Labs ARM Exploitation", provider: "Azeria Labs" },
        { name: "SEC661 ARM Exploit Development", provider: "SANS" },
        { name: "Browser Exploitation", provider: "Zero Day Initiative" },
        { name: "Hypervisor Exploitation", provider: "Offensive Security Research" },
      ],
    },
  },
  {
    title: "Web Application Security and Bug Bounty",
    description: "Web application testing certifications covering OWASP risks, chaining, and reporting.",
    icon: <LanguageIcon sx={{ fontSize: 32 }} />,
    color: "#22c55e",
    tracks: {
      Beginner: [
        { name: "Web Security Academy", provider: "PortSwigger" },
        { name: "OWASP Juice Shop and WebGoat", provider: "OWASP" },
        { name: "CPSA", provider: "CREST" },
        { name: "Web App Security Fundamentals", provider: "QA" },
        { name: "Bug Bounty Hunter", provider: "HackerOne" },
        { name: "Bugcrowd University", provider: "Bugcrowd" },
      ],
      Intermediate: [
        { name: "GWAPT", provider: "SANS / GIAC" },
        { name: "CBBH", provider: "Hack The Box" },
        { name: "eWPT", provider: "INE / eLearnSecurity" },
        { name: "CEH (Web track)", provider: "EC-Council" },
        { name: "API Security Architect", provider: "APIsec" },
        { name: "APISEC Certified Professional", provider: "APIsec University" },
        { name: "Certified Bug Bounty Hunter", provider: "HackerOne" },
        { name: "AWAE/OSWE Prep", provider: "OffSec" },
      ],
      Advanced: [
        { name: "OSWE", provider: "OffSec" },
        { name: "Burp Suite Certified Practitioner (BSCP)", provider: "PortSwigger" },
        { name: "eWPTX", provider: "INE / eLearnSecurity" },
        { name: "GWEB", provider: "SANS / GIAC" },
        { name: "CDSA", provider: "Hack The Box" },
        { name: "GWAPT Advanced", provider: "SANS / GIAC" },
        { name: "Real World Bug Bounty", provider: "PentesterLab" },
      ],
    },
  },
  {
    title: "Mobile Pentesting",
    description: "Android and iOS security testing certifications and mobile-specific training paths.",
    icon: <PhoneAndroidIcon sx={{ fontSize: 32 }} />,
    color: "#10b981",
    tracks: {
      Beginner: [
        { name: "OWASP MSTG / MASVS", provider: "OWASP" },
        { name: "Mobile Security Foundations", provider: "NowSecure Academy" },
        { name: "Mobile App Security Fundamentals", provider: "QA" },
      ],
      Intermediate: [
        { name: "eMAPT", provider: "INE / eLearnSecurity" },
        { name: "Mobile modules", provider: "Hack The Box" },
        { name: "Mobile Security Essentials", provider: "NowSecure Academy" },
        { name: "Android Security Internals", provider: "Pentester Academy" },
      ],
      Advanced: [
        { name: "GMOB", provider: "SANS / GIAC" },
        { name: "SEC575 Mobile Device Security", provider: "SANS" },
        { name: "Advanced Mobile Security", provider: "NowSecure Academy" },
        { name: "iOS App Pentesting", provider: "TCM Security" },
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
        { name: "eCRE", provider: "INE / eLearnSecurity" },
        { name: "Practical Malware Analysis and Triage (PMAT)", provider: "TCM Security" },
        { name: "Intro to Reverse Engineering", provider: "OpenSecurityTraining" },
        { name: "Malware Traffic Analysis", provider: "malware-traffic-analysis.net" },
        { name: "Reverse Engineering 101", provider: "Malware Unicorn" },
        { name: "Ghidra Basics", provider: "NSA / Ghidra" },
      ],
      Intermediate: [
        { name: "FOR610 Reverse Engineering Malware", provider: "SANS" },
        { name: "GREM", provider: "SANS / GIAC" },
        { name: "Malware Analysis Fundamentals", provider: "Mandiant" },
        { name: "eCMAP", provider: "INE / eLearnSecurity" },
        { name: "Advanced x86 Disassembly", provider: "OpenSecurityTraining" },
        { name: "IDA Pro Essentials", provider: "Hex-Rays" },
        { name: "Zero2Automated Malware Analysis", provider: "Zero2Automated" },
      ],
      Advanced: [
        { name: "FOR710 Advanced Reverse Engineering Malware", provider: "SANS" },
        { name: "Advanced Malware Analysis", provider: "Mandiant" },
        { name: "OSED", provider: "OffSec" },
        { name: "Android Malware Reverse Engineering", provider: "Pentester Academy" },
        { name: "Firmware Reverse Engineering", provider: "Attify" },
        { name: "Kernel Mode Rootkit Analysis", provider: "CrowdStrike" },
        { name: "GCTI (Cyber Threat Intelligence)", provider: "SANS / GIAC" },
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
        { name: "CHFI", provider: "EC-Council" },
        { name: "GCFE", provider: "SANS / GIAC" },
        { name: "Digital Forensics Fundamentals", provider: "QA" },
        { name: "Autopsy Basics and Hands-On", provider: "Basis Technology" },
        { name: "Computer Hacking Forensic Investigator", provider: "EC-Council" },
        { name: "Cyber Forensics Associate", provider: "IACIS" },
      ],
      Intermediate: [
        { name: "EnCE", provider: "OpenText" },
        { name: "CFCE", provider: "IACIS" },
        { name: "MCFE", provider: "Magnet Forensics" },
        { name: "ACE (AccessData Certified Examiner)", provider: "Exterro" },
        { name: "FOR500 Windows Forensics", provider: "SANS" },
        { name: "FOR508 Advanced Incident Response", provider: "SANS" },
        { name: "AXIOM Certified Examiner", provider: "Magnet Forensics" },
      ],
      Advanced: [
        { name: "GCFA", provider: "SANS / GIAC" },
        { name: "GNFA", provider: "SANS / GIAC" },
        { name: "GASF", provider: "SANS / GIAC" },
        { name: "X-Ways Forensics Training", provider: "X-Ways" },
        { name: "Cellebrite Certified Operator", provider: "Cellebrite" },
        { name: "FOR518 Mac/iOS Forensics", provider: "SANS" },
        { name: "FOR585 Advanced Smartphone Forensics", provider: "SANS" },
        { name: "GCFR (Cloud Forensics)", provider: "SANS / GIAC" },
      ],
    },
  },
  {
    title: "Incident Response and Blue Team",
    description: "Detection, incident handling, and response certifications for blue team roles.",
    icon: <LocalPoliceIcon sx={{ fontSize: 32 }} />,
    color: "#e11d48",
    tracks: {
      Beginner: [
        { name: "CySA+", provider: "CompTIA" },
        { name: "BTL1", provider: "Security Blue Team" },
        { name: "Incident Response Fundamentals", provider: "QA" },
        { name: "Splunk Core Certified User", provider: "Splunk" },
        { name: "LetsDefend SOC Analyst", provider: "LetsDefend" },
        { name: "TryHackMe SOC Level 1", provider: "TryHackMe" },
      ],
      Intermediate: [
        { name: "GCIH", provider: "SANS / GIAC" },
        { name: "ECIH", provider: "EC-Council" },
        { name: "SC-200", provider: "Microsoft" },
        { name: "BTL2", provider: "Security Blue Team" },
        { name: "Splunk Core Certified Power User", provider: "Splunk" },
        { name: "CrowdStrike Certified Falcon Administrator", provider: "CrowdStrike" },
        { name: "Carbon Black Certified Professional", provider: "VMware" },
        { name: "SentinelOne Certified Administrator", provider: "SentinelOne" },
      ],
      Advanced: [
        { name: "GCFA", provider: "SANS / GIAC" },
        { name: "GCED", provider: "SANS / GIAC" },
        { name: "CCIM", provider: "CREST" },
        { name: "Splunk Certified Architect", provider: "Splunk" },
        { name: "Elastic Certified Engineer", provider: "Elastic" },
        { name: "FOR508 Advanced Incident Response", provider: "SANS" },
        { name: "GRID (Intrusion Detection)", provider: "SANS / GIAC" },
      ],
    },
  },
  {
    title: "Security Operations (SOC)",
    description: "Security operations center certifications for analysts, engineers, and SOC leads.",
    icon: <AssessmentIcon sx={{ fontSize: 32 }} />,
    color: "#7c3aed",
    tracks: {
      Beginner: [
        { name: "CySA+", provider: "CompTIA" },
        { name: "SC-900 Security Fundamentals", provider: "Microsoft" },
        { name: "BTL1", provider: "Security Blue Team" },
        { name: "Splunk Core Certified User", provider: "Splunk" },
        { name: "SOC Analyst Level 1", provider: "Hack The Box" },
      ],
      Intermediate: [
        { name: "SC-200 Security Operations Analyst", provider: "Microsoft" },
        { name: "GCIH", provider: "SANS / GIAC" },
        { name: "CDSA", provider: "Hack The Box" },
        { name: "Splunk Core Certified Power User", provider: "Splunk" },
        { name: "Elastic Certified Analyst", provider: "Elastic" },
      ],
      Advanced: [
        { name: "GMON", provider: "SANS / GIAC" },
        { name: "GCED", provider: "SANS / GIAC" },
        { name: "SC-100 Cybersecurity Architect", provider: "Microsoft" },
        { name: "Splunk Enterprise Security Admin", provider: "Splunk" },
        { name: "Picus Security Validation Expert", provider: "Picus Security" },
      ],
    },
  },
  {
    title: "Cloud Security",
    description: "Cloud security certifications across AWS, Azure, and Google Cloud, plus vendor-neutral options.",
    icon: <CloudIcon sx={{ fontSize: 32 }} />,
    color: "#60a5fa",
    tracks: {
      Beginner: [
        { name: "AWS Cloud Practitioner", provider: "AWS" },
        { name: "SC-900", provider: "Microsoft" },
        { name: "Google Cloud Digital Leader", provider: "Google Cloud" },
        { name: "CCSK", provider: "Cloud Security Alliance" },
      ],
      Intermediate: [
        { name: "AWS Security Specialty", provider: "AWS" },
        { name: "AZ-500", provider: "Microsoft" },
        { name: "Professional Cloud Security Engineer", provider: "Google Cloud" },
        { name: "CKS (Certified Kubernetes Security)", provider: "CNCF" },
        { name: "Prisma Certified Cloud Security Engineer", provider: "Palo Alto Networks" },
      ],
      Advanced: [
        { name: "CCSP", provider: "ISC2" },
        { name: "SEC488 Cloud Security Essentials", provider: "SANS" },
        { name: "SEC549 Cloud Security Architecture", provider: "SANS" },
        { name: "GPCS", provider: "SANS / GIAC" },
        { name: "SC-100 Cybersecurity Architect", provider: "Microsoft" },
      ],
    },
  },
  {
    title: "AI and Machine Learning Security",
    description: "Emerging certifications for AI/ML security, adversarial ML, and AI governance.",
    icon: <PsychologyIcon sx={{ fontSize: 32 }} />,
    color: "#a855f7",
    tracks: {
      Beginner: [
        { name: "AI-900 Azure AI Fundamentals", provider: "Microsoft" },
        { name: "AWS AI Practitioner", provider: "AWS" },
        { name: "Google Cloud AI Fundamentals", provider: "Google Cloud" },
        { name: "Certified Artificial Intelligence Practitioner", provider: "CertNexus" },
      ],
      Intermediate: [
        { name: "AI-102 Azure AI Engineer", provider: "Microsoft" },
        { name: "AWS Machine Learning Engineer Associate", provider: "AWS" },
        { name: "Professional Machine Learning Engineer", provider: "Google Cloud" },
        { name: "Databricks Machine Learning Associate", provider: "Databricks" },
      ],
      Advanced: [
        { name: "AWS Machine Learning Specialty", provider: "AWS" },
        { name: "Databricks Machine Learning Professional", provider: "Databricks" },
        { name: "Certified Ethical Emerging Technologist", provider: "CertNexus" },
        { name: "AI Security Professional", provider: "ISACA", notes: "Emerging" },
      ],
    },
  },
  {
    title: "IT Project Management",
    description: "Project management and IT service management certifications for technical leaders.",
    icon: <BuildIcon sx={{ fontSize: 32 }} />,
    color: "#f59e0b",
    tracks: {
      Beginner: [
        { name: "ITIL 4 Foundation", provider: "ITIL / Axelos" },
        { name: "CompTIA Project+", provider: "CompTIA" },
        { name: "Certified ScrumMaster (CSM)", provider: "Scrum Alliance" },
        { name: "PMI-CAPM", provider: "PMI" },
      ],
      Intermediate: [
        { name: "PMP (Project Management Professional)", provider: "PMI" },
        { name: "ITIL 4 Managing Professional", provider: "ITIL / Axelos" },
        { name: "PMI-ACP (Agile Certified Practitioner)", provider: "PMI" },
        { name: "PRINCE2 Practitioner", provider: "Axelos" },
        { name: "Certified Scrum Product Owner (CSPO)", provider: "Scrum Alliance" },
      ],
      Advanced: [
        { name: "PMI-PgMP (Program Management Professional)", provider: "PMI" },
        { name: "ITIL 4 Strategic Leader", provider: "ITIL / Axelos" },
        { name: "ITIL 4 Master", provider: "ITIL / Axelos" },
        { name: "Certified Scrum Professional (CSP)", provider: "Scrum Alliance" },
        { name: "SAFe Program Consultant (SPC)", provider: "Scaled Agile" },
      ],
    },
  },
  {
    title: "GRC and Security Leadership",
    description: "Governance, risk, compliance, and leadership certifications for security management.",
    icon: <GavelIcon sx={{ fontSize: 32 }} />,
    color: "#facc15",
    tracks: {
      Beginner: [
        { name: "ISO 27001 Foundation", provider: "PECB" },
        { name: "Certified in Cybersecurity (CC)", provider: "ISC2" },
        { name: "Security+", provider: "CompTIA" },
        { name: "ITIL 4 Foundation", provider: "ITIL / Axelos" },
      ],
      Intermediate: [
        { name: "CISA", provider: "ISACA" },
        { name: "ISO 27001 Lead Implementer", provider: "PECB" },
        { name: "COBIT Foundation", provider: "ISACA" },
        { name: "CDPSE (Data Privacy)", provider: "ISACA" },
        { name: "ISO 27001 Lead Auditor", provider: "PECB" },
      ],
      Advanced: [
        { name: "CISSP", provider: "ISC2" },
        { name: "CISM", provider: "ISACA" },
        { name: "CRISC", provider: "ISACA" },
        { name: "CGEIT", provider: "ISACA" },
        { name: "CCISO", provider: "EC-Council" },
      ],
    },
  },
];

const CyberSecurityCertificationsPage: React.FC = () => {
  const navigate = useNavigate();

  const pageContext = `This page provides a comprehensive guide to cybersecurity certifications organized by domain. Domains covered include: General Security Foundations, Networking Fundamentals, System Administration (Windows and Linux), Cloud Computing (AWS, Azure, Google Cloud), DevOps and Site Reliability, Virtualization and Data Center, Database Administration, Penetration Testing and Red Team, Vulnerability Research and Exploit Development, Web Application Security and Bug Bounty, Mobile Pentesting, Reverse Engineering and Malware Analysis, Digital Forensics, Incident Response and Blue Team, Security Operations (SOC), Cloud Security, AI and Machine Learning Security, IT Project Management, and GRC and Security Leadership. Certifications are organized by beginner, intermediate, and advanced levels from providers like SANS/GIAC, CompTIA, OffSec, ISC2, ISACA, EC-Council, Hack The Box, and many others.`;

  return (
    <LearnPageLayout pageTitle="Cyber Security Certifications" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a12", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

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
            Cyber Security Certifications
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Curated paths by domain with beginner, intermediate, and advanced certification options.
        </Typography>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          {levelOrder.map((level) => (
            <Chip
              key={level}
              label={level}
              size="small"
              sx={{
                bgcolor: alpha(levelMeta[level].color, 0.15),
                color: levelMeta[level].color,
                fontWeight: 700,
              }}
            />
          ))}
        </Box>

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
                title: "Pick a domain",
                copy: "Choose the subject that matches your role goals or the work you are doing today.",
                color: "#38bdf8",
              },
              {
                title: "Match the level",
                copy: "Start with beginner certs, then progress to intermediate and advanced as you build depth.",
                color: "#22c55e",
              },
              {
                title: "Validate requirements",
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

        {subjects.map((subject, index) => (
          <Accordion
            key={subject.title}
            defaultExpanded={index === 0}
            sx={{
              mb: 2,
              bgcolor: "#0f1422",
              borderRadius: 2,
              border: `1px solid ${alpha(subject.color, 0.25)}`,
              "&:before": { display: "none" },
            }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: subject.color }} />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
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
                <Box>
                  <Typography variant="h6" sx={{ color: "grey.100", fontWeight: 700 }}>
                    {subject.title}
                  </Typography>
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
                            {item.notes && (
                              <Typography variant="caption" sx={{ color: "grey.500" }}>
                                {item.notes}
                              </Typography>
                            )}
                            {itemIndex < subject.tracks[level].length - 1 && (
                              <Divider sx={{ borderColor: "rgba(148,163,184,0.15)" }} />
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
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default CyberSecurityCertificationsPage;
