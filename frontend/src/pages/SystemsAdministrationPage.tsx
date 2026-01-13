import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  Chip,
  alpha,
  useTheme,
  useMediaQuery,
  Divider,
  Button,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Fab,
  Drawer,
  IconButton,
  Tooltip,
  LinearProgress,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import StorageIcon from "@mui/icons-material/Storage";
import DnsIcon from "@mui/icons-material/Dns";
import SecurityIcon from "@mui/icons-material/Security";
import BackupIcon from "@mui/icons-material/Backup";
import SettingsIcon from "@mui/icons-material/Settings";
import GroupIcon from "@mui/icons-material/Group";
import MonitorHeartIcon from "@mui/icons-material/MonitorHeart";
import BuildIcon from "@mui/icons-material/Build";
import TerminalIcon from "@mui/icons-material/Terminal";
import CloudIcon from "@mui/icons-material/Cloud";
import UpdateIcon from "@mui/icons-material/Update";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import LockIcon from "@mui/icons-material/Lock";
import DescriptionIcon from "@mui/icons-material/Description";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import WarningIcon from "@mui/icons-material/Warning";
import SchoolIcon from "@mui/icons-material/School";
import WorkIcon from "@mui/icons-material/Work";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import { Link, useNavigate } from "react-router-dom";

// ========== COURSE OUTLINE SECTIONS ==========
const outlineSections = [
  {
    id: "what-is-sysadmin",
    title: "What is Systems Administration?",
    icon: <DnsIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "The role, responsibilities, and importance of sysadmins in modern IT infrastructure",
  },
  {
    id: "server-hardware",
    title: "Server Hardware Fundamentals",
    icon: <StorageIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "Rack servers, blade servers, components, RAID configurations, and data center basics",
  },
  {
    id: "operating-systems",
    title: "Server Operating Systems",
    icon: <TerminalIcon />,
    color: "#22c55e",
    status: "Complete",
    description: "Windows Server vs Linux servers, installation, configuration, and management",
  },
  {
    id: "user-management",
    title: "User & Group Management",
    icon: <GroupIcon />,
    color: "#f59e0b",
    status: "Complete",
    description: "Creating users, groups, permissions, Active Directory, LDAP, and identity management",
  },
  {
    id: "networking-services",
    title: "Network Services",
    icon: <NetworkCheckIcon />,
    color: "#ef4444",
    status: "Complete",
    description: "DNS, DHCP, NTP, firewalls, load balancers, and network infrastructure",
  },
  {
    id: "storage-management",
    title: "Storage Management",
    icon: <StorageIcon />,
    color: "#6366f1",
    status: "Complete",
    description: "File systems, NAS, SAN, LVM, disk quotas, and storage best practices",
  },
  {
    id: "backup-recovery",
    title: "Backup & Disaster Recovery",
    icon: <BackupIcon />,
    color: "#0ea5e9",
    status: "Complete",
    description: "Backup strategies (3-2-1 rule), RPO/RTO, disaster recovery planning, and testing",
  },
  {
    id: "monitoring-logging",
    title: "Monitoring & Logging",
    icon: <MonitorHeartIcon />,
    color: "#ec4899",
    status: "Complete",
    description: "System monitoring, log management, alerting, SIEM basics, and performance metrics",
  },
  {
    id: "security-hardening",
    title: "Security & Hardening",
    icon: <LockIcon />,
    color: "#dc2626",
    status: "Complete",
    description: "Server hardening, patch management, security baselines, and compliance",
  },
  {
    id: "automation-scripting",
    title: "Automation & Scripting",
    icon: <AutorenewIcon />,
    color: "#10b981",
    status: "Complete",
    description: "Bash, PowerShell, configuration management (Ansible, Puppet), and IaC basics",
  },
  {
    id: "virtualization",
    title: "Virtualization & Containers",
    icon: <CloudIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "VMware, Hyper-V, KVM, Docker, Kubernetes fundamentals, and container orchestration",
  },
  {
    id: "web-services",
    title: "Web & Application Services",
    icon: <DnsIcon />,
    color: "#f97316",
    status: "Complete",
    description: "Web servers (Apache, Nginx, IIS), application servers, reverse proxies, and SSL/TLS",
  },
  {
    id: "database-admin",
    title: "Database Administration Basics",
    icon: <StorageIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "SQL vs NoSQL, basic DBA tasks, backups, performance tuning, and high availability",
  },
  {
    id: "documentation",
    title: "Documentation & Procedures",
    icon: <DescriptionIcon />,
    color: "#22c55e",
    status: "Complete",
    description: "Runbooks, SOPs, change management, knowledge bases, and documentation best practices",
  },
  {
    id: "troubleshooting",
    title: "Troubleshooting Methodology",
    icon: <BuildIcon />,
    color: "#f59e0b",
    status: "Complete",
    description: "Systematic troubleshooting, root cause analysis, diagnostic tools, and escalation",
  },
  {
    id: "career-certs",
    title: "Career Paths & Certifications",
    icon: <WorkIcon />,
    color: "#6366f1",
    status: "Complete",
    description: "CompTIA Server+, RHCSA/RHCE, MCSA, career progression, and specializations",
  },
];

// Quick stats for hero section
const quickStats = [
  { value: "16", label: "Topics", color: "#3b82f6" },
  { value: "24/7", label: "Uptime Goal", color: "#22c55e" },
  { value: "99.9%", label: "SLA Target", color: "#8b5cf6" },
  { value: "∞", label: "Coffee Required", color: "#f59e0b" },
];

const ACCENT_COLOR = "#3b82f6";
const QUIZ_QUESTION_COUNT = 10;

const selectRandomQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "What is the primary goal of systems administration?",
    options: [
      "Keep systems reliable and available",
      "Design user interfaces",
      "Write only application code",
      "Sell hardware and licenses",
    ],
    correctAnswer: 0,
    explanation: "Sysadmins focus on uptime, reliability, and operations.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "An SLA of 99.9% uptime allows about how much downtime per year?",
    options: ["About 8.8 hours", "About 1 hour", "About 1 day", "About 1 week"],
    correctAnswer: 0,
    explanation: "99.9% uptime equates to roughly 8.8 hours of downtime annually.",
  },
  {
    id: 3,
    topic: "Backup & DR",
    question: "RPO (Recovery Point Objective) is the:",
    options: [
      "Maximum acceptable data loss measured in time",
      "Time to restore service",
      "Number of backups stored",
      "Cost of downtime",
    ],
    correctAnswer: 0,
    explanation: "RPO defines how much data loss is acceptable in time.",
  },
  {
    id: 4,
    topic: "Backup & DR",
    question: "RTO (Recovery Time Objective) is the:",
    options: [
      "Target time to restore service after an outage",
      "Maximum data loss window",
      "Number of replicas required",
      "Time between backups",
    ],
    correctAnswer: 0,
    explanation: "RTO sets the time goal to bring services back online.",
  },
  {
    id: 5,
    topic: "Backup & DR",
    question: "The 3-2-1 backup rule means:",
    options: [
      "3 copies, 2 media types, 1 offsite copy",
      "3 backups per day, 2 per week, 1 per month",
      "3 servers, 2 switches, 1 firewall",
      "3 disks, 2 RAID cards, 1 spare",
    ],
    correctAnswer: 0,
    explanation: "3-2-1 ensures redundancy across media and location.",
  },
  {
    id: 6,
    topic: "Storage & Hardware",
    question: "RAID 1 provides:",
    options: ["Mirroring for redundancy", "Striping with no redundancy", "Parity across disks only", "A single disk volume"],
    correctAnswer: 0,
    explanation: "RAID 1 mirrors data to provide redundancy.",
  },
  {
    id: 7,
    topic: "Storage & Hardware",
    question: "RAID 5 can tolerate:",
    options: ["One disk failure", "Two disk failures", "No disk failures", "Only controller failure"],
    correctAnswer: 0,
    explanation: "RAID 5 uses parity and tolerates one disk failure.",
  },
  {
    id: 8,
    topic: "Storage & Hardware",
    question: "RAID 10 is best described as:",
    options: ["Stripe of mirrors", "Mirror of stripes", "Parity with striping", "Single large disk"],
    correctAnswer: 0,
    explanation: "RAID 10 combines striping and mirroring for performance and redundancy.",
  },
  {
    id: 9,
    topic: "Storage & Hardware",
    question: "RAID 0 provides:",
    options: ["No redundancy, improved performance", "Mirroring only", "Parity and mirroring", "Automatic backups"],
    correctAnswer: 0,
    explanation: "RAID 0 stripes data with no redundancy.",
  },
  {
    id: 10,
    topic: "Storage & Hardware",
    question: "ECC memory is used to:",
    options: ["Detect and correct memory errors", "Increase storage capacity", "Improve GPU performance", "Encrypt disks"],
    correctAnswer: 0,
    explanation: "ECC reduces the impact of memory errors.",
  },
  {
    id: 11,
    topic: "Storage & Hardware",
    question: "Hot-swappable drives allow you to:",
    options: [
      "Replace a drive without shutting down the server",
      "Increase CPU speed instantly",
      "Run containers faster",
      "Avoid backups",
    ],
    correctAnswer: 0,
    explanation: "Hot swap enables hardware replacement without downtime.",
  },
  {
    id: 12,
    topic: "Hardware",
    question: "A 1U rack unit is approximately:",
    options: ["1.75 inches tall", "1 inch tall", "2.5 inches tall", "4 inches tall"],
    correctAnswer: 0,
    explanation: "1U equals 1.75 inches in rack height.",
  },
  {
    id: 13,
    topic: "Identity & Access",
    question: "Active Directory is primarily used for:",
    options: ["Centralized authentication and management", "Web hosting", "DNS caching only", "Disk encryption"],
    correctAnswer: 0,
    explanation: "Active Directory centralizes identity and access control.",
  },
  {
    id: 14,
    topic: "Identity & Access",
    question: "LDAP is a protocol for:",
    options: ["Directory services and authentication", "File transfers", "Routing packets", "Web APIs"],
    correctAnswer: 0,
    explanation: "LDAP is commonly used for directory and auth services.",
  },
  {
    id: 15,
    topic: "Operating Systems",
    question: "The root user in Linux is:",
    options: ["The superuser with full privileges", "A standard user", "A guest account", "A read-only account"],
    correctAnswer: 0,
    explanation: "Root has unrestricted access to the system.",
  },
  {
    id: 16,
    topic: "Operating Systems",
    question: "The sudo command is used to:",
    options: ["Run commands with elevated privileges", "Create new disks", "Start the GUI", "Encrypt files automatically"],
    correctAnswer: 0,
    explanation: "sudo runs commands as another user, typically root.",
  },
  {
    id: 17,
    topic: "Operating Systems",
    question: "On systemd-based Linux systems, services are managed with:",
    options: ["systemctl", "init.d only", "taskmgr", "regedit"],
    correctAnswer: 0,
    explanation: "systemctl controls systemd services.",
  },
  {
    id: 18,
    topic: "Network Services",
    question: "DNS is responsible for:",
    options: ["Resolving names to IP addresses", "Assigning IPs to hosts", "Encrypting traffic", "Filtering spam"],
    correctAnswer: 0,
    explanation: "DNS maps human-friendly names to IP addresses.",
  },
  {
    id: 19,
    topic: "Network Services",
    question: "DHCP is responsible for:",
    options: ["Automatically assigning IP configuration", "Resolving hostnames", "Synchronizing time", "Logging events"],
    correctAnswer: 0,
    explanation: "DHCP assigns IP settings to clients.",
  },
  {
    id: 20,
    topic: "Network Services",
    question: "NTP is used to:",
    options: ["Synchronize system clocks", "Route network packets", "Back up files", "Compress logs"],
    correctAnswer: 0,
    explanation: "NTP keeps system time in sync.",
  },
  {
    id: 21,
    topic: "Network Services",
    question: "A load balancer:",
    options: ["Distributes traffic across servers", "Stores backups", "Manages user accounts", "Provides disk parity"],
    correctAnswer: 0,
    explanation: "Load balancers spread traffic for availability and scale.",
  },
  {
    id: 22,
    topic: "Network Services",
    question: "A firewall is used to:",
    options: ["Allow or block network traffic", "Detect malware signatures only", "Provide DNS resolution", "Balance CPU load"],
    correctAnswer: 0,
    explanation: "Firewalls enforce network access rules.",
  },
  {
    id: 23,
    topic: "Network Services",
    question: "A VLAN is used to:",
    options: ["Segment networks logically", "Encrypt data at rest", "Create backups", "Increase disk speed"],
    correctAnswer: 0,
    explanation: "VLANs separate traffic at the network layer.",
  },
  {
    id: 24,
    topic: "Storage",
    question: "NAS typically provides:",
    options: ["File-level storage over the network", "Block-level storage only", "Local-only storage", "GPU acceleration"],
    correctAnswer: 0,
    explanation: "NAS exposes shared files over the network.",
  },
  {
    id: 25,
    topic: "Storage",
    question: "LVM allows you to:",
    options: ["Resize and manage logical volumes flexibly", "Disable file permissions", "Replace CPUs live", "Create DNS zones"],
    correctAnswer: 0,
    explanation: "LVM adds flexible volume management.",
  },
  {
    id: 26,
    topic: "Storage",
    question: "NTFS is a filesystem commonly used by:",
    options: ["Windows", "Linux only", "macOS only", "Network switches"],
    correctAnswer: 0,
    explanation: "NTFS is the default filesystem for Windows.",
  },
  {
    id: 27,
    topic: "Storage",
    question: "ext4 is a filesystem commonly used by:",
    options: ["Linux", "Windows only", "macOS only", "Routers"],
    correctAnswer: 0,
    explanation: "ext4 is a common Linux filesystem.",
  },
  {
    id: 28,
    topic: "Storage",
    question: "iSCSI is primarily used for:",
    options: ["Block storage over IP networks", "File sharing over SMB", "Email transfer", "VPN tunneling only"],
    correctAnswer: 0,
    explanation: "iSCSI carries block storage over IP.",
  },
  {
    id: 29,
    topic: "Monitoring",
    question: "Which is an example of a metric?",
    options: ["CPU utilization percentage", "System event log", "Audit log entry", "Email body"],
    correctAnswer: 0,
    explanation: "Metrics are numeric measurements like CPU usage.",
  },
  {
    id: 30,
    topic: "Monitoring",
    question: "A SIEM is used to:",
    options: ["Aggregate and analyze security logs", "Provision VMs", "Manage DNS zones", "Run backups only"],
    correctAnswer: 0,
    explanation: "SIEMs collect and analyze security events.",
  },
  {
    id: 31,
    topic: "Monitoring",
    question: "SNMP is commonly used for:",
    options: ["Monitoring network devices", "Encrypting disks", "Deploying containers", "Managing user groups"],
    correctAnswer: 0,
    explanation: "SNMP provides monitoring for network equipment.",
  },
  {
    id: 32,
    topic: "Monitoring",
    question: "Log rotation helps prevent:",
    options: ["Disks filling up from log files", "User logins", "CPU spikes", "Network latency"],
    correctAnswer: 0,
    explanation: "Rotation controls log growth and disk usage.",
  },
  {
    id: 33,
    topic: "Monitoring",
    question: "A good way to reduce alert fatigue is to:",
    options: ["Tune alerts and remove noisy rules", "Disable all monitoring", "Send every alert to everyone", "Ignore false positives"],
    correctAnswer: 0,
    explanation: "Alert tuning focuses attention on meaningful signals.",
  },
  {
    id: 34,
    topic: "Security",
    question: "Least privilege means:",
    options: ["Users get only the access they need", "All users are admins", "Access is never reviewed", "Permissions are shared broadly"],
    correctAnswer: 0,
    explanation: "Least privilege limits access to reduce risk.",
  },
  {
    id: 35,
    topic: "Security",
    question: "MFA improves security by:",
    options: ["Requiring a second verification factor", "Doubling CPU cores", "Encrypting RAM", "Stopping backups"],
    correctAnswer: 0,
    explanation: "MFA adds another layer beyond passwords.",
  },
  {
    id: 36,
    topic: "Security",
    question: "Patch management is important because it:",
    options: ["Fixes vulnerabilities and bugs", "Increases storage size", "Replaces hardware", "Disables logging"],
    correctAnswer: 0,
    explanation: "Patching removes known weaknesses and issues.",
  },
  {
    id: 37,
    topic: "Security",
    question: "A security baseline is:",
    options: ["A standard configuration used to harden systems", "A backup schedule", "A monitoring dashboard", "A network cable type"],
    correctAnswer: 0,
    explanation: "Baselines define secure default configurations.",
  },
  {
    id: 38,
    topic: "Security",
    question: "Defense in depth means:",
    options: ["Using multiple layers of security controls", "Only a firewall", "Only antivirus", "Only encryption"],
    correctAnswer: 0,
    explanation: "Multiple layers reduce single points of failure.",
  },
  {
    id: 39,
    topic: "Automation",
    question: "Ansible is known for being:",
    options: ["Agentless and push-based", "Agent-only and pull-based", "A database engine", "A hypervisor"],
    correctAnswer: 0,
    explanation: "Ansible uses SSH and pushes configuration without agents.",
  },
  {
    id: 40,
    topic: "Automation",
    question: "Puppet typically works by:",
    options: ["Using agents to pull configuration", "Running only in browsers", "Managing DNS only", "Providing backup storage"],
    correctAnswer: 0,
    explanation: "Puppet agents pull configuration from the master.",
  },
  {
    id: 41,
    topic: "Automation",
    question: "Infrastructure as Code is best stored in:",
    options: ["Version control", "A printer", "Email threads", "Temporary folders"],
    correctAnswer: 0,
    explanation: "IaC should be versioned like software.",
  },
  {
    id: 42,
    topic: "Automation",
    question: "PowerShell is primarily used for:",
    options: ["Windows automation and scripting", "GPU programming", "Web design", "Database replication"],
    correctAnswer: 0,
    explanation: "PowerShell automates Windows administration.",
  },
  {
    id: 43,
    topic: "Automation",
    question: "Cron is used to:",
    options: ["Schedule recurring tasks on Unix-like systems", "Manage DNS caches", "Start GUI sessions", "Encrypt disks"],
    correctAnswer: 0,
    explanation: "Cron schedules recurring jobs on Unix-like systems.",
  },
  {
    id: 44,
    topic: "Automation",
    question: "Windows Task Scheduler is used to:",
    options: ["Schedule jobs and scripts", "Manage RAID arrays", "Create DNS records", "Run containers"],
    correctAnswer: 0,
    explanation: "Task Scheduler runs tasks at scheduled times.",
  },
  {
    id: 45,
    topic: "Virtualization",
    question: "A Type 1 hypervisor runs:",
    options: ["Directly on hardware", "Inside a guest VM", "Only on a router", "Only with containers"],
    correctAnswer: 0,
    explanation: "Type 1 hypervisors run on bare metal.",
  },
  {
    id: 46,
    topic: "Virtualization",
    question: "A VM snapshot is:",
    options: ["A point-in-time copy of a VM state", "A live migration", "A backup tape", "A disk format"],
    correctAnswer: 0,
    explanation: "Snapshots capture the VM state at a point in time.",
  },
  {
    id: 47,
    topic: "Containers",
    question: "Containers differ from VMs because they:",
    options: ["Share the host OS kernel", "Require separate hardware", "Cannot be moved", "Only run Windows"],
    correctAnswer: 0,
    explanation: "Containers share the host kernel for efficiency.",
  },
  {
    id: 48,
    topic: "Containers",
    question: "Kubernetes is used to:",
    options: ["Orchestrate and scale containers", "Manage RAID arrays", "Provide DNS only", "Encrypt backups"],
    correctAnswer: 0,
    explanation: "Kubernetes manages container deployment and scaling.",
  },
  {
    id: 49,
    topic: "Containers",
    question: "A Docker image is:",
    options: ["A template for creating containers", "A running container", "A VM snapshot", "A backup schedule"],
    correctAnswer: 0,
    explanation: "Images are templates for container instances.",
  },
  {
    id: 50,
    topic: "Web Services",
    question: "HTTPS provides security using:",
    options: ["TLS encryption", "DNS caching", "DHCP leases", "NTP sync"],
    correctAnswer: 0,
    explanation: "HTTPS secures traffic using TLS.",
  },
  {
    id: 51,
    topic: "Web Services",
    question: "A reverse proxy:",
    options: ["Sits in front of servers and forwards requests", "Runs only on desktops", "Creates backups", "Stores passwords"],
    correctAnswer: 0,
    explanation: "Reverse proxies front-end services and route requests.",
  },
  {
    id: 52,
    topic: "Web Services",
    question: "Apache and Nginx are:",
    options: ["Web servers", "Database engines", "Hypervisors", "DNS clients"],
    correctAnswer: 0,
    explanation: "Apache and Nginx are common web servers.",
  },
  {
    id: 53,
    topic: "Web Services",
    question: "IIS is a web server on:",
    options: ["Windows", "Linux only", "macOS only", "Network switches"],
    correctAnswer: 0,
    explanation: "IIS is Microsoft's web server for Windows.",
  },
  {
    id: 54,
    topic: "Databases",
    question: "SQL databases typically use:",
    options: ["Structured schemas and tables", "Only key-value pairs", "Only files", "No queries"],
    correctAnswer: 0,
    explanation: "SQL databases use tables with defined schemas.",
  },
  {
    id: 55,
    topic: "Databases",
    question: "In ACID, Atomicity means:",
    options: ["Transactions are all-or-nothing", "Transactions are fast", "Data is encrypted", "Queries are cached"],
    correctAnswer: 0,
    explanation: "Atomicity ensures full success or full rollback.",
  },
  {
    id: 56,
    topic: "Backup & DR",
    question: "A differential backup includes changes:",
    options: ["Since the last full backup", "Since the last incremental backup", "From all time", "Only from today"],
    correctAnswer: 0,
    explanation: "Differential backups capture changes since the last full backup.",
  },
  {
    id: 57,
    topic: "Documentation",
    question: "A runbook is:",
    options: ["Step-by-step operational instructions", "A hardware inventory", "A DNS zone file", "A container image"],
    correctAnswer: 0,
    explanation: "Runbooks describe procedures for operations.",
  },
  {
    id: 58,
    topic: "Change Management",
    question: "Change management often uses:",
    options: ["Maintenance windows", "Always-on changes with no notice", "No approvals", "No documentation"],
    correctAnswer: 0,
    explanation: "Maintenance windows reduce risk during changes.",
  },
  {
    id: 59,
    topic: "Operations",
    question: "A ticketing system is used to:",
    options: ["Track work requests and incidents", "Store backups", "Run antivirus scans", "Load balance traffic"],
    correctAnswer: 0,
    explanation: "Tickets track work and incidents for accountability.",
  },
  {
    id: 60,
    topic: "Operations",
    question: "A post-incident review helps teams:",
    options: ["Learn and prevent future issues", "Avoid logging", "Increase downtime", "Delete evidence"],
    correctAnswer: 0,
    explanation: "Postmortems capture lessons and improvements.",
  },
  {
    id: 61,
    topic: "Troubleshooting",
    question: "A good first troubleshooting step is to:",
    options: ["Identify and define the problem", "Reinstall the OS immediately", "Ignore user reports", "Change multiple things at once"],
    correctAnswer: 0,
    explanation: "Clear problem definition guides efficient troubleshooting.",
  },
  {
    id: 62,
    topic: "Troubleshooting",
    question: "The ping command is used to:",
    options: ["Test basic network connectivity", "List running processes", "Create user accounts", "Rotate logs"],
    correctAnswer: 0,
    explanation: "Ping checks reachability and latency.",
  },
  {
    id: 63,
    topic: "Troubleshooting",
    question: "Traceroute (tracert) is used to:",
    options: ["Show the path packets take across the network", "Change DNS zones", "Encrypt traffic", "Mount disks"],
    correctAnswer: 0,
    explanation: "Traceroute shows each hop along a network path.",
  },
  {
    id: 64,
    topic: "Troubleshooting",
    question: "netstat is commonly used to:",
    options: ["View network connections and listening ports", "Edit files", "Compress logs", "Schedule tasks"],
    correctAnswer: 0,
    explanation: "netstat lists active connections and ports.",
  },
  {
    id: 65,
    topic: "Network Services",
    question: "SSH typically uses port:",
    options: ["22", "25", "80", "443"],
    correctAnswer: 0,
    explanation: "SSH default port is 22.",
  },
  {
    id: 66,
    topic: "Network Services",
    question: "RDP typically uses port:",
    options: ["3389", "22", "53", "161"],
    correctAnswer: 0,
    explanation: "RDP default port is 3389.",
  },
  {
    id: 67,
    topic: "Monitoring",
    question: "Syslog is:",
    options: ["A standard for logging messages", "A firewall rule", "A backup appliance", "A filesystem"],
    correctAnswer: 0,
    explanation: "Syslog standardizes logging formats and transport.",
  },
  {
    id: 68,
    topic: "Identity & Access",
    question: "Centralized authentication (AD/LDAP) helps by:",
    options: ["Managing users in one place", "Eliminating passwords entirely", "Replacing backups", "Speeding up storage"],
    correctAnswer: 0,
    explanation: "Centralized identity simplifies access control.",
  },
  {
    id: 69,
    topic: "Backup & DR",
    question: "Backups should be tested to ensure:",
    options: ["They can be restored successfully", "They never change", "They use more CPU", "They are always incremental"],
    correctAnswer: 0,
    explanation: "Only tested backups are reliable.",
  },
  {
    id: 70,
    topic: "Capacity Planning",
    question: "Capacity planning involves:",
    options: ["Forecasting resource growth and needs", "Disabling monitoring", "Removing logs", "Avoiding upgrades"],
    correctAnswer: 0,
    explanation: "Planning keeps infrastructure ahead of demand.",
  },
  {
    id: 71,
    topic: "Availability",
    question: "High availability is achieved through:",
    options: ["Redundancy and failover", "Single points of failure", "Manual recovery only", "No monitoring"],
    correctAnswer: 0,
    explanation: "Redundancy and failover reduce downtime.",
  },
  {
    id: 72,
    topic: "Hardware",
    question: "A UPS provides:",
    options: ["Battery backup power", "Network routing", "Disk encryption", "CPU scheduling"],
    correctAnswer: 0,
    explanation: "UPS systems keep equipment powered during outages.",
  },
  {
    id: 73,
    topic: "Security",
    question: "RBAC stands for:",
    options: ["Role-Based Access Control", "Remote Backup and Cache", "Rapid Build and Configure", "Routing Between Access Circuits"],
    correctAnswer: 0,
    explanation: "RBAC assigns permissions based on roles.",
  },
  {
    id: 74,
    topic: "Availability",
    question: "Clustering is commonly used for:",
    options: ["Failover and high availability", "Encrypting files", "User training", "DNS resolution"],
    correctAnswer: 0,
    explanation: "Clusters provide redundancy and failover.",
  },
  {
    id: 75,
    topic: "Security",
    question: "A service account should generally be:",
    options: ["Non-interactive with least-privilege access", "Shared by all users", "Used for email", "Given domain admin by default"],
    correctAnswer: 0,
    explanation: "Service accounts should be scoped and non-interactive.",
  },
];


export default function SystemsAdministrationPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");

  // Module navigation items
  const moduleNavItems = [
    { id: "what-is-sysadmin", label: "What is SysAdmin?", icon: "🖥️" },
    { id: "server-hardware", label: "Server Hardware", icon: "🔧" },
    { id: "operating-systems", label: "Server OS", icon: "💻" },
    { id: "user-management", label: "User Management", icon: "👥" },
    { id: "networking-services", label: "Network Services", icon: "🌐" },
    { id: "storage-management", label: "Storage", icon: "💾" },
    { id: "backup-recovery", label: "Backup & DR", icon: "🔄" },
    { id: "monitoring-logging", label: "Monitoring", icon: "📊" },
    { id: "security-hardening", label: "Security", icon: "🔒" },
    { id: "automation-scripting", label: "Automation", icon: "⚙️" },
    { id: "virtualization", label: "Virtualization", icon: "☁️" },
    { id: "web-services", label: "Web Services", icon: "🌍" },
    { id: "database-admin", label: "Database Admin", icon: "🗃️" },
    { id: "documentation", label: "Documentation", icon: "📝" },
    { id: "troubleshooting", label: "Troubleshooting", icon: "🔍" },
    { id: "career-certs", label: "Career & Certs", icon: "🎓" },
    { id: "quiz", label: "Quiz", icon: "❓" },
  ];

  // Scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

  // Track active section on scroll
  useEffect(() => {
    const handleScroll = () => {
      const sections = moduleNavItems.map(item => item.id);
      let currentSection = "";
      
      for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150) {
            currentSection = sectionId;
          }
        }
      }
      setActiveSection(currentSection);
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll(); // Initial check
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Scroll to top helper
  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  // Calculate progress based on active section
  const currentIndex = moduleNavItems.findIndex(item => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / moduleNavItems.length) * 100 : 0;

  // Desktop sidebar navigation component
  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        width: 220,
        flexShrink: 0,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        borderRadius: 3,
        border: `1px solid ${alpha(ACCENT_COLOR, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(ACCENT_COLOR, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: ACCENT_COLOR, display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: ACCENT_COLOR }}>{Math.round(progressPercent)}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(ACCENT_COLOR, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: ACCENT_COLOR,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {moduleNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(ACCENT_COLOR, 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? ACCENT_COLOR : "text.secondary",
                      fontSize: "0.75rem",
                    }}
                  >
                    {item.label}
                  </Typography>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );

  const pageContext = `Systems Administration comprehensive guide covering server management, infrastructure, and IT operations. Topics include: server hardware (rack/blade servers, RAID, data centers), server operating systems (Windows Server, Linux), user and group management (Active Directory, LDAP), network services (DNS, DHCP, firewalls), storage management (NAS, SAN, LVM), backup and disaster recovery (3-2-1 rule, RPO/RTO), monitoring and logging (SIEM, alerting), security hardening (patching, baselines), automation (Ansible, PowerShell, Bash), virtualization (VMware, Hyper-V, Docker, Kubernetes), web services (Apache, Nginx, IIS, SSL/TLS), database administration, documentation best practices, troubleshooting methodology, and career certifications (CompTIA Server+, RHCSA, MCSA).`;

  return (
    <LearnPageLayout pageTitle="Systems Administration" pageContext={pageContext}>
      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Navigate Sections" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            zIndex: 1000,
            bgcolor: ACCENT_COLOR,
            "&:hover": { bgcolor: "#2563eb" },
            boxShadow: `0 4px 20px ${alpha(ACCENT_COLOR, 0.4)}`,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Top Button - Mobile Only */}
      <Tooltip title="Scroll to Top" placement="left">
        <Fab
          size="small"
          onClick={scrollToTop}
          sx={{
            position: "fixed",
            bottom: 32,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha(ACCENT_COLOR, 0.15),
            color: ACCENT_COLOR,
            "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Tooltip>

      {/* Navigation Drawer - Mobile */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: isMobile ? "85%" : 320,
            bgcolor: theme.palette.background.paper,
            backgroundImage: "none",
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: ACCENT_COLOR }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>
          
          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(ACCENT_COLOR, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">Progress</Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: ACCENT_COLOR }}>{Math.round(progressPercent)}%</Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(ACCENT_COLOR, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: ACCENT_COLOR,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {moduleNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(ACCENT_COLOR, 0.1),
                  },
                  transition: "all 0.2s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? ACCENT_COLOR : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
                {activeSection === item.id && (
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha(ACCENT_COLOR, 0.2),
                      color: ACCENT_COLOR,
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          {/* Quick Actions */}
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha(ACCENT_COLOR, 0.3), color: ACCENT_COLOR }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(ACCENT_COLOR, 0.3), color: ACCENT_COLOR }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {/* Desktop Sidebar */}
        {sidebarNav}

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
        {/* Back Button */}
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2, mb: 3 }}
        />

        {/* Hero Banner */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.15)} 0%, ${alpha("#8b5cf6", 0.15)} 50%, ${alpha("#22c55e", 0.15)} 100%)`,
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          {/* Decorative elements */}
          <Box
            sx={{
              position: "absolute",
              top: -50,
              right: -50,
              width: 200,
              height: 200,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#3b82f6", 0.1)} 0%, transparent 70%)`,
            }}
          />
          <Box
            sx={{
              position: "absolute",
              bottom: -30,
              left: "30%",
              width: 150,
              height: 150,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#22c55e", 0.1)} 0%, transparent 70%)`,
            }}
          />

          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, #3b82f6, #8b5cf6)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#3b82f6", 0.3)}`,
                }}
              >
                <DnsIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Systems Administration
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  The backbone of IT infrastructure — keeping servers running 24/7
                </Typography>
              </Box>
            </Box>

            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="IT Fundamentals" color="primary" />
              <Chip label="Servers" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
              <Chip label="Infrastructure" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
              <Chip label="Operations" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
              <Chip label="DevOps Ready" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 600 }} />
            </Box>

            {/* Quick Stats */}
            <Grid container spacing={2}>
              {quickStats.map((stat) => (
                <Grid item xs={6} sm={3} key={stat.label}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      borderRadius: 2,
                      bgcolor: alpha(stat.color, 0.1),
                      border: `1px solid ${alpha(stat.color, 0.2)}`,
                    }}
                  >
                    <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                      {stat.value}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                      {stat.label}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>

        {/* ==================== COURSE OUTLINE (Moved to top) ==================== */}
        <Box id="outline" sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, scrollMarginTop: 80 }}>
          <Typography variant="h4" sx={{ fontWeight: 800 }}>
            📚 Course Outline
          </Typography>
          <Chip label={`${outlineSections.length} Sections`} size="small" color="primary" variant="outlined" />
        </Box>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {outlineSections.map((section, index) => (
            <Grid item xs={12} sm={6} md={4} key={section.id}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 3,
                  border: `1px solid ${alpha(section.color, 0.2)}`,
                  cursor: section.status === "Complete" ? "pointer" : "default",
                  transition: "all 0.2s",
                  "&:hover": section.status === "Complete" ? {
                    borderColor: section.color,
                    transform: "translateY(-2px)",
                    boxShadow: `0 4px 12px ${alpha(section.color, 0.15)}`,
                  } : {},
                }}
                onClick={() => {
                  if (section.status === "Complete") {
                    document.getElementById(section.id)?.scrollIntoView({ behavior: "smooth" });
                  }
                }}
              >
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                  <Box sx={{ 
                    p: 1, 
                    borderRadius: 2, 
                    bgcolor: alpha(section.color, 0.1),
                    color: section.color,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}>
                    {section.icon}
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5, flexWrap: "wrap" }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary" }}>
                        {String(index + 1).padStart(2, "0")}
                      </Typography>
                      <Chip
                        label={section.status}
                        size="small"
                        icon={section.status === "Complete" ? <CheckCircleIcon sx={{ fontSize: 14 }} /> : <RadioButtonUncheckedIcon sx={{ fontSize: 14 }} />}
                        sx={{
                          fontSize: "0.6rem",
                          height: 20,
                          bgcolor: section.status === "Complete" ? alpha("#10b981", 0.1) : alpha("#6b7280", 0.1),
                          color: section.status === "Complete" ? "#10b981" : "#6b7280",
                          "& .MuiChip-icon": {
                            color: section.status === "Complete" ? "#10b981" : "#6b7280",
                          },
                        }}
                      />
                    </Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5, lineHeight: 1.3 }}>
                      {section.title}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1.4 }}>
                      {section.description}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== WHAT IS SYSTEMS ADMINISTRATION ==================== */}
        <Typography id="what-is-sysadmin" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🖥️ What is Systems Administration?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding the role that keeps businesses running
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Systems Administration</strong> (or <strong>sysadmin</strong>) is the field of IT responsible for 
            maintaining, configuring, and ensuring the reliable operation of computer systems — particularly servers. 
            A systems administrator is the guardian of an organization's IT infrastructure, ensuring that email flows, 
            databases respond, websites stay online, and users can log in every morning.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            Unlike desktop support which focuses on end-user devices, sysadmins work with the <strong>backend infrastructure</strong> 
            that powers business operations: physical and virtual servers, storage systems, network services, authentication 
            systems, and the countless services that modern organizations depend on. When everything works perfectly, 
            no one notices the sysadmin; when something breaks at 3 AM, they're the ones getting paged.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Systems administration sits at the intersection of <strong>hardware, software, networking, and security</strong>. 
            A good sysadmin needs broad knowledge across all these domains, plus the ability to troubleshoot problems 
            under pressure, automate repetitive tasks, and document everything for the next person (or their future self). 
            It's a role that has evolved significantly with cloud computing, DevOps practices, and infrastructure-as-code, 
            but the core mission remains the same: <strong>keep the systems running</strong>.
          </Typography>
        </Paper>

        {/* The Sysadmin's Mission */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon /> The Sysadmin's Core Mission
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Availability</Typography>
              <Typography variant="body2" color="text.secondary">
                Keep systems running 24/7. Minimize downtime. Meet SLA commitments. Every minute of outage costs money 
                and reputation.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Reliability</Typography>
              <Typography variant="body2" color="text.secondary">
                Ensure systems perform consistently. Prevent failures before they happen. Build redundancy. Plan for 
                the worst while hoping for the best.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Security</Typography>
              <Typography variant="body2" color="text.secondary">
                Protect systems from threats. Apply patches promptly. Implement least-privilege access. Security is 
                everyone's job, but sysadmins are the first line.
              </Typography>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== CORE RESPONSIBILITIES ==================== */}
        <Typography id="responsibilities" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📋 Core Responsibilities
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          What sysadmins actually do day-to-day
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6", display: "flex", alignItems: "center", gap: 1 }}>
                <DnsIcon /> Server Management
              </Typography>
              <List dense>
                {[
                  "Installing and configuring server operating systems",
                  "Managing physical and virtual servers",
                  "Capacity planning and resource allocation",
                  "Performance tuning and optimization",
                  "Server lifecycle management (build, maintain, retire)",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
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
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
                <GroupIcon /> User & Access Management
              </Typography>
              <List dense>
                {[
                  "Creating and managing user accounts",
                  "Configuring groups and permissions",
                  "Managing Active Directory / LDAP",
                  "Implementing access control policies",
                  "Password policies and MFA setup",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
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
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
                <BackupIcon /> Backup & Recovery
              </Typography>
              <List dense>
                {[
                  "Designing backup strategies (full, incremental, differential)",
                  "Testing restore procedures regularly",
                  "Managing backup schedules and retention",
                  "Disaster recovery planning and documentation",
                  "Ensuring compliance with data retention policies",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
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
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
                <MonitorHeartIcon /> Monitoring & Maintenance
              </Typography>
              <List dense>
                {[
                  "Setting up monitoring and alerting systems",
                  "Reviewing logs and system health metrics",
                  "Applying patches and updates",
                  "Performing routine maintenance tasks",
                  "Responding to incidents and outages",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
                <LockIcon /> Security & Compliance
              </Typography>
              <List dense>
                {[
                  "Hardening servers and services",
                  "Managing firewalls and security groups",
                  "Implementing security baselines",
                  "Audit logging and compliance reporting",
                  "Vulnerability scanning and remediation",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9", display: "flex", alignItems: "center", gap: 1 }}>
                <AutorenewIcon /> Automation & Documentation
              </Typography>
              <List dense>
                {[
                  "Writing scripts to automate repetitive tasks",
                  "Implementing configuration management",
                  "Creating and maintaining runbooks",
                  "Documenting systems and procedures",
                  "Knowledge base management",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#0ea5e9" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== A DAY IN THE LIFE ==================== */}
        <Typography id="daily-tasks" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          ☀️ A Day in the Life
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          What a typical sysadmin's day looks like
        </Typography>

        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
          <Grid container spacing={3}>
            {[
              { time: "8:00 AM", task: "Check overnight alerts, review monitoring dashboards, and catch up on emails", icon: "☕" },
              { time: "9:00 AM", task: "Morning standup, review tickets, prioritize work for the day", icon: "📋" },
              { time: "10:00 AM", task: "Work on planned changes: server builds, updates, configuration changes", icon: "🔧" },
              { time: "12:00 PM", task: "Lunch (or what passes for it between tickets)", icon: "🍕" },
              { time: "1:00 PM", task: "Handle user requests, troubleshoot issues, respond to incidents", icon: "🎫" },
              { time: "3:00 PM", task: "Documentation, automation scripts, proactive improvements", icon: "📝" },
              { time: "5:00 PM", task: "Handoff notes, schedule after-hours changes, set up monitoring for overnight", icon: "🌙" },
              { time: "3:00 AM", task: "Get paged because something broke (hopefully rare!)", icon: "📟" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.time}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ mb: 1 }}>{item.icon}</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>{item.time}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.task}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== WINDOWS VS LINUX ==================== */}
        <Typography id="windows-vs-linux" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🪟 vs 🐧 Windows Server vs Linux
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The two major server operating system ecosystems
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0078d4" }}>
                🪟 Windows Server
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Microsoft's server OS, dominant in enterprise environments. GUI-focused but PowerShell is increasingly 
                essential. Tight integration with Active Directory, Exchange, and Microsoft ecosystem.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Key Technologies:</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                {["Active Directory", "Group Policy", "IIS", "Hyper-V", "PowerShell", "WSUS", "SQL Server"].map((tech) => (
                  <Chip key={tech} label={tech} size="small" variant="outlined" />
                ))}
              </Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Best For:</Typography>
              <Typography variant="body2" color="text.secondary">
                Enterprise environments, Microsoft-centric shops, .NET applications, file/print services, 
                organizations using Microsoft 365
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
                🐧 Linux (RHEL, Ubuntu, Debian, etc.)
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Open-source, command-line focused, dominant in cloud and web hosting. More flexible but steeper 
                learning curve. Powers most of the internet's infrastructure.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Key Technologies:</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                {["Bash/Shell", "systemd", "Apache/Nginx", "Docker", "Ansible", "SSH", "MySQL/PostgreSQL"].map((tech) => (
                  <Chip key={tech} label={tech} size="small" variant="outlined" />
                ))}
              </Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Best For:</Typography>
              <Typography variant="body2" color="text.secondary">
                Web servers, cloud infrastructure, containers/Kubernetes, DevOps environments, 
                cost-sensitive deployments, open-source stacks
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon /> Pro Tip: Learn Both
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
            Most organizations use a mix of Windows and Linux. Being proficient in both dramatically increases your 
            value and job opportunities. Start with whichever is most relevant to your current or target job, 
            then expand. The concepts (users, permissions, services, networking) transfer between platforms - 
            only the specific commands and tools differ.
          </Typography>
        </Paper>

        {/* Sysadmin Skill Stack */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6", display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon /> Sysadmin Skill Stack
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Technical Foundation</Typography>
              <List dense>
                {[
                  "Linux and Windows administration",
                  "Networking fundamentals (DNS, DHCP, TCP/IP)",
                  "Storage, backups, and data protection",
                  "Security hardening and patching",
                  "Scripting and automation basics",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Operational Discipline</Typography>
              <List dense>
                {[
                  "Monitoring and alerting strategy",
                  "Change management and approvals",
                  "Incident response and RCA",
                  "Documentation and runbooks",
                  "Capacity planning and budgeting",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>People and Business</Typography>
              <List dense>
                {[
                  "Clear status updates under pressure",
                  "Translate risk into business impact",
                  "Vendor and contract coordination",
                  "Prioritization across stakeholders",
                  "On-call communication etiquette",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 2: SERVER HARDWARE FUNDAMENTALS ==================== */}
        <Typography id="server-hardware" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🖥️ Server Hardware Fundamentals
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding the physical foundation of IT infrastructure
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Server hardware</strong> differs significantly from desktop computers. Servers are designed for 
            <strong> reliability, redundancy, and 24/7 operation</strong> — not for running games or word processors. 
            They're built to handle multiple simultaneous users, process large amounts of data, and keep running 
            even when components fail. Understanding server hardware is essential because hardware decisions directly 
            impact performance, reliability, and cost.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            Modern servers come in several <strong>form factors</strong>. <strong>Rack-mounted servers</strong> (1U, 2U, 4U) 
            are the most common in data centers, designed to stack in standard 19-inch equipment racks. 
            <strong> Tower servers</strong> look like large desktop PCs and are common in small offices. 
            <strong> Blade servers</strong> are thin, modular units that slide into a chassis, sharing power and cooling 
            for maximum density. Each form factor has trade-offs between density, expandability, and cost.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Servers are typically found in <strong>data centers</strong> — specialized facilities with controlled 
            cooling, redundant power (UPS, generators), fire suppression, and physical security. Even if you never 
            set foot in a data center, understanding what's there helps you appreciate the infrastructure supporting 
            your VMs and cloud instances.
          </Typography>
        </Paper>

        {/* Server Form Factors */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Server Form Factors</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>🗄️ Rack Servers</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Standard 19" wide, measured in "U" (1.75" height units). Most common in enterprise.
              </Typography>
              <List dense>
                {[
                  "1U: Dense, limited expansion",
                  "2U: Balance of density and capacity",
                  "4U: Maximum expansion, GPUs",
                  "Requires rack infrastructure",
                  "Excellent airflow management",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>🗼 Tower Servers</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Standalone units resembling large desktop PCs. Ideal for small offices.
              </Typography>
              <List dense>
                {[
                  "No rack infrastructure needed",
                  "Quieter operation",
                  "Easy to expand/upgrade",
                  "Takes up floor space",
                  "Good for small businesses",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>📦 Blade Servers</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Modular servers in a shared chassis. Maximum density for large deployments.
              </Typography>
              <List dense>
                {[
                  "Highest density possible",
                  "Shared power/cooling/networking",
                  "Hot-swappable blades",
                  "High upfront chassis cost",
                  "Enterprise/cloud data centers",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Key Server Components */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Key Server Components</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "CPU (Processor)", desc: "Intel Xeon or AMD EPYC. Multi-socket support, high core counts, ECC memory support.", color: "#3b82f6" },
            { name: "RAM (ECC Memory)", desc: "Error-Correcting Code memory detects and fixes bit errors. Critical for reliability.", color: "#8b5cf6" },
            { name: "Storage Controllers", desc: "RAID controllers, HBAs, NVMe. Hardware RAID offloads processing from CPU.", color: "#22c55e" },
            { name: "Network Interfaces", desc: "Multiple NICs (1GbE, 10GbE, 25GbE+), NIC teaming, iSCSI offload, RDMA.", color: "#f59e0b" },
            { name: "Power Supplies", desc: "Redundant hot-swappable PSUs (N+1). 80 Plus efficiency ratings.", color: "#ef4444" },
            { name: "BMC/IPMI/iLO/iDRAC", desc: "Out-of-band management. Remote console, power control, hardware monitoring.", color: "#0ea5e9" },
          ].map((comp) => (
            <Grid item xs={12} sm={6} md={4} key={comp.name}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(comp.color, 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: comp.color, mb: 0.5 }}>{comp.name}</Typography>
                <Typography variant="caption" color="text.secondary">{comp.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* RAID Configurations */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>RAID Configurations</Typography>
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#6366f1", 0.2)}` }}>
          <Typography variant="body2" sx={{ mb: 2 }}>
            <strong>RAID (Redundant Array of Independent Disks)</strong> combines multiple drives for performance and/or redundancy.
          </Typography>
          <Grid container spacing={2}>
            {[
              { level: "RAID 0", name: "Striping", min: "2", perf: "Excellent", fault: "None", use: "Temp data, scratch" },
              { level: "RAID 1", name: "Mirroring", min: "2", perf: "Good read", fault: "1 drive", use: "OS, boot drives" },
              { level: "RAID 5", name: "Striping + Parity", min: "3", perf: "Good", fault: "1 drive", use: "General purpose" },
              { level: "RAID 6", name: "Double Parity", min: "4", perf: "Moderate", fault: "2 drives", use: "Large arrays" },
              { level: "RAID 10", name: "Mirror + Stripe", min: "4", perf: "Excellent", fault: "1 per pair", use: "Databases, VMs" },
            ].map((raid) => (
              <Grid item xs={12} sm={6} md={4} key={raid.level}>
                <Box sx={{ p: 1.5, bgcolor: alpha("#6366f1", 0.05), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#6366f1" }}>{raid.level}: {raid.name}</Typography>
                  <Typography variant="caption" color="text.secondary" component="div">
                    Min drives: {raid.min} | Fault tolerance: {raid.fault}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">Use: {raid.use}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Sizing and Redundancy */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon /> Sizing and Redundancy Planning
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Sizing Checklist</Typography>
              <List dense>
                {[
                  "Establish CPU, memory, and disk baselines",
                  "Measure peak vs average utilization",
                  "Forecast growth for 12 to 24 months",
                  "Validate storage IOPS and latency needs",
                  "Plan network bandwidth for peak traffic",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Redundancy Checklist</Typography>
              <List dense>
                {[
                  "Dual power supplies on separate circuits",
                  "RAID with hot spare or fast replacement",
                  "Dual NICs with bonding or teaming",
                  "Spare disks and standardized firmware",
                  "Failover or clustering for critical workloads",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 3: SERVER OPERATING SYSTEMS ==================== */}
        <Typography id="operating-systems" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          💻 Server Operating Systems
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Windows Server and Linux — the two dominant platforms
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            A <strong>server operating system</strong> is optimized differently than a desktop OS. It's designed to 
            run <strong>headless</strong> (without a monitor), handle many concurrent connections, provide network 
            services, and run 24/7 without rebooting. Server OSes include features like advanced networking, 
            directory services, role-based administration, and enterprise management tools.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Windows Server</strong> (2016, 2019, 2022) dominates in corporate environments, especially where 
            Active Directory, Exchange, SharePoint, or .NET applications are used. It provides a familiar GUI but 
            increasingly requires PowerShell proficiency. Licensing is complex (per-core, CALs) and expensive.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Linux</strong> (RHEL, Ubuntu Server, Debian, Rocky Linux, AlmaLinux) dominates in web hosting, 
            cloud infrastructure, and DevOps environments. It's command-line focused, highly customizable, and 
            typically free (though enterprise support costs money). Linux powers the majority of web servers, 
            containers, and cloud VMs worldwide.
          </Typography>
        </Paper>

        {/* OS Comparison Table */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#0078d4", 0.03), border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0078d4" }}>🪟 Windows Server</Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Key Editions:</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                <Chip label="Standard" size="small" />
                <Chip label="Datacenter" size="small" />
                <Chip label="Essentials" size="small" />
              </Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Server Roles:</Typography>
              <List dense>
                {[
                  "Active Directory Domain Services (AD DS)",
                  "DNS Server, DHCP Server",
                  "File Services, Print Services",
                  "IIS Web Server",
                  "Hyper-V Virtualization",
                  "Remote Desktop Services",
                  "Windows Server Update Services (WSUS)",
                ].map((role) => (
                  <ListItem key={role} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#0078d4" }} />
                    </ListItemIcon>
                    <ListItemText primary={role} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, mt: 2 }}>Management Tools:</Typography>
              <Typography variant="caption" color="text.secondary">
                Server Manager, PowerShell, MMC snap-ins, Windows Admin Center, RSAT
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>🐧 Linux Server</Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Popular Distros:</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                <Chip label="RHEL/Rocky/Alma" size="small" />
                <Chip label="Ubuntu Server" size="small" />
                <Chip label="Debian" size="small" />
                <Chip label="SUSE" size="small" />
              </Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Common Services:</Typography>
              <List dense>
                {[
                  "BIND (DNS), ISC DHCP, dnsmasq",
                  "Apache, Nginx (web servers)",
                  "Samba (Windows file sharing)",
                  "NFS (Linux file sharing)",
                  "OpenSSH (remote access)",
                  "Postfix/Sendmail (email)",
                  "MySQL/PostgreSQL (databases)",
                ].map((service) => (
                  <ListItem key={service} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#f97316" }} />
                    </ListItemIcon>
                    <ListItemText primary={service} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, mt: 2 }}>Management:</Typography>
              <Typography variant="caption" color="text.secondary">
                SSH, systemctl, journalctl, package managers (yum/dnf, apt), Cockpit, Webmin
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        {/* Server Installation Considerations */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon /> Installation Considerations
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Before Installation:</Typography>
              <List dense>
                {[
                  "Verify hardware compatibility (HCL)",
                  "Plan disk partitioning scheme",
                  "Document network settings (IP, gateway, DNS)",
                  "Decide on hostname and domain",
                  "Prepare license keys (Windows)",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Post-Installation:</Typography>
              <List dense>
                {[
                  "Apply all security updates immediately",
                  "Configure network settings",
                  "Set up remote management (SSH/RDP)",
                  "Configure firewall rules",
                  "Install monitoring agents",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* Service Lifecycle Essentials */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
            <SettingsIcon /> Service Lifecycle Essentials
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Linux (systemd)</Typography>
              <Paper sx={{ p: 1.5, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  systemctl status nginx<br/>
                  systemctl restart nginx<br/>
                  systemctl enable nginx<br/>
                  journalctl -u nginx --since "1 hour ago"
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Windows Services</Typography>
              <Paper sx={{ p: 1.5, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  Get-Service -Name W3SVC<br/>
                  Restart-Service -Name W3SVC<br/>
                  sc query W3SVC<br/>
                  Get-EventLog -LogName System -Newest 5
                </Typography>
              </Paper>
            </Grid>
          </Grid>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 2 }}>
            Always document service ownership, dependencies, and a safe restart procedure before touching production.
          </Typography>
        </Paper>

        {/* ==================== SECTION 4: USER & GROUP MANAGEMENT ==================== */}
        <Typography id="user-management" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          👥 User & Group Management
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Identity, authentication, and authorization fundamentals
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>User management</strong> is fundamental to system administration. Every person (and many services) 
            that accesses a system needs an <strong>identity</strong> — a user account. Users are organized into 
            <strong> groups</strong> to simplify permission management. Instead of granting permissions to 100 
            individual users, you grant them to a group and add users to that group.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            The key concepts are <strong>authentication</strong> (proving who you are — passwords, MFA, certificates) 
            and <strong>authorization</strong> (what you're allowed to do — permissions, group memberships, roles). 
            The principle of <strong>least privilege</strong> dictates that users should have only the minimum 
            permissions necessary to perform their jobs.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            In enterprise environments, <strong>centralized identity management</strong> is essential. 
            <strong> Active Directory</strong> (Windows) and <strong>LDAP</strong> (Linux/cross-platform) allow 
            users to log in to any system with a single account, with permissions managed centrally. Modern 
            environments increasingly use <strong>SSO (Single Sign-On)</strong> and <strong>federated identity</strong> 
            with protocols like SAML, OAuth, and OpenID Connect.
          </Typography>
        </Paper>

        {/* Windows vs Linux User Management */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0078d4" }}>🪟 Windows User Management</Typography>
              
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Local Users & Groups:</Typography>
              <Paper sx={{ p: 1.5, mb: 2, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  # PowerShell commands<br/>
                  New-LocalUser -Name "jsmith"<br/>
                  Add-LocalGroupMember -Group "Administrators" -Member "jsmith"<br/>
                  Get-LocalUser | Select-Object Name, Enabled
                </Typography>
              </Paper>

              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Active Directory:</Typography>
              <List dense>
                {[
                  "Centralized user database (domain)",
                  "Group Policy for settings management",
                  "Organizational Units (OUs) for structure",
                  "Security groups & distribution groups",
                  "Kerberos authentication",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#0078d4" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>🐧 Linux User Management</Typography>
              
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Common Commands:</Typography>
              <Paper sx={{ p: 1.5, mb: 2, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  # User management<br/>
                  useradd -m -s /bin/bash jsmith<br/>
                  passwd jsmith<br/>
                  usermod -aG sudo jsmith<br/>
                  id jsmith  # Show user info
                </Typography>
              </Paper>

              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Key Files:</Typography>
              <List dense>
                {[
                  "/etc/passwd — User accounts",
                  "/etc/shadow — Encrypted passwords",
                  "/etc/group — Group definitions",
                  "/etc/sudoers — Sudo privileges",
                  "~/.ssh/authorized_keys — SSH keys",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#f97316" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Permission Models */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Permission Models</Typography>
        <Grid container spacing={2} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2.5, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Linux: UGO + Octal</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                User/Group/Other with Read(4)/Write(2)/Execute(1)
              </Typography>
              <Paper sx={{ p: 1, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  chmod 755 script.sh  # rwxr-xr-x<br/>
                  chown user:group file.txt
                </Typography>
              </Paper>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2.5, borderRadius: 3, border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0078d4", mb: 1 }}>Windows: NTFS ACLs</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Access Control Lists with granular permissions
              </Typography>
              <Paper sx={{ p: 1, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  icacls file.txt /grant Users:R<br/>
                  # Or use GUI: Properties → Security
                </Typography>
              </Paper>
            </Paper>
          </Grid>
        </Grid>

        {/* Identity Hygiene */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon /> Identity Hygiene and Service Accounts
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>User Lifecycle Practices</Typography>
              <List dense>
                {[
                  "Joiner/mover/leaver process with approvals",
                  "Quarterly access reviews for critical groups",
                  "Group-based access rather than direct grants",
                  "Disable stale accounts after inactivity",
                  "Require MFA for privileged accounts",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Service Account Hygiene</Typography>
              <List dense>
                {[
                  "Use non-interactive accounts with least privilege",
                  "Separate accounts per service or application",
                  "Rotate credentials and store in a vault",
                  "Use managed identities where available",
                  "Audit logon rights and usage regularly",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 5: NETWORK SERVICES ==================== */}
        <Typography id="networking-services" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🌐 Network Services
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          DNS, DHCP, and other essential infrastructure services
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Network services</strong> are the invisible infrastructure that makes everything work. 
            When you type a website name, <strong>DNS</strong> translates it to an IP address. When your laptop 
            connects to the network, <strong>DHCP</strong> gives it an IP address automatically. When your computer 
            needs to know what time it is, <strong>NTP</strong> synchronizes its clock. These services are so 
            fundamental that when they fail, "the internet is down" — even though the actual network is fine.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            As a sysadmin, you'll configure, maintain, and troubleshoot these services constantly. Understanding 
            how they work — not just which buttons to click — is essential for effective troubleshooting. When 
            DNS fails at 2 AM, you need to know where to look and how to fix it fast.
          </Typography>
        </Paper>

        {/* Core Network Services */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>🔍 DNS (Domain Name System)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Translates names (google.com) to IP addresses. The "phone book" of the internet.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Record Types:</Typography>
              <List dense>
                {[
                  "A / AAAA — IPv4/IPv6 addresses",
                  "CNAME — Aliases",
                  "MX — Mail servers",
                  "TXT — SPF, DKIM, verification",
                  "PTR — Reverse DNS",
                  "NS — Name servers",
                  "SOA — Zone authority",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, mt: 1 }}>Servers:</Typography>
              <Typography variant="caption" color="text.secondary">
                Windows DNS, BIND, Unbound, dnsmasq, PowerDNS
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>📡 DHCP</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Automatically assigns IP addresses, subnet masks, gateways, and DNS servers to clients.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>DORA Process:</Typography>
              <List dense>
                {[
                  "Discover — Client broadcasts",
                  "Offer — Server offers IP",
                  "Request — Client requests IP",
                  "Acknowledge — Server confirms",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, mt: 1 }}>Key Concepts:</Typography>
              <Typography variant="caption" color="text.secondary">
                Scopes, reservations, leases, exclusions, options (gateway, DNS, NTP)
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🕐 NTP (Time Sync)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Synchronizes system clocks. Critical for authentication, logging, and certificates.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Why It Matters:</Typography>
              <List dense>
                {[
                  "Kerberos auth fails if >5 min drift",
                  "Logs become useless without sync",
                  "SSL certs fail with wrong time",
                  "Distributed systems need sync",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, mt: 1 }}>Servers:</Typography>
              <Typography variant="caption" color="text.secondary">
                Windows Time (w32time), chrony, ntpd, systemd-timesyncd
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        {/* Firewalls */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Firewalls & Traffic Control</Typography>
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Firewalls control network traffic based on rules. They can be <strong>host-based</strong> (on the server itself) 
            or <strong>network-based</strong> (dedicated appliances/VMs protecting network segments).
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#0078d4" }}>Windows Firewall:</Typography>
              <Paper sx={{ p: 1, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  # PowerShell<br/>
                  New-NetFirewallRule -DisplayName "Allow HTTP" `<br/>
                  &nbsp;&nbsp;-Direction Inbound -Port 80 -Protocol TCP -Action Allow<br/>
                  Get-NetFirewallRule | Where Enabled -eq True
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f97316" }}>Linux (firewalld/iptables):</Typography>
              <Paper sx={{ p: 1, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  # firewalld (RHEL/CentOS)<br/>
                  firewall-cmd --add-service=http --permanent<br/>
                  firewall-cmd --reload<br/>
                  # UFW (Ubuntu): ufw allow 80/tcp
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* Subnetting and Troubleshooting */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
            <NetworkCheckIcon /> Network Troubleshooting Quickstart
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Subnetting Quick Facts</Typography>
              <List dense>
                {[
                  "CIDR /24 = 255.255.255.0 (254 hosts)",
                  "CIDR /26 = 255.255.255.192 (62 hosts)",
                  "CIDR /30 = 255.255.255.252 (2 hosts)",
                  "Default gateway must be in the same subnet",
                  "Reserve space for growth and VLAN separation",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>First Response Checklist</Typography>
              <List dense>
                {[
                  "Verify IP, mask, gateway, DNS settings",
                  "Test local connectivity (ping gateway)",
                  "Resolve DNS and test by IP vs hostname",
                  "Check firewall rules and port access",
                  "Trace route to identify network hop issues",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
          <Paper sx={{ p: 1.5, mt: 2, bgcolor: "#1e1e1e", borderRadius: 1 }}>
            <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
              ipconfig /all&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Windows IP details<br/>
              ip addr show&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Linux IP details<br/>
              nslookup example.com&nbsp;&nbsp;# DNS lookup<br/>
              ping 8.8.8.8&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Connectivity test<br/>
              tracert example.com&nbsp;&nbsp;# Windows trace route<br/>
              traceroute example.com&nbsp;# Linux trace route
            </Typography>
          </Paper>
        </Paper>

        {/* ==================== SECTION 6: STORAGE MANAGEMENT ==================== */}
        <Typography id="storage-management" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          💾 Storage Management
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          File systems, disk management, and enterprise storage solutions
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Storage management</strong> is one of the most critical sysadmin responsibilities. Data is the 
            lifeblood of every organization — losing it can be catastrophic. You need to understand how to provision 
            storage, manage file systems, expand volumes without downtime, and ensure data integrity through proper 
            RAID configurations and backup strategies.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            Storage comes in multiple tiers: <strong>local storage</strong> (disks inside the server), 
            <strong> network-attached storage (NAS)</strong> for file sharing, and <strong>storage area networks (SAN)</strong> 
            for high-performance block storage. Modern environments also use <strong>object storage</strong> (S3-style) 
            and <strong>software-defined storage</strong> solutions.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Understanding <strong>file systems</strong> is essential: NTFS and ReFS for Windows; ext4, XFS, and Btrfs 
            for Linux. Each has different features for journaling, snapshots, compression, and maximum file/volume sizes. 
            Choosing the right file system for the workload can significantly impact performance and reliability.
          </Typography>
        </Paper>

        {/* Storage Types */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Storage Types</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>🖴 DAS (Direct Attached)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Storage directly connected to a single server. Simplest and often fastest.
              </Typography>
              <List dense>
                {[
                  "Internal drives (SATA, SAS, NVMe)",
                  "External JBOD enclosures",
                  "Not shared between servers",
                  "Best for: single-server workloads",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>📁 NAS (Network Attached)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                File-level storage shared over the network. Easy to manage and share.
              </Typography>
              <List dense>
                {[
                  "Protocols: SMB/CIFS, NFS, AFP",
                  "Shared folders & permissions",
                  "Appliances or software (FreeNAS)",
                  "Best for: file shares, home dirs",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>🗄️ SAN (Storage Area Network)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Block-level storage over dedicated network. High performance for VMs, databases.
              </Typography>
              <List dense>
                {[
                  "Protocols: FC, iSCSI, FCoE",
                  "LUNs presented as local disks",
                  "Dedicated fabric/network",
                  "Best for: VMs, databases, clusters",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* File Systems */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>File Systems Comparison</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "NTFS", os: "Windows", features: "ACLs, journaling, compression, encryption (EFS), quotas", max: "256TB volume" },
            { name: "ReFS", os: "Windows", features: "Integrity streams, auto-repair, Storage Spaces", max: "35PB volume" },
            { name: "ext4", os: "Linux", features: "Journaling, extents, backward compatible, mature", max: "1EB volume" },
            { name: "XFS", os: "Linux", features: "High performance, parallel I/O, online resize", max: "8EB volume" },
            { name: "Btrfs", os: "Linux", features: "Snapshots, compression, checksums, RAID built-in", max: "16EB volume" },
            { name: "ZFS", os: "Linux/BSD", features: "Snapshots, dedup, compression, RAID-Z, self-healing", max: "256ZB volume" },
          ].map((fs) => (
            <Grid item xs={12} sm={6} md={4} key={fs.name}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#6366f1", 0.15)}`, height: "100%" }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.5 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#6366f1" }}>{fs.name}</Typography>
                  <Chip label={fs.os} size="small" sx={{ fontSize: "0.65rem", height: 18 }} />
                </Box>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
                  {fs.features}
                </Typography>
                <Typography variant="caption" sx={{ fontWeight: 600 }}>Max: {fs.max}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* LVM */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon /> Linux LVM (Logical Volume Manager)
          </Typography>
          <Typography variant="body2" sx={{ mb: 2 }}>
            LVM adds a layer of abstraction between physical disks and file systems, enabling flexible volume management:
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Physical Volumes (PV)</Typography>
              <Typography variant="caption" color="text.secondary">
                Raw disks or partitions added to LVM
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Volume Groups (VG)</Typography>
              <Typography variant="caption" color="text.secondary">
                Pool of storage from one or more PVs
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Logical Volumes (LV)</Typography>
              <Typography variant="caption" color="text.secondary">
                Virtual partitions carved from VG — can span disks, resize online
              </Typography>
            </Grid>
          </Grid>
          <Paper sx={{ p: 1.5, mt: 2, bgcolor: "#1e1e1e", borderRadius: 1 }}>
            <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
              # Extend a logical volume online<br/>
              lvextend -L +10G /dev/vg_data/lv_storage<br/>
              resize2fs /dev/vg_data/lv_storage  # For ext4<br/>
              xfs_growfs /dev/vg_data/lv_storage  # For XFS
            </Typography>
          </Paper>
        </Paper>

        {/* Storage Performance and Protection */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1", display: "flex", alignItems: "center", gap: 1 }}>
            <StorageIcon /> Storage Performance and Protection
          </Typography>
          <Grid container spacing={2} sx={{ mb: 2 }}>
            {[
              { name: "IOPS", desc: "Operations per second. Important for random read/write workloads.", color: "#3b82f6" },
              { name: "Throughput", desc: "MB/s for large sequential reads and writes.", color: "#22c55e" },
              { name: "Latency", desc: "Time per operation. High latency slows databases and VMs.", color: "#f59e0b" },
            ].map((item) => (
              <Grid item xs={12} md={4} key={item.name}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(item.color, 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.name}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Snapshots vs Backups</Typography>
          <List dense>
            {[
              "Snapshots are fast point-in-time copies on the same storage",
              "Backups are separate copies for recovery and compliance",
              "Snapshots are not a replacement for offsite backups",
              "Use immutable storage or object lock when possible",
              "Test restores regularly to validate recovery",
            ].map((item) => (
              <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 24 }}>
                  <CheckCircleIcon sx={{ fontSize: 14, color: "#6366f1" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* ==================== SECTION 7: BACKUP & DISASTER RECOVERY ==================== */}
        <Typography id="backup-recovery" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          💾 Backup & Disaster Recovery
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Protecting data and ensuring business continuity
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Backups are your insurance policy</strong>. Hardware fails, users delete files, ransomware encrypts 
            data, and disasters happen. The question isn't <em>if</em> you'll need to restore from backup, but <em>when</em>. 
            A sysadmin who doesn't take backups seriously isn't a sysadmin for long — either they learn the hard way, 
            or they find a new career after a catastrophic data loss.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Disaster Recovery (DR)</strong> goes beyond backups. It's a comprehensive plan for how your 
            organization will continue operating after a major incident — data center fire, regional outage, or 
            cyber attack. DR planning involves identifying critical systems, establishing recovery priorities, 
            setting up failover sites, and regularly testing the plan.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Two key metrics define your DR requirements: <strong>RPO (Recovery Point Objective)</strong> — how much 
            data loss is acceptable (determines backup frequency), and <strong>RTO (Recovery Time Objective)</strong> — 
            how long can systems be down (determines recovery infrastructure investment).
          </Typography>
        </Paper>

        {/* 3-2-1 Rule */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon /> The 3-2-1 Backup Rule
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Typography variant="h3" sx={{ fontWeight: 800, color: "#f59e0b", mb: 1 }}>3</Typography>
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Copies of Data</Typography>
              <Typography variant="body2" color="text.secondary">
                Keep at least three copies of important data (original + two backups)
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="h3" sx={{ fontWeight: 800, color: "#f59e0b", mb: 1 }}>2</Typography>
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Different Media Types</Typography>
              <Typography variant="body2" color="text.secondary">
                Store backups on at least two different types of media (disk, tape, cloud)
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="h3" sx={{ fontWeight: 800, color: "#f59e0b", mb: 1 }}>1</Typography>
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Offsite Location</Typography>
              <Typography variant="body2" color="text.secondary">
                Keep at least one backup copy offsite (different building, region, cloud)
              </Typography>
            </Grid>
          </Grid>
        </Paper>

        {/* Backup Types */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Backup Types</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { type: "Full", desc: "Complete copy of all data. Takes longest, uses most space, but simplest to restore.", when: "Weekly/Monthly", color: "#3b82f6" },
            { type: "Incremental", desc: "Only data changed since last backup (any type). Fast, small, but restore requires all incrementals.", when: "Daily/Hourly", color: "#22c55e" },
            { type: "Differential", desc: "All data changed since last full backup. Middle ground between full and incremental.", when: "Daily", color: "#f59e0b" },
            { type: "Snapshot", desc: "Point-in-time copy at filesystem/VM level. Near-instant, great for before changes.", when: "Before changes", color: "#8b5cf6" },
            { type: "Continuous (CDP)", desc: "Continuous Data Protection — every change captured. Minimal data loss, higher cost.", when: "Real-time", color: "#ec4899" },
            { type: "Synthetic Full", desc: "Creates full backup from previous full + incrementals without reading source.", when: "Scheduled", color: "#0ea5e9" },
          ].map((backup) => (
            <Grid item xs={12} sm={6} md={4} key={backup.type}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 3, border: `1px solid ${alpha(backup.color, 0.2)}` }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: backup.color }}>{backup.type}</Typography>
                  <Chip label={backup.when} size="small" sx={{ fontSize: "0.65rem", height: 20 }} />
                </Box>
                <Typography variant="caption" color="text.secondary">{backup.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* RPO/RTO */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>⏰ RPO (Recovery Point Objective)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Maximum acceptable data loss measured in time. "How much work can we afford to lose?"
              </Typography>
              <List dense>
                {[
                  "RPO = 0: No data loss (requires synchronous replication)",
                  "RPO = 1 hour: Lose at most 1 hour of work",
                  "RPO = 24 hours: Nightly backups acceptable",
                  "Determines: Backup frequency, replication strategy",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>⚡ RTO (Recovery Time Objective)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Maximum acceptable downtime. "How quickly must we be back online?"
              </Typography>
              <List dense>
                {[
                  "RTO = 0: No downtime (requires hot standby/HA)",
                  "RTO = 4 hours: Business-critical systems",
                  "RTO = 24 hours: Important but not critical",
                  "Determines: DR site investment, automation level",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Restore Testing */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9", display: "flex", alignItems: "center", gap: 1 }}>
            <BackupIcon /> Restore Testing and Backup Security
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Restore Testing Checklist</Typography>
              <List dense>
                {[
                  "Monthly sample restores for critical systems",
                  "Quarterly full restore or DR rehearsal",
                  "Validate RPO and RTO against SLAs",
                  "Document results and update runbooks",
                  "Automate backup verification where possible",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#0ea5e9" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Backup Security Practices</Typography>
              <List dense>
                {[
                  "Separate backup admin accounts with MFA",
                  "Use immutable storage or object lock",
                  "Restrict network access to backup servers",
                  "Monitor backup job failures and delays",
                  "Store encryption keys securely and offsite",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#0ea5e9" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 8: MONITORING & LOGGING ==================== */}
        <Typography id="monitoring-logging" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📊 Monitoring & Logging
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Visibility into system health and behavior
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>You can't fix what you can't see</strong>. Monitoring and logging are how sysadmins maintain 
            visibility into their infrastructure. <strong>Monitoring</strong> watches system metrics in real-time 
            (CPU, memory, disk, network) and alerts when things go wrong. <strong>Logging</strong> records events 
            and activities for troubleshooting and security analysis.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            Good monitoring is <strong>proactive</strong> — it tells you about problems before users notice. 
            A disk filling up? Get an alert at 80% full, not when it hits 100% and the database crashes. 
            CPU spiking? Know immediately so you can investigate before the server becomes unresponsive.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Logs are invaluable for <strong>forensics</strong> — understanding what happened after an incident. 
            They're also increasingly important for <strong>security</strong>. SIEM (Security Information and Event 
            Management) systems aggregate logs to detect suspicious patterns and support incident response.
          </Typography>
        </Paper>

        {/* Key Metrics to Monitor */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Key Metrics to Monitor</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { metric: "CPU Utilization", warn: ">80%", crit: ">95%", desc: "Sustained high CPU indicates overload or runaway process", color: "#3b82f6" },
            { metric: "Memory Usage", warn: ">85%", crit: ">95%", desc: "High memory can cause swapping and severe slowdown", color: "#22c55e" },
            { metric: "Disk Space", warn: ">80%", crit: ">90%", desc: "Full disks crash databases and stop log collection", color: "#f59e0b" },
            { metric: "Disk I/O", warn: "High latency", crit: ">100ms", desc: "I/O bottlenecks slow everything on the server", color: "#8b5cf6" },
            { metric: "Network Traffic", warn: ">80% capacity", crit: "Saturation", desc: "Bandwidth saturation causes drops and latency", color: "#ec4899" },
            { metric: "Service Status", warn: "Degraded", crit: "Down", desc: "Are critical services running and responding?", color: "#ef4444" },
          ].map((m) => (
            <Grid item xs={12} sm={6} md={4} key={m.metric}>
              <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha(m.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: m.color, mb: 0.5 }}>{m.metric}</Typography>
                <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
                  <Chip label={`Warn: ${m.warn}`} size="small" sx={{ fontSize: "0.6rem", height: 18, bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
                  <Chip label={`Crit: ${m.crit}`} size="small" sx={{ fontSize: "0.6rem", height: 18, bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
                </Box>
                <Typography variant="caption" color="text.secondary">{m.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Monitoring Tools */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>📈 Monitoring Tools</Typography>
              <List dense>
                {[
                  { name: "Prometheus + Grafana", desc: "Industry standard for metrics. Pull-based, powerful queries." },
                  { name: "Zabbix", desc: "Enterprise-grade, agent-based. Great for traditional infrastructure." },
                  { name: "Nagios/Icinga", desc: "Classic monitoring. Plugin ecosystem, service checks." },
                  { name: "Datadog/New Relic", desc: "SaaS monitoring. Full-stack observability, APM." },
                  { name: "PRTG", desc: "Windows-focused. Easy setup, sensor-based licensing." },
                ].map((tool) => (
                  <ListItem key={tool.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={tool.name} 
                      secondary={tool.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>📝 Logging Stack</Typography>
              <List dense>
                {[
                  { name: "ELK Stack", desc: "Elasticsearch + Logstash + Kibana. The classic log aggregation." },
                  { name: "Loki + Grafana", desc: "Like Prometheus but for logs. Label-based, efficient." },
                  { name: "Splunk", desc: "Enterprise log analysis. Powerful but expensive." },
                  { name: "Graylog", desc: "Open-source log management. Good middle ground." },
                  { name: "Windows Event Log", desc: "Built-in Windows logging. Forward to SIEM.", },
                ].map((tool) => (
                  <ListItem key={tool.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={tool.name} 
                      secondary={tool.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Log Locations */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>📂 Important Log Locations</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f97316" }}>Linux:</Typography>
              <Paper sx={{ p: 1, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  /var/log/syslog (or /var/log/messages)<br/>
                  /var/log/auth.log — Authentication events<br/>
                  /var/log/secure — Security logs (RHEL)<br/>
                  journalctl -u servicename — systemd logs<br/>
                  /var/log/nginx/ — Web server logs
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#0078d4" }}>Windows:</Typography>
              <Paper sx={{ p: 1, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  Event Viewer → Windows Logs:<br/>
                  • Application — App errors/warnings<br/>
                  • Security — Logon events, audit<br/>
                  • System — Service, driver events<br/>
                  Get-EventLog -LogName Security -Newest 50
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* Signals and Alert Hygiene */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899", display: "flex", alignItems: "center", gap: 1 }}>
            <MonitorHeartIcon /> Signals and Alert Hygiene
          </Typography>
          <Grid container spacing={2} sx={{ mb: 2 }}>
            {[
              { name: "Metrics", desc: "Numeric time series. Great for capacity and performance trends." },
              { name: "Logs", desc: "Event records. Best for troubleshooting and security analysis." },
              { name: "Traces", desc: "Request flows across services. Ideal for latency analysis." },
            ].map((item) => (
              <Grid item xs={12} md={4} key={item.name}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#ec4899", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Alerting Best Practices</Typography>
          <List dense>
            {[
              "Alert on user impact, not every metric spike",
              "Use warning and critical thresholds with context",
              "Route alerts to the right on-call owner",
              "Suppress noisy alerts during maintenance windows",
              "Review and tune alerts after incidents",
            ].map((item) => (
              <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 24 }}>
                  <CheckCircleIcon sx={{ fontSize: 14, color: "#ec4899" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* ==================== SECTION 9: SECURITY & HARDENING ==================== */}
        <Typography id="security-hardening" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🔒 Security & Hardening
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Reducing attack surface and protecting systems
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#dc2626", 0.03), border: `1px solid ${alpha("#dc2626", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Server hardening</strong> is the process of reducing a system's attack surface — eliminating 
            unnecessary services, closing unused ports, applying secure configurations, and keeping software patched. 
            Every running service is a potential vulnerability. Every open port is an entry point. The goal is to 
            make your servers as small a target as possible while still performing their function.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Defense in depth</strong> is the guiding principle: multiple layers of security so that if one 
            fails, others still protect you. Firewalls, access controls, encryption, monitoring, patching — each 
            layer adds protection. No single control is perfect, but together they create strong security.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Patch management</strong> is critical but challenging. Patches fix known vulnerabilities, but 
            they can also break things. You need a process: test patches in a non-production environment, schedule 
            maintenance windows, have rollback plans, and prioritize critical security updates.
          </Typography>
        </Paper>

        {/* Hardening Checklist */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Server Hardening Checklist</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 2 }}>🛡️ Essential Hardening</Typography>
              <List dense>
                {[
                  "Remove/disable unnecessary services and software",
                  "Close unused ports (firewall default deny)",
                  "Disable root/Administrator direct login",
                  "Enforce strong password policies",
                  "Enable and require MFA where possible",
                  "Keep all software patched and updated",
                  "Enable audit logging for security events",
                  "Encrypt data at rest and in transit",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>✅ Advanced Hardening</Typography>
              <List dense>
                {[
                  "Implement security baselines (CIS Benchmarks)",
                  "Use configuration management to enforce standards",
                  "Network segmentation and VLANs",
                  "Implement privileged access management (PAM)",
                  "Regular vulnerability scanning",
                  "File integrity monitoring (FIM)",
                  "Application whitelisting",
                  "Disable unnecessary kernel modules/features",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
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

        {/* Patch Management */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
            <UpdateIcon /> Patch Management Process
          </Typography>
          <Grid container spacing={2}>
            {[
              { step: "1. Identify", desc: "Subscribe to vendor security bulletins. Know what needs patching." },
              { step: "2. Evaluate", desc: "Assess severity (CVSS), applicability, and potential impact." },
              { step: "3. Test", desc: "Apply patches in dev/staging environment first. Look for breaks." },
              { step: "4. Schedule", desc: "Plan maintenance window. Notify stakeholders. Have rollback plan." },
              { step: "5. Deploy", desc: "Apply patches. Monitor for issues during and after." },
              { step: "6. Verify", desc: "Confirm patches applied. Vulnerability scan to validate." },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.step}>
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>{item.step}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Security Operations Routine */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#dc2626", 0.03), border: `1px solid ${alpha("#dc2626", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626", display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon /> Security Operations Routine
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Daily</Typography>
              <List dense>
                {[
                  "Review critical security alerts",
                  "Check for failed logins and anomalies",
                  "Validate backup job success",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#dc2626" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Weekly</Typography>
              <List dense>
                {[
                  "Review patch backlog and risk",
                  "Validate endpoint protection status",
                  "Audit privileged group membership",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#dc2626" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Monthly or Quarterly</Typography>
              <List dense>
                {[
                  "Run vulnerability scans and track fixes",
                  "Review firewall rules and clean up stale entries",
                  "Test restore from backup for one critical system",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#dc2626" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 10: AUTOMATION & SCRIPTING ==================== */}
        <Typography id="automation-scripting" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🤖 Automation & Scripting
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Work smarter, not harder — automate everything
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>If you do something twice, automate it</strong>. This is the modern sysadmin's mantra. 
            Automation reduces human error, ensures consistency, saves time, and enables you to manage far 
            more systems than would otherwise be possible. The best sysadmins are lazy — they automate 
            themselves out of repetitive work so they can focus on more interesting problems.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Scripting</strong> is the foundation — Bash for Linux, PowerShell for Windows. Write scripts 
            to automate user creation, log rotation, backup verification, and health checks. 
            <strong> Configuration management</strong> (Ansible, Puppet, Chef) takes it further — define your 
            infrastructure as code and apply configurations to hundreds of servers consistently.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Infrastructure as Code (IaC)</strong> is the evolution — treat infrastructure like software. 
            Version control your configurations. Code review changes. Test in staging. Deploy through CI/CD. 
            Tools like Terraform, Ansible, and cloud-native services make this possible.
          </Typography>
        </Paper>

        {/* Scripting Languages */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>🐧 Bash Scripting (Linux)</Typography>
              <Paper sx={{ p: 1.5, mb: 2, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  #!/bin/bash<br/>
                  # Check disk usage and alert if {'>'} 80%<br/>
                  THRESHOLD=80<br/>
                  USAGE=$(df -h / | awk 'NR==2 {'{'}print $5{'}'}' | tr -d '%')<br/>
                  if [ "$USAGE" -gt "$THRESHOLD" ]; then<br/>
                  &nbsp;&nbsp;echo "Disk usage critical: ${'$'}USAGE%" | mail -s "Alert" admin@co<br/>
                  fi
                </Typography>
              </Paper>
              <Typography variant="caption" color="text.secondary">
                Essential for: cron jobs, log parsing, system tasks, glue scripts
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0078d4" }}>🪟 PowerShell (Windows)</Typography>
              <Paper sx={{ p: 1.5, mb: 2, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  # Get all disabled AD users inactive 90+ days<br/>
                  $DaysInactive = 90<br/>
                  $CutoffDate = (Get-Date).AddDays(-$DaysInactive)<br/>
                  Get-ADUser -Filter {'{'}<br/>
                  &nbsp;&nbsp;Enabled -eq $false -and<br/>
                  &nbsp;&nbsp;LastLogonDate -lt $CutoffDate<br/>
                  {'}'} | Select-Object Name, LastLogonDate
                </Typography>
              </Paper>
              <Typography variant="caption" color="text.secondary">
                Essential for: AD management, Exchange, Azure, Windows automation
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        {/* Configuration Management */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Configuration Management Tools</Typography>
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { name: "Ansible", desc: "Agentless, YAML playbooks, push-based. Great for getting started.", color: "#ee0000" },
            { name: "Puppet", desc: "Agent-based, declarative DSL, pull-based. Enterprise scale.", color: "#ffae1a" },
            { name: "Chef", desc: "Agent-based, Ruby DSL, pull-based. Powerful but complex.", color: "#f09820" },
            { name: "SaltStack", desc: "Agent or agentless, YAML, fast. Good for large scale.", color: "#57bcad" },
            { name: "Terraform", desc: "Infrastructure provisioning (IaC). Multi-cloud, declarative.", color: "#7b42bc" },
            { name: "DSC (Windows)", desc: "PowerShell Desired State Configuration. Built into Windows.", color: "#0078d4" },
          ].map((tool) => (
            <Grid item xs={12} sm={6} md={4} key={tool.name}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(tool.color, 0.3)}`, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: tool.color }}>{tool.name}</Typography>
                <Typography variant="caption" color="text.secondary">{tool.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Automation Playbook */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
            <AutorenewIcon /> Automation Starter Playbook
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>High-Value Quick Wins</Typography>
              <List dense>
                {[
                  "User onboarding and offboarding scripts",
                  "Standard server build and patching routine",
                  "Backup validation and reporting",
                  "Log rotation and cleanup tasks",
                  "Daily health checks with summary output",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Safety Guardrails</Typography>
              <List dense>
                {[
                  "Dry-run or audit mode before change",
                  "Backups or snapshots before automation",
                  "Idempotent scripts that can be re-run safely",
                  "Logging and error handling with exit codes",
                  "Code review and version control for scripts",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 11: VIRTUALIZATION & CONTAINERS ==================== */}
        <Typography id="virtualization" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          ☁️ Virtualization & Containers
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Running multiple workloads on shared infrastructure
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Virtualization</strong> revolutionized IT. Instead of one OS per physical server, 
            <strong> hypervisors</strong> allow multiple virtual machines (VMs) to share the same hardware. 
            This dramatically improves server utilization (from ~10% to 60-80%), enables rapid provisioning, 
            and provides isolation between workloads. VMware vSphere, Microsoft Hyper-V, and KVM are the 
            dominant hypervisors.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Containers</strong> take a different approach. Instead of virtualizing hardware, they 
            virtualize the operating system. Containers share the host kernel but have isolated filesystems, 
            processes, and networking. They're lighter weight than VMs (seconds to start vs. minutes), 
            more portable, and perfect for microservices architectures. Docker popularized containers; 
            Kubernetes orchestrates them at scale.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Modern infrastructure typically uses <strong>both</strong>: VMs for isolation and traditional 
            workloads, containers for cloud-native applications. Understanding both is essential for today's 
            sysadmin.
          </Typography>
        </Paper>

        {/* VMs vs Containers */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>🖥️ Virtual Machines</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Full OS virtualization with hardware abstraction
              </Typography>
              <List dense>
                {[
                  "Complete OS isolation (own kernel)",
                  "GB of overhead per VM",
                  "Minutes to boot",
                  "Best for: legacy apps, Windows, full isolation",
                  "Hypervisors: VMware, Hyper-V, KVM, Xen",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>📦 Containers</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                OS-level virtualization sharing host kernel
              </Typography>
              <List dense>
                {[
                  "Process isolation (shared kernel)",
                  "MB of overhead per container",
                  "Seconds to start",
                  "Best for: microservices, cloud-native, CI/CD",
                  "Tools: Docker, Podman, containerd, Kubernetes",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#0ea5e9" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Container Commands */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>🐳 Essential Docker Commands</Typography>
          <Paper sx={{ p: 1.5, bgcolor: "#1e1e1e", borderRadius: 1 }}>
            <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
              docker pull nginx:latest&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Download image<br/>
              docker run -d -p 80:80 nginx&nbsp;&nbsp;&nbsp;# Run container (detached, port mapped)<br/>
              docker ps&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# List running containers<br/>
              docker logs container_id&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# View container logs<br/>
              docker exec -it container bash&nbsp;# Shell into container<br/>
              docker stop container_id&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Stop container<br/>
              docker-compose up -d&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Start multi-container app
            </Typography>
          </Paper>
        </Paper>

        {/* Virtualization Operations */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
            <CloudIcon /> Virtualization Operations Checklist
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>VM Lifecycle Hygiene</Typography>
              <List dense>
                {[
                  "Tag VMs with owner, purpose, and environment",
                  "Remove old snapshots to avoid performance hits",
                  "Standardize templates and golden images",
                  "Right-size CPU and memory allocations",
                  "Retire unused VMs to reclaim capacity",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Host and Cluster Care</Typography>
              <List dense>
                {[
                  "Monitor CPU and memory oversubscription",
                  "Balance workloads across hosts",
                  "Validate storage multipath and redundancy",
                  "Patch hypervisors in a rolling window",
                  "Test failover and live migration regularly",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 12: WEB & APPLICATION SERVICES ==================== */}
        <Typography id="web-services" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🌍 Web & Application Services
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Serving content and applications to users
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Web servers</strong> are the workhorses of the internet. They receive HTTP requests and 
            respond with web pages, API responses, or file downloads. The big three are <strong>Apache</strong> 
            (mature, modular, .htaccess), <strong>Nginx</strong> (fast, efficient, great reverse proxy), and 
            <strong> IIS</strong> (Windows-integrated, ASP.NET). Most sysadmins will work with at least one.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Reverse proxies</strong> sit in front of web servers, handling SSL termination, load 
            balancing, caching, and request routing. Nginx and HAProxy are popular choices. 
            <strong> Application servers</strong> run the actual application code — Tomcat for Java, 
            Gunicorn/uWSGI for Python, Node.js for JavaScript.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>SSL/TLS</strong> is no longer optional — it's expected. Let's Encrypt provides free 
            certificates. Understanding certificate chains, renewal automation, and TLS configuration is 
            essential for any sysadmin managing web services.
          </Typography>
        </Paper>

        {/* Web Server Comparison */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Web Server Comparison</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#c73b3b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#c73b3b" }}>🪶 Apache</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                The original. Mature, extensible, well-documented.
              </Typography>
              <List dense>
                {[
                  "Process/thread per connection model",
                  ".htaccess for per-directory config",
                  "Massive module ecosystem",
                  "Great for: shared hosting, PHP",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#009639", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#009639" }}>⚡ Nginx</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Fast, efficient, modern. Event-driven architecture.
              </Typography>
              <List dense>
                {[
                  "Async, event-driven, non-blocking",
                  "Excellent as reverse proxy/LB",
                  "Low memory footprint",
                  "Great for: high traffic, static, proxy",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#0078d4" }}>🪟 IIS</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Windows-native. GUI management, AD integration.
              </Typography>
              <List dense>
                {[
                  "Built into Windows Server",
                  "Application pools for isolation",
                  "Native ASP.NET/Core support",
                  "Great for: .NET apps, Windows shops",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* SSL/TLS */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
            <LockIcon /> SSL/TLS Essentials
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Certificate Types:</Typography>
              <List dense>
                {[
                  "DV (Domain Validated): Basic, automated",
                  "OV (Org Validated): Business verified",
                  "EV (Extended Validation): Green bar (legacy)",
                  "Wildcard: *.domain.com",
                  "SAN/Multi-domain: Multiple domains",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Let's Encrypt (Free Certs):</Typography>
              <Paper sx={{ p: 1, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  # Install certbot and get cert<br/>
                  apt install certbot python3-certbot-nginx<br/>
                  certbot --nginx -d example.com<br/>
                  # Auto-renewal via cron/systemd timer
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* HTTP and TLS Essentials */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316", display: "flex", alignItems: "center", gap: 1 }}>
            <LockIcon /> HTTP and TLS Essentials
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>HTTP Basics</Typography>
              <List dense>
                {[
                  "Common methods: GET, POST, PUT, DELETE",
                  "Status codes: 200 OK, 301 Redirect, 404 Not Found, 500 Server Error",
                  "Headers control caching, auth, and content type",
                  "Keep-alive reduces connection overhead",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#f97316" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>TLS Management</Typography>
              <List dense>
                {[
                  "Automate renewals with ACME (Lets Encrypt)",
                  "Use strong ciphers and disable legacy protocols",
                  "Track certificate expiration in monitoring",
                  "Store private keys securely and restrict access",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#f97316" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 13: DATABASE ADMINISTRATION BASICS ==================== */}
        <Typography id="database-admin" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🗃️ Database Administration Basics
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Managing the data that powers applications
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Databases</strong> are where applications store their data. While dedicated DBAs handle complex 
            database environments, sysadmins often manage database servers, perform basic administration, handle 
            backups, and troubleshoot connectivity issues. Understanding database fundamentals is essential — 
            even if you're not writing SQL daily.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Relational databases (SQL)</strong> like MySQL, PostgreSQL, SQL Server, and Oracle store data 
            in structured tables with defined relationships. They use SQL (Structured Query Language) for queries 
            and guarantee ACID properties (Atomicity, Consistency, Isolation, Durability).
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>NoSQL databases</strong> sacrifice some SQL guarantees for flexibility and scale. Document 
            stores (MongoDB), key-value stores (Redis), column stores (Cassandra), and graph databases (Neo4j) 
            each optimize for different use cases. Modern applications often use multiple database types.
          </Typography>
        </Paper>

        {/* SQL vs NoSQL */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>🗄️ Relational (SQL)</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                <Chip label="MySQL" size="small" />
                <Chip label="PostgreSQL" size="small" />
                <Chip label="SQL Server" size="small" />
                <Chip label="Oracle" size="small" />
                <Chip label="MariaDB" size="small" />
              </Box>
              <List dense>
                {[
                  "Structured data with schemas",
                  "ACID transactions guaranteed",
                  "Complex queries with JOINs",
                  "Best for: transactional data, reporting",
                  "Scales vertically (bigger servers)",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>🍃 NoSQL</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                <Chip label="MongoDB" size="small" />
                <Chip label="Redis" size="small" />
                <Chip label="Cassandra" size="small" />
                <Chip label="DynamoDB" size="small" />
                <Chip label="Elasticsearch" size="small" />
              </Box>
              <List dense>
                {[
                  "Flexible/schema-less data",
                  "Eventual consistency (often)",
                  "Simple queries, no JOINs",
                  "Best for: unstructured, big data, caching",
                  "Scales horizontally (more servers)",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Basic DBA Tasks */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Essential DBA Tasks for Sysadmins</Typography>
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { task: "Backup & Restore", desc: "Regular backups, test restores, point-in-time recovery", color: "#ef4444" },
            { task: "User Management", desc: "Create users, grant permissions, principle of least privilege", color: "#f59e0b" },
            { task: "Monitoring", desc: "Connection counts, query performance, disk usage, replication lag", color: "#22c55e" },
            { task: "Performance Tuning", desc: "Index optimization, query analysis, memory/buffer configuration", color: "#3b82f6" },
            { task: "High Availability", desc: "Replication setup, failover configuration, clustering", color: "#8b5cf6" },
            { task: "Security", desc: "Encryption at rest/transit, audit logging, access controls", color: "#ec4899" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.task}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(item.color, 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.task}</Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Database Maintenance Essentials */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6", display: "flex", alignItems: "center", gap: 1 }}>
            <StorageIcon /> Database Maintenance Essentials
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Reliability and HA</Typography>
              <List dense>
                {[
                  "Automated backups with regular restore tests",
                  "Replication or clustering for failover",
                  "Separate storage for data and logs when possible",
                  "Monitor replication lag and disk growth",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Performance and Maintenance</Typography>
              <List dense>
                {[
                  "Review slow query logs and add indexes",
                  "Run vacuum/analyze or optimize tasks",
                  "Capacity planning for storage and IOPS",
                  "Least-privilege database users and roles",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 14: DOCUMENTATION & PROCEDURES ==================== */}
        <Typography id="documentation" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📝 Documentation & Procedures
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The unsung hero of IT operations
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Documentation is the difference between a 5-minute fix and a 5-hour outage</strong>. When 
            you're troubleshooting at 3 AM with your brain running on coffee fumes, good documentation saves 
            the day. When you leave for a new job, documentation is what you leave behind. When a new team 
            member joins, documentation is how they get up to speed.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Runbooks</strong> document how to perform routine tasks and respond to common incidents. 
            <strong> SOPs (Standard Operating Procedures)</strong> define how processes should be executed. 
            <strong> Architecture diagrams</strong> show how systems connect. <strong>Knowledge bases</strong> 
            capture tribal knowledge that would otherwise exist only in people's heads.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            The best documentation is <strong>kept up to date</strong>. Outdated documentation can be worse 
            than no documentation — it gives false confidence. Build documentation updates into your change 
            process: if you change a system, update the docs.
          </Typography>
        </Paper>

        {/* Types of Documentation */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Types of Documentation</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>📖 Runbooks</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Step-by-step procedures for operational tasks
              </Typography>
              <List dense>
                {[
                  "Incident response procedures",
                  "Maintenance task checklists",
                  "Escalation paths and contacts",
                  "Recovery procedures",
                  "Should be usable by anyone on the team",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>🗺️ Architecture Docs</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                System design and relationships
              </Typography>
              <List dense>
                {[
                  "Network diagrams",
                  "System dependencies",
                  "Data flow diagrams",
                  "DR/failover architecture",
                  "Keep diagrams as code when possible",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>📚 Knowledge Base</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Searchable repository of solutions and info
              </Typography>
              <List dense>
                {[
                  "Troubleshooting guides",
                  "FAQ and common issues",
                  "Vendor-specific notes",
                  "Lessons learned / post-mortems",
                  "Tools: Confluence, Wiki, Notion, GitBook",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Change Management */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
            <SettingsIcon /> Change Management
          </Typography>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Formal process for making changes to production systems. Reduces risk of outages from untested changes.
          </Typography>
          <Grid container spacing={2}>
            {[
              { step: "1. Request", desc: "Document what, why, when, and who" },
              { step: "2. Review", desc: "Peer review, risk assessment" },
              { step: "3. Approve", desc: "CAB or designated approver" },
              { step: "4. Schedule", desc: "Maintenance window, notify stakeholders" },
              { step: "5. Implement", desc: "Execute with rollback plan ready" },
              { step: "6. Verify", desc: "Confirm success, close change record" },
            ].map((item) => (
              <Grid item xs={6} sm={4} md={2} key={item.step}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6" }}>{item.step}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Runbook Template */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
            <DescriptionIcon /> Runbook Template
          </Typography>
          <Typography variant="body2" sx={{ mb: 2 }}>
            A runbook should be short, tested, and easy to follow under pressure. Use a consistent structure so anyone can execute it.
          </Typography>
          <Paper sx={{ p: 1.5, bgcolor: "#1e1e1e", borderRadius: 1 }}>
            <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
              Title: Restore Web Server from Backup<br/>
              Purpose: What this runbook achieves<br/>
              Scope: Systems and environments covered<br/>
              Prereqs: Access, tools, approvals required<br/>
              Steps: Numbered actions with expected output<br/>
              Rollback: How to revert if something fails<br/>
              Validation: How to confirm success<br/>
              Escalation: Who to contact and when
            </Typography>
          </Paper>
        </Paper>

        {/* ==================== SECTION 15: TROUBLESHOOTING METHODOLOGY ==================== */}
        <Typography id="troubleshooting" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🔧 Troubleshooting Methodology
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Systematic problem-solving for IT issues
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Troubleshooting is the core skill</strong> that separates good sysadmins from great ones. 
            Anyone can follow a runbook when things work as expected. The real test is when something breaks 
            in a way no one has seen before, users are screaming, and management wants answers. A systematic 
            approach keeps you calm and effective under pressure.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            The key is <strong>not to panic</strong>. Resist the urge to make random changes hoping something 
            works. Each change should be deliberate, documented, and reversible. The worst thing you can do 
            is make a bad situation worse by introducing more variables.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Root cause analysis</strong> goes beyond fixing the immediate problem. Why did this happen? 
            How do we prevent it from happening again? Without RCA, you're just putting out fires instead of 
            building a fireproof house.
          </Typography>
        </Paper>

        {/* Troubleshooting Steps */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Systematic Troubleshooting Process</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { step: "1", title: "Identify the Problem", desc: "What exactly is broken? Who is affected? When did it start? What changed?", color: "#ef4444" },
            { step: "2", title: "Gather Information", desc: "Check logs, monitoring, recent changes. Reproduce if possible. Ask questions.", color: "#f59e0b" },
            { step: "3", title: "Establish Theory", desc: "Based on symptoms, what could cause this? Prioritize by likelihood.", color: "#22c55e" },
            { step: "4", title: "Test Theory", desc: "Test your hypothesis. If wrong, go back to step 3 with new info.", color: "#3b82f6" },
            { step: "5", title: "Implement Solution", desc: "Fix the problem. Document what you did. Have rollback ready.", color: "#8b5cf6" },
            { step: "6", title: "Verify & Document", desc: "Confirm issue resolved. Document root cause and solution. Update runbooks.", color: "#ec4899" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.step}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 3, border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Box sx={{ width: 28, height: 28, borderRadius: "50%", bgcolor: alpha(item.color, 0.1), display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 800, color: item.color }}>{item.step}</Typography>
                  </Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                </Box>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Diagnostic Commands */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Essential Diagnostic Commands</Typography>
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f97316" }}>🐧 Linux</Typography>
              <Paper sx={{ p: 1.5, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  top / htop&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Process/resource usage<br/>
                  df -h&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Disk space<br/>
                  free -m&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Memory usage<br/>
                  netstat -tulpn&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Open ports/connections<br/>
                  ss -tulpn&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Modern netstat<br/>
                  journalctl -xe&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Recent system logs<br/>
                  dmesg | tail&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Kernel messages<br/>
                  ping / traceroute&nbsp;&nbsp;&nbsp;# Network connectivity
                </Typography>
              </Paper>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, borderRadius: 3, border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#0078d4" }}>🪟 Windows</Typography>
              <Paper sx={{ p: 1.5, bgcolor: "#1e1e1e", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9cdcfe" }}>
                  Get-Process | Sort CPU -Desc<br/>
                  Get-Service | Where Status -eq Stopped<br/>
                  Get-EventLog -LogName System -Newest 20<br/>
                  Test-NetConnection host -Port 443<br/>
                  netstat -ano&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Connections with PIDs<br/>
                  Get-Counter '\Processor(_Total)\% Processor Time'<br/>
                  Resolve-DnsName domain.com<br/>
                  tracert hostname&nbsp;&nbsp;&nbsp;&nbsp;# Trace route
                </Typography>
              </Paper>
            </Paper>
          </Grid>
        </Grid>

        {/* Incident Response Timeline */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
            <BuildIcon /> Incident Response Timeline
          </Typography>
          <Grid container spacing={2}>
            {[
              { phase: "Detect", desc: "Alert triggers or user reports. Confirm impact and scope." },
              { phase: "Triage", desc: "Prioritize severity, assign owner, and communicate status." },
              { phase: "Mitigate", desc: "Stabilize service and reduce user impact quickly." },
              { phase: "Recover", desc: "Restore normal operations and verify systems." },
              { phase: "Postmortem", desc: "Document root cause and preventive actions." },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.phase}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.phase}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, mt: 2 }}>Postmortem Questions</Typography>
          <List dense>
            {[
              "What was the customer impact and duration?",
              "Which signals should have alerted us sooner?",
              "What change or condition triggered the incident?",
              "How do we prevent recurrence with automation or guardrails?",
            ].map((item) => (
              <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 24 }}>
                  <CheckCircleIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* ==================== SECTION 16: CAREER PATHS & CERTIFICATIONS ==================== */}
        <Typography id="career-certs" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🚀 Career Paths & Certifications
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Growing your career in systems administration
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Systems administration is a launching pad</strong>, not a dead end. The skills you learn — 
            troubleshooting, automation, infrastructure management — transfer to many related fields. Some 
            sysadmins specialize deeper (security, databases, networking). Others move into DevOps, cloud 
            architecture, or management. The path you choose depends on your interests and goals.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Certifications</strong> validate your knowledge and can open doors, especially early in your 
            career or when transitioning to a new specialty. They're not mandatory, but they demonstrate commitment 
            to learning and provide structured study paths. Focus on certs relevant to your target role and the 
            technologies you work with.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Never stop learning</strong>. Technology evolves constantly. The sysadmin of 2010 managed 
            physical servers in a data center. The sysadmin of today manages hybrid cloud infrastructure, 
            containers, and infrastructure as code. Stay curious, build home labs, contribute to open source, 
            and embrace change.
          </Typography>
        </Paper>

        {/* Career Progression */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Career Progression</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { level: "Entry", title: "Help Desk / IT Support", salary: "$40-55k", skills: "Customer service, basic troubleshooting, ticketing", color: "#22c55e" },
            { level: "Junior", title: "Jr. Systems Administrator", salary: "$55-75k", skills: "Server basics, AD, backups, monitoring", color: "#3b82f6" },
            { level: "Mid", title: "Systems Administrator", salary: "$75-100k", skills: "Full server lifecycle, automation, projects", color: "#8b5cf6" },
            { level: "Senior", title: "Sr. Systems Administrator", salary: "$100-130k", skills: "Architecture, mentoring, complex troubleshooting", color: "#f59e0b" },
            { level: "Lead", title: "Lead / Principal Engineer", salary: "$130-160k+", skills: "Strategy, cross-team leadership, standards", color: "#ef4444" },
            { level: "Mgmt", title: "IT Manager / Director", salary: "$120-180k+", skills: "People management, budgets, vendor relations", color: "#ec4899" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.level}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(item.color, 0.2)}`, height: "100%" }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.5 }}>
                  <Chip label={item.level} size="small" sx={{ fontSize: "0.65rem", height: 18, bgcolor: alpha(item.color, 0.1), color: item.color, fontWeight: 700 }} />
                  <Typography variant="caption" sx={{ fontWeight: 600, color: "#22c55e" }}>{item.salary}</Typography>
                </Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>{item.title}</Typography>
                <Typography variant="caption" color="text.secondary">{item.skills}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Specializations */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Specialization Paths</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { path: "DevOps / SRE", desc: "CI/CD, IaC, Kubernetes, reliability engineering", hot: true },
            { path: "Cloud Engineer", desc: "AWS, Azure, GCP architecture and operations", hot: true },
            { path: "Security Engineer", desc: "Hardening, compliance, incident response", hot: true },
            { path: "Database Administrator", desc: "Performance tuning, HA, data management", hot: false },
            { path: "Network Engineer", desc: "Routing, switching, firewalls, SD-WAN", hot: false },
            { path: "Virtualization Specialist", desc: "VMware, Hyper-V, VDI, cloud migrations", hot: false },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.path}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#6366f1", 0.15)}`, height: "100%" }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.path}</Typography>
                  {item.hot && <Chip label="Hot" size="small" sx={{ fontSize: "0.6rem", height: 16, bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />}
                </Box>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Certifications */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Recommended Certifications</Typography>
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>🏅 CompTIA</Typography>
              <List dense>
                {[
                  { cert: "A+", desc: "IT fundamentals, hardware, troubleshooting" },
                  { cert: "Network+", desc: "Networking concepts and troubleshooting" },
                  { cert: "Security+", desc: "Security fundamentals (often required)" },
                  { cert: "Server+", desc: "Server administration (less common)" },
                  { cert: "Linux+", desc: "Linux administration basics" },
                ].map((item) => (
                  <ListItem key={item.cert} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.cert} 
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>🐧 Linux / Red Hat</Typography>
              <List dense>
                {[
                  { cert: "RHCSA", desc: "Red Hat Certified System Administrator" },
                  { cert: "RHCE", desc: "Red Hat Certified Engineer" },
                  { cert: "LFCS", desc: "Linux Foundation Certified Sysadmin" },
                  { cert: "LPIC-1/2/3", desc: "Linux Professional Institute certs" },
                ].map((item) => (
                  <ListItem key={item.cert} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.cert} 
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0078d4" }}>☁️ Cloud & Microsoft</Typography>
              <List dense>
                {[
                  { cert: "AZ-104", desc: "Azure Administrator Associate" },
                  { cert: "AWS SysOps", desc: "AWS SysOps Administrator" },
                  { cert: "GCP Associate", desc: "Google Cloud Associate Engineer" },
                  { cert: "MS-102", desc: "Microsoft 365 Administrator" },
                ].map((item) => (
                  <ListItem key={item.cert} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.cert} 
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Key Takeaways */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon sx={{ color: "#10b981" }} />
            Key Takeaways for Your SysAdmin Journey
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Build a Home Lab</Typography>
              <Typography variant="body2" color="text.secondary">
                Nothing beats hands-on experience. Old hardware, VMs, or cloud free tiers — practice breaking 
                and fixing things in a safe environment.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Automate Everything</Typography>
              <Typography variant="body2" color="text.secondary">
                Learn scripting early. Bash, PowerShell, Python. The ability to automate is what separates 
                good sysadmins from great ones.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Stay Curious</Typography>
              <Typography variant="body2" color="text.secondary">
                Technology never stops evolving. Embrace continuous learning. Read blogs, follow experts, 
                attend meetups, and experiment with new tools.
              </Typography>
            </Grid>
          </Grid>
        </Paper>

        <Typography id="prerequisites" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📋 Prerequisites
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          What you should know before diving into systems administration
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
                ✅ Should Have
              </Typography>
              <List dense>
                {[
                  "Basic computer literacy",
                  "Understanding of file systems",
                  "Familiarity with command line basics",
                  "Basic networking concepts (IP, DNS)",
                  "Patience and willingness to learn",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                ⚡ Helpful to Have
              </Typography>
              <List dense>
                {[
                  "Windows or Linux desktop experience",
                  "Basic scripting knowledge",
                  "Home lab or VM environment",
                  "Help desk or support experience",
                  "Networking fundamentals (OSI model)",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <TipsAndUpdatesIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                📚 We'll Teach You
              </Typography>
              <List dense>
                {[
                  "Server installation and configuration",
                  "User and permission management",
                  "Essential services (DNS, DHCP)",
                  "Backup strategies",
                  "Monitoring and troubleshooting",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <SchoolIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== NEXT STEPS ==================== */}
        <Typography id="next-steps" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🚀 Next Steps
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Continue your learning journey with these related topics
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { title: "Linux Fundamentals", path: "/learn/linux-fundamentals", color: "#f97316", description: "Master the Linux command line" },
            { title: "Windows Fundamentals", path: "/learn/windows-basics", color: "#0078d4", description: "Windows OS deep dive" },
            { title: "Computer Networking", path: "/learn/networking", color: "#0ea5e9", description: "Networking essentials" },
            { title: "Cloud Computing", path: "/learn/cloud-computing", color: "#8b5cf6", description: "Cloud infrastructure basics" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.title}>
              <Paper
                onClick={() => navigate(item.path)}
                sx={{
                  p: 2.5,
                  textAlign: "center",
                  cursor: "pointer",
                  borderRadius: 3,
                  border: `1px solid ${alpha(item.color, 0.2)}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    borderColor: item.color,
                    boxShadow: `0 8px 24px ${alpha(item.color, 0.2)}`,
                  },
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>
                  {item.title}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {item.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Key Takeaways */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon sx={{ color: "#10b981" }} />
            Key Takeaways
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>It's About Uptime</Typography>
              <Typography variant="body2" color="text.secondary">
                Your primary job is keeping systems running reliably. Everything else — security, performance, 
                automation — supports that goal.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Document Everything</Typography>
              <Typography variant="body2" color="text.secondary">
                Future you (and your colleagues) will thank you. Good documentation is the difference between 
                a 5-minute fix and a 5-hour outage.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Automate Relentlessly</Typography>
              <Typography variant="body2" color="text.secondary">
                If you do something twice, script it. Automation reduces errors, saves time, and lets you 
                focus on more interesting problems.
              </Typography>
            </Grid>
          </Grid>
        </Paper>

        {/* Quiz Section */}
        <Box id="quiz" sx={{ mt: 5 }}>
          <QuizSection
            questions={quizPool}
            accentColor={ACCENT_COLOR}
            title="Systems Administration Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Box>

        {/* Footer Navigation */}
        <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
          <Button
            variant="outlined"
            size="large"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{
              borderRadius: 2,
              px: 4,
              py: 1.5,
              fontWeight: 600,
              borderColor: alpha("#3b82f6", 0.3),
              color: "#3b82f6",
              "&:hover": {
                borderColor: "#3b82f6",
                bgcolor: alpha("#3b82f6", 0.05),
              },
            }}
          >
            Return to Learning Hub
          </Button>
        </Box>
      </Box>
      </Box>
    </LearnPageLayout>
  );
}
