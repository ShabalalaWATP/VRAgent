import React from "react";
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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import FolderSpecialIcon from "@mui/icons-material/FolderSpecial";
import GitHubIcon from "@mui/icons-material/GitHub";
import CreateIcon from "@mui/icons-material/Create";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import BugReportIcon from "@mui/icons-material/BugReport";
import PublicIcon from "@mui/icons-material/Public";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import StarIcon from "@mui/icons-material/Star";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import HomeIcon from "@mui/icons-material/Home";
import SchoolIcon from "@mui/icons-material/School";
import WorkIcon from "@mui/icons-material/Work";
import SecurityIcon from "@mui/icons-material/Security";
import CodeIcon from "@mui/icons-material/Code";
import TerminalIcon from "@mui/icons-material/Terminal";
import StorageIcon from "@mui/icons-material/Storage";
import CloudIcon from "@mui/icons-material/Cloud";
import PsychologyIcon from "@mui/icons-material/Psychology";
import VerifiedIcon from "@mui/icons-material/Verified";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import GroupsIcon from "@mui/icons-material/Groups";
import VideocamIcon from "@mui/icons-material/Videocam";
import ArticleIcon from "@mui/icons-material/Article";
import BuildIcon from "@mui/icons-material/Build";
import ShieldIcon from "@mui/icons-material/Shield";
import WarningIcon from "@mui/icons-material/Warning";
import LinkIcon from "@mui/icons-material/Link";
import AssessmentIcon from "@mui/icons-material/Assessment";
import UpdateIcon from "@mui/icons-material/Update";
import LocationOnIcon from "@mui/icons-material/LocationOn";
import FolderIcon from "@mui/icons-material/Folder";
import AssignmentIcon from "@mui/icons-material/Assignment";
import VisibilityIcon from "@mui/icons-material/Visibility";
import AutoStoriesIcon from "@mui/icons-material/AutoStories";
import RouteIcon from "@mui/icons-material/Route";
import QuestionAnswerIcon from "@mui/icons-material/QuestionAnswer";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import { useNavigate } from "react-router-dom";

interface PortfolioSection {
  title: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  items: string[];
  tip: string;
}

const portfolioSections: PortfolioSection[] = [
  {
    title: "GitHub Projects",
    icon: <GitHubIcon sx={{ fontSize: 36 }} />,
    color: "#6366f1",
    description: "Showcase your technical skills with public repositories demonstrating real security work.",
    items: [
      "Security tools (scanners, fuzzers, parsers, analyzers)",
      "CTF writeups with solution scripts and methodology",
      "Home lab automation (Ansible, Terraform, Docker configs)",
      "Vulnerability research and PoCs (responsibly disclosed)",
      "Contributions to major open-source security projects",
      "Custom detection rules (Sigma, YARA, Snort/Suricata)",
      "Malware analysis reports and reverse engineering notes",
      "Security automation scripts and integrations",
    ],
    tip: "Keep repos organized with clear READMEs, proper documentation, meaningful commit history, and CI/CD where applicable.",
  },
  {
    title: "Blog / Technical Writing",
    icon: <CreateIcon sx={{ fontSize: 36 }} />,
    color: "#ec4899",
    description: "Demonstrate expertise, analytical thinking, and communication skills through writing.",
    items: [
      "CTF walkthroughs with step-by-step explanations",
      "Vulnerability analysis and root cause breakdowns",
      "Tool tutorials, comparisons, and how-to guides",
      "Career reflections, lessons learned, and mentorship posts",
      "News commentary, threat intelligence, and trend analysis",
      "Research papers, whitepapers, and technical deep-dives",
      "Conference talk write-ups and presentation notes",
      "Book reviews and learning resource recommendations",
    ],
    tip: "Platforms: Medium, DEV.to, Hashnode, Substack, personal Hugo/Jekyll site, or GitHub Pages. Cross-post for visibility.",
  },
  {
    title: "CTF Achievements",
    icon: <EmojiEventsIcon sx={{ fontSize: 36 }} />,
    color: "#f59e0b",
    description: "Prove your hands-on skills through competitive hacking and gamified challenges.",
    items: [
      "HackTheBox rank, Pro Labs completion, machine writeups",
      "TryHackMe badges, learning paths, and streak achievements",
      "CTFtime profile with event history and team rankings",
      "Notable placements in major competitions (DEF CON, PicoCTF, etc.)",
      "Specialization areas (web, pwn, crypto, forensics, reversing)",
      "PentesterLab badges and exercise completions",
      "PortSwigger Web Security Academy progress",
      "Root-Me, OverTheWire, and Cryptohack achievements",
    ],
    tip: "Document your journey with screenshots, writeups (after events end), and methodology notes. Show progression over time.",
  },
  {
    title: "Bug Bounty & Research",
    icon: <BugReportIcon sx={{ fontSize: 36 }} />,
    color: "#ef4444",
    description: "Show real-world impact through responsible disclosure and original research.",
    items: [
      "Hall of Fame listings from companies (Google, Microsoft, etc.)",
      "CVEs you've discovered, reported, and got assigned",
      "HackerOne / Bugcrowd / Intigriti reputation and statistics",
      "Detailed case studies (with permission and proper redaction)",
      "Methodology documentation and recon techniques",
      "Payout statistics and severity distribution",
      "Coordination with vendors and responsible disclosure timelines",
      "Conference presentations on disclosed vulnerabilities",
    ],
    tip: "Focus on quality findings over quantity. One critical RCE beats dozens of low-severity informational reports.",
  },
  {
    title: "Home Lab Documentation",
    icon: <HomeIcon sx={{ fontSize: 36 }} />,
    color: "#10b981",
    description: "Demonstrate practical infrastructure skills with documented lab environments.",
    items: [
      "Network diagrams and architecture documentation",
      "Active Directory lab with attack/defend scenarios",
      "SIEM deployment (Splunk, ELK, Wazuh) with custom dashboards",
      "Malware analysis sandbox setup and procedures",
      "Cloud security lab (AWS, Azure, GCP) configurations",
      "Container security testing environment (Kubernetes, Docker)",
      "ICS/SCADA simulation lab documentation",
      "Purple team exercise documentation and playbooks",
    ],
    tip: "Use draw.io or Excalidraw for diagrams. Document everything as if someone else needs to reproduce it.",
  },
  {
    title: "Certifications & Training",
    icon: <SchoolIcon sx={{ fontSize: 36 }} />,
    color: "#8b5cf6",
    description: "Validate your knowledge with recognized industry certifications.",
    items: [
      "OSCP, OSWE, OSEP, OSED, OSCE3 (OffSec certifications)",
      "GIAC certifications (GPEN, GCIH, GWAPT, GREM, etc.)",
      "CompTIA Security+, CySA+, PenTest+, CASP+",
      "AWS/Azure/GCP security specialty certifications",
      "CREST certifications (CRT, CCT, CPSA)",
      "ISC2 certifications (CISSP, SSCP, CCSP)",
      "Vendor-specific (CCNA Security, Fortinet NSE, etc.)",
      "Continuous learning evidence (SANS, Pluralsight, etc.)",
    ],
    tip: "Show the certification badges, but also demonstrate how you apply the knowledge in practical projects.",
  },
];

// Expanded online presence tips
const presenceTips = [
  "LinkedIn profile optimized with security keywords, certifications, and detailed experience",
  "Twitter/X for engaging with security community, sharing research, and following researchers",
  "Conference talks, even at local BSides or meetups, significantly boost credibility",
  "Podcast appearances, YouTube content, or Twitch streams on security topics",
  "Newsletter (Substack, Ghost) or community Discord/Slack involvement",
  "Mastodon (infosec.exchange) for alternative social presence",
  "Personal website/domain showing professionalism and ownership of your brand",
  "Stack Overflow or Security StackExchange contributions",
  "Open-source contributions with visible GitHub activity graph",
  "Mentorship programs (informal or through SANS, ISC2, etc.)",
];

const portfolioMistakes = [
  "Empty GitHub with no commits or meaningful activity for months",
  "Claiming skills you can't demonstrate or explain in an interview",
  "Sharing tools without context, documentation, or usage examples",
  "Exposing sensitive info (API keys, real target IPs, credentials)",
  "Not updating portfolio for months/years - shows lack of engagement",
  "Copying others' work without attribution or understanding",
  "Publishing exploit code for actively vulnerable production systems",
  "Overly complex projects with no clear purpose or value proposition",
  "Poor grammar, spelling, or unprofessional writing in documentation",
  "No clear way to contact you or verify your identity",
  "Mixing personal opinions/politics with professional content",
  "Focusing only on offensive skills when applying for defensive roles",
];

// Expanded role tracks with much more detail
const roleTracks = [
  {
    role: "Application Security Engineer",
    icon: <CodeIcon />,
    color: "#6366f1",
    focus: "Secure code review, web/API testing, SDLC integration, threat modeling",
    examples: [
      "OWASP Top 10 lab implementations with fixes",
      "SAST/DAST tool comparison and integration guides",
      "Secure code review findings with remediation examples",
      "Threat models for common architectures (microservices, SPAs)",
      "CI/CD security pipeline configurations (GitHub Actions, GitLab CI)",
      "API security testing methodology documentation",
      "Secure coding guidelines and developer training materials",
    ],
    platforms: ["OWASP WebGoat", "DVWA", "Juice Shop", "crAPI", "Damn Vulnerable GraphQL"],
    certifications: ["OSWE", "GWAPT", "CASE", "CSSLP", "AWS Security Specialty"],
  },
  {
    role: "Cloud Security Engineer",
    icon: <CloudIcon />,
    color: "#3b82f6",
    focus: "Cloud security posture, IaC hardening, container security, DevSecOps",
    examples: [
      "Terraform/Pulumi security modules with compliance checks",
      "CSPM findings and remediation playbooks",
      "Container security scanning pipeline (Trivy, Grype, Snyk)",
      "Kubernetes security configurations and policies (OPA/Gatekeeper)",
      "Cloud-native SIEM integration (CloudTrail, Azure Sentinel)",
      "Multi-cloud security architecture comparisons",
      "Serverless security patterns and implementations",
    ],
    platforms: ["CloudGoat", "Flaws.cloud", "DVCA", "Kubernetes Goat", "TerraGoat"],
    certifications: ["AWS Security Specialty", "AZ-500", "GCP Security", "CKS", "CCSK"],
  },
  {
    role: "Penetration Tester",
    icon: <SecurityIcon />,
    color: "#ef4444",
    focus: "End-to-end engagements, network/web/AD testing, professional reporting",
    examples: [
      "Full penetration test reports with executive summaries",
      "Active Directory attack path documentation and diagrams",
      "Scoping questionnaires and rules of engagement templates",
      "Custom exploitation tools and payloads (sanitized)",
      "Red team operation playbooks and TTPs",
      "Physical security assessment methodology",
      "Wireless penetration testing documentation",
    ],
    platforms: ["HackTheBox Pro Labs", "Offshore", "RastaLabs", "DVWA", "Metasploitable"],
    certifications: ["OSCP", "OSEP", "GPEN", "CRTO", "PNPT", "eCPPT", "CREST CRT/CCT"],
  },
  {
    role: "SOC Analyst / Threat Detection",
    icon: <ShieldIcon />,
    color: "#10b981",
    focus: "Log analysis, SIEM operations, detection engineering, incident response",
    examples: [
      "Sigma detection rules mapped to MITRE ATT&CK",
      "SIEM queries and dashboards (Splunk SPL, KQL, Lucene)",
      "Detection coverage matrix and gap analysis",
      "Incident response playbooks and runbooks",
      "Threat hunting hypothesis documentation",
      "Alert triage and escalation procedures",
      "Malware analysis reports with IOCs",
    ],
    platforms: ["Blue Team Labs Online", "LetsDefend", "CyberDefenders", "Splunk BOTS"],
    certifications: ["GCIH", "GCIA", "GCFA", "BTL1", "CySA+", "SC-200", "Splunk Core"],
  },
  {
    role: "Threat Intelligence Analyst",
    icon: <PsychologyIcon />,
    color: "#8b5cf6",
    focus: "Threat research, APT tracking, intelligence reporting, OSINT",
    examples: [
      "APT group profile and campaign analysis",
      "Malware family technical analysis reports",
      "OSINT investigation methodology documentation",
      "Threat intelligence platform integrations (MISP, OpenCTI)",
      "Diamond Model and Kill Chain analyses",
      "Geopolitical cyber threat assessments",
      "Dark web monitoring and research methodology",
    ],
    platforms: ["MITRE ATT&CK Navigator", "ANY.RUN", "VirusTotal", "Shodan", "Censys"],
    certifications: ["GCTI", "CTIA", "FOR578", "OSINT certifications"],
  },
  {
    role: "Security Engineer / Architect",
    icon: <BuildIcon />,
    color: "#f59e0b",
    focus: "Security infrastructure, zero trust architecture, security tool deployment",
    examples: [
      "Zero Trust architecture designs and implementations",
      "Network segmentation and microsegmentation plans",
      "Security tool evaluation and comparison matrices",
      "Identity and access management implementations",
      "Encryption and key management architectures",
      "Security operations center (SOC) designs",
      "Disaster recovery and business continuity plans",
    ],
    platforms: ["Home lab environments", "Cloud sandboxes", "GNS3/EVE-NG"],
    certifications: ["CISSP", "CCSP", "SABSA", "TOGAF", "CISM"],
  },
  {
    role: "GRC / Compliance Analyst",
    icon: <VerifiedIcon />,
    color: "#64748b",
    focus: "Risk assessment, compliance frameworks, policy development, auditing",
    examples: [
      "Risk assessment templates and methodologies",
      "Compliance mapping documents (SOC 2, ISO 27001, PCI DSS)",
      "Security policy templates and frameworks",
      "Audit preparation checklists and evidence collection",
      "Vendor security assessment questionnaires",
      "Privacy impact assessment documentation",
      "Control implementation evidence portfolios",
    ],
    platforms: ["NIST CSF", "CIS Controls", "ISO 27001", "SOC 2 frameworks"],
    certifications: ["CISA", "CRISC", "CGRC", "ISO 27001 Lead Auditor", "CIPP/E"],
  },
  {
    role: "Malware Analyst / Reverse Engineer",
    icon: <TerminalIcon />,
    color: "#dc2626",
    focus: "Malware analysis, reverse engineering, threat research, IOC extraction",
    examples: [
      "Malware analysis reports with behavioral and static analysis",
      "Reverse engineering writeups (Ghidra, IDA, x64dbg)",
      "YARA rules for malware family detection",
      "Unpacking and deobfuscation techniques documentation",
      "Sandbox setup and automation scripts",
      "C2 protocol analysis and emulation",
      "Memory forensics analysis reports",
    ],
    platforms: ["FlareVM", "REMnux", "ANY.RUN", "Malware Traffic Analysis", "crackmes.one"],
    certifications: ["GREM", "OSED", "OSCE3", "FOR610", "eCMAP"],
  },
];

const caseStudyTemplate = [
  "Title + 1-line impact statement (e.g., 'Critical RCE in Widget Corp API')",
  "Scope and rules of engagement (lab, authorized target, bug bounty program)",
  "Methodology breakdown (recon techniques, testing approach, tools used)",
  "Finding details (root cause analysis, impact assessment, CVSS if applicable)",
  "Technical deep-dive (code snippets, request/response examples, screenshots)",
  "Fix recommendations and verification steps (how you confirmed remediation)",
  "Artifacts gallery (PoC, screenshots, logs, timeline)",
  "Lessons learned, next steps, and what you'd do differently",
  "Acknowledgments and disclosure timeline (if applicable)",
];

const qualityChecklist = [
  "Clear README with project purpose, setup instructions, and screenshots",
  "Reproducible steps that work on a clean machine or fresh environment",
  "Dependencies pinned with versions and documented installation process",
  "License clearly stated (MIT, Apache 2.0, GPL, etc.) and contribution guidelines",
  "Clean commit history with meaningful messages (no 'asdf' or 'fix stuff')",
  "Security considerations documented (safe usage notes, ethical guidelines)",
  "Tests included where applicable (unit tests, integration tests)",
  "CI/CD pipeline status badge displayed in README",
  "Issue templates and PR templates for contributors",
  "CHANGELOG or release notes for versioned projects",
];

const evidenceArtifacts = [
  "PoC scripts or payloads (sanitized, no live targets)",
  "Architecture diagrams (draw.io, Excalidraw, Mermaid)",
  "Threat model documents (STRIDE, PASTA, attack trees)",
  "Scan reports or findings summaries (redacted appropriately)",
  "Before/after remediation evidence with diff comparisons",
  "Writeups linked to repo tags or releases for versioning",
  "Short demo videos or GIFs (Asciinema for terminal, OBS for GUI)",
  "Jupyter notebooks for data analysis and visualization",
  "Network diagrams and packet captures (sanitized)",
  "Timeline diagrams for incident response or attack chains",
  "Code snippets with syntax highlighting and annotations",
  "MITRE ATT&CK mapping visualizations",
];

const metricsThatMatter = [
  "Impact: severity rating, affected scope, potential business risk, CVSS score",
  "Coverage: what was tested, out of scope items, testing limitations",
  "Reproducibility: clear steps, environment requirements, expected output",
  "Signal quality: false positive rate, true positive confirmation method",
  "Performance: runtime benchmarks, scalability notes, resource usage",
  "Completeness: edge cases covered, negative test cases, boundary testing",
  "Time investment: hours spent, phases, learning curve considerations",
];

const safetyGuidelines = [
  "Only test systems you own or have explicit written authorization to test",
  "Use labs, CTF platforms, or targets with explicit permission always",
  "Redact all tokens, API keys, IPs, hostnames, and PII from public content",
  "Never publish exploit code for actively vulnerable production systems",
  "Follow responsible disclosure timelines (90 days industry standard)",
  "Call out assumptions, limitations, and ethical considerations clearly",
  "Include disclaimers about educational purpose and legal compliance",
  "Don't include real malware samples without proper warnings and precautions",
  "Respect NDAs and client confidentiality in all case studies",
  "Blur or redact sensitive data in screenshots and videos",
];

const maintenanceCadence = [
  "Ship a meaningful update every 4-6 weeks to show consistent activity",
  "Archive outdated projects with a deprecation note explaining why",
  "Track a public roadmap or backlog using GitHub Projects or similar",
  "Refresh screenshots and demos after major changes or UI updates",
  "Review and update dependencies quarterly for security patches",
  "Respond to issues and PRs within 48-72 hours when possible",
  "Write release notes for significant updates or milestones",
  "Cross-post updates to social media to maintain visibility",
];

const portfolioBlueprint = [
  { section: "Homepage / About", detail: "Who you are, focus areas, career objectives, and 2-3 featured projects that represent your best work." },
  { section: "Projects Gallery", detail: "Detailed case studies with scope, methodology, impact assessment, and downloadable artifacts." },
  { section: "Technical Writing", detail: "Blog posts, research summaries, CTF writeups, and thought leadership pieces." },
  { section: "Talks & Media", detail: "Conference slides, video recordings, podcast appearances, and presentation abstracts." },
  { section: "Certifications", detail: "Verified badges, exam dates, and brief descriptions of what each certification covers." },
  { section: "Resume / CV", detail: "One-page PDF with keywords, skills matrix, and links to supporting evidence." },
  { section: "Contact & Social", detail: "Professional email, LinkedIn, GitHub, Twitter/X, and preferred contact method." },
  { section: "Testimonials", detail: "Quotes from colleagues, mentors, or clients (with permission) about your work quality." },
];

const projectIdeasByLevel = [
  {
    level: "Beginner",
    color: "#10b981",
    ideas: [
      "Home lab inventory report with asset list and basic vulnerability findings",
      "Simple web scanner or log parser with clear README and basic tests",
      "CTF writeups focused on one category (web, crypto, forensics, or pwn)",
      "Threat model document for a common application (login flow, REST API)",
      "Security awareness training presentation for non-technical audience",
      "Password policy analyzer tool with strength recommendations",
      "Phishing email analysis report with indicators and detection tips",
      "Basic SIEM query collection for common security events",
      "Network diagram of your home lab with security controls documented",
      "Comparison review of two security tools in the same category",
    ],
  },
  {
    level: "Intermediate",
    color: "#f59e0b",
    ideas: [
      "Mini penetration test report with scope definition, evidence, and fix recommendations",
      "CI/CD security pipeline with SAST, DAST, SCA, and secrets scanning integrated",
      "Container hardening guide with CIS benchmarks and automated scanning",
      "Detection rules (Sigma/YARA) mapped to MITRE ATT&CK techniques",
      "Incident response playbook for a specific threat scenario (ransomware, BEC)",
      "Bug bounty program case study (redacted) with methodology breakdown",
      "Cloud security assessment for a sample AWS/Azure/GCP environment",
      "Active Directory lab writeup with common attack paths demonstrated",
      "Malware analysis report with static and dynamic analysis findings",
      "API security testing methodology with Postman/Burp collections",
      "Threat intelligence report on a specific APT group or malware family",
      "Security architecture review template with risk scoring",
    ],
  },
  {
    level: "Advanced",
    color: "#ef4444",
    ideas: [
      "Original security tool with performance benchmarks and release automation",
      "Vulnerability research writeup with responsible disclosure coordination",
      "Cloud posture assessment with custom compliance framework mapping",
      "Purple team exercise documentation with detection and response analysis",
      "Exploit development writeup (buffer overflow, format string, ROP chains)",
      "Reverse engineering analysis of a real malware sample with C2 protocol docs",
      "Zero Trust architecture design with implementation guide",
      "Detection engineering project with coverage metrics and gap analysis",
      "Custom C2 framework (educational) with evasion techniques documented",
      "Kernel exploitation research and writeup (Linux or Windows)",
      "Machine learning for security project (malware classification, anomaly detection)",
      "Open-source contribution to major security project (Metasploit, Burp extensions)",
      "Full red team engagement report (sanitized) with TTPs documented",
      "Security research paper submitted to a conference or journal",
    ],
  },
];

const reviewerChecklist = [
  "Is the project goal crystal clear within the first 1-2 sentences?",
  "Can I reproduce the results quickly without extensive troubleshooting?",
  "Do you show measurable impact and explain how you validated findings?",
  "Is the work properly scoped with ethical considerations addressed?",
  "Are results organized, well-formatted, and easy to skim?",
  "Is there evidence of iteration and improvement over time?",
  "Does the project demonstrate both technical skill and communication ability?",
  "Are dependencies, setup steps, and prerequisites clearly documented?",
];

const interviewHooks = [
  "Top 3 project stories you can demo live with screen sharing",
  "One significant failure and how you learned from and fixed it",
  "A project that shows teamwork, collaboration, or mentorship",
  "A project that shows automation, efficiency, or scale",
  "Technical deep-dive you can explain at multiple levels of detail",
  "Example of receiving and incorporating feedback constructively",
  "Story about debugging a complex, multi-layered problem",
  "Example of balancing security with business requirements",
];

const storytellingFramework = [
  "Situation: the environment, context, constraints, and stakeholders involved",
  "Task: what you specifically set out to accomplish and why it mattered",
  "Action: detailed steps taken, tools used, decisions made, and pivots along the way",
  "Result: quantifiable impact, evidence collected, lessons for the organization",
  "Reflection: what you learned, what you'd do differently, how it shaped your approach",
];

const signalToEmployers = [
  "Clarity: easy to understand and navigate, professional presentation",
  "Depth: not just outputs, but reasoning, methodology, and trade-offs",
  "Safety: ethical scope, responsible data handling, and professional judgment",
  "Rigor: validation steps, reproducibility, and attention to detail",
  "Communication: concise, professional writing tailored to the audience",
  "Growth: evidence of learning, iteration, and skill development over time",
  "Collaboration: contributions to teams, communities, or open source",
  "Business awareness: understanding of risk, priorities, and stakeholder needs",
];

// New: GitHub Project Examples
const githubProjectExamples = [
  {
    category: "Security Scanners & Tools",
    examples: [
      { name: "Web vulnerability scanner", description: "Automated scanner for OWASP Top 10 with report generation", tech: "Python, requests, BeautifulSoup" },
      { name: "Subdomain enumeration tool", description: "Multi-source subdomain discovery with DNS validation", tech: "Go, concurrent workers, API integrations" },
      { name: "Secret scanner", description: "Git repository scanner for leaked credentials and API keys", tech: "Python, regex patterns, Git hooks" },
      { name: "Port scanner", description: "Fast async port scanner with service detection", tech: "Python asyncio, Rust, or Go" },
      { name: "SSL/TLS analyzer", description: "Certificate chain validator and configuration checker", tech: "Python, OpenSSL bindings" },
    ],
  },
  {
    category: "Detection & Monitoring",
    examples: [
      { name: "Sigma rule collection", description: "Custom detection rules for specific threats mapped to ATT&CK", tech: "YAML, Sigma format" },
      { name: "YARA rules repository", description: "Malware family detection signatures with test samples", tech: "YARA, documentation" },
      { name: "Log analyzer", description: "Security event parser for Windows/Linux with alerting", tech: "Python, ELK integration" },
      { name: "Network traffic analyzer", description: "PCAP parser for suspicious pattern detection", tech: "Python, Scapy, Zeek" },
      { name: "File integrity monitor", description: "Real-time file change detection with alerting", tech: "Python, Go, inotify/FSEvents" },
    ],
  },
  {
    category: "Automation & Integration",
    examples: [
      { name: "Security pipeline", description: "CI/CD security scanning integration (SAST, DAST, SCA)", tech: "GitHub Actions, GitLab CI, Docker" },
      { name: "Incident response automation", description: "SOAR playbook implementations for common scenarios", tech: "Python, API integrations" },
      { name: "Threat intel aggregator", description: "IOC collector from multiple feeds with deduplication", tech: "Python, MISP integration" },
      { name: "Vulnerability management", description: "Scanner result aggregator with prioritization logic", tech: "Python, PostgreSQL, REST API" },
      { name: "Compliance checker", description: "Automated CIS benchmark validation for cloud/servers", tech: "Python, Ansible, Terraform" },
    ],
  },
  {
    category: "CTF & Learning Tools",
    examples: [
      { name: "CTF writeups repository", description: "Organized challenge solutions with methodology notes", tech: "Markdown, scripts, screenshots" },
      { name: "Vulnerable application", description: "Custom intentionally vulnerable app for training", tech: "Python Flask, Node.js, Docker" },
      { name: "Crypto challenge solver", description: "Common CTF cryptography attack implementations", tech: "Python, SageMath" },
      { name: "Binary exploitation toolkit", description: "Collection of exploit development helpers", tech: "Python, pwntools, GDB scripts" },
      { name: "Forensics toolkit", description: "Evidence collection and analysis automation", tech: "Python, Volatility plugins" },
    ],
  },
];

// New: CTF Platform Details
const ctfPlatforms = [
  {
    name: "HackTheBox",
    url: "hackthebox.com",
    type: "Offensive",
    description: "Industry-leading platform with realistic machines and Pro Labs for certification prep",
    focus: ["Active machines", "Retired machines", "Pro Labs (AD, Cloud)", "Challenges", "Battlegrounds"],
    portfolioTip: "Show your rank progression over time, Pro Lab completions, and machine writeups (retired only)",
  },
  {
    name: "TryHackMe",
    url: "tryhackme.com",
    type: "Learning",
    description: "Beginner-friendly guided learning paths with gamification and structured progression",
    focus: ["Learning paths", "Rooms (guided challenges)", "King of the Hill", "Advent of Cyber"],
    portfolioTip: "Display completed learning paths, streak achievements, and room completion certificates",
  },
  {
    name: "PentesterLab",
    url: "pentesterlab.com",
    type: "Web Security",
    description: "Web application security focused with progressive difficulty exercises",
    focus: ["Web exploitation", "Code review", "Real-world CVE exercises", "Badge system"],
    portfolioTip: "Showcase badge completions and highlight any rare or difficult badges earned",
  },
  {
    name: "PortSwigger Web Security Academy",
    url: "portswigger.net/web-security",
    type: "Web Security",
    description: "Free, comprehensive web security training from the makers of Burp Suite",
    focus: ["Lab exercises", "All OWASP categories", "Expert-level challenges", "Certification"],
    portfolioTip: "Link to your completed labs list and any certification achievements",
  },
  {
    name: "Blue Team Labs Online",
    url: "blueteamlabs.online",
    type: "Defensive",
    description: "Blue team focused challenges for SOC analysts and incident responders",
    focus: ["Incident response", "SIEM analysis", "Malware analysis", "Forensics"],
    portfolioTip: "Perfect for defensive portfolios - show challenge completions and writeups",
  },
  {
    name: "LetsDefend",
    url: "letsdefend.io",
    type: "Defensive",
    description: "SOC analyst training with realistic alert triage and investigation scenarios",
    focus: ["SOC simulation", "Alert investigation", "Malware analysis", "Threat intelligence"],
    portfolioTip: "Document your analyst score, completed investigations, and detection rules created",
  },
  {
    name: "CyberDefenders",
    url: "cyberdefenders.org",
    type: "Defensive",
    description: "Blue team challenges including memory forensics, network analysis, and DFIR",
    focus: ["DFIR challenges", "Memory forensics", "Network forensics", "Threat hunting"],
    portfolioTip: "Great for DFIR portfolios - writeups show analytical thinking and tool proficiency",
  },
  {
    name: "Root-Me",
    url: "root-me.org",
    type: "Mixed",
    description: "Large variety of challenges across all categories with point-based ranking",
    focus: ["Web", "Cryptography", "Steganography", "Forensics", "Programming", "Reversing"],
    portfolioTip: "Show your overall rank and highlight categories where you excel",
  },
];

// New: UK-specific portfolio considerations
const ukPortfolioTips = [
  {
    category: "UK Compliance Focus",
    tips: [
      "Demonstrate knowledge of UK GDPR and Data Protection Act 2018 requirements",
      "Show experience with UK Cyber Essentials and Cyber Essentials Plus",
      "Reference NCSC guidance and 10 Steps to Cyber Security framework",
      "Include PCI DSS knowledge if relevant (heavily used in UK financial sector)",
      "Highlight any NHS Digital / DSPT experience for healthcare roles",
      "Show awareness of FCA regulations for financial services security roles",
    ],
  },
  {
    category: "UK Certifications",
    tips: [
      "CREST certifications (CRT, CCT, CPSA) are highly valued by UK employers",
      "CHECK team member status is prestigious for penetration testing roles",
      "Tiger Scheme certifications recognized in UK government and defence",
      "NCSC Certified Professional scheme shows government-recognized competence",
      "Cyber Scheme (previously CREST) certifications for offensive security",
      "SC and DV clearance eligibility (don't disclose status, just eligibility)",
    ],
  },
  {
    category: "UK Industry Context",
    tips: [
      "Reference UK-specific threat landscape (nation-state actors, domestic cybercrime)",
      "Show knowledge of UK critical national infrastructure (CNI) categories",
      "Demonstrate understanding of UK incident reporting requirements (ICO, NIS)",
      "Include experience with UK public sector frameworks (G-Cloud, Crown Commercial Service)",
      "Reference UK CERT (NCSC) advisories and vulnerability disclosures",
      "Show awareness of UK Skills Framework for the Information Age (SFIA)",
    ],
  },
  {
    category: "UK Networking",
    tips: [
      "Attend BSides London, BSides Manchester, BSides Leeds, BSides Bristol events",
      "Join OWASP UK chapters (London, Manchester, Bristol, Edinburgh, Cambridge)",
      "Engage with UK cyber security community on Twitter/X and LinkedIn",
      "Consider ISSA UK, BCS Cybersecurity Specialist Group memberships",
      "Attend 44CON, SteelCon, and other UK security conferences",
      "Mention participation in CyberFirst or NCSC talent programs if applicable",
    ],
  },
];

// New: Home Lab Examples
const homeLabExamples = [
  {
    name: "Active Directory Lab",
    purpose: "Practice AD attacks, detection, and remediation",
    components: [
      "Windows Server 2019/2022 Domain Controller",
      "Windows 10/11 workstations (domain-joined)",
      "DVWA or vulnerable web apps for lateral movement",
      "Splunk or ELK for logging and detection",
      "Sysmon configured with SwiftOnSecurity rules",
    ],
    documentation: ["Network diagram", "Attack paths documented", "Detection rules created", "Remediation playbook"],
    resources: ["DetectionLab", "DVAD", "PurpleCloud"],
  },
  {
    name: "SIEM / SOC Lab",
    purpose: "Learn detection engineering and alert triage",
    components: [
      "Splunk Free, ELK Stack, or Wazuh as SIEM",
      "Log sources (Windows, Linux, firewall, web server)",
      "Atomic Red Team for attack simulation",
      "MITRE ATT&CK Navigator for coverage mapping",
      "TheHive + Cortex for incident management",
    ],
    documentation: ["Dashboard screenshots", "Detection rules with ATT&CK mapping", "Alert triage procedures", "Coverage matrix"],
    resources: ["SOC-in-a-Box", "HELK", "Security Onion"],
  },
  {
    name: "Malware Analysis Sandbox",
    purpose: "Safe malware analysis and reverse engineering",
    components: [
      "FlareVM or REMnux analysis VMs",
      "INetSim for network simulation",
      "Ghidra, IDA Free, x64dbg for reversing",
      "Cuckoo Sandbox or CAPE for automated analysis",
      "Isolated network segment with no internet access",
    ],
    documentation: ["Analysis reports with IOCs", "Unpacking writeups", "YARA rules created", "C2 protocol analysis"],
    resources: ["FlareVM", "REMnux", "CAPE Sandbox"],
  },
  {
    name: "Cloud Security Lab",
    purpose: "Practice cloud security assessments and hardening",
    components: [
      "AWS Free Tier / Azure Free / GCP Free accounts",
      "Terraform for infrastructure as code",
      "CloudGoat, Flaws.cloud, or TerraGoat for vulnerable setups",
      "Prowler, ScoutSuite, or CloudSploit for scanning",
      "CloudTrail / Azure Monitor for logging",
    ],
    documentation: ["Architecture diagrams", "Misconfigurations found and fixed", "Compliance scan results", "Cost management notes"],
    resources: ["CloudGoat", "Flaws.cloud", "SadCloud"],
  },
  {
    name: "Web Application Testing Lab",
    purpose: "Practice web vulnerability assessment",
    components: [
      "OWASP Juice Shop, DVWA, WebGoat, crAPI",
      "Burp Suite Professional or OWASP ZAP",
      "Docker/Docker Compose for easy deployment",
      "Postman for API testing",
      "SQLMap, ffuf, Nuclei for automation",
    ],
    documentation: ["Vulnerability findings with screenshots", "Exploitation methodology", "Remediation guidance", "Custom Burp/ZAP configs"],
    resources: ["VulnHub", "OWASP Projects", "PortSwigger Labs"],
  },
];

// New: Portfolio Platform Recommendations
const portfolioPlatforms = [
  {
    platform: "GitHub Pages + Jekyll/Hugo",
    pros: ["Free hosting", "Custom domain support", "Version controlled", "Developer credibility"],
    cons: ["Requires some technical setup", "Static only"],
    bestFor: "Technical portfolio with code focus",
  },
  {
    platform: "Notion",
    pros: ["Easy to update", "Rich formatting", "Database views", "Collaboration features"],
    cons: ["Limited customization", "Notion branding on free tier"],
    bestFor: "Quick setup, documentation-heavy portfolios",
  },
  {
    platform: "Custom Website (React/Next.js)",
    pros: ["Full control", "Interactive features", "Shows web dev skills", "No platform limitations"],
    cons: ["Hosting costs", "Maintenance overhead", "Time investment"],
    bestFor: "AppSec roles, demonstrating full-stack skills",
  },
  {
    platform: "LinkedIn Featured Section",
    pros: ["High visibility to recruiters", "Easy to update", "No separate site needed"],
    cons: ["Limited formatting", "Platform dependent", "Not portfolio-focused"],
    bestFor: "Supplementing main portfolio, quick wins",
  },
  {
    platform: "Hashnode/DEV.to Blog",
    pros: ["Built-in audience", "SEO benefits", "Custom domain option", "No hosting needed"],
    cons: ["Platform dependent", "Less customization"],
    bestFor: "Writing-focused portfolios, thought leadership",
  },
];

// New: Industry-specific portfolio focus
const industryPortfolioTips = [
  {
    industry: "Financial Services",
    focus: "Regulatory compliance, fraud detection, secure transactions",
    highlights: [
      "PCI DSS compliance experience",
      "FCA/PRA regulatory knowledge",
      "Fraud detection and prevention",
      "Secure API design for payments",
      "Third-party risk management",
    ],
    avoid: ["Discussing specific client vulnerabilities", "Sharing proprietary detection rules"],
  },
  {
    industry: "Healthcare / NHS",
    focus: "Patient data protection, medical device security, compliance",
    highlights: [
      "DSPT (Data Security Protection Toolkit) experience",
      "HL7/FHIR security considerations",
      "Medical device security assessments",
      "NHS Digital standards knowledge",
      "Caldicott principles awareness",
    ],
    avoid: ["Any PII/PHI in examples", "Specific patient data scenarios"],
  },
  {
    industry: "Government / Defence",
    focus: "Classified systems, national security, compliance frameworks",
    highlights: [
      "Security clearance eligibility (don't disclose level)",
      "NCSC guidelines implementation",
      "Risk management frameworks (HMG IA Standards)",
      "Secure by design principles",
      "Supply chain security",
    ],
    avoid: ["Classified information", "Specific government client names without permission"],
  },
  {
    industry: "Technology / SaaS",
    focus: "Product security, DevSecOps, cloud-native security",
    highlights: [
      "Shift-left security implementation",
      "Bug bounty program management",
      "SOC 2 compliance experience",
      "Container and Kubernetes security",
      "API security at scale",
    ],
    avoid: ["Proprietary security architectures", "Zero-day details before disclosure"],
  },
  {
    industry: "Critical Infrastructure / OT",
    focus: "ICS/SCADA security, operational continuity, safety",
    highlights: [
      "IEC 62443 knowledge",
      "OT network segmentation",
      "Safety-critical systems awareness",
      "PLC/HMI security testing",
      "Air-gapped network experience",
    ],
    avoid: ["Specific plant vulnerabilities", "Attack details that could endanger safety"],
  },
];

export default function SecurityPortfolioPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Building a Security Portfolio Guide - How to build an impressive cybersecurity portfolio including GitHub projects (security tools, CTF writeups, home lab configs), technical blog writing (walkthroughs, tutorials, research), CTF achievements (HackTheBox, TryHackMe, CTFtime), and bug bounty/research (CVEs, hall of fame, case studies). Covers role-focused strategy, case study templates, evidence artifacts, metrics that matter, safety guidelines, maintenance cadence, online presence, and common portfolio mistakes to avoid.`;

  // Quick stats for visual impact
  const quickStats = [
    { value: "6", label: "Portfolio Components", color: "#6366f1" },
    { value: "8", label: "Role Specializations", color: "#ec4899" },
    { value: "8", label: "CTF Platforms", color: "#f59e0b" },
    { value: "5", label: "Home Lab Types", color: "#10b981" },
  ];

  return (
    <LearnPageLayout pageTitle="Building a Security Portfolio" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Back Button */}
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate("/learn")}
          sx={{ mb: 3 }}
        >
          Back to Learning Hub
        </Button>

        {/* Hero Banner */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#6366f1", 0.15)} 0%, ${alpha("#ec4899", 0.15)} 50%, ${alpha("#f59e0b", 0.15)} 100%)`,
            border: `1px solid ${alpha("#6366f1", 0.2)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          {/* Decorative background elements */}
          <Box
            sx={{
              position: "absolute",
              top: -50,
              right: -50,
              width: 200,
              height: 200,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#6366f1", 0.1)} 0%, transparent 70%)`,
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
              background: `radial-gradient(circle, ${alpha("#ec4899", 0.1)} 0%, transparent 70%)`,
            }}
          />
          
          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, #6366f1, #8b5cf6)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#6366f1", 0.3)}`,
                }}
              >
                <FolderSpecialIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Building a Security Portfolio
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  Stand out to employers with compelling proof of your skills
                </Typography>
              </Box>
            </Box>
            
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Career Development" color="primary" />
              <Chip label="GitHub" sx={{ bgcolor: alpha("#6366f1", 0.15), color: "#6366f1", fontWeight: 600 }} />
              <Chip label="CTF" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
              <Chip label="Bug Bounty" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 600 }} />
              <Chip label="Technical Writing" sx={{ bgcolor: alpha("#ec4899", 0.15), color: "#ec4899", fontWeight: 600 }} />
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

        {/* Quick Navigation */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 3,
            position: "sticky",
            top: 70,
            zIndex: 100,
            backdropFilter: "blur(10px)",
            bgcolor: alpha(theme.palette.background.paper, 0.9),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            boxShadow: `0 4px 20px ${alpha("#000", 0.1)}`,
          }}
        >
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.secondary" }}>
            Quick Navigation
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {[
              { label: "Components", id: "components" },
              { label: "Role Focus", id: "role-focus" },
              { label: "Blueprint", id: "blueprint" },
              { label: "Project Ideas", id: "project-ideas" },
              { label: "GitHub Examples", id: "github-examples" },
              { label: "CTF Platforms", id: "ctf-platforms" },
              { label: "Home Labs", id: "home-labs" },
              { label: "Case Study", id: "case-study" },
              { label: "Safety", id: "safety" },
              { label: "Mistakes", id: "mistakes" },
              { label: "UK Tips", id: "uk-tips" },
              { label: "Industry Focus", id: "industry-focus" },
              { label: "Platforms", id: "platforms" },
            ].map((nav) => (
              <Chip
                key={nav.id}
                label={nav.label}
                size="small"
                clickable
                onClick={() => document.getElementById(nav.id)?.scrollIntoView({ behavior: "smooth", block: "start" })}
                sx={{
                  fontWeight: 600,
                  fontSize: "0.75rem",
                  "&:hover": {
                    bgcolor: alpha("#6366f1", 0.15),
                    color: "#6366f1",
                  },
                }}
              />
            ))}
          </Box>
        </Paper>

        {/* Why Build a Portfolio - Enhanced */}
        <Paper 
          sx={{ 
            p: 4, 
            mb: 5, 
            borderRadius: 4, 
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.02)} 0%, ${alpha("#6366f1", 0.02)} 100%)`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                bgcolor: alpha("#3b82f6", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
              }}
            >
              <TipsAndUpdatesIcon sx={{ color: "#3b82f6", fontSize: 28 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 1.5 }}>
                Why Build a Portfolio?
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
                In cybersecurity, demonstrating practical skills matters more than degrees alone. A strong portfolio shows 
                employers what you can actually do—not just what you claim. It differentiates you from other candidates, 
                especially when breaking into the field. Think of it as <strong>proof-of-work</strong> for your security skills.
              </Typography>
              <Box sx={{ display: "flex", gap: 2, mt: 2 }}>
                <Chip icon={<VerifiedIcon />} label="Proves Real Skills" variant="outlined" />
                <Chip icon={<TrendingUpIcon />} label="Career Differentiator" variant="outlined" />
                <Chip icon={<GroupsIcon />} label="Community Building" variant="outlined" />
              </Box>
            </Box>
          </Box>
        </Paper>

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            PORTFOLIO ESSENTIALS
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Portfolio Sections Grid - Enhanced */}
        <Typography id="components" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🎯 Portfolio Components
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The six essential elements that make up a compelling cybersecurity portfolio
        </Typography>
        <Grid container spacing={3} sx={{ mb: 5 }}>
          {portfolioSections.map((section, index) => (
            <Grid item xs={12} md={6} key={section.title}>
              <Paper
                sx={{
                  p: 0,
                  height: "100%",
                  borderRadius: 4,
                  overflow: "hidden",
                  border: `1px solid ${alpha(section.color, 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    borderColor: section.color,
                    boxShadow: `0 12px 40px ${alpha(section.color, 0.2)}`,
                  },
                }}
              >
                {/* Card Header with gradient */}
                <Box
                  sx={{
                    p: 2.5,
                    background: `linear-gradient(135deg, ${alpha(section.color, 0.1)} 0%, ${alpha(section.color, 0.05)} 100%)`,
                    borderBottom: `1px solid ${alpha(section.color, 0.1)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box
                      sx={{
                        width: 56,
                        height: 56,
                        borderRadius: 3,
                        background: `linear-gradient(135deg, ${section.color}, ${alpha(section.color, 0.7)})`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "white",
                        boxShadow: `0 4px 14px ${alpha(section.color, 0.4)}`,
                      }}
                    >
                      {section.icon}
                    </Box>
                    <Box>
                      <Typography variant="h6" sx={{ fontWeight: 700 }}>
                        {section.title}
                      </Typography>
                      <Chip 
                        label={`${index + 1} of 6`} 
                        size="small" 
                        sx={{ 
                          fontSize: "0.65rem", 
                          height: 20,
                          bgcolor: alpha(section.color, 0.1), 
                          color: section.color 
                        }} 
                      />
                    </Box>
                  </Box>
                </Box>
                
                {/* Card Body */}
                <Box sx={{ p: 2.5 }}>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                    {section.description}
                  </Typography>

                  <List dense sx={{ mb: 2 }}>
                    {section.items.map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.4, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: section.color }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={item}
                          primaryTypographyProps={{ variant: "body2", sx: { lineHeight: 1.5 } }}
                        />
                      </ListItem>
                    ))}
                  </List>

                  {/* Tip Box */}
                  <Box
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      bgcolor: alpha(section.color, 0.05),
                      border: `1px dashed ${alpha(section.color, 0.3)}`,
                    }}
                  >
                    <Typography variant="body2" sx={{ fontWeight: 600, color: section.color, display: "flex", alignItems: "flex-start", gap: 1 }}>
                      <TipsAndUpdatesIcon sx={{ fontSize: 18, mt: 0.2 }} />
                      {section.tip}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            ROLE-SPECIFIC STRATEGIES
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Role Focus - Enhanced */}
        <Typography id="role-focus" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🎯 Focus Your Portfolio by Role
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Tailor your portfolio to your target career path with role-specific examples and certifications
        </Typography>
        <Grid container spacing={3} sx={{ mb: 5 }}>
          {roleTracks.map((track) => (
            <Grid item xs={12} md={6} key={track.role}>
              <Paper
                sx={{
                  p: 0,
                  height: "100%",
                  borderRadius: 4,
                  overflow: "hidden",
                  border: `1px solid ${alpha(track.color, 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    borderColor: track.color,
                    boxShadow: `0 12px 40px ${alpha(track.color, 0.2)}`,
                  },
                }}
              >
                {/* Header */}
                <Box
                  sx={{
                    p: 2,
                    background: `linear-gradient(135deg, ${alpha(track.color, 0.15)} 0%, ${alpha(track.color, 0.05)} 100%)`,
                    borderBottom: `1px solid ${alpha(track.color, 0.1)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box
                      sx={{
                        width: 48,
                        height: 48,
                        borderRadius: 2,
                        background: `linear-gradient(135deg, ${track.color}, ${alpha(track.color, 0.7)})`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "white",
                        boxShadow: `0 4px 14px ${alpha(track.color, 0.4)}`,
                      }}
                    >
                      {track.icon}
                    </Box>
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {track.role}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {track.focus}
                      </Typography>
                    </Box>
                  </Box>
                </Box>
                
                {/* Body */}
                <Box sx={{ p: 2.5 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: track.color }}>
                    📁 Portfolio Examples
                  </Typography>
                  <List dense sx={{ mb: 2 }}>
                    {track.examples.slice(0, 5).map((example) => (
                      <ListItem key={example} sx={{ py: 0.25, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 22 }}>
                          <CheckCircleIcon sx={{ fontSize: 14, color: track.color }} />
                        </ListItemIcon>
                        <ListItemText primary={example} primaryTypographyProps={{ variant: "body2", fontSize: "0.85rem" }} />
                      </ListItem>
                    ))}
                  </List>
                  
                  <Grid container spacing={1}>
                    <Grid item xs={12}>
                      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 0.5 }}>
                        🎮 Practice Platforms
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {track.platforms.map((platform) => (
                          <Chip 
                            key={platform} 
                            label={platform} 
                            size="small" 
                            variant="outlined" 
                            sx={{ fontSize: "0.65rem", height: 24 }} 
                          />
                        ))}
                      </Box>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 0.5, mt: 1 }}>
                        📜 Certifications
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {track.certifications.map((cert) => (
                          <Chip 
                            key={cert} 
                            label={cert} 
                            size="small" 
                            sx={{ fontSize: "0.65rem", height: 24, bgcolor: alpha(track.color, 0.1), color: track.color }} 
                          />
                        ))}
                      </Box>
                    </Grid>
                  </Grid>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            BUILDING YOUR PORTFOLIO
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Portfolio Blueprint - Enhanced */}
        <Paper 
          id="blueprint"
          sx={{ 
            p: 4, 
            mb: 5, 
            borderRadius: 4, 
            scrollMarginTop: 180,
            background: `linear-gradient(135deg, ${alpha("#6366f1", 0.05)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)`,
            border: `1px solid ${alpha("#6366f1", 0.15)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #6366f1, #8b5cf6)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <ArticleIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                🗺️ Portfolio Layout Blueprint
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Structure your portfolio for maximum impact
              </Typography>
            </Box>
          </Box>
          <Grid container spacing={2}>
            {portfolioBlueprint.map((item, index) => (
              <Grid item xs={12} sm={6} md={4} key={item.section}>
                <Paper 
                  sx={{ 
                    p: 2, 
                    height: "100%",
                    borderRadius: 3, 
                    border: `1px solid ${alpha("#6366f1", 0.15)}`,
                    bgcolor: "background.paper",
                    transition: "all 0.2s ease",
                    "&:hover": {
                      borderColor: "#6366f1",
                      transform: "translateY(-2px)",
                    },
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Box
                      sx={{
                        width: 24,
                        height: 24,
                        borderRadius: 1,
                        bgcolor: alpha("#6366f1", 0.1),
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontSize: "0.75rem",
                        fontWeight: 700,
                        color: "#6366f1",
                      }}
                    >
                      {index + 1}
                    </Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                      {item.section}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.85rem", lineHeight: 1.6 }}>
                    {item.detail}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Project Ideas - Enhanced */}
        <Typography id="project-ideas" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          💡 Project Ideas by Level
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Start with beginner projects and progress to advanced as you grow your skills
        </Typography>
        <Grid container spacing={3} sx={{ mb: 5 }}>
          {projectIdeasByLevel.map((group) => (
            <Grid item xs={12} md={4} key={group.level}>
              <Paper 
                sx={{ 
                  p: 0, 
                  height: "100%", 
                  borderRadius: 4,
                  overflow: "hidden",
                  border: `2px solid ${alpha(group.color, 0.3)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    borderColor: group.color,
                    transform: "translateY(-4px)",
                    boxShadow: `0 12px 40px ${alpha(group.color, 0.2)}`,
                  },
                }}
              >
                {/* Header */}
                <Box
                  sx={{
                    p: 2,
                    background: `linear-gradient(135deg, ${alpha(group.color, 0.2)} 0%, ${alpha(group.color, 0.1)} 100%)`,
                    borderBottom: `2px solid ${alpha(group.color, 0.2)}`,
                    textAlign: "center",
                  }}
                >
                  <Typography variant="h5" sx={{ fontWeight: 800, color: group.color }}>
                    {group.level}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {group.level === "Beginner" ? "Start here" : group.level === "Intermediate" ? "Growing skills" : "Expert level"}
                  </Typography>
                </Box>
                
                {/* Ideas */}
                <Box sx={{ p: 2.5 }}>
                  <List dense>
                    {group.ideas.map((idea, i) => (
                      <ListItem key={idea} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Box
                            sx={{
                              width: 20,
                              height: 20,
                              borderRadius: 1,
                              bgcolor: alpha(group.color, 0.1),
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              fontSize: "0.65rem",
                              fontWeight: 700,
                              color: group.color,
                            }}
                          >
                            {i + 1}
                          </Box>
                        </ListItemIcon>
                        <ListItemText primary={idea} primaryTypographyProps={{ variant: "body2", fontSize: "0.85rem" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            PRACTICAL RESOURCES
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* GitHub Project Examples - Enhanced */}
        <Typography id="github-examples" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🔧 GitHub Project Examples
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Concrete project ideas organized by category with tech stack recommendations
        </Typography>
        {githubProjectExamples.map((category, idx) => (
          <Accordion 
            key={category.category} 
            defaultExpanded={idx === 0}
            sx={{ 
              mb: 1.5, 
              borderRadius: "16px !important", 
              overflow: "hidden",
              "&:before": { display: "none" },
              border: `1px solid ${alpha("#6366f1", 0.15)}`,
            }}
          >
            <AccordionSummary 
              expandIcon={<ExpandMoreIcon />} 
              sx={{ 
                bgcolor: alpha("#6366f1", 0.03),
                "&:hover": { bgcolor: alpha("#6366f1", 0.06) },
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Box
                  sx={{
                    width: 40,
                    height: 40,
                    borderRadius: 2,
                    bgcolor: alpha("#6366f1", 0.1),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  <GitHubIcon sx={{ color: "#6366f1" }} />
                </Box>
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    {category.category}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {category.examples.length} project ideas
                  </Typography>
                </Box>
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ p: 0 }}>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#6366f1", 0.02) }}>
                      <TableCell sx={{ fontWeight: 700, width: "25%" }}>Project</TableCell>
                      <TableCell sx={{ fontWeight: 700, width: "45%" }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700, width: "30%" }}>Tech Stack</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {category.examples.map((example) => (
                      <TableRow key={example.name} sx={{ "&:hover": { bgcolor: alpha("#6366f1", 0.02) } }}>
                        <TableCell sx={{ fontWeight: 600, color: "#6366f1" }}>{example.name}</TableCell>
                        <TableCell>{example.description}</TableCell>
                        <TableCell>
                          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                            {example.tech.split(", ").map((t) => (
                              <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: "0.65rem", height: 22 }} />
                            ))}
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        ))}
        <Box sx={{ mb: 5 }} />

        {/* CTF Platform Guide - Enhanced */}
        <Typography id="ctf-platforms" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🏆 CTF & Training Platforms
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Build your skills and showcase achievements on these platforms
        </Typography>
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {ctfPlatforms.map((platform) => (
            <Grid item xs={12} sm={6} lg={4} key={platform.name}>
              <Paper
                sx={{
                  p: 0,
                  height: "100%",
                  borderRadius: 3,
                  overflow: "hidden",
                  border: `1px solid ${alpha("#f59e0b", 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    borderColor: "#f59e0b",
                    boxShadow: `0 8px 30px ${alpha("#f59e0b", 0.15)}`,
                  },
                }}
              >
                {/* Header */}
                <Box
                  sx={{
                    p: 2,
                    background: platform.type === "Offensive" 
                      ? `linear-gradient(135deg, ${alpha("#ef4444", 0.1)}, ${alpha("#ef4444", 0.05)})`
                      : platform.type === "Defensive"
                      ? `linear-gradient(135deg, ${alpha("#10b981", 0.1)}, ${alpha("#10b981", 0.05)})`
                      : platform.type === "Learning"
                      ? `linear-gradient(135deg, ${alpha("#3b82f6", 0.1)}, ${alpha("#3b82f6", 0.05)})`
                      : `linear-gradient(135deg, ${alpha("#f59e0b", 0.1)}, ${alpha("#f59e0b", 0.05)})`,
                  }}
                >
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {platform.name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {platform.url}
                      </Typography>
                    </Box>
                    <Chip 
                      label={platform.type} 
                      size="small" 
                      sx={{ 
                        fontSize: "0.65rem",
                        fontWeight: 600,
                        bgcolor: platform.type === "Offensive" ? alpha("#ef4444", 0.15) : 
                                 platform.type === "Defensive" ? alpha("#10b981", 0.15) :
                                 platform.type === "Learning" ? alpha("#3b82f6", 0.15) :
                                 alpha("#f59e0b", 0.15),
                        color: platform.type === "Offensive" ? "#ef4444" : 
                               platform.type === "Defensive" ? "#10b981" :
                               platform.type === "Learning" ? "#3b82f6" :
                               "#f59e0b",
                      }} 
                    />
                  </Box>
                </Box>
                
                {/* Body */}
                <Box sx={{ p: 2 }}>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2, fontSize: "0.85rem", lineHeight: 1.6 }}>
                    {platform.description}
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                    {platform.focus.map((f) => (
                      <Chip key={f} label={f} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 22 }} />
                    ))}
                  </Box>
                  <Box 
                    sx={{ 
                      p: 1.5, 
                      bgcolor: alpha("#f59e0b", 0.05), 
                      borderRadius: 2,
                      border: `1px dashed ${alpha("#f59e0b", 0.3)}`,
                    }}
                  >
                    <Typography variant="caption" sx={{ fontWeight: 600, display: "flex", alignItems: "flex-start", gap: 0.5 }}>
                      <TipsAndUpdatesIcon sx={{ fontSize: 14, color: "#f59e0b", mt: 0.2 }} />
                      {platform.portfolioTip}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Home Lab Examples - Enhanced */}
        <Typography id="home-labs" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🏠 Home Lab Documentation
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Document your home lab to demonstrate practical infrastructure skills
        </Typography>
        <Grid container spacing={3} sx={{ mb: 5 }}>
          {homeLabExamples.map((lab, index) => (
            <Grid item xs={12} md={6} key={lab.name}>
              <Paper
                sx={{
                  p: 0,
                  height: "100%",
                  borderRadius: 4,
                  overflow: "hidden",
                  border: `1px solid ${alpha("#10b981", 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    borderColor: "#10b981",
                    boxShadow: `0 12px 40px ${alpha("#10b981", 0.15)}`,
                  },
                }}
              >
                {/* Header */}
                <Box
                  sx={{
                    p: 2,
                    background: `linear-gradient(135deg, ${alpha("#10b981", 0.15)} 0%, ${alpha("#10b981", 0.05)} 100%)`,
                    borderBottom: `1px solid ${alpha("#10b981", 0.1)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box
                      sx={{
                        width: 48,
                        height: 48,
                        borderRadius: 2,
                        background: `linear-gradient(135deg, #10b981, ${alpha("#10b981", 0.7)})`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "white",
                        boxShadow: `0 4px 14px ${alpha("#10b981", 0.4)}`,
                      }}
                    >
                      <HomeIcon sx={{ fontSize: 28 }} />
                    </Box>
                    <Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {lab.name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {lab.purpose}
                      </Typography>
                    </Box>
                  </Box>
                </Box>
                
                {/* Body */}
                <Box sx={{ p: 2.5 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>
                    🔧 Components
                  </Typography>
                  <List dense sx={{ mb: 2 }}>
                    {lab.components.slice(0, 4).map((component) => (
                      <ListItem key={component} sx={{ py: 0.25, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 20 }}>
                          <Box sx={{ width: 4, height: 4, borderRadius: "50%", bgcolor: "#10b981" }} />
                        </ListItemIcon>
                        <ListItemText primary={component} primaryTypographyProps={{ variant: "caption" }} />
                      </ListItem>
                    ))}
                  </List>

                  <Grid container spacing={1}>
                    <Grid item xs={12}>
                      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 0.5 }}>
                        📄 Documentation
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {lab.documentation.map((doc) => (
                          <Chip key={doc} label={doc} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 22 }} />
                        ))}
                      </Box>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 0.5, mt: 1 }}>
                        🔗 Resources
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {lab.resources.map((resource) => (
                          <Chip 
                            key={resource} 
                            label={resource} 
                            size="small" 
                            sx={{ fontSize: "0.6rem", height: 22, bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} 
                          />
                        ))}
                      </Box>
                    </Grid>
                  </Grid>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            QUALITY & PRESENTATION
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Case Study + Quality Checklist */}
        <Grid id="case-study" container spacing={3} sx={{ mb: 4, scrollMarginTop: 180 }}>
          <Grid item xs={12} md={6}>
            <Paper 
              sx={{ 
                p: 0, 
                height: "100%", 
                borderRadius: 4, 
                overflow: "hidden",
                border: `1px solid ${alpha("#3b82f6", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 12px 40px ${alpha("#3b82f6", 0.15)}`,
                },
              }}
            >
              <Box
                sx={{
                  p: 2,
                  background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.15)} 0%, ${alpha("#3b82f6", 0.05)} 100%)`,
                  borderBottom: `1px solid ${alpha("#3b82f6", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  <ArticleIcon sx={{ color: "#3b82f6" }} />
                  Case Study Template
                </Typography>
              </Box>
              <Box sx={{ p: 2.5 }}>
                <List dense>
                  {caseStudyTemplate.map((step, index) => (
                    <ListItem key={step} sx={{ py: 0.5, px: 0, alignItems: "flex-start" }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <Box
                          sx={{
                            width: 20,
                            height: 20,
                            borderRadius: 1,
                            bgcolor: alpha("#3b82f6", 0.1),
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: "0.7rem",
                            fontWeight: 700,
                            color: "#3b82f6",
                          }}
                        >
                          {index + 1}
                        </Box>
                      </ListItemIcon>
                      <ListItemText primary={step} primaryTypographyProps={{ variant: "body2", lineHeight: 1.6 }} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper 
              sx={{ 
                p: 0, 
                height: "100%", 
                borderRadius: 4, 
                overflow: "hidden",
                border: `1px solid ${alpha("#10b981", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 12px 40px ${alpha("#10b981", 0.15)}`,
                },
              }}
            >
              <Box
                sx={{
                  p: 2,
                  background: `linear-gradient(135deg, ${alpha("#10b981", 0.15)} 0%, ${alpha("#10b981", 0.05)} 100%)`,
                  borderBottom: `1px solid ${alpha("#10b981", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon sx={{ color: "#10b981" }} />
                  Quality Checklist
                </Typography>
              </Box>
              <Box sx={{ p: 2.5 }}>
                <List dense>
                  {qualityChecklist.map((item) => (
                    <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", lineHeight: 1.6 }} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* Storytelling and Review Signals */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper 
              sx={{ 
                p: 0, 
                height: "100%", 
                borderRadius: 4, 
                overflow: "hidden",
                border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 12px 40px ${alpha("#8b5cf6", 0.15)}`,
                },
              }}
            >
              <Box
                sx={{
                  p: 2,
                  background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.15)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)`,
                  borderBottom: `1px solid ${alpha("#8b5cf6", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  <AutoStoriesIcon sx={{ color: "#8b5cf6" }} />
                  Storytelling Framework
                </Typography>
              </Box>
              <Box sx={{ p: 2.5 }}>
                <List dense>
                  {storytellingFramework.map((item, index) => (
                    <ListItem key={item} sx={{ py: 0.5, px: 0, alignItems: "flex-start" }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <Box
                          sx={{
                            width: 20,
                            height: 20,
                            borderRadius: "50%",
                            bgcolor: alpha("#8b5cf6", 0.15),
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                          }}
                        >
                          <StarIcon sx={{ fontSize: 12, color: "#8b5cf6" }} />
                        </Box>
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", lineHeight: 1.6 }} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper 
              sx={{ 
                p: 0, 
                height: "100%", 
                borderRadius: 4, 
                overflow: "hidden",
                border: `1px solid ${alpha("#10b981", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 12px 40px ${alpha("#10b981", 0.15)}`,
                },
              }}
            >
              <Box
                sx={{
                  p: 2,
                  background: `linear-gradient(135deg, ${alpha("#10b981", 0.15)} 0%, ${alpha("#10b981", 0.05)} 100%)`,
                  borderBottom: `1px solid ${alpha("#10b981", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  <VisibilityIcon sx={{ color: "#10b981" }} />
                  What Reviewers Look For
                </Typography>
              </Box>
              <Box sx={{ p: 2.5 }}>
                <List dense>
                  {signalToEmployers.map((item) => (
                    <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", lineHeight: 1.6 }} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* Evidence Artifacts */}
        <Paper 
          sx={{ 
            p: 0, 
            mb: 4, 
            borderRadius: 4, 
            overflow: "hidden",
            border: `1px solid ${alpha("#6366f1", 0.2)}`,
          }}
        >
          <Box
            sx={{
              p: 2,
              background: `linear-gradient(135deg, ${alpha("#6366f1", 0.1)} 0%, ${alpha("#8b5cf6", 0.1)} 100%)`,
              borderBottom: `1px solid ${alpha("#6366f1", 0.1)}`,
            }}
          >
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <FolderIcon sx={{ color: "#6366f1" }} />
              Evidence and Artifacts
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Types of evidence to include in your portfolio projects
            </Typography>
          </Box>
          <Box sx={{ p: 3 }}>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {evidenceArtifacts.map((artifact, index) => (
                <Chip 
                  key={artifact} 
                  label={artifact} 
                  size="small"
                  sx={{
                    bgcolor: index % 3 === 0 ? alpha("#6366f1", 0.1) : 
                             index % 3 === 1 ? alpha("#8b5cf6", 0.1) : 
                             alpha("#3b82f6", 0.1),
                    color: index % 3 === 0 ? "#6366f1" : 
                           index % 3 === 1 ? "#8b5cf6" : 
                           "#3b82f6",
                    fontWeight: 500,
                    "&:hover": {
                      bgcolor: index % 3 === 0 ? alpha("#6366f1", 0.2) : 
                               index % 3 === 1 ? alpha("#8b5cf6", 0.2) : 
                               alpha("#3b82f6", 0.2),
                    },
                  }}
                />
              ))}
            </Box>
          </Box>
        </Paper>

        {/* Reviewer Checklist and Interview Hooks */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper 
              sx={{ 
                p: 0, 
                height: "100%", 
                borderRadius: 4, 
                overflow: "hidden",
                border: `1px solid ${alpha("#3b82f6", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 12px 40px ${alpha("#3b82f6", 0.15)}`,
                },
              }}
            >
              <Box
                sx={{
                  p: 2,
                  background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.15)} 0%, ${alpha("#3b82f6", 0.05)} 100%)`,
                  borderBottom: `1px solid ${alpha("#3b82f6", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  <AssignmentIcon sx={{ color: "#3b82f6" }} />
                  Reviewer Checklist
                </Typography>
              </Box>
              <Box sx={{ p: 2.5 }}>
                <List dense>
                  {reviewerChecklist.map((item) => (
                    <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", lineHeight: 1.6 }} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper 
              sx={{ 
                p: 0, 
                height: "100%", 
                borderRadius: 4, 
                overflow: "hidden",
                border: `1px solid ${alpha("#f59e0b", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 12px 40px ${alpha("#f59e0b", 0.15)}`,
                },
              }}
            >
              <Box
                sx={{
                  p: 2,
                  background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.15)} 0%, ${alpha("#f59e0b", 0.05)} 100%)`,
                  borderBottom: `1px solid ${alpha("#f59e0b", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
                  Interview Hooks
                </Typography>
              </Box>
              <Box sx={{ p: 2.5 }}>
                <List dense>
                  {interviewHooks.map((item) => (
                    <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <StarIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", lineHeight: 1.6 }} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            METRICS & BEST PRACTICES
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Three-column grid: Metrics, Safety, Maintenance */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          {/* Metrics */}
          <Grid item xs={12} md={4}>
            <Paper 
              sx={{ 
                p: 0, 
                height: "100%", 
                borderRadius: 4, 
                overflow: "hidden",
                border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 12px 40px ${alpha("#8b5cf6", 0.15)}`,
                },
              }}
            >
              <Box
                sx={{
                  p: 2,
                  background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.15)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)`,
                  borderBottom: `1px solid ${alpha("#8b5cf6", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  <AssessmentIcon sx={{ color: "#8b5cf6" }} />
                  Metrics That Matter
                </Typography>
              </Box>
              <Box sx={{ p: 2.5 }}>
                <List dense>
                  {metricsThatMatter.map((metric, index) => (
                    <ListItem key={metric} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <Box
                          sx={{
                            width: 18,
                            height: 18,
                            borderRadius: 1,
                            bgcolor: alpha("#8b5cf6", 0.1),
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: "0.65rem",
                            fontWeight: 700,
                            color: "#8b5cf6",
                          }}
                        >
                          {index + 1}
                        </Box>
                      </ListItemIcon>
                      <ListItemText primary={metric} primaryTypographyProps={{ variant: "body2", fontSize: "0.85rem", lineHeight: 1.5 }} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            </Paper>
          </Grid>

          {/* Safety and Ethics */}
          <Grid id="safety" item xs={12} md={4} sx={{ scrollMarginTop: 180 }}>
            <Paper 
              sx={{ 
                p: 0, 
                height: "100%", 
                borderRadius: 4, 
                overflow: "hidden",
                border: `1px solid ${alpha("#ef4444", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 12px 40px ${alpha("#ef4444", 0.15)}`,
                },
              }}
            >
              <Box
                sx={{
                  p: 2,
                  background: `linear-gradient(135deg, ${alpha("#ef4444", 0.15)} 0%, ${alpha("#ef4444", 0.05)} 100%)`,
                  borderBottom: `1px solid ${alpha("#ef4444", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  <ShieldIcon sx={{ color: "#ef4444" }} />
                  Safety & Ethics
                </Typography>
              </Box>
              <Box sx={{ p: 2.5 }}>
                <List dense>
                  {safetyGuidelines.map((item) => (
                    <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", fontSize: "0.85rem", lineHeight: 1.5 }} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            </Paper>
          </Grid>

          {/* Maintenance */}
          <Grid item xs={12} md={4}>
            <Paper 
              sx={{ 
                p: 0, 
                height: "100%", 
                borderRadius: 4, 
                overflow: "hidden",
                border: `1px solid ${alpha("#f59e0b", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 12px 40px ${alpha("#f59e0b", 0.15)}`,
                },
              }}
            >
              <Box
                sx={{
                  p: 2,
                  background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.15)} 0%, ${alpha("#f59e0b", 0.05)} 100%)`,
                  borderBottom: `1px solid ${alpha("#f59e0b", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                  <UpdateIcon sx={{ color: "#f59e0b" }} />
                  Maintenance Cadence
                </Typography>
              </Box>
              <Box sx={{ p: 2.5 }}>
                <List dense>
                  {maintenanceCadence.map((item) => (
                    <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", fontSize: "0.85rem", lineHeight: 1.5 }} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* Online Presence */}
        <Paper
          sx={{
            p: 0,
            mb: 5,
            borderRadius: 4,
            overflow: "hidden",
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
          }}
        >
          <Box
            sx={{
              p: 2.5,
              background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.1)} 0%, ${alpha("#6366f1", 0.1)} 100%)`,
              borderBottom: `1px solid ${alpha("#3b82f6", 0.1)}`,
            }}
          >
            <Typography variant="h5" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <PublicIcon sx={{ color: "#3b82f6" }} /> Building Your Online Presence
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Establish a strong digital footprint to complement your portfolio
            </Typography>
          </Box>
          <Box sx={{ p: 3 }}>
            <Grid container spacing={2}>
              {presenceTips.map((tip, i) => (
                <Grid item xs={12} md={6} key={i}>
                  <Box 
                    sx={{ 
                      display: "flex", 
                      alignItems: "flex-start", 
                      gap: 1.5,
                      p: 1.5,
                      borderRadius: 2,
                      bgcolor: alpha("#3b82f6", 0.03),
                      transition: "all 0.2s ease",
                      "&:hover": {
                        bgcolor: alpha("#3b82f6", 0.08),
                      },
                    }}
                  >
                    <Box
                      sx={{
                        width: 24,
                        height: 24,
                        borderRadius: 1,
                        bgcolor: alpha("#3b82f6", 0.1),
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontSize: "0.7rem",
                        fontWeight: 700,
                        color: "#3b82f6",
                        flexShrink: 0,
                        mt: 0.25,
                      }}
                    >
                      {i + 1}
                    </Box>
                    <Typography variant="body2" sx={{ lineHeight: 1.6 }}>{tip}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>

        {/* Common Mistakes */}
        <Paper
          id="mistakes"
          sx={{
            p: 0,
            mb: 5,
            borderRadius: 4,
            overflow: "hidden",
            scrollMarginTop: 180,
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Box
            sx={{
              p: 2.5,
              background: `linear-gradient(135deg, ${alpha("#ef4444", 0.1)} 0%, ${alpha("#f59e0b", 0.1)} 100%)`,
              borderBottom: `1px solid ${alpha("#ef4444", 0.1)}`,
            }}
          >
            <Typography variant="h5" sx={{ fontWeight: 700, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
              <WarningIcon /> Portfolio Mistakes to Avoid
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Common pitfalls that can undermine your portfolio's effectiveness
            </Typography>
          </Box>
          <Box sx={{ p: 3 }}>
            <Grid container spacing={2}>
              {portfolioMistakes.map((mistake, i) => (
                <Grid item xs={12} md={6} key={i}>
                  <Box 
                    sx={{ 
                      display: "flex", 
                      alignItems: "flex-start", 
                      gap: 1.5,
                      p: 1.5,
                      borderRadius: 2,
                      bgcolor: alpha("#ef4444", 0.03),
                      border: `1px dashed ${alpha("#ef4444", 0.15)}`,
                      transition: "all 0.2s ease",
                      "&:hover": {
                        bgcolor: alpha("#ef4444", 0.06),
                        borderColor: alpha("#ef4444", 0.3),
                      },
                    }}
                  >
                    <WarningIcon sx={{ fontSize: 18, color: "#ef4444", mt: 0.25, flexShrink: 0 }} />
                    <Typography variant="body2" sx={{ lineHeight: 1.6 }}>{mistake}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            REGIONAL & INDUSTRY GUIDANCE
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* UK-Specific Portfolio Tips */}
        <Typography id="uk-tips" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🇬🇧 UK-Specific Portfolio Considerations
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Tailor your portfolio for the UK cybersecurity market
        </Typography>
        <Grid container spacing={3} sx={{ mb: 5 }}>
          {ukPortfolioTips.map((section, index) => (
            <Grid item xs={12} md={6} key={section.category}>
              <Paper
                sx={{
                  p: 0,
                  height: "100%",
                  borderRadius: 4,
                  overflow: "hidden",
                  border: `1px solid ${alpha("#3b82f6", 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    boxShadow: `0 12px 40px ${alpha("#3b82f6", 0.15)}`,
                  },
                }}
              >
                <Box
                  sx={{
                    p: 2,
                    background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.15)} 0%, ${alpha("#3b82f6", 0.05)} 100%)`,
                    borderBottom: `1px solid ${alpha("#3b82f6", 0.1)}`,
                  }}
                >
                  <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                    <LocationOnIcon sx={{ color: "#3b82f6" }} />
                    {section.category}
                  </Typography>
                </Box>
                <Box sx={{ p: 2.5 }}>
                  <List dense>
                    {section.tips.map((tip) => (
                      <ListItem key={tip} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                        </ListItemIcon>
                        <ListItemText primary={tip} primaryTypographyProps={{ variant: "body2", lineHeight: 1.6 }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Industry-Specific Tips */}
        <Typography id="industry-focus" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🏢 Industry-Specific Portfolio Focus
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Customize your portfolio based on your target industry
        </Typography>
        <Box sx={{ mb: 5 }}>
          {industryPortfolioTips.map((industry, index) => (
            <Accordion 
              key={industry.industry} 
              sx={{ 
                mb: 1.5, 
                borderRadius: "16px !important", 
                overflow: "hidden",
                border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
                "&:before": { display: "none" },
                "&:hover": {
                  borderColor: alpha("#8b5cf6", 0.3),
                },
              }}
            >
              <AccordionSummary 
                expandIcon={<ExpandMoreIcon sx={{ color: "#8b5cf6" }} />} 
                sx={{ 
                  background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.05)} 0%, ${alpha("#8b5cf6", 0.02)} 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)`,
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box
                    sx={{
                      width: 40,
                      height: 40,
                      borderRadius: 2,
                      background: `linear-gradient(135deg, #8b5cf6, ${alpha("#8b5cf6", 0.7)})`,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: "white",
                    }}
                  >
                    <WorkIcon />
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      {industry.industry}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {industry.focus}
                    </Typography>
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails sx={{ p: 3 }}>
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Box
                      sx={{
                        p: 2,
                        borderRadius: 3,
                        bgcolor: alpha("#10b981", 0.05),
                        border: `1px solid ${alpha("#10b981", 0.15)}`,
                      }}
                    >
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#10b981", display: "flex", alignItems: "center", gap: 0.5 }}>
                        <CheckCircleIcon sx={{ fontSize: 18 }} /> Highlight These
                      </Typography>
                      <List dense>
                        {industry.highlights.map((highlight) => (
                          <ListItem key={highlight} sx={{ py: 0.25, px: 0 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                            </ListItemIcon>
                            <ListItemText primary={highlight} primaryTypographyProps={{ variant: "body2" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Box
                      sx={{
                        p: 2,
                        borderRadius: 3,
                        bgcolor: alpha("#ef4444", 0.05),
                        border: `1px solid ${alpha("#ef4444", 0.15)}`,
                      }}
                    >
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#ef4444", display: "flex", alignItems: "center", gap: 0.5 }}>
                        <WarningIcon sx={{ fontSize: 18 }} /> Avoid These
                      </Typography>
                      <List dense>
                        {industry.avoid.map((item) => (
                          <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <WarningIcon sx={{ fontSize: 14, color: "#ef4444" }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}
        </Box>

        {/* Portfolio Platform Recommendations */}
        <Typography id="platforms" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🌐 Portfolio Platform Recommendations
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Choose the best platform to host and showcase your security work
        </Typography>
        <TableContainer 
          component={Paper} 
          sx={{ 
            mb: 5, 
            borderRadius: 4,
            overflow: "hidden",
            border: `1px solid ${alpha("#6366f1", 0.15)}`,
          }}
        >
          <Table>
            <TableHead>
              <TableRow 
                sx={{ 
                  background: `linear-gradient(135deg, ${alpha("#6366f1", 0.1)} 0%, ${alpha("#8b5cf6", 0.1)} 100%)`,
                }}
              >
                <TableCell sx={{ fontWeight: 700, fontSize: "0.9rem" }}>Platform</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: "0.9rem" }}>Pros</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: "0.9rem" }}>Cons</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: "0.9rem" }}>Best For</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {portfolioPlatforms.map((platform, index) => (
                <TableRow 
                  key={platform.platform}
                  sx={{
                    bgcolor: index % 2 === 0 ? "transparent" : alpha("#6366f1", 0.02),
                    "&:hover": {
                      bgcolor: alpha("#6366f1", 0.05),
                    },
                  }}
                >
                  <TableCell sx={{ fontWeight: 700, color: "#6366f1" }}>{platform.platform}</TableCell>
                  <TableCell>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {platform.pros.map((pro) => (
                        <Chip key={pro} label={pro} size="small" sx={{ fontSize: "0.6rem", height: 22, bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {platform.cons.map((con) => (
                        <Chip key={con} label={con} size="small" sx={{ fontSize: "0.6rem", height: 22, bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontStyle: "italic", color: "text.secondary", fontSize: "0.85rem" }}>
                      {platform.bestFor}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Related Pages - Enhanced */}
        <Paper 
          sx={{ 
            p: 0, 
            borderRadius: 4, 
            overflow: "hidden",
            border: `1px solid ${alpha(theme.palette.primary.main, 0.15)}`,
          }}
        >
          <Box
            sx={{
              p: 2.5,
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)`,
              borderBottom: `1px solid ${alpha(theme.palette.primary.main, 0.1)}`,
            }}
          >
            <Typography variant="h5" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <SchoolIcon sx={{ color: theme.palette.primary.main }} />
              Continue Your Learning Journey
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Explore related topics to accelerate your cybersecurity career
            </Typography>
          </Box>
          <Box sx={{ p: 3 }}>
            <Grid container spacing={2}>
              <Grid item xs={6} md={3}>
                <Paper
                  onClick={() => navigate("/learn/career-paths")}
                  sx={{
                    p: 2,
                    textAlign: "center",
                    cursor: "pointer",
                    borderRadius: 3,
                    border: `1px solid ${alpha("#6366f1", 0.15)}`,
                    transition: "all 0.2s ease",
                    "&:hover": {
                      transform: "translateY(-2px)",
                      borderColor: "#6366f1",
                      boxShadow: `0 8px 24px ${alpha("#6366f1", 0.15)}`,
                    },
                  }}
                >
                  <RouteIcon sx={{ fontSize: 32, color: "#6366f1", mb: 1 }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Career Paths</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper
                  onClick={() => navigate("/learn/certifications")}
                  sx={{
                    p: 2,
                    textAlign: "center",
                    cursor: "pointer",
                    borderRadius: 3,
                    border: `1px solid ${alpha("#10b981", 0.15)}`,
                    transition: "all 0.2s ease",
                    "&:hover": {
                      transform: "translateY(-2px)",
                      borderColor: "#10b981",
                      boxShadow: `0 8px 24px ${alpha("#10b981", 0.15)}`,
                    },
                  }}
                >
                  <VerifiedIcon sx={{ fontSize: 32, color: "#10b981", mb: 1 }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Certifications</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper
                  onClick={() => navigate("/learn/interview-prep")}
                  sx={{
                    p: 2,
                    textAlign: "center",
                    cursor: "pointer",
                    borderRadius: 3,
                    border: `1px solid ${alpha("#f59e0b", 0.15)}`,
                    transition: "all 0.2s ease",
                    "&:hover": {
                      transform: "translateY(-2px)",
                      borderColor: "#f59e0b",
                      boxShadow: `0 8px 24px ${alpha("#f59e0b", 0.15)}`,
                    },
                  }}
                >
                  <QuestionAnswerIcon sx={{ fontSize: 32, color: "#f59e0b", mb: 1 }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Interview Prep</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper
                  onClick={() => navigate("/learn/getting-started")}
                  sx={{
                    p: 2,
                    textAlign: "center",
                    cursor: "pointer",
                    borderRadius: 3,
                    border: `1px solid ${alpha("#3b82f6", 0.15)}`,
                    transition: "all 0.2s ease",
                    "&:hover": {
                      transform: "translateY(-2px)",
                      borderColor: "#3b82f6",
                      boxShadow: `0 8px 24px ${alpha("#3b82f6", 0.15)}`,
                    },
                  }}
                >
                  <RocketLaunchIcon sx={{ fontSize: 32, color: "#3b82f6", mb: 1 }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Getting Started</Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
