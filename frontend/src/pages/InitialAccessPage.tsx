import React, { useState } from "react";
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
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  IconButton,
  Tooltip,
  Divider,
  alpha,
  useTheme,
  useMediaQuery,
  Drawer,
  Fab,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import EmailIcon from "@mui/icons-material/Email";
import LanguageIcon from "@mui/icons-material/Language";
import BugReportIcon from "@mui/icons-material/BugReport";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import SecurityIcon from "@mui/icons-material/Security";
import UsbIcon from "@mui/icons-material/Usb";
import LocalShippingIcon from "@mui/icons-material/LocalShipping";
import HandshakeIcon from "@mui/icons-material/Handshake";
import BuildIcon from "@mui/icons-material/Build";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import ShieldIcon from "@mui/icons-material/Shield";
import SearchIcon from "@mui/icons-material/Search";
import QuizIcon from "@mui/icons-material/Quiz";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import HistoryEduIcon from "@mui/icons-material/HistoryEdu";
import ScienceIcon from "@mui/icons-material/Science";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import TimelineIcon from "@mui/icons-material/Timeline";
import AssignmentIcon from "@mui/icons-material/Assignment";
import TerminalIcon from "@mui/icons-material/Terminal";
import PolicyIcon from "@mui/icons-material/Policy";
import { useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

// Section Navigation Items
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <RocketLaunchIcon /> },
  { id: "mitre", label: "MITRE ATT&CK", icon: <GpsFixedIcon /> },
  { id: "phishing", label: "Phishing", icon: <EmailIcon /> },
  { id: "drive-by", label: "Drive-by Compromise", icon: <LanguageIcon /> },
  { id: "public-apps", label: "Public-Facing Apps", icon: <BugReportIcon /> },
  { id: "external-services", label: "External Services", icon: <VpnKeyIcon /> },
  { id: "supply-chain", label: "Supply Chain", icon: <LocalShippingIcon /> },
  { id: "trusted-relationship", label: "Trusted Relationships", icon: <HandshakeIcon /> },
  { id: "physical", label: "Physical Access", icon: <UsbIcon /> },
  { id: "case-studies", label: "Case Studies", icon: <HistoryEduIcon /> },
  { id: "tools", label: "Tools & Frameworks", icon: <BuildIcon /> },
  { id: "detection", label: "Detection", icon: <ShieldIcon /> },
  { id: "labs", label: "Hands-On Labs", icon: <ScienceIcon /> },
  { id: "glossary", label: "Glossary", icon: <MenuBookIcon /> },
  { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon /> },
];

// Theme colors
const theme = {
  primary: "#dc2626",
  primaryLight: "#ef4444",
  secondary: "#f97316",
  accent: "#a855f7",
  success: "#10b981",
  warning: "#f59e0b",
  info: "#06b6d4",
  bgDark: "#0a0a0f",
  bgCard: "#12121a",
  bgNested: "#0f1024",
  bgCode: "#1a1a2e",
  border: "rgba(220, 38, 38, 0.2)",
  text: "#e2e8f0",
  textMuted: "#94a3b8",
};

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = theme.accent;

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Foundations",
    question: "What is Initial Access in the context of red teaming?",
    options: [
      "The first foothold gained in a target environment",
      "Escalating privileges on a compromised system",
      "Moving laterally between network segments",
      "Exfiltrating data from the network",
    ],
    correctAnswer: 0,
    explanation: "Initial Access refers to techniques adversaries use to gain their first foothold within a target network.",
  },
  {
    id: 2,
    topic: "Foundations",
    question: "Which MITRE ATT&CK tactic ID represents Initial Access?",
    options: [
      "TA0001",
      "TA0002",
      "TA0003",
      "TA0004",
    ],
    correctAnswer: 0,
    explanation: "TA0001 is the MITRE ATT&CK tactic ID for Initial Access.",
  },
  {
    id: 3,
    topic: "Phishing",
    question: "What is spearphishing?",
    options: [
      "Targeted phishing aimed at specific individuals or organizations",
      "Mass email campaigns to random recipients",
      "Phishing attacks via phone calls",
      "Automated credential harvesting",
    ],
    correctAnswer: 0,
    explanation: "Spearphishing is a targeted form of phishing directed at specific individuals or organizations.",
  },
  {
    id: 4,
    topic: "Phishing",
    question: "Which technique involves sending malicious files via email?",
    options: [
      "Spearphishing Attachment (T1566.001)",
      "Spearphishing Link (T1566.002)",
      "Spearphishing via Service (T1566.003)",
      "Drive-by Compromise (T1189)",
    ],
    correctAnswer: 0,
    explanation: "Spearphishing Attachment involves sending emails with malicious file attachments.",
  },
  {
    id: 5,
    topic: "Phishing",
    question: "What makes spearphishing via service different from traditional email phishing?",
    options: [
      "It uses third-party services like social media or messaging platforms",
      "It only targets IT administrators",
      "It requires physical access to the target",
      "It uses DNS tunneling for delivery",
    ],
    correctAnswer: 0,
    explanation: "Spearphishing via Service uses third-party platforms rather than email for delivery.",
  },
  {
    id: 6,
    topic: "Techniques",
    question: "What is a drive-by compromise?",
    options: [
      "Infecting victims when they visit a compromised website",
      "Physically driving to a target location",
      "Compromising backup systems",
      "Attacking cloud storage services",
    ],
    correctAnswer: 0,
    explanation: "Drive-by compromise infects users when they browse to a malicious or compromised website.",
  },
  {
    id: 7,
    topic: "Techniques",
    question: "Which technique exploits vulnerabilities in internet-facing applications?",
    options: [
      "Exploit Public-Facing Application (T1190)",
      "Valid Accounts (T1078)",
      "Trusted Relationship (T1199)",
      "Hardware Additions (T1200)",
    ],
    correctAnswer: 0,
    explanation: "T1190 covers exploiting vulnerabilities in public-facing applications like web servers.",
  },
  {
    id: 8,
    topic: "Techniques",
    question: "What is the primary risk of external remote services?",
    options: [
      "Attackers can authenticate using stolen or weak credentials",
      "They require physical access",
      "They only work on Linux systems",
      "They cannot be monitored",
    ],
    correctAnswer: 0,
    explanation: "External remote services like VPN and RDP can be abused with compromised credentials.",
  },
  {
    id: 9,
    topic: "Supply Chain",
    question: "What is a supply chain attack?",
    options: [
      "Compromising a trusted vendor to reach the ultimate target",
      "Attacking shipping companies",
      "Stealing physical packages",
      "Targeting retail point-of-sale systems",
    ],
    correctAnswer: 0,
    explanation: "Supply chain attacks compromise trusted third parties to gain access to the ultimate target.",
  },
  {
    id: 10,
    topic: "Supply Chain",
    question: "Which is a famous example of a supply chain attack?",
    options: [
      "SolarWinds Orion compromise",
      "WannaCry ransomware",
      "Heartbleed vulnerability",
      "Log4Shell",
    ],
    correctAnswer: 0,
    explanation: "The SolarWinds attack compromised build systems to distribute malicious updates.",
  },
  {
    id: 11,
    topic: "Techniques",
    question: "What does the Trusted Relationship technique exploit?",
    options: [
      "Access granted to third parties like MSPs or contractors",
      "Personal friendships with employees",
      "Social media connections",
      "Family relationships of targets",
    ],
    correctAnswer: 0,
    explanation: "Trusted Relationship exploits the access granted to legitimate third parties.",
  },
  {
    id: 12,
    topic: "Physical",
    question: "What is Hardware Additions (T1200)?",
    options: [
      "Introducing malicious hardware like USB devices or implants",
      "Upgrading server RAM",
      "Installing network switches",
      "Adding storage devices",
    ],
    correctAnswer: 0,
    explanation: "Hardware Additions involves physically introducing malicious devices into the environment.",
  },
  {
    id: 13,
    topic: "Physical",
    question: "What technique involves malware spread via USB drives?",
    options: [
      "Replication Through Removable Media (T1091)",
      "Drive-by Compromise (T1189)",
      "Supply Chain Compromise (T1195)",
      "Phishing (T1566)",
    ],
    correctAnswer: 0,
    explanation: "T1091 covers malware that spreads via removable media like USB drives.",
  },
  {
    id: 14,
    topic: "Credentials",
    question: "Valid Accounts (T1078) typically involves:",
    options: [
      "Using legitimate credentials obtained through various means",
      "Creating new unauthorized accounts",
      "Exploiting kernel vulnerabilities",
      "DNS poisoning",
    ],
    correctAnswer: 0,
    explanation: "Valid Accounts uses legitimate credentials that were stolen, purchased, or guessed.",
  },
  {
    id: 15,
    topic: "Credentials",
    question: "Password spraying targets:",
    options: [
      "Many accounts with a few common passwords",
      "One account with many password attempts",
      "Encrypted password databases",
      "Password reset mechanisms",
    ],
    correctAnswer: 0,
    explanation: "Password spraying tries common passwords across many accounts to avoid lockouts.",
  },
  {
    id: 16,
    topic: "Tools",
    question: "GoPhish is primarily used for:",
    options: [
      "Phishing campaign simulation and awareness testing",
      "Network vulnerability scanning",
      "Password cracking",
      "Malware analysis",
    ],
    correctAnswer: 0,
    explanation: "GoPhish is an open-source phishing framework for security awareness testing.",
  },
  {
    id: 17,
    topic: "Tools",
    question: "Evilginx is a tool for:",
    options: [
      "Man-in-the-middle phishing to bypass MFA",
      "SQL injection testing",
      "Network traffic analysis",
      "Wireless attacks",
    ],
    correctAnswer: 0,
    explanation: "Evilginx is a reverse proxy for phishing that can capture session tokens and bypass MFA.",
  },
  {
    id: 18,
    topic: "Detection",
    question: "Which log source is most useful for detecting phishing attacks?",
    options: [
      "Email gateway logs and endpoint detection",
      "DNS query logs only",
      "DHCP logs",
      "Print server logs",
    ],
    correctAnswer: 0,
    explanation: "Email gateway logs and endpoint detection provide visibility into phishing attempts.",
  },
  {
    id: 19,
    topic: "Detection",
    question: "What indicator might suggest a drive-by compromise?",
    options: [
      "Browser process spawning unexpected child processes",
      "High CPU usage",
      "Full disk storage",
      "Slow network speeds",
    ],
    correctAnswer: 0,
    explanation: "Unusual process creation from browsers can indicate exploit kit activity.",
  },
  {
    id: 20,
    topic: "Detection",
    question: "Which defense helps prevent exploitation of public-facing applications?",
    options: [
      "Regular patching and web application firewalls",
      "Disabling all internet access",
      "Using only internal DNS",
      "Removing all logging",
    ],
    correctAnswer: 0,
    explanation: "Patching vulnerabilities and using WAFs help protect public-facing applications.",
  },
  {
    id: 21,
    topic: "Detection",
    question: "Failed login attempts from unusual locations may indicate:",
    options: [
      "Credential stuffing or password spraying attacks",
      "Normal user behavior",
      "System maintenance",
      "DNS issues",
    ],
    correctAnswer: 0,
    explanation: "Unusual authentication patterns often indicate credential-based attacks.",
  },
  {
    id: 22,
    topic: "Detection",
    question: "What makes supply chain attacks difficult to detect?",
    options: [
      "Malicious code comes from trusted sources",
      "They only happen at night",
      "They don't leave logs",
      "They target only small businesses",
    ],
    correctAnswer: 0,
    explanation: "Supply chain attacks are stealthy because the malicious code comes from trusted vendors.",
  },
  {
    id: 23,
    topic: "Prevention",
    question: "Which control best prevents credential-based initial access?",
    options: [
      "Multi-factor authentication",
      "Firewalls",
      "Antivirus software",
      "Disk encryption",
    ],
    correctAnswer: 0,
    explanation: "MFA adds an extra layer preventing access even if passwords are compromised.",
  },
  {
    id: 24,
    topic: "Prevention",
    question: "User security awareness training primarily helps prevent:",
    options: [
      "Phishing and social engineering attacks",
      "Zero-day exploits",
      "DDoS attacks",
      "Hardware failures",
    ],
    correctAnswer: 0,
    explanation: "Training helps users recognize and report phishing attempts.",
  },
  {
    id: 25,
    topic: "Prevention",
    question: "Disabling USB ports helps prevent which technique?",
    options: [
      "Replication Through Removable Media and Hardware Additions",
      "Spearphishing",
      "Drive-by Compromise",
      "Supply Chain attacks",
    ],
    correctAnswer: 0,
    explanation: "Disabling USB ports prevents malicious devices and removable media threats.",
  },
  {
    id: 26,
    topic: "Techniques",
    question: "A watering hole attack is a type of:",
    options: [
      "Drive-by Compromise targeting specific groups",
      "Phishing via email",
      "Physical intrusion",
      "Supply chain attack",
    ],
    correctAnswer: 0,
    explanation: "Watering hole attacks compromise websites frequented by the target group.",
  },
  {
    id: 27,
    topic: "Techniques",
    question: "Which protocol is commonly targeted for external remote service attacks?",
    options: [
      "RDP (Remote Desktop Protocol)",
      "ICMP",
      "NTP",
      "SNMP",
    ],
    correctAnswer: 0,
    explanation: "RDP is frequently targeted for brute force and credential-based attacks.",
  },
  {
    id: 28,
    topic: "Tools",
    question: "SET (Social Engineering Toolkit) is used for:",
    options: [
      "Creating social engineering attack scenarios",
      "Network scanning",
      "Log analysis",
      "Incident response",
    ],
    correctAnswer: 0,
    explanation: "SET provides tools for crafting various social engineering attacks.",
  },
  {
    id: 29,
    topic: "Phishing",
    question: "What is pretexting in the context of initial access?",
    options: [
      "Creating a fabricated scenario to manipulate targets",
      "Adding text to phishing emails",
      "Encoding malware",
      "Network reconnaissance",
    ],
    correctAnswer: 0,
    explanation: "Pretexting involves creating a believable scenario to manipulate targets.",
  },
  {
    id: 30,
    topic: "Detection",
    question: "DMARC, DKIM, and SPF help prevent:",
    options: [
      "Email spoofing used in phishing",
      "SQL injection",
      "Buffer overflow attacks",
      "Privilege escalation",
    ],
    correctAnswer: 0,
    explanation: "These email authentication protocols help prevent domain spoofing.",
  },
  {
    id: 31,
    topic: "Case Studies",
    question: "In the SolarWinds attack, what was the name of the backdoor?",
    options: [
      "SUNBURST",
      "WANNACRY",
      "NOTPETYA",
      "STUXNET",
    ],
    correctAnswer: 0,
    explanation: "SUNBURST was the backdoor injected into SolarWinds Orion software updates.",
  },
  {
    id: 32,
    topic: "Case Studies",
    question: "The ProxyLogon vulnerabilities affected which Microsoft product?",
    options: [
      "Microsoft Exchange Server",
      "Microsoft Office",
      "Microsoft Teams",
      "Azure Active Directory",
    ],
    correctAnswer: 0,
    explanation: "ProxyLogon was a chain of vulnerabilities in Microsoft Exchange Server.",
  },
  {
    id: 33,
    topic: "Detection",
    question: "Which Windows Event ID indicates a successful logon?",
    options: [
      "4624",
      "4625",
      "4648",
      "4771",
    ],
    correctAnswer: 0,
    explanation: "Event ID 4624 logs successful authentication events.",
  },
  {
    id: 34,
    topic: "Detection",
    question: "Which Sysmon Event ID records process creation?",
    options: [
      "Event ID 1",
      "Event ID 3",
      "Event ID 7",
      "Event ID 22",
    ],
    correctAnswer: 0,
    explanation: "Sysmon Event ID 1 captures detailed process creation information.",
  },
  {
    id: 35,
    topic: "Detection",
    question: "What does a logon type 10 in Event 4624 indicate?",
    options: [
      "Remote Desktop (RDP) logon",
      "Network logon",
      "Batch logon",
      "Service logon",
    ],
    correctAnswer: 0,
    explanation: "Logon type 10 specifically indicates Remote Desktop/Terminal Services logon.",
  },
  {
    id: 36,
    topic: "Tools",
    question: "What is Evilginx primarily used for?",
    options: [
      "MFA bypass through reverse proxy phishing",
      "Network vulnerability scanning",
      "Password cracking",
      "Malware analysis",
    ],
    correctAnswer: 0,
    explanation: "Evilginx is a man-in-the-middle framework that can capture session tokens and bypass MFA.",
  },
  {
    id: 37,
    topic: "Techniques",
    question: "What is HTML smuggling?",
    options: [
      "Constructing malicious payloads on client-side using HTML5/JavaScript",
      "Hiding malware in HTML comments",
      "Encoding URLs in emails",
      "Compressing HTML files",
    ],
    correctAnswer: 0,
    explanation: "HTML smuggling uses HTML5 and JavaScript to construct payloads client-side, bypassing network security.",
  },
  {
    id: 38,
    topic: "Case Studies",
    question: "The 3CX supply chain attack was attributed to which threat actor?",
    options: [
      "Lazarus Group (North Korea)",
      "APT29 (Russia)",
      "APT41 (China)",
      "FIN7",
    ],
    correctAnswer: 0,
    explanation: "The 3CX compromise was attributed to North Korean threat actors (Lazarus Group).",
  },
  {
    id: 39,
    topic: "Terminology",
    question: "What is an Initial Access Broker (IAB)?",
    options: [
      "Threat actor who sells network access to other criminals",
      "Legitimate security consultant",
      "Firewall vendor",
      "Cloud service provider",
    ],
    correctAnswer: 0,
    explanation: "IABs specialize in gaining initial access and selling it to ransomware operators or other threat actors.",
  },
  {
    id: 40,
    topic: "Terminology",
    question: "What is AiTM (Adversary-in-the-Middle)?",
    options: [
      "Attack positioning between user and service to capture credentials/tokens",
      "Malware analysis technique",
      "Encryption algorithm",
      "Network monitoring tool",
    ],
    correctAnswer: 0,
    explanation: "AiTM attacks intercept authentication in real-time to capture credentials and session tokens.",
  },
  {
    id: 41,
    topic: "Detection",
    question: "Which email header should match the From header to avoid suspicion?",
    options: [
      "Return-Path",
      "Content-Type",
      "X-Mailer",
      "Date",
    ],
    correctAnswer: 0,
    explanation: "A mismatch between Return-Path and From headers is a common phishing indicator.",
  },
  {
    id: 42,
    topic: "Case Studies",
    question: "How did the Twitter Bitcoin scam (2020) achieve initial access?",
    options: [
      "Phone-based social engineering (vishing) of employees",
      "Exploiting a zero-day vulnerability",
      "SQL injection attack",
      "Supply chain compromise",
    ],
    correctAnswer: 0,
    explanation: "Attackers used vishing to trick Twitter employees into providing VPN and admin tool credentials.",
  },
  {
    id: 43,
    topic: "Prevention",
    question: "What can detect password spraying attacks?",
    options: [
      "Multiple failed logins across many accounts from same source",
      "High CPU usage",
      "Disk space alerts",
      "DNS query volume",
    ],
    correctAnswer: 0,
    explanation: "Password spraying shows a pattern of failed logins across many accounts with few password attempts each.",
  },
  {
    id: 44,
    topic: "Techniques",
    question: "What distinguishes credential stuffing from password spraying?",
    options: [
      "Credential stuffing uses known username/password pairs from breaches",
      "Credential stuffing is slower",
      "Password spraying uses more passwords per account",
      "There is no difference",
    ],
    correctAnswer: 0,
    explanation: "Credential stuffing uses leaked credentials, while password spraying tries common passwords across accounts.",
  },
  {
    id: 45,
    topic: "Tools",
    question: "Nuclei is primarily used for:",
    options: [
      "Fast vulnerability scanning with customizable templates",
      "Password cracking",
      "Phishing campaigns",
      "Malware development",
    ],
    correctAnswer: 0,
    explanation: "Nuclei is a fast, template-based vulnerability scanner widely used for security testing.",
  },
];

// Code block component
const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "bash",
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        p: 2,
        bgcolor: theme.bgCode,
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: `1px solid ${theme.border}`,
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8 }}>
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: theme.textMuted }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Typography
        component="pre"
        sx={{
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: theme.text,
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          m: 0,
          pr: 4,
        }}
      >
        {code}
      </Typography>
    </Paper>
  );
};

// MITRE Techniques data
const mitreInitialAccessTechniques = [
  { id: "T1189", name: "Drive-by Compromise", description: "Exploit browser/plugin vulnerabilities via malicious websites" },
  { id: "T1190", name: "Exploit Public-Facing Application", description: "Exploit vulnerabilities in internet-facing systems" },
  { id: "T1133", name: "External Remote Services", description: "Abuse remote services like VPN, RDP, SSH" },
  { id: "T1200", name: "Hardware Additions", description: "Introduce malicious hardware devices" },
  { id: "T1566", name: "Phishing", description: "Social engineering via email or other services" },
  { id: "T1091", name: "Replication Through Removable Media", description: "Spread via USB drives and other removable media" },
  { id: "T1195", name: "Supply Chain Compromise", description: "Manipulate products before delivery" },
  { id: "T1199", name: "Trusted Relationship", description: "Abuse trusted third-party access" },
  { id: "T1078", name: "Valid Accounts", description: "Use legitimate credentials for access" },
];

const InitialAccessPage: React.FC = () => {
  const navigate = useNavigate();
  const muiTheme = useTheme();
  const isMobile = useMediaQuery(muiTheme.breakpoints.down("md"));
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    setNavDrawerOpen(false);
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // Sidebar navigation
  const sidebarNav = (
    <Box sx={{ position: "sticky", top: 24 }}>
      <Paper
        sx={{
          bgcolor: theme.bgCard,
          border: `1px solid ${theme.border}`,
          borderRadius: 2,
          p: 2,
        }}
      >
        <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 2, fontWeight: 600 }}>
          NAVIGATION
        </Typography>
        <List dense disablePadding>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              component="button"
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1,
                mb: 0.5,
                cursor: "pointer",
                border: "none",
                bgcolor: "transparent",
                width: "100%",
                textAlign: "left",
                "&:hover": {
                  bgcolor: alpha(theme.primary, 0.1),
                },
              }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: theme.primary }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  variant: "body2",
                  sx: { color: theme.text },
                }}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );

  return (
    <LearnPageLayout
      pageTitle="Initial Access"
      pageContext="This page covers red team initial access techniques from the MITRE ATT&CK framework including phishing, drive-by compromise, exploiting public-facing applications, supply chain attacks, and more. Focus on educational content about how adversaries gain their first foothold in target environments."
    >
      <Box sx={{ bgcolor: theme.bgDark, minHeight: "100vh", py: 4 }}>
        <Container maxWidth="xl">
          <Grid container spacing={3}>
            {/* Sidebar - Desktop */}
            <Grid item md={3} sx={{ display: { xs: "none", md: "block" } }}>
              {sidebarNav}
            </Grid>

            {/* Main Content */}
            <Grid item xs={12} md={9}>
              {/* Header */}
              <Paper
                sx={{
                  p: 4,
                  mb: 4,
                  bgcolor: theme.bgCard,
                  border: `1px solid ${theme.border}`,
                  borderRadius: 2,
                  background: `linear-gradient(135deg, ${theme.bgCard} 0%, ${alpha(theme.primary, 0.1)} 100%)`,
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <RocketLaunchIcon sx={{ fontSize: 48, color: theme.primary }} />
                  <Box>
                    <Typography variant="h4" sx={{ color: theme.text, fontWeight: 700 }}>
                      Initial Access
                    </Typography>
                    <Typography variant="subtitle1" sx={{ color: theme.textMuted }}>
                      Red Team Techniques for Gaining First Foothold
                    </Typography>
                  </Box>
                </Box>
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 2 }}>
                  <Chip label="MITRE ATT&CK TA0001" size="small" sx={{ bgcolor: alpha(theme.primary, 0.2), color: theme.primary }} />
                  <Chip label="Phishing" size="small" sx={{ bgcolor: alpha(theme.secondary, 0.2), color: theme.secondary }} />
                  <Chip label="Exploitation" size="small" sx={{ bgcolor: alpha(theme.accent, 0.2), color: theme.accent }} />
                  <Chip label="Supply Chain" size="small" sx={{ bgcolor: alpha(theme.info, 0.2), color: theme.info }} />
                </Box>
              </Paper>

              {/* Introduction Section */}
              <Box id="intro" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <RocketLaunchIcon /> Introduction to Initial Access
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Initial Access represents the first phase of an adversary's intrusion into a target network. It encompasses all the techniques
                    attackers use to establish their first foothold within an environment. Understanding these techniques is essential for both
                    offensive security professionals conducting authorized engagements and defenders seeking to protect their organizations.
                  </Typography>
                  <Alert severity="info" sx={{ mb: 2, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      <strong>Educational Purpose:</strong> This content is designed for security professionals conducting authorized penetration
                      testing, red team engagements, and security awareness training. Always obtain proper authorization before testing.
                    </Typography>
                  </Alert>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    The initial access phase is critical because it determines whether an attacker can proceed to subsequent phases like
                    execution, persistence, and lateral movement. A well-defended perimeter with proper monitoring can detect and prevent
                    many initial access attempts.
                  </Typography>
                  <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1, mt: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: theme.secondary, mb: 1 }}>
                      Key Objectives of Initial Access:
                    </Typography>
                    <List dense>
                      {[
                        "Establish first code execution or shell access on a target system",
                        "Bypass perimeter security controls (firewalls, email gateways, WAFs)",
                        "Avoid detection during the intrusion attempt",
                        "Position for subsequent attack phases",
                      ].map((item, idx) => (
                        <ListItem key={idx} sx={{ py: 0.5 }}>
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            <KeyboardArrowRightIcon sx={{ color: theme.secondary }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.text } }} />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                </Paper>
              </Box>

              {/* MITRE ATT&CK Section */}
              <Box id="mitre" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <GpsFixedIcon /> MITRE ATT&CK: Initial Access (TA0001)
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    The MITRE ATT&CK framework categorizes Initial Access as tactic TA0001 and defines nine primary techniques that
                    adversaries use to gain entry into target environments.
                  </Typography>
                  <TableContainer component={Paper} sx={{ bgcolor: theme.bgNested, mb: 3 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Technique ID</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Name</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Description</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {mitreInitialAccessTechniques.map((tech) => (
                          <TableRow key={tech.id} sx={{ "&:hover": { bgcolor: alpha(theme.primary, 0.05) } }}>
                            <TableCell sx={{ color: theme.secondary, fontFamily: "monospace" }}>{tech.id}</TableCell>
                            <TableCell sx={{ color: theme.text, fontWeight: 500 }}>{tech.name}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{tech.description}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              </Box>

              {/* Phishing Section */}
              <Box id="phishing" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <EmailIcon /> Phishing (T1566)
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Phishing remains one of the most prevalent and effective initial access techniques. It leverages social engineering
                    to trick users into executing malicious code, revealing credentials, or taking other harmful actions.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        T1566.001 - Spearphishing Attachment
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Adversaries send emails with malicious attachments that execute code when opened. Common file types include:
                      </Typography>
                      <List dense>
                        {[
                          "Microsoft Office documents with macros (.docm, .xlsm)",
                          "PDF files with embedded JavaScript or exploits",
                          "ISO/IMG files containing executables",
                          "HTML files with embedded scripts (HTML smuggling)",
                          "LNK shortcut files pointing to malicious resources",
                          "Archive files (.zip, .rar) containing executables",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon sx={{ fontSize: 16, color: theme.success }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                          </ListItem>
                        ))}
                      </List>
                      <CodeBlock
                        code={`# Example: Creating a macro-enabled document payload (for authorized testing)
# GoPhish template with attachment
{
  "name": "Security Update Required",
  "subject": "Action Required: Security Certificate Update",
  "html": "<p>Please review the attached security document...</p>",
  "attachments": ["security_update.docm"]
}`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        T1566.002 - Spearphishing Link
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Instead of attachments, adversaries include links to credential harvesting pages, drive-by download sites,
                        or pages that prompt users to download malicious files.
                      </Typography>
                      <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          Modern MFA bypass techniques like Evilginx can capture session tokens even when MFA is enabled,
                          making link-based phishing extremely dangerous.
                        </Typography>
                      </Alert>
                      <Typography variant="subtitle2" sx={{ color: theme.text, mb: 1 }}>
                        Common Techniques:
                      </Typography>
                      <List dense>
                        {[
                          "Credential harvesting with cloned login pages",
                          "OAuth consent phishing (illicit consent grants)",
                          "Reverse proxy phishing (Evilginx, Modlishka)",
                          "QR code phishing (Quishing)",
                          "Browser-in-the-Browser (BitB) attacks",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <WarningIcon sx={{ fontSize: 16, color: theme.warning }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        T1566.003 - Spearphishing via Service
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Attackers use third-party services rather than email to deliver phishing content:
                      </Typography>
                      <List dense>
                        {[
                          "LinkedIn messages and connection requests",
                          "Slack/Teams messages in shared workspaces",
                          "Social media direct messages",
                          "SMS/text message phishing (Smishing)",
                          "Voice calls with pretexting (Vishing)",
                          "Collaboration platforms (Discord, Telegram)",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <KeyboardArrowRightIcon sx={{ fontSize: 16, color: theme.info }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Drive-by Compromise Section */}
              <Box id="drive-by" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <LanguageIcon /> Drive-by Compromise (T1189)
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Drive-by compromise occurs when a user visits a website that has been compromised or contains malicious content,
                    resulting in automatic code execution without user interaction beyond browsing.
                  </Typography>

                  <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1, mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: theme.secondary, mb: 1 }}>
                      Attack Variations:
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: theme.bgCode, height: "100%" }}>
                          <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>
                            Watering Hole Attacks
                          </Typography>
                          <Typography variant="body2" sx={{ color: theme.textMuted }}>
                            Compromise websites frequently visited by target group members. Attackers identify
                            industry-specific sites, inject exploit code, and wait for targets to browse.
                          </Typography>
                        </Paper>
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Paper sx={{ p: 2, bgcolor: theme.bgCode, height: "100%" }}>
                          <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>
                            Exploit Kits
                          </Typography>
                          <Typography variant="body2" sx={{ color: theme.textMuted }}>
                            Automated exploit frameworks that probe browsers for vulnerabilities and deliver
                            payloads. Examples include RIG, Fallout, and historically Angler and Nuclear.
                          </Typography>
                        </Paper>
                      </Grid>
                    </Grid>
                  </Box>

                  <Typography variant="subtitle2" sx={{ color: theme.text, mb: 1 }}>
                    Common Exploit Targets:
                  </Typography>
                  <List dense>
                    {[
                      "Browser vulnerabilities (Chrome, Firefox, Edge, Safari)",
                      "Browser plugins (Flash - legacy, Java - legacy, PDF readers)",
                      "JavaScript engines (V8, SpiderMonkey, JavaScriptCore)",
                      "WebKit/Blink rendering engine flaws",
                    ].map((item, idx) => (
                      <ListItem key={idx} sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <BugReportIcon sx={{ fontSize: 16, color: theme.primary }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Box>

              {/* Public-Facing Applications Section */}
              <Box id="public-apps" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <BugReportIcon /> Exploit Public-Facing Application (T1190)
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Adversaries exploit vulnerabilities in internet-facing systems including web applications, remote access services,
                    and network appliances. This technique often provides direct access to internal networks.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Web Application Vulnerabilities
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        {[
                          { vuln: "SQL Injection", desc: "Database manipulation through unsanitized input" },
                          { vuln: "Command Injection", desc: "OS command execution via application" },
                          { vuln: "SSRF", desc: "Server-Side Request Forgery for internal access" },
                          { vuln: "Deserialization", desc: "Code execution via malicious serialized objects" },
                          { vuln: "File Upload", desc: "Uploading web shells or malicious files" },
                          { vuln: "Authentication Bypass", desc: "Circumventing login mechanisms" },
                        ].map((item, idx) => (
                          <Grid item xs={12} sm={6} key={idx}>
                            <Box sx={{ p: 1.5, bgcolor: theme.bgCode, borderRadius: 1 }}>
                              <Typography variant="subtitle2" sx={{ color: theme.primary }}>{item.vuln}</Typography>
                              <Typography variant="caption" sx={{ color: theme.textMuted }}>{item.desc}</Typography>
                            </Box>
                          </Grid>
                        ))}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Network Appliance Exploits
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Network devices at the perimeter are high-value targets due to their privileged network position:
                      </Typography>
                      <List dense>
                        {[
                          "VPN appliances (Pulse Secure, Fortinet, Citrix, Palo Alto)",
                          "Firewalls and UTM devices",
                          "Load balancers and reverse proxies",
                          "Email gateways and spam filters",
                          "Remote access gateways",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <WarningIcon sx={{ fontSize: 16, color: theme.warning }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                          </ListItem>
                        ))}
                      </List>
                      <Alert severity="error" sx={{ mt: 2, bgcolor: alpha(theme.primary, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          Notable recent vulnerabilities: CVE-2024-3400 (PAN-OS), CVE-2023-4966 (Citrix Bleed),
                          CVE-2023-27997 (FortiGate), CVE-2021-22893 (Pulse Secure)
                        </Typography>
                      </Alert>
                    </AccordionDetails>
                  </Accordion>

                  <CodeBlock
                    code={`# Reconnaissance for public-facing applications
# Subdomain enumeration
subfinder -d target.com -o subdomains.txt
amass enum -d target.com -o amass_results.txt

# Service identification
nmap -sV -sC -p- -oA nmap_full target.com
nuclei -u https://target.com -t cves/ -o nuclei_results.txt

# Web application scanning
nikto -h https://target.com
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ`}
                  />
                </Paper>
              </Box>

              {/* External Remote Services Section */}
              <Box id="external-services" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <VpnKeyIcon /> External Remote Services (T1133)
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Adversaries leverage external-facing remote services using valid accounts obtained through credential theft,
                    brute force, or purchasing from underground markets.
                  </Typography>

                  <TableContainer component={Paper} sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Service</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Default Port</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Attack Methods</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          { service: "RDP", port: "3389", attacks: "Brute force, credential stuffing, BlueKeep" },
                          { service: "SSH", port: "22", attacks: "Key theft, brute force, password spraying" },
                          { service: "VPN", port: "443/1194", attacks: "Credential stuffing, stolen cookies" },
                          { service: "Citrix", port: "443", attacks: "Credential theft, known CVEs" },
                          { service: "RDWeb", port: "443", attacks: "Password spraying, MFA bypass" },
                        ].map((row, idx) => (
                          <TableRow key={idx}>
                            <TableCell sx={{ color: theme.secondary, fontWeight: 500 }}>{row.service}</TableCell>
                            <TableCell sx={{ color: theme.text, fontFamily: "monospace" }}>{row.port}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{row.attacks}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1 }}>
                    <Typography variant="subtitle2" sx={{ color: theme.secondary, mb: 1 }}>
                      Valid Accounts (T1078) - Credential Sources:
                    </Typography>
                    <List dense>
                      {[
                        "Credential dumps from previous breaches (dehashed, leakcheck)",
                        "Password spraying with common passwords",
                        "Phishing campaigns harvesting credentials",
                        "Initial Access Brokers (IABs) on dark web forums",
                        "Infostealer logs (Redline, Raccoon, Vidar)",
                        "Keyloggers and session hijacking",
                      ].map((item, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <KeyboardArrowRightIcon sx={{ fontSize: 16, color: theme.accent }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                </Paper>
              </Box>

              {/* Supply Chain Section */}
              <Box id="supply-chain" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <LocalShippingIcon /> Supply Chain Compromise (T1195)
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Supply chain attacks compromise products or services before they reach the final consumer. These attacks
                    are highly effective because they abuse inherent trust in software vendors and service providers.
                  </Typography>

                  <Alert severity="error" sx={{ mb: 3, bgcolor: alpha(theme.primary, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      <strong>High Impact:</strong> Supply chain attacks can affect thousands of organizations simultaneously,
                      as seen in SolarWinds (18,000+ organizations), Kaseya VSA, and 3CX incidents.
                    </Typography>
                  </Alert>

                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%" }}>
                        <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>
                          T1195.001 - Compromise Software Dependencies
                        </Typography>
                        <Typography variant="body2" sx={{ color: theme.textMuted }}>
                          Inject malicious code into open source packages (npm, PyPI, RubyGems) or compromise
                          package maintainer accounts.
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%" }}>
                        <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>
                          T1195.002 - Compromise Software Supply Chain
                        </Typography>
                        <Typography variant="body2" sx={{ color: theme.textMuted }}>
                          Compromise build systems, code signing, or distribution mechanisms to inject
                          malicious code into legitimate software.
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%" }}>
                        <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>
                          T1195.003 - Compromise Hardware Supply Chain
                        </Typography>
                        <Typography variant="body2" sx={{ color: theme.textMuted }}>
                          Implant malicious firmware or hardware modifications during manufacturing or
                          shipping processes.
                        </Typography>
                      </Paper>
                    </Grid>
                  </Grid>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Notable Supply Chain Attacks
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense>
                        {[
                          { name: "SolarWinds (2020)", desc: "SUNBURST backdoor in Orion software updates" },
                          { name: "Kaseya VSA (2021)", desc: "REvil ransomware via MSP software" },
                          { name: "3CX (2023)", desc: "Trojanized desktop application with staged payload" },
                          { name: "Codecov (2021)", desc: "Bash uploader script modified to exfiltrate credentials" },
                          { name: "ua-parser-js (2021)", desc: "Popular npm package compromised with crypto miners" },
                          { name: "event-stream (2018)", desc: "npm package targeted Bitcoin wallets" },
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 32 }}>
                              <WarningIcon sx={{ fontSize: 18, color: theme.warning }} />
                            </ListItemIcon>
                            <ListItemText
                              primary={item.name}
                              secondary={item.desc}
                              primaryTypographyProps={{ variant: "body2", sx: { color: theme.text, fontWeight: 600 } }}
                              secondaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Trusted Relationship Section */}
              <Box id="trusted-relationship" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <HandshakeIcon /> Trusted Relationship (T1199)
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Adversaries abuse the access granted to third parties such as managed service providers (MSPs),
                    IT contractors, or business partners who have legitimate access to target environments.
                  </Typography>

                  <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1, mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: theme.secondary, mb: 1 }}>
                      Common Trust Relationships Abused:
                    </Typography>
                    <Grid container spacing={2}>
                      {[
                        { type: "MSPs/MSSPs", risk: "Remote management tools, admin credentials" },
                        { type: "IT Contractors", risk: "VPN access, privileged accounts" },
                        { type: "Cloud Partners", risk: "API integrations, shared tenants" },
                        { type: "Software Vendors", risk: "Support access, update mechanisms" },
                        { type: "Business Partners", risk: "B2B connections, data sharing" },
                        { type: "Subsidiaries", risk: "Domain trusts, network connections" },
                      ].map((item, idx) => (
                        <Grid item xs={12} sm={6} key={idx}>
                          <Box sx={{ p: 1.5, bgcolor: theme.bgCode, borderRadius: 1 }}>
                            <Typography variant="subtitle2" sx={{ color: theme.primary }}>{item.type}</Typography>
                            <Typography variant="caption" sx={{ color: theme.textMuted }}>{item.risk}</Typography>
                          </Box>
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                </Paper>
              </Box>

              {/* Physical Access Section */}
              <Box id="physical" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <UsbIcon /> Physical Access Techniques
                  </Typography>

                  <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                      <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1, height: "100%" }}>
                        <Typography variant="subtitle1" sx={{ color: theme.secondary, mb: 1 }}>
                          Hardware Additions (T1200)
                        </Typography>
                        <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                          Physical introduction of malicious hardware devices:
                        </Typography>
                        <List dense>
                          {[
                            "Keystroke injection devices (Rubber Ducky, Bash Bunny)",
                            "Network implants (LAN Turtle, Packet Squirrel)",
                            "Rogue access points",
                            "Hardware keyloggers",
                            "Malicious charging cables (O.MG Cable)",
                          ].map((item, idx) => (
                            <ListItem key={idx} sx={{ py: 0.25 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <UsbIcon sx={{ fontSize: 16, color: theme.accent }} />
                              </ListItemIcon>
                              <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1, height: "100%" }}>
                        <Typography variant="subtitle1" sx={{ color: theme.secondary, mb: 1 }}>
                          Replication Through Removable Media (T1091)
                        </Typography>
                        <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                          Malware propagation via removable storage:
                        </Typography>
                        <List dense>
                          {[
                            "USB drive malware (autorun, shortcut files)",
                            "Infected firmware on USB devices",
                            "Baiting attacks (dropped USB drives)",
                            "Air-gapped network bridging",
                            "Historical: Stuxnet propagation method",
                          ].map((item, idx) => (
                            <ListItem key={idx} sx={{ py: 0.25 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <UsbIcon sx={{ fontSize: 16, color: theme.warning }} />
                              </ListItemIcon>
                              <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>
              </Box>

              {/* Real-World Case Studies Section */}
              <Box id="case-studies" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <HistoryEduIcon /> Real-World Case Studies
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    Understanding how major breaches occurred provides valuable insights into initial access techniques and their real-world impact.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                        <Chip label="Supply Chain" size="small" sx={{ bgcolor: alpha(theme.primary, 0.2), color: theme.primary }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          SolarWinds SUNBURST (2020)
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="error" sx={{ mb: 2, bgcolor: alpha(theme.primary, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Impact:</strong> 18,000+ organizations affected, including US government agencies and Fortune 500 companies.
                        </Typography>
                      </Alert>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Russian threat actors (APT29/Cozy Bear) compromised SolarWinds' build system to inject the SUNBURST backdoor into
                        Orion software updates. The attack remained undetected for months.
                      </Typography>
                      <Box sx={{ bgcolor: theme.bgCode, p: 2, borderRadius: 1, mb: 2 }}>
                        <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>Attack Chain:</Typography>
                        <List dense>
                          {[
                            "1. Compromised SolarWinds build environment (initial access to vendor)",
                            "2. Injected SUNBURST backdoor into Orion software updates",
                            "3. Trojanized updates distributed to 18,000+ customers",
                            "4. SUNBURST activated after 12-14 day dormancy period",
                            "5. C2 communication via DNS, mimicking legitimate Orion traffic",
                            "6. Deployed Cobalt Strike BEACON for further exploitation",
                          ].map((step, idx) => (
                            <ListItem key={idx} sx={{ py: 0.25 }}>
                              <ListItemText primary={step} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted, fontFamily: "monospace" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                      <Typography variant="subtitle2" sx={{ color: theme.success, mb: 1 }}>Detection Opportunities Missed:</Typography>
                      <List dense>
                        {[
                          "Build system integrity monitoring was insufficient",
                          "Code signing occurred after malware injection",
                          "DNS-based C2 blended with legitimate traffic",
                          "Long dormancy period evaded sandbox analysis",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <WarningIcon sx={{ fontSize: 16, color: theme.warning }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                        <Chip label="Public App" size="small" sx={{ bgcolor: alpha(theme.secondary, 0.2), color: theme.secondary }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Microsoft Exchange ProxyLogon (2021)
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="error" sx={{ mb: 2, bgcolor: alpha(theme.primary, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Impact:</strong> 250,000+ Exchange servers compromised worldwide, multiple threat actors exploited simultaneously.
                        </Typography>
                      </Alert>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        A chain of four zero-day vulnerabilities (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065) allowed
                        unauthenticated attackers to execute arbitrary code on Microsoft Exchange servers.
                      </Typography>
                      <Box sx={{ bgcolor: theme.bgCode, p: 2, borderRadius: 1, mb: 2 }}>
                        <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>CVE Chain:</Typography>
                        <TableContainer>
                          <Table size="small">
                            <TableBody>
                              {[
                                { cve: "CVE-2021-26855", type: "SSRF", desc: "Bypass authentication via server-side request forgery" },
                                { cve: "CVE-2021-26857", type: "Deserialization", desc: "Unified Messaging service code execution" },
                                { cve: "CVE-2021-26858", type: "File Write", desc: "Arbitrary file write after authentication" },
                                { cve: "CVE-2021-27065", type: "File Write", desc: "Arbitrary file write for webshell deployment" },
                              ].map((row, idx) => (
                                <TableRow key={idx}>
                                  <TableCell sx={{ color: theme.secondary, fontFamily: "monospace", border: "none", py: 0.5 }}>{row.cve}</TableCell>
                                  <TableCell sx={{ color: theme.accent, border: "none", py: 0.5 }}>{row.type}</TableCell>
                                  <TableCell sx={{ color: theme.textMuted, border: "none", py: 0.5 }}>{row.desc}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Box>
                      <CodeBlock
                        code={`# Detection: Check for webshells in Exchange directories
Get-ChildItem -Path "C:\\inetpub\\wwwroot\\aspnet_client\\" -Recurse -Include *.aspx
Get-ChildItem -Path "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\" -Include *.aspx

# Check Exchange logs for exploitation
Select-String -Path "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log" -Pattern "POST /owa/auth/Current/"`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                        <Chip label="Phishing" size="small" sx={{ bgcolor: alpha(theme.accent, 0.2), color: theme.accent }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Twitter Bitcoin Scam (2020)
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Impact:</strong> High-profile accounts compromised (Elon Musk, Barack Obama, Apple), $120,000+ stolen in Bitcoin.
                        </Typography>
                      </Alert>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Attackers used phone spearphishing (vishing) to target Twitter employees, convincing them to provide credentials
                        to internal admin tools. This demonstrates how social engineering bypasses technical controls.
                      </Typography>
                      <Box sx={{ bgcolor: theme.bgCode, p: 2, borderRadius: 1, mb: 2 }}>
                        <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>Attack Progression:</Typography>
                        <List dense>
                          {[
                            "1. Reconnaissance: Identified Twitter employees on LinkedIn",
                            "2. Vishing: Called employees posing as IT support",
                            "3. Credential Theft: Obtained VPN and admin tool credentials",
                            "4. Internal Access: Accessed Twitter admin tools",
                            "5. Account Takeover: Reset passwords on verified accounts",
                            "6. Monetization: Posted Bitcoin scam from compromised accounts",
                          ].map((step, idx) => (
                            <ListItem key={idx} sx={{ py: 0.25 }}>
                              <ListItemText primary={step} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted, fontFamily: "monospace" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                        <Chip label="Supply Chain" size="small" sx={{ bgcolor: alpha(theme.primary, 0.2), color: theme.primary }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          3CX Desktop App Compromise (2023)
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="error" sx={{ mb: 2, bgcolor: alpha(theme.primary, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Impact:</strong> 600,000+ organizations potentially affected, attributed to North Korean threat actors (Lazarus Group).
                        </Typography>
                      </Alert>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Attackers compromised the 3CX build environment, inserting malicious code into the legitimate desktop application.
                        The trojanized app was signed with valid certificates and distributed through official channels.
                      </Typography>
                      <Box sx={{ bgcolor: theme.bgCode, p: 2, borderRadius: 1, mb: 2 }}>
                        <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>Infection Chain:</Typography>
                        <List dense>
                          {[
                            "1. Malicious DLL (ffmpeg.dll) loaded by legitimate 3CXDesktopApp.exe",
                            "2. DLL reads encrypted payload from d3dcompiler_47.dll",
                            "3. Payload beacons to GitHub for C2 server list (icon files)",
                            "4. Downloads final payload from C2 servers",
                            "5. Information stealer deployed targeting browser data",
                          ].map((step, idx) => (
                            <ListItem key={idx} sx={{ py: 0.25 }}>
                              <ListItemText primary={step} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted, fontFamily: "monospace" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                      <Typography variant="subtitle2" sx={{ color: theme.success, mb: 1 }}>Key Lesson:</Typography>
                      <Typography variant="body2" sx={{ color: theme.textMuted }}>
                        Valid code signatures don't guarantee safety. The trojanized app was signed by 3CX, demonstrating that
                        supply chain attacks can bypass signature-based detection entirely.
                      </Typography>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                        <Chip label="VPN Exploit" size="small" sx={{ bgcolor: alpha(theme.info, 0.2), color: theme.info }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Fortinet FortiOS Exploits (2023-2024)
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="error" sx={{ mb: 2, bgcolor: alpha(theme.primary, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Impact:</strong> Mass exploitation by multiple threat actors including ransomware groups and nation-states.
                        </Typography>
                      </Alert>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Multiple critical vulnerabilities in Fortinet products have been actively exploited for initial access,
                        highlighting the danger of unpatched perimeter devices.
                      </Typography>
                      <TableContainer component={Paper} sx={{ bgcolor: theme.bgCode, mb: 2 }}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>CVE</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>CVSS</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Type</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Exploitation</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {[
                              { cve: "CVE-2024-21762", cvss: "9.8", type: "Out-of-bounds Write", exploit: "Unauthenticated RCE" },
                              { cve: "CVE-2023-27997", cvss: "9.8", type: "Heap Overflow", exploit: "Pre-auth RCE via SSL VPN" },
                              { cve: "CVE-2022-42475", cvss: "9.8", type: "Heap Overflow", exploit: "Pre-auth RCE, used by APTs" },
                            ].map((row, idx) => (
                              <TableRow key={idx}>
                                <TableCell sx={{ color: theme.secondary, fontFamily: "monospace" }}>{row.cve}</TableCell>
                                <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>{row.cvss}</TableCell>
                                <TableCell sx={{ color: theme.textMuted }}>{row.type}</TableCell>
                                <TableCell sx={{ color: theme.warning }}>{row.exploit}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                      <CodeBlock
                        code={`# Check Fortinet device version
get system status

# Indicators of Compromise - check for suspicious files
/data/lib/libips.bak
/data/lib/libgif.so
/data/lib/libiptcp.so
/data/lib/libipudp.so

# Network indicators - monitor for C2 callbacks
# Unusual outbound connections from FortiGate management interface`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Tools & Frameworks Section */}
              <Box id="tools" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <BuildIcon /> Tools & Frameworks
                  </Typography>

                  {/* Tool Comparison Matrix */}
                  <Typography variant="subtitle1" sx={{ color: theme.text, mb: 2 }}>
                    Initial Access Tool Comparison
                  </Typography>
                  <TableContainer component={Paper} sx={{ bgcolor: theme.bgNested, mb: 3 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Tool</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Type</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Use Case</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Difficulty</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>License</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          { tool: "GoPhish", type: "Phishing", use: "Awareness campaigns, credential harvesting", diff: "Easy", license: "Open Source" },
                          { tool: "Evilginx", type: "Phishing", use: "MFA bypass, session hijacking", diff: "Medium", license: "Open Source" },
                          { tool: "Metasploit", type: "Exploitation", use: "Vulnerability exploitation, payload delivery", diff: "Medium", license: "Community/Pro" },
                          { tool: "Cobalt Strike", type: "Red Team", use: "Full adversary simulation", diff: "Advanced", license: "Commercial" },
                          { tool: "Nuclei", type: "Scanning", use: "Vulnerability discovery, CVE detection", diff: "Easy", license: "Open Source" },
                          { tool: "Hydra", type: "Credential", use: "Brute force, password spraying", diff: "Easy", license: "Open Source" },
                          { tool: "SET", type: "Social Eng", use: "Phishing, payload generation", diff: "Easy", license: "Open Source" },
                          { tool: "BeEF", type: "Browser", use: "Browser exploitation, client-side attacks", diff: "Medium", license: "Open Source" },
                        ].map((row, idx) => (
                          <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha(theme.primary, 0.05) } }}>
                            <TableCell sx={{ color: theme.secondary, fontWeight: 500 }}>{row.tool}</TableCell>
                            <TableCell sx={{ color: theme.accent }}>{row.type}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{row.use}</TableCell>
                            <TableCell>
                              <Chip
                                label={row.diff}
                                size="small"
                                sx={{
                                  bgcolor: row.diff === "Easy" ? alpha(theme.success, 0.2) :
                                           row.diff === "Medium" ? alpha(theme.warning, 0.2) : alpha(theme.primary, 0.2),
                                  color: row.diff === "Easy" ? theme.success :
                                         row.diff === "Medium" ? theme.warning : theme.primary,
                                }}
                              />
                            </TableCell>
                            <TableCell sx={{ color: theme.info }}>{row.license}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Phishing Frameworks
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        {[
                          { name: "GoPhish", desc: "Open-source phishing framework for awareness campaigns", url: "gophish.io" },
                          { name: "Evilginx", desc: "MitM attack framework for session hijacking", url: "github.com/kgretzky/evilginx2" },
                          { name: "King Phisher", desc: "Phishing campaign toolkit", url: "github.com/rsmusllp/king-phisher" },
                          { name: "SET", desc: "Social Engineering Toolkit for penetration testing", url: "github.com/trustedsec/social-engineer-toolkit" },
                        ].map((tool, idx) => (
                          <Grid item xs={12} sm={6} key={idx}>
                            <Paper sx={{ p: 2, bgcolor: theme.bgCode }}>
                              <Typography variant="subtitle2" sx={{ color: theme.primary }}>{tool.name}</Typography>
                              <Typography variant="caption" sx={{ color: theme.textMuted, display: "block" }}>{tool.desc}</Typography>
                              <Typography variant="caption" sx={{ color: theme.info, fontFamily: "monospace" }}>{tool.url}</Typography>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Exploitation Frameworks
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        {[
                          { name: "Metasploit", desc: "Comprehensive exploit and payload framework" },
                          { name: "Cobalt Strike", desc: "Commercial adversary simulation platform" },
                          { name: "Nuclei", desc: "Fast vulnerability scanner with templates" },
                          { name: "BeEF", desc: "Browser Exploitation Framework for client-side attacks" },
                        ].map((tool, idx) => (
                          <Grid item xs={12} sm={6} key={idx}>
                            <Paper sx={{ p: 2, bgcolor: theme.bgCode }}>
                              <Typography variant="subtitle2" sx={{ color: theme.primary }}>{tool.name}</Typography>
                              <Typography variant="caption" sx={{ color: theme.textMuted }}>{tool.desc}</Typography>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Credential Tools
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        {[
                          { name: "Hydra", desc: "Fast network logon cracker supporting many protocols" },
                          { name: "Spray", desc: "Password spraying tool for Active Directory" },
                          { name: "Ruler", desc: "Tool for Exchange/Outlook abuse" },
                          { name: "CredMaster", desc: "AWS credential and password spraying tool" },
                        ].map((tool, idx) => (
                          <Grid item xs={12} sm={6} key={idx}>
                            <Paper sx={{ p: 2, bgcolor: theme.bgCode }}>
                              <Typography variant="subtitle2" sx={{ color: theme.primary }}>{tool.name}</Typography>
                              <Typography variant="caption" sx={{ color: theme.textMuted }}>{tool.desc}</Typography>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Detection Section */}
              <Box id="detection" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <ShieldIcon /> Detection & Prevention
                  </Typography>

                  <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                      <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1, height: "100%" }}>
                        <Typography variant="subtitle1" sx={{ color: theme.success, mb: 2 }}>
                          Detection Strategies
                        </Typography>
                        <List dense>
                          {[
                            "Email gateway analysis for suspicious attachments",
                            "URL reputation and sandboxing",
                            "EDR monitoring for suspicious process creation",
                            "Network traffic analysis for C2 patterns",
                            "Authentication anomaly detection",
                            "Web application firewall (WAF) alerts",
                            "Vulnerability scanning and management",
                            "Third-party access auditing",
                          ].map((item, idx) => (
                            <ListItem key={idx} sx={{ py: 0.25 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <SearchIcon sx={{ fontSize: 16, color: theme.success }} />
                              </ListItemIcon>
                              <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1, height: "100%" }}>
                        <Typography variant="subtitle1" sx={{ color: theme.info, mb: 2 }}>
                          Prevention Controls
                        </Typography>
                        <List dense>
                          {[
                            "Multi-factor authentication (MFA) everywhere",
                            "Email authentication (DMARC, DKIM, SPF)",
                            "User security awareness training",
                            "Patch management and vulnerability remediation",
                            "Network segmentation and zero trust",
                            "Application allowlisting",
                            "USB device policies and controls",
                            "Vendor risk management programs",
                          ].map((item, idx) => (
                            <ListItem key={idx} sx={{ py: 0.25 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <CheckCircleIcon sx={{ fontSize: 16, color: theme.info }} />
                              </ListItemIcon>
                              <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    </Grid>
                  </Grid>

                  <Divider sx={{ my: 3, borderColor: theme.border }} />

                  <Typography variant="subtitle1" sx={{ color: theme.text, mb: 2 }}>
                    Key Detection Indicators
                  </Typography>
                  <TableContainer component={Paper} sx={{ bgcolor: theme.bgNested, mb: 3 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Technique</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Indicators</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          { tech: "Phishing", indicators: "Email headers, attachment analysis, URL inspection, sender reputation" },
                          { tech: "Drive-by", indicators: "Browser process anomalies, exploit kit signatures, unusual downloads" },
                          { tech: "Public App Exploit", indicators: "WAF alerts, error spikes, unusual requests, known CVE patterns" },
                          { tech: "External Services", indicators: "Failed auth spikes, unusual geolocations, off-hours access" },
                          { tech: "Supply Chain", indicators: "Unsigned updates, unexpected network connections, hash mismatches" },
                        ].map((row, idx) => (
                          <TableRow key={idx}>
                            <TableCell sx={{ color: theme.secondary, fontWeight: 500 }}>{row.tech}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{row.indicators}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  <Divider sx={{ my: 3, borderColor: theme.border }} />

                  {/* Windows Event IDs Section */}
                  <Typography variant="subtitle1" sx={{ color: theme.text, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <AssignmentIcon sx={{ color: theme.primary }} /> Windows Event IDs for Initial Access Detection
                  </Typography>
                  <TableContainer component={Paper} sx={{ bgcolor: theme.bgNested, mb: 3 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Event ID</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Source</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Description</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Initial Access Relevance</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          { id: "4624", source: "Security", desc: "Successful logon", relevance: "Type 10 (RDP), Type 3 (Network) from external IPs" },
                          { id: "4625", source: "Security", desc: "Failed logon", relevance: "Brute force, password spraying detection" },
                          { id: "4648", source: "Security", desc: "Explicit credentials", relevance: "Credential use from compromised accounts" },
                          { id: "4768", source: "Security", desc: "Kerberos TGT request", relevance: "Initial authentication attempts" },
                          { id: "4771", source: "Security", desc: "Kerberos pre-auth failed", relevance: "Password spraying against AD" },
                          { id: "1116", source: "Defender", desc: "Malware detected", relevance: "Phishing payload detection" },
                          { id: "1", source: "Sysmon", desc: "Process creation", relevance: "Suspicious child processes from Office/browsers" },
                          { id: "3", source: "Sysmon", desc: "Network connection", relevance: "C2 callbacks, unusual destinations" },
                          { id: "7", source: "Sysmon", desc: "Image loaded", relevance: "Malicious DLL loading" },
                          { id: "11", source: "Sysmon", desc: "File created", relevance: "Payload drops, webshell creation" },
                          { id: "22", source: "Sysmon", desc: "DNS query", relevance: "C2 domain lookups, DGA detection" },
                        ].map((row, idx) => (
                          <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha(theme.primary, 0.05) } }}>
                            <TableCell sx={{ color: theme.secondary, fontFamily: "monospace", fontWeight: 600 }}>{row.id}</TableCell>
                            <TableCell sx={{ color: theme.accent }}>{row.source}</TableCell>
                            <TableCell sx={{ color: theme.text }}>{row.desc}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{row.relevance}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  {/* Detection Queries */}
                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        <TerminalIcon sx={{ mr: 1, verticalAlign: "middle" }} />
                        Detection Queries & Hunting Tips
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>KQL - Failed Authentication Spike:</Typography>
                      <CodeBlock
                        code={`// Detect password spraying - multiple accounts, few passwords
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count(),
            DistinctAccounts = dcount(TargetUserName),
            Accounts = make_set(TargetUserName)
  by IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10 and DistinctAccounts > 5
| order by FailedAttempts desc`}
                      />
                      <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1, mt: 2 }}>KQL - Suspicious Office Child Process:</Typography>
                      <CodeBlock
                        code={`// Detect malicious macro execution
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc`}
                      />
                      <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1, mt: 2 }}>Sigma Rule - External RDP Access:</Typography>
                      <CodeBlock
                        code={`title: External RDP Connection
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    filter:
        IpAddress|startswith:
            - '10.'
            - '192.168.'
            - '172.16.'
    condition: selection and not filter
level: medium`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  {/* Email Security Headers */}
                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        <EmailIcon sx={{ mr: 1, verticalAlign: "middle" }} />
                        Email Header Analysis for Phishing Detection
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Key email headers to analyze when investigating potential phishing:
                      </Typography>
                      <TableContainer component={Paper} sx={{ bgcolor: theme.bgCode }}>
                        <Table size="small">
                          <TableBody>
                            {[
                              { header: "Authentication-Results", check: "SPF, DKIM, DMARC pass/fail status" },
                              { header: "Received", check: "Trace email path, identify spoofed hops" },
                              { header: "Return-Path", check: "Compare with From header for mismatches" },
                              { header: "X-Originating-IP", check: "Sender's actual IP address" },
                              { header: "Message-ID", check: "Domain should match sender domain" },
                              { header: "Reply-To", check: "Different from From = suspicious" },
                            ].map((row, idx) => (
                              <TableRow key={idx}>
                                <TableCell sx={{ color: theme.secondary, fontFamily: "monospace", fontWeight: 600, border: "none" }}>{row.header}</TableCell>
                                <TableCell sx={{ color: theme.textMuted, border: "none" }}>{row.check}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                      <CodeBlock
                        code={`# PowerShell - Extract email headers for analysis
$msg = Get-Content "suspicious_email.eml" -Raw
$headers = $msg -split "\r?\n\r?\n" | Select-Object -First 1
$headers -split "\r?\n" | Where-Object { $_ -match "^(From|To|Subject|Received|Authentication-Results|Return-Path|Reply-To):" }

# Check DMARC/SPF/DKIM using online tools or:
nslookup -type=txt _dmarc.domain.com
nslookup -type=txt domain.com  # SPF record`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Hands-On Labs Section */}
              <Box id="labs" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <ScienceIcon /> Hands-On Labs
                  </Typography>
                  <Alert severity="info" sx={{ mb: 3, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      <strong>Educational Purpose:</strong> These labs are designed for learning in controlled environments only.
                      Always obtain proper authorization and use dedicated lab infrastructure.
                    </Typography>
                  </Alert>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Beginner" size="small" sx={{ bgcolor: alpha(theme.success, 0.2), color: theme.success }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 1: Phishing Email Analysis
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>Objectives:</Typography>
                      <List dense>
                        {[
                          "Identify common phishing indicators in email headers",
                          "Analyze suspicious attachments safely",
                          "Document findings in a structured report",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon sx={{ fontSize: 16, color: theme.success }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.text } }} />
                          </ListItem>
                        ))}
                      </List>
                      <Box sx={{ bgcolor: theme.bgCode, p: 2, borderRadius: 1, my: 2 }}>
                        <Typography variant="subtitle2" sx={{ color: theme.secondary, mb: 1 }}>Exercise Steps:</Typography>
                        <CodeBlock
                          code={`# Step 1: Examine email headers
# Look for: Authentication-Results, Received headers, Return-Path mismatches

# Step 2: Check sender reputation
# Use tools: VirusTotal, AbuseIPDB, MXToolbox

# Step 3: Analyze URLs without clicking
# Extract and decode URLs, check against threat intel

# Step 4: Safe attachment analysis
# Use sandbox: any.run, hybrid-analysis.com, VirusTotal

# Step 5: Document indicators of compromise (IOCs)
# Record: sender, subject, URLs, file hashes, IPs`}
                        />
                      </Box>
                      <Alert severity="warning" sx={{ bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Safe Boundaries:</strong> Never open attachments on production systems. Use isolated VMs or online sandboxes.
                        </Typography>
                      </Alert>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Beginner" size="small" sx={{ bgcolor: alpha(theme.success, 0.2), color: theme.success }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 2: GoPhish Campaign Setup
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>Objectives:</Typography>
                      <List dense>
                        {[
                          "Set up GoPhish for security awareness testing",
                          "Create a phishing template and landing page",
                          "Understand campaign metrics and reporting",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon sx={{ fontSize: 16, color: theme.success }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.text } }} />
                          </ListItem>
                        ))}
                      </List>
                      <CodeBlock
                        code={`# Install GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish
./gophish

# Default credentials shown in console output
# Access admin panel: https://localhost:3333

# Key configuration steps:
# 1. Sending Profile - Configure SMTP server
# 2. Landing Page - Create credential capture page
# 3. Email Template - Design phishing email
# 4. Users & Groups - Import target list
# 5. Campaign - Launch and monitor

# IMPORTANT: Only target users who have consented to testing`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Intermediate" size="small" sx={{ bgcolor: alpha(theme.warning, 0.2), color: theme.warning }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 3: Public Application Reconnaissance
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>Objectives:</Typography>
                      <List dense>
                        {[
                          "Enumerate subdomains and web services",
                          "Identify potential vulnerabilities using passive scanning",
                          "Document attack surface findings",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon sx={{ fontSize: 16, color: theme.success }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.text } }} />
                          </ListItem>
                        ))}
                      </List>
                      <CodeBlock
                        code={`# Subdomain enumeration (passive)
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com -o amass.txt

# Technology fingerprinting
whatweb https://target.com
wappalyzer-cli https://target.com

# Directory enumeration
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ -mc 200,301,302,403

# Vulnerability scanning with Nuclei
nuclei -u https://target.com -t technologies/ -o tech_findings.txt
nuclei -u https://target.com -t cves/ -severity critical,high -o cve_findings.txt

# Check for exposed sensitive files
nuclei -u https://target.com -t exposures/ -o exposures.txt`}
                      />
                      <Alert severity="error" sx={{ mt: 2, bgcolor: alpha(theme.primary, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Authorization Required:</strong> Only perform these scans against systems you own or have written authorization to test.
                        </Typography>
                      </Alert>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Intermediate" size="small" sx={{ bgcolor: alpha(theme.warning, 0.2), color: theme.warning }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 4: Supply Chain Verification
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>Objectives:</Typography>
                      <List dense>
                        {[
                          "Verify digital signatures on downloaded software",
                          "Check file hashes against known-good values",
                          "Identify signs of tampering in software packages",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon sx={{ fontSize: 16, color: theme.success }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.text } }} />
                          </ListItem>
                        ))}
                      </List>
                      <CodeBlock
                        code={`# Windows - Verify digital signature
Get-AuthenticodeSignature -FilePath "C:\\path\\to\\file.exe"
sigcheck.exe -h -v "C:\\path\\to\\file.exe"

# Windows - Calculate file hash
Get-FileHash -Path "file.exe" -Algorithm SHA256

# Linux - Verify GPG signature
gpg --verify file.sig file.tar.gz
gpg --keyserver keyserver.ubuntu.com --recv-keys KEY_ID

# Linux - Calculate hash
sha256sum file.tar.gz

# Compare with vendor's published hash
# Check: Official website, GitHub releases, package manager

# npm - Check package integrity
npm audit
npm ls --all

# Python - Check package signatures
pip-audit
pip hash -v package_name`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Glossary Section */}
              <Box id="glossary" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <MenuBookIcon /> Glossary & Terminology
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.textMuted, mb: 3 }}>
                    Key terms and concepts related to initial access techniques.
                  </Typography>

                  <Grid container spacing={2}>
                    {[
                      { term: "Initial Access Broker (IAB)", def: "Threat actors who specialize in gaining initial access to networks and selling that access to other criminals, often ransomware operators.", related: "Ransomware, Dark Web Markets" },
                      { term: "Spearphishing", def: "Targeted phishing attacks directed at specific individuals or organizations, often using personalized content to increase success rates.", related: "Social Engineering, BEC" },
                      { term: "Watering Hole", def: "Attack strategy where adversaries compromise websites frequently visited by members of a target group, waiting for victims to browse and get infected.", related: "Drive-by Compromise, Exploit Kit" },
                      { term: "Zero-Day Exploit", def: "An exploit for a vulnerability that is unknown to the software vendor, meaning no patch exists at the time of exploitation.", related: "CVE, Vulnerability" },
                      { term: "Credential Stuffing", def: "Automated injection of breached username/password pairs to fraudulently gain access to user accounts.", related: "Password Spraying, Brute Force" },
                      { term: "Password Spraying", def: "Attempting a few commonly used passwords against many accounts, avoiding account lockouts while still testing credentials.", related: "Credential Stuffing, MFA" },
                      { term: "Exploit Kit", def: "Automated toolkit that probes browsers for vulnerabilities and delivers appropriate exploits and payloads based on detected weaknesses.", related: "Drive-by Compromise, Malvertising" },
                      { term: "HTML Smuggling", def: "Technique that uses HTML5 and JavaScript to construct malicious payloads on the client side, bypassing network security controls.", related: "Phishing, Payload Delivery" },
                      { term: "MFA Bypass", def: "Techniques to circumvent multi-factor authentication, including session hijacking, real-time phishing proxies, and MFA fatigue attacks.", related: "Evilginx, AiTM" },
                      { term: "AiTM (Adversary-in-the-Middle)", def: "Attack where adversary positions between user and legitimate service, capturing credentials and session tokens in real-time.", related: "Evilginx, Modlishka" },
                      { term: "Pretexting", def: "Social engineering technique involving creating a fabricated scenario (pretext) to engage a victim and gain their trust.", related: "Vishing, Social Engineering" },
                      { term: "Vishing", def: "Voice phishing - using phone calls to manipulate targets into revealing sensitive information or performing actions.", related: "Phishing, Social Engineering" },
                    ].map((item, idx) => (
                      <Grid item xs={12} md={6} key={idx}>
                        <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%", border: `1px solid ${theme.border}` }}>
                          <Typography variant="subtitle2" sx={{ color: theme.primary, fontWeight: 600 }}>{item.term}</Typography>
                          <Typography variant="body2" sx={{ color: theme.text, my: 1 }}>{item.def}</Typography>
                          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                            {item.related.split(", ").map((tag, tidx) => (
                              <Chip key={tidx} label={tag} size="small" sx={{ bgcolor: alpha(theme.accent, 0.1), color: theme.accent, fontSize: "0.7rem" }} />
                            ))}
                          </Box>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>
              </Box>

              {/* Quiz Section */}
              <Box id="quiz-section" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <QuizIcon /> Knowledge Check
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.textMuted, mb: 3 }}>
                    Test your understanding of initial access techniques with {QUIZ_QUESTION_COUNT} randomly selected questions.
                  </Typography>
                  <QuizSection questions={quizQuestions} accentColor={QUIZ_ACCENT_COLOR} questionsPerQuiz={QUIZ_QUESTION_COUNT} />
                </Paper>
              </Box>

              {/* Back Button */}
              <Box sx={{ textAlign: "center", mt: 4 }}>
                <Button
                  variant="outlined"
                  startIcon={<ArrowBackIcon />}
                  onClick={() => navigate("/learn")}
                  sx={{
                    borderColor: theme.primary,
                    color: theme.primary,
                    "&:hover": {
                      borderColor: theme.primaryLight,
                      bgcolor: alpha(theme.primary, 0.1),
                    },
                  }}
                >
                  Back to Learning Hub
                </Button>
              </Box>
            </Grid>
          </Grid>
        </Container>

        {/* Mobile Navigation Drawer */}
        <Drawer
          anchor="left"
          open={navDrawerOpen}
          onClose={() => setNavDrawerOpen(false)}
          PaperProps={{
            sx: { bgcolor: theme.bgCard, width: 280 },
          }}
        >
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
              <Typography variant="subtitle1" sx={{ color: theme.primary, fontWeight: 600 }}>
                Navigation
              </Typography>
              <IconButton onClick={() => setNavDrawerOpen(false)} sx={{ color: theme.text }}>
                <CloseIcon />
              </IconButton>
            </Box>
            <List>
              {sectionNavItems.map((item) => (
                <ListItem
                  key={item.id}
                  component="button"
                  onClick={() => scrollToSection(item.id)}
                  sx={{
                    borderRadius: 1,
                    mb: 0.5,
                    cursor: "pointer",
                    border: "none",
                    bgcolor: "transparent",
                    width: "100%",
                    textAlign: "left",
                    "&:hover": {
                      bgcolor: alpha(theme.primary, 0.1),
                    },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 32, color: theme.primary }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.label}
                    primaryTypographyProps={{
                      variant: "body2",
                      sx: { color: theme.text },
                    }}
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        </Drawer>

        {/* Mobile FABs */}
        <Box
          sx={{
            display: { xs: "flex", md: "none" },
            position: "fixed",
            bottom: 16,
            right: 16,
            flexDirection: "column",
            gap: 1,
          }}
        >
          <Fab
            size="small"
            onClick={scrollToTop}
            sx={{ bgcolor: theme.bgCard, color: theme.text, "&:hover": { bgcolor: theme.bgNested } }}
          >
            <KeyboardArrowUpIcon />
          </Fab>
          <Fab
            size="small"
            onClick={() => setNavDrawerOpen(true)}
            sx={{ bgcolor: theme.primary, color: "white", "&:hover": { bgcolor: theme.primaryLight } }}
          >
            <SecurityIcon />
          </Fab>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default InitialAccessPage;
