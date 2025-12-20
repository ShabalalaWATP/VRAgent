import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
  Chip,
  Button,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import SecurityIcon from "@mui/icons-material/Security";
import SearchIcon from "@mui/icons-material/Search";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ShieldIcon from "@mui/icons-material/Shield";
import BuildIcon from "@mui/icons-material/Build";
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

const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "powershell",
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
        bgcolor: "#121424",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(168, 85, 247, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#a855f7", color: "#0b1020" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#e2e8f0" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          overflow: "auto",
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          pt: 2,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const CredentialHarvestingPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `This page covers credential harvesting concepts and defense strategies. Topics include harvesting methods (phishing, browser/password manager abuse, credential dumping, keylogging, token/ticket theft, secrets in files, legacy protocol abuse, password spraying), credential storage locations (Windows Credential Manager, LSASS memory, browser profiles, local files, SSH keys, CI/CD secrets, cloud access keys), detection signals and behavior indicators, telemetry sources, prevention strategies, and response actions. The page focuses on defensive awareness with safe, read-only checks and beginner-friendly lab exercises.`;

  const objectives = [
    "Explain credential harvesting in simple terms.",
    "Recognize common harvesting techniques at a high level.",
    "Identify sensitive storage locations and risks.",
    "Review basic detection signals and logging sources.",
    "Practice safe, read-only checks in a lab.",
  ];
  const beginnerPath = [
    "1) Read the glossary so the terms make sense.",
    "2) Learn where credentials usually live (browsers, vaults, files).",
    "3) Review the high-level methods without touching real data.",
    "4) Run safe checks and note what logs are available.",
    "5) Write a short report with risks and prevention ideas.",
  ];
  const whyHard = [
    "Credentials are used everywhere, so normal activity looks similar to attacks.",
    "Many systems store credentials for convenience, creating more exposure.",
    "Attackers may use cloud logins with no malware on the device.",
  ];
  const misconceptions = [
    {
      myth: "Credential harvesting always means someone installed malware.",
      reality: "It can be as simple as a fake login page or a reused password.",
    },
    {
      myth: "MFA stops all credential attacks.",
      reality: "MFA helps a lot, but attackers may still steal tokens or approve prompts.",
    },
    {
      myth: "Only admins are targeted.",
      reality: "Any account can be a stepping stone to higher access.",
    },
  ];
  const roles = [
    { role: "SOC analyst", focus: "Triage alerts and correlate login events." },
    { role: "Blue team", focus: "Harden systems and reduce credential exposure." },
    { role: "IT admin", focus: "Enforce MFA and manage password policies." },
    { role: "DevOps", focus: "Remove secrets from repos and pipelines." },
  ];
  const whatItIsNot = [
    "It is not penetration testing; this page avoids offensive instructions.",
    "It is not collecting real passwords in training environments.",
    "It is not a single tool or product; it is a set of risks and behaviors.",
  ];

  const glossary = [
    { term: "Credential", desc: "A username, password, token, or key used to authenticate." },
    { term: "Harvesting", desc: "Collecting credentials from systems or users." },
    { term: "Phishing", desc: "Tricking users into entering credentials on fake pages." },
    { term: "Memory scraping", desc: "Attempting to read credentials from running processes." },
    { term: "Credential vault", desc: "Secure storage for passwords and tokens." },
    { term: "MFA", desc: "Multi-factor authentication, a second verification step." },
  ];
  const credentialSources = [
    { source: "User input", desc: "Typing into login forms, terminals, or prompts." },
    { source: "Saved storage", desc: "Browsers, vaults, or cached credentials." },
    { source: "Memory", desc: "Credentials temporarily present while apps run." },
    { source: "Files", desc: "Configs, scripts, or notes with secrets." },
    { source: "Network", desc: "Captured tokens or insecure transfers." },
  ];
  const credentialTypes = [
    { type: "Passwords", desc: "Shared secrets used to authenticate." },
    { type: "Tokens", desc: "Session or API tokens used in place of passwords." },
    { type: "Keys", desc: "SSH or private keys for secure access." },
    { type: "Cookies", desc: "Browser sessions that can grant access." },
    { type: "Hashes", desc: "Hashed passwords that can sometimes be abused." },
  ];
  const accountTypes = [
    { type: "Local user", impact: "Limited to one device unless reused elsewhere." },
    { type: "Domain user", impact: "Can access multiple systems and services." },
    { type: "Service account", impact: "Often has broad, persistent access." },
    { type: "Admin account", impact: "High impact; can change systems or policies." },
    { type: "Cloud account", impact: "May access SaaS, mailboxes, or cloud resources." },
  ];
  const exampleFlow = [
    "User receives a fake login email and enters credentials.",
    "Attacker logs in from a new location using the stolen password.",
    "MFA blocks the login or the attacker tries another account.",
    "Security team sees unusual login alerts and investigates.",
    "Password reset and MFA enforcement stop further access.",
  ];

  const methods = [
    {
      title: "Phishing and Social Engineering",
      desc: "Attackers trick users into typing credentials into fake pages or prompts.",
      signals: "Unusual login locations, multiple failed attempts, new device logins.",
      prevention: "MFA, phishing training, and domain protections.",
    },
    {
      title: "Browser and Password Manager Abuse",
      desc: "Attackers attempt to access saved passwords or cookies.",
      signals: "Unexpected browser data access or profile copying.",
      prevention: "Restrict profile access, use OS account separation, MFA.",
    },
    {
      title: "Credential Dumping (High Level)",
      desc: "Attackers try to access credentials stored in memory or system stores.",
      signals: "Suspicious process access to LSASS or vault components.",
      prevention: "Credential Guard, LSASS protection, least privilege.",
    },
    {
      title: "Keylogging and Input Capture",
      desc: "Attempts to capture what a user types at the keyboard.",
      signals: "Unexpected keyboard hooks or unknown monitoring software.",
      prevention: "Endpoint protection, allowlisting, and user awareness.",
    },
    {
      title: "Token and Ticket Theft",
      desc: "Stealing session tokens or Kerberos tickets for reuse.",
      signals: "Unusual ticket usage or logons without interactive sessions.",
      prevention: "Short session lifetimes, monitoring, and segmentation.",
    },
    {
      title: "Secrets in Files",
      desc: "Credentials stored in config files, scripts, or notes.",
      signals: "Sensitive strings in repositories or user directories.",
      prevention: "Secret scanning, vaulting, and rotation.",
    },
    {
      title: "Legacy Protocol Abuse",
      desc: "Older protocols that do not enforce MFA or modern protections.",
      signals: "Logins from legacy auth or basic auth endpoints.",
      prevention: "Disable legacy protocols and enforce modern auth.",
    },
    {
      title: "Password Spraying (High Level)",
      desc: "Trying a few common passwords across many accounts.",
      signals: "Many accounts with a few failed attempts each.",
      prevention: "MFA, lockout policies, and monitoring.",
    },
  ];

  const storageTable = [
    {
      location: "Windows Credential Manager",
      risk: "Saved passwords can be abused if access controls are weak.",
      safeCheck: "cmdkey /list (read-only list of stored entries).",
    },
    {
      location: "LSASS memory",
      risk: "Credentials may be present in memory on some systems.",
      safeCheck: "Verify Credential Guard and LSA protection settings.",
    },
    {
      location: "Browser profiles",
      risk: "Saved passwords or session cookies stored in user profiles.",
      safeCheck: "Review profile permissions and access controls.",
    },
    {
      location: "Local files (.env, configs)",
      risk: "Secrets stored in plaintext configuration files.",
      safeCheck: "Use secret scanning in repos and user folders.",
    },
    {
      location: "SSH keys",
      risk: "Private keys stored without strong passphrases.",
      safeCheck: "Check key permissions and passphrase usage.",
    },
    {
      location: "CI/CD secrets",
      risk: "Build pipelines storing tokens with broad access.",
      safeCheck: "Review secret scopes and rotation schedules.",
    },
    {
      location: "Cloud access keys",
      risk: "Keys stored in local files or terminals.",
      safeCheck: "Check key age and least privilege policy.",
    },
  ];

  const signals = [
    "Many failed logins followed by a successful login.",
    "Credential access tools launched from unusual paths.",
    "Office or browser spawning command shells.",
    "Access to sensitive system processes by non-admin users.",
    "New logins from previously unseen devices or locations.",
  ];
  const behaviorIndicators = [
    "Multiple authentication attempts across many accounts.",
    "Unusual access to browser or vault data by non-browser processes.",
    "Repeated access to sensitive files by scripts or automation.",
    "High-volume access to credential stores in a short time window.",
  ];
  const redFlags = [
    "Password resets requested outside normal helpdesk flow.",
    "Multiple accounts locked out from a single IP.",
    "Tokens used after user sign-out or device wipe.",
    "Unusual authentication from legacy protocols.",
    "Credential access attempts on service accounts.",
  ];

  const telemetrySources = [
    "Process creation logs (with command-line arguments).",
    "Authentication logs and failed login records.",
    "Browser or application access logs.",
    "EDR alerts for credential access or dumping behavior.",
    "Secret scanning results and repository audit logs.",
  ];
  const detectionMatrix = [
    {
      stage: "Initial lure",
      signal: "User clicks a link from an unusual sender.",
      evidence: "Email logs and URL reputation.",
    },
    {
      stage: "Login attempt",
      signal: "New device or location sign-in.",
      evidence: "IdP sign-in logs and MFA prompts.",
    },
    {
      stage: "Credential access",
      signal: "Access to browser profiles or vault APIs.",
      evidence: "Process logs and EDR alerts.",
    },
    {
      stage: "Reuse",
      signal: "Same credentials used across services.",
      evidence: "Auth logs from multiple systems.",
    },
  ];
  const platformLogs = [
    { platform: "Windows", logs: "Security log, Defender/EDR, Sysmon if enabled." },
    { platform: "Linux", logs: "Auth logs, sudo logs, auditd if enabled." },
    { platform: "macOS", logs: "Unified logs, loginwindow, EDR logs." },
    { platform: "Cloud/SaaS", logs: "IdP logs, sign-in logs, audit logs." },
  ];
  const evidenceChecklist = [
    "User account and source IP",
    "Timestamp and device name",
    "Authentication method (password, MFA, token)",
    "Process tree for any local alerts",
    "Related alert IDs or EDR case links",
  ];

  const safeChecks = `# Windows: list stored credentials (read-only)
cmdkey /list

# Windows: check Credential Guard and LSA protections (read-only)
Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" | Select-Object RunAsPPL, LsaCfgFlags

# Windows: list local users (read-only)
Get-LocalUser | Select-Object Name, Enabled

# Linux: check permissions on /etc/shadow (read-only)
ls -l /etc/shadow

# macOS: list available keychains (read-only)
security list-keychains`;

  const beginnerLabSteps = [
    "Use a lab VM or test system you own.",
    "Create a fake secrets file in a lab folder (not real credentials).",
    "Run a simple search to find the fake secret.",
    "Document where it was found and how you would fix it.",
    "Enable MFA on a test account and note the difference in login flow.",
  ];
  const responseSteps = [
    "Reset impacted credentials and revoke active sessions.",
    "Check for lateral movement or reused passwords.",
    "Review MFA settings and enforce where missing.",
    "Communicate to affected users with clear guidance.",
    "Document the incident and update training material.",
  ];
  const preventionChecklist = [
    "Enable MFA everywhere possible.",
    "Use password managers and strong unique passwords.",
    "Harden browser profiles and protect stored credentials.",
    "Scan repos and endpoints for secrets regularly.",
    "Monitor for new devices and impossible travel logins.",
  ];
  const policyIdeas = [
    "Disable legacy authentication where possible.",
    "Require phishing-resistant MFA for admins.",
    "Rotate service account secrets on a schedule.",
    "Block password reuse with policy enforcement.",
    "Require approvals for new OAuth applications.",
  ];
  const safeBoundaries = [
    "Never handle real passwords in a lab exercise.",
    "Use fake secrets and disposable test accounts only.",
    "Avoid collecting sensitive user data during training.",
    "Get written approval before any testing outside a lab.",
  ];

  return (
    <LearnPageLayout pageTitle="Credential Harvesting" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <VpnKeyIcon sx={{ fontSize: 42, color: "#a855f7" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #a855f7 0%, #ec4899 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Credential Harvesting
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Credential harvesting is the process of collecting usernames, passwords, or tokens so an attacker can log in.
        </Typography>
        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            In simple terms, attackers want the same things you use to log in. They might trick people with fake
            login pages, look for passwords saved in files, or abuse tools that access stored credentials. This page
            focuses on the basics, the most common risks, and safe checks you can run in a lab.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
            Think of credentials like keys. If someone copies the key, they can open the door without breaking it.
            Learning where those keys are stored and how they are abused helps you protect accounts early.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            Everything here is designed for beginners and uses read-only commands. The goal is to understand where
            credentials live, how they are abused, and how to detect and prevent it.
          </Typography>
        </Paper>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<SecurityIcon />} label="Credentials" size="small" />
          <Chip icon={<SearchIcon />} label="Detection" size="small" />
          <Chip icon={<ShieldIcon />} label="Prevention" size="small" />
          <Chip icon={<WarningIcon />} label="Risk Areas" size="small" />
        </Box>

        <Paper sx={{ bgcolor: "#111424", borderRadius: 2 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              "& .MuiTab-root": { color: "grey.400" },
              "& .Mui-selected": { color: "#a855f7" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<WarningIcon />} label="Methods (High Level)" />
            <Tab icon={<SearchIcon />} label="Storage and Risks" />
            <Tab icon={<ShieldIcon />} label="Detection" />
            <Tab icon={<BuildIcon />} label="Prevention and Response" />
            <Tab icon={<VpnKeyIcon />} label="Beginner Lab" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Learning Objectives
                </Typography>
                <List dense>
                  {objectives.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Beginner Path
                </Typography>
                <List dense>
                  {beginnerPath.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Why This Is Hard
                </Typography>
                <List dense>
                  {whyHard.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  What This Is Not
                </Typography>
                <List dense>
                  {whatItIsNot.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Term</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Meaning</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {glossary.map((item) => (
                        <TableRow key={item.term}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.term}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Who Uses This Knowledge
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Role</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Focus</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {roles.map((item) => (
                        <TableRow key={item.role}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.role}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.focus}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Credential Types
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Type</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {credentialTypes.map((item) => (
                        <TableRow key={item.type}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Where Credentials Come From
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Source</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {credentialSources.map((item) => (
                        <TableRow key={item.source}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.source}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Account Types and Impact
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Account Type</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Why it matters</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {accountTypes.map((item) => (
                        <TableRow key={item.type}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.impact}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Common Misconceptions
                </Typography>
                <Grid container spacing={2}>
                  {misconceptions.map((item) => (
                    <Grid item xs={12} md={4} key={item.myth}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(168,85,247,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#a855f7", mb: 1 }}>
                          Myth
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                          {item.myth}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ color: "#a5b4fc", mb: 0.5 }}>
                          Reality
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>
                          {item.reality}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Example Flow (Simple)
                </Typography>
                <List dense>
                  {exampleFlow.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Grid container spacing={2}>
                {methods.map((item) => (
                  <Grid item xs={12} md={6} key={item.title}>
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: "#0c0f1c",
                        borderRadius: 2,
                        border: "1px solid rgba(168,85,247,0.2)",
                        height: "100%",
                      }}
                    >
                      <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 600 }}>
                        {item.title}
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        {item.desc}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "#a5b4fc", display: "block" }}>
                        Signals: {item.signals}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "#94a3b8", display: "block" }}>
                        Prevention: {item.prevention}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <TableContainer sx={{ mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#a855f7" }}>Location</TableCell>
                      <TableCell sx={{ color: "#a855f7" }}>Risk</TableCell>
                      <TableCell sx={{ color: "#a855f7" }}>Safe Check</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {storageTable.map((item) => (
                      <TableRow key={item.location}>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.location}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.safeCheck}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Read-only Checks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={safeChecks} language="powershell" />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Detection Signals
                </Typography>
                <List dense>
                  {signals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Red Flags for Investigations
                </Typography>
                <List dense>
                  {redFlags.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Behavior Indicators
                </Typography>
                <List dense>
                  {behaviorIndicators.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Telemetry Sources to Check
                </Typography>
                <List dense>
                  {telemetrySources.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Detection Matrix (Simple)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Stage</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Signal</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Evidence</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {detectionMatrix.map((item) => (
                        <TableRow key={item.stage}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.stage}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.signal}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.evidence}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Platform Log Pointers
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Platform</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Logs to review</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {platformLogs.map((item) => (
                        <TableRow key={item.platform}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.platform}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.logs}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Evidence Checklist
                </Typography>
                <List dense>
                  {evidenceChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Prevention Basics
                </Typography>
                <List dense>
                  {[
                    "Enable MFA for all critical systems.",
                    "Limit local admin privileges and rotate passwords.",
                    "Use password managers instead of browser auto-fill where possible.",
                    "Scan repositories and endpoints for secrets.",
                    "Harden LSASS with Credential Guard and RunAsPPL.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Prevention Checklist
                </Typography>
                <List dense>
                  {preventionChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Policy and Control Ideas
                </Typography>
                <List dense>
                  {policyIdeas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Beginner Triage Steps
                </Typography>
                <List dense>
                  {[
                    "Verify the alert details (user, host, and process).",
                    "Check if MFA was bypassed or not enabled.",
                    "Search for other hosts with the same indicator.",
                    "Reset impacted credentials and rotate tokens.",
                    "Escalate to incident response if multiple systems are affected.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Response Actions (Safe)
                </Typography>
                <List dense>
                  {responseSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Beginner Lab Walkthrough (Safe)
                </Typography>
                <List dense>
                  {beginnerLabSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Safe Boundaries
                </Typography>
                <List dense>
                  {safeBoundaries.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Fake Secret Search Example</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="powershell"
                    code={`# Create a safe lab file with a fake secret
New-Item -ItemType Directory -Force -Path C:\\LabSecrets
"API_KEY=FAKE-12345" | Out-File C:\\LabSecrets\\sample.env

# Search for the fake secret (read-only)
Select-String -Path C:\\LabSecrets\\* -Pattern "API_KEY"

# Clean up
Remove-Item -Recurse -Force C:\\LabSecrets`}
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#a855f7", color: "#a855f7" }}
          >
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default CredentialHarvestingPage;
