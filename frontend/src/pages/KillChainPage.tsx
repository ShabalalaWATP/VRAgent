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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert,
} from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import BuildIcon from "@mui/icons-material/Build";
import LocalShippingIcon from "@mui/icons-material/LocalShipping";
import BugReportIcon from "@mui/icons-material/BugReport";
import InstallDesktopIcon from "@mui/icons-material/InstallDesktop";
import SettingsRemoteIcon from "@mui/icons-material/SettingsRemote";
import FlagIcon from "@mui/icons-material/Flag";
import ShieldIcon from "@mui/icons-material/Shield";
import WarningIcon from "@mui/icons-material/Warning";

interface KillChainPhase {
  id: number;
  name: string;
  subtitle: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  attackerActions: string[];
  defenderActions: string[];
  tools: string[];
  indicators: string[];
  realWorldExample: string;
}

const killChainPhases: KillChainPhase[] = [
  {
    id: 1,
    name: "Reconnaissance",
    subtitle: "Target Research & Information Gathering",
    icon: <GpsFixedIcon />,
    color: "#6366f1",
    description:
      "The attacker identifies and researches targets. They gather information about the organization, employees, technology stack, and potential vulnerabilities without directly interacting with target systems.",
    attackerActions: [
      "Harvest email addresses from websites, social media, job postings",
      "Identify employees on LinkedIn, their roles and technologies used",
      "Enumerate subdomains, IP ranges, and exposed services",
      "Research technology stack via job postings, Wappalyzer, BuiltWith",
      "Gather leaked credentials from breach databases",
      "Map organizational structure and identify high-value targets",
    ],
    defenderActions: [
      "Monitor for domain enumeration in DNS logs",
      "Limit public exposure of employee information",
      "Review and sanitize job postings for technical details",
      "Implement brand monitoring for credential leaks",
      "Use honeypots to detect reconnaissance activity",
      "Conduct red team exercises to identify exposed data",
    ],
    tools: ["Maltego", "Shodan", "theHarvester", "Recon-ng", "SpiderFoot", "OSINT Framework", "hunter.io"],
    indicators: ["Unusual DNS queries", "Port scanning from single source", "Social engineering attempts", "Job posting scraping"],
    realWorldExample: "In the 2020 SolarWinds attack, threat actors spent months researching targets and understanding the supply chain before proceeding.",
  },
  {
    id: 2,
    name: "Weaponization",
    subtitle: "Malware Development & Payload Creation",
    icon: <BuildIcon />,
    color: "#8b5cf6",
    description:
      "The attacker creates or acquires tools to exploit identified vulnerabilities. This includes developing malware, creating exploit payloads, and setting up attack infrastructure.",
    attackerActions: [
      "Develop custom malware tailored to target environment",
      "Modify existing exploits to bypass specific defenses",
      "Create weaponized documents (macro-enabled Office files)",
      "Set up command and control (C2) infrastructure",
      "Acquire or develop zero-day exploits",
      "Create phishing pages mimicking legitimate services",
      "Generate obfuscated payloads to evade detection",
    ],
    defenderActions: [
      "Share threat intelligence with industry peers (ISACs)",
      "Implement application allowlisting",
      "Use sandboxing for unknown executables",
      "Block macro execution in Office documents",
      "Monitor dark web for threats targeting your org",
      "Patch vulnerabilities before exploits are developed",
    ],
    tools: ["Metasploit", "Cobalt Strike", "Veil", "msfvenom", "Empire", "Custom malware frameworks"],
    indicators: ["This phase occurs outside your network - limited visibility"],
    realWorldExample: "APT groups often spend months developing custom implants. Lazarus Group developed ELECTRICFISH tunneling tool specifically for financial institutions.",
  },
  {
    id: 3,
    name: "Delivery",
    subtitle: "Transmission of Malicious Payload",
    icon: <LocalShippingIcon />,
    color: "#a855f7",
    description:
      "The attacker transmits the weaponized payload to the target. Common vectors include phishing emails, compromised websites, USB drops, and supply chain compromises.",
    attackerActions: [
      "Send spear-phishing emails with malicious attachments",
      "Compromise legitimate websites to host exploit kits",
      "Deploy watering hole attacks on sites victims visit",
      "Distribute infected USB drives near target facilities",
      "Exploit public-facing applications directly",
      "Compromise third-party vendors in supply chain",
      "Use social engineering via phone or in-person",
    ],
    defenderActions: [
      "Deploy email security with attachment sandboxing",
      "Implement web filtering and secure web gateways",
      "Train employees on phishing identification",
      "Disable USB ports or implement device control",
      "Patch public-facing applications immediately",
      "Implement vendor security assessments",
      "Use DMARC, DKIM, SPF for email authentication",
    ],
    tools: ["GoPhish", "King Phisher", "SET (Social Engineering Toolkit)", "Evilginx2", "BeEF"],
    indicators: ["Phishing emails detected", "Malicious attachments blocked", "Suspicious downloads", "Drive-by compromise attempts"],
    realWorldExample: "The 2017 NotPetya attack used a compromised Ukrainian accounting software update as the delivery mechanism, affecting companies globally.",
  },
  {
    id: 4,
    name: "Exploitation",
    subtitle: "Vulnerability Exploitation & Code Execution",
    icon: <BugReportIcon />,
    color: "#ec4899",
    description:
      "The attacker exploits a vulnerability to execute malicious code on the target system. This could be a software vulnerability, misconfiguration, or user action (clicking a link, enabling macros).",
    attackerActions: [
      "Execute exploit code against vulnerable software",
      "Leverage user interaction (clicking links, enabling macros)",
      "Exploit browser vulnerabilities for drive-by downloads",
      "Use credential stuffing or password spraying",
      "Bypass authentication mechanisms",
      "Exploit misconfigurations in cloud services",
      "Chain multiple vulnerabilities for greater impact",
    ],
    defenderActions: [
      "Maintain aggressive patch management program",
      "Implement exploit prevention (DEP, ASLR, CFG)",
      "Use endpoint detection and response (EDR)",
      "Deploy application-level firewalls (WAF)",
      "Enforce MFA on all accounts",
      "Regular vulnerability scanning and remediation",
      "Implement least privilege access controls",
    ],
    tools: ["Metasploit", "Burp Suite", "sqlmap", "CrackMapExec", "Impacket", "BloodHound"],
    indicators: ["Exploit attempts in logs", "Unexpected process execution", "Failed authentication spikes", "Vulnerability scanner activity"],
    realWorldExample: "The Equifax breach (2017) exploited CVE-2017-5638, an Apache Struts vulnerability that was 2 months old with a patch available.",
  },
  {
    id: 5,
    name: "Installation",
    subtitle: "Persistence Establishment & Backdoor Deployment",
    icon: <InstallDesktopIcon />,
    color: "#f43f5e",
    description:
      "The attacker installs persistent access mechanisms to maintain access even after reboots or password changes. This includes backdoors, RATs, and privilege escalation.",
    attackerActions: [
      "Install remote access trojans (RATs)",
      "Create scheduled tasks for persistence",
      "Modify registry run keys",
      "Deploy web shells on compromised servers",
      "Create rogue admin accounts",
      "Install rootkits to hide presence",
      "Establish multiple persistence mechanisms",
      "Escalate privileges to SYSTEM/root",
    ],
    defenderActions: [
      "Monitor for unauthorized software installation",
      "Audit scheduled tasks and startup items",
      "Implement application allowlisting",
      "Monitor registry modifications",
      "Audit user account creation",
      "Use file integrity monitoring",
      "Implement privileged access management",
      "Regular system baselining and comparison",
    ],
    tools: ["Mimikatz", "PowerSploit", "SharPersist", "PoshC2", "DVTA", "Web shells (China Chopper, WSO)"],
    indicators: ["New admin accounts", "Unexpected scheduled tasks", "Modified registry keys", "New services installed", "Web shells detected"],
    realWorldExample: "APT29 (Cozy Bear) uses multiple persistence mechanisms including scheduled tasks, WMI subscriptions, and startup folder shortcuts.",
  },
  {
    id: 6,
    name: "Command & Control",
    subtitle: "Remote Control & Communication Channel",
    icon: <SettingsRemoteIcon />,
    color: "#ef4444",
    description:
      "The attacker establishes a communication channel to remotely control compromised systems. C2 channels are often encrypted and designed to blend with normal traffic.",
    attackerActions: [
      "Establish encrypted C2 channel over HTTPS",
      "Use DNS tunneling for covert communication",
      "Leverage legitimate services (Slack, Teams, GitHub)",
      "Implement domain fronting to hide C2 traffic",
      "Use fast-flux DNS to evade blocking",
      "Deploy peer-to-peer C2 networks",
      "Schedule check-ins during business hours to blend in",
    ],
    defenderActions: [
      "Monitor outbound traffic patterns and anomalies",
      "Implement DNS monitoring and filtering",
      "Use SSL/TLS inspection for encrypted traffic",
      "Block known C2 infrastructure (threat intel feeds)",
      "Deploy network detection and response (NDR)",
      "Implement egress filtering",
      "Monitor for beaconing behavior patterns",
    ],
    tools: ["Cobalt Strike", "Covenant", "PoshC2", "Mythic", "Sliver", "DNS over HTTPS tunneling"],
    indicators: ["Beaconing traffic patterns", "Unusual DNS queries", "Traffic to newly registered domains", "Long-duration connections", "Encrypted traffic to unusual destinations"],
    realWorldExample: "Sunburst malware used multiple legitimate domains and cloud services for C2, making detection extremely difficult.",
  },
  {
    id: 7,
    name: "Actions on Objectives",
    subtitle: "Mission Execution & Goal Achievement",
    icon: <FlagIcon />,
    color: "#dc2626",
    description:
      "The attacker achieves their ultimate goal, whether it's data exfiltration, destruction, ransom, or espionage. This is the final stage where damage occurs.",
    attackerActions: [
      "Exfiltrate sensitive data (IP, PII, credentials)",
      "Deploy ransomware for extortion",
      "Manipulate or destroy data",
      "Move laterally to additional systems",
      "Establish long-term persistent access",
      "Use access for cryptocurrency mining",
      "Sell access to other threat actors",
      "Conduct espionage or surveillance",
    ],
    defenderActions: [
      "Implement data loss prevention (DLP)",
      "Monitor for large data transfers",
      "Segment networks to limit lateral movement",
      "Maintain offline backups for ransomware recovery",
      "Implement zero trust architecture",
      "Monitor database queries for anomalies",
      "Deploy deception technologies (honeypots)",
      "Have incident response plan ready",
    ],
    tools: ["Rclone", "MEGAsync", "7-Zip for compression", "Custom exfil tools", "Ransomware variants (LockBit, BlackCat)"],
    indicators: ["Large data transfers", "Unusual database queries", "Access to sensitive file shares", "Encryption activity", "Ransom notes"],
    realWorldExample: "Colonial Pipeline (2021) - DarkSide ransomware encrypted systems after exfiltrating 100GB of data, leading to fuel shortages.",
  },
];

export default function KillChainPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [expandedPhase, setExpandedPhase] = useState<number | false>(false);

  const pageContext = `Cyber Kill Chain educational page. This page teaches the Lockheed Martin Cyber Kill Chain framework including all 7 phases: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, and Actions on Objectives. It covers attack techniques and defensive measures for each phase.`;

  return (
    <LearnPageLayout pageTitle="Cyber Kill Chain" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <IconButton onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
        <ArrowBackIcon />
      </IconButton>

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, #ef4444, #a855f7)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          ⚔️ Cyber Kill Chain
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          The Lockheed Martin Cyber Kill Chain® is a framework describing the stages of a targeted cyberattack. Understanding each phase helps defenders identify and stop attacks before damage occurs.
        </Typography>
      </Box>

      {/* Overview Section */}
      <Paper
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#6366f1", 0.05)}, ${alpha("#dc2626", 0.05)})`,
        }}
      >
        <Grid container spacing={4}>
          <Grid item xs={12} md={7}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
              Why the Kill Chain Matters
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              Developed by Lockheed Martin in 2011, the Cyber Kill Chain breaks down cyberattacks into 7 sequential phases. This model helps security teams understand attacker methodology, identify where attacks can be detected and stopped, and measure defensive capabilities at each stage.
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              <strong>Key Insight:</strong> Breaking ANY single link in the chain stops the attack. Early detection (phases 1-3) is ideal, but defenses should exist at every phase for defense in depth.
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="7 Phases" sx={{ bgcolor: alpha("#6366f1", 0.1), color: "#6366f1", fontWeight: 600 }} />
              <Chip label="Defense in Depth" variant="outlined" />
              <Chip label="Lockheed Martin" variant="outlined" />
              <Chip label="Threat Intelligence" variant="outlined" />
            </Box>
          </Grid>
          <Grid item xs={12} md={5}>
            <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>Remember:</strong> Attackers only need to succeed once. Defenders must succeed at every phase.
              </Typography>
            </Alert>
            <Box sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5), p: 3, borderRadius: 2, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>Quick Reference</Typography>
              {killChainPhases.map((phase) => (
                <Box
                  key={phase.id}
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    gap: 1.5,
                    mb: 1,
                    cursor: "pointer",
                    p: 0.5,
                    borderRadius: 1,
                    "&:hover": { bgcolor: alpha(phase.color, 0.1) },
                  }}
                  onClick={() => setExpandedPhase(phase.id)}
                >
                  <Box sx={{ color: phase.color, display: "flex" }}>{phase.icon}</Box>
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>
                    {phase.id}. {phase.name}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Visual Chain */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        🔗 The 7 Phases
      </Typography>
      <Box
        sx={{
          display: "flex",
          overflowX: "auto",
          gap: 1,
          mb: 5,
          pb: 2,
          "&::-webkit-scrollbar": { height: 6 },
          "&::-webkit-scrollbar-thumb": { bgcolor: alpha(theme.palette.primary.main, 0.3), borderRadius: 3 },
        }}
      >
        {killChainPhases.map((phase, index) => (
          <Box
            key={phase.id}
            onClick={() => setExpandedPhase(phase.id)}
            sx={{
              display: "flex",
              alignItems: "center",
              flexShrink: 0,
              cursor: "pointer",
            }}
          >
            <Paper
              sx={{
                px: 3,
                py: 2,
                borderRadius: 2,
                bgcolor: expandedPhase === phase.id ? alpha(phase.color, 0.15) : alpha(phase.color, 0.05),
                border: `2px solid ${expandedPhase === phase.id ? phase.color : "transparent"}`,
                transition: "all 0.2s",
                "&:hover": { bgcolor: alpha(phase.color, 0.1), transform: "translateY(-2px)" },
                minWidth: 140,
                textAlign: "center",
              }}
            >
              <Box sx={{ color: phase.color, mb: 1 }}>{phase.icon}</Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: phase.color }}>
                {phase.name}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Phase {phase.id}
              </Typography>
            </Paper>
            {index < killChainPhases.length - 1 && (
              <Box sx={{ px: 1, color: "text.disabled", fontSize: "1.5rem" }}>→</Box>
            )}
          </Box>
        ))}
      </Box>

      {/* Phase Details */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        📋 Detailed Phase Breakdown
      </Typography>
      {killChainPhases.map((phase) => (
        <Accordion
          key={phase.id}
          expanded={expandedPhase === phase.id}
          onChange={(_, expanded) => setExpandedPhase(expanded ? phase.id : false)}
          sx={{
            mb: 2,
            borderRadius: 2,
            "&:before": { display: "none" },
            border: `1px solid ${alpha(phase.color, 0.2)}`,
            "&.Mui-expanded": { border: `2px solid ${phase.color}` },
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{
              bgcolor: alpha(phase.color, 0.05),
              borderRadius: "8px 8px 0 0",
              "&.Mui-expanded": { borderBottom: `1px solid ${alpha(phase.color, 0.2)}` },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ p: 1, borderRadius: 2, bgcolor: alpha(phase.color, 0.15), color: phase.color }}>
                {phase.icon}
              </Box>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>
                  Phase {phase.id}: {phase.name}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {phase.subtitle}
                </Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ p: 4 }}>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              {phase.description}
            </Typography>

            <Grid container spacing={4}>
              {/* Attacker Actions */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <WarningIcon fontSize="small" /> Attacker Actions
                  </Typography>
                  <List dense>
                    {phase.attackerActions.map((action, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Typography variant="body2" color="error.main">•</Typography>
                        </ListItemIcon>
                        <ListItemText primary={action} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>

              {/* Defender Actions */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <ShieldIcon fontSize="small" /> Defender Actions
                  </Typography>
                  <List dense>
                    {phase.defenderActions.map((action, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Typography variant="body2" color="success.main">•</Typography>
                        </ListItemIcon>
                        <ListItemText primary={action} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            {/* Tools & Indicators */}
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>🛠️ Common Tools</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {phase.tools.map((tool) => (
                    <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.75rem" }} />
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>🔍 Detection Indicators</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {phase.indicators.map((indicator) => (
                    <Chip key={indicator} label={indicator} size="small" sx={{ fontSize: "0.75rem", bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
                  ))}
                </Box>
              </Grid>
            </Grid>

            {/* Real World Example */}
            <Alert severity="info" sx={{ mt: 3, borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Real-World Example</Typography>
              <Typography variant="body2">{phase.realWorldExample}</Typography>
            </Alert>
          </AccordionDetails>
        </Accordion>
      ))}

      {/* Footer */}
      <Paper sx={{ p: 4, mt: 4, borderRadius: 3, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          🎓 Key Takeaways
        </Typography>
        <Grid container spacing={2}>
          {[
            "Early detection is best - stopping reconnaissance or delivery prevents all later phases",
            "Defense in depth is critical - have controls at every phase",
            "Threat intelligence helps identify patterns across the chain",
            "Modern attacks may skip or combine phases (e.g., supply chain attacks)",
          ].map((point, i) => (
            <Grid item xs={12} md={6} key={i}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                <Chip label={i + 1} size="small" sx={{ bgcolor: "info.main", color: "white", fontWeight: 700, minWidth: 24, height: 24 }} />
                <Typography variant="body2">{point}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
