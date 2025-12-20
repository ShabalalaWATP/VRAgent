import React, { useState } from "react";
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
import RouteIcon from "@mui/icons-material/Route";
import SecurityIcon from "@mui/icons-material/Security";
import HubIcon from "@mui/icons-material/Hub";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ShieldIcon from "@mui/icons-material/Shield";
import SearchIcon from "@mui/icons-material/Search";
import { useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

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
        bgcolor: "#121424",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(59, 130, 246, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#3b82f6", color: "#0b1020" }} />
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

const PivotingTunnelingPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const objectives = [
    "Explain pivoting and tunneling in plain language.",
    "Identify common use cases and risks.",
    "Understand where tunnels show up in telemetry.",
    "Review safe detection and hardening ideas.",
    "Practice a safe, lab-only walkthrough.",
  ];

  const beginnerPath = [
    "1) Read the glossary and simple definitions.",
    "2) Learn the difference between pivoting and tunneling.",
    "3) Review common signals and safe checks.",
    "4) Study defenses and segmentation guidance.",
    "5) Complete the lab walkthrough in an isolated network.",
  ];
  const whatItIsNot = [
    "It is not an offensive how-to for bypassing controls.",
    "It is not about running tunnels on production networks.",
    "It is focused on detection and defensive awareness.",
  ];
  const whyItMatters = [
    "Pivoting can bypass perimeter defenses by using internal hosts.",
    "Tunneling can hide traffic inside allowed protocols.",
    "Both techniques can blur the true source of activity.",
  ];

  const glossary = [
    { term: "Pivoting", desc: "Using one system to reach another network segment." },
    { term: "Tunneling", desc: "Encapsulating traffic inside another protocol." },
    { term: "Relay", desc: "Forwarding traffic through an intermediate host." },
    { term: "Proxy", desc: "A service that forwards traffic on your behalf." },
    { term: "Jump host", desc: "A controlled system used to access internal networks." },
  ];
  const pivotTypes = [
    { type: "Network pivot", desc: "Use a host as a gateway to another subnet." },
    { type: "Application pivot", desc: "Use an app proxy to reach internal services." },
    { type: "Account pivot", desc: "Use stolen credentials to access new systems." },
  ];

  const simpleDefinitions = [
    "Pivoting is like using one hallway to reach rooms you could not access directly.",
    "Tunneling is like hiding one conversation inside another to pass through filters.",
  ];

  const misconceptions = [
    {
      myth: "Tunnels are always malicious.",
      reality: "Legitimate admins use VPNs and proxies for remote access.",
    },
    {
      myth: "If a tunnel is encrypted, it is safe.",
      reality: "Encryption can also hide malicious traffic from inspection.",
    },
    {
      myth: "Blocking a single port stops all tunneling.",
      reality: "Tunnels can use many protocols and ports.",
    },
  ];
  const impactExamples = [
    "Internal databases reachable from a compromised workstation.",
    "Sensitive services exposed through a misconfigured jump host.",
    "Hidden C2 traffic inside allowed web traffic.",
  ];

  const commonUseCases = [
    {
      title: "Legitimate remote access",
      desc: "Admins use jump hosts or VPNs to reach internal systems.",
      risk: "If misconfigured, it can expose internal networks.",
    },
    {
      title: "Incident response",
      desc: "Secure access to affected hosts for analysis and containment.",
      risk: "Ensure strong auth and logging are enabled.",
    },
    {
      title: "Malicious lateral movement",
      desc: "Attackers pivot through a compromised host to reach deeper assets.",
      risk: "Bypasses perimeter controls and obscures source IPs.",
    },
  ];

  const techniquesHighLevel = [
    { name: "Port forwarding", idea: "Forward traffic from one port to another." },
    { name: "Proxy chains", idea: "Route traffic through one or more proxies." },
    { name: "VPN tunnels", idea: "Create encrypted connections to internal networks." },
    { name: "HTTP(S) tunnels", idea: "Encapsulate traffic inside web protocols." },
    { name: "DNS tunnels", idea: "Encode traffic inside DNS queries." },
  ];
  const techniqueRisks = [
    { technique: "Port forwarding", visibility: "Internal connections appear from pivot host.", risk: "Bypasses network segmentation rules." },
    { technique: "Proxy chains", visibility: "Multiple hops and altered source context.", risk: "Obscures origin and attribution." },
    { technique: "VPN tunnels", visibility: "New tunnel interfaces and long-lived sessions.", risk: "Expands access scope if misconfigured." },
    { technique: "HTTP(S) tunnels", visibility: "Unusual payload sizes and persistent sessions.", risk: "Blends with allowed web traffic." },
    { technique: "DNS tunnels", visibility: "High query volume and long subdomains.", risk: "Exfiltration over DNS paths." },
  ];
  const attckMapping = [
    { tactic: "Lateral Movement", technique: "T1021", example: "Remote services via a pivot host." },
    { tactic: "Command and Control", technique: "T1071", example: "Tunneling over web protocols." },
    { tactic: "Exfiltration", technique: "T1041", example: "Data over C2 channel or tunnel." },
    { tactic: "Defense Evasion", technique: "T1573", example: "Encrypted channels to hide traffic." },
  ];
  const detectionMatrix = [
    {
      stage: "Access",
      signal: "New host talking to sensitive services.",
      evidence: "Netflow logs and firewall rules.",
    },
    {
      stage: "Tunnel setup",
      signal: "Long-lived connections with steady traffic.",
      evidence: "Proxy logs and endpoint process data.",
    },
    {
      stage: "Pivot usage",
      signal: "Traffic to internal networks from user endpoints.",
      evidence: "Internal routing logs and EDR alerts.",
    },
  ];
  const investigationChecklist = [
    "Identify the first host that initiated the tunnel.",
    "Confirm user account and authentication method.",
    "Validate the destination segment and asset criticality.",
    "Check for other endpoints with similar patterns.",
    "Correlate DNS, proxy, and EDR timeline.",
  ];
  const baselineQuestions = [
    "Is this host a known jump box or admin workstation?",
    "Is this traffic normal for this role or team?",
    "Has this destination been seen before?",
    "Are there approved maintenance windows?",
    "Is there a matching change ticket?",
  ];
  const reportingChecklist = [
    "Summarize pivot path and affected segments.",
    "Document all evidence sources and timestamps.",
    "List impacted assets and business owners.",
    "State containment actions and approvals.",
    "Recommend control improvements.",
  ];

  const signals = [
    "Internal traffic originating from a non-standard host.",
    "Unexpected connections between segments or VLANs.",
    "Long-lived connections with steady outbound traffic.",
    "High DNS query volume or unusual query sizes.",
    "New proxy services listening on endpoints.",
  ];
  const behaviorSignals = [
    "High DNS query volume with long subdomains.",
    "Unusual HTTP methods or large POST bodies to rare hosts.",
    "Persistent outbound connections over uncommon ports.",
    "Internal scans originating from user devices.",
  ];

  const telemetry = [
    "Firewall and proxy logs (source, destination, bytes).",
    "Netflow or Zeek logs for lateral movement.",
    "Endpoint process and listening port inventory.",
    "DNS logs and query size anomalies.",
    "VPN and remote access logs.",
  ];
  const telemetryCoverage = [
    { area: "Endpoint", detail: "Process, service, and socket telemetry." },
    { area: "Network", detail: "Flow logs, IDS, and internal routing." },
    { area: "DNS", detail: "Query length, volume, and NXDOMAIN rates." },
    { area: "Proxy", detail: "User agents, methods, and session duration." },
    { area: "Auth", detail: "VPN, SSO, and jump host logins." },
  ];
  const logSources = [
    { source: "Firewall", detail: "Cross-segment traffic and new destinations." },
    { source: "Proxy", detail: "Long-lived HTTP/S sessions and large payloads." },
    { source: "DNS", detail: "Query volume, length, and NXDOMAIN spikes." },
    { source: "EDR", detail: "New listeners and unusual parent processes." },
  ];
  const detectionPitfalls = [
    "Treating all tunnels as malicious and flagging legitimate VPN use.",
    "Missing lateral movement because logs lack east-west visibility.",
    "Ignoring time alignment issues across data sources.",
    "Focusing on ports only and missing protocol-based tunneling.",
    "Not correlating host process data with network flows.",
  ];
  const tuningIdeas = [
    "Baseline normal proxy and VPN usage by team.",
    "Alert on first-time cross-segment access patterns.",
    "Flag new listening services on user endpoints.",
    "Enrich flows with asset criticality and owner tags.",
    "Track DNS query length distributions by host.",
  ];

  const defenses = [
    "Use segmentation and restrict east-west traffic.",
    "Require MFA for remote access and jump hosts.",
    "Limit admin tools to approved hosts.",
    "Monitor for new listening services on endpoints.",
    "Block unauthorized DNS or HTTP tunneling tools.",
  ];
  const hardeningChecklist = [
    "Require MFA for VPN and jump hosts.",
    "Restrict local admin rights on endpoints.",
    "Disable unused services and unused ports.",
    "Apply egress filtering and allowlists.",
    "Monitor for new listening services on endpoints.",
  ];
  const policyGuidance = [
    "Document approved jump hosts and proxy services.",
    "Enforce least-privilege routes between segments.",
    "Separate admin access from user browsing paths.",
    "Apply strict egress rules for sensitive segments.",
    "Review tunnel approvals on a fixed cadence.",
  ];

  const segmentationGuidance = [
    "Separate user, server, and admin networks.",
    "Use allowlists for inter-segment access.",
    "Restrict management ports to jump hosts only.",
    "Log and review all cross-segment connections.",
  ];
  const responseSteps = [
    "Identify the pivot host and isolate it if needed.",
    "Capture logs and process trees for evidence.",
    "Review firewall rules and remove unauthorized routes.",
    "Reset exposed credentials and rotate tokens.",
    "Document the timeline and update detections.",
  ];
  const responseChecklist = [
    "Confirm scope and impacted segments.",
    "Validate indicators with at least two sources.",
    "Coordinate containment with system owners.",
    "Preserve evidence before remediation.",
    "Add or tune detections after closure.",
  ];

  const evidenceChecklist = [
    "Source and destination IPs and ports",
    "Process name and parent process on the pivot host",
    "Bytes transferred and connection duration",
    "DNS query patterns or anomalies",
    "Authentication context and user account",
  ];
  const labArtifacts = [
    "Baseline network map and allowed paths",
    "Sample log entries showing normal traffic",
    "List of approved remote access tools",
    "Screenshots of detection dashboards",
    "Final report with findings and recommendations",
  ];
  const reportTemplate = `Host: <pivot host>
Date: <utc>
Observed signal: <what was seen>
Source/Destination: <IPs/ports>
Process: <name and parent>
Evidence: <logs, screenshots>
Risk: <impact>
Recommendation: <block, monitor, segment>`;

  const safeChecks = `# Windows: list listening ports
netstat -ano | findstr LISTENING

# Windows: active connections
netstat -ano | findstr ESTABLISHED

# Linux: listening ports
ss -lntp

# Linux: active connections
ss -ntp

# macOS: active connections
netstat -anv | head -n 20`;

  const labSteps = [
    "Use an isolated lab with two small networks.",
    "Map which systems can talk to each other (baseline).",
    "Create a diagram of allowed paths and blocked paths.",
    "Observe connections and log normal traffic.",
    "Write a report describing what would be suspicious.",
  ];

  const safeBoundaries = [
    "Do not set up tunnels on real networks without approval.",
    "Avoid tools or steps that bypass security controls.",
    "Keep the lab isolated and use test data only.",
    "Document findings rather than attempting exploitation.",
  ];

  const pageContext = `This page covers network pivoting and tunneling techniques, including port forwarding, proxy chains, VPN tunnels, HTTP/DNS tunnels, detection signals, and defensive controls. Topics include lateral movement, traffic routing through compromised hosts, ATT&CK mapping, detection pitfalls, tuning ideas, response checklists, and network segmentation.`;

  return (
    <LearnPageLayout pageTitle="Pivoting and Tunneling" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <RouteIcon sx={{ fontSize: 42, color: "#3b82f6" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #3b82f6 0%, #60a5fa 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Pivoting and Tunneling
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Pivoting and tunneling describe ways traffic is routed through other systems or hidden inside other protocols.
        </Typography>
        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            In simple terms, pivoting is using one computer to reach another network you could not reach directly.
            Tunneling is wrapping one kind of traffic inside another to pass through filters. Both can be used for
            legitimate administration or abused by attackers. This page focuses on understanding the concepts,
            spotting warning signs, and building safer defenses.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
            Think of pivoting like using a secure door to access a hallway behind it. Tunneling is like hiding a
            smaller package inside a larger, allowed shipment. Knowing the patterns helps you detect misuse.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            Everything here is beginner-friendly and defensive. Use safe checks and lab-only exercises.
          </Typography>
        </Paper>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<HubIcon />} label="Pivoting" size="small" />
          <Chip icon={<RouteIcon />} label="Tunneling" size="small" />
          <Chip icon={<SecurityIcon />} label="Detection" size="small" />
          <Chip icon={<ShieldIcon />} label="Defenses" size="small" />
          <Chip icon={<WarningIcon />} label="Risk Signals" size="small" />
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
              "& .Mui-selected": { color: "#3b82f6" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<HubIcon />} label="Concepts" />
            <Tab icon={<RouteIcon />} label="Techniques" />
            <Tab icon={<SearchIcon />} label="Detection" />
            <Tab icon={<ShieldIcon />} label="Defenses" />
            <Tab icon={<WarningIcon />} label="Beginner Lab" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Simple Definitions
                </Typography>
                <List dense>
                  {simpleDefinitions.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Why It Matters
                </Typography>
                <List dense>
                  {whyItMatters.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Pivot Types
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
                      {pivotTypes.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Impact Examples
                </Typography>
                <List dense>
                  {impactExamples.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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
                          border: "1px solid rgba(59,130,246,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>
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
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                Pivoting uses a host you already control to reach internal assets. Tunneling hides traffic inside
                a different protocol to pass through network restrictions.
              </Typography>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Common Use Cases
                </Typography>
                <Grid container spacing={2}>
                  {commonUseCases.map((item) => (
                    <Grid item xs={12} md={4} key={item.title}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(59,130,246,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 600 }}>
                          {item.title}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                          {item.desc}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "#94a3b8" }}>
                          Risk: {item.risk}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Policy and Context
                </Typography>
                <List dense>
                  {policyGuidance.map((item) => (
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

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Technique Risk and Visibility
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#3b82f6" }}>Technique</TableCell>
                        <TableCell sx={{ color: "#3b82f6" }}>Visibility</TableCell>
                        <TableCell sx={{ color: "#3b82f6" }}>Risk</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {techniqueRisks.map((item) => (
                        <TableRow key={item.technique}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.technique}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.visibility}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  ATT&CK Mapping (High-Level)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Tactic</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Technique</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Example</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {attckMapping.map((item) => (
                        <TableRow key={item.technique}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.tactic}</TableCell>
                          <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>{item.technique}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.example}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#3b82f6" }}>Technique</TableCell>
                      <TableCell sx={{ color: "#3b82f6" }}>High-level idea</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {techniquesHighLevel.map((item) => (
                      <TableRow key={item.name}>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.name}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.idea}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Baseline Questions
                </Typography>
                <List dense>
                  {baselineQuestions.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Detection Pitfalls
                </Typography>
                <List dense>
                  {detectionPitfalls.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon sx={{ color: "#f59e0b" }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Tuning Ideas
                </Typography>
                <List dense>
                  {tuningIdeas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Behavior Signals
                </Typography>
                <List dense>
                  {behaviorSignals.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Telemetry Sources
                </Typography>
                <List dense>
                  {telemetry.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Telemetry Coverage Map
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Area</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>What it tells you</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {telemetryCoverage.map((item) => (
                        <TableRow key={item.area}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.area}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.detail}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Log Sources (Examples)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Source</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>What to look for</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {logSources.map((item) => (
                        <TableRow key={item.source}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.source}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.detail}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Investigation Checklist
                </Typography>
                <List dense>
                  {investigationChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Read-only Checks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={safeChecks} language="bash" />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Defensive Controls
                </Typography>
                <List dense>
                  {defenses.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Hardening Checklist
                </Typography>
                <List dense>
                  {hardeningChecklist.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Segmentation Guidance
                </Typography>
                <List dense>
                  {segmentationGuidance.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Response Steps
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

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Response Checklist
                </Typography>
                <List dense>
                  {responseChecklist.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Reporting Checklist
                </Typography>
                <List dense>
                  {reportingChecklist.map((item) => (
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

          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Beginner Lab Walkthrough (Safe)
                </Typography>
                <List dense>
                  {labSteps.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Lab Evidence to Collect
                </Typography>
                <List dense>
                  {labArtifacts.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Report Template
                </Typography>
                <CodeBlock code={reportTemplate} language="text" />
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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
            </Box>
          </TabPanel>
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#3b82f6", color: "#3b82f6" }}
          >
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default PivotingTunnelingPage;
