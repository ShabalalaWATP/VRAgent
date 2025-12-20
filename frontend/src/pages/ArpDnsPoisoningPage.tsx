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
import DnsIcon from "@mui/icons-material/Dns";
import WifiIcon from "@mui/icons-material/Wifi";
import SecurityIcon from "@mui/icons-material/Security";
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
        border: "1px solid rgba(14, 165, 233, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#0ea5e9", color: "#0b1020" }} />
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

const ArpDnsPoisoningPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const objectives = [
    "Explain ARP and DNS poisoning in simple terms.",
    "Recognize common symptoms and warning signs.",
    "Identify safe, read-only checks for network state.",
    "Understand how to defend against spoofing.",
    "Practice a safe lab walkthrough without attacking systems.",
  ];
  const practicalTakeaways = [
    "Keep a baseline of gateway MAC and DNS resolver IPs.",
    "Alert on rapid ARP table changes on multiple hosts.",
    "Treat DNS anomalies as potential MITM indicators.",
    "Use segmentation and switch controls to limit impact.",
  ];
  const beginnerPath = [
    "1) Read the glossary and the simple explanation.",
    "2) Learn how ARP and DNS normally work on a LAN.",
    "3) Review warning signs and safe checks.",
    "4) Study defensive controls and segmentation ideas.",
    "5) Run the lab walkthrough in an isolated environment.",
  ];

  const glossary = [
    { term: "ARP", desc: "Maps IP addresses to MAC addresses on a local network." },
    { term: "DNS", desc: "Resolves domain names to IP addresses." },
    { term: "Poisoning", desc: "Tricking systems to trust incorrect network information." },
    { term: "MITM", desc: "Man-in-the-middle interception between two systems." },
    { term: "Cache", desc: "Stored results to speed up lookups." },
  ];
  const arpBasics = [
    "ARP is only used on the local network (same subnet).",
    "Your device keeps an ARP table that maps IP to MAC addresses.",
    "Poisoning happens when that table is updated with false data.",
  ];
  const dnsBasics = [
    "DNS turns names like example.com into IP addresses.",
    "Devices and resolvers cache DNS answers for a period of time.",
    "Poisoning happens when the cache is filled with incorrect answers.",
  ];

  const misconceptions = [
    {
      myth: "Poisoning only affects hacked computers.",
      reality: "It can affect any device on the same network segment.",
    },
    {
      myth: "DNS poisoning always changes every domain.",
      reality: "Attackers often target specific domains.",
    },
    {
      myth: "HTTPS always prevents MITM.",
      reality: "HTTPS helps, but trust issues and misconfigurations can still be abused.",
    },
  ];
  const userImpact = [
    "Users see certificate warnings or TLS errors.",
    "Browsers redirect to unfamiliar sites.",
    "Slow or unstable network connections.",
    "Login failures despite correct passwords.",
  ];
  const scenarios = [
    "A user connects to a public Wi-Fi network and DNS responses are altered.",
    "A compromised device on the LAN changes ARP entries for the gateway.",
    "An internal DNS resolver is misconfigured and serves incorrect records.",
  ];

  const arpSignals = [
    "Multiple IPs mapping to the same MAC address.",
    "Frequent ARP changes for the gateway address.",
    "Unexpected ARP replies without requests.",
  ];
  const arpBaselineChecks = [
    "Record the normal MAC address for the default gateway.",
    "Record ARP entries for key servers and DNS resolvers.",
    "Capture ARP tables at different times of day.",
  ];

  const dnsSignals = [
    "DNS answers that point to unexpected IP ranges.",
    "Short TTL values for sensitive domains.",
    "Frequent cache flushes or NXDOMAIN spikes.",
  ];
  const dnsBaselineChecks = [
    "Record normal DNS resolvers used by clients.",
    "Check expected IP ranges for key domains.",
    "Compare TTL values across trusted resolvers.",
  ];
  const responseSteps = [
    "Confirm the affected scope (which VLAN, which clients).",
    "Capture ARP and DNS state for evidence.",
    "Isolate suspicious devices if possible.",
    "Flush caches or restart resolvers if approved.",
    "Document findings and adjust controls.",
  ];
  const triageChecklist = [
    "Which device reported the issue?",
    "Is the default gateway MAC address consistent?",
    "Do DNS responses match a trusted resolver?",
    "Are multiple clients affected or just one?",
    "Is there evidence of new devices on the VLAN?",
  ];

  const defenses = [
    "Enable DHCP snooping and dynamic ARP inspection on switches.",
    "Use static ARP entries for critical systems where feasible.",
    "Enforce DNSSEC and trusted DNS resolvers.",
    "Monitor for ARP table changes and DNS anomalies.",
    "Segment networks to limit blast radius.",
  ];
  const segmentationGuidance = [
    "Separate user, server, and IoT devices into different VLANs.",
    "Limit inter-VLAN traffic with ACLs and least privilege routing.",
    "Keep DNS and DHCP infrastructure in protected segments.",
    "Isolate guest Wi-Fi from internal networks.",
    "Monitor east-west traffic for unexpected peer-to-peer flows.",
  ];
  const dnssecGuidance = [
    "Enable DNSSEC validation on resolvers.",
    "Use trusted recursive resolvers and limit rogue DNS via DHCP.",
    "Watch for sudden spikes in SERVFAIL or validation errors.",
    "Prefer DoT/DoH where policy allows to reduce tampering risk.",
    "Document which critical domains must validate successfully.",
  ];
  const switchControls = [
    { control: "DHCP Snooping", goal: "Block rogue DHCP servers." },
    { control: "Dynamic ARP Inspection (DAI)", goal: "Reject spoofed ARP replies." },
    { control: "IP Source Guard", goal: "Bind IP/MAC/port to prevent spoofing." },
    { control: "Port Security", goal: "Limit MAC addresses per switch port." },
    { control: "VLAN ACLs", goal: "Restrict traffic between segments." },
  ];

  const telemetry = [
    "ARP table snapshots and gateway mapping changes.",
    "DNS resolver logs and response anomalies.",
    "Switch logs for ARP inspection events.",
    "Endpoint alerts for MITM indicators.",
  ];
  const logSources = [
    { source: "Switch", detail: "DAI or DHCP snooping violations." },
    { source: "DNS resolver", detail: "Unexpected responses or validation errors." },
    { source: "Endpoint", detail: "TLS warnings or proxy changes." },
    { source: "Firewall/proxy", detail: "Connections to new destinations." },
  ];
  const detectionMatrix = [
    {
      stage: "Local spoofing",
      signal: "Gateway MAC changes on multiple hosts.",
      evidence: "ARP tables and switch logs.",
    },
    {
      stage: "DNS cache issues",
      signal: "Incorrect IPs for critical domains.",
      evidence: "Resolver logs and cache outputs.",
    },
    {
      stage: "MITM indicators",
      signal: "Certificate warnings or connection resets.",
      evidence: "Browser logs and endpoint alerts.",
    },
  ];

  const safeChecks = `# Windows: view ARP table
arp -a

# Windows: DNS cache
ipconfig /displaydns

# Linux: neighbor table (ARP)
ip neigh show

# Linux: DNS resolver info
systemd-resolve --status

# macOS: ARP table
arp -a`;
  const dnsQueryChecks = `# Windows: query DNS resolver
nslookup example.com

# Linux: query DNS resolver
dig example.com

# macOS: query DNS resolver
dig example.com`;

  const labSteps = [
    "Use a lab or isolated network only.",
    "Capture baseline ARP and DNS state.",
    "Change a local DNS entry in a lab resolver and observe effects.",
    "Record what changed and how it appeared in logs.",
    "Reset the lab and document findings.",
  ];
  const safeBoundaries = [
    "Do not run spoofing tools on real networks.",
    "Use a disposable lab VM and local resolver only.",
    "Do not intercept real user traffic.",
    "Get written approval for any non-lab testing.",
  ];

  const pageContext = `This page covers ARP and DNS poisoning attacks, including how they work, warning signs, detection methods, and defensive controls. Topics include ARP table manipulation, DNS cache poisoning, MITM risks, network segmentation, DHCP snooping, and dynamic ARP inspection.`;

  return (
    <LearnPageLayout pageTitle="ARP and DNS Poisoning" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <DnsIcon sx={{ fontSize: 42, color: "#0ea5e9" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #0ea5e9 0%, #38bdf8 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            ARP and DNS Poisoning
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          ARP and DNS poisoning are ways to trick devices into trusting the wrong network information.
        </Typography>
        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            In simple terms, ARP poisoning changes who your computer thinks is on the local network, and DNS
            poisoning changes where your computer thinks a website lives. Both can redirect traffic without you
            noticing. This page focuses on understanding the risks and detecting unusual behavior.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
            Think of ARP like a neighborhood address book and DNS like the phone book for the internet. If those
            books are updated with wrong entries, you may call the wrong person or drive to the wrong house.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            Everything here is defensive and beginner-friendly. Use safe checks and lab-only exercises.
          </Typography>
        </Paper>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<WifiIcon />} label="ARP" size="small" />
          <Chip icon={<DnsIcon />} label="DNS" size="small" />
          <Chip icon={<SecurityIcon />} label="Detection" size="small" />
          <Chip icon={<ShieldIcon />} label="Prevention" size="small" />
          <Chip icon={<WarningIcon />} label="MITM Risk" size="small" />
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
              "& .Mui-selected": { color: "#0ea5e9" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<WifiIcon />} label="ARP Poisoning" />
            <Tab icon={<DnsIcon />} label="DNS Poisoning" />
            <Tab icon={<SearchIcon />} label="Detection" />
            <Tab icon={<ShieldIcon />} label="Defenses" />
            <Tab icon={<WarningIcon />} label="Beginner Lab" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Practical Takeaways
                </Typography>
                <List dense>
                  {practicalTakeaways.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  User-Visible Impact
                </Typography>
                <List dense>
                  {userImpact.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  ARP Basics (Plain Language)
                </Typography>
                <List dense>
                  {arpBasics.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  DNS Basics (Plain Language)
                </Typography>
                <List dense>
                  {dnsBasics.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Simple Scenarios
                </Typography>
                <List dense>
                  {scenarios.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
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
                          border: "1px solid rgba(14,165,233,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#0ea5e9", mb: 1 }}>
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
                ARP poisoning targets the local network by changing IP-to-MAC mappings. It can redirect traffic to an
                attacker-controlled device on the same LAN.
              </Typography>
              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  ARP Warning Signs
                </Typography>
                <List dense>
                  {arpSignals.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  ARP Baseline Checks
                </Typography>
                <List dense>
                  {arpBaselineChecks.map((item) => (
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

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                DNS poisoning alters name resolution so users are redirected to the wrong IP address when they type
                a familiar domain.
              </Typography>
              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  DNS Warning Signs
                </Typography>
                <List dense>
                  {dnsSignals.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  DNS Baseline Checks
                </Typography>
                <List dense>
                  {dnsBaselineChecks.map((item) => (
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

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Telemetry Sources
                </Typography>
                <List dense>
                  {telemetry.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
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

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Read-only Checks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={safeChecks} language="powershell" />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Basic DNS Query Checks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={dnsQueryChecks} language="bash" />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Defensive Controls
                </Typography>
                <List dense>
                  {defenses.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Network Segmentation Guidance
                </Typography>
                <List dense>
                  {segmentationGuidance.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  DNSSEC and Resolver Hygiene
                </Typography>
                <List dense>
                  {dnssecGuidance.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Switch-Level Defenses
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Control</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Goal</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {switchControls.map((item) => (
                        <TableRow key={item.control}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.control}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.goal}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
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

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Triage Checklist
                </Typography>
                <List dense>
                  {triageChecklist.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#0ea5e9", mb: 1 }}>
                  Response Steps (High Level)
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
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#0ea5e9", color: "#0ea5e9" }}
          >
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default ArpDnsPoisoningPage;
