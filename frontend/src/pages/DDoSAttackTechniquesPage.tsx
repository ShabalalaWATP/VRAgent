import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  Box,
  Typography,
  Paper,
  Tabs,
  Tab,
  Grid,
  Card,
  CardContent,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
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
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Divider,
  AlertTitle,
  Button,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SecurityIcon from "@mui/icons-material/Security";
import CloudIcon from "@mui/icons-material/Cloud";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import SpeedIcon from "@mui/icons-material/Speed";
import ShieldIcon from "@mui/icons-material/Shield";
import WarningIcon from "@mui/icons-material/Warning";
import StorageIcon from "@mui/icons-material/Storage";
import RouterIcon from "@mui/icons-material/Router";
import PublicIcon from "@mui/icons-material/Public";
import GavelIcon from "@mui/icons-material/Gavel";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import MonetizationOnIcon from "@mui/icons-material/MonetizationOn";
import GroupsIcon from "@mui/icons-material/Groups";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import ComputerIcon from "@mui/icons-material/Computer";
import DnsIcon from "@mui/icons-material/Dns";
import HttpIcon from "@mui/icons-material/Http";
import BugReportIcon from "@mui/icons-material/BugReport";
import SearchIcon from "@mui/icons-material/Search";
import AnalyticsIcon from "@mui/icons-material/Analytics";
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
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

// Code block component
const CodeBlock = ({ children, language }: { children: string; language?: string }) => (
  <Paper
    sx={{
      p: 2,
      bgcolor: "#1e1e1e",
      color: "#d4d4d4",
      fontFamily: "monospace",
      fontSize: "0.85rem",
      overflow: "auto",
      my: 2,
      borderRadius: 1,
    }}
  >
    {language && (
      <Typography variant="caption" sx={{ color: "#888", display: "block", mb: 1 }}>
        {language}
      </Typography>
    )}
    <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{children}</pre>
  </Paper>
);

// =============================================================================
// DATA ARRAYS
// =============================================================================

const attackCategories = [
  {
    name: "Volumetric Attacks",
    icon: <CloudIcon />,
    description: "Overwhelm bandwidth with massive traffic volume",
    longDescription: "Volumetric attacks are the most common type of DDoS. They work by flooding the target with so much traffic that the network connection becomes saturated. Think of it like trying to drink from a fire hose - there's simply too much coming at once. These attacks are measured in bits per second (bps) and can reach terabits of traffic.",
    techniques: [
      { name: "UDP Flood", description: "Sends massive UDP packets to random ports, forcing the server to check for applications and respond with ICMP 'destination unreachable'" },
      { name: "ICMP Flood", description: "Also called 'Ping Flood' - overwhelms target with ICMP echo requests (pings) without waiting for replies" },
      { name: "DNS Amplification", description: "Spoofs victim's IP and sends DNS queries to open resolvers, which send large responses to the victim" },
      { name: "NTP Amplification", description: "Exploits NTP servers' monlist command to amplify traffic up to 556x" },
      { name: "Memcached Amplification", description: "Abuses misconfigured Memcached servers for up to 51,000x amplification - the most powerful amplification vector known" },
    ],
  },
  {
    name: "Protocol Attacks",
    icon: <NetworkCheckIcon />,
    description: "Exploit weaknesses in network protocols (Layer 3/4)",
    longDescription: "Protocol attacks exploit weaknesses in how network protocols work. Instead of using raw bandwidth, they consume server resources or intermediate equipment like firewalls and load balancers. These are measured in packets per second (pps) and target the 'handshake' process that computers use to establish connections.",
    techniques: [
      { name: "SYN Flood", description: "Exploits TCP handshake by sending SYN requests but never completing the connection, exhausting server's connection table" },
      { name: "Ping of Death", description: "Sends malformed or oversized ping packets that crash the target system when reassembled" },
      { name: "Smurf Attack", description: "Spoofs victim's IP and broadcasts ICMP requests to a network, causing all hosts to reply to the victim" },
      { name: "Fragmentation Attacks", description: "Sends fragmented packets that the target cannot reassemble, consuming memory and CPU" },
    ],
  },
  {
    name: "Application Layer Attacks",
    icon: <StorageIcon />,
    description: "Target application vulnerabilities (Layer 7)",
    longDescription: "Application layer attacks are the most sophisticated type. They target the actual web server or application, mimicking legitimate user behavior to evade detection. These are measured in requests per second (rps) and often require fewer resources to execute but can be devastating because they're hard to distinguish from real traffic.",
    techniques: [
      { name: "HTTP Flood", description: "Sends seemingly legitimate HTTP GET or POST requests to overwhelm web servers" },
      { name: "Slowloris", description: "Opens connections and sends partial HTTP headers very slowly, keeping connections open and exhausting server limits" },
      { name: "RUDY (R-U-Dead-Yet)", description: "Sends HTTP POST with extremely long content-length, then transmits data very slowly" },
      { name: "DNS Query Flood", description: "Floods DNS servers with valid but random subdomain queries that can't be cached" },
    ],
  },
];

const amplificationVectors = [
  { protocol: "Memcached", amplification: "51,000x", port: "11211/UDP", description: "Abuses key-value cache servers. A 15-byte request can generate 750KB response.", prevention: "Disable UDP, bind to localhost, use authentication" },
  { protocol: "NTP", amplification: "556x", port: "123/UDP", description: "Exploits monlist command on older NTP servers to get list of last 600 clients.", prevention: "Upgrade NTP, disable monlist, use rate limiting" },
  { protocol: "DNS", amplification: "28-54x", port: "53/UDP", description: "Uses ANY or TXT queries to generate large responses from open resolvers.", prevention: "Disable recursion, implement response rate limiting (RRL)" },
  { protocol: "CharGEN", amplification: "358x", port: "19/UDP", description: "Legacy character generator protocol, sends 74-byte response to 1-byte request.", prevention: "Disable CharGEN service entirely" },
  { protocol: "SSDP", amplification: "30x", port: "1900/UDP", description: "Simple Service Discovery Protocol used by UPnP devices.", prevention: "Disable SSDP on internet-facing interfaces" },
  { protocol: "SNMP", amplification: "6.3x", port: "161/UDP", description: "Network management protocol with GetBulk requests.", prevention: "Use SNMPv3 with authentication, restrict to internal networks" },
  { protocol: "CLDAP", amplification: "56-70x", port: "389/UDP", description: "Connectionless LDAP used by Active Directory.", prevention: "Block external access to port 389/UDP" },
  { protocol: "TFTP", amplification: "60x", port: "69/UDP", description: "Trivial File Transfer Protocol for bootstrapping.", prevention: "Restrict TFTP to internal networks only" },
];

const mitigationStrategies = [
  {
    name: "Rate Limiting",
    description: "Limit requests per IP/session to prevent single sources from overwhelming resources",
    layer: "Network/Application",
    longDescription: "Rate limiting caps the number of requests a single IP address or session can make within a time window. This is your first line of defense and should be implemented at multiple layers.",
    implementation: "Configure nginx: limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;",
  },
  {
    name: "Anycast Network Diffusion",
    description: "Distribute traffic across multiple data centers globally",
    layer: "Network",
    longDescription: "Anycast uses BGP to route traffic to the nearest data center. When attack traffic arrives, it's automatically distributed across your entire network, preventing any single location from being overwhelmed.",
    implementation: "Requires multiple PoPs advertising same IP prefix via BGP",
  },
  {
    name: "Black Hole Routing",
    description: "Route attack traffic to null to protect upstream networks",
    layer: "Network",
    longDescription: "Also called 'null routing' - drops all traffic to the target IP. This sacrifices the target but protects the rest of the network. Often used as a last resort when attack is overwhelming.",
    implementation: "ip route add blackhole 203.0.113.50/32",
  },
  {
    name: "Web Application Firewall (WAF)",
    description: "Filter malicious HTTP traffic based on signatures and behavior",
    layer: "Application",
    longDescription: "WAFs inspect HTTP traffic and block requests matching known attack patterns. Modern WAFs use machine learning to detect anomalies and can stop application-layer attacks that volumetric defenses miss.",
    implementation: "Deploy Cloudflare, AWS WAF, or ModSecurity with OWASP rules",
  },
  {
    name: "CDN Protection",
    description: "Absorb traffic with distributed edge nodes worldwide",
    layer: "Network/Application",
    longDescription: "CDNs have massive distributed infrastructure that can absorb volumetric attacks. They cache content at edge locations and only forward legitimate requests to origin servers.",
    implementation: "Use Cloudflare, Akamai, or AWS CloudFront with DDoS protection enabled",
  },
  {
    name: "BGP Flowspec",
    description: "Distribute filtering rules via BGP to block attacks at network edge",
    layer: "Network",
    longDescription: "Flowspec extends BGP to distribute traffic filtering rules to routers. This allows ISPs to drop attack traffic at the network edge before it reaches your infrastructure.",
    implementation: "Requires BGP-capable routers and ISP support for Flowspec",
  },
  {
    name: "SYN Cookies",
    description: "Defend against SYN floods without using connection table memory",
    layer: "Network",
    longDescription: "Instead of storing half-open connections, the server encodes connection state in the sequence number. Only completed handshakes consume memory.",
    implementation: "sysctl -w net.ipv4.tcp_syncookies=1",
  },
  {
    name: "Scrubbing Centers",
    description: "Route traffic through cleaning facilities during attacks",
    layer: "Network",
    longDescription: "Dedicated facilities that analyze traffic and filter out attack packets while forwarding legitimate traffic. Traffic is rerouted via BGP or DNS during active attacks.",
    implementation: "Contract with providers like Akamai Prolexic, Cloudflare Magic Transit, or Radware",
  },
];

const botnets = [
  { 
    name: "Mirai", 
    target: "IoT devices", 
    peakSize: "600+ Gbps",
    year: "2016",
    description: "Scans for IoT devices using default credentials. Source code was publicly released, spawning many variants.",
    notableAttacks: ["Dyn DNS (2016)", "OVH (1.1 Tbps)", "KrebsOnSecurity (620 Gbps)"],
  },
  { 
    name: "Meris", 
    target: "MikroTik routers", 
    peakSize: "21.8M RPS",
    year: "2021",
    description: "Exploits vulnerable MikroTik RouterOS devices. Known for record-breaking HTTP request floods.",
    notableAttacks: ["Yandex (21.8M RPS)", "Cloudflare customers"],
  },
  { 
    name: "Mozi", 
    target: "IoT/Routers", 
    peakSize: "Variable",
    year: "2019",
    description: "P2P botnet using DHT for C2. Combines code from Gafgyt, Mirai, and IoT Reaper.",
    notableAttacks: ["Responsible for 90% of IoT attacks in 2020"],
  },
  { 
    name: "Mantis", 
    target: "VMs/Servers", 
    peakSize: "26M RPS",
    year: "2022",
    description: "Uses hijacked virtual machines and servers rather than IoT devices for more powerful attacks.",
    notableAttacks: ["Cloudflare (26M RPS HTTP flood)"],
  },
];

const detectionIndicators = [
  { indicator: "Sudden spike in traffic from single IP or range", severity: "high", tool: "NetFlow, firewall logs" },
  { indicator: "Unusual traffic patterns (same packet size, timing)", severity: "high", tool: "Wireshark, tcpdump" },
  { indicator: "High volume of requests to single endpoint", severity: "medium", tool: "Web server logs, WAF" },
  { indicator: "Geographic anomalies in traffic sources", severity: "medium", tool: "GeoIP analysis, SIEM" },
  { indicator: "Protocol anomalies (malformed packets)", severity: "high", tool: "IDS/IPS, packet analysis" },
  { indicator: "Server resource exhaustion without legitimate cause", severity: "high", tool: "System monitoring, APM" },
  { indicator: "Increase in TCP half-open connections", severity: "high", tool: "netstat, ss command" },
  { indicator: "DNS query rate spike for non-existent domains", severity: "medium", tool: "DNS logs, BIND statistics" },
];

const attackLifecycle = [
  { label: "Reconnaissance", description: "Attacker identifies target, maps infrastructure, finds vulnerabilities in DDoS defenses" },
  { label: "Weaponization", description: "Builds or rents botnet, configures attack tools, tests amplification vectors" },
  { label: "Attack Launch", description: "Initiates DDoS attack, often starting small to test defenses before full-scale assault" },
  { label: "Adaptation", description: "Monitors attack effectiveness, switches vectors or targets as defenses respond" },
  { label: "Persistence", description: "Maintains attack pressure, may demand ransom or continue until objectives met" },
];

const legalConsiderations = [
  { law: "Computer Fraud and Abuse Act (CFAA)", jurisdiction: "United States", penalty: "Up to 10 years imprisonment, $500K+ fines" },
  { law: "Computer Misuse Act 1990", jurisdiction: "United Kingdom", penalty: "Up to 10 years imprisonment" },
  { law: "Criminal Code Section 342.1", jurisdiction: "Canada", penalty: "Up to 10 years imprisonment" },
  { law: "Cybercrime Act 2001", jurisdiction: "Australia", penalty: "Up to 10 years imprisonment" },
  { law: "IT Act Section 66", jurisdiction: "India", penalty: "Up to 3 years imprisonment" },
];

const keyMetrics = [
  { metric: "Bandwidth (bps)", meaning: "Total inbound volume on links", defense: "Trigger upstream scrubbing or CDN absorption" },
  { metric: "Packet rate (pps)", meaning: "Packets per second hitting devices", defense: "Protect routers and firewalls from CPU exhaustion" },
  { metric: "Request rate (rps)", meaning: "Application requests per second", defense: "Apply WAF rules and per-endpoint rate limits" },
  { metric: "Concurrent connections", meaning: "Open and half-open TCP connections", defense: "Tune timeouts, enable SYN cookies" },
  { metric: "Latency and error rate", meaning: "User-visible degradation", defense: "Activate load shedding and incident response" },
];

const commonTargets = [
  { name: "DNS resolvers and authoritative DNS", icon: <DnsIcon /> },
  { name: "Load balancers, API gateways, and reverse proxies", icon: <RouterIcon /> },
  { name: "CDN edges and origin servers", icon: <CloudIcon /> },
  { name: "Login, search, checkout, and upload endpoints", icon: <HttpIcon /> },
  { name: "Stateful services like databases or auth backends", icon: <StorageIcon /> },
  { name: "Gaming, streaming, and VoIP services", icon: <PublicIcon /> },
];

const impactChain = [
  "Link saturation increases latency and packet loss.",
  "Health checks fail and autoscaling triggers.",
  "Caches miss and origin traffic spikes.",
  "Databases and shared services become bottlenecks.",
  "Users see timeouts, errors, and degraded experience.",
];

const attackSignalMatrix = [
  { category: "Volumetric", signals: "Huge bps spikes, large UDP traffic", response: "Enable CDN/Anycast and upstream scrubbing" },
  { category: "Protocol", signals: "High pps, many half-open connections", response: "SYN cookies, connection limits, ACLs" },
  { category: "Application", signals: "High rps to expensive endpoints", response: "WAF rules, rate limits, caching" },
];

const appLayerHotspots = [
  "Authentication and login endpoints",
  "Search and filtering endpoints with heavy queries",
  "Checkout or payment flows",
  "File upload or report generation endpoints",
  "API endpoints with expensive database joins",
];

const protocolPressurePoints = [
  "TCP handshake state tables",
  "Firewall and load balancer connection tracking",
  "DNS resolver recursion and cache",
  "TLS handshakes and certificate validation",
  "UDP services without rate limits",
];

const hybridPatterns = [
  "Start with volumetric flood to distract, then switch to L7.",
  "Mix UDP reflection with HTTP floods for defense evasion.",
  "Pulse attacks in waves to bypass rate limits.",
];

const amplificationPrinciples = [
  "Amplification factor = response size / request size.",
  "Reflection hides the attacker by bouncing traffic off third parties.",
  "Spoofed source IPs are required for classic reflection attacks.",
  "Open resolvers and misconfigured services create large blast radius.",
];

const reflectionComparison = [
  { aspect: "Traffic source", reflection: "Third-party servers reply", amplification: "Third-party servers reply with larger payloads" },
  { aspect: "Spoofing needed", reflection: "Usually yes", amplification: "Yes for large scale" },
  { aspect: "Defender focus", reflection: "Block abusable services", amplification: "Block plus reduce response size" },
];

const spoofingControls = [
  "BCP38 and BCP84 ingress filtering at ISPs.",
  "Unicast RPF on edge routers.",
  "Egress filtering for your own networks.",
  "Drop spoofed RFC1918 and bogon ranges.",
];

const amplificationDefenderChecklist = [
  "Disable or restrict UDP services not needed publicly.",
  "Close open DNS resolvers and enable response rate limiting.",
  "Patch NTP and disable legacy queries like monlist.",
  "Secure Memcached with auth and no UDP exposure.",
  "Monitor outbound responses for size anomalies.",
];

const botnetLifecycle = [
  { label: "Infection", description: "Devices compromised via vulnerabilities or weak credentials." },
  { label: "Enrollment", description: "Bot registers with command infrastructure." },
  { label: "Command", description: "Bot receives attack config and targets." },
  { label: "Monetization", description: "Botnet rented, used for extortion or disruption." },
  { label: "Disruption", description: "Takedowns, sinkholes, or firmware updates remove bots." },
];

const infectionVectors = [
  "Default or reused passwords on IoT devices.",
  "Exposed admin services (Telnet, SSH, HTTP).",
  "Unpatched firmware and RCE vulnerabilities.",
  "Supply chain or device management compromise.",
  "Malicious downloads or fake updates.",
];

const c2Models = [
  { model: "Centralized (IRC/HTTP)", strengths: "Simple to control", weaknesses: "Single points of failure", defenderSignals: "Known C2 domains and IPs" },
  { model: "P2P", strengths: "Resilient to takedown", weaknesses: "Complex to manage", defenderSignals: "Unusual peer-to-peer traffic" },
  { model: "Fast-flux/DGA", strengths: "Hard to block", weaknesses: "Predictable patterns", defenderSignals: "Many DNS queries to new domains" },
];

const botnetDefenderSignals = [
  "Outbound scans to random IPs or ports.",
  "Repeated connections to rare domains.",
  "Traffic bursts aligned with global attack times.",
  "Devices communicating on unusual ports.",
];

const preparednessChecklist = [
  "Establish baseline traffic and capacity limits.",
  "Pre-contract upstream DDoS protection or CDN.",
  "Harden DNS, NTP, and UDP services.",
  "Create an incident communication plan.",
  "Test failover and rate limiting policies.",
];

const responseRunbook = [
  { label: "Detect and confirm", description: "Validate traffic anomalies against baseline metrics." },
  { label: "Triage scope", description: "Identify affected endpoints, regions, and protocols." },
  { label: "Engage partners", description: "Notify ISP/CDN/scrubbing provider with indicators." },
  { label: "Apply controls", description: "Enable rate limits, WAF rules, and filtering." },
  { label: "Monitor and adapt", description: "Watch for vector changes and tune defenses." },
  { label: "Recover and review", description: "Verify stability and document lessons learned." },
];

const postIncidentHardening = [
  "Tune rate limits based on observed traffic.",
  "Add caching or queueing to expensive endpoints.",
  "Improve logging and alert thresholds.",
  "Patch exposed services and close unused ports.",
];

const capacityPlanning = [
  { item: "Peak bps headroom", detail: "2x to 4x normal peak volume", owner: "Network/ISP" },
  { item: "Pps handling", detail: "Router and firewall line-rate pps", owner: "Network" },
  { item: "App rps budget", detail: "Per endpoint limits with caching", owner: "App team" },
  { item: "DNS resilience", detail: "Anycast DNS and secondary provider", owner: "Platform" },
];

const mitigationPitfalls = [
  "Blocking entire regions without business impact review.",
  "Over-reliance on IP blocking for botnets that rotate.",
  "Leaving cache bypass endpoints exposed.",
  "Not coordinating changes with upstream providers.",
];

const baselineMetrics = [
  "Normal bps, pps, and rps ranges by hour.",
  "Top endpoints and expected error rates.",
  "Average connection duration and handshake rates.",
  "Geographic distribution of legitimate users.",
  "Cache hit ratios and origin load.",
];

const flashCrowdComparison = [
  { signal: "User-agent diversity", flash: "Varied devices and browsers", ddos: "Uniform or missing UA" },
  { signal: "Request paths", flash: "Popular pages and assets", ddos: "Expensive endpoints or random paths" },
  { signal: "Session behavior", flash: "Natural navigation", ddos: "High repetition, no think time" },
  { signal: "Geo patterns", flash: "Matches marketing audience", ddos: "Odd or rotating geos" },
];

const forensicArtifacts = [
  "Packet captures of initial spike.",
  "WAF logs and blocked request samples.",
  "Top talker IP lists and ASN mapping.",
  "Error rates and latency graphs.",
  "Timeline of mitigation actions.",
];

const falsePositiveSources = [
  "Marketing campaigns or product launches.",
  "Misconfigured health checks or monitoring.",
  "Partner integrations with retry storms.",
  "Web crawlers or indexing spikes.",
];

const authorizationChecklist = [
  "Written permission and signed scope.",
  "Defined targets and allowed test windows.",
  "Traffic limits and abort criteria.",
  "On-call contacts for escalation.",
  "Logging and evidence handling plan.",
];

const scopeRules = [
  "Test only owned systems or explicitly authorized assets.",
  "Use lab or staging for experiments.",
  "Avoid impacting shared infrastructure or third parties.",
  "Do not attempt to bypass provider protections.",
];

const dataHandlingGuidelines = [
  "Minimize collection of user data in logs.",
  "Protect logs containing IPs or identifiers.",
  "Retain evidence only as long as required.",
  "Coordinate disclosure with stakeholders.",
];

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const DDoSAttackTechniquesPage: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const pageContext = `This page covers DDoS attack techniques including volumetric, protocol, and application layer attacks. Topics include amplification methods, botnet coordination, attack detection, traffic analysis, baseline metrics, response runbooks, and mitigation strategies.`;

  return (
    <LearnPageLayout pageTitle="DDoS Attack Techniques" pageContext={pageContext}>
    <Box sx={{ p: 3 }}>
      <Box sx={{ mb: 3 }}>
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2 }}
        />
      </Box>
      <Typography variant="h4" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <SecurityIcon color="error" />
        DDoS Attack Techniques
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Understanding Distributed Denial of Service attacks for defense and security research
      </Typography>

      <Alert severity="warning" sx={{ mb: 3 }}>
        <AlertTitle>Educational Purpose Only</AlertTitle>
        This content is for defensive security understanding and authorized penetration testing.
        Launching DDoS attacks against systems you don't own is illegal and unethical.
      </Alert>

      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab icon={<WarningIcon />} label="Overview" />
          <Tab icon={<CloudIcon />} label="Attack Types" />
          <Tab icon={<SpeedIcon />} label="Amplification" />
          <Tab icon={<RouterIcon />} label="Botnets" />
          <Tab icon={<ShieldIcon />} label="Mitigation" />
          <Tab icon={<NetworkCheckIcon />} label="Detection" />
          <Tab icon={<GavelIcon />} label="Legal & Ethics" />
        </Tabs>
      </Paper>

      {/* Tab 0: Overview */}
      <TabPanel value={tabValue} index={0}>
        <Typography variant="h5" gutterBottom>What is a DDoS Attack?</Typography>
        
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>Simple Explanation</AlertTitle>
          Imagine a popular restaurant that can serve 100 customers per hour. A DDoS attack is like 
          sending 10,000 fake customers to stand in line, making it impossible for real customers 
          to get served. The restaurant isn't broken - it's just overwhelmed.
        </Alert>

        <Typography paragraph>
          A <strong>Distributed Denial of Service (DDoS)</strong> attack attempts to make an online service 
          unavailable by overwhelming it with traffic from multiple sources. Unlike a simple DoS attack 
          (which comes from one source), DDoS attacks use thousands or millions of compromised computers, 
          making them much harder to stop.
        </Typography>

        <Typography paragraph>
          These attacks don't try to "hack" into systems or steal data - they simply try to make 
          services unavailable. Think of it as the difference between picking a lock (hacking) and 
          blocking the door with a crowd (DDoS).
        </Typography>

        <Divider sx={{ my: 3 }} />

        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <LightbulbIcon color="primary" />
          DoS vs DDoS: What's the Difference?
        </Typography>
        
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: "100%", borderLeft: "4px solid orange" }}>
              <CardContent>
                <Typography variant="h6">DoS (Denial of Service)</Typography>
                <List dense>
                  <ListItem><ListItemText primary="Single attack source" /></ListItem>
                  <ListItem><ListItemText primary="Easier to identify and block" /></ListItem>
                  <ListItem><ListItemText primary="Limited attack power" /></ListItem>
                  <ListItem><ListItemText primary="Example: One computer flooding a server" /></ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: "100%", borderLeft: "4px solid red" }}>
              <CardContent>
                <Typography variant="h6">DDoS (Distributed DoS)</Typography>
                <List dense>
                  <ListItem><ListItemText primary="Multiple attack sources (botnet)" /></ListItem>
                  <ListItem><ListItemText primary="Very difficult to mitigate" /></ListItem>
                  <ListItem><ListItemText primary="Can generate terabits of traffic" /></ListItem>
                  <ListItem><ListItemText primary="Example: 100,000 bots flooding a server" /></ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <TrendingUpIcon color="primary" />
          Key Metrics to Track
        </Typography>
        <TableContainer component={Paper} sx={{ mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: "action.hover" }}>
                <TableCell><strong>Metric</strong></TableCell>
                <TableCell><strong>What It Tells You</strong></TableCell>
                <TableCell><strong>Defensive Use</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {keyMetrics.map((row) => (
                <TableRow key={row.metric}>
                  <TableCell>{row.metric}</TableCell>
                  <TableCell>{row.meaning}</TableCell>
                  <TableCell>{row.defense}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <PublicIcon color="primary" />
          Common Targets and Dependencies
        </Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {commonTargets.map((target) => (
              <ListItem key={target.name}>
                <ListItemIcon>{target.icon}</ListItemIcon>
                <ListItemText primary={target.name} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <GroupsIcon color="primary" />
          Who Launches DDoS Attacks and Why?
        </Typography>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[
            { title: "Hacktivists", icon: <PublicIcon />, reason: "Political protest, drawing attention to causes" },
            { title: "Competitors", icon: <MonetizationOnIcon />, reason: "Disrupting rival businesses, especially during peak times" },
            { title: "Extortionists", icon: <WarningIcon />, reason: "Ransom DDoS (RDoS) - demanding payment to stop attacks" },
            { title: "Nation States", icon: <GavelIcon />, reason: "Cyber warfare, disrupting critical infrastructure" },
            { title: "Script Kiddies", icon: <ComputerIcon />, reason: "Bragging rights, testing skills, causing chaos for fun" },
            { title: "Disgruntled Users", icon: <BugReportIcon />, reason: "Revenge against companies or gaming servers" },
          ].map((actor) => (
            <Grid item xs={12} sm={6} md={4} key={actor.title}>
              <Card>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    {actor.icon}
                    <Typography variant="subtitle1" fontWeight="bold">{actor.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">{actor.reason}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <AccessTimeIcon color="primary" />
          Attack Lifecycle
        </Typography>

        <Stepper orientation="vertical" sx={{ mb: 3 }}>
          {attackLifecycle.map((step, index) => (
            <Step key={step.label} active>
              <StepLabel>{step.label}</StepLabel>
              <StepContent>
                <Typography>{step.description}</Typography>
              </StepContent>
            </Step>
          ))}
        </Stepper>

        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <TrendingUpIcon color="primary" />
          Service Impact Chain
        </Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {impactChain.map((item) => (
              <ListItem key={item}>
                <ListItemIcon>
                  <TrendingUpIcon color="warning" />
                </ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <MonetizationOnIcon color="primary" />
          Real-World Impact & Costs
        </Typography>

        <Alert severity="error" sx={{ mb: 2 }}>
          The average cost of a DDoS attack to a business is <strong>$40,000 per hour</strong> of downtime. 
          For large enterprises, this can exceed <strong>$1 million per hour</strong>.
        </Alert>

        <Grid container spacing={2}>
          {[
            { stat: "$2.5M+", label: "Average total cost per attack", desc: "Including lost revenue, recovery, reputation damage" },
            { stat: "6 hours", label: "Average attack duration", desc: "Though some last days or weeks" },
            { stat: "2.9 Tbps", label: "Largest recorded attack", desc: "Microsoft Azure, November 2021" },
            { stat: "15.3M", label: "DDoS attacks in 2023", desc: "One attack every 2 seconds globally" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.label}>
              <Card sx={{ textAlign: "center" }}>
                <CardContent>
                  <Typography variant="h4" color="error.main">{item.stat}</Typography>
                  <Typography variant="subtitle2" fontWeight="bold">{item.label}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Tab 1: Attack Types */}
      <TabPanel value={tabValue} index={1}>
        <Typography variant="h5" gutterBottom>Attack Categories</Typography>
        
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>The Three Layers of DDoS</AlertTitle>
          DDoS attacks target different parts of the network stack. Understanding which layer is being 
          attacked is crucial for choosing the right defense. Most sophisticated attacks combine multiple types.
        </Alert>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={4}>
            <Card sx={{ height: "100%", bgcolor: "error.dark" }}>
              <CardContent>
                <Typography variant="h6" color="white">Volumetric (Layer 3/4)</Typography>
                <Typography color="rgba(255,255,255,0.8)" variant="body2">
                  Measured in: <strong>Gbps/Tbps</strong>
                </Typography>
                <Typography color="rgba(255,255,255,0.7)" variant="body2">
                  Goal: Saturate bandwidth
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card sx={{ height: "100%", bgcolor: "warning.dark" }}>
              <CardContent>
                <Typography variant="h6" color="white">Protocol (Layer 3/4)</Typography>
                <Typography color="rgba(255,255,255,0.8)" variant="body2">
                  Measured in: <strong>Packets/sec</strong>
                </Typography>
                <Typography color="rgba(255,255,255,0.7)" variant="body2">
                  Goal: Exhaust state tables
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card sx={{ height: "100%", bgcolor: "info.dark" }}>
              <CardContent>
                <Typography variant="h6" color="white">Application (Layer 7)</Typography>
                <Typography color="rgba(255,255,255,0.8)" variant="body2">
                  Measured in: <strong>Requests/sec</strong>
                </Typography>
                <Typography color="rgba(255,255,255,0.7)" variant="body2">
                  Goal: Crash applications
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        
        {attackCategories.map((category) => (
          <Accordion key={category.name} defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                {category.icon}
                <Typography variant="h6">{category.name}</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Alert severity="info" sx={{ mb: 2 }}>{category.longDescription}</Alert>
              
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell><strong>Technique</strong></TableCell>
                      <TableCell><strong>How It Works</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {category.techniques.map((tech) => (
                      <TableRow key={tech.name}>
                        <TableCell>
                          <Chip label={tech.name} size="small" color="primary" />
                        </TableCell>
                        <TableCell>{tech.description}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        ))}

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>Signals and First Response</Typography>
        <TableContainer component={Paper} sx={{ mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: "action.hover" }}>
                <TableCell><strong>Category</strong></TableCell>
                <TableCell><strong>Common Signals</strong></TableCell>
                <TableCell><strong>First Response</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {attackSignalMatrix.map((row) => (
                <TableRow key={row.category}>
                  <TableCell>{row.category}</TableCell>
                  <TableCell>{row.signals}</TableCell>
                  <TableCell>{row.response}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <HttpIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Application Layer Hotspots
                </Typography>
                <List dense>
                  {appLayerHotspots.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon><HttpIcon fontSize="small" /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <NetworkCheckIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Protocol Pressure Points
                </Typography>
                <List dense>
                  {protocolPressurePoints.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon><NetworkCheckIcon fontSize="small" /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        <Typography variant="h6" sx={{ mb: 2 }}>Multi-Vector Patterns</Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {hybridPatterns.map((item) => (
              <ListItem key={item}>
                <ListItemIcon><WarningIcon color="warning" fontSize="small" /></ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>SYN Flood Explained (Visual)</Typography>
        <CodeBlock language="diagram">
{`Normal TCP Handshake:          SYN Flood Attack:
Client    Server               Attacker   Server
  |         |                     |          |
  |--SYN--->|                     |--SYN---->| (Spoofed IP)
  |<-SYN/ACK|                     |--SYN---->| (Spoofed IP)
  |--ACK--->|                     |--SYN---->| (Spoofed IP)
  |Connected|                     |    ...   | 
                                  |          |
                                  Server waits for ACK
                                  that never comes...
                                  Connection table fills up
                                  Legitimate users can't connect`}
        </CodeBlock>
      </TabPanel>

      {/* Tab 2: Amplification */}
      <TabPanel value={tabValue} index={2}>
        <Typography variant="h5" gutterBottom>Amplification Attacks</Typography>
        
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>What is Amplification?</AlertTitle>
          Amplification attacks use third-party servers to multiply attack traffic. The attacker sends 
          small requests with the victim's spoofed IP address, and the servers send much larger responses 
          to the victim. It's like writing 100 postcards requesting catalogs with someone else's return address.
        </Alert>

        <Typography variant="h6" gutterBottom>How Amplification Works</Typography>
        <CodeBlock language="diagram">
{`Attacker (1 Mbps)                    Victim
      |                                 |
      |-- Small request (spoofed IP)-->|
      |      to 1000 DNS servers        |
      |                                 |
      |   DNS servers send              |
      |   large responses               |
      |        (50x larger)             |
      |                                 |
      |                     <-----------| 50 Gbps flood!
      
Example: 1 Mbps × 50x amplification × 1000 servers = 50 Gbps attack`}
        </CodeBlock>
        
        <Typography variant="h6" gutterBottom>Amplification Principles</Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {amplificationPrinciples.map((item) => (
              <ListItem key={item}>
                <ListItemIcon><SpeedIcon color="warning" fontSize="small" /></ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" gutterBottom>Reflection vs Amplification</Typography>
        <TableContainer component={Paper} sx={{ mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: "action.hover" }}>
                <TableCell><strong>Aspect</strong></TableCell>
                <TableCell><strong>Reflection</strong></TableCell>
                <TableCell><strong>Amplification</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {reflectionComparison.map((row) => (
                <TableRow key={row.aspect}>
                  <TableCell>{row.aspect}</TableCell>
                  <TableCell>{row.reflection}</TableCell>
                  <TableCell>{row.amplification}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <ShieldIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Source Spoofing Controls
                </Typography>
                <List dense>
                  {spoofingControls.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon><ShieldIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <SecurityIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Defender Checklist
                </Typography>
                <List dense>
                  {amplificationDefenderChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon><SecurityIcon color="primary" fontSize="small" /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>Amplification Vectors</Typography>
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: "action.hover" }}>
                <TableCell><strong>Protocol</strong></TableCell>
                <TableCell><strong>Amplification</strong></TableCell>
                <TableCell><strong>Port</strong></TableCell>
                <TableCell><strong>Description</strong></TableCell>
                <TableCell><strong>Prevention</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {amplificationVectors.map((row) => (
                <TableRow key={row.protocol}>
                  <TableCell>
                    <Chip label={row.protocol} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={row.amplification} 
                      color={parseInt(row.amplification.replace(/[^0-9]/g, "")) > 100 ? "error" : "warning"} 
                      size="small" 
                    />
                  </TableCell>
                  <TableCell><code>{row.port}</code></TableCell>
                  <TableCell><Typography variant="body2">{row.description}</Typography></TableCell>
                  <TableCell><Typography variant="body2" color="success.main">{row.prevention}</Typography></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Alert severity="warning" sx={{ mt: 3 }}>
          <AlertTitle>Memcached: The Most Dangerous Amplifier</AlertTitle>
          In 2018, GitHub was hit with a 1.35 Tbps attack using Memcached amplification. A single 
          attacker with just 100 Mbps of bandwidth could theoretically generate 5 Tbps of attack traffic 
          using misconfigured Memcached servers.
        </Alert>

        <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>DNS Amplification Attack Example</Typography>
        <CodeBlock language="bash">
{`# Legitimate DNS query (small):
dig ANY google.com @8.8.8.8
# Request size: ~40 bytes

# Response size: ~3000 bytes (75x amplification)

# Attack command (DO NOT USE):
# Attacker spoofs victim's IP and sends queries to open resolvers
# hping3 --udp -p 53 --spoof <victim_ip> -d 40 <open_resolver>

# Detection: Look for large outbound DNS responses
tcpdump -i eth0 'udp port 53 and udp[10:2] > 512'`}
        </CodeBlock>
      </TabPanel>

      {/* Tab 3: Botnets */}
      <TabPanel value={tabValue} index={3}>
        <Typography variant="h5" gutterBottom>Botnets & Attack Infrastructure</Typography>
        
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>What is a Botnet?</AlertTitle>
          A botnet is a network of compromised computers (called "bots" or "zombies") controlled by 
          an attacker. These infected devices can be commanded to attack targets simultaneously, 
          making the attack distributed and very difficult to stop.
        </Alert>

        <Typography paragraph>
          Modern botnets primarily target <strong>IoT devices</strong> (cameras, routers, smart home devices) 
          because they often have weak security, are always connected, and users rarely update them. 
          A botnet of 100,000 IoT devices can generate massive attack traffic.
        </Typography>

        <Typography variant="h6" sx={{ mb: 2 }}>Botnet Lifecycle</Typography>
        <Stepper orientation="vertical" sx={{ mb: 3 }}>
          {botnetLifecycle.map((step) => (
            <Step key={step.label} active>
              <StepLabel>{step.label}</StepLabel>
              <StepContent>
                <Typography>{step.description}</Typography>
              </StepContent>
            </Step>
          ))}
        </Stepper>

        <Typography variant="h6" gutterBottom>Command and Control Models</Typography>
        <TableContainer component={Paper} sx={{ mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: "action.hover" }}>
                <TableCell><strong>Model</strong></TableCell>
                <TableCell><strong>Strengths</strong></TableCell>
                <TableCell><strong>Weaknesses</strong></TableCell>
                <TableCell><strong>Defender Signals</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {c2Models.map((row) => (
                <TableRow key={row.model}>
                  <TableCell>{row.model}</TableCell>
                  <TableCell>{row.strengths}</TableCell>
                  <TableCell>{row.weaknesses}</TableCell>
                  <TableCell>{row.defenderSignals}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <BugReportIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Common Infection Vectors
                </Typography>
                <List dense>
                  {infectionVectors.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon><BugReportIcon fontSize="small" /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <SearchIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Signs of Bot Activity
                </Typography>
                <List dense>
                  {botnetDefenderSignals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon><SearchIcon fontSize="small" /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        <Typography variant="h6" sx={{ mb: 2 }}>Famous Botnets</Typography>
        <Grid container spacing={2}>
          {botnets.map((botnet) => (
            <Grid item xs={12} md={6} key={botnet.name}>
              <Card sx={{ height: "100%" }}>
                <CardContent>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="h6">{botnet.name}</Typography>
                    <Chip label={botnet.year} size="small" color="primary" />
                  </Box>
                  <Typography variant="body2" paragraph>{botnet.description}</Typography>
                  <Box sx={{ mb: 1 }}>
                    <Typography variant="caption" color="text.secondary">Target:</Typography>
                    <Typography variant="body2">{botnet.target}</Typography>
                  </Box>
                  <Box sx={{ mb: 1 }}>
                    <Typography variant="caption" color="text.secondary">Peak Attack Size:</Typography>
                    <Chip label={botnet.peakSize} size="small" color="error" sx={{ ml: 1 }} />
                  </Box>
                  <Typography variant="caption" color="text.secondary">Notable Attacks:</Typography>
                  <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 0.5 }}>
                    {botnet.notableAttacks.map((attack) => (
                      <Chip key={attack} label={attack} size="small" variant="outlined" />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>Botnet Architecture</Typography>
        <CodeBlock language="diagram">
{`                    ┌─────────────────┐
                    │   Attacker /    │
                    │   Bot Herder    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  C2 Server(s)   │  Command & Control
                    │  (Command and   │  - IRC, HTTP, P2P
                    │   Control)      │  - Tor hidden services
                    └────────┬────────┘
                             │
         ┌───────────┬───────┴───────┬───────────┐
         ▼           ▼               ▼           ▼
    ┌─────────┐ ┌─────────┐    ┌─────────┐ ┌─────────┐
    │  Bot 1  │ │  Bot 2  │    │ Bot 999 │ │Bot 1000 │
    │ (IoT)   │ │ (Router)│    │  (PC)   │ │(Camera) │
    └────┬────┘ └────┬────┘    └────┬────┘ └────┬────┘
         │           │              │           │
         └───────────┴──────┬───────┴───────────┘
                            ▼
                    ┌───────────────┐
                    │    VICTIM     │
                    │   (Target)    │
                    └───────────────┘`}
        </CodeBlock>

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>DDoS-for-Hire Services ("Booters/Stressers")</Typography>
        <Alert severity="error" sx={{ mb: 2 }}>
          DDoS-for-hire services (marketed as "stress testing") are illegal when used against targets 
          without authorization. Despite law enforcement takedowns, these services persist and cost as 
          little as $20-50 per attack.
        </Alert>

        <Grid container spacing={2}>
          {[
            { title: "How They Work", items: ["Web-based control panel", "Payment via cryptocurrency", "Choose target, duration, attack type", "Uses shared botnet infrastructure"] },
            { title: "Law Enforcement Response", items: ["Operation Power Off (2018+)", "Hundreds of services seized", "Users have been prosecuted", "Many services are FBI honeypots"] },
          ].map((section) => (
            <Grid item xs={12} md={6} key={section.title}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>{section.title}</Typography>
                  <List dense>
                    {section.items.map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon><BugReportIcon fontSize="small" /></ListItemIcon>
                        <ListItemText primary={item} />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Tab 4: Mitigation */}
      <TabPanel value={tabValue} index={4}>
        <Typography variant="h5" gutterBottom>Mitigation Strategies</Typography>
        
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>Defense in Depth</AlertTitle>
          No single solution stops all DDoS attacks. Effective defense requires multiple layers of 
          protection, from network-level filtering to application-aware inspection. The goal is to 
          filter attack traffic while allowing legitimate users through.
        </Alert>

        <Typography variant="h6" gutterBottom>Preparation Checklist</Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {preparednessChecklist.map((item) => (
              <ListItem key={item}>
                <ListItemIcon><ShieldIcon color="success" fontSize="small" /></ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" gutterBottom>Mitigation Layers</Typography>
        <CodeBlock language="diagram">
{`Internet Traffic
        │
        ▼
┌───────────────────────────────┐
│  ISP / Upstream Filtering     │  ← BGP Flowspec, Black hole routing
│  (Filter at network edge)     │
└───────────────┬───────────────┘
                ▼
┌───────────────────────────────┐
│  CDN / Scrubbing Center       │  ← Anycast, traffic scrubbing
│  (Absorb volumetric attacks)  │
└───────────────┬───────────────┘
                ▼
┌───────────────────────────────┐
│  Load Balancer / WAF          │  ← Rate limiting, bot detection
│  (Filter application attacks) │
└───────────────┬───────────────┘
                ▼
┌───────────────────────────────┐
│  Your Server / Application    │  ← Connection limits, timeouts
└───────────────────────────────┘`}
        </CodeBlock>
        
        <Grid container spacing={2} sx={{ mt: 2 }}>
          {mitigationStrategies.map((strategy) => (
            <Grid item xs={12} md={6} key={strategy.name}>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <ShieldIcon color="success" />
                    <Typography variant="subtitle1" fontWeight="bold">{strategy.name}</Typography>
                    <Chip label={strategy.layer} size="small" sx={{ ml: "auto" }} />
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>{strategy.longDescription}</Typography>
                  <Typography variant="subtitle2" color="primary">Implementation:</Typography>
                  <CodeBlock language="config">{strategy.implementation}</CodeBlock>
                </AccordionDetails>
              </Accordion>
            </Grid>
          ))}
        </Grid>

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>Quick Wins: Essential Configurations</Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold">Linux Kernel Hardening</Typography>
                <CodeBlock language="bash">
{`# Enable SYN cookies
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Reduce SYN-ACK retries
echo 2 > /proc/sys/net/ipv4/tcp_synack_retries

# Increase backlog queue
echo 4096 > /proc/sys/net/core/netdev_max_backlog

# Ignore ICMP broadcasts
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts`}
                </CodeBlock>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold">Nginx Rate Limiting</Typography>
                <CodeBlock language="nginx">
{`# Define rate limit zone
limit_req_zone $binary_remote_addr 
    zone=one:10m rate=10r/s;

# Apply to location
location /api/ {
    limit_req zone=one burst=20 nodelay;
    limit_req_status 429;
}

# Connection limits
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_conn addr 100;`}
                </CodeBlock>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>Incident Response Runbook</Typography>
        <Stepper orientation="vertical" sx={{ mb: 3 }}>
          {responseRunbook.map((step) => (
            <Step key={step.label} active>
              <StepLabel>{step.label}</StepLabel>
              <StepContent>
                <Typography>{step.description}</Typography>
              </StepContent>
            </Step>
          ))}
        </Stepper>

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>Capacity Planning Snapshot</Typography>
        <TableContainer component={Paper} sx={{ mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: "action.hover" }}>
                <TableCell><strong>Area</strong></TableCell>
                <TableCell><strong>Target</strong></TableCell>
                <TableCell><strong>Owner</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {capacityPlanning.map((row) => (
                <TableRow key={row.item}>
                  <TableCell>{row.item}</TableCell>
                  <TableCell>{row.detail}</TableCell>
                  <TableCell>{row.owner}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>Common Mitigation Pitfalls</Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {mitigationPitfalls.map((item) => (
              <ListItem key={item}>
                <ListItemIcon><WarningIcon color="warning" fontSize="small" /></ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>Post-Incident Hardening</Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {postIncidentHardening.map((item) => (
              <ListItem key={item}>
                <ListItemIcon><ShieldIcon color="success" fontSize="small" /></ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>
      </TabPanel>

      {/* Tab 5: Detection */}
      <TabPanel value={tabValue} index={5}>
        <Typography variant="h5" gutterBottom>Detection & Monitoring</Typography>
        
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>Early Detection is Critical</AlertTitle>
          The faster you detect an attack, the faster you can respond. Establish baseline traffic 
          patterns during normal operations so you can quickly identify anomalies. Automated alerting 
          is essential - attacks often start outside business hours.
        </Alert>

        <Typography variant="h6" gutterBottom>Baseline Metrics to Capture</Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {baselineMetrics.map((item) => (
              <ListItem key={item}>
                <ListItemIcon><TrendingUpIcon color="primary" fontSize="small" /></ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" gutterBottom>DDoS vs Flash Crowd</Typography>
        <TableContainer component={Paper} sx={{ mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: "action.hover" }}>
                <TableCell><strong>Signal</strong></TableCell>
                <TableCell><strong>Flash Crowd</strong></TableCell>
                <TableCell><strong>DDoS Pattern</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {flashCrowdComparison.map((row) => (
                <TableRow key={row.signal}>
                  <TableCell>{row.signal}</TableCell>
                  <TableCell>{row.flash}</TableCell>
                  <TableCell>{row.ddos}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Typography variant="h6" gutterBottom>Detection Indicators</Typography>
        <TableContainer component={Paper} sx={{ mb: 3 }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: "action.hover" }}>
                <TableCell><strong>Indicator</strong></TableCell>
                <TableCell><strong>Severity</strong></TableCell>
                <TableCell><strong>Detection Tool</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {detectionIndicators.map((item, idx) => (
                <TableRow key={idx}>
                  <TableCell>{item.indicator}</TableCell>
                  <TableCell>
                    <Chip 
                      label={item.severity} 
                      size="small" 
                      color={item.severity === "high" ? "error" : "warning"} 
                    />
                  </TableCell>
                  <TableCell><code>{item.tool}</code></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Typography variant="h6" gutterBottom>Detection Commands</Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <SearchIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Check Connection States
                </Typography>
                <CodeBlock language="bash">
{`# Count connections by state
ss -s

# Show SYN_RECV connections (SYN flood indicator)
netstat -ant | grep SYN_RECV | wc -l

# Top IPs by connection count
netstat -ntu | awk '{print $5}' | cut -d: -f1 | \\
  sort | uniq -c | sort -rn | head -20

# Watch connections in real-time
watch -n 1 'netstat -ant | wc -l'`}
                </CodeBlock>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <AnalyticsIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Traffic Analysis
                </Typography>
                <CodeBlock language="bash">
{`# Monitor bandwidth in real-time
iftop -i eth0

# Capture suspicious traffic
tcpdump -i eth0 -w capture.pcap \\
  'port 80 or port 443'

# Analyze with tshark
tshark -r capture.pcap -q -z io,stat,1

# Top talkers
tcpdump -tnn -c 10000 -i eth0 | \\
  awk '{print $3}' | cut -d. -f1-4 | \\
  sort | uniq -c | sort -rn | head`}
                </CodeBlock>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        <Typography variant="h6" gutterBottom>Artifacts to Capture</Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {forensicArtifacts.map((item) => (
              <ListItem key={item}>
                <ListItemIcon><AnalyticsIcon color="primary" fontSize="small" /></ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" gutterBottom>Common False Positives</Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {falsePositiveSources.map((item) => (
              <ListItem key={item}>
                <ListItemIcon><WarningIcon color="warning" fontSize="small" /></ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>Monitoring Architecture</Typography>
        <CodeBlock language="diagram">
{`┌─────────────────────────────────────────────────────────────┐
│                     Monitoring Stack                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐ │
│  │ NetFlow  │   │ Server   │   │ WAF/LB   │   │ App      │ │
│  │ Exporters│   │ Metrics  │   │ Logs     │   │ Logs     │ │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘ │
│       │              │              │              │        │
│       └──────────────┴──────────────┴──────────────┘        │
│                          │                                   │
│                  ┌───────▼───────┐                          │
│                  │  Log Aggregator│  (ELK, Splunk, Loki)    │
│                  │  + SIEM        │                          │
│                  └───────┬───────┘                          │
│                          │                                   │
│           ┌──────────────┼──────────────┐                   │
│           ▼              ▼              ▼                   │
│     ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│     │Dashboard │  │ Alerting │  │ Anomaly  │               │
│     │(Grafana) │  │(PagerDuty│  │Detection │               │
│     └──────────┘  └──────────┘  └──────────┘               │
│                                                              │
└─────────────────────────────────────────────────────────────┘`}
        </CodeBlock>
      </TabPanel>

      {/* Tab 6: Legal & Ethics */}
      <TabPanel value={tabValue} index={6}>
        <Typography variant="h5" gutterBottom>Legal & Ethical Considerations</Typography>
        
        <Alert severity="error" sx={{ mb: 3 }}>
          <AlertTitle>DDoS Attacks Are Serious Crimes</AlertTitle>
          In virtually every country, launching a DDoS attack against systems you don't own (or 
          don't have written permission to test) is a criminal offense. Penalties include 
          significant prison time and fines. Even "testing" services or attacking gaming servers 
          is illegal.
        </Alert>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <GavelIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Authorization Checklist
                </Typography>
                <List dense>
                  {authorizationChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon><GavelIcon fontSize="small" /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  <ShieldIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                  Scope and Rules of Engagement
                </Typography>
                <List dense>
                  {scopeRules.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon><ShieldIcon fontSize="small" /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        <Typography variant="h6" gutterBottom>Criminal Laws by Jurisdiction</Typography>
        <TableContainer component={Paper} sx={{ mb: 3 }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: "error.dark" }}>
                <TableCell sx={{ color: "white" }}><strong>Law</strong></TableCell>
                <TableCell sx={{ color: "white" }}><strong>Jurisdiction</strong></TableCell>
                <TableCell sx={{ color: "white" }}><strong>Maximum Penalty</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {legalConsiderations.map((item) => (
                <TableRow key={item.law}>
                  <TableCell>{item.law}</TableCell>
                  <TableCell>{item.jurisdiction}</TableCell>
                  <TableCell>
                    <Chip label={item.penalty} size="small" color="error" variant="outlined" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Typography variant="h6" gutterBottom>Data Handling and Privacy</Typography>
        <Paper sx={{ p: 2, mb: 3 }}>
          <List dense>
            {dataHandlingGuidelines.map((item) => (
              <ListItem key={item}>
                <ListItemIcon><ShieldIcon color="success" fontSize="small" /></ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Typography variant="h6" gutterBottom>What Can Get You Arrested</Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[
            { action: "Launching attacks", illegal: true, desc: "Even against 'deserving' targets" },
            { action: "Using booter/stresser services", illegal: true, desc: "You are liable for attacks you pay for" },
            { action: "Operating a botnet", illegal: true, desc: "Regardless of what you use it for" },
            { action: "Selling DDoS services", illegal: true, desc: "Even if marketed as 'stress testing'" },
            { action: "Testing your own systems", illegal: false, desc: "But document authorization" },
            { action: "Authorized penetration testing", illegal: false, desc: "With written permission only" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.action}>
              <Card sx={{ borderLeft: `4px solid ${item.illegal ? "red" : "green"}` }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    {item.illegal ? <WarningIcon color="error" /> : <ShieldIcon color="success" />}
                    <Typography variant="subtitle2" fontWeight="bold">{item.action}</Typography>
                  </Box>
                  <Chip 
                    label={item.illegal ? "ILLEGAL" : "Legal"} 
                    size="small" 
                    color={item.illegal ? "error" : "success"} 
                    sx={{ mb: 1 }}
                  />
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Typography variant="h6" gutterBottom>Ethical Security Research</Typography>
        <Alert severity="success" sx={{ mb: 2 }}>
          <AlertTitle>How to Study DDoS Legally</AlertTitle>
          <List dense>
            <ListItem>
              <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
              <ListItemText primary="Set up your own lab environment (VMs, isolated network)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
              <ListItemText primary="Use cloud providers' legitimate stress testing services" />
            </ListItem>
            <ListItem>
              <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
              <ListItemText primary="Study captured attack traffic (public datasets exist)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
              <ListItemText primary="Work in cybersecurity - get paid to defend against DDoS" />
            </ListItem>
            <ListItem>
              <ListItemIcon><ShieldIcon color="success" /></ListItemIcon>
              <ListItemText primary="Participate in CTF competitions with DDoS defense challenges" />
            </ListItem>
          </List>
        </Alert>

        <Typography variant="h6" gutterBottom>If You're a Victim</Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Immediate Response</Typography>
                <List dense>
                  <ListItem><ListItemText primary="1. Contact your ISP/hosting provider" /></ListItem>
                  <ListItem><ListItemText primary="2. Enable any DDoS protection services" /></ListItem>
                  <ListItem><ListItemText primary="3. Preserve logs for evidence" /></ListItem>
                  <ListItem><ListItemText primary="4. Don't pay ransom demands" /></ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Reporting</Typography>
                <List dense>
                  <ListItem><ListItemText primary="US: FBI IC3 (ic3.gov)" /></ListItem>
                  <ListItem><ListItemText primary="UK: Action Fraud / NCSC" /></ListItem>
                  <ListItem><ListItemText primary="EU: Local CERT/CSIRT" /></ListItem>
                  <ListItem><ListItemText primary="Include: timestamps, IPs, logs, damage estimate" /></ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>
    </Box>
    </LearnPageLayout>
  );
};

export default DDoSAttackTechniquesPage;
