import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
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
  Avatar,
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
import SchoolIcon from "@mui/icons-material/School";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import QuizIcon from "@mui/icons-material/Quiz";
import ScienceIcon from "@mui/icons-material/Science";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CancelIcon from "@mui/icons-material/Cancel";
import TimelineIcon from "@mui/icons-material/Timeline";
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

// =============================================================================
// PART 1: DDOS FUNDAMENTALS FOR BEGINNERS
// =============================================================================

const ddosFundamentals = {
  whatIsDDoS: {
    title: "What is a DDoS Attack?",
    icon: "🎯",
    beginnerExplanation: `Imagine you're trying to call a pizza place, but 10,000 people are also calling at the exact same time. 
The phone lines get jammed, and nobody can get through - including you with your legitimate order. 
That's essentially what a DDoS attack does to websites and online services.

DDoS stands for "Distributed Denial of Service". Let's break that down:
• DISTRIBUTED = The attack comes from many different computers at once
• DENIAL = The goal is to DENY access to legitimate users  
• SERVICE = The target is a service (website, game server, etc.)

The "distributed" part is what makes these attacks so dangerous. If 1,000 computers each send 1,000 requests 
per second, that's 1 MILLION requests per second hitting the target!`,
    technicalDetails: `A DDoS attack exploits the fundamental nature of how the internet works - servers must respond to requests.
By overwhelming the target with more requests than it can handle, attackers cause:
• Bandwidth exhaustion (network pipe is full)
• State table exhaustion (too many connections to track)
• CPU/Memory exhaustion (too much work to process)
• Application resource exhaustion (database connections, etc.)`,
    realWorldAnalogy: "Restaurant Analogy",
    analogyExplanation: `Think of a popular restaurant:
• Normal day: 100 customers/hour, kitchen handles it fine
• Flash mob attack: 10,000 people show up demanding service
• Result: Real customers can't get in, staff overwhelmed, chaos

The restaurant isn't "broken" - it's just overwhelmed. Same with DDoS targets.`,
    keyPoints: [
      "DDoS doesn't 'hack' into systems - it overwhelms them with traffic",
      "Attacks come from thousands or millions of sources simultaneously",
      "The goal is to make services unavailable, not to steal data",
      "Even the biggest companies can be affected (AWS, Google, Microsoft have been hit)",
      "Attacks can cost businesses $40,000+ per hour of downtime"
    ]
  },
  howInternetWorks: {
    title: "How the Internet Works (Simplified)",
    icon: "🌐",
    beginnerExplanation: `Before understanding DDoS, you need to understand the basics of how the internet works.

When you type "google.com" in your browser, here's what happens:
1. YOUR COMPUTER asks "Where is google.com?" (DNS lookup)
2. DNS server responds with an IP address (like 142.250.80.46)
3. Your computer sends a REQUEST to that IP address
4. Google's server sends back a RESPONSE (the webpage)
5. Your browser displays the page

This process involves PACKETS - small chunks of data that travel across networks.
Every web request involves multiple packets going back and forth.`,
    technicalDetails: `The internet uses a layered communication model:
• Layer 7 (Application): HTTP, HTTPS, DNS - what apps use
• Layer 4 (Transport): TCP, UDP - how data is delivered reliably
• Layer 3 (Network): IP - how packets find their destination

DDoS attacks can target ANY of these layers:
• Layer 7 attacks: Flood with HTTP requests (looks like real users)
• Layer 4 attacks: Flood with TCP/UDP packets (exhaust connections)
• Layer 3 attacks: Flood with raw packets (saturate bandwidth)`,
    keyPoints: [
      "Every internet interaction involves packets traveling between computers",
      "Servers have limited resources (bandwidth, memory, CPU, connections)",
      "When these limits are exceeded, the server can't serve legitimate users",
      "DDoS attacks work by exceeding these limits with fake traffic"
    ]
  },
  bandwidth: {
    title: "Understanding Bandwidth",
    icon: "📊",
    beginnerExplanation: `Bandwidth is like the width of a highway. A wider highway can handle more cars.
Internet bandwidth is measured in bits per second (bps):
• Kbps = 1,000 bits per second (kilobits)
• Mbps = 1,000,000 bits per second (megabits)
• Gbps = 1,000,000,000 bits per second (gigabits)
• Tbps = 1,000,000,000,000 bits per second (terabits)

Your home internet might be 100 Mbps. A typical web server might have 1 Gbps.
Large DDoS attacks can generate 1+ Tbps - that's 1000x more than most servers can handle!`,
    technicalDetails: `Bandwidth capacity vs actual usage:
• Provisioned bandwidth: What you pay for (e.g., 10 Gbps link)
• Baseline usage: Normal traffic (maybe 2 Gbps)
• Headroom: Available capacity (8 Gbps buffer)
• Attack threshold: Where problems start (>10 Gbps = saturated)

DDoS attacks fill up this "pipe" so legitimate traffic can't get through.
It's like a 4-lane highway where 100 cars try to merge at once.`,
    keyPoints: [
      "Bandwidth is the 'width of the pipe' for internet traffic",
      "Measured in bits per second (Mbps, Gbps, Tbps)",
      "Volumetric DDoS attacks try to fill up all available bandwidth",
      "Even 100 Mbps of attack traffic can overwhelm small servers"
    ]
  },
  packetsAndConnections: {
    title: "Packets and Connections",
    icon: "📦",
    beginnerExplanation: `Data on the internet travels in PACKETS - small chunks of information.
Think of packets like letters in the mail:
• Each packet has a source address (where it came from)
• Each packet has a destination address (where it's going)
• Each packet carries a small piece of data (payload)

A simple web page might require 50-100 packets to load.
A video stream might use thousands of packets per second.`,
    technicalDetails: `TCP Connections require a "handshake":
1. Client sends SYN ("Hello, I want to connect")
2. Server responds SYN-ACK ("Hello, I hear you, go ahead")
3. Client sends ACK ("Great, let's talk")
4. Connection is now "established"

The server must remember EACH connection in a "state table".
This table has LIMITED SIZE. If attackers fill it with fake half-open connections,
legitimate users can't connect. This is how SYN flood attacks work!`,
    keyPoints: [
      "Packets are small chunks of data with source/destination addresses",
      "TCP connections require a 3-way handshake",
      "Servers track connections in state tables (limited memory)",
      "Protocol attacks try to exhaust connection tracking resources"
    ]
  },
  dosVsDDoS: {
    title: "DoS vs DDoS: What's the Difference?",
    icon: "⚔️",
    beginnerExplanation: `DoS (Denial of Service) comes from ONE source.
DDoS (Distributed Denial of Service) comes from MANY sources.

Why does this matter?
• DoS from 1 IP: Easy to block that IP address
• DDoS from 100,000 IPs: Can't block them all without blocking real users!

It's like the difference between:
• One person crank-calling you repeatedly (DoS) - just block their number
• 10,000 different people calling you (DDoS) - how do you know who's real?`,
    technicalDetails: `Technical comparison:
DoS Attack:
• Single source IP address
• Limited attack bandwidth (attacker's connection)
• Easy to identify and filter
• Example: Single machine running LOIC

DDoS Attack:
• Thousands to millions of source IPs
• Combined bandwidth of entire botnet
• Hard to filter without affecting legitimate traffic
• Example: Mirai botnet with 400,000+ infected devices`,
    keyPoints: [
      "DoS = one attacker, DDoS = many attackers (distributed)",
      "Single-source attacks are easy to block",
      "Distributed attacks are much harder to mitigate",
      "Most modern attacks are DDoS using botnets"
    ]
  },
  attackMetrics: {
    title: "How DDoS Attacks Are Measured",
    icon: "📈",
    beginnerExplanation: `DDoS attacks are measured in three main ways:

1. BANDWIDTH (bps) - How much data per second
   • "A 100 Gbps attack" = 100 billion bits of traffic per second
   • Used for volumetric attacks that flood the network pipe

2. PACKETS (pps) - How many packets per second
   • "A 50 Mpps attack" = 50 million packets per second
   • Used for protocol attacks that exhaust state tables

3. REQUESTS (rps) - How many application requests per second
   • "A 10 Mrps attack" = 10 million HTTP requests per second
   • Used for application layer attacks`,
    technicalDetails: `Why different metrics matter:
• bps (bits per second): Measures link saturation
  - High bps = your internet connection is full
  - Mitigated by more bandwidth or upstream filtering

• pps (packets per second): Measures device processing
  - High pps = routers/firewalls can't keep up
  - Mitigated by hardware rate limiting

• rps (requests per second): Measures application load
  - High rps = web servers/databases overwhelmed
  - Mitigated by caching, WAF, rate limiting`,
    keyPoints: [
      "bps measures raw bandwidth consumption",
      "pps measures network device processing load",
      "rps measures application-level request load",
      "Different attack types optimize for different metrics"
    ]
  }
};

const expandedGlossary: Record<string, { term: string; definition: string; example: string; relatedTerms: string[]; difficulty: 'beginner' | 'intermediate' | 'advanced' }> = {
  ddos: {
    term: "DDoS (Distributed Denial of Service)",
    definition: "An attack where many computers flood a target with traffic simultaneously, making it unavailable to legitimate users.",
    example: "A botnet of 100,000 infected computers all sending traffic to amazon.com at once, causing the site to slow down or become unreachable.",
    relatedTerms: ["DoS", "Botnet", "Flood attack"],
    difficulty: "beginner"
  },
  botnet: {
    term: "Botnet",
    definition: "A network of computers infected with malware that can be remotely controlled to perform attacks without the owners' knowledge.",
    example: "The Mirai botnet consisted of 400,000+ infected IoT devices (cameras, routers) that were used to launch the 1.1 Tbps attack on OVH.",
    relatedTerms: ["Bot", "Zombie", "C2", "Malware"],
    difficulty: "beginner"
  },
  amplification: {
    term: "Amplification",
    definition: "A technique where attackers send small requests to servers that respond with much larger replies, multiplying the attack traffic.",
    example: "A 100-byte DNS query can generate a 3000-byte response (30x amplification). Memcached can amplify up to 51,000x!",
    relatedTerms: ["Reflection", "DNS amplification", "NTP amplification"],
    difficulty: "intermediate"
  },
  reflection: {
    term: "Reflection",
    definition: "Using third-party servers to bounce attack traffic to the victim by spoofing the source IP address.",
    example: "Attacker sends DNS query with victim's IP as source. DNS server sends large response to victim, not attacker.",
    relatedTerms: ["Amplification", "IP spoofing", "Open resolver"],
    difficulty: "intermediate"
  },
  synFlood: {
    term: "SYN Flood",
    definition: "An attack that exploits the TCP handshake by sending many SYN packets but never completing connections, exhausting server resources.",
    example: "Attacker sends 1 million SYN packets/sec with random source IPs. Server waits for ACKs that never come, filling connection table.",
    relatedTerms: ["TCP handshake", "SYN-ACK", "Connection table"],
    difficulty: "intermediate"
  },
  volumetric: {
    term: "Volumetric Attack",
    definition: "DDoS attacks that aim to saturate the target's bandwidth with massive amounts of traffic.",
    example: "UDP flood sending 500 Gbps of traffic to overwhelm a target with only 10 Gbps bandwidth capacity.",
    relatedTerms: ["Bandwidth", "UDP flood", "ICMP flood"],
    difficulty: "beginner"
  },
  layer7: {
    term: "Layer 7 / Application Layer",
    definition: "The top layer of the network stack where user applications operate (HTTP, HTTPS, DNS). Layer 7 attacks target application logic.",
    example: "HTTP flood sending millions of legitimate-looking web requests to exhaust web server resources.",
    relatedTerms: ["HTTP flood", "Slowloris", "OSI model"],
    difficulty: "intermediate"
  },
  scrubbing: {
    term: "Scrubbing Center",
    definition: "Specialized facilities that filter DDoS traffic by analyzing and separating malicious packets from legitimate traffic.",
    example: "During an attack, traffic is routed through Cloudflare's scrubbing center, which drops attack packets and forwards clean traffic.",
    relatedTerms: ["Traffic cleaning", "Mitigation", "CDN"],
    difficulty: "intermediate"
  },
  anycast: {
    term: "Anycast",
    definition: "A network routing method where the same IP address is announced from multiple locations, distributing traffic globally.",
    example: "Cloudflare announces the same IP from 200+ data centers. Attack traffic is automatically spread across all locations.",
    relatedTerms: ["BGP", "Load balancing", "CDN"],
    difficulty: "advanced"
  },
  rateLimit: {
    term: "Rate Limiting",
    definition: "Restricting the number of requests a single source can make in a given time period.",
    example: "API allows 100 requests per minute per IP. The 101st request gets blocked with '429 Too Many Requests'.",
    relatedTerms: ["Throttling", "WAF", "Traffic shaping"],
    difficulty: "beginner"
  },
  c2: {
    term: "C2 / Command and Control",
    definition: "The infrastructure attackers use to control their botnet and coordinate attacks.",
    example: "Bot-infected devices connect to a C2 server via IRC, HTTP, or P2P to receive attack commands and targets.",
    relatedTerms: ["Botnet", "Bot herder", "Malware"],
    difficulty: "intermediate"
  },
  blackhole: {
    term: "Black Hole Routing",
    definition: "Discarding all traffic destined to a specific IP address to protect the rest of the network during an attack.",
    example: "ISP null-routes victim's IP during massive attack. Victim goes offline but rest of ISP's customers are protected.",
    relatedTerms: ["Null routing", "RTBH", "BGP"],
    difficulty: "advanced"
  },
  slowloris: {
    term: "Slowloris",
    definition: "An application-layer attack that opens many connections to a web server and keeps them open by sending partial HTTP requests very slowly.",
    example: "Attacker opens 10,000 connections, each sending 1 byte every 10 seconds. Server waits for complete requests that never finish.",
    relatedTerms: ["HTTP flood", "Connection exhaustion", "Layer 7"],
    difficulty: "intermediate"
  },
  synCookies: {
    term: "SYN Cookies",
    definition: "A defense technique where servers encode connection state in the TCP sequence number instead of storing it, preventing SYN flood attacks.",
    example: "Instead of storing 100,000 half-open connections, server encodes state in sequence number and only stores completed connections.",
    relatedTerms: ["SYN flood", "TCP handshake", "Connection table"],
    difficulty: "advanced"
  },
  pps: {
    term: "PPS (Packets Per Second)",
    definition: "A metric measuring how many network packets are being transmitted per second. High PPS can overwhelm network devices.",
    example: "A 50 Mpps attack sends 50 million packets per second, potentially overwhelming router CPU regardless of bandwidth.",
    relatedTerms: ["Bandwidth", "bps", "rps"],
    difficulty: "intermediate"
  }
};

const visualLearningAids = {
  ddosVsDosDiagram: `
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DoS vs DDoS Comparison                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   DoS (Single Source)              DDoS (Distributed)                        │
│                                                                              │
│       ┌─────────┐                     ┌─────┐ ┌─────┐ ┌─────┐               │
│       │Attacker │                     │Bot 1│ │Bot 2│ │Bot 3│               │
│       └────┬────┘                     └──┬──┘ └──┬──┘ └──┬──┘               │
│            │                             │       │       │                   │
│            │ Traffic                     │       │       │                   │
│            │                             └───────┼───────┘                   │
│            │                                     │ Combined                  │
│            │                                     │ Traffic                   │
│            ▼                                     ▼                           │
│       ┌─────────┐                          ┌─────────┐                       │
│       │ Target  │                          │ Target  │                       │
│       └─────────┘                          └─────────┘                       │
│                                                                              │
│   • Easy to block (1 IP)               • Hard to block (1000s of IPs)        │
│   • Limited bandwidth                  • Massive combined bandwidth          │
│   • Simple to trace                    • Complex to investigate              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘`,
  bandwidthPipeDiagram: `
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Bandwidth as a Pipe (Visual)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   NORMAL TRAFFIC:                                                            │
│   ╔═══════════════════════════════════════════════════════════════════════╗ │
│   ║ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ ║ │
│   ║ ░░░░ LEGITIMATE TRAFFIC (30%) ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ ║ │
│   ║ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ ║ │
│   ╚═══════════════════════════════════════════════════════════════════════╝ │
│   [====================                                    ] 30% Used        │
│   Plenty of room for more traffic ✓                                          │
│                                                                              │
│   DURING DDOS ATTACK:                                                        │
│   ╔═══════════════════════════════════════════════════════════════════════╗ │
│   ║ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ║ │
│   ║ ▓▓▓▓ ATTACK TRAFFIC (95%) ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░ LEGIT (5%) ░░ ║ │
│   ║ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ║ │
│   ╚═══════════════════════════════════════════════════════════════════════╝ │
│   [════════════════════════════════════════════════════════] 100% SATURATED │
│   Legitimate traffic gets dropped! ✗                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘`,
  tcpHandshakeDiagram: `
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TCP 3-Way Handshake Explained                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Normal TCP Connection:           SYN Flood Attack:                         │
│                                                                              │
│   Client         Server            Attacker         Server                   │
│     │              │                  │               │                      │
│     │──── SYN ────►│  "Can I         │──── SYN ────►│  Spoofed IP            │
│     │              │   connect?"     │──── SYN ────►│  Spoofed IP            │
│     │◄─ SYN-ACK ──│  "Yes, go       │──── SYN ────►│  Spoofed IP            │
│     │              │   ahead!"       │    ...       │  (thousands)           │
│     │──── ACK ────►│  "Great,        │              │                        │
│     │              │   connected!"   │              │                        │
│     │◄──  Data  ──►│                 │              ▼                        │
│     │              │                 │         ╔═══════════╗                 │
│                                      │         ║ Server    ║                 │
│   Connection Table:                  │         ║ waiting   ║                 │
│   [Slot 1: Connected]                │         ║ for ACKs  ║                 │
│   [Slot 2: Available]                │         ║ that will ║                 │
│   [Slot 3: Available]                │         ║ never     ║                 │
│                                      │         ║ come...   ║                 │
│   ✓ Works normally                   │         ╚═══════════╝                 │
│                                      │         Connection table FULL!        │
│                                      │         ✗ Legitimate users blocked    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘`
};

const realWorldIncidents = [
  {
    name: "GitHub (2018)",
    target: "GitHub.com",
    attackSize: "1.35 Tbps",
    duration: "~20 minutes",
    attackType: "Memcached Amplification",
    description: "The largest DDoS attack recorded at the time. Attackers used misconfigured Memcached servers to amplify traffic 51,000x. GitHub's DDoS protection automatically routed traffic through scrubbing centers.",
    outcome: "GitHub was intermittently unavailable for about 10 minutes. Their DDoS protection worked as designed.",
    lessonsLearned: [
      "Memcached UDP should be disabled or firewalled",
      "Automatic DDoS mitigation is essential for high-profile targets",
      "Amplification attacks can generate enormous traffic from minimal resources"
    ],
    difficulty: "intermediate"
  },
  {
    name: "Dyn DNS (2016)",
    target: "Dyn DNS infrastructure",
    attackSize: "1.2 Tbps",
    duration: "Most of the day",
    attackType: "Mirai Botnet",
    description: "The Mirai botnet, consisting of 100,000+ compromised IoT devices, attacked Dyn's DNS servers. This caused major websites (Twitter, Netflix, Reddit, CNN) to become unreachable for millions of users.",
    outcome: "Major internet outage affecting East Coast US. Highlighted the vulnerability of DNS infrastructure.",
    lessonsLearned: [
      "IoT devices are a massive security risk due to default credentials",
      "DNS is a critical single point of failure for many services",
      "Multi-provider DNS strategies are essential"
    ],
    difficulty: "beginner"
  },
  {
    name: "AWS (2020)",
    target: "AWS customer",
    attackSize: "2.3 Tbps",
    duration: "3 days",
    attackType: "CLDAP Reflection",
    description: "The largest DDoS attack ever recorded at the time. Attackers used CLDAP (Connectionless LDAP) reflection to generate massive traffic volumes targeting an AWS customer.",
    outcome: "AWS Shield mitigated the attack. Customer experienced minimal impact due to AWS's infrastructure.",
    lessonsLearned: [
      "Cloud providers have massive capacity to absorb attacks",
      "CLDAP servers should not be exposed to the internet",
      "Investment in DDoS protection pays off"
    ],
    difficulty: "intermediate"
  },
  {
    name: "Cloudflare (2023)",
    target: "Cloudflare customer",
    attackSize: "71 Million RPS",
    duration: "~1 hour",
    attackType: "HTTP/2 Rapid Reset",
    description: "Exploited a zero-day vulnerability in HTTP/2 (CVE-2023-44487) where attackers rapidly open and reset streams, overwhelming servers. This was a new attack technique that bypassed traditional rate limiting.",
    outcome: "Cloudflare automatically mitigated the attack. The incident led to industry-wide patches for HTTP/2 implementations.",
    lessonsLearned: [
      "New attack techniques can bypass existing protections",
      "Protocol-level vulnerabilities can be devastating",
      "Coordinated disclosure is essential for new attack types"
    ],
    difficulty: "advanced"
  },
  {
    name: "Spamhaus (2013)",
    target: "Spamhaus anti-spam organization",
    attackSize: "300 Gbps",
    duration: "Over a week",
    attackType: "DNS Amplification",
    description: "Cyberbunker, upset at being blacklisted, launched one of the largest attacks of its time against Spamhaus. The attack was so large it caused collateral slowdowns across the internet.",
    outcome: "Cloudflare helped mitigate. Several people were arrested. Highlighted the need for DDoS protection.",
    lessonsLearned: [
      "Open DNS resolvers are dangerous amplification vectors",
      "Even anti-spam organizations can be DDoS targets",
      "Law enforcement can trace and prosecute attackers"
    ],
    difficulty: "beginner"
  }
];

const beginnerQuiz = [
  {
    question: "What does the 'D' in DDoS stand for?",
    options: ["Dangerous", "Distributed", "Direct", "Dynamic"],
    correctIndex: 1,
    explanation: "DDoS stands for Distributed Denial of Service. 'Distributed' means the attack comes from many different computers simultaneously."
  },
  {
    question: "Why are DDoS attacks harder to stop than regular DoS attacks?",
    options: [
      "They use stronger computers",
      "They come from many different IP addresses",
      "They use encryption",
      "They are faster"
    ],
    correctIndex: 1,
    explanation: "DDoS attacks come from thousands or millions of different IP addresses, making it impossible to simply block the attacker's IP."
  },
  {
    question: "What is a botnet?",
    options: [
      "A type of firewall",
      "A network of infected computers controlled by an attacker",
      "A security tool for detecting attacks",
      "A type of web server"
    ],
    correctIndex: 1,
    explanation: "A botnet is a network of compromised computers (bots) that can be remotely controlled to launch DDoS attacks."
  },
  {
    question: "What does 'amplification' mean in DDoS attacks?",
    options: [
      "Making the attack louder",
      "Using bigger computers",
      "Small requests generating much larger responses",
      "Attacking multiple targets at once"
    ],
    correctIndex: 2,
    explanation: "Amplification means sending small requests to servers that respond with much larger replies, multiplying the attack traffic."
  },
  {
    question: "Which layer do 'volumetric' DDoS attacks target?",
    options: [
      "Application layer (Layer 7)",
      "Network layer (Layer 3/4) - bandwidth",
      "Physical layer (Layer 1)",
      "Database layer"
    ],
    correctIndex: 1,
    explanation: "Volumetric attacks target the network layer, trying to saturate bandwidth with massive amounts of traffic."
  },
  {
    question: "What is a SYN flood attack?",
    options: [
      "Flooding with water damage",
      "Sending fake connection requests that never complete",
      "Sending too many DNS requests",
      "Overwhelming with HTTP requests"
    ],
    correctIndex: 1,
    explanation: "A SYN flood sends many TCP connection requests (SYN packets) but never completes the handshake, exhausting server connection tables."
  }
];

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

// =============================================================================
// PART 2: ATTACK TYPE DEEP DIVES
// =============================================================================

const attackTypeDeepDives: Record<string, {
  name: string;
  category: 'volumetric' | 'protocol' | 'application';
  icon: string;
  difficultyToExecute: 'easy' | 'medium' | 'hard';
  difficultyToDefend: 'easy' | 'medium' | 'hard';
  beginnerExplanation: string;
  howItWorks: string;
  technicalDetails: string;
  packetStructure?: string;
  attackTimeline: string;
  realWorldExample: { name: string; date: string; description: string };
  indicators: string[];
  defenses: string[];
  codeExample?: string;
  bandwidth?: string;
}> = {
  udpFlood: {
    name: "UDP Flood",
    category: "volumetric",
    icon: "🌊",
    difficultyToExecute: "easy",
    difficultyToDefend: "medium",
    beginnerExplanation: `Imagine someone sending you millions of letters, but none of them have a return address 
and none of them make sense. You have to open each one to see if it's important, but they're all garbage.
That's a UDP flood - overwhelming you with useless traffic that you still have to process.

UDP (User Datagram Protocol) doesn't require a "handshake" like TCP - you can just start sending packets.
This makes it perfect for flooding attacks because there's no overhead.`,
    howItWorks: `1. Attacker sends massive amounts of UDP packets to random ports
2. Target server receives each packet and checks if any application is listening on that port
3. If no application is listening, server responds with ICMP "Destination Unreachable"
4. This consumes both bandwidth AND CPU cycles
5. Legitimate traffic gets dropped because resources are exhausted`,
    technicalDetails: `Protocol: UDP (Layer 4)
Typical Packet Size: 512-1500 bytes
Attack Bandwidth: 1 Gbps - 1+ Tbps
Spoofing: Source IP can be easily spoofed

Why UDP is easy to abuse:
- Connectionless: No handshake required, just send packets
- No flow control: Can send at maximum rate
- Spoofable: Source IP not verified
- Processing required: Server must check each packet`,
    packetStructure: `
┌───────────────────────────────────────────────────────┐
│                    UDP Flood Packet                    │
├───────────────────────────────────────────────────────┤
│ IP Header (20 bytes)                                  │
│   Source IP: [SPOOFED - Random or specific]           │
│   Dest IP: [VICTIM IP]                                │
│   Protocol: 17 (UDP)                                  │
├───────────────────────────────────────────────────────┤
│ UDP Header (8 bytes)                                  │
│   Source Port: [Random high port]                     │
│   Dest Port: [Random - often 53, 80, 443]            │
│   Length: [Size of UDP packet]                        │
│   Checksum: [Often 0 or invalid]                      │
├───────────────────────────────────────────────────────┤
│ Payload (variable)                                    │
│   [Random data or zeros - just to fill bandwidth]     │
└───────────────────────────────────────────────────────┘`,
    attackTimeline: `
Time 0:00 - Attack begins
  └─ Botnet starts sending UDP packets
  └─ Target receives 100,000 pps

Time 0:30 - Resource exhaustion begins
  └─ Bandwidth utilization reaches 80%
  └─ Server CPU spikes processing packets

Time 1:00 - Service degradation
  └─ Legitimate users experience slowdowns
  └─ Packet loss increases

Time 2:00 - Service failure
  └─ Bandwidth saturated at 100%
  └─ Server stops responding to legitimate traffic`,
    realWorldExample: {
      name: "Spamhaus Attack (2013)",
      date: "March 2013",
      description: "Attackers used UDP floods combined with DNS amplification to generate 300 Gbps of traffic against Spamhaus, causing noticeable slowdowns across Europe."
    },
    indicators: [
      "Sudden spike in UDP traffic",
      "High volume of ICMP Destination Unreachable messages",
      "Traffic to random high ports",
      "Network interface saturation",
      "Uniform packet sizes in attack traffic"
    ],
    defenses: [
      "Rate limit UDP traffic per source IP",
      "Use hardware-based packet filtering",
      "Implement upstream black hole routing",
      "Deploy anycast network distribution",
      "Use cloud-based DDoS mitigation services"
    ],
    codeExample: `# Detection with tcpdump
tcpdump -i eth0 'udp and not port 53 and not port 123' -c 1000

# Count UDP packets per second
watch -n 1 'netstat -su | grep "packets received"'

# Iptables rate limiting (defense)
iptables -A INPUT -p udp -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A INPUT -p udp -j DROP`,
    bandwidth: "Can generate 100 Gbps - 1+ Tbps with botnets"
  },
  synFlood: {
    name: "SYN Flood",
    category: "protocol",
    icon: "🤝",
    difficultyToExecute: "easy",
    difficultyToDefend: "medium",
    beginnerExplanation: `When you visit a website, your computer and the server do a "handshake":
1. You: "Hi, can I connect?" (SYN)
2. Server: "Sure, I'm ready!" (SYN-ACK)
3. You: "Great, let's go!" (ACK)

A SYN flood sends millions of "Hi, can I connect?" messages but NEVER responds with "Great, let's go!"
The server sits there waiting for responses that never come, eventually running out of memory to track all these incomplete connections.`,
    howItWorks: `1. Attacker sends thousands of SYN packets with spoofed source IPs
2. Server allocates memory for each "half-open" connection
3. Server sends SYN-ACK to spoofed IPs (which don't respond)
4. Server waits (typically 75 seconds) for ACK that never comes
5. Connection table fills up - no room for legitimate users!`,
    technicalDetails: `Protocol: TCP (Layer 4)
Attack Type: State exhaustion
Target: TCP connection table (backlog queue)
Typical Rate: 10,000 - 1,000,000+ SYN packets/second

TCP Connection States:
- LISTEN: Server waiting for connections
- SYN_RECEIVED: Half-open connection (attack target!)
- ESTABLISHED: Fully connected (legitimate users)

The Problem:
Server has LIMITED slots for half-open connections (backlog).
Default Linux backlog: 128-1024 connections.
Once full, ALL new connections are rejected!`,
    packetStructure: `
┌───────────────────────────────────────────────────────┐
│                    SYN Flood Packet                    │
├───────────────────────────────────────────────────────┤
│ IP Header (20 bytes)                                  │
│   Source IP: [SPOOFED - Random address]               │
│   Dest IP: [VICTIM IP]                                │
│   Protocol: 6 (TCP)                                   │
├───────────────────────────────────────────────────────┤
│ TCP Header (20+ bytes)                                │
│   Source Port: [Random high port]                     │
│   Dest Port: [80, 443, or target service]            │
│   Sequence Number: [Random]                           │
│   Flags: SYN (0x02) ← Only SYN flag set!             │
│   Window Size: [Usually 65535]                        │
│   Options: [MSS, Window Scale, etc.]                  │
├───────────────────────────────────────────────────────┤
│ Payload                                               │
│   [Empty - SYN packets have no data]                  │
└───────────────────────────────────────────────────────┘`,
    attackTimeline: `
Time 0:00 - Attack begins
  └─ Attacker sends 50,000 SYN packets/second
  └─ Server starts allocating memory for connections

Time 0:10 - Backlog filling
  └─ Half-open connections: 1,000 (backlog: 1,024)
  └─ Server still accepting some connections

Time 0:15 - Backlog full!
  └─ Half-open connections: 1,024/1,024
  └─ New legitimate connections REJECTED

Time 0:15+ - Sustained attack
  └─ Server periodically times out old connections
  └─ New SYN packets immediately fill freed slots
  └─ Legitimate users cannot connect`,
    realWorldExample: {
      name: "Panix ISP Attack (1996)",
      date: "September 1996",
      description: "One of the first documented SYN flood attacks. Panix, a New York ISP, was knocked offline for several days. This attack led to the development of SYN cookies."
    },
    indicators: [
      "Large number of SYN_RECEIVED connections (netstat -an)",
      "Connections from diverse/suspicious IP ranges",
      "No corresponding ACK packets",
      "High rate of new connections with low completion rate",
      "Server logs showing connection timeouts"
    ],
    defenses: [
      "Enable SYN cookies (kernel-level defense)",
      "Increase TCP backlog queue size",
      "Reduce SYN-ACK retries",
      "Use hardware SYN proxy/firewall",
      "Deploy cloud-based scrubbing"
    ],
    codeExample: `# Enable SYN cookies (CRITICAL defense!)
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
# Or permanently: sysctl -w net.ipv4.tcp_syncookies=1

# Check for SYN flood (count SYN_RECV connections)
netstat -ant | grep SYN_RECV | wc -l

# Watch half-open connections in real-time
watch -n 1 'ss -s | grep "synrecv"'

# Increase backlog
echo 4096 > /proc/sys/net/core/somaxconn
echo 4096 > /proc/sys/net/ipv4/tcp_max_syn_backlog

# Reduce SYN-ACK retries (faster timeout)
echo 2 > /proc/sys/net/ipv4/tcp_synack_retries`
  },
  httpFlood: {
    name: "HTTP Flood",
    category: "application",
    icon: "🌐",
    difficultyToExecute: "medium",
    difficultyToDefend: "hard",
    beginnerExplanation: `An HTTP flood is like sending thousands of real customers into a store, 
each asking complex questions that take the staff time to answer.

Unlike other attacks that just flood with garbage, HTTP floods send what look like REAL web requests.
This makes them incredibly hard to block - how do you tell a malicious request from a real user?`,
    howItWorks: `1. Attacker (via botnet) sends valid HTTP requests
2. Requests are indistinguishable from legitimate traffic
3. Each request requires server resources to process:
   - CPU to parse request
   - Database queries to fetch data
   - Memory to build response
4. Server becomes overwhelmed processing fake requests
5. Legitimate users experience timeouts or errors`,
    technicalDetails: `Protocol: HTTP/HTTPS (Layer 7)
Attack Type: Application resource exhaustion
Target: Web servers, application servers, databases
Measurement: Requests per second (RPS)
Modern attacks: 1M - 100M+ RPS

Attack Variants:
- GET flood: Requests for static or dynamic pages
- POST flood: Submits form data (heavier on server)
- Randomized URLs: Bypass caching, hit database
- Slowloris: Keep connections open with slow requests
- Cache bypass: Add random parameters (?rand=12345)

Why L7 is Hard to Defend:
- Traffic looks legitimate
- Uses valid HTTP protocol
- Can't just block by IP (bots rotate)
- Rate limiting hurts real users too`,
    attackTimeline: `
Time 0:00 - Attack begins
  └─ Botnet sends 100,000 HTTP requests/second
  └─ Requests target expensive endpoints

Time 0:30 - Resource consumption rises
  └─ Database connection pool exhausted
  └─ CPU usage: 95%
  └─ Response times increasing

Time 1:00 - Degradation visible
  └─ 50% of requests timing out
  └─ Cache miss rate increasing
  └─ Backend services struggling

Time 2:00 - Service failure
  └─ Application crashes or stops responding
  └─ Database overwhelmed
  └─ Legitimate users get 503 errors`,
    realWorldExample: {
      name: "Cloudflare 71M RPS Attack",
      date: "February 2023",
      description: "Used HTTP/2 Rapid Reset vulnerability (CVE-2023-44487) to generate 71 million requests per second - the largest HTTP flood ever recorded."
    },
    indicators: [
      "Spike in requests per second",
      "Unusual request patterns (same URL, no referer)",
      "Requests from unusual geographic locations",
      "High rate of requests from few user agents",
      "Requests bypassing cache (random query params)",
      "Abnormal request/session ratios"
    ],
    defenses: [
      "Web Application Firewall (WAF)",
      "Rate limiting per IP/session",
      "CAPTCHA challenges for suspicious traffic",
      "Bot detection and fingerprinting",
      "Caching to reduce origin load",
      "Challenge-response cookies"
    ],
    codeExample: `# Nginx rate limiting
limit_req_zone $binary_remote_addr zone=flood:10m rate=10r/s;

server {
    location / {
        limit_req zone=flood burst=20 nodelay;
        limit_req_status 429;
    }
}

# Detect HTTP flood with Apache logs
# Look for high request rate from single IP
cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Real-time monitoring
tail -f access.log | awk '{print $1}' | uniq -c`
  },
  slowloris: {
    name: "Slowloris",
    category: "application",
    icon: "🦥",
    difficultyToExecute: "easy",
    difficultyToDefend: "medium",
    beginnerExplanation: `Imagine you're at a restaurant and 1000 people each order food but then say 
"hold on, I'm still deciding" and never finish ordering. The waiters are stuck waiting, 
and no new customers can be served!

Slowloris works the same way - it opens many connections to a web server and keeps them open 
by sending partial HTTP requests VERY slowly. The server waits patiently for each request 
to complete, but they never do.`,
    howItWorks: `1. Attacker opens many HTTP connections to the target
2. Sends partial HTTP headers (doesn't complete the request)
3. Periodically sends additional header bytes to keep connection alive
4. Server waits for complete request (it's being patient!)
5. All connection slots fill up with "waiting" connections
6. No room left for legitimate users`,
    technicalDetails: `Protocol: HTTP (Layer 7)
Attack Type: Connection/thread exhaustion
Target: Web servers with limited max connections
Packets Required: Very few (low bandwidth attack!)
Vulnerable: Apache (default config), some others

How Partial Requests Work:
Normal HTTP request:
GET / HTTP/1.1\\r\\n
Host: example.com\\r\\n
\\r\\n  ← This blank line signals END of headers

Slowloris sends:
GET / HTTP/1.1\\r\\n
Host: example.com\\r\\n
X-header: value\\r\\n    ← Never sends final \\r\\n\\r\\n
                          Server keeps waiting...

Why It's Devastating:
- Requires minimal attacker bandwidth
- Single computer can take down a server
- Hard to detect (looks like slow users)
- Keeps connections in "receiving headers" state`,
    packetStructure: `
┌───────────────────────────────────────────────────────┐
│               Slowloris Request Pattern                │
├───────────────────────────────────────────────────────┤
│ Initial Request (sent immediately):                   │
│   "GET / HTTP/1.1\\r\\n"                               │
│   "Host: target.com\\r\\n"                             │
│                                                        │
│ Keep-alive headers (sent every 10-15 seconds):        │
│   "X-a: b\\r\\n"  ← Random header, keeps conn alive    │
│   "X-c: d\\r\\n"                                       │
│   "X-e: f\\r\\n"                                       │
│                                                        │
│ ⚠️ NEVER sends final "\\r\\n" to complete request!     │
│                                                        │
│ Result: Server keeps waiting... and waiting...        │
└───────────────────────────────────────────────────────┘`,
    attackTimeline: `
Time 0:00 - Attack begins
  └─ Attacker opens 500 connections
  └─ Sends partial HTTP headers to each

Time 0:30 - Connections accumulating
  └─ Server has 500 "waiting" connections
  └─ Normal users still connecting fine

Time 1:00 - Max connections reached
  └─ Server MaxClients/workers exhausted
  └─ Apache default: 256 connections

Time 1:00+ - Denial of service achieved
  └─ New connections refused
  └─ Legitimate users get "connection refused"
  └─ Attacker maintains with ~10 bytes/conn every 15 sec`,
    realWorldExample: {
      name: "Iranian Election Protests (2009)",
      date: "June 2009",
      description: "Slowloris was used to attack Iranian government websites during the election protests. A single attacker could take down servers due to the low resource requirements."
    },
    indicators: [
      "Many connections in 'reading headers' state",
      "Connections staying open for very long periods",
      "Low bandwidth but high connection count",
      "Incomplete HTTP requests in logs",
      "MaxClients/workers exhausted"
    ],
    defenses: [
      "Set aggressive connection timeouts",
      "Limit connections per IP address",
      "Use reverse proxy (nginx handles this better)",
      "Increase MaxClients with req_timeout module",
      "Use mod_reqtimeout (Apache)",
      "Deploy CDN/load balancer in front"
    ],
    codeExample: `# Apache mod_reqtimeout (defense)
RequestReadTimeout header=20-40,MinRate=500

# Nginx is naturally resistant - configure:
client_header_timeout 10s;
client_body_timeout 10s;
keepalive_timeout 65s;

# Detect Slowloris - look for incomplete requests
netstat -ant | grep ESTABLISHED | wc -l

# Check Apache status for hanging connections
apachectl status | grep "Reading Request"`
  },
  dnsAmplification: {
    name: "DNS Amplification",
    category: "volumetric",
    icon: "📡",
    difficultyToExecute: "medium",
    difficultyToDefend: "medium",
    beginnerExplanation: `Imagine you could write a postcard asking for a phone book, and someone would mail 
a HUGE phone book to whoever's address you wrote on the card - even if it wasn't yours!

DNS amplification works like this:
1. Attacker sends tiny DNS query (50 bytes)
2. Uses VICTIM's IP address as the "return address"  
3. DNS server sends HUGE response (3000+ bytes) to victim
4. 60x more traffic hits the victim than the attacker sent!`,
    howItWorks: `1. Attacker finds "open DNS resolvers" (misconfigured servers)
2. Sends DNS queries with spoofed source IP (victim's IP)
3. Uses special query types that generate large responses:
   - ANY: Returns all records for a domain
   - TXT: Can contain large text records  
   - DNSSEC: Includes large signatures
4. DNS servers send huge responses to the victim
5. Victim receives 28-54x more traffic than attacker sent`,
    technicalDetails: `Protocol: DNS/UDP (Port 53)
Amplification Factor: 28-54x (ANY queries)
Query Size: ~50 bytes
Response Size: ~3000 bytes
Required: Open recursive DNS resolvers + IP spoofing

Query Types for Maximum Amplification:
- ANY: Requests ALL record types
- TXT: Large text records
- DNSKEY: DNSSEC public keys
- RRSIG: DNSSEC signatures

Why Open Resolvers Exist:
- Misconfigured DNS servers
- Default "allow recursion" settings
- ISPs not implementing BCP38 (egress filtering)`,
    packetStructure: `
┌───────────────────────────────────────────────────────┐
│              DNS Amplification Attack Flow             │
├───────────────────────────────────────────────────────┤
│                                                        │
│  Attacker          Open Resolvers          Victim      │
│     │                    │                    │        │
│     │── Query (50B) ────►│                    │        │
│     │   src: VICTIM_IP   │                    │        │
│     │   query: ANY       │                    │        │
│     │                    │                    │        │
│     │                    │── Response ───────►│        │
│     │                    │   (3000B = 60x!)   │        │
│     │                    │                    │        │
│     │── Query (50B) ────►│                    │        │
│     │     × 100,000      │── Response ×100K ─►│        │
│                          │                    │        │
│                          │                    ▼        │
│                                        ┌────────────┐  │
│                                        │  VICTIM    │  │
│                                        │ Overwhelmed│  │
│                                        └────────────┘  │
│                                                        │
└───────────────────────────────────────────────────────┘`,
    attackTimeline: `
Time 0:00 - Attack begins
  └─ Attacker sends queries to 10,000 open resolvers
  └─ Each query is 50 bytes, spoofed with victim's IP

Time 0:01 - Amplified traffic arrives
  └─ Each resolver sends ~3000 byte response to victim
  └─ 10,000 resolvers × 3000 bytes = 30 MB in 1 second!

Time 0:05 - Attack scales up
  └─ Attacker sending 100 Mbps of queries
  └─ Victim receiving 5+ Gbps of responses!

Time 0:10 - Target overwhelmed
  └─ Victim's bandwidth saturated
  └─ All services unreachable`,
    realWorldExample: {
      name: "Spamhaus Attack",
      date: "March 2013",
      description: "Attackers used DNS amplification to generate 300 Gbps against Spamhaus, one of the largest attacks at that time. The attack was so large it caused collateral slowdowns across the internet."
    },
    indicators: [
      "Large spike in inbound DNS responses",
      "UDP port 53 traffic from many sources",
      "Traffic from known open resolver IPs",
      "Large DNS packet sizes (>512 bytes)",
      "DNS responses without corresponding queries"
    ],
    defenses: [
      "Close open recursive resolvers",
      "Implement Response Rate Limiting (RRL)",
      "Use BCP38 egress filtering",
      "Deploy anycast DNS infrastructure",
      "Use upstream DDoS mitigation"
    ],
    codeExample: `# Check if your server is an open resolver
dig +short test.openresolver.com TXT @your.server.ip
# If it responds, you're open!

# BIND9 - Disable open recursion
options {
    allow-recursion { localhost; 192.168.0.0/16; };
    rate-limit {
        responses-per-second 10;
    };
};

# Detect DNS amplification
tcpdump -i eth0 'udp port 53 and udp[10] & 0x80 = 0x80' -c 100`
  }
};

const attackComparison = [
  { attack: "UDP Flood", layer: "3/4", measurement: "Gbps", difficulty: "Easy", defense: "Rate limiting, filtering" },
  { attack: "SYN Flood", layer: "4", measurement: "PPS", difficulty: "Easy", defense: "SYN cookies, timeouts" },
  { attack: "HTTP Flood", layer: "7", measurement: "RPS", difficulty: "Medium", defense: "WAF, CAPTCHA, bot detection" },
  { attack: "Slowloris", layer: "7", measurement: "Connections", difficulty: "Easy", defense: "Timeouts, reverse proxy" },
  { attack: "DNS Amp", layer: "3/4", measurement: "Gbps", difficulty: "Medium", defense: "Close resolvers, BCP38" },
  { attack: "Memcached Amp", layer: "3/4", measurement: "Gbps", difficulty: "Medium", defense: "Disable UDP, firewall" },
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

// =============================================================================
// PART 3: DETECTION METHODOLOGY & LAB EXERCISES
// =============================================================================

const detectionMethodologyDetailed = {
  networkMonitoring: {
    title: "Network Traffic Monitoring",
    icon: "📡",
    description: "Monitor network traffic patterns to identify DDoS attacks in real-time",
    difficulty: "intermediate",
    timeToImplement: "1-4 hours",
    approach: `Network monitoring is your first line of defense. By establishing baselines and watching for 
anomalies, you can detect attacks before they cause significant damage.

The key is to know what "normal" looks like for YOUR network. This varies dramatically between 
organizations - a gaming company and a bank have very different traffic patterns.`,
    steps: [
      {
        step: 1,
        title: "Establish Traffic Baselines",
        description: "Record normal traffic patterns over 2-4 weeks",
        commands: `# Capture baseline metrics with vnStat
vnstat -l -i eth0

# Record hourly traffic patterns
vnstat -h

# Export to CSV for analysis
vnstat --exportdb > baseline.db`,
        tips: ["Capture during peak and off-peak hours", "Note day-of-week patterns", "Record special events (sales, launches)"]
      },
      {
        step: 2,
        title: "Configure Real-Time Monitoring",
        description: "Set up tools to watch traffic continuously",
        commands: `# Real-time bandwidth monitoring
iftop -i eth0 -B

# Packet rate monitoring
tcpdump -i eth0 -c 1000 -w sample.pcap

# Connection state monitoring
watch -n 1 'netstat -s | grep -E "active|passive|failed"'

# Using nload for visual bandwidth
nload eth0`,
        tips: ["Use multiple vantage points", "Monitor both ingress and egress", "Set up automatic data collection"]
      },
      {
        step: 3,
        title: "Configure Alerting",
        description: "Set thresholds for automatic alert generation",
        commands: `# Example Prometheus alerting rule
groups:
- name: ddos_alerts
  rules:
  - alert: HighPacketRate
    expr: rate(node_network_receive_packets_total[1m]) > 100000
    for: 30s
    labels:
      severity: critical
    annotations:
      summary: "Possible DDoS attack detected"`,
        tips: ["Start with conservative thresholds", "Tune to reduce false positives", "Have escalation procedures ready"]
      },
      {
        step: 4,
        title: "Analyze Traffic Patterns",
        description: "Look for DDoS indicators in collected data",
        commands: `# Identify top talkers
tcpdump -nn -c 10000 -i eth0 | \\
  awk '{print $3}' | cut -d. -f1-4 | \\
  sort | uniq -c | sort -rn | head -20

# Check packet size distribution
tcpdump -nn -c 1000 -i eth0 -l | \\
  awk '{print length}' | sort | uniq -c

# Protocol distribution
tshark -i eth0 -c 10000 -q -z io,phs`,
        tips: ["Look for uniform packet sizes", "Check for unusual protocols", "Identify traffic from unusual ASNs"]
      }
    ],
    indicators: [
      "Traffic volume 2-10x above baseline",
      "Single protocol dominating traffic mix",
      "Requests from unusual geographic regions",
      "Packet sizes unusually uniform",
      "Source IP addresses rotating or spoofed"
    ],
    tools: ["Wireshark", "tcpdump", "ntopng", "Prometheus + Grafana", "Elastic Stack"]
  },
  logAnalysis: {
    title: "Log-Based Detection",
    icon: "📋",
    description: "Analyze server and application logs to identify attack patterns",
    difficulty: "beginner",
    timeToImplement: "30 minutes - 2 hours",
    approach: `Server logs contain a wealth of information about incoming requests. During a DDoS attack, 
log analysis can reveal attack patterns, help identify malicious IPs, and guide mitigation efforts.

The challenge is processing logs fast enough during an attack - you need automation!`,
    steps: [
      {
        step: 1,
        title: "Configure Comprehensive Logging",
        description: "Ensure all relevant data is being captured",
        commands: `# Nginx logging with timing and request details
log_format ddos '$remote_addr - $request_time - $status '
                '"$request" $body_bytes_sent '
                '"$http_referer" "$http_user_agent"';

# Apache combined + timing
LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\" %D" combined_timing

# Enable verbose firewall logging
iptables -A INPUT -j LOG --log-prefix "iptables: " --log-level 4`,
        tips: ["Include response times in logs", "Log User-Agent strings", "Capture client IP even behind proxies"]
      },
      {
        step: 2,
        title: "Identify Attack Patterns",
        description: "Analyze logs for DDoS indicators",
        commands: `# Top IPs by request count
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20

# Requests per second over time
awk '{print $4}' access.log | cut -d: -f1-3 | uniq -c

# Top requested URLs (L7 attack detection)
awk '{print $7}' access.log | sort | uniq -c | sort -rn | head -20

# User-Agent analysis (bot detection)
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn | head -20`,
        tips: ["Compare current vs historical patterns", "Look for missing referers", "Check for suspicious user agents"]
      },
      {
        step: 3,
        title: "Detect HTTP Flood Patterns",
        description: "Look for application-layer attack signatures",
        commands: `# Find IPs making too many requests
awk '{print $1}' access.log | sort | uniq -c | \\
  awk '$1 > 1000 {print $2}' > suspicious_ips.txt

# Check for cache bypass attacks (random query strings)
grep '\\?' access.log | awk '{print $7}' | \\
  cut -d'?' -f1 | sort | uniq -c | sort -rn

# Detect Slowloris (long request times)
awk '$2 > 30 {print $0}' access.log | head -100`,
        tips: ["Look for requests to expensive endpoints", "Check POST vs GET ratios", "Monitor error rates by endpoint"]
      },
      {
        step: 4,
        title: "Set Up Automated Analysis",
        description: "Use tools to process logs in real-time",
        commands: `# GoAccess for real-time log analysis
goaccess access.log -o report.html --real-time-html

# Fail2ban for automatic blocking
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD).*
maxretry = 100
findtime = 60

# Log shipping to central SIEM
filebeat -e -c filebeat.yml`,
        tips: ["Use log aggregation (ELK, Splunk)", "Create dashboards for quick assessment", "Automate IP blocking based on patterns"]
      }
    ],
    indicators: [
      "Single IP making 100+ requests/minute",
      "Requests with no or fake referer headers",
      "Unusual user agent strings or missing UA",
      "High 4xx/5xx error rates",
      "Requests targeting expensive endpoints"
    ],
    tools: ["GoAccess", "AWStats", "Fail2ban", "ELK Stack", "Splunk"]
  },
  threatHunting: {
    title: "Proactive Threat Hunting",
    icon: "🔍",
    description: "Actively search for DDoS indicators before attacks cause damage",
    difficulty: "advanced",
    timeToImplement: "Ongoing process",
    approach: `Threat hunting goes beyond passive monitoring - you actively look for signs of attack 
preparation or ongoing low-level attacks. This can help you detect attacks before they reach 
full intensity.

Key areas to hunt: unusual traffic patterns, scanning activity, botnet beacons, and infrastructure probing.`,
    steps: [
      {
        step: 1,
        title: "Hunt for Reconnaissance",
        description: "Look for attackers mapping your infrastructure",
        commands: `# Detect port scanning
grep -E "SYN|SCAN" /var/log/messages | \\
  awk '{print $NF}' | sort | uniq -c | sort -rn

# Find DNS enumeration attempts
grep -E "NXDOMAIN|SERVFAIL" /var/log/named/query.log | \\
  awk '{print $6}' | sort | uniq -c | sort -rn

# Detect vulnerability scanning
grep -E "wp-admin|phpmyadmin|.env|.git" access.log`,
        tips: ["Monitor for increased DNS queries", "Watch for ICMP probes", "Check for HTTP fingerprinting"]
      },
      {
        step: 2,
        title: "Monitor for Botnet Activity",
        description: "Identify compromised hosts in your network",
        commands: `# Look for C2 communication patterns
tcpdump -i eth0 -nn 'udp and port != 53 and port != 123' -c 1000

# Detect beaconing behavior
zeek -r traffic.pcap local
cat conn.log | awk '{print $3, $5}' | sort | uniq -c | sort -rn

# Check for unusual outbound connections
netstat -an | grep ESTABLISHED | \\
  awk '{print $5}' | cut -d: -f1 | sort | uniq -c`,
        tips: ["Look for regular interval connections", "Check for connections to known bad IPs", "Monitor unusual port usage"]
      },
      {
        step: 3,
        title: "Analyze Traffic Anomalies",
        description: "Deep dive into suspicious traffic patterns",
        commands: `# Entropy analysis for DDoS detection
tshark -r capture.pcap -T fields -e ip.src | \\
  sort | uniq -c | sort -rn > ip_distribution.txt

# Protocol ratio analysis
tshark -r capture.pcap -q -z io,phs

# Packet timing analysis
tshark -r capture.pcap -T fields -e frame.time_delta | \\
  awk '{sum+=$1; count++} END {print sum/count}'`,
        tips: ["Compare with historical baselines", "Look for protocol anomalies", "Check packet timing regularity"]
      },
      {
        step: 4,
        title: "Correlate Threat Intelligence",
        description: "Use external data to identify known threats",
        commands: `# Check IPs against threat feeds
for ip in $(cat suspicious_ips.txt); do
  curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip" \\
    -H "Key: YOUR_API_KEY"
done

# Shodan lookup for infrastructure
shodan host <IP_ADDRESS>

# Check ASN reputation
whois -h whois.radb.net -- "-i origin AS12345"`,
        tips: ["Maintain updated threat feeds", "Correlate with global attack trends", "Share intel with peers/ISACs"]
      }
    ],
    indicators: [
      "Increased port scanning from multiple sources",
      "DNS queries for random subdomains (DGA detection)",
      "Connections to known C2 infrastructure",
      "Traffic patterns matching known attack tools",
      "Unusual geographic distribution of traffic"
    ],
    tools: ["Zeek (Bro)", "RITA", "Suricata", "Threat intelligence platforms", "MISP"]
  }
};

const labExercisesDetailed = [
  {
    id: 1,
    title: "DDoS Traffic Analysis Lab",
    icon: "📊",
    difficulty: "beginner",
    duration: "45-60 minutes",
    description: "Learn to identify DDoS attack patterns by analyzing packet captures from real attacks.",
    objectives: [
      "Identify volumetric attack patterns in packet captures",
      "Calculate attack bandwidth and packet rates",
      "Distinguish between legitimate traffic and attack traffic",
      "Document findings in a structured format"
    ],
    prerequisites: [
      "Basic understanding of TCP/IP",
      "Wireshark or tshark installed",
      "Familiarity with command line"
    ],
    labEnvironment: `This lab uses publicly available DDoS packet captures for analysis.
You will NOT generate any attack traffic - this is purely defensive analysis.

Required tools:
- Wireshark (GUI) or tshark (CLI)
- tcpdump (optional)
- Python (for scripting analysis)`,
    steps: [
      {
        step: 1,
        title: "Obtain Sample DDoS Captures",
        description: "Download legitimate DDoS research captures",
        commands: `# Download from public DDoS dataset
# (Use datasets from universities/research institutions)
wget https://example.com/ddos-samples/syn-flood.pcap
wget https://example.com/ddos-samples/udp-flood.pcap

# Or capture your own LEGITIMATE traffic for baseline
tcpdump -i eth0 -w baseline.pcap -c 10000`,
        expectedOutput: "Downloaded capture files ready for analysis",
        tips: ["Only use captures you have permission to analyze", "Start with smaller captures (100MB or less)"]
      },
      {
        step: 2,
        title: "Analyze Traffic Statistics",
        description: "Get an overview of the capture contents",
        commands: `# Basic capture statistics
capinfos syn-flood.pcap

# Protocol hierarchy
tshark -r syn-flood.pcap -q -z io,phs

# Conversation statistics
tshark -r syn-flood.pcap -q -z conv,ip

# Top talkers
tshark -r syn-flood.pcap -T fields -e ip.src | \\
  sort | uniq -c | sort -rn | head -20`,
        expectedOutput: "Summary showing packet counts, protocols, and traffic distribution",
        tips: ["Note the total packets and time span", "Calculate packets/second"]
      },
      {
        step: 3,
        title: "Identify Attack Patterns",
        description: "Look for indicators of DDoS attack traffic",
        commands: `# Check for SYN flood (lots of SYN, few ACK)
tshark -r syn-flood.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" | wc -l

# Check TCP flag distribution
tshark -r syn-flood.pcap -q -z io,stat,1,"tcp.flags.syn==1","tcp.flags.ack==1"

# Look for spoofed sources (random source IPs)
tshark -r syn-flood.pcap -T fields -e ip.src | \\
  sort -u | wc -l  # High number = likely spoofed

# Check packet size distribution
tshark -r syn-flood.pcap -T fields -e frame.len | \\
  sort | uniq -c | head -20`,
        expectedOutput: "Evidence of attack patterns (high SYN count, many unique IPs, uniform packet sizes)",
        tips: ["SYN floods have SYN >> ACK ratio", "Spoofed attacks have very high unique IP count"]
      },
      {
        step: 4,
        title: "Calculate Attack Metrics",
        description: "Quantify the attack intensity",
        commands: `# Calculate bandwidth (requires Python)
python3 << 'EOF'
import subprocess
import re

# Get capture duration
result = subprocess.run(['capinfos', 'syn-flood.pcap'], capture_output=True, text=True)
duration = float(re.search(r'Capture duration:\\s+(\\d+\\.?\\d*)', result.stdout).group(1))
bytes_val = int(re.search(r'File size:\\s+(\\d+)', result.stdout).group(1))
packets = int(re.search(r'Number of packets:\\s+(\\d+)', result.stdout).group(1))

print(f"Duration: {duration:.2f} seconds")
print(f"Packets/second: {packets/duration:.0f} pps")
print(f"Bandwidth: {(bytes_val*8/duration/1000000):.2f} Mbps")
EOF`,
        expectedOutput: "Calculated attack metrics (pps, Mbps)",
        tips: ["Compare with your baseline metrics", "Consider peak vs average rates"]
      },
      {
        step: 5,
        title: "Document Your Findings",
        description: "Create a structured analysis report",
        commands: `# Create analysis report
cat << 'EOF' > analysis_report.md
# DDoS Traffic Analysis Report

## Capture Information
- File: syn-flood.pcap
- Duration: [X] seconds
- Total packets: [X]

## Attack Classification
- Type: [SYN Flood / UDP Flood / etc.]
- Layer: [3/4 / 7]
- Estimated bandwidth: [X] Mbps
- Packet rate: [X] pps

## Indicators Observed
1. [Indicator 1]
2. [Indicator 2]

## Recommended Mitigations
1. [Mitigation 1]
2. [Mitigation 2]
EOF`,
        expectedOutput: "Completed analysis report",
        tips: ["Include timestamps and evidence", "Recommend specific mitigations"]
      }
    ],
    quiz: [
      {
        question: "What TCP flag pattern indicates a SYN flood attack?",
        options: ["Many ACK packets", "Many SYN packets with few ACK responses", "Many FIN packets", "Many RST packets"],
        correctIndex: 1,
        explanation: "SYN floods send many SYN packets but never complete the handshake with ACK."
      },
      {
        question: "A capture shows 50,000 unique source IPs in 30 seconds. What does this suggest?",
        options: ["Normal web traffic", "Legitimate traffic spike", "Likely IP spoofing", "Load balancer traffic"],
        correctIndex: 2,
        explanation: "50,000 unique IPs in 30 seconds is extremely high and suggests spoofed source addresses."
      }
    ]
  },
  {
    id: 2,
    title: "SYN Cookie Defense Lab",
    icon: "🍪",
    difficulty: "intermediate",
    duration: "30-45 minutes",
    description: "Understand and implement SYN cookie protection against SYN flood attacks.",
    objectives: [
      "Understand how SYN cookies work",
      "Configure Linux kernel for SYN flood protection",
      "Test and verify SYN cookie effectiveness",
      "Tune TCP parameters for optimal protection"
    ],
    prerequisites: [
      "Linux system with root access (VM recommended)",
      "Basic understanding of TCP handshake",
      "Familiarity with sysctl"
    ],
    labEnvironment: `This lab requires a Linux system where you can modify kernel parameters.
Use a virtual machine - do not test on production systems!

Required:
- Linux VM (Ubuntu/Debian/CentOS)
- Root/sudo access
- hping3 (for testing with safe traffic)`,
    steps: [
      {
        step: 1,
        title: "Understand Current TCP Settings",
        description: "Check existing TCP configuration",
        commands: `# Check if SYN cookies are enabled
sysctl net.ipv4.tcp_syncookies

# Check current backlog sizes
sysctl net.ipv4.tcp_max_syn_backlog
sysctl net.core.somaxconn

# Check SYN-ACK retries
sysctl net.ipv4.tcp_synack_retries

# View current connection states
ss -s
netstat -s | grep -i syn`,
        expectedOutput: "Current TCP parameters and connection statistics",
        tips: ["Note default values before changing", "Understanding defaults helps with troubleshooting"]
      },
      {
        step: 2,
        title: "Configure SYN Cookie Protection",
        description: "Enable and tune SYN cookies",
        commands: `# Enable SYN cookies (most important!)
sudo sysctl -w net.ipv4.tcp_syncookies=1

# Increase backlog queue
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sudo sysctl -w net.core.somaxconn=4096

# Reduce SYN-ACK retries (faster timeout)
sudo sysctl -w net.ipv4.tcp_synack_retries=2

# Make changes permanent
sudo tee -a /etc/sysctl.conf << EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_synack_retries = 2
EOF`,
        expectedOutput: "Parameters set successfully",
        tips: ["Always enable tcp_syncookies on internet-facing servers", "Test changes in staging first"]
      },
      {
        step: 3,
        title: "Test SYN Cookie Activation",
        description: "Verify SYN cookies activate under load",
        commands: `# Start a simple listener (in terminal 1)
nc -l 8080

# Monitor SYN_RECV connections (in terminal 2)
watch -n 0.5 'ss -s; echo "---"; netstat -ant | grep SYN_RECV | wc -l'

# Generate LEGITIMATE test connections (in terminal 3)
# This simulates high connection rate, not an attack
for i in {1..100}; do
  (echo "test" | nc -w 1 localhost 8080 &)
done

# Check if SYN cookies were used
dmesg | grep -i "syn"`,
        expectedOutput: "System handles high connection rate without exhausting backlog",
        tips: ["With SYN cookies, server doesn't store state until handshake completes", "Watch for 'possible SYN flooding' in dmesg"]
      },
      {
        step: 4,
        title: "Compare With and Without Protection",
        description: "Understand the difference SYN cookies make",
        commands: `# Create test script
cat << 'EOF' > test_syn_protection.sh
#!/bin/bash
echo "Testing TCP connection handling..."

# Check current settings
echo "SYN Cookies: $(sysctl -n net.ipv4.tcp_syncookies)"
echo "Backlog: $(sysctl -n net.ipv4.tcp_max_syn_backlog)"

# Before: Count starting SYN_RECV
start_syn=$(netstat -ant 2>/dev/null | grep SYN_RECV | wc -l)
echo "Starting SYN_RECV count: $start_syn"

# After high load test
echo "Results help understand protection level"
EOF

chmod +x test_syn_protection.sh
./test_syn_protection.sh`,
        expectedOutput: "Comparison showing protection effectiveness",
        tips: ["Without SYN cookies, backlog fills quickly", "With SYN cookies, connections complete normally"]
      },
      {
        step: 5,
        title: "Document Best Practice Configuration",
        description: "Create a hardened configuration template",
        commands: `# Create recommended sysctl.conf for DDoS protection
cat << 'EOF' > ddos_protection_sysctl.conf
# SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_synack_retries = 2

# Additional hardening
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 15

# ICMP hardening
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

echo "Save this as /etc/sysctl.d/99-ddos-protection.conf"`,
        expectedOutput: "Complete DDoS protection sysctl configuration",
        tips: ["Test each setting before deploying to production", "Monitor system performance after changes"]
      }
    ],
    quiz: [
      {
        question: "How do SYN cookies prevent SYN flood attacks?",
        options: [
          "By blocking all SYN packets",
          "By encoding connection state in the sequence number instead of storing it",
          "By rate limiting SYN packets",
          "By requiring client certificates"
        ],
        correctIndex: 1,
        explanation: "SYN cookies encode state in the initial sequence number, so the server doesn't need to store half-open connections."
      }
    ]
  },
  {
    id: 3,
    title: "Rate Limiting Implementation Lab",
    icon: "🚦",
    difficulty: "intermediate",
    duration: "45-60 minutes",
    description: "Implement and test rate limiting at multiple layers to protect against DDoS.",
    objectives: [
      "Configure iptables rate limiting for L3/L4 protection",
      "Implement nginx rate limiting for L7 protection",
      "Test rate limiting effectiveness",
      "Understand rate limiting trade-offs"
    ],
    prerequisites: [
      "Linux server with nginx installed",
      "Root/sudo access",
      "Basic understanding of iptables"
    ],
    labEnvironment: `This lab configures rate limiting on a test server.
Use a VM or test environment - not production!

Required:
- Linux VM with nginx
- iptables
- Apache Bench (ab) or hey for testing`,
    steps: [
      {
        step: 1,
        title: "Implement iptables Rate Limiting",
        description: "Configure network-layer rate limiting",
        commands: `# Rate limit new connections (per source IP)
sudo iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 50 -j DROP

# Rate limit packets per second
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Rate limit new TCP connections
sudo iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m limit --limit 50/s --limit-burst 100 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j DROP

# View rules
sudo iptables -L -v -n`,
        expectedOutput: "iptables rules configured for rate limiting",
        tips: ["Start with conservative limits", "Monitor dropped packets", "Have a way to remove rules quickly"]
      },
      {
        step: 2,
        title: "Configure nginx Rate Limiting",
        description: "Add application-layer rate limiting",
        commands: `# Edit nginx.conf
sudo cat << 'EOF' > /etc/nginx/conf.d/rate_limit.conf
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

server {
    listen 80;
    server_name localhost;
    
    # Apply rate limiting
    location / {
        limit_req zone=req_limit burst=20 nodelay;
        limit_req_status 429;
        
        limit_conn conn_limit 20;
        limit_conn_status 429;
        
        root /var/www/html;
        index index.html;
    }
    
    # Stricter limits for expensive endpoints
    location /api/ {
        limit_req zone=req_limit burst=5 nodelay;
        limit_conn conn_limit 10;
        
        proxy_pass http://backend;
    }
}
EOF

# Test configuration and reload
sudo nginx -t && sudo systemctl reload nginx`,
        expectedOutput: "nginx configured with rate limiting",
        tips: ["Different endpoints may need different limits", "Monitor 429 responses in access logs"]
      },
      {
        step: 3,
        title: "Test Rate Limiting",
        description: "Verify rate limits are working",
        commands: `# Test with Apache Bench
ab -n 1000 -c 50 http://localhost/

# Or use hey (better for testing)
hey -n 1000 -c 50 http://localhost/

# Watch nginx logs for 429 responses
tail -f /var/log/nginx/access.log | grep "429"

# Check iptables packet counts
sudo iptables -L -v -n | grep -E "DROP|REJECT"

# Monitor in real-time
watch -n 1 'sudo iptables -L -v -n | grep "limit"'`,
        expectedOutput: "Rate limiting blocking excess requests (429 responses)",
        tips: ["Verify legitimate traffic still works", "Check both accepted and dropped counts"]
      },
      {
        step: 4,
        title: "Fine-Tune Rate Limits",
        description: "Adjust limits based on testing",
        commands: `# Analyze current traffic patterns
awk '{print $1}' /var/log/nginx/access.log | \\
  sort | uniq -c | sort -rn | head -20

# Calculate requests per IP per minute
awk '{print $1, $4}' /var/log/nginx/access.log | \\
  cut -d: -f1-2 | sort | uniq -c | \\
  awk '$1 > 60 {print}'  # More than 1/sec

# Adjust rate limit based on findings
# If legitimate users need more:
# limit_req zone=req_limit burst=50 nodelay;

# Create allowlist for known good IPs
cat << 'EOF' >> /etc/nginx/conf.d/rate_limit.conf
geo $rate_limit {
    default 1;
    10.0.0.0/8 0;      # Internal network
    192.168.0.0/16 0;  # Internal network
}

map $rate_limit $limit_key {
    0 "";
    1 $binary_remote_addr;
}

limit_req_zone $limit_key zone=req_limit:10m rate=10r/s;
EOF`,
        expectedOutput: "Fine-tuned rate limiting configuration",
        tips: ["Balance security with user experience", "Create allowlists for legitimate high-volume sources"]
      },
      {
        step: 5,
        title: "Document Rate Limiting Strategy",
        description: "Create operational documentation",
        commands: `cat << 'EOF' > rate_limiting_runbook.md
# Rate Limiting Runbook

## Current Configuration
- L3/L4: iptables limiting new connections to 50/s per IP
- L7: nginx limiting to 10 req/s per IP (burst 20)

## Emergency Procedures

### To tighten limits during attack:
\`\`\`bash
# Reduce nginx limit
sed -i 's/rate=10r/rate=5r/' /etc/nginx/conf.d/rate_limit.conf
nginx -s reload
\`\`\`

### To disable rate limiting:
\`\`\`bash
# nginx
mv /etc/nginx/conf.d/rate_limit.conf /tmp/
nginx -s reload

# iptables
iptables -F
\`\`\`

## Monitoring
- Watch: tail -f /var/log/nginx/access.log | grep 429
- Dashboard: http://grafana:3000/d/rate-limits
EOF`,
        expectedOutput: "Complete rate limiting documentation",
        tips: ["Document how to adjust limits quickly", "Include rollback procedures"]
      }
    ],
    quiz: [
      {
        question: "What HTTP status code indicates rate limiting?",
        options: ["403 Forbidden", "429 Too Many Requests", "503 Service Unavailable", "504 Gateway Timeout"],
        correctIndex: 1,
        explanation: "429 Too Many Requests is the standard response for rate limiting."
      },
      {
        question: "Why use both iptables AND nginx rate limiting?",
        options: [
          "They do the same thing",
          "Defense in depth - iptables stops L3/L4, nginx stops L7",
          "One is for inbound, one for outbound",
          "iptables is faster"
        ],
        correctIndex: 1,
        explanation: "Defense in depth: iptables filters at network layer before packets reach nginx, while nginx can make application-aware decisions."
      }
    ]
  }
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
  const navigate = useNavigate();
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
          <Tab icon={<SchoolIcon />} label="Fundamentals" />
          <Tab icon={<WarningIcon />} label="Overview" />
          <Tab icon={<CloudIcon />} label="Attack Types" />
          <Tab icon={<SpeedIcon />} label="Amplification" />
          <Tab icon={<RouterIcon />} label="Botnets" />
          <Tab icon={<ShieldIcon />} label="Mitigation" />
          <Tab icon={<NetworkCheckIcon />} label="Detection" />
          <Tab icon={<ScienceIcon />} label="Safe Lab" />
          <Tab icon={<GavelIcon />} label="Legal & Ethics" />
        </Tabs>
      </Paper>

      {/* Tab 0: Fundamentals */}
      <TabPanel value={tabValue} index={0}>
        <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <SchoolIcon color="primary" />
          DDoS Fundamentals for Beginners
        </Typography>

        <Alert severity="success" sx={{ mb: 3 }}>
          <AlertTitle>Start Here If You're New!</AlertTitle>
          This section explains DDoS concepts from the ground up. No prior networking knowledge required.
          Work through each section in order for the best learning experience.
        </Alert>

        {/* What is DDoS */}
        <Accordion defaultExpanded sx={{ mb: 2, border: '2px solid', borderColor: 'primary.main' }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: 'primary.dark' }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Typography variant="h4">{ddosFundamentals.whatIsDDoS.icon}</Typography>
              <Box>
                <Typography variant="h6" color="white">{ddosFundamentals.whatIsDDoS.title}</Typography>
                <Typography variant="caption" color="rgba(255,255,255,0.7)">Essential • 5 min read</Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 2 }}>
              <AlertTitle>Beginner-Friendly Explanation</AlertTitle>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                {ddosFundamentals.whatIsDDoS.beginnerExplanation}
              </Typography>
            </Alert>

            <Paper sx={{ p: 2, mb: 2, bgcolor: 'success.dark' }}>
              <Typography variant="subtitle1" fontWeight="bold" color="white" gutterBottom>
                🍕 {ddosFundamentals.whatIsDDoS.realWorldAnalogy}
              </Typography>
              <Typography variant="body2" color="rgba(255,255,255,0.9)" sx={{ whiteSpace: 'pre-line' }}>
                {ddosFundamentals.whatIsDDoS.analogyExplanation}
              </Typography>
            </Paper>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">🔧 Technical Details (Advanced)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-line', fontFamily: 'monospace' }}>
                  {ddosFundamentals.whatIsDDoS.technicalDetails}
                </Typography>
              </AccordionDetails>
            </Accordion>

            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Key Takeaways:</Typography>
            <List dense>
              {ddosFundamentals.whatIsDDoS.keyPoints.map((point, idx) => (
                <ListItem key={idx}>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary={point} />
                </ListItem>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>

        {/* How Internet Works */}
        <Accordion sx={{ mb: 2, border: '2px solid', borderColor: 'info.main' }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: 'info.dark' }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Typography variant="h4">{ddosFundamentals.howInternetWorks.icon}</Typography>
              <Box>
                <Typography variant="h6" color="white">{ddosFundamentals.howInternetWorks.title}</Typography>
                <Typography variant="caption" color="rgba(255,255,255,0.7)">Background Knowledge • 4 min read</Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 2 }}>
              <AlertTitle>Understanding the Basics</AlertTitle>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                {ddosFundamentals.howInternetWorks.beginnerExplanation}
              </Typography>
            </Alert>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">🔧 Technical Details (Network Layers)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-line', fontFamily: 'monospace' }}>
                  {ddosFundamentals.howInternetWorks.technicalDetails}
                </Typography>
              </AccordionDetails>
            </Accordion>

            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Key Takeaways:</Typography>
            <List dense>
              {ddosFundamentals.howInternetWorks.keyPoints.map((point, idx) => (
                <ListItem key={idx}>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary={point} />
                </ListItem>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>

        {/* Bandwidth */}
        <Accordion sx={{ mb: 2, border: '2px solid', borderColor: 'warning.main' }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: 'warning.dark' }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Typography variant="h4">{ddosFundamentals.bandwidth.icon}</Typography>
              <Box>
                <Typography variant="h6" color="white">{ddosFundamentals.bandwidth.title}</Typography>
                <Typography variant="caption" color="rgba(255,255,255,0.7)">Core Concept • 3 min read</Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 2 }}>
              <AlertTitle>The Highway Analogy</AlertTitle>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                {ddosFundamentals.bandwidth.beginnerExplanation}
              </Typography>
            </Alert>

            <CodeBlock language="diagram">{visualLearningAids.bandwidthPipeDiagram}</CodeBlock>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">🔧 Technical Details</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-line', fontFamily: 'monospace' }}>
                  {ddosFundamentals.bandwidth.technicalDetails}
                </Typography>
              </AccordionDetails>
            </Accordion>

            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Key Takeaways:</Typography>
            <List dense>
              {ddosFundamentals.bandwidth.keyPoints.map((point, idx) => (
                <ListItem key={idx}>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary={point} />
                </ListItem>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>

        {/* Packets and Connections */}
        <Accordion sx={{ mb: 2, border: '2px solid', borderColor: 'secondary.main' }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: 'secondary.dark' }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Typography variant="h4">{ddosFundamentals.packetsAndConnections.icon}</Typography>
              <Box>
                <Typography variant="h6" color="white">{ddosFundamentals.packetsAndConnections.title}</Typography>
                <Typography variant="caption" color="rgba(255,255,255,0.7)">Core Concept • 4 min read</Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 2 }}>
              <AlertTitle>Data Travels in Packets</AlertTitle>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                {ddosFundamentals.packetsAndConnections.beginnerExplanation}
              </Typography>
            </Alert>

            <CodeBlock language="diagram">{visualLearningAids.tcpHandshakeDiagram}</CodeBlock>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">🔧 Technical Details (TCP Handshake)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-line', fontFamily: 'monospace' }}>
                  {ddosFundamentals.packetsAndConnections.technicalDetails}
                </Typography>
              </AccordionDetails>
            </Accordion>

            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Key Takeaways:</Typography>
            <List dense>
              {ddosFundamentals.packetsAndConnections.keyPoints.map((point, idx) => (
                <ListItem key={idx}>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary={point} />
                </ListItem>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>

        {/* DoS vs DDoS */}
        <Accordion sx={{ mb: 2, border: '2px solid', borderColor: 'error.main' }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: 'error.dark' }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Typography variant="h4">{ddosFundamentals.dosVsDDoS.icon}</Typography>
              <Box>
                <Typography variant="h6" color="white">{ddosFundamentals.dosVsDDoS.title}</Typography>
                <Typography variant="caption" color="rgba(255,255,255,0.7)">Key Distinction • 3 min read</Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 2 }}>
              <AlertTitle>The Critical Difference</AlertTitle>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                {ddosFundamentals.dosVsDDoS.beginnerExplanation}
              </Typography>
            </Alert>

            <CodeBlock language="diagram">{visualLearningAids.ddosVsDosDiagram}</CodeBlock>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">🔧 Technical Comparison</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-line', fontFamily: 'monospace' }}>
                  {ddosFundamentals.dosVsDDoS.technicalDetails}
                </Typography>
              </AccordionDetails>
            </Accordion>

            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Key Takeaways:</Typography>
            <List dense>
              {ddosFundamentals.dosVsDDoS.keyPoints.map((point, idx) => (
                <ListItem key={idx}>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary={point} />
                </ListItem>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>

        {/* Attack Metrics */}
        <Accordion sx={{ mb: 2, border: '2px solid', borderColor: 'success.main' }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: 'success.dark' }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Typography variant="h4">{ddosFundamentals.attackMetrics.icon}</Typography>
              <Box>
                <Typography variant="h6" color="white">{ddosFundamentals.attackMetrics.title}</Typography>
                <Typography variant="caption" color="rgba(255,255,255,0.7)">Understanding Scale • 4 min read</Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 2 }}>
              <AlertTitle>Three Ways to Measure Attacks</AlertTitle>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                {ddosFundamentals.attackMetrics.beginnerExplanation}
              </Typography>
            </Alert>

            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">🔧 Why Different Metrics Matter</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-line', fontFamily: 'monospace' }}>
                  {ddosFundamentals.attackMetrics.technicalDetails}
                </Typography>
              </AccordionDetails>
            </Accordion>

            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Key Takeaways:</Typography>
            <List dense>
              {ddosFundamentals.attackMetrics.keyPoints.map((point, idx) => (
                <ListItem key={idx}>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary={point} />
                </ListItem>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>

        <Divider sx={{ my: 4 }} />

        {/* Expanded Glossary */}
        <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <MenuBookIcon color="primary" />
          DDoS Glossary
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Key terms you'll encounter when learning about DDoS attacks. Click to expand each term for a detailed explanation.
        </Typography>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          {Object.entries(expandedGlossary).map(([key, term]) => (
            <Grid item xs={12} md={6} key={key}>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                    <Typography fontWeight="bold">{term.term}</Typography>
                    <Chip 
                      label={term.difficulty} 
                      size="small" 
                      color={term.difficulty === 'beginner' ? 'success' : term.difficulty === 'intermediate' ? 'warning' : 'error'}
                      sx={{ ml: 'auto' }}
                    />
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>{term.definition}</Typography>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    <AlertTitle>Example</AlertTitle>
                    {term.example}
                  </Alert>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                    <Typography variant="caption" color="text.secondary">Related:</Typography>
                    {term.relatedTerms.map((related) => (
                      <Chip key={related} label={related} size="small" variant="outlined" />
                    ))}
                  </Box>
                </AccordionDetails>
              </Accordion>
            </Grid>
          ))}
        </Grid>

        <Divider sx={{ my: 4 }} />

        {/* Real-World Incidents */}
        <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <TimelineIcon color="error" />
          Notable DDoS Incidents
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Learn from real attacks that made headlines. Understanding what happened helps you defend against future attacks.
        </Typography>

        {realWorldIncidents.map((incident) => (
          <Accordion key={incident.name} sx={{ mb: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                <Typography variant="h6">{incident.name}</Typography>
                <Chip label={incident.attackSize} color="error" size="small" />
                <Chip label={incident.attackType} size="small" sx={{ ml: "auto" }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={8}>
                  <Typography paragraph>{incident.description}</Typography>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    <AlertTitle>Outcome</AlertTitle>
                    {incident.outcome}
                  </Alert>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, bgcolor: "action.hover" }}>
                    <Typography variant="subtitle2" fontWeight="bold">Attack Details</Typography>
                    <List dense>
                      <ListItem>
                        <ListItemText primary="Target" secondary={incident.target} />
                      </ListItem>
                      <ListItem>
                        <ListItemText primary="Size" secondary={incident.attackSize} />
                      </ListItem>
                      <ListItem>
                        <ListItemText primary="Duration" secondary={incident.duration} />
                      </ListItem>
                      <ListItem>
                        <ListItemText primary="Type" secondary={incident.attackType} />
                      </ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom sx={{ mt: 2 }}>
                Lessons Learned:
              </Typography>
              <List dense>
                {incident.lessonsLearned.map((lesson, idx) => (
                  <ListItem key={idx}>
                    <ListItemIcon><LightbulbIcon color="warning" /></ListItemIcon>
                    <ListItemText primary={lesson} />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        ))}

        <Divider sx={{ my: 4 }} />

        {/* Knowledge Check Quiz */}
        <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <QuizIcon color="secondary" />
          Knowledge Check
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Test your understanding of DDoS fundamentals. Click on an answer to check if you're right!
        </Typography>

        {beginnerQuiz.map((q, qIdx) => (
          <Accordion key={qIdx} sx={{ mb: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Question {qIdx + 1}: {q.question}</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={1}>
                {q.options.map((option, oIdx) => (
                  <Grid item xs={12} sm={6} key={oIdx}>
                    <Paper 
                      sx={{ 
                        p: 2, 
                        cursor: "pointer",
                        border: "2px solid",
                        borderColor: oIdx === q.correctIndex ? "success.main" : "divider",
                        bgcolor: oIdx === q.correctIndex ? "success.dark" : "background.paper",
                        "&:hover": { borderColor: "primary.main" }
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        {oIdx === q.correctIndex ? (
                          <CheckCircleIcon color="success" />
                        ) : (
                          <CancelIcon color="disabled" />
                        )}
                        <Typography color={oIdx === q.correctIndex ? "white" : "text.primary"}>
                          {option}
                        </Typography>
                      </Box>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
              <Alert severity="success" sx={{ mt: 2 }}>
                <AlertTitle>Explanation</AlertTitle>
                {q.explanation}
              </Alert>
            </AccordionDetails>
          </Accordion>
        ))}
      </TabPanel>

      {/* Tab 1: Overview */}
      <TabPanel value={tabValue} index={1}>
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

      {/* Tab 2: Attack Types */}
      <TabPanel value={tabValue} index={2}>
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

        <Typography variant="h6" sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
          <MenuBookIcon color="primary" />
          Attack Comparison Matrix
        </Typography>
        <TableContainer component={Paper} sx={{ mb: 4 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: "primary.dark" }}>
                <TableCell sx={{ color: "white" }}><strong>Attack Type</strong></TableCell>
                <TableCell sx={{ color: "white" }}><strong>Layer</strong></TableCell>
                <TableCell sx={{ color: "white" }}><strong>Measurement</strong></TableCell>
                <TableCell sx={{ color: "white" }}><strong>Difficulty</strong></TableCell>
                <TableCell sx={{ color: "white" }}><strong>Primary Defense</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {attackComparison.map((row) => (
                <TableRow key={row.attack}>
                  <TableCell><strong>{row.attack}</strong></TableCell>
                  <TableCell><Chip label={`Layer ${row.layer}`} size="small" /></TableCell>
                  <TableCell>{row.measurement}</TableCell>
                  <TableCell>
                    <Chip 
                      label={row.difficulty} 
                      size="small" 
                      color={row.difficulty === 'Easy' ? 'success' : row.difficulty === 'Medium' ? 'warning' : 'error'} 
                    />
                  </TableCell>
                  <TableCell><Typography variant="body2">{row.defense}</Typography></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        
        <Typography variant="h5" gutterBottom sx={{ mt: 4, display: "flex", alignItems: "center", gap: 1 }}>
          <BugReportIcon color="error" />
          Attack Deep Dives
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Click on each attack type to learn how it works, see packet structures, and understand detection and defense.
        </Typography>

        {Object.entries(attackTypeDeepDives).map(([key, attack]) => (
          <Accordion key={key} sx={{ mb: 2, border: '2px solid', borderColor: attack.category === 'volumetric' ? 'error.main' : attack.category === 'protocol' ? 'warning.main' : 'info.main' }}>
            <AccordionSummary 
              expandIcon={<ExpandMoreIcon />}
              sx={{ bgcolor: attack.category === 'volumetric' ? 'error.dark' : attack.category === 'protocol' ? 'warning.dark' : 'info.dark' }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                <Typography variant="h5">{attack.icon}</Typography>
                <Box sx={{ flexGrow: 1 }}>
                  <Typography variant="h6" color="white">{attack.name}</Typography>
                  <Typography variant="caption" color="rgba(255,255,255,0.7)">
                    {attack.category.toUpperCase()} • Execute: {attack.difficultyToExecute} • Defend: {attack.difficultyToDefend}
                  </Typography>
                </Box>
                <Chip 
                  label={attack.category} 
                  size="small" 
                  sx={{ 
                    bgcolor: 'rgba(255,255,255,0.2)', 
                    color: 'white',
                    textTransform: 'uppercase'
                  }} 
                />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {/* Beginner Explanation */}
              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>🎓 Beginner Explanation</AlertTitle>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                  {attack.beginnerExplanation}
                </Typography>
              </Alert>

              {/* How It Works */}
              <Paper sx={{ p: 2, mb: 3, bgcolor: 'action.hover' }}>
                <Typography variant="h6" gutterBottom>How It Works</Typography>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                  {attack.howItWorks}
                </Typography>
              </Paper>

              {/* Technical Details */}
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">🔧 Technical Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ whiteSpace: 'pre-line', fontFamily: 'monospace' }}>
                    {attack.technicalDetails}
                  </Typography>
                </AccordionDetails>
              </Accordion>

              {/* Packet Structure */}
              {attack.packetStructure && (
                <Accordion sx={{ mb: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">📦 Packet Structure</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <CodeBlock language="diagram">{attack.packetStructure}</CodeBlock>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Attack Timeline */}
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">⏱️ Attack Timeline</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock language="timeline">{attack.attackTimeline}</CodeBlock>
                </AccordionDetails>
              </Accordion>

              {/* Real World Example */}
              <Paper sx={{ p: 2, mb: 3, bgcolor: 'error.dark' }}>
                <Typography variant="h6" color="white" gutterBottom>
                  🌍 Real-World Example: {attack.realWorldExample.name}
                </Typography>
                <Typography variant="caption" color="rgba(255,255,255,0.7)">
                  {attack.realWorldExample.date}
                </Typography>
                <Typography variant="body2" color="rgba(255,255,255,0.9)" sx={{ mt: 1 }}>
                  {attack.realWorldExample.description}
                </Typography>
              </Paper>

              <Grid container spacing={2}>
                {/* Indicators */}
                <Grid item xs={12} md={6}>
                  <Card>
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                        <SearchIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                        Detection Indicators
                      </Typography>
                      <List dense>
                        {attack.indicators.map((indicator, idx) => (
                          <ListItem key={idx}>
                            <ListItemIcon><WarningIcon color="warning" fontSize="small" /></ListItemIcon>
                            <ListItemText primary={indicator} />
                          </ListItem>
                        ))}
                      </List>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Defenses */}
                <Grid item xs={12} md={6}>
                  <Card>
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                        <ShieldIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                        Defenses
                      </Typography>
                      <List dense>
                        {attack.defenses.map((defense, idx) => (
                          <ListItem key={idx}>
                            <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                            <ListItemText primary={defense} />
                          </ListItem>
                        ))}
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>

              {/* Code Example */}
              {attack.codeExample && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                    💻 Detection & Defense Commands
                  </Typography>
                  <CodeBlock language="bash">{attack.codeExample}</CodeBlock>
                </Box>
              )}
            </AccordionDetails>
          </Accordion>
        ))}

        <Divider sx={{ my: 4 }} />

        <Typography variant="h5" gutterBottom>Original Attack Categories</Typography>
        
        {attackCategories.map((category) => (
          <Accordion key={category.name}>
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

      {/* Tab 3: Amplification */}
      <TabPanel value={tabValue} index={3}>
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

      {/* Tab 4: Botnets */}
      <TabPanel value={tabValue} index={4}>
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

      {/* Tab 5: Mitigation */}
      <TabPanel value={tabValue} index={5}>
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

      {/* Tab 6: Detection */}
      <TabPanel value={tabValue} index={6}>
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

      {/* Tab 7: Safe Lab */}
      <TabPanel value={tabValue} index={7}>
        <Typography variant="h5" gutterBottom>🧪 DDoS Defense Lab Environment</Typography>
        
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>Safe Practice Environment</AlertTitle>
          These labs are designed to be run in isolated virtual environments or containers.
          <strong> NEVER test DDoS techniques on production systems or networks you don't own!</strong>
          All exercises use safe, controlled traffic generation within your own lab.
        </Alert>

        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" gutterBottom color="primary">
            <MenuBookIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Hands-On Lab Exercises
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Complete these labs in order to build your DDoS defense skills progressively.
          </Typography>
        </Box>

        {/* Lab Exercises */}
        {labExercisesDetailed.map((lab, labIndex) => (
          <Accordion key={lab.id} sx={{ mb: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', gap: 2 }}>
                <Avatar sx={{ 
                  bgcolor: lab.difficulty === 'beginner' ? 'success.main' : 
                           lab.difficulty === 'intermediate' ? 'warning.main' : 'error.main',
                  width: 40, height: 40
                }}>
                  {labIndex + 1}
                </Avatar>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="h6">{lab.title}</Typography>
                  <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                    <Chip 
                      size="small" 
                      label={lab.difficulty}
                      color={lab.difficulty === 'beginner' ? 'success' : 
                             lab.difficulty === 'intermediate' ? 'warning' : 'error'}
                    />
                    <Chip size="small" label={lab.duration} icon={<TimelineIcon />} variant="outlined" />
                  </Box>
                </Box>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {/* Description */}
              <Typography variant="body1" sx={{ mb: 3 }}>{lab.description}</Typography>

              {/* Objectives */}
              <Paper sx={{ p: 2, mb: 3, bgcolor: 'success.50', border: '1px solid', borderColor: 'success.200' }}>
                <Typography variant="subtitle1" fontWeight="bold" color="success.dark" gutterBottom>
                  🎯 Learning Objectives
                </Typography>
                <List dense>
                  {lab.objectives.map((obj, i) => (
                    <ListItem key={i}>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary={obj} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              {/* Prerequisites */}
              <Paper sx={{ p: 2, mb: 3, bgcolor: 'warning.50', border: '1px solid', borderColor: 'warning.200' }}>
                <Typography variant="subtitle1" fontWeight="bold" color="warning.dark" gutterBottom>
                  📋 Prerequisites
                </Typography>
                <List dense>
                  {lab.prerequisites.map((prereq, i) => (
                    <ListItem key={i}>
                      <ListItemIcon><SecurityIcon color="warning" fontSize="small" /></ListItemIcon>
                      <ListItemText primary={prereq} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              {/* Lab Environment */}
              <Paper sx={{ p: 2, mb: 3, bgcolor: 'info.50', border: '1px solid', borderColor: 'info.200' }}>
                <Typography variant="subtitle1" fontWeight="bold" color="info.dark" gutterBottom>
                  🖥️ Lab Environment Setup
                </Typography>
                <CodeBlock language="text">
                  {lab.labEnvironment}
                </CodeBlock>
              </Paper>

              <Divider sx={{ my: 3 }} />

              {/* Steps */}
              <Typography variant="h6" gutterBottom color="primary">
                📝 Step-by-Step Instructions
              </Typography>
              
              {lab.steps.map((step) => (
                <Paper key={step.step} sx={{ p: 2, mb: 2, border: '1px solid', borderColor: 'divider' }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                    <Avatar sx={{ bgcolor: 'primary.main', width: 32, height: 32, fontSize: '0.9rem' }}>
                      {step.step}
                    </Avatar>
                    <Typography variant="subtitle1" fontWeight="bold">{step.title}</Typography>
                  </Box>
                  
                  <Typography variant="body2" sx={{ mb: 2 }}>{step.description}</Typography>
                  
                  {step.commands && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="caption" color="text.secondary">Commands:</Typography>
                      <CodeBlock language="bash">
                        {step.commands}
                      </CodeBlock>
                    </Box>
                  )}
                  
                  {step.expectedOutput && (
                    <Accordion sx={{ bgcolor: 'grey.50' }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="body2" color="text.secondary">
                          👁️ Expected Output
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <CodeBlock language="text">
                          {step.expectedOutput}
                        </CodeBlock>
                      </AccordionDetails>
                    </Accordion>
                  )}
                  
                  {step.tips && step.tips.length > 0 && (
                    <Alert severity="info" sx={{ mt: 2 }}>
                      <AlertTitle>💡 Tips</AlertTitle>
                      <ul style={{ margin: 0, paddingLeft: 20 }}>
                        {step.tips.map((tip, i) => (
                          <li key={i}><Typography variant="body2">{tip}</Typography></li>
                        ))}
                      </ul>
                    </Alert>
                  )}
                </Paper>
              ))}

              <Divider sx={{ my: 3 }} />

              {/* Quiz Section */}
              <Paper sx={{ p: 3, bgcolor: 'secondary.50', border: '2px solid', borderColor: 'secondary.200' }}>
                <Typography variant="h6" gutterBottom color="secondary.dark">
                  <QuizIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  Lab Knowledge Check
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Test your understanding of the concepts covered in this lab.
                </Typography>
                
                {lab.quiz.map((q, qIndex) => (
                  <Accordion key={qIndex} sx={{ mb: 1 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="body1">
                        <strong>Q{qIndex + 1}:</strong> {q.question}
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{ mb: 2 }}>
                        {q.options.map((option, optIdx) => (
                          <Chip 
                            key={optIdx}
                            label={option}
                            color={optIdx === q.correctIndex ? 'success' : 'default'}
                            variant={optIdx === q.correctIndex ? 'filled' : 'outlined'}
                            sx={{ m: 0.5 }}
                            icon={optIdx === q.correctIndex ? <CheckCircleIcon /> : undefined}
                          />
                        ))}
                      </Box>
                      <Alert severity="success">
                        <AlertTitle>Correct Answer</AlertTitle>
                        {q.options[q.correctIndex]}
                      </Alert>
                      {q.explanation && (
                        <Typography variant="body2" sx={{ mt: 2, color: 'text.secondary' }}>
                          <strong>Explanation:</strong> {q.explanation}
                        </Typography>
                      )}
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Paper>
            </AccordionDetails>
          </Accordion>
        ))}

        {/* Detection Methodology Deep Dives */}
        <Box sx={{ mt: 5, mb: 4 }}>
          <Typography variant="h6" gutterBottom color="primary">
            <AnalyticsIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Detection Methodology Deep Dives
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Advanced techniques for identifying and analyzing DDoS attacks.
          </Typography>
        </Box>

        {Object.entries(detectionMethodologyDetailed).map(([key, methodology]) => (
          <Accordion key={key} sx={{ mb: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Avatar sx={{ bgcolor: 'error.main' }}>
                  {methodology.icon === '📡' ? <NetworkCheckIcon /> : 
                   methodology.icon === '📋' ? <StorageIcon /> : <SearchIcon />}
                </Avatar>
                <Box>
                  <Typography variant="h6">{methodology.title}</Typography>
                  <Typography variant="body2" color="text.secondary">{methodology.description}</Typography>
                </Box>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {/* Approach Overview */}
              {methodology.approach && (
                <Paper sx={{ p: 2, mb: 3, bgcolor: 'grey.50' }}>
                  <Typography variant="body2" style={{ whiteSpace: 'pre-line' }}>
                    {methodology.approach}
                  </Typography>
                </Paper>
              )}

              {/* Steps */}
              {methodology.steps.map((step, stepIndex) => (
                <Paper key={stepIndex} sx={{ p: 2, mb: 2, border: '1px solid', borderColor: 'divider' }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                    <Avatar sx={{ bgcolor: 'primary.main', width: 32, height: 32, fontSize: '0.9rem' }}>
                      {step.step}
                    </Avatar>
                    <Typography variant="subtitle1" fontWeight="bold">{step.title}</Typography>
                  </Box>
                  <Typography variant="body2" sx={{ mb: 2 }}>{step.description}</Typography>
                  
                  {step.commands && (
                    <Box sx={{ mb: 2 }}>
                      <CodeBlock language="bash">
                        {step.commands}
                      </CodeBlock>
                    </Box>
                  )}
                  
                  {step.tips && step.tips.length > 0 && (
                    <Alert severity="info" sx={{ mt: 2 }}>
                      <ul style={{ margin: 0, paddingLeft: 20 }}>
                        {step.tips.map((tip, i) => (
                          <li key={i}><Typography variant="body2">{tip}</Typography></li>
                        ))}
                      </ul>
                    </Alert>
                  )}
                </Paper>
              ))}

              {/* Indicators */}
              {methodology.indicators && methodology.indicators.length > 0 && (
                <Paper sx={{ p: 2, mb: 2, bgcolor: 'error.50', border: '1px solid', borderColor: 'error.200' }}>
                  <Typography variant="subtitle1" fontWeight="bold" color="error.dark" gutterBottom>
                    🚨 Key Indicators
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {methodology.indicators.map((indicator: string, i: number) => (
                      <Chip key={i} label={indicator} size="small" color="error" variant="outlined" />
                    ))}
                  </Box>
                </Paper>
              )}

              {/* Tools */}
              {methodology.tools && methodology.tools.length > 0 && (
                <Paper sx={{ p: 2, bgcolor: 'primary.50', border: '1px solid', borderColor: 'primary.200' }}>
                  <Typography variant="subtitle1" fontWeight="bold" color="primary.dark" gutterBottom>
                    🛠️ Recommended Tools
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {methodology.tools.map((tool: string, i: number) => (
                      <Chip key={i} label={tool} size="small" color="primary" variant="outlined" />
                    ))}
                  </Box>
                </Paper>
              )}
            </AccordionDetails>
          </Accordion>
        ))}

        {/* Lab Completion Checklist */}
        <Paper sx={{ p: 3, mt: 4, bgcolor: 'success.50', border: '2px solid', borderColor: 'success.300' }}>
          <Typography variant="h6" gutterBottom color="success.dark">
            ✅ Skills Acquired After Completing All Labs
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <List dense>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Analyze DDoS attack traffic with Wireshark and tshark" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Configure SYN cookies and kernel-level defenses" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Implement rate limiting with iptables" />
                </ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <List dense>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Configure nginx for connection rate limiting" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Identify attack patterns from network metrics" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText primary="Apply detection methodologies in real scenarios" />
                </ListItem>
              </List>
            </Grid>
          </Grid>
        </Paper>
      </TabPanel>

      {/* Tab 8: Legal & Ethics */}
      <TabPanel value={tabValue} index={8}>
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

      {/* Bottom Navigation */}
      <Box sx={{ mt: 4, textAlign: "center" }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate("/learn")}
          sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
        >
          Back to Learning Hub
        </Button>
      </Box>
    </Box>
    </LearnPageLayout>
  );
};

export default DDoSAttackTechniquesPage;
