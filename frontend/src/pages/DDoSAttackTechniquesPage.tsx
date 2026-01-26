import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Box,
  Typography,
  Paper,
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
  Container,
  useTheme,
  Drawer,
  Fab,
  IconButton,
  LinearProgress,
  useMediaQuery,
  alpha,
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
import InfoIcon from "@mui/icons-material/Info";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import LearnPageLayout from "../components/LearnPageLayout";

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
  },
  typesOfDDoS: {
    title: "Types of DDoS Attacks",
    icon: "🎭",
    beginnerExplanation: `DDoS attacks come in three main flavors, each targeting different parts of the network:

1. VOLUMETRIC - Flood the network with raw data
2. PROTOCOL - Exploit weaknesses in network protocols  
3. APPLICATION - Target specific applications with smart requests

Understanding these categories helps you identify and defend against different attacks.`,
    categories: [
      { name: "Volumetric", color: "#f44336", description: "Overwhelm bandwidth with massive traffic (UDP floods, amplification)" },
      { name: "Protocol", color: "#ff9800", description: "Exhaust server resources with protocol exploits (SYN floods)" },
      { name: "Application", color: "#9c27b0", description: "Target app layer with expensive requests (HTTP floods, Slowloris)" }
    ]
  },
  realWorldExamples: {
    title: "Famous DDoS Attacks",
    icon: "📰",
    intro: "These real-world attacks show how devastating DDoS can be and what we can learn from them:",
    examples: [
      { name: "GitHub Attack", year: "2018", impact: "1.35 Tbps - largest at the time", method: "Memcached amplification", lesson: "Even giants are vulnerable; proper DDoS protection is essential" },
      { name: "Dyn DNS Attack", year: "2016", impact: "Major websites down (Twitter, Netflix, Reddit)", method: "Mirai botnet IoT devices", lesson: "IoT security matters; DNS is a critical single point of failure" },
      { name: "AWS Shield Attack", year: "2020", impact: "2.3 Tbps - largest ever mitigated", method: "CLDAP reflection", lesson: "Cloud providers offer massive absorption capacity" }
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
    name: "GitHub (2018) - When Memcached Became a Weapon",
    target: "GitHub.com",
    attackSize: "1.35 Tbps",
    duration: "~20 minutes",
    attackType: "Memcached Amplification",
    description: "**On February 28, 2018, GitHub experienced the largest DDoS attack ever recorded at that time** - a staggering 1.35 terabits per second of traffic. The attack exploited misconfigured Memcached servers across the internet. Memcached is a caching system used to speed up websites, but when exposed on UDP port 11211 without authentication, it can be abused for amplification attacks with a factor of up to 51,000x.\n\nThe attackers sent small queries (about 15 bytes) to thousands of exposed Memcached servers with GitHub's IP as the source address. Each server responded with massive payloads (up to 750KB), flooding GitHub with traffic. **Within minutes, GitHub's infrastructure was overwhelmed**, but their DDoS mitigation kicked in automatically, routing traffic through Akamai's scrubbing centers.\n\n**What made this attack significant:** It demonstrated that even tech giants with sophisticated defenses can be brought to their knees by protocol-level vulnerabilities. The attack also sparked an immediate global response - network operators and cloud providers began scanning for and patching exposed Memcached servers. Within weeks, the number of vulnerable servers dropped by over 80%.",
    outcome: "GitHub was intermittently unavailable for about 10 minutes. Their DDoS protection worked as designed, automatically detecting the attack and rerouting traffic. The real-world impact to users was minimal thanks to rapid mitigation, but the incident made headlines as the 'largest DDoS attack ever' and raised awareness about amplification vectors.",
    lessonsLearned: [
      "**Memcached UDP should be disabled or firewalled:** The attack exploited a feature (UDP support) that most Memcached deployments don't even need. After this attack, the Memcached team changed defaults to disable UDP by default. Lesson: Review what protocols/ports your services expose and close anything unnecessary.",
      "**Automatic DDoS mitigation is essential for high-profile targets:** GitHub's defenses activated within 10 minutes without human intervention. Manual response would have taken 30-60 minutes - an eternity during an attack. If you're a likely target, invest in automated defenses that react in seconds, not minutes.",
      "**Amplification attacks can generate enormous traffic from minimal resources:** The attackers needed relatively little bandwidth themselves - they weaponized internet infrastructure to do the heavy lifting. This is why securing misconfigured services matters: YOUR server might be weaponized against someone else without you even knowing.",
      "**Defense in depth works:** GitHub had multiple layers - ISP-level filtering, Akamai scrubbing, and application-level protections. When one layer was overwhelmed, others picked up the slack. Don't rely on a single point of defense."
    ],
    difficulty: "intermediate"
  },
  {
    name: "Dyn DNS (2016) - The Mirai Botnet's Wake-Up Call",
    target: "Dyn DNS infrastructure",
    attackSize: "1.2 Tbps",
    duration: "Most of the day (three waves)",
    attackType: "Mirai Botnet (IoT-based)",
    description: "**On October 21, 2016, the internet broke for millions of users on the US East Coast.** The Mirai botnet, consisting of over 100,000 compromised IoT devices (security cameras, DVRs, routers), launched a massive DDoS attack against Dyn, a major DNS provider. Since Dyn provided DNS services for companies like Twitter, Netflix, Reddit, GitHub, and CNN, taking down Dyn effectively made these services unreachable for huge portions of the internet.\n\n**How IoT devices became weapons:** The Mirai malware automatically scanned the internet for IoT devices with default or weak credentials (admin/admin, root/password, etc.), infected them, and added them to a botnet. Most device owners had no idea their security cameras were part of a global attack infrastructure. The attack came in three waves throughout the day, suggesting attackers were testing different tactics and overwhelmed defenses each time.\n\n**The DNS single point of failure:** DNS is like the phone book of the internet - without it, you can't translate 'twitter.com' into an IP address to connect. By attacking DNS providers, attackers can make hundreds of websites simultaneously unreachable without targeting those sites directly. This attack exposed how much of the internet's critical infrastructure is concentrated in a few providers.",
    outcome: "Major internet outage affecting the East Coast US for most of the day. Millions of users couldn't access major websites. The incident highlighted both the vulnerability of centralized DNS infrastructure and the security nightmare of IoT devices. It sparked conversations about IoT security that continue today.",
    lessonsLearned: [
      "**IoT devices are a massive security risk due to default credentials:** The Mirai source code (released publicly after the attack) showed how trivial it was to compromise these devices. Manufacturers rarely patch IoT firmware, and users rarely change defaults. If you have IoT devices, isolate them on a separate network and change all default passwords immediately.",
      "**DNS is a critical single point of failure for many services:** Companies learned to use multiple DNS providers (NS1 + Cloudflare, for example) so that if one is attacked, the other can handle traffic. Never rely on a single DNS provider for critical infrastructure - it's a single point of failure attackers love to target.",
      "**The 'Defense in Depth' principle applies to infrastructure choices:** Don't put all your eggs in one basket. Use multiple DNS providers, multiple CDNs, multiple regions. Yes, it's more complex and expensive, but when Dyn went down, companies with backup DNS providers stayed online while their competitors went dark."
    ],
    difficulty: "beginner"
  },
  {
    name: "AWS (2020) - Setting the Record with CLDAP",
    target: "AWS customer (unnamed)",
    attackSize: "2.3 Tbps - The largest ever recorded",
    duration: "3 days with multiple peaks",
    attackType: "CLDAP Reflection/Amplification",
    description: "**In February 2020, AWS Shield mitigated the largest DDoS attack ever recorded** - a crushing 2.3 terabits per second directed at an AWS customer. The attack exploited CLDAP (Connectionless LDAP), a protocol used by Microsoft Active Directory for authentication queries. When misconfigured CLDAP servers are exposed to the internet, they can be abused for amplification attacks with factors of 56-70x.\n\n**How the attack worked:** Attackers sent small CLDAP queries to thousands of misconfigured Active Directory servers, spoofing the victim's IP address. These servers responded with much larger LDAP search results, flooding the target. The attack persisted for 3 days, with multiple peaks as attackers adjusted their tactics and AWS fine-tuned defenses in real-time.\n\n**AWS infrastructure absorbed the impact:** The attack would have completely overwhelmed most organizations, but AWS's massive globally distributed infrastructure and AWS Shield protection absorbed the traffic. The customer experienced minimal impact - they might not have even noticed the attack was happening. This demonstrated the value of cloud-scale DDoS protection: AWS has the bandwidth and infrastructure that individual companies simply cannot match.",
    outcome: "AWS Shield automatically mitigated the attack with minimal customer impact. The customer's services remained available throughout the 3-day attack. This incident proved that cloud-scale infrastructure can absorb even record-breaking attacks - something that would have devastated on-premises infrastructure.",
    lessonsLearned: [
      "**Cloud providers have massive capacity to absorb attacks:** AWS, Google Cloud, and Azure have globally distributed infrastructure with terabits of available bandwidth. For most companies, cloud-based DDoS protection is the ONLY realistic defense against multi-terabit attacks. You literally cannot buy enough bandwidth on your own.",
      "**CLDAP servers should not be exposed to the internet:** This attack exploited misconfigured Active Directory servers that were unnecessarily internet-accessible. Lesson: Audit ALL services exposed to the internet. Just because a service CAN be exposed doesn't mean it SHOULD be. Use firewalls to restrict access to trusted networks only.",
      "**Investment in DDoS protection pays off:** AWS Shield (especially the Premium tier) costs money, but it can save your business. Calculate the cost of downtime (often $5,000-$50,000 per minute for e-commerce) and you'll see that DDoS protection is cheap insurance. One attack like this would bankrupt most companies without protection.",
      "**Modern attacks use less common protocols:** As popular amplification vectors get patched (DNS, NTP, Memcached), attackers find new ones (CLDAP, WS-Discovery, etc.). You can't just secure the 'big 3' protocols - you need continuous monitoring and a zero-trust approach to internet-exposed services."
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
    color: "#f44336",
    description: "Overwhelm bandwidth with massive traffic volume",
    longDescription: "Volumetric attacks are the most common type of DDoS. They work by flooding the target with so much traffic that the network connection becomes saturated. Think of it like trying to drink from a fire hose - there's simply too much coming at once. These attacks are measured in bits per second (bps) and can reach terabits of traffic.",
    examples: ["UDP Flood", "ICMP Flood", "DNS Amplification", "NTP Amplification"],
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
    color: "#ff9800",
    description: "Exploit weaknesses in network protocols (Layer 3/4)",
    longDescription: "Protocol attacks exploit weaknesses in how network protocols work. Instead of using raw bandwidth, they consume server resources or intermediate equipment like firewalls and load balancers. These are measured in packets per second (pps) and target the 'handshake' process that computers use to establish connections.",
    examples: ["SYN Flood", "Ping of Death", "Smurf Attack", "Fragmentation Attacks"],
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
    color: "#9c27b0",
    description: "Target application vulnerabilities (Layer 7)",
    longDescription: "Application layer attacks are the most sophisticated type. They target the actual web server or application, mimicking legitimate user behavior to evade detection. These are measured in requests per second (rps) and often require fewer resources to execute but can be devastating because they're hard to distinguish from real traffic.",
    examples: ["HTTP Flood", "Slowloris", "RUDY", "DNS Query Flood"],
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
  beginnerTips?: string[];
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
    beginnerTips: [
      "**Start with detection first:** Before defending against UDP floods, learn to recognize them. Look for sudden spikes in UDP traffic to random ports (you can see this in firewall logs or with tools like tcpdump).",
      "**UDP is 'connectionless' which makes it easy to abuse:** Unlike TCP which requires a handshake, UDP packets can be sent without any setup. This is why attackers love it - they can just fire and forget millions of packets per second.",
      "**Legitimate UDP traffic is actually quite rare on most servers:** The main legitimate UDP uses are DNS (port 53), NTP (port 123), and some VoIP. If you're seeing huge amounts of UDP to random ports like 1337 or 5555, that's almost certainly malicious.",
      "**Rate limiting is your friend but be careful:** Setting up iptables rules to limit UDP packets per second per source IP is effective, but set the limits too low and you'll block legitimate DNS queries or game traffic. Start conservative (like 100 pps) and adjust based on your normal traffic."
    ],
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
    beginnerTips: [
      "**Check 'netstat' to see the attack in action:** Run 'netstat -an | grep SYN_RECV | wc -l' on Linux. If you see thousands of connections in SYN_RECV state, you're being SYN flooded. Normal servers have just a handful of these at any time.",
      "**SYN cookies are your most important defense:** This Linux kernel feature (enabled with 'sysctl -w net.ipv4.tcp_syncookies=1') lets the server handle SYN floods WITHOUT storing each half-open connection. It's like taking a rain check instead of holding a table - you only allocate resources when the customer actually shows up (sends the final ACK).",
      "**IP spoofing makes SYN floods hard to block:** Attackers typically use fake (spoofed) source IP addresses that change constantly. You can't just block the attacker's IP because there are millions of them. This is why protocol-level defenses like SYN cookies matter more than IP blocking.",
      "**The 'backlog queue' is what fills up:** Every operating system has a limit on how many half-open TCP connections it can track (the backlog). In Linux, check it with 'sysctl net.ipv4.tcp_max_syn_backlog'. Default is often just 128-512 connections - attackers can fill this in seconds. Increase it to 4096 or higher for internet-facing servers."
    ],
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
    beginnerTips: [
      "**Look for suspicious patterns in access logs:** Legitimate users browse multiple pages, have realistic User-Agent strings, and come from residential IPs. Attack bots often request the same URL repeatedly, have missing/fake User-Agents, or come from hosting providers. Look for IPs making 100+ requests per minute to the same endpoint.",
      "**Not all HTTP requests are equal in cost:** A request for your homepage image (cached, cheap) vs a search query that scans your entire database (expensive, slow) are vastly different. Attackers target your most expensive endpoints. Identify these with profiling tools and protect them with stricter rate limits.",
      "**Modern attacks use 'low and slow' techniques:** Instead of one IP blasting 10,000 requests/sec (easy to detect), sophisticated attackers use 100,000 IPs each sending 10 requests/sec. This stays under most rate limit thresholds while still generating 1 million requests/sec total. Defense requires behavioral analysis, not just rate limiting.",
      "**Web Application Firewalls (WAFs) are essential for L7 protection:** Tools like Cloudflare, AWS WAF, or ModSecurity can identify bot behavior that simple rate limiting misses: no JavaScript execution, missing cookies, suspicious request patterns. A good WAF is worth its weight in gold for defending against HTTP floods."
    ],
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
    beginnerTips: [
      "**Apache is particularly vulnerable to Slowloris:** Each Apache connection uses a worker thread, and the default config has a limit (like 256). Once all workers are tied up waiting for slow requests, no new connections are accepted. Check 'apachectl status' during an attack - you'll see all workers in 'Reading Request' state.",
      "**The attack is surprisingly low-bandwidth:** A single laptop can take down an unprotected Apache server because Slowloris only needs to send one byte every 10-15 seconds per connection to keep it alive. It's not about flooding with traffic, it's about holding resources hostage.",
      "**Use mod_reqtimeout for Apache or switch to nginx:** Apache's mod_reqtimeout module sets aggressive timeouts for reading headers (like 'RequestReadTimeout header=20-40,MinRate=500'). Better yet, nginx is naturally resistant because it doesn't allocate a worker per connection - it can handle thousands of slow clients without breaking a sweat.",
      "**Limit connections per IP address:** Even simple connection limits help: 'iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 -j REJECT'. This prevents a single attacker IP from opening hundreds of connections. Combine this with timeout tuning for effective protection."
    ],
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
    beginnerTips: [
      "**Check if YOUR DNS server is being abused:** Run 'dig +short test.openresolver.com TXT @YOUR_SERVER_IP'. If it responds, your server is an 'open resolver' that can be abused for amplification attacks. Fix this immediately by restricting recursion to only trusted IPs in your DNS server config.",
      "**The 'ANY' query type gives maximum amplification:** DNS has different query types (A, MX, TXT, ANY, etc.). The 'ANY' query asks for all records for a domain, generating the biggest response. Many DNS servers now refuse ANY queries from untrusted sources specifically to prevent abuse.",
      "**Amplification requires IP spoofing:** The attacker must be able to send packets with a fake source IP (the victim's IP). This requires the attacker's network to not have 'BCP38' egress filtering. Good ISPs filter spoofed packets, but many residential and cheap hosting networks don't, making them sources of amplification attacks.",
      "**Response Rate Limiting (RRL) is the DNS server defense:** Modern DNS servers like BIND support RRL, which limits how many identical responses a DNS server will send to the same IP in a time window. Configure it with 'rate-limit { responses-per-second 10; };'. This prevents your DNS server from being weaponized even if it's open."
    ],
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
      name: "Spamhaus Attack (2013) - The Attack That 'Broke the Internet'",
      date: "March 2013",
      description: "When anti-spam organization Spamhaus blocked cyberbunker.com, the hosting provider retaliated with one of the largest DDoS attacks ever seen at the time. **The attack peaked at 300 Gbps** using DNS amplification from thousands of open DNS resolvers worldwide. What made this attack historic wasn't just the size - it was so massive that congestion affected major internet exchange points, causing slowdowns for millions of users who had nothing to do with Spamhaus. Cloudflare stepped in to help mitigate the attack, routing traffic through their distributed network. The attack lasted over a week, and several people were eventually arrested. **Key lesson:** Even organizations dedicated to fighting cybercrime need robust DDoS protection. The attack also highlighted the danger of open DNS resolvers - many of the amplification sources were misconfigured home routers and poorly maintained DNS servers."
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
    detailedDescription: `**Network traffic monitoring is your eyes and ears on the network.** Think of it like security cameras for your internet connection - you're constantly watching what goes in and out, looking for suspicious activity. The key principle is simple: you can't defend against what you can't see. By establishing what 'normal' looks like for YOUR specific network, you can quickly spot when something unusual is happening - like when your typical 100 Mbps traffic suddenly spikes to 10 Gbps at 3 AM.

**Why baseline metrics matter:** Every network is different. A gaming company might normally see 5 Gbps of traffic during peak hours, while a small business website might only see 50 Mbps. If you don't know your baseline, you can't tell if a spike is an attack or just Black Friday traffic. Professional defenders spend weeks collecting baseline data before setting up alerts.

**Real-time monitoring gives you early warning:** The difference between detecting an attack in 30 seconds vs 30 minutes can be the difference between minimal impact and complete service outage. Modern monitoring tools can alert you the instant traffic patterns change, giving you precious time to activate defenses before systems fail.`,
    beginnerTips: [
      "**Start with free tools before buying expensive solutions:** You don't need a $50,000 appliance to get started. Tools like 'iftop', 'ntop', and 'tcpdump' are free and can show you real-time traffic. Once you understand what you're looking for, then consider commercial solutions.",
      "**Focus on these 3 key metrics first:** Bandwidth (Mbps), packet rate (pps), and connection count. If any of these suddenly triple or more, investigate immediately. These are your 'smoke detectors' - they won't tell you exactly what's wrong, but they'll tell you SOMETHING is wrong.",
      "**Set up alerts, but tune them to avoid 'alert fatigue':** If your monitoring system cries wolf every 5 minutes with false alarms, you'll start ignoring it. Start with very high thresholds (like 5x your normal traffic) and gradually lower them as you tune out false positives. Better to catch 80% of attacks reliably than to burn out your team with noise.",
      "**Monitor your monitors:** Set up monitoring for your monitoring system itself. I've seen situations where a DDoS attack took down the monitoring infrastructure first, leaving defenders blind. Have a simple external check (like pingdom or uptimerobot) that alerts you if your monitoring goes dark."
    ],
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
    detailedDescription: `**Server logs are like a detailed diary of everything that happens on your system.** Every web request, connection attempt, and error gets recorded with timestamps, source IPs, and request details. During a DDoS attack, these logs can reveal patterns that network monitoring misses - like discovering that 90% of your traffic is requesting the same expensive search endpoint, or that you're getting thousands of requests from IPs in countries where you don't even have customers.

**The challenge is volume:** During a large DDoS attack, you might generate gigabytes of logs per minute. Trying to analyze this manually is impossible - you need automation. Tools like 'awk', 'grep', and log aggregation systems (like ELK stack) can process millions of log lines per second to extract patterns.

**Application logs reveal Layer 7 attacks that network tools miss:** A sophisticated HTTP flood might look like normal traffic to your firewall, but application logs reveal the truth: the same URL getting hammered, missing referer headers, suspicious user agents, or requests that bypass your cache. This is why log analysis is essential for defending against modern DDoS attacks.`,
    beginnerTips: [
      "**Learn basic log parsing with 'awk' - it's a superpower:** The command 'awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20' shows you the top 20 IPs hitting your server. Master this pattern and you can answer 80% of attack questions in seconds without fancy tools.",
      "**Separate legitimate spikes from attacks:** Your marketing team launches a campaign and traffic triples - that's not a DDoS! Look for these red flags that indicate attacks: uniform packet sizes, missing HTTP headers (no User-Agent or Referer), geographic anomalies (traffic from countries you don't serve), and requests to URLs that don't exist.",
      "**Enable detailed logging BEFORE you're attacked:** Default Apache/Nginx logs might not include critical info like response times or request processing time. Add these fields NOW (when you're not under attack) so you have the data you need when it matters. Include: $request_time, $upstream_response_time, $http_user_agent.",
      "**Use log aggregation for multiple servers:** If you have more than one server, analyzing logs on each individually is madness during an attack. Set up centralized logging with syslog, Elastic/Logstash, or even just 'rsyslog' to ship logs to one place. During an attack, this could save you hours."
    ],
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
    detailedDescription: `**Threat hunting is like being a detective instead of a security guard.** Instead of waiting for alarms to go off, you actively search for signs of trouble. You look for reconnaissance activity (attackers mapping your infrastructure), low-level probing attacks (testing your defenses), and signs of compromised systems in your network (which could become part of someone's botnet).

**Why hunt proactively?** Many DDoS attacks aren't instant - attackers often probe defenses for days or weeks before launching the main assault. They scan your ports, test your rate limits, and identify your most vulnerable endpoints. If you catch these preparation activities, you can strengthen defenses before the real attack begins.

**Focus on behavioral anomalies, not just signatures:** Modern attackers change their techniques constantly to evade signature-based detection. Threat hunting focuses on finding BEHAVIOR that's suspicious: a DNS query spike at 3 AM, periodic connections to unusual IPs, or traffic patterns that don't match human behavior. These behavioral indicators are harder for attackers to hide.`,
    beginnerTips: [
      "**Start by hunting for reconnaissance:** Attackers often scan your infrastructure before attacking. Look for: port scans (many connection attempts to different ports from one IP), DNS enumeration (queries for subdomains like admin.yoursite.com, test.yoursite.com), and HTTP endpoint probing (requests to /admin, /.env, /backup.zip). These indicate someone is mapping your attack surface.",
      "**Check for signs YOUR network is part of a botnet:** Run 'netstat -an | grep ESTABLISHED | wc -l' regularly. If you suddenly have way more outbound connections than normal, or connections to unusual countries, your server might be compromised and participating in attacks against others. Also check for unusual cronjobs or startup scripts that weren't there before.",
      "**Use free threat intelligence feeds:** Services like abuse.ch, Spamhaus, and Emerging Threats publish lists of known malicious IPs, C2 servers, and attack infrastructure. Check your firewall logs against these lists weekly. If you see connections to known bad IPs, investigate immediately - you might be compromised or under reconnaissance.",
      "**Document your baseline behavior first:** Before you can hunt for anomalies, you need to know what 'normal' looks like. Spend a week documenting: typical traffic patterns by hour, common geographic sources, normal DNS query patterns, and typical connection counts. Save this baseline and compare future activity against it. Threat hunting without a baseline is just guessing."
    ],
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
    detailedDescription: `**This hands-on lab teaches you to recognize DDoS attacks in network traffic.** You'll analyze real packet captures (PCAPs) using industry-standard tools like Wireshark and tshark. By the end, you'll be able to look at a packet capture and immediately identify whether it's normal traffic or a DDoS attack - and what TYPE of attack it is.

**Why this skill matters:** In real incidents, you often don't know you're under attack until you dig into the traffic. Learning to analyze PCAPs is like learning to read X-rays - at first it's all noise, but with practice you'll spot patterns that scream 'attack!' This lab gives you that practice in a safe, controlled environment.

**What makes this beginner-friendly:** We use pre-captured traffic (no need to generate attacks), provide step-by-step commands you can copy-paste, and explain what each command does. You don't need to be a Linux expert or networking guru - just follow along and you'll learn by doing.`,
    beginnerTips: [
      "**You don't need to understand every packet detail:** When starting out, focus on the BIG patterns - packet counts, repeated IPs, connection states. Don't get lost trying to understand every TCP flag or protocol field. Those details matter, but first master seeing the forest (attack pattern) before examining individual trees (packets).",
      "**Start with the summary statistics, not individual packets:** Wireshark shows you every single packet, which is overwhelming. Instead, use the Statistics menu: Protocol Hierarchy (shows traffic breakdown), Conversations (shows who's talking to who), and IO Graph (shows traffic over time). These summaries reveal attacks instantly.",
      "**Compare attack traffic to your baseline capture:** The BEST way to spot attacks is comparison. Capture 5 minutes of your own normal network traffic as a 'baseline', then analyze the attack capture. The differences will be OBVIOUS: attack traffic has uniform timing, repeated packets, way more connections, etc.",
      "**Don't be afraid to Google the tools:** Commands like 'tshark -r capture.pcap -q -z io,phs' look scary but each part has meaning. When you see a command you don't understand, Google 'tshark io phs' to learn what it does. Building this habit makes you independent."
    ],
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
    detailedDescription: `**This lab teaches you the single most important defense against SYN flood attacks: SYN cookies.** You'll learn what they are, how they work, and most importantly - how to configure them on a Linux server. SYN cookies are a brilliant hack that lets servers handle SYN floods without consuming memory for half-open connections.

**The magic of SYN cookies:** Normally, when a client sends SYN, the server allocates memory to track that connection. SYN floods exploit this by sending millions of SYNs, filling up the server's connection table. SYN cookies solve this by encoding the connection state in the TCP sequence number itself - no memory needed until the handshake completes!

**Real-world impact:** Enabling SYN cookies (one sysctl command) can be the difference between staying online during an attack and going down completely. Major hosting providers enable this by default. After this lab, you'll understand why.`,
    beginnerTips: [
      "**SYN cookies are already built into Linux kernel:** You don't need to install anything special - the kernel already has this capability. You're just flipping a switch with 'sysctl -w net.ipv4.tcp_syncookies=1'. This is one of the easiest yet most powerful security configurations you can make.",
      "**Test in a VM before production:** This lab asks you to modify kernel parameters. While SYN cookies are safe and used everywhere, get comfortable testing in a virtual machine first. This builds good habits - always test system changes in non-production first.",
      "**SYN cookies activate automatically when needed:** Even with SYN cookies enabled, the server operates normally under regular load. They only kick in when the SYN backlog fills up. This 'automatic emergency mode' is why they're so elegant - no performance impact during normal operation.",
      "**Combine SYN cookies with other TCP tuning:** SYN cookies are powerful but work best with friends: increase tcp_max_syn_backlog (more buffer before emergency mode), reduce tcp_synack_retries (faster timeout), and use connection limits per IP. The lab teaches you the full defensive stack."
    ],
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
    detailedDescription: `**Rate limiting is your traffic cop - it prevents any single source from hogging all resources.** This lab teaches you to implement rate limiting at TWO critical layers: network layer (iptables) and application layer (nginx). You'll learn to set thresholds, test them, and fine-tune them to block attacks while allowing legitimate traffic.

**Why multi-layer rate limiting matters:** Network-level rate limiting (iptables) is fast but dumb - it only sees packets, not requests. Application-level rate limiting (nginx) is slower but smart - it understands HTTP and can make nuanced decisions. Using both gives you defense in depth.

**The balancing act:** Set limits too strict and you block real users (false positives). Set limits too loose and attacks get through (false negatives). This lab teaches you to find the sweet spot through testing and monitoring. There's no 'one size fits all' - your limits depend on YOUR traffic patterns.`,
    beginnerTips: [
      "**Start with generous limits and tighten gradually:** It's tempting to set aggressive rate limits (10 req/sec per IP!) but you'll immediately block legitimate users: people on corporate NAT, mobile networks, or just fast clickers. Start at 100 req/sec and lower it over days as you monitor for false positives. Better to let some attack traffic through initially than to block paying customers.",
      "**Monitor the '429 Too Many Requests' responses:** When rate limiting triggers, nginx returns HTTP 429. Watch your access logs for these: 'tail -f access.log | grep 429'. If you see legitimate user patterns getting 429s (like search engines, API clients), you need to either raise limits or add those IPs to an allowlist.",
      "**Burst limits are critical for real-world usage:** Real users don't generate perfectly smooth traffic - they load a page (10 requests at once), wait, then click (10 more requests). This is 'bursty' traffic. Configure burst limits (like 'burst=20') to allow these spikes while still blocking sustained floods. Without burst limits, normal web browsing triggers rate limiting!",
      "**Have an emergency 'disable' procedure:** When you're troubleshooting an outage, fumbling with rate limit configs is the last thing you need. Create simple scripts NOW: 'disable-ratelimit.sh' and 'enable-ratelimit.sh'. Test them. Knowing you can instantly disable rate limits if something goes wrong gives you confidence to implement them."
    ],
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

// Additional data for sections
const economicsData = [
  {
    title: "Attack Costs",
    color: "#ffebee",
    items: [
      "Basic DDoS-for-hire: $10-50/hour",
      "Sophisticated botnet rental: $500-5000/day",
      "Large-scale attack infrastructure: $10,000+",
    ],
  },
  {
    title: "Defense Costs",
    color: "#e8f5e9",
    items: [
      "Cloud DDoS protection: $3,000-50,000/month",
      "On-premise appliances: $25,000-500,000",
      "24/7 SOC monitoring: $100,000+/year",
    ],
  },
  {
    title: "Damage Costs",
    color: "#fff3e0",
    items: [
      "Average downtime cost: $5,600/minute",
      "Reputation damage: Hard to quantify",
      "Customer churn: 5-10% increase",
    ],
  },
];

const attackVectors = [
  { name: "UDP Flood", layer: "L3/L4", mechanism: "Massive UDP packets to random ports", mitigation: "Rate limiting, traffic scrubbing" },
  { name: "SYN Flood", layer: "L3/L4", mechanism: "Incomplete TCP handshakes", mitigation: "SYN cookies, connection limits" },
  { name: "HTTP Flood", layer: "L7", mechanism: "Legitimate-looking HTTP requests", mitigation: "WAF rules, behavioral analysis" },
  { name: "DNS Amplification", layer: "L3/L4", mechanism: "Spoofed DNS queries to open resolvers", mitigation: "BCP38, rate limiting" },
  { name: "Slowloris", layer: "L7", mechanism: "Keep connections open with partial headers", mitigation: "Timeout tuning, connection limits" },
];

const amplificationSteps = [
  { label: "IP Spoofing", description: "Attacker sends requests with victim's IP as source address" },
  { label: "Request to Reflector", description: "Requests sent to servers with amplification potential (DNS, NTP, Memcached)" },
  { label: "Amplified Response", description: "Reflector sends much larger response to spoofed IP (victim)" },
  { label: "Target Overwhelmed", description: "Victim receives massive traffic from multiple reflectors" },
];

const amplificationFactors = [
  { protocol: "DNS", factor: "28-54", port: "53/UDP", notes: "ANY query type gives largest amplification" },
  { protocol: "NTP", factor: "556", port: "123/UDP", notes: "monlist command (deprecated)" },
  { protocol: "Memcached", factor: "51,000", port: "11211/UDP", notes: "Most powerful known vector" },
  { protocol: "SSDP", factor: "30", port: "1900/UDP", notes: "UPnP devices on home networks" },
  { protocol: "CLDAP", factor: "56-70", port: "389/UDP", notes: "Microsoft Active Directory" },
  { protocol: "CharGEN", factor: "358", port: "19/UDP", notes: "Legacy protocol, rarely seen" },
];

const botnetInfo = [
  {
    title: "Botnet Composition",
    icon: <RouterIcon />,
    points: [
      "IoT devices (cameras, routers, DVRs)",
      "Compromised servers and VPS",
      "Infected home computers",
      "Hijacked cloud instances",
    ],
  },
  {
    title: "Command & Control",
    icon: <SecurityIcon />,
    points: [
      "Centralized C2 servers",
      "Peer-to-peer communication",
      "Domain generation algorithms (DGA)",
      "Tor hidden services",
    ],
  },
  {
    title: "Attack Capabilities",
    icon: <SpeedIcon />,
    points: [
      "Multi-vector attacks",
      "Geographic distribution",
      "On-demand scaling",
      "Evasion techniques",
    ],
  },
  {
    title: "Monetization",
    icon: <MonetizationOnIcon />,
    points: [
      "DDoS-for-hire services",
      "Ransom/extortion demands",
      "Competitive attacks",
      "Hacktivism campaigns",
    ],
  },
];

const notableBotnets = [
  { name: "Mirai", size: "600,000+ devices", capability: "1.2 Tbps attacks", targets: "Dyn DNS, OVH, Krebs on Security" },
  { name: "Mēris", size: "250,000+ devices", capability: "21.8M RPS HTTP attacks", targets: "Yandex, Cloudflare customers" },
  { name: "Emotet", size: "1M+ endpoints", capability: "Multi-purpose including DDoS", targets: "Financial institutions, enterprises" },
  { name: "Mantis", size: "5,000 VMs", capability: "26M RPS HTTPS attacks", targets: "Cloudflare customers" },
];

const mitigationLayers = [
  {
    name: "Network Layer",
    color: "#2196f3",
    description: "First line of defense at the network edge",
    techniques: [
      "Anycast network distribution",
      "BGP flowspec and RTBH",
      "ISP scrubbing centers",
      "Rate limiting at edge",
    ],
  },
  {
    name: "Infrastructure Layer",
    color: "#4caf50",
    description: "Protect servers and services",
    techniques: [
      "Load balancer configuration",
      "SYN cookies and proxies",
      "Connection timeouts",
      "Resource isolation",
    ],
  },
  {
    name: "Application Layer",
    color: "#ff9800",
    description: "Defend against L7 attacks",
    techniques: [
      "WAF rules and signatures",
      "Bot detection and CAPTCHA",
      "Rate limiting per endpoint",
      "Caching strategies",
    ],
  },
];

const detectionCommandsData = [
  {
    title: "Network Traffic Analysis",
    lang: "bash",
    command: "tcpdump -i eth0 -n 'udp and port 53' -c 1000 | \\\n  awk '{print $3}' | sort | uniq -c | sort -rn | head -20",
    description: "Identify top DNS query sources",
  },
  {
    title: "Connection State Check",
    lang: "bash",
    command: "ss -s\nnetstat -an | awk '/tcp/ {print $6}' | sort | uniq -c | sort -rn",
    description: "Check TCP connection states for SYN flood indicators",
  },
  {
    title: "Real-time Bandwidth",
    lang: "bash",
    command: "iftop -i eth0 -nNP",
    description: "Monitor bandwidth usage by connection",
  },
  {
    title: "HTTP Request Rate",
    lang: "bash",
    command: "tail -f /var/log/nginx/access.log | \\\n  awk '{print $1}' | uniq -c | sort -rn | head -10",
    description: "Watch for HTTP flood patterns",
  },
];

const safeLabOptions = [
  {
    name: "Local Virtual Lab",
    color: "#4caf50",
    description: "Completely isolated environment on your machine",
    features: [
      "VirtualBox/VMware with isolated networks",
      "Docker containers with network isolation",
      "No internet connectivity required",
      "Full control over all components",
    ],
  },
  {
    name: "Cloud Sandbox",
    color: "#2196f3",
    description: "Isolated cloud environment for testing",
    features: [
      "AWS/Azure/GCP isolated VPCs",
      "Controlled egress rules",
      "Auto-teardown after testing",
      "Cost controls and limits",
    ],
  },
  {
    name: "Commercial Platforms",
    color: "#ff9800",
    description: "Purpose-built DDoS testing platforms",
    features: [
      "Authorized stress testing services",
      "Compliance with legal requirements",
      "Detailed reporting and analytics",
      "Insurance and liability coverage",
    ],
  },
  {
    name: "CTF Environments",
    color: "#9c27b0",
    description: "Capture The Flag competitions",
    features: [
      "Legal hacking challenges",
      "Learn attack techniques safely",
      "Community and mentorship",
      "Real-world scenario simulation",
    ],
  },
];

const labSetupYaml = `# docker-compose.yml for DDoS Lab
version: '3.8'
services:
  target-web:
    image: nginx:alpine
    networks:
      - ddos-lab
    ports:
      - "8080:80"
    
  target-dns:
    image: coredns/coredns
    networks:
      - ddos-lab
    ports:
      - "5353:53/udp"
    
  attacker:
    image: kalilinux/kali-rolling
    networks:
      - ddos-lab
    cap_add:
      - NET_ADMIN
    command: sleep infinity

  monitor:
    image: grafana/grafana
    networks:
      - ddos-lab
    ports:
      - "3000:3000"

networks:
  ddos-lab:
    driver: bridge
    internal: true  # No external access`;

const legalInfo = [
  { region: "United States", law: "Computer Fraud and Abuse Act (CFAA)", penalty: "Up to 10 years imprisonment, $500K+ fines" },
  { region: "United Kingdom", law: "Computer Misuse Act 1990", penalty: "Up to 10 years imprisonment" },
  { region: "European Union", law: "Directive on Attacks Against Information Systems", penalty: "Varies by member state, up to 10 years" },
  { region: "Canada", law: "Criminal Code Section 342.1", penalty: "Up to 10 years imprisonment" },
  { region: "Australia", law: "Criminal Code Act 1995", penalty: "Up to 10 years imprisonment" },
];

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const DDoSAttackTechniquesPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const accent = "#ef4444"; // Red accent for DDoS/attack theme

  // Section navigation items
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <InfoIcon /> },
    { id: "fundamentals", label: "Fundamentals", icon: <SchoolIcon /> },
    { id: "overview", label: "Attack Overview", icon: <WarningIcon /> },
    { id: "attack-types", label: "Attack Types", icon: <CloudIcon /> },
    { id: "amplification", label: "Amplification", icon: <SpeedIcon /> },
    { id: "botnets", label: "Botnets", icon: <RouterIcon /> },
    { id: "mitigation", label: "Mitigation", icon: <ShieldIcon /> },
    { id: "detection", label: "Detection", icon: <NetworkCheckIcon /> },
    { id: "safe-lab", label: "Safe Lab", icon: <ScienceIcon /> },
    { id: "legal", label: "Legal & Ethics", icon: <GavelIcon /> },
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
      const sections = sectionNavItems.map((item) => item.id);
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
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Scroll to top
  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  // Progress calculation
  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

  const pageContext = `This page covers DDoS attack techniques including volumetric, protocol, and application layer attacks. Topics include amplification methods, botnet coordination, attack detection, traffic analysis, baseline metrics, response runbooks, and mitigation strategies.`;

  // Sidebar navigation component
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
        border: `1px solid ${alpha(accent, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(accent, 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>{item.icon}</ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? accent : "text.secondary",
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

  return (
    <LearnPageLayout pageTitle="DDoS Attack Techniques" pageContext={pageContext}>
      <Box sx={{ display: "flex", gap: 3, position: "relative" }}>
        {/* Sidebar Navigation */}
        {sidebarNav}

        {/* Main Content */}
        <Container maxWidth="lg" sx={{ py: 4, flex: 1 }}>
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
              background: `linear-gradient(135deg, ${alpha(accent, 0.15)} 0%, ${alpha("#f97316", 0.1)} 100%)`,
              border: `1px solid ${alpha(accent, 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            <Box
              sx={{
                position: "absolute",
                top: -50,
                right: -50,
                width: 200,
                height: 200,
                borderRadius: "50%",
                background: `linear-gradient(135deg, ${alpha(accent, 0.1)}, transparent)`,
              }}
            />
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, ${accent}, #f97316)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha(accent, 0.3)}`,
                }}
              >
                <SecurityIcon sx={{ fontSize: 45, color: "white" }} />
              </Box>
              <Box>
                <Chip label="Offensive Security" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha(accent, 0.1), color: accent }} />
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 1 }}>
                  DDoS Attack Techniques
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600 }}>
                  Understanding Distributed Denial of Service attacks for defense and security research
                </Typography>
              </Box>
            </Box>
          </Paper>

          {/* Tags */}
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
            <Chip label="Network Security" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
            <Chip label="Traffic Analysis" size="small" sx={{ bgcolor: alpha("#f97316", 0.1), color: "#f97316" }} />
            <Chip label="Incident Response" size="small" sx={{ bgcolor: alpha("#eab308", 0.1), color: "#eab308" }} />
            <Chip label="Intermediate" size="small" variant="outlined" />
          </Box>

          {/* Introduction Section */}
          <Box id="intro">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <InfoIcon sx={{ color: accent }} />
                Overview
              </Typography>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Distributed Denial of Service (DDoS) attacks are among the most disruptive and common cyber threats 
                facing organizations today. These attacks aim to overwhelm target systems, networks, or services with 
                a flood of traffic, rendering them unavailable to legitimate users.
              </Typography>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Understanding DDoS attack techniques is essential for security professionals who need to defend against 
                these threats. This comprehensive guide covers attack vectors, amplification methods, botnet infrastructure, 
                detection techniques, and mitigation strategies.
              </Typography>
              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                Whether you're a security analyst, network administrator, or incident responder, this guide will equip 
                you with the knowledge needed to identify, analyze, and defend against DDoS attacks effectively.
              </Typography>

              <Alert severity="warning" sx={{ mb: 3 }}>
                <AlertTitle>Educational Purpose Only</AlertTitle>
                This content is for defensive security understanding and authorized penetration testing.
                Launching DDoS attacks against systems you don't own is illegal and unethical.
              </Alert>

              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Who This Is For</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Security analysts, network administrators, SOC teams, and incident responders who need to 
                      understand and defend against DDoS attacks.
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Prerequisites</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Basic networking knowledge (TCP/IP, OSI model, routing). Familiarity with traffic analysis 
                      tools is helpful but not required.
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>What You'll Learn</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Attack vectors, amplification techniques, botnet infrastructure, detection methods, 
                      mitigation strategies, and safe lab practices.
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </Paper>
          </Box>

          {/* Fundamentals Section */}
          <Box id="fundamentals">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SchoolIcon sx={{ color: accent }} />
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

                  <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Key Points:</Typography>
                  <List dense>
                    {ddosFundamentals.howInternetWorks.keyPoints.map((point, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon><CheckCircleIcon color="info" /></ListItemIcon>
                        <ListItemText primary={point} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              {/* Types of DDoS */}
              <Accordion sx={{ mb: 2, border: '2px solid', borderColor: 'warning.main' }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: 'warning.dark' }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Typography variant="h4">{ddosFundamentals.typesOfDDoS.icon}</Typography>
                    <Box>
                      <Typography variant="h6" color="white">{ddosFundamentals.typesOfDDoS.title}</Typography>
                      <Typography variant="caption" color="rgba(255,255,255,0.7)">Core Knowledge • 6 min read</Typography>
                    </Box>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    <AlertTitle>The Three Categories</AlertTitle>
                    <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                      {ddosFundamentals.typesOfDDoS.beginnerExplanation}
                    </Typography>
                  </Alert>

                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    {ddosFundamentals.typesOfDDoS.categories.map((cat, idx) => (
                      <Grid item xs={12} md={4} key={idx}>
                        <Card sx={{ height: '100%', bgcolor: cat.color }}>
                          <CardContent>
                            <Typography variant="h6" color="white" gutterBottom>{cat.name}</Typography>
                            <Typography variant="body2" color="rgba(255,255,255,0.9)">{cat.description}</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              {/* Real World Examples */}
              <Accordion sx={{ mb: 2, border: '2px solid', borderColor: 'error.main' }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: 'error.dark' }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Typography variant="h4">{ddosFundamentals.realWorldExamples.icon}</Typography>
                    <Box>
                      <Typography variant="h6" color="white">{ddosFundamentals.realWorldExamples.title}</Typography>
                      <Typography variant="caption" color="rgba(255,255,255,0.7)">Case Studies • 5 min read</Typography>
                    </Box>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    {ddosFundamentals.realWorldExamples.intro}
                  </Typography>

                  {ddosFundamentals.realWorldExamples.examples.map((example, idx) => (
                    <Card key={idx} sx={{ mb: 2 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>{example.name} ({example.year})</Typography>
                        <Typography variant="body2" sx={{ mb: 1 }}><strong>Impact:</strong> {example.impact}</Typography>
                        <Typography variant="body2" sx={{ mb: 1 }}><strong>Method:</strong> {example.method}</Typography>
                        <Typography variant="body2"><strong>Lesson:</strong> {example.lesson}</Typography>
                      </CardContent>
                    </Card>
                  ))}
                </AccordionDetails>
              </Accordion>
            </Paper>
          </Box>

          {/* Overview Section */}
          <Box id="overview">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: accent }} />
                What is a DDoS Attack?
              </Typography>

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
                        <TableCell><Chip label={row.metric} size="small" /></TableCell>
                        <TableCell>{row.meaning}</TableCell>
                        <TableCell>{row.defense}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <MonetizationOnIcon color="primary" />
                The Economics of DDoS
              </Typography>
              <Grid container spacing={2}>
                {economicsData.map((item, idx) => (
                  <Grid item xs={12} md={4} key={idx}>
                    <Card sx={{ height: "100%", bgcolor: item.color }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>{item.title}</Typography>
                        <List dense>
                          {item.items.map((point, pIdx) => (
                            <ListItem key={pIdx}>
                              <ListItemText primary={point} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Box>

          {/* Attack Types Section */}
          <Box id="attack-types">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <CloudIcon sx={{ color: accent }} />
                Attack Categories
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>The Three Layers of DDoS</AlertTitle>
                DDoS attacks target different parts of the network stack. Understanding which layer is being 
                attacked is crucial for choosing the right defense. Most sophisticated attacks combine multiple types.
              </Alert>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                {attackCategories.map((cat, idx) => (
                  <Grid item xs={12} md={4} key={idx}>
                    <Card sx={{ height: "100%", borderTop: `4px solid ${cat.color}` }}>
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                          {cat.icon}
                          <Typography variant="h6">{cat.name}</Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {cat.description}
                        </Typography>
                        <Typography variant="subtitle2" gutterBottom>Examples:</Typography>
                        <List dense>
                          {cat.examples.map((ex, eIdx) => (
                            <ListItem key={eIdx}>
                              <ListItemIcon><BugReportIcon fontSize="small" /></ListItemIcon>
                              <ListItemText primary={ex} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" gutterBottom>Common Attack Vectors</Typography>
              <TableContainer component={Paper}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "action.hover" }}>
                      <TableCell><strong>Attack Type</strong></TableCell>
                      <TableCell><strong>Layer</strong></TableCell>
                      <TableCell><strong>Mechanism</strong></TableCell>
                      <TableCell><strong>Mitigation</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {attackVectors.map((attack) => (
                      <TableRow key={attack.name}>
                        <TableCell><strong>{attack.name}</strong></TableCell>
                        <TableCell><Chip label={attack.layer} size="small" color={attack.layer === "L3/L4" ? "warning" : "error"} /></TableCell>
                        <TableCell>{attack.mechanism}</TableCell>
                        <TableCell>{attack.mitigation}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Box>

          {/* Amplification Section */}
          <Box id="amplification">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SpeedIcon sx={{ color: accent }} />
                Amplification Attacks
              </Typography>

              <Alert severity="warning" sx={{ mb: 3 }}>
                <AlertTitle>Understanding Amplification</AlertTitle>
                Amplification attacks exploit protocols that respond with more data than they receive. 
                A small request can trigger a response 50-500x larger, allowing attackers to multiply 
                their bandwidth. This is why they're so dangerous.
              </Alert>

              <Typography variant="h6" gutterBottom>How Amplification Works</Typography>
              <Stepper orientation="vertical" sx={{ mb: 3 }}>
                {amplificationSteps.map((step, idx) => (
                  <Step key={idx} active>
                    <StepLabel>{step.label}</StepLabel>
                    <StepContent>
                      <Typography variant="body2">{step.description}</Typography>
                    </StepContent>
                  </Step>
                ))}
              </Stepper>

              <Typography variant="h6" gutterBottom>Amplification Factors by Protocol</Typography>
              <TableContainer component={Paper} sx={{ mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "action.hover" }}>
                      <TableCell><strong>Protocol</strong></TableCell>
                      <TableCell><strong>Amplification Factor</strong></TableCell>
                      <TableCell><strong>Port</strong></TableCell>
                      <TableCell><strong>Notes</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {amplificationFactors.map((row) => (
                      <TableRow key={row.protocol}>
                        <TableCell><strong>{row.protocol}</strong></TableCell>
                        <TableCell>
                          <Chip 
                            label={`${row.factor}x`} 
                            size="small" 
                            color={parseInt(row.factor) > 100 ? "error" : "warning"} 
                          />
                        </TableCell>
                        <TableCell>{row.port}</TableCell>
                        <TableCell>{row.notes}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Box>

          {/* Botnets Section */}
          <Box id="botnets">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <RouterIcon sx={{ color: accent }} />
                Botnets & Attack Infrastructure
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>What is a Botnet?</AlertTitle>
                A botnet is a network of compromised computers (bots/zombies) controlled by an attacker. 
                These can range from thousands to millions of devices, including IoT devices, and can 
                generate massive amounts of attack traffic.
              </Alert>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                {botnetInfo.map((info, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Card sx={{ height: "100%" }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          {info.icon}
                          {info.title}
                        </Typography>
                        <List dense>
                          {info.points.map((point, pIdx) => (
                            <ListItem key={pIdx}>
                              <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                              <ListItemText primary={point} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" gutterBottom>Notable Botnets in History</Typography>
              <TableContainer component={Paper}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "action.hover" }}>
                      <TableCell><strong>Botnet</strong></TableCell>
                      <TableCell><strong>Peak Size</strong></TableCell>
                      <TableCell><strong>Attack Capability</strong></TableCell>
                      <TableCell><strong>Notable Targets</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {notableBotnets.map((bot) => (
                      <TableRow key={bot.name}>
                        <TableCell><strong>{bot.name}</strong></TableCell>
                        <TableCell>{bot.size}</TableCell>
                        <TableCell>{bot.capability}</TableCell>
                        <TableCell>{bot.targets}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Box>

          {/* Mitigation Section */}
          <Box id="mitigation">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <ShieldIcon sx={{ color: accent }} />
                Mitigation Strategies
              </Typography>

              <Alert severity="success" sx={{ mb: 3 }}>
                <AlertTitle>Defense in Depth</AlertTitle>
                Effective DDoS mitigation requires multiple layers of defense. No single solution can 
                protect against all attack types. Combine network-level, application-level, and 
                cloud-based protections.
              </Alert>

              <Typography variant="h6" gutterBottom>Mitigation Layers</Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {mitigationLayers.map((layer, idx) => (
                  <Grid item xs={12} md={4} key={idx}>
                    <Card sx={{ height: "100%", borderTop: `4px solid ${layer.color}` }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>{layer.name}</Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {layer.description}
                        </Typography>
                        <List dense>
                          {layer.techniques.map((tech, tIdx) => (
                            <ListItem key={tIdx}>
                              <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                              <ListItemText primary={tech} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" gutterBottom>Response Runbook</Typography>
              <Stepper orientation="vertical">
                {responseRunbook.map((step, idx) => (
                  <Step key={idx} active>
                    <StepLabel>
                      <Typography variant="subtitle1">{step.label}</Typography>
                    </StepLabel>
                    <StepContent>
                      <Typography variant="body2" color="text.secondary">
                        {step.description}
                      </Typography>
                    </StepContent>
                  </Step>
                ))}
              </Stepper>
            </Paper>
          </Box>

          {/* Detection Section */}
          <Box id="detection">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <NetworkCheckIcon sx={{ color: accent }} />
                Detection & Analysis
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>Early Detection is Key</AlertTitle>
                The faster you detect a DDoS attack, the faster you can respond. Establish baseline 
                metrics for your normal traffic patterns so you can quickly identify anomalies.
              </Alert>

              <Typography variant="h6" gutterBottom>Traffic Analysis Indicators</Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {detectionIndicators.map((indicator, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Card>
                      <CardContent>
                        <Typography variant="subtitle1" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <NetworkCheckIcon fontSize="small" sx={{ color: indicator.severity === "high" ? "#ef4444" : "#f59e0b" }} />
                          {indicator.indicator}
                        </Typography>
                        <Chip 
                          label={indicator.severity} 
                          size="small" 
                          color={indicator.severity === "high" ? "error" : "warning"} 
                          sx={{ mb: 1 }} 
                        />
                        <Typography variant="body2" color="text.secondary">
                          <strong>Tool:</strong> {indicator.tool}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" gutterBottom>Detection Tools & Commands</Typography>
              <Grid container spacing={2}>
                {detectionCommandsData.map((cmd, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Card sx={{ bgcolor: "#1e1e1e" }}>
                      <CardContent>
                        <Typography variant="subtitle2" color="primary.light" gutterBottom>
                          {cmd.title}
                        </Typography>
                        <CodeBlock language={cmd.lang}>{cmd.command}</CodeBlock>
                        <Typography variant="caption" color="grey.500">
                          {cmd.description}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Box>

          {/* Safe Lab Section */}
          <Box id="safe-lab">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <ScienceIcon sx={{ color: accent }} />
                Safe Lab Environment
              </Typography>

              <Alert severity="error" sx={{ mb: 3 }}>
                <AlertTitle>⚠️ Critical Warning</AlertTitle>
                NEVER test DDoS techniques against systems you don't own or without explicit written 
                permission. This includes public websites, cloud services, and shared networks. 
                Violations can result in criminal charges and civil liability.
              </Alert>

              <Typography variant="h6" gutterBottom>Safe Testing Options</Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {safeLabOptions.map((option, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Card sx={{ height: "100%", borderLeft: `4px solid ${option.color}` }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>{option.name}</Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {option.description}
                        </Typography>
                        <List dense>
                          {option.features.map((feature, fIdx) => (
                            <ListItem key={fIdx}>
                              <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                              <ListItemText primary={feature} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" gutterBottom>Recommended Lab Setup</Typography>
              <CodeBlock language="yaml">{labSetupYaml}</CodeBlock>
            </Paper>
          </Box>

          {/* Legal & Ethics Section */}
          <Box id="legal">
            <Paper
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <GavelIcon sx={{ color: accent }} />
                Legal & Ethical Considerations
              </Typography>

              <Alert severity="error" sx={{ mb: 3 }}>
                <AlertTitle>Legal Consequences</AlertTitle>
                DDoS attacks are illegal in virtually all jurisdictions. Penalties can include:
                imprisonment (up to 10+ years), massive fines ($250,000+), civil lawsuits, and 
                permanent criminal records affecting future employment.
              </Alert>

              <Typography variant="h6" gutterBottom>Key Laws by Region</Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {legalInfo.map((info, idx) => (
                  <Grid item xs={12} md={4} key={idx}>
                    <Card sx={{ height: "100%" }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>{info.region}</Typography>
                        <Typography variant="subtitle2" color="primary">{info.law}</Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                          {info.penalty}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" gutterBottom>If You're Attacked</Typography>
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
            </Paper>
          </Box>

          {/* Bottom Navigation */}
          <Box sx={{ mt: 4, textAlign: "center" }}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ borderColor: accent, color: accent, "&:hover": { bgcolor: alpha(accent, 0.1) } }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Container>
      </Box>

      {/* Floating Action Buttons */}
      <Fab
        color="primary"
        onClick={() => setNavDrawerOpen(true)}
        sx={{
          position: "fixed",
          bottom: 90,
          right: 24,
          zIndex: 1000,
          bgcolor: accent,
          "&:hover": { bgcolor: "#dc2626" },
          boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
          display: { xs: "flex", lg: "none" },
        }}
      >
        <ListAltIcon />
      </Fab>

      {/* Scroll to Top FAB */}
      <Fab
        size="small"
        onClick={scrollToTop}
        sx={{
          position: "fixed",
          bottom: 32,
          right: 28,
          zIndex: 1000,
          bgcolor: alpha(accent, 0.15),
          color: accent,
          "&:hover": { bgcolor: alpha(accent, 0.25) },
          display: { xs: "flex", lg: "none" },
        }}
      >
        <KeyboardArrowUpIcon />
      </Fab>

      {/* Navigation Drawer for Mobile */}
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
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Box>

          {/* Progress */}
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: accent,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.08),
                  },
                  transition: "all 0.15s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? accent : "text.secondary" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? accent : "text.primary",
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
      </Drawer>
    </LearnPageLayout>
  );
};

export default DDoSAttackTechniquesPage;
