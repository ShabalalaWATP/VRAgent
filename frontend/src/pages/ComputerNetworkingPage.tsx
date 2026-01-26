import React, { useState, useCallback, useMemo, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  Chip,
  alpha,
  useTheme,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  AlertTitle,
  TextField,
  Button,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Fab,
  IconButton,
  Slider,
  LinearProgress,
  Radio,
  RadioGroup,
  FormControlLabel,
  FormControl,
  Checkbox,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  useMediaQuery,
} from "@mui/material";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CalculateIcon from "@mui/icons-material/Calculate";
import SwapVertIcon from "@mui/icons-material/SwapVert";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import CancelIcon from "@mui/icons-material/Cancel";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import SchoolIcon from "@mui/icons-material/School";
import { Link, useNavigate } from "react-router-dom";

// ========== NETWORKING QUIZ BANK (100 Questions, 75 Used) ==========
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correct: number;
  explanation: string;
  category: string;
}

const networkingQuizBank: QuizQuestion[] = [
  // OSI Model Questions (1-15)
  { id: 1, question: "Which OSI layer is responsible for routing packets between networks?", options: ["Transport Layer", "Network Layer", "Data Link Layer", "Session Layer"], correct: 1, explanation: "The Network Layer (Layer 3) handles logical addressing (IP) and routing packets between different networks.", category: "OSI Model" },
  { id: 2, question: "What is the PDU (Protocol Data Unit) at the Transport Layer?", options: ["Bits", "Frames", "Packets", "Segments"], correct: 3, explanation: "The Transport Layer uses Segments (TCP) or Datagrams (UDP) as its PDU.", category: "OSI Model" },
  { id: 3, question: "Which layer handles MAC addresses?", options: ["Physical Layer", "Data Link Layer", "Network Layer", "Transport Layer"], correct: 1, explanation: "The Data Link Layer (Layer 2) handles physical addressing through MAC addresses.", category: "OSI Model" },
  { id: 4, question: "SSL/TLS encryption operates at which OSI layer?", options: ["Application", "Presentation", "Session", "Transport"], correct: 1, explanation: "SSL/TLS primarily operates at the Presentation Layer (Layer 6), handling encryption and decryption.", category: "OSI Model" },
  { id: 5, question: "What device operates at Layer 3 of the OSI model?", options: ["Hub", "Switch", "Router", "Repeater"], correct: 2, explanation: "Routers operate at Layer 3 (Network Layer) and make forwarding decisions based on IP addresses.", category: "OSI Model" },
  { id: 6, question: "Which OSI layer establishes, manages, and terminates sessions?", options: ["Transport", "Session", "Presentation", "Application"], correct: 1, explanation: "The Session Layer (Layer 5) manages dialog control and session establishment between applications.", category: "OSI Model" },
  { id: 7, question: "At which layer does a switch operate?", options: ["Layer 1", "Layer 2", "Layer 3", "Layer 4"], correct: 1, explanation: "Standard switches operate at Layer 2 (Data Link), using MAC addresses to forward frames.", category: "OSI Model" },
  { id: 8, question: "What is the correct order of OSI layers from bottom to top?", options: ["Physical, Data Link, Network, Transport, Session, Presentation, Application", "Application, Presentation, Session, Transport, Network, Data Link, Physical", "Physical, Network, Data Link, Transport, Session, Application, Presentation", "Data Link, Physical, Network, Transport, Session, Presentation, Application"], correct: 0, explanation: "The OSI model from Layer 1-7: Physical, Data Link, Network, Transport, Session, Presentation, Application.", category: "OSI Model" },
  { id: 9, question: "Which layer is responsible for flow control and error recovery?", options: ["Network Layer", "Transport Layer", "Session Layer", "Data Link Layer"], correct: 1, explanation: "The Transport Layer provides flow control, error recovery, and reliable data delivery (TCP).", category: "OSI Model" },
  { id: 10, question: "HTTP, FTP, and SMTP operate at which OSI layer?", options: ["Layer 4", "Layer 5", "Layer 6", "Layer 7"], correct: 3, explanation: "HTTP, FTP, and SMTP are Application Layer (Layer 7) protocols.", category: "OSI Model" },
  { id: 11, question: "What is encapsulation in networking?", options: ["Removing headers from data", "Adding headers at each layer as data moves down", "Converting data to binary", "Compressing data for transmission"], correct: 1, explanation: "Encapsulation is the process of adding headers (and trailers) at each layer as data moves down the OSI model.", category: "OSI Model" },
  { id: 12, question: "Which layer converts data formats between systems?", options: ["Application", "Presentation", "Session", "Transport"], correct: 1, explanation: "The Presentation Layer handles data translation, encryption, and compression between different formats.", category: "OSI Model" },
  { id: 13, question: "Hubs operate at which OSI layer?", options: ["Layer 1", "Layer 2", "Layer 3", "Layer 4"], correct: 0, explanation: "Hubs are simple devices that operate at Layer 1 (Physical), just repeating electrical signals.", category: "OSI Model" },
  { id: 14, question: "What does the acronym 'PDU' stand for?", options: ["Protocol Data Unit", "Packet Delivery Unit", "Physical Data Unit", "Port Data Unit"], correct: 0, explanation: "PDU stands for Protocol Data Unit - the form data takes at each layer of the OSI model.", category: "OSI Model" },
  { id: 15, question: "Which layer adds the FCS (Frame Check Sequence)?", options: ["Physical Layer", "Data Link Layer", "Network Layer", "Transport Layer"], correct: 1, explanation: "The Data Link Layer adds FCS for error detection in frames.", category: "OSI Model" },

  // TCP/IP & Protocols (16-35)
  { id: 16, question: "What is the default port for HTTPS?", options: ["80", "443", "8080", "8443"], correct: 1, explanation: "HTTPS uses port 443 by default for encrypted web traffic.", category: "Ports & Protocols" },
  { id: 17, question: "Which protocol uses port 22?", options: ["Telnet", "FTP", "SSH", "SMTP"], correct: 2, explanation: "SSH (Secure Shell) uses port 22 for encrypted remote access.", category: "Ports & Protocols" },
  { id: 18, question: "What is the main difference between TCP and UDP?", options: ["TCP is faster", "UDP is connection-oriented", "TCP provides reliable delivery", "UDP has error correction"], correct: 2, explanation: "TCP is connection-oriented and provides reliable, ordered delivery. UDP is connectionless and faster but unreliable.", category: "Ports & Protocols" },
  { id: 19, question: "Which protocol is used for email sending?", options: ["POP3", "IMAP", "SMTP", "HTTP"], correct: 2, explanation: "SMTP (Simple Mail Transfer Protocol) is used for sending emails (ports 25/587).", category: "Ports & Protocols" },
  { id: 20, question: "DNS primarily uses which transport protocol?", options: ["TCP only", "UDP only", "Both TCP and UDP", "Neither"], correct: 2, explanation: "DNS uses UDP (port 53) for queries and TCP for zone transfers or large responses.", category: "Ports & Protocols" },
  { id: 21, question: "What port does FTP use for data transfer?", options: ["20", "21", "22", "23"], correct: 0, explanation: "FTP uses port 20 for data transfer and port 21 for control commands.", category: "Ports & Protocols" },
  { id: 22, question: "Which protocol assigns IP addresses automatically?", options: ["DNS", "DHCP", "ARP", "RARP"], correct: 1, explanation: "DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses to devices.", category: "Ports & Protocols" },
  { id: 23, question: "What is the TCP three-way handshake sequence?", options: ["ACK, SYN, SYN-ACK", "SYN, SYN-ACK, ACK", "SYN, ACK, SYN-ACK", "ACK, ACK, SYN"], correct: 1, explanation: "TCP connection: Client sends SYN → Server replies SYN-ACK → Client sends ACK.", category: "Ports & Protocols" },
  { id: 24, question: "Which port is used by SNMP?", options: ["22", "53", "161", "443"], correct: 2, explanation: "SNMP uses ports 161 (queries) and 162 (traps) for network management.", category: "Ports & Protocols" },
  { id: 25, question: "What protocol resolves IP addresses to MAC addresses?", options: ["DNS", "DHCP", "ARP", "ICMP"], correct: 2, explanation: "ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network.", category: "Ports & Protocols" },
  { id: 26, question: "Which protocol does 'ping' use?", options: ["TCP", "UDP", "ICMP", "ARP"], correct: 2, explanation: "Ping uses ICMP (Internet Control Message Protocol) Echo Request/Reply messages.", category: "Ports & Protocols" },
  { id: 27, question: "What port does Telnet use?", options: ["21", "22", "23", "25"], correct: 2, explanation: "Telnet uses port 23 (insecure - use SSH instead).", category: "Ports & Protocols" },
  { id: 28, question: "RDP (Remote Desktop Protocol) uses which port?", options: ["22", "443", "3306", "3389"], correct: 3, explanation: "RDP uses port 3389 for Windows Remote Desktop connections.", category: "Ports & Protocols" },
  { id: 29, question: "Which layer of TCP/IP model corresponds to OSI Layers 5-7?", options: ["Network Access", "Internet", "Transport", "Application"], correct: 3, explanation: "The TCP/IP Application layer combines OSI's Session, Presentation, and Application layers.", category: "Ports & Protocols" },
  { id: 30, question: "What is the purpose of the TTL field in IP packets?", options: ["Encrypt data", "Prevent routing loops", "Prioritize traffic", "Fragment packets"], correct: 1, explanation: "TTL (Time to Live) decrements at each hop, preventing packets from circulating forever.", category: "Ports & Protocols" },
  { id: 31, question: "IMAP uses which port for secure connections?", options: ["110", "143", "993", "995"], correct: 2, explanation: "IMAP uses port 143 normally and port 993 for IMAPS (secure/SSL).", category: "Ports & Protocols" },
  { id: 32, question: "Which protocol is more suitable for video streaming?", options: ["TCP", "UDP", "ICMP", "ARP"], correct: 1, explanation: "UDP is preferred for streaming because low latency is more important than guaranteed delivery.", category: "Ports & Protocols" },
  { id: 33, question: "What does TFTP stand for?", options: ["Transmission File Transfer Protocol", "Trivial File Transfer Protocol", "Trusted File Transfer Protocol", "Timed File Transfer Protocol"], correct: 1, explanation: "TFTP (Trivial File Transfer Protocol) is a simple file transfer protocol using UDP port 69.", category: "Ports & Protocols" },
  { id: 34, question: "Which TCP flag is used to terminate a connection?", options: ["SYN", "ACK", "FIN", "RST"], correct: 2, explanation: "FIN (Finish) flag is used for graceful connection termination. RST is for abrupt termination.", category: "Ports & Protocols" },
  { id: 35, question: "What is the well-known port range?", options: ["0-255", "0-1023", "1024-49151", "49152-65535"], correct: 1, explanation: "Well-known ports: 0-1023, Registered: 1024-49151, Dynamic/Private: 49152-65535.", category: "Ports & Protocols" },

  // IP Addressing & Subnetting (36-55)
  { id: 36, question: "What is the subnet mask for a /24 network?", options: ["255.255.0.0", "255.255.255.0", "255.255.255.128", "255.255.255.192"], correct: 1, explanation: "/24 means 24 network bits = 255.255.255.0 (11111111.11111111.11111111.00000000).", category: "Subnetting" },
  { id: 37, question: "How many usable host addresses are in a /28 network?", options: ["14", "16", "30", "32"], correct: 0, explanation: "/28 = 32 total - 2 (network + broadcast) = 14 usable hosts.", category: "Subnetting" },
  { id: 38, question: "Which IP class has a default subnet mask of 255.255.0.0?", options: ["Class A", "Class B", "Class C", "Class D"], correct: 1, explanation: "Class B (128.0.0.0 - 191.255.255.255) has a default /16 mask.", category: "Subnetting" },
  { id: 39, question: "What is the network address of 192.168.1.50/26?", options: ["192.168.1.0", "192.168.1.32", "192.168.1.64", "192.168.1.48"], correct: 0, explanation: "/26 has blocks of 64. 50 falls in 0-63 range, so network is 192.168.1.0.", category: "Subnetting" },
  { id: 40, question: "Which address range is reserved for APIPA?", options: ["10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"], correct: 1, explanation: "APIPA (Automatic Private IP Addressing) uses 169.254.0.0/16 when DHCP fails.", category: "Subnetting" },
  { id: 41, question: "What is the broadcast address for 10.0.0.0/8?", options: ["10.0.0.255", "10.255.255.255", "10.0.255.255", "10.255.0.255"], correct: 1, explanation: "/8 means only the first octet is network, so broadcast is 10.255.255.255.", category: "Subnetting" },
  { id: 42, question: "Which private IP range provides the most addresses?", options: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"], correct: 0, explanation: "10.0.0.0/8 provides ~16.7 million addresses (Class A private range).", category: "Subnetting" },
  { id: 43, question: "What is CIDR notation for subnet mask 255.255.255.224?", options: ["/25", "/26", "/27", "/28"], correct: 2, explanation: "255.255.255.224 = 11111111.11111111.11111111.11100000 = 27 ones = /27.", category: "Subnetting" },
  { id: 44, question: "How many subnets can you create with a /26 from a /24?", options: ["2", "4", "8", "16"], correct: 1, explanation: "Going from /24 to /26 = 2 extra bits = 2² = 4 subnets.", category: "Subnetting" },
  { id: 45, question: "What is the wildcard mask for 255.255.255.240?", options: ["0.0.0.15", "0.0.0.16", "0.0.0.31", "0.0.0.32"], correct: 0, explanation: "Wildcard = 255.255.255.255 - subnet mask. 255-240 = 15, so 0.0.0.15.", category: "Subnetting" },
  { id: 46, question: "Which is a valid Class C IP address?", options: ["10.0.0.1", "172.16.0.1", "192.168.1.1", "224.0.0.1"], correct: 2, explanation: "Class C: 192.0.0.0 - 223.255.255.255. 192.168.1.1 is Class C (also private).", category: "Subnetting" },
  { id: 47, question: "What is the loopback IP address?", options: ["0.0.0.0", "127.0.0.1", "192.168.0.1", "255.255.255.255"], correct: 1, explanation: "127.0.0.1 (or any 127.x.x.x) is the loopback address for testing local TCP/IP stack.", category: "Subnetting" },
  { id: 48, question: "How many host bits are in a /20 network?", options: ["8", "10", "12", "20"], correct: 2, explanation: "32 total bits - 20 network bits = 12 host bits.", category: "Subnetting" },
  { id: 49, question: "What does VLSM stand for?", options: ["Variable Length Subnet Mask", "Virtual LAN Subnet Management", "Very Large Subnet Module", "Variable Local Subnet Method"], correct: 0, explanation: "VLSM (Variable Length Subnet Mask) allows different subnet sizes within the same network.", category: "Subnetting" },
  { id: 50, question: "What is the first usable IP in 192.168.10.64/26?", options: ["192.168.10.64", "192.168.10.65", "192.168.10.66", "192.168.10.1"], correct: 1, explanation: ".64 is the network address, so .65 is the first usable host address.", category: "Subnetting" },
  { id: 51, question: "Which IP is the network address?", options: ["The first IP", "The last IP", "Any IP", "The router IP"], correct: 0, explanation: "The network address is the first IP in a subnet (all host bits = 0).", category: "Subnetting" },
  { id: 52, question: "What is supernetting?", options: ["Creating smaller subnets", "Combining multiple networks", "Encrypting subnet data", "Converting IPv4 to IPv6"], correct: 1, explanation: "Supernetting (summarization) combines multiple contiguous networks into one larger network.", category: "Subnetting" },
  { id: 53, question: "255.255.255.252 provides how many usable hosts?", options: ["2", "4", "6", "8"], correct: 0, explanation: "255.255.255.252 = /30, gives 4 total IPs - 2 = 2 usable (for point-to-point links).", category: "Subnetting" },
  { id: 54, question: "What is NAT primarily used for?", options: ["Encryption", "Address translation between private and public", "Routing", "DNS resolution"], correct: 1, explanation: "NAT (Network Address Translation) translates private IPs to public IPs for internet access.", category: "Subnetting" },
  { id: 55, question: "Which RFC defines private IP address ranges?", options: ["RFC 791", "RFC 1918", "RFC 2460", "RFC 3022"], correct: 1, explanation: "RFC 1918 defines private address ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.", category: "Subnetting" },

  // Network Security (56-70)
  { id: 56, question: "What type of attack floods a network with traffic?", options: ["Man-in-the-Middle", "DoS/DDoS", "Phishing", "SQL Injection"], correct: 1, explanation: "DoS (Denial of Service) and DDoS attacks flood systems with traffic to overwhelm them.", category: "Security" },
  { id: 57, question: "Which security feature prevents MAC address spoofing on switches?", options: ["VLAN", "Port Security", "ACL", "NAT"], correct: 1, explanation: "Port Security limits which MAC addresses can connect to a switch port.", category: "Security" },
  { id: 58, question: "What does a firewall ACL do?", options: ["Encrypt traffic", "Filter traffic based on rules", "Assign IP addresses", "Route packets"], correct: 1, explanation: "ACLs (Access Control Lists) filter traffic by permitting or denying based on criteria.", category: "Security" },
  { id: 59, question: "ARP spoofing exploits which protocol?", options: ["DNS", "DHCP", "ARP", "HTTP"], correct: 2, explanation: "ARP spoofing sends fake ARP messages to link attacker's MAC with victim's IP.", category: "Security" },
  { id: 60, question: "What is the purpose of DNSSEC?", options: ["Encrypt DNS queries", "Authenticate DNS responses", "Speed up DNS", "Cache DNS records"], correct: 1, explanation: "DNSSEC adds digital signatures to DNS records to prevent tampering and spoofing.", category: "Security" },
  { id: 61, question: "Which attack intercepts communication between two parties?", options: ["DDoS", "Brute Force", "Man-in-the-Middle", "Buffer Overflow"], correct: 2, explanation: "MITM attacks intercept and potentially alter communication between two parties.", category: "Security" },
  { id: 62, question: "What does IDS stand for?", options: ["Internet Domain System", "Intrusion Detection System", "Internal Data Security", "Integrated Defense Service"], correct: 1, explanation: "IDS (Intrusion Detection System) monitors for suspicious activity and alerts administrators.", category: "Security" },
  { id: 63, question: "802.1X provides what type of security?", options: ["Wireless encryption", "Port-based authentication", "Firewall filtering", "VPN tunneling"], correct: 1, explanation: "802.1X provides port-based network access control, authenticating devices before network access.", category: "Security" },
  { id: 64, question: "What is a DMZ in networking?", options: ["Encrypted zone", "Demilitarized zone between networks", "Data Management Zone", "Dynamic Mapping Zone"], correct: 1, explanation: "DMZ is a network segment between internal and external networks for public-facing servers.", category: "Security" },
  { id: 65, question: "Which VPN protocol is considered most secure?", options: ["PPTP", "L2TP", "IKEv2/IPsec", "All equally secure"], correct: 2, explanation: "IKEv2/IPsec is considered most secure. PPTP has known vulnerabilities.", category: "Security" },
  { id: 66, question: "What is VLAN hopping?", options: ["Jumping between VLANs without authorization", "Creating new VLANs", "Deleting VLANs", "VLAN tagging"], correct: 0, explanation: "VLAN hopping exploits vulnerabilities to access VLANs the attacker shouldn't reach.", category: "Security" },
  { id: 67, question: "RADIUS is used for what purpose?", options: ["Routing", "Authentication", "Encryption", "DNS"], correct: 1, explanation: "RADIUS provides centralized Authentication, Authorization, and Accounting (AAA).", category: "Security" },
  { id: 68, question: "What does 'stateful' mean for firewalls?", options: ["Stores no connection info", "Tracks connection states", "Static rules only", "No logging"], correct: 1, explanation: "Stateful firewalls track connection states, allowing return traffic for established sessions.", category: "Security" },
  { id: 69, question: "What is SYN flood attack?", options: ["DNS attack", "TCP handshake exhaustion", "ARP attack", "ICMP attack"], correct: 1, explanation: "SYN flood sends many SYN packets without completing handshake, exhausting server resources.", category: "Security" },
  { id: 70, question: "WPA3 improves on WPA2 with what feature?", options: ["Faster speeds", "SAE/Dragonfly handshake", "Longer passwords", "More channels"], correct: 1, explanation: "WPA3 uses SAE (Simultaneous Authentication of Equals) for protection against offline attacks.", category: "Security" },

  // Wireless Networking (71-80)
  { id: 71, question: "What frequency does 802.11n operate on?", options: ["2.4 GHz only", "5 GHz only", "Both 2.4 and 5 GHz", "6 GHz"], correct: 2, explanation: "802.11n (Wi-Fi 4) can operate on both 2.4 GHz and 5 GHz bands.", category: "Wireless" },
  { id: 72, question: "Which wireless standard is also known as Wi-Fi 6?", options: ["802.11n", "802.11ac", "802.11ax", "802.11ad"], correct: 2, explanation: "802.11ax is Wi-Fi 6, offering better performance in crowded environments.", category: "Wireless" },
  { id: 73, question: "What is the maximum theoretical speed of 802.11ac?", options: ["600 Mbps", "1.3 Gbps", "3.5 Gbps", "10 Gbps"], correct: 2, explanation: "802.11ac (Wi-Fi 5) Wave 2 can reach up to 3.5 Gbps with 4 spatial streams.", category: "Wireless" },
  { id: 74, question: "What does SSID stand for?", options: ["Service Set Identifier", "System Security ID", "Signal Strength Indicator", "Secure Session ID"], correct: 0, explanation: "SSID (Service Set Identifier) is the name of a wireless network.", category: "Wireless" },
  { id: 75, question: "Which security protocol should NOT be used for Wi-Fi?", options: ["WPA2", "WPA3", "WEP", "802.1X"], correct: 2, explanation: "WEP is deprecated and easily cracked - never use it.", category: "Wireless" },
  { id: 76, question: "What is channel bonding in wireless?", options: ["Combining channels for more bandwidth", "Securing channel access", "Separating channels", "Channel encryption"], correct: 0, explanation: "Channel bonding combines adjacent channels to increase bandwidth (e.g., 40MHz, 80MHz).", category: "Wireless" },
  { id: 77, question: "2.4 GHz has what advantage over 5 GHz?", options: ["Faster speeds", "More channels", "Better range and wall penetration", "Less interference"], correct: 2, explanation: "2.4 GHz has longer wavelength, providing better range and obstacle penetration.", category: "Wireless" },
  { id: 78, question: "What is a rogue access point?", options: ["Unauthorized AP on network", "AP with strong signal", "Backup AP", "Guest AP"], correct: 0, explanation: "A rogue AP is an unauthorized access point connected to a network, potentially malicious.", category: "Wireless" },
  { id: 79, question: "What technology does Wi-Fi 6 use to handle many devices?", options: ["MIMO", "OFDMA", "WMM", "DFS"], correct: 1, explanation: "OFDMA (Orthogonal Frequency Division Multiple Access) allows serving multiple devices simultaneously.", category: "Wireless" },
  { id: 80, question: "What is the purpose of WPS?", options: ["Speed up connections", "Simplified Wi-Fi setup", "Increase range", "Improve security"], correct: 1, explanation: "WPS (Wi-Fi Protected Setup) simplifies connecting devices but has security vulnerabilities.", category: "Wireless" },

  // Network Devices & Concepts (81-90)
  { id: 81, question: "What is the spanning tree protocol used for?", options: ["Routing", "Preventing loops", "Encryption", "IP assignment"], correct: 1, explanation: "STP (Spanning Tree Protocol) prevents Layer 2 loops by blocking redundant paths.", category: "Network Devices" },
  { id: 82, question: "What is the purpose of a VLAN?", options: ["Increase speed", "Segment network logically", "Encrypt traffic", "Assign IPs"], correct: 1, explanation: "VLANs logically segment a network without requiring separate physical infrastructure.", category: "Network Devices" },
  { id: 83, question: "What does a Layer 3 switch do?", options: ["Only switching", "Switching and routing", "Only routing", "Wireless bridging"], correct: 1, explanation: "Layer 3 switches combine Layer 2 switching with Layer 3 routing capabilities.", category: "Network Devices" },
  { id: 84, question: "What is port mirroring used for?", options: ["Load balancing", "Traffic monitoring/analysis", "Redundancy", "Speed increase"], correct: 1, explanation: "Port mirroring (SPAN) copies traffic from one port to another for monitoring.", category: "Network Devices" },
  { id: 85, question: "What is the native VLAN on a trunk?", options: ["VLAN 0", "VLAN 1 (default)", "VLAN 100", "No native VLAN"], correct: 1, explanation: "Native VLAN is untagged traffic on a trunk, default is VLAN 1.", category: "Network Devices" },
  { id: 86, question: "Link aggregation combines what?", options: ["VLANs", "Multiple physical links", "IP addresses", "MAC addresses"], correct: 1, explanation: "Link aggregation (LACP) bundles multiple physical links into one logical link.", category: "Network Devices" },
  { id: 87, question: "What is a collision domain?", options: ["Network segment where collisions can occur", "VLAN boundary", "Router interface", "Switch port"], correct: 0, explanation: "A collision domain is where devices compete for the same medium (shared hubs).", category: "Network Devices" },
  { id: 88, question: "What protocol does HSRP provide?", options: ["Load balancing", "First Hop Redundancy", "VLAN trunking", "QoS"], correct: 1, explanation: "HSRP (Hot Standby Router Protocol) provides gateway redundancy for high availability.", category: "Network Devices" },
  { id: 89, question: "PoE (Power over Ethernet) uses which pins?", options: ["1-2 only", "3-6 only", "1-2, 3-6 or all 8", "7-8 only"], correct: 2, explanation: "PoE can use spare pairs (4,5,7,8) or data pairs (1,2,3,6) depending on standard.", category: "Network Devices" },
  { id: 90, question: "What does QoS prioritize?", options: ["Security", "Traffic types", "IP addresses", "MAC addresses"], correct: 1, explanation: "QoS (Quality of Service) prioritizes certain traffic types (voice, video) over others.", category: "Network Devices" },

  // DNS & DHCP (91-95)
  { id: 91, question: "What type of DNS record maps hostname to IP?", options: ["A Record", "CNAME", "MX", "PTR"], correct: 0, explanation: "A (Address) record maps a hostname to an IPv4 address. AAAA for IPv6.", category: "DNS/DHCP" },
  { id: 92, question: "What is a PTR record used for?", options: ["Forward lookup", "Reverse lookup (IP to name)", "Mail routing", "Aliases"], correct: 1, explanation: "PTR (Pointer) records map IP addresses to hostnames (reverse DNS).", category: "DNS/DHCP" },
  { id: 93, question: "DHCP DORA stands for?", options: ["Discover, Offer, Request, Acknowledge", "Data, Operation, Route, Address", "Dynamic, Optimal, Reliable, Automatic", "Deny, Open, Relay, Accept"], correct: 0, explanation: "DHCP process: Discover → Offer → Request → Acknowledge.", category: "DNS/DHCP" },
  { id: 94, question: "What DNS record type is used for email servers?", options: ["A", "AAAA", "MX", "NS"], correct: 2, explanation: "MX (Mail Exchange) records specify mail servers for a domain.", category: "DNS/DHCP" },
  { id: 95, question: "What is DHCP relay agent used for?", options: ["Speed up DHCP", "Forward DHCP across subnets", "Secure DHCP", "Cache DHCP leases"], correct: 1, explanation: "DHCP relay forwards DHCP broadcasts across different subnets to reach the DHCP server.", category: "DNS/DHCP" },

  // IPv6 & Modern Networking (96-100)
  { id: 96, question: "How many bits are in an IPv6 address?", options: ["32", "64", "128", "256"], correct: 2, explanation: "IPv6 addresses are 128 bits long (compared to IPv4's 32 bits).", category: "IPv6" },
  { id: 97, question: "What is the IPv6 loopback address?", options: ["127.0.0.1", "::1", "fe80::1", "ff02::1"], correct: 1, explanation: "The IPv6 loopback address is ::1 (all zeros except the last bit).", category: "IPv6" },
  { id: 98, question: "What type of IPv6 address starts with fe80?", options: ["Global Unicast", "Link-Local", "Multicast", "Anycast"], correct: 1, explanation: "fe80::/10 are Link-Local addresses, auto-configured and not routable.", category: "IPv6" },
  { id: 99, question: "IPv6 eliminates the need for what?", options: ["DNS", "DHCP", "NAT", "Routing"], correct: 2, explanation: "IPv6's vast address space eliminates the need for NAT - every device can have a public IP.", category: "IPv6" },
  { id: 100, question: "What replaced broadcast in IPv6?", options: ["Unicast", "Anycast", "Multicast", "Nothing"], correct: 2, explanation: "IPv6 has no broadcast - it uses multicast and anycast for similar purposes.", category: "IPv6" },
];

const QUIZ_BANK_SIZE = 75;
const QUIZ_QUESTION_COUNT = 10;
const quizBank = networkingQuizBank.slice(0, QUIZ_BANK_SIZE);
const quizCategoryOrder = ["OSI Model", "Ports & Protocols", "Subnetting", "Security", "Wireless", "Network Devices", "DNS/DHCP", "IPv6"];
const quizCategoryColors: Record<string, string> = {
  "OSI Model": "#3b82f6",
  "Ports & Protocols": "#22c55e",
  "Subnetting": "#f59e0b",
  "Security": "#ef4444",
  "Wireless": "#8b5cf6",
  "Network Devices": "#06b6d4",
  "DNS/DHCP": "#0ea5e9",
  "IPv6": "#ec4899",
};

const selectRandomQuizQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import RouterIcon from "@mui/icons-material/Router";
import LayersIcon from "@mui/icons-material/Layers";
import DnsIcon from "@mui/icons-material/Dns";
import WifiIcon from "@mui/icons-material/Wifi";
import SecurityIcon from "@mui/icons-material/Security";
import StorageIcon from "@mui/icons-material/Storage";
import HubIcon from "@mui/icons-material/Hub";
import CableIcon from "@mui/icons-material/Cable";
import LanguageIcon from "@mui/icons-material/Language";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import SpeedIcon from "@mui/icons-material/Speed";
import CloudIcon from "@mui/icons-material/Cloud";
import SettingsEthernetIcon from "@mui/icons-material/SettingsEthernet";
import ComputerIcon from "@mui/icons-material/Computer";
import PublicIcon from "@mui/icons-material/Public";
import LockIcon from "@mui/icons-material/Lock";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import InfoIcon from "@mui/icons-material/Info";
import TerminalIcon from "@mui/icons-material/Terminal";
import VisibilityIcon from "@mui/icons-material/Visibility";
import SettingsIcon from "@mui/icons-material/Settings";
import SyncAltIcon from "@mui/icons-material/SyncAlt";
import CodeIcon from "@mui/icons-material/Code";

// ========== OSI MODEL ==========
const osiLayers = [
  { layer: 7, name: "Application", protocols: "HTTP, HTTPS, FTP, SMTP, DNS, SSH, Telnet", pdu: "Data", devices: "Firewalls, Proxies", description: "User interface, network services" },
  { layer: 6, name: "Presentation", protocols: "SSL/TLS, JPEG, GIF, ASCII, MPEG", pdu: "Data", devices: "None specific", description: "Encryption, compression, translation" },
  { layer: 5, name: "Session", protocols: "NetBIOS, RPC, PPTP", pdu: "Data", devices: "None specific", description: "Session management, authentication" },
  { layer: 4, name: "Transport", protocols: "TCP, UDP, SCTP", pdu: "Segment/Datagram", devices: "Firewalls, Load Balancers", description: "End-to-end delivery, flow control" },
  { layer: 3, name: "Network", protocols: "IP, ICMP, OSPF, BGP, ARP", pdu: "Packet", devices: "Routers, L3 Switches", description: "Logical addressing, routing" },
  { layer: 2, name: "Data Link", protocols: "Ethernet, Wi-Fi (802.11), PPP", pdu: "Frame", devices: "Switches, Bridges, NICs", description: "Physical addressing (MAC), error detection" },
  { layer: 1, name: "Physical", protocols: "Ethernet cables, Fiber, Radio waves", pdu: "Bits", devices: "Hubs, Repeaters, Cables", description: "Physical transmission of raw bits" },
];

// ========== TCP/IP MODEL ==========
const tcpipLayers = [
  { layer: 4, name: "Application", osiEquiv: "Application, Presentation, Session", protocols: "HTTP, FTP, DNS, SMTP, SSH", description: "Application protocols and services" },
  { layer: 3, name: "Transport", osiEquiv: "Transport", protocols: "TCP, UDP", description: "End-to-end communication, ports" },
  { layer: 2, name: "Internet", osiEquiv: "Network", protocols: "IP, ICMP, ARP, RARP", description: "Logical addressing and routing" },
  { layer: 1, name: "Network Access", osiEquiv: "Data Link, Physical", protocols: "Ethernet, Wi-Fi, PPP", description: "Physical network access" },
];

// ========== COMMON PROTOCOLS ==========
const protocols = [
  { name: "HTTP/HTTPS", port: "80/443", layer: "Application", description: "Web traffic (HTTPS = encrypted)", security: "Use HTTPS, HSTS headers" },
  { name: "FTP", port: "20-21", layer: "Application", description: "File transfer (unencrypted)", security: "Use SFTP or FTPS instead" },
  { name: "SSH", port: "22", layer: "Application", description: "Secure remote shell", security: "Key-based auth, disable root login" },
  { name: "Telnet", port: "23", layer: "Application", description: "Remote terminal (unencrypted)", security: "Never use - use SSH" },
  { name: "SMTP", port: "25/587", layer: "Application", description: "Email sending", security: "Use STARTTLS, SPF, DKIM" },
  { name: "DNS", port: "53", layer: "Application", description: "Domain name resolution", security: "DNSSEC, DoH, DoT" },
  { name: "DHCP", port: "67-68", layer: "Application", description: "Dynamic IP assignment", security: "DHCP snooping" },
  { name: "TFTP", port: "69", layer: "Application", description: "Simple file transfer", security: "Restrict to management networks" },
  { name: "HTTP (alt)", port: "8080", layer: "Application", description: "Alternative HTTP/proxy", security: "Same as HTTP" },
  { name: "POP3", port: "110/995", layer: "Application", description: "Email retrieval", security: "Use SSL (995)" },
  { name: "IMAP", port: "143/993", layer: "Application", description: "Email access", security: "Use SSL (993)" },
  { name: "SNMP", port: "161-162", layer: "Application", description: "Network management", security: "Use SNMPv3, strong community strings" },
  { name: "LDAP", port: "389/636", layer: "Application", description: "Directory services", security: "Use LDAPS (636)" },
  { name: "SMB", port: "445", layer: "Application", description: "Windows file sharing", security: "Disable SMBv1, use SMBv3" },
  { name: "RDP", port: "3389", layer: "Application", description: "Remote Desktop", security: "NLA, VPN, limit exposure" },
  { name: "MySQL", port: "3306", layer: "Application", description: "Database", security: "Never expose publicly" },
  { name: "PostgreSQL", port: "5432", layer: "Application", description: "Database", security: "Never expose publicly" },
];

// ========== IP ADDRESSING ==========
const ipv4Classes = [
  { class: "A", range: "1.0.0.0 - 126.255.255.255", defaultMask: "255.0.0.0 (/8)", hosts: "16,777,214", use: "Large networks" },
  { class: "B", range: "128.0.0.0 - 191.255.255.255", defaultMask: "255.255.0.0 (/16)", hosts: "65,534", use: "Medium networks" },
  { class: "C", range: "192.0.0.0 - 223.255.255.255", defaultMask: "255.255.255.0 (/24)", hosts: "254", use: "Small networks" },
  { class: "D", range: "224.0.0.0 - 239.255.255.255", defaultMask: "N/A", hosts: "N/A", use: "Multicast" },
  { class: "E", range: "240.0.0.0 - 255.255.255.255", defaultMask: "N/A", hosts: "N/A", use: "Reserved/Experimental" },
];

const privateRanges = [
  { range: "10.0.0.0 - 10.255.255.255", cidr: "10.0.0.0/8", class: "A", hosts: "16,777,216" },
  { range: "172.16.0.0 - 172.31.255.255", cidr: "172.16.0.0/12", class: "B", hosts: "1,048,576" },
  { range: "192.168.0.0 - 192.168.255.255", cidr: "192.168.0.0/16", class: "C", hosts: "65,536" },
];

const specialAddresses = [
  { address: "127.0.0.1", name: "Localhost/Loopback", description: "Points to the local machine" },
  { address: "0.0.0.0", name: "Default route / All interfaces", description: "Listen on all interfaces or default gateway" },
  { address: "255.255.255.255", name: "Broadcast", description: "Send to all hosts on local network" },
  { address: "169.254.x.x", name: "APIPA (Link-local)", description: "Auto-assigned when DHCP fails" },
  { address: "224.0.0.0/4", name: "Multicast", description: "One-to-many communication" },
];

// ========== SUBNETTING ==========
const cidrTable = [
  { cidr: "/32", mask: "255.255.255.255", hosts: 1, wildcard: "0.0.0.0" },
  { cidr: "/31", mask: "255.255.255.254", hosts: 2, wildcard: "0.0.0.1" },
  { cidr: "/30", mask: "255.255.255.252", hosts: 2, wildcard: "0.0.0.3" },
  { cidr: "/29", mask: "255.255.255.248", hosts: 6, wildcard: "0.0.0.7" },
  { cidr: "/28", mask: "255.255.255.240", hosts: 14, wildcard: "0.0.0.15" },
  { cidr: "/27", mask: "255.255.255.224", hosts: 30, wildcard: "0.0.0.31" },
  { cidr: "/26", mask: "255.255.255.192", hosts: 62, wildcard: "0.0.0.63" },
  { cidr: "/25", mask: "255.255.255.128", hosts: 126, wildcard: "0.0.0.127" },
  { cidr: "/24", mask: "255.255.255.0", hosts: 254, wildcard: "0.0.0.255" },
  { cidr: "/23", mask: "255.255.254.0", hosts: 510, wildcard: "0.0.1.255" },
  { cidr: "/22", mask: "255.255.252.0", hosts: 1022, wildcard: "0.0.3.255" },
  { cidr: "/21", mask: "255.255.248.0", hosts: 2046, wildcard: "0.0.7.255" },
  { cidr: "/20", mask: "255.255.240.0", hosts: 4094, wildcard: "0.0.15.255" },
  { cidr: "/16", mask: "255.255.0.0", hosts: 65534, wildcard: "0.0.255.255" },
  { cidr: "/8", mask: "255.0.0.0", hosts: 16777214, wildcard: "0.255.255.255" },
];

// ========== TCP vs UDP ==========
const tcpVsUdp = [
  { feature: "Connection", tcp: "Connection-oriented (3-way handshake)", udp: "Connectionless" },
  { feature: "Reliability", tcp: "Guaranteed delivery, acknowledgments", udp: "Best effort, no guarantees" },
  { feature: "Ordering", tcp: "Packets delivered in order", udp: "No ordering guarantee" },
  { feature: "Speed", tcp: "Slower (overhead)", udp: "Faster (minimal overhead)" },
  { feature: "Header size", tcp: "20-60 bytes", udp: "8 bytes" },
  { feature: "Flow control", tcp: "Yes (windowing)", udp: "No" },
  { feature: "Use cases", tcp: "HTTP, FTP, SSH, Email", udp: "DNS, VoIP, Gaming, Streaming" },
  { feature: "Error checking", tcp: "Checksum + retransmission", udp: "Checksum only" },
];

// ========== NETWORK DEVICES ==========
const networkDevices = [
  { device: "Hub", layer: "1 (Physical)", function: "Broadcasts to all ports", intelligence: "None - dumb device", security: "Avoid - enables sniffing" },
  { device: "Switch", layer: "2 (Data Link)", function: "Forwards based on MAC address", intelligence: "MAC address table", security: "VLANs, port security" },
  { device: "Router", layer: "3 (Network)", function: "Routes between networks (IP)", intelligence: "Routing table", security: "ACLs, firewall rules" },
  { device: "Firewall", layer: "3-7", function: "Filters traffic by rules", intelligence: "Stateful inspection", security: "Core security device" },
  { device: "Load Balancer", layer: "4-7", function: "Distributes traffic", intelligence: "Health checks", security: "SSL termination" },
  { device: "Proxy", layer: "7 (Application)", function: "Intermediary for requests", intelligence: "Content caching", security: "Content filtering, anonymity" },
  { device: "IDS/IPS", layer: "3-7", function: "Detect/prevent intrusions", intelligence: "Signature/anomaly detection", security: "Threat detection" },
  { device: "WAF", layer: "7", function: "Web application firewall", intelligence: "HTTP inspection", security: "OWASP protection" },
];

// ========== DNS RECORD TYPES ==========
const dnsRecords = [
  { type: "A", description: "Maps hostname to IPv4 address", example: "example.com → 93.184.216.34" },
  { type: "AAAA", description: "Maps hostname to IPv6 address", example: "example.com → 2606:2800:220:1:248:..." },
  { type: "CNAME", description: "Alias to another hostname", example: "www.example.com → example.com" },
  { type: "MX", description: "Mail server for domain", example: "example.com → mail.example.com (priority 10)" },
  { type: "NS", description: "Authoritative nameservers", example: "example.com → ns1.example.com" },
  { type: "TXT", description: "Text records (SPF, DKIM, verification)", example: "v=spf1 include:_spf.google.com ~all" },
  { type: "PTR", description: "Reverse DNS (IP to hostname)", example: "34.216.184.93.in-addr.arpa → example.com" },
  { type: "SOA", description: "Start of Authority - zone info", example: "Primary NS, admin email, serial number" },
  { type: "SRV", description: "Service location", example: "_sip._tcp.example.com → sipserver.example.com:5060" },
  { type: "CAA", description: "Certificate Authority Authorization", example: "Only allow Let's Encrypt to issue certs" },
];

// ========== COMMON NETWORK COMMANDS ==========
const networkCommands = [
  { command: "ping <host>", description: "Test connectivity (ICMP echo)", os: "All", example: "ping 8.8.8.8" },
  { command: "traceroute / tracert", description: "Show path to destination", os: "Linux/Windows", example: "traceroute google.com" },
  { command: "nslookup <domain>", description: "DNS lookup", os: "All", example: "nslookup example.com" },
  { command: "dig <domain>", description: "Advanced DNS lookup", os: "Linux/Mac", example: "dig example.com +short" },
  { command: "netstat -an", description: "Show all connections and listening ports", os: "All", example: "netstat -tulpn (Linux)" },
  { command: "ss -tulpn", description: "Socket statistics (modern netstat)", os: "Linux", example: "ss -tulpn" },
  { command: "ifconfig / ip addr", description: "Show network interfaces", os: "Linux", example: "ip addr show" },
  { command: "ipconfig", description: "Show network config", os: "Windows", example: "ipconfig /all" },
  { command: "arp -a", description: "Show ARP cache (IP-MAC mappings)", os: "All", example: "arp -a" },
  { command: "route / ip route", description: "Show/modify routing table", os: "All", example: "ip route show" },
  { command: "nmap <target>", description: "Network scanner", os: "All", example: "nmap -sV 192.168.1.0/24" },
  { command: "tcpdump", description: "Packet capture", os: "Linux", example: "tcpdump -i eth0 port 80" },
  { command: "curl / wget", description: "HTTP requests", os: "All", example: "curl -I https://example.com" },
  { command: "whois <domain>", description: "Domain registration info", os: "All", example: "whois example.com" },
  { command: "host <domain>", description: "Simple DNS lookup", os: "Linux/Mac", example: "host example.com" },
];

// ========== NETWORK TOPOLOGIES ==========
const topologies = [
  { name: "Star", description: "All devices connect to central hub/switch", pros: "Easy to manage, fault isolation", cons: "Single point of failure (central device)" },
  { name: "Bus", description: "All devices on single cable", pros: "Simple, inexpensive", cons: "Single point of failure, collisions" },
  { name: "Ring", description: "Devices connected in circular chain", pros: "Equal access, predictable", cons: "Single break disrupts entire network" },
  { name: "Mesh", description: "Every device connects to every other", pros: "Highly redundant, fault tolerant", cons: "Expensive, complex" },
  { name: "Hybrid", description: "Combination of topologies", pros: "Flexible, scalable", cons: "Complex management" },
];

// ========== VLAN CONCEPTS ==========
const vlanConcepts = [
  { concept: "VLAN", description: "Virtual LAN - logical network segmentation", benefit: "Isolate broadcast domains, improve security" },
  { concept: "Trunk Port", description: "Carries multiple VLANs between switches", benefit: "Connect switches while maintaining VLAN separation" },
  { concept: "Access Port", description: "Belongs to single VLAN (end devices)", benefit: "Simple device connectivity" },
  { concept: "Native VLAN", description: "Untagged traffic on trunk port", benefit: "Backward compatibility" },
  { concept: "802.1Q", description: "VLAN tagging standard", benefit: "Industry standard for VLAN trunking" },
  { concept: "Inter-VLAN Routing", description: "Route traffic between VLANs", benefit: "Controlled communication between segments" },
];

// ========== WIRELESS STANDARDS ==========
const wirelessStandards = [
  { standard: "802.11a", frequency: "5 GHz", maxSpeed: "54 Mbps", range: "~35m", year: "1999" },
  { standard: "802.11b", frequency: "2.4 GHz", maxSpeed: "11 Mbps", range: "~38m", year: "1999" },
  { standard: "802.11g", frequency: "2.4 GHz", maxSpeed: "54 Mbps", range: "~38m", year: "2003" },
  { standard: "802.11n (Wi-Fi 4)", frequency: "2.4/5 GHz", maxSpeed: "600 Mbps", range: "~70m", year: "2009" },
  { standard: "802.11ac (Wi-Fi 5)", frequency: "5 GHz", maxSpeed: "6.9 Gbps", range: "~35m", year: "2013" },
  { standard: "802.11ax (Wi-Fi 6)", frequency: "2.4/5/6 GHz", maxSpeed: "9.6 Gbps", range: "~35m", year: "2019" },
  { standard: "802.11be (Wi-Fi 7)", frequency: "2.4/5/6 GHz", maxSpeed: "46 Gbps", range: "~35m", year: "2024" },
];

// ========== WIRELESS SECURITY ==========
const wirelessSecurity = [
  { protocol: "WEP", security: "Broken", description: "Weak encryption, easily cracked", recommendation: "Never use" },
  { protocol: "WPA", security: "Weak", description: "TKIP encryption, vulnerable", recommendation: "Avoid if possible" },
  { protocol: "WPA2-Personal", security: "Good", description: "AES encryption, PSK", recommendation: "Minimum acceptable" },
  { protocol: "WPA2-Enterprise", security: "Better", description: "RADIUS authentication", recommendation: "Recommended for business" },
  { protocol: "WPA3-Personal", security: "Strong", description: "SAE handshake, forward secrecy", recommendation: "Best for home/small office" },
  { protocol: "WPA3-Enterprise", security: "Strongest", description: "192-bit encryption, RADIUS", recommendation: "Best for enterprise" },
];

// ========== NAT TYPES ==========
const natTypes = [
  { type: "Static NAT", description: "One-to-one mapping (public to private)", useCase: "Servers needing consistent public IP" },
  { type: "Dynamic NAT", description: "Pool of public IPs assigned dynamically", useCase: "Multiple hosts, limited public IPs" },
  { type: "PAT/NAT Overload", description: "Many private IPs share one public IP (port-based)", useCase: "Home routers, most common" },
  { type: "DNAT", description: "Destination NAT - redirect incoming traffic", useCase: "Port forwarding to internal servers" },
  { type: "SNAT", description: "Source NAT - change source IP of outgoing", useCase: "Hide internal IPs" },
];

// ========== IPv6 BASICS ==========
const ipv6Basics = [
  { concept: "Address Format", description: "128-bit, 8 groups of 4 hex digits (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334)" },
  { concept: "Abbreviation", description: "Leading zeros can be omitted, :: replaces consecutive zero groups (once)" },
  { concept: "Link-Local", description: "fe80::/10 - auto-configured, not routable" },
  { concept: "Global Unicast", description: "2000::/3 - publicly routable addresses" },
  { concept: "Loopback", description: "::1 - equivalent to 127.0.0.1" },
  { concept: "No NAT needed", description: "Enough addresses for every device (340 undecillion)" },
  { concept: "No broadcast", description: "Uses multicast instead (ff00::/8)" },
];

// ========== INTERACTIVE TOOL COMPONENTS ==========

// Helper function for IP calculations
const ipToNum = (ip: string): number => {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
};

const numToIP = (num: number): string => {
  return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join(".");
};

// ========== VLSM CALCULATOR COMPONENT ==========
interface VLSMSubnet {
  name: string;
  hostsNeeded: number;
  cidr: number;
  networkAddress: string;
  broadcastAddress: string;
  firstHost: string;
  lastHost: string;
  subnetMask: string;
  usableHosts: number;
  totalAddresses: number;
}

const VLSMCalculator: React.FC<{ theme: any; alpha: any }> = ({ theme, alpha }) => {
  const [baseNetwork, setBaseNetwork] = useState("192.168.1.0");
  const [baseCIDR, setBaseCIDR] = useState(24);
  const [requirements, setRequirements] = useState([
    { name: "Subnet A", hosts: 100 },
    { name: "Subnet B", hosts: 50 },
    { name: "Subnet C", hosts: 25 },
    { name: "Point-to-Point", hosts: 2 },
  ]);
  const [results, setResults] = useState<VLSMSubnet[]>([]);
  const [error, setError] = useState("");

  const addRequirement = () => {
    setRequirements([...requirements, { name: `Subnet ${String.fromCharCode(65 + requirements.length)}`, hosts: 10 }]);
  };

  const removeRequirement = (index: number) => {
    setRequirements(requirements.filter((_, i) => i !== index));
  };

  const updateRequirement = (index: number, field: "name" | "hosts", value: string | number) => {
    const updated = [...requirements];
    if (field === "hosts") {
      updated[index].hosts = Number(value) || 0;
    } else {
      updated[index].name = value as string;
    }
    setRequirements(updated);
  };

  const calculateVLSM = () => {
    setError("");
    setResults([]);

    // Validate base network
    const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    if (!ipRegex.test(baseNetwork)) {
      setError("Invalid base network address");
      return;
    }

    // Sort requirements by hosts needed (largest first - VLSM best practice)
    const sorted = [...requirements].sort((a, b) => b.hosts - a.hosts);

    // Calculate total addresses needed
    let totalNeeded = 0;
    const subnets: VLSMSubnet[] = [];

    // Calculate available addresses in base network
    const hostBits = 32 - baseCIDR;
    const totalAvailable = Math.pow(2, hostBits);

    let currentIP = ipToNum(baseNetwork);
    const baseNetworkNum = currentIP;
    const maxIP = baseNetworkNum + totalAvailable;

    for (const req of sorted) {
      // Calculate required CIDR for this subnet
      let neededHosts = req.hosts + 2; // +2 for network and broadcast
      let subnetBits = Math.ceil(Math.log2(neededHosts));
      if (subnetBits < 2) subnetBits = 2; // Minimum /30
      const subnetCIDR = 32 - subnetBits;
      const subnetSize = Math.pow(2, subnetBits);

      // Align to subnet boundary
      const alignedIP = Math.ceil(currentIP / subnetSize) * subnetSize;

      if (alignedIP + subnetSize > maxIP) {
        setError(`Not enough address space! Need ${req.hosts} hosts for "${req.name}" but ran out of addresses.`);
        return;
      }

      const networkAddr = alignedIP;
      const broadcastAddr = alignedIP + subnetSize - 1;
      const maskNum = (0xFFFFFFFF << subnetBits) >>> 0;

      subnets.push({
        name: req.name,
        hostsNeeded: req.hosts,
        cidr: subnetCIDR,
        networkAddress: numToIP(networkAddr),
        broadcastAddress: numToIP(broadcastAddr),
        firstHost: numToIP(networkAddr + 1),
        lastHost: numToIP(broadcastAddr - 1),
        subnetMask: numToIP(maskNum),
        usableHosts: subnetSize - 2,
        totalAddresses: subnetSize,
      });

      currentIP = broadcastAddr + 1;
      totalNeeded += subnetSize;
    }

    setResults(subnets);
  };

  return (
    <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.08)} 0%, ${alpha("#8b5cf6", 0.08)} 100%)`, border: `2px solid ${alpha("#06b6d4", 0.3)}` }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <AccountTreeIcon sx={{ fontSize: 36, color: "#06b6d4" }} />
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800, color: "#06b6d4" }}>VLSM Calculator</Typography>
          <Typography variant="body2" color="text.secondary">Variable Length Subnet Masking - Efficiently allocate IP addresses based on host requirements</Typography>
        </Box>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Base Network:</Typography>
          <TextField
            fullWidth
            size="small"
            value={baseNetwork}
            onChange={(e) => setBaseNetwork(e.target.value)}
            placeholder="192.168.1.0"
            sx={{ mb: 2, "& input": { fontFamily: "monospace" } }}
          />
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Base CIDR: /{baseCIDR}</Typography>
          <Slider
            value={baseCIDR}
            onChange={(_, v) => setBaseCIDR(v as number)}
            min={8}
            max={30}
            marks={[{ value: 8, label: "/8" }, { value: 16, label: "/16" }, { value: 24, label: "/24" }]}
            sx={{ color: "#06b6d4", mb: 2 }}
          />
          <Alert severity="info" sx={{ mb: 2 }}>
            <Typography variant="caption">Available: {Math.pow(2, 32 - baseCIDR).toLocaleString()} addresses</Typography>
          </Alert>
        </Grid>

        <Grid item xs={12} md={8}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Host Requirements (sorted largest first for optimal allocation):</Typography>
          <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, maxHeight: 250, overflow: "auto" }}>
            {requirements.map((req, idx) => (
              <Box key={idx} sx={{ display: "flex", gap: 1, mb: 1, alignItems: "center" }}>
                <TextField
                  size="small"
                  value={req.name}
                  onChange={(e) => updateRequirement(idx, "name", e.target.value)}
                  sx={{ flex: 1 }}
                />
                <TextField
                  size="small"
                  type="number"
                  value={req.hosts}
                  onChange={(e) => updateRequirement(idx, "hosts", e.target.value)}
                  sx={{ width: 100 }}
                  InputProps={{ endAdornment: <Typography variant="caption">hosts</Typography> }}
                />
                <IconButton size="small" onClick={() => removeRequirement(idx)} color="error">
                  <CancelIcon fontSize="small" />
                </IconButton>
              </Box>
            ))}
            <Button size="small" onClick={addRequirement} sx={{ mt: 1 }}>+ Add Subnet</Button>
          </Paper>
        </Grid>
      </Grid>

      <Box sx={{ mt: 3, textAlign: "center" }}>
        <Button variant="contained" onClick={calculateVLSM} startIcon={<CalculateIcon />} sx={{ bgcolor: "#06b6d4", "&:hover": { bgcolor: "#0891b2" } }}>
          Calculate VLSM Subnets
        </Button>
      </Box>

      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}

      {results.length > 0 && (
        <TableContainer component={Paper} sx={{ mt: 3, borderRadius: 2 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Subnet</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Needed</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>CIDR</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Network</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Usable Range</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Broadcast</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Usable</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {results.map((r, idx) => (
                <TableRow key={idx}>
                  <TableCell sx={{ fontWeight: 600 }}>{r.name}</TableCell>
                  <TableCell>{r.hostsNeeded}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#06b6d4", fontWeight: 700 }}>/{r.cidr}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#ef4444" }}>{r.networkAddress}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{r.firstHost} - {r.lastHost}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#8b5cf6" }}>{r.broadcastAddress}</TableCell>
                  <TableCell sx={{ fontWeight: 600, color: "#22c55e" }}>{r.usableHosts}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Paper>
  );
};

// ========== ENHANCED NETWORK PLANNER TOOL ==========
interface PlannedSubnet {
  id: string;
  name: string;
  currentHosts: number;
  growthRate: number; // percentage per year
  years: number;
  color: string;
}

interface SubnetResult {
  name: string;
  currentHosts: number;
  futureHosts: number;
  cidr: number;
  mask: string;
  usable: number;
  total: number;
  efficiency: number;
  networkAddress: string;
  firstHost: string;
  lastHost: string;
  broadcastAddress: string;
  color: string;
}

const NetworkPlannerTool: React.FC<{ theme: any; alpha: any }> = ({ theme, alpha }) => {
  const [mode, setMode] = useState<"single" | "multi">("single");
  const [hostCount, setHostCount] = useState(100);
  const [growthRate, setGrowthRate] = useState(20);
  const [planYears, setPlanYears] = useState(3);
  const [baseNetwork, setBaseNetwork] = useState("10.0.0.0");
  const [baseCIDR, setBaseCIDR] = useState(16);
  const [showGrowth, setShowGrowth] = useState(true);

  // Multi-subnet planning
  const [subnets, setSubnets] = useState<PlannedSubnet[]>([
    { id: "1", name: "Servers", currentHosts: 50, growthRate: 10, years: 3, color: "#ef4444" },
    { id: "2", name: "Workstations", currentHosts: 200, growthRate: 15, years: 3, color: "#3b82f6" },
    { id: "3", name: "IoT Devices", currentHosts: 100, growthRate: 30, years: 3, color: "#22c55e" },
    { id: "4", name: "Guest WiFi", currentHosts: 50, growthRate: 25, years: 3, color: "#f59e0b" },
  ]);

  const [multiResults, setMultiResults] = useState<SubnetResult[]>([]);

  const subnetColors = ["#ef4444", "#3b82f6", "#22c55e", "#f59e0b", "#8b5cf6", "#ec4899", "#06b6d4", "#84cc16"];

  // Calculate future hosts with growth
  const calculateFutureHosts = (current: number, rate: number, years: number): number => {
    return Math.ceil(current * Math.pow(1 + rate / 100, years));
  };

  // Calculate optimal subnet for given hosts
  const getOptimalSubnet = (hosts: number) => {
    const needed = hosts + 2;
    let bits = Math.ceil(Math.log2(needed));
    if (bits < 2) bits = 2;
    const cidr = 32 - bits;
    const total = Math.pow(2, bits);
    const usable = total - 2;
    const maskNum = (0xFFFFFFFF << bits) >>> 0;
    const mask = numToIP(maskNum);
    return { cidr, mask, usable, total, bits };
  };

  // Get alternative subnet suggestions
  const getAlternatives = (hosts: number) => {
    const optimal = getOptimalSubnet(hosts);
    const alternatives = [];

    // Smaller subnet (if possible and hosts still fit)
    if (optimal.cidr < 30) {
      const smallerBits = optimal.bits - 1;
      const smallerTotal = Math.pow(2, smallerBits);
      const smallerUsable = smallerTotal - 2;
      if (smallerUsable >= hosts) {
        const smallerMaskNum = (0xFFFFFFFF << smallerBits) >>> 0;
        alternatives.push({
          label: "Smaller (Tighter fit)",
          cidr: 32 - smallerBits,
          mask: numToIP(smallerMaskNum),
          usable: smallerUsable,
          total: smallerTotal,
          waste: smallerUsable - hosts,
          efficiency: (hosts / smallerUsable) * 100,
          recommendation: smallerUsable - hosts < hosts * 0.1 ? "⚠️ Very tight - no room for growth" : "✓ Good for static networks",
        });
      }
    }

    // Optimal
    alternatives.push({
      label: "Optimal (Recommended)",
      cidr: optimal.cidr,
      mask: optimal.mask,
      usable: optimal.usable,
      total: optimal.total,
      waste: optimal.usable - hosts,
      efficiency: (hosts / optimal.usable) * 100,
      recommendation: "✓ Best balance of efficiency and room for growth",
      isOptimal: true,
    });

    // Larger subnet (more room)
    if (optimal.cidr > 8) {
      const largerBits = optimal.bits + 1;
      const largerTotal = Math.pow(2, largerBits);
      const largerUsable = largerTotal - 2;
      const largerMaskNum = (0xFFFFFFFF << largerBits) >>> 0;
      alternatives.push({
        label: "Larger (Room to grow)",
        cidr: 32 - largerBits,
        mask: numToIP(largerMaskNum),
        usable: largerUsable,
        total: largerTotal,
        waste: largerUsable - hosts,
        efficiency: (hosts / largerUsable) * 100,
        recommendation: "✓ Good for networks expecting significant growth",
      });
    }

    return alternatives.sort((a, b) => b.cidr - a.cidr);
  };

  // Single mode results
  const futureHosts = showGrowth ? calculateFutureHosts(hostCount, growthRate, planYears) : hostCount;
  const singleResult = getOptimalSubnet(futureHosts);
  const alternatives = getAlternatives(futureHosts);
  const singleEfficiency = (futureHosts / singleResult.usable) * 100;

  // Multi-subnet planning calculation
  const calculateMultiSubnets = () => {
    const sortedSubnets = [...subnets]
      .map(s => ({
        ...s,
        futureHosts: calculateFutureHosts(s.currentHosts, s.growthRate, s.years),
      }))
      .sort((a, b) => b.futureHosts - a.futureHosts);

    const baseNetworkNum = ipToNum(baseNetwork);
    const maxIP = baseNetworkNum + Math.pow(2, 32 - baseCIDR);
    let currentIP = baseNetworkNum;
    const results: SubnetResult[] = [];

    for (const subnet of sortedSubnets) {
      const optimal = getOptimalSubnet(subnet.futureHosts);
      const subnetSize = optimal.total;

      // Align to subnet boundary
      const alignedIP = Math.ceil(currentIP / subnetSize) * subnetSize;

      if (alignedIP + subnetSize > maxIP) {
        continue; // Skip if doesn't fit
      }

      const networkAddr = alignedIP;
      const broadcastAddr = alignedIP + subnetSize - 1;

      results.push({
        name: subnet.name,
        currentHosts: subnet.currentHosts,
        futureHosts: subnet.futureHosts,
        cidr: optimal.cidr,
        mask: optimal.mask,
        usable: optimal.usable,
        total: optimal.total,
        efficiency: (subnet.futureHosts / optimal.usable) * 100,
        networkAddress: numToIP(networkAddr),
        firstHost: numToIP(networkAddr + 1),
        lastHost: numToIP(broadcastAddr - 1),
        broadcastAddress: numToIP(broadcastAddr),
        color: subnet.color,
      });

      currentIP = broadcastAddr + 1;
    }

    setMultiResults(results);
  };

  React.useEffect(() => {
    if (mode === "multi") {
      calculateMultiSubnets();
    }
  }, [subnets, baseNetwork, baseCIDR, mode]);

  const addSubnet = () => {
    const newId = Date.now().toString();
    setSubnets([...subnets, {
      id: newId,
      name: `Subnet ${subnets.length + 1}`,
      currentHosts: 50,
      growthRate: 15,
      years: 3,
      color: subnetColors[subnets.length % subnetColors.length],
    }]);
  };

  const updateSubnet = (id: string, field: keyof PlannedSubnet, value: any) => {
    setSubnets(subnets.map(s => s.id === id ? { ...s, [field]: value } : s));
  };

  const removeSubnet = (id: string) => {
    setSubnets(subnets.filter(s => s.id !== id));
  };

  const totalAddressesUsed = multiResults.reduce((acc, r) => acc + r.total, 0);
  const totalAvailable = Math.pow(2, 32 - baseCIDR);
  const overallEfficiency = (totalAddressesUsed / totalAvailable) * 100;

  const presets = [
    { label: "Home Office", hosts: 10, growth: 10, desc: "Small home network" },
    { label: "Small Business", hosts: 50, growth: 20, desc: "Growing small business" },
    { label: "Department", hosts: 100, growth: 15, desc: "Corporate department" },
    { label: "Branch Office", hosts: 200, growth: 25, desc: "Branch location" },
    { label: "Data Center", hosts: 500, growth: 30, desc: "Server infrastructure" },
  ];

  return (
    <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#22c55e", 0.05)} 0%, ${alpha("#06b6d4", 0.05)} 100%)`, border: `2px solid ${alpha("#22c55e", 0.3)}` }}>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          <SettingsIcon sx={{ fontSize: 36, color: "#22c55e" }} />
          <Box>
            <Typography variant="h5" sx={{ fontWeight: 800, color: "#22c55e" }}>Advanced Network Planner</Typography>
            <Typography variant="body2" color="text.secondary">Plan subnets with growth forecasting and multi-network support</Typography>
          </Box>
        </Box>
        <ToggleButtonGroup value={mode} exclusive onChange={(_, v) => v && setMode(v)} size="small">
          <ToggleButton value="single">Single Subnet</ToggleButton>
          <ToggleButton value="multi">Multi-Subnet</ToggleButton>
        </ToggleButtonGroup>
      </Box>

      {mode === "single" ? (
        <>
          {/* Single Subnet Mode */}
          <Grid container spacing={3}>
            <Grid item xs={12} md={5}>
              <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>📊 Host Requirements</Typography>

                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Current Hosts Needed:</Typography>
                <TextField
                  fullWidth
                  type="number"
                  size="small"
                  value={hostCount}
                  onChange={(e) => setHostCount(Math.max(1, Number(e.target.value) || 0))}
                  sx={{ mb: 2, "& input": { fontFamily: "monospace" } }}
                />

                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                  {presets.map((p) => (
                    <Tooltip key={p.label} title={p.desc}>
                      <Chip
                        label={p.label}
                        size="small"
                        clickable
                        onClick={() => { setHostCount(p.hosts); setGrowthRate(p.growth); }}
                        variant={hostCount === p.hosts ? "filled" : "outlined"}
                        color={hostCount === p.hosts ? "success" : "default"}
                      />
                    </Tooltip>
                  ))}
                </Box>

                <FormControlLabel
                  control={<Checkbox checked={showGrowth} onChange={(e) => setShowGrowth(e.target.checked)} color="success" />}
                  label={<Typography variant="body2" sx={{ fontWeight: 600 }}>Include Growth Planning</Typography>}
                />

                {showGrowth && (
                  <Box sx={{ mt: 2, p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                      Annual Growth Rate: <Box component="span" sx={{ color: "#22c55e" }}>{growthRate}%</Box>
                    </Typography>
                    <Slider
                      value={growthRate}
                      onChange={(_, v) => setGrowthRate(v as number)}
                      min={0}
                      max={100}
                      marks={[{ value: 0, label: "0%" }, { value: 50, label: "50%" }, { value: 100, label: "100%" }]}
                      sx={{ color: "#22c55e" }}
                    />

                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, mt: 2 }}>
                      Plan for: <Box component="span" sx={{ color: "#22c55e" }}>{planYears} years</Box>
                    </Typography>
                    <Slider
                      value={planYears}
                      onChange={(_, v) => setPlanYears(v as number)}
                      min={1}
                      max={10}
                      marks={[{ value: 1, label: "1yr" }, { value: 5, label: "5yr" }, { value: 10, label: "10yr" }]}
                      sx={{ color: "#22c55e" }}
                    />

                    <Alert severity="info" sx={{ mt: 2 }}>
                      <Typography variant="caption">
                        <strong>Growth Projection:</strong> {hostCount} hosts → <strong>{futureHosts}</strong> hosts in {planYears} years
                      </Typography>
                    </Alert>
                  </Box>
                )}
              </Paper>
            </Grid>

            <Grid item xs={12} md={7}>
              {/* Results */}
              <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>✓ Recommended Subnet</Typography>

                <Grid container spacing={2}>
                  <Grid item xs={4}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#22c55e", 0.1), borderRadius: 2 }}>
                      <Typography variant="caption" color="text.secondary">CIDR</Typography>
                      <Typography variant="h3" sx={{ fontFamily: "monospace", fontWeight: 800, color: "#22c55e" }}>/{singleResult.cidr}</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={4}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#06b6d4", 0.1), borderRadius: 2 }}>
                      <Typography variant="caption" color="text.secondary">Subnet Mask</Typography>
                      <Typography variant="h6" sx={{ fontFamily: "monospace", fontWeight: 700 }}>{singleResult.mask}</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={4}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#8b5cf6", 0.1), borderRadius: 2 }}>
                      <Typography variant="caption" color="text.secondary">Usable Hosts</Typography>
                      <Typography variant="h4" sx={{ fontWeight: 800, color: "#8b5cf6" }}>{singleResult.usable.toLocaleString()}</Typography>
                    </Paper>
                  </Grid>
                </Grid>

                {/* Efficiency Bar */}
                <Box sx={{ mt: 3 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                    <Typography variant="caption" color="text.secondary">Address Utilization</Typography>
                    <Typography variant="caption" sx={{ fontWeight: 700, color: singleEfficiency > 80 ? "#f59e0b" : "#22c55e" }}>
                      {singleEfficiency.toFixed(1)}% ({futureHosts}/{singleResult.usable})
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={Math.min(singleEfficiency, 100)}
                    sx={{
                      height: 12,
                      borderRadius: 2,
                      bgcolor: alpha("#22c55e", 0.1),
                      "& .MuiLinearProgress-bar": {
                        borderRadius: 2,
                        bgcolor: singleEfficiency > 90 ? "#ef4444" : singleEfficiency > 75 ? "#f59e0b" : "#22c55e",
                      },
                    }}
                  />
                  <Box sx={{ display: "flex", justifyContent: "space-between", mt: 0.5 }}>
                    <Typography variant="caption" color="text.secondary">Spare: {singleResult.usable - futureHosts} addresses</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {singleEfficiency > 90 ? "⚠️ Very tight" : singleEfficiency > 75 ? "⚡ Efficient" : "✓ Room to grow"}
                    </Typography>
                  </Box>
                </Box>
              </Paper>

              {/* Alternative Suggestions */}
              <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>📋 Alternative Options</Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 700 }}>Option</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>CIDR</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Mask</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Usable</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Efficiency</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {alternatives.map((alt, idx) => (
                        <TableRow key={idx} sx={{ bgcolor: (alt as any).isOptimal ? alpha("#22c55e", 0.1) : "transparent" }}>
                          <TableCell sx={{ fontWeight: (alt as any).isOptimal ? 700 : 400 }}>{alt.label}</TableCell>
                          <TableCell sx={{ fontFamily: "monospace", fontWeight: 700, color: "#22c55e" }}>/{alt.cidr}</TableCell>
                          <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{alt.mask}</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>{alt.usable.toLocaleString()}</TableCell>
                          <TableCell>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <LinearProgress
                                variant="determinate"
                                value={alt.efficiency}
                                sx={{ width: 50, height: 6, borderRadius: 1 }}
                              />
                              <Typography variant="caption">{alt.efficiency.toFixed(0)}%</Typography>
                            </Box>
                          </TableCell>
                          <TableCell sx={{ fontSize: "0.75rem" }}>{alt.recommendation}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>
        </>
      ) : (
        <>
          {/* Multi-Subnet Mode */}
          <Grid container spacing={3}>
            <Grid item xs={12} md={5}>
              <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>🌐 Base Network</Typography>
                <Grid container spacing={2}>
                  <Grid item xs={7}>
                    <Typography variant="caption" color="text.secondary">Network Address</Typography>
                    <TextField
                      fullWidth
                      size="small"
                      value={baseNetwork}
                      onChange={(e) => setBaseNetwork(e.target.value)}
                      sx={{ "& input": { fontFamily: "monospace" } }}
                    />
                  </Grid>
                  <Grid item xs={5}>
                    <Typography variant="caption" color="text.secondary">CIDR</Typography>
                    <TextField
                      fullWidth
                      size="small"
                      type="number"
                      value={baseCIDR}
                      onChange={(e) => setBaseCIDR(Math.max(8, Math.min(24, Number(e.target.value))))}
                      InputProps={{ startAdornment: <Typography sx={{ mr: 0.5 }}>/</Typography> }}
                      sx={{ "& input": { fontFamily: "monospace" } }}
                    />
                  </Grid>
                </Grid>
                <Alert severity="info" sx={{ mt: 2 }}>
                  <Typography variant="caption">Available: {totalAvailable.toLocaleString()} addresses</Typography>
                </Alert>
              </Paper>

              <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2 }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>🏢 Subnet Requirements</Typography>
                  <Button size="small" onClick={addSubnet} startIcon={<CheckCircleIcon />}>Add</Button>
                </Box>

                <Box sx={{ maxHeight: 350, overflow: "auto" }}>
                  {subnets.map((subnet, idx) => (
                    <Paper key={subnet.id} sx={{ p: 2, mb: 1.5, borderLeft: `4px solid ${subnet.color}`, bgcolor: alpha(subnet.color, 0.03) }}>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                        <TextField
                          size="small"
                          value={subnet.name}
                          onChange={(e) => updateSubnet(subnet.id, "name", e.target.value)}
                          variant="standard"
                          sx={{ fontWeight: 700, "& input": { fontWeight: 700, color: subnet.color } }}
                        />
                        <IconButton size="small" onClick={() => removeSubnet(subnet.id)} sx={{ color: "#ef4444" }}>
                          <CancelIcon fontSize="small" />
                        </IconButton>
                      </Box>
                      <Grid container spacing={1}>
                        <Grid item xs={4}>
                          <Typography variant="caption" color="text.secondary">Hosts</Typography>
                          <TextField
                            fullWidth
                            size="small"
                            type="number"
                            value={subnet.currentHosts}
                            onChange={(e) => updateSubnet(subnet.id, "currentHosts", Number(e.target.value))}
                          />
                        </Grid>
                        <Grid item xs={4}>
                          <Typography variant="caption" color="text.secondary">Growth %</Typography>
                          <TextField
                            fullWidth
                            size="small"
                            type="number"
                            value={subnet.growthRate}
                            onChange={(e) => updateSubnet(subnet.id, "growthRate", Number(e.target.value))}
                          />
                        </Grid>
                        <Grid item xs={4}>
                          <Typography variant="caption" color="text.secondary">Years</Typography>
                          <TextField
                            fullWidth
                            size="small"
                            type="number"
                            value={subnet.years}
                            onChange={(e) => updateSubnet(subnet.id, "years", Number(e.target.value))}
                          />
                        </Grid>
                      </Grid>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                        → Future: {calculateFutureHosts(subnet.currentHosts, subnet.growthRate, subnet.years)} hosts
                      </Typography>
                    </Paper>
                  ))}
                </Box>
              </Paper>
            </Grid>

            <Grid item xs={12} md={7}>
              {/* Visual Network Diagram */}
              <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>📈 Address Space Allocation</Typography>

                {/* Visual bar */}
                <Box sx={{ mb: 3, borderRadius: 2, overflow: "hidden", border: "1px solid", borderColor: "divider" }}>
                  <Box sx={{ display: "flex", height: 40 }}>
                    {multiResults.map((r, idx) => (
                      <Tooltip key={idx} title={`${r.name}: ${r.networkAddress}/${r.cidr} (${r.total} IPs)`}>
                        <Box
                          sx={{
                            width: `${(r.total / totalAvailable) * 100}%`,
                            bgcolor: r.color,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            color: "white",
                            fontSize: "0.7rem",
                            fontWeight: 700,
                            cursor: "pointer",
                            "&:hover": { opacity: 0.8 },
                            minWidth: r.total / totalAvailable > 0.05 ? "auto" : 0,
                            overflow: "hidden",
                          }}
                        >
                          {r.total / totalAvailable > 0.08 && r.name}
                        </Box>
                      </Tooltip>
                    ))}
                    <Box sx={{ flex: 1, bgcolor: alpha("#888", 0.1), display: "flex", alignItems: "center", justifyContent: "center" }}>
                      <Typography variant="caption" color="text.secondary">Unallocated</Typography>
                    </Box>
                  </Box>
                </Box>

                {/* Stats */}
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={4}>
                    <Typography variant="caption" color="text.secondary">Total Allocated</Typography>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{totalAddressesUsed.toLocaleString()}</Typography>
                  </Grid>
                  <Grid item xs={4}>
                    <Typography variant="caption" color="text.secondary">Remaining</Typography>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>{(totalAvailable - totalAddressesUsed).toLocaleString()}</Typography>
                  </Grid>
                  <Grid item xs={4}>
                    <Typography variant="caption" color="text.secondary">Utilization</Typography>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: overallEfficiency > 80 ? "#f59e0b" : "#22c55e" }}>{overallEfficiency.toFixed(1)}%</Typography>
                  </Grid>
                </Grid>

                {/* Legend */}
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                  {multiResults.map((r, idx) => (
                    <Chip
                      key={idx}
                      size="small"
                      label={`${r.name} (/${r.cidr})`}
                      sx={{ bgcolor: alpha(r.color, 0.2), color: r.color, fontWeight: 600, fontSize: "0.7rem" }}
                    />
                  ))}
                </Box>
              </Paper>

              {/* Detailed Results Table */}
              <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>📋 Subnet Allocation Details</Typography>
                <TableContainer sx={{ maxHeight: 300 }}>
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 700 }}>Subnet</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>CIDR</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Network</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Range</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Hosts</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Util.</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {multiResults.map((r, idx) => (
                        <TableRow key={idx}>
                          <TableCell>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <Box sx={{ width: 12, height: 12, borderRadius: 1, bgcolor: r.color }} />
                              <Typography variant="body2" sx={{ fontWeight: 600 }}>{r.name}</Typography>
                            </Box>
                          </TableCell>
                          <TableCell sx={{ fontFamily: "monospace", fontWeight: 700, color: "#22c55e" }}>/{r.cidr}</TableCell>
                          <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{r.networkAddress}</TableCell>
                          <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>{r.firstHost} - {r.lastHost}</TableCell>
                          <TableCell>
                            <Typography variant="caption">{r.futureHosts}/{r.usable}</Typography>
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                              <LinearProgress
                                variant="determinate"
                                value={r.efficiency}
                                sx={{ width: 40, height: 6, borderRadius: 1, bgcolor: alpha(r.color, 0.2), "& .MuiLinearProgress-bar": { bgcolor: r.color } }}
                              />
                              <Typography variant="caption">{r.efficiency.toFixed(0)}%</Typography>
                            </Box>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>
        </>
      )}
    </Paper>
  );
};

// ========== BANDWIDTH CALCULATOR ==========
const BandwidthCalculator: React.FC<{ theme: any; alpha: any }> = ({ theme, alpha }) => {
  const [mode, setMode] = useState<"transfer" | "convert">("transfer");
  const [fileSize, setFileSize] = useState(1);
  const [fileSizeUnit, setFileSizeUnit] = useState<"MB" | "GB" | "TB">("GB");
  const [bandwidth, setBandwidth] = useState(100);
  const [bandwidthUnit, setBandwidthUnit] = useState<"Mbps" | "Gbps">("Mbps");
  const [convertValue, setConvertValue] = useState(100);
  const [convertFrom, setConvertFrom] = useState("Mbps");

  const calculateTransferTime = () => {
    const sizeInBits = fileSize * (fileSizeUnit === "MB" ? 8388608 : fileSizeUnit === "GB" ? 8589934592 : 8796093022208);
    const bwInBps = bandwidth * (bandwidthUnit === "Mbps" ? 1000000 : 1000000000);
    const seconds = sizeInBits / bwInBps;

    if (seconds < 60) return `${seconds.toFixed(2)} seconds`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(2)} minutes`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(2)} hours`;
    return `${(seconds / 86400).toFixed(2)} days`;
  };

  const conversions = {
    "bps": 1,
    "Kbps": 1000,
    "Mbps": 1000000,
    "Gbps": 1000000000,
    "B/s": 8,
    "KB/s": 8000,
    "MB/s": 8000000,
    "GB/s": 8000000000,
  };

  const convertSpeed = () => {
    const bps = convertValue * (conversions[convertFrom as keyof typeof conversions] || 1);
    return Object.entries(conversions).map(([unit, factor]) => ({
      unit,
      value: bps / factor,
    })).filter(c => c.value >= 0.001 && c.value < 10000000);
  };

  return (
    <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#f59e0b", 0.03), border: `2px solid ${alpha("#f59e0b", 0.2)}` }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <SpeedIcon sx={{ fontSize: 36, color: "#f59e0b" }} />
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800, color: "#f59e0b" }}>Bandwidth Calculator</Typography>
          <Typography variant="body2" color="text.secondary">Calculate transfer times and convert between speed units</Typography>
        </Box>
      </Box>

      <ToggleButtonGroup
        value={mode}
        exclusive
        onChange={(_, v) => v && setMode(v)}
        sx={{ mb: 3 }}
        size="small"
      >
        <ToggleButton value="transfer">Transfer Time</ToggleButton>
        <ToggleButton value="convert">Unit Converter</ToggleButton>
      </ToggleButtonGroup>

      {mode === "transfer" ? (
        <Grid container spacing={3} alignItems="center">
          <Grid item xs={12} md={5}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>File Size:</Typography>
            <Box sx={{ display: "flex", gap: 1 }}>
              <TextField
                type="number"
                size="small"
                value={fileSize}
                onChange={(e) => setFileSize(Number(e.target.value))}
                sx={{ flex: 1 }}
              />
              <ToggleButtonGroup
                value={fileSizeUnit}
                exclusive
                onChange={(_, v) => v && setFileSizeUnit(v)}
                size="small"
              >
                <ToggleButton value="MB">MB</ToggleButton>
                <ToggleButton value="GB">GB</ToggleButton>
                <ToggleButton value="TB">TB</ToggleButton>
              </ToggleButtonGroup>
            </Box>
          </Grid>
          <Grid item xs={12} md={5}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Connection Speed:</Typography>
            <Box sx={{ display: "flex", gap: 1 }}>
              <TextField
                type="number"
                size="small"
                value={bandwidth}
                onChange={(e) => setBandwidth(Number(e.target.value))}
                sx={{ flex: 1 }}
              />
              <ToggleButtonGroup
                value={bandwidthUnit}
                exclusive
                onChange={(_, v) => v && setBandwidthUnit(v)}
                size="small"
              >
                <ToggleButton value="Mbps">Mbps</ToggleButton>
                <ToggleButton value="Gbps">Gbps</ToggleButton>
              </ToggleButtonGroup>
            </Box>
          </Grid>
          <Grid item xs={12} md={2}>
            <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2, textAlign: "center" }}>
              <Typography variant="caption" color="text.secondary">Transfer Time</Typography>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>{calculateTransferTime()}</Typography>
            </Paper>
          </Grid>
        </Grid>
      ) : (
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Enter Speed:</Typography>
            <Box sx={{ display: "flex", gap: 1 }}>
              <TextField
                type="number"
                size="small"
                value={convertValue}
                onChange={(e) => setConvertValue(Number(e.target.value))}
                sx={{ flex: 1 }}
              />
              <TextField
                select
                size="small"
                value={convertFrom}
                onChange={(e) => setConvertFrom(e.target.value)}
                sx={{ width: 100 }}
                SelectProps={{ native: true }}
              >
                {Object.keys(conversions).map((u) => <option key={u} value={u}>{u}</option>)}
              </TextField>
            </Box>
          </Grid>
          <Grid item xs={12} md={8}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Conversions:</Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              {convertSpeed().map((c) => (
                <Chip
                  key={c.unit}
                  label={`${c.value < 1 ? c.value.toFixed(4) : c.value < 100 ? c.value.toFixed(2) : c.value.toFixed(0)} ${c.unit}`}
                  sx={{ fontFamily: "monospace", bgcolor: alpha("#f59e0b", 0.1) }}
                />
              ))}
            </Box>
          </Grid>
        </Grid>
      )}

      <Box sx={{ mt: 3, display: "flex", gap: 1, flexWrap: "wrap" }}>
        <Typography variant="caption" color="text.secondary">Quick presets:</Typography>
        {[
          { label: "Home Fiber", bw: 1000, unit: "Mbps" as const },
          { label: "5G Mobile", bw: 100, unit: "Mbps" as const },
          { label: "10G Enterprise", bw: 10, unit: "Gbps" as const },
          { label: "USB 3.0", bw: 5, unit: "Gbps" as const },
        ].map((p) => (
          <Chip
            key={p.label}
            label={p.label}
            size="small"
            clickable
            onClick={() => { setBandwidth(p.bw); setBandwidthUnit(p.unit); }}
          />
        ))}
      </Box>
    </Paper>
  );
};

// ========== IP RANGE CHECKER ==========
const IPRangeChecker: React.FC<{ theme: any; alpha: any; ipToNumber: (ip: string) => number; numberToIP: (num: number) => string }> = ({ theme, alpha }) => {
  const [ip1, setIP1] = useState("192.168.1.50");
  const [ip2, setIP2] = useState("192.168.1.150");
  const [cidr, setCIDR] = useState(24);
  const [results, setResults] = useState<{
    sameSubnet: boolean;
    network1: string;
    network2: string;
    distance: number;
  } | null>(null);

  const checkIPs = () => {
    const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    if (!ipRegex.test(ip1) || !ipRegex.test(ip2)) {
      setResults(null);
      return;
    }

    const ip1Num = ipToNum(ip1);
    const ip2Num = ipToNum(ip2);
    const maskNum = cidr === 0 ? 0 : (0xFFFFFFFF << (32 - cidr)) >>> 0;
    const network1 = (ip1Num & maskNum) >>> 0;
    const network2 = (ip2Num & maskNum) >>> 0;

    setResults({
      sameSubnet: network1 === network2,
      network1: numToIP(network1),
      network2: numToIP(network2),
      distance: Math.abs(ip1Num - ip2Num),
    });
  };

  React.useEffect(() => {
    checkIPs();
  }, [ip1, ip2, cidr]);

  return (
    <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#8b5cf6", 0.03), border: `2px solid ${alpha("#8b5cf6", 0.2)}` }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <SyncAltIcon sx={{ fontSize: 36, color: "#8b5cf6" }} />
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800, color: "#8b5cf6" }}>IP Range Checker</Typography>
          <Typography variant="body2" color="text.secondary">Check if two IP addresses are in the same subnet</Typography>
        </Box>
      </Box>

      <Grid container spacing={3} alignItems="center">
        <Grid item xs={12} md={3}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>First IP:</Typography>
          <TextField
            fullWidth
            size="small"
            value={ip1}
            onChange={(e) => setIP1(e.target.value)}
            sx={{ "& input": { fontFamily: "monospace" } }}
          />
        </Grid>
        <Grid item xs={12} md={3}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Second IP:</Typography>
          <TextField
            fullWidth
            size="small"
            value={ip2}
            onChange={(e) => setIP2(e.target.value)}
            sx={{ "& input": { fontFamily: "monospace" } }}
          />
        </Grid>
        <Grid item xs={12} md={3}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Subnet: /{cidr}</Typography>
          <Slider
            value={cidr}
            onChange={(_, v) => setCIDR(v as number)}
            min={0}
            max={32}
            sx={{ color: "#8b5cf6" }}
          />
        </Grid>
        <Grid item xs={12} md={3}>
          {results && (
            <Paper sx={{ p: 2, bgcolor: results.sameSubnet ? alpha("#22c55e", 0.1) : alpha("#ef4444", 0.1), borderRadius: 2, textAlign: "center" }}>
              {results.sameSubnet ? (
                <>
                  <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 32 }} />
                  <Typography variant="body1" sx={{ fontWeight: 700, color: "#22c55e" }}>Same Subnet!</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace" }}>{results.network1}/{cidr}</Typography>
                </>
              ) : (
                <>
                  <CancelIcon sx={{ color: "#ef4444", fontSize: 32 }} />
                  <Typography variant="body1" sx={{ fontWeight: 700, color: "#ef4444" }}>Different Subnets</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block" }}>{results.network1} vs {results.network2}</Typography>
                </>
              )}
            </Paper>
          )}
        </Grid>
      </Grid>
    </Paper>
  );
};

// ========== SUBNET PRACTICE QUIZ ==========
const SubnetPracticeQuiz: React.FC<{ theme: any; alpha: any }> = ({ theme, alpha }) => {
  const [question, setQuestion] = useState<{
    type: string;
    question: string;
    answer: string;
    options?: string[];
    ip?: string;
    cidr?: number;
  } | null>(null);
  const [userAnswer, setUserAnswer] = useState("");
  const [showAnswer, setShowAnswer] = useState(false);
  const [score, setScore] = useState({ correct: 0, total: 0 });

  const generateQuestion = () => {
    const types = ["network", "broadcast", "hosts", "mask", "cidr"];
    const type = types[Math.floor(Math.random() * types.length)];
    const octet3 = Math.floor(Math.random() * 256);
    const octet4 = Math.floor(Math.random() * 256);
    const cidr = Math.floor(Math.random() * 9) + 24; // /24 to /32
    const ip = `192.168.${octet3}.${octet4}`;

    const ipNum = ipToNum(ip);
    const maskNum = (0xFFFFFFFF << (32 - cidr)) >>> 0;
    const networkNum = (ipNum & maskNum) >>> 0;
    const broadcastNum = (networkNum | (~maskNum >>> 0)) >>> 0;
    const hostBits = 32 - cidr;
    const usableHosts = hostBits <= 1 ? Math.pow(2, hostBits) : Math.pow(2, hostBits) - 2;

    let q: typeof question = { type, question: "", answer: "", ip, cidr };

    switch (type) {
      case "network":
        q.question = `What is the network address for ${ip}/${cidr}?`;
        q.answer = numToIP(networkNum);
        break;
      case "broadcast":
        q.question = `What is the broadcast address for ${ip}/${cidr}?`;
        q.answer = numToIP(broadcastNum);
        break;
      case "hosts":
        q.question = `How many usable hosts are in a /${cidr} network?`;
        q.answer = usableHosts.toString();
        break;
      case "mask":
        q.question = `What is the subnet mask for /${cidr}?`;
        q.answer = numToIP(maskNum);
        break;
      case "cidr":
        const maskStr = numToIP(maskNum);
        q.question = `What is the CIDR notation for subnet mask ${maskStr}?`;
        q.answer = `/${cidr}`;
        break;
    }

    setQuestion(q);
    setUserAnswer("");
    setShowAnswer(false);
  };

  const checkAnswer = () => {
    if (!question) return;
    const isCorrect = userAnswer.trim().toLowerCase().replace(/^\//, "") === question.answer.toLowerCase().replace(/^\//, "");
    setScore({ correct: score.correct + (isCorrect ? 1 : 0), total: score.total + 1 });
    setShowAnswer(true);
  };

  React.useEffect(() => {
    generateQuestion();
  }, []);

  return (
    <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#ec4899", 0.08)} 0%, ${alpha("#f59e0b", 0.08)} 100%)`, border: `2px solid ${alpha("#ec4899", 0.3)}` }}>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          <SchoolIcon sx={{ fontSize: 36, color: "#ec4899" }} />
          <Box>
            <Typography variant="h5" sx={{ fontWeight: 800, color: "#ec4899" }}>Subnet Practice Quiz</Typography>
            <Typography variant="body2" color="text.secondary">Random subnetting questions to test your skills</Typography>
          </Box>
        </Box>
        <Chip
          icon={<EmojiEventsIcon />}
          label={`Score: ${score.correct}/${score.total}`}
          sx={{ bgcolor: alpha("#ec4899", 0.1), color: "#ec4899", fontWeight: 700 }}
        />
      </Box>

      {question && (
        <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, mb: 3 }}>{question.question}</Typography>

          <Box sx={{ display: "flex", gap: 2, alignItems: "center", mb: 2 }}>
            <TextField
              fullWidth
              size="small"
              value={userAnswer}
              onChange={(e) => setUserAnswer(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && !showAnswer && checkAnswer()}
              placeholder="Your answer..."
              disabled={showAnswer}
              sx={{ "& input": { fontFamily: "monospace", fontSize: "1.1rem" } }}
            />
            {!showAnswer ? (
              <Button variant="contained" onClick={checkAnswer} sx={{ bgcolor: "#ec4899", "&:hover": { bgcolor: "#db2777" } }}>
                Check
              </Button>
            ) : (
              <Button variant="contained" onClick={generateQuestion} startIcon={<RefreshIcon />}>
                Next
              </Button>
            )}
          </Box>

          {showAnswer && (
            <Alert severity={userAnswer.trim().toLowerCase().replace(/^\//, "") === question.answer.toLowerCase().replace(/^\//, "") ? "success" : "error"}>
              <Typography variant="body1">
                {userAnswer.trim().toLowerCase().replace(/^\//, "") === question.answer.toLowerCase().replace(/^\//, "") ? "Correct! " : "Incorrect. "}
                The answer is: <strong style={{ fontFamily: "monospace" }}>{question.answer}</strong>
              </Typography>
            </Alert>
          )}
        </Paper>
      )}
    </Paper>
  );
};

// ========== MAC ADDRESS ANALYZER ==========
const MACAddressAnalyzer: React.FC<{ theme: any; alpha: any }> = ({ theme, alpha }) => {
  const [mac, setMAC] = useState("00:1A:2B:3C:4D:5E");
  const [results, setResults] = useState<{
    normalized: string;
    binary: string;
    oui: string;
    isUnicast: boolean;
    isLocal: boolean;
  } | null>(null);

  // Common OUI prefixes (sample - in production would be a larger database)
  const ouiDatabase: Record<string, string> = {
    "00:1A:2B": "Ayecom Technology",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "00:00:00": "Unknown/Xerox",
    "FF:FF:FF": "Broadcast",
    "00:1A:A0": "Dell",
    "00:25:00": "Apple",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "00:1B:63": "Apple",
    "D4:F4:6F": "Apple",
  };

  const analyzeMAC = (input: string) => {
    // Normalize MAC address (remove separators, uppercase)
    const cleaned = input.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
    if (cleaned.length !== 12) {
      setResults(null);
      return;
    }

    const normalized = cleaned.match(/.{2}/g)?.join(":") || "";
    const binary = cleaned.split("").map(c => parseInt(c, 16).toString(2).padStart(4, "0")).join(" ");
    const oui = normalized.substring(0, 8);
    const firstByte = parseInt(cleaned.substring(0, 2), 16);
    const isUnicast = (firstByte & 1) === 0;
    const isLocal = (firstByte & 2) !== 0;

    setResults({
      normalized,
      binary,
      oui,
      isUnicast,
      isLocal,
    });
  };

  React.useEffect(() => {
    analyzeMAC(mac);
  }, [mac]);

  return (
    <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#0ea5e9", 0.03), border: `2px solid ${alpha("#0ea5e9", 0.2)}` }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <CableIcon sx={{ fontSize: 36, color: "#0ea5e9" }} />
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800, color: "#0ea5e9" }}>MAC Address Analyzer</Typography>
          <Typography variant="body2" color="text.secondary">Parse and analyze MAC addresses, identify vendor OUI</Typography>
        </Box>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={5}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Enter MAC Address:</Typography>
          <TextField
            fullWidth
            size="small"
            value={mac}
            onChange={(e) => setMAC(e.target.value)}
            placeholder="00:1A:2B:3C:4D:5E or 001A2B3C4D5E"
            sx={{ mb: 2, "& input": { fontFamily: "monospace", textTransform: "uppercase" } }}
          />
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            {["00:50:56:12:34:56", "08:00:27:AB:CD:EF", "00:1B:63:00:00:00", "FF:FF:FF:FF:FF:FF"].map((sample) => (
              <Chip
                key={sample}
                label={sample.substring(0, 8) + "..."}
                size="small"
                clickable
                onClick={() => setMAC(sample)}
                sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}
              />
            ))}
          </Box>
        </Grid>
        <Grid item xs={12} md={7}>
          {results && (
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Normalized Format</Typography>
                  <Typography variant="h6" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#0ea5e9" }}>{results.normalized}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">OUI (Vendor)</Typography>
                  <Typography variant="body1" sx={{ fontFamily: "monospace" }}>{results.oui}</Typography>
                  <Typography variant="body2" color="text.secondary">{ouiDatabase[results.oui] || "Unknown vendor"}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Address Type</Typography>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 0.5 }}>
                    <Chip label={results.isUnicast ? "Unicast" : "Multicast"} size="small" color={results.isUnicast ? "success" : "warning"} />
                    <Chip label={results.isLocal ? "Local" : "Universal"} size="small" variant="outlined" />
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Binary Representation</Typography>
                  <Typography sx={{ fontFamily: "monospace", fontSize: "0.7rem", wordBreak: "break-all" }}>{results.binary}</Typography>
                </Grid>
              </Grid>
            </Paper>
          )}
        </Grid>
      </Grid>
    </Paper>
  );
};

// ========== IPv6 TOOLS ==========
const IPv6Tools: React.FC<{ theme: any; alpha: any }> = ({ theme, alpha }) => {
  const [ipv6Input, setIPv6Input] = useState("2001:0db8:0000:0000:0000:0000:0000:0001");
  const [results, setResults] = useState<{
    full: string;
    compressed: string;
    type: string;
    scope: string;
  } | null>(null);

  const expandIPv6 = (ip: string): string => {
    // Handle :: expansion
    let expanded = ip;
    if (ip.includes("::")) {
      const parts = ip.split("::");
      const left = parts[0] ? parts[0].split(":") : [];
      const right = parts[1] ? parts[1].split(":") : [];
      const missing = 8 - left.length - right.length;
      const middle = Array(missing).fill("0000");
      expanded = [...left, ...middle, ...right].join(":");
    }

    // Pad each group
    return expanded.split(":").map(g => g.padStart(4, "0")).join(":");
  };

  const compressIPv6 = (ip: string): string => {
    const full = expandIPv6(ip);
    let groups = full.split(":").map(g => g.replace(/^0+/, "") || "0");

    // Find longest run of zeros
    let longestStart = -1, longestLen = 0, currentStart = -1, currentLen = 0;
    groups.forEach((g, i) => {
      if (g === "0") {
        if (currentStart === -1) currentStart = i;
        currentLen++;
        if (currentLen > longestLen) {
          longestStart = currentStart;
          longestLen = currentLen;
        }
      } else {
        currentStart = -1;
        currentLen = 0;
      }
    });

    if (longestLen > 1) {
      const before = groups.slice(0, longestStart);
      const after = groups.slice(longestStart + longestLen);
      return before.join(":") + "::" + after.join(":");
    }

    return groups.join(":");
  };

  const getIPv6Type = (ip: string): { type: string; scope: string } => {
    const full = expandIPv6(ip).toLowerCase();
    if (full === "0000:0000:0000:0000:0000:0000:0000:0001") return { type: "Loopback", scope: "Host" };
    if (full === "0000:0000:0000:0000:0000:0000:0000:0000") return { type: "Unspecified", scope: "N/A" };
    if (full.startsWith("fe80")) return { type: "Link-Local", scope: "Link" };
    if (full.startsWith("fc") || full.startsWith("fd")) return { type: "Unique Local", scope: "Organization" };
    if (full.startsWith("ff")) return { type: "Multicast", scope: "Varies" };
    if (full.startsWith("2") || full.startsWith("3")) return { type: "Global Unicast", scope: "Internet" };
    return { type: "Unknown", scope: "Unknown" };
  };

  const analyzeIPv6 = () => {
    try {
      const full = expandIPv6(ipv6Input);
      const compressed = compressIPv6(ipv6Input);
      const { type, scope } = getIPv6Type(ipv6Input);
      setResults({ full, compressed, type, scope });
    } catch {
      setResults(null);
    }
  };

  React.useEffect(() => {
    analyzeIPv6();
  }, [ipv6Input]);

  return (
    <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#a855f7", 0.03), border: `2px solid ${alpha("#a855f7", 0.2)}` }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <PublicIcon sx={{ fontSize: 36, color: "#a855f7" }} />
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800, color: "#a855f7" }}>IPv6 Tools</Typography>
          <Typography variant="body2" color="text.secondary">Expand, compress, and analyze IPv6 addresses</Typography>
        </Box>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Enter IPv6 Address:</Typography>
          <TextField
            fullWidth
            size="small"
            value={ipv6Input}
            onChange={(e) => setIPv6Input(e.target.value)}
            placeholder="2001:db8::1 or full form"
            sx={{ mb: 2, "& input": { fontFamily: "monospace" } }}
          />
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            {["::1", "fe80::1", "2001:db8::1", "ff02::1"].map((sample) => (
              <Chip key={sample} label={sample} size="small" clickable onClick={() => setIPv6Input(sample)} sx={{ fontFamily: "monospace" }} />
            ))}
          </Box>
        </Grid>
        <Grid item xs={12} md={6}>
          {results && (
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
              <Typography variant="caption" color="text.secondary">Full (Expanded) Form</Typography>
              <Typography sx={{ fontFamily: "monospace", fontSize: "0.8rem", mb: 1, wordBreak: "break-all" }}>{results.full}</Typography>

              <Typography variant="caption" color="text.secondary">Compressed Form</Typography>
              <Typography sx={{ fontFamily: "monospace", fontSize: "1rem", fontWeight: 700, color: "#a855f7", mb: 1 }}>{results.compressed}</Typography>

              <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
                <Chip label={results.type} size="small" sx={{ bgcolor: alpha("#a855f7", 0.1), color: "#a855f7" }} />
                <Chip label={`Scope: ${results.scope}`} size="small" variant="outlined" />
              </Box>
            </Paper>
          )}
        </Grid>
      </Grid>
    </Paper>
  );
};

// ========== LATENCY CALCULATOR ==========
const LatencyCalculator: React.FC<{ theme: any; alpha: any }> = ({ theme, alpha }) => {
  const [distance, setDistance] = useState(1000);
  const [medium, setMedium] = useState<"fiber" | "copper" | "satellite">("fiber");
  const [hops, setHops] = useState(10);

  const speedOfLight = 299792; // km/s in vacuum
  const refractionIndex = { fiber: 1.5, copper: 1.0, satellite: 1.0 };
  const hopLatency = 0.5; // ms per hop (processing + queuing)

  const calculateLatency = () => {
    const speed = speedOfLight / refractionIndex[medium];
    let totalDistance = distance;

    // Satellite goes up and down (geostationary at ~35,786 km)
    if (medium === "satellite") {
      totalDistance = 35786 * 2 + distance; // Up, satellite, down
    }

    const propagation = (totalDistance / speed) * 1000; // Convert to ms
    const processing = hops * hopLatency;
    const rtt = (propagation + processing) * 2; // Round trip

    return {
      propagation: propagation.toFixed(2),
      processing: processing.toFixed(2),
      oneWay: (propagation + processing).toFixed(2),
      rtt: rtt.toFixed(2),
    };
  };

  const results = calculateLatency();

  return (
    <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#ef4444", 0.03), border: `2px solid ${alpha("#ef4444", 0.2)}` }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <NetworkCheckIcon sx={{ fontSize: 36, color: "#ef4444" }} />
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800, color: "#ef4444" }}>Latency Calculator</Typography>
          <Typography variant="body2" color="text.secondary">Estimate network latency based on distance and medium</Typography>
        </Box>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Distance (km): {distance.toLocaleString()}</Typography>
          <Slider
            value={distance}
            onChange={(_, v) => setDistance(v as number)}
            min={10}
            max={20000}
            step={10}
            sx={{ color: "#ef4444" }}
          />
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 1 }}>
            {[
              { label: "Local", km: 10 },
              { label: "City", km: 100 },
              { label: "Cross-country", km: 4000 },
              { label: "Intercontinental", km: 10000 },
            ].map((p) => (
              <Chip key={p.label} label={p.label} size="small" clickable onClick={() => setDistance(p.km)} />
            ))}
          </Box>
        </Grid>
        <Grid item xs={12} md={4}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Transmission Medium:</Typography>
          <ToggleButtonGroup
            value={medium}
            exclusive
            onChange={(_, v) => v && setMedium(v)}
            size="small"
            fullWidth
          >
            <ToggleButton value="fiber">Fiber Optic</ToggleButton>
            <ToggleButton value="copper">Copper</ToggleButton>
            <ToggleButton value="satellite">Satellite</ToggleButton>
          </ToggleButtonGroup>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, mt: 2 }}>Network Hops: {hops}</Typography>
          <Slider value={hops} onChange={(_, v) => setHops(v as number)} min={1} max={30} sx={{ color: "#ef4444" }} />
        </Grid>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
            <Grid container spacing={1}>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">Propagation</Typography>
                <Typography variant="body1" sx={{ fontWeight: 600 }}>{results.propagation} ms</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">Processing</Typography>
                <Typography variant="body1" sx={{ fontWeight: 600 }}>{results.processing} ms</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">One-Way</Typography>
                <Typography variant="body1" sx={{ fontWeight: 600 }}>{results.oneWay} ms</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">Round Trip (RTT)</Typography>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#ef4444" }}>{results.rtt} ms</Typography>
              </Grid>
            </Grid>
            {medium === "satellite" && (
              <Alert severity="info" sx={{ mt: 2 }}>
                <Typography variant="caption">Satellite adds ~600ms due to geostationary orbit distance</Typography>
              </Alert>
            )}
          </Paper>
        </Grid>
      </Grid>
    </Paper>
  );
};

const ComputerNetworkingPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const accent = "#3b82f6"; // Blue accent color for Computer Networking
  const isMobile = useMediaQuery(theme.breakpoints.down("lg"));

  // Navigation State
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("");

  // Binary Calculator State
  const [calcInput, setCalcInput] = useState("");
  const [calcInputType, setCalcInputType] = useState<"decimal" | "binary" | "hex" | "octal">("decimal");
  const [calcResults, setCalcResults] = useState<{
    decimal: string;
    binary: string;
    hex: string;
    octal: string;
    binaryGrouped: string;
  } | null>(null);
  const [calcError, setCalcError] = useState("");

  // Conversion functions
  const convertNumber = useCallback((input: string, inputType: string) => {
    setCalcError("");
    if (!input.trim()) {
      setCalcResults(null);
      return;
    }

    try {
      let decimalValue: number;

      switch (inputType) {
        case "decimal":
          if (!/^\d+$/.test(input)) throw new Error("Invalid decimal number");
          decimalValue = parseInt(input, 10);
          break;
        case "binary":
          if (!/^[01]+$/.test(input)) throw new Error("Invalid binary number (only 0 and 1)");
          decimalValue = parseInt(input, 2);
          break;
        case "hex":
          if (!/^[0-9a-fA-F]+$/.test(input)) throw new Error("Invalid hexadecimal (0-9, A-F)");
          decimalValue = parseInt(input, 16);
          break;
        case "octal":
          if (!/^[0-7]+$/.test(input)) throw new Error("Invalid octal number (0-7)");
          decimalValue = parseInt(input, 8);
          break;
        default:
          throw new Error("Unknown input type");
      }

      if (isNaN(decimalValue) || decimalValue < 0) {
        throw new Error("Invalid number");
      }

      const binary = decimalValue.toString(2);
      const binaryPadded = binary.padStart(Math.ceil(binary.length / 8) * 8, "0");
      const binaryGrouped = binaryPadded.match(/.{1,8}/g)?.join(" ") || binary;

      setCalcResults({
        decimal: decimalValue.toString(),
        binary: binary,
        hex: decimalValue.toString(16).toUpperCase(),
        octal: decimalValue.toString(8),
        binaryGrouped: binaryGrouped,
      });
    } catch (err) {
      setCalcError(err instanceof Error ? err.message : "Conversion error");
      setCalcResults(null);
    }
  }, []);

  const handleCalcInputChange = (value: string) => {
    setCalcInput(value);
    convertNumber(value, calcInputType);
  };

  const handleCalcTypeChange = (newType: "decimal" | "binary" | "hex" | "octal") => {
    setCalcInputType(newType);
    setCalcInput("");
    setCalcResults(null);
    setCalcError("");
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  // ========== SUBNET CALCULATOR STATE ==========
  const [subnetIP, setSubnetIP] = useState("192.168.1.100");
  const [subnetCIDR, setSubnetCIDR] = useState(24);
  const [subnetResults, setSubnetResults] = useState<{
    networkAddress: string;
    broadcastAddress: string;
    firstHost: string;
    lastHost: string;
    subnetMask: string;
    wildcardMask: string;
    totalHosts: number;
    usableHosts: number;
    binaryMask: string;
    binaryIP: string;
    binaryNetwork: string;
    ipClass: string;
    isPrivate: boolean;
    networkBits: number;
    hostBits: number;
  } | null>(null);
  const [subnetError, setSubnetError] = useState("");

  // Subnet Calculator Functions
  const ipToNumber = useCallback((ip: string): number => {
    const parts = ip.split(".").map(Number);
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  }, []);

  const numberToIP = useCallback((num: number): string => {
    return [
      (num >>> 24) & 255,
      (num >>> 16) & 255,
      (num >>> 8) & 255,
      num & 255
    ].join(".");
  }, []);

  const numberToBinary = useCallback((num: number): string => {
    return [
      ((num >>> 24) & 255).toString(2).padStart(8, "0"),
      ((num >>> 16) & 255).toString(2).padStart(8, "0"),
      ((num >>> 8) & 255).toString(2).padStart(8, "0"),
      (num & 255).toString(2).padStart(8, "0")
    ].join(".");
  }, []);

  const calculateSubnet = useCallback((ip: string, cidr: number) => {
    setSubnetError("");
    
    // Validate IP
    const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = ip.match(ipRegex);
    if (!match) {
      setSubnetError("Invalid IP address format");
      setSubnetResults(null);
      return;
    }
    
    const octets = [parseInt(match[1]), parseInt(match[2]), parseInt(match[3]), parseInt(match[4])];
    if (octets.some(o => o < 0 || o > 255)) {
      setSubnetError("IP octets must be 0-255");
      setSubnetResults(null);
      return;
    }

    if (cidr < 0 || cidr > 32) {
      setSubnetError("CIDR must be 0-32");
      setSubnetResults(null);
      return;
    }

    try {
      const ipNum = ipToNumber(ip);
      const hostBits = 32 - cidr;
      const maskNum = cidr === 0 ? 0 : (0xFFFFFFFF << hostBits) >>> 0;
      const networkNum = (ipNum & maskNum) >>> 0;
      const broadcastNum = (networkNum | (~maskNum >>> 0)) >>> 0;
      
      const totalHosts = Math.pow(2, hostBits);
      const usableHosts = hostBits <= 1 ? totalHosts : totalHosts - 2;
      
      // Determine IP class
      let ipClass = "Classless";
      if (octets[0] >= 1 && octets[0] <= 126) ipClass = "A";
      else if (octets[0] >= 128 && octets[0] <= 191) ipClass = "B";
      else if (octets[0] >= 192 && octets[0] <= 223) ipClass = "C";
      else if (octets[0] >= 224 && octets[0] <= 239) ipClass = "D (Multicast)";
      else if (octets[0] >= 240 && octets[0] <= 255) ipClass = "E (Reserved)";
      
      // Check if private
      const isPrivate = 
        (octets[0] === 10) ||
        (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
        (octets[0] === 192 && octets[1] === 168) ||
        (octets[0] === 127);

      setSubnetResults({
        networkAddress: numberToIP(networkNum),
        broadcastAddress: numberToIP(broadcastNum),
        firstHost: hostBits <= 1 ? numberToIP(networkNum) : numberToIP(networkNum + 1),
        lastHost: hostBits <= 1 ? numberToIP(broadcastNum) : numberToIP(broadcastNum - 1),
        subnetMask: numberToIP(maskNum),
        wildcardMask: numberToIP((~maskNum) >>> 0),
        totalHosts,
        usableHosts,
        binaryMask: numberToBinary(maskNum),
        binaryIP: numberToBinary(ipNum),
        binaryNetwork: numberToBinary(networkNum),
        ipClass,
        isPrivate,
        networkBits: cidr,
        hostBits,
      });
    } catch (err) {
      setSubnetError("Calculation error");
      setSubnetResults(null);
    }
  }, [ipToNumber, numberToIP, numberToBinary]);

  // Calculate on mount and when inputs change
  React.useEffect(() => {
    calculateSubnet(subnetIP, subnetCIDR);
  }, [subnetIP, subnetCIDR, calculateSubnet]);

  // ========== QUIZ STATE ==========
  const [quizActive, setQuizActive] = useState(false);
  const [quizQuestions, setQuizQuestions] = useState<QuizQuestion[]>([]);
  const [quizAnswers, setQuizAnswers] = useState<{ [key: number]: number }>({});
  const [quizSubmitted, setQuizSubmitted] = useState(false);
  const [quizScore, setQuizScore] = useState(0);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuizQuestions(quizBank, QUIZ_QUESTION_COUNT)
  );
  // Scroll trigger for back-to-top button

  // Select 10 random questions from the 75-question bank
  const selectRandomQuestions = useCallback(() => (
    selectRandomQuizQuestions(quizBank, QUIZ_QUESTION_COUNT)
  ), []);

  // Start a new quiz
  const startQuiz = useCallback((forceNew = false) => {
    const questions = forceNew ? selectRandomQuestions() : quizPool;
    setQuizQuestions(questions);
    setQuizAnswers({});
    setQuizSubmitted(false);
    setQuizScore(0);
    setCurrentQuestionIndex(0);
    setQuizActive(true);
  }, [quizPool, selectRandomQuestions]);

  // Reset quiz
  const resetQuiz = useCallback(() => {
    setQuizActive(false);
    setQuizQuestions([]);
    setQuizAnswers({});
    setQuizSubmitted(false);
    setQuizScore(0);
    setCurrentQuestionIndex(0);
  }, []);

  // Handle answer selection
  const handleAnswerSelect = useCallback((questionId: number, answerIndex: number) => {
    if (quizSubmitted) return;
    setQuizAnswers(prev => ({ ...prev, [questionId]: answerIndex }));
  }, [quizSubmitted]);

  // Submit quiz
  const submitQuiz = useCallback(() => {
    let score = 0;
    quizQuestions.forEach(q => {
      if (quizAnswers[q.id] === q.correct) {
        score++;
      }
    });
    setQuizScore(score);
    setQuizSubmitted(true);
  }, [quizQuestions, quizAnswers]);

  // Get quiz progress
  const quizProgress = useMemo(() => {
    const answered = Object.keys(quizAnswers).length;
    return { answered, total: quizQuestions.length };
  }, [quizAnswers, quizQuestions.length]);

  const quizCategoryStats = useMemo(() => {
    const counts = quizBank.reduce((acc, question) => {
      acc[question.category] = (acc[question.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return quizCategoryOrder
      .filter(category => counts[category])
      .map(category => ({
        label: category,
        count: counts[category],
        color: quizCategoryColors[category] ?? "#94a3b8",
      }));
  }, []);

  // Scroll handler for back-to-top is now handled by useScrollTrigger hook

  // Get score color
  const getScoreColor = (score: number) => {
    if (score >= 9) return "#22c55e"; // Green - Excellent
    if (score >= 7) return "#84cc16"; // Lime - Good
    if (score >= 5) return "#f59e0b"; // Amber - Okay
    return "#ef4444"; // Red - Needs work
  };

  // Get score message
  const getScoreMessage = (score: number) => {
    if (score === 10) return "🏆 Perfect Score! You're a networking expert!";
    if (score >= 9) return "🌟 Excellent! Almost perfect!";
    if (score >= 7) return "👍 Good job! Keep studying!";
    if (score >= 5) return "📚 Not bad, but room to improve!";
    return "💪 Keep learning! Review the explanations below.";
  };

  const pageContext = `Computer Networking Fundamentals learning page - Essential networking concepts for IT and security professionals. Covers OSI model, TCP/IP, IP addressing, subnetting, protocols, ports, DNS, wireless standards, network devices, VLANs, NAT, and essential commands.`;

  // Section Navigation Items
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "data-transmission", label: "Data Transmission", icon: <SwapHorizIcon /> },
    { id: "osi-model", label: "OSI Model", icon: <LayersIcon /> },
    { id: "tcpip-model", label: "TCP/IP Model", icon: <AccountTreeIcon /> },
    { id: "ip-addressing", label: "IP Addressing", icon: <LanguageIcon /> },
    { id: "subnetting", label: "Subnetting", icon: <CalculateIcon /> },
    { id: "interactive-tools", label: "Interactive Tools", icon: <NetworkCheckIcon /> },
    { id: "protocols-ports", label: "Protocols & Ports", icon: <SettingsEthernetIcon /> },
    { id: "devices", label: "Network Devices", icon: <RouterIcon /> },
    { id: "dns", label: "DNS", icon: <DnsIcon /> },
    { id: "wireless-security", label: "Wireless & Security", icon: <WifiIcon /> },
    { id: "commands", label: "Commands", icon: <TerminalIcon /> },
    { id: "routing-nat", label: "Routing & NAT", icon: <HubIcon /> },
    { id: "vlan-switching", label: "VLAN & Switching", icon: <CableIcon /> },
    { id: "ipv6", label: "IPv6", icon: <PublicIcon /> },
    { id: "automation-sdn", label: "Automation & SDN", icon: <CloudIcon /> },
    { id: "quiz", label: "Quiz", icon: <QuizIcon /> },
  ];

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

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

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

  // Sidebar Navigation Component
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
    <LearnPageLayout pageTitle="Computer Networking" pageContext={pageContext}>
      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Navigate Sections" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            zIndex: 1000,
            bgcolor: accent,
            "&:hover": { bgcolor: "#2563eb" },
            boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Top Button - Mobile Only */}
      <Tooltip title="Scroll to Top" placement="left">
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
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
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
                    bgcolor: alpha(accent, 0.1),
                  },
                  transition: "all 0.2s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>{item.icon}</ListItemIcon>
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
                {activeSection === item.id && (
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha(accent, 0.2),
                      color: accent,
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          {/* Quick Actions */}
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Container maxWidth="lg" sx={{ py: 0, px: 0 }} id="top">
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
            background: `linear-gradient(135deg, ${alpha("#0ea5e9", 0.15)} 0%, ${alpha("#0891b2", 0.1)} 100%)`,
            border: `1px solid ${alpha("#0ea5e9", 0.2)}`,
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
              background: `linear-gradient(135deg, ${alpha("#0ea5e9", 0.1)}, transparent)`,
            }}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
            <Box
              sx={{
                width: 80,
                height: 80,
                borderRadius: 3,
                background: `linear-gradient(135deg, #0ea5e9, #0891b2)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#0ea5e9", 0.3)}`,
              }}
            >
              <RouterIcon sx={{ fontSize: 45, color: "white" }} />
            </Box>
            <Box>
              <Chip label="IT Fundamentals" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha("#0ea5e9", 0.1), color: "#0ea5e9" }} />
              <Typography variant="h3" sx={{ fontWeight: 800, mb: 1 }}>
                Computer Networking
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600 }}>
                Essential networking concepts for IT and security professionals
              </Typography>
            </Box>
          </Box>
        </Paper>

      {/* Written Introduction Section */}
      <Paper
        id="intro"
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 4,
          bgcolor: alpha(theme.palette.background.paper, 0.6),
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          scrollMarginTop: 96,
        }}
      >
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
          <InfoIcon sx={{ color: "#0ea5e9" }} />
          Introduction to Computer Networking
        </Typography>

        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#0ea5e9", 0.03), borderRadius: 2, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
            The Foundation of Modern Computing: Why Networking Powers Everything
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            Every time you send a message, stream a video, make a video call, or access a cloud application, you're relying on computer
            networks—vast interconnected systems that have become the invisible backbone of modern life. Networking isn't just about
            connecting devices; it's about enabling the seamless flow of information that powers global commerce, communication, entertainment,
            and collaboration. From your smartphone connecting to a cell tower to massive data centers serving millions of requests per second,
            networking protocols and architectures make it all possible.
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            The beauty of networking lies in its universal principles. Whether you're setting up a small home Wi-Fi network or designing
            infrastructure for a Fortune 500 company, the same fundamental concepts apply: <strong>addressing</strong> (how devices identify
            themselves), <strong>routing</strong> (how data finds its path), <strong>protocols</strong> (the rules governing communication),
            and <strong>security</strong> (protecting data in transit). Understanding these concepts opens doors to careers in network
            engineering, cybersecurity, cloud architecture, DevOps, and system administration.
          </Typography>
          <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            For cybersecurity professionals, networking knowledge is non-negotiable. You cannot defend what you don't understand. Attackers
            exploit network vulnerabilities—man-in-the-middle attacks intercept unencrypted traffic, DDoS attacks flood network resources,
            DNS poisoning redirects users to malicious sites, and ARP spoofing enables lateral movement within networks. Whether you're
            performing penetration testing, analyzing packet captures in Wireshark, configuring firewall rules, or investigating security
            incidents, deep networking knowledge is your most powerful tool.
          </Typography>
        </Paper>

        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            From ARPANET to 5G: The Evolution of Networking
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            The history of computer networking begins in 1969 with <strong>ARPANET</strong>, the U.S. Department of Defense's experimental
            network that connected four universities. This pioneering network introduced packet switching—breaking data into small packets that
            could take different routes to their destination and be reassembled. This resilient approach to data transmission became the
            foundation of the modern Internet. In 1983, ARPANET adopted the TCP/IP protocol suite, officially birthing the Internet as we know it.
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            The 1990s brought the World Wide Web (thanks to Tim Berners-Lee's HTTP and HTML), transforming the Internet from an academic tool
            into a consumer platform. Ethernet emerged as the dominant LAN technology, Wi-Fi standards (802.11) enabled wireless connectivity,
            and the IPv4 address space began to strain under explosive growth. By the 2000s, the shift to cloud computing, mobile devices, and
            IoT created unprecedented demands on network infrastructure. Today, we're in the era of <strong>software-defined networking (SDN)</strong>,
            where network behavior is programmable, and <strong>5G wireless</strong>, delivering gigabit speeds to mobile devices.
          </Typography>
          <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            Yet despite decades of innovation, the core principles remain remarkably consistent. The OSI model created in 1984 still guides
            how we think about networking. TCP's three-way handshake still establishes connections. IP addresses still identify devices. The
            protocols and standards developed decades ago continue to underpin trillion-dollar industries. Learning networking means learning
            concepts that will remain relevant for your entire career.
          </Typography>
        </Paper>

        <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
          Computer networking is the practice of connecting computers and other devices together to share resources,
          exchange data, and communicate. From the smallest home network to the vast infrastructure of the Internet,
          networking principles remain consistent: devices need a way to identify each other, a medium to transmit data,
          and agreed-upon rules (protocols) for communication.
        </Typography>

        <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
          Understanding networking is foundational for anyone in IT or cybersecurity. Whether you're troubleshooting 
          connectivity issues, configuring firewalls, analyzing network traffic for threats, or designing secure 
          architectures, you need to understand how data flows through networks. This knowledge helps you identify 
          vulnerabilities, detect attacks, and implement proper security controls.
        </Typography>

        <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
          Networks operate through a layered approach, most commonly described by the <strong>OSI (Open Systems Interconnection) 
          model</strong> with 7 layers, or the <strong>TCP/IP model</strong> with 4 layers. Each layer has specific responsibilities, 
          from the physical transmission of electrical signals to the application protocols that deliver services like 
          web browsing and email.
        </Typography>

        <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
          Key concepts you'll learn include <strong>IP addressing</strong> (how devices are uniquely identified), 
          <strong>subnetting</strong> (dividing networks into smaller segments), <strong>routing</strong> (how data 
          finds its path across networks), <strong>protocols</strong> (the rules governing communication), and 
          <strong>network devices</strong> (routers, switches, firewalls). For security professionals, understanding 
          these fundamentals is critical for tasks like packet analysis, penetration testing, and incident response.
        </Typography>

        <Alert severity="success" sx={{ mt: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>What You'll Learn</AlertTitle>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Typography variant="body2">• OSI & TCP/IP Models</Typography>
              <Typography variant="body2">• IP Addressing Classes</Typography>
              <Typography variant="body2">• Subnetting & CIDR</Typography>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Typography variant="body2">• Common Protocols & Ports</Typography>
              <Typography variant="body2">• TCP vs UDP</Typography>
              <Typography variant="body2">• DNS Record Types</Typography>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Typography variant="body2">• Network Devices</Typography>
              <Typography variant="body2">• VLANs & NAT</Typography>
              <Typography variant="body2">• Wireless Standards</Typography>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Typography variant="body2">• Network Topologies</Typography>
              <Typography variant="body2">• IPv6 Basics</Typography>
              <Typography variant="body2">• Essential Commands</Typography>
            </Grid>
          </Grid>
        </Alert>
      </Paper>

      {/* Data Transmission Types */}
      <Paper
        id="data-transmission"
        sx={{
          p: 3,
          mb: 5,
          borderRadius: 3,
          background: alpha("#a855f7", 0.03),
          border: "1px solid",
          borderColor: alpha("#a855f7", 0.1),
          scrollMarginTop: 96,
        }}
      >
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
          📡 Data Transmission Types
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Understanding how data flows between network devices - unicast (one-to-one), broadcast (one-to-all), 
          and multicast (one-to-many) are fundamental concepts for network communication.
        </Typography>
        <Box sx={{ display: "flex", justifyContent: "center" }}>
          <Box
            component="img"
            src="/images/transmission.jpg"
            alt="Network Transmission Types - Unicast, Broadcast, Multicast"
            sx={{
              maxWidth: "100%",
              maxHeight: 400,
              borderRadius: 2,
              boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
              border: "1px solid rgba(255,255,255,0.1)",
            }}
          />
        </Box>
        <Grid container spacing={2} sx={{ mt: 2 }}>
          <Grid item xs={12} md={4}>
            <Box sx={{ textAlign: "center", p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e" }}>Unicast</Typography>
              <Typography variant="caption" color="text.secondary">One-to-One transmission</Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ textAlign: "center", p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>Broadcast</Typography>
              <Typography variant="caption" color="text.secondary">One-to-All transmission</Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ textAlign: "center", p: 2, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9" }}>Multicast</Typography>
              <Typography variant="caption" color="text.secondary">One-to-Many transmission</Typography>
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* OSI Model */}
      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 96 }} id="osi-model">
        🏗️ OSI Model (7 Layers)
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
        The Open Systems Interconnection (OSI) model is a conceptual framework developed by the International Organization for Standardization (ISO) in 1984. It standardizes the communication functions of telecommunication and computing systems without regard to their underlying internal structure and technology.
      </Typography>

      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
          Why the OSI Model Matters
        </Typography>
        <Typography variant="body2" paragraph>
          The OSI model breaks down the complex process of network communication into seven distinct layers, each with specific responsibilities. This modular approach allows network engineers, developers, and administrators to:
        </Typography>
        <Box component="ul" sx={{ pl: 3, "& li": { mb: 1 } }}>
          <li><Typography variant="body2"><strong>Troubleshoot effectively:</strong> By isolating problems to specific layers, you can identify whether an issue is physical (cable), logical (IP routing), or application-level (DNS resolution).</Typography></li>
          <li><Typography variant="body2"><strong>Design scalable systems:</strong> Each layer can be upgraded or modified independently without affecting other layers, enabling modular network design.</Typography></li>
          <li><Typography variant="body2"><strong>Understand protocols:</strong> Knowing which layer a protocol operates at helps you understand its purpose and limitations (e.g., TCP at Layer 4 vs IP at Layer 3).</Typography></li>
          <li><Typography variant="body2"><strong>Vendor interoperability:</strong> The standardized model ensures different vendors' equipment can communicate, as long as they adhere to the same layer protocols.</Typography></li>
        </Box>

        <Typography variant="body2" paragraph sx={{ mt: 2 }}>
          <strong>Data Flow:</strong> When you send data across a network, it travels down through all seven layers on the sending device (encapsulation), across the physical medium, and then up through the seven layers on the receiving device (de-encapsulation). Each layer adds its own header information during encapsulation.
        </Typography>

        <Typography variant="body2" paragraph>
          <strong>Mnemonic to Remember:</strong> "Please Do Not Throw Sausage Pizza Away" (Physical, Data Link, Network, Transport, Session, Presentation, Application) or reversed: "All People Seem To Need Data Processing" (Application to Physical).
        </Typography>
      </Paper>

      {/* OSI Model Image */}
      <Paper sx={{ p: 2, mb: 3, borderRadius: 3, textAlign: "center", bgcolor: alpha("#0ea5e9", 0.02) }}>
        <Box
          component="img"
          src="/images/7layer.jpg"
          alt="OSI 7 Layer Model"
          sx={{
            maxWidth: "100%",
            maxHeight: 500,
            borderRadius: 2,
            boxShadow: `0 4px 20px ${alpha("#000", 0.15)}`,
          }}
        />
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
          The OSI 7 Layer Model - Each layer has specific responsibilities
        </Typography>
      </Paper>

      <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ bgcolor: alpha("#0ea5e9", 0.1) }}>
              <TableCell sx={{ fontWeight: 700 }}>Layer</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Name</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>PDU</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Protocols</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Devices</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Function</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {osiLayers.map((layer) => (
              <TableRow key={layer.layer}>
                <TableCell>
                  <Chip label={layer.layer} size="small" sx={{ fontWeight: 700, bgcolor: alpha("#0ea5e9", 0.15) }} />
                </TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{layer.name}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{layer.pdu}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem" }}>{layer.protocols}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem" }}>{layer.devices}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{layer.description}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Deep Dive: Layer-by-Layer Explanation */}
      <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.02) }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 3, color: "#0ea5e9" }}>
          🔍 Deep Dive: Understanding Each OSI Layer
        </Typography>

        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
            Layer 7 - Application Layer
          </Typography>
          <Typography variant="body2" paragraph>
            This is the layer closest to the end user. It provides network services directly to applications and handles high-level protocols like HTTP, FTP, SMTP, and DNS. The Application Layer doesn't refer to applications like Chrome or Outlook, but rather the protocols these applications use to communicate over the network. For example, when you browse a website, your browser uses HTTP/HTTPS (Layer 7) to request web pages from a server.
          </Typography>
          <Typography variant="body2">
            <strong>Real-world example:</strong> When you type "google.com" in your browser, the DNS protocol (Layer 7) resolves the domain name to an IP address before the connection can be established.
          </Typography>
        </Box>

        <Divider sx={{ my: 2 }} />

        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
            Layer 6 - Presentation Layer
          </Typography>
          <Typography variant="body2" paragraph>
            The Presentation Layer acts as a data translator for the network. It handles data encoding, encryption, compression, and format conversion. This layer ensures that data sent from the Application Layer of one system can be read by the Application Layer of another system, even if they use different data formats. SSL/TLS encryption happens here, converting plaintext into encrypted ciphertext before transmission.
          </Typography>
          <Typography variant="body2">
            <strong>Real-world example:</strong> When you visit an HTTPS website, the Presentation Layer encrypts your login credentials before sending them across the internet, protecting them from interception.
          </Typography>
        </Box>

        <Divider sx={{ my: 2 }} />

        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>
            Layer 5 - Session Layer
          </Typography>
          <Typography variant="body2" paragraph>
            The Session Layer establishes, manages, and terminates connections (sessions) between applications. It provides synchronization, dialog control, and manages the orderly exchange of data. This layer handles authentication and reconnection if a session is interrupted. NetBIOS and RPC (Remote Procedure Call) operate at this layer.
          </Typography>
          <Typography variant="body2">
            <strong>Real-world example:</strong> When you're on a video call and your internet briefly drops, the Session Layer can help re-establish the connection and synchronize where you left off, rather than starting completely over.
          </Typography>
        </Box>

        <Divider sx={{ my: 2 }} />

        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
            Layer 4 - Transport Layer
          </Typography>
          <Typography variant="body2" paragraph>
            The Transport Layer provides reliable data transfer services to the upper layers. It handles segmentation, flow control, error checking, and acknowledgments. The two main protocols here are TCP (Transmission Control Protocol) and UDP (User Datagram Protocol). TCP provides reliable, connection-oriented communication with error checking and retransmission, while UDP provides fast, connectionless communication without guaranteed delivery.
          </Typography>
          <Typography variant="body2" paragraph>
            <strong>Port numbers</strong> operate at this layer - they identify specific applications or services (e.g., port 80 for HTTP, port 443 for HTTPS). When data arrives at a computer, the Transport Layer uses the port number to determine which application should receive it.
          </Typography>
          <Typography variant="body2">
            <strong>Real-world example:</strong> When you download a file, TCP ensures every packet arrives in order and requests retransmission of any lost packets. When you stream live video, UDP is often used because speed is more important than perfect accuracy.
          </Typography>
        </Box>

        <Divider sx={{ my: 2 }} />

        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>
            Layer 3 - Network Layer
          </Typography>
          <Typography variant="body2" paragraph>
            The Network Layer handles routing and forwarding of data packets between different networks. It provides logical addressing (IP addresses) and determines the best path for data to travel from source to destination across multiple networks. Routers operate at this layer, making forwarding decisions based on IP addresses. The primary protocol is IP (Internet Protocol), along with routing protocols like OSPF, BGP, and RIP.
          </Typography>
          <Typography variant="body2" paragraph>
            This layer also handles packet fragmentation and reassembly when data is too large to fit in a single frame. It's responsible for logical network topology and path determination.
          </Typography>
          <Typography variant="body2">
            <strong>Real-world example:</strong> When you send an email from New York to Tokyo, the Network Layer (routers) determines the optimal path through dozens of intermediate routers to get your data across the world.
          </Typography>
        </Box>

        <Divider sx={{ my: 2 }} />

        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
            Layer 2 - Data Link Layer
          </Typography>
          <Typography variant="body2" paragraph>
            The Data Link Layer provides node-to-node data transfer between two directly connected nodes. It handles physical addressing (MAC addresses), frame formatting, error detection (using FCS - Frame Check Sequence), and media access control. This layer is divided into two sublayers: LLC (Logical Link Control) and MAC (Media Access Control).
          </Typography>
          <Typography variant="body2" paragraph>
            Switches operate at this layer, using MAC address tables to forward frames only to the intended recipient port rather than broadcasting to all ports like hubs do. The Data Link Layer also handles collision detection and avoidance in shared media environments.
          </Typography>
          <Typography variant="body2">
            <strong>Real-world example:</strong> When your computer sends data to your router over Ethernet, the Data Link Layer adds the router's MAC address to the frame header so the data reaches the correct device on your local network.
          </Typography>
        </Box>

        <Divider sx={{ my: 2 }} />

        <Box>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>
            Layer 1 - Physical Layer
          </Typography>
          <Typography variant="body2" paragraph>
            The Physical Layer deals with the actual physical transmission of raw bit streams over a physical medium. It defines the electrical, mechanical, and procedural specifications for activating, maintaining, and deactivating physical links. This includes cables (copper, fiber optic), connectors (RJ45, SC), voltage levels, cable distances, physical data rates, and network topology (bus, star, ring).
          </Typography>
          <Typography variant="body2" paragraph>
            This layer converts digital data (1s and 0s) into electrical signals (copper cables), light pulses (fiber optics), or radio waves (wireless). It doesn't care about the content of the data - it just transmits raw bits.
          </Typography>
          <Typography variant="body2">
            <strong>Real-world example:</strong> When you plug an Ethernet cable into your computer, the Physical Layer handles the electrical signals traveling through the copper wires at speeds defined by standards like 10/100/1000 Mbps Ethernet.
          </Typography>
        </Box>
      </Paper>

      {/* TCP/IP Model */}
      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 96 }} id="tcpip-model">
        🌐 TCP/IP Model (4 Layers)
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
        The TCP/IP model, also known as the Internet Protocol Suite, is the practical networking model that powers the modern Internet. Developed by the U.S. Department of Defense in the 1970s, it predates the OSI model and is more widely implemented in real-world networks.
      </Typography>

      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
          TCP/IP vs OSI: Key Differences
        </Typography>
        <Typography variant="body2" paragraph>
          While the OSI model is a theoretical framework with seven layers, the TCP/IP model is a practical, four-layer model that directly corresponds to how the Internet actually works. Here's why both models are important:
        </Typography>
        <Box component="ul" sx={{ pl: 3, "& li": { mb: 1 } }}>
          <li><Typography variant="body2"><strong>TCP/IP is implementation-focused:</strong> It describes the actual protocols used on the Internet (TCP, IP, HTTP, etc.), not just theoretical concepts.</Typography></li>
          <li><Typography variant="body2"><strong>OSI is educational:</strong> The seven-layer OSI model is excellent for teaching and troubleshooting because it breaks down complex concepts into more granular pieces.</Typography></li>
          <li><Typography variant="body2"><strong>Layer mapping:</strong> The TCP/IP Application layer combines OSI layers 5, 6, and 7. The Network Access layer combines OSI layers 1 and 2.</Typography></li>
          <li><Typography variant="body2"><strong>Protocol specificity:</strong> TCP/IP defines specific protocols (like TCP and IP), while OSI defines generic functions each layer should perform.</Typography></li>
        </Box>
        <Typography variant="body2" paragraph sx={{ mt: 2 }}>
          In practice, network engineers reference both models: OSI for conceptual understanding and troubleshooting ("Is this a Layer 2 or Layer 3 issue?"), and TCP/IP for actual protocol implementation.
        </Typography>
      </Paper>

      {/* TCP/IP Model Image */}
      <Box sx={{ display: "flex", justifyContent: "center", mb: 4 }}>
        <Box
          component="img"
          src="/images/tcpip.jpg"
          alt="TCP/IP Model Layers"
          sx={{
            maxWidth: "100%",
            maxHeight: 400,
            borderRadius: 3,
            boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
            border: "1px solid rgba(255,255,255,0.1)",
          }}
        />
      </Box>

      <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
              <TableCell sx={{ fontWeight: 700 }}>Layer</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Name</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>OSI Equivalent</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Protocols</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Function</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {tcpipLayers.map((layer) => (
              <TableRow key={layer.layer}>
                <TableCell><Chip label={layer.layer} size="small" sx={{ fontWeight: 700, bgcolor: alpha("#22c55e", 0.15) }} /></TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{layer.name}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem" }}>{layer.osiEquiv}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{layer.protocols}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{layer.description}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Divider */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, scrollMarginTop: 96 }} id="ip-addressing">
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>IP ADDRESSING</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      {/* IP Addressing */}
      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        📍 IP Addressing
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
        IP (Internet Protocol) addresses are unique identifiers assigned to every device on a network. They enable devices to locate and communicate with each other across local networks and the Internet.
      </Typography>

      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.02) }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
          Understanding IPv4 Addressing
        </Typography>
        <Typography variant="body2" paragraph>
          An IPv4 address is a 32-bit number divided into four octets (8 bits each), written in dotted-decimal notation like <strong>192.168.1.100</strong>. Each octet can range from 0 to 255 (2⁸ = 256 possible values). This gives us approximately 4.3 billion total IPv4 addresses (2³² = 4,294,967,296).
        </Typography>

        <Typography variant="body2" paragraph>
          <strong>IP Address Structure:</strong> An IP address consists of two parts:
        </Typography>
        <Box component="ul" sx={{ pl: 3, mb: 2, "& li": { mb: 1 } }}>
          <li><Typography variant="body2"><strong>Network portion:</strong> Identifies the network the device belongs to (like a street name)</Typography></li>
          <li><Typography variant="body2"><strong>Host portion:</strong> Identifies the specific device on that network (like a house number)</Typography></li>
        </Box>

        <Typography variant="body2" paragraph>
          The <strong>subnet mask</strong> determines which bits represent the network and which represent the host. Common masks include:
        </Typography>
        <Box component="ul" sx={{ pl: 3, mb: 2, "& li": { mb: 1 } }}>
          <li><Typography variant="body2" sx={{ fontFamily: "monospace" }}>255.255.255.0 (/24) - 254 usable hosts</Typography></li>
          <li><Typography variant="body2" sx={{ fontFamily: "monospace" }}>255.255.0.0 (/16) - 65,534 usable hosts</Typography></li>
          <li><Typography variant="body2" sx={{ fontFamily: "monospace" }}>255.0.0.0 (/8) - 16,777,214 usable hosts</Typography></li>
        </Box>

        <Typography variant="body2" paragraph>
          <strong>Classful vs Classless Addressing:</strong> Originally, IP addresses were divided into fixed classes (A, B, C, D, E). This "classful" system was inefficient and wasted many addresses. Modern networks use CIDR (Classless Inter-Domain Routing), which allows flexible subnet masks of any length, maximizing address utilization.
        </Typography>

        <Typography variant="body2">
          <strong>Special Addresses:</strong> Not all IP addresses can be assigned to hosts. Each network reserves two addresses: the <strong>network address</strong> (all host bits = 0, e.g., 192.168.1.0) identifies the network itself, and the <strong>broadcast address</strong> (all host bits = 1, e.g., 192.168.1.255) sends data to all devices on the network.
        </Typography>
      </Paper>

      {/* IPv4 Classes */}
      <Accordion defaultExpanded sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f59e0b", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <PublicIcon sx={{ color: "#f59e0b" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>IPv4 Address Classes</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Class</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Range</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Default Mask</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Hosts</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Use</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {ipv4Classes.map((c) => (
                  <TableRow key={c.class}>
                    <TableCell><Chip label={`Class ${c.class}`} size="small" sx={{ fontWeight: 700 }} /></TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{c.range}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{c.defaultMask}</TableCell>
                    <TableCell>{c.hosts}</TableCell>
                    <TableCell sx={{ color: "text.secondary" }}>{c.use}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* Private Ranges */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#8b5cf6", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <LockIcon sx={{ color: "#8b5cf6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Private IP Ranges (RFC 1918)</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Range</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>CIDR</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Class</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Addresses</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {privateRanges.map((r) => (
                  <TableRow key={r.cidr}>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{r.range}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#8b5cf6", fontWeight: 600 }}>{r.cidr}</TableCell>
                    <TableCell>{r.class}</TableCell>
                    <TableCell>{r.hosts}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* Special Addresses */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ef4444", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <StorageIcon sx={{ color: "#ef4444" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>Special Addresses</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {specialAddresses.map((addr) => (
              <Grid item xs={12} sm={6} md={4} key={addr.address}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                  <Typography sx={{ fontFamily: "monospace", fontWeight: 700, color: "#ef4444" }}>{addr.address}</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{addr.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>{addr.description}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Subnetting */}
      <Accordion
        id="subnetting"
        sx={{ mb: 5, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 96 }}
      >
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#06b6d4", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <AccountTreeIcon sx={{ color: "#06b6d4" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>CIDR & Subnetting Cheat Sheet</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>CIDR</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Subnet Mask</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Wildcard</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Usable Hosts</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {cidrTable.map((row) => (
                  <TableRow key={row.cidr}>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 700, color: "#06b6d4" }}>{row.cidr}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.mask}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.wildcard}</TableCell>
                    <TableCell>{row.hosts.toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* ========== SUBNETTING TUTORIAL SECTION ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>SUBNETTING MASTERY</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        🧮 How to Subnet (Complete Guide)
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
        Subnetting is one of the most important skills for network engineers. It's essential for efficient IP address management, network segmentation, and is heavily tested in CCNA and other networking certifications.
      </Typography>

      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#06b6d4", 0.02) }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
          Why Subnet? Real-World Benefits
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                🚀 Network Performance
              </Typography>
              <Typography variant="body2">
                Smaller broadcast domains mean less broadcast traffic. Instead of 254 devices shouting on one network, you can have multiple networks of 30 devices each, dramatically reducing network noise.
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={6}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                🔒 Security & Isolation
              </Typography>
              <Typography variant="body2">
                Separate departments into different subnets (Finance: 10.0.10.0/24, HR: 10.0.20.0/24) and control traffic between them with firewalls and ACLs. A compromised device in one subnet can't easily spread to others.
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={6}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                💰 IP Address Efficiency
              </Typography>
              <Typography variant="body2">
                Don't waste addresses! A point-to-point link between two routers only needs 2 IPs - use /30 (4 total, 2 usable) instead of /24 (256 total, 254 usable). This conserves precious IPv4 space.
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={6}>
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                📊 Organized Network Design
              </Typography>
              <Typography variant="body2">
                Hierarchical addressing makes troubleshooting easier. If all subnets for Building A start with 10.1.x.x and Building B with 10.2.x.x, you immediately know where a problem is located.
              </Typography>
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Subnetting Image */}
      <Paper sx={{ p: 3, mb: 4, borderRadius: 3, textAlign: "center", bgcolor: alpha("#06b6d4", 0.02), border: "1px solid", borderColor: alpha("#06b6d4", 0.1) }}>
        <Box
          component="img"
          src="/images/subnetting.jpg"
          alt="Subnetting Diagram"
          sx={{
            maxWidth: "100%",
            maxHeight: 450,
            borderRadius: 2,
            boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
            border: "1px solid rgba(255,255,255,0.1)",
          }}
        />
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 2 }}>
          Visual representation of subnetting concepts
        </Typography>
      </Paper>

      {/* Subnetting Basics */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#06b6d4", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#06b6d4" }}>
          📚 Understanding Subnetting Fundamentals
        </Typography>

        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>What is Subnetting?</strong> Subnetting divides a larger network into smaller, more manageable 
            sub-networks (subnets). This improves network performance, security, and efficient IP address allocation.
          </Typography>
        </Alert>

        <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>Key Concepts:</Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e" }}>Network Portion</Typography>
              <Typography variant="body2" color="text.secondary">
                Identifies the network - same for all hosts in the subnet
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>Host Portion</Typography>
              <Typography variant="body2" color="text.secondary">
                Identifies individual hosts within the network
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444" }}>Network Address</Typography>
              <Typography variant="body2" color="text.secondary">
                First address in range - all host bits are 0 (not usable for hosts)
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Broadcast Address</Typography>
              <Typography variant="body2" color="text.secondary">
                Last address in range - all host bits are 1 (not usable for hosts)
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>The Magic Formula:</Typography>
        <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2, mb: 3, fontFamily: "monospace" }}>
          <Typography variant="body1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>
            Usable Hosts = 2^(Host Bits) - 2
          </Typography>
          <Typography variant="body2" color="text.secondary">
            We subtract 2 because the network address and broadcast address cannot be assigned to hosts.
          </Typography>
        </Paper>
      </Paper>

      {/* Step-by-Step Subnetting */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#22c55e", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#22c55e" }}>
          📋 Step-by-Step Subnetting Process
        </Typography>

        <Accordion defaultExpanded sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ fontWeight: 600 }}>Step 1: Identify the Network Requirements</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Determine how many subnets you need and how many hosts per subnet.
            </Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
              <Typography variant="body2">Example: You need 4 subnets with at least 50 hosts each</Typography>
            </Paper>
          </AccordionDetails>
        </Accordion>

        <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ fontWeight: 600 }}>Step 2: Calculate Subnet Bits Needed</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Use the formula: 2^n ≥ number of subnets needed (where n = subnet bits)
            </Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", mb: 2 }}>
              <Typography variant="body2">For 4 subnets: 2^2 = 4 → Need 2 subnet bits</Typography>
            </Paper>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Subnets Needed</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Bits Required</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>2^n Value</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { subnets: "2", bits: "1", value: "2" },
                    { subnets: "3-4", bits: "2", value: "4" },
                    { subnets: "5-8", bits: "3", value: "8" },
                    { subnets: "9-16", bits: "4", value: "16" },
                    { subnets: "17-32", bits: "5", value: "32" },
                    { subnets: "33-64", bits: "6", value: "64" },
                  ].map((row) => (
                    <TableRow key={row.bits}>
                      <TableCell>{row.subnets}</TableCell>
                      <TableCell sx={{ color: "#22c55e", fontWeight: 600 }}>{row.bits}</TableCell>
                      <TableCell>{row.value}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ fontWeight: 600 }}>Step 3: Determine the New Subnet Mask</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Add subnet bits to the original network bits. The new CIDR = original CIDR + subnet bits.
            </Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ mb: 1 }}>Original: 192.168.1.0/24 (Class C)</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>Adding 2 subnet bits: /24 + 2 = /26</Typography>
              <Typography variant="body2">New subnet mask: 255.255.255.192</Typography>
            </Paper>
          </AccordionDetails>
        </Accordion>

        <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ fontWeight: 600 }}>Step 4: Calculate Hosts per Subnet</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Host bits = 32 - CIDR notation. Usable hosts = 2^(host bits) - 2
            </Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ mb: 1 }}>/26 means 32 - 26 = 6 host bits</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>2^6 = 64 total addresses</Typography>
              <Typography variant="body2" sx={{ color: "#22c55e", fontWeight: 600 }}>64 - 2 = 62 usable hosts per subnet ✓</Typography>
            </Paper>
          </AccordionDetails>
        </Accordion>

        <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ fontWeight: 600 }}>Step 5: Calculate Subnet Ranges</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Block size = 256 - subnet mask last octet (or 2^host bits for that octet)
            </Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", mb: 2 }}>
              <Typography variant="body2">Block size for /26: 256 - 192 = 64</Typography>
            </Paper>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Subnet</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Network</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>First Host</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Last Host</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Broadcast</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { num: "1", network: "192.168.1.0", first: "192.168.1.1", last: "192.168.1.62", broadcast: "192.168.1.63" },
                    { num: "2", network: "192.168.1.64", first: "192.168.1.65", last: "192.168.1.126", broadcast: "192.168.1.127" },
                    { num: "3", network: "192.168.1.128", first: "192.168.1.129", last: "192.168.1.190", broadcast: "192.168.1.191" },
                    { num: "4", network: "192.168.1.192", first: "192.168.1.193", last: "192.168.1.254", broadcast: "192.168.1.255" },
                  ].map((row) => (
                    <TableRow key={row.num}>
                      <TableCell sx={{ fontWeight: 600, color: "#06b6d4" }}>Subnet {row.num}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", color: "#ef4444" }}>{row.network}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{row.first}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{row.last}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", color: "#8b5cf6" }}>{row.broadcast}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      </Paper>

      {/* Quick Subnetting Shortcuts */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#f59e0b", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#f59e0b" }}>
          ⚡ Quick Subnetting Shortcuts
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>Powers of 2 (Memorize!):</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
              <TableContainer>
                <Table size="small">
                  <TableBody>
                    {[
                      { power: "2^1", value: "2" },
                      { power: "2^2", value: "4" },
                      { power: "2^3", value: "8" },
                      { power: "2^4", value: "16" },
                      { power: "2^5", value: "32" },
                      { power: "2^6", value: "64" },
                      { power: "2^7", value: "128" },
                      { power: "2^8", value: "256" },
                    ].map((row) => (
                      <TableRow key={row.power}>
                        <TableCell sx={{ fontFamily: "monospace", fontWeight: 600 }}>{row.power}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", color: "#f59e0b" }}>{row.value}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>Subnet Mask Values:</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
              <TableContainer>
                <Table size="small">
                  <TableBody>
                    {[
                      { bits: "1 bit on", value: "128" },
                      { bits: "2 bits on", value: "192" },
                      { bits: "3 bits on", value: "224" },
                      { bits: "4 bits on", value: "240" },
                      { bits: "5 bits on", value: "248" },
                      { bits: "6 bits on", value: "252" },
                      { bits: "7 bits on", value: "254" },
                      { bits: "8 bits on", value: "255" },
                    ].map((row) => (
                      <TableRow key={row.bits}>
                        <TableCell sx={{ fontFamily: "monospace" }}>{row.bits}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", color: "#f59e0b", fontWeight: 600 }}>{row.value}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        </Grid>

        <Alert severity="success" sx={{ mt: 3 }}>
          <Typography variant="body2">
            <strong>Pro Tip:</strong> Block size = 256 - subnet mask value. Subnets start at multiples of the block size!
          </Typography>
        </Alert>
      </Paper>

      {/* Practice Problems */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3, background: alpha("#8b5cf6", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#8b5cf6" }}>
          🎯 Practice Problems
        </Typography>

        <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ fontWeight: 600 }}>Problem 1: Given 10.0.0.0/8, create 16 subnets</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" sx={{ mb: 2 }}>
              <strong>Solution:</strong>
            </Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ mb: 1 }}>• Need 16 subnets → 2^4 = 16 → 4 subnet bits needed</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>• New CIDR: /8 + 4 = /12</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>• New mask: 255.240.0.0</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>• Host bits: 32 - 12 = 20</Typography>
              <Typography variant="body2" sx={{ color: "#22c55e" }}>• Hosts per subnet: 2^20 - 2 = 1,048,574</Typography>
            </Paper>
          </AccordionDetails>
        </Accordion>

        <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ fontWeight: 600 }}>Problem 2: What subnet is 172.16.45.200/20 in?</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" sx={{ mb: 2 }}>
              <strong>Solution:</strong>
            </Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ mb: 1 }}>• /20 means 255.255.240.0</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>• Block size in 3rd octet: 256 - 240 = 16</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>• 45 ÷ 16 = 2.8 → Floor = 2</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>• Network starts at: 2 × 16 = 32</Typography>
              <Typography variant="body2" sx={{ color: "#22c55e" }}>• Answer: 172.16.32.0/20</Typography>
            </Paper>
          </AccordionDetails>
        </Accordion>

        <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ fontWeight: 600 }}>Problem 3: You need 500 hosts. What's the minimum subnet mask?</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" sx={{ mb: 2 }}>
              <strong>Solution:</strong>
            </Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ mb: 1 }}>• Need at least 502 addresses (500 hosts + network + broadcast)</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>• 2^9 = 512 (first power of 2 ≥ 502)</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>• 9 host bits needed → 32 - 9 = /23</Typography>
              <Typography variant="body2" sx={{ color: "#22c55e" }}>• Answer: /23 or 255.255.254.0 (510 usable hosts)</Typography>
            </Paper>
          </AccordionDetails>
        </Accordion>
      </Paper>

      {/* ========== BEGINNER'S COMPLETE SUBNETTING GUIDE ========== */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: "linear-gradient(135deg, rgba(6,182,212,0.05) 0%, rgba(139,92,246,0.05) 100%)", border: "2px solid", borderColor: alpha("#06b6d4", 0.2) }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 2, color: "#06b6d4" }}>
          🎓 Beginner's Complete Subnetting Guide
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
          Learn subnetting from absolute scratch - no prior knowledge required!
        </Typography>

        {/* Chapter 1: Binary Basics - COMPREHENSIVE GUIDE */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03) }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            📖 Chapter 1: Complete Guide to Binary, Decimal, Hexadecimal & Octal
          </Typography>
          
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Why Learn Number Systems?</strong> Computers think in binary (1s and 0s). IP addresses, MAC addresses, 
              memory addresses, and color codes all use these number systems. Mastering conversions is essential for networking, 
              programming, and cybersecurity!
            </Typography>
          </Alert>

          {/* Number Systems Overview */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <CalculateIcon /> Understanding Number Systems
          </Typography>
          
          <TableContainer component={Paper} sx={{ mb: 4, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>System</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Base</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Digits Used</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Prefix</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Common Uses</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700, color: "#22c55e" }}>Binary</TableCell>
                  <TableCell>Base-2</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>0, 1</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>11001010</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>0b</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>IP addresses, subnet masks, bitwise operations</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700, color: "#0ea5e9" }}>Decimal</TableCell>
                  <TableCell>Base-10</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>0-9</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>202</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>None</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>Human-readable IPs, port numbers</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>Hexadecimal</TableCell>
                  <TableCell>Base-16</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>0-9, A-F</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>CA</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>0x</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>MAC addresses, IPv6, memory, colors</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700, color: "#8b5cf6" }}>Octal</TableCell>
                  <TableCell>Base-8</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>0-7</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>312</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>0o</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>Unix file permissions (chmod 755)</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>

          {/* Interactive Calculator */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.05), border: `2px solid ${alpha("#8b5cf6", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
              🧮 Interactive Number System Calculator
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Enter a number in any format and instantly see all conversions!
            </Typography>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>1. Select Input Format:</Typography>
                <ToggleButtonGroup
                  value={calcInputType}
                  exclusive
                  onChange={(_, newValue) => newValue && handleCalcTypeChange(newValue)}
                  sx={{ mb: 2, flexWrap: "wrap" }}
                  size="small"
                >
                  <ToggleButton value="decimal" sx={{ px: 2 }}>Decimal</ToggleButton>
                  <ToggleButton value="binary" sx={{ px: 2 }}>Binary</ToggleButton>
                  <ToggleButton value="hex" sx={{ px: 2 }}>Hexadecimal</ToggleButton>
                  <ToggleButton value="octal" sx={{ px: 2 }}>Octal</ToggleButton>
                </ToggleButtonGroup>

                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>2. Enter Your Number:</Typography>
                <TextField
                  fullWidth
                  variant="outlined"
                  value={calcInput}
                  onChange={(e) => handleCalcInputChange(e.target.value)}
                  placeholder={
                    calcInputType === "decimal" ? "e.g., 192" :
                    calcInputType === "binary" ? "e.g., 11000000" :
                    calcInputType === "hex" ? "e.g., C0" :
                    "e.g., 300"
                  }
                  error={!!calcError}
                  helperText={calcError || `Enter a ${calcInputType} number`}
                  sx={{ 
                    mb: 2,
                    "& .MuiInputBase-input": { fontFamily: "monospace", fontSize: "1.1rem" }
                  }}
                />

                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                  <Typography variant="caption" color="text.secondary">Quick Examples:</Typography>
                  {(calcInputType === "decimal" ? ["192", "255", "127", "10"] :
                    calcInputType === "binary" ? ["11000000", "11111111", "10101010"] :
                    calcInputType === "hex" ? ["C0", "FF", "AA", "7F"] :
                    ["300", "377", "177", "12"]
                  ).map((example) => (
                    <Chip
                      key={example}
                      label={example}
                      size="small"
                      clickable
                      onClick={() => handleCalcInputChange(example)}
                      sx={{ fontFamily: "monospace" }}
                    />
                  ))}
                </Box>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>3. Results (All Formats):</Typography>
                {calcResults ? (
                  <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                    <Grid container spacing={1}>
                      {[
                        { label: "Decimal", value: calcResults.decimal, color: "#0ea5e9" },
                        { label: "Binary", value: calcResults.binary, color: "#22c55e" },
                        { label: "Binary (grouped)", value: calcResults.binaryGrouped, color: "#22c55e" },
                        { label: "Hexadecimal", value: `0x${calcResults.hex}`, color: "#f59e0b" },
                        { label: "Octal", value: `0o${calcResults.octal}`, color: "#8b5cf6" },
                      ].map((item) => (
                        <Grid item xs={12} key={item.label}>
                          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", py: 0.5 }}>
                            <Typography variant="body2" sx={{ fontWeight: 600, color: item.color }}>
                              {item.label}:
                            </Typography>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 700 }}>
                                {item.value}
                              </Typography>
                              <Tooltip title="Copy">
                                <IconButton size="small" onClick={() => copyToClipboard(item.value)}>
                                  <ContentCopyIcon sx={{ fontSize: 14 }} />
                                </IconButton>
                              </Tooltip>
                            </Box>
                          </Box>
                        </Grid>
                      ))}
                    </Grid>
                  </Paper>
                ) : (
                  <Paper sx={{ p: 3, bgcolor: "background.default", borderRadius: 2, textAlign: "center" }}>
                    <Typography variant="body2" color="text.secondary">
                      Enter a number above to see conversions
                    </Typography>
                  </Paper>
                )}
              </Grid>
            </Grid>
          </Paper>

          {/* Binary Place Values */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🔢 Binary Place Values (Memorize This!)</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Each position in binary represents a power of 2, starting from 2⁰ (=1) on the right. For an 8-bit octet:
          </Typography>
          <TableContainer component={Paper} sx={{ mb: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Position</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>8th (MSB)</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>7th</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>6th</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>5th</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>4th</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>3rd</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>2nd</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>1st (LSB)</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow>
                  <TableCell sx={{ fontWeight: 600 }}>Power of 2</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>2⁷</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>2⁶</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>2⁵</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>2⁴</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>2³</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>2²</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>2¹</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>2⁰</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell sx={{ fontWeight: 600 }}>Decimal Value</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>128</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>64</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>32</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>16</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>8</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>4</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>2</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>1</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>

          <Alert severity="success" sx={{ mb: 4 }}>
            <Typography variant="body2">
              <strong>Quick Tip:</strong> Memorize: 128, 64, 32, 16, 8, 4, 2, 1 - Each number is half the previous! 
              All 8 bits ON (11111111) = 128+64+32+16+8+4+2+1 = <strong>255</strong> (max value of an octet)
            </Typography>
          </Alert>

          {/* Decimal to Binary - Step by Step */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
            📘 Method 1: Decimal → Binary (Subtraction Method)
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Start from the left (128) and check if each value fits. If yes, write 1 and subtract. If no, write 0.
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: alpha("#0ea5e9", 0.03), borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Example: Convert 197 to Binary</Typography>
                <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.9rem" }}>
                  <Typography variant="body2" sx={{ mb: 1 }}>Starting value: <strong>197</strong></Typography>
                  <Divider sx={{ my: 1 }} />
                  <Typography variant="body2" sx={{ mb: 0.5 }}>197 ≥ 128? <Box component="span" sx={{ color: "#22c55e" }}>Yes!</Box> → Write <strong>1</strong>, remainder: 197-128 = <strong>69</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>69 ≥ 64? <Box component="span" sx={{ color: "#22c55e" }}>Yes!</Box> → Write <strong>1</strong>, remainder: 69-64 = <strong>5</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>5 ≥ 32? <Box component="span" sx={{ color: "#ef4444" }}>No</Box> → Write <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>5 ≥ 16? <Box component="span" sx={{ color: "#ef4444" }}>No</Box> → Write <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>5 ≥ 8? <Box component="span" sx={{ color: "#ef4444" }}>No</Box> → Write <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>5 ≥ 4? <Box component="span" sx={{ color: "#22c55e" }}>Yes!</Box> → Write <strong>1</strong>, remainder: 5-4 = <strong>1</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>1 ≥ 2? <Box component="span" sx={{ color: "#ef4444" }}>No</Box> → Write <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>1 ≥ 1? <Box component="span" sx={{ color: "#22c55e" }}>Yes!</Box> → Write <strong>1</strong>, remainder: 0 ✓</Typography>
                  <Divider sx={{ my: 1 }} />
                  <Typography variant="body2" sx={{ color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>
                    Result: 197 = 11000101
                  </Typography>
                </Paper>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Example: Convert 45 to Binary</Typography>
                <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.9rem" }}>
                  <Typography variant="body2" sx={{ mb: 1 }}>Starting value: <strong>45</strong></Typography>
                  <Divider sx={{ my: 1 }} />
                  <Typography variant="body2" sx={{ mb: 0.5 }}>45 ≥ 128? <Box component="span" sx={{ color: "#ef4444" }}>No</Box> → Write <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>45 ≥ 64? <Box component="span" sx={{ color: "#ef4444" }}>No</Box> → Write <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>45 ≥ 32? <Box component="span" sx={{ color: "#22c55e" }}>Yes!</Box> → Write <strong>1</strong>, remainder: 45-32 = <strong>13</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>13 ≥ 16? <Box component="span" sx={{ color: "#ef4444" }}>No</Box> → Write <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>13 ≥ 8? <Box component="span" sx={{ color: "#22c55e" }}>Yes!</Box> → Write <strong>1</strong>, remainder: 13-8 = <strong>5</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>5 ≥ 4? <Box component="span" sx={{ color: "#22c55e" }}>Yes!</Box> → Write <strong>1</strong>, remainder: 5-4 = <strong>1</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>1 ≥ 2? <Box component="span" sx={{ color: "#ef4444" }}>No</Box> → Write <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>1 ≥ 1? <Box component="span" sx={{ color: "#22c55e" }}>Yes!</Box> → Write <strong>1</strong>, remainder: 0 ✓</Typography>
                  <Divider sx={{ my: 1 }} />
                  <Typography variant="body2" sx={{ color: "#22c55e", fontWeight: 700, fontSize: "1rem" }}>
                    Result: 45 = 00101101
                  </Typography>
                </Paper>
              </Paper>
            </Grid>
          </Grid>

          {/* Division Method */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            📙 Method 2: Decimal → Binary (Division Method)
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Divide by 2 repeatedly. The remainders (read bottom-to-top) give the binary!
          </Typography>

          <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Example: Convert 156 using Division</Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>156 ÷ 2 = 78 remainder <strong>0</strong> ← LSB</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>78 ÷ 2 = 39 remainder <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>39 ÷ 2 = 19 remainder <strong>1</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>19 ÷ 2 = 9 remainder <strong>1</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>9 ÷ 2 = 4 remainder <strong>1</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>4 ÷ 2 = 2 remainder <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>2 ÷ 2 = 1 remainder <strong>0</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>1 ÷ 2 = 0 remainder <strong>1</strong> ← MSB</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                  <Typography variant="body2" sx={{ mb: 2 }}>Read remainders from <strong>bottom to top</strong>:</Typography>
                  <Typography variant="h6" sx={{ fontFamily: "monospace", color: "#8b5cf6", fontWeight: 700 }}>
                    156 = 10011100
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                    Verify: 128 + 16 + 8 + 4 = 156 ✓
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Paper>

          {/* Binary to Decimal */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            📗 Binary → Decimal (Addition Method)
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Multiply each bit by its position value and add them all together.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Example: Convert 10110011 to Decimal</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Binary Digit</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>1</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>0</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>1</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>1</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>0</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>0</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>1</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>1</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow>
                    <TableCell>Position Value</TableCell>
                    <TableCell>128</TableCell>
                    <TableCell>64</TableCell>
                    <TableCell>32</TableCell>
                    <TableCell>16</TableCell>
                    <TableCell>8</TableCell>
                    <TableCell>4</TableCell>
                    <TableCell>2</TableCell>
                    <TableCell>1</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Calculation</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>128</TableCell>
                    <TableCell sx={{ color: "#ef4444" }}>0</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>32</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>16</TableCell>
                    <TableCell sx={{ color: "#ef4444" }}>0</TableCell>
                    <TableCell sx={{ color: "#ef4444" }}>0</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>2</TableCell>
                    <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>1</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
            <Typography variant="body1" sx={{ textAlign: "center", fontFamily: "monospace" }}>
              128 + 32 + 16 + 2 + 1 = <Box component="span" sx={{ color: "#22c55e", fontWeight: 700, fontSize: "1.2rem" }}>179</Box>
            </Typography>
          </Paper>

          {/* Hexadecimal Section */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            📕 Hexadecimal (Base-16) - The Shorthand for Binary
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Hex uses 0-9 and A-F. Each hex digit = exactly 4 binary bits (a "nibble"). This makes conversions easy!
          </Typography>

          <TableContainer component={Paper} sx={{ mb: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Decimal</TableCell>
                  <TableCell>0</TableCell><TableCell>1</TableCell><TableCell>2</TableCell><TableCell>3</TableCell>
                  <TableCell>4</TableCell><TableCell>5</TableCell><TableCell>6</TableCell><TableCell>7</TableCell>
                  <TableCell>8</TableCell><TableCell>9</TableCell><TableCell>10</TableCell><TableCell>11</TableCell>
                  <TableCell>12</TableCell><TableCell>13</TableCell><TableCell>14</TableCell><TableCell>15</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>Hex</TableCell>
                  <TableCell>0</TableCell><TableCell>1</TableCell><TableCell>2</TableCell><TableCell>3</TableCell>
                  <TableCell>4</TableCell><TableCell>5</TableCell><TableCell>6</TableCell><TableCell>7</TableCell>
                  <TableCell>8</TableCell><TableCell>9</TableCell><TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>A</TableCell><TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>B</TableCell>
                  <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>C</TableCell><TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>D</TableCell><TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>E</TableCell><TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>F</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700, color: "#22c55e" }}>Binary</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>0000</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>0001</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>0010</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>0011</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>0100</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>0101</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>0110</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>0111</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>1000</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>1001</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>1010</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>1011</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>1100</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>1101</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>1110</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>1111</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>Binary → Hex (Group by 4)</Typography>
                <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
                  <Typography variant="body2" sx={{ mb: 1 }}>Convert: 11001010</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Split into groups of 4:</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}><strong>1100</strong> | <strong>1010</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Look up each group:</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>1100 = 12 = <strong>C</strong></Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>1010 = 10 = <strong>A</strong></Typography>
                  <Typography variant="body2" sx={{ color: "#f59e0b", fontWeight: 700 }}>Answer: 0xCA</Typography>
                </Paper>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>Hex → Binary (Expand each digit)</Typography>
                <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
                  <Typography variant="body2" sx={{ mb: 1 }}>Convert: 0x5F</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Expand each hex digit to 4 bits:</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}><strong>5</strong> = 0101</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}><strong>F</strong> = 15 = 1111</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Combine:</Typography>
                  <Typography variant="body2" sx={{ color: "#22c55e", fontWeight: 700 }}>Answer: 01011111</Typography>
                </Paper>
              </Paper>
            </Grid>
          </Grid>

          {/* Real World Examples */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🌐 Real-World Applications</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, borderRadius: 2, borderLeft: "4px solid #0ea5e9" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9" }}>MAC Addresses</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>AA:BB:CC:DD:EE:FF</Typography>
                <Typography variant="caption" color="text.secondary">6 octets in hexadecimal (48 bits total)</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, borderRadius: 2, borderLeft: "4px solid #f59e0b" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>IPv6 Addresses</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1, fontSize: "0.75rem" }}>2001:0db8:85a3::8a2e</Typography>
                <Typography variant="caption" color="text.secondary">128 bits in hexadecimal (8 groups of 16 bits)</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, borderRadius: 2, borderLeft: "4px solid #8b5cf6" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Unix Permissions</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>chmod 755</Typography>
                <Typography variant="caption" color="text.secondary">rwxr-xr-x in octal (7=rwx, 5=r-x)</Typography>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="warning" sx={{ mt: 3 }}>
            <Typography variant="body2">
              <strong>Practice Makes Perfect!</strong> Try converting IP octets like 192 (11000000), 168 (10101000), 
              and subnet masks like 255 (11111111), 240 (11110000), 224 (11100000). Use the calculator above to verify!
            </Typography>
          </Alert>
        </Paper>

        {/* Chapter 2: IP Address Structure */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03) }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
            📖 Chapter 2: IP Address Structure
          </Typography>

          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            An IPv4 address is a 32-bit number divided into 4 octets (8 bits each), separated by dots.
          </Typography>

          <Paper sx={{ p: 3, mb: 3, bgcolor: "background.default", borderRadius: 2, textAlign: "center" }}>
            <Typography variant="h6" sx={{ fontFamily: "monospace", mb: 2 }}>
              <Box component="span" sx={{ color: "#ef4444" }}>192</Box>.
              <Box component="span" sx={{ color: "#f59e0b" }}>168</Box>.
              <Box component="span" sx={{ color: "#22c55e" }}>1</Box>.
              <Box component="span" sx={{ color: "#0ea5e9" }}>100</Box>
            </Typography>
            <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
              <Box component="span" sx={{ color: "#ef4444" }}>11000000</Box>.
              <Box component="span" sx={{ color: "#f59e0b" }}>10101000</Box>.
              <Box component="span" sx={{ color: "#22c55e" }}>00000001</Box>.
              <Box component="span" sx={{ color: "#0ea5e9" }}>01100100</Box>
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
              Each octet can be 0-255 (8 bits = 2⁸ = 256 possible values)
            </Typography>
          </Paper>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Network Portion</Typography>
                <Typography variant="body2" color="text.secondary">
                  Identifies which network the device belongs to. Like a street name - all houses on the same street share it.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>Host Portion</Typography>
                <Typography variant="body2" color="text.secondary">
                  Identifies the specific device on that network. Like a house number - unique to each house on the street.
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* Chapter 3: Subnet Masks Explained */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03) }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            📖 Chapter 3: Subnet Masks Explained
          </Typography>

          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>What is a Subnet Mask?</strong> It's a 32-bit number that tells us which part of the IP is the network 
              and which part is the host. The mask has 1s for network bits and 0s for host bits!
            </Typography>
          </Alert>

          <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>Common Subnet Masks:</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>CIDR</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Decimal Mask</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Binary (Last Octet)</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Network Bits</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Host Bits</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { cidr: "/24", mask: "255.255.255.0", binary: "00000000", netBits: "24", hostBits: "8" },
                  { cidr: "/25", mask: "255.255.255.128", binary: "10000000", netBits: "25", hostBits: "7" },
                  { cidr: "/26", mask: "255.255.255.192", binary: "11000000", netBits: "26", hostBits: "6" },
                  { cidr: "/27", mask: "255.255.255.224", binary: "11100000", netBits: "27", hostBits: "5" },
                  { cidr: "/28", mask: "255.255.255.240", binary: "11110000", netBits: "28", hostBits: "4" },
                  { cidr: "/29", mask: "255.255.255.248", binary: "11111000", netBits: "29", hostBits: "3" },
                  { cidr: "/30", mask: "255.255.255.252", binary: "11111100", netBits: "30", hostBits: "2" },
                ].map((row) => (
                  <TableRow key={row.cidr}>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 700, color: "#f59e0b" }}>{row.cidr}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace" }}>{row.mask}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.binary}</TableCell>
                    <TableCell sx={{ color: "#ef4444", fontWeight: 600 }}>{row.netBits}</TableCell>
                    <TableCell sx={{ color: "#0ea5e9", fontWeight: 600 }}>{row.hostBits}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="body2">
              <strong>The Pattern:</strong> Subnet mask values are always: 128, 192, 224, 240, 248, 252, 254, 255.
              These come from turning on bits left to right: 10000000, 11000000, 11100000, etc.
            </Typography>
          </Alert>
        </Paper>

        {/* Chapter 4: Finding Network Address */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            📖 Chapter 4: Finding the Network Address (AND Operation)
          </Typography>

          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            To find the network address, perform a binary AND operation between the IP and subnet mask.
            AND means: 1 AND 1 = 1, anything else = 0.
          </Typography>

          <Paper sx={{ p: 3, mb: 3, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
            <Typography variant="body2" sx={{ mb: 2, fontWeight: 700 }}>Example: Find network for 192.168.1.100/26</Typography>
            <Grid container spacing={1}>
              <Grid item xs={12}>
                <Typography variant="body2" sx={{ mb: 0.5 }}>IP Address:    192.168.1.<Box component="span" sx={{ color: "#0ea5e9" }}>100</Box></Typography>
                <Typography variant="body2" sx={{ mb: 0.5, fontSize: "0.8rem", color: "text.secondary" }}>Binary:        11000000.10101000.00000001.<Box component="span" sx={{ color: "#0ea5e9" }}>01100100</Box></Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="body2" sx={{ mb: 0.5 }}>Subnet Mask:   255.255.255.<Box component="span" sx={{ color: "#f59e0b" }}>192</Box></Typography>
                <Typography variant="body2" sx={{ mb: 0.5, fontSize: "0.8rem", color: "text.secondary" }}>Binary:        11111111.11111111.11111111.<Box component="span" sx={{ color: "#f59e0b" }}>11000000</Box></Typography>
              </Grid>
              <Grid item xs={12}>
                <Divider sx={{ my: 1 }} />
                <Typography variant="body2" sx={{ mb: 0.5 }}>AND Result:    192.168.1.<Box component="span" sx={{ color: "#22c55e", fontWeight: 700 }}>64</Box></Typography>
                <Typography variant="body2" sx={{ fontSize: "0.8rem", color: "text.secondary" }}>Binary:        11000000.10101000.00000001.<Box component="span" sx={{ color: "#22c55e" }}>01000000</Box></Typography>
              </Grid>
            </Grid>
            <Alert severity="success" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>Network Address:</strong> 192.168.1.64/26
              </Typography>
            </Alert>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>The Quick Method (No Binary!):</Typography>
          <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
            <Typography variant="body2" sx={{ mb: 1 }}>1. Find the "magic number": 256 - subnet mask value = block size</Typography>
            <Typography variant="body2" sx={{ mb: 1 }}>2. For /26 (255.255.255.192): 256 - 192 = <strong>64</strong></Typography>
            <Typography variant="body2" sx={{ mb: 1 }}>3. Networks start at multiples of 64: 0, 64, 128, 192</Typography>
            <Typography variant="body2" sx={{ color: "#22c55e" }}>4. 100 falls between 64 and 128, so network is <strong>192.168.1.64</strong></Typography>
          </Paper>
        </Paper>

        {/* Chapter 5: Complete Subnet Calculation */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            📖 Chapter 5: Complete Subnet Calculation Walkthrough
          </Typography>

          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Let's calculate everything for the subnet containing 10.20.30.40/27
          </Typography>

          <Accordion defaultExpanded sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>Step 1: Gather Information</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
                <Typography variant="body2">IP Address: 10.20.30.40</Typography>
                <Typography variant="body2">CIDR: /27</Typography>
                <Typography variant="body2">Subnet Mask: 255.255.255.224</Typography>
                <Typography variant="body2">Host bits: 32 - 27 = 5</Typography>
                <Typography variant="body2">Block size: 256 - 224 = 32</Typography>
              </Paper>
            </AccordionDetails>
          </Accordion>

          <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>Step 2: Find Network Address</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
                <Typography variant="body2">Block size is 32</Typography>
                <Typography variant="body2">Subnets start at: 0, 32, 64, 96, 128, 160, 192, 224</Typography>
                <Typography variant="body2">40 is between 32 and 64</Typography>
                <Typography variant="body2" sx={{ color: "#22c55e", fontWeight: 700 }}>Network Address: 10.20.30.32</Typography>
              </Paper>
            </AccordionDetails>
          </Accordion>

          <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>Step 3: Find Broadcast Address</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
                <Typography variant="body2">Next network starts at: 32 + 32 = 64</Typography>
                <Typography variant="body2">Broadcast = Next network - 1</Typography>
                <Typography variant="body2" sx={{ color: "#8b5cf6", fontWeight: 700 }}>Broadcast Address: 10.20.30.63</Typography>
              </Paper>
            </AccordionDetails>
          </Accordion>

          <Accordion sx={{ mb: 2, borderRadius: "8px !important", "&:before": { display: "none" } }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>Step 4: Find Usable Host Range</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace" }}>
                <Typography variant="body2">First usable = Network + 1 = 10.20.30.33</Typography>
                <Typography variant="body2">Last usable = Broadcast - 1 = 10.20.30.62</Typography>
                <Typography variant="body2">Total usable hosts = 2^5 - 2 = 30</Typography>
                <Typography variant="body2" sx={{ color: "#0ea5e9", fontWeight: 700 }}>Host Range: 10.20.30.33 - 10.20.30.62</Typography>
              </Paper>
            </AccordionDetails>
          </Accordion>

          <Alert severity="success" sx={{ mt: 2 }}>
            <AlertTitle>Complete Answer for 10.20.30.40/27:</AlertTitle>
            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
              Network: 10.20.30.32 | First Host: 10.20.30.33 | Last Host: 10.20.30.62 | Broadcast: 10.20.30.63 | Usable: 30 hosts
            </Typography>
          </Alert>
        </Paper>

        {/* Chapter 6: VLSM */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#06b6d4", 0.03) }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            📖 Chapter 6: Variable Length Subnet Masking (VLSM)
          </Typography>

          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            VLSM allows you to use different subnet masks in the same network to efficiently allocate IP addresses.
            Always start with the largest subnet requirement first!
          </Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Scenario:</strong> You have 192.168.1.0/24 and need:
              <br/>• Department A: 100 hosts
              <br/>• Department B: 50 hosts  
              <br/>• Department C: 25 hosts
              <br/>• Point-to-point links: 2 hosts each (x2)
            </Typography>
          </Alert>

          <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Department</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Hosts Needed</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Subnet Size</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>CIDR</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Network Address</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Usable Range</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { dept: "Dept A", needed: "100", size: "/25 (126)", cidr: "/25", network: "192.168.1.0", range: ".1 - .126" },
                  { dept: "Dept B", needed: "50", size: "/26 (62)", cidr: "/26", network: "192.168.1.128", range: ".129 - .190" },
                  { dept: "Dept C", needed: "25", size: "/27 (30)", cidr: "/27", network: "192.168.1.192", range: ".193 - .222" },
                  { dept: "Link 1", needed: "2", size: "/30 (2)", cidr: "/30", network: "192.168.1.224", range: ".225 - .226" },
                  { dept: "Link 2", needed: "2", size: "/30 (2)", cidr: "/30", network: "192.168.1.228", range: ".229 - .230" },
                ].map((row) => (
                  <TableRow key={row.dept}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.dept}</TableCell>
                    <TableCell>{row.needed}</TableCell>
                    <TableCell sx={{ color: "#06b6d4" }}>{row.size}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 600 }}>{row.cidr}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace" }}>{row.network}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.range}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </Paper>

      {/* ========== INTERACTIVE SUBNET CALCULATOR ========== */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: "linear-gradient(135deg, rgba(34,197,94,0.08) 0%, rgba(6,182,212,0.08) 100%)", border: "3px solid", borderColor: alpha("#22c55e", 0.4) }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <NetworkCheckIcon sx={{ fontSize: 40, color: "#22c55e" }} />
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 800, color: "#22c55e" }}>
              🧮 Interactive Subnet Calculator
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Enter any IP address and CIDR to instantly calculate all subnet details!
            </Typography>
          </Box>
        </Box>

        {/* Input Section */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
          <Grid container spacing={3} alignItems="center">
            <Grid item xs={12} md={5}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>IP Address:</Typography>
              <TextField
                fullWidth
                value={subnetIP}
                onChange={(e) => setSubnetIP(e.target.value)}
                placeholder="192.168.1.100"
                error={!!subnetError}
                sx={{ 
                  "& .MuiInputBase-input": { fontFamily: "monospace", fontSize: "1.2rem", fontWeight: 600 }
                }}
              />
              <Box sx={{ display: "flex", gap: 1, mt: 1, flexWrap: "wrap" }}>
                {["192.168.1.100", "10.0.0.50", "172.16.45.200", "8.8.8.8"].map((example) => (
                  <Chip
                    key={example}
                    label={example}
                    size="small"
                    clickable
                    onClick={() => setSubnetIP(example)}
                    sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}
                  />
                ))}
              </Box>
            </Grid>
            <Grid item xs={12} md={5}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                CIDR Prefix: <Box component="span" sx={{ color: "#22c55e", fontFamily: "monospace" }}>/{subnetCIDR}</Box>
              </Typography>
              <Slider
                value={subnetCIDR}
                onChange={(_, value) => setSubnetCIDR(value as number)}
                min={0}
                max={32}
                marks={[
                  { value: 8, label: "/8" },
                  { value: 16, label: "/16" },
                  { value: 24, label: "/24" },
                  { value: 32, label: "/32" },
                ]}
                sx={{ color: "#22c55e" }}
              />
              <Box sx={{ display: "flex", gap: 1, mt: 1, flexWrap: "wrap" }}>
                {[8, 16, 20, 24, 26, 27, 28, 30].map((cidr) => (
                  <Chip
                    key={cidr}
                    label={`/${cidr}`}
                    size="small"
                    clickable
                    onClick={() => setSubnetCIDR(cidr)}
                    variant={subnetCIDR === cidr ? "filled" : "outlined"}
                    color={subnetCIDR === cidr ? "success" : "default"}
                    sx={{ fontFamily: "monospace" }}
                  />
                ))}
              </Box>
            </Grid>
            <Grid item xs={12} md={2}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#22c55e", 0.1), borderRadius: 2 }}>
                <Typography variant="caption" color="text.secondary">Network Bits</Typography>
                <Typography variant="h4" sx={{ fontWeight: 800, color: "#22c55e" }}>{subnetCIDR}</Typography>
                <Typography variant="caption" color="text.secondary">Host Bits: {32 - subnetCIDR}</Typography>
              </Paper>
            </Grid>
          </Grid>
          {subnetError && (
            <Alert severity="error" sx={{ mt: 2 }}>{subnetError}</Alert>
          )}
        </Paper>

        {/* Results Section */}
        {subnetResults && (
          <>
            {/* Main Results Grid */}
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, borderLeft: "4px solid #ef4444", height: "100%" }}>
                  <Typography variant="caption" color="text.secondary">Network Address</Typography>
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <Typography variant="h5" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#ef4444" }}>
                      {subnetResults.networkAddress}
                    </Typography>
                    <Tooltip title="Copy">
                      <IconButton size="small" onClick={() => copyToClipboard(subnetResults.networkAddress)}>
                        <ContentCopyIcon sx={{ fontSize: 16 }} />
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary", fontSize: "0.65rem" }}>
                    Binary: {subnetResults.binaryNetwork}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, borderLeft: "4px solid #8b5cf6", height: "100%" }}>
                  <Typography variant="caption" color="text.secondary">Broadcast Address</Typography>
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <Typography variant="h5" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#8b5cf6" }}>
                      {subnetResults.broadcastAddress}
                    </Typography>
                    <Tooltip title="Copy">
                      <IconButton size="small" onClick={() => copyToClipboard(subnetResults.broadcastAddress)}>
                        <ContentCopyIcon sx={{ fontSize: 16 }} />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, borderLeft: "4px solid #22c55e", height: "100%" }}>
                  <Typography variant="caption" color="text.secondary">First Usable Host</Typography>
                  <Typography variant="h6" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#22c55e" }}>
                    {subnetResults.firstHost}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, borderLeft: "4px solid #22c55e", height: "100%" }}>
                  <Typography variant="caption" color="text.secondary">Last Usable Host</Typography>
                  <Typography variant="h6" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#22c55e" }}>
                    {subnetResults.lastHost}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Masks and Host Count */}
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#0ea5e9", 0.05), textAlign: "center" }}>
                  <Typography variant="caption" color="text.secondary">Subnet Mask</Typography>
                  <Typography variant="h6" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#0ea5e9" }}>
                    {subnetResults.subnetMask}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), textAlign: "center" }}>
                  <Typography variant="caption" color="text.secondary">Wildcard Mask</Typography>
                  <Typography variant="h6" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#f59e0b" }}>
                    {subnetResults.wildcardMask}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1), textAlign: "center" }}>
                  <Typography variant="caption" color="text.secondary">Usable Hosts</Typography>
                  <Typography variant="h5" sx={{ fontWeight: 800, color: "#22c55e" }}>
                    {subnetResults.usableHosts.toLocaleString()}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), textAlign: "center" }}>
                  <Typography variant="caption" color="text.secondary">Total Addresses</Typography>
                  <Typography variant="h5" sx={{ fontWeight: 800, color: "#8b5cf6" }}>
                    {subnetResults.totalHosts.toLocaleString()}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Binary Visualization */}
            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🔢 Binary Breakdown</Typography>
              
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>IP Address in Binary:</Typography>
                <Typography sx={{ fontFamily: "monospace", fontSize: "0.9rem", letterSpacing: "0.5px" }}>
                  {subnetResults.binaryIP.split(".").map((octet, idx) => (
                    <Box component="span" key={idx}>
                      <Box component="span" sx={{ color: idx < Math.floor(subnetCIDR / 8) ? "#ef4444" : idx === Math.floor(subnetCIDR / 8) ? "#f59e0b" : "#22c55e" }}>
                        {octet}
                      </Box>
                      {idx < 3 && <Box component="span" sx={{ color: "text.secondary" }}>.</Box>}
                    </Box>
                  ))}
                </Typography>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>Subnet Mask in Binary:</Typography>
                <Typography sx={{ fontFamily: "monospace", fontSize: "0.9rem", letterSpacing: "0.5px" }}>
                  {subnetResults.binaryMask.split(".").map((octet, idx) => (
                    <Box component="span" key={idx}>
                      <Box component="span" sx={{ color: octet === "11111111" ? "#ef4444" : octet === "00000000" ? "#22c55e" : "#f59e0b" }}>
                        {octet}
                      </Box>
                      {idx < 3 && <Box component="span" sx={{ color: "text.secondary" }}>.</Box>}
                    </Box>
                  ))}
                </Typography>
              </Box>

              <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                <Chip 
                  icon={<CheckCircleIcon />}
                  label={`Network Bits: ${subnetResults.networkBits}`} 
                  sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} 
                />
                <Chip 
                  icon={<CheckCircleIcon />}
                  label={`Host Bits: ${subnetResults.hostBits}`} 
                  sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} 
                />
                <Chip 
                  label={`Class: ${subnetResults.ipClass}`} 
                  sx={{ bgcolor: alpha("#0ea5e9", 0.1), color: "#0ea5e9" }} 
                />
                <Chip 
                  label={subnetResults.isPrivate ? "🔒 Private IP" : "🌐 Public IP"} 
                  sx={{ bgcolor: subnetResults.isPrivate ? alpha("#22c55e", 0.1) : alpha("#f59e0b", 0.1) }} 
                />
              </Box>
            </Paper>

            {/* Visual Network Range */}
            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "background.default" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📊 Network Range Visualization</Typography>
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="caption" sx={{ color: "#ef4444" }}>Network: {subnetResults.networkAddress}</Typography>
                  <Typography variant="caption" sx={{ color: "#8b5cf6" }}>Broadcast: {subnetResults.broadcastAddress}</Typography>
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={100}
                  sx={{ 
                    height: 24, 
                    borderRadius: 2,
                    bgcolor: alpha("#22c55e", 0.2),
                    "& .MuiLinearProgress-bar": {
                      background: "linear-gradient(90deg, #ef4444 2%, #22c55e 5%, #22c55e 95%, #8b5cf6 98%)",
                      borderRadius: 2,
                    }
                  }}
                />
                <Box sx={{ display: "flex", justifyContent: "space-between", mt: 1 }}>
                  <Typography variant="caption" color="text.secondary">↑ Reserved</Typography>
                  <Typography variant="caption" sx={{ color: "#22c55e", fontWeight: 600 }}>
                    {subnetResults.usableHosts.toLocaleString()} usable hosts
                  </Typography>
                  <Typography variant="caption" color="text.secondary">Reserved ↑</Typography>
                </Box>
              </Box>

              {/* CIDR Notation Summary */}
              <Alert severity="success" sx={{ mt: 2 }}>
                <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                  <strong>{subnetResults.networkAddress}/{subnetCIDR}</strong> = Network with {subnetResults.usableHosts.toLocaleString()} usable hosts 
                  ({subnetResults.firstHost} to {subnetResults.lastHost})
                </Typography>
              </Alert>
            </Paper>
          </>
        )}
      </Paper>

      {/* ========== SUBNET REFERENCE TABLE ========== */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: "linear-gradient(135deg, rgba(139,92,246,0.08) 0%, rgba(6,182,212,0.08) 100%)", border: "2px solid", borderColor: alpha("#8b5cf6", 0.3) }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 2, color: "#8b5cf6" }}>
          📋 Complete Subnet Reference Table
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
          Quick reference for all IPv4 CIDR notations - essential for exams and network design!
        </Typography>

        <TableContainer component={Paper} sx={{ borderRadius: 3, maxHeight: 500 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>CIDR</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Subnet Mask</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Wildcard</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Block Size</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Total IPs</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Usable Hosts</TableCell>
                <TableCell sx={{ fontWeight: 700, bgcolor: "background.paper" }}>Class</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                { cidr: "/8", mask: "255.0.0.0", wild: "0.255.255.255", block: "16,777,216", total: "16,777,216", usable: "16,777,214", class: "A" },
                { cidr: "/9", mask: "255.128.0.0", wild: "0.127.255.255", block: "8,388,608", total: "8,388,608", usable: "8,388,606", class: "A" },
                { cidr: "/10", mask: "255.192.0.0", wild: "0.63.255.255", block: "4,194,304", total: "4,194,304", usable: "4,194,302", class: "A" },
                { cidr: "/11", mask: "255.224.0.0", wild: "0.31.255.255", block: "2,097,152", total: "2,097,152", usable: "2,097,150", class: "A" },
                { cidr: "/12", mask: "255.240.0.0", wild: "0.15.255.255", block: "1,048,576", total: "1,048,576", usable: "1,048,574", class: "A" },
                { cidr: "/13", mask: "255.248.0.0", wild: "0.7.255.255", block: "524,288", total: "524,288", usable: "524,286", class: "A" },
                { cidr: "/14", mask: "255.252.0.0", wild: "0.3.255.255", block: "262,144", total: "262,144", usable: "262,142", class: "A" },
                { cidr: "/15", mask: "255.254.0.0", wild: "0.1.255.255", block: "131,072", total: "131,072", usable: "131,070", class: "A" },
                { cidr: "/16", mask: "255.255.0.0", wild: "0.0.255.255", block: "65,536", total: "65,536", usable: "65,534", class: "B" },
                { cidr: "/17", mask: "255.255.128.0", wild: "0.0.127.255", block: "32,768", total: "32,768", usable: "32,766", class: "B" },
                { cidr: "/18", mask: "255.255.192.0", wild: "0.0.63.255", block: "16,384", total: "16,384", usable: "16,382", class: "B" },
                { cidr: "/19", mask: "255.255.224.0", wild: "0.0.31.255", block: "8,192", total: "8,192", usable: "8,190", class: "B" },
                { cidr: "/20", mask: "255.255.240.0", wild: "0.0.15.255", block: "4,096", total: "4,096", usable: "4,094", class: "B" },
                { cidr: "/21", mask: "255.255.248.0", wild: "0.0.7.255", block: "2,048", total: "2,048", usable: "2,046", class: "B" },
                { cidr: "/22", mask: "255.255.252.0", wild: "0.0.3.255", block: "1,024", total: "1,024", usable: "1,022", class: "B" },
                { cidr: "/23", mask: "255.255.254.0", wild: "0.0.1.255", block: "512", total: "512", usable: "510", class: "B" },
                { cidr: "/24", mask: "255.255.255.0", wild: "0.0.0.255", block: "256", total: "256", usable: "254", class: "C" },
                { cidr: "/25", mask: "255.255.255.128", wild: "0.0.0.127", block: "128", total: "128", usable: "126", class: "C" },
                { cidr: "/26", mask: "255.255.255.192", wild: "0.0.0.63", block: "64", total: "64", usable: "62", class: "C" },
                { cidr: "/27", mask: "255.255.255.224", wild: "0.0.0.31", block: "32", total: "32", usable: "30", class: "C" },
                { cidr: "/28", mask: "255.255.255.240", wild: "0.0.0.15", block: "16", total: "16", usable: "14", class: "C" },
                { cidr: "/29", mask: "255.255.255.248", wild: "0.0.0.7", block: "8", total: "8", usable: "6", class: "C" },
                { cidr: "/30", mask: "255.255.255.252", wild: "0.0.0.3", block: "4", total: "4", usable: "2", class: "C" },
                { cidr: "/31", mask: "255.255.255.254", wild: "0.0.0.1", block: "2", total: "2", usable: "2*", class: "P2P" },
                { cidr: "/32", mask: "255.255.255.255", wild: "0.0.0.0", block: "1", total: "1", usable: "1*", class: "Host" },
              ].map((row, idx) => (
                <TableRow 
                  key={row.cidr} 
                  sx={{ 
                    bgcolor: idx % 2 === 0 ? "transparent" : alpha("#8b5cf6", 0.02),
                    cursor: "pointer",
                    "&:hover": { bgcolor: alpha("#8b5cf6", 0.08) }
                  }}
                  onClick={() => setSubnetCIDR(parseInt(row.cidr.slice(1)))}
                >
                  <TableCell sx={{ fontFamily: "monospace", fontWeight: 700, color: "#8b5cf6" }}>{row.cidr}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.mask}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "text.secondary" }}>{row.wild}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.block}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.total}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#22c55e", fontWeight: 600 }}>{row.usable}</TableCell>
                  <TableCell><Chip label={row.class} size="small" sx={{ fontSize: "0.65rem" }} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 2 }}>
          💡 Click any row to load that CIDR into the calculator above! | * /31 and /32 are special cases
        </Typography>
      </Paper>

      {/* ========== ADVANCED NETWORKING TOOLS SECTION ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 6, scrollMarginTop: 96 }} id="interactive-tools">
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>ADVANCED NETWORKING TOOLS</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
        🛠️ Interactive Network Planning Tools
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
        Professional-grade calculators and tools for network design, planning, and troubleshooting
      </Typography>

      {/* VLSM Calculator */}
      <VLSMCalculator theme={theme} alpha={alpha} />

      {/* Network Planner Tool */}
      <NetworkPlannerTool theme={theme} alpha={alpha} />

      {/* Bandwidth Calculator */}
      <BandwidthCalculator theme={theme} alpha={alpha} />

      {/* IP Range Checker */}
      <IPRangeChecker theme={theme} alpha={alpha} ipToNumber={ipToNumber} numberToIP={numberToIP} />

      {/* Subnet Practice Quiz Generator */}
      <SubnetPracticeQuiz theme={theme} alpha={alpha} />

      {/* MAC Address Analyzer */}
      <MACAddressAnalyzer theme={theme} alpha={alpha} />

      {/* IPv6 Tools */}
      <IPv6Tools theme={theme} alpha={alpha} />

      {/* Latency Calculator */}
      <LatencyCalculator theme={theme} alpha={alpha} />

      {/* Protocols Section */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, scrollMarginTop: 96 }} id="protocols-ports">
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>PROTOCOLS & PORTS</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        🔌 Common Protocols & Ports
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Essential protocols, their default ports, and security considerations
      </Typography>

      <TableContainer component={Paper} sx={{ mb: 4, borderRadius: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
              <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Port(s)</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Layer</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Security Note</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {protocols.map((p) => (
              <TableRow key={p.name}>
                <TableCell sx={{ fontWeight: 600 }}>{p.name}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", color: "#3b82f6", fontWeight: 600 }}>{p.port}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem" }}>{p.layer}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem" }}>{p.description}</TableCell>
                <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{p.security}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* TCP vs UDP */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
        TCP vs UDP: Transport Layer Protocols
      </Typography>

      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#06b6d4", 0.02) }}>
        <Typography variant="body2" paragraph>
          At the Transport Layer (Layer 4), two primary protocols handle how data moves between applications: TCP (Transmission Control Protocol) and UDP (User Datagram Protocol). Choosing between them is a fundamental network design decision that affects reliability, speed, and application behavior.
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, height: "100%", bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>
                ✅ TCP (Transmission Control Protocol)
              </Typography>
              <Typography variant="body2" paragraph>
                TCP is <strong>connection-oriented</strong> and <strong>reliable</strong>. It guarantees that data arrives in order, without errors, and without duplication. This reliability comes at the cost of overhead and latency.
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>Key Features:</Typography>
              <Box component="ul" sx={{ pl: 2, mt: 0, fontSize: "0.85rem", "& li": { mb: 0.5 } }}>
                <li>Connection establishment (3-way handshake)</li>
                <li>Sequence numbers for ordering</li>
                <li>Acknowledgments (ACKs) for delivery confirmation</li>
                <li>Retransmission of lost packets</li>
                <li>Flow control (prevents overwhelming receiver)</li>
                <li>Congestion control (adjusts to network conditions)</li>
              </Box>
              <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mt: 1, mb: 0.5 }}>Best For:</Typography>
              <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>
                HTTP/HTTPS, Email (SMTP/IMAP), File Transfers (FTP), SSH, Database Connections
              </Typography>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, height: "100%", bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>
                ⚡ UDP (User Datagram Protocol)
              </Typography>
              <Typography variant="body2" paragraph>
                UDP is <strong>connectionless</strong> and <strong>unreliable</strong> (best-effort delivery). It sends data without establishing a connection, doesn't guarantee delivery, and doesn't preserve order. The trade-off is minimal overhead and low latency.
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>Key Features:</Typography>
              <Box component="ul" sx={{ pl: 2, mt: 0, fontSize: "0.85rem", "& li": { mb: 0.5 } }}>
                <li>No connection setup (just send)</li>
                <li>No acknowledgments or retransmissions</li>
                <li>No ordering guarantees</li>
                <li>Minimal header overhead (8 bytes vs TCP's 20+ bytes)</li>
                <li>Application handles reliability if needed</li>
                <li>Supports broadcast and multicast</li>
              </Box>
              <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mt: 1, mb: 0.5 }}>Best For:</Typography>
              <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>
                DNS Queries, Live Streaming, VoIP, Online Gaming, IoT Sensors, DHCP, SNMP
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        <Alert severity="info" sx={{ mt: 3 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>When to Choose Which?</AlertTitle>
          <Typography variant="body2">
            <strong>Use TCP</strong> when data integrity is critical - every byte must arrive correctly (web pages, file downloads, emails).
            <strong> Use UDP</strong> when speed matters more than perfect accuracy - losing a video frame or voice packet is acceptable if it keeps the stream smooth.
          </Typography>
        </Alert>
      </Paper>

      {/* TCP 3-Way Handshake Image */}
      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, background: alpha("#22c55e", 0.03) }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
          🤝 TCP 3-Way Handshake
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Before any data can be transmitted via TCP, a connection must be established using a three-step process called the 3-way handshake. This synchronizes sequence numbers and ensures both sides are ready:
        </Typography>
        <Box component="ol" sx={{ pl: 3, mb: 2, "& li": { mb: 1 } }}>
          <li><Typography variant="body2"><strong>SYN:</strong> Client sends a SYN (synchronize) packet with an initial sequence number</Typography></li>
          <li><Typography variant="body2"><strong>SYN-ACK:</strong> Server acknowledges with SYN-ACK, sending its own sequence number</Typography></li>
          <li><Typography variant="body2"><strong>ACK:</strong> Client acknowledges the server's sequence number, connection established</Typography></li>
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          After communication ends, TCP gracefully closes the connection with a 4-way handshake (FIN → ACK → FIN → ACK).
        </Typography>
        <Box sx={{ display: "flex", justifyContent: "center" }}>
          <Box
            component="img"
            src="/images/3wayhandshake.jpg"
            alt="TCP 3-Way Handshake Process"
            sx={{
              maxWidth: "100%",
              maxHeight: 350,
              borderRadius: 2,
              boxShadow: "0 4px 16px rgba(0,0,0,0.2)",
              border: "1px solid rgba(255,255,255,0.1)",
            }}
          />
        </Box>
      </Paper>

      <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 700 }}>Feature</TableCell>
              <TableCell sx={{ fontWeight: 700, color: "#22c55e" }}>TCP</TableCell>
              <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>UDP</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {tcpVsUdp.map((row) => (
              <TableRow key={row.feature}>
                <TableCell sx={{ fontWeight: 600 }}>{row.feature}</TableCell>
                <TableCell sx={{ fontSize: "0.85rem" }}>{row.tcp}</TableCell>
                <TableCell sx={{ fontSize: "0.85rem" }}>{row.udp}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Network Devices */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, scrollMarginTop: 96 }} id="devices">
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>INFRASTRUCTURE</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        🖧 Network Devices
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
        Network infrastructure devices operate at different OSI layers and provide varying levels of intelligence, security, and traffic management capabilities.
      </Typography>

      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.02) }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
          Understanding Network Device Intelligence Levels
        </Typography>
        <Typography variant="body2" paragraph>
          As you move up the OSI model, devices become more "intelligent" - they understand more about the data they're handling and can make smarter forwarding decisions:
        </Typography>

        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, height: "100%" }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ec4899" }}>
                Layer 1 - Physical (Hub, Repeater)
              </Typography>
              <Typography variant="body2" sx={{ fontSize: "0.9rem" }}>
                <strong>Dumb devices</strong> that simply amplify and repeat electrical signals. No intelligence - they don't read MAC addresses or IP addresses. They broadcast everything to all ports, creating collision domains. Hubs are largely obsolete, replaced by switches.
              </Typography>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, height: "100%" }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>
                Layer 2 - Data Link (Switch, Bridge)
              </Typography>
              <Typography variant="body2" sx={{ fontSize: "0.9rem" }}>
                <strong>MAC-aware devices</strong> that learn which MAC addresses are connected to which ports. They build MAC address tables and forward frames only to the destination port, reducing collisions. Each port is its own collision domain. Modern switches also support VLANs, port security, and QoS.
              </Typography>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, height: "100%" }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>
                Layer 3 - Network (Router, Layer 3 Switch)
              </Typography>
              <Typography variant="body2" sx={{ fontSize: "0.9rem" }}>
                <strong>IP-aware devices</strong> that make routing decisions based on IP addresses. They connect different networks, maintain routing tables, and determine the best path for packets. Routers create broadcast domains, provide NAT, and can run routing protocols like OSPF, BGP, and EIGRP.
              </Typography>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, height: "100%" }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>
                Layer 4-7 - Higher Layers (Firewall, Load Balancer)
              </Typography>
              <Typography variant="body2" sx={{ fontSize: "0.9rem" }}>
                <strong>Application-aware devices</strong> that understand port numbers, protocols, and even application data. Firewalls inspect packets for security threats. Load balancers distribute traffic across servers based on application health. These devices provide deep packet inspection (DPI) and content-based routing.
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        <Alert severity="warning" sx={{ mt: 3 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>Collision vs Broadcast Domains</AlertTitle>
          <Typography variant="body2">
            <strong>Collision Domain:</strong> Area where data packets can collide. Hubs have one large collision domain. Switches split into separate collision domains per port.
            <br />
            <strong>Broadcast Domain:</strong> Area where broadcast traffic reaches all devices. Switches don't split broadcast domains (unless using VLANs). Routers create separate broadcast domains.
          </Typography>
        </Alert>
      </Paper>

      <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
              <TableCell sx={{ fontWeight: 700 }}>Device</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>OSI Layer</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Function</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Intelligence</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Security</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {networkDevices.map((d) => (
              <TableRow key={d.device}>
                <TableCell sx={{ fontWeight: 600 }}>{d.device}</TableCell>
                <TableCell><Chip label={d.layer} size="small" sx={{ fontSize: "0.7rem" }} /></TableCell>
                <TableCell sx={{ fontSize: "0.85rem" }}>{d.function}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{d.intelligence}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem" }}>{d.security}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* DNS */}
      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 96 }} id="dns">
        🌍 Domain Name System (DNS)
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
        DNS is the "phone book" of the Internet, translating human-readable domain names (like google.com) into machine-readable IP addresses (like 142.250.80.46). Without DNS, you'd need to memorize IP addresses for every website you visit.
      </Typography>

      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.02) }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
          How DNS Works: The Resolution Process
        </Typography>
        <Typography variant="body2" paragraph>
          When you type a URL into your browser, a complex multi-step process happens in milliseconds:
        </Typography>

        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
            Step-by-Step DNS Query Resolution:
          </Typography>
          <Box component="ol" sx={{ pl: 3, "& li": { mb: 2 } }}>
            <li>
              <Typography variant="body2">
                <strong>Browser Cache Check:</strong> Your browser first checks its own cache to see if it recently looked up this domain. If found, it uses the cached IP immediately.
              </Typography>
            </li>
            <li>
              <Typography variant="body2">
                <strong>Operating System Cache:</strong> If not in browser cache, the OS checks its own DNS cache (you can view this with <code>ipconfig /displaydns</code> on Windows or <code>dscacheutil -cachedump -entries Host</code> on macOS).
              </Typography>
            </li>
            <li>
              <Typography variant="body2">
                <strong>Recursive Resolver:</strong> If still not found, your computer queries your configured DNS server (usually provided by your ISP or services like 8.8.8.8 Google DNS, 1.1.1.1 Cloudflare). This is called a "recursive resolver" because it does all the work for you.
              </Typography>
            </li>
            <li>
              <Typography variant="body2">
                <strong>Root Nameserver:</strong> The recursive resolver queries one of the 13 root nameserver clusters (labeled A through M). The root server doesn't know the IP but points to the TLD (Top-Level Domain) server for .com, .org, etc.
              </Typography>
            </li>
            <li>
              <Typography variant="body2">
                <strong>TLD Nameserver:</strong> The resolver then queries the .com TLD server, which points to the authoritative nameserver for the specific domain (e.g., google.com's nameservers).
              </Typography>
            </li>
            <li>
              <Typography variant="body2">
                <strong>Authoritative Nameserver:</strong> Finally, the resolver queries the authoritative nameserver for google.com, which returns the actual IP address.
              </Typography>
            </li>
            <li>
              <Typography variant="body2">
                <strong>Cache and Return:</strong> The recursive resolver caches this result (TTL-based) and returns the IP to your computer, which also caches it.
              </Typography>
            </li>
          </Box>
        </Box>

        <Alert severity="info" sx={{ mb: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>DNS Hierarchy</AlertTitle>
          <Typography variant="body2">
            DNS uses a hierarchical, distributed database. For "www.example.com", it's read right-to-left:
            <strong>.com</strong> (TLD) → <strong>example</strong> (Second-Level Domain) → <strong>www</strong> (subdomain/hostname).
          </Typography>
        </Alert>

        <Typography variant="body2" paragraph>
          <strong>DNS Protocols:</strong> DNS primarily uses <strong>UDP port 53</strong> for queries because it's fast and lightweight. However, DNS switches to <strong>TCP port 53</strong> for zone transfers (AXFR) between nameservers or when responses exceed 512 bytes (though EDNS0 allows larger UDP responses).
        </Typography>

        <Typography variant="body2">
          <strong>TTL (Time To Live):</strong> Each DNS record has a TTL value (in seconds) that tells resolvers how long to cache the result. Short TTLs (60-300s) allow quick changes but increase query load. Long TTLs (3600s-86400s) reduce load but slow down propagation of changes.
        </Typography>
      </Paper>

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
        DNS Record Types
      </Typography>

      <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
              <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {dnsRecords.map((r) => (
              <TableRow key={r.type}>
                <TableCell><Chip label={r.type} size="small" sx={{ fontFamily: "monospace", fontWeight: 700, bgcolor: alpha("#22c55e", 0.15) }} /></TableCell>
                <TableCell sx={{ fontSize: "0.85rem" }}>{r.description}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "text.secondary" }}>{r.example}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* ========== COLLISION DETECTION vs COLLISION AVOIDANCE ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>MEDIA ACCESS CONTROL</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        💥 Collision Detection vs Collision Avoidance
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
        Understanding CSMA/CD and CSMA/CA - how networks manage shared media access
      </Typography>

      <Grid container spacing={4} sx={{ mb: 4 }}>
        {/* CSMA/CD */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, borderRadius: 3, height: "100%", background: alpha("#ef4444", 0.03), border: "2px solid", borderColor: alpha("#ef4444", 0.2) }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              🔌 CSMA/CD (Collision Detection)
            </Typography>
            <Chip label="Wired Networks (Ethernet)" size="small" sx={{ mb: 2, bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
            
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>How It Works:</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, mb: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>1. <strong>Carrier Sense:</strong> Listen to see if the medium is idle</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>2. <strong>Multiple Access:</strong> Multiple devices share the medium</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>3. <strong>Transmit:</strong> If idle, start transmitting while listening</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>4. <strong>Collision Detect:</strong> If collision detected, stop immediately</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>5. <strong>Jam Signal:</strong> Send jam signal to notify all devices</Typography>
              <Typography variant="body2">6. <strong>Random Backoff:</strong> Wait random time, then retry</Typography>
            </Paper>

            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>Key Point:</strong> CSMA/CD can DETECT collisions as they happen because wired connections 
                allow devices to transmit AND receive simultaneously.
              </Typography>
            </Alert>

            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Used In:</Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="10BASE-T" size="small" variant="outlined" />
              <Chip label="100BASE-TX" size="small" variant="outlined" />
              <Chip label="Half-Duplex Ethernet" size="small" variant="outlined" />
              <Chip label="Hubs (Legacy)" size="small" variant="outlined" />
            </Box>

            <Alert severity="warning" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>Modern Note:</strong> Full-duplex switches eliminated collision domains, making CSMA/CD 
                largely obsolete in modern wired networks!
              </Typography>
            </Alert>
          </Paper>
        </Grid>

        {/* CSMA/CA */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, borderRadius: 3, height: "100%", background: alpha("#0ea5e9", 0.03), border: "2px solid", borderColor: alpha("#0ea5e9", 0.2) }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
              📶 CSMA/CA (Collision Avoidance)
            </Typography>
            <Chip label="Wireless Networks (Wi-Fi)" size="small" sx={{ mb: 2, bgcolor: alpha("#0ea5e9", 0.1), color: "#0ea5e9" }} />
            
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>How It Works:</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, mb: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>1. <strong>Carrier Sense:</strong> Listen to see if the medium is idle</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>2. <strong>Wait DIFS:</strong> Wait for Distributed Inter-Frame Space</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>3. <strong>Random Backoff:</strong> Wait random time BEFORE transmitting</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>4. <strong>RTS/CTS (Optional):</strong> Request/Clear to Send handshake</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>5. <strong>Transmit:</strong> Send data after reservation</Typography>
              <Typography variant="body2">6. <strong>ACK:</strong> Wait for acknowledgment, retransmit if no ACK</Typography>
            </Paper>

            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>Key Point:</strong> CSMA/CA tries to AVOID collisions because wireless devices can't 
                detect collisions (can't transmit and receive on same frequency simultaneously).
              </Typography>
            </Alert>

            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Used In:</Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="802.11 Wi-Fi" size="small" variant="outlined" />
              <Chip label="Bluetooth" size="small" variant="outlined" />
              <Chip label="Zigbee" size="small" variant="outlined" />
              <Chip label="All Wireless" size="small" variant="outlined" />
            </Box>

            <Alert severity="success" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>RTS/CTS:</strong> Solves the "hidden node" problem where two devices can't hear each 
                other but both can reach the access point.
              </Typography>
            </Alert>
          </Paper>
        </Grid>
      </Grid>

      {/* Comparison Table */}
      <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          📊 Side-by-Side Comparison
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Feature</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#ef4444" }}>CSMA/CD (Detection)</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#0ea5e9" }}>CSMA/CA (Avoidance)</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                { feature: "Medium Type", cd: "Wired (Ethernet)", ca: "Wireless (Wi-Fi)" },
                { feature: "Collision Handling", cd: "Detect & Stop", ca: "Avoid Before Transmit" },
                { feature: "When Action Taken", cd: "After collision", ca: "Before transmission" },
                { feature: "Can Detect Collisions?", cd: "Yes - full duplex capable", ca: "No - half duplex only" },
                { feature: "Acknowledgments", cd: "Not required", ca: "Required (ACK frames)" },
                { feature: "Backoff Timing", cd: "After collision", ca: "Before transmission" },
                { feature: "RTS/CTS", cd: "Not used", ca: "Optional (hidden node)" },
                { feature: "Efficiency", cd: "High (less overhead)", ca: "Lower (more overhead)" },
                { feature: "Modern Usage", cd: "Obsolete (full-duplex)", ca: "Active (all Wi-Fi)" },
              ].map((row) => (
                <TableRow key={row.feature}>
                  <TableCell sx={{ fontWeight: 600 }}>{row.feature}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{row.cd}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{row.ca}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* How to Spot the Difference */}
      <Paper sx={{ p: 3, mb: 5, borderRadius: 3, background: alpha("#f59e0b", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#f59e0b" }}>
          🔍 How to Spot the Difference (Exam Tips)
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>🔌 It's CSMA/CD if:</Typography>
              <Typography variant="body2">• Question mentions Ethernet or wired</Typography>
              <Typography variant="body2">• Mentions "collision domain"</Typography>
              <Typography variant="body2">• Talks about hubs or half-duplex</Typography>
              <Typography variant="body2">• Mentions "jam signal"</Typography>
              <Typography variant="body2">• Says "detect and retransmit"</Typography>
              <Typography variant="body2">• Uses exponential backoff AFTER collision</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>📶 It's CSMA/CA if:</Typography>
              <Typography variant="body2">• Question mentions wireless or Wi-Fi</Typography>
              <Typography variant="body2">• Mentions 802.11 standard</Typography>
              <Typography variant="body2">• Talks about RTS/CTS frames</Typography>
              <Typography variant="body2">• Mentions "hidden node problem"</Typography>
              <Typography variant="body2">• Says "wait before transmit"</Typography>
              <Typography variant="body2">• Mentions ACK frames or DIFS/SIFS</Typography>
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      {/* ========== ADDITIONAL NETWORKING CONCEPTS ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, scrollMarginTop: 96 }} id="wireless-security">
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>ADDITIONAL CONCEPTS</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      {/* ARP */}
      <Paper sx={{ p: 3, mb: 4, borderRadius: 3, background: alpha("#22c55e", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
          🔗 ARP (Address Resolution Protocol)
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          ARP resolves IP addresses to MAC addresses on a local network. Essential for Layer 2 communication!
        </Typography>
        
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>How ARP Works:</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.85rem" }}>
              <Typography variant="body2">1. Host A wants to send to 192.168.1.5</Typography>
              <Typography variant="body2">2. Host A checks ARP cache - not found</Typography>
              <Typography variant="body2">3. Host A broadcasts: "Who has 192.168.1.5?"</Typography>
              <Typography variant="body2">4. Host B responds: "I'm 192.168.1.5, MAC: AA:BB:CC:DD:EE:FF"</Typography>
              <Typography variant="body2">5. Host A caches the mapping</Typography>
              <Typography variant="body2">6. Host A sends frame to MAC AA:BB:CC:DD:EE:FF</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>ARP Commands:</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.85rem" }}>
              <Typography variant="body2" sx={{ color: "#22c55e" }}>Windows:</Typography>
              <Typography variant="body2">arp -a          # View ARP cache</Typography>
              <Typography variant="body2">arp -d *        # Clear ARP cache</Typography>
              <Typography variant="body2" sx={{ color: "#22c55e", mt: 1 }}>Linux:</Typography>
              <Typography variant="body2">arp -n          # View ARP cache</Typography>
              <Typography variant="body2">ip neigh show   # Modern alternative</Typography>
            </Paper>
            <Alert severity="error" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>Security:</strong> ARP Spoofing/Poisoning allows attackers to intercept traffic. 
                Use Dynamic ARP Inspection (DAI) on switches!
              </Typography>
            </Alert>
          </Grid>
        </Grid>
      </Paper>

      {/* DHCP */}
      <Paper sx={{ p: 3, mb: 4, borderRadius: 3, background: alpha("#0ea5e9", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
          🎯 DHCP (Dynamic Host Configuration Protocol)
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          DHCP automatically assigns IP addresses and network configuration to devices.
        </Typography>
        
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>DHCP DORA Process:</Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[
            { step: "D", name: "Discover", desc: "Client broadcasts to find DHCP server", port: "UDP 67/68" },
            { step: "O", name: "Offer", desc: "Server offers an IP address", port: "Unicast/Broadcast" },
            { step: "R", name: "Request", desc: "Client requests the offered IP", port: "Broadcast" },
            { step: "A", name: "Acknowledge", desc: "Server confirms the lease", port: "Unicast" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.step}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2 }}>
                <Typography variant="h4" sx={{ fontWeight: 800, color: "#0ea5e9" }}>{item.step}</Typography>
                <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>What DHCP Provides:</Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
          <Chip label="IP Address" size="small" sx={{ bgcolor: alpha("#0ea5e9", 0.1) }} />
          <Chip label="Subnet Mask" size="small" sx={{ bgcolor: alpha("#0ea5e9", 0.1) }} />
          <Chip label="Default Gateway" size="small" sx={{ bgcolor: alpha("#0ea5e9", 0.1) }} />
          <Chip label="DNS Servers" size="small" sx={{ bgcolor: alpha("#0ea5e9", 0.1) }} />
          <Chip label="Lease Time" size="small" sx={{ bgcolor: alpha("#0ea5e9", 0.1) }} />
          <Chip label="Domain Name" size="small" sx={{ bgcolor: alpha("#0ea5e9", 0.1) }} />
        </Box>
      </Paper>

      {/* TCP vs UDP Deep Dive */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3, background: alpha("#22c55e", 0.02), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 2, color: "#22c55e" }}>
          🔀 TCP vs UDP: The Transport Layer Battle
        </Typography>

        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            TCP: The Reliable Workhorse of the Internet
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            <strong>Transmission Control Protocol (TCP)</strong> is the foundation of reliable internet communication. When you load a webpage,
            send an email, or download a file, TCP ensures every single byte arrives correctly and in order. TCP is connection-oriented, meaning
            it establishes a virtual circuit between sender and receiver before data transmission begins. This connection is created through the
            famous <strong>three-way handshake</strong>: SYN (synchronize), SYN-ACK (synchronize-acknowledge), and ACK (acknowledge). Only after
            this handshake succeeds does data transfer begin.
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            TCP provides <strong>guaranteed delivery</strong> through acknowledgments and retransmissions. Each TCP segment includes a sequence
            number, and the receiver sends ACKs confirming receipt. If the sender doesn't receive an ACK within a timeout period, it retransmits
            the segment. TCP also implements <strong>flow control</strong> via sliding windows—the receiver advertises how much data it can accept,
            preventing buffer overflow. <strong>Congestion control</strong> algorithms (like TCP Reno, Cubic, BBR) detect network congestion by
            monitoring packet loss and adjust transmission rates accordingly.
          </Typography>
          <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            The cost of this reliability is overhead. Each TCP segment includes a 20-byte header (or more with options), and the acknowledgment
            mechanism introduces latency. For every data packet sent, you must wait for an ACK before sending more (unless using window scaling).
            This makes TCP unsuitable for real-time applications where slight data loss is acceptable but delays are not. Yet for applications
            where correctness matters—web browsing (HTTP/HTTPS), file transfers (FTP/SFTP), email (SMTP/IMAP), and database queries—TCP is
            irreplaceable. Its reliability guarantee means developers can build applications without worrying about lost or out-of-order data.
          </Typography>
        </Paper>

        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            UDP: Speed Over Reliability
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            <strong>User Datagram Protocol (UDP)</strong> takes the opposite approach: it's fast, lightweight, and unreliable. UDP is connectionless—no
            handshake, no acknowledgments, no guaranteed delivery. When you send a UDP datagram, it's fired off into the network with no confirmation
            it will arrive. The UDP header is only 8 bytes (compared to TCP's minimum 20 bytes), containing just source port, destination port,
            length, and an optional checksum. This minimal overhead makes UDP ideal for applications where speed trumps reliability.
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            <strong>Real-time applications</strong> are UDP's domain. Video conferencing (Zoom, Teams), VoIP calls (Skype, WhatsApp), and live
            streaming use UDP because a single lost packet causing a brief audio glitch or video artifact is preferable to the delay TCP retransmission
            would introduce. Online multiplayer games use UDP—if a position update packet is lost, the next packet (arriving milliseconds later)
            makes it irrelevant. <strong>DNS queries</strong> use UDP port 53 because most DNS responses fit in a single datagram, and if it's lost,
            the client simply retries. DHCP, TFTP, and SNMP all choose UDP for similar reasons.
          </Typography>
          <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            Modern protocols like <strong>QUIC</strong> (Quick UDP Internet Connections), used by HTTP/3, implement TCP-like reliability features
            on top of UDP. Why? Because UDP allows protocol innovation without waiting for operating system TCP stack updates. QUIC provides
            multiplexing, encryption, and congestion control while avoiding TCP's head-of-line blocking problem. This demonstrates that UDP's
            simplicity makes it an excellent foundation for building custom transport protocols tailored to specific application needs.
          </Typography>
        </Paper>
      </Paper>

      {/* Routing Protocols */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3, background: alpha("#8b5cf6", 0.02), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 2, color: "#8b5cf6" }}>
          🗺️ Routing Protocols: How the Internet Finds Its Way
        </Typography>

        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            The Routing Problem: Billions of Paths, Milliseconds to Decide
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            When you access a website hosted across the world, your data might traverse 15-20 routers to reach its destination. Each router must
            decide: which interface should I forward this packet through? This decision happens billions of times per second across the global internet.
            <strong>Routing protocols</strong> are the distributed algorithms that build and maintain routing tables—the databases routers consult
            to make forwarding decisions. Without routing protocols, the internet couldn't exist at scale.
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            Routing protocols fall into two categories: <strong>Interior Gateway Protocols (IGPs)</strong> for routing within an organization
            (like RIP, OSPF, EIGRP), and <strong>Exterior Gateway Protocols (EGPs)</strong> for routing between organizations—primarily BGP, which
            glues the entire internet together. They also differ in approach: <strong>distance-vector</strong> protocols (RIP, EIGRP) share routing
            tables with neighbors and calculate best paths based on hop count or composite metrics, while <strong>link-state</strong> protocols
            (OSPF, IS-IS) build a complete topology map and calculate shortest paths using Dijkstra's algorithm.
          </Typography>
          <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            <strong>Convergence time</strong>—how quickly routers agree on topology after a change—is critical. When a link fails, routing protocols
            must detect the failure, propagate updates, recalculate paths, and update forwarding tables. During this convergence period, traffic may
            be dropped or loop. Modern link-state protocols like OSPF converge in seconds, while older distance-vector protocols like RIP could take
            minutes, causing prolonged outages.
          </Typography>
        </Paper>

        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            BGP: The Protocol That Runs the Internet
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            <strong>Border Gateway Protocol (BGP)</strong> is the internet's routing protocol. Every major ISP, cloud provider, and large enterprise
            uses BGP to exchange routing information between <strong>Autonomous Systems (AS)</strong>—independent networks with their own routing
            policies. When you access Google, Facebook, or AWS, BGP determines the path your packets take through dozens of ISPs and transit providers.
            BGP is a path-vector protocol: instead of just advertising destination networks, it advertises the full AS path, preventing routing loops.
          </Typography>
          <Typography paragraph sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            BGP's flexibility is both its strength and weakness. Routing decisions are based on <strong>policy</strong> (business relationships,
            traffic engineering) rather than purely on shortest path. ISPs can prefer certain routes, filter advertisements, or manipulate path
            attributes to influence routing. This policy-based routing enables sophisticated traffic engineering but also creates security risks.
            <strong>BGP hijacking</strong>—maliciously advertising IP prefixes you don't own—has caused major internet outages. In 2008, Pakistan's
            attempt to block YouTube internally resulted in advertising YouTube's IP space to the entire internet, taking YouTube offline globally.
          </Typography>
          <Typography sx={{ fontSize: "0.95rem", lineHeight: 1.8, color: "grey.300" }}>
            Despite being designed in the 1980s with no built-in security, BGP still underpins the modern internet. <strong>RPKI (Resource Public
            Key Infrastructure)</strong> and <strong>BGPsec</strong> are efforts to add cryptographic validation, but adoption remains slow.
            Understanding BGP is essential for network engineers and cybersecurity professionals—many of the internet's largest outages and attacks
            stem from BGP misconfigurations or malicious manipulation.
          </Typography>
        </Paper>
      </Paper>

      {/* Network Troubleshooting */}
      <Paper sx={{ p: 3, mb: 4, borderRadius: 3, background: alpha("#f59e0b", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
          🔧 Network Troubleshooting Methodology
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          A systematic approach to diagnosing network issues - work from Layer 1 up!
        </Typography>

        <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Step</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Layer</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Check</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Tools</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                { step: "1", layer: "Physical (1)", check: "Cables, ports, link lights, power", tools: "Visual inspection, cable tester" },
                { step: "2", layer: "Data Link (2)", check: "MAC address, NIC driver, switch port", tools: "arp -a, ipconfig /all" },
                { step: "3", layer: "Network (3)", check: "IP config, routing, gateway", tools: "ping, traceroute, route print" },
                { step: "4", layer: "Transport (4)", check: "Ports, firewall rules, connectivity", tools: "netstat, telnet, Test-NetConnection" },
                { step: "5", layer: "Application (7)", check: "Service running, DNS, app config", tools: "nslookup, curl, service status" },
              ].map((row) => (
                <TableRow key={row.step}>
                  <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>{row.step}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{row.layer}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{row.check}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.tools}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Alert severity="success">
          <Typography variant="body2">
            <strong>Pro Tip:</strong> Always start with "ping 127.0.0.1" (loopback) to verify TCP/IP stack is working, 
            then ping your IP, then gateway, then external host!
          </Typography>
        </Alert>
      </Paper>

      {/* Network Performance Metrics */}
      <Paper sx={{ p: 3, mb: 5, borderRadius: 3, background: alpha("#8b5cf6", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
          📈 Network Performance Metrics
        </Typography>
        
        <Grid container spacing={3}>
          {[
            { 
              metric: "Bandwidth", 
              desc: "Maximum data transfer rate", 
              unit: "Mbps, Gbps", 
              example: "1 Gbps connection",
              color: "#22c55e"
            },
            { 
              metric: "Throughput", 
              desc: "Actual data transfer rate achieved", 
              unit: "Mbps, Gbps", 
              example: "800 Mbps actual",
              color: "#0ea5e9"
            },
            { 
              metric: "Latency", 
              desc: "Time for data to travel (delay)", 
              unit: "ms (milliseconds)", 
              example: "20ms ping time",
              color: "#f59e0b"
            },
            { 
              metric: "Jitter", 
              desc: "Variation in latency over time", 
              unit: "ms variance", 
              example: "±5ms variation",
              color: "#ef4444"
            },
            { 
              metric: "Packet Loss", 
              desc: "Percentage of lost packets", 
              unit: "% of packets", 
              example: "0.1% loss",
              color: "#8b5cf6"
            },
            { 
              metric: "MTU", 
              desc: "Maximum Transmission Unit size", 
              unit: "bytes", 
              example: "1500 bytes (Ethernet)",
              color: "#06b6d4"
            },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.metric}>
              <Paper sx={{ p: 2, height: "100%", bgcolor: alpha(item.color, 0.05), borderRadius: 2, borderLeft: `4px solid ${item.color}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color }}>{item.metric}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block" }}>Unit: {item.unit}</Typography>
                <Typography variant="caption" color="text.secondary">Ex: {item.example}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Wireless */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>WIRELESS & SECURITY</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        📶 Wireless Standards
      </Typography>

      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={6}>
          <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#0ea5e9", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Standard</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Freq</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Speed</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Year</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {wirelessStandards.map((w) => (
                  <TableRow key={w.standard}>
                    <TableCell sx={{ fontWeight: 600, fontSize: "0.8rem" }}>{w.standard}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem" }}>{w.frequency}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem" }}>{w.maxSpeed}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem" }}>{w.year}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Grid>
        <Grid item xs={12} md={6}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🔒 Wireless Security</Typography>
          <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Security</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Recommendation</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {wirelessSecurity.map((w) => (
                  <TableRow key={w.protocol}>
                    <TableCell sx={{ fontWeight: 600 }}>{w.protocol}</TableCell>
                    <TableCell>
                      <Chip 
                        label={w.security} 
                        size="small" 
                        sx={{ 
                          fontSize: "0.65rem",
                          bgcolor: w.security === "Broken" || w.security === "Weak" ? alpha("#ef4444", 0.15) : 
                                   w.security === "Good" || w.security === "Better" ? alpha("#f59e0b", 0.15) : alpha("#22c55e", 0.15),
                          color: w.security === "Broken" || w.security === "Weak" ? "#ef4444" : 
                                 w.security === "Good" || w.security === "Better" ? "#f59e0b" : "#22c55e",
                        }} 
                      />
                    </TableCell>
                    <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{w.recommendation}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Grid>
      </Grid>

      {/* Network Commands */}
      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 96 }} id="commands">
        ⌨️ Essential Network Commands
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Command-line tools for network troubleshooting and analysis
      </Typography>

      <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
              <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>OS</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {networkCommands.map((c) => (
              <TableRow key={c.command}>
                <TableCell sx={{ fontFamily: "monospace", fontWeight: 600, color: "#f59e0b", fontSize: "0.85rem" }}>{c.command}</TableCell>
                <TableCell sx={{ fontSize: "0.85rem" }}>{c.description}</TableCell>
                <TableCell><Chip label={c.os} size="small" sx={{ fontSize: "0.65rem" }} /></TableCell>
                <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "text.secondary" }}>{c.example}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Additional Topics - VLANs, NAT, IPv6 */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>ADVANCED TOPICS</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      {/* VLANs */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#6366f1", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <HubIcon sx={{ color: "#6366f1" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#6366f1" }}>VLANs (Virtual LANs)</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {vlanConcepts.map((v) => (
              <Grid item xs={12} sm={6} md={4} key={v.concept}>
                <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#6366f1", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#6366f1" }}>{v.concept}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.85rem", mb: 1 }}>{v.description}</Typography>
                  <Typography variant="caption" color="text.secondary">{v.benefit}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* NAT */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ec4899", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <SwapHorizIcon sx={{ color: "#ec4899" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ec4899" }}>NAT (Network Address Translation)</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#ec4899", 0.03), borderRadius: 2 }}>
            <Typography variant="body2" paragraph>
              <strong>NAT (Network Address Translation)</strong> is a critical technology that enables multiple devices on a private network to share a single public IP address when accessing the Internet. It was created to address IPv4 address exhaustion and adds a layer of security by hiding internal network structure.
            </Typography>
            <Typography variant="body2" paragraph>
              <strong>How NAT Works:</strong> When a device on your home network (e.g., 192.168.1.10) sends a request to a website, your router replaces the private source IP with its public IP address and tracks the connection in a NAT translation table. When the response comes back, the router uses the table to forward it to the correct internal device.
            </Typography>
            <Typography variant="body2" paragraph>
              <strong>Why NAT Matters:</strong>
            </Typography>
            <Box component="ul" sx={{ pl: 3, mb: 2, "& li": { mb: 0.5 } }}>
              <li><Typography variant="body2"><strong>IP Conservation:</strong> Millions of devices share far fewer public IPv4 addresses</Typography></li>
              <li><Typography variant="body2"><strong>Security:</strong> Internal network structure is hidden from the Internet</Typography></li>
              <li><Typography variant="body2"><strong>Flexibility:</strong> You can change ISPs without reconfiguring internal devices</Typography></li>
              <li><Typography variant="body2"><strong>Challenges:</strong> Breaks end-to-end connectivity, complicates peer-to-peer apps, requires port forwarding for incoming connections</Typography></li>
            </Box>
          </Paper>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#ec4899", 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {natTypes.map((n) => (
                  <TableRow key={n.type}>
                    <TableCell sx={{ fontWeight: 600, color: "#ec4899" }}>{n.type}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{n.description}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{n.useCase}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* IPv6 */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#14b8a6", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <LanguageIcon sx={{ color: "#14b8a6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#14b8a6" }}>IPv6 Basics</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {ipv6Basics.map((item) => (
              <Grid item xs={12} sm={6} key={item.concept}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6" }}>{item.concept}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.85rem", color: "text.secondary" }}>{item.description}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Topologies */}
      <Accordion sx={{ mb: 5, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f59e0b", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <AccountTreeIcon sx={{ color: "#f59e0b" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>Network Topologies</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          {/* Topology Diagram Image */}
          <Box sx={{ display: "flex", justifyContent: "center", mb: 3 }}>
            <Box
              component="img"
              src="/images/topology.jpg"
              alt="Network Topologies Diagram"
              sx={{
                maxWidth: "100%",
                maxHeight: 350,
                borderRadius: 2,
                boxShadow: "0 4px 16px rgba(0,0,0,0.2)",
                border: "1px solid rgba(255,255,255,0.1)",
              }}
            />
          </Box>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Topology</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Pros</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Cons</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {topologies.map((t) => (
                  <TableRow key={t.name}>
                    <TableCell sx={{ fontWeight: 600, color: "#f59e0b" }}>{t.name}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{t.description}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem", color: "#22c55e" }}>{t.pros}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem", color: "#ef4444" }}>{t.cons}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* ========== CCNA COMMANDS & TERMINOLOGY ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>CCNA CERTIFICATION PREP</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        🎓 CCNA Commands & Terminology
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Cisco IOS commands and networking terminology for CCNA certification preparation
      </Typography>

      <Alert severity="info" sx={{ mb: 4 }}>
        <Typography variant="body2">
          <strong>Note:</strong> This section outlines key CCNA topics and will be expanded with detailed content. 
          Use this as a study guide for the Cisco Certified Network Associate exam.
        </Typography>
      </Alert>

      {/* Cisco IOS Modes */}
      <Accordion defaultExpanded sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#0ea5e9", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <TerminalIcon sx={{ color: "#0ea5e9" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#0ea5e9" }}>Cisco IOS Modes</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#0ea5e9", 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Mode</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Prompt</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Access Command</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { mode: "User EXEC", prompt: "Router>", access: "Login", desc: "Limited monitoring commands" },
                  { mode: "Privileged EXEC", prompt: "Router#", access: "enable", desc: "All show commands, debug, configuration access" },
                  { mode: "Global Config", prompt: "Router(config)#", access: "configure terminal", desc: "Global configuration changes" },
                  { mode: "Interface Config", prompt: "Router(config-if)#", access: "interface [type] [num]", desc: "Configure specific interfaces" },
                  { mode: "Line Config", prompt: "Router(config-line)#", access: "line [type] [num]", desc: "Configure console, VTY, AUX lines" },
                  { mode: "Router Config", prompt: "Router(config-router)#", access: "router [protocol]", desc: "Configure routing protocols" },
                ].map((row) => (
                  <TableRow key={row.mode}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.mode}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", color: "#0ea5e9" }}>{row.prompt}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.access}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem", color: "text.secondary" }}>{row.desc}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* Essential Show Commands */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#22c55e", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <VisibilityIcon sx={{ color: "#22c55e" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>Essential Show Commands</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>General Information</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
                <Typography variant="body2">show running-config</Typography>
                <Typography variant="body2">show startup-config</Typography>
                <Typography variant="body2">show version</Typography>
                <Typography variant="body2">show history</Typography>
                <Typography variant="body2">show flash</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>Interface Commands</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
                <Typography variant="body2">show interfaces</Typography>
                <Typography variant="body2">show ip interface brief</Typography>
                <Typography variant="body2">show interface status</Typography>
                <Typography variant="body2">show interface [interface]</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>Routing Commands</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
                <Typography variant="body2">show ip route</Typography>
                <Typography variant="body2">show ip protocols</Typography>
                <Typography variant="body2">show ip ospf neighbor</Typography>
                <Typography variant="body2">show ip eigrp neighbors</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>Switching Commands</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
                <Typography variant="body2">show mac address-table</Typography>
                <Typography variant="body2">show vlan brief</Typography>
                <Typography variant="body2">show spanning-tree</Typography>
                <Typography variant="body2">show etherchannel summary</Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Basic Configuration Commands */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f59e0b", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <SettingsIcon sx={{ color: "#f59e0b" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>Basic Configuration Commands</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>Device Setup</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
                <Typography variant="body2">hostname [name]</Typography>
                <Typography variant="body2">enable secret [password]</Typography>
                <Typography variant="body2">service password-encryption</Typography>
                <Typography variant="body2">banner motd #message#</Typography>
                <Typography variant="body2">no ip domain-lookup</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>Save & Reset</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
                <Typography variant="body2">copy running-config startup-config</Typography>
                <Typography variant="body2">write memory (wr)</Typography>
                <Typography variant="body2">erase startup-config</Typography>
                <Typography variant="body2">reload</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>Interface Config</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
                <Typography variant="body2">interface [type] [number]</Typography>
                <Typography variant="body2">ip address [ip] [mask]</Typography>
                <Typography variant="body2">no shutdown</Typography>
                <Typography variant="body2">description [text]</Typography>
                <Typography variant="body2">speed [10|100|1000|auto]</Typography>
                <Typography variant="body2">duplex [half|full|auto]</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>Line Configuration</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
                <Typography variant="body2">line console 0</Typography>
                <Typography variant="body2">line vty 0 15</Typography>
                <Typography variant="body2">password [password]</Typography>
                <Typography variant="body2">login</Typography>
                <Typography variant="body2">logging synchronous</Typography>
                <Typography variant="body2">exec-timeout [min] [sec]</Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* CCNA Key Terminology */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#8b5cf6", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <SchoolIcon sx={{ color: "#8b5cf6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>CCNA Key Terminology</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>Routing Concepts</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Administrative Distance (AD)</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Metric</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Autonomous System (AS)</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Default Gateway</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Static vs Dynamic Routing</Typography>
                <Typography variant="body2">• Longest Prefix Match</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>Switching Concepts</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• MAC Address Table</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• VLAN (Virtual LAN)</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Trunk Ports</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Access Ports</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• STP (Spanning Tree Protocol)</Typography>
                <Typography variant="body2">• EtherChannel</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>Security Concepts</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• ACL (Access Control List)</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Port Security</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• AAA (Authentication)</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• DHCP Snooping</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Dynamic ARP Inspection</Typography>
                <Typography variant="body2">• 802.1X</Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Routing Protocols Overview */}
      <Accordion
        id="routing-nat"
        sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 96 }}
      >
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ef4444", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <RouterIcon sx={{ color: "#ef4444" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>Routing Protocols Overview</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#ef4444", 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>AD</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Metric</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { protocol: "Connected", type: "-", ad: "0", metric: "-", notes: "Directly connected networks" },
                  { protocol: "Static", type: "-", ad: "1", metric: "-", notes: "Manually configured routes" },
                  { protocol: "EIGRP", type: "Hybrid", ad: "90/170", metric: "Bandwidth + Delay", notes: "Cisco proprietary (now open)" },
                  { protocol: "OSPF", type: "Link-State", ad: "110", metric: "Cost (bandwidth)", notes: "Open standard, hierarchical" },
                  { protocol: "RIP", type: "Distance Vector", ad: "120", metric: "Hop Count (max 15)", notes: "Simple, limited scalability" },
                  { protocol: "BGP eBGP", type: "Path Vector", ad: "20", metric: "Path Attributes", notes: "Internet routing protocol" },
                  { protocol: "BGP iBGP", type: "Path Vector", ad: "200", metric: "Path Attributes", notes: "Internal AS routing" },
                ].map((row) => (
                  <TableRow key={row.protocol}>
                    <TableCell sx={{ fontWeight: 600, color: "#ef4444" }}>{row.protocol}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.type}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 600 }}>{row.ad}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.metric}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{row.notes}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* Topics to Expand */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#06b6d4", 0.03), border: "1px solid", borderColor: alpha("#06b6d4", 0.1) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
          📋 CCNA 200-301 Exam Domains
        </Typography>
        <Grid container spacing={2}>
          {[
            { domain: "Network Fundamentals", weight: "20%", color: "#3b82f6" },
            { domain: "Network Access", weight: "20%", color: "#22c55e" },
            { domain: "IP Connectivity", weight: "25%", color: "#f59e0b" },
            { domain: "IP Services", weight: "10%", color: "#ef4444" },
            { domain: "Security Fundamentals", weight: "15%", color: "#8b5cf6" },
            { domain: "Automation & Programmability", weight: "10%", color: "#06b6d4" },
          ].map((d) => (
            <Grid item xs={6} md={2} key={d.domain}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(d.color, 0.05), borderRadius: 2 }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: d.color }}>{d.weight}</Typography>
                <Typography variant="caption" sx={{ fontWeight: 600 }}>{d.domain}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* ========== VLAN CONFIGURATION ========== */}
      <Accordion
        id="vlan-switching"
        sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 96 }}
      >
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#22c55e", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <LayersIcon sx={{ color: "#22c55e" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>VLAN Configuration</Typography>
            <Chip label="Network Access" size="small" sx={{ ml: 1, bgcolor: alpha("#22c55e", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>VLANs</strong> (Virtual LANs) logically segment a network at Layer 2, creating separate broadcast domains without physical separation.
            </Typography>
          </Alert>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>📝 Create & Name VLANs</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`Switch(config)# vlan 10
Switch(config-vlan)# name SALES
Switch(config-vlan)# exit
Switch(config)# vlan 20
Switch(config-vlan)# name ENGINEERING
Switch(config-vlan)# exit`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>📝 Assign Ports to VLANs</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`Switch(config)# interface fa0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# exit
! Range of ports:
Switch(config)# interface range fa0/2-10
Switch(config-if-range)# switchport access vlan 20`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>📝 Voice VLAN</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Data + Voice on same port
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# switchport voice vlan 50
! Phone tags voice traffic with VLAN 50`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>🔍 Verification Commands</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`show vlan brief
show vlan id 10
show interfaces fa0/1 switchport
show interfaces trunk`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <TableContainer component={Paper} sx={{ mt: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>VLAN Range</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Usage</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { range: "1", type: "Default", usage: "All ports belong here by default, cannot be deleted" },
                  { range: "2-1001", type: "Normal", usage: "User-created VLANs, stored in vlan.dat" },
                  { range: "1002-1005", type: "Legacy", usage: "Token Ring/FDDI, cannot be deleted" },
                  { range: "1006-4094", type: "Extended", usage: "VTP transparent mode only, stored in running-config" },
                ].map((row) => (
                  <TableRow key={row.range}>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 600, color: "#22c55e" }}>{row.range}</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>{row.type}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.usage}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* ========== TRUNKING (802.1Q) ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#3b82f6", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <CableIcon sx={{ color: "#3b82f6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>Trunking & 802.1Q</Typography>
            <Chip label="Network Access" size="small" sx={{ ml: 1, bgcolor: alpha("#3b82f6", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Trunk ports</strong> carry traffic for multiple VLANs using 802.1Q tagging. The <strong>native VLAN</strong> is sent untagged.
            </Typography>
          </Alert>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>📝 Configure Trunk Port</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`Switch(config)# interface gi0/1
Switch(config-if)# switchport trunk encapsulation dot1q
Switch(config-if)# switchport mode trunk
! Change native VLAN (security best practice)
Switch(config-if)# switchport trunk native vlan 999
! Allow specific VLANs only
Switch(config-if)# switchport trunk allowed vlan 10,20,30`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>📝 DTP (Dynamic Trunking Protocol)</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Disable DTP negotiation (recommended)
Switch(config-if)# switchport nonegotiate

! DTP Modes:
! - dynamic auto: passive, waits for trunk
! - dynamic desirable: actively negotiates
! - trunk: forces trunk, still sends DTP
! - access: forces access mode`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>⚠️ Native VLAN Security</Typography>
            <Typography variant="body2">
              • Native VLAN mismatch can cause traffic leakage between VLANs<br/>
              • Best practice: Use an unused VLAN as native (e.g., VLAN 999)<br/>
              • Consider: <code>vlan dot1q tag native</code> to tag native VLAN traffic
            </Typography>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* ========== INTER-VLAN ROUTING ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f59e0b", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <RouterIcon sx={{ color: "#f59e0b" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>Inter-VLAN Routing</Typography>
            <Chip label="IP Connectivity" size="small" sx={{ ml: 1, bgcolor: alpha("#f59e0b", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>📝 Router-on-a-Stick (ROAS)</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Router config - subinterfaces
Router(config)# interface gi0/0
Router(config-if)# no shutdown
Router(config)# interface gi0/0.10
Router(config-subif)# encapsulation dot1Q 10
Router(config-subif)# ip address 192.168.10.1 255.255.255.0
Router(config)# interface gi0/0.20
Router(config-subif)# encapsulation dot1Q 20
Router(config-subif)# ip address 192.168.20.1 255.255.255.0
! Native VLAN subinterface
Router(config)# interface gi0/0.99
Router(config-subif)# encapsulation dot1Q 99 native`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>📝 Layer 3 Switch (SVI)</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Enable IP routing on L3 switch
Switch(config)# ip routing

! Create SVI (Switch Virtual Interface)
Switch(config)# interface vlan 10
Switch(config-if)# ip address 192.168.10.1 255.255.255.0
Switch(config-if)# no shutdown
Switch(config)# interface vlan 20
Switch(config-if)# ip address 192.168.20.1 255.255.255.0
Switch(config-if)# no shutdown

! Verify: show ip route`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <TableContainer component={Paper} sx={{ mt: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Method</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Pros</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Cons</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { method: "ROAS", pros: "Works with any router, cost-effective", cons: "Single link bottleneck, higher latency" },
                  { method: "L3 Switch (SVI)", pros: "Wire-speed routing, scalable", cons: "More expensive hardware" },
                  { method: "Routed Ports", pros: "No VLAN overhead, simple", cons: "Each port = one network" },
                ].map((row) => (
                  <TableRow key={row.method}>
                    <TableCell sx={{ fontWeight: 600, color: "#f59e0b" }}>{row.method}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem", color: "#22c55e" }}>{row.pros}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem", color: "#ef4444" }}>{row.cons}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* ========== SPANNING TREE PROTOCOL ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#8b5cf6", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <AccountTreeIcon sx={{ color: "#8b5cf6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Spanning Tree Protocol (STP)</Typography>
            <Chip label="Network Access" size="small" sx={{ ml: 1, bgcolor: alpha("#8b5cf6", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>STP</strong> prevents Layer 2 loops by blocking redundant paths. <strong>RSTP</strong> (802.1w) provides faster convergence.
            </Typography>
          </Alert>

          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>Port States (STP)</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>1. <strong>Blocking</strong> - No forwarding (20s)</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>2. <strong>Listening</strong> - Learning topology (15s)</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>3. <strong>Learning</strong> - Building MAC table (15s)</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>4. <strong>Forwarding</strong> - Normal operation</Typography>
                <Typography variant="body2">5. <strong>Disabled</strong> - Admin down</Typography>
                <Divider sx={{ my: 2 }} />
                <Typography variant="caption" color="text.secondary">Total convergence: ~50 seconds</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>Port States (RSTP)</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>1. <strong>Discarding</strong> - Not forwarding</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>2. <strong>Learning</strong> - Building MAC table</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>3. <strong>Forwarding</strong> - Normal operation</Typography>
                <Divider sx={{ my: 2 }} />
                <Typography variant="caption" color="text.secondary">Convergence: ~6 seconds or less</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>Port Roles</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Root</strong> - Best path to root bridge</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Designated</strong> - Forwards on segment</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Non-Designated</strong> - Blocked (STP)</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Alternate</strong> - Backup root (RSTP)</Typography>
                <Typography variant="body2">• <strong>Backup</strong> - Backup designated (RSTP)</Typography>
              </Paper>
            </Grid>
          </Grid>

          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>📝 Configure Root Bridge</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Make switch the root bridge
Switch(config)# spanning-tree vlan 10 root primary
! Or set priority directly (lower = better)
Switch(config)# spanning-tree vlan 10 priority 4096
! Secondary root bridge
Switch(config)# spanning-tree vlan 10 root secondary

! Enable RSTP (Rapid PVST+)
Switch(config)# spanning-tree mode rapid-pvst`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>📝 PortFast & BPDU Guard</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! PortFast - skip STP states (access ports only!)
Switch(config-if)# spanning-tree portfast
! Global PortFast for all access ports
Switch(config)# spanning-tree portfast default

! BPDU Guard - shutdown if BPDU received
Switch(config-if)# spanning-tree bpduguard enable
! Global BPDU Guard
Switch(config)# spanning-tree portfast bpduguard default`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>🔢 Bridge ID & Election</Typography>
            <Typography variant="body2" sx={{ mb: 1 }}>
              <strong>Bridge ID</strong> = Priority (4 bits) + Extended System ID (12 bits = VLAN) + MAC Address
            </Typography>
            <Typography variant="body2">
              <strong>Election:</strong> Lowest Bridge ID wins → Lowest Root Path Cost → Lowest Sender Bridge ID → Lowest Port ID
            </Typography>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* ========== ETHERCHANNEL ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#06b6d4", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <HubIcon sx={{ color: "#06b6d4" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>EtherChannel / Link Aggregation</Typography>
            <Chip label="Network Access" size="small" sx={{ ml: 1, bgcolor: alpha("#06b6d4", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>EtherChannel</strong> bundles multiple physical links into one logical link for increased bandwidth and redundancy.
            </Typography>
          </Alert>

          <TableContainer component={Paper} sx={{ mb: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Standard</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Modes</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { proto: "PAgP", std: "Cisco Proprietary", modes: "auto / desirable", notes: "Cisco switches only" },
                  { proto: "LACP", std: "IEEE 802.3ad", modes: "passive / active", notes: "Industry standard, recommended" },
                  { proto: "Static", std: "Manual", modes: "on", notes: "No negotiation, must match both sides" },
                ].map((row) => (
                  <TableRow key={row.proto}>
                    <TableCell sx={{ fontWeight: 600, color: "#06b6d4" }}>{row.proto}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.std}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.modes}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.notes}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>📝 LACP Configuration</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Create EtherChannel with LACP
Switch(config)# interface range gi0/1-2
Switch(config-if-range)# channel-group 1 mode active
Switch(config-if-range)# exit

! Configure the Port-Channel interface
Switch(config)# interface port-channel 1
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20,30`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>📝 L3 EtherChannel</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Layer 3 EtherChannel (routed)
Switch(config)# interface range gi0/1-2
Switch(config-if-range)# no switchport
Switch(config-if-range)# channel-group 1 mode active
Switch(config)# interface port-channel 1
Switch(config-if)# ip address 10.0.0.1 255.255.255.252

! Verify
show etherchannel summary
show etherchannel port-channel`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>⚠️ Requirements (All Must Match)</Typography>
            <Typography variant="body2">
              Speed • Duplex • VLAN mode (access/trunk) • Allowed VLANs • Native VLAN • STP settings
            </Typography>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* ========== OSPF CONFIGURATION ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ef4444", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <PublicIcon sx={{ color: "#ef4444" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>OSPF Configuration</Typography>
            <Chip label="IP Connectivity" size="small" sx={{ ml: 1, bgcolor: alpha("#ef4444", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>OSPF</strong> is a link-state routing protocol using Dijkstra's SPF algorithm. CCNA focuses on single-area OSPF (Area 0).
            </Typography>
          </Alert>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>📝 Basic OSPF Configuration</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`Router(config)# router ospf 1
Router(config-router)# router-id 1.1.1.1
! Network command method
Router(config-router)# network 192.168.1.0 0.0.0.255 area 0
Router(config-router)# network 10.0.0.0 0.0.0.3 area 0

! Interface method (preferred)
Router(config)# interface gi0/0
Router(config-if)# ip ospf 1 area 0

! Passive interface (no OSPF hello)
Router(config-router)# passive-interface gi0/1`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>📝 OSPF Tuning</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Set interface cost manually
Router(config-if)# ip ospf cost 100

! Adjust reference bandwidth (Gbps networks)
Router(config-router)# auto-cost reference-bandwidth 10000

! Change hello/dead timers (must match!)
Router(config-if)# ip ospf hello-interval 5
Router(config-if)# ip ospf dead-interval 20

! Default route injection
Router(config-router)# default-information originate`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>OSPF Neighbor Requirements</Typography>
                <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>
                  ✓ Same Area ID<br/>
                  ✓ Same Subnet<br/>
                  ✓ Same Hello/Dead timers<br/>
                  ✓ Same Authentication<br/>
                  ✓ Same MTU (or ignore)<br/>
                  ✓ Compatible network type
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>OSPF States</Typography>
                <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>
                  1. Down → 2. Init →<br/>
                  3. 2-Way → 4. ExStart →<br/>
                  5. Exchange → 6. Loading →<br/>
                  7. Full (Adjacency formed)
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>DR/BDR Election</Typography>
                <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>
                  1. Highest OSPF Priority (0-255)<br/>
                  2. Highest Router ID<br/>
                  • Priority 0 = never DR<br/>
                  • Non-preemptive (wait for failure)
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Paper sx={{ p: 2, mt: 3, bgcolor: "#0d1117", borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>🔍 OSPF Verification Commands</Typography>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`show ip ospf neighbor              ! Check neighbor relationships
show ip ospf interface brief        ! Interface OSPF status
show ip route ospf                  ! OSPF learned routes
show ip ospf database               ! Link-state database
show ip protocols                   ! Routing protocol info`}
            </Typography>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* ========== STATIC ROUTING ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ec4899", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <RouterIcon sx={{ color: "#ec4899" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ec4899" }}>Static Routing</Typography>
            <Chip label="IP Connectivity" size="small" sx={{ ml: 1, bgcolor: alpha("#ec4899", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ec4899" }}>📝 Static Route Types</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Standard static route
ip route 192.168.2.0 255.255.255.0 10.0.0.2

! Default route (gateway of last resort)
ip route 0.0.0.0 0.0.0.0 10.0.0.1

! Floating static (backup, higher AD)
ip route 192.168.2.0 255.255.255.0 10.0.1.2 200

! Directly connected static
ip route 192.168.2.0 255.255.255.0 gi0/1

! Fully specified (both)
ip route 192.168.2.0 255.255.255.0 gi0/1 10.0.0.2`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ec4899" }}>📝 IPv6 Static Routing</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Enable IPv6 routing
ipv6 unicast-routing

! IPv6 static route
ipv6 route 2001:db8:2::/64 2001:db8:1::2

! IPv6 default route
ipv6 route ::/0 2001:db8:1::1

! Link-local next-hop (requires interface)
ipv6 route 2001:db8:2::/64 gi0/1 fe80::1`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* ========== ACCESS CONTROL LISTS (ACLs) ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ef4444", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <SecurityIcon sx={{ color: "#ef4444" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>Access Control Lists (ACLs)</Typography>
            <Chip label="Security Fundamentals" size="small" sx={{ ml: 1, bgcolor: alpha("#ef4444", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>ACLs</strong> filter traffic based on source/destination IP, ports, and protocols. Applied inbound or outbound on interfaces.
            </Typography>
          </Alert>

          <TableContainer component={Paper} sx={{ mb: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Number Range</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Matches On</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Placement</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { type: "Standard", range: "1-99, 1300-1999", matches: "Source IP only", placement: "Close to destination" },
                  { type: "Extended", range: "100-199, 2000-2699", matches: "Src/Dst IP, Port, Protocol", placement: "Close to source" },
                  { type: "Named", range: "Any name", matches: "Depends on type", placement: "Depends on type" },
                ].map((row) => (
                  <TableRow key={row.type}>
                    <TableCell sx={{ fontWeight: 600, color: "#ef4444" }}>{row.type}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.range}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.matches}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.placement}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>📝 Standard ACL</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Numbered Standard ACL
Router(config)# access-list 10 permit 192.168.1.0 0.0.0.255
Router(config)# access-list 10 deny any

! Named Standard ACL
Router(config)# ip access-list standard BLOCK_GUESTS
Router(config-std-nacl)# permit 192.168.10.0 0.0.0.255
Router(config-std-nacl)# deny any

! Apply to interface
Router(config)# interface gi0/1
Router(config-if)# ip access-group 10 out`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>📝 Extended ACL</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Named Extended ACL
Router(config)# ip access-list extended WEB_ACCESS
! Allow HTTP/HTTPS to web server
Router(config-ext-nacl)# permit tcp any host 10.0.0.100 eq 80
Router(config-ext-nacl)# permit tcp any host 10.0.0.100 eq 443
! Block all other traffic to server
Router(config-ext-nacl)# deny ip any host 10.0.0.100
! Allow everything else
Router(config-ext-nacl)# permit ip any any

! Apply inbound on interface
Router(config-if)# ip access-group WEB_ACCESS in`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>⚠️ ACL Rules to Remember</Typography>
            <Typography variant="body2">
              • Implicit <code>deny any</code> at end of every ACL<br/>
              • Processed top-down, first match wins<br/>
              • One ACL per interface, per direction, per protocol<br/>
              • <code>show access-lists</code> &nbsp;|&nbsp; <code>show ip interface gi0/1</code>
            </Typography>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* ========== NAT & PAT ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#22c55e", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <SwapHorizIcon sx={{ color: "#22c55e" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>NAT & PAT Configuration</Typography>
            <Chip label="IP Services" size="small" sx={{ ml: 1, bgcolor: alpha("#22c55e", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>NAT</strong> translates private IPs to public IPs. <strong>PAT</strong> (overload) uses ports to allow many devices to share one public IP.
            </Typography>
          </Alert>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { type: "Static NAT", desc: "1:1 mapping, permanent", use: "Servers needing external access", color: "#3b82f6" },
              { type: "Dynamic NAT", desc: "Pool of public IPs", use: "When you have multiple public IPs", color: "#8b5cf6" },
              { type: "PAT (Overload)", desc: "Many:1 using ports", use: "Most common - home/office internet", color: "#22c55e" },
            ].map((n) => (
              <Grid item xs={12} md={4} key={n.type}>
                <Paper sx={{ p: 2, bgcolor: alpha(n.color, 0.05), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: n.color }}>{n.type}</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>{n.desc}</Typography>
                  <Typography variant="caption" color="text.secondary">{n.use}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>📝 Static NAT</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Map internal server to public IP
Router(config)# ip nat inside source static 192.168.1.100 203.0.113.10

! Define inside/outside interfaces
Router(config)# interface gi0/0
Router(config-if)# ip nat inside
Router(config)# interface gi0/1
Router(config-if)# ip nat outside`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>📝 PAT (Overload) - Most Common</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Define what traffic to NAT
Router(config)# access-list 1 permit 192.168.0.0 0.0.255.255

! PAT using outside interface IP
Router(config)# ip nat inside source list 1 interface gi0/1 overload

! Define interfaces
Router(config)# interface gi0/0
Router(config-if)# ip nat inside
Router(config)# interface gi0/1
Router(config-if)# ip nat outside`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Paper sx={{ p: 2, mt: 3, bgcolor: "#0d1117", borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>🔍 NAT Verification</Typography>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`show ip nat translations       ! View NAT table
show ip nat statistics         ! Translation stats
clear ip nat translation *     ! Clear all translations
debug ip nat                   ! Real-time NAT debugging`}
            </Typography>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* ========== DHCP ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#3b82f6", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <DnsIcon sx={{ color: "#3b82f6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>DHCP Server & Relay</Typography>
            <Chip label="IP Services" size="small" sx={{ ml: 1, bgcolor: alpha("#3b82f6", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>📝 Configure DHCP Server</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Exclude addresses (gateway, servers, etc.)
Router(config)# ip dhcp excluded-address 192.168.10.1 192.168.10.10

! Create DHCP pool
Router(config)# ip dhcp pool SALES_VLAN
Router(dhcp-config)# network 192.168.10.0 255.255.255.0
Router(dhcp-config)# default-router 192.168.10.1
Router(dhcp-config)# dns-server 8.8.8.8 8.8.4.4
Router(dhcp-config)# domain-name company.local
Router(dhcp-config)# lease 7

! Verify
show ip dhcp binding
show ip dhcp pool`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>📝 DHCP Relay Agent</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! When DHCP server is on different subnet
! Configure on interface facing clients
Router(config)# interface gi0/0
Router(config-if)# ip helper-address 10.0.0.50

! ip helper-address also forwards:
! - TFTP (69)
! - DNS (53)
! - TACACS (49)
! - NetBIOS (137, 138)
! - Time (37)`}
                </Typography>
              </Paper>
              <Paper sx={{ p: 2, mt: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>DORA Process</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                  <strong>D</strong>iscover → <strong>O</strong>ffer → <strong>R</strong>equest → <strong>A</strong>ck
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* ========== FIRST HOP REDUNDANCY (HSRP) ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#8b5cf6", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <SyncAltIcon sx={{ color: "#8b5cf6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>First Hop Redundancy (HSRP/VRRP)</Typography>
            <Chip label="IP Connectivity" size="small" sx={{ ml: 1, bgcolor: alpha("#8b5cf6", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>FHRP</strong> provides gateway redundancy. If the active gateway fails, standby takes over using the same virtual IP.
            </Typography>
          </Alert>

          <TableContainer component={Paper} sx={{ mb: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Standard</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Virtual MAC</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Multicast</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { proto: "HSRP v1", std: "Cisco", mac: "0000.0c07.acXX", mcast: "224.0.0.2" },
                  { proto: "HSRP v2", std: "Cisco", mac: "0000.0c9f.fXXX", mcast: "224.0.0.102" },
                  { proto: "VRRP", std: "IEEE", mac: "0000.5e00.01XX", mcast: "224.0.0.18" },
                  { proto: "GLBP", std: "Cisco", mac: "0007.b400.XXYY", mcast: "224.0.0.102" },
                ].map((row) => (
                  <TableRow key={row.proto}>
                    <TableCell sx={{ fontWeight: 600, color: "#8b5cf6" }}>{row.proto}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.std}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{row.mac}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.mcast}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>📝 HSRP Configuration</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Router 1 (Active)
Router1(config)# interface gi0/0
Router1(config-if)# ip address 192.168.1.2 255.255.255.0
Router1(config-if)# standby version 2
Router1(config-if)# standby 1 ip 192.168.1.1
Router1(config-if)# standby 1 priority 110
Router1(config-if)# standby 1 preempt

! Router 2 (Standby)
Router2(config)# interface gi0/0
Router2(config-if)# ip address 192.168.1.3 255.255.255.0
Router2(config-if)# standby version 2
Router2(config-if)# standby 1 ip 192.168.1.1
! Default priority is 100`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>HSRP States</Typography>
                <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>
                  Initial → Learn → Listen → Speak → Standby → Active
                </Typography>
              </Paper>
              <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Key Concepts</Typography>
                <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>
                  • <strong>Priority:</strong> Higher wins (default 100)<br/>
                  • <strong>Preempt:</strong> Take over when higher priority comes online<br/>
                  • <strong>Track:</strong> Lower priority if uplink fails<br/>
                  • Clients use virtual IP as gateway
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* ========== DEVICE SECURITY ========== */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f59e0b", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <LockIcon sx={{ color: "#f59e0b" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>Device Security & Hardening</Typography>
            <Chip label="Security Fundamentals" size="small" sx={{ ml: 1, bgcolor: alpha("#f59e0b", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>📝 Password Security</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Enable secret (encrypted, preferred)
Router(config)# enable secret Str0ngP@ss!

! Encrypt all passwords in config
Router(config)# service password-encryption

! Minimum password length
Router(config)# security passwords min-length 10

! Console line security
Router(config)# line console 0
Router(config-line)# password ConsoleP@ss
Router(config-line)# login
Router(config-line)# exec-timeout 5 0
Router(config-line)# logging synchronous`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>📝 SSH Configuration</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Set hostname and domain (required for SSH)
Router(config)# hostname R1
R1(config)# ip domain-name company.local

! Generate RSA keys
R1(config)# crypto key generate rsa modulus 2048

! Create local user
R1(config)# username admin privilege 15 secret AdminP@ss

! Configure VTY lines for SSH only
R1(config)# line vty 0 15
R1(config-line)# transport input ssh
R1(config-line)# login local
R1(config-line)# exec-timeout 10 0

! Use SSH version 2
R1(config)# ip ssh version 2`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>📝 Port Security</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`Switch(config)# interface fa0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 2
Switch(config-if)# switchport port-security mac-address sticky
Switch(config-if)# switchport port-security violation shutdown

! Violation modes: protect | restrict | shutdown
! Re-enable after shutdown:
Switch(config-if)# shutdown
Switch(config-if)# no shutdown`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>📝 Unused Port Security</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Disable unused ports
Switch(config)# interface range fa0/10-24
Switch(config-if-range)# shutdown

! Move to unused VLAN (black hole)
Switch(config-if-range)# switchport access vlan 999

! Enable DHCP snooping
Switch(config)# ip dhcp snooping
Switch(config)# ip dhcp snooping vlan 10,20
Switch(config)# interface gi0/1
Switch(config-if)# ip dhcp snooping trust`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* ========== IPv6 ========== */}
      <Accordion
        id="ipv6"
        sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 96 }}
      >
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#06b6d4", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <PublicIcon sx={{ color: "#06b6d4" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>IPv6 Addressing & Configuration</Typography>
            <Chip label="Network Fundamentals" size="small" sx={{ ml: 1, bgcolor: alpha("#06b6d4", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { type: "Global Unicast", prefix: "2000::/3", desc: "Internet routable (like public IPv4)", color: "#22c55e" },
              { type: "Link-Local", prefix: "fe80::/10", desc: "Auto-generated, single link only", color: "#3b82f6" },
              { type: "Unique Local", prefix: "fc00::/7", desc: "Private addresses (like RFC 1918)", color: "#8b5cf6" },
              { type: "Multicast", prefix: "ff00::/8", desc: "One-to-many communication", color: "#f59e0b" },
            ].map((a) => (
              <Grid item xs={6} md={3} key={a.type}>
                <Paper sx={{ p: 2, bgcolor: alpha(a.color, 0.05), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: a.color }}>{a.type}</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.75rem", mb: 0.5 }}>{a.prefix}</Typography>
                  <Typography variant="caption" color="text.secondary">{a.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>📝 IPv6 Interface Configuration</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! Enable IPv6 routing
Router(config)# ipv6 unicast-routing

! Manual IPv6 address
Router(config)# interface gi0/0
Router(config-if)# ipv6 address 2001:db8:1::1/64
Router(config-if)# no shutdown

! EUI-64 (auto-generate from MAC)
Router(config-if)# ipv6 address 2001:db8:1::/64 eui-64

! Link-local only
Router(config-if)# ipv6 enable

! SLAAC (clients auto-configure)
! Router sends RA with prefix info`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>📝 OSPFv3 for IPv6</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`! OSPFv3 configuration
Router(config)# ipv6 router ospf 1
Router(config-rtr)# router-id 1.1.1.1

! Enable on interface
Router(config)# interface gi0/0
Router(config-if)# ipv6 ospf 1 area 0

! Verification
show ipv6 route
show ipv6 interface brief
show ipv6 ospf neighbor
show ipv6 protocols`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>📝 IPv6 Address Shortening Rules</Typography>
            <Typography variant="body2">
              • Remove leading zeros: <code>2001:0db8:0000:0001</code> → <code>2001:db8:0:1</code><br/>
              • Replace consecutive zeros with <code>::</code> (once): <code>2001:db8:0:0:0:0:0:1</code> → <code>2001:db8::1</code><br/>
              • <code>::</code> can only be used once per address
            </Typography>
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* ========== NETWORK AUTOMATION ========== */}
      <Accordion
        id="automation-sdn"
        sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 96 }}
      >
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ec4899", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <CodeIcon sx={{ color: "#ec4899" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ec4899" }}>Network Automation Basics</Typography>
            <Chip label="Automation" size="small" sx={{ ml: 1, bgcolor: alpha("#ec4899", 0.1) }} />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              CCNA covers automation concepts including REST APIs, JSON/XML data formats, and configuration management tools.
            </Typography>
          </Alert>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ec4899" }}>🔧 Configuration Management Tools</Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableBody>
                    {[
                      { tool: "Ansible", type: "Agentless", lang: "YAML Playbooks", push: "Push-based" },
                      { tool: "Puppet", type: "Agent-based", lang: "Puppet DSL", push: "Pull-based" },
                      { tool: "Chef", type: "Agent-based", lang: "Ruby DSL", push: "Pull-based" },
                      { tool: "SaltStack", type: "Both", lang: "YAML/Python", push: "Both" },
                    ].map((t) => (
                      <TableRow key={t.tool}>
                        <TableCell sx={{ fontWeight: 600, color: "#ec4899" }}>{t.tool}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem" }}>{t.type}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem" }}>{t.lang}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem" }}>{t.push}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ec4899" }}>📝 REST API Basics</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`HTTP Methods (CRUD):
  GET    - Read/Retrieve data
  POST   - Create new resource
  PUT    - Update/Replace resource
  PATCH  - Partial update
  DELETE - Remove resource

Response Codes:
  200 OK          - Success
  201 Created     - Resource created
  400 Bad Request - Client error
  401 Unauthorized- Auth required
  404 Not Found   - Resource missing
  500 Server Error- Server issue`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ec4899" }}>📝 JSON Example</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`{
  "interface": {
    "name": "GigabitEthernet0/0",
    "ip-address": "192.168.1.1",
    "subnet-mask": "255.255.255.0",
    "enabled": true
  }
}`}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ec4899" }}>📝 YAML Example (Ansible)</Typography>
              <Paper sx={{ p: 2, bgcolor: "#0d1117", borderRadius: 2 }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e6edf3", m: 0, whiteSpace: "pre-wrap" }}>
{`---
- name: Configure interface
  hosts: routers
  tasks:
    - name: Set IP address
      ios_config:
        lines:
          - ip address 192.168.1.1 255.255.255.0
        parents: interface Gi0/0`}
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* CCNA Study Tips */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: "linear-gradient(135deg, rgba(34,197,94,0.05) 0%, rgba(59,130,246,0.05) 100%)", border: "2px solid", borderColor: alpha("#22c55e", 0.2) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#22c55e" }}>
          🎯 CCNA Exam Tips
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>📚 Key Topics by Weight</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.85rem" }}>
              • IP Connectivity (25%) - Routing, OSPF<br/>
              • Network Fundamentals (20%)<br/>
              • Network Access (20%) - VLANs, STP<br/>
              • Security (15%) - ACLs, hardening<br/>
              • IP Services (10%) - NAT, DHCP<br/>
              • Automation (10%) - REST, JSON
            </Typography>
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>⏱️ Exam Format</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.85rem" }}>
              • 120 minutes<br/>
              • ~100 questions<br/>
              • Multiple choice, drag-drop, simlets<br/>
              • Passing score: ~825/1000<br/>
              • Valid for 3 years
            </Typography>
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>💡 Study Strategy</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.85rem" }}>
              • Lab everything in Packet Tracer/GNS3<br/>
              • Know your show commands<br/>
              • Understand subnetting quickly<br/>
              • Practice ACL logic<br/>
              • Memorize port numbers & protocols
            </Typography>
          </Grid>
        </Grid>
      </Paper>

      {/* ========== SOFTWARE DEFINED NETWORKING (SDN) ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>SOFTWARE DEFINED NETWORKING</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        🌐 Software Defined Networking (SDN)
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
        The modern approach to network management - separating the control plane from the data plane
      </Typography>

      {/* SDN Overview */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: "linear-gradient(135deg, rgba(99,102,241,0.05) 0%, rgba(14,165,233,0.05) 100%)", border: "2px solid", borderColor: alpha("#6366f1", 0.2) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#6366f1" }}>
          🎯 What is SDN?
        </Typography>
        
        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>SDN (Software Defined Networking)</strong> is an approach that separates the network's control plane 
            (decision-making) from the data plane (packet forwarding), enabling centralized, programmable network management.
          </Typography>
        </Alert>

        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, textAlign: "center" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Traditional Networking</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Control & Data plane combined in each device
              </Typography>
              <Box sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                  [Router 1] ←→ [Router 2]<br/>
                  (Control+Data) (Control+Data)<br/>
                  ↓<br/>
                  Each device makes<br/>
                  its own decisions
                </Typography>
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, textAlign: "center" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>→ Transition →</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Separating concerns
              </Typography>
              <Box sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                  Control Plane:<br/>
                  "What to do"<br/>
                  ↓<br/>
                  Data Plane:<br/>
                  "How to forward"
                </Typography>
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, textAlign: "center" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>SDN Architecture</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Centralized control, distributed forwarding
              </Typography>
              <Box sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                  [SDN Controller]<br/>
                  (All Control)<br/>
                  ↓ ↓ ↓<br/>
                  [Sw1][Sw2][Sw3]<br/>
                  (Data only)
                </Typography>
              </Box>
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      {/* SDN Architecture Layers */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#6366f1", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#6366f1" }}>
          🏗️ SDN Architecture (Three Layers)
        </Typography>

        <Grid container spacing={3}>
          {/* Application Layer */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.08), borderRadius: 2, border: "2px solid", borderColor: alpha("#22c55e", 0.3) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Chip label="Layer 3" sx={{ bgcolor: "#22c55e", color: "white", fontWeight: 700 }} />
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>Application Layer</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Business applications that communicate network requirements to the controller
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                <Chip label="Network Monitoring" size="small" variant="outlined" />
                <Chip label="Load Balancers" size="small" variant="outlined" />
                <Chip label="Firewalls" size="small" variant="outlined" />
                <Chip label="IDS/IPS" size="small" variant="outlined" />
                <Chip label="Traffic Engineering" size="small" variant="outlined" />
                <Chip label="QoS Apps" size="small" variant="outlined" />
              </Box>
              <Alert severity="success" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  <strong>Northbound API (NBI):</strong> REST APIs, Python scripts - how apps talk to the controller
                </Typography>
              </Alert>
            </Paper>
          </Grid>

          {/* Control Layer */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: alpha("#0ea5e9", 0.08), borderRadius: 2, border: "2px solid", borderColor: alpha("#0ea5e9", 0.3) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Chip label="Layer 2" sx={{ bgcolor: "#0ea5e9", color: "white", fontWeight: 700 }} />
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#0ea5e9" }}>Control Layer (SDN Controller)</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                The "brain" of the network - centralizes all control plane functions
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Controller Functions:</Typography>
                  <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontSize: "0.85rem" }}>
                    <Typography variant="body2">• Topology discovery & management</Typography>
                    <Typography variant="body2">• Path computation & routing</Typography>
                    <Typography variant="body2">• Policy enforcement</Typography>
                    <Typography variant="body2">• Flow table management</Typography>
                    <Typography variant="body2">• Network state maintenance</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Popular Controllers:</Typography>
                  <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontSize: "0.85rem" }}>
                    <Typography variant="body2">• <strong>OpenDaylight</strong> - Linux Foundation</Typography>
                    <Typography variant="body2">• <strong>ONOS</strong> - Open Network OS</Typography>
                    <Typography variant="body2">• <strong>Cisco ACI</strong> - Application Centric</Typography>
                    <Typography variant="body2">• <strong>VMware NSX</strong> - Data center</Typography>
                    <Typography variant="body2">• <strong>Ryu</strong> - Python-based</Typography>
                  </Paper>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          {/* Infrastructure Layer */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.08), borderRadius: 2, border: "2px solid", borderColor: alpha("#f59e0b", 0.3) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Chip label="Layer 1" sx={{ bgcolor: "#f59e0b", color: "white", fontWeight: 700 }} />
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>Infrastructure Layer (Data Plane)</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Physical/virtual network devices that forward traffic based on controller instructions
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                <Chip label="OpenFlow Switches" size="small" variant="outlined" />
                <Chip label="Virtual Switches" size="small" variant="outlined" />
                <Chip label="Routers" size="small" variant="outlined" />
                <Chip label="Access Points" size="small" variant="outlined" />
              </Box>
              <Alert severity="warning">
                <Typography variant="body2">
                  <strong>Southbound API (SBI):</strong> OpenFlow, NETCONF, OVSDB - how controller talks to devices
                </Typography>
              </Alert>
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      {/* OpenFlow Protocol */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#8b5cf6", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#8b5cf6" }}>
          📡 OpenFlow Protocol
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          The first and most widely used southbound API for SDN - defines how controllers communicate with switches
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>OpenFlow Components:</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Component</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Function</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { comp: "Flow Table", func: "Stores forwarding rules (match + action)" },
                    { comp: "Group Table", func: "Defines groups of ports for multicast/load balancing" },
                    { comp: "Meter Table", func: "QoS and rate limiting" },
                    { comp: "Secure Channel", func: "TLS connection to controller" },
                    { comp: "OpenFlow Protocol", func: "Messages between controller and switch" },
                  ].map((row) => (
                    <TableRow key={row.comp}>
                      <TableCell sx={{ fontWeight: 600, color: "#8b5cf6" }}>{row.comp}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.func}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Flow Entry Structure:</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
              <Typography variant="body2" sx={{ color: "#8b5cf6", fontWeight: 700, mb: 1 }}>Match Fields (What to match):</Typography>
              <Typography variant="body2">• Ingress Port, MAC src/dst</Typography>
              <Typography variant="body2">• IP src/dst, Protocol</Typography>
              <Typography variant="body2">• TCP/UDP ports, VLAN ID</Typography>
              <Divider sx={{ my: 1 }} />
              <Typography variant="body2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>Actions (What to do):</Typography>
              <Typography variant="body2">• Forward to port(s)</Typography>
              <Typography variant="body2">• Drop packet</Typography>
              <Typography variant="body2">• Send to controller</Typography>
              <Typography variant="body2">• Modify headers</Typography>
            </Paper>
          </Grid>
        </Grid>

        <Alert severity="info" sx={{ mt: 3 }}>
          <Typography variant="body2">
            <strong>How it works:</strong> When a packet arrives with no matching flow entry, the switch sends it to the 
            controller (Packet-In). The controller decides what to do and installs a flow entry (Flow-Mod) for future packets.
          </Typography>
        </Alert>
      </Paper>

      {/* SDN Benefits & Use Cases */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          ✨ SDN Benefits & Use Cases
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>Benefits:</Typography>
            <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>✓ <strong>Centralized Management</strong> - Single point of control</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>✓ <strong>Programmability</strong> - Automate network changes</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>✓ <strong>Agility</strong> - Rapid deployment and changes</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>✓ <strong>Vendor Neutral</strong> - Use any OpenFlow device</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>✓ <strong>Cost Reduction</strong> - Use commodity hardware</Typography>
              <Typography variant="body2">✓ <strong>Better Security</strong> - Centralized policy enforcement</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>Use Cases:</Typography>
            <Paper sx={{ p: 2, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>📊 <strong>Data Centers</strong> - Dynamic workload placement</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>☁️ <strong>Cloud Computing</strong> - Multi-tenant networking</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>🏢 <strong>Campus Networks</strong> - Policy-based access</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>🌐 <strong>WAN Optimization</strong> - Traffic engineering</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>🔒 <strong>Security</strong> - Microsegmentation</Typography>
              <Typography variant="body2">🧪 <strong>Network Testing</strong> - Easy to test changes</Typography>
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      {/* SDN vs Traditional Comparison */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3, background: alpha("#ef4444", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#ef4444" }}>
          📊 SDN vs Traditional Networking
        </Typography>

        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Aspect</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Traditional Networking</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Software Defined Networking</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                { aspect: "Control Plane", trad: "Distributed (in each device)", sdn: "Centralized (SDN Controller)" },
                { aspect: "Configuration", trad: "Device-by-device (CLI)", sdn: "Centralized (API/GUI)" },
                { aspect: "Flexibility", trad: "Vendor-specific features", sdn: "Open, programmable" },
                { aspect: "Automation", trad: "Limited, script-based", sdn: "Native, API-driven" },
                { aspect: "Visibility", trad: "Per-device view", sdn: "Network-wide view" },
                { aspect: "Speed of Change", trad: "Slow (manual changes)", sdn: "Fast (automated)" },
                { aspect: "Hardware", trad: "Proprietary, expensive", sdn: "Commodity, cheaper" },
                { aspect: "Skillset", trad: "Vendor certifications", sdn: "Programming + networking" },
              ].map((row) => (
                <TableRow key={row.aspect}>
                  <TableCell sx={{ fontWeight: 600 }}>{row.aspect}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem", color: "#ef4444" }}>{row.trad}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem", color: "#22c55e" }}>{row.sdn}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* ========== NETWORK VIRTUALIZATION ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>NETWORK VIRTUALIZATION</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        🖥️ Network Virtualization
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
        Creating virtual networks independent of physical infrastructure - essential for modern data centers and cloud
      </Typography>

      {/* Virtual Network Components */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#06b6d4", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#06b6d4" }}>
          🔧 Virtual Network Components
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>Virtual Switches (vSwitch)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Software-based Layer 2 switches running inside hypervisors to connect VMs
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Common vSwitch Implementations:</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>VMware vSwitch/VDS</strong> - VMware environments</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Open vSwitch (OVS)</strong> - Open source, production-grade</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Hyper-V Virtual Switch</strong> - Microsoft environments</Typography>
                <Typography variant="body2">• <strong>Linux Bridge</strong> - Native Linux switching</Typography>
              </Paper>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Virtual NICs (vNIC)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Software network interfaces assigned to virtual machines
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>vNIC Types:</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Emulated</strong> - Fully software-based (slower)</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Paravirtualized</strong> - VM-aware drivers (faster)</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>SR-IOV</strong> - Direct hardware access (fastest)</Typography>
                <Typography variant="body2">• <strong>DPDK</strong> - Kernel bypass for high performance</Typography>
              </Paper>
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      {/* Overlay Networks */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#f59e0b", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#f59e0b" }}>
          🌐 Overlay Networks
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Virtual networks built on top of physical networks using encapsulation - enables network isolation and scalability
        </Typography>

        <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Technology</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Full Name</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Encapsulation</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Header Size</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Max Networks</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                { tech: "VXLAN", full: "Virtual eXtensible LAN", encap: "UDP (port 4789)", header: "50 bytes", max: "16 million", use: "Data center, multi-tenant" },
                { tech: "NVGRE", full: "Network Virtualization using GRE", encap: "GRE", header: "42 bytes", max: "16 million", use: "Microsoft Hyper-V" },
                { tech: "GENEVE", full: "Generic Network Virtualization", encap: "UDP (port 6081)", header: "Variable", max: "16 million", use: "Next-gen (flexible)" },
                { tech: "STT", full: "Stateless Transport Tunneling", encap: "TCP-like", header: "54 bytes", max: "16 million", use: "VMware NSX" },
              ].map((row) => (
                <TableRow key={row.tech}>
                  <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>{row.tech}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{row.full}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.encap}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{row.header}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{row.max}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{row.use}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Alert severity="info">
          <Typography variant="body2">
            <strong>Why Overlays?</strong> Traditional VLANs only support 4,096 networks (12-bit ID). 
            Overlay technologies use 24-bit IDs (16+ million networks) - essential for cloud scale!
          </Typography>
        </Alert>
      </Paper>

      {/* Network Virtualization Platforms */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          🏢 Network Virtualization Platforms
        </Typography>

        <Grid container spacing={2}>
          {[
            { name: "VMware NSX", desc: "Full network virtualization for vSphere", features: "Micro-segmentation, distributed firewall, load balancing", color: "#0ea5e9" },
            { name: "Cisco ACI", desc: "Application Centric Infrastructure", features: "Policy-driven automation, hardware + software integration", color: "#22c55e" },
            { name: "Microsoft Azure Virtual Network", desc: "Cloud-native virtual networking", features: "VNet peering, Network Security Groups, Azure Firewall", color: "#8b5cf6" },
            { name: "AWS VPC", desc: "Amazon Virtual Private Cloud", features: "Subnets, route tables, internet gateways, NAT", color: "#f59e0b" },
            { name: "OpenStack Neutron", desc: "Open source cloud networking", features: "Plugin architecture, multi-tenant, L2/L3 services", color: "#ef4444" },
            { name: "Kubernetes CNI", desc: "Container Network Interface", features: "Pod networking, network policies, service mesh", color: "#06b6d4" },
          ].map((platform) => (
            <Grid item xs={12} md={4} key={platform.name}>
              <Paper sx={{ p: 2, height: "100%", borderLeft: `4px solid ${platform.color}`, bgcolor: alpha(platform.color, 0.03) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: platform.color }}>{platform.name}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{platform.desc}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>{platform.features}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* ========== NETWORK TYPES ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>NETWORK TYPES & CABLING</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        🌍 Network Types by Geographic Scope
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
        Networks are classified by their size and geographic coverage
      </Typography>

      <TableContainer component={Paper} sx={{ mb: 4, borderRadius: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
              <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Full Name</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Range</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Speed</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Examples</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>Technologies</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {[
              { type: "PAN", name: "Personal Area Network", range: "~10 meters", speed: "1-3 Mbps", examples: "Bluetooth devices, wearables", tech: "Bluetooth, Zigbee, NFC" },
              { type: "LAN", name: "Local Area Network", range: "Building/Campus", speed: "10 Mbps - 100 Gbps", examples: "Office network, home network", tech: "Ethernet, Wi-Fi" },
              { type: "WLAN", name: "Wireless LAN", range: "Building/Campus", speed: "Up to 9.6 Gbps", examples: "Office Wi-Fi, public hotspots", tech: "802.11 a/b/g/n/ac/ax" },
              { type: "CAN", name: "Campus Area Network", range: "Multiple buildings", speed: "1-100 Gbps", examples: "University, corporate campus", tech: "Ethernet, Fiber" },
              { type: "MAN", name: "Metropolitan Area Network", range: "City-wide", speed: "10-100 Gbps", examples: "City government, ISP backbone", tech: "Metro Ethernet, SONET" },
              { type: "WAN", name: "Wide Area Network", range: "Countries/Global", speed: "Variable", examples: "The Internet, corporate WAN", tech: "MPLS, Leased lines, VPN" },
              { type: "SAN", name: "Storage Area Network", range: "Data center", speed: "16-128 Gbps", examples: "Disk arrays, tape libraries", tech: "Fibre Channel, iSCSI, FCoE" },
              { type: "GAN", name: "Global Area Network", range: "Worldwide", speed: "Variable", examples: "Satellite networks, global corps", tech: "Satellite, undersea cables" },
            ].map((row) => (
              <TableRow key={row.type}>
                <TableCell><Chip label={row.type} size="small" sx={{ fontWeight: 700, bgcolor: alpha("#8b5cf6", 0.15) }} /></TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{row.name}</TableCell>
                <TableCell sx={{ fontSize: "0.85rem" }}>{row.range}</TableCell>
                <TableCell sx={{ fontSize: "0.85rem" }}>{row.speed}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{row.examples}</TableCell>
                <TableCell sx={{ fontSize: "0.8rem" }}>{row.tech}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Cable Types */}
      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        🔌 Cable Types & Standards
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
        Physical layer cabling - the foundation of wired networking
      </Typography>

      {/* Copper Cables */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#f59e0b", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#f59e0b" }}>
          🔶 Copper Twisted Pair Cables
        </Typography>

        <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Max Speed</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Bandwidth</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Max Length</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Shielding</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                { cat: "Cat 5", speed: "100 Mbps", bw: "100 MHz", len: "100m", shield: "UTP", use: "Legacy networks (obsolete)" },
                { cat: "Cat 5e", speed: "1 Gbps", bw: "100 MHz", len: "100m", shield: "UTP", use: "Most common, home/office" },
                { cat: "Cat 6", speed: "10 Gbps*", bw: "250 MHz", len: "55m @10G", shield: "UTP/STP", use: "Enterprise, short 10G runs" },
                { cat: "Cat 6a", speed: "10 Gbps", bw: "500 MHz", len: "100m", shield: "STP/F/UTP", use: "Full 10G, data centers" },
                { cat: "Cat 7", speed: "10 Gbps", bw: "600 MHz", len: "100m", shield: "S/FTP", use: "High interference areas" },
                { cat: "Cat 7a", speed: "10 Gbps", bw: "1000 MHz", len: "100m", shield: "S/FTP", use: "Future-proofing, 40G short" },
                { cat: "Cat 8", speed: "25/40 Gbps", bw: "2000 MHz", len: "30m", shield: "S/FTP", use: "Data center, switch-to-switch" },
              ].map((row) => (
                <TableRow key={row.cat}>
                  <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>{row.cat}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{row.speed}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{row.bw}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{row.len}</TableCell>
                  <TableCell><Chip label={row.shield} size="small" sx={{ fontSize: "0.65rem" }} /></TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{row.use}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>UTP (Unshielded)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>
                No shielding, most common, susceptible to EMI
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>STP (Shielded)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>
                Overall foil shield, better EMI protection
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>S/FTP (Fully Shielded)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>
                Individual pair + overall shield, best protection
              </Typography>
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      {/* Fiber Cables */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#22c55e", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#22c55e" }}>
          🟢 Fiber Optic Cables
        </Typography>

        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>Multi-Mode Fiber (MMF)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Larger core (50-62.5µm), multiple light paths, shorter distances
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableBody>
                    {[
                      { type: "OM1", core: "62.5µm", speed: "1 Gbps", dist: "275m" },
                      { type: "OM2", core: "50µm", speed: "1 Gbps", dist: "550m" },
                      { type: "OM3", core: "50µm", speed: "10 Gbps", dist: "300m" },
                      { type: "OM4", core: "50µm", speed: "10 Gbps", dist: "400m" },
                      { type: "OM5", core: "50µm", speed: "100 Gbps", dist: "150m" },
                    ].map((row) => (
                      <TableRow key={row.type}>
                        <TableCell sx={{ fontWeight: 700, color: "#f59e0b", py: 0.5 }}>{row.type}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem", py: 0.5 }}>{row.core}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem", py: 0.5 }}>{row.speed}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem", py: 0.5 }}>{row.dist}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Single-Mode Fiber (SMF)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Smaller core (9µm), single light path, long distances
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableBody>
                    {[
                      { type: "OS1", core: "9µm", speed: "10+ Gbps", dist: "10 km" },
                      { type: "OS2", core: "9µm", speed: "100+ Gbps", dist: "200 km" },
                    ].map((row) => (
                      <TableRow key={row.type}>
                        <TableCell sx={{ fontWeight: 700, color: "#22c55e", py: 0.5 }}>{row.type}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem", py: 0.5 }}>{row.core}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem", py: 0.5 }}>{row.speed}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem", py: 0.5 }}>{row.dist}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              <Alert severity="success" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  <strong>Long-haul:</strong> SMF can reach 100+ km with amplification - used for ISP backbones and undersea cables
                </Typography>
              </Alert>
            </Paper>
          </Grid>
        </Grid>

        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Fiber Connector Types:</Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
          <Chip label="LC (Small form factor)" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1) }} />
          <Chip label="SC (Square connector)" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1) }} />
          <Chip label="ST (Bayonet style)" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1) }} />
          <Chip label="MPO/MTP (Multi-fiber)" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1) }} />
          <Chip label="FC (Threaded)" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1) }} />
        </Box>
      </Paper>

      {/* ========== SPANNING TREE PROTOCOL ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>LAYER 2 PROTOCOLS</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        🌳 Spanning Tree Protocol (STP)
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
        Preventing Layer 2 loops - critical for network stability
      </Typography>

      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#ef4444", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#ef4444" }}>
          ⚠️ The Problem: Switching Loops
        </Typography>
        
        <Alert severity="error" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>Without STP:</strong> Broadcast frames would loop infinitely, consuming all bandwidth and crashing the network 
            (broadcast storm). MAC address tables would become unstable (MAC flapping).
          </Typography>
        </Alert>

        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, textAlign: "center" }}>
              <Typography variant="h6" sx={{ color: "#ef4444", fontWeight: 700 }}>💥 Broadcast Storm</Typography>
              <Typography variant="body2" color="text.secondary">Frames multiply exponentially</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, textAlign: "center" }}>
              <Typography variant="h6" sx={{ color: "#f59e0b", fontWeight: 700 }}>🔄 MAC Flapping</Typography>
              <Typography variant="body2" color="text.secondary">MAC table constantly changing</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, textAlign: "center" }}>
              <Typography variant="h6" sx={{ color: "#8b5cf6", fontWeight: 700 }}>📦 Duplicate Frames</Typography>
              <Typography variant="body2" color="text.secondary">Same frame received multiple times</Typography>
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      {/* STP Operation */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: alpha("#22c55e", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#22c55e" }}>
          🛠️ How STP Works
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>STP Election Process:</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}><strong>Step 1:</strong> Elect Root Bridge (lowest Bridge ID)</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}><strong>Step 2:</strong> Select Root Ports (best path to root)</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}><strong>Step 3:</strong> Select Designated Ports (best port per segment)</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}><strong>Step 4:</strong> Block Non-Designated Ports</Typography>
              <Divider sx={{ my: 1 }} />
              <Typography variant="body2" sx={{ fontStyle: "italic", color: "text.secondary" }}>
                Bridge ID = Priority (4 bits) + System ID + MAC Address
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Port States (802.1D):</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableBody>
                  {[
                    { state: "Blocking", time: "-", desc: "Not forwarding, learning MAC", color: "#ef4444" },
                    { state: "Listening", time: "15 sec", desc: "Processing BPDUs", color: "#f59e0b" },
                    { state: "Learning", time: "15 sec", desc: "Building MAC table", color: "#f59e0b" },
                    { state: "Forwarding", time: "-", desc: "Normal operation", color: "#22c55e" },
                    { state: "Disabled", time: "-", desc: "Admin disabled", color: "#6b7280" },
                  ].map((row) => (
                    <TableRow key={row.state}>
                      <TableCell sx={{ fontWeight: 700, color: row.color }}>{row.state}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.time}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem", color: "text.secondary" }}>{row.desc}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Grid>
        </Grid>

        <Alert severity="warning" sx={{ mt: 3 }}>
          <Typography variant="body2">
            <strong>Convergence Time:</strong> Classic STP (802.1D) takes 30-50 seconds to converge after a topology change - 
            this is why RSTP was developed!
          </Typography>
        </Alert>
      </Paper>

      {/* STP Versions */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          📋 STP Versions Comparison
        </Typography>

        <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Standard</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Convergence</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>VLAN Support</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                { proto: "STP", std: "802.1D", conv: "30-50 sec", vlan: "One tree for all", desc: "Original, slow convergence" },
                { proto: "RSTP", std: "802.1w", conv: "1-2 sec", vlan: "One tree for all", desc: "Rapid STP - much faster" },
                { proto: "PVST+", std: "Cisco", conv: "30-50 sec", vlan: "Per-VLAN tree", desc: "Cisco per-VLAN STP" },
                { proto: "Rapid PVST+", std: "Cisco", conv: "1-2 sec", vlan: "Per-VLAN tree", desc: "Rapid + per-VLAN (best of both)" },
                { proto: "MSTP", std: "802.1s", conv: "1-2 sec", vlan: "Multiple trees", desc: "Maps VLANs to instances" },
              ].map((row) => (
                <TableRow key={row.proto}>
                  <TableCell sx={{ fontWeight: 700, color: "#8b5cf6" }}>{row.proto}</TableCell>
                  <TableCell><Chip label={row.std} size="small" sx={{ fontSize: "0.65rem" }} /></TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: row.conv.includes("30") ? "#ef4444" : "#22c55e" }}>{row.conv}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{row.vlan}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{row.desc}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* STP Configuration */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3, background: alpha("#06b6d4", 0.03) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#06b6d4" }}>
          ⚙️ STP Configuration & Best Practices
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Essential Commands (Cisco):</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
              <Typography variant="body2" sx={{ color: "#06b6d4" }}># Show STP status</Typography>
              <Typography variant="body2">show spanning-tree</Typography>
              <Typography variant="body2">show spanning-tree vlan 10</Typography>
              <Typography variant="body2" sx={{ color: "#06b6d4", mt: 1 }}># Set root bridge</Typography>
              <Typography variant="body2">spanning-tree vlan 10 root primary</Typography>
              <Typography variant="body2">spanning-tree vlan 10 priority 4096</Typography>
              <Typography variant="body2" sx={{ color: "#06b6d4", mt: 1 }}># Enable RSTP</Typography>
              <Typography variant="body2">spanning-tree mode rapid-pvst</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>STP Protection Features:</Typography>
            <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>🛡️ <strong>PortFast:</strong> Skip listening/learning on access ports</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>🛡️ <strong>BPDU Guard:</strong> Shutdown port if BPDU received (PortFast ports)</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>🛡️ <strong>Root Guard:</strong> Prevent port from becoming root</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>🛡️ <strong>Loop Guard:</strong> Prevent alternate ports from forwarding</Typography>
              <Typography variant="body2">🛡️ <strong>UDLD:</strong> Unidirectional Link Detection</Typography>
            </Paper>
          </Grid>
        </Grid>

        <Alert severity="success" sx={{ mt: 3 }}>
          <Typography variant="body2">
            <strong>Best Practice:</strong> Always manually configure root bridge (don't leave to chance), enable PortFast + BPDU Guard 
            on access ports, and use RSTP or Rapid PVST+ for faster convergence.
          </Typography>
        </Alert>
      </Paper>

      {/* ========== DETAILED PROTOCOL INFO ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>PROTOCOL DEEP DIVES</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
        📚 Protocol Deep Dives
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
        Detailed information on common networking protocols
      </Typography>

      {/* HTTP/HTTPS */}
      <Accordion defaultExpanded sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#22c55e", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <LanguageIcon sx={{ color: "#22c55e" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>HTTP/HTTPS (Port 80/443)</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>HTTP Methods:</Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableBody>
                    {[
                      { method: "GET", desc: "Retrieve data", safe: "Yes", body: "No" },
                      { method: "POST", desc: "Submit data", safe: "No", body: "Yes" },
                      { method: "PUT", desc: "Replace resource", safe: "No", body: "Yes" },
                      { method: "PATCH", desc: "Partial update", safe: "No", body: "Yes" },
                      { method: "DELETE", desc: "Remove resource", safe: "No", body: "Optional" },
                      { method: "HEAD", desc: "GET without body", safe: "Yes", body: "No" },
                      { method: "OPTIONS", desc: "Supported methods", safe: "Yes", body: "No" },
                    ].map((row) => (
                      <TableRow key={row.method}>
                        <TableCell sx={{ fontWeight: 700, color: "#22c55e" }}>{row.method}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem" }}>{row.desc}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem" }}>{row.safe}</TableCell>
                        <TableCell sx={{ fontSize: "0.8rem" }}>{row.body}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>HTTP Status Codes:</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2" sx={{ color: "#0ea5e9", mb: 0.5 }}><strong>1xx</strong> - Informational (100 Continue)</Typography>
                <Typography variant="body2" sx={{ color: "#22c55e", mb: 0.5 }}><strong>2xx</strong> - Success (200 OK, 201 Created)</Typography>
                <Typography variant="body2" sx={{ color: "#f59e0b", mb: 0.5 }}><strong>3xx</strong> - Redirect (301 Moved, 304 Not Modified)</Typography>
                <Typography variant="body2" sx={{ color: "#ef4444", mb: 0.5 }}><strong>4xx</strong> - Client Error (400 Bad, 401 Unauth, 404 Not Found)</Typography>
                <Typography variant="body2" sx={{ color: "#8b5cf6" }}><strong>5xx</strong> - Server Error (500 Internal, 503 Unavailable)</Typography>
              </Paper>
              <Alert severity="info" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  <strong>HTTPS:</strong> HTTP + TLS encryption. Always use HTTPS for sensitive data!
                </Typography>
              </Alert>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* DNS Deep Dive */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#0ea5e9", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <DnsIcon sx={{ color: "#0ea5e9" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#0ea5e9" }}>DNS Deep Dive (Port 53)</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>DNS Resolution Process:</Typography>
          <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2, mb: 3, fontFamily: "monospace", fontSize: "0.85rem" }}>
            <Typography variant="body2">1. Client checks local cache → Not found</Typography>
            <Typography variant="body2">2. Client queries Recursive Resolver (ISP DNS)</Typography>
            <Typography variant="body2">3. Resolver queries Root Server (.)</Typography>
            <Typography variant="body2">4. Root refers to TLD Server (.com)</Typography>
            <Typography variant="body2">5. TLD refers to Authoritative Server (example.com)</Typography>
            <Typography variant="body2">6. Authoritative returns IP address</Typography>
            <Typography variant="body2">7. Resolver caches and returns to client</Typography>
          </Paper>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>DNS Query Types:</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2">• <strong>Recursive:</strong> "Give me the answer or find it"</Typography>
                <Typography variant="body2">• <strong>Iterative:</strong> "Give me the next server to ask"</Typography>
                <Typography variant="body2">• <strong>Inverse:</strong> IP → Domain (PTR records)</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>DNS Security:</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2">• <strong>DNSSEC:</strong> Cryptographic signatures for authenticity</Typography>
                <Typography variant="body2">• <strong>DoH:</strong> DNS over HTTPS (encrypted)</Typography>
                <Typography variant="body2">• <strong>DoT:</strong> DNS over TLS (port 853)</Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* SSH */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#8b5cf6", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <VpnKeyIcon sx={{ color: "#8b5cf6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>SSH (Port 22)</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Secure Shell - encrypted remote access and file transfer
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>SSH Capabilities:</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2">• Remote command execution</Typography>
                <Typography variant="body2">• Secure file transfer (SCP, SFTP)</Typography>
                <Typography variant="body2">• Port forwarding / tunneling</Typography>
                <Typography variant="body2">• X11 forwarding (GUI over SSH)</Typography>
                <Typography variant="body2">• Agent forwarding (key management)</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Authentication Methods:</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2">🔑 <strong>Password:</strong> Simple but less secure</Typography>
                <Typography variant="body2">🔐 <strong>Public Key:</strong> Recommended, no password needed</Typography>
                <Typography variant="body2">📱 <strong>2FA/MFA:</strong> Additional verification</Typography>
                <Typography variant="body2">🎫 <strong>Certificate:</strong> Enterprise/CA-based</Typography>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="success" sx={{ mt: 2 }}>
            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
              ssh-keygen -t ed25519 -C "your_email" # Generate modern key pair
            </Typography>
          </Alert>
        </AccordionDetails>
      </Accordion>

      {/* SNMP */}
      <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f59e0b", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <StorageIcon sx={{ color: "#f59e0b" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>SNMP (Port 161/162)</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Simple Network Management Protocol - monitor and manage network devices
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>SNMP Components:</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2">• <strong>Manager:</strong> Central monitoring station (NMS)</Typography>
                <Typography variant="body2">• <strong>Agent:</strong> Software on managed devices</Typography>
                <Typography variant="body2">• <strong>MIB:</strong> Management Information Base (data structure)</Typography>
                <Typography variant="body2">• <strong>OID:</strong> Object Identifier (unique data point)</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>SNMP Operations:</Typography>
              <Paper sx={{ p: 2, bgcolor: "background.default", borderRadius: 2 }}>
                <Typography variant="body2">📤 <strong>GET:</strong> Request specific value</Typography>
                <Typography variant="body2">📤 <strong>GET-NEXT:</strong> Walk through MIB</Typography>
                <Typography variant="body2">📥 <strong>SET:</strong> Modify configuration</Typography>
                <Typography variant="body2">🚨 <strong>TRAP:</strong> Unsolicited alert from agent</Typography>
              </Paper>
            </Grid>
          </Grid>

          <TableContainer component={Paper} sx={{ mt: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Version</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Security</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Authentication</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Recommendation</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { ver: "SNMPv1", sec: "None", auth: "Community string (cleartext)", rec: "❌ Don't use" },
                  { ver: "SNMPv2c", sec: "None", auth: "Community string (cleartext)", rec: "⚠️ Internal only" },
                  { ver: "SNMPv3", sec: "Full", auth: "Username + Auth + Encryption", rec: "✅ Use this" },
                ].map((row) => (
                  <TableRow key={row.ver}>
                    <TableCell sx={{ fontWeight: 700, color: "#f59e0b" }}>{row.ver}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.sec}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.auth}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.rec}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* FTP/SFTP */}
      <Accordion sx={{ mb: 5, borderRadius: "12px !important", "&:before": { display: "none" } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ef4444", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <SwapHorizIcon sx={{ color: "#ef4444" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>FTP/SFTP/FTPS (Port 20-21/22/990)</Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Port</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Encryption</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>How It Works</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Security</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { proto: "FTP", port: "20 (data), 21 (ctrl)", enc: "None", how: "Separate control & data channels", sec: "❌ Insecure - cleartext" },
                  { proto: "FTPS", port: "990 (implicit)", enc: "TLS/SSL", how: "FTP + TLS encryption", sec: "✅ Encrypted, but complex" },
                  { proto: "SFTP", port: "22", enc: "SSH", how: "Subsystem of SSH", sec: "✅ Recommended - simple & secure" },
                  { proto: "SCP", port: "22", enc: "SSH", how: "Copy over SSH", sec: "✅ Secure but less features" },
                ].map((row) => (
                  <TableRow key={row.proto}>
                    <TableCell sx={{ fontWeight: 700, color: "#ef4444" }}>{row.proto}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.port}</TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{row.enc}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem" }}>{row.how}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem" }}>{row.sec}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Alert severity="warning" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>FTP Active vs Passive:</strong> Active mode - server connects back to client (firewall issues). 
              Passive mode - client initiates both connections (firewall-friendly). Use PASV for most scenarios.
            </Typography>
          </Alert>
        </AccordionDetails>
      </Accordion>

      {/* ========== NETWORKING QUIZ SECTION ========== */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 6, scrollMarginTop: 96 }} id="quiz">
        <Divider sx={{ flex: 1 }} />
        <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>TEST YOUR KNOWLEDGE</Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      <Paper sx={{ 
        p: 4, 
        mb: 4, 
        borderRadius: 3, 
        background: "linear-gradient(135deg, rgba(139,92,246,0.1) 0%, rgba(59,130,246,0.1) 100%)", 
        border: "3px solid", 
        borderColor: alpha("#8b5cf6", 0.4) 
      }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <QuizIcon sx={{ fontSize: 40, color: "#8b5cf6" }} />
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 800, color: "#8b5cf6" }}>
              🧠 Networking Quiz
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Test your knowledge with {QUIZ_QUESTION_COUNT} random questions from our {quizBank.length}-question bank!
            </Typography>
          </Box>
        </Box>

        {!quizActive ? (
          // Quiz Start Screen
          <Paper sx={{ p: 4, borderRadius: 2, bgcolor: "background.default", textAlign: "center" }}>
            <EmojiEventsIcon sx={{ fontSize: 80, color: "#f59e0b", mb: 2 }} />
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>Ready to Test Yourself?</Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
              Each quiz randomly selects {QUIZ_QUESTION_COUNT} questions from our comprehensive bank of {quizBank.length} networking questions
              covering OSI Model, TCP/IP, Subnetting, Security, Wireless, and more!
            </Typography>
            <Grid container spacing={2} justifyContent="center" sx={{ mb: 4 }}>
              {quizCategoryStats.map((cat) => (
                <Grid item key={cat.label}>
                  <Chip
                    label={`${cat.label} (${cat.count})`}
                    sx={{ bgcolor: alpha(cat.color, 0.1), color: cat.color, fontWeight: 600 }}
                  />
                </Grid>
              ))}
            </Grid>
            <Button 
              variant="contained" 
              size="large" 
              onClick={() => startQuiz(false)}
              startIcon={<QuizIcon />}
              sx={{ 
                px: 6, 
                py: 1.5, 
                fontSize: "1.1rem",
                background: "linear-gradient(135deg, #8b5cf6 0%, #3b82f6 100%)",
                "&:hover": { background: "linear-gradient(135deg, #7c3aed 0%, #2563eb 100%)" }
              }}
            >
              Start Quiz ({QUIZ_QUESTION_COUNT} Questions)
            </Button>
          </Paper>
        ) : (
          // Active Quiz
          <>
            {/* Progress Bar */}
            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Progress: {quizProgress.answered}/{quizProgress.total} answered
                </Typography>
                {!quizSubmitted && (
                  <Typography variant="body2" color="text.secondary">
                    Question {currentQuestionIndex + 1} of {quizQuestions.length}
                  </Typography>
                )}
                {quizSubmitted && (
                  <Chip 
                    icon={<EmojiEventsIcon />}
                    label={`Score: ${quizScore}/10`} 
                    sx={{ bgcolor: alpha(getScoreColor(quizScore), 0.2), color: getScoreColor(quizScore), fontWeight: 700 }}
                  />
                )}
              </Box>
              <LinearProgress 
                variant="determinate" 
                value={(quizProgress.answered / quizProgress.total) * 100}
                sx={{ 
                  height: 10, 
                  borderRadius: 5,
                  bgcolor: alpha("#8b5cf6", 0.1),
                  "& .MuiLinearProgress-bar": { 
                    bgcolor: quizSubmitted ? getScoreColor(quizScore) : "#8b5cf6",
                    borderRadius: 5 
                  }
                }}
              />
            </Paper>

            {quizSubmitted ? (
              // Results View
              <>
                <Paper sx={{ 
                  p: 4, 
                  mb: 3, 
                  borderRadius: 2, 
                  bgcolor: alpha(getScoreColor(quizScore), 0.05),
                  border: "2px solid",
                  borderColor: alpha(getScoreColor(quizScore), 0.3),
                  textAlign: "center"
                }}>
                  <Typography variant="h2" sx={{ fontWeight: 800, color: getScoreColor(quizScore), mb: 1 }}>
                    {quizScore}/10
                  </Typography>
                  <Typography variant="h5" sx={{ fontWeight: 600, mb: 2 }}>
                    {getScoreMessage(quizScore)}
                  </Typography>
                  <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                    {quizScore >= 7 ? "Great job! Try another quiz to keep learning." : "Review the explanations below and try again!"}
                  </Typography>
                  <Box sx={{ display: "flex", gap: 2, justifyContent: "center" }}>
                    <Button 
                      variant="contained" 
                      onClick={() => startQuiz(true)} 
                      startIcon={<RefreshIcon />}
                      sx={{ bgcolor: "#8b5cf6", "&:hover": { bgcolor: "#7c3aed" } }}
                    >
                      New Quiz ({QUIZ_QUESTION_COUNT} New Questions)
                    </Button>
                    <Button variant="outlined" onClick={resetQuiz}>
                      Exit Quiz
                    </Button>
                  </Box>
                </Paper>

                {/* Show all questions with answers */}
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📝 Review Your Answers:</Typography>
                {quizQuestions.map((q, idx) => {
                  const userAnswer = quizAnswers[q.id];
                  const isCorrect = userAnswer === q.correct;
                  return (
                    <Paper 
                      key={q.id} 
                      sx={{ 
                        p: 3, 
                        mb: 2, 
                        borderRadius: 2, 
                        border: "2px solid",
                        borderColor: isCorrect ? alpha("#22c55e", 0.4) : alpha("#ef4444", 0.4),
                        bgcolor: isCorrect ? alpha("#22c55e", 0.03) : alpha("#ef4444", 0.03)
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 2 }}>
                        {isCorrect ? (
                          <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 28 }} />
                        ) : (
                          <CancelIcon sx={{ color: "#ef4444", fontSize: 28 }} />
                        )}
                        <Box sx={{ flex: 1 }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            <Chip label={`Q${idx + 1}`} size="small" sx={{ fontWeight: 700 }} />
                            <Chip label={q.category} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                          </Box>
                          <Typography variant="body1" sx={{ fontWeight: 600 }}>{q.question}</Typography>
                        </Box>
                      </Box>
                      
                      <Grid container spacing={1} sx={{ mb: 2 }}>
                        {q.options.map((opt, optIdx) => (
                          <Grid item xs={12} sm={6} key={optIdx}>
                            <Paper 
                              sx={{ 
                                p: 1.5, 
                                borderRadius: 1,
                                bgcolor: optIdx === q.correct 
                                  ? alpha("#22c55e", 0.15) 
                                  : optIdx === userAnswer && optIdx !== q.correct
                                    ? alpha("#ef4444", 0.15)
                                    : "background.default",
                                border: "1px solid",
                                borderColor: optIdx === q.correct 
                                  ? "#22c55e" 
                                  : optIdx === userAnswer && optIdx !== q.correct
                                    ? "#ef4444"
                                    : "divider"
                              }}
                            >
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Typography 
                                  variant="body2" 
                                  sx={{ 
                                    fontWeight: optIdx === q.correct ? 700 : 400,
                                    color: optIdx === q.correct ? "#22c55e" : "inherit"
                                  }}
                                >
                                  {String.fromCharCode(65 + optIdx)}. {opt}
                                </Typography>
                                {optIdx === q.correct && <CheckCircleIcon sx={{ fontSize: 16, color: "#22c55e", ml: "auto" }} />}
                                {optIdx === userAnswer && optIdx !== q.correct && <CancelIcon sx={{ fontSize: 16, color: "#ef4444", ml: "auto" }} />}
                              </Box>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                      
                      <Alert severity="info" sx={{ "& .MuiAlert-message": { width: "100%" } }}>
                        <Typography variant="body2"><strong>Explanation:</strong> {q.explanation}</Typography>
                      </Alert>
                    </Paper>
                  );
                })}
              </>
            ) : (
              // Question View (One at a time)
              <>
                {quizQuestions.map((q, idx) => (
                  <Paper 
                    key={q.id}
                    sx={{ 
                      p: 3, 
                      mb: 2, 
                      borderRadius: 2, 
                      display: idx === currentQuestionIndex ? "block" : "none",
                      bgcolor: "background.default"
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
                      <Chip 
                        label={`Question ${idx + 1}`} 
                        sx={{ bgcolor: "#8b5cf6", color: "white", fontWeight: 700, fontSize: "0.9rem" }} 
                      />
                      <Chip label={q.category} size="small" variant="outlined" />
                    </Box>
                    
                    <Typography variant="h6" sx={{ fontWeight: 600, mb: 3 }}>{q.question}</Typography>
                    
                    <FormControl component="fieldset" sx={{ width: "100%" }}>
                      <RadioGroup 
                        value={quizAnswers[q.id] ?? ""} 
                        onChange={(e) => handleAnswerSelect(q.id, parseInt(e.target.value))}
                      >
                        {q.options.map((opt, optIdx) => (
                          <Paper 
                            key={optIdx}
                            sx={{ 
                              mb: 1.5, 
                              p: 0.5,
                              borderRadius: 2,
                              border: "2px solid",
                              borderColor: quizAnswers[q.id] === optIdx ? "#8b5cf6" : "transparent",
                              bgcolor: quizAnswers[q.id] === optIdx ? alpha("#8b5cf6", 0.05) : "background.paper",
                              cursor: "pointer",
                              transition: "all 0.2s",
                              "&:hover": { 
                                bgcolor: alpha("#8b5cf6", 0.08),
                                borderColor: alpha("#8b5cf6", 0.3)
                              }
                            }}
                            onClick={() => handleAnswerSelect(q.id, optIdx)}
                          >
                            <FormControlLabel
                              value={optIdx}
                              control={<Radio sx={{ color: "#8b5cf6", "&.Mui-checked": { color: "#8b5cf6" } }} />}
                              label={
                                <Typography sx={{ fontWeight: quizAnswers[q.id] === optIdx ? 600 : 400 }}>
                                  {String.fromCharCode(65 + optIdx)}. {opt}
                                </Typography>
                              }
                              sx={{ m: 0, width: "100%", py: 1, px: 1 }}
                            />
                          </Paper>
                        ))}
                      </RadioGroup>
                    </FormControl>
                  </Paper>
                ))}

                {/* Navigation Buttons */}
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mt: 3 }}>
                  <Button 
                    variant="outlined" 
                    onClick={() => setCurrentQuestionIndex(prev => Math.max(0, prev - 1))}
                    disabled={currentQuestionIndex === 0}
                  >
                    ← Previous
                  </Button>
                  
                  {/* Question Dots */}
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", justifyContent: "center" }}>
                    {quizQuestions.map((q, idx) => (
                      <Box
                        key={q.id}
                        onClick={() => setCurrentQuestionIndex(idx)}
                        sx={{
                          width: 32,
                          height: 32,
                          borderRadius: "50%",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          cursor: "pointer",
                          bgcolor: quizAnswers[q.id] !== undefined 
                            ? "#22c55e" 
                            : idx === currentQuestionIndex 
                              ? "#8b5cf6" 
                              : alpha("#8b5cf6", 0.1),
                          color: quizAnswers[q.id] !== undefined || idx === currentQuestionIndex ? "white" : "text.secondary",
                          fontWeight: 700,
                          fontSize: "0.8rem",
                          border: idx === currentQuestionIndex ? "2px solid #8b5cf6" : "none",
                          transition: "all 0.2s",
                          "&:hover": { transform: "scale(1.1)" }
                        }}
                      >
                        {idx + 1}
                      </Box>
                    ))}
                  </Box>
                  
                  {currentQuestionIndex < quizQuestions.length - 1 ? (
                    <Button 
                      variant="outlined" 
                      onClick={() => setCurrentQuestionIndex(prev => Math.min(quizQuestions.length - 1, prev + 1))}
                    >
                      Next →
                    </Button>
                  ) : (
                    <Button 
                      variant="contained" 
                      onClick={submitQuiz}
                      disabled={quizProgress.answered < quizProgress.total}
                      sx={{ 
                        bgcolor: quizProgress.answered === quizProgress.total ? "#22c55e" : "grey.400",
                        "&:hover": { bgcolor: "#16a34a" }
                      }}
                    >
                      Submit Quiz ✓
                    </Button>
                  )}
                </Box>

                {quizProgress.answered < quizProgress.total && (
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      Answer all {quizProgress.total - quizProgress.answered} remaining question(s) to submit!
                    </Typography>
                  </Alert>
                )}
              </>
            )}
          </>
        )}
      </Paper>

      {/* Completion Banner */}
      <Paper
        sx={{
          p: 4,
          mt: 6,
          mb: 4,
          borderRadius: 4,
          background: `linear-gradient(135deg, ${alpha("#22c55e", 0.15)} 0%, ${alpha("#10b981", 0.1)} 100%)`,
          border: `1px solid ${alpha("#22c55e", 0.3)}`,
          textAlign: "center",
        }}
      >
        <EmojiEventsIcon sx={{ fontSize: 60, color: "#22c55e", mb: 2 }} />
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 2, color: "#22c55e" }}>
          🎉 Congratulations!
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ mb: 3, maxWidth: 600, mx: "auto" }}>
          You've explored all the core networking concepts. Keep practicing with the quiz above,
          and use the quick navigation to review any section!
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
          <Button
            variant="contained"
            onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
            sx={{
              bgcolor: "#22c55e",
              "&:hover": { bgcolor: "#16a34a" },
              fontWeight: 700,
              px: 3,
            }}
          >
            ↑ Back to Top
          </Button>
          <Button
            variant="outlined"
            onClick={() => navigate("/learn")}
            sx={{
              borderColor: "#22c55e",
              color: "#22c55e",
              "&:hover": { borderColor: "#16a34a", bgcolor: alpha("#22c55e", 0.05) },
              fontWeight: 700,
              px: 3,
            }}
          >
            More Learning Resources
          </Button>
        </Box>
      </Paper>

          </Container>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default ComputerNetworkingPage;
