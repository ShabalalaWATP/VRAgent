import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
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
  Drawer,
  Fab,
  IconButton,
  Tooltip,
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import TerminalIcon from "@mui/icons-material/Terminal";
import FolderIcon from "@mui/icons-material/Folder";
import SettingsIcon from "@mui/icons-material/Settings";
import PersonIcon from "@mui/icons-material/Person";
import StorageIcon from "@mui/icons-material/Storage";
import SecurityIcon from "@mui/icons-material/Security";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import SchoolIcon from "@mui/icons-material/School";
import InfoIcon from "@mui/icons-material/Info";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import ComputerIcon from "@mui/icons-material/Computer";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import WarningIcon from "@mui/icons-material/Warning";
import BuildIcon from "@mui/icons-material/Build";
import MemoryIcon from "@mui/icons-material/Memory";
import HistoryIcon from "@mui/icons-material/History";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import SpeedIcon from "@mui/icons-material/Speed";
import BugReportIcon from "@mui/icons-material/BugReport";
import KeyIcon from "@mui/icons-material/Key";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import LayersIcon from "@mui/icons-material/Layers";
import DnsIcon from "@mui/icons-material/Dns";
import DescriptionIcon from "@mui/icons-material/Description";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import SearchIcon from "@mui/icons-material/Search";
import VisibilityIcon from "@mui/icons-material/Visibility";
import LockIcon from "@mui/icons-material/Lock";
import WifiIcon from "@mui/icons-material/Wifi";
import CodeIcon from "@mui/icons-material/Code";
import LoopIcon from "@mui/icons-material/Loop";
import FunctionsIcon from "@mui/icons-material/Functions";
import PatternIcon from "@mui/icons-material/Pattern";
import EditIcon from "@mui/icons-material/Edit";
import SaveIcon from "@mui/icons-material/Save";
import NavigationIcon from "@mui/icons-material/Navigation";
import SelectAllIcon from "@mui/icons-material/SelectAll";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";

// Core Linux concepts with detailed beginner-friendly explanations
const linuxConcepts = [
  {
    title: "File System Hierarchy",
    icon: <FolderIcon />,
    color: "#f59e0b",
    description: "Linux organizes all files in a single tree structure starting from the root directory (/). Unlike Windows with C:, D: drives, Linux mounts everything under one unified hierarchy.",
    beginnerExplanation: "Think of the Linux file system like a family tree. At the very top is '/' (called 'root' - but not the same as the root user!). Every folder and file branches down from there. When you plug in a USB drive, it doesn't get a new letter like E: - instead, it appears as a folder somewhere in this tree (usually under /mnt or /media). This consistent structure makes it easy to navigate once you understand it.",
    keyPoints: [
      "Everything is a file (including devices, sockets, pipes)",
      "Forward slash (/) as path separator",
      "Case-sensitive file and directory names",
      "No drive letters - mount points instead",
      "File permissions: read, write, execute (rwx)",
      "Inodes store file metadata (not filenames)",
      "Hard links vs symbolic (soft) links",
    ],
    securityNote: "Proper file permissions are critical for Linux security. Misconfigured permissions are a common attack vector.",
  },
  {
    title: "Users & Groups",
    icon: <PersonIcon />,
    color: "#3b82f6",
    description: "Linux was designed from the start for multiple users to share one computer securely. Each user has their own space and permissions.",
    beginnerExplanation: "Imagine a building with many offices. Each person (user) has their own office (home directory at /home/username) with a key. Some areas are shared, some are restricted. The 'root' user is like the building manager - they have keys to everything. Groups are like departments: everyone in 'marketing' can access marketing files. This system keeps your files separate from others and prevents unauthorized access.",
    keyPoints: [
      "Root user (UID 0) has full system access",
      "Regular users have limited privileges",
      "Groups allow shared access permissions",
      "sudo for temporary privilege elevation",
      "/etc/passwd - user account info (world-readable)",
      "/etc/shadow - encrypted passwords (root only)",
      "/etc/group - group definitions",
      "Special users: nobody, www-data, daemon",
    ],
    securityNote: "Never run services as root. Use principle of least privilege. Lock unused accounts.",
  },
  {
    title: "Processes & Services",
    icon: <SettingsIcon />,
    color: "#10b981",
    description: "Every program running on Linux is a 'process'. Services (daemons) are background processes that start automatically and keep running.",
    beginnerExplanation: "When you open Firefox, Linux creates a 'process' - a running instance of that program. Each process gets a unique number (PID). Services are special processes that run in the background without you seeing them - like the web server waiting for visitors, or the SSH server waiting for remote connections. 'systemd' is like a manager that starts, stops, and monitors these services. When something goes wrong, you can 'kill' a process to stop it.",
    keyPoints: [
      "PID (Process ID) identifies each process",
      "PPID - Parent Process ID (process tree)",
      "Daemons run in background (services)",
      "systemd manages services on modern distros",
      "Signals: SIGTERM (15), SIGKILL (9), SIGHUP (1)",
      "Process states: Running, Sleeping, Zombie, Stopped",
      "Nice values control CPU priority (-20 to 19)",
      "cgroups limit resource usage",
    ],
    securityNote: "Monitor running processes regularly. Unexpected processes may indicate compromise.",
  },
  {
    title: "Package Management",
    icon: <StorageIcon />,
    color: "#8b5cf6",
    description: "Package managers are like app stores for Linux - they install, update, and remove software automatically, handling all dependencies.",
    beginnerExplanation: "Instead of downloading .exe files from websites like on Windows, Linux uses 'package managers'. They're like an app store that's built into your system. When you want to install something, you just type 'apt install firefox' (on Ubuntu) or 'dnf install firefox' (on Fedora). The package manager automatically downloads the software, installs it, and grabs any other software it needs to work (dependencies). Updates are also easy - one command updates everything.",
    keyPoints: [
      "APT (Debian/Ubuntu): apt, apt-get, dpkg",
      "YUM/DNF (RHEL/Fedora): yum, dnf, rpm",
      "Pacman (Arch): pacman",
      "Zypper (openSUSE): zypper",
      "Repositories store available packages",
      "Dependencies resolved automatically",
      "Package signing ensures authenticity",
      "Snap, Flatpak, AppImage - universal formats",
    ],
    securityNote: "Keep packages updated. Only use trusted repositories. Verify package signatures.",
  },
  {
    title: "Shell & Command Line",
    icon: <TerminalIcon />,
    color: "#ef4444",
    description: "The shell (terminal/command line) is where you type commands to control Linux. It's much more powerful than clicking through menus.",
    beginnerExplanation: "The shell is a text-based way to talk to your computer. Instead of clicking icons, you type commands. 'Bash' is the most common shell - it's the program that reads your commands and carries them out. Why use it? It's much faster for repetitive tasks, you can write scripts to automate work, it works over remote connections (SSH), and many Linux servers have no graphical interface at all. Don't be intimidated - start with simple commands like 'ls' (list files), 'cd' (change directory), and 'cat' (show file contents).",
    keyPoints: [
      "Bash is the most common shell",
      "Other shells: zsh, fish, dash, ksh",
      "Shell scripts for automation (.sh files)",
      "Pipes (|) connect command output to input",
      "Redirection: > (write), >> (append), < (input)",
      "2>&1 redirects stderr to stdout",
      "Environment variables configure behavior",
      "Shell expansion: *, ?, [], {}, ~",
    ],
    securityNote: "Be careful with commands run as root. Sanitize inputs in shell scripts.",
  },
  {
    title: "Networking",
    icon: <NetworkCheckIcon />,
    color: "#06b6d4",
    description: "Linux has powerful networking built into the kernel. You can configure IP addresses, firewalls, routing, and network services from the command line.",
    beginnerExplanation: "Linux excels at networking - that's why it runs most web servers. Your computer has 'network interfaces' (like eth0 for ethernet or wlan0 for WiFi). You can see your IP address with 'ip addr', test connectivity with 'ping', and check what's listening for connections with 'ss -tuln'. The firewall controls what traffic is allowed in and out - on Ubuntu, 'ufw' makes this easy (ufw enable, ufw allow 22/tcp for SSH). Understanding networking is essential because most security work involves network traffic.",
    keyPoints: [
      "Network interfaces: eth0, wlan0, lo, ens33",
      "IP configuration: ip addr, ifconfig (legacy)",
      "Routing tables: ip route, route (legacy)",
      "DNS resolution: /etc/resolv.conf, systemd-resolved",
      "Firewall: iptables, nftables, firewalld, ufw",
      "Network services: SSH (22), HTTP (80/443)",
      "Socket files for local IPC",
      "Network namespaces for isolation",
    ],
    securityNote: "Close unnecessary ports. Use SSH keys instead of passwords. Enable firewall.",
  },
];

// Linux distributions - basic overview
const linuxDistributions = [
  { 
    name: "Ubuntu", 
    family: "Debian", 
    packageManager: "APT", 
    useCase: "Desktop, Server, Cloud",
    releaseModel: "Fixed (LTS 5 years)",
    notes: "Most popular desktop distro. Large community.",
  },
  { 
    name: "Debian", 
    family: "Debian", 
    packageManager: "APT", 
    useCase: "Server, Stability-focused",
    releaseModel: "Fixed (stable releases)",
    notes: "Rock-solid stability. Foundation for many distros.",
  },
  { 
    name: "Red Hat Enterprise Linux", 
    family: "RHEL", 
    packageManager: "DNF", 
    useCase: "Enterprise Server",
    releaseModel: "Fixed (10 year lifecycle)",
    notes: "Industry standard for enterprise. Paid support.",
  },
  { 
    name: "Fedora", 
    family: "RHEL", 
    packageManager: "DNF", 
    useCase: "Workstation, Cutting-edge",
    releaseModel: "Fixed (~13 months)",
    notes: "Upstream for RHEL. Latest features.",
  },
  { 
    name: "Arch Linux", 
    family: "Arch", 
    packageManager: "Pacman", 
    useCase: "Advanced Users, DIY",
    releaseModel: "Rolling",
    notes: "Bleeding edge. Excellent documentation (ArchWiki).",
  },
  { 
    name: "Kali Linux", 
    family: "Debian", 
    packageManager: "APT", 
    useCase: "Penetration Testing",
    releaseModel: "Rolling",
    notes: "Pre-installed security tools. NOT for daily use.",
  },
  { 
    name: "Alpine Linux", 
    family: "Alpine", 
    packageManager: "APK", 
    useCase: "Containers, Minimal",
    releaseModel: "Fixed",
    notes: "Tiny footprint (~5MB). musl libc. Docker favorite.",
  },
];

// Detailed Ubuntu info
const ubuntuDetails = {
  name: "Ubuntu",
  developer: "Canonical Ltd.",
  firstRelease: "October 20, 2004",
  basedOn: "Debian",
  defaultDesktop: "GNOME (Ubuntu Desktop)",
  packageFormat: ".deb",
  packageManager: "APT (apt, apt-get, dpkg)",
  versions: [
    { version: "24.04 LTS", codename: "Noble Numbat", release: "April 2024", support: "April 2029 (Standard), April 2034 (ESM)" },
    { version: "23.10", codename: "Mantic Minotaur", release: "October 2023", support: "July 2024" },
    { version: "22.04 LTS", codename: "Jammy Jellyfish", release: "April 2022", support: "April 2027 (Standard), April 2032 (ESM)" },
    { version: "20.04 LTS", codename: "Focal Fossa", release: "April 2020", support: "April 2025 (Standard), April 2030 (ESM)" },
    { version: "18.04 LTS", codename: "Bionic Beaver", release: "April 2018", support: "April 2023 (Standard), April 2028 (ESM)" },
  ],
  flavors: [
    { name: "Ubuntu Desktop", description: "Default GNOME desktop for personal use" },
    { name: "Ubuntu Server", description: "CLI-only server installation" },
    { name: "Ubuntu Cloud", description: "Optimized for cloud deployment (AWS, Azure, GCP)" },
    { name: "Kubuntu", description: "KDE Plasma desktop" },
    { name: "Xubuntu", description: "Xfce desktop (lightweight)" },
    { name: "Lubuntu", description: "LXQt desktop (very lightweight)" },
    { name: "Ubuntu MATE", description: "MATE desktop (traditional)" },
    { name: "Ubuntu Studio", description: "Multimedia production" },
  ],
  keyCommands: [
    { cmd: "sudo apt update", desc: "Update package lists" },
    { cmd: "sudo apt upgrade", desc: "Upgrade installed packages" },
    { cmd: "sudo apt install <pkg>", desc: "Install a package" },
    { cmd: "sudo apt remove <pkg>", desc: "Remove a package" },
    { cmd: "sudo apt autoremove", desc: "Remove unused dependencies" },
    { cmd: "apt search <term>", desc: "Search for packages" },
    { cmd: "apt show <pkg>", desc: "Show package details" },
    { cmd: "dpkg -l", desc: "List all installed packages" },
    { cmd: "do-release-upgrade", desc: "Upgrade to next Ubuntu release" },
  ],
};

// Detailed Kali Linux info
const kaliDetails = {
  name: "Kali Linux",
  developer: "Offensive Security",
  firstRelease: "March 13, 2013",
  basedOn: "Debian Testing",
  predecessor: "BackTrack Linux",
  defaultDesktop: "Xfce (formerly GNOME)",
  packageFormat: ".deb",
  packageManager: "APT",
  versions: [
    { version: "2024.4", release: "December 2024", kernel: "6.11", notes: "Latest rolling release" },
    { version: "2024.3", release: "September 2024", kernel: "6.10", notes: "New tools, ARM improvements" },
    { version: "2024.2", release: "June 2024", kernel: "6.8", notes: "t64 transition, new tools" },
    { version: "2024.1", release: "February 2024", kernel: "6.6", notes: "Yearly theme refresh" },
    { version: "2023.4", release: "December 2023", kernel: "6.5", notes: "GNOME 45, new tools" },
  ],
  editions: [
    { name: "Kali Installer", description: "Full installation to disk" },
    { name: "Kali Live", description: "Boot from USB without installing" },
    { name: "Kali NetInstaller", description: "Minimal installer, downloads packages" },
    { name: "Kali VM", description: "Pre-built VMware/VirtualBox images" },
    { name: "Kali ARM", description: "For Raspberry Pi, ARM devices" },
    { name: "Kali Cloud", description: "AWS, Azure, Linode images" },
    { name: "Kali Docker", description: "Official Docker container" },
    { name: "Kali WSL", description: "Windows Subsystem for Linux" },
  ],
  toolCategories: [
    { category: "Information Gathering", tools: "nmap, recon-ng, maltego, theharvester" },
    { category: "Vulnerability Analysis", tools: "nikto, nessus, openvas, legion" },
    { category: "Web Application", tools: "burpsuite, sqlmap, dirb, wpscan" },
    { category: "Password Attacks", tools: "john, hashcat, hydra, medusa" },
    { category: "Wireless Attacks", tools: "aircrack-ng, kismet, wifite, fern" },
    { category: "Exploitation", tools: "metasploit, exploitdb, armitage" },
    { category: "Sniffing/Spoofing", tools: "wireshark, ettercap, bettercap" },
    { category: "Post Exploitation", tools: "mimikatz, bloodhound, empire" },
    { category: "Forensics", tools: "autopsy, binwalk, volatility, sleuthkit" },
    { category: "Reverse Engineering", tools: "ghidra, radare2, gdb, objdump" },
  ],
  keyCommands: [
    { cmd: "sudo apt update && sudo apt full-upgrade", desc: "Update Kali (rolling)" },
    { cmd: "kali-tweaks", desc: "Configure Kali settings" },
    { cmd: "sudo apt install kali-linux-large", desc: "Install all tools (large)" },
    { cmd: "sudo apt install kali-tools-web", desc: "Install web testing tools" },
    { cmd: "msfconsole", desc: "Launch Metasploit Framework" },
    { cmd: "searchsploit <term>", desc: "Search ExploitDB locally" },
  ],
};

// Detailed Red Hat info
const rhelDetails = {
  name: "Red Hat Enterprise Linux (RHEL)",
  developer: "Red Hat, Inc. (IBM subsidiary)",
  firstRelease: "February 22, 2000",
  basedOn: "Fedora (upstream)",
  defaultDesktop: "GNOME",
  packageFormat: ".rpm",
  packageManager: "DNF (formerly YUM)",
  versions: [
    { version: "RHEL 9.4", release: "May 2024", kernel: "5.14", support: "May 2032", notes: "Latest minor release" },
    { version: "RHEL 9.0", release: "May 2022", kernel: "5.14", support: "May 2032", notes: "Current major version" },
    { version: "RHEL 8.10", release: "May 2024", kernel: "4.18", support: "May 2029", notes: "Latest RHEL 8 minor" },
    { version: "RHEL 8.0", release: "May 2019", kernel: "4.18", support: "May 2029", notes: "Previous major version" },
    { version: "RHEL 7.9", release: "September 2020", kernel: "3.10", support: "June 2024 (Maintenance)", notes: "Legacy, extended support" },
  ],
  freeAlternatives: [
    { name: "CentOS Stream", description: "Upstream for RHEL, rolling preview" },
    { name: "Rocky Linux", description: "1:1 RHEL binary compatible, community-driven" },
    { name: "AlmaLinux", description: "1:1 RHEL binary compatible, CloudLinux backed" },
    { name: "Oracle Linux", description: "RHEL compatible, Oracle support available" },
  ],
  certifications: [
    { name: "RHCSA", fullName: "Red Hat Certified System Administrator", exam: "EX200" },
    { name: "RHCE", fullName: "Red Hat Certified Engineer", exam: "EX294" },
    { name: "RHCA", fullName: "Red Hat Certified Architect", exam: "Multiple" },
  ],
  keyCommands: [
    { cmd: "sudo dnf update", desc: "Update all packages" },
    { cmd: "sudo dnf install <pkg>", desc: "Install a package" },
    { cmd: "sudo dnf remove <pkg>", desc: "Remove a package" },
    { cmd: "sudo dnf search <term>", desc: "Search for packages" },
    { cmd: "sudo dnf info <pkg>", desc: "Show package info" },
    { cmd: "rpm -qa", desc: "List all installed RPMs" },
    { cmd: "sudo subscription-manager register", desc: "Register RHEL subscription" },
    { cmd: "sudo dnf module list", desc: "List available module streams" },
    { cmd: "firewall-cmd --list-all", desc: "Show firewall rules" },
    { cmd: "sestatus", desc: "Show SELinux status" },
  ],
  enterprises: "Used by: Fortune 500 companies, US Government, NYSE, major banks, airlines, healthcare systems",
};

// Linux history and timeline
const linuxHistory = [
  { year: "1969", event: "Unix created at AT&T Bell Labs by Ken Thompson and Dennis Ritchie" },
  { year: "1983", event: "Richard Stallman announces GNU Project to create free Unix-like OS" },
  { year: "1987", event: "MINIX released by Andrew Tanenbaum for teaching" },
  { year: "1991", event: "Linus Torvalds announces Linux kernel (version 0.01) on comp.os.minix" },
  { year: "1992", event: "Linux relicensed under GPL; first distributions emerge (SLS, Yggdrasil)" },
  { year: "1993", event: "Slackware and Debian founded - oldest surviving distros" },
  { year: "1994", event: "Linux 1.0 released; Red Hat Linux founded" },
  { year: "1996", event: "Linux 2.0 with SMP support; Tux mascot created" },
  { year: "1998", event: "Major companies (IBM, Oracle) announce Linux support" },
  { year: "2000", event: "Red Hat Enterprise Linux (RHEL) first released" },
  { year: "2004", event: "Ubuntu 4.10 'Warty Warthog' released by Canonical" },
  { year: "2007", event: "Android announced (Linux-based mobile OS)" },
  { year: "2011", event: "Linux 3.0 released; Linux runs on 91% of supercomputers" },
  { year: "2013", event: "Kali Linux replaces BackTrack; Docker released" },
  { year: "2015", event: "Linux 4.0 released; Microsoft announces Linux support" },
  { year: "2020", event: "Linux 5.x powers 100% of TOP500 supercomputers" },
  { year: "2022", event: "Linux 6.0 released with Rust language support" },
  { year: "2024", event: "Linux kernel 6.x; 33+ years of development, 30M+ lines of code" },
];

// Linux market share stats
const linuxStats = [
  { stat: "96.3%", description: "of top 1 million web servers run Linux" },
  { stat: "100%", description: "of TOP500 supercomputers run Linux" },
  { stat: "85%+", description: "of smartphones run Linux (Android)" },
  { stat: "90%+", description: "of cloud infrastructure runs Linux" },
  { stat: "70%+", description: "of embedded devices run Linux" },
  { stat: "30M+", description: "lines of code in the Linux kernel" },
  { stat: "20,000+", description: "developers have contributed to Linux kernel" },
  { stat: "600+", description: "active Linux distributions" },
];

// Linux boot process
const bootProcess = [
  { 
    step: 1, 
    name: "BIOS/UEFI", 
    description: "Firmware initializes hardware, runs POST, finds bootloader",
    details: "UEFI is modern replacement for BIOS. Secure Boot validates signatures.",
  },
  { 
    step: 2, 
    name: "Bootloader (GRUB2)", 
    description: "Loads kernel and initramfs into memory",
    details: "Config in /boot/grub/grub.cfg. Can boot multiple OSes.",
  },
  { 
    step: 3, 
    name: "Kernel Initialization", 
    description: "Kernel decompresses, initializes hardware, mounts initramfs",
    details: "Kernel parameters passed via bootloader. dmesg shows boot messages.",
  },
  { 
    step: 4, 
    name: "initramfs/initrd", 
    description: "Temporary root filesystem loads necessary drivers",
    details: "Needed to access real root filesystem (LVM, RAID, encryption).",
  },
  { 
    step: 5, 
    name: "Init System (systemd)", 
    description: "First userspace process (PID 1) starts services",
    details: "systemd replaced SysVinit/Upstart on most distros.",
  },
  { 
    step: 6, 
    name: "Target/Runlevel", 
    description: "System reaches target state (multi-user, graphical)",
    details: "multi-user.target = runlevel 3, graphical.target = runlevel 5",
  },
];

// Important directories
const importantDirectories = [
  { path: "/", description: "Root of the file system - everything starts here", purpose: "System", forensicNote: "Check for hidden files in root" },
  { path: "/bin", description: "Essential user binaries (ls, cp, cat, bash)", purpose: "System", forensicNote: "Symlinked to /usr/bin on modern systems" },
  { path: "/sbin", description: "System binaries requiring root (fdisk, iptables)", purpose: "System", forensicNote: "Critical for system administration" },
  { path: "/etc", description: "System-wide configuration files", purpose: "Config", forensicNote: "Check for unauthorized config changes" },
  { path: "/etc/passwd", description: "User account information (world-readable)", purpose: "Config", forensicNote: "New users? Unusual shells? UID 0 accounts?" },
  { path: "/etc/shadow", description: "Encrypted password hashes (root only)", purpose: "Security", forensicNote: "Check permissions - must be 640 or 600" },
  { path: "/etc/sudoers", description: "Sudo privilege configuration", purpose: "Security", forensicNote: "NOPASSWD entries? Unusual privileges?" },
  { path: "/etc/ssh", description: "SSH server configuration and keys", purpose: "Security", forensicNote: "Check authorized_keys, sshd_config changes" },
  { path: "/etc/cron.d", description: "System cron jobs directory", purpose: "Config", forensicNote: "Persistence mechanism - check for malicious jobs" },
  { path: "/home", description: "User home directories", purpose: "User Data", forensicNote: "Check .bash_history, .ssh, hidden files" },
  { path: "/root", description: "Root user's home directory", purpose: "User Data", forensicNote: "High-value target for attackers" },
  { path: "/var", description: "Variable data (logs, mail, spool, www)", purpose: "Data", forensicNote: "Logs, web data, mail queues" },
  { path: "/var/log", description: "System and application logs", purpose: "Logs", forensicNote: "auth.log, syslog, apache2/, audit/" },
  { path: "/var/www", description: "Web server document root (default)", purpose: "Web", forensicNote: "Web shells, defacements, uploads" },
  { path: "/tmp", description: "Temporary files (world-writable, cleared on reboot)", purpose: "Temporary", forensicNote: "Common malware staging location" },
  { path: "/var/tmp", description: "Persistent temporary files (survives reboot)", purpose: "Temporary", forensicNote: "Another staging/persistence location" },
  { path: "/usr", description: "User programs, libraries, documentation", purpose: "System", forensicNote: "Should not change after install" },
  { path: "/usr/local", description: "Locally installed software (not from packages)", purpose: "Applications", forensicNote: "Manual installs, custom software" },
  { path: "/opt", description: "Optional/third-party software", purpose: "Applications", forensicNote: "Commercial software, manual installs" },
  { path: "/dev", description: "Device files (block, character devices)", purpose: "System", forensicNote: "/dev/null, /dev/zero, /dev/random" },
  { path: "/dev/shm", description: "Shared memory (tmpfs, world-writable)", purpose: "Memory", forensicNote: "In-memory malware execution" },
  { path: "/proc", description: "Virtual filesystem exposing process/kernel info", purpose: "Virtual", forensicNote: "/proc/[pid]/, /proc/net/, /proc/self/" },
  { path: "/sys", description: "Virtual filesystem for kernel/hardware config", purpose: "Virtual", forensicNote: "Hardware and driver information" },
  { path: "/boot", description: "Boot loader files, kernel, initramfs", purpose: "System", forensicNote: "Bootkit/rootkit persistence" },
  { path: "/lib", description: "Essential shared libraries for /bin and /sbin", purpose: "System", forensicNote: "Library injection attacks" },
  { path: "/run", description: "Runtime data (PIDs, sockets) - cleared on boot", purpose: "Runtime", forensicNote: "Temporary runtime state" },
];

// Important configuration files
const importantConfigFiles = [
  { file: "/etc/passwd", description: "User accounts (username:x:UID:GID:info:home:shell)", permissions: "644" },
  { file: "/etc/shadow", description: "Encrypted passwords and aging info", permissions: "640" },
  { file: "/etc/group", description: "Group definitions (group:x:GID:members)", permissions: "644" },
  { file: "/etc/sudoers", description: "Sudo privileges (edit with visudo only!)", permissions: "440" },
  { file: "/etc/fstab", description: "Filesystem mount configuration (auto-mount)", permissions: "644" },
  { file: "/etc/hosts", description: "Static hostname to IP mappings", permissions: "644" },
  { file: "/etc/resolv.conf", description: "DNS resolver configuration", permissions: "644" },
  { file: "/etc/hostname", description: "System hostname", permissions: "644" },
  { file: "/etc/crontab", description: "System-wide cron schedule", permissions: "644" },
  { file: "/etc/ssh/sshd_config", description: "SSH server configuration", permissions: "644" },
  { file: "/etc/sysctl.conf", description: "Kernel parameter configuration", permissions: "644" },
  { file: "/etc/security/limits.conf", description: "User resource limits", permissions: "644" },
  { file: "~/.bashrc", description: "User bash configuration (interactive shells)", permissions: "644" },
  { file: "~/.bash_profile", description: "User bash login configuration", permissions: "644" },
  { file: "~/.ssh/authorized_keys", description: "Allowed SSH public keys", permissions: "600" },
];

// Essential commands - greatly expanded
const essentialCommands = [
  // Navigation & File Management
  { command: "ls", description: "List directory contents", example: "ls -la", category: "Navigation", flags: "-l (long), -a (all), -h (human), -R (recursive)" },
  { command: "cd", description: "Change directory", example: "cd /var/log", category: "Navigation", flags: "cd - (previous), cd ~ (home)" },
  { command: "pwd", description: "Print working directory", example: "pwd", category: "Navigation", flags: "-P (physical path)" },
  { command: "mkdir", description: "Create directories", example: "mkdir -p /path/to/dir", category: "Files", flags: "-p (create parents)" },
  { command: "cat", description: "Display/concatenate file contents", example: "cat /etc/passwd", category: "Files", flags: "-n (numbers), -A (show all)" },
  { command: "less/more", description: "View files with pagination", example: "less /var/log/syslog", category: "Files", flags: "/ (search), q (quit), G (end)" },
  { command: "head/tail", description: "View start/end of files", example: "tail -f /var/log/auth.log", category: "Files", flags: "-n (lines), -f (follow)" },
  { command: "cp", description: "Copy files/directories", example: "cp -rp src dest", category: "Files", flags: "-r (recursive), -p (preserve)" },
  { command: "mv", description: "Move or rename files", example: "mv old.txt new.txt", category: "Files", flags: "-i (interactive), -n (no clobber)" },
  { command: "rm", description: "Remove files/directories", example: "rm -rf directory", category: "Files", flags: "-r (recursive), -f (force), -i (interactive)" },
  { command: "ln", description: "Create links", example: "ln -s /target /link", category: "Files", flags: "-s (symbolic), default=hard link" },
  { command: "touch", description: "Create empty file / update timestamps", example: "touch newfile.txt", category: "Files", flags: "-a (access), -m (modify)" },
  { command: "file", description: "Determine file type", example: "file mystery.bin", category: "Files", flags: "-i (MIME type)" },
  { command: "stat", description: "Display file/filesystem status", example: "stat /etc/passwd", category: "Files", flags: "Shows inode, permissions, times" },
  
  // Permissions & Ownership
  { command: "chmod", description: "Change file permissions", example: "chmod 755 script.sh", category: "Permissions", flags: "+x (add exec), -R (recursive)" },
  { command: "chown", description: "Change file ownership", example: "chown user:group file", category: "Permissions", flags: "-R (recursive)" },
  { command: "chgrp", description: "Change group ownership", example: "chgrp developers file", category: "Permissions", flags: "-R (recursive)" },
  { command: "umask", description: "Set default permissions mask", example: "umask 022", category: "Permissions", flags: "Subtracts from 777/666" },
  { command: "getfacl", description: "Get file ACLs", example: "getfacl /path/file", category: "Permissions", flags: "Extended permissions beyond rwx" },
  { command: "setfacl", description: "Set file ACLs", example: "setfacl -m u:user:rwx file", category: "Permissions", flags: "-m (modify), -x (remove)" },
  
  // Process Management
  { command: "ps", description: "List processes", example: "ps aux", category: "Processes", flags: "a (all), u (user), x (no tty)" },
  { command: "top/htop", description: "Interactive process monitor", example: "htop", category: "Processes", flags: "k (kill), r (renice), f (fields)" },
  { command: "kill", description: "Send signal to process", example: "kill -9 PID", category: "Processes", flags: "-9 (SIGKILL), -15 (SIGTERM)" },
  { command: "killall", description: "Kill processes by name", example: "killall nginx", category: "Processes", flags: "-9 (force), -i (interactive)" },
  { command: "pkill/pgrep", description: "Kill/find by pattern", example: "pkill -u user", category: "Processes", flags: "-u (user), -f (full cmd)" },
  { command: "nice/renice", description: "Set/change process priority", example: "nice -n 10 command", category: "Processes", flags: "-20 (high) to 19 (low)" },
  { command: "nohup", description: "Run command immune to hangups", example: "nohup ./script.sh &", category: "Processes", flags: "Output to nohup.out" },
  { command: "jobs/bg/fg", description: "Job control", example: "bg %1", category: "Processes", flags: "Ctrl+Z (suspend), & (background)" },
  { command: "lsof", description: "List open files/sockets", example: "lsof -i :80", category: "Processes", flags: "-i (network), -u (user), -p (pid)" },
  { command: "strace", description: "Trace system calls", example: "strace -p PID", category: "Processes", flags: "-f (follow forks), -e (filter)" },
  
  // Search & Text Processing
  { command: "grep", description: "Search text patterns", example: "grep -r 'error' /var/log", category: "Search", flags: "-r (recursive), -i (ignore case), -v (invert)" },
  { command: "find", description: "Find files by criteria", example: "find / -name '*.conf' -type f", category: "Search", flags: "-name, -type, -perm, -mtime, -exec" },
  { command: "locate", description: "Fast file search (uses database)", example: "locate passwd", category: "Search", flags: "Run updatedb first" },
  { command: "which/whereis", description: "Locate command binary", example: "which python", category: "Search", flags: "whereis includes man/src" },
  { command: "awk", description: "Pattern scanning and processing", example: "awk '{print $1}' file", category: "Text", flags: "-F (delimiter), powerful language" },
  { command: "sed", description: "Stream editor for filtering/transform", example: "sed 's/old/new/g' file", category: "Text", flags: "-i (in-place), -e (expression)" },
  { command: "cut", description: "Extract sections from lines", example: "cut -d: -f1 /etc/passwd", category: "Text", flags: "-d (delimiter), -f (fields)" },
  { command: "sort", description: "Sort lines", example: "sort -u file", category: "Text", flags: "-n (numeric), -r (reverse), -u (unique)" },
  { command: "uniq", description: "Report/filter repeated lines", example: "sort file | uniq -c", category: "Text", flags: "-c (count), -d (duplicates)" },
  { command: "wc", description: "Count lines, words, bytes", example: "wc -l file", category: "Text", flags: "-l (lines), -w (words), -c (bytes)" },
  { command: "diff", description: "Compare files line by line", example: "diff file1 file2", category: "Text", flags: "-u (unified), -r (recursive)" },
  { command: "tr", description: "Translate/delete characters", example: "tr 'a-z' 'A-Z'", category: "Text", flags: "-d (delete), -s (squeeze)" },
  
  // User & System Administration
  { command: "sudo", description: "Execute as superuser", example: "sudo apt update", category: "Admin", flags: "-u (user), -i (login shell), -l (list)" },
  { command: "su", description: "Switch user", example: "su - username", category: "Admin", flags: "- (login shell)" },
  { command: "useradd", description: "Create user account", example: "useradd -m -s /bin/bash user", category: "Admin", flags: "-m (home), -s (shell), -G (groups)" },
  { command: "usermod", description: "Modify user account", example: "usermod -aG sudo user", category: "Admin", flags: "-aG (append group), -L (lock)" },
  { command: "userdel", description: "Delete user account", example: "userdel -r user", category: "Admin", flags: "-r (remove home)" },
  { command: "passwd", description: "Change password", example: "passwd username", category: "Admin", flags: "-l (lock), -u (unlock), -e (expire)" },
  { command: "groups", description: "Show user's groups", example: "groups username", category: "Admin", flags: "id -Gn (alternative)" },
  { command: "id", description: "Show user/group IDs", example: "id username", category: "Admin", flags: "-u (UID), -g (GID), -G (all groups)" },
  { command: "whoami", description: "Print effective username", example: "whoami", category: "Admin", flags: "id -un (alternative)" },
  { command: "last", description: "Show login history", example: "last -n 20", category: "Admin", flags: "-n (count), lastb (bad logins)" },
  { command: "w/who", description: "Show logged-in users", example: "w", category: "Admin", flags: "Shows activity, idle time" },
  
  // Services & systemd
  { command: "systemctl", description: "Control systemd services", example: "systemctl status sshd", category: "Services", flags: "start, stop, restart, enable, disable" },
  { command: "journalctl", description: "Query systemd journal", example: "journalctl -u nginx -f", category: "Services", flags: "-u (unit), -f (follow), -b (boot)" },
  { command: "service", description: "SysVinit service control (legacy)", example: "service nginx restart", category: "Services", flags: "Wrapper for systemctl" },
  
  // Networking
  { command: "ip", description: "Network configuration (modern)", example: "ip addr show", category: "Network", flags: "addr, route, link, neigh" },
  { command: "ifconfig", description: "Network interfaces (legacy)", example: "ifconfig eth0", category: "Network", flags: "Deprecated, use ip" },
  { command: "ping", description: "Test network connectivity", example: "ping -c 4 google.com", category: "Network", flags: "-c (count), -i (interval)" },
  { command: "netstat", description: "Network statistics (legacy)", example: "netstat -tulpn", category: "Network", flags: "-t (tcp), -u (udp), -l (listen), -p (pid)" },
  { command: "ss", description: "Socket statistics (modern)", example: "ss -tulpn", category: "Network", flags: "Same flags as netstat" },
  { command: "curl", description: "Transfer data from URLs", example: "curl -I https://example.com", category: "Network", flags: "-I (headers), -o (output), -X (method)" },
  { command: "wget", description: "Download files", example: "wget https://example.com/file", category: "Network", flags: "-O (output), -r (recursive), -c (continue)" },
  { command: "dig/nslookup", description: "DNS lookup", example: "dig example.com", category: "Network", flags: "+short, MX, NS, TXT" },
  { command: "traceroute", description: "Trace packet route", example: "traceroute google.com", category: "Network", flags: "-n (no DNS), -I (ICMP)" },
  { command: "nc (netcat)", description: "Network Swiss army knife", example: "nc -zv host 1-1000", category: "Network", flags: "-l (listen), -z (scan), -v (verbose)" },
  { command: "tcpdump", description: "Packet capture", example: "tcpdump -i eth0 port 80", category: "Network", flags: "-i (interface), -w (write pcap)" },
  
  // Disk & Storage
  { command: "df", description: "Disk space usage", example: "df -h", category: "Disk", flags: "-h (human), -i (inodes)" },
  { command: "du", description: "Directory space usage", example: "du -sh /var/*", category: "Disk", flags: "-s (summary), -h (human)" },
  { command: "mount/umount", description: "Mount/unmount filesystems", example: "mount /dev/sda1 /mnt", category: "Disk", flags: "-t (type), -o (options)" },
  { command: "fdisk", description: "Partition management", example: "fdisk -l", category: "Disk", flags: "-l (list), interactive mode" },
  { command: "lsblk", description: "List block devices", example: "lsblk -f", category: "Disk", flags: "-f (filesystems)" },
  { command: "blkid", description: "Block device attributes", example: "blkid", category: "Disk", flags: "Shows UUID, TYPE" },
  
  // Archives & Compression
  { command: "tar", description: "Archive files", example: "tar -czvf archive.tar.gz dir/", category: "Archives", flags: "-c (create), -x (extract), -z (gzip), -v (verbose)" },
  { command: "gzip/gunzip", description: "Compress/decompress", example: "gzip file", category: "Archives", flags: "-d (decompress), -k (keep)" },
  { command: "zip/unzip", description: "ZIP archives", example: "zip -r archive.zip dir/", category: "Archives", flags: "-r (recursive)" },
  { command: "xz", description: "High compression ratio", example: "xz -9 file", category: "Archives", flags: "-d (decompress), -9 (max compression)" },
  { command: "bzip2", description: "Block-sorting compression", example: "bzip2 file", category: "Archives", flags: "-d (decompress), -k (keep)" },
  { command: "7z", description: "7-Zip archiver", example: "7z x archive.7z", category: "Archives", flags: "a (add), x (extract), l (list)" },
  
  // System Information
  { command: "uname", description: "System information", example: "uname -a", category: "System", flags: "-a (all), -r (kernel), -m (machine)" },
  { command: "hostname", description: "Show/set hostname", example: "hostname -I", category: "System", flags: "-I (IP addresses)" },
  { command: "uptime", description: "System uptime and load", example: "uptime", category: "System", flags: "Shows load averages" },
  { command: "free", description: "Memory usage", example: "free -h", category: "System", flags: "-h (human), -m (MB)" },
  { command: "dmesg", description: "Kernel ring buffer messages", example: "dmesg | tail", category: "System", flags: "-T (timestamps), --level" },
  { command: "date", description: "Display/set date/time", example: "date +%Y-%m-%d", category: "System", flags: "Format strings" },
  { command: "history", description: "Command history", example: "history | grep ssh", category: "System", flags: "!n (run nth), !! (repeat last)" },
  { command: "alias", description: "Create command shortcuts", example: "alias ll='ls -la'", category: "System", flags: "Add to .bashrc for persistence" },
  { command: "env/printenv", description: "Show environment variables", example: "env | grep PATH", category: "System", flags: "export VAR=value (set)" },
  { command: "lscpu", description: "CPU architecture information", example: "lscpu", category: "System", flags: "Shows cores, threads, cache" },
  { command: "lsusb", description: "List USB devices", example: "lsusb -v", category: "System", flags: "-v (verbose), -t (tree)" },
  { command: "lspci", description: "List PCI devices", example: "lspci -v", category: "System", flags: "-v (verbose), -k (kernel drivers)" },
  { command: "dmidecode", description: "Hardware information from BIOS", example: "dmidecode -t memory", category: "System", flags: "-t (type: bios, system, memory)" },
  
  // Security & Forensics
  { command: "md5sum/sha256sum", description: "Compute file checksums", example: "sha256sum file", category: "Security", flags: "-c (check), sha1sum, sha512sum also" },
  { command: "openssl", description: "Cryptography toolkit", example: "openssl enc -aes-256-cbc -in file", category: "Security", flags: "enc, dgst, req, x509, rsa" },
  { command: "ssh-keygen", description: "Generate SSH keys", example: "ssh-keygen -t ed25519", category: "Security", flags: "-t (type), -b (bits), -C (comment)" },
  { command: "ssh-copy-id", description: "Copy SSH key to server", example: "ssh-copy-id user@host", category: "Security", flags: "-i (identity file)" },
  { command: "gpg", description: "GNU Privacy Guard", example: "gpg --encrypt -r user file", category: "Security", flags: "--encrypt, --decrypt, --sign, --verify" },
  { command: "chroot", description: "Change root directory", example: "chroot /mnt/system /bin/bash", category: "Security", flags: "Used for recovery/containers" },
  { command: "auditctl", description: "Audit system control", example: "auditctl -l", category: "Security", flags: "-l (list), -w (watch), -a (add rule)" },
  { command: "ausearch", description: "Search audit logs", example: "ausearch -k login", category: "Security", flags: "-k (key), -m (message type)" },
  { command: "aureport", description: "Audit log reports", example: "aureport --login", category: "Security", flags: "--login, --auth, --file, --summary" },
  { command: "lastlog", description: "Recent login of all users", example: "lastlog", category: "Security", flags: "-u (user), -t (days)" },
  { command: "faillog", description: "Display login failures", example: "faillog -u user", category: "Security", flags: "-u (user), -r (reset)" },
  
  // Package Management (Multi-distro)
  { command: "apt/apt-get", description: "Debian/Ubuntu package manager", example: "apt install pkg", category: "Packages", flags: "install, remove, update, upgrade, search" },
  { command: "dpkg", description: "Debian package manager (low-level)", example: "dpkg -l | grep pkg", category: "Packages", flags: "-i (install), -r (remove), -l (list)" },
  { command: "dnf/yum", description: "RHEL/Fedora package manager", example: "dnf install pkg", category: "Packages", flags: "install, remove, update, search, info" },
  { command: "rpm", description: "RPM package manager (low-level)", example: "rpm -qa | grep pkg", category: "Packages", flags: "-i (install), -e (erase), -q (query)" },
  { command: "pacman", description: "Arch Linux package manager", example: "pacman -S pkg", category: "Packages", flags: "-S (sync), -R (remove), -Q (query)" },
  { command: "snap", description: "Snap package manager", example: "snap install pkg", category: "Packages", flags: "install, remove, list, refresh" },
  { command: "flatpak", description: "Flatpak package manager", example: "flatpak install app", category: "Packages", flags: "install, uninstall, list, run" },
  
  // Advanced Text Processing
  { command: "xargs", description: "Build command lines from input", example: "find . -name '*.log' | xargs rm", category: "Text", flags: "-I (replace), -P (parallel), -0 (null)" },
  { command: "tee", description: "Read stdin, write to stdout and files", example: "echo 'text' | tee file.txt", category: "Text", flags: "-a (append)" },
  { command: "column", description: "Format into columns", example: "cat file | column -t", category: "Text", flags: "-t (table), -s (separator)" },
  { command: "paste", description: "Merge lines of files", example: "paste file1 file2", category: "Text", flags: "-d (delimiter)" },
  { command: "split", description: "Split file into pieces", example: "split -b 100M file", category: "Text", flags: "-b (bytes), -l (lines), -n (number)" },
  { command: "csplit", description: "Split by context/pattern", example: "csplit file '/pattern/' {*}", category: "Text", flags: "Context-based splitting" },
  { command: "comm", description: "Compare sorted files line-by-line", example: "comm file1 file2", category: "Text", flags: "-1 (hide col1), -2, -3" },
  { command: "join", description: "Join lines on common field", example: "join file1 file2", category: "Text", flags: "-t (delimiter), -1/-2 (field)" },
  
  // Debugging & Performance
  { command: "ltrace", description: "Library call tracer", example: "ltrace ./program", category: "Debug", flags: "-p (pid), -e (filter), -c (count)" },
  { command: "gdb", description: "GNU debugger", example: "gdb ./program", category: "Debug", flags: "run, break, step, continue, print" },
  { command: "perf", description: "Performance analysis", example: "perf stat command", category: "Debug", flags: "stat, record, report, top" },
  { command: "vmstat", description: "Virtual memory statistics", example: "vmstat 1 5", category: "Debug", flags: "interval count" },
  { command: "iostat", description: "I/O statistics", example: "iostat -x 1", category: "Debug", flags: "-x (extended), -d (device)" },
  { command: "sar", description: "System activity reporter", example: "sar -u 1 5", category: "Debug", flags: "-u (CPU), -r (memory), -d (disk)" },
  { command: "mpstat", description: "Processor statistics", example: "mpstat -P ALL 1", category: "Debug", flags: "-P (processor)" },
  
  // Containers & Virtualization
  { command: "docker", description: "Container management", example: "docker run -it ubuntu bash", category: "Containers", flags: "run, ps, images, exec, logs, build" },
  { command: "docker-compose", description: "Multi-container Docker", example: "docker-compose up -d", category: "Containers", flags: "up, down, logs, ps, build" },
  { command: "podman", description: "Rootless containers", example: "podman run -it alpine sh", category: "Containers", flags: "Same as Docker, daemonless" },
  { command: "kubectl", description: "Kubernetes CLI", example: "kubectl get pods", category: "Containers", flags: "get, describe, apply, delete, logs" },
  { command: "crictl", description: "CRI container runtime CLI", example: "crictl ps", category: "Containers", flags: "ps, images, logs, exec" },
];

// File permissions reference - expanded
const permissionsReference = [
  { symbol: "r", numeric: "4", meaning: "Read", fileEffect: "View contents", dirEffect: "List contents (ls)" },
  { symbol: "w", numeric: "2", meaning: "Write", fileEffect: "Modify contents", dirEffect: "Create/delete files" },
  { symbol: "x", numeric: "1", meaning: "Execute", fileEffect: "Run as program", dirEffect: "Enter directory (cd)" },
];

// Special permission bits
const specialPermissions = [
  { name: "SUID", numeric: "4000", symbol: "s (user x)", description: "Execute as file owner", example: "/usr/bin/passwd", risk: "Privilege escalation if misconfigured" },
  { name: "SGID", numeric: "2000", symbol: "s (group x)", description: "Execute as group / inherit group on new files", example: "/usr/bin/wall", risk: "Group privilege escalation" },
  { name: "Sticky Bit", numeric: "1000", symbol: "t (other x)", description: "Only owner can delete files in directory", example: "/tmp", risk: "Low - protective measure" },
];

// Common permission examples
const permissionExamples = [
  { numeric: "777", symbolic: "rwxrwxrwx", description: "Full access for everyone", useCase: "NEVER use - major security risk" },
  { numeric: "755", symbolic: "rwxr-xr-x", description: "Owner full, others read/execute", useCase: "Directories, executable scripts" },
  { numeric: "644", symbolic: "rw-r--r--", description: "Owner read/write, others read", useCase: "Regular files, configs" },
  { numeric: "700", symbolic: "rwx------", description: "Owner full, no access for others", useCase: "Private directories, .ssh" },
  { numeric: "600", symbolic: "rw-------", description: "Owner read/write only", useCase: "Private keys, sensitive files" },
  { numeric: "640", symbolic: "rw-r-----", description: "Owner read/write, group read", useCase: "/etc/shadow style" },
  { numeric: "750", symbolic: "rwxr-x---", description: "Owner full, group read/execute", useCase: "Shared project directories" },
  { numeric: "1777", symbolic: "rwxrwxrwt", description: "Sticky bit + full access", useCase: "/tmp directory" },
  { numeric: "4755", symbolic: "rwsr-xr-x", description: "SUID + standard executable", useCase: "passwd, sudo binaries" },
];

// Important log files
const logFiles = [
  { path: "/var/log/syslog", description: "General system activity log (Debian/Ubuntu)", service: "rsyslog" },
  { path: "/var/log/messages", description: "General system activity log (RHEL/CentOS)", service: "rsyslog" },
  { path: "/var/log/auth.log", description: "Authentication events (logins, sudo)", service: "rsyslog" },
  { path: "/var/log/secure", description: "Authentication events (RHEL/CentOS)", service: "rsyslog" },
  { path: "/var/log/kern.log", description: "Kernel messages", service: "rsyslog" },
  { path: "/var/log/dmesg", description: "Boot and hardware messages", service: "kernel" },
  { path: "/var/log/boot.log", description: "Boot process log", service: "systemd" },
  { path: "/var/log/cron", description: "Cron job execution logs", service: "crond" },
  { path: "/var/log/maillog", description: "Mail server logs", service: "postfix/sendmail" },
  { path: "/var/log/apache2/", description: "Apache web server logs", service: "apache2" },
  { path: "/var/log/nginx/", description: "Nginx web server logs", service: "nginx" },
  { path: "/var/log/mysql/", description: "MySQL/MariaDB logs", service: "mysql" },
  { path: "/var/log/audit/audit.log", description: "SELinux/auditd security events", service: "auditd" },
  { path: "/var/log/faillog", description: "Failed login attempts (binary)", service: "pam" },
  { path: "/var/log/lastlog", description: "Last login info per user (binary)", service: "login" },
  { path: "/var/log/wtmp", description: "Login/logout history (binary, use last)", service: "login" },
  { path: "/var/log/btmp", description: "Bad login attempts (binary, use lastb)", service: "login" },
];

// Security-relevant events to monitor
const securityEvents = [
  { event: "Failed SSH login", logFile: "/var/log/auth.log", pattern: "Failed password for", severity: "Medium" },
  { event: "Successful SSH login", logFile: "/var/log/auth.log", pattern: "Accepted password|Accepted publickey", severity: "Info" },
  { event: "sudo command execution", logFile: "/var/log/auth.log", pattern: "sudo:.*COMMAND=", severity: "Info" },
  { event: "User added", logFile: "/var/log/auth.log", pattern: "useradd|adduser", severity: "High" },
  { event: "Password changed", logFile: "/var/log/auth.log", pattern: "password changed", severity: "Medium" },
  { event: "su command used", logFile: "/var/log/auth.log", pattern: "su:.*session opened", severity: "Medium" },
  { event: "SSH brute force", logFile: "/var/log/auth.log", pattern: "Failed password.*(repeated)", severity: "High" },
  { event: "Cron job executed", logFile: "/var/log/cron", pattern: "CMD|CMDOUT", severity: "Info" },
  { event: "Service started/stopped", logFile: "journalctl", pattern: "Started|Stopped", severity: "Info" },
  { event: "Kernel module loaded", logFile: "/var/log/kern.log", pattern: "module.*loaded", severity: "High" },
  { event: "Firewall blocked", logFile: "/var/log/kern.log", pattern: "iptables|nftables|UFW BLOCK", severity: "Info" },
  { event: "Segfault/crash", logFile: "/var/log/kern.log", pattern: "segfault|general protection", severity: "Medium" },
];

// systemd commands
const systemdCommands = [
  { command: "systemctl status <service>", description: "Check service status and recent logs" },
  { command: "systemctl start <service>", description: "Start a service" },
  { command: "systemctl stop <service>", description: "Stop a service" },
  { command: "systemctl restart <service>", description: "Restart a service" },
  { command: "systemctl reload <service>", description: "Reload config without restart" },
  { command: "systemctl enable <service>", description: "Enable service at boot" },
  { command: "systemctl disable <service>", description: "Disable service at boot" },
  { command: "systemctl is-enabled <service>", description: "Check if enabled at boot" },
  { command: "systemctl is-active <service>", description: "Check if currently running" },
  { command: "systemctl list-units --type=service", description: "List all services" },
  { command: "systemctl list-unit-files", description: "List all unit files and states" },
  { command: "systemctl daemon-reload", description: "Reload systemd manager config" },
  { command: "systemctl mask <service>", description: "Completely disable (cannot start)" },
  { command: "systemctl unmask <service>", description: "Remove mask" },
  { command: "journalctl -u <service>", description: "View service logs" },
  { command: "journalctl -f", description: "Follow system log in real-time" },
  { command: "journalctl -b", description: "Logs since last boot" },
  { command: "journalctl --since '1 hour ago'", description: "Logs from time period" },
];

// Common security tools
const securityTools = [
  { name: "fail2ban", category: "Defense", description: "Ban IPs with too many failed logins", example: "fail2ban-client status sshd" },
  { name: "ufw", category: "Firewall", description: "Uncomplicated Firewall (Ubuntu)", example: "ufw allow 22/tcp" },
  { name: "firewalld", category: "Firewall", description: "Dynamic firewall (RHEL/Fedora)", example: "firewall-cmd --list-all" },
  { name: "iptables", category: "Firewall", description: "Kernel packet filter (legacy)", example: "iptables -L -n -v" },
  { name: "nftables", category: "Firewall", description: "Modern packet filter", example: "nft list ruleset" },
  { name: "auditd", category: "Audit", description: "Linux audit framework", example: "ausearch -k audit_key" },
  { name: "SELinux", category: "MAC", description: "Mandatory Access Control (RHEL)", example: "getenforce, setenforce" },
  { name: "AppArmor", category: "MAC", description: "Mandatory Access Control (Ubuntu)", example: "aa-status" },
  { name: "chkrootkit", category: "Detection", description: "Rootkit detector", example: "chkrootkit" },
  { name: "rkhunter", category: "Detection", description: "Rootkit Hunter", example: "rkhunter --check" },
  { name: "ClamAV", category: "Antivirus", description: "Open source antivirus", example: "clamscan -r /path" },
  { name: "Lynis", category: "Audit", description: "Security auditing tool", example: "lynis audit system" },
  { name: "AIDE", category: "IDS", description: "File integrity monitoring", example: "aide --check" },
  { name: "tripwire", category: "IDS", description: "File integrity monitoring", example: "tripwire --check" },
  { name: "OpenSSH", category: "Remote", description: "Secure Shell server/client", example: "ssh user@host" },
  { name: "GPG", category: "Crypto", description: "GNU Privacy Guard (encryption)", example: "gpg --encrypt file" },
];

// Cron schedule format
const cronFormat = [
  { field: "Minute", range: "0-59", example: "*/15 = every 15 min" },
  { field: "Hour", range: "0-23", example: "0 = midnight, 12 = noon" },
  { field: "Day of Month", range: "1-31", example: "1 = first day" },
  { field: "Month", range: "1-12", example: "1 = Jan, 12 = Dec" },
  { field: "Day of Week", range: "0-7", example: "0,7 = Sun, 1 = Mon" },
];

// Cron examples
const cronExamples = [
  { schedule: "0 * * * *", description: "Every hour on the hour" },
  { schedule: "*/5 * * * *", description: "Every 5 minutes" },
  { schedule: "0 0 * * *", description: "Daily at midnight" },
  { schedule: "0 2 * * 0", description: "Weekly at 2 AM on Sunday" },
  { schedule: "0 0 1 * *", description: "Monthly on the 1st at midnight" },
  { schedule: "30 4 * * 1-5", description: "Weekdays at 4:30 AM" },
  { schedule: "@reboot", description: "Run once at startup" },
  { schedule: "@daily", description: "Same as 0 0 * * *" },
];

// Environment variables
const environmentVariables = [
  { variable: "PATH", description: "Directories to search for executables", example: "/usr/local/bin:/usr/bin:/bin" },
  { variable: "HOME", description: "Current user's home directory", example: "/home/username" },
  { variable: "USER", description: "Current username", example: "username" },
  { variable: "SHELL", description: "Current user's shell", example: "/bin/bash" },
  { variable: "PWD", description: "Present working directory", example: "/var/log" },
  { variable: "OLDPWD", description: "Previous directory (cd -)", example: "/home/user" },
  { variable: "TERM", description: "Terminal type", example: "xterm-256color" },
  { variable: "EDITOR", description: "Default text editor", example: "vim" },
  { variable: "LANG", description: "System locale", example: "en_US.UTF-8" },
  { variable: "LD_LIBRARY_PATH", description: "Library search path", example: "/usr/local/lib" },
  { variable: "HISTFILE", description: "Command history file", example: "~/.bash_history" },
  { variable: "HISTSIZE", description: "History lines in memory", example: "1000" },
  { variable: "PS1", description: "Primary shell prompt", example: "\\u@\\h:\\w\\$ " },
];

// Keyboard shortcuts
const keyboardShortcuts = [
  { shortcut: "Ctrl+C", action: "Interrupt/kill current process", context: "Terminal" },
  { shortcut: "Ctrl+Z", action: "Suspend current process (bg/fg to resume)", context: "Terminal" },
  { shortcut: "Ctrl+D", action: "End of input / logout", context: "Terminal" },
  { shortcut: "Ctrl+L", action: "Clear screen (same as clear)", context: "Terminal" },
  { shortcut: "Ctrl+R", action: "Reverse search command history", context: "Bash" },
  { shortcut: "Ctrl+A", action: "Move cursor to beginning of line", context: "Bash" },
  { shortcut: "Ctrl+E", action: "Move cursor to end of line", context: "Bash" },
  { shortcut: "Ctrl+U", action: "Delete from cursor to beginning", context: "Bash" },
  { shortcut: "Ctrl+K", action: "Delete from cursor to end", context: "Bash" },
  { shortcut: "Ctrl+W", action: "Delete word before cursor", context: "Bash" },
  { shortcut: "Alt+.", action: "Insert last argument of previous command", context: "Bash" },
  { shortcut: "Tab", action: "Auto-complete commands/paths", context: "Bash" },
  { shortcut: "Tab Tab", action: "Show all completions", context: "Bash" },
  { shortcut: "!!", action: "Repeat last command", context: "Bash" },
  { shortcut: "!$", action: "Last argument of previous command", context: "Bash" },
  { shortcut: "!n", action: "Run command number n from history", context: "Bash" },
];

// ========== SHELL SCRIPTING BASICS ==========

// Shell script structure and basics
const shellScriptBasics = [
  { concept: "Shebang", syntax: "#!/bin/bash", description: "First line - tells system which interpreter to use", example: "#!/bin/bash or #!/usr/bin/env bash (more portable)" },
  { concept: "Variables", syntax: "VAR=value (no spaces!)", description: "Store data, access with $VAR or ${VAR}", example: "NAME=\"John\"; echo \"Hello $NAME\"" },
  { concept: "Command substitution", syntax: "$(command) or `command`", description: "Capture command output into variable", example: "TODAY=$(date +%Y-%m-%d)" },
  { concept: "Quoting", syntax: "\"double\" vs 'single'", description: "Double quotes expand variables, single quotes are literal", example: "echo \"$VAR\" vs echo '$VAR'" },
  { concept: "Exit codes", syntax: "$? (0=success)", description: "Check if previous command succeeded", example: "command; if [ $? -eq 0 ]; then echo 'OK'; fi" },
  { concept: "Arguments", syntax: "$1, $2... $@, $#", description: "$1=first arg, $@=all args, $#=count", example: "echo \"First arg: $1, Total: $#\"" },
  { concept: "Script name", syntax: "$0", description: "Name of the script being executed", example: "echo \"Running: $0\"" },
  { concept: "Make executable", syntax: "chmod +x script.sh", description: "Required before running with ./script.sh", example: "chmod +x myscript.sh && ./myscript.sh" },
];

// Conditionals
const shellConditionals = [
  { type: "if/then/else", syntax: "if [ condition ]; then ... elif ... else ... fi", example: "if [ \"$1\" = \"hello\" ]; then echo 'Hi!'; fi" },
  { type: "String comparison", syntax: "= (equal), != (not equal)", example: "if [ \"$VAR\" = \"test\" ]; then ..." },
  { type: "Numeric comparison", syntax: "-eq -ne -lt -le -gt -ge", example: "if [ $COUNT -gt 10 ]; then echo 'More than 10'; fi" },
  { type: "File tests", syntax: "-f (file), -d (dir), -e (exists), -r (readable), -w (writable), -x (executable)", example: "if [ -f /etc/passwd ]; then echo 'File exists'; fi" },
  { type: "String tests", syntax: "-z (empty), -n (not empty)", example: "if [ -z \"$VAR\" ]; then echo 'VAR is empty'; fi" },
  { type: "Logical operators", syntax: "&& (AND), || (OR), ! (NOT)", example: "if [ -f file ] && [ -r file ]; then cat file; fi" },
  { type: "Case statement", syntax: "case $VAR in pattern) ... ;; esac", example: "case $1 in start) echo 'Starting';; stop) echo 'Stopping';; *) echo 'Unknown';; esac" },
  { type: "[[ ]] vs [ ]", syntax: "[[ ]] is bash-specific, more features", example: "[[ $VAR =~ ^[0-9]+$ ]] # regex matching" },
];

// Loops
const shellLoops = [
  { type: "for loop (list)", syntax: "for VAR in item1 item2 item3; do ... done", example: "for file in *.txt; do echo \"Processing $file\"; done" },
  { type: "for loop (C-style)", syntax: "for ((i=0; i<10; i++)); do ... done", example: "for ((i=1; i<=5; i++)); do echo $i; done" },
  { type: "for loop (range)", syntax: "for i in {1..10}; do ... done", example: "for i in {1..10}; do echo $i; done" },
  { type: "while loop", syntax: "while [ condition ]; do ... done", example: "while [ $COUNT -lt 10 ]; do ((COUNT++)); done" },
  { type: "until loop", syntax: "until [ condition ]; do ... done", example: "until [ -f /tmp/ready ]; do sleep 1; done" },
  { type: "Read file line by line", syntax: "while read line; do ... done < file", example: "while read line; do echo \"$line\"; done < /etc/passwd" },
  { type: "Loop control", syntax: "break (exit loop), continue (skip iteration)", example: "for i in {1..10}; do [ $i -eq 5 ] && break; echo $i; done" },
  { type: "Infinite loop", syntax: "while true; do ... done", example: "while true; do check_service; sleep 60; done" },
];

// Functions
const shellFunctions = [
  { concept: "Define function", syntax: "function_name() { commands; }", example: "greet() { echo \"Hello, $1!\"; }" },
  { concept: "Call function", syntax: "function_name arg1 arg2", example: "greet \"World\"  # Output: Hello, World!" },
  { concept: "Return value", syntax: "return N (0-255 only)", example: "is_even() { [ $(($1 % 2)) -eq 0 ] && return 0 || return 1; }" },
  { concept: "Capture output", syntax: "result=$(function_name)", example: "get_date() { date +%Y-%m-%d; }; TODAY=$(get_date)" },
  { concept: "Local variables", syntax: "local VAR=value", example: "myfunc() { local temp=\"local value\"; echo $temp; }" },
  { concept: "Check function exists", syntax: "type function_name", example: "type greet &>/dev/null && greet \"User\"" },
];

// Useful script patterns
const shellPatterns = [
  { pattern: "Error handling", code: "set -e  # Exit on any error\\nset -u  # Error on undefined vars\\nset -o pipefail  # Catch pipe failures", useCase: "Robust scripts" },
  { pattern: "Logging function", code: "log() { echo \"[$(date '+%Y-%m-%d %H:%M:%S')] $*\"; }", useCase: "Timestamped output" },
  { pattern: "Check root", code: "if [ \"$(id -u)\" -ne 0 ]; then echo 'Run as root'; exit 1; fi", useCase: "Require sudo/root" },
  { pattern: "Check command exists", code: "command -v docker &>/dev/null || { echo 'Docker required'; exit 1; }", useCase: "Dependency check" },
  { pattern: "Default variable", code: "VAR=\"${1:-default_value}\"", useCase: "Optional argument with default" },
  { pattern: "Trap cleanup", code: "cleanup() { rm -f /tmp/tempfile; }\\ntrap cleanup EXIT", useCase: "Clean up on exit" },
  { pattern: "Read user input", code: "read -p 'Enter name: ' NAME\\necho \"Hello, $NAME\"", useCase: "Interactive scripts" },
  { pattern: "Yes/No prompt", code: "read -p 'Continue? [y/N] ' -n 1 -r\\n[[ $REPLY =~ ^[Yy]$ ]] || exit 1", useCase: "Confirmation" },
  { pattern: "Process arguments", code: "while getopts 'f:vh' opt; do\\n  case $opt in\\n    f) FILE=$OPTARG;;\\n    v) VERBOSE=1;;\\n    h) usage; exit 0;;\\n  esac\\ndone", useCase: "Parse flags" },
  { pattern: "Lock file", code: "LOCK=/tmp/script.lock\\n[ -f $LOCK ] && exit 1\\ntrap \"rm -f $LOCK\" EXIT\\ntouch $LOCK", useCase: "Prevent duplicate runs" },
];

// Script example template
const scriptTemplate = `#!/bin/bash
#
# Script: example.sh
# Description: Brief description of what this script does
# Author: Your Name
# Date: $(date +%Y-%m-%d)
#

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/myscript.log"

# Functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <argument>

Options:
    -h, --help     Show this help message
    -v, --verbose  Enable verbose output
    -f FILE        Input file to process

Example:
    $(basename "$0") -v -f input.txt
EOF
}

cleanup() {
    log "Cleaning up..."
    # Remove temp files, etc.
}
trap cleanup EXIT

# Main logic
main() {
    log "Script started"
    
    # Your code here
    
    log "Script completed"
}

# Parse arguments
VERBOSE=0
INPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -f)
            INPUT_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Run main
main "$@"`;

// Debugging tips
const shellDebugging = [
  { technique: "set -x", description: "Print each command before execution (trace mode)", usage: "Add to script or run: bash -x script.sh" },
  { technique: "set -v", description: "Print lines as they are read", usage: "Shows input including comments" },
  { technique: "set -e", description: "Exit immediately if command fails", usage: "Prevents silent failures" },
  { technique: "set -u", description: "Error on undefined variables", usage: "Catches typos in variable names" },
  { technique: "shellcheck", description: "Static analysis tool for shell scripts", usage: "shellcheck script.sh (install: apt install shellcheck)" },
  { technique: "echo debugging", description: "Print variable values at key points", usage: "echo \"DEBUG: VAR=$VAR\" >&2" },
  { technique: "trap DEBUG", description: "Execute command before every line", usage: "trap 'echo \"Line $LINENO\"' DEBUG" },
  { technique: "PS4 variable", description: "Customize -x output format", usage: "PS4='+${BASH_SOURCE}:${LINENO}: ' (shows file:line)" },
];

// ========== TEXT EDITORS ==========

// Vim basics
const vimBasics = {
  modes: [
    { mode: "Normal", key: "Esc", description: "Navigation and commands (default mode)", color: "#22c55e" },
    { mode: "Insert", key: "i, a, o", description: "Type and edit text", color: "#3b82f6" },
    { mode: "Visual", key: "v, V, Ctrl+v", description: "Select text", color: "#8b5cf6" },
    { mode: "Command", key: ":", description: "Execute ex commands", color: "#f97316" },
  ],
  navigation: [
    { key: "h/j/k/l", action: "Left/Down/Up/Right (like arrow keys)" },
    { key: "w/b", action: "Next/previous word" },
    { key: "0/$", action: "Beginning/end of line" },
    { key: "gg/G", action: "Go to first/last line" },
    { key: ":n or nG", action: "Go to line n (e.g., :50 or 50G)" },
    { key: "Ctrl+d/u", action: "Half page down/up" },
    { key: "Ctrl+f/b", action: "Full page down/up" },
    { key: "%", action: "Jump to matching bracket" },
    { key: "*/#", action: "Search for word under cursor forward/backward" },
  ],
  editing: [
    { key: "i", action: "Insert before cursor" },
    { key: "a", action: "Insert after cursor" },
    { key: "I", action: "Insert at beginning of line" },
    { key: "A", action: "Insert at end of line" },
    { key: "o/O", action: "Open new line below/above" },
    { key: "x", action: "Delete character" },
    { key: "dd", action: "Delete entire line" },
    { key: "dw", action: "Delete word" },
    { key: "d$", action: "Delete to end of line" },
    { key: "yy", action: "Yank (copy) line" },
    { key: "yw", action: "Yank word" },
    { key: "p/P", action: "Paste after/before cursor" },
    { key: "u", action: "Undo" },
    { key: "Ctrl+r", action: "Redo" },
    { key: ".", action: "Repeat last command" },
    { key: "r", action: "Replace single character" },
    { key: "cw", action: "Change word (delete + insert mode)" },
    { key: "cc", action: "Change entire line" },
    { key: ">>", action: "Indent line" },
    { key: "<<", action: "Unindent line" },
  ],
  search: [
    { key: "/pattern", action: "Search forward" },
    { key: "?pattern", action: "Search backward" },
    { key: "n/N", action: "Next/previous match" },
    { key: ":%s/old/new/g", action: "Replace all in file" },
    { key: ":%s/old/new/gc", action: "Replace all with confirmation" },
    { key: ":noh", action: "Clear search highlighting" },
  ],
  fileOps: [
    { key: ":w", action: "Save file" },
    { key: ":w filename", action: "Save as filename" },
    { key: ":q", action: "Quit (fails if unsaved)" },
    { key: ":q!", action: "Force quit (discard changes)" },
    { key: ":wq or :x or ZZ", action: "Save and quit" },
    { key: ":e filename", action: "Open file" },
    { key: ":r filename", action: "Insert file contents" },
    { key: ":!command", action: "Run shell command" },
    { key: ":r !command", action: "Insert command output" },
  ],
  visual: [
    { key: "v", action: "Character-wise visual mode" },
    { key: "V", action: "Line-wise visual mode" },
    { key: "Ctrl+v", action: "Block visual mode (column select)" },
    { key: "y (in visual)", action: "Yank selection" },
    { key: "d (in visual)", action: "Delete selection" },
    { key: "> (in visual)", action: "Indent selection" },
    { key: "gv", action: "Reselect last visual selection" },
  ],
};

// Nano basics
const nanoBasics = {
  description: "Nano is a simple, user-friendly terminal text editor. Commands shown at bottom of screen.",
  shortcuts: [
    { key: "Ctrl+O", action: "Save file (Write Out)" },
    { key: "Ctrl+X", action: "Exit (prompts to save)" },
    { key: "Ctrl+K", action: "Cut line (or selection)" },
    { key: "Ctrl+U", action: "Paste (Uncut)" },
    { key: "Ctrl+W", action: "Search (Where is)" },
    { key: "Ctrl+\\\\", action: "Search and replace" },
    { key: "Ctrl+G", action: "Help" },
    { key: "Ctrl+C", action: "Show cursor position" },
    { key: "Ctrl+_", action: "Go to line number" },
    { key: "Ctrl+A", action: "Go to beginning of line" },
    { key: "Ctrl+E", action: "Go to end of line" },
    { key: "Ctrl+Y", action: "Page up" },
    { key: "Ctrl+V", action: "Page down" },
    { key: "Alt+A", action: "Start/stop selecting text" },
    { key: "Alt+6", action: "Copy line/selection" },
    { key: "Ctrl+J", action: "Justify paragraph" },
    { key: "Alt+U", action: "Undo" },
    { key: "Alt+E", action: "Redo" },
    { key: "Ctrl+T", action: "Spell check (if available)" },
    { key: "Alt+N", action: "Toggle line numbers" },
  ],
  config: "Create ~/.nanorc for settings: set linenumbers, set tabsize 4, set autoindent, include /usr/share/nano/*.nanorc (syntax highlighting)",
};

// Editor comparison
const editorComparison = [
  { feature: "Learning curve", vim: "Steep (but powerful)", nano: "Minimal (intuitive)" },
  { feature: "Speed (once learned)", vim: "Very fast", nano: "Moderate" },
  { feature: "Available by default", vim: "Usually (vi at minimum)", nano: "Usually" },
  { feature: "Syntax highlighting", vim: "Extensive", nano: "Basic (with config)" },
  { feature: "Customization", vim: "Extremely customizable", nano: "Limited" },
  { feature: "Best for", vim: "Power users, developers", nano: "Quick edits, beginners" },
  { feature: "Config file editing", vim: "Excellent", nano: "Good enough" },
  { feature: "Resource usage", vim: "Light", nano: "Very light" },
];

// ========== EXPANDED LINUX HISTORY ==========

// Key people in Linux/Unix history
const linuxPioneers = [
  { name: "Ken Thompson", contribution: "Co-creator of Unix (1969), B language, UTF-8", org: "Bell Labs, Google", years: "1969-present" },
  { name: "Dennis Ritchie", contribution: "Co-creator of Unix, creator of C language", org: "Bell Labs", years: "1969-2011" },
  { name: "Richard Stallman", contribution: "GNU Project (1983), Free Software Foundation, GPL license, Emacs, GCC", org: "MIT, FSF", years: "1983-present" },
  { name: "Linus Torvalds", contribution: "Creator of Linux kernel (1991), Git version control (2005)", org: "Linux Foundation", years: "1991-present" },
  { name: "Andrew Tanenbaum", contribution: "Created MINIX (1987), inspired Linux development", org: "Vrije Universiteit", years: "1987-present" },
  { name: "Ian Murdock", contribution: "Founded Debian project (1993)", org: "Debian, Sun", years: "1993-2015" },
  { name: "Mark Shuttleworth", contribution: "Founded Canonical, created Ubuntu (2004)", org: "Canonical", years: "2004-present" },
  { name: "Patrick Volkerding", contribution: "Created Slackware (1993) - oldest surviving distro", org: "Slackware", years: "1993-present" },
  { name: "Bob Young & Marc Ewing", contribution: "Founded Red Hat (1994)", org: "Red Hat", years: "1994-present" },
  { name: "Greg Kroah-Hartman", contribution: "Linux kernel maintainer, stable branch maintainer", org: "Linux Foundation", years: "1999-present" },
];

// Unix/Linux philosophy
const unixPhilosophy = [
  { principle: "Do one thing well", description: "Each program should do one thing and do it well. Write programs to work together.", example: "cat, grep, sort, uniq - each simple, but powerful when piped together" },
  { principle: "Everything is a file", description: "Devices, processes, network sockets - all accessed as files", example: "/dev/sda (disk), /proc/cpuinfo (CPU info), /dev/null (bit bucket)" },
  { principle: "Text streams", description: "Use text as universal interface between programs", example: "ps aux | grep nginx | awk '{print $2}' - text flows between commands" },
  { principle: "Small is beautiful", description: "Small, simple programs are easier to maintain and compose", example: "Core utilities are typically <1000 lines of code" },
  { principle: "Silence is golden", description: "Programs should be silent when successful", example: "cp file1 file2 - no output means success" },
  { principle: "Fail loudly", description: "Report errors clearly to stderr", example: "Error messages go to stderr (>&2), not stdout" },
  { principle: "Prototype early", description: "Build working version first, optimize later", example: "\"Plan to throw one away; you will anyhow\" - Fred Brooks" },
  { principle: "Portability over efficiency", description: "Portable code is more valuable than fast code", example: "POSIX compliance allows scripts to run on any Unix-like system" },
];

// Linux kernel architecture
const kernelArchitecture = [
  { component: "Process Scheduler", description: "Manages CPU time allocation between processes", subsystem: "Core", file: "kernel/sched/" },
  { component: "Memory Management", description: "Virtual memory, paging, memory allocation", subsystem: "Core", file: "mm/" },
  { component: "Virtual File System (VFS)", description: "Abstraction layer for different filesystems", subsystem: "Core", file: "fs/" },
  { component: "Network Stack", description: "TCP/IP implementation, sockets, protocols", subsystem: "Core", file: "net/" },
  { component: "Device Drivers", description: "Hardware abstraction (largest part of kernel)", subsystem: "Drivers", file: "drivers/" },
  { component: "System Calls", description: "Interface between user space and kernel", subsystem: "Core", file: "arch/x86/entry/" },
  { component: "IPC", description: "Inter-process communication (pipes, shared memory, signals)", subsystem: "Core", file: "ipc/" },
  { component: "Security Modules", description: "SELinux, AppArmor, capabilities", subsystem: "Security", file: "security/" },
];

// ========== LINUX ADMINISTRATION SECTION ==========

// User administration tasks
const userAdminTasks = [
  { task: "Create a new user with home directory", command: "useradd -m -s /bin/bash username", notes: "Use -m for home, -s for shell" },
  { task: "Create user with specific UID/GID", command: "useradd -u 1500 -g 1500 username", notes: "Useful for NFS/shared systems" },
  { task: "Add user to supplementary group", command: "usermod -aG groupname username", notes: "-a = append, prevents removing from other groups" },
  { task: "Lock a user account", command: "usermod -L username", notes: "Prepends ! to password hash in /etc/shadow" },
  { task: "Unlock a user account", command: "usermod -U username", notes: "Removes the ! lock prefix" },
  { task: "Set password expiration", command: "chage -M 90 username", notes: "Force password change every 90 days" },
  { task: "Force password change on next login", command: "chage -d 0 username", notes: "Sets last change to epoch" },
  { task: "View password aging info", command: "chage -l username", notes: "Shows all expiration details" },
  { task: "Delete user and home directory", command: "userdel -r username", notes: "-r removes home and mail spool" },
  { task: "Create a system account (no login)", command: "useradd -r -s /sbin/nologin svcaccount", notes: "For service accounts" },
  { task: "Change user's login shell", command: "chsh -s /bin/zsh username", notes: "Or usermod -s /bin/zsh" },
  { task: "View user info", command: "id username && getent passwd username", notes: "Shows UID, GID, groups, and passwd entry" },
];

// Group administration tasks
const groupAdminTasks = [
  { task: "Create a new group", command: "groupadd groupname", notes: "System assigns next available GID" },
  { task: "Create group with specific GID", command: "groupadd -g 2000 groupname", notes: "Useful for consistency across systems" },
  { task: "Delete a group", command: "groupdel groupname", notes: "Cannot delete primary group with members" },
  { task: "Add user to group", command: "gpasswd -a username groupname", notes: "Alternative to usermod -aG" },
  { task: "Remove user from group", command: "gpasswd -d username groupname", notes: "Removes without affecting other groups" },
  { task: "Set group administrators", command: "gpasswd -A admin1,admin2 groupname", notes: "Can manage group membership" },
  { task: "List group members", command: "getent group groupname", notes: "Or: members groupname (if installed)" },
  { task: "Change user's primary group", command: "usermod -g newgroup username", notes: "Affects new file ownership" },
];

// Disk and storage administration
const diskAdminTasks = [
  { task: "List all block devices", command: "lsblk -f", notes: "Shows filesystem type, mount points, UUIDs" },
  { task: "View disk usage by directory", command: "du -sh /* 2>/dev/null | sort -h", notes: "Human-readable, sorted" },
  { task: "Find large files", command: "find / -type f -size +100M -exec ls -lh {} \\;", notes: "Files over 100MB" },
  { task: "Check filesystem integrity", command: "fsck -n /dev/sda1", notes: "-n = no changes (safe check)" },
  { task: "Create ext4 filesystem", command: "mkfs.ext4 /dev/sdb1", notes: "DESTROYS all data on partition" },
  { task: "Mount filesystem", command: "mount /dev/sdb1 /mnt/data", notes: "Temporary until reboot" },
  { task: "Mount with specific options", command: "mount -o ro,noexec /dev/sdb1 /mnt", notes: "Read-only, no execution" },
  { task: "Add permanent mount to fstab", command: "echo 'UUID=xxx /mnt/data ext4 defaults 0 2' >> /etc/fstab", notes: "Use UUID, not /dev/sdX" },
  { task: "Extend LVM logical volume", command: "lvextend -L +10G /dev/vg/lv && resize2fs /dev/vg/lv", notes: "Add space and resize FS" },
  { task: "Check disk health (SMART)", command: "smartctl -a /dev/sda", notes: "Requires smartmontools" },
  { task: "Create swap file", command: "dd if=/dev/zero of=/swapfile bs=1M count=4096 && mkswap /swapfile && swapon /swapfile", notes: "4GB swap file" },
  { task: "View disk I/O statistics", command: "iostat -xz 1", notes: "Extended stats every 1 second" },
];

// Network administration
const networkAdminTasks = [
  { task: "View all IP addresses", command: "ip addr show", notes: "Or: ip a" },
  { task: "Add IP address to interface", command: "ip addr add 192.168.1.100/24 dev eth0", notes: "Temporary until reboot" },
  { task: "Remove IP address", command: "ip addr del 192.168.1.100/24 dev eth0", notes: "Removes specific IP" },
  { task: "Bring interface up/down", command: "ip link set eth0 up|down", notes: "Or: ifup/ifdown eth0" },
  { task: "View routing table", command: "ip route show", notes: "Or: route -n (legacy)" },
  { task: "Add default gateway", command: "ip route add default via 192.168.1.1", notes: "Temporary" },
  { task: "View DNS configuration", command: "cat /etc/resolv.conf && resolvectl status", notes: "systemd-resolved status" },
  { task: "Test DNS resolution", command: "dig +short example.com && nslookup example.com", notes: "Multiple tools for comparison" },
  { task: "View listening ports", command: "ss -tulpn", notes: "TCP/UDP, listening, process, numeric" },
  { task: "View established connections", command: "ss -tunap state established", notes: "Active connections with process" },
  { task: "Configure static IP (Netplan)", command: "Edit /etc/netplan/*.yaml then: netplan apply", notes: "Ubuntu 18.04+" },
  { task: "Configure static IP (NetworkManager)", command: "nmcli con mod 'Wired' ipv4.addresses 192.168.1.100/24 ipv4.method manual", notes: "RHEL/Fedora" },
  { task: "View network interface stats", command: "ip -s link show eth0", notes: "Packets, bytes, errors" },
  { task: "Flush DNS cache", command: "systemd-resolve --flush-caches", notes: "Or: resolvectl flush-caches" },
  { task: "Test port connectivity", command: "nc -zv hostname 22", notes: "Or: telnet hostname 22" },
];

// Service administration
const serviceAdminTasks = [
  { task: "View all running services", command: "systemctl list-units --type=service --state=running", notes: "Active services only" },
  { task: "View failed services", command: "systemctl --failed", notes: "Shows services that failed to start" },
  { task: "Check why service failed", command: "systemctl status servicename -l && journalctl -xeu servicename", notes: "Full logs" },
  { task: "Reload service configuration", command: "systemctl reload servicename", notes: "Without full restart (if supported)" },
  { task: "View service dependencies", command: "systemctl list-dependencies servicename", notes: "Shows what it needs to start" },
  { task: "View what depends on service", command: "systemctl list-dependencies --reverse servicename", notes: "What depends on it" },
  { task: "Check boot time analysis", command: "systemd-analyze blame", notes: "Shows slowest services" },
  { task: "View service resource usage", command: "systemctl status servicename | grep -E 'Memory|CPU'", notes: "Or use systemd-cgtop" },
  { task: "Create custom service", command: "Create /etc/systemd/system/myservice.service then: systemctl daemon-reload", notes: "See unit file format below" },
  { task: "Edit existing service override", command: "systemctl edit servicename", notes: "Creates override.conf in /etc/systemd/system/servicename.service.d/" },
  { task: "View service logs (last hour)", command: "journalctl -u servicename --since '1 hour ago'", notes: "Time-based filtering" },
  { task: "Follow logs in real-time", command: "journalctl -fu servicename", notes: "-f = follow, like tail -f" },
];

// System unit file template
const unitFileTemplate = `[Unit]
Description=My Custom Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=serviceuser
Group=servicegroup
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/start.sh
ExecStop=/opt/myapp/stop.sh
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target`;

// Performance tuning
const performanceTuning = [
  { category: "CPU", task: "View CPU usage by process", command: "top -o %CPU", notes: "Or: htop, ps aux --sort=-%cpu" },
  { category: "CPU", task: "Set process priority", command: "nice -n 10 command", notes: "-20 (high) to 19 (low)" },
  { category: "CPU", task: "Change running process priority", command: "renice -n 5 -p PID", notes: "Adjust existing process" },
  { category: "CPU", task: "Pin process to CPU cores", command: "taskset -c 0,1 command", notes: "Run on cores 0 and 1" },
  { category: "Memory", task: "View memory usage", command: "free -h && cat /proc/meminfo", notes: "Human-readable + detailed" },
  { category: "Memory", task: "Clear page cache", command: "sync && echo 3 > /proc/sys/vm/drop_caches", notes: "Frees cached memory (use carefully)" },
  { category: "Memory", task: "View top memory consumers", command: "ps aux --sort=-%mem | head -20", notes: "Top 20 by memory" },
  { category: "Memory", task: "Check for OOM killer activity", command: "dmesg | grep -i 'killed process'", notes: "Out of Memory events" },
  { category: "I/O", task: "View I/O wait", command: "iostat -x 1 5", notes: "Extended stats, 5 samples" },
  { category: "I/O", task: "Set I/O priority", command: "ionice -c 2 -n 4 command", notes: "Best-effort, priority 4" },
  { category: "I/O", task: "View processes by I/O", command: "iotop -o", notes: "Only show active I/O (needs iotop)" },
  { category: "Network", task: "View network throughput", command: "iftop -i eth0", notes: "Or: nload, bmon" },
  { category: "Network", task: "View connection states", command: "ss -s", notes: "Summary of socket statistics" },
  { category: "Kernel", task: "View/set kernel parameters", command: "sysctl -a | grep param && sysctl -w param=value", notes: "Persist in /etc/sysctl.conf" },
];

// Backup and recovery tasks
const backupTasks = [
  { task: "Backup directory with rsync", command: "rsync -avz --progress /source/ /backup/", notes: "-a archive, -v verbose, -z compress" },
  { task: "Rsync to remote server", command: "rsync -avz -e ssh /local/ user@remote:/backup/", notes: "Over SSH" },
  { task: "Create tarball backup", command: "tar -czvf backup-$(date +%Y%m%d).tar.gz /path/to/backup", notes: "Date-stamped archive" },
  { task: "Backup with exclusions", command: "tar --exclude='*.log' --exclude='cache' -czvf backup.tar.gz /path", notes: "Skip logs and cache" },
  { task: "Create disk image", command: "dd if=/dev/sda of=/backup/disk.img bs=4M status=progress", notes: "Full disk clone" },
  { task: "Clone partition", command: "dd if=/dev/sda1 of=/dev/sdb1 bs=4M status=progress", notes: "Partition to partition" },
  { task: "Backup MySQL database", command: "mysqldump -u root -p --all-databases > all-db-backup.sql", notes: "All databases" },
  { task: "Backup PostgreSQL database", command: "pg_dump -U postgres dbname > dbname-backup.sql", notes: "Single database" },
  { task: "List files in tarball", command: "tar -tzvf backup.tar.gz", notes: "View contents without extracting" },
  { task: "Extract specific file from tarball", command: "tar -xzvf backup.tar.gz path/to/file", notes: "Extract single file" },
  { task: "Verify rsync without changes", command: "rsync -avzn /source/ /dest/", notes: "-n = dry run" },
];

// Security hardening checklist
const securityHardening = [
  { category: "SSH", task: "Disable root SSH login", file: "/etc/ssh/sshd_config", setting: "PermitRootLogin no", priority: "High" },
  { category: "SSH", task: "Use SSH key authentication only", file: "/etc/ssh/sshd_config", setting: "PasswordAuthentication no", priority: "High" },
  { category: "SSH", task: "Change default SSH port", file: "/etc/ssh/sshd_config", setting: "Port 2222", priority: "Medium" },
  { category: "SSH", task: "Limit SSH to specific users", file: "/etc/ssh/sshd_config", setting: "AllowUsers user1 user2", priority: "High" },
  { category: "SSH", task: "Set SSH idle timeout", file: "/etc/ssh/sshd_config", setting: "ClientAliveInterval 300\\nClientAliveCountMax 2", priority: "Medium" },
  { category: "Firewall", task: "Enable firewall (UFW)", file: "Command", setting: "ufw enable && ufw default deny incoming", priority: "Critical" },
  { category: "Firewall", task: "Allow only necessary ports", file: "Command", setting: "ufw allow 22/tcp && ufw allow 80,443/tcp", priority: "Critical" },
  { category: "Users", task: "Set password complexity", file: "/etc/security/pwquality.conf", setting: "minlen=14 dcredit=-1 ucredit=-1 ocredit=-1", priority: "High" },
  { category: "Users", task: "Set account lockout", file: "/etc/pam.d/common-auth", setting: "auth required pam_tally2.so deny=5 unlock_time=900", priority: "High" },
  { category: "Users", task: "Disable unused accounts", file: "Command", setting: "usermod -L username && usermod -s /sbin/nologin username", priority: "Medium" },
  { category: "Filesystem", task: "Set noexec on /tmp", file: "/etc/fstab", setting: "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0", priority: "High" },
  { category: "Filesystem", task: "Enable disk quotas", file: "/etc/fstab", setting: "Add usrquota,grpquota to mount options", priority: "Medium" },
  { category: "Kernel", task: "Disable IPv6 (if not needed)", file: "/etc/sysctl.conf", setting: "net.ipv6.conf.all.disable_ipv6=1", priority: "Low" },
  { category: "Kernel", task: "Enable SYN flood protection", file: "/etc/sysctl.conf", setting: "net.ipv4.tcp_syncookies=1", priority: "High" },
  { category: "Kernel", task: "Disable IP source routing", file: "/etc/sysctl.conf", setting: "net.ipv4.conf.all.accept_source_route=0", priority: "High" },
  { category: "Kernel", task: "Enable ASLR", file: "/etc/sysctl.conf", setting: "kernel.randomize_va_space=2", priority: "High" },
  { category: "Logging", task: "Enable process accounting", file: "Command", setting: "apt install acct && accton on", priority: "Medium" },
  { category: "Logging", task: "Configure log rotation", file: "/etc/logrotate.conf", setting: "Set appropriate rotation policies", priority: "Medium" },
  { category: "Updates", task: "Enable automatic security updates", file: "Command", setting: "apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades", priority: "High" },
];

const ACCENT_COLOR = "#f97316";
const QUIZ_QUESTION_COUNT = 10;

const selectRandomQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "File System",
    question: "What is the root directory in Linux?",
    options: ["/", "/root", "/home", "C:\\"],
    correctAnswer: 0,
    explanation: "Linux uses a single hierarchy rooted at /.",
  },
  {
    id: 2,
    topic: "File System",
    question: "Which character separates directories in Linux paths?",
    options: ["/", "\\", ":", "|"],
    correctAnswer: 0,
    explanation: "Linux paths use the forward slash.",
  },
  {
    id: 3,
    topic: "File System",
    question: "What directory typically stores user home folders?",
    options: ["/home", "/etc", "/var", "/bin"],
    correctAnswer: 0,
    explanation: "User home directories are usually under /home.",
  },
  {
    id: 4,
    topic: "File System",
    question: "Which directory contains system configuration files?",
    options: ["/etc", "/usr", "/opt", "/srv"],
    correctAnswer: 0,
    explanation: "/etc stores system-wide configuration.",
  },
  {
    id: 5,
    topic: "File System",
    question: "Which directory is used for variable data like logs?",
    options: ["/var", "/tmp", "/dev", "/proc"],
    correctAnswer: 0,
    explanation: "/var holds variable data such as logs and spool files.",
  },
  {
    id: 6,
    topic: "File System",
    question: "Which directory is intended for temporary files?",
    options: ["/tmp", "/boot", "/lib", "/root"],
    correctAnswer: 0,
    explanation: "/tmp is used for temporary files.",
  },
  {
    id: 7,
    topic: "File System",
    question: "Which directory contains essential user binaries?",
    options: ["/bin", "/sbin", "/etc", "/opt"],
    correctAnswer: 0,
    explanation: "/bin stores essential user commands.",
  },
  {
    id: 8,
    topic: "File System",
    question: "Which directory contains system administration binaries?",
    options: ["/sbin", "/bin", "/usr/bin", "/home"],
    correctAnswer: 0,
    explanation: "/sbin holds system administration commands.",
  },
  {
    id: 9,
    topic: "File System",
    question: "What does the /proc directory provide?",
    options: ["Process and kernel information", "User profiles", "Installed packages", "Network logs"],
    correctAnswer: 0,
    explanation: "/proc is a virtual filesystem exposing process and kernel info.",
  },
  {
    id: 10,
    topic: "File System",
    question: "Which directory commonly stores third-party software?",
    options: ["/opt", "/etc", "/dev", "/sys"],
    correctAnswer: 0,
    explanation: "/opt is commonly used for optional or third-party apps.",
  },
  {
    id: 11,
    topic: "Users",
    question: "Which user ID (UID) is reserved for root?",
    options: ["0", "1", "1000", "65534"],
    correctAnswer: 0,
    explanation: "Root always has UID 0.",
  },
  {
    id: 12,
    topic: "Users",
    question: "Which file lists user accounts and basic info?",
    options: ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"],
    correctAnswer: 0,
    explanation: "/etc/passwd stores user account entries.",
  },
  {
    id: 13,
    topic: "Users",
    question: "Where are hashed user passwords stored?",
    options: ["/etc/shadow", "/etc/passwd", "/etc/group", "/var/log/auth.log"],
    correctAnswer: 0,
    explanation: "/etc/shadow contains password hashes and is readable by root only.",
  },
  {
    id: 14,
    topic: "Users",
    question: "Which file defines group memberships?",
    options: ["/etc/group", "/etc/passwd", "/etc/shadow", "/etc/hosts"],
    correctAnswer: 0,
    explanation: "/etc/group contains group definitions.",
  },
  {
    id: 15,
    topic: "Users",
    question: "What command shows the current user and groups?",
    options: ["id", "who", "uname", "uptime"],
    correctAnswer: 0,
    explanation: "id prints the current user identity and group memberships.",
  },
  {
    id: 16,
    topic: "Users",
    question: "Which command switches to another user account?",
    options: ["su", "ssh", "scp", "sudo"],
    correctAnswer: 0,
    explanation: "su switches to another user account.",
  },
  {
    id: 17,
    topic: "Users",
    question: "Which command creates a new user?",
    options: ["useradd", "usermod", "userdel", "passwd"],
    correctAnswer: 0,
    explanation: "useradd creates a new user account.",
  },
  {
    id: 18,
    topic: "Users",
    question: "Which command adds a user to a supplementary group?",
    options: ["usermod -aG", "useradd -g", "groupadd", "passwd -g"],
    correctAnswer: 0,
    explanation: "usermod -aG adds a user to additional groups.",
  },
  {
    id: 19,
    topic: "Users",
    question: "Which file controls sudo permissions?",
    options: ["/etc/sudoers", "/etc/passwd", "/etc/group", "/etc/profile"],
    correctAnswer: 0,
    explanation: "/etc/sudoers defines sudo rules.",
  },
  {
    id: 20,
    topic: "Users",
    question: "What command prints the current username?",
    options: ["whoami", "hostname", "groups", "users"],
    correctAnswer: 0,
    explanation: "whoami prints the effective user name.",
  },
  {
    id: 21,
    topic: "Permissions",
    question: "Linux file permissions are represented by:",
    options: ["rwx for user, group, others", "rwx for user only", "read only flags", "ACLs only"],
    correctAnswer: 0,
    explanation: "Standard permissions are rwx for user, group, and others.",
  },
  {
    id: 22,
    topic: "Permissions",
    question: "What does chmod 755 set?",
    options: ["rwxr-xr-x", "rw-r--r--", "rwx------", "r--r--r--"],
    correctAnswer: 0,
    explanation: "755 corresponds to rwxr-xr-x.",
  },
  {
    id: 23,
    topic: "Permissions",
    question: "What does chmod 644 set?",
    options: ["rw-r--r--", "rwxr-xr-x", "rw-rw----", "r--------"],
    correctAnswer: 0,
    explanation: "644 corresponds to rw-r--r--.",
  },
  {
    id: 24,
    topic: "Permissions",
    question: "Which command changes file ownership?",
    options: ["chown", "chmod", "chgrp", "umask"],
    correctAnswer: 0,
    explanation: "chown changes file owner.",
  },
  {
    id: 25,
    topic: "Permissions",
    question: "Which command changes file permissions?",
    options: ["chmod", "chown", "ls", "cat"],
    correctAnswer: 0,
    explanation: "chmod changes permissions on files or directories.",
  },
  {
    id: 26,
    topic: "Permissions",
    question: "What does the SUID bit do?",
    options: [
      "Runs a program with the file owner's privileges",
      "Hides files from listings",
      "Encrypts files automatically",
      "Forces a file to be read-only",
    ],
    correctAnswer: 0,
    explanation: "SUID runs the program with the owner's permissions.",
  },
  {
    id: 27,
    topic: "Permissions",
    question: "What does the SGID bit do on a file?",
    options: [
      "Runs with the file group's privileges",
      "Encrypts group files",
      "Changes the owner to root",
      "Disables execution",
    ],
    correctAnswer: 0,
    explanation: "SGID runs with the file group's permissions.",
  },
  {
    id: 28,
    topic: "Permissions",
    question: "What does the sticky bit do on /tmp?",
    options: [
      "Prevents users from deleting other users' files",
      "Automatically deletes files",
      "Encrypts temporary files",
      "Forces root ownership",
    ],
    correctAnswer: 0,
    explanation: "The sticky bit restricts deletions to file owners.",
  },
  {
    id: 29,
    topic: "Permissions",
    question: "What does umask control?",
    options: ["Default permission mask", "Process priority", "System time zone", "Network routes"],
    correctAnswer: 0,
    explanation: "umask sets default permissions for new files.",
  },
  {
    id: 30,
    topic: "Permissions",
    question: "Which command shows permissions in a long listing?",
    options: ["ls -l", "ls -a", "ls -h", "ls -t"],
    correctAnswer: 0,
    explanation: "ls -l shows permissions, owner, group, and timestamps.",
  },
  {
    id: 31,
    topic: "Processes",
    question: "What does PID stand for?",
    options: ["Process ID", "Program Index Descriptor", "Process Instance Directory", "Priority ID"],
    correctAnswer: 0,
    explanation: "PID means Process ID.",
  },
  {
    id: 32,
    topic: "Processes",
    question: "What does PPID represent?",
    options: ["Parent process ID", "Primary process ID", "Process priority ID", "Protected process ID"],
    correctAnswer: 0,
    explanation: "PPID is the Parent Process ID.",
  },
  {
    id: 33,
    topic: "Processes",
    question: "Which command lists running processes?",
    options: ["ps", "grep", "find", "mount"],
    correctAnswer: 0,
    explanation: "ps lists processes.",
  },
  {
    id: 34,
    topic: "Processes",
    question: "Which command provides a real-time process view?",
    options: ["top", "cat", "ls", "pwd"],
    correctAnswer: 0,
    explanation: "top shows processes in real time.",
  },
  {
    id: 35,
    topic: "Processes",
    question: "Which command manages services on systemd systems?",
    options: ["systemctl", "service", "initctl", "chkconfig"],
    correctAnswer: 0,
    explanation: "systemctl is used with systemd.",
  },
  {
    id: 36,
    topic: "Processes",
    question: "Which command views systemd logs?",
    options: ["journalctl", "dmesg", "tail", "logger"],
    correctAnswer: 0,
    explanation: "journalctl queries the systemd journal.",
  },
  {
    id: 37,
    topic: "Processes",
    question: "Which signal does kill -9 send?",
    options: ["SIGKILL", "SIGTERM", "SIGHUP", "SIGINT"],
    correctAnswer: 0,
    explanation: "kill -9 sends SIGKILL.",
  },
  {
    id: 38,
    topic: "Processes",
    question: "Which signal is a graceful termination request?",
    options: ["SIGTERM", "SIGKILL", "SIGSTOP", "SIGSEGV"],
    correctAnswer: 0,
    explanation: "SIGTERM requests graceful termination.",
  },
  {
    id: 39,
    topic: "Processes",
    question: "What does nice adjust?",
    options: ["Process priority", "Memory usage", "Disk quotas", "Network routes"],
    correctAnswer: 0,
    explanation: "nice adjusts process CPU priority.",
  },
  {
    id: 40,
    topic: "Processes",
    question: "What init system is common on modern Linux?",
    options: ["systemd", "sysvinit", "launchd", "upstart only"],
    correctAnswer: 0,
    explanation: "systemd is widely used on modern distributions.",
  },
  {
    id: 41,
    topic: "Packages",
    question: "Which command updates package lists on Debian-based systems?",
    options: ["apt update", "apt install", "apt clean", "apt remove"],
    correctAnswer: 0,
    explanation: "apt update refreshes package lists.",
  },
  {
    id: 42,
    topic: "Packages",
    question: "Which command upgrades installed packages on Debian-based systems?",
    options: ["apt upgrade", "apt update", "apt purge", "apt search"],
    correctAnswer: 0,
    explanation: "apt upgrade installs available updates.",
  },
  {
    id: 43,
    topic: "Packages",
    question: "Which package manager is common on Red Hat based systems?",
    options: ["dnf", "apt", "pacman", "zypper"],
    correctAnswer: 0,
    explanation: "dnf (or yum) is common on Red Hat based systems.",
  },
  {
    id: 44,
    topic: "Packages",
    question: "Which command installs a .deb package file?",
    options: ["dpkg -i", "rpm -i", "apt update", "snap install"],
    correctAnswer: 0,
    explanation: "dpkg -i installs a .deb package.",
  },
  {
    id: 45,
    topic: "Packages",
    question: "Which command installs an RPM package file?",
    options: ["rpm -i", "dpkg -i", "apt install", "pacman -S"],
    correctAnswer: 0,
    explanation: "rpm -i installs an RPM package.",
  },
  {
    id: 46,
    topic: "Packages",
    question: "Which command removes a package on Debian-based systems?",
    options: ["apt remove", "apt update", "apt list", "apt show"],
    correctAnswer: 0,
    explanation: "apt remove uninstalls packages.",
  },
  {
    id: 47,
    topic: "Packages",
    question: "Which command removes a package and its config files?",
    options: ["apt purge", "apt remove", "apt update", "apt policy"],
    correctAnswer: 0,
    explanation: "apt purge removes packages and configuration files.",
  },
  {
    id: 48,
    topic: "Packages",
    question: "Which command searches for packages on Debian-based systems?",
    options: ["apt search", "apt cache", "apt list", "apt repo"],
    correctAnswer: 0,
    explanation: "apt search finds packages by keyword.",
  },
  {
    id: 49,
    topic: "Packages",
    question: "Which command updates the package list on Alpine Linux?",
    options: ["apk update", "apt update", "dnf update", "yum update"],
    correctAnswer: 0,
    explanation: "apk update is used on Alpine.",
  },
  {
    id: 50,
    topic: "Packages",
    question: "Which command installs packages on Arch Linux?",
    options: ["pacman -S", "apt install", "rpm -i", "dnf install"],
    correctAnswer: 0,
    explanation: "pacman -S installs packages on Arch.",
  },
  {
    id: 51,
    topic: "Networking",
    question: "Which command shows IP addresses and interfaces?",
    options: ["ip a", "ifdown", "route", "arp"],
    correctAnswer: 0,
    explanation: "ip a shows addresses and interfaces.",
  },
  {
    id: 52,
    topic: "Networking",
    question: "Which command tests connectivity to a host?",
    options: ["ping", "dig", "curl", "ssh"],
    correctAnswer: 0,
    explanation: "ping checks reachability.",
  },
  {
    id: 53,
    topic: "Networking",
    question: "Which command traces the path to a host?",
    options: ["traceroute", "ping", "ss", "netstat"],
    correctAnswer: 0,
    explanation: "traceroute shows hops to a destination.",
  },
  {
    id: 54,
    topic: "Networking",
    question: "Which command lists listening sockets?",
    options: ["ss -tuln", "ls -l", "ps aux", "dmesg"],
    correctAnswer: 0,
    explanation: "ss -tuln lists listening TCP and UDP sockets.",
  },
  {
    id: 55,
    topic: "Networking",
    question: "Which command resolves DNS names?",
    options: ["dig", "pwd", "kill", "uname"],
    correctAnswer: 0,
    explanation: "dig queries DNS servers.",
  },
  {
    id: 56,
    topic: "Networking",
    question: "Which command provides a remote shell over SSH?",
    options: ["ssh", "scp", "rsync", "sftp"],
    correctAnswer: 0,
    explanation: "ssh opens a secure remote shell.",
  },
  {
    id: 57,
    topic: "Networking",
    question: "Which command copies files over SSH?",
    options: ["scp", "ssh", "rsync", "wget"],
    correctAnswer: 0,
    explanation: "scp copies files over SSH.",
  },
  {
    id: 58,
    topic: "Networking",
    question: "Which firewall tool is a frontend for iptables on Ubuntu?",
    options: ["ufw", "firewalld", "nft", "tcpdump"],
    correctAnswer: 0,
    explanation: "ufw is a simple firewall on Ubuntu.",
  },
  {
    id: 59,
    topic: "Networking",
    question: "Which file maps hostnames to IPs locally?",
    options: ["/etc/hosts", "/etc/resolv.conf", "/etc/passwd", "/etc/network/interfaces"],
    correctAnswer: 0,
    explanation: "/etc/hosts contains local hostname mappings.",
  },
  {
    id: 60,
    topic: "Networking",
    question: "Which file lists DNS servers?",
    options: ["/etc/resolv.conf", "/etc/hosts", "/etc/hostname", "/etc/apt/sources.list"],
    correctAnswer: 0,
    explanation: "/etc/resolv.conf defines DNS servers.",
  },
  {
    id: 61,
    topic: "Shell",
    question: "Which command prints the current directory?",
    options: ["pwd", "ls", "cd", "whoami"],
    correctAnswer: 0,
    explanation: "pwd shows the current working directory.",
  },
  {
    id: 62,
    topic: "Shell",
    question: "Which command lists files including hidden files?",
    options: ["ls -a", "ls -l", "ls -h", "ls -t"],
    correctAnswer: 0,
    explanation: "ls -a shows hidden files.",
  },
  {
    id: 63,
    topic: "Shell",
    question: "Which command searches text within files?",
    options: ["grep", "cat", "touch", "mkdir"],
    correctAnswer: 0,
    explanation: "grep searches for text patterns in files.",
  },
  {
    id: 64,
    topic: "Shell",
    question: "Which command finds files by name?",
    options: ["find", "locate", "which", "whereis"],
    correctAnswer: 0,
    explanation: "find searches the filesystem for matching files.",
  },
  {
    id: 65,
    topic: "Shell",
    question: "Which command prints the contents of a file?",
    options: ["cat", "pwd", "cd", "ls"],
    correctAnswer: 0,
    explanation: "cat prints file contents.",
  },
  {
    id: 66,
    topic: "Shell",
    question: "Which command shows a file page by page?",
    options: ["less", "cp", "mv", "rm"],
    correctAnswer: 0,
    explanation: "less provides paged viewing.",
  },
  {
    id: 67,
    topic: "Shell",
    question: "Which command archives files into a tarball?",
    options: ["tar -czf", "zip -r", "gzip -d", "unzip"],
    correctAnswer: 0,
    explanation: "tar -czf creates a compressed tarball.",
  },
  {
    id: 68,
    topic: "Shell",
    question: "Which command changes directories?",
    options: ["cd", "ls", "pwd", "echo"],
    correctAnswer: 0,
    explanation: "cd changes the current directory.",
  },
  {
    id: 69,
    topic: "Shell",
    question: "Which command displays command history?",
    options: ["history", "alias", "export", "env"],
    correctAnswer: 0,
    explanation: "history shows recent commands.",
  },
  {
    id: 70,
    topic: "Shell",
    question: "Which command edits a user's crontab?",
    options: ["crontab -e", "cron -e", "at -e", "systemctl edit"],
    correctAnswer: 0,
    explanation: "crontab -e edits the user's cron entries.",
  },
  {
    id: 71,
    topic: "Security",
    question: "Where are most system logs stored?",
    options: ["/var/log", "/etc/logs", "/usr/logs", "/root/logs"],
    correctAnswer: 0,
    explanation: "System logs are typically under /var/log.",
  },
  {
    id: 72,
    topic: "Security",
    question: "Which log file commonly records SSH and sudo activity on Debian?",
    options: ["/var/log/auth.log", "/var/log/secure", "/var/log/messages", "/var/log/syslog"],
    correctAnswer: 0,
    explanation: "Debian-based systems use /var/log/auth.log for auth events.",
  },
  {
    id: 73,
    topic: "Security",
    question: "What does the command 'sudo !!' do?",
    options: ["Repeats the last command with sudo", "Shows sudo logs", "Edits sudoers", "Clears sudo cache"],
    correctAnswer: 0,
    explanation: "sudo !! re-runs the previous command with sudo.",
  },
  {
    id: 74,
    topic: "Security",
    question: "Which tool helps block brute force SSH attempts?",
    options: ["fail2ban", "cron", "rsync", "telnet"],
    correctAnswer: 0,
    explanation: "fail2ban bans IPs after repeated failed logins.",
  },
  {
    id: 75,
    topic: "Security",
    question: "Which SSH setting disables root logins?",
    options: ["PermitRootLogin no", "PasswordAuthentication yes", "AllowUsers root", "UsePAM no"],
    correctAnswer: 0,
    explanation: "PermitRootLogin no prevents root SSH logins.",
  },
];

export default function LinuxFundamentalsPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const accent = "#22c55e";

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "history", label: "History & Timeline", icon: <HistoryIcon /> },
    { id: "stats", label: "By The Numbers", icon: <SpeedIcon /> },
    { id: "core-concepts", label: "Core Concepts", icon: <ComputerIcon /> },
    { id: "distributions", label: "Distributions", icon: <LayersIcon /> },
    { id: "boot-process", label: "Boot Process", icon: <PlayArrowIcon /> },
    { id: "directories", label: "Directories", icon: <FolderIcon /> },
    { id: "commands", label: "Essential Commands", icon: <TerminalIcon /> },
    { id: "permissions", label: "File Permissions", icon: <LockIcon /> },
    { id: "logs", label: "Log Files", icon: <DescriptionIcon /> },
    { id: "systemd", label: "systemd & Services", icon: <SettingsIcon /> },
    { id: "security-tools", label: "Security Tools", icon: <SecurityIcon /> },
    { id: "cron", label: "Cron Scheduling", icon: <LoopIcon /> },
    { id: "environment", label: "Environment Vars", icon: <BuildIcon /> },
    { id: "shortcuts", label: "Keyboard Shortcuts", icon: <KeyIcon /> },
    { id: "scripting", label: "Shell Scripting", icon: <CodeIcon /> },
    { id: "editors", label: "Text Editors", icon: <EditIcon /> },
    { id: "pioneers", label: "Pioneers & Philosophy", icon: <MenuBookIcon /> },
    { id: "administration", label: "Administration", icon: <AdminPanelSettingsIcon /> },
    { id: "quiz", label: "Knowledge Check", icon: <QuizIcon /> },
  ];

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      const yOffset = -80;
      const y = element.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: "smooth" });
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
          if (rect.top <= 150 && rect.bottom >= 150) {
            currentSection = sectionId;
            break;
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

  const [quizPool] = React.useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  const pageContext = `Linux Fundamentals learning page - Essential Linux operating system concepts for security professionals. Covers file system hierarchy, users & groups, processes & services, package management, and shell basics.`;

  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        position: "sticky",
        top: 80,
        p: 2,
        borderRadius: 3,
        border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        backdropFilter: "blur(20px)",
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-track": { background: "transparent" },
        "&::-webkit-scrollbar-thumb": {
          background: alpha(accent, 0.3),
          borderRadius: 3,
          "&:hover": { background: alpha(accent, 0.5) },
        },
      }}
    >
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", textTransform: "uppercase", letterSpacing: 1 }}>
          Navigation
        </Typography>
        <Box sx={{ mt: 1 }}>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 4,
              borderRadius: 2,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 2,
              },
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
    <LearnPageLayout pageTitle="Linux Fundamentals" pageContext={pageContext}>
      {/* Floating Action Buttons */}
      <Tooltip title="Navigation" placement="left">
        <Fab
          color="primary"
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            bgcolor: accent,
            "&:hover": { bgcolor: alpha(accent, 0.9) },
            zIndex: 1000,
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
            backdropFilter: "blur(10px)",
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            "&:hover": { bgcolor: theme.palette.background.paper },
            zIndex: 1000,
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
            <Typography variant="h6" sx={{ fontWeight: 700 }}>
              Navigation
            </Typography>
            <IconButton size="small" onClick={() => setNavDrawerOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Box>

          {/* Progress Bar */}
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
              <Typography variant="caption" sx={{ fontWeight: 600, color: "text.secondary" }}>
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 700, color: accent }}>
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
                {activeSection === item.id && (
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      fontWeight: 700,
                      bgcolor: accent,
                      color: "white",
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>

      <Container maxWidth="xl" sx={{ py: 4 }}>
        <Grid container spacing={3}>
          {/* Sidebar Navigation - Desktop */}
          {!isMobile && (
            <Grid item md={3}>
              {sidebarNav}
            </Grid>
          )}

          {/* Main Content */}
          <Grid item xs={12} md={9}>
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
            background: `linear-gradient(135deg, ${alpha("#f97316", 0.15)} 0%, ${alpha("#ea580c", 0.1)} 100%)`,
            border: `1px solid ${alpha("#f97316", 0.2)}`,
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
              background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)}, transparent)`,
            }}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
            <Box
              sx={{
                width: 80,
                height: 80,
                borderRadius: 3,
                background: `linear-gradient(135deg, #f97316, #ea580c)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#f97316", 0.3)}`,
              }}
            >
              <ComputerIcon sx={{ fontSize: 45, color: "white" }} />
            </Box>
            <Box>
              <Chip label="IT Fundamentals" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha("#f97316", 0.1), color: "#f97316" }} />
              <Typography variant="h3" sx={{ fontWeight: 800, mb: 1 }}>
                Linux Fundamentals
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600 }}>
                Master the Linux operating system from the ground up
              </Typography>
            </Box>
          </Box>
        </Paper>

        {/* Back to Learning Hub Link */}
        <Box sx={{ mb: 3 }}>
          <Chip
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            onClick={() => navigate("/learn")}
            sx={{
              cursor: "pointer",
              fontWeight: 600,
              bgcolor: alpha("#f97316", 0.1),
              color: "#f97316",
              "&:hover": { bgcolor: alpha("#f97316", 0.2) },
            }}
          />
        </Box>

        {/* Overview Section - Comprehensive */}
        <Paper
          id="intro"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <InfoIcon sx={{ color: "#f97316" }} />
            What is Linux?
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            <strong>Linux</strong> is a free, open-source, Unix-like operating system kernel first created by 
            <strong> Linus Torvalds</strong> in 1991 while he was a computer science student at the University of Helsinki, Finland.
            What started as a hobby project ("just a hobby, won't be big and professional like GNU") has grown into the most 
            widely deployed operating system on the planet. The name "Linux" is a combination of Linus's first name and 
            Unix, the operating system that inspired its creation.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Technically, "Linux" refers only to the <strong>kernel</strong>—the core component that manages hardware resources, 
            memory, processes, and system calls. A complete operating system also requires system libraries, utilities, 
            and applications, which is why you'll often hear the term <strong>"GNU/Linux"</strong>—acknowledging that most 
            Linux distributions use the GNU Project's tools (created by Richard Stallman in 1983) alongside the Linux kernel.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Linux is licensed under the <strong>GNU General Public License (GPL)</strong>, which means anyone can view, modify, 
            and distribute the source code freely. This open-source model has led to an incredible ecosystem of collaboration, 
            with over 20,000 developers contributing to the kernel alone. Companies like Red Hat, Canonical, SUSE, and Google 
            all contribute to Linux development while building their businesses around it.
          </Typography>

          <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
            <Typography variant="body2">
              <strong>Fun Fact:</strong> The Linux mascot is a penguin named <strong>Tux</strong>, created by Larry Ewing in 1996. 
              Linus Torvalds chose a penguin because he was once bitten by one at an aquarium in Australia!
            </Typography>
          </Alert>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1.5, color: "#f97316" }}>
            Why Linux Dominates Infrastructure
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Linux powers the digital world in ways most people never see. It runs on <strong>96% of the world's top 1 million 
            web servers</strong>, <strong>100% of the TOP500 supercomputers</strong>, and forms the foundation of 
            <strong>Android</strong> (85%+ of smartphones). Major cloud providers (AWS, Azure, Google Cloud) default to Linux. 
            Netflix, Google, Facebook, Amazon, and virtually every major tech company runs on Linux infrastructure.
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            The reasons are clear: Linux is <strong>stable</strong> (servers run for years without reboots), 
            <strong>secure</strong> (open-source means vulnerabilities are found and fixed quickly), 
            <strong>flexible</strong> (runs on everything from embedded devices to supercomputers), 
            <strong>free</strong> (no licensing costs), and <strong>customizable</strong> (you control every aspect).
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1.5, color: "#f97316" }}>
            Why Security Professionals MUST Learn Linux
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { title: "Security Tools", desc: "Metasploit, Nmap, Burp Suite, Wireshark—most run natively on Linux" },
              { title: "Server Targets", desc: "Most servers you'll audit or penetration test run Linux" },
              { title: "Forensics", desc: "Disk imaging, memory analysis, and log examination require Linux skills" },
              { title: "Scripting & Automation", desc: "Bash scripting is essential for automating security tasks" },
              { title: "Incident Response", desc: "Analyzing compromised systems requires deep Linux knowledge" },
              { title: "Container Security", desc: "Docker, Kubernetes, and cloud-native security all revolve around Linux" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.title}>
                <Box sx={{ p: 2, bgcolor: alpha("#f97316", 0.05), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 0.5 }}>
                    {item.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {item.desc}
                  </Typography>
                </Box>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1.5, color: "#f97316" }}>
            What You'll Learn in This Guide
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            This comprehensive guide covers everything you need to become proficient in Linux: the <strong>file system 
            hierarchy</strong> and where things live, <strong>user management</strong> and permissions, <strong>process 
            control</strong> and monitoring, the <strong>boot process</strong>, <strong>systemd</strong> and service management, 
            <strong>networking</strong> from the command line, <strong>log analysis</strong>, <strong>security hardening</strong>, 
            and mastering <strong>80+ essential commands</strong>. We also cover the major distributions (Ubuntu, Kali Linux, 
            Red Hat Enterprise Linux) in detail with version histories and specific use cases.
          </Typography>
        </Paper>

        {/* Linux History Timeline */}
        <Typography id="history" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          📜 Linux History & Timeline
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Key milestones in Linux development from Unix origins to today
        </Typography>
        <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
          <Typography variant="body2">
            <strong>Why History Matters:</strong> Understanding Linux's roots helps you understand why things work the way they do. 
            Linux inherited many concepts from Unix (created in 1969), so commands like <code>ls</code>, <code>grep</code>, and 
            <code>chmod</code> have been around for over 50 years! The open-source philosophy that drives Linux development means 
            thousands of developers contribute improvements, making it the most battle-tested operating system for servers.
          </Typography>
        </Alert>

        <Paper sx={{ p: 3, mb: 5, borderRadius: 4, border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
          <Box sx={{ position: "relative" }}>
            {linuxHistory.map((event, index) => (
              <Box key={event.year} sx={{ display: "flex", gap: 3, mb: index < linuxHistory.length - 1 ? 2 : 0 }}>
                <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                  <Box
                    sx={{
                      minWidth: 60,
                      px: 1,
                      py: 0.5,
                      borderRadius: 2,
                      bgcolor: "#8b5cf6",
                      color: "white",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
                      fontSize: "0.75rem",
                    }}
                  >
                    {event.year}
                  </Box>
                  {index < linuxHistory.length - 1 && (
                    <Box sx={{ width: 2, height: 20, bgcolor: alpha("#8b5cf6", 0.3), mt: 0.5 }} />
                  )}
                </Box>
                <Box sx={{ flex: 1, pb: 1 }}>
                  <Typography variant="body2">{event.event}</Typography>
                </Box>
              </Box>
            ))}
          </Box>
        </Paper>

        {/* Linux Market Stats */}
        <Typography id="stats" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          📊 Linux By The Numbers
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Statistics showing Linux's dominance in modern computing
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {linuxStats.map((item) => (
            <Grid item xs={6} md={3} key={item.stat}>
              <Paper
                sx={{
                  p: 2.5,
                  textAlign: "center",
                  borderRadius: 3,
                  border: `1px solid ${alpha("#10b981", 0.2)}`,
                  height: "100%",
                }}
              >
                <Typography variant="h4" sx={{ fontWeight: 800, color: "#10b981", mb: 0.5 }}>
                  {item.stat}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {item.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Quick Stats */}
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { value: "6", label: "Core Concepts", color: "#f97316" },
            { value: "26", label: "Key Directories", color: "#10b981" },
            { value: "120+", label: "Essential Commands", color: "#3b82f6" },
            { value: "7", label: "Distro Families", color: "#8b5cf6" },
            { value: "17", label: "Log Files", color: "#ef4444" },
            { value: "16", label: "Security Tools", color: "#06b6d4" },
          ].map((stat) => (
            <Grid item xs={6} md={2} key={stat.label}>
              <Paper
                sx={{
                  p: 2,
                  textAlign: "center",
                  borderRadius: 3,
                  border: `1px solid ${alpha(stat.color, 0.2)}`,
                }}
              >
                <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                  {stat.value}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {stat.label}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Core Concepts */}
        <Typography id="core-concepts" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🐧 Core Linux Concepts
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Fundamental building blocks of the Linux operating system
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          {linuxConcepts.map((concept) => (
            <Grid item xs={12} md={6} key={concept.title}>
              <Paper
                sx={{
                  p: 0,
                  height: "100%",
                  borderRadius: 4,
                  overflow: "hidden",
                  border: `1px solid ${alpha(concept.color, 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    boxShadow: `0 12px 40px ${alpha(concept.color, 0.15)}`,
                  },
                }}
              >
                <Box
                  sx={{
                    p: 2,
                    background: `linear-gradient(135deg, ${alpha(concept.color, 0.15)} 0%, ${alpha(concept.color, 0.05)} 100%)`,
                    borderBottom: `1px solid ${alpha(concept.color, 0.1)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box
                      sx={{
                        width: 48,
                        height: 48,
                        borderRadius: 2,
                        background: `linear-gradient(135deg, ${concept.color}, ${alpha(concept.color, 0.7)})`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "white",
                      }}
                    >
                      {concept.icon}
                    </Box>
                    <Box>
                      <Typography variant="h6" sx={{ fontWeight: 700 }}>
                        {concept.title}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {concept.description}
                      </Typography>
                    </Box>
                  </Box>
                </Box>
                <Box sx={{ p: 2.5 }}>
                  {/* Beginner-friendly explanation */}
                  {(concept as any).beginnerExplanation && (
                    <Box
                      sx={{
                        mb: 2,
                        p: 2,
                        borderRadius: 2,
                        bgcolor: alpha(concept.color, 0.05),
                        borderLeft: `3px solid ${concept.color}`,
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ lineHeight: 1.7, color: "text.secondary", fontSize: "0.85rem" }}
                      >
                        💡 <strong>For Beginners:</strong> {(concept as any).beginnerExplanation}
                      </Typography>
                    </Box>
                  )}
                  <List dense>
                    {concept.keyPoints.map((point) => (
                      <ListItem key={point} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: concept.color }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={point}
                          primaryTypographyProps={{ variant: "body2", lineHeight: 1.5 }}
                        />
                      </ListItem>
                    ))}
                  </List>
                  <Box
                    sx={{
                      mt: 2,
                      p: 1.5,
                      borderRadius: 2,
                      bgcolor: alpha("#f59e0b", 0.05),
                      border: `1px dashed ${alpha("#f59e0b", 0.3)}`,
                    }}
                  >
                    <Typography
                      variant="caption"
                      sx={{ display: "flex", alignItems: "flex-start", gap: 0.5, fontWeight: 500 }}
                    >
                      <SecurityIcon sx={{ fontSize: 14, color: "#f59e0b", mt: 0.2 }} />
                      {concept.securityNote}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Linux Distributions */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            DISTRIBUTIONS
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="distributions" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🐧 Linux Distributions
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Major Linux distributions and their use cases
        </Typography>
        
        <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>🤔 What's a "Distro"? Which Should You Choose?</AlertTitle>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            A "distribution" (distro) is a complete Linux operating system package. They all use the same Linux kernel, but differ in 
            what software is included, how packages are managed, and who they're designed for. Think of it like different car brands - 
            they all have wheels and engines, but Toyota and Ferrari serve different needs.
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Beginner recommendations:</strong><br/>
            • <strong>Ubuntu/Linux Mint</strong> - Best for beginners, huge community, tons of tutorials online<br/>
            • <strong>Kali Linux</strong> - For security/hacking learning (NOT for daily use!)<br/>
            • <strong>CentOS Stream/Rocky/AlmaLinux</strong> - For server admin practice (mimics enterprise RHEL)
          </Typography>
          <Typography variant="body2">
            <strong>Pro tip:</strong> Start with Ubuntu in a virtual machine (VirtualBox is free). Once comfortable, try others. 
            The commands you learn transfer between distros - mostly just package managers differ.
          </Typography>
        </Alert>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {linuxDistributions.map((distro) => (
            <Grid item xs={12} md={6} lg={4} key={distro.name}>
              <Paper
                sx={{
                  p: 2.5,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha("#f97316", 0.15)}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    transform: "translateY(-2px)",
                    boxShadow: `0 8px 24px ${alpha("#f97316", 0.1)}`,
                  },
                }}
              >
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1.5 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#f97316" }}>
                    {distro.name}
                  </Typography>
                  <Chip label={distro.family} size="small" sx={{ bgcolor: alpha("#f97316", 0.1), fontWeight: 600, fontSize: "0.65rem" }} />
                </Box>
                <Box sx={{ display: "flex", gap: 1, mb: 1.5, flexWrap: "wrap" }}>
                  <Chip label={distro.packageManager} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                  <Chip label={distro.releaseModel} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  <strong>Use Case:</strong> {distro.useCase}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {distro.notes}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Ubuntu Deep Dive */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            border: `2px solid ${alpha("#E95420", 0.3)}`,
            background: `linear-gradient(135deg, ${alpha("#E95420", 0.05)} 0%, transparent 100%)`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 60,
                height: 60,
                borderRadius: 3,
                bgcolor: "#E95420",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Typography variant="h4" sx={{ color: "white", fontWeight: 800 }}>U</Typography>
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#E95420" }}>
                {ubuntuDetails.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Developer: {ubuntuDetails.developer} | First Release: {ubuntuDetails.firstRelease}
              </Typography>
            </Box>
          </Box>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E95420" }}>
                📋 Version History (LTS = Long Term Support)
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#E95420", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Version</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Codename</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Release</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Support Until</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {ubuntuDetails.versions.map((v) => (
                      <TableRow key={v.version}>
                        <TableCell sx={{ fontWeight: v.version.includes("LTS") ? 700 : 400, color: v.version.includes("LTS") ? "#E95420" : "inherit" }}>
                          {v.version}
                        </TableCell>
                        <TableCell>{v.codename}</TableCell>
                        <TableCell>{v.release}</TableCell>
                        <TableCell sx={{ fontSize: "0.75rem" }}>{v.support}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              <Alert severity="info" sx={{ mt: 2, borderRadius: 2 }}>
                <Typography variant="body2">
                  <strong>Recommendation:</strong> For servers, always use LTS versions (5 years of standard support, 
                  10 years with ESM - Extended Security Maintenance).
                </Typography>
              </Alert>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E95420" }}>
                🖥️ Ubuntu Flavors
              </Typography>
              <Grid container spacing={1}>
                {ubuntuDetails.flavors.map((f) => (
                  <Grid item xs={12} key={f.name}>
                    <Box sx={{ p: 1.5, bgcolor: alpha("#E95420", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{f.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{f.description}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E95420" }}>
                ⌨️ Ubuntu-Specific Commands
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {ubuntuDetails.keyCommands.map((c) => (
                  <Chip
                    key={c.cmd}
                    label={
                      <Box>
                        <Typography sx={{ fontFamily: "monospace", fontSize: "0.75rem", fontWeight: 600 }}>{c.cmd}</Typography>
                        <Typography sx={{ fontSize: "0.65rem", color: "text.secondary" }}>{c.desc}</Typography>
                      </Box>
                    }
                    sx={{ height: "auto", py: 1, borderRadius: 2 }}
                    variant="outlined"
                  />
                ))}
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Kali Linux Deep Dive */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            border: `2px solid ${alpha("#557C94", 0.3)}`,
            background: `linear-gradient(135deg, ${alpha("#557C94", 0.05)} 0%, transparent 100%)`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 60,
                height: 60,
                borderRadius: 3,
                bgcolor: "#557C94",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SecurityIcon sx={{ fontSize: 32, color: "white" }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#557C94" }}>
                {kaliDetails.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Developer: {kaliDetails.developer} | First Release: {kaliDetails.firstRelease} | Successor to: {kaliDetails.predecessor}
              </Typography>
            </Box>
          </Box>

          <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
            <Typography variant="body2">
              <strong>⚠️ Ethical Use Only:</strong> Kali Linux is designed for security professionals. Only use these tools 
              on systems you own or have explicit written authorization to test. Unauthorized access is illegal.
            </Typography>
          </Alert>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#557C94" }}>
                📋 Recent Versions (Rolling Release)
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#557C94", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Version</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Release</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Kernel</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {kaliDetails.versions.map((v) => (
                      <TableRow key={v.version}>
                        <TableCell sx={{ fontWeight: 600, color: "#557C94" }}>{v.version}</TableCell>
                        <TableCell>{v.release}</TableCell>
                        <TableCell>{v.kernel}</TableCell>
                        <TableCell sx={{ fontSize: "0.75rem" }}>{v.notes}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#557C94" }}>
                💿 Available Editions
              </Typography>
              <Grid container spacing={1}>
                {kaliDetails.editions.map((e) => (
                  <Grid item xs={6} key={e.name}>
                    <Box sx={{ p: 1.5, bgcolor: alpha("#557C94", 0.05), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{e.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{e.description}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#557C94" }}>
                🛠️ Pre-Installed Tool Categories
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#557C94", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Example Tools</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {kaliDetails.toolCategories.map((t) => (
                      <TableRow key={t.category}>
                        <TableCell sx={{ fontWeight: 600 }}>{t.category}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{t.tools}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#557C94" }}>
                ⌨️ Kali-Specific Commands
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {kaliDetails.keyCommands.map((c) => (
                  <Chip
                    key={c.cmd}
                    label={
                      <Box>
                        <Typography sx={{ fontFamily: "monospace", fontSize: "0.75rem", fontWeight: 600 }}>{c.cmd}</Typography>
                        <Typography sx={{ fontSize: "0.65rem", color: "text.secondary" }}>{c.desc}</Typography>
                      </Box>
                    }
                    sx={{ height: "auto", py: 1, borderRadius: 2 }}
                    variant="outlined"
                  />
                ))}
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* RHEL Deep Dive */}
        <Paper
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            border: `2px solid ${alpha("#EE0000", 0.3)}`,
            background: `linear-gradient(135deg, ${alpha("#EE0000", 0.05)} 0%, transparent 100%)`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 60,
                height: 60,
                borderRadius: 3,
                bgcolor: "#EE0000",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <StorageIcon sx={{ fontSize: 32, color: "white" }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#EE0000" }}>
                {rhelDetails.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Developer: {rhelDetails.developer} | First Release: {rhelDetails.firstRelease}
              </Typography>
            </Box>
          </Box>

          <Alert severity="success" sx={{ mb: 3, borderRadius: 2 }}>
            <Typography variant="body2">
              <strong>Enterprise Standard:</strong> {rhelDetails.enterprises}
            </Typography>
          </Alert>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#EE0000" }}>
                📋 Version History (10-Year Lifecycle)
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha("#EE0000", 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Version</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Release</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Kernel</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Support Until</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rhelDetails.versions.map((v) => (
                      <TableRow key={v.version}>
                        <TableCell sx={{ fontWeight: 600, color: "#EE0000" }}>{v.version}</TableCell>
                        <TableCell>{v.release}</TableCell>
                        <TableCell>{v.kernel}</TableCell>
                        <TableCell sx={{ fontSize: "0.75rem" }}>{v.support}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#EE0000" }}>
                🆓 Free RHEL-Compatible Alternatives
              </Typography>
              <Grid container spacing={1}>
                {rhelDetails.freeAlternatives.map((a) => (
                  <Grid item xs={12} key={a.name}>
                    <Box sx={{ p: 1.5, bgcolor: alpha("#EE0000", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{a.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{a.description}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#EE0000" }}>
                🎓 Red Hat Certifications
              </Typography>
              <Grid container spacing={1}>
                {rhelDetails.certifications.map((c) => (
                  <Grid item xs={12} key={c.name}>
                    <Box sx={{ p: 1.5, bgcolor: alpha("#EE0000", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{c.name} ({c.exam})</Typography>
                      <Typography variant="caption" color="text.secondary">{c.fullName}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#EE0000" }}>
                ⌨️ RHEL-Specific Commands
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {rhelDetails.keyCommands.map((c) => (
                  <Chip
                    key={c.cmd}
                    label={
                      <Box>
                        <Typography sx={{ fontFamily: "monospace", fontSize: "0.75rem", fontWeight: 600 }}>{c.cmd}</Typography>
                        <Typography sx={{ fontSize: "0.65rem", color: "text.secondary" }}>{c.desc}</Typography>
                      </Box>
                    }
                    sx={{ height: "auto", py: 1, borderRadius: 2 }}
                    variant="outlined"
                  />
                ))}
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Boot Process */}
        <Typography id="boot-process" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🚀 Linux Boot Process
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Understanding how Linux starts up
        </Typography>
        <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
          <Typography variant="body2">
            <strong>For Beginners:</strong> When you press the power button, your computer goes through a careful sequence to start up. 
            First, the hardware initializes (BIOS/UEFI), then a small program called the bootloader (GRUB) loads the Linux kernel into 
            memory. The kernel is the core of Linux - it talks to your hardware. Then systemd (the init system) takes over and starts 
            all your services like networking, login screens, and web servers. Understanding this sequence helps you troubleshoot boot 
            problems and understand how services start.
          </Typography>
        </Alert>

        <Paper sx={{ p: 3, mb: 5, borderRadius: 4, border: `1px solid ${alpha("#10b981", 0.15)}` }}>
          <Box sx={{ position: "relative" }}>
            {bootProcess.map((step, index) => (
              <Box key={step.step} sx={{ display: "flex", gap: 3, mb: index < bootProcess.length - 1 ? 3 : 0 }}>
                <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                  <Box
                    sx={{
                      width: 40,
                      height: 40,
                      borderRadius: "50%",
                      bgcolor: "#10b981",
                      color: "white",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
                    }}
                  >
                    {step.step}
                  </Box>
                  {index < bootProcess.length - 1 && (
                    <Box sx={{ width: 2, height: 40, bgcolor: alpha("#10b981", 0.3), mt: 1 }} />
                  )}
                </Box>
                <Box sx={{ flex: 1, pb: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981" }}>
                    {step.name}
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>{step.description}</Typography>
                  <Typography variant="caption" color="text.secondary">{step.details}</Typography>
                </Box>
              </Box>
            ))}
          </Box>
        </Paper>

        {/* Important Directories */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            FILE SYSTEM
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="directories" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          📁 Important Directories
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Key locations in the Linux file system hierarchy with forensic notes
        </Typography>
        <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
          <Typography variant="body2">
            <strong>For Beginners:</strong> Every Linux system follows a standard directory layout called the Filesystem Hierarchy Standard (FHS). 
            This means once you learn it, you can navigate any Linux system! Here's a quick mental map: <strong>/home</strong> = your personal files, 
            <strong>/etc</strong> = configuration files, <strong>/var/log</strong> = log files, <strong>/usr</strong> = installed programs, 
            <strong>/tmp</strong> = temporary files that get deleted. The "forensic notes" column shows what security professionals look for 
            when investigating a compromised system - these are common hiding spots for malware and signs of intrusion.
          </Typography>
        </Alert>

        <TableContainer
          component={Paper}
          sx={{
            mb: 4,
            borderRadius: 4,
            border: `1px solid ${alpha("#f97316", 0.15)}`,
          }}
        >
          <Table size="small">
            <TableHead>
              <TableRow
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)} 0%, ${alpha("#ea580c", 0.1)} 100%)`,
                }}
              >
                <TableCell sx={{ fontWeight: 700 }}>Path</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Forensic Note</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {importantDirectories.map((dir, index) => (
                <TableRow
                  key={dir.path}
                  sx={{
                    bgcolor: index % 2 === 0 ? "transparent" : alpha("#f97316", 0.02),
                  }}
                >
                  <TableCell>
                    <Typography
                      variant="body2"
                      sx={{ fontFamily: "monospace", fontWeight: 600, color: "#f97316", fontSize: "0.75rem" }}
                    >
                      {dir.path}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{dir.description}</Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={dir.purpose}
                      size="small"
                      sx={{
                        bgcolor: alpha("#f97316", 0.1),
                        color: "#f97316",
                        fontWeight: 600,
                        fontSize: "0.65rem",
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" sx={{ color: "#f59e0b", fontSize: "0.7rem" }}>{dir.forensicNote}</Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Important Config Files */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          📄 Important Configuration Files
        </Typography>

        <TableContainer
          component={Paper}
          sx={{
            mb: 5,
            borderRadius: 4,
            border: `1px solid ${alpha("#3b82f6", 0.15)}`,
          }}
        >
          <Table size="small">
            <TableHead>
              <TableRow
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.1)} 0%, ${alpha("#2563eb", 0.1)} 100%)`,
                }}
              >
                <TableCell sx={{ fontWeight: 700 }}>File</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Permissions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {importantConfigFiles.map((file, index) => (
                <TableRow
                  key={file.file}
                  sx={{
                    bgcolor: index % 2 === 0 ? "transparent" : alpha("#3b82f6", 0.02),
                  }}
                >
                  <TableCell>
                    <Typography
                      variant="body2"
                      sx={{ fontFamily: "monospace", fontWeight: 600, color: "#3b82f6", fontSize: "0.75rem" }}
                    >
                      {file.file}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{file.description}</Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={file.permissions}
                      size="small"
                      sx={{
                        fontFamily: "monospace",
                        bgcolor: alpha("#3b82f6", 0.1),
                        fontWeight: 600,
                        fontSize: "0.7rem",
                      }}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Essential Commands - Accordion by Category */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            COMMAND LINE
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="commands" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          ⌨️ Essential Commands
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          120+ commands organized by category - click to expand
        </Typography>
        <Alert severity="success" sx={{ mb: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>🎯 Start Here If You're New</AlertTitle>
          <Typography variant="body2">
            Don't try to memorize all these! Start with the basics and learn more as you need them:<br/>
            • <strong>Navigation:</strong> <code>ls</code> (list files), <code>cd</code> (change directory), <code>pwd</code> (where am I?)<br/>
            • <strong>Reading files:</strong> <code>cat</code> (show contents), <code>less</code> (scrollable view), <code>head/tail</code> (first/last lines)<br/>
            • <strong>File operations:</strong> <code>cp</code> (copy), <code>mv</code> (move/rename), <code>rm</code> (delete - be careful!)<br/>
            • <strong>Searching:</strong> <code>grep</code> (find text in files), <code>find</code> (locate files)<br/>
            • <strong>Help:</strong> <code>man command</code> (manual), <code>command --help</code> (quick help)<br/>
            Pro tip: Use <strong>Tab</strong> for auto-complete and <strong>↑/↓</strong> arrows for command history!
          </Typography>
        </Alert>

        {/* Group commands by category */}
        {Array.from(new Set(essentialCommands.map(c => c.category))).map((category) => (
          <Accordion
            key={category}
            sx={{
              mb: 1,
              borderRadius: "12px !important",
              border: `1px solid ${alpha("#10b981", 0.15)}`,
              "&:before": { display: "none" },
              overflow: "hidden",
            }}
          >
            <AccordionSummary
              expandIcon={<ExpandMoreIcon />}
              sx={{
                background: `linear-gradient(135deg, ${alpha("#10b981", 0.05)} 0%, transparent 100%)`,
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981" }}>
                  {category}
                </Typography>
                <Chip
                  label={`${essentialCommands.filter(c => c.category === category).length} commands`}
                  size="small"
                  sx={{ fontSize: "0.65rem" }}
                />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={1.5}>
                {essentialCommands
                  .filter(c => c.category === category)
                  .map((cmd) => (
                    <Grid item xs={12} sm={6} md={4} key={cmd.command}>
                      <Paper
                        sx={{
                          p: 1.5,
                          borderRadius: 2,
                          border: `1px solid ${alpha("#10b981", 0.1)}`,
                          bgcolor: alpha("#10b981", 0.02),
                        }}
                      >
                        <Typography
                          variant="subtitle2"
                          sx={{ fontWeight: 700, fontFamily: "monospace", color: "#10b981" }}
                        >
                          {cmd.command}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
                          {cmd.description}
                        </Typography>
                        <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#6b7280", display: "block" }}>
                          {cmd.example}
                        </Typography>
                        {cmd.flags && (
                          <Typography variant="caption" sx={{ color: "#9ca3af", display: "block", mt: 0.5, fontSize: "0.65rem" }}>
                            {cmd.flags}
                          </Typography>
                        )}
                      </Paper>
                    </Grid>
                  ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        ))}

        {/* File Permissions Section */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            PERMISSIONS
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="permissions" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🔐 File Permissions
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Understanding the Linux permission system (rwx)
        </Typography>
        
        {/* Beginner-friendly permissions explanation */}
        <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>🎓 Understanding Permissions: The Basics</AlertTitle>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            Linux permissions answer three questions: <strong>WHO</strong> can do <strong>WHAT</strong> to this file?
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>WHO (three categories):</strong><br/>
            • <strong>Owner (u)</strong> - the user who created the file<br/>
            • <strong>Group (g)</strong> - users in the file's group<br/>
            • <strong>Others (o)</strong> - everyone else
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>WHAT (three actions):</strong><br/>
            • <strong>r (read) = 4</strong> - view contents<br/>
            • <strong>w (write) = 2</strong> - modify contents<br/>
            • <strong>x (execute) = 1</strong> - run as program (or enter directory)
          </Typography>
          <Typography variant="body2">
            <strong>Example:</strong> <code>-rwxr-xr--</code> breaks down as: <code>rwx</code> (owner can read+write+execute), 
            <code>r-x</code> (group can read+execute), <code>r--</code> (others can only read).<br/>
            As numbers: 7 (4+2+1), 5 (4+0+1), 4 (4+0+0) = <strong>754</strong>
          </Typography>
        </Alert>

        <Grid container spacing={3} sx={{ mb: 4 }}>
          {/* Basic Permissions */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2.5, borderRadius: 4, border: `1px solid ${alpha("#8b5cf6", 0.15)}`, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                Basic Permissions (rwx)
              </Typography>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Symbol</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Value</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Files</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Directories</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {permissionsReference.map((perm) => (
                    <TableRow key={perm.symbol}>
                      <TableCell>
                        <Typography sx={{ fontFamily: "monospace", fontWeight: 700, color: "#8b5cf6" }}>
                          {perm.symbol} = {perm.numeric}
                        </Typography>
                      </TableCell>
                      <TableCell>{perm.meaning}</TableCell>
                      <TableCell>{perm.fileEffect}</TableCell>
                      <TableCell>{perm.dirEffect}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Paper>
          </Grid>

          {/* Special Permissions */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2.5, borderRadius: 4, border: `1px solid ${alpha("#ef4444", 0.15)}`, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                Special Permission Bits
              </Typography>
              {specialPermissions.map((perm) => (
                <Box key={perm.name} sx={{ mb: 2 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444" }}>
                      {perm.name}
                    </Typography>
                    <Chip label={perm.numeric} size="small" sx={{ fontFamily: "monospace", fontSize: "0.65rem" }} />
                    <Chip label={perm.symbol} size="small" variant="outlined" sx={{ fontFamily: "monospace", fontSize: "0.65rem" }} />
                  </Box>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{perm.description}</Typography>
                  <Typography variant="caption" color="text.secondary">Example: {perm.example}</Typography>
                  <Typography variant="caption" sx={{ display: "block", color: "#f59e0b" }}>
                    ⚠️ {perm.risk}
                  </Typography>
                </Box>
              ))}
            </Paper>
          </Grid>
        </Grid>

        {/* Permission Examples */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Common Permission Examples
        </Typography>
        <Grid container spacing={1.5} sx={{ mb: 5 }}>
          {permissionExamples.map((perm) => (
            <Grid item xs={12} sm={6} md={4} key={perm.numeric}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 3,
                  border: `1px solid ${alpha(perm.numeric === "777" ? "#ef4444" : "#8b5cf6", 0.2)}`,
                  bgcolor: perm.numeric === "777" ? alpha("#ef4444", 0.05) : "transparent",
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                  <Typography sx={{ fontFamily: "monospace", fontWeight: 800, color: "#8b5cf6", fontSize: "1.1rem" }}>
                    {perm.numeric}
                  </Typography>
                  <Typography sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "text.secondary" }}>
                    {perm.symbolic}
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ mb: 0.5 }}>{perm.description}</Typography>
                <Typography variant="caption" sx={{ color: perm.numeric === "777" ? "#ef4444" : "#6b7280" }}>
                  {perm.useCase}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Log Files Section */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            LOGGING & MONITORING
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="logs" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          📋 Log Files
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Important log files for monitoring and forensics
        </Typography>
        
        <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>🔍 For Beginners: Why Logs Matter</AlertTitle>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            Logs are like a journal that Linux keeps about everything happening on your system. When something goes wrong, 
            logs help you figure out <strong>what happened</strong> and <strong>when</strong>. For security, they're crucial 
            for detecting intrusions and understanding attacks.
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Essential log commands:</strong><br/>
            • <code>tail -f /var/log/syslog</code> - watch logs in real-time (like a live feed)<br/>
            • <code>grep "error" /var/log/syslog</code> - search for specific words<br/>
            • <code>journalctl -xe</code> - view systemd logs with explanations<br/>
            • <code>journalctl -u nginx</code> - logs for a specific service
          </Typography>
          <Typography variant="body2">
            <strong>Pro tip:</strong> Most logs are in <code>/var/log/</code>. On modern systems using systemd, 
            use <code>journalctl</code> instead of reading files directly - it has powerful filtering!
          </Typography>
        </Alert>

        <TableContainer
          component={Paper}
          sx={{
            mb: 4,
            borderRadius: 4,
            border: `1px solid ${alpha("#ef4444", 0.15)}`,
          }}
        >
          <Table size="small">
            <TableHead>
              <TableRow
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#ef4444", 0.1)} 0%, ${alpha("#dc2626", 0.1)} 100%)`,
                }}
              >
                <TableCell sx={{ fontWeight: 700 }}>Log File</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Service</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {logFiles.map((log, index) => (
                <TableRow
                  key={log.path}
                  sx={{
                    bgcolor: index % 2 === 0 ? "transparent" : alpha("#ef4444", 0.02),
                  }}
                >
                  <TableCell>
                    <Typography
                      variant="body2"
                      sx={{ fontFamily: "monospace", fontWeight: 600, color: "#ef4444", fontSize: "0.75rem" }}
                    >
                      {log.path}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{log.description}</Typography>
                  </TableCell>
                  <TableCell>
                    <Chip label={log.service} size="small" sx={{ fontSize: "0.65rem" }} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Security Events to Monitor */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          🔍 Security Events to Monitor
        </Typography>
        <Grid container spacing={1.5} sx={{ mb: 5 }}>
          {securityEvents.map((event) => (
            <Grid item xs={12} sm={6} md={4} key={event.event}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 3,
                  border: `1px solid ${alpha(
                    event.severity === "High" ? "#ef4444" : event.severity === "Medium" ? "#f59e0b" : "#10b981",
                    0.2
                  )}`,
                }}
              >
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                    {event.event}
                  </Typography>
                  <Chip
                    label={event.severity}
                    size="small"
                    sx={{
                      bgcolor: alpha(
                        event.severity === "High" ? "#ef4444" : event.severity === "Medium" ? "#f59e0b" : "#10b981",
                        0.1
                      ),
                      color: event.severity === "High" ? "#ef4444" : event.severity === "Medium" ? "#f59e0b" : "#10b981",
                      fontSize: "0.6rem",
                      fontWeight: 700,
                    }}
                  />
                </Box>
                <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", color: "#6b7280", mb: 0.5 }}>
                  {event.logFile}
                </Typography>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#9ca3af", fontSize: "0.65rem" }}>
                  {event.pattern}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* systemd Commands */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            SERVICES
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="systemd" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          ⚙️ systemd & Service Management
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Commands for managing services with systemd
        </Typography>
        
        <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>💡 For Beginners: What is systemd?</AlertTitle>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>systemd</strong> is the "manager" that starts all your services (web servers, databases, SSH, etc.) when Linux boots. 
            It's like a supervisor that starts, stops, and monitors background programs. Almost all modern Linux distros use it.
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>The 5 commands you'll use most:</strong><br/>
            • <code>systemctl status nginx</code> - Is nginx running? Any errors?<br/>
            • <code>systemctl start nginx</code> - Start the nginx service<br/>
            • <code>systemctl stop nginx</code> - Stop the nginx service<br/>
            • <code>systemctl restart nginx</code> - Restart (reload config changes)<br/>
            • <code>systemctl enable nginx</code> - Start automatically at boot
          </Typography>
          <Typography variant="body2">
            Replace "nginx" with any service: sshd, apache2, mysql, docker, etc. Use <code>systemctl list-units --type=service</code> to see all services.
          </Typography>
        </Alert>

        <Grid container spacing={1.5} sx={{ mb: 5 }}>
          {systemdCommands.map((cmd) => (
            <Grid item xs={12} sm={6} md={4} key={cmd.command}>
              <Paper
                sx={{
                  p: 1.5,
                  borderRadius: 2,
                  border: `1px solid ${alpha("#06b6d4", 0.15)}`,
                  transition: "all 0.2s ease",
                  "&:hover": { borderColor: "#06b6d4" },
                }}
              >
                <Typography
                  variant="body2"
                  sx={{ fontFamily: "monospace", fontWeight: 600, color: "#06b6d4", fontSize: "0.8rem" }}
                >
                  {cmd.command}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {cmd.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Security Tools */}
        <Typography id="security-tools" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🛡️ Security Tools
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Essential Linux security tools
        </Typography>
        
        <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>🎯 Security Tools: Learning Path</AlertTitle>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Start with the basics before diving into security tools:</strong> Know how to navigate, read files, understand 
            permissions, and manage processes. Security tools are powerful, but understanding Linux fundamentals makes you more effective.
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Key tools to learn first:</strong><br/>
            • <code>ufw</code> - Simple firewall management (Ubuntu) - <code>ufw enable</code>, <code>ufw allow 22/tcp</code><br/>
            • <code>fail2ban</code> - Automatically blocks IPs that try to break in<br/>
            • <code>netstat/ss</code> - See what's connected to your system<br/>
            • <code>nmap</code> - Scan networks to find open ports (ethical use only!)
          </Typography>
          <Typography variant="body2">
            <strong>Important:</strong> Only use security/hacking tools on systems you own or have explicit permission to test. 
            Unauthorized scanning or penetration testing is illegal.
          </Typography>
        </Alert>

        {Array.from(new Set(securityTools.map(t => t.category))).map((category) => (
          <Box key={category} sx={{ mb: 3 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1.5, color: "#8b5cf6" }}>
              {category}
            </Typography>
            <Grid container spacing={1.5}>
              {securityTools
                .filter(t => t.category === category)
                .map((tool) => (
                  <Grid item xs={12} sm={6} md={4} key={tool.name}>
                    <Paper
                      sx={{
                        p: 2,
                        borderRadius: 3,
                        border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
                        height: "100%",
                      }}
                    >
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6" }}>
                        {tool.name}
                      </Typography>
                      <Typography variant="body2" sx={{ fontSize: "0.8rem", mb: 0.5 }}>
                        {tool.description}
                      </Typography>
                      <Typography
                        variant="caption"
                        sx={{ fontFamily: "monospace", color: "#6b7280", fontSize: "0.7rem" }}
                      >
                        {tool.example}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
            </Grid>
          </Box>
        ))}

        {/* Cron Section */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            SCHEDULING
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="cron" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          ⏰ Cron Scheduling
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Automating tasks with cron jobs
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2.5, borderRadius: 4, border: `1px solid ${alpha("#f59e0b", 0.15)}`, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                Cron Format
              </Typography>
              <Box sx={{ fontFamily: "monospace", mb: 2, p: 1.5, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
                <Typography sx={{ fontSize: "0.85rem" }}>
                  * &nbsp;&nbsp;&nbsp;&nbsp; * &nbsp;&nbsp;&nbsp;&nbsp; * &nbsp;&nbsp;&nbsp;&nbsp; * &nbsp;&nbsp;&nbsp;&nbsp; * &nbsp;&nbsp;&nbsp;&nbsp; command
                </Typography>
                <Typography sx={{ fontSize: "0.7rem", color: "text.secondary" }}>
                  min &nbsp; hour &nbsp; day &nbsp; month &nbsp; dow
                </Typography>
              </Box>
              <Table size="small">
                <TableBody>
                  {cronFormat.map((field) => (
                    <TableRow key={field.field}>
                      <TableCell sx={{ fontWeight: 600, py: 0.5 }}>{field.field}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", py: 0.5 }}>{field.range}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", py: 0.5, color: "text.secondary" }}>{field.example}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2.5, borderRadius: 4, border: `1px solid ${alpha("#f59e0b", 0.15)}`, height: "100%" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                Common Examples
              </Typography>
              {cronExamples.map((ex) => (
                <Box key={ex.schedule} sx={{ display: "flex", gap: 2, mb: 1.5, alignItems: "center" }}>
                  <Typography
                    sx={{
                      fontFamily: "monospace",
                      bgcolor: alpha("#f59e0b", 0.1),
                      px: 1,
                      py: 0.25,
                      borderRadius: 1,
                      fontSize: "0.75rem",
                      minWidth: 120,
                    }}
                  >
                    {ex.schedule}
                  </Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>
                    {ex.description}
                  </Typography>
                </Box>
              ))}
            </Paper>
          </Grid>
        </Grid>

        {/* Environment Variables */}
        <Typography id="environment" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🔧 Environment Variables
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Important environment variables in Linux
        </Typography>
        
        <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
          <Typography variant="body2">
            <strong>For Beginners:</strong> Environment variables are like "settings" that programs can read. For example, 
            <code>$PATH</code> tells Linux where to look for programs when you type a command. <code>$HOME</code> stores your 
            home directory path. To see any variable, type <code>echo $VARIABLE_NAME</code>. To set one, use 
            <code>export NAME="value"</code>. These are essential for configuring how Linux and your programs behave.
          </Typography>
        </Alert>

        <Grid container spacing={1.5} sx={{ mb: 5 }}>
          {environmentVariables.map((env) => (
            <Grid item xs={12} sm={6} md={4} key={env.variable}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 3,
                  border: `1px solid ${alpha("#06b6d4", 0.15)}`,
                }}
              >
                <Typography
                  sx={{ fontFamily: "monospace", fontWeight: 700, color: "#06b6d4", mb: 0.5 }}
                >
                  ${env.variable}
                </Typography>
                <Typography variant="body2" sx={{ fontSize: "0.8rem", mb: 0.5 }}>
                  {env.description}
                </Typography>
                <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#6b7280" }}>
                  {env.example}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Keyboard Shortcuts */}
        <Typography id="shortcuts" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          ⌨️ Keyboard Shortcuts
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Essential keyboard shortcuts for the terminal
        </Typography>

        <Grid container spacing={1.5} sx={{ mb: 5 }}>
          {keyboardShortcuts.map((shortcut) => (
            <Grid item xs={12} sm={6} md={4} key={shortcut.shortcut}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 3,
                  border: `1px solid ${alpha("#10b981", 0.15)}`,
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 2,
                }}
              >
                <Chip
                  label={shortcut.shortcut}
                  sx={{
                    fontFamily: "monospace",
                    fontWeight: 700,
                    bgcolor: alpha("#10b981", 0.1),
                    color: "#10b981",
                    minWidth: 80,
                  }}
                />
                <Box>
                  <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>
                    {shortcut.action}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {shortcut.context}
                  </Typography>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ========== SHELL SCRIPTING SECTION ========== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            SHELL SCRIPTING
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="scripting" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          📜 Shell Scripting Basics
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Learn to automate tasks with Bash shell scripts - essential for system administration and DevOps
        </Typography>
        
        {/* Beginner-friendly shell scripting explanation */}
        <Alert severity="success" sx={{ mb: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>🚀 Shell Scripting: Why & How to Start</AlertTitle>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>What is a shell script?</strong> It's just a text file containing a list of commands that run one after another. 
            Instead of typing 20 commands manually every day, put them in a script and run it with one command!
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Your first script in 3 steps:</strong><br/>
            1. Create a file: <code>nano myfirst.sh</code><br/>
            2. Add <code>#!/bin/bash</code> as the first line (this tells Linux to use Bash)<br/>
            3. Add your commands below, then save, make executable (<code>chmod +x myfirst.sh</code>), and run (<code>./myfirst.sh</code>)
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Example script:</strong><br/>
            <code>#!/bin/bash</code><br/>
            <code>echo "Starting backup..."</code><br/>
            <code>cp -r /home/user/documents /backup/</code><br/>
            <code>echo "Backup complete!"</code>
          </Typography>
          <Typography variant="body2">
            <strong>Pro tip:</strong> Start simple! Variables (<code>NAME="John"</code>), conditionals (<code>if [ -f file.txt ]; then</code>), 
            and loops (<code>for file in *.txt; do</code>) come naturally as you automate more tasks.
          </Typography>
        </Alert>

        {/* Script Basics */}
        <Accordion
          defaultExpanded
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#f59e0b", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <CodeIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                Script Fundamentals
              </Typography>
              <Chip label={`${shellScriptBasics.length} concepts`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700, width: "15%" }}>Concept</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "20%" }}>Syntax</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "30%" }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "35%" }}>Example</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {shellScriptBasics.map((item) => (
                    <TableRow key={item.concept}>
                      <TableCell sx={{ fontSize: "0.8rem", fontWeight: 600 }}>{item.concept}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#f59e0b" }}>{item.syntax}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{item.description}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "text.secondary" }}>{item.example}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Conditionals */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#ef4444", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#ef4444", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <AccountTreeIcon sx={{ color: "#ef4444" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>
                Conditionals (if/case)
              </Typography>
              <Chip label={`${shellConditionals.length} types`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ef4444", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700, width: "20%" }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "35%" }}>Syntax</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "45%" }}>Example</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {shellConditionals.map((item) => (
                    <TableRow key={item.type}>
                      <TableCell sx={{ fontSize: "0.8rem", fontWeight: 600 }}>{item.type}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#ef4444" }}>{item.syntax}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "text.secondary" }}>{item.example}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Loops */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#06b6d4", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <LoopIcon sx={{ color: "#06b6d4" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>
                Loops (for/while/until)
              </Typography>
              <Chip label={`${shellLoops.length} types`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700, width: "20%" }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "35%" }}>Syntax</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "45%" }}>Example</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {shellLoops.map((item) => (
                    <TableRow key={item.type}>
                      <TableCell sx={{ fontSize: "0.8rem", fontWeight: 600 }}>{item.type}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#06b6d4" }}>{item.syntax}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "text.secondary" }}>{item.example}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Functions */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <FunctionsIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>
                Functions
              </Typography>
              <Chip label={`${shellFunctions.length} concepts`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700, width: "20%" }}>Concept</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "35%" }}>Syntax</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "45%" }}>Example</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {shellFunctions.map((item) => (
                    <TableRow key={item.concept}>
                      <TableCell sx={{ fontSize: "0.8rem", fontWeight: 600 }}>{item.concept}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#8b5cf6" }}>{item.syntax}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "text.secondary" }}>{item.example}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Common Patterns */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#22c55e", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#22c55e", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <PatternIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>
                Common Patterns & Best Practices
              </Typography>
              <Chip label={`${shellPatterns.length} patterns`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {shellPatterns.map((item) => (
                <Grid item xs={12} md={6} key={item.pattern}>
                  <Paper
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      border: `1px solid ${alpha("#22c55e", 0.15)}`,
                      height: "100%",
                    }}
                  >
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e" }}>
                        {item.pattern}
                      </Typography>
                      <Chip label={item.useCase} size="small" sx={{ fontSize: "0.6rem", bgcolor: alpha("#22c55e", 0.1) }} />
                    </Box>
                    <Typography
                      variant="body2"
                      sx={{
                        fontFamily: "monospace",
                        fontSize: "0.7rem",
                        bgcolor: alpha("#000", 0.05),
                        p: 1.5,
                        borderRadius: 1,
                        whiteSpace: "pre-wrap",
                        color: "text.secondary",
                      }}
                    >
                      {item.code.replace(/\\n/g, '\n')}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Debugging */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#f97316", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#f97316", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <BugReportIcon sx={{ color: "#f97316" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f97316" }}>
                Debugging Techniques
              </Typography>
              <Chip label={`${shellDebugging.length} techniques`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#f97316", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700, width: "15%" }}>Technique</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "40%" }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: "45%" }}>Usage</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {shellDebugging.map((item) => (
                    <TableRow key={item.technique}>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem", fontWeight: 600, color: "#f97316" }}>{item.technique}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem" }}>{item.description}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "text.secondary" }}>{item.usage}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Script Template */}
        <Accordion
          sx={{
            mb: 5,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#ec4899", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#ec4899", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <DescriptionIcon sx={{ color: "#ec4899" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ec4899" }}>
                Complete Script Template
              </Typography>
              <Chip label="Copy & Use" size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha("#ec4899", 0.1) }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
              A production-ready script template with error handling, argument parsing, logging, and cleanup:
            </Typography>
            <Paper
              sx={{
                p: 2,
                bgcolor: alpha("#000", 0.05),
                borderRadius: 2,
                overflow: "auto",
                maxHeight: 500,
              }}
            >
              <Typography
                component="pre"
                sx={{
                  fontFamily: "monospace",
                  fontSize: "0.75rem",
                  whiteSpace: "pre-wrap",
                  color: "text.primary",
                  m: 0,
                }}
              >
                {scriptTemplate}
              </Typography>
            </Paper>
          </AccordionDetails>
        </Accordion>

        {/* ========== TEXT EDITORS SECTION ========== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            TEXT EDITORS
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="editors" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          ✏️ Text Editors (Vim & Nano)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Master the essential terminal text editors - Vim for power and Nano for simplicity
        </Typography>
        
        <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>💡 Choosing Your Editor: Nano vs Vim</AlertTitle>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Start with Nano</strong> if you're a beginner. It's simple and shows commands at the bottom of the screen 
            (^ means Ctrl, so ^O means Ctrl+O to save). Type <code>nano filename</code> to start.
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Learn Vim later</strong> for power and speed. Vim is everywhere (even on minimal servers), and once mastered, 
            you'll edit text incredibly fast. The learning curve is steep but worthwhile.
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Vim Survival Guide (to start):</strong><br/>
            • Press <code>i</code> to enter Insert mode (now you can type)<br/>
            • Press <code>Esc</code> to return to Normal mode<br/>
            • Type <code>:w</code> to save, <code>:q</code> to quit, <code>:wq</code> to save and quit<br/>
            • Type <code>:q!</code> to quit without saving (the ! forces it)
          </Typography>
          <Typography variant="body2">
            <strong>Pro tip:</strong> Run <code>vimtutor</code> in your terminal for an interactive 30-minute Vim tutorial!
          </Typography>
        </Alert>

        {/* Editor Comparison */}
        <Paper
          sx={{
            p: 3,
            mb: 3,
            borderRadius: 3,
            border: `1px solid ${alpha("#6366f1", 0.15)}`,
            background: `linear-gradient(135deg, ${alpha("#6366f1", 0.05)} 0%, transparent 100%)`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            📊 Vim vs Nano Comparison
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Feature</TableCell>
                  <TableCell sx={{ fontWeight: 700, color: "#22c55e" }}>Vim</TableCell>
                  <TableCell sx={{ fontWeight: 700, color: "#3b82f6" }}>Nano</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {editorComparison.map((item) => (
                  <TableRow key={item.feature}>
                    <TableCell sx={{ fontWeight: 600, fontSize: "0.85rem" }}>{item.feature}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem" }}>{item.vim}</TableCell>
                    <TableCell sx={{ fontSize: "0.8rem" }}>{item.nano}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* Vim Section */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
          🟢 Vim (Vi IMproved)
        </Typography>

        {/* Vim Modes */}
        <Paper
          sx={{
            p: 3,
            mb: 3,
            borderRadius: 3,
            border: `1px solid ${alpha("#22c55e", 0.15)}`,
          }}
        >
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
            Vim Modes - The Key Concept
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Vim uses different modes for different tasks. Always know what mode you're in!
          </Typography>
          <Grid container spacing={2}>
            {vimBasics.modes.map((mode) => (
              <Grid item xs={12} sm={6} md={3} key={mode.mode}>
                <Paper
                  sx={{
                    p: 2,
                    borderRadius: 2,
                    border: `2px solid ${mode.color}`,
                    textAlign: "center",
                  }}
                >
                  <Typography variant="h6" sx={{ fontWeight: 800, color: mode.color }}>
                    {mode.mode}
                  </Typography>
                  <Chip
                    label={mode.key}
                    sx={{
                      fontFamily: "monospace",
                      fontWeight: 700,
                      my: 1,
                      bgcolor: alpha(mode.color, 0.1),
                      color: mode.color,
                    }}
                  />
                  <Typography variant="body2" sx={{ fontSize: "0.75rem", color: "text.secondary" }}>
                    {mode.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Vim Navigation */}
        <Accordion
          defaultExpanded
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#22c55e", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#22c55e", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <NavigationIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>
                Vim Navigation
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={1}>
              {vimBasics.navigation.map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.key}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 1 }}>
                    <Chip
                      label={item.key}
                      size="small"
                      sx={{ fontFamily: "monospace", fontWeight: 700, minWidth: 70, bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }}
                    />
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{item.action}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Vim Editing */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#22c55e", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#22c55e", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <EditIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>
                Vim Editing Commands
              </Typography>
              <Chip label={`${vimBasics.editing.length} commands`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={1}>
              {vimBasics.editing.map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.key}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 1 }}>
                    <Chip
                      label={item.key}
                      size="small"
                      sx={{ fontFamily: "monospace", fontWeight: 700, minWidth: 50, bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }}
                    />
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{item.action}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Vim Search */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#22c55e", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#22c55e", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SearchIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>
                Vim Search & Replace
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={1}>
              {vimBasics.search.map((item) => (
                <Grid item xs={12} sm={6} key={item.key}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 1 }}>
                    <Chip
                      label={item.key}
                      size="small"
                      sx={{ fontFamily: "monospace", fontWeight: 700, minWidth: 120, bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }}
                    />
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{item.action}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Vim File Operations */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#22c55e", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#22c55e", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SaveIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>
                Vim File Operations
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={1}>
              {vimBasics.fileOps.map((item) => (
                <Grid item xs={12} sm={6} key={item.key}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 1 }}>
                    <Chip
                      label={item.key}
                      size="small"
                      sx={{ fontFamily: "monospace", fontWeight: 700, minWidth: 100, bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }}
                    />
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{item.action}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Vim Visual Mode */}
        <Accordion
          sx={{
            mb: 4,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#22c55e", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#22c55e", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SelectAllIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>
                Vim Visual Mode (Selection)
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={1}>
              {vimBasics.visual.map((item) => (
                <Grid item xs={12} sm={6} key={item.key}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 1 }}>
                    <Chip
                      label={item.key}
                      size="small"
                      sx={{ fontFamily: "monospace", fontWeight: 700, minWidth: 100, bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }}
                    />
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{item.action}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Nano Section */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
          🔵 Nano (Simple & Friendly)
        </Typography>

        <Paper
          sx={{
            p: 3,
            mb: 3,
            borderRadius: 3,
            border: `1px solid ${alpha("#3b82f6", 0.15)}`,
            background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.05)} 0%, transparent 100%)`,
          }}
        >
          <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
            {nanoBasics.description}
          </Typography>
          <Grid container spacing={1}>
            {nanoBasics.shortcuts.map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.key}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 1 }}>
                  <Chip
                    label={item.key}
                    size="small"
                    sx={{ fontFamily: "monospace", fontWeight: 700, minWidth: 70, bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }}
                  />
                  <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{item.action}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
          <Divider sx={{ my: 2 }} />
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
            📝 Nano Configuration
          </Typography>
          <Typography
            variant="body2"
            sx={{
              fontFamily: "monospace",
              fontSize: "0.75rem",
              bgcolor: alpha("#000", 0.05),
              p: 1.5,
              borderRadius: 1,
              color: "text.secondary",
            }}
          >
            {nanoBasics.config}
          </Typography>
        </Paper>

        {/* ========== EXPANDED HISTORY SECTION ========== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            LINUX HERITAGE
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="pioneers" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🏛️ Linux Pioneers & Philosophy
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The people, ideas, and architecture behind Linux/Unix
        </Typography>

        {/* Pioneers */}
        <Accordion
          defaultExpanded
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#a855f7", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#a855f7", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <PersonIcon sx={{ color: "#a855f7" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#a855f7" }}>
                Key Pioneers
              </Typography>
              <Chip label={`${linuxPioneers.length} people`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#a855f7", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Name</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Contribution</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Organization</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Years Active</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {linuxPioneers.map((person) => (
                    <TableRow key={person.name}>
                      <TableCell sx={{ fontWeight: 600, fontSize: "0.85rem", color: "#a855f7" }}>{person.name}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{person.contribution}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{person.org}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem" }}>{person.years}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Unix Philosophy */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#0ea5e9", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#0ea5e9", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <MenuBookIcon sx={{ color: "#0ea5e9" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#0ea5e9" }}>
                Unix Philosophy
              </Typography>
              <Chip label={`${unixPhilosophy.length} principles`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {unixPhilosophy.map((item) => (
                <Grid item xs={12} md={6} key={item.principle}>
                  <Paper
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      border: `1px solid ${alpha("#0ea5e9", 0.15)}`,
                      height: "100%",
                    }}
                  >
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>
                      {item.principle}
                    </Typography>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem", mb: 1 }}>
                      {item.description}
                    </Typography>
                    <Typography
                      variant="body2"
                      sx={{
                        fontFamily: "monospace",
                        fontSize: "0.7rem",
                        bgcolor: alpha("#000", 0.05),
                        p: 1,
                        borderRadius: 1,
                        color: "text.secondary",
                      }}
                    >
                      {item.example}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Kernel Architecture */}
        <Accordion
          sx={{
            mb: 5,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#eab308", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#eab308", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <MemoryIcon sx={{ color: "#eab308" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#eab308" }}>
                Linux Kernel Architecture
              </Typography>
              <Chip label={`${kernelArchitecture.length} components`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#eab308", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Component</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Subsystem</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Source Path</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {kernelArchitecture.map((item) => (
                    <TableRow key={item.component}>
                      <TableCell sx={{ fontWeight: 600, fontSize: "0.85rem", color: "#eab308" }}>{item.component}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{item.description}</TableCell>
                      <TableCell>
                        <Chip label={item.subsystem} size="small" sx={{ fontSize: "0.6rem" }} />
                      </TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "text.secondary" }}>{item.file}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* ========== LINUX ADMINISTRATION SECTION ========== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            SYSTEM ADMINISTRATION
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="administration" variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🔧 Linux Administration
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Essential system administration tasks for managing Linux servers
        </Typography>
        
        <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
          <AlertTitle sx={{ fontWeight: 700 }}>⚠️ Important: Use sudo Carefully</AlertTitle>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            Most admin tasks require root (superuser) privileges. On Ubuntu/Debian, prefix commands with <code>sudo</code>. 
            On RHEL, you might log in as root directly. Either way, these commands can seriously damage your system if used incorrectly!
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Golden rules for beginners:</strong><br/>
            • Always know what a command does before running it with sudo<br/>
            • Test commands on non-critical systems first (use a VM!)<br/>
            • Make backups before changing configurations<br/>
            • Read error messages carefully - they often tell you exactly what's wrong
          </Typography>
          <Typography variant="body2">
            <strong>Common admin tasks you'll do often:</strong> Adding users, installing software, managing services 
            (starting/stopping), checking disk space (<code>df -h</code>), and monitoring system resources (<code>htop</code>).
          </Typography>
        </Alert>

        {/* User Administration */}
        <Accordion
          defaultExpanded
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#3b82f6", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <PersonIcon sx={{ color: "#3b82f6" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>
                User Administration
              </Typography>
              <Chip label={`${userAdminTasks.length} tasks`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Task</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {userAdminTasks.map((item) => (
                    <TableRow key={item.task}>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{item.task}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#3b82f6" }}>{item.command}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{item.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Group Administration */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <AdminPanelSettingsIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>
                Group Administration
              </Typography>
              <Chip label={`${groupAdminTasks.length} tasks`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Task</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {groupAdminTasks.map((item) => (
                    <TableRow key={item.task}>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{item.task}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#8b5cf6" }}>{item.command}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{item.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Disk & Storage Administration */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#10b981", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#10b981", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <StorageIcon sx={{ color: "#10b981" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#10b981" }}>
                Disk & Storage Administration
              </Typography>
              <Chip label={`${diskAdminTasks.length} tasks`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#10b981", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Task</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {diskAdminTasks.map((item) => (
                    <TableRow key={item.task}>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{item.task}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#10b981" }}>{item.command}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{item.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Network Administration */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#f97316", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#f97316", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <NetworkCheckIcon sx={{ color: "#f97316" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f97316" }}>
                Network Administration
              </Typography>
              <Chip label={`${networkAdminTasks.length} tasks`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#f97316", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Task</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {networkAdminTasks.map((item) => (
                    <TableRow key={item.task}>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{item.task}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#f97316" }}>{item.command}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{item.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Service Administration */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#ef4444", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#ef4444", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SettingsIcon sx={{ color: "#ef4444" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>
                Service Administration
              </Typography>
              <Chip label={`${serviceAdminTasks.length} tasks`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer sx={{ mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ef4444", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Task</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {serviceAdminTasks.map((item) => (
                    <TableRow key={item.task}>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{item.task}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#ef4444" }}>{item.command}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{item.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            
            {/* Systemd Unit File Template */}
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              📄 Systemd Unit File Template
            </Typography>
            <Paper sx={{ p: 2, bgcolor: alpha("#000", 0.03), borderRadius: 2, mb: 1 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", whiteSpace: "pre-wrap", m: 0 }}>
                {unitFileTemplate}
              </Typography>
            </Paper>
            <Typography variant="caption" color="text.secondary">
              Save as /etc/systemd/system/myservice.service, then run: systemctl daemon-reload && systemctl enable --now myservice
            </Typography>
          </AccordionDetails>
        </Accordion>

        {/* Performance Tuning */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#06b6d4", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SpeedIcon sx={{ color: "#06b6d4" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>
                Performance Tuning
              </Typography>
              <Chip label={`${performanceTuning.length} tasks`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            {["CPU", "Memory", "I/O", "Network", "Kernel"].map((category) => (
              <Box key={category} sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>
                  {category}
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableBody>
                      {performanceTuning.filter(t => t.category === category).map((item) => (
                        <TableRow key={item.task}>
                          <TableCell sx={{ fontSize: "0.8rem", width: "30%" }}>{item.task}</TableCell>
                          <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#06b6d4" }}>{item.command}</TableCell>
                          <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{item.notes}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Box>
            ))}
          </AccordionDetails>
        </Accordion>

        {/* Backup & Recovery */}
        <Accordion
          sx={{
            mb: 2,
            borderRadius: "12px !important",
            border: `1px solid ${alpha("#22c55e", 0.15)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#22c55e", 0.08)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <HistoryIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>
                Backup & Recovery
              </Typography>
              <Chip label={`${backupTasks.length} tasks`} size="small" sx={{ fontSize: "0.65rem" }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#22c55e", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Task</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {backupTasks.map((item) => (
                    <TableRow key={item.task}>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{item.task}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#22c55e" }}>{item.command}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{item.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Security Hardening */}
        <Accordion
          sx={{
            mb: 5,
            borderRadius: "12px !important",
            border: `2px solid ${alpha("#dc2626", 0.2)}`,
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{ background: `linear-gradient(135deg, ${alpha("#dc2626", 0.1)} 0%, transparent 100%)` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SecurityIcon sx={{ color: "#dc2626" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#dc2626" }}>
                Security Hardening Checklist
              </Typography>
              <Chip label={`${securityHardening.length} items`} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha("#dc2626", 0.1), color: "#dc2626" }} />
              <Chip label="IMPORTANT" size="small" sx={{ fontSize: "0.65rem", bgcolor: "#dc2626", color: "white", fontWeight: 700 }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>⚠️ Test in a non-production environment first!</strong> These settings can lock you out if misconfigured.
                Always have console/out-of-band access before changing SSH settings.
              </Typography>
            </Alert>
            {["SSH", "Firewall", "Users", "Filesystem", "Kernel", "Logging", "Updates"].map((category) => {
              const categoryItems = securityHardening.filter(h => h.category === category);
              if (categoryItems.length === 0) return null;
              return (
                <Box key={category} sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#dc2626" }}>
                    {category}
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha("#dc2626", 0.05) }}>
                          <TableCell sx={{ fontWeight: 700, width: "5%" }}>Priority</TableCell>
                          <TableCell sx={{ fontWeight: 700, width: "25%" }}>Task</TableCell>
                          <TableCell sx={{ fontWeight: 700, width: "25%" }}>File/Location</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Setting</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {categoryItems.map((item) => (
                          <TableRow key={item.task}>
                            <TableCell>
                              <Chip
                                label={item.priority}
                                size="small"
                                sx={{
                                  fontSize: "0.65rem",
                                  fontWeight: 700,
                                  bgcolor: item.priority === "Critical" ? "#dc2626" : item.priority === "High" ? "#f97316" : item.priority === "Medium" ? "#eab308" : "#6b7280",
                                  color: "white",
                                }}
                              />
                            </TableCell>
                            <TableCell sx={{ fontSize: "0.8rem" }}>{item.task}</TableCell>
                            <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#dc2626" }}>{item.file}</TableCell>
                            <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", whiteSpace: "pre-wrap" }}>{item.setting}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              );
            })}
          </AccordionDetails>
        </Accordion>

        {/* Pro Tips */}
        <Paper
          sx={{
            p: 3,
            mb: 5,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.05)} 0%, ${alpha("#f59e0b", 0.02)} 100%)`,
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography
            variant="h6"
            sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}
          >
            <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
            Pro Tips
          </Typography>
          <Grid container spacing={2}>
            {[
              "Use Tab for auto-completion of commands and file paths",
              "Press Ctrl+R to reverse search command history",
              "Use 'man command' to read the manual for any command",
              "Pipe commands together with | for powerful one-liners",
              "Use 'sudo !!' to repeat the last command with sudo",
              "Create aliases in ~/.bashrc for frequently used commands",
              "Use 'screen' or 'tmux' for persistent terminal sessions",
              "Check /var/log/auth.log for SSH and sudo activity",
              "Use 'find / -perm -4000' to find SUID files",
              "Monitor with 'htop', 'iotop', 'nethogs' for performance",
              "Use 'lsof -i' to see network connections by process",
              "Check cron jobs in /etc/cron.* and user crontabs",
            ].map((tip, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 18, color: "#f59e0b", mt: 0.3 }} />
                  <Typography variant="body2">{tip}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Security Checklist Alert */}
        <Alert
          severity="warning"
          icon={<SecurityIcon />}
          sx={{
            mb: 5,
            borderRadius: 4,
            "& .MuiAlert-icon": { color: "#f59e0b" },
          }}
        >
          <AlertTitle sx={{ fontWeight: 700 }}>Linux Security Checklist</AlertTitle>
          <Grid container spacing={1}>
            {[
              "Keep system and packages updated (apt update && apt upgrade)",
              "Use strong passwords and SSH keys instead of password auth",
              "Configure firewall (ufw, firewalld, or iptables)",
              "Disable root SSH login (PermitRootLogin no)",
              "Remove unnecessary services and packages",
              "Set proper file permissions (especially on /etc/shadow, SSH keys)",
              "Enable and review audit logs",
              "Use fail2ban to prevent brute force attacks",
            ].map((item, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Typography variant="body2" sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, mt: 0.3 }} />
                  {item}
                </Typography>
              </Grid>
            ))}
          </Grid>
        </Alert>

        {/* Related Learning */}
        <Paper
          sx={{
            p: 3,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, transparent 100%)`,
            border: `1px solid ${alpha(theme.palette.primary.main, 0.15)}`,
          }}
        >
          <Typography
            variant="h6"
            sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}
          >
            <SchoolIcon sx={{ color: theme.palette.primary.main }} />
            Continue Learning
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip
              label="Windows Fundamentals →"
              clickable
              onClick={() => navigate("/learn/windows-basics")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="Privilege Escalation →"
              clickable
              onClick={() => navigate("/learn/privilege-escalation")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="Docker Forensics →"
              clickable
              onClick={() => navigate("/learn/docker-forensics")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="Network Protocols →"
              clickable
              onClick={() => navigate("/learn/network-protocol-exploitation")}
              sx={{ fontWeight: 600 }}
            />
          </Box>
        </Paper>

            {/* Quiz Section */}
            <Box id="quiz" sx={{ mt: 5 }}>
              <QuizSection
                questions={quizPool}
                accentColor={ACCENT_COLOR}
                title="Linux Fundamentals Knowledge Check"
                description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
                questionsPerQuiz={QUIZ_QUESTION_COUNT}
              />
            </Box>
          </Grid>
        </Grid>
      </Container>
    </LearnPageLayout>
  );
}
