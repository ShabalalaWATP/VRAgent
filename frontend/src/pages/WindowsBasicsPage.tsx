import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Button,
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
  Card,
  CardContent,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import DesktopWindowsIcon from "@mui/icons-material/DesktopWindows";
import FolderIcon from "@mui/icons-material/Folder";
import SettingsIcon from "@mui/icons-material/Settings";
import PersonIcon from "@mui/icons-material/Person";
import TerminalIcon from "@mui/icons-material/Terminal";
import StorageIcon from "@mui/icons-material/Storage";
import SecurityIcon from "@mui/icons-material/Security";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import SchoolIcon from "@mui/icons-material/School";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import BuildIcon from "@mui/icons-material/Build";
import MemoryIcon from "@mui/icons-material/Memory";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import HistoryIcon from "@mui/icons-material/History";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import SpeedIcon from "@mui/icons-material/Speed";
import BugReportIcon from "@mui/icons-material/BugReport";
import KeyIcon from "@mui/icons-material/Key";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import LayersIcon from "@mui/icons-material/Layers";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import ShieldIcon from "@mui/icons-material/Shield";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import PolicyIcon from "@mui/icons-material/Policy";
import DnsIcon from "@mui/icons-material/Dns";
import RouterIcon from "@mui/icons-material/Router";
import GppGoodIcon from "@mui/icons-material/GppGood";
import FindInPageIcon from "@mui/icons-material/FindInPage";
import LockIcon from "@mui/icons-material/Lock";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import UpdateIcon from "@mui/icons-material/Update";
import DataObjectIcon from "@mui/icons-material/DataObject";
import RestoreIcon from "@mui/icons-material/Restore";
import CloudIcon from "@mui/icons-material/Cloud";
import ScheduleIcon from "@mui/icons-material/Schedule";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";

// ============================================================================
// CORE WINDOWS CONCEPTS - With Detailed Beginner-Friendly Explanations
// ============================================================================

const windowsConcepts = [
  {
    title: "File System (NTFS)",
    icon: <FolderIcon />,
    color: "#f59e0b",
    shortDescription: "How Windows organizes and stores your files on disk",

    // DETAILED BEGINNER EXPLANATION
    beginnerExplanation: `Think of NTFS (New Technology File System) like a massive, incredibly organized filing cabinet. When you save a document, photo, or program on your computer, NTFS decides exactly where on your hard drive to put it, keeps track of its location, and makes sure you can find it again later.

But NTFS does much more than just store files. Imagine each file in your filing cabinet has a security guard who checks IDs before letting anyone open it - that's what NTFS permissions do. They control who can read, write, or even see each file.

NTFS also keeps a detailed journal (like a ship's captain's log) of every change made to files. If your computer crashes mid-save, this journal helps Windows figure out what happened and recover your data. This is called "journaling" and it's why modern Windows systems rarely lose data during power outages.`,

    technicalDescription: `NTFS is the primary file system for modern Windows installations, replacing the older FAT32 system. It uses a Master File Table (MFT) - essentially a database that stores metadata about every file and folder on the volume. Each file has an MFT entry containing its name, timestamps, security descriptor (permissions), and pointers to its actual data on disk.

For small files (typically under 900 bytes), the file data itself is stored directly in the MFT entry, making access extremely fast. Larger files have their data stored in "extents" (contiguous blocks) elsewhere on disk, with the MFT entry containing pointers to these locations.

NTFS implements Access Control Lists (ACLs) that define granular permissions for each object. Unlike simple Unix permissions (owner/group/other), Windows ACLs can specify permissions for any number of users or groups, with inheritance rules that flow down through folder hierarchies.`,

    keyPoints: [
      "Drive letters (C:, D:, E:) identify different storage volumes - unlike Linux which mounts everything under one root",
      "Backslash (\\) separates folder names in paths: C:\\Users\\John\\Documents",
      "File names are case-insensitive (FILE.txt = file.TXT) but Windows preserves the case you type",
      "Access Control Lists (ACLs) provide granular permission control for each file and folder",
      "Alternate Data Streams (ADS) allow hidden data to be attached to files - used legitimately but also by malware",
      "File attributes (Hidden, System, Read-only, Archive) provide additional metadata",
      "Master File Table (MFT) stores all file metadata in a database-like structure",
      "Journaling ensures filesystem consistency even after crashes or power failures",
      "Supports native file compression, encryption (EFS), and disk quotas",
    ],

    securityNote: "NTFS permissions and ACLs are the first line of defense for file security. Misconfigured permissions are a common vulnerability. Alternate Data Streams can hide malware payloads - a technique called 'ADS hiding'. Always check for ADS when investigating suspicious files using 'dir /r' or PowerShell's Get-Item -Stream.",

    realWorldExample: `When you right-click a file and go to Properties > Security, you're viewing and editing the NTFS ACL. Try this: create a folder, right-click it, go to Security tab, and click "Advanced". You'll see entries like "Users - Read & Execute" or "Administrators - Full Control". Each line is an Access Control Entry (ACE), and together they form the Access Control List (ACL).`,

    commonMistakes: [
      "Assuming 'Everyone' group doesn't include anonymous users (it does on older systems)",
      "Forgetting that Deny permissions override Allow permissions",
      "Not understanding permission inheritance from parent folders",
      "Ignoring Alternate Data Streams during security investigations",
    ],
  },
  {
    title: "Windows Registry",
    icon: <StorageIcon />,
    color: "#8b5cf6",
    shortDescription: "The central database storing all Windows and application settings",

    beginnerExplanation: `The Windows Registry is like the brain of your computer - it remembers everything. Every setting you change, every program you install, every preference you configure gets recorded here. When Windows starts up, it reads the Registry to figure out what programs should run, what your desktop should look like, and how everything should behave.

Imagine a massive spreadsheet with millions of rows. Each row has a name (like "Wallpaper") and a value (like "C:\\Pictures\\beach.jpg"). Programs read and write to this spreadsheet constantly. When you change your desktop background, Windows writes the new path to the Registry. When you restart your computer, Windows reads that path from the Registry and displays your wallpaper.

The Registry is organized into five main sections called "hives" - think of them as different filing cabinets for different purposes:
- HKEY_LOCAL_MACHINE (HKLM): Computer-wide settings that apply to everyone
- HKEY_CURRENT_USER (HKCU): Your personal settings and preferences
- HKEY_USERS (HKU): Settings for all user accounts on the computer
- HKEY_CLASSES_ROOT (HKCR): File associations (what program opens .docx files?)
- HKEY_CURRENT_CONFIG (HKCC): Current hardware profile information`,

    technicalDescription: `The Registry is a hierarchical database implemented as a collection of binary files called "hives". Each hive is a tree structure containing keys (similar to folders) and values (name-data pairs). Values can be several data types: REG_SZ (string), REG_DWORD (32-bit number), REG_QWORD (64-bit number), REG_BINARY (raw binary data), REG_MULTI_SZ (array of strings), and REG_EXPAND_SZ (string with environment variable references).

The Registry is memory-mapped for performance - frequently accessed portions are kept in RAM. Changes are written to disk either immediately or when the system flushes its cache. Critical hives (SYSTEM, SAM, SECURITY, SOFTWARE) are stored in C:\\Windows\\System32\\config, while user hives (NTUSER.DAT) reside in each user's profile folder.

Registry virtualization was introduced in Windows Vista for backwards compatibility. When legacy 32-bit applications try to write to protected areas like HKLM\\SOFTWARE, Windows silently redirects them to a virtualized location under the user's profile, preventing system-wide changes while maintaining application functionality.`,

    keyPoints: [
      "HKEY_LOCAL_MACHINE (HKLM) - System-wide settings affecting all users",
      "HKEY_CURRENT_USER (HKCU) - Settings for the currently logged-in user only",
      "HKEY_CLASSES_ROOT (HKCR) - File type associations and COM class registrations",
      "HKEY_USERS (HKU) - Contains HKCU for each user profile on the system",
      "HKEY_CURRENT_CONFIG (HKCC) - Current hardware configuration profile",
      "Keys are like folders; Values are the actual settings (name + data pairs)",
      "Data types: REG_SZ (string), REG_DWORD (32-bit integer), REG_BINARY (raw bytes)",
      "regedit.exe provides a GUI; reg.exe provides command-line access",
      "Changes take effect immediately for most settings; some require restart",
    ],

    securityNote: "The Registry is ground zero for malware persistence. Attackers add entries to Run/RunOnce keys to survive reboots, modify shell handlers to hijack program execution, or alter service configurations to run malicious code as SYSTEM. The SAM hive contains password hashes - extracting and cracking these is a primary privilege escalation technique.",

    realWorldExample: `Open Registry Editor (Win+R, type 'regedit') and navigate to HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run. Any entries here are programs that automatically start when YOU log in. Each value name is a description, and the data is the path to the program. Malware often adds itself here. Compare this to HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run which affects ALL users.`,

    commonMistakes: [
      "Editing the Registry without backing it up first (use File > Export)",
      "Deleting keys without understanding their purpose",
      "Confusing HKLM (all users) with HKCU (current user only)",
      "Forgetting that some changes require a restart or re-login",
      "Not checking both 32-bit and 64-bit Registry locations on 64-bit Windows",
    ],
  },
  {
    title: "Windows Services",
    icon: <SettingsIcon />,
    color: "#10b981",
    shortDescription: "Background programs that run automatically to provide system functionality",

    beginnerExplanation: `Windows Services are like the staff that keep a hotel running smoothly - they work in the background, often invisibly, handling essential tasks so everything functions properly. You don't see them, but without them, nothing would work.

When you turn on your computer, dozens of services spring into action before you even see the login screen. The "Windows Update" service checks for patches. The "Print Spooler" service waits to handle print jobs. The "DHCP Client" service gets your network address. The "Windows Defender" service scans for malware. All running silently in the background.

Each service has a "startup type" that determines when it runs:
- Automatic: Starts when Windows boots (essential services)
- Automatic (Delayed): Starts after boot completes (less critical services)
- Manual: Only starts when another program or user requests it
- Disabled: Never runs unless you change this setting

Services run under special accounts with different privilege levels:
- LocalSystem: The most powerful account - full access to everything
- LocalService: Limited privileges, designed for services that don't need network access
- NetworkService: Limited privileges with ability to authenticate to network resources`,

    technicalDescription: `Services are managed by the Service Control Manager (SCM), a core Windows component that starts during boot. Each service is defined by a registry entry under HKLM\\SYSTEM\\CurrentControlSet\\Services containing its binary path, startup type, dependencies, and the account it runs under.

Services run in Session 0, isolated from user sessions (Session 1+) for security. This "Session 0 Isolation" prevents services from interacting directly with user desktops, mitigating certain attack vectors. Interactive services are deprecated and should not be used.

The SCM handles service dependencies - if Service A depends on Service B, the SCM ensures B starts first. Services can be grouped for parallel startup to improve boot times. Failed services can be configured with recovery actions: restart the service, run a program, or reboot the computer.

Service accounts have specific access tokens. LocalSystem has full local administrator privileges plus network computer account credentials. NetworkService has limited local privileges but can authenticate to network resources using the computer's identity. LocalService has the same limited local privileges but no network credentials.`,

    keyPoints: [
      "services.msc - The graphical Service Management Console",
      "sc.exe - Command-line tool for service control (query, start, stop, config)",
      "Service accounts: LocalSystem (highest privilege), LocalService, NetworkService",
      "Startup types: Automatic, Automatic (Delayed Start), Manual, Disabled",
      "Services run in Session 0, isolated from user interactive sessions",
      "Service dependencies ensure proper startup order",
      "Recovery options can restart failed services automatically",
      "Get-Service and Set-Service PowerShell cmdlets for scripted management",
      "Each service has a unique name (e.g., 'wuauserv' for Windows Update)",
    ],

    securityNote: "Services running as LocalSystem are high-value targets for attackers. Misconfigured service permissions can lead to privilege escalation - if a low-privileged user can modify a service binary or its configuration, they can gain SYSTEM access. Always audit services with 'sc qc <servicename>' to check configuration. Unquoted service paths are a classic vulnerability.",

    realWorldExample: `Press Win+R, type 'services.msc' and press Enter. Find "Windows Update" (wuauserv). Right-click it and select Properties. You'll see its Display Name, Description, startup type, and the account it runs under (look at "Log On" tab). Now open an admin Command Prompt and run 'sc qc wuauserv' to see the same information from the command line.`,

    commonMistakes: [
      "Disabling services without understanding dependencies",
      "Running custom services as LocalSystem when lower privileges would suffice",
      "Not specifying a service account for third-party services",
      "Forgetting that service changes may require a system restart",
      "Using unquoted paths for service binaries (creates hijacking vulnerability)",
    ],
  },
  {
    title: "Users & Permissions",
    icon: <PersonIcon />,
    color: "#3b82f6",
    shortDescription: "How Windows controls who can do what on the system",

    beginnerExplanation: `Windows uses a sophisticated system to control who can access what. Think of it like a building with key cards - different people have access to different rooms, and some people can do more things in those rooms than others.

Every person (or program) that does something on Windows has an identity. This identity carries a list of permissions and group memberships, kind of like a badge that says "Hi, I'm John, and I'm allowed in rooms A, B, and C, and I'm a member of the IT Department."

There are several built-in accounts you should know about:
- Administrator: The all-powerful account that can do anything
- SYSTEM: Even more powerful than Administrator - it's the account Windows itself uses
- Guest: A very limited account for temporary access (usually disabled)
- Your personal account: Created when you set up the computer

Groups make permission management easier. Instead of saying "John can access this folder, and Jane can access this folder, and Bob can access this folder," you can say "Everyone in the Accounting group can access this folder" and just add people to the Accounting group.

User Account Control (UAC) is the system that asks "Do you want to allow this program to make changes?" It's Windows protecting you from accidentally (or maliciously) running something that could harm your system. Even if you're an administrator, you run with standard user privileges until you explicitly approve elevated access.`,

    technicalDescription: `Windows security is built on Security Identifiers (SIDs) - unique identifiers for security principals (users, groups, computers). A SID looks like S-1-5-21-3623811015-3361044348-30300820-1013, where the final number (RID) is unique per domain. Well-known SIDs like S-1-5-18 (SYSTEM) and S-1-5-32-544 (Administrators group) are consistent across all Windows installations.

When a user logs in, Windows creates an access token containing their SID, group SIDs, privileges, and integrity level. Every process inherits its creator's token (with possible modifications). When accessing an object, the Security Reference Monitor compares the token's SIDs against the object's security descriptor (ACL) to determine access rights.

Privileges are separate from permissions - they grant system-wide capabilities like SeDebugPrivilege (debug any process), SeBackupPrivilege (bypass ACLs for backup), or SeImpersonatePrivilege (impersonate another user's token). These are powerful and should be carefully controlled.

UAC implements a split-token model for administrative users. At login, two tokens are created: a filtered token with admin privileges removed (used normally) and a full admin token (used after elevation). The Secure Desktop (dimmed background during UAC prompts) prevents other applications from tampering with the consent dialog.`,

    keyPoints: [
      "Built-in accounts: Administrator, SYSTEM (most powerful), Guest, DefaultAccount",
      "Built-in groups: Administrators, Users, Backup Operators, Remote Desktop Users",
      "Security Identifiers (SIDs) uniquely identify every user and group",
      "Access tokens carry the user's security context to every process they run",
      "User Account Control (UAC) prompts for consent before elevated operations",
      "Privileges grant system-wide capabilities (SeDebugPrivilege, SeBackupPrivilege)",
      "Local accounts exist only on one machine; Domain accounts work across the network",
      "SAM database (C:\\Windows\\System32\\config\\SAM) stores local account information",
      "Password hashes use NTLM format - MD4-based, no salt, vulnerable to attacks",
    ],

    securityNote: "Principle of least privilege is paramount - users and services should have only the permissions they need. The SYSTEM account should be avoided for services that don't require it. Credential Guard on modern Windows uses virtualization to protect NTLM hashes from theft. LAPS (Local Administrator Password Solution) provides unique local admin passwords per machine. Beware of 'token impersonation' attacks where services can assume user identities.",

    realWorldExample: `Open an elevated Command Prompt (right-click, Run as administrator). Run 'whoami /all' to see your complete security context: your SID, all group memberships, and all privileges with their current state (enabled/disabled). Compare this to running the same command in a non-elevated prompt - notice how many fewer privileges you have.`,

    commonMistakes: [
      "Using the built-in Administrator account for daily tasks",
      "Granting more permissions than necessary 'just to make it work'",
      "Adding users directly to the Administrators group instead of delegating specific rights",
      "Disabling UAC (it's annoying but provides real security)",
      "Assuming 'Admin rights' means unlimited access (SYSTEM is more powerful)",
    ],
  },
  {
    title: "Command Line Interfaces",
    icon: <TerminalIcon />,
    color: "#ef4444",
    shortDescription: "Text-based tools for controlling Windows: CMD and PowerShell",

    beginnerExplanation: `Before Windows had pretty buttons and icons, people controlled computers by typing commands. These command-line interfaces are still incredibly powerful - in fact, most professional IT work and all serious security work requires command-line proficiency.

Windows has two main command-line environments:

**CMD (Command Prompt)**: The old-school command line, descended from MS-DOS. It's simple, fast, and works the same way it has for 30+ years. When you need to do something quick like ping a server or check your IP address, CMD is often the fastest option. Commands are simple: 'dir' lists files, 'cd' changes directory, 'copy' copies files.

**PowerShell**: The modern, powerful command line. Instead of just running commands, PowerShell works with objects. When you run 'Get-Process', you don't just get text - you get actual process objects that you can filter, sort, and manipulate. It's like the difference between getting a list of names on paper versus getting a spreadsheet where you can sort, filter, and calculate.

**Windows Terminal**: A new app that provides a modern interface for both CMD and PowerShell (and Linux shells if you have WSL). It supports tabs, split panes, and lots of customization.

Environment variables are like shortcuts that hold important information. Instead of typing 'C:\\Users\\John' every time, you can use '%USERPROFILE%'. Windows and programs use these constantly - the %PATH% variable tells Windows where to look for programs when you type a command.`,

    technicalDescription: `CMD.exe is a command interpreter that processes batch files and built-in commands. It has limited capabilities - no native object handling, limited string manipulation, and relies on parsing text output. However, it has near-universal compatibility and minimal overhead.

PowerShell is built on .NET and processes objects through a pipeline. When you run 'Get-Process | Where-Object CPU -gt 100 | Stop-Process', actual Process objects flow through the pipeline - not text. This enables powerful filtering and manipulation without parsing. PowerShell also supports .NET methods, COM objects, WMI, and CIM for deep system access.

Execution policies control PowerShell script execution: Restricted (no scripts), AllSigned (only signed scripts), RemoteSigned (downloaded scripts must be signed), Unrestricted (all scripts run). These aren't security boundaries - they prevent accidental execution, not determined attackers.

PowerShell logging capabilities include Script Block Logging (logs all code execution), Module Logging (logs pipeline execution), and Transcription (logs all I/O). These are critical for security monitoring and forensics. AMSI (Antimalware Scan Interface) allows security software to scan PowerShell commands before execution.`,

    keyPoints: [
      "CMD.exe - Traditional command prompt, simple but limited, runs .bat/.cmd scripts",
      "PowerShell - Modern object-oriented shell, runs .ps1 scripts, built on .NET",
      "Windows Terminal - New unified terminal supporting CMD, PowerShell, WSL, and more",
      "Environment variables: %PATH%, %USERPROFILE%, %TEMP%, %SYSTEMROOT%",
      "Running as Administrator grants elevated privileges to command-line sessions",
      "Execution policies control PowerShell script execution (not a security boundary)",
      "PowerShell remoting enables remote management via WinRM on port 5985/5986",
      "WSL (Windows Subsystem for Linux) provides Linux command-line tools on Windows",
    ],

    securityNote: "PowerShell is extremely powerful for both defenders and attackers - it's a 'living off the land' binary (LOLBIN) present on every Windows system. Enable PowerShell logging (Script Block, Module, Transcription) and monitor for suspicious commands. Constrained Language Mode limits PowerShell capabilities for untrusted code. AMSI integration allows antimalware to scan PowerShell commands.",

    realWorldExample: `Open PowerShell and try: 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, CPU, Id'. This gets all processes, sorts by CPU usage descending, and shows the top 5. Compare to CMD where you'd run 'tasklist' and manually find the information. Now try 'Get-Process chrome | Stop-Process' to kill all Chrome processes - the object pipeline makes this trivial.`,

    commonMistakes: [
      "Running commands in a non-elevated prompt when admin rights are needed",
      "Forgetting that PowerShell execution policy isn't a security feature",
      "Not using quotes around paths with spaces: cd \"C:\\Program Files\"",
      "Confusing CMD syntax (dir, copy) with PowerShell (Get-ChildItem, Copy-Item)",
      "Not understanding that PowerShell commands are case-insensitive",
    ],
  },
  {
    title: "Processes & Memory",
    icon: <MemoryIcon />,
    color: "#06b6d4",
    shortDescription: "How Windows runs programs and manages system memory",

    beginnerExplanation: `When you double-click an application, Windows creates a "process" - a running instance of that program. Each process is like a worker in a factory: it has its own workspace (memory), its own instructions (the program code), and its own thread of work.

A process can have multiple "threads" - think of these as multiple workers doing different tasks for the same project. Your web browser, for example, might have one thread handling what you see, another downloading images, and another running JavaScript.

Windows gives each process its own "virtual memory" - an illusion that the process has the entire computer's memory to itself. In reality, Windows is a master juggler, constantly moving data between physical RAM and the hard drive (the "page file") to make this illusion work. This is why adding RAM makes your computer faster - less juggling required.

Process IDs (PIDs) are unique numbers that identify each running process. When something goes wrong and you need to kill a hung program, you find it by name or PID in Task Manager and end it. The Parent Process ID (PPID) tells you which process started another - useful for understanding how processes relate and for spotting suspicious activity.

The most important processes running on your computer are:
- System (PID 4): The Windows kernel itself
- smss.exe: Session Manager - sets up the Windows environment
- csrss.exe: Client Server Runtime - handles Windows subsystem
- lsass.exe: Local Security Authority - handles logins and credentials
- services.exe: Starts and manages all Windows services
- explorer.exe: Your desktop and Start menu`,

    technicalDescription: `Windows processes exist in a tree hierarchy. The System process (PID 4) is the kernel's user-mode representation. smss.exe (Session Manager) is started by the kernel during boot and spawns csrss.exe and wininit.exe for Session 0, then csrss.exe and winlogon.exe for Session 1 (first interactive session).

Each process has a virtual address space - typically 2GB for 32-bit processes (4GB with LAA) or 8TB for 64-bit processes. The Memory Manager handles virtual-to-physical translation using page tables. Pages can be in physical RAM, paged to disk, or marked invalid (access causes an exception).

Security is enforced at the process level through access tokens. Each process runs under a security context determined by its token. Threads within a process can impersonate different identities for specific operations but inherit the process's base security context.

Memory protection mechanisms include DEP (Data Execution Prevention) preventing code execution in data regions, ASLR (Address Space Layout Randomization) randomizing memory addresses, and CFG (Control Flow Guard) validating indirect calls. Process isolation prevents one process from reading another's memory without special privileges (SeDebugPrivilege).`,

    keyPoints: [
      "Process = running instance of a program with its own memory and security context",
      "Thread = unit of execution within a process; processes can have multiple threads",
      "Virtual memory gives each process an isolated address space",
      "Process ID (PID) uniquely identifies running processes; Parent PID (PPID) shows creator",
      "Kernel mode (Ring 0) vs User mode (Ring 3) - different privilege levels",
      "Task Manager shows processes; Process Explorer provides advanced details",
      "Critical processes: System, smss.exe, csrss.exe, lsass.exe, services.exe, svchost.exe",
      "Memory protections: DEP (no-execute data), ASLR (random addresses), CFG (flow integrity)",
    ],

    securityNote: "Process injection (inserting code into another process) and process hollowing (replacing a legitimate process's code) are common attack techniques. Monitor parent-child process relationships for anomalies - lsass.exe should only be spawned by wininit.exe, for example. SeDebugPrivilege allows reading any process's memory - attackers use this for credential theft. Watch for processes with unusual parents, strange network connections, or high CPU without user activity.",

    realWorldExample: `Open Task Manager, go to Details tab, and add the columns "PID" and "Parent PID". Find explorer.exe - its parent should be userinit.exe (or sometimes itself after explorer restarts). Now find lsass.exe - its parent should be wininit.exe. If you ever see lsass.exe with a different parent, that's a red flag for process hollowing. Download Process Explorer from Sysinternals for even more detail.`,

    commonMistakes: [
      "Assuming high memory usage is always bad (modern apps use RAM for caching)",
      "Killing system processes without understanding consequences",
      "Not recognizing that multiple svchost.exe instances are normal",
      "Thinking a single high-CPU process is malware (could be legitimate)",
      "Ignoring parent-child relationships when investigating suspicious processes",
    ],
  },
];

// ============================================================================
// WINDOWS ARCHITECTURE - Kernel and User Mode Components
// ============================================================================

const windowsArchitecture = [
  {
    layer: "User Mode Applications",
    description: "Regular programs you run - browsers, Office, games",
    components: ["Win32 Applications", "UWP Apps", ".NET Applications", "Console Applications"],
    beginnerNote: "This is where YOUR programs run. They can't directly touch hardware - they have to ask Windows nicely.",
    securityRelevance: "Malware runs here too. Limited damage potential due to privilege separation.",
    ring: "Ring 3",
  },
  {
    layer: "Subsystem DLLs",
    description: "Windows API libraries that applications call",
    components: ["kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "ws2_32.dll"],
    beginnerNote: "These are like translators. Your program says 'open file' and kernel32.dll translates that into something Windows understands.",
    securityRelevance: "DLL hijacking attacks target these. If malware can replace a DLL, it runs when legitimate programs load it.",
    ring: "Ring 3",
  },
  {
    layer: "NTDLL.DLL",
    description: "The gateway between user mode and kernel mode",
    components: ["Native API functions", "System call stubs", "Runtime library"],
    beginnerNote: "NTDLL is the last stop before entering the kernel. Every Windows API call eventually passes through here.",
    securityRelevance: "Security products hook NTDLL to monitor API calls. Malware tries to bypass these hooks by calling the kernel directly.",
    ring: "Ring 3 (but interfaces with Ring 0)",
  },
  {
    layer: "Executive Services",
    description: "Core Windows kernel services",
    components: ["I/O Manager", "Object Manager", "Process Manager", "Memory Manager", "Security Reference Monitor", "Cache Manager"],
    beginnerNote: "These are the managers that actually run Windows. They handle files, memory, security, and everything else.",
    securityRelevance: "Vulnerabilities here (kernel exploits) give attackers complete system control.",
    ring: "Ring 0",
  },
  {
    layer: "Kernel & HAL",
    description: "Windows kernel and Hardware Abstraction Layer",
    components: ["ntoskrnl.exe (Windows Kernel)", "hal.dll (Hardware Abstraction Layer)", "Device Drivers"],
    beginnerNote: "The kernel is the heart of Windows. HAL is like a universal translator between Windows and different hardware.",
    securityRelevance: "Kernel rootkits operate here, virtually undetectable by normal means. Drivers are common attack targets.",
    ring: "Ring 0",
  },
];

// ============================================================================
// IMPORTANT WINDOWS DIRECTORIES
// ============================================================================

const importantDirectories = [
  {
    path: "C:\\",
    description: "Root of the system drive",
    purpose: "System",
    beginnerNote: "The top level of your main hard drive. Everything on Windows starts here.",
    securityRelevance: "Check for suspicious files at root level - legitimate software rarely puts files directly here.",
  },
  {
    path: "C:\\Windows",
    description: "Core Windows operating system files",
    purpose: "System",
    beginnerNote: "The Windows folder contains everything Windows needs to run. Don't delete things here!",
    securityRelevance: "Malware often hides here to blend in. Check for misspelled system files (svchost vs svch0st).",
  },
  {
    path: "C:\\Windows\\System32",
    description: "64-bit system executables and DLLs (despite the name)",
    purpose: "System",
    beginnerNote: "Despite being called 'System32', on 64-bit Windows this contains 64-bit programs. Historical naming.",
    securityRelevance: "Most critical system files live here. Malware loves to impersonate files in this directory.",
  },
  {
    path: "C:\\Windows\\SysWOW64",
    description: "32-bit system files on 64-bit Windows",
    purpose: "System",
    beginnerNote: "WOW64 = Windows 32-bit on Windows 64-bit. This folder runs old 32-bit programs on modern Windows.",
    securityRelevance: "Some malware targets 32-bit subsystem specifically for compatibility with older exploits.",
  },
  {
    path: "C:\\Windows\\Temp",
    description: "System temporary files",
    purpose: "Temporary",
    beginnerNote: "Windows and programs drop temporary files here. Safe to clean periodically.",
    securityRelevance: "Common malware staging location. Check for executables here - they shouldn't normally exist.",
  },
  {
    path: "C:\\Windows\\Prefetch",
    description: "Application launch optimization data",
    purpose: "Performance",
    beginnerNote: "Windows remembers which programs you run and pre-loads them for faster startup.",
    securityRelevance: "Forensic goldmine! Shows what programs ran and when. Attackers sometimes clear this.",
  },
  {
    path: "C:\\Users",
    description: "User profile directories",
    purpose: "User Data",
    beginnerNote: "Each person who uses this computer has a folder here with their documents, desktop, and settings.",
    securityRelevance: "Check for unexpected user profiles. Attackers may create hidden admin accounts.",
  },
  {
    path: "C:\\Users\\<username>\\AppData",
    description: "Per-user application data (often hidden)",
    purpose: "User Data",
    beginnerNote: "Programs store your personal settings and data here. It's hidden by default.",
    securityRelevance: "Malware persistence hotspot. Contains Local, LocalLow, and Roaming subdirectories.",
  },
  {
    path: "C:\\Users\\<username>\\AppData\\Local\\Temp",
    description: "User temporary files",
    purpose: "Temporary",
    beginnerNote: "Your personal temp folder. Downloads and program temp files go here.",
    securityRelevance: "Very common malware execution location. Many attacks drop payloads here first.",
  },
  {
    path: "C:\\Users\\<username>\\AppData\\Roaming",
    description: "User data that follows you across computers (in domain environments)",
    purpose: "User Data",
    beginnerNote: "In corporate environments, this folder can follow you when you log into different computers.",
    securityRelevance: "Startup folder and many persistence locations are here. Check for suspicious entries.",
  },
  {
    path: "C:\\Program Files",
    description: "64-bit installed applications",
    purpose: "Applications",
    beginnerNote: "When you install a 64-bit program, it usually goes here.",
    securityRelevance: "Should only contain legitimate software. Requires admin rights to modify.",
  },
  {
    path: "C:\\Program Files (x86)",
    description: "32-bit installed applications on 64-bit Windows",
    purpose: "Applications",
    beginnerNote: "Older 32-bit programs install here on 64-bit Windows.",
    securityRelevance: "Same as Program Files - check for unexpected software.",
  },
  {
    path: "C:\\ProgramData",
    description: "Shared application data for all users (hidden)",
    purpose: "Application Data",
    beginnerNote: "Programs store data here that needs to be shared between all users on the computer.",
    securityRelevance: "Hidden folder - malware uses it for persistence. Many legitimate programs store data here too.",
  },
  {
    path: "C:\\Windows\\System32\\config",
    description: "Registry hive files",
    purpose: "System",
    beginnerNote: "The actual files that make up the Windows Registry live here.",
    securityRelevance: "Contains SAM (passwords), SECURITY, SYSTEM, SOFTWARE hives. High-value forensic target.",
  },
  {
    path: "C:\\Windows\\System32\\winevt\\Logs",
    description: "Windows Event Log files",
    purpose: "Logs",
    beginnerNote: "All Windows event logs are stored here as .evtx files.",
    securityRelevance: "Critical for incident response. Attackers often try to clear these logs.",
  },
];

// ============================================================================
// SECURITY-CRITICAL REGISTRY KEYS
// ============================================================================

const registryKeys = [
  {
    key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    description: "Programs that run at startup for ALL users",
    beginnerNote: "Anything listed here runs automatically when Windows starts, for every user. Great for legitimate software, loved by malware.",
    securityRelevance: "Primary malware persistence location. Check this first when hunting for persistence.",
    dataType: "REG_SZ (string paths to executables)",
  },
  {
    key: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    description: "Programs that run at startup for the CURRENT user only",
    beginnerNote: "Same as HKLM\\...\\Run, but only for your user account. Easier to modify (no admin needed).",
    securityRelevance: "User-level persistence. Malware often uses this when it lacks admin rights.",
    dataType: "REG_SZ",
  },
  {
    key: "HKLM\\SYSTEM\\CurrentControlSet\\Services",
    description: "Windows services configuration",
    beginnerNote: "Every Windows service is defined here - its name, executable path, startup type, and account.",
    securityRelevance: "Malicious services provide stealthy persistence. Check for services with suspicious paths or descriptions.",
    dataType: "Multiple subkeys and values",
  },
  {
    key: "HKLM\\SAM\\SAM",
    description: "Security Account Manager - local user accounts and password hashes",
    beginnerNote: "This is where Windows stores local account information. Heavily protected - even admins can't read it normally.",
    securityRelevance: "Contains NTLM password hashes. Attackers dump this for offline cracking. Protected by SYSTEM permissions.",
    dataType: "Binary (encrypted)",
  },
  {
    key: "HKLM\\SECURITY",
    description: "Security policy database",
    beginnerNote: "Stores local security policies, LSA secrets, and cached domain credentials.",
    securityRelevance: "LSA secrets can contain service account passwords in plaintext. High-value target.",
    dataType: "Binary",
  },
  {
    key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    description: "Windows logon configuration",
    beginnerNote: "Controls what happens when you log in - like the shell (explorer.exe) and logon scripts.",
    securityRelevance: "Shell and Userinit values are persistence locations. Should point to explorer.exe and userinit.exe.",
    dataType: "REG_SZ",
  },
  {
    key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
    description: "Group Policy settings stored in Registry",
    beginnerNote: "Many Group Policy settings ultimately get written here. Controls what users can and can't do.",
    securityRelevance: "Attackers may modify policies to disable security features or enable remote access.",
    dataType: "Various",
  },
  {
    key: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
    description: "Recent Run dialog commands",
    beginnerNote: "When you press Win+R and type a command, it's remembered here.",
    securityRelevance: "Forensic artifact - shows what commands a user has run. Useful for investigation.",
    dataType: "REG_SZ",
  },
  {
    key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
    description: "Application paths for execution without full path",
    beginnerNote: "This is why you can type 'notepad' instead of 'C:\\Windows\\System32\\notepad.exe'.",
    securityRelevance: "Can be abused for DLL search order hijacking or to redirect legitimate commands to malware.",
    dataType: "REG_SZ",
  },
  {
    key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
    description: "DLLs that Windows loads from System32 only",
    beginnerNote: "These DLLs are 'known' to Windows and always loaded from a secure location to prevent hijacking.",
    securityRelevance: "Adding DLLs here protects against DLL hijacking. Check for suspicious additions.",
    dataType: "REG_SZ",
  },
];

// ============================================================================
// ESSENTIAL CMD COMMANDS
// ============================================================================

const essentialCommands = [
  // File System Commands
  { command: "dir", category: "File System", description: "List directory contents", example: "dir /a /s C:\\Users", flags: "/a (all files), /s (subdirs), /b (bare), /o (order)", beginnerNote: "Like 'ls' in Linux. Shows files and folders." },
  { command: "cd", category: "File System", description: "Change directory", example: "cd C:\\Users\\Public", flags: "/d (change drive too)", beginnerNote: "Navigate between folders. Use 'cd ..' to go up one level." },
  { command: "copy", category: "File System", description: "Copy files", example: "copy file.txt D:\\Backup\\", flags: "/y (overwrite), /v (verify)", beginnerNote: "Copies files. For folders, use xcopy or robocopy." },
  { command: "move", category: "File System", description: "Move files or rename", example: "move old.txt new.txt", flags: "/y (overwrite)", beginnerNote: "Moves or renames files and folders." },
  { command: "del", category: "File System", description: "Delete files", example: "del /f /q temp.txt", flags: "/f (force), /q (quiet), /s (subdirs)", beginnerNote: "Deletes files permanently - no Recycle Bin!" },
  { command: "mkdir", category: "File System", description: "Create directory", example: "mkdir C:\\NewFolder", flags: "None", beginnerNote: "Creates a new folder. Can create nested folders in one command." },
  { command: "rmdir", category: "File System", description: "Remove directory", example: "rmdir /s /q C:\\OldFolder", flags: "/s (recursive), /q (quiet)", beginnerNote: "Deletes folders. /s removes contents too." },
  { command: "xcopy", category: "File System", description: "Extended copy with more options", example: "xcopy C:\\Source D:\\Dest /e /h", flags: "/e (empty dirs), /h (hidden), /s (subdirs)", beginnerNote: "More powerful than copy. Good for backup scripts." },
  { command: "robocopy", category: "File System", description: "Robust file copy (best for large transfers)", example: "robocopy C:\\Source D:\\Dest /mir", flags: "/mir (mirror), /mt (multithread), /z (restartable)", beginnerNote: "The best file copy tool. Handles network issues and large files." },
  { command: "attrib", category: "File System", description: "View or change file attributes", example: "attrib +h +s secret.txt", flags: "+/- r (readonly), h (hidden), s (system), a (archive)", beginnerNote: "Make files hidden or read-only. Malware often hides files this way." },

  // System Information
  { command: "systeminfo", category: "System Info", description: "Detailed system information", example: "systeminfo | findstr /i \"OS\"", flags: "/s (remote), /u (user), /p (password)", beginnerNote: "Shows everything about your system - OS version, RAM, network, hotfixes." },
  { command: "hostname", category: "System Info", description: "Display computer name", example: "hostname", flags: "None", beginnerNote: "Shows this computer's network name." },
  { command: "whoami", category: "System Info", description: "Current user and privileges", example: "whoami /all", flags: "/priv (privileges), /groups, /all", beginnerNote: "Shows who you're logged in as. /all shows your complete security context." },
  { command: "ver", category: "System Info", description: "Windows version", example: "ver", flags: "None", beginnerNote: "Quick way to see Windows version number." },
  { command: "set", category: "System Info", description: "Display environment variables", example: "set PATH", flags: "None (displays), = (sets)", beginnerNote: "Shows all environment variables or specific ones." },

  // Network Commands
  { command: "ipconfig", category: "Network", description: "IP configuration", example: "ipconfig /all", flags: "/all (detailed), /release, /renew, /flushdns", beginnerNote: "Shows your IP address, subnet, gateway. /flushdns clears DNS cache." },
  { command: "ping", category: "Network", description: "Test network connectivity", example: "ping -t google.com", flags: "-t (continuous), -n (count), -l (size)", beginnerNote: "Tests if you can reach another computer. -t pings forever." },
  { command: "tracert", category: "Network", description: "Trace route to destination", example: "tracert google.com", flags: "-d (no DNS), -h (max hops)", beginnerNote: "Shows every router between you and the destination." },
  { command: "netstat", category: "Network", description: "Network statistics and connections", example: "netstat -ano", flags: "-a (all), -n (numeric), -o (PID), -b (process name)", beginnerNote: "Shows open ports and connections. -ano is the most useful combo." },
  { command: "nslookup", category: "Network", description: "DNS lookup", example: "nslookup google.com 8.8.8.8", flags: "Interactive mode available", beginnerNote: "Looks up IP addresses for domain names using DNS." },
  { command: "arp", category: "Network", description: "ARP cache (IP to MAC mappings)", example: "arp -a", flags: "-a (display), -d (delete)", beginnerNote: "Shows which MAC addresses are associated with IP addresses." },
  { command: "netsh", category: "Network", description: "Network configuration utility", example: "netsh wlan show profiles", flags: "Many subcommands", beginnerNote: "Powerful network config tool. Can show saved WiFi passwords!" },
  { command: "route", category: "Network", description: "View/modify routing table", example: "route print", flags: "print, add, delete, change", beginnerNote: "Shows how network traffic is routed. Used for VPN troubleshooting." },

  // Process & Task Management
  { command: "tasklist", category: "Process", description: "List running processes", example: "tasklist /v", flags: "/v (verbose), /svc (services), /m (modules)", beginnerNote: "Like Task Manager in command form. Shows all running programs." },
  { command: "taskkill", category: "Process", description: "Terminate processes", example: "taskkill /f /im notepad.exe", flags: "/f (force), /im (by name), /pid (by ID)", beginnerNote: "Forcefully closes programs. /f is needed for stubborn processes." },
  { command: "sc", category: "Process", description: "Service control", example: "sc query wuauserv", flags: "query, start, stop, config, create, delete", beginnerNote: "Manages Windows services. More powerful than the Services GUI." },
  { command: "wmic", category: "Process", description: "WMI command-line (deprecated but useful)", example: "wmic process list brief", flags: "Many classes: process, service, os, etc.", beginnerNote: "Query Windows Management Instrumentation. Being replaced by PowerShell." },

  // User & Security
  { command: "net user", category: "User", description: "User account management", example: "net user administrator", flags: "/add, /delete, /active:yes|no", beginnerNote: "View and manage local user accounts." },
  { command: "net localgroup", category: "User", description: "Local group management", example: "net localgroup administrators", flags: "/add, /delete", beginnerNote: "View and manage local groups like Administrators." },
  { command: "gpresult", category: "Security", description: "Group Policy results", example: "gpresult /r", flags: "/r (summary), /v (verbose), /h (HTML)", beginnerNote: "Shows which Group Policies apply to you or the computer." },
];

// ============================================================================
// POWERSHELL EQUIVALENTS
// ============================================================================

const powershellCommands = [
  { cmdCommand: "dir", psCommand: "Get-ChildItem", alias: "ls, dir, gci", description: "List files and directories", example: "Get-ChildItem -Recurse -Force" },
  { cmdCommand: "cd", psCommand: "Set-Location", alias: "cd, sl, chdir", description: "Change directory", example: "Set-Location C:\\Users" },
  { cmdCommand: "copy", psCommand: "Copy-Item", alias: "cp, copy, cpi", description: "Copy files", example: "Copy-Item file.txt -Destination D:\\Backup" },
  { cmdCommand: "move", psCommand: "Move-Item", alias: "mv, move, mi", description: "Move files", example: "Move-Item old.txt new.txt" },
  { cmdCommand: "del", psCommand: "Remove-Item", alias: "rm, del, ri", description: "Delete files", example: "Remove-Item -Recurse -Force C:\\Temp\\*" },
  { cmdCommand: "mkdir", psCommand: "New-Item -ItemType Directory", alias: "mkdir, md", description: "Create directory", example: "New-Item -ItemType Directory -Path C:\\NewFolder" },
  { cmdCommand: "type", psCommand: "Get-Content", alias: "cat, type, gc", description: "Display file contents", example: "Get-Content log.txt -Tail 50" },
  { cmdCommand: "tasklist", psCommand: "Get-Process", alias: "ps, gps", description: "List processes", example: "Get-Process | Sort-Object CPU -Descending | Select -First 10" },
  { cmdCommand: "taskkill", psCommand: "Stop-Process", alias: "kill, spps", description: "Kill process", example: "Stop-Process -Name notepad -Force" },
  { cmdCommand: "sc query", psCommand: "Get-Service", alias: "gsv", description: "List services", example: "Get-Service | Where-Object Status -eq Running" },
  { cmdCommand: "ipconfig", psCommand: "Get-NetIPConfiguration", alias: "gip", description: "IP configuration", example: "Get-NetIPConfiguration | Select InterfaceAlias, IPv4Address" },
  { cmdCommand: "netstat", psCommand: "Get-NetTCPConnection", alias: "None", description: "Network connections", example: "Get-NetTCPConnection -State Established" },
  { cmdCommand: "net user", psCommand: "Get-LocalUser", alias: "None", description: "List users", example: "Get-LocalUser | Select Name, Enabled, LastLogon" },
  { cmdCommand: "net localgroup", psCommand: "Get-LocalGroup", alias: "None", description: "List groups", example: "Get-LocalGroupMember -Group Administrators" },
  { cmdCommand: "systeminfo", psCommand: "Get-ComputerInfo", alias: "None", description: "System information", example: "Get-ComputerInfo | Select OsName, OsVersion, CsName" },
];

// ============================================================================
// IMPORTANT WINDOWS PROCESSES
// ============================================================================

const importantProcesses = [
  {
    name: "System (PID 4)",
    parent: "None (kernel)",
    description: "The Windows kernel's user-mode representation",
    path: "N/A - kernel process",
    securityNote: "Always PID 4. If you see another 'System' process, it's suspicious.",
    normalBehavior: "Runs from boot, never terminates, no visible window",
  },
  {
    name: "smss.exe",
    parent: "System",
    description: "Session Manager Subsystem - first user-mode process",
    path: "C:\\Windows\\System32\\smss.exe",
    securityNote: "Should only run from System32. Creates csrss.exe and wininit.exe.",
    normalBehavior: "Starts early in boot, minimal resource usage",
  },
  {
    name: "csrss.exe",
    parent: "smss.exe",
    description: "Client/Server Runtime Subsystem - essential Windows subsystem",
    path: "C:\\Windows\\System32\\csrss.exe",
    securityNote: "Multiple instances normal (one per session). MUST be in System32. High-value impersonation target.",
    normalBehavior: "Runs for each user session, handles console windows and threads",
  },
  {
    name: "wininit.exe",
    parent: "smss.exe",
    description: "Windows Initialization - starts critical system processes",
    path: "C:\\Windows\\System32\\wininit.exe",
    securityNote: "Only one instance, only in Session 0. Spawns services.exe and lsass.exe.",
    normalBehavior: "Runs once at boot in Session 0",
  },
  {
    name: "services.exe",
    parent: "wininit.exe",
    description: "Service Control Manager - manages all Windows services",
    path: "C:\\Windows\\System32\\services.exe",
    securityNote: "Only one instance. Parent of all svchost.exe processes. Should never terminate.",
    normalBehavior: "Runs at boot, manages service lifecycle",
  },
  {
    name: "lsass.exe",
    parent: "wininit.exe",
    description: "Local Security Authority Subsystem - handles authentication",
    path: "C:\\Windows\\System32\\lsass.exe",
    securityNote: "CRITICAL - contains credentials in memory. Target of Mimikatz. Only one instance from wininit.exe.",
    normalBehavior: "High memory usage, handles all login events",
  },
  {
    name: "svchost.exe",
    parent: "services.exe",
    description: "Service Host - hosts multiple Windows services",
    path: "C:\\Windows\\System32\\svchost.exe",
    securityNote: "Multiple instances NORMAL. Always from System32, always parent is services.exe. Run with -k flag.",
    normalBehavior: "Many instances with -k groupname. Use tasklist /svc to see hosted services.",
  },
  {
    name: "explorer.exe",
    parent: "userinit.exe",
    description: "Windows Shell - desktop, taskbar, Start menu",
    path: "C:\\Windows\\explorer.exe",
    securityNote: "One per user session. Runs in user context. Common injection target.",
    normalBehavior: "Starts at login, runs continuously, shows desktop",
  },
  {
    name: "winlogon.exe",
    parent: "smss.exe",
    description: "Windows Logon - handles secure attention sequence (Ctrl+Alt+Del)",
    path: "C:\\Windows\\System32\\winlogon.exe",
    securityNote: "One per session. Handles secure logon. Spawns LogonUI.exe.",
    normalBehavior: "Runs per interactive session",
  },
  {
    name: "dwm.exe",
    parent: "svchost.exe",
    description: "Desktop Window Manager - desktop composition and rendering",
    path: "C:\\Windows\\System32\\dwm.exe",
    securityNote: "One instance per session. Runs as DWM user account, not SYSTEM.",
    normalBehavior: "Handles all window rendering and effects",
  },
];

// ============================================================================
// WINDOWS SECURITY EVENT IDs
// ============================================================================

const securityEventIds = [
  { eventId: "4624", category: "Logon", description: "Successful account logon", severity: "Info", investigation: "Normal, but check for unusual times, logon types, or source IPs." },
  { eventId: "4625", category: "Logon", description: "Failed account logon", severity: "Warning", investigation: "Multiple failures may indicate brute force. Check source IP and target account." },
  { eventId: "4634", category: "Logon", description: "Account logoff", severity: "Info", investigation: "Normal event. Correlate with 4624 for session duration analysis." },
  { eventId: "4648", category: "Logon", description: "Logon with explicit credentials", severity: "Medium", investigation: "Someone used runas or mapped drive with different creds. Common for admins." },
  { eventId: "4672", category: "Privilege", description: "Special privileges assigned at logon", severity: "Info", investigation: "Admin logon. Track who gets elevated privileges." },
  { eventId: "4688", category: "Process", description: "New process created", severity: "Info", investigation: "Essential for tracking execution. Enable command line logging!" },
  { eventId: "4689", category: "Process", description: "Process terminated", severity: "Info", investigation: "Correlate with 4688 for process lifetime analysis." },
  { eventId: "4697", category: "Service", description: "Service installed", severity: "Medium", investigation: "New service = potential persistence. Investigate unfamiliar services." },
  { eventId: "4698", category: "Task", description: "Scheduled task created", severity: "Medium", investigation: "Persistence mechanism. Check task details for suspicious commands." },
  { eventId: "4699", category: "Task", description: "Scheduled task deleted", severity: "Medium", investigation: "May indicate attacker cleanup or legitimate maintenance." },
  { eventId: "4720", category: "Account", description: "User account created", severity: "High", investigation: "New accounts need justification. Attackers create backdoor accounts." },
  { eventId: "4722", category: "Account", description: "User account enabled", severity: "Medium", investigation: "Disabled account enabled. Check if authorized." },
  { eventId: "4724", category: "Account", description: "Password reset attempt", severity: "Medium", investigation: "Verify this was authorized. May indicate account takeover." },
  { eventId: "4728", category: "Group", description: "Member added to security-enabled global group", severity: "Medium", investigation: "Track group membership changes, especially to privileged groups." },
  { eventId: "4732", category: "Group", description: "Member added to local group", severity: "High", investigation: "Adding users to Administrators = major event." },
  { eventId: "4768", category: "Kerberos", description: "Kerberos TGT requested", severity: "Info", investigation: "Normal domain auth. Anomalies may indicate Pass-the-Ticket." },
  { eventId: "4769", category: "Kerberos", description: "Kerberos service ticket requested", severity: "Info", investigation: "Watch for Kerberoasting - many requests for service tickets." },
  { eventId: "4776", category: "Credential", description: "NTLM authentication attempt", severity: "Info", investigation: "NTLM should be minimized. May indicate downgrade attack." },
  { eventId: "1102", category: "Audit", description: "Audit log cleared", severity: "Critical", investigation: "RED FLAG - attackers clear logs to cover tracks. Investigate immediately." },
  { eventId: "7045", category: "System", description: "Service installed (System log)", severity: "Medium", investigation: "Alternative to 4697. New services need investigation." },
];

// ============================================================================
// KEYBOARD SHORTCUTS
// ============================================================================

const keyboardShortcuts = [
  { shortcut: "Win + R", action: "Open Run dialog", category: "System", tip: "Quick way to launch programs and commands" },
  { shortcut: "Win + X", action: "Power User menu (WinX menu)", category: "System", tip: "Fast access to admin tools, Event Viewer, etc." },
  { shortcut: "Win + I", action: "Open Settings", category: "System", tip: "Modern Windows settings app" },
  { shortcut: "Win + E", action: "Open File Explorer", category: "Navigation", tip: "Quickly browse files and folders" },
  { shortcut: "Win + L", action: "Lock workstation", category: "Security", tip: "Always lock when leaving your desk!" },
  { shortcut: "Ctrl + Shift + Esc", action: "Open Task Manager directly", category: "System", tip: "Faster than Ctrl+Alt+Del menu" },
  { shortcut: "Win + Pause/Break", action: "Open System Properties", category: "System", tip: "Quick access to computer name and domain info" },
  { shortcut: "Alt + F4", action: "Close current window/Shutdown dialog", category: "System", tip: "On desktop, opens shutdown dialog" },
  { shortcut: "Win + Tab", action: "Task View (virtual desktops)", category: "Navigation", tip: "See all windows and create virtual desktops" },
  { shortcut: "Win + D", action: "Show/hide desktop", category: "Navigation", tip: "Minimize all windows to see desktop" },
  { shortcut: "Win + . (period)", action: "Emoji picker", category: "Input", tip: "Insert emojis anywhere" },
  { shortcut: "Win + V", action: "Clipboard history", category: "Input", tip: "Access previously copied items" },
  { shortcut: "Win + Shift + S", action: "Screenshot snipping tool", category: "Capture", tip: "Modern screenshot tool with area selection" },
  { shortcut: "Win + PrtScn", action: "Screenshot to Pictures folder", category: "Capture", tip: "Saves full screenshot automatically" },
  { shortcut: "Ctrl + Shift + Enter", action: "Run as Administrator", category: "Security", tip: "Launch selected item with elevated privileges" },
  { shortcut: "F2", action: "Rename selected item", category: "File Operations", tip: "Quick rename in Explorer" },
  { shortcut: "Shift + Delete", action: "Permanently delete (skip Recycle Bin)", category: "File Operations", tip: "Be careful - no recovery!" },
  { shortcut: "Alt + Tab", action: "Switch between windows", category: "Navigation", tip: "Hold Alt, tap Tab to cycle" },
  { shortcut: "Win + Arrow Keys", action: "Snap windows", category: "Navigation", tip: "Snap windows to sides or corners" },
  { shortcut: "Ctrl + Z / Ctrl + Y", action: "Undo / Redo", category: "Editing", tip: "Works in Explorer for file operations too" },
];

// ============================================================================
// WINDOWS VERSION HISTORY
// ============================================================================

const windowsVersions = [
  { version: "Windows 11", buildRange: "22000+", releaseYear: "2021", support: "Active", keyFeatures: "Centered taskbar, Snap layouts, Android apps, TPM 2.0 required" },
  { version: "Windows 10", buildRange: "10240-19045", releaseYear: "2015", support: "Until Oct 2025", keyFeatures: "Start menu return, Cortana, Edge, Windows as a Service" },
  { version: "Windows 8.1", buildRange: "9600", releaseYear: "2013", support: "Ended Jan 2023", keyFeatures: "Start button return, improved search" },
  { version: "Windows 8", buildRange: "9200", releaseYear: "2012", support: "Ended", keyFeatures: "Metro UI, no Start menu, touch focus" },
  { version: "Windows 7", buildRange: "7600-7601", releaseYear: "2009", support: "Ended Jan 2020", keyFeatures: "Aero, taskbar improvements, libraries" },
  { version: "Windows Vista", buildRange: "6000-6002", releaseYear: "2006", support: "Ended", keyFeatures: "UAC introduced, Aero Glass, sidebar" },
  { version: "Windows XP", buildRange: "2600", releaseYear: "2001", support: "Ended Apr 2014", keyFeatures: "Luna theme, fast boot, long lifecycle" },
  { version: "Windows 2000", buildRange: "2195", releaseYear: "2000", support: "Ended", keyFeatures: "Active Directory, NTFS 3.0, Plug and Play" },
  { version: "Windows Server 2022", buildRange: "20348", releaseYear: "2021", support: "Active", keyFeatures: "Secured-core, Azure integration, containers" },
  { version: "Windows Server 2019", buildRange: "17763", releaseYear: "2018", support: "Active", keyFeatures: "Windows Admin Center, Kubernetes support" },
  { version: "Windows Server 2016", buildRange: "14393", releaseYear: "2016", support: "Active", keyFeatures: "Nano Server, containers, Hyper-V improvements" },
];

// ============================================================================
// WINDOWS BOOT PROCESS
// ============================================================================

const bootProcess = [
  {
    step: 1,
    name: "Power-On Self Test (POST)",
    description: "BIOS/UEFI firmware initializes hardware and runs diagnostics",
    technical: "CPU, RAM, storage devices tested. Boot device identified.",
    beginnerNote: "This is what happens in the few seconds before you see anything on screen.",
  },
  {
    step: 2,
    name: "UEFI/BIOS Boot",
    description: "Firmware locates and loads the bootloader from the boot device",
    technical: "UEFI looks for EFI\\Microsoft\\Boot\\bootmgfw.efi on EFI System Partition.",
    beginnerNote: "The firmware hands off control to Windows Boot Manager.",
  },
  {
    step: 3,
    name: "Windows Boot Manager",
    description: "bootmgr.efi reads BCD (Boot Configuration Data) and displays boot menu",
    technical: "BCD is the modern replacement for boot.ini. Stored in \\EFI\\Microsoft\\Boot\\BCD.",
    beginnerNote: "If you dual-boot, this is where you choose which OS to start.",
  },
  {
    step: 4,
    name: "Windows Loader",
    description: "winload.efi loads the kernel (ntoskrnl.exe), HAL, and boot-start drivers",
    technical: "Verifies digital signatures, loads Registry SYSTEM hive, initializes drivers.",
    beginnerNote: "The Windows logo appears here. Critical drivers are loaded.",
  },
  {
    step: 5,
    name: "Kernel Initialization",
    description: "ntoskrnl.exe initializes executive subsystems and starts Session Manager",
    technical: "Executive components: Object Manager, Security Reference Monitor, I/O Manager, etc.",
    beginnerNote: "Windows is now running. The kernel sets up the Windows environment.",
  },
  {
    step: 6,
    name: "Session Manager (smss.exe)",
    description: "First user-mode process - initializes sessions and starts subsystems",
    technical: "Creates environment variables, starts csrss.exe and wininit.exe (Session 0).",
    beginnerNote: "Session Manager prepares Windows for user logins.",
  },
  {
    step: 7,
    name: "Service Control Manager",
    description: "services.exe starts all auto-start Windows services",
    technical: "Reads HKLM\\SYSTEM\\CurrentControlSet\\Services, starts services by dependency order.",
    beginnerNote: "All those background services (antivirus, network, etc.) start here.",
  },
  {
    step: 8,
    name: "Winlogon & User Session",
    description: "winlogon.exe handles secure logon, starts LogonUI for credentials",
    technical: "Invokes credential providers, authenticates via LSASS, starts userinit.exe then explorer.exe.",
    beginnerNote: "You see the login screen. After you log in, your desktop appears.",
  },
];

// ============================================================================
// WINDOWS TOOLS (BUILT-IN AND SYSINTERNALS)
// ============================================================================

const windowsTools = [
  // Built-in Tools
  { name: "Task Manager", path: "taskmgr.exe", category: "Built-in", description: "Process, performance, startup, services management", securityUse: "Identify suspicious processes, check resource usage" },
  { name: "Event Viewer", path: "eventvwr.msc", category: "Built-in", description: "View Windows event logs", securityUse: "Investigate security events, track user activity" },
  { name: "Services", path: "services.msc", category: "Built-in", description: "Manage Windows services", securityUse: "Identify suspicious services, check startup types" },
  { name: "Registry Editor", path: "regedit.exe", category: "Built-in", description: "Edit Windows Registry", securityUse: "Check persistence locations, investigate malware" },
  { name: "Computer Management", path: "compmgmt.msc", category: "Built-in", description: "All-in-one system management", securityUse: "User management, disk, services, event logs" },
  { name: "Device Manager", path: "devmgmt.msc", category: "Built-in", description: "Hardware and driver management", securityUse: "Check for suspicious devices or drivers" },
  { name: "Group Policy Editor", path: "gpedit.msc", category: "Built-in", description: "Local group policy configuration", securityUse: "Configure security policies, audit settings" },
  { name: "Resource Monitor", path: "resmon.exe", category: "Built-in", description: "Detailed resource usage monitoring", securityUse: "Track network connections per process" },
  { name: "Windows Defender", path: "Windows Security", category: "Built-in", description: "Built-in antimalware", securityUse: "Scan for malware, check protection status" },
  { name: "Disk Management", path: "diskmgmt.msc", category: "Built-in", description: "Partition and volume management", securityUse: "Check for hidden partitions" },

  // Sysinternals Tools
  { name: "Process Explorer", path: "procexp.exe", category: "Sysinternals", description: "Advanced Task Manager replacement", securityUse: "Deep process analysis, DLL inspection, VirusTotal integration" },
  { name: "Process Monitor", path: "procmon.exe", category: "Sysinternals", description: "Real-time file, registry, process monitoring", securityUse: "Track malware behavior, troubleshoot issues" },
  { name: "Autoruns", path: "autoruns.exe", category: "Sysinternals", description: "Comprehensive startup program viewer", securityUse: "Find ALL persistence mechanisms, detect malware" },
  { name: "TCPView", path: "tcpview.exe", category: "Sysinternals", description: "Real-time network connections viewer", securityUse: "Identify suspicious network connections" },
  { name: "Handle", path: "handle.exe", category: "Sysinternals", description: "View open handles by process", securityUse: "Find what's locking files, investigate processes" },
  { name: "PsExec", path: "psexec.exe", category: "Sysinternals", description: "Execute processes remotely", securityUse: "Remote administration (also used by attackers!)" },
  { name: "AccessChk", path: "accesschk.exe", category: "Sysinternals", description: "View permissions on objects", securityUse: "Find misconfigured permissions, privilege escalation paths" },
  { name: "Sigcheck", path: "sigcheck.exe", category: "Sysinternals", description: "Verify file signatures, VirusTotal submission", securityUse: "Check if files are signed, scan suspicious files" },
  { name: "Strings", path: "strings.exe", category: "Sysinternals", description: "Extract readable strings from binaries", securityUse: "Basic malware analysis, find embedded data" },
  { name: "ListDLLs", path: "listdlls.exe", category: "Sysinternals", description: "List DLLs loaded by processes", securityUse: "Detect DLL injection, find suspicious DLLs" },
];

// ============================================================================
// ENVIRONMENT VARIABLES
// ============================================================================

const environmentVariables = [
  { variable: "%USERPROFILE%", example: "C:\\Users\\John", description: "Current user's profile folder", usage: "Access user-specific folders" },
  { variable: "%APPDATA%", example: "C:\\Users\\John\\AppData\\Roaming", description: "Application data that roams with user", usage: "User settings, persistence location" },
  { variable: "%LOCALAPPDATA%", example: "C:\\Users\\John\\AppData\\Local", description: "Local application data", usage: "Cached data, local settings" },
  { variable: "%TEMP% / %TMP%", example: "C:\\Users\\John\\AppData\\Local\\Temp", description: "Temporary files directory", usage: "Temporary file storage, common malware location" },
  { variable: "%SYSTEMROOT%", example: "C:\\Windows", description: "Windows installation directory", usage: "System files, Windows folder" },
  { variable: "%SYSTEMDRIVE%", example: "C:", description: "Drive where Windows is installed", usage: "System drive letter" },
  { variable: "%PROGRAMFILES%", example: "C:\\Program Files", description: "64-bit program installation folder", usage: "Default program location" },
  { variable: "%PROGRAMFILES(X86)%", example: "C:\\Program Files (x86)", description: "32-bit program folder on 64-bit Windows", usage: "Legacy 32-bit programs" },
  { variable: "%PROGRAMDATA%", example: "C:\\ProgramData", description: "Shared application data", usage: "All-user application data" },
  { variable: "%PATH%", example: "C:\\Windows\\System32;C:\\Windows;...", description: "Executable search path", usage: "Determines where Windows looks for programs" },
  { variable: "%COMPUTERNAME%", example: "DESKTOP-ABC123", description: "Computer's network name", usage: "Machine identification" },
  { variable: "%USERNAME%", example: "John", description: "Current user's name", usage: "Identify logged-in user" },
  { variable: "%USERDOMAIN%", example: "WORKGROUP or DOMAIN", description: "User's domain or workgroup", usage: "Domain identification" },
  { variable: "%HOMEDRIVE%", example: "C:", description: "Drive containing user profile", usage: "Profile location" },
  { variable: "%HOMEPATH%", example: "\\Users\\John", description: "Path to user profile (without drive)", usage: "Profile path component" },
];

// ============================================================================
// WINDOWS SECURITY FEATURES
// ============================================================================

const windowsSecurityFeatures = [
  {
    name: "Windows Defender Antivirus",
    description: "Built-in antimalware protection",
    beginnerNote: "Your computer's immune system. Scans files and monitors behavior for threats.",
    configuration: "Windows Security app or Group Policy",
    securityTips: "Keep real-time protection on. Schedule regular scans. Don't disable for 'performance'.",
  },
  {
    name: "Windows Firewall",
    description: "Built-in network traffic filtering",
    beginnerNote: "Controls what network traffic is allowed in and out. Like a security guard for your network connection.",
    configuration: "wf.msc (Windows Firewall with Advanced Security)",
    securityTips: "Enable for all profiles. Block inbound by default. Create specific allow rules.",
  },
  {
    name: "BitLocker",
    description: "Full disk encryption for Windows",
    beginnerNote: "Encrypts your entire drive so stolen laptops can't be read. Uses TPM chip for key storage.",
    configuration: "Control Panel > BitLocker Drive Encryption",
    securityTips: "Enable on all drives. Store recovery key securely (NOT on the encrypted drive!).",
  },
  {
    name: "User Account Control (UAC)",
    description: "Elevation prompt for administrative actions",
    beginnerNote: "Those 'Do you want to allow this app to make changes?' popups. Protects against accidental or malicious admin actions.",
    configuration: "User Account Control Settings or Group Policy",
    securityTips: "Keep at default or higher. Never set to 'Never notify' - that disables protection.",
  },
  {
    name: "Windows Hello",
    description: "Biometric and PIN-based authentication",
    beginnerNote: "Sign in with your face, fingerprint, or PIN instead of a password.",
    configuration: "Settings > Accounts > Sign-in options",
    securityTips: "Use for convenience. PIN is stored locally and protected by TPM.",
  },
  {
    name: "Credential Guard",
    description: "Virtualization-based credential protection",
    beginnerNote: "Uses hardware virtualization to protect passwords from theft (like Mimikatz attacks).",
    configuration: "Group Policy or Windows Security Baseline",
    securityTips: "Enable on all compatible systems. Requires UEFI, Secure Boot, TPM.",
  },
  {
    name: "Windows Sandbox",
    description: "Isolated desktop environment for testing",
    beginnerNote: "A temporary Windows-within-Windows for safely testing suspicious files.",
    configuration: "Windows Features > Windows Sandbox",
    securityTips: "Use for testing untrusted programs. Everything is deleted when closed.",
  },
  {
    name: "SmartScreen",
    description: "Reputation-based protection for downloads and apps",
    beginnerNote: "Checks files against Microsoft's database of known good/bad software.",
    configuration: "Windows Security > App & browser control",
    securityTips: "Keep enabled. Warns about unrecognized apps and blocks known malware.",
  },
  {
    name: "Controlled Folder Access",
    description: "Ransomware protection for important folders",
    beginnerNote: "Prevents unauthorized programs from modifying files in protected folders.",
    configuration: "Windows Security > Ransomware protection",
    securityTips: "Enable and add trusted apps to allowed list. Protects Documents, Pictures, etc.",
  },
  {
    name: "Exploit Protection",
    description: "Mitigation technologies against exploits",
    beginnerNote: "Technical protections like DEP, ASLR, CFG that make exploiting vulnerabilities harder.",
    configuration: "Windows Security > App & browser control > Exploit protection",
    securityTips: "Keep system defaults. Can configure per-application mitigations.",
  },
];

// ============================================================================
// IMPORTANT GROUP POLICY SETTINGS
// ============================================================================

const groupPolicySettings = [
  { path: "Computer Configuration\\Windows Settings\\Security Settings\\Account Policies", setting: "Password Policy", description: "Minimum length, complexity, history", securityRecommendation: "Min 12 chars, complexity on, 24 password history" },
  { path: "Computer Configuration\\Windows Settings\\Security Settings\\Account Policies", setting: "Account Lockout Policy", description: "Lockout threshold and duration", securityRecommendation: "5 invalid attempts, 15 min lockout, reset after 15 min" },
  { path: "Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Audit Policy", setting: "Audit Policy", description: "What events to log", securityRecommendation: "Enable success/failure for logon, object access, policy change" },
  { path: "Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\User Rights Assignment", setting: "User Rights Assignment", description: "Who can perform system tasks", securityRecommendation: "Minimize SeDebugPrivilege, restrict remote access rights" },
  { path: "Computer Configuration\\Administrative Templates\\System\\Credentials Delegation", setting: "Credential Delegation", description: "Controls credential forwarding", securityRecommendation: "Enable Credential Guard, restrict delegation" },
  { path: "Computer Configuration\\Administrative Templates\\Windows Components\\Windows PowerShell", setting: "PowerShell Logging", description: "Script block and module logging", securityRecommendation: "Enable script block logging for security monitoring" },
  { path: "Computer Configuration\\Windows Settings\\Security Settings\\Windows Firewall", setting: "Windows Firewall", description: "Firewall rules and settings", securityRecommendation: "Enable for all profiles, block inbound by default" },
  { path: "User Configuration\\Administrative Templates\\System", setting: "Don't run specified Windows applications", description: "Block applications by name", securityRecommendation: "Block unauthorized tools, but prefer AppLocker" },
  { path: "Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender", setting: "Windows Defender Settings", description: "Antimalware configuration", securityRecommendation: "Enable real-time protection, cloud-based protection, automatic updates" },
  { path: "Computer Configuration\\Windows Settings\\Security Settings\\Advanced Audit Policy", setting: "Advanced Audit Policy", description: "Granular audit settings", securityRecommendation: "Enable detailed event logging for security-relevant categories" },
];

// ============================================================================
// FORENSIC ARTIFACTS
// ============================================================================

const forensicArtifacts = [
  { artifact: "Prefetch", location: "C:\\Windows\\Prefetch", category: "Execution", description: "Records program execution for performance optimization", investigation: "Shows what programs ran and when. Files named programname-HASH.pf" },
  { artifact: "Shimcache", location: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", category: "Execution", description: "Application compatibility cache", investigation: "Tracks executed programs, survives reboots. Parse with tools." },
  { artifact: "Amcache", location: "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", category: "Execution", description: "Application execution and installation tracking", investigation: "Rich execution data including SHA1 hashes and file sizes." },
  { artifact: "UserAssist", location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", category: "Execution", description: "ROT13 encoded GUI program execution", investigation: "Shows programs run via Explorer, execution count and last run time." },
  { artifact: "Recent Files", location: "%APPDATA%\\Microsoft\\Windows\\Recent", category: "File Access", description: "Recently accessed files shortcuts", investigation: "Shows what files user opened. LNK files contain metadata." },
  { artifact: "Jump Lists", location: "%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations", category: "File Access", description: "Taskbar jump list data", investigation: "Recent files per application. Rich file access history." },
  { artifact: "Shellbags", location: "HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags", category: "File Access", description: "Folder view settings and access", investigation: "Proves folders were accessed even if deleted. Contains timestamps." },
  { artifact: "MRU Lists", location: "Various Registry locations", category: "File Access", description: "Most Recently Used lists", investigation: "Recent documents, search terms, typed paths, run commands." },
  { artifact: "Event Logs", location: "C:\\Windows\\System32\\winevt\\Logs", category: "Logs", description: "Windows event logging", investigation: "Security, System, Application logs. Critical for timeline." },
  { artifact: "SRUM", location: "C:\\Windows\\System32\\sru\\SRUDB.dat", category: "Activity", description: "System Resource Usage Monitor", investigation: "Network usage, application usage, energy usage per app." },
  { artifact: "Browser History", location: "Various per browser", category: "Web Activity", description: "Web browsing history", investigation: "URLs visited, downloads, cookies. Profile-specific locations." },
  { artifact: "USB Device History", location: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB", category: "Devices", description: "Connected USB device records", investigation: "Shows USB devices that were connected. Serial numbers, times." },
];

// ============================================================================
// NETWORK CONFIGURATION
// ============================================================================

const networkConfiguration = [
  { command: "ipconfig /all", description: "Show complete IP configuration", purpose: "View IP, subnet, gateway, DNS, DHCP lease" },
  { command: "ipconfig /release", description: "Release DHCP lease", purpose: "Give up current IP address" },
  { command: "ipconfig /renew", description: "Renew DHCP lease", purpose: "Get new IP from DHCP server" },
  { command: "ipconfig /flushdns", description: "Clear DNS resolver cache", purpose: "Force fresh DNS lookups" },
  { command: "netsh interface ip show config", description: "Show interface configuration", purpose: "Detailed network adapter settings" },
  { command: "netsh wlan show profiles", description: "List saved WiFi networks", purpose: "See stored wireless profiles" },
  { command: "netsh wlan show profile name=X key=clear", description: "Show WiFi password", purpose: "Reveal stored WiFi password (admin required)" },
  { command: "netsh advfirewall show allprofiles", description: "Show firewall status", purpose: "Check firewall state for all profiles" },
  { command: "netsh advfirewall set allprofiles state off", description: "Disable firewall (dangerous!)", purpose: "Turn off Windows Firewall - use with caution" },
  { command: "net use", description: "Show mapped network drives", purpose: "List active network drive mappings" },
  { command: "net share", description: "Show shared folders", purpose: "List folders shared from this computer" },
  { command: "net session", description: "Show active sessions", purpose: "List users connected to this computer's shares" },
  { command: "arp -a", description: "Show ARP cache", purpose: "View IP to MAC address mappings" },
  { command: "route print", description: "Show routing table", purpose: "View how traffic is routed" },
  { command: "nbtstat -n", description: "Show NetBIOS names", purpose: "View registered NetBIOS names" },
];

// ============================================================================
// POWERSHELL SECURITY COMMANDS
// ============================================================================

const powershellSecurityCommands = [
  { command: "Get-Process | Sort-Object CPU -Descending | Select -First 10", description: "Top 10 CPU-consuming processes", category: "Process Analysis" },
  { command: "Get-NetTCPConnection -State Established | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess", description: "Active network connections with PIDs", category: "Network" },
  { command: "Get-WinEvent -LogName Security -MaxEvents 100", description: "Recent security events", category: "Logs" },
  { command: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50", description: "Recent successful logons", category: "Logs" },
  { command: "Get-LocalUser | Select Name, Enabled, LastLogon", description: "List local users with status", category: "Users" },
  { command: "Get-LocalGroupMember -Group Administrators", description: "List members of Administrators group", category: "Users" },
  { command: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'", description: "Startup programs (HKLM)", category: "Persistence" },
  { command: "Get-ScheduledTask | Where-Object State -eq Ready", description: "List enabled scheduled tasks", category: "Persistence" },
  { command: "Get-Service | Where-Object StartType -eq Automatic | Select Name, Status, DisplayName", description: "Auto-start services", category: "Services" },
  { command: "Get-FileHash <file> -Algorithm SHA256", description: "Calculate file hash", category: "Forensics" },
  { command: "Get-ChildItem -Path C:\\ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}", description: "Files modified in last 24 hours", category: "Forensics" },
  { command: "Get-MpThreatDetection", description: "Recent Windows Defender detections", category: "Security" },
  { command: "Get-MpComputerStatus", description: "Windows Defender status", category: "Security" },
  { command: "Get-ExecutionPolicy -List", description: "PowerShell execution policy", category: "Security" },
  { command: "Test-NetConnection -ComputerName <host> -Port <port>", description: "Test TCP connectivity", category: "Network" },
];

// ============================================================================
// WINDOWS HARDENING CHECKLIST
// ============================================================================

const hardeningChecklist = [
  { category: "Updates", item: "Enable automatic Windows Update", priority: "Critical", description: "Patches are your first line of defense against known vulnerabilities." },
  { category: "Updates", item: "Install updates within 48 hours of release", priority: "Critical", description: "Critical patches should be applied quickly to close attack windows." },
  { category: "Accounts", item: "Disable default Administrator account", priority: "High", description: "Rename or disable the built-in Administrator. Create named admin accounts." },
  { category: "Accounts", item: "Use unique local admin passwords (LAPS)", priority: "High", description: "Each machine should have a unique local admin password managed by LAPS." },
  { category: "Accounts", item: "Remove unnecessary accounts", priority: "Medium", description: "Disable Guest account. Remove unused service accounts." },
  { category: "Authentication", item: "Enforce strong password policy", priority: "High", description: "12+ characters, complexity, no common words. Consider passphrases." },
  { category: "Authentication", item: "Enable account lockout", priority: "High", description: "Lock accounts after 5 failed attempts to prevent brute force." },
  { category: "Authentication", item: "Enable MFA where possible", priority: "High", description: "Use Windows Hello, smart cards, or third-party MFA solutions." },
  { category: "Network", item: "Enable Windows Firewall", priority: "Critical", description: "Enable for all profiles. Block inbound by default." },
  { category: "Network", item: "Disable unnecessary services", priority: "Medium", description: "Disable services you don't need: Telnet, SMBv1, WinRM if unused." },
  { category: "Network", item: "Disable LLMNR and NBT-NS", priority: "Medium", description: "Prevents LLMNR poisoning attacks on the local network." },
  { category: "Endpoint", item: "Enable Windows Defender", priority: "Critical", description: "Keep real-time protection and cloud-based protection enabled." },
  { category: "Endpoint", item: "Enable Controlled Folder Access", priority: "Medium", description: "Protects against ransomware encrypting your files." },
  { category: "Endpoint", item: "Configure BitLocker", priority: "High", description: "Encrypt all drives, especially on laptops." },
  { category: "Logging", item: "Enable PowerShell script block logging", priority: "High", description: "Critical for detecting malicious PowerShell activity." },
  { category: "Logging", item: "Enable command line in process creation events", priority: "High", description: "Event ID 4688 should include command line arguments." },
  { category: "Logging", item: "Configure adequate log sizes", priority: "Medium", description: "Increase Security log size to at least 1GB." },
  { category: "Applications", item: "Enable UAC at default or higher", priority: "High", description: "Never disable UAC. Provides defense in depth." },
  { category: "Applications", item: "Implement application whitelisting", priority: "High", description: "Use AppLocker or WDAC to control what can run." },
  { category: "Applications", item: "Uninstall unnecessary software", priority: "Medium", description: "Every installed application is potential attack surface." },
];

// ============================================================================
// COMMON WINDOWS PORTS
// ============================================================================

const commonPorts = [
  { port: "21", protocol: "TCP", service: "FTP", description: "File Transfer Protocol (insecure)", securityNote: "Use SFTP instead. Block if not needed." },
  { port: "22", protocol: "TCP", service: "SSH", description: "Secure Shell (OpenSSH on modern Windows)", securityNote: "OpenSSH now built into Windows 10+." },
  { port: "23", protocol: "TCP", service: "Telnet", description: "Unencrypted remote terminal", securityNote: "NEVER use. Always use SSH instead." },
  { port: "25", protocol: "TCP", service: "SMTP", description: "Email sending", securityNote: "Block outbound 25 except from mail servers." },
  { port: "53", protocol: "TCP/UDP", service: "DNS", description: "Domain Name System", securityNote: "Should only be open on DNS servers." },
  { port: "80", protocol: "TCP", service: "HTTP", description: "Web traffic (unencrypted)", securityNote: "Redirect to HTTPS where possible." },
  { port: "88", protocol: "TCP/UDP", service: "Kerberos", description: "Domain authentication", securityNote: "Required for Active Directory." },
  { port: "135", protocol: "TCP", service: "RPC Endpoint Mapper", description: "Remote Procedure Call", securityNote: "Often targeted. Block from internet." },
  { port: "137-139", protocol: "TCP/UDP", service: "NetBIOS", description: "Legacy Windows networking", securityNote: "Disable if not needed. Security risk." },
  { port: "389", protocol: "TCP/UDP", service: "LDAP", description: "Lightweight Directory Access Protocol", securityNote: "Use LDAPS (636) for encryption." },
  { port: "443", protocol: "TCP", service: "HTTPS", description: "Encrypted web traffic", securityNote: "Default for secure web." },
  { port: "445", protocol: "TCP", service: "SMB", description: "Windows file sharing", securityNote: "Block from internet! SMBv1 is vulnerable." },
  { port: "636", protocol: "TCP", service: "LDAPS", description: "Secure LDAP", securityNote: "Encrypted AD queries. Prefer over 389." },
  { port: "3389", protocol: "TCP", service: "RDP", description: "Remote Desktop Protocol", securityNote: "Never expose directly to internet. Use VPN." },
  { port: "5985/5986", protocol: "TCP", service: "WinRM", description: "Windows Remote Management", securityNote: "PowerShell remoting. Secure but powerful." },
];

// ============================================================================
// ACTIVE DIRECTORY BASICS
// ============================================================================

const activeDirectoryBasics = [
  { concept: "Domain", description: "A logical grouping of objects (users, computers, groups) that share a common directory database", beginnerNote: "Think of a domain as a company's central IT management system. All employees and computers are registered here.", securityRelevance: "Compromising a domain = compromising everything in it." },
  { concept: "Domain Controller (DC)", description: "Server that hosts the AD database and authenticates users", beginnerNote: "The 'brain' of Active Directory. When you log in, the DC checks your password.", securityRelevance: "Highest-value target. Compromise DC = game over. Protect at all costs." },
  { concept: "Organizational Unit (OU)", description: "Container for organizing objects within a domain", beginnerNote: "Like folders for organizing users and computers. Can apply different policies to each OU.", securityRelevance: "Group Policy is applied to OUs. Misconfigured OUs may have weak policies." },
  { concept: "Group Policy", description: "Centralized configuration management for domain computers and users", beginnerNote: "Allows IT to push settings to all computers at once - security policies, software installation, etc.", securityRelevance: "GPOs can deploy software, run scripts. Compromised GPO = mass compromise." },
  { concept: "Security Groups", description: "Collections of users/computers for permission management", beginnerNote: "Instead of giving permissions to individuals, give them to groups and add people to groups.", securityRelevance: "Domain Admins group = full control. Monitor group membership changes." },
  { concept: "Kerberos", description: "Authentication protocol used by Active Directory", beginnerNote: "The technology that checks your password and issues 'tickets' to access resources.", securityRelevance: "Target of Pass-the-Ticket, Golden Ticket, Kerberoasting attacks." },
  { concept: "NTLM", description: "Legacy authentication protocol (hash-based)", beginnerNote: "Older authentication method. Less secure than Kerberos but still widely used.", securityRelevance: "NTLM hashes can be 'passed' without cracking. Disable where possible." },
  { concept: "Forest", description: "Collection of one or more domains that share a common schema", beginnerNote: "The largest container in AD. A company might have multiple domains in one forest.", securityRelevance: "Forest is the security boundary. Compromise of forest root = all domains compromised." },
  { concept: "Trust Relationship", description: "Link between domains that allows authentication across domain boundaries", beginnerNote: "Allows users from one domain to access resources in another domain.", securityRelevance: "Trusts can be exploited for lateral movement between domains." },
  { concept: "LDAP", description: "Protocol for querying and modifying Active Directory", beginnerNote: "The 'language' used to search AD. Tools use LDAP to find users, groups, computers.", securityRelevance: "Anonymous LDAP binds can leak information. Use LDAPS (encrypted)." },
];

// ============================================================================
// QUIZ QUESTIONS
// ============================================================================

const quizQuestions: QuizQuestion[] = [
  // File System & NTFS
  { id: 1, question: "What file system is used by modern Windows installations?", options: ["FAT32", "NTFS", "ext4", "HFS+"], correctAnswer: 1, topic: "File System", explanation: "NTFS (New Technology File System) is the default file system for modern Windows, providing features like ACLs, encryption, and journaling." },
  { id: 2, question: "What does the Master File Table (MFT) store?", options: ["Boot information", "User passwords", "File metadata", "Network settings"], correctAnswer: 2, topic: "File System", explanation: "The MFT is the core of NTFS, storing metadata about every file including name, timestamps, permissions, and data locations." },
  { id: 3, question: "What are Alternate Data Streams (ADS) used for?", options: ["Network streaming", "Attaching hidden data to files", "Video playback", "System logs"], correctAnswer: 1, topic: "File System", explanation: "ADS allows additional data streams to be attached to files, used legitimately for metadata but also by malware to hide payloads." },
  { id: 4, question: "What command shows Alternate Data Streams?", options: ["dir /s", "dir /r", "dir /a", "dir /w"], correctAnswer: 1, topic: "File System", explanation: "The 'dir /r' command reveals Alternate Data Streams attached to files." },

  // Registry
  { id: 5, question: "Which registry hive contains settings for all users?", options: ["HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USERS", "HKEY_CLASSES_ROOT"], correctAnswer: 1, topic: "Registry", explanation: "HKEY_LOCAL_MACHINE (HKLM) contains system-wide settings that apply to all users on the computer." },
  { id: 6, question: "Where is the most common location for startup program persistence?", options: ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\SYSTEM\\Services", "HKCU\\Environment", "HKLM\\SECURITY"], correctAnswer: 0, topic: "Registry", explanation: "The Run key is the most common persistence location. Programs listed here run at every Windows startup." },
  { id: 7, question: "Which registry hive stores local password hashes?", options: ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"], correctAnswer: 2, topic: "Registry", explanation: "The SAM (Security Account Manager) hive contains local user account information including password hashes." },
  { id: 8, question: "What tool is used to edit the Windows Registry?", options: ["notepad.exe", "regedit.exe", "cmd.exe", "services.msc"], correctAnswer: 1, topic: "Registry", explanation: "Regedit.exe is the Registry Editor, providing a graphical interface to view and modify registry settings." },

  // Services
  { id: 9, question: "Which account type has the highest privileges for services?", options: ["NetworkService", "LocalService", "LocalSystem", "Administrator"], correctAnswer: 2, topic: "Services", explanation: "LocalSystem (SYSTEM) is the highest privilege level for services, with full access to the local machine." },
  { id: 10, question: "What command queries a service's configuration?", options: ["sc query", "sc qc", "net start", "services list"], correctAnswer: 1, topic: "Services", explanation: "The 'sc qc servicename' command shows the service configuration including path, startup type, and service account." },
  { id: 11, question: "What session do services run in?", options: ["Session 0", "Session 1", "User Session", "Desktop Session"], correctAnswer: 0, topic: "Services", explanation: "Services run in Session 0, isolated from user sessions (Session 1+) for security." },

  // Processes
  { id: 12, question: "What is the PID of the System process?", options: ["0", "1", "4", "Random"], correctAnswer: 2, topic: "Processes", explanation: "The System process always has PID 4 on Windows. This is the kernel's user-mode representation." },
  { id: 13, question: "Which process handles authentication and contains credentials?", options: ["csrss.exe", "lsass.exe", "services.exe", "svchost.exe"], correctAnswer: 1, topic: "Processes", explanation: "LSASS (Local Security Authority Subsystem Service) handles authentication and stores credentials in memory - a high-value target for attackers." },
  { id: 14, question: "What is the parent process of all svchost.exe instances?", options: ["System", "wininit.exe", "services.exe", "explorer.exe"], correctAnswer: 2, topic: "Processes", explanation: "All svchost.exe processes should have services.exe as their parent. Any other parent is suspicious." },
  { id: 15, question: "Which Sysinternals tool is best for detailed process analysis?", options: ["TCPView", "Autoruns", "Process Explorer", "Handle"], correctAnswer: 2, topic: "Processes", explanation: "Process Explorer is an advanced Task Manager replacement with detailed process information, DLL inspection, and VirusTotal integration." },

  // Security
  { id: 16, question: "What does UAC stand for?", options: ["User Access Control", "User Account Control", "Universal Access Check", "User Authentication Center"], correctAnswer: 1, topic: "Security", explanation: "UAC (User Account Control) prompts for consent before allowing administrative actions, protecting against unauthorized changes." },
  { id: 17, question: "Which feature protects credentials using virtualization?", options: ["BitLocker", "Windows Defender", "Credential Guard", "SmartScreen"], correctAnswer: 2, topic: "Security", explanation: "Credential Guard uses virtualization-based security to protect credentials from theft by tools like Mimikatz." },
  { id: 18, question: "What is the Security Identifier (SID) for the SYSTEM account?", options: ["S-1-5-18", "S-1-5-32-544", "S-1-1-0", "S-1-5-21"], correctAnswer: 0, topic: "Security", explanation: "S-1-5-18 is the SID for the LocalSystem account, the highest privilege account on Windows." },
  { id: 19, question: "Which Event ID indicates a successful logon?", options: ["4624", "4625", "4648", "4672"], correctAnswer: 0, topic: "Security", explanation: "Event ID 4624 is logged when an account successfully logs on to a Windows system." },

  // Networking
  { id: 20, question: "What port does RDP use?", options: ["22", "443", "3389", "5985"], correctAnswer: 2, topic: "Networking", explanation: "Remote Desktop Protocol (RDP) uses TCP port 3389 by default." },
  { id: 21, question: "What command shows all active network connections with PIDs?", options: ["ipconfig /all", "netstat -ano", "route print", "arp -a"], correctAnswer: 1, topic: "Networking", explanation: "The 'netstat -ano' command shows all connections with their states and owning process IDs." },
  { id: 22, question: "What port does SMB use?", options: ["135", "139", "445", "3389"], correctAnswer: 2, topic: "Networking", explanation: "SMB (Server Message Block) for Windows file sharing uses TCP port 445." },
  { id: 23, question: "Which command shows WiFi passwords?", options: ["ipconfig /all", "netsh wlan show profiles key=clear", "route print", "net use"], correctAnswer: 1, topic: "Networking", explanation: "The netsh command with 'key=clear' parameter reveals stored WiFi passwords." },

  // Boot Process
  { id: 24, question: "What is the first user-mode process during Windows boot?", options: ["csrss.exe", "smss.exe", "wininit.exe", "services.exe"], correctAnswer: 1, topic: "Boot", explanation: "Session Manager Subsystem (smss.exe) is the first user-mode process, started by the kernel during boot." },
  { id: 25, question: "Where is the Boot Configuration Data stored on UEFI systems?", options: ["boot.ini", "BCD on EFI partition", "MBR", "C:\\Windows\\Boot"], correctAnswer: 1, topic: "Boot", explanation: "On UEFI systems, BCD is stored on the EFI System Partition at \\EFI\\Microsoft\\Boot\\BCD." },
  { id: 26, question: "What file is the Windows kernel?", options: ["kernel32.dll", "ntdll.dll", "ntoskrnl.exe", "hal.dll"], correctAnswer: 2, topic: "Boot", explanation: "ntoskrnl.exe is the Windows NT kernel, the core of the operating system." },

  // PowerShell
  { id: 27, question: "What is the PowerShell equivalent of 'dir'?", options: ["Get-Directory", "Get-ChildItem", "List-Files", "Show-Item"], correctAnswer: 1, topic: "PowerShell", explanation: "Get-ChildItem (aliases: ls, dir, gci) is the PowerShell equivalent of the dir command." },
  { id: 28, question: "Which PowerShell cmdlet lists running services?", options: ["Get-Process", "Get-Service", "Get-Task", "Get-Running"], correctAnswer: 1, topic: "PowerShell", explanation: "Get-Service lists all Windows services and their current status." },
  { id: 29, question: "What PowerShell feature should be enabled for security monitoring?", options: ["Execution Policy", "Script Block Logging", "Remote Signing", "Constrained Mode"], correctAnswer: 1, topic: "PowerShell", explanation: "Script Block Logging records all PowerShell code execution, critical for detecting malicious activity." },

  // Active Directory
  { id: 30, question: "What authentication protocol does Active Directory primarily use?", options: ["NTLM", "Kerberos", "OAuth", "SAML"], correctAnswer: 1, topic: "Active Directory", explanation: "Active Directory primarily uses Kerberos for authentication, though NTLM is still supported for compatibility." },
  { id: 31, question: "What is a Domain Controller?", options: ["The main user account", "Server hosting AD database", "Firewall appliance", "DNS server only"], correctAnswer: 1, topic: "Active Directory", explanation: "A Domain Controller hosts the Active Directory database and handles authentication for domain users." },
  { id: 32, question: "Which attack targets Kerberos service tickets?", options: ["Pass-the-Hash", "Kerberoasting", "Silver Ticket", "LDAP Injection"], correctAnswer: 1, topic: "Active Directory", explanation: "Kerberoasting requests service tickets that can be cracked offline to reveal service account passwords." },

  // Tools
  { id: 33, question: "Which Sysinternals tool shows ALL startup programs?", options: ["Process Explorer", "Autoruns", "TCPView", "ProcMon"], correctAnswer: 1, topic: "Tools", explanation: "Autoruns shows all programs configured to run at startup from every possible persistence location." },
  { id: 34, question: "What tool captures real-time file, registry, and network activity?", options: ["Task Manager", "Resource Monitor", "Process Monitor", "Event Viewer"], correctAnswer: 2, topic: "Tools", explanation: "Process Monitor (ProcMon) captures real-time file system, registry, and process/thread activity." },
  { id: 35, question: "Which built-in tool manages disk partitions?", options: ["diskpart.exe", "diskmgmt.msc", "Both", "Neither"], correctAnswer: 2, topic: "Tools", explanation: "Both diskpart (command-line) and diskmgmt.msc (GUI) can manage disk partitions on Windows." },
];

// Quiz helper constants
const QUIZ_QUESTION_COUNT = 15;

const selectRandomQuestions = (questions: QuizQuestion[], count: number): QuizQuestion[] => {
  const shuffled = [...questions].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, count);
};

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function WindowsBasicsPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const accent = "#0078d4"; // Windows blue

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  // Section navigation items
  const sectionNavItems = [
    { id: "overview", label: "Overview", icon: <SchoolIcon /> },
    { id: "core-concepts", label: "Core Concepts", icon: <DesktopWindowsIcon /> },
    { id: "architecture", label: "Architecture", icon: <LayersIcon /> },
    { id: "directories", label: "Important Directories", icon: <FolderIcon /> },
    { id: "registry", label: "Registry Keys", icon: <StorageIcon /> },
    { id: "commands", label: "CMD Commands", icon: <TerminalIcon /> },
    { id: "powershell", label: "PowerShell", icon: <DataObjectIcon /> },
    { id: "processes", label: "Critical Processes", icon: <MemoryIcon /> },
    { id: "events", label: "Security Events", icon: <HistoryIcon /> },
    { id: "shortcuts", label: "Keyboard Shortcuts", icon: <KeyIcon /> },
    { id: "versions", label: "Windows Versions", icon: <UpdateIcon /> },
    { id: "boot", label: "Boot Process", icon: <PlayArrowIcon /> },
    { id: "tools", label: "Windows Tools", icon: <BuildIcon /> },
    { id: "env-vars", label: "Environment Variables", icon: <DataObjectIcon /> },
    { id: "security-features", label: "Security Features", icon: <ShieldIcon /> },
    { id: "group-policy", label: "Group Policy", icon: <PolicyIcon /> },
    { id: "forensics", label: "Forensic Artifacts", icon: <FindInPageIcon /> },
    { id: "network-config", label: "Network Config", icon: <NetworkCheckIcon /> },
    { id: "ps-security", label: "PS Security Commands", icon: <LockIcon /> },
    { id: "hardening", label: "Hardening Checklist", icon: <VerifiedUserIcon /> },
    { id: "ports", label: "Common Ports", icon: <RouterIcon /> },
    { id: "active-directory", label: "Active Directory", icon: <AccountTreeIcon /> },
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

  const [quizPool] = useState<QuizQuestion[]>(() => selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT));

  const pageContext = `Windows Basics learning page - Comprehensive Windows operating system fundamentals for IT professionals and security practitioners. Covers file system, registry, services, processes, security features, and more.`;

  // Sidebar navigation component
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
              "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 2 },
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
    <LearnPageLayout pageTitle="Windows Basics" pageContext={pageContext}>
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
            <Typography variant="h6" sx={{ fontWeight: 700 }}>Navigation</Typography>
            <IconButton size="small" onClick={() => setNavDrawerOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Box>
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
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
                  "&:hover": { bgcolor: alpha(accent, 0.1) },
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
                background: `linear-gradient(135deg, ${alpha(accent, 0.15)} 0%, ${alpha("#00a4ef", 0.1)} 100%)`,
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
                    background: `linear-gradient(135deg, ${accent}, #00a4ef)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha(accent, 0.3)}`,
                  }}
                >
                  <DesktopWindowsIcon sx={{ fontSize: 45, color: "white" }} />
                </Box>
                <Box>
                  <Chip label="IT Fundamentals" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha(accent, 0.1), color: accent }} />
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 1 }}>Windows Basics</Typography>
                  <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600 }}>
                    Master Windows operating system fundamentals for IT and security
                  </Typography>
                </Box>
              </Box>
            </Paper>

            {/* Overview Section */}
            <Box id="overview" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SchoolIcon sx={{ color: accent }} /> Overview
              </Typography>
              <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.background.paper, 0.6) }}>
                <Typography variant="body1" paragraph>
                  Windows is the world's most widely used desktop operating system, powering over 1 billion devices worldwide.
                  Understanding Windows fundamentals is essential for IT professionals, system administrators, and security practitioners.
                </Typography>
                <Typography variant="body1" paragraph>
                  This comprehensive guide covers everything from the Windows file system and registry to security features
                  and Active Directory. Whether you're troubleshooting issues, hardening systems, or investigating incidents,
                  this knowledge forms the foundation of Windows expertise.
                </Typography>
                <Alert severity="info" sx={{ mt: 2 }}>
                  <AlertTitle>For Beginners</AlertTitle>
                  Each topic includes beginner-friendly explanations alongside technical details. Look for the "For Beginners" boxes
                  and the "beginnerNote" fields to get plain-language explanations of complex concepts.
                </Alert>
              </Paper>
            </Box>

            {/* Core Concepts Section */}
            <Box id="core-concepts" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DesktopWindowsIcon sx={{ color: accent }} /> Core Windows Concepts
              </Typography>
              {windowsConcepts.map((concept, index) => (
                <Accordion
                  key={index}
                  sx={{
                    mb: 2,
                    borderRadius: "12px !important",
                    "&:before": { display: "none" },
                    border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                  }}
                >
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Box
                        sx={{
                          width: 40,
                          height: 40,
                          borderRadius: 2,
                          bgcolor: alpha(concept.color, 0.15),
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          color: concept.color,
                        }}
                      >
                        {concept.icon}
                      </Box>
                      <Box>
                        <Typography variant="h6" sx={{ fontWeight: 600 }}>{concept.title}</Typography>
                        <Typography variant="body2" color="text.secondary">{concept.shortDescription}</Typography>
                      </Box>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Alert severity="info" sx={{ mb: 3 }}>
                      <AlertTitle>For Beginners</AlertTitle>
                      <Typography variant="body2" sx={{ whiteSpace: "pre-line" }}>{concept.beginnerExplanation}</Typography>
                    </Alert>
                    <Typography variant="body1" sx={{ mb: 2, whiteSpace: "pre-line" }}>{concept.technicalDescription}</Typography>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Key Points:</Typography>
                    <List dense>
                      {concept.keyPoints.map((point, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <CheckCircleIcon sx={{ fontSize: 16, color: concept.color }} />
                          </ListItemIcon>
                          <ListItemText primary={point} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      <AlertTitle>Security Note</AlertTitle>
                      {concept.securityNote}
                    </Alert>
                    {concept.realWorldExample && (
                      <Paper sx={{ p: 2, mt: 2, bgcolor: alpha(concept.color, 0.05), borderRadius: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                          <TipsAndUpdatesIcon sx={{ fontSize: 18 }} /> Try It Yourself
                        </Typography>
                        <Typography variant="body2">{concept.realWorldExample}</Typography>
                      </Paper>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>

            {/* Architecture Section */}
            <Box id="architecture" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <LayersIcon sx={{ color: accent }} /> Windows Architecture
              </Typography>
              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>For Beginners</AlertTitle>
                Windows is organized in layers, like a building with different floors. The top floors (User Mode) are where
                your programs run. The bottom floors (Kernel Mode) are where Windows itself operates with full access to hardware.
              </Alert>
              <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Layer</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Ring</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Components</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {windowsArchitecture.map((layer, index) => (
                      <TableRow key={index} sx={{ "&:hover": { bgcolor: alpha(accent, 0.05) } }}>
                        <TableCell sx={{ fontWeight: 600 }}>{layer.layer}</TableCell>
                        <TableCell>
                          <Chip label={layer.ring} size="small" sx={{ bgcolor: layer.ring === "Ring 0" ? alpha("#ef4444", 0.1) : alpha("#22c55e", 0.1) }} />
                        </TableCell>
                        <TableCell>{layer.description}</TableCell>
                        <TableCell>
                          {layer.components.map((comp, i) => (
                            <Chip key={i} label={comp} size="small" sx={{ mr: 0.5, mb: 0.5, fontSize: "0.7rem" }} />
                          ))}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Important Directories Section */}
            <Box id="directories" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <FolderIcon sx={{ color: accent }} /> Important Directories
              </Typography>
              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>For Beginners</AlertTitle>
                Windows organizes files in a specific folder structure. Understanding where things are stored helps with troubleshooting
                and is essential for security investigations.
              </Alert>
              <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Path</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Security Relevance</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {importantDirectories.map((dir, index) => (
                      <TableRow key={index} sx={{ "&:hover": { bgcolor: alpha(accent, 0.05) } }}>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem", fontWeight: 600 }}>{dir.path}</TableCell>
                        <TableCell>
                          <Chip label={dir.purpose} size="small" />
                        </TableCell>
                        <TableCell>{dir.description}</TableCell>
                        <TableCell>
                          <Typography variant="body2" color="warning.main">{dir.securityRelevance}</Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Registry Keys Section */}
            <Box id="registry" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon sx={{ color: accent }} /> Security-Critical Registry Keys
              </Typography>
              <Alert severity="warning" sx={{ mb: 3 }}>
                <AlertTitle>Security Warning</AlertTitle>
                The Registry is a common target for malware persistence. These keys should be monitored for unauthorized changes.
              </Alert>
              {registryKeys.map((key, index) => (
                <Paper key={index} sx={{ p: 2, mb: 2, borderRadius: 2, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
                  <Typography variant="subtitle1" sx={{ fontFamily: "monospace", fontWeight: 600, color: accent, mb: 1 }}>
                    {key.key}
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>{key.description}</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>
                    Data Type: {key.dataType}
                  </Typography>
                  <Alert severity="info" sx={{ py: 0 }}>
                    <Typography variant="caption">{key.beginnerNote}</Typography>
                  </Alert>
                </Paper>
              ))}
            </Box>

            {/* CMD Commands Section */}
            <Box id="commands" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon sx={{ color: accent }} /> Essential CMD Commands
              </Typography>
              {["File System", "System Info", "Network", "Process", "User"].map((category) => (
                <Box key={category} sx={{ mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>{category}</Typography>
                  <Grid container spacing={2}>
                    {essentialCommands
                      .filter((cmd) => cmd.category === category)
                      .map((cmd, index) => (
                        <Grid item xs={12} md={6} key={index}>
                          <Card sx={{ height: "100%", borderRadius: 2 }}>
                            <CardContent>
                              <Typography variant="subtitle1" sx={{ fontFamily: "monospace", fontWeight: 700, color: accent }}>
                                {cmd.command}
                              </Typography>
                              <Typography variant="body2" sx={{ mb: 1 }}>{cmd.description}</Typography>
                              <Paper sx={{ p: 1, bgcolor: alpha(theme.palette.common.black, 0.05), borderRadius: 1, mb: 1 }}>
                                <Typography variant="caption" sx={{ fontFamily: "monospace" }}>{cmd.example}</Typography>
                              </Paper>
                              <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                                Flags: {cmd.flags}
                              </Typography>
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                  </Grid>
                </Box>
              ))}
            </Box>

            {/* PowerShell Section */}
            <Box id="powershell" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DataObjectIcon sx={{ color: accent }} /> PowerShell Commands
              </Typography>
              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>For Beginners</AlertTitle>
                PowerShell is the modern command-line for Windows. It works with objects, not just text, making it much more powerful than CMD.
              </Alert>
              <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>CMD</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>PowerShell</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Aliases</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {powershellCommands.map((cmd, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ fontFamily: "monospace" }}>{cmd.cmdCommand}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", color: accent, fontWeight: 600 }}>{cmd.psCommand}</TableCell>
                        <TableCell>{cmd.alias}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{cmd.example}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Critical Processes Section */}
            <Box id="processes" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <MemoryIcon sx={{ color: accent }} /> Critical Windows Processes
              </Typography>
              <Alert severity="warning" sx={{ mb: 3 }}>
                <AlertTitle>Security Note</AlertTitle>
                Knowing normal process behavior helps identify anomalies. Malware often impersonates these processes or runs from wrong locations.
              </Alert>
              <Grid container spacing={2}>
                {importantProcesses.map((proc, index) => (
                  <Grid item xs={12} md={6} key={index}>
                    <Card sx={{ height: "100%", borderRadius: 2 }}>
                      <CardContent>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: accent }}>{proc.name}</Typography>
                        <Typography variant="body2" sx={{ mb: 1 }}>{proc.description}</Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                          <strong>Path:</strong> {proc.path}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                          <strong>Parent:</strong> {proc.parent}
                        </Typography>
                        <Alert severity="info" sx={{ mt: 1, py: 0 }}>
                          <Typography variant="caption">{proc.securityNote}</Typography>
                        </Alert>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>

            {/* Security Events Section */}
            <Box id="events" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <HistoryIcon sx={{ color: accent }} /> Security Event IDs
              </Typography>
              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>For Beginners</AlertTitle>
                Windows logs everything in Event Viewer. These Event IDs are the most important for security monitoring and incident response.
              </Alert>
              <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Event ID</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Severity</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Investigation Tips</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {securityEventIds.map((evt, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ fontWeight: 700, color: accent }}>{evt.eventId}</TableCell>
                        <TableCell>{evt.category}</TableCell>
                        <TableCell>{evt.description}</TableCell>
                        <TableCell>
                          <Chip
                            label={evt.severity}
                            size="small"
                            sx={{
                              bgcolor:
                                evt.severity === "Critical" ? alpha("#ef4444", 0.15) :
                                evt.severity === "High" ? alpha("#f97316", 0.15) :
                                evt.severity === "Medium" ? alpha("#eab308", 0.15) :
                                evt.severity === "Warning" ? alpha("#f59e0b", 0.15) :
                                alpha("#22c55e", 0.15),
                              color:
                                evt.severity === "Critical" ? "#ef4444" :
                                evt.severity === "High" ? "#f97316" :
                                evt.severity === "Medium" ? "#eab308" :
                                evt.severity === "Warning" ? "#f59e0b" :
                                "#22c55e",
                            }}
                          />
                        </TableCell>
                        <TableCell><Typography variant="caption">{evt.investigation}</Typography></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Keyboard Shortcuts Section */}
            <Box id="shortcuts" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <KeyIcon sx={{ color: accent }} /> Keyboard Shortcuts
              </Typography>
              <Grid container spacing={2}>
                {keyboardShortcuts.map((shortcut, index) => (
                  <Grid item xs={12} sm={6} md={4} key={index}>
                    <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                      <Chip label={shortcut.shortcut} sx={{ fontWeight: 700, mb: 1, bgcolor: alpha(accent, 0.1), color: accent }} />
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{shortcut.action}</Typography>
                      <Typography variant="caption" color="text.secondary">{shortcut.tip}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>

            {/* Windows Versions Section */}
            <Box id="versions" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <UpdateIcon sx={{ color: accent }} /> Windows Version History
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Version</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Build Range</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Release Year</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Support Status</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Key Features</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {windowsVersions.map((ver, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ fontWeight: 600 }}>{ver.version}</TableCell>
                        <TableCell>{ver.buildRange}</TableCell>
                        <TableCell>{ver.releaseYear}</TableCell>
                        <TableCell>
                          <Chip
                            label={ver.support}
                            size="small"
                            sx={{
                              bgcolor: ver.support === "Active" ? alpha("#22c55e", 0.15) : alpha("#ef4444", 0.15),
                              color: ver.support === "Active" ? "#22c55e" : "#ef4444",
                            }}
                          />
                        </TableCell>
                        <TableCell><Typography variant="caption">{ver.keyFeatures}</Typography></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Boot Process Section */}
            <Box id="boot" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <PlayArrowIcon sx={{ color: accent }} /> Windows Boot Process
              </Typography>
              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>For Beginners</AlertTitle>
                When you turn on your computer, a complex sequence of events happens before you see your desktop.
                Understanding this helps with troubleshooting boot issues and detecting boot-level malware.
              </Alert>
              <Box sx={{ position: "relative" }}>
                {bootProcess.map((step, index) => (
                  <Box key={index} sx={{ display: "flex", mb: 2 }}>
                    <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", mr: 3 }}>
                      <Box
                        sx={{
                          width: 40,
                          height: 40,
                          borderRadius: "50%",
                          bgcolor: accent,
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
                        <Box sx={{ width: 2, flexGrow: 1, bgcolor: alpha(accent, 0.3), my: 1 }} />
                      )}
                    </Box>
                    <Paper sx={{ p: 2, flexGrow: 1, borderRadius: 2 }}>
                      <Typography variant="h6" sx={{ fontWeight: 600 }}>{step.name}</Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>{step.description}</Typography>
                      <Typography variant="caption" color="text.secondary">{step.technical}</Typography>
                    </Paper>
                  </Box>
                ))}
              </Box>
            </Box>

            {/* Windows Tools Section */}
            <Box id="tools" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <BuildIcon sx={{ color: accent }} /> Windows Tools
              </Typography>
              {["Built-in", "Sysinternals"].map((category) => (
                <Box key={category} sx={{ mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>{category} Tools</Typography>
                  <Grid container spacing={2}>
                    {windowsTools
                      .filter((tool) => tool.category === category)
                      .map((tool, index) => (
                        <Grid item xs={12} md={6} key={index}>
                          <Card sx={{ height: "100%", borderRadius: 2 }}>
                            <CardContent>
                              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: accent }}>{tool.name}</Typography>
                              <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary", display: "block", mb: 1 }}>
                                {tool.path}
                              </Typography>
                              <Typography variant="body2" sx={{ mb: 1 }}>{tool.description}</Typography>
                              <Typography variant="caption" color="warning.main">{tool.securityUse}</Typography>
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                  </Grid>
                </Box>
              ))}
            </Box>

            {/* Environment Variables Section */}
            <Box id="env-vars" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DataObjectIcon sx={{ color: accent }} /> Environment Variables
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Variable</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Example Value</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Usage</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {environmentVariables.map((env, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ fontFamily: "monospace", fontWeight: 600, color: accent }}>{env.variable}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{env.example}</TableCell>
                        <TableCell>{env.description}</TableCell>
                        <TableCell>{env.usage}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Security Features Section */}
            <Box id="security-features" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <ShieldIcon sx={{ color: accent }} /> Windows Security Features
              </Typography>
              <Grid container spacing={2}>
                {windowsSecurityFeatures.map((feature, index) => (
                  <Grid item xs={12} md={6} key={index}>
                    <Card sx={{ height: "100%", borderRadius: 2 }}>
                      <CardContent>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: accent }}>{feature.name}</Typography>
                        <Typography variant="body2" sx={{ mb: 1 }}>{feature.description}</Typography>
                        <Alert severity="info" sx={{ py: 0, mb: 1 }}>
                          <Typography variant="caption">{feature.beginnerNote}</Typography>
                        </Alert>
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                          <strong>Configure:</strong> {feature.configuration}
                        </Typography>
                        <Typography variant="caption" color="warning.main" sx={{ display: "block", mt: 1 }}>
                          {feature.securityTips}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>

            {/* Group Policy Section */}
            <Box id="group-policy" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <PolicyIcon sx={{ color: accent }} /> Group Policy Settings
              </Typography>
              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>For Beginners</AlertTitle>
                Group Policy (gpedit.msc) allows centralized configuration of Windows settings. In enterprises, policies are pushed from
                domain controllers. On standalone machines, local policies can still be configured.
              </Alert>
              <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Setting</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Recommendation</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {groupPolicySettings.map((gpo, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ fontWeight: 600 }}>{gpo.setting}</TableCell>
                        <TableCell>{gpo.description}</TableCell>
                        <TableCell><Typography variant="caption" color="success.main">{gpo.securityRecommendation}</Typography></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Forensic Artifacts Section */}
            <Box id="forensics" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <FindInPageIcon sx={{ color: accent }} /> Forensic Artifacts
              </Typography>
              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>For Beginners</AlertTitle>
                Windows leaves traces of activity everywhere. Forensic investigators use these artifacts to reconstruct what happened on a system.
              </Alert>
              {forensicArtifacts.map((artifact, index) => (
                <Paper key={index} sx={{ p: 2, mb: 2, borderRadius: 2 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>{artifact.artifact}</Typography>
                    <Chip label={artifact.category} size="small" />
                  </Box>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary", display: "block", mb: 1 }}>
                    {artifact.location}
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>{artifact.description}</Typography>
                  <Typography variant="caption" color="warning.main">{artifact.investigation}</Typography>
                </Paper>
              ))}
            </Box>

            {/* Network Configuration Section */}
            <Box id="network-config" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <NetworkCheckIcon sx={{ color: accent }} /> Network Configuration Commands
              </Typography>
              <Grid container spacing={2}>
                {networkConfiguration.map((cmd, index) => (
                  <Grid item xs={12} md={6} key={index}>
                    <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontFamily: "monospace", fontWeight: 700, color: accent }}>{cmd.command}</Typography>
                      <Typography variant="body2">{cmd.description}</Typography>
                      <Typography variant="caption" color="text.secondary">{cmd.purpose}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>

            {/* PowerShell Security Commands Section */}
            <Box id="ps-security" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <LockIcon sx={{ color: accent }} /> PowerShell Security Commands
              </Typography>
              {powershellSecurityCommands.map((cmd, index) => (
                <Paper key={index} sx={{ p: 2, mb: 2, borderRadius: 2 }}>
                  <Chip label={cmd.category} size="small" sx={{ mb: 1 }} />
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: alpha(theme.palette.common.black, 0.05), p: 1, borderRadius: 1, mb: 1 }}>
                    {cmd.command}
                  </Typography>
                  <Typography variant="caption">{cmd.description}</Typography>
                </Paper>
              ))}
            </Box>

            {/* Hardening Checklist Section */}
            <Box id="hardening" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <VerifiedUserIcon sx={{ color: accent }} /> Windows Hardening Checklist
              </Typography>
              {["Updates", "Accounts", "Authentication", "Network", "Endpoint", "Logging", "Applications"].map((category) => (
                <Box key={category} sx={{ mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>{category}</Typography>
                  {hardeningChecklist
                    .filter((item) => item.category === category)
                    .map((item, index) => (
                      <Paper key={index} sx={{ p: 2, mb: 1, borderRadius: 2, display: "flex", alignItems: "flex-start", gap: 2 }}>
                        <Chip
                          label={item.priority}
                          size="small"
                          sx={{
                            bgcolor:
                              item.priority === "Critical" ? alpha("#ef4444", 0.15) :
                              item.priority === "High" ? alpha("#f97316", 0.15) :
                              alpha("#22c55e", 0.15),
                            color:
                              item.priority === "Critical" ? "#ef4444" :
                              item.priority === "High" ? "#f97316" :
                              "#22c55e",
                            minWidth: 70,
                          }}
                        />
                        <Box>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{item.item}</Typography>
                          <Typography variant="caption" color="text.secondary">{item.description}</Typography>
                        </Box>
                      </Paper>
                    ))}
                </Box>
              ))}
            </Box>

            {/* Common Ports Section */}
            <Box id="ports" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <RouterIcon sx={{ color: accent }} /> Common Windows Ports
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Port</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Service</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Security Note</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {commonPorts.map((port, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ fontWeight: 700, color: accent }}>{port.port}</TableCell>
                        <TableCell>{port.protocol}</TableCell>
                        <TableCell>{port.service}</TableCell>
                        <TableCell>{port.description}</TableCell>
                        <TableCell><Typography variant="caption" color="warning.main">{port.securityNote}</Typography></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Active Directory Section */}
            <Box id="active-directory" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <AccountTreeIcon sx={{ color: accent }} /> Active Directory Basics
              </Typography>
              <Alert severity="info" sx={{ mb: 3 }}>
                <AlertTitle>For Beginners</AlertTitle>
                Active Directory (AD) is Microsoft's directory service for Windows domain networks. It's how enterprises manage
                users, computers, and security at scale. Understanding AD is essential for enterprise security.
              </Alert>
              <Grid container spacing={2}>
                {activeDirectoryBasics.map((item, index) => (
                  <Grid item xs={12} md={6} key={index}>
                    <Card sx={{ height: "100%", borderRadius: 2 }}>
                      <CardContent>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: accent }}>{item.concept}</Typography>
                        <Typography variant="body2" sx={{ mb: 1 }}>{item.description}</Typography>
                        <Alert severity="info" sx={{ py: 0, mb: 1 }}>
                          <Typography variant="caption">{item.beginnerNote}</Typography>
                        </Alert>
                        <Typography variant="caption" color="warning.main">{item.securityRelevance}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>

            {/* Quiz Section */}
            <Box id="quiz" sx={{ mb: 6, scrollMarginTop: 100 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <QuizIcon sx={{ color: accent }} /> Knowledge Check
              </Typography>
              <QuizSection questions={quizPool} />
            </Box>

          </Grid>
        </Grid>
      </Container>
    </LearnPageLayout>
  );
}
